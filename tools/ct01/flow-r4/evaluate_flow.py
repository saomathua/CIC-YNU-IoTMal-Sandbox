#!/usr/bin/env python3
"""OFFLINE evaluator R2 of a flow_lane.py run directory. Reads files only. Exit 0 only when every criterion of the mode holds, 1 = a criterion failed, 2 = the
directory is incomplete/unreadable (not a result). Never a CT-01 PASS: it covers T01/T02-runtime, T18, T19 (success), F3/F4 (fault modes) and F5 (Compose
restart) of THIS lane.

R2 (independent review 2026-10-11, finding F1): every REQUIRED measurement is validated by its rc (allowed rc per command kind), its stderr where the kind
says so, and a minimal schema BEFORE its content is compared; two equal failed reads never count as 'unchanged'. pgrep rc 1 with empty stdout/stderr is the
only legitimate 'absent' and is accepted for pgrep only. The run identity pins the staged tree (manifest, runner, evaluator, pins, export helper, entry).

    python3 -I -B evaluate_flow.py <run_dir> <pins.json> [--out verdicts.json]"""
import hashlib, io, json, pathlib, re, sys, zipfile

MODES = ("success", "f3", "f4", "f5")
HERE = pathlib.Path(__file__).resolve().parent


class Incomplete(Exception):
    pass


def rd(p):
    try:
        return pathlib.Path(p).read_text(errors="replace")
    except OSError as e:
        raise Incomplete(f"cannot read {p}: {e}")


def rj(p):
    try:
        return json.loads(rd(p))
    except ValueError as e:
        raise Incomplete(f"cannot parse {p}: {e}")


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, group, name, ok, detail=""):
        self.rows.append({"group": group, "name": name, "ok": bool(ok), "detail": str(detail)[:400]})
        print(("PASS " if ok else "FAIL ") + f"[{group}] {name}" + ("" if ok else f"  -> {str(detail)[:200]}"))


def sha_of(p):
    try:
        return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def read_meas(run, rel):
    """-> (rc, stdout, stderr) from <rel>.rc/.txt/.err written by the lane, or None when the rc file is absent/unparsable."""
    base = str(pathlib.Path(run) / rel)
    try:
        rc = int(pathlib.Path(base + ".rc").read_text().strip())
    except (OSError, ValueError):
        return None
    out = pathlib.Path(base + ".txt").read_text(errors="replace") if pathlib.Path(base + ".txt").exists() else ""
    err = pathlib.Path(base + ".err").read_text(errors="replace") if pathlib.Path(base + ".err").exists() else ""
    return rc, out, err


def judge(kind, m):
    """-> (ok, state, why). state: 'present' | 'absent' | 'read'. Schema is the minimum that a real reading of that command must have."""
    if m is None:
        return False, None, "no rc file: not measured"
    rc, out, err = m
    o = out.strip()
    if kind == "pgrep":
        if rc == 0 and o:
            return True, "present", ""
        if rc == 1 and not o and not err.strip():
            return True, "absent", ""
        return False, None, f"pgrep rc={rc} stdout={o[:60]!r} stderr={err.strip()[:60]!r}"
    if rc != 0:
        return False, None, f"rc={rc} stderr={err.strip()[:80]!r}"
    if kind == "rc0":
        return True, "read", ""
    if kind == "list-any":                                 # `docker ps` with a filter: rc 0, empty is a valid answer
        return True, "read", ""
    if not o:
        return False, None, "empty stdout"
    if kind == "nft" and "table " not in o:
        return False, None, "no 'table' in the ruleset text"
    if kind == "route" and " dev " not in (" " + o.replace("\n", " ") + " "):
        return False, None, "no 'dev' in the route text"
    if kind == "addr" and not re.search(r"\binet \d+\.\d+\.\d+\.\d+", o):
        return False, None, "no inet address"
    if kind == "sysctl" and o not in ("0", "1"):
        return False, None, f"not 0/1: {o[:20]!r}"
    if kind == "dockerps" and any(len(l.split()) < 3 for l in o.splitlines()):
        return False, None, "a docker ps row has fewer than 3 fields"
    if kind == "image-id" and not re.fullmatch(r"sha256:[0-9a-f]{64}", o):
        return False, None, f"not an image id: {o[:30]!r}"
    return True, "read", ""


def ts_lines(text):
    return [l.split(" ", 1)[1] if re.match(r"^\d{4}-\d\d-\d\dT", l) and " " in l else l for l in text.splitlines()]


def merged_log(run, name):
    """docker logs: stdout in <name>.txt, stderr in <name>.err (the worker's python logging is on stderr). Merged by the docker timestamp (stable)."""
    rows = []
    for ext in ("txt", "err"):
        p = pathlib.Path(run) / f"{name}.{ext}"
        if p.exists():
            rows += [l for l in rd(p).splitlines() if l.strip()]
    key = lambda l: l.split(" ", 1)[0] if re.match(r"^\d{4}-\d\d-\d\dT", l) else ""   # noqa: E731
    return sorted(rows, key=key)


def order_ok(lines, pats, start=0):
    """each pattern found after the previous one; returns (ok, missing)"""
    pos = start
    for p in pats:
        for i in range(pos, len(lines)):
            if re.search(p, lines[i]):
                pos = i + 1
                break
        else:
            return False, p
    return True, None


def bind_problem(run, arch, tag, tid, trigger_re):
    """-> (ok, detail). The sample file written by the lane: schema; task id; the trigger log line really matches the checkpoint; t_start < t_end; at BOTH
    ends the manager said PROCESSING for this task and `pgrep -a qemu-system` in the worker gave rc 0 with the same non-empty pid set."""
    try:
        d = json.loads(rd(run / f"verify-{arch}-{tag}.json"))
    except (Incomplete, ValueError) as e:
        return False, f"sample file: {e}"
    why = []
    if d.get("schema") != "ct01-flow-verify-sample/1" or d.get("task_id") != tid or d.get("arch") != arch or d.get("tag") != tag:
        why.append("schema/task/arch/tag")
    if not re.search(trigger_re, str((d.get("trigger") or {}).get("line", ""))):
        why.append("trigger line does not match the checkpoint")
    ts, te = d.get("t_start"), d.get("t_end")
    if not (isinstance(ts, (int, float)) and isinstance(te, (int, float)) and ts < te):
        why.append("t_start/t_end not ordered")
    pidsets = []
    for side in ("before", "after"):
        b = d.get(side) or {}
        if b.get("task_status") != "PROCESSING" or b.get("tasks_http") != 200:
            why.append(f"{side}: task status {b.get('task_status')!r} (http {b.get('tasks_http')})")
        pids = sorted(re.findall(r"^(\d+) qemu-system", b.get("qemu", ""), re.M))
        if b.get("qemu_rc") != 0 or not pids:
            why.append(f"{side}: no qemu-system process seen in the worker (rc {b.get('qemu_rc')})")
        pidsets.append(pids)
    if len(pidsets) == 2 and pidsets[0] != pidsets[1]:
        why.append(f"QEMU pid set changed during the verifier run: {pidsets[0]} -> {pidsets[1]}")
    return not why, "; ".join(why)


def evaluate_f5(run, pins, ck, ident, mode):
    """F5: `docker compose restart sandbox-worker-1` on the Compose worker created by this lane. See flow_lane.run_f5."""
    cp = pins["compose"]

    def jf(rel):
        try:
            return json.loads(rd(run / rel))
        except (Incomplete, ValueError):
            return None
    for tag in ("before", "after"):
        for n, kind in (("nft-table", "nft"), ("tap0", "rc0"), ("verify", "rc0"), ("health", "rc0"), ("inspect", "rc0")):
            ok, _, why = judge(kind, read_meas(run, f"f5-{tag}-{n}"))
            ck.add("measure", f"f5-{tag}-{n}: rc/schema ({kind})", ok, why)
    for n in ("f5-compose-up", "f5-compose-restart"):
        ok, _, why = judge("rc0", read_meas(run, n))
        ck.add("compose", f"{n}: rc 0", ok, why)
    b, a = jf("f5-before.json") or {}, jf("f5-after.json") or {}
    ob, oa = jf("f5-others-before.json") or {}, jf("f5-others-after.json") or {}
    cb, ca = jf("f5-log-counts-before.json") or {}, jf("f5-log-counts-after.json") or {}
    lab = lambda x: (x.get("labels") or {})                                          # noqa: E731
    ck.add("target", "the restart target is exactly the Compose service container: project/service labels pinned, name as Compose names it, image = pin, IP 192.168.60.2",
           all(x and lab(x).get("com.docker.compose.project") == cp["project"] and lab(x).get("com.docker.compose.service") == cp["service"]
               and x.get("name") == cp["expected_container_name"] and x.get("image") == pins["image_id"]
               and (x.get("networks") or {}).get(cp["project"] + "_sandboxnet") == cp["worker_ip"] for x in (b, a)), f"{b.get('name')} {lab(b)} {b.get('networks')}")
    ck.add("target", "restart kept the container (same id before/after) and the compose project listed exactly this one container before and after the restart",
           bool(b.get("id")) and b.get("id") == a.get("id"))
    ck.add("restart", "A14: the process was really restarted: StartedAt later, PID different, running", bool(b.get("started_at")) and bool(a.get("started_at"))
           and a.get("started_at") > b.get("started_at") and isinstance(b.get("pid"), int) and isinstance(a.get("pid"), int) and a["pid"] != b["pid"]
           and a.get("running") is True and b.get("running") is True, f"{b.get('started_at')} {b.get('pid')} -> {a.get('started_at')} {a.get('pid')}")
    # R3 (F5 run 20261011T040725Z, kept as history): an inode number of /proc/<pid>/ns/net is NOT evidence of the same namespace -- freed nsfs inode numbers are
    # reused (the R2 run read net:[4026532810] before and after although Docker had built a new sandbox). The criteria are the sandbox identity Docker reports
    # and what the application itself saw on the second start (no tap0, ip_forward back to 1 before run.sh).
    def sandbox(tag):
        d_ = jf(f"f5-{tag}-inspect.txt")
        d_ = d_[0] if isinstance(d_, list) and d_ else {}
        ns = d_.get("NetworkSettings", {})
        eps = sorted(str((v or {}).get("EndpointID")) for v in (ns.get("Networks") or {}).values())
        return ns.get("SandboxID"), ns.get("SandboxKey"), eps
    sb_b, sb_a = sandbox("before"), sandbox("after")
    ck.add("restart", "A14: Docker built a NEW network sandbox: SandboxID, SandboxKey and EndpointID all differ (netns inode shown for reference only; equality of inodes proves nothing)",
           all(sb_b) and all(sb_a) and sb_b[0] != sb_a[0] and sb_b[1] != sb_a[1] and sb_b[2] != sb_a[2],
           f"{sb_b[0] and sb_b[0][:12]} -> {sb_a[0] and sb_a[0][:12]}; key {sb_b[1]} -> {sb_a[1]}; netns {b.get('netns')} -> {a.get('netns')}")
    wl_ = ts_lines("\n".join(merged_log(run, "worker-logs-final")))
    pre = [(i, l) for i, l in enumerate(wl_) if "SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=" in l]
    seen = []
    for i, l in pre:
        nxt = next((x for x in wl_[i + 1:i + 6] if "SYSCTL REPORT (before run.sh): rp_filter" in x), "")
        seen.append(("ip_forward=1" in l, "tap0=None" in nxt))
    post = [l for l in wl_ if "SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0" in l]
    ck.add("restart", "A14: both starts saw a pristine namespace before run.sh (ip_forward=1, tap0 absent) and run.sh set ip_forward=0 each time (the second start did not inherit the first start's state)",
           len(pre) == 2 and all(x == (True, True) for x in seen) and len(post) == 2, f"pre={seen} post={len(post)}")
    ck.add("restart", "V0 OK once before and twice after the restart (the container log is cumulative), poller started again",
           cb.get("v0") == 1 and ca.get("v0") == 2 and cb.get("poller") == 1 and ca.get("poller") == 2, f"{cb} -> {ca}")
    for tag in ("before", "after"):
        vo = rd(run / f"f5-{tag}-verify.txt") if (run / f"f5-{tag}-verify.rc").exists() else ""
        ck.add("isolation", f"after set-up ({tag} the restart): table inet sandbox_guest present, tap0 present, verifier rc 0 ISOLATION OK, manager -> worker healthcheck 200",
               all(judge(k, read_meas(run, f"f5-{tag}-{n}"))[0] for n, k in (("nft-table", "nft"), ("tap0", "rc0"), ("verify", "rc0"), ("health", "rc0")))
               and "ISOLATION OK" in vo and re.fullmatch(r"200 \d+(\.\d+)?", rd(run / f"f5-{tag}-health.txt").strip()) is not None)
    ck.add("others", "manager and MongoDB untouched: same container ids, same StartedAt, running, same restart count",
           set(ob) == {cp["manager_container"], cp["mongo_container"]} and ob == oa and all(v.get("running") is True and v.get("id") for v in ob.values()), f"{ob} vs {oa}")
    cl = jf("cleanup.json") or {}
    ck.add("host", "cleanup: the labels of the exact id were read back, it was removed (rc 0), nothing with the project/service labels is left",
           cl.get("labels_ok") is True and cl.get("rm_rc") == 0 and cl.get("ps_rc") == 0 and cl.get("labelled_after") == [] and cl.get("id") == b.get("id"))
    sb, sa = rj(run / "manager-before-status.json"), rj(run / "manager-after-status.json")
    try:
        cbs, cas = json.loads(sb["body"]), json.loads(sa["body"])
    except Exception as e:                                       # noqa: BLE001
        raise Incomplete(f"manager status unreadable: {e}")
    ck.add("manager", "/status unchanged (no task was submitted or taken)", cbs == cas, f"{cbs} -> {cas}")
    return ck, mode


def evaluate(run, pins, pins_path=None):
    run = pathlib.Path(run)
    ck = Checks()
    ident = rj(run / "identity.json")
    status = rj(run / "lane-status.json")
    mode = ident.get("mode")
    if mode not in MODES:
        raise Incomplete(f"unknown mode {mode!r}")
    ck.add("lane", "identity: schema, label, pinned image id", ident.get("schema") in ("ct01-flow-identity/1", "ct01-flow-identity/2") and ident.get("image_id") == pins["image_id"]
           and status.get("label") == ident.get("label") and status.get("mode") == mode)
    tr = ident.get("tree") if ident.get("schema") == "ct01-flow-identity/2" else None
    if tr is None:
        ck.add("lane", "identity pins the staged tree (manifest/runner/evaluator/pins/export/entry)", False, "legacy identity schema /1: nothing pinned")
    else:
        mine = {"manifest_sha256": sha_of(HERE / "SHA256SUMS"), "runner_sha256": sha_of(HERE / "flow_lane.py"), "evaluator_sha256": sha_of(HERE / "evaluate_flow.py"),
                "pins_sha256": sha_of(pins_path) if pins_path else sha_of(HERE / "pins.json"), "export_sha256": sha_of(HERE / "export_run.py"),
                "entry_sha256": sha_of(HERE / "lane_entry.sh")}
        listed = {}
        try:
            for l in (HERE / "SHA256SUMS").read_text().splitlines():
                h, n = l.split("  ", 1)
                listed[n] = h
        except OSError:
            pass
        bad = [k for k, v in mine.items() if v is None or tr.get(k) != v]
        bad += [f"manifest entry {n}" for n, k in (("flow_lane.py", "runner_sha256"), ("evaluate_flow.py", "evaluator_sha256"), ("pins.json", "pins_sha256"),
                                                    ("export_run.py", "export_sha256"), ("lane_entry.sh", "entry_sha256")) if listed.get(n) != tr.get(k)]
        if tr.get("manifest_literal") is not None and tr.get("manifest_literal") != tr.get("manifest_sha256"):
            bad.append("manifest literal differs from the staged manifest")
        ck.add("lane", "identity pins the staged tree: manifest/runner/evaluator/pins/export/entry hashes equal the files evaluating this run and the manifest entries",
               not bad and tr.get("manifest_literal") is not None, f"differing: {bad}; literal={tr.get('manifest_literal')}")
    ck.add("lane", "the lane completed: no signal, no abort reason", status.get("completed") is True and status.get("signal") is None and status.get("abort_reason") is None,
           f"completed={status.get('completed')} signal={status.get('signal')} abort={status.get('abort_reason')}")
    if status.get("completed") is not True:
        return ck, mode
    # environment gates
    ok, _, why = judge("image-id", read_meas(run, "env-image-id"))
    ck.add("measure", "env-image-id: rc 0 and an image id", ok, why)
    ck.add("env", "worker image id equals the pinned one", ok and rd(run / "env-image-id.txt").strip() == pins["image_id"])
    okq, stq, whyq = judge("pgrep", read_meas(run, "env-qemu"))
    ck.add("measure", "env-qemu: pgrep rc 0 (found) or rc 1 with empty output (absent)", okq, whyq)
    okl, _, whyl = judge("list-any", read_meas(run, "env-leftover"))
    ck.add("measure", "env-leftover: docker ps rc 0", okl, whyl)
    ck.add("env", "no qemu-system and no ct01-flow container before the lane", okq and stq == "absent" and okl and rd(run / "env-leftover.txt").strip() == "")
    mh = rj(run / "manager-before-health.json")
    ck.add("env", "manager healthcheck 200 before the lane (host -> manager API)", mh.get("http") == 200)
    try:
        c0 = json.loads(rj(run / "manager-before-status.json")["body"])
    except Exception:                                            # noqa: BLE001
        c0 = {}
    ck.add("env", "manager queue empty before the lane (queued/processing/in_memory_queue 0)", all(c0.get(k) == 0 for k in ("queued", "processing", "in_memory_queue")), c0)
    # host invariants
    def norm(n, x):
        # `ip -4 -o addr` carries the DHCP lease countdown (valid_lft/preferred_lft); only that is ignored
        return re.sub(r"(valid_lft|preferred_lft) \d+sec", r"\1 N", x) if n == "ip-addr" else x
    KINDS = (("nft", "nft"), ("ip-route", "route"), ("ip-addr", "addr"), ("sysctl-forward", "sysctl"), ("docker-ps", "dockerps"), ("qemu", "pgrep"), ("capture", "pgrep"))
    J = {}
    for side in ("before", "after"):
        for n, kind in KINDS:
            J[(side, n)] = judge(kind, read_meas(run, f"host-{side}/{n}"))
            ck.add("measure", f"host-{side}/{n}: rc/schema ({kind})", J[(side, n)][0], J[(side, n)][2])
    for n, _ in KINDS[:4]:
        both = J[("before", n)][0] and J[("after", n)][0]
        ck.add("host", f"{n} unchanged before/after (both readings valid)", both and norm(n, rd(run / f"host-before/{n}.txt")) == norm(n, rd(run / f"host-after/{n}.txt")))
    ck.add("host", "no qemu-system after the lane (a valid 'absent' reading)", J[("after", "qemu")][0] and J[("after", "qemu")][1] == "absent")
    ck.add("host", "capture processes after = before (valid readings)", J[("before", "capture")][0] and J[("after", "capture")][0]
           and J[("before", "capture")][1] == J[("after", "capture")][1])
    names_b = sorted(l.split()[0] for l in rd(run / "host-before/docker-ps.txt").splitlines() if l.strip())
    names_a = sorted(l.split()[0] for l in rd(run / "host-after/docker-ps.txt").splitlines() if l.strip())
    sc = {"f5": ()}.get(mode, ("ct01-flow-worker",))
    ck.add("host", "container set after = container set before (the worker was removed)",
           J[("before", "docker-ps")][0] and J[("after", "docker-ps")][0] and names_b == names_a and not any(x in names_a for x in sc), f"{names_b} vs {names_a}")
    if mode != "f5":
        cl = rj(run / "cleanup.json")
        ck.add("host", "cleanup by label: the labelled set is empty afterwards, both queries rc 0", cl.get("labelled_after") == [] and cl.get("ps_rc") == 0 and cl.get("ps_after_rc") == 0)
    # worker log
    okw, _, whyw = judge("rc0", read_meas(run, "worker-logs-final"))
    ck.add("measure", "worker-logs-final: docker logs rc 0", okw, whyw)
    if mode == "f5":
        return evaluate_f5(run, pins, ck, ident, mode)
    wl = ts_lines("\n".join(merged_log(run, "worker-logs-final")))
    v0 = [i for i, l in enumerate(wl) if re.search(r"ISOLATION OK \(V0 startup\)", l)]
    recv = [i for i, l in enumerate(wl) if "Received task:" in l]
    ck.add("worker", "V0 OK exactly once and before the first task", len(v0) == 1 and (not recv or v0[0] < recv[0]), f"v0={v0} recv={recv}")
    ck.add("worker", "the real poller and server started (entrypoint run.sh path)", any("Starting worker poller" in l for l in wl))
    sb, sa = rj(run / "manager-before-status.json"), rj(run / "manager-after-status.json")
    try:
        cb, ca = json.loads(sb["body"]), json.loads(sa["body"])
    except Exception as e:                                       # noqa: BLE001
        raise Incomplete(f"manager status unreadable: {e}")
    archs = ["ARM", "MIPS"] if mode == "success" else ["ARM"]
    if mode == "success":
        t19 = rd(run / "t19-manager-to-worker-health.txt").strip()
        m19 = read_meas(run, "t19-manager-to-worker-health")
        ck.add("T19", "manager container -> worker healthcheck 200 (source is the manager container, with the worker idle)",
               m19 is not None and m19[0] == 0 and re.fullmatch(r"200 \d+(\.\d+)?", t19) is not None, t19)
    for idx, arch in enumerate(archs):
        sub = rj(run / f"submit-{arch}.json")
        fx = pins["fixtures"][arch]["sha256"]
        ck.add(arch, "fixture submitted through the manager API: HTTP 200, status QUEUED, a task id", sub.get("http") == 200 and sub.get("task_id")
               and '"QUEUED"' in sub.get("response", "") and sub.get("bytes") == pins["fixtures"][arch]["size"], sub.get("response"))
        tid = sub.get("task_id") or ""
        rows = []
        for l in rd(run / f"poll-{arch}.jsonl").splitlines():
            if l.strip():
                rows.append(json.loads(l))
        sts = [r["task"]["status"] for r in rows if r.get("task")]
        proc = [r["task"] for r in rows if r.get("task") and r["task"].get("status") == "PROCESSING"]
        final = rj(run / f"final-{arch}.json")
        if mode == "success":
            ck.add(arch, "T18: the real poller took the task: PROCESSING with worker_id ct01-flow-worker, then COMPLETED, never FAILED/CANCELLED",
                   bool(proc) and all(p.get("worker_id") == "ct01-flow-worker" for p in proc) and (final or {}).get("status") == "COMPLETED"
                   and not ({"FAILED", "CANCELLED"} & set(sts)), f"statuses={sorted(set(sts))}")
            seg = wl[next((i for i, l in enumerate(wl) if f"Received task: {tid}" in l), 0):]
            ok, miss = order_ok(seg, [rf"Received task: {tid}", rf"Detected architecture: {arch}", r"Starting QEMU", r"Started QEMU", r"Got the executable inside QEMU",
                                      r"Started network capture", r"Stopped network capture", r"QEMU shutdown complete \(phase 1", r"Starting QEMU", r"Started QEMU",
                                      r"Uploading strace", r"Uploading sar", r"QEMU shutdown complete \(phase 2", r"Upload response: 200"])
            ck.add(arch, "T01/T02 runtime order in the worker log: download in guest -> capture -> phase-1 shutdown -> phase-2 boot -> upload strace/sar -> phase-2 shutdown -> result upload 200",
                   ok, f"missing/out of order: {miss}")
            for tag, trig in (("p1-running", r"Got the executable inside QEMU"), ("p2-uploading", r"Uploading strace")):
                vo = rd(run / f"verify-{arch}-{tag}.txt") if (run / f"verify-{arch}-{tag}.rc").exists() else ""
                ck.add(arch, f"isolation verifier run IN the worker while {tag}: rc 0 and ISOLATION OK",
                       (run / f"verify-{arch}-{tag}.rc").exists() and rd(run / f"verify-{arch}-{tag}.rc").strip() == "0" and "ISOLATION OK" in vo)
                ck.add(arch, f"verifier sample {tag} bound to the task and the QEMU process set (checkpoint, not a timing proof)",
                       *bind_problem(run, arch, tag, tid, trig))
            zp = run / f"result-{arch}.zip"
            ck.add(arch, "result zip copied from the manager's output", zp.exists() and zp.stat().st_size > 0 and rd(run / f"result-{arch}-cp.rc").strip() == "0")
            if zp.exists():
                try:
                    z = zipfile.ZipFile(zp)
                    names = z.namelist()
                    members = {n: z.read(n) for n in names if not n.endswith("/")}
                except Exception as e:                           # noqa: BLE001
                    names, members = [], {}
                    ck.add(arch, "result zip readable", False, e)
                binm = members.get(tid)
                ck.add(arch, "result: the task binary is the submitted fixture (sha256)", binm is not None and hashlib.sha256(binm).hexdigest() == fx)
                st = members.get("strace.log", b"")
                ck.add(arch, "result: strace.log non-empty and shows the guest executing ./exec (execve)", len(st) > 0 and b"execve" in st and b"./exec" in st)
                ck.add(arch, "result: sar.out non-empty", len(members.get("sar.out", b"")) > 0)
                ck.add(arch, "result: network.pcap and qemu.log present", "network.pcap" in members and "qemu.log" in members, names)
                ck.add(arch, "result: no image directory leaked into the archive", not any(n.startswith("image/") for n in names))
        elif mode == "f3":
            reason = (final or {}).get("failure_reason", "")
            ck.add(arch, "F3: FAILED with the V1 isolation reason (fault injected while the worker was idle)", (final or {}).get("status") == "FAILED"
                   and "network isolation check failed (V1 before phase 1)" in reason, f"{(final or {}).get('status')} {reason[:160]}")
            ck.add(arch, "F3: the fault command succeeded before the submit", rd(run / "fault-f3-nft-delete.rc").strip() == "0")
            ck.add(arch, "F3: no QEMU was started for the task", not any(re.search(r"Starting QEMU|Started QEMU", l) for l in wl))
            ck.add(arch, "F3: no network.pcap / result for the task", not (run / f"result-{arch}.zip").exists())
        else:
            reason = (final or {}).get("failure_reason", "")
            ck.add(arch, "F4: the fault was armed while phase 1 ran (guest had the executable) and the delete command succeeded",
                   rd(run / "fault-f4-armed.txt").startswith("True") and rd(run / "fault-f4-nft-delete.rc").strip() == "0")
            ck.add(arch, "F4: FAILED with the V2 isolation reason", (final or {}).get("status") == "FAILED"
                   and "network isolation check failed (V2 before phase 2)" in reason, f"{(final or {}).get('status')} {reason[:160]}")
            starts = [l for l in wl if re.search(r"Starting QEMU", l)]
            sd1 = [l for l in wl if re.search(r"QEMU shutdown complete \(phase 1", l)]
            sd2 = [l for l in wl if re.search(r"QEMU shutdown complete \(phase 2", l)]
            ck.add(arch, "F4: phase 1 QEMU was confirmed down; phase 2 never started", len(starts) == 1 and len(sd1) == 1 and not sd2, f"starts={len(starts)} sd1={len(sd1)} sd2={len(sd2)}")
            ck.add(arch, "F4: no result zip, no 'Upload response' for the task", not (run / f"result-{arch}.zip").exists() and not any("Upload response" in l for l in wl))
    # manager counters
    nb = len(archs)
    if mode == "success":
        ck.add("manager", f"/status: completed +{nb}, failed unchanged, nothing left queued/processing",
               ca.get("completed") == cb.get("completed", 0) + nb and ca.get("failed") == cb.get("failed", 0) and ca.get("processing") == 0 and ca.get("in_memory_queue") == 0,
               f"{cb} -> {ca}")
    else:
        ck.add("manager", "/status: failed +1, completed unchanged, nothing left queued/processing",
               ca.get("failed") == cb.get("failed", 0) + 1 and ca.get("completed") == cb.get("completed", 0) and ca.get("processing") == 0 and ca.get("in_memory_queue") == 0,
               f"{cb} -> {ca}")
    return ck, mode


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    try:
        ck, mode = evaluate(argv[0], json.loads(pathlib.Path(argv[1]).read_text()), argv[1])
    except Incomplete as e:
        print(f"INCOMPLETE: {e}")
        out = {"all_ok": False, "incomplete": True, "reason": str(e)}
        if "--out" in argv:
            pathlib.Path(argv[argv.index("--out") + 1]).write_text(json.dumps(out, indent=1))
        return 2
    ok = all(r["ok"] for r in ck.rows) and bool(ck.rows)
    out = {"all_ok": ok, "mode": mode, "checks": ck.rows, "statement": "criteria of this lane only; not a CT-01 PASS; F1b/F6/B1/T16/T17 are other lanes"}
    if "--out" in argv:
        pathlib.Path(argv[argv.index("--out") + 1]).write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print("FLOW-LANE:", "ALL CRITERIA HELD" if ok else "CRITERIA NOT MET", "|", mode)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
