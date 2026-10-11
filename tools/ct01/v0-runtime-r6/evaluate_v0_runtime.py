#!/usr/bin/env python3
"""CT-01 V0 runtime (F1b, F6) — OFFLINE evaluator of the artefacts that run-v0-runtime.sh writes. Reads files only: no docker, no root, no network.

    python3 -I -B evaluate_v0_runtime.py <RUN_DIR> <pins.json> [--root STAGE_DIR] [--out verdicts.json]

Exit 0 only if EVERY criterion of the control, F1b, F6 and the global host/cleanup checks holds; 1 if a criterion failed (a result); 2 if the run
directory is incomplete/unreadable (not a result). Nothing here is a PASS of CT-01. The item number of an F6 diff is NEVER compared with a constant:
it is only parsed; a value derived from the pinned expected ruleset is reported as information.
"""
import collections
import hashlib
import json
import pathlib
import re
import sys

CTRL, F1B, F6 = "control", "f1b", "f6"
OK_LINE = "ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route"
ALLOWED_DOCKER = {"image", "ps", "network", "inspect", "run", "wait", "logs", "exec", "stop", "rm", "events", "info"}
DIFF_RE = re.compile(r"ISOLATION FAIL \(V0 startup\): ruleset: table 'inet sandbox_guest' differs at item (\d+): expected=(.*?) actual=(.*)$")


class Incomplete(Exception):
    pass


def rd(p, binary=False):
    try:
        return p.read_bytes() if binary else p.read_text(errors="replace")
    except OSError as e:
        raise Incomplete(f"cannot read {p}: {e}")


def rj(p):
    try:
        return json.loads(rd(p))
    except ValueError as e:
        raise Incomplete(f"cannot parse {p}: {e}")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def merged_log(d, name="docker-logs.txt"):
    """R6: `docker logs` writes the container's stdout to <name> and its stderr to <name>.err (R5 run 20261010T164552Z: the F1b `command not found` and
    the F6 `ISOLATION FAIL` line were on stderr). Both streams are criteria evidence: merge them by the docker timestamp (stable for equal stamps)."""
    out = rd(d / name).splitlines()
    err_p = d / (name + ".err")
    err = rd(err_p).splitlines() if err_p.exists() else []
    tag = lambda ls: [(l.split(" ", 1)[0] if re.match(r"^\d{4}-\d\d-\d\dT", l) else "", l) for l in ls]   # noqa: E731
    return [l for _, l in sorted(tag(out) + tag(err), key=lambda x: x[0])]


NFT_BENIGN_WARNING = re.compile(r"^# Warning: table (?:ip|ip6|inet|arp|bridge) \S+ is managed by iptables-nft, do not touch!$")


def real_stderr(text):
    """R6: `nft -s list ruleset` on a host with iptables-nft prints that single warning per table on stderr with rc 0; only that exact text is ignored."""
    return "\n".join(l for l in text.splitlines() if l.strip() and not NFT_BENIGN_WARNING.match(l.strip()))


def strip_ts(line):
    """docker logs --timestamps: '<RFC3339Nano> <text>'"""
    parts = line.split(" ", 1)
    return parts[1] if len(parts) == 2 and re.match(r"^\d{4}-\d\d-\d\dT", parts[0]) else line


def ts_of(line):
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z", line)
    return (m.group(1) + (m.group(2) or ".0")[:7]) if m else None


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, case, name, ok, detail=""):
        self.rows.append({"case": case, "check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def all_ok(self, case=None):
        return all(r["ok"] for r in self.rows if case is None or r["case"] == case)


def derived_item_index(expected_tables):
    """Information only: where `nft -j` lists a rule appended to chain `input` of inet sandbox_guest = right after the last existing rule of that chain."""
    items = expected_tables["inet sandbox_guest"]
    last = None
    for i, it in enumerate(items):
        r = it.get("rule")
        if r and r.get("chain") == "input":
            last = i
    return None if last is None else last + 1


def case_common(ck, case, d, pins, net_name, label):
    insp = rj(d / "inspect.json")
    insp = insp[0] if isinstance(insp, list) else insp
    hc, cfg = insp.get("HostConfig", {}), insp.get("Config", {})
    ck.add(case, "image id equals the pinned image id", insp.get("Image") == pins["image_id"], f"{insp.get('Image')!r}")
    ck.add(case, "own network namespace on the existing sandboxnet (not host, not none)", hc.get("NetworkMode") == net_name and net_name not in ("host", "none"), f"{hc.get('NetworkMode')!r}")
    ck.add(case, "no published ports", not hc.get("PortBindings"), json.dumps(hc.get("PortBindings")))
    ck.add(case, "restart policy none and no restart happened", (hc.get("RestartPolicy") or {}).get("Name") in ("no", "") and insp.get("RestartCount") == 0,
           f"{hc.get('RestartPolicy')} restarts={insp.get('RestartCount')}")
    env = cfg.get("Env") or []
    ck.add(case, "ALLOW_VM_INTERNET=false", "ALLOW_VM_INTERNET=false" in env)
    ck.add(case, "created with this run's label", (cfg.get("Labels") or {}).get("ct01-v0rt") == label, f"{(cfg.get('Labels') or {}).get('ct01-v0rt')!r} vs {label!r}")
    binds = {b.split(":")[1]: b for b in (hc.get("Binds") or []) if b.count(":") >= 2}
    for dst, src_name in (("/app/server.py", "sentinel/server.py"), ("/app/poller.py", "sentinel/poller.py")):
        b = binds.get(dst, "")
        ck.add(case, f"{dst} is the SENTINEL, mounted read-only", b.endswith(":ro") and b.split(":")[0].endswith(src_name), b)
    return insp, binds, env


def file_set(p):
    return sorted(x.name for x in p.iterdir()) if p.is_dir() else None


ROOT = pathlib.Path(".")


def res(p):
    """pins.json holds stage-relative paths (inputs/…, tree/…); an absolute path is used as is."""
    return pathlib.Path(p) if str(p).startswith("/") else ROOT / p


HOST_FILES = {"ip-route": "ip-route.txt", "ip6-route": "ip6-route.txt", "tap0": "host-tap0.txt", "nft": "nft-ruleset-stateless.txt", "iptables": "iptables-save.txt",
              "ss": "listen-tcp-raw.txt", "pgrep": "qemu.txt", "image-inspect": "image-id.txt", "image-ls": "image-ls.txt", "ps-all": "ps-all.txt"}
SYSCTL_KEYS = (["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"]
               + [f"net.ipv4.conf.{d}.{a}" for d in ("all", "default", "ens33") for a in ("rp_filter", "arp_ignore", "arp_announce", "arp_accept", "forwarding")])
CORE_SYSCTL = SYSCTL_KEYS[:4] + [f"net.ipv4.conf.{d}.{a}" for d in ("all", "default") for a in ("rp_filter", "arp_ignore", "arp_announce", "arp_accept", "forwarding")]
FIXED_NAMES = {   # non-host measurements: name -> run-relative file (exactly one row each in a completed run)
    "image-inspect": "image-inspect.txt", "names": "running-names.txt", "pgrep0": "qemu-guard.txt",
    "exists:ct01-v0rt-control": "exists-ct01-v0rt-control.txt", "exists:ct01-v0rt-f1b": "exists-ct01-v0rt-f1b.txt", "exists:ct01-v0rt-f6": "exists-ct01-v0rt-f6.txt",
    "network-ls": "network-ls.txt", "network-inspect": "sandboxnet.txt",
    "pre:resolve-default": "preflight/resolve-default-path.txt", "pre:resolve-nonft": "preflight/resolve-nonft-path.txt",
    "pre:sha": "preflight/sha256-in-image.txt", "pre:nftc": "preflight/f6-nft-check.txt",
    "ctl:state": "control/state-before-stop.json", "ctl:logs": "control/docker-logs.txt", "ctl:running": "control/exec/running.txt",
    "ctl:verify": "control/exec/verify-recheck.txt", "ctl:ps": "control/exec/ps.txt", "ctl:grep": "control/exec/sentinel-grep.txt",
    "ctl:sha": "control/exec/sha256-in-container.txt", "ctl:norm": "control/exec/normalized-runtime.json", "ctl:nftver": "control/exec/nft-version.txt",
    "ctl:nft": "control/exec/nft-ruleset-stateless.txt", "ctl:iplink": "control/exec/ip-d-link.txt", "ctl:stop": "control/stop.txt",
    "ctl:inspect": "control/inspect.json", "ctl:logsfinal": "control/docker-logs-final.txt", "ctl:rm": "control/rm.txt",
    "f1b:logs": "f1b/docker-logs.txt", "f1b:inspect": "f1b/inspect.json", "f1b:rm": "f1b/rm.txt",
    "f6:logs": "f6/docker-logs.txt", "f6:inspect": "f6/inspect.json", "f6:rm": "f6/rm.txt"}


def rc_rows(run):
    """measure-rc.tsv -> list of dict rows (name, rc, path, label, seq, line). Every line must have exactly five tab-separated fields with integer rc and
    seq (a garbled table is an incomplete run); duplicates/binding problems are NOT raised here: measure_problems() reports them as criteria."""
    rows = []
    for n, l in enumerate(rd(run / "measure-rc.tsv").splitlines(), 1):
        p = l.split("\t")
        if len(p) != 5 or not re.fullmatch(r"-?\d+", p[1]) or not re.fullmatch(r"\d+", p[4]):
            raise Incomplete(f"bad line {n} in measure-rc.tsv (need name, rc, path, label, seq): {l!r}")
        rows.append({"name": p[0], "rc": int(p[1]), "path": p[2], "label": p[3], "seq": int(p[4]), "line": n})
    return rows


def rc_table(rows):
    """{name: rc}; a name that occurs more than once maps to None (never to one of its values): every `rcs.get(n) == 0` then fails closed."""
    t, dup = {}, set()
    for r in rows:
        if r["name"] in t:
            dup.add(r["name"])
        t[r["name"]] = r["rc"]
    for n in dup:
        t[n] = None
    return t


def _read(p):
    try:
        return p.read_text(errors="replace")
    except OSError:
        return None


def measure_problems(run, rows, label, completed, pins):
    """D1. -> {criterion name: [problems]}. Binding (run label, expected file of each measurement, sequence 1..n in file order), uniqueness, presence of every
    required host measurement before and after (and of every other measurement of a completed run), and contradictions between an rc and what the
    measurement wrote."""
    out = {k: [] for k in ("table", "unique", "binding", "present-before", "present-after", "contradiction", "inspect-set")}
    names = collections.Counter(r["name"] for r in rows)
    out["unique"] += [f"measurement {n!r} recorded {c} times" for n, c in sorted(names.items()) if c > 1]
    for i, r in enumerate(rows, 1):
        if r["seq"] != i:
            out["table"].append(f"line {i}: seq {r['seq']} != {i}")
        if r["label"] != label:
            out["table"].append(f"line {i}: run label {r['label']!r} != {label!r}")
    side_dirs = {s: (run / f"host-{s}").is_dir() for s in ("before", "after")}
    expected = {}
    for side in ("before", "after"):
        for base, f in HOST_FILES.items():
            expected[f"h-{side}:{base}"] = f"host-{side}/{f}"
        for k in SYSCTL_KEYS:
            expected[f"h-{side}:sysctl:{k}"] = f"host-{side}/sysctl-{k}.txt"
        ps = _read(run / f"host-{side}" / "ps-all.txt")
        ids = sorted({x.strip() for x in (ps or "").splitlines() if x.strip()})
        for i_ in ids:
            expected[f"h-{side}:inspect:{i_[:12]}"] = f"host-{side}/inspect-{i_[:12]}.txt"
        have = {r["name"] for r in rows if r["name"].startswith(f"h-{side}:inspect:")}
        want = {f"h-{side}:inspect:{i_[:12]}" for i_ in ids}
        if ps is not None:
            out["inspect-set"] += [f"{side}: container {n.rsplit(':', 1)[1]} listed by docker ps has no inspect row" for n in sorted(want - have)]
            out["inspect-set"] += [f"{side}: inspect row {n} for a container docker ps did not list" for n in sorted(have - want)]
            dothers = _read(run / f"host-{side}" / "docker-others.txt")
            ins = []
            for i_ in ids:
                t_ = _read(run / f"host-{side}" / f"inspect-{i_[:12]}.txt")
                ins += (t_ or "").splitlines()
            if dothers is None or sorted(dothers.splitlines()) != sorted(ins):
                out["inspect-set"].append(f"{side}: docker-others.txt is not the sorted concatenation of the inspect outputs")
    expected.update({n: f for n, f in FIXED_NAMES.items()})
    seen_unknown = []
    for r in rows:
        if r["name"] not in expected:
            seen_unknown.append(r["name"])
            continue
        if r["path"] != expected[r["name"]]:
            out["binding"].append(f"{r['name']}: path {r['path']!r} != {expected[r['name']]!r}")
        elif not (run / r["path"]).is_file():
            out["binding"].append(f"{r['name']}: file {r['path']} missing")
    out["unique"] += [f"unknown measurement name {n!r}" for n in sorted(set(seen_unknown))]
    # ordering: every before-row precedes every after-row
    bs = [r["seq"] for r in rows if r["name"].startswith("h-before:")]
    as_ = [r["seq"] for r in rows if r["name"].startswith("h-after:")]
    if bs and as_ and max(bs) > min(as_):
        out["table"].append("a host-before measurement was taken after a host-after one")
    # presence
    have = {r["name"] for r in rows}
    for side, key in (("before", "present-before"), ("after", "present-after")):
        if side_dirs[side] or (completed and side == "after") or side == "before" and completed:
            req = [n for n in expected if n.startswith(f"h-{side}:")]
            out[key] += [f"required host measurement missing: {n}" for n in sorted(set(req) - have)]
    if completed:
        out["present-after"] += [f"required measurement missing: {n}" for n in sorted(set(FIXED_NAMES) - have)]
    # contradictions between rc and the recorded output
    byname = {}
    for r in rows:
        byname.setdefault(r["name"], []).append(r)
    for n, rr in byname.items():
        if len(rr) != 1 or n not in expected or not (run / expected[n]).is_file():
            continue
        r = rr[0]
        o = _read(run / expected[n]) or ""
        e = _read(run / (expected[n] + ".err")) or ""
        base = n.split(":", 1)[1] if n.startswith("h-") else n
        if base == "nft":
            e = real_stderr(e)
        if r["rc"] == 0 and e.strip() and (base in ("nft", "ip-route", "ip6-route", "image-inspect", "ps-all") or base.startswith("inspect:")):
            out["contradiction"].append(f"{n}: rc 0 but stderr is not empty ({e.strip()[:60]!r})")
        if base.startswith("sysctl:") and r["rc"] == 0 and not re.fullmatch(r"\s*-?\d+\s*", o):
            out["contradiction"].append(f"{n}: rc 0 but the value is not an integer ({o.strip()[:40]!r})")
        if base.startswith("sysctl:") and r["rc"] != 0 and base.split(":", 1)[1] in CORE_SYSCTL:
            out["contradiction"].append(f"{n}: core sysctl exited {r['rc']}")
        if base == "image-inspect" and n.startswith("h-") and r["rc"] == 0 and o.strip() != pins["image_id"]:
            out["contradiction"].append(f"{n}: rc 0 but the image id is {o.strip()[:20]!r}, not the pinned one")
        if base == "pgrep" and n.startswith("h-"):
            if r["rc"] == 1 and o.strip():
                out["contradiction"].append(f"{n}: rc 1 (none) but qemu lines were recorded")
            if r["rc"] == 0 and not o.strip():
                out["contradiction"].append(f"{n}: rc 0 (found) but nothing was recorded")
        if base == "tap0" and n.startswith("h-") and r["rc"] == 0 and not o.strip():
            out["contradiction"].append(f"{n}: rc 0 but no link was recorded")
    return out


STAGES = ("start", "guards", "preflight", "control", "f1b", "f6", "host-after", "evaluating")
SIGNALS = {"INT": 2, "TERM": 15, "HUP": 1}


def final_status_problems(fs, run, pins, root):
    """D2. completed / stage / signal / abort_reason / exit code / identity must agree with each other and with this run."""
    p = []
    keys = {"completed", "stage_reached", "signal", "abort_reason", "exit_code_at_finalize", "label"}
    if not isinstance(fs, dict) or set(fs) != keys:
        return [f"final-status keys {sorted(fs) if isinstance(fs, dict) else type(fs).__name__} != {sorted(keys)}"]
    if not isinstance(fs["completed"], bool):
        p.append(f"completed is {fs['completed']!r}, not a boolean")
    if fs["stage_reached"] not in STAGES:
        p.append(f"stage_reached {fs['stage_reached']!r} is not a known stage")
    if fs["signal"] not in (None, *SIGNALS):
        p.append(f"signal {fs['signal']!r} is not INT/TERM/HUP/null")
    if fs["abort_reason"] is not None and not (isinstance(fs["abort_reason"], str) and fs["abort_reason"].strip()):
        p.append("abort_reason is neither null nor a non-empty string")
    ec = fs["exit_code_at_finalize"]
    if not isinstance(ec, int) or isinstance(ec, bool) or not 0 <= ec <= 255:
        p.append(f"exit_code_at_finalize {ec!r} is not an exit code")
        return p
    if p:
        return p
    sig, ab, comp, st = fs["signal"], fs["abort_reason"], fs["completed"], fs["stage_reached"]
    if sig is not None:
        if ec != 128 + SIGNALS[sig]:
            p.append(f"signal {sig} but exit code {ec} (expected {128 + SIGNALS[sig]})")
        if comp:
            p.append("completed with a signal")
    elif ab is not None:
        if ec != 3:
            p.append(f"abort_reason set but exit code {ec} (expected 3)")
        if comp:
            p.append("completed with an abort reason")
    elif comp:
        if st != "evaluating":
            p.append(f"completed but stage_reached is {st!r}")
        if ec != 0:
            p.append(f"completed but exit code {ec}")
    else:
        if st == "evaluating":
            p.append("not completed, no signal and no abort reason, yet the evaluation stage was reached")
        if ec == 0:
            p.append("not completed but exit code 0")
    if comp and st != "evaluating":
        p.append(f"completed but stage_reached is {st!r}")
    # identity
    label_file = (_read(run / "run-label.txt") or "").strip()
    try:
        ident = json.loads(_read(run / "run-identity.json") or "")
    except ValueError:
        ident = None
    if fs["label"] != label_file:
        p.append(f"final-status label {fs['label']!r} != run-label.txt {label_file!r}")
    if not isinstance(ident, dict):
        p.append("run-identity.json missing or unreadable")
    else:
        if ident.get("label") != label_file:
            p.append(f"run-identity label {ident.get('label')!r} != run-label.txt {label_file!r}")
        want_tree = hashlib.sha256((root / "tree/SHA256SUMS").read_bytes()).hexdigest() if (root / "tree/SHA256SUMS").exists() else None
        if ident.get("tree_manifest_sha256") != want_tree:
            p.append("run-identity tree manifest differs from the staged tree manifest")
        if ident.get("image_id") != pins.get("image_id"):
            p.append("run-identity image id differs from the pinned image id")
        if ident.get("stage") != str(root.resolve()):
            p.append(f"run-identity stage {ident.get('stage')!r} != {str(root.resolve())!r}")
        hs = _read(run / "harness-sha256.txt")
        if hs is not None and want_tree is not None and f"{want_tree}  tree/SHA256SUMS" not in hs:
            p.append("harness-sha256.txt does not bind the staged tree manifest")
    return p


def evaluate(run, pins):
    ck = Checks()
    info = {}
    net = rd(run / "network-name.txt").strip()
    label = rd(run / "run-label.txt").strip()
    exp = json.loads(res(pins["expected_ruleset"]).read_text())
    rows = rc_rows(run)
    rcs = rc_table(rows)
    fs = rj(run / "final-status.json")
    ck.add("global", "the run completed all branches: no signal, no abort, evaluator reached by the normal path", fs.get("completed") is True,
           json.dumps({k: fs.get(k) for k in ("completed", "stage_reached", "signal", "abort_reason")}))
    fsp = final_status_problems(fs, run, pins, ROOT)
    ck.add("global", "final-status is consistent (completed/stage/signal/abort_reason/exit code) and bound to this run (label, identity, tree manifest, image)", not fsp, "; ".join(fsp[:4]))
    mp = measure_problems(run, rows, label, fs.get("completed") is True, pins)
    for key, title in (("table", "measurement table: run label on every row, seq 1..n in file order, before precedes after"),
                       ("unique", "measurement table: every measurement exactly once, no unknown name"),
                       ("binding", "measurement table: every row points at the expected file of that measurement and the file exists"),
                       ("present-before", "host measurements: every required one present BEFORE (and every inspect of a listed container)"),
                       ("present-after", "host measurements: every required one present AFTER and every other required measurement of a completed run"),
                       ("contradiction", "measurement table: no contradiction between an rc and what the measurement wrote"),
                       ("inspect-set", "host measurements: the inspect rows are exactly the containers docker ps listed, before and after")):
        ck.add("global", title, not mp[key], "; ".join(mp[key][:4]))
    info["derived_item_index_for_a_rule_appended_to_input"] = derived_item_index(exp["tables"])
    runsh = res(pins["sources"]["run.sh"]["path"]).read_text().splitlines()
    nft_line = next(i + 1 for i, l in enumerate(runsh) if l.startswith("nft -f "))
    info["pinned_run_sh_nft_line"] = nft_line

    # ------------------------------------------------------------------ preflight (what is resolvable in each PATH, which bytes the image holds)
    pre = run / "preflight"
    resolve = rd(pre / "resolve-nonft-path.txt")
    ck.add("preflight", "nft is NOT resolvable in the restricted PATH, ip and python3 are", "nft=NONE" in resolve and re.search(r"ip=/\S+", resolve) and re.search(r"python3=/\S+", resolve), resolve.strip()[:200])
    resolve_def = rd(pre / "resolve-default-path.txt")
    ck.add("preflight", "nft IS resolvable in the image's default PATH (the restricted PATH is the only difference)", re.search(r"nft=/\S+", resolve_def) is not None, resolve_def.strip()[:200])
    inimg = {}
    for l in rd(pre / "sha256-in-image.txt").splitlines():
        h, _, f = l.partition("  ")
        inimg[f.strip().lstrip("/").removeprefix("app/")] = h
    for rel, meta in pins["sources"].items():
        if rel == "isolation/__init__.py":
            continue
        ck.add("preflight", f"image holds the pinned bytes of {rel}", inimg.get(rel) == meta["sha256"], f"{inimg.get(rel)}")
    ck.add("preflight", "nft -c (check only) accepts guest-f6.nft with the pinned load.nft", rd(pre / "f6-nft-check.rc").strip() == "0", rd(pre / "f6-nft-check.txt")[:200])
    ck.add("preflight", "guest-f6.nft bytes at run time equal the pin", sha(rd(pathlib.Path(rd(run / 'f6-guest-path.txt').strip()), binary=True)) == pins["guest_f6_sha256"])
    for n in ("pre:resolve-default", "pre:resolve-nonft", "pre:sha", "pre:nftc"):
        ck.add("preflight", f"measurement {n} exited 0", rcs.get(n) == 0, f"rc={rcs.get(n)}")
    info["f1b_scope"] = ("nft does not RESOLVE through the restricted PATH of the entrypoint; the file in the image is still there (default-PATH resolution is recorded in "
                         "preflight/resolve-default-path.txt). This is not evidence of an image without the nft executable.")

    # ------------------------------------------------------------------ control
    d = run / CTRL
    insp, binds, env = case_common(ck, CTRL, d, pins, net, label)
    st_run = rj(d / "state-before-stop.json")
    ck.add(CTRL, "control was running (sentinel poller keeps it alive) with 0 restarts", st_run.get("Status") == "running" and st_run.get("ExitCode") == 0 and st_run.get("RestartCount", 0) == 0, json.dumps(st_run))
    ck.add(CTRL, "no PATH override and no guest.nft mount in the control", not any(e.startswith("PATH=/ct01") for e in env) and "/app/isolation/guest.nft" not in binds)
    log = merged_log(d)
    okl = [i for i, l in enumerate(log) if strip_ts(l).strip() == OK_LINE]
    ck.add(CTRL, "exactly one V0 OK line, no ISOLATION FAIL", len(okl) == 1 and not any("ISOLATION FAIL" in l for l in log))
    # R6: the poller/server markers are written without a newline (R5 evidence: both in ONE log line), so they are counted as markers, not as lines
    marks = [(i, m) for i, l in enumerate(log) for m in ("SENTINEL poller.py called", "SENTINEL server.py called") for _ in range(l.count(m))]
    n_sentinel = sum(l.count("SENTINEL") for l in log)
    ck.add(CTRL, "both sentinels logged (each exactly once, nothing else named SENTINEL) after the V0 OK line",
           sorted(m for _, m in marks) == ["SENTINEL poller.py called", "SENTINEL server.py called"] and n_sentinel == 2 and bool(okl) and all(i > okl[0] for i, _ in marks),
           f"ok@{okl} markers@{marks} SENTINEL occurrences {n_sentinel}")
    ck.add(CTRL, "sentinel markers server-called and poller-called exist", file_set(d / "sentinel") == ["poller-called", "server-called"], str(file_set(d / "sentinel")))
    ex = d / "exec"
    for n in ("ctl:state", "ctl:logs", "ctl:running", "ctl:ps", "ctl:sha", "ctl:norm", "ctl:nftver", "ctl:nft", "ctl:iplink", "ctl:stop", "ctl:inspect", "ctl:logsfinal", "ctl:rm"):
        ck.add(CTRL, f"measurement {n} exited 0", rcs.get(n) == 0, f"rc={rcs.get(n)}")
    ck.add(CTRL, "read-only recheck: verify exit 0", rd(ex / "verify-recheck.rc").strip() == "0" and rcs.get("ctl:verify") == 0)
    ps = rd(ex / "ps.txt")
    ck.add(CTRL, "no qemu/tshark process in the container", not re.search(r"qemu-system|tshark", ps), "")
    ck.add(CTRL, "/app/poller.py and /app/server.py in the container are the sentinels", rd(ex / "sentinel-grep.rc").strip() == "0")
    csums = {}
    for l in rd(ex / "sha256-in-container.txt").splitlines():
        h, _, f = l.partition("  ")
        csums[f.strip().removeprefix("/app/")] = h
    for rel, meta in pins["sources"].items():
        if rel == "isolation/__init__.py":
            continue
        ck.add(CTRL, f"running container holds the pinned bytes of {rel}", csums.get(rel) == meta["sha256"], csums.get(rel, ""))
    try:
        norm = json.loads(rd(ex / "normalized-runtime.json"))
        ck.add(CTRL, "REAL kernel ruleset (nft -j through verify --dump-normalized) equals the pinned expected ruleset", norm == exp, "")
    except ValueError:
        ck.add(CTRL, "REAL kernel ruleset equals the pinned expected ruleset", False, "normalized-runtime.json unreadable")

    # ------------------------------------------------------------------ F1b
    d = run / F1B
    insp, binds, env = case_common(ck, F1B, d, pins, net, label)
    st = insp["State"]
    ec = rd(d / "exit-code.txt").strip()
    ck.add(F1B, "the wait for the container did not time out and its exit code equals the inspected one", ec == "exit code: 127" and rd(d / "wait.rc").strip() == "0", ec)
    for n in ("f1b:logs", "f1b:inspect", "f1b:rm"):
        ck.add(F1B, f"measurement {n} exited 0", rcs.get(n) == 0, f"rc={rcs.get(n)}")
    ck.add(F1B, "exited with exit code 127, not OOM-killed", st.get("Status") == "exited" and st.get("ExitCode") == 127 and not st.get("OOMKilled"), f"{st.get('Status')} {st.get('ExitCode')}")
    ck.add(F1B, "restricted PATH is the only environment difference (PATH=/ct01-path, mounted read-only)", "PATH=/ct01-path" in env and any(b.endswith("/ct01-path:ro") or b.endswith(":/ct01-path:ro") for b in (insp["HostConfig"].get("Binds") or [])))
    log = [strip_ts(l) for l in merged_log(d)]
    m = [re.search(r"run\.sh: line (\d+): nft: command not found", l) for l in log]
    m = [x for x in m if x]
    ck.add(F1B, "original bash message 'nft: command not found' at the pinned line of `nft -f`", len(m) == 1 and int(m[0].group(1)) == nft_line, f"{[x.group(0) for x in m]} expected line {nft_line}")
    ck.add(F1B, "stopped after the first sysctl report: no 'after run.sh' report, no V0 line, no SENTINEL",
           any("SYSCTL REPORT (before run.sh)" in l for l in log) and not any(("SYSCTL REPORT (after run.sh)" in l) or ("ISOLATION " in l) or ("SENTINEL" in l) for l in log))
    ck.add(F1B, "sentinel marker directory empty (0 server, 0 poller)", file_set(d / "sentinel") == [], str(file_set(d / "sentinel")))

    # ------------------------------------------------------------------ F6
    d = run / F6
    insp, binds, env = case_common(ck, F6, d, pins, net, label)
    st = insp["State"]
    ec = rd(d / "exit-code.txt").strip()
    ck.add(F6, "the wait for the container did not time out and its exit code equals the inspected one", ec == "exit code: 1" and rd(d / "wait.rc").strip() == "0", ec)
    for n in ("f6:logs", "f6:inspect", "f6:rm"):
        ck.add(F6, f"measurement {n} exited 0", rcs.get(n) == 0, f"rc={rcs.get(n)}")
    ck.add(F6, "exited with exit code 1, not OOM-killed", st.get("Status") == "exited" and st.get("ExitCode") == 1 and not st.get("OOMKilled"), f"{st.get('Status')} {st.get('ExitCode')}")
    g = binds.get("/app/isolation/guest.nft", "")
    ck.add(F6, "guest-f6.nft mounted read-only over /app/isolation/guest.nft; load.nft untouched", g.endswith(":ro") and "/app/isolation/load.nft" not in binds and "guest-f6.nft" in g, g)
    ck.add(F6, "no PATH override in F6", not any(e.startswith("PATH=/ct01") for e in env))
    raw = [strip_ts(l) for l in merged_log(d)]
    ck.add(F6, "nft -f accepted the file (no nft Error: line), V0 reached (after-run.sh report present)", not any(l.startswith("Error:") or "/app/isolation/" in l and "Error" in l for l in raw) and any("SYSCTL REPORT (after run.sh)" in l for l in raw))
    fails = [l for l in raw if l.startswith("ISOLATION FAIL")]
    ck.add(F6, "exactly one ISOLATION FAIL line and no ISOLATION OK", len(fails) == 1 and not any(l.strip() == OK_LINE for l in raw), f"{len(fails)} fail lines")
    dm = DIFF_RE.match(fails[0]) if fails else None
    ck.add(F6, "the line is a structural diff of table inet sandbox_guest with item/expected/actual", dm is not None, fails[0][:160] if fails else "")
    actual = None
    if dm:
        try:
            actual = json.loads(dm.group(3))
            exp_item = json.loads(dm.group(2))
        except ValueError:
            actual, exp_item = None, None
        want_rule = {"chain": "input", "family": "inet", "table": "sandbox_guest",
                     "expr": [{"match": {"left": {"payload": {"field": "saddr", "protocol": "ip"}}, "op": "==", "right": "203.0.113.250"}}, {"accept": None}]}
        ok_rule = actual == {"rule": want_rule}          # the WHOLE rule: chain, family, table, field, protocol, op, right, order of expressions, verdict
        items = exp["tables"]["inet sandbox_guest"]
        idx = int(dm.group(1))
        ok_exp = 0 <= idx < len(items) and exp_item == items[idx]     # the "expected" side equals the pinned expected item at that index
        ck.add(F6, "the diff's expected item equals the pinned expected ruleset item at the reported index", ok_exp, f"index {idx}")
        ck.add(F6, "actual JSON is exactly the F6 fixture rule `ip saddr 203.0.113.250 accept` in chain input (field/protocol/op/right/order/verdict)", ok_rule, json.dumps(actual)[:200])
        info["f6_reported_item"] = int(dm.group(1))
        info["f6_item_equals_derived_information_only"] = int(dm.group(1)) == info["derived_item_index_for_a_rule_appended_to_input"]
        (run / "f6-v0-diff.json").write_text(json.dumps({"item": int(dm.group(1)), "expected": exp_item, "actual": actual, "line": fails[0]}, indent=2) + "\n")
        ck.add(F6, "diff JSON retained next to the raw log (f6-v0-diff.json)", (run / "f6-v0-diff.json").exists())
    else:
        ck.add(F6, "actual JSON is exactly the F6 fixture rule", False, "no diff line")
        ck.add(F6, "the diff's expected item equals the pinned expected ruleset item at the reported index", False, "no diff line")
        ck.add(F6, "diff JSON retained next to the raw log (f6-v0-diff.json)", False, "no diff line")
    ck.add(F6, "sentinel marker directory empty (0 server, 0 poller); no SENTINEL in the log", file_set(d / "sentinel") == [] and not any("SENTINEL" in l for l in raw), str(file_set(d / "sentinel")))

    # ------------------------------------------------------------------ global: events, commands, host, cleanup
    evs = [json.loads(l) for l in rd(run / "events.jsonl").splitlines() if l.strip()]
    by = {}
    for e in evs:
        if e.get("Type", "container") != "container":
            continue
        by.setdefault(e.get("id") or e.get("Actor", {}).get("ID"), []).append(e)
    ids = {c: rd(run / c / "container-id.txt").strip() for c in (CTRL, F1B, F6)}
    for c, i in ids.items():
        seq = [(x.get("status") or x.get("Action")) for x in by.get(i, [])]
        dies = [x for x in by.get(i, []) if (x.get("status") or x.get("Action")) == "die"]
        code = (dies[0].get("Actor", {}).get("Attributes", {}).get("exitCode") if dies else None)
        want = {F1B: {"127"}, F6: {"1"}, CTRL: {"0", "137"}}[c]
        ck.add("global", f"{c}: docker events show one start, one die (exit code {sorted(want)}), no restart/oom", "start" in seq and seq.count("start") == 1 and len(dies) == 1 and code in want and not {"restart", "oom"} & set(seq), f"{seq} exitCode={code}")
    cmds = rd(run / "docker-commands.log").splitlines()
    sub = [c.split()[0] for c in cmds if c.strip()]
    ck.add("global", "only allow-listed docker sub-commands (no build/pull/commit/tag/network create/compose/cp/kill/prune/rmi)", set(sub) <= ALLOWED_DOCKER, str(sorted(set(sub) - ALLOWED_DOCKER)))
    names = {"ct01-v0rt-control", "ct01-v0rt-f1b", "ct01-v0rt-f6"}
    allowed_t = set(ids.values()) | names
    bad_t = []
    for c in cmds:
        w = c.split()
        if w and w[0] in ("exec", "stop", "rm", "wait", "logs"):
            cand = [t for t in w[1:] if re.fullmatch(r"[0-9a-f]{64}|ct01-v0rt-\w+", t)]
            if not cand or not set(cand) <= allowed_t:
                bad_t.append(c[:80])
    ck.add("global", "exec/stop/rm/wait/logs only ever target containers created by this run", not bad_t, str(bad_t[:3]))
    ck.add("global", "no `docker run` used --network host or --publish", not any(c.startswith("run ") and re.search(r"--network[= ]host|--net[= ]host|\s-p\s|--publish", c) for c in cmds))
    OPT = ("iptables", "tap0")                    # tools/devices that may legitimately fail: the exit code must still be the same before and after
    for side in ("before", "after"):
        names = [n for n in rcs if n.startswith(f"h-{side}:")]
        ck.add("global", f"host measurements ({side}) were taken: {len(names)} entries incl. nft, ip route, sysctl, ss, pgrep, docker ps", len(names) >= 14, str(len(names)))
    for base in sorted({n.split(":", 1)[1] for n in rcs if n.startswith("h-before:")}):
        b0, a0 = rcs.get(f"h-before:{base}"), rcs.get(f"h-after:{base}")
        required_ok = b0 == 0 and a0 == 0
        if base in OPT or (base.startswith("sysctl:") and ".ens33." in base):
            ok, why = b0 is not None and b0 == a0, f"optional measurement; rc before={b0} after={a0}"
        elif base == "pgrep":
            ok, why = b0 in (0, 1) and a0 in (0, 1), f"pgrep rc before={b0} after={a0} (0 found, 1 none, anything else is an error)"
        elif base.startswith("inspect:"):
            ok, why = required_ok, f"rc before={b0} after={a0}"
        else:
            ok, why = required_ok, f"rc before={b0} after={a0}"
        ck.add("global", f"host measurement {base}: exit code usable", ok, why)
    ids_b = {n for n in rcs if n.startswith("h-before:inspect:")}
    ids_a = {n.replace("h-after:", "h-before:") for n in rcs if n.startswith("h-after:inspect:")}
    ck.add("global", "the set of other containers measured before equals the set measured after", ids_b == ids_a, f"{len(ids_b)} vs {len(ids_a)}")
    for f in ("nft-ruleset-stateless.txt", "sysctl.txt", "ip-route.txt", "ip6-route.txt", "qemu.txt", "listen-tcp.txt", "docker-others.txt", "image-id.txt", "image-ls.txt", "iptables-save.txt"):
        a, b = run / "host-before" / f, run / "host-after" / f
        # R6: iptables-save also carries live packet/byte counters of the chain policies (`:PREROUTING ACCEPT [pkts:bytes]`): traffic, not configuration
        strip = (lambda t: "\n".join(re.sub(r"\[\d+:\d+\]", "[0:0]", l) for l in t.splitlines() if not l.startswith("#"))) if f == "iptables-save.txt" else (lambda t: t)
        ck.add("global", f"host {f} unchanged", strip(rd(a)) == strip(rd(b)))
    for f in ("nft-ruleset-stateless.txt", "ip-route.txt", "ip6-route.txt", "image-id.txt"):
        er = real_stderr if f == "nft-ruleset-stateless.txt" else (lambda t: t.strip())
        ck.add("global", f"host {f}: no error text on stderr", er(rd(run / "host-before" / (f + ".err"))) == "" and er(rd(run / "host-after" / (f + ".err"))) == "")
    ck.add("global", "no qemu-system on the host before/after", rd(run / "host-before/qemu.txt").strip() == "" and rd(run / "host-after/qemu.txt").strip() == "")
    clog = [l for l in rd(run / "cleanup.log").splitlines() if l.strip()]
    cerr = rd(run / "cleanup.err").strip() if (run / "cleanup.err").exists() else ""
    ck.add("global", "cleanup: every rm/ps of the finalizer returned 0 and wrote nothing on stderr", all(l.endswith("rc=0") for l in clog) and cerr == "", f"{clog[:4]} {cerr[:80]}")
    ck.add("global", "no container had to be reaped by label (every created container was removed by its own branch)", not any("rm-by-" in l for l in rd(run / "cleanup.log").splitlines()))
    left = rd(run / "leftover-containers.txt").strip()
    ck.add("global", "no container created by this run is left (docker ps -a --filter label; the query itself exited 0)", left == "" and rd(run / "leftover-containers.rc").strip() == "0", left[:200])
    tb, ta = rd(run / "host-before/host-tap0.txt") + rd(run / "host-before/host-tap0.txt.err"), rd(run / "host-after/host-tap0.txt") + rd(run / "host-after/host-tap0.txt.err")
    ck.add("global", "host tap0 state identical before/after and no tap0 link listed after", tb == ta and not re.search(r"^\d+: tap0", ta, re.M), ta.strip()[:120])
    return ck, info


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    global ROOT
    run, pins = pathlib.Path(argv[0]), json.loads(pathlib.Path(argv[1]).read_text())
    ROOT = pathlib.Path(argv[argv.index("--root") + 1]) if "--root" in argv else run.parent
    try:
        ck, info = evaluate(run, pins)
    except Incomplete as e:
        print("INCOMPLETE:", e)
        fs = {}
        try:
            fs = json.loads((run / "final-status.json").read_text())
        except (OSError, ValueError):
            pass
        path = argv[argv.index("--out") + 1] if "--out" in argv else str(run / "verdicts.json")
        pathlib.Path(path).write_text(json.dumps({"all_ok": False, "incomplete": True, "reason": str(e), "final_status": fs,
                                                  "statement": "Incomplete/interrupted run: no criterion is claimed to hold."}, indent=2) + "\n")
        return 2
    out = {"all_ok": ck.all_ok(), "info": info, "checks": ck.rows,
           "statement": "Runtime evidence for F1b/F6 under the stated method only (restricted PATH / mounted guest.nft, real kernel + real nft + real image bytes, "
                        "sentinel server/poller, no guest). F1b means: nft does not resolve through the restricted PATH (the file is still in the image); container state/exit codes "
                        "are not evidence of the manager /status endpoint. Not CT-01 PASS; V1, restart, task flows not covered."}
    path = argv[argv.index("--out") + 1] if "--out" in argv else str(run / "verdicts.json")
    pathlib.Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    for r in ck.rows:
        print(("PASS " if r["ok"] else "FAIL ") + f"[{r['case']}] {r['check']}" + ("" if r["ok"] or not r["detail"] else f"  -> {r['detail']}"))
    print("V0-RUNTIME:", "ALL CRITERIA HELD" if ck.all_ok() else "CRITERIA NOT MET", "| info:", json.dumps(info))
    return 0 if ck.all_ok() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
