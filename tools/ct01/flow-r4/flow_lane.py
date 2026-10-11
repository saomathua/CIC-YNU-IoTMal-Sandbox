#!/usr/bin/env python3
"""CT-01 REAL task-flow lane R2 (T01/T02-runtime, T18, T19; F3/F4 fault modes; F5 Compose restart). Stdlib only. The runner is a thin driver: every observation is written to the run
directory as raw files; the verdict is computed OFFLINE by evaluate_flow.py. Nothing here decides PASS.

    flow_lane.py <mode> <run_dir> <label> <image_id> <fixtures_dir> [<manifest_literal>]        mode: success | f3 | f4 | f5

Starts ONE worker container from the pinned image with the REAL entrypoint (run.sh -> V0 -> server.py + poller.py) on the existing sandboxnet at 192.168.60.2,
labelled ct01-flow=<label>; submits the harmless fixture(s) to the EXISTING manager through its public API (/submit-file); waits for the task status; copies the
result from the manager; saves logs; removes the labelled container. The manager, MongoDB and compose files are not modified, restarted or stopped.
R2 (review of 2026-10-11): identity.json pins the stage tree (manifest, runner, evaluator, pins, export helper) and the literal the entry was reviewed with;
the isolation-verifier samples carry start/end times, the task status and the QEMU process set seen in the worker at both ends. Mode f5 restarts the REAL Compose
service sandbox-worker-1 (`docker compose restart`), created by this lane with `up --no-deps --no-build --pull never`; the manager and MongoDB containers are
only read (inspect) and must be unchanged. Nothing here decides PASS.
Environment (tests only): CT01_FLOW_DOCKER (docker CLI), CT01_FLOW_MANAGER_URL, CT01_FLOW_PROC_ROOT, CT01_FLOW_COMPOSE_FILE."""
import datetime, hashlib, http.client, json, os, pathlib, re, signal, subprocess, sys, threading, time, urllib.request, urllib.error, uuid

DOCKER = os.environ.get("CT01_FLOW_DOCKER", "/usr/bin/docker")
MGR_URL = os.environ.get("CT01_FLOW_MANAGER_URL", "http://127.0.0.1:8011/api/v1/sandbox-manager")
MANAGER = "cic-ynu-iotmal-sandbox-sandbox-manager-1"
NET = "cic-ynu-iotmal-sandbox_sandboxnet"
WORKER_NAME = "ct01-flow-worker"
WORKER_IP = "192.168.60.2"
V0_WAIT_S = int(os.environ.get("CT01_FLOW_V0_WAIT_S", "90"))
TASK_WAIT_S = int(os.environ.get("CT01_FLOW_TASK_WAIT_S", "900"))
FAULT_WAIT_S = int(os.environ.get("CT01_FLOW_FAULT_WAIT_S", "400"))
HERE = pathlib.Path(__file__).resolve().parent
PROC_ROOT = os.environ.get("CT01_FLOW_PROC_ROOT", "/proc")
PINS = json.loads((HERE / "pins.json").read_text())
COMPOSE = PINS.get("compose", {})
COMPOSE_FILE = os.environ.get("CT01_FLOW_COMPOSE_FILE", COMPOSE.get("file", ""))
MONGO = COMPOSE.get("mongo_container", "mongo-db")

OUT = None
LABEL = None
STATE = {"worker": None, "signal": None, "phase": "start", "wref": WORKER_NAME, "f5_id": None}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def log(msg):
    line = f"{now()} {msg}"
    print(line, flush=True)
    if OUT:
        with open(OUT / "lane.log", "a") as f:
            f.write(line + "\n")


def sh(name, argv, timeout=60, check_to_file=True):
    """Run argv; write <name>.txt (stdout), <name>.err, <name>.rc. Never raises; returns (rc, stdout)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = 124, (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "TIMEOUT"
    except OSError as e:
        rc, out, err = 127, "", f"{type(e).__name__}: {e}"
    if check_to_file:
        d = OUT / name
        d.parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(str(d) + ".txt").write_text(out)
        pathlib.Path(str(d) + ".err").write_text(err)
        pathlib.Path(str(d) + ".rc").write_text(f"{rc}\n")
    return rc, out


ROOT_URL = MGR_URL.split("/api/")[0]       # /healthcheck is mounted at the ROOT of manager and worker (R1 run 20261011T030352Z: 404 under the API prefix)


def http(method, path, body=None, headers=None, timeout=20):
    base = ROOT_URL if path == "/healthcheck" else MGR_URL
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                       # noqa: BLE001
        return None, f"{type(e).__name__}: {e}".encode()


def multipart(filename, data):
    b = "ct01flow" + uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
        + data + f"\r\n--{b}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={b}"}


def host_snapshot(tag):
    d = f"host-{tag}"
    for n, argv in (("nft", ["nft", "-s", "list", "ruleset"]), ("ip-route", ["ip", "route", "show", "table", "all"]), ("ip-addr", ["ip", "-4", "-o", "addr"]),
                    ("qemu", ["pgrep", "-a", "qemu-system"]), ("capture", ["pgrep", "-af", "tshark|tcpdump|dumpcap"]),
                    ("docker-ps", [DOCKER, "ps", "-a", "--no-trunc", "--format", "{{.Names}} {{.ID}} {{.Status}}"]),
                    ("sysctl-forward", ["sysctl", "-n", "net.ipv4.ip_forward"])):
        sh(f"{d}/{n}", argv, 30)


def mgr_snapshot(tag):
    for n, p in (("status", "/status"), ("tasks", "/tasks"), ("health", "/healthcheck")):
        code, body = http("GET", p)
        (OUT / f"manager-{tag}-{n}.json").write_text(json.dumps({"http": code, "body": body.decode(errors="replace")}))


def worker_logs(name):
    sh(name, [DOCKER, "logs", "--timestamps", STATE["wref"]], 60)


def cleanup():
    """Label-based: whatever carries ct01-flow=<label> is removed; the result is recorded (never silently ignored)."""
    rc, out = sh("cleanup-ps", [DOCKER, "ps", "-aq", "--filter", f"label=ct01-flow={LABEL}"], 30)
    ids = out.split() if rc == 0 else []
    for i in ids:
        sh(f"cleanup-rm-{i[:12]}", [DOCKER, "rm", "-f", i], 60)
    rc2, out2 = sh("cleanup-ps-after", [DOCKER, "ps", "-aq", "--filter", f"label=ct01-flow={LABEL}"], 30)
    (OUT / "cleanup.json").write_text(json.dumps({"labelled_before": ids, "ps_rc": rc, "labelled_after": out2.split(), "ps_after_rc": rc2}))


def cleanup_f5():
    """The compose worker is removed by its EXACT container id, and only after its Compose project/service labels were read back from `docker inspect`
    (never by name pattern, never `compose down`). Afterwards the project/service label query must be empty. Recorded in cleanup.json."""
    rec = {"id": STATE.get("f5_id"), "labels_ok": None, "rm_rc": None, "ps_rc": None, "labelled_after": None}
    wid = STATE.get("f5_id")
    if not wid:
        rc, ids = compose_ids()
        rec.update(ps_rc=rc, labelled_after=ids, labelled_before=ids)
        (OUT / "cleanup.json").write_text(json.dumps(rec))
        if ids:
            raise_after = f"containers exist for the project/service but no id was recorded: {ids}"
            (OUT / "cleanup-note.txt").write_text(raise_after + "\n")
        return
    ins = inspect_to("f5-cleanup-inspect", wid) or {}
    labels = (ins.get("Config") or {}).get("Labels") or {}
    rec["labels_ok"] = (labels.get("com.docker.compose.project") == COMPOSE["project"] and labels.get("com.docker.compose.service") == COMPOSE["service"]
                        and ins.get("Id") == wid)
    if rec["labels_ok"]:
        rc, _ = sh("f5-cleanup-rm", [DOCKER, "rm", "-f", wid], 120)
        rec["rm_rc"] = rc
    rc, ids = compose_ids()
    rec.update(ps_rc=rc, labelled_after=ids)
    (OUT / "cleanup.json").write_text(json.dumps(rec))


def on_signal(signum, _f):
    STATE["signal"] = signum
    raise KeyboardInterrupt(f"signal {signum}")


def logs_text():
    """`docker logs` of the worker, stdout AND stderr merged (the worker's python logging goes to stderr: R1 run 20261011T030551Z found every
    pattern wait empty because only stdout was read). -> (rc, text)"""
    try:
        p = subprocess.run([DOCKER, "logs", "--timestamps", STATE["wref"]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        return p.returncode, p.stdout
    except Exception as e:                                       # noqa: BLE001
        return 127, f"{type(e).__name__}: {e}"


def wait_log(pattern, timeout, poll=1):
    pat = re.compile(pattern)
    t_end = time.time() + timeout
    while time.time() < t_end:
        rc, out = logs_text()
        if rc == 0 and pat.search(out):
            return True
        time.sleep(poll)
    return False


def start_worker(image):
    argv = [DOCKER, "run", "-d", "--name", WORKER_NAME, "--label", f"ct01-flow={LABEL}", "--privileged", "--restart", "no", "--network", NET, "--ip", WORKER_IP,
            "-e", "PORT=8011", "-e", "APP_BASE_URL=/api/v1/sandbox-worker", "-e", "APP_NAME=ct01-flow-worker",
            "-e", "SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager", "-e", "ANALYSIS_DURATION=30", "-e", "POST_ANALYSIS_WAIT=30",
            "-e", "ALLOW_VM_INTERNET=false", image]
    rc, out = sh("worker-run", argv, 120)
    STATE["worker"] = out.strip() if rc == 0 else None
    return rc == 0


def bind_ctx(task_id):
    """What can be said about the task and the QEMU process set at this instant: the manager's status of the task and `pgrep -a qemu-system` INSIDE the
    worker container (QEMU runs in the worker's namespaces). Never raises."""
    t = time.time()
    try:
        rc, out = _run([DOCKER, "exec", STATE["wref"], "pgrep", "-a", "qemu-system"], 20)
    except Exception as e:                                       # noqa: BLE001
        rc, out = 127, f"{type(e).__name__}: {e}"
    code, body = http("GET", "/tasks")
    st = None
    if code == 200:
        try:
            for x in json.loads(body)["tasks"]:
                if x["task_id"] == task_id:
                    st = x.get("status")
        except Exception:                                        # noqa: BLE001
            pass
    return {"t": t, "qemu_rc": rc, "qemu": out.strip(), "task_status": st, "tasks_http": code}


def _run(argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError as e:
        return 127, f"{type(e).__name__}: {e}"


def sample_isolation(arch, index, stop, task_id):
    """Positive isolation evidence DURING the task (the worker logs only V-failures, never a V1/V2 success): the worker's own read-only verifier
    (`python3 -m isolation.verify`, the same code run.sh/V0 uses) is run in the worker container when phase 1 is running and when phase 2 is uploading.
    R2: each sample is bound to the task and to the QEMU process set: <name>.json carries the log trigger, the verifier's own start/end, and the task
    status / QEMU pgrep taken immediately before and after it. The claim is still 'verifier rc 0 at a checkpoint of this task', not a timing proof."""
    for tag, pat in (("p1-running", r"Got the executable inside QEMU"), ("p2-uploading", r"Uploading strace\.\.\.")):
        t_end = time.time() + TASK_WAIT_S
        seen = None
        while time.time() < t_end and not stop.is_set():
            rc, out = logs_text()
            if rc == 0 and len(re.findall(pat, out)) >= index + 1:
                hits = [l for l in out.splitlines() if re.search(pat, l)]
                seen = {"t": time.time(), "line": hits[index] if index < len(hits) else hits[-1], "count": len(hits)}
                break
            time.sleep(1)
        if seen is None:
            (OUT / f"verify-{arch}-{tag}.skipped").write_text("pattern not seen before the task ended\n")
            continue
        argv = [DOCKER, "exec", STATE["wref"], "python3", "-m", "isolation.verify", "--phase", f"ct01-flow {arch} {tag}"]
        b0 = bind_ctx(task_id)
        t0 = time.time()
        sh(f"verify-{arch}-{tag}", argv, 60)
        t1 = time.time()
        b1 = bind_ctx(task_id)
        (OUT / f"verify-{arch}-{tag}.json").write_text(json.dumps(
            {"schema": "ct01-flow-verify-sample/1", "arch": arch, "tag": tag, "task_id": task_id, "container": STATE["wref"], "trigger": seen,
             "argv": argv, "t_start": t0, "t_end": t1, "before": b0, "after": b1}, indent=1))


def submit(arch, fixtures):
    data = (pathlib.Path(fixtures) / f"busybox-{arch}").read_bytes()
    fname = f"ct01-flow-{LABEL}-{arch}.elf"
    body, hdr = multipart(fname, data)
    t0 = time.time()
    code, resp = http("POST", "/submit-file", body, hdr, timeout=60)
    rec = {"arch": arch, "filename": fname, "http": code, "response": resp.decode(errors="replace"), "t": t0, "bytes": len(data)}
    try:
        rec["task_id"] = json.loads(resp)["task_id"]
    except Exception:                                            # noqa: BLE001
        rec["task_id"] = None
    (OUT / f"submit-{arch}.json").write_text(json.dumps(rec))
    return rec


def poll_task(rec, timeout, stop_on=("COMPLETED", "FAILED", "CANCELLED")):
    t_end = time.time() + timeout
    fh = open(OUT / f"poll-{rec['arch']}.jsonl", "a")
    last = None
    while time.time() < t_end:
        code, body = http("GET", "/tasks")
        st = None
        if code == 200:
            try:
                for t in json.loads(body)["tasks"]:
                    if t["task_id"] == rec["task_id"]:
                        st = t
            except Exception:                                    # noqa: BLE001
                pass
        row = {"t": time.time(), "http": code, "task": st}
        fh.write(json.dumps(row) + "\n"); fh.flush()
        last = st
        if st and st.get("status") in stop_on:
            fh.close()
            return st
        time.sleep(3)
    fh.close()
    return last


def fetch_result(rec):
    sh(f"result-{rec['arch']}-cp", [DOCKER, "cp", f"{MANAGER}:/app/output/{rec['task_id']}.zip", str(OUT / f"result-{rec['arch']}.zip")], 120)


def exit_code(h):
    return 0 if h["completed"] else (128 + (h["signal"] or 0) if h["signal"] else 3)


def finish(h):
    return exit_code(h)


def compose(*args):
    return [DOCKER, "compose", "-p", COMPOSE["project"], "-f", COMPOSE_FILE, "--project-directory", str(pathlib.Path(COMPOSE_FILE).parent)] + list(args)


def compose_ids():
    """IDs of every container (running or not) carrying the pinned Compose project AND service labels: the F5 target set. -> (rc, [ids])"""
    rc, out = sh("f5-ps-" + str(STATE.setdefault("f5_n", 0)), [DOCKER, "ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={COMPOSE['project']}",
                                                               "--filter", f"label=com.docker.compose.service={COMPOSE['service']}"], 30)
    STATE["f5_n"] += 1
    return rc, (out.split() if rc == 0 else [])


def inspect_to(name, ref):
    rc, out = sh(name, [DOCKER, "inspect", ref], 30)
    try:
        return json.loads(out)[0] if rc == 0 else None
    except Exception:                                            # noqa: BLE001
        return None


def netns_of(pid):
    try:
        return os.readlink(f"{PROC_ROOT}/{pid}/ns/net")
    except OSError as e:
        return f"ERROR {type(e).__name__}: {e}"


def f5_state(tag):
    """One before/after observation of the compose worker: container identity, start time, PID, network namespace (inode string), the isolation table, tap0, the
    isolation verifier, and the manager -> worker healthcheck. Raw command files + <tag>.json."""
    wid = STATE["wref"]
    ins = inspect_to(f"f5-{tag}-inspect", wid) or {}
    st = ins.get("State", {})
    pid = st.get("Pid")
    sh(f"f5-{tag}-nft-table", [DOCKER, "exec", wid, "nft", "list", "table", "inet", "sandbox_guest"], 30)
    sh(f"f5-{tag}-tap0", [DOCKER, "exec", wid, "ip", "-o", "link", "show", "tap0"], 30)
    sh(f"f5-{tag}-verify", [DOCKER, "exec", wid, "python3", "-m", "isolation.verify", "--phase", f"ct01-flow f5 {tag}"], 60)
    sh(f"f5-{tag}-health",
       [DOCKER, "exec", MANAGER, "python3", "-c",
        "import urllib.request,time;t=time.time();r=urllib.request.urlopen('http://%s:8011/healthcheck',timeout=5);print(r.status, round(time.time()-t,3))" % WORKER_IP], 30)
    rec = {"tag": tag, "t": time.time(), "id": ins.get("Id"), "name": (ins.get("Name") or "").lstrip("/"), "image": ins.get("Image"),
           "started_at": st.get("StartedAt"), "running": st.get("Running"), "pid": pid, "restart_count": ins.get("RestartCount"),
           "netns": netns_of(pid) if isinstance(pid, int) and pid > 0 else None,
           "labels": {k: v for k, v in (ins.get("Config", {}).get("Labels") or {}).items() if k.startswith("com.docker.compose.")},
           "networks": {n: (v or {}).get("IPAddress") for n, v in (ins.get("NetworkSettings", {}).get("Networks") or {}).items()}}
    (OUT / f"f5-{tag}.json").write_text(json.dumps(rec, indent=1))
    return rec


def others_snapshot(tag):
    """manager and MongoDB containers are only READ: identity, start time, running flag."""
    rows = {}
    for name in (MANAGER, MONGO):
        ins = inspect_to(f"f5-{tag}-other-{name}", name) or {}
        rows[name] = {"id": ins.get("Id"), "started_at": (ins.get("State") or {}).get("StartedAt"), "running": (ins.get("State") or {}).get("Running"),
                      "restart_count": ins.get("RestartCount")}
    (OUT / f"f5-others-{tag}.json").write_text(json.dumps(rows, indent=1))
    return rows


def count_log(pattern):
    rc, out = logs_text()
    return len(re.findall(pattern, out)) if rc == 0 else -1


def run_f5(image):
    """F5 (design network-isolation-design.md F5/A14): `docker compose restart sandbox-worker-1` re-establishes the isolation (V0 OK again) in a NEW network
    namespace. The container is the Compose service created here with `up --no-deps --no-build --pull never` (nothing else of the project is touched)."""
    STATE["phase"] = "f5-pre"
    rc, ids = compose_ids()
    if rc != 0 or ids:
        raise RuntimeError(f"containers of project/service already exist or could not be listed: rc={rc} {ids}")
    others_snapshot("before")
    STATE["phase"] = "f5-up"
    rc, out = sh("f5-compose-up", compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", COMPOSE["service"]), 240)
    rc2, ids = compose_ids()
    if len(ids) == 1:
        STATE["f5_id"] = ids[0]
        STATE["wref"] = ids[0]
    if rc != 0 or rc2 != 0 or len(ids) != 1:
        raise RuntimeError(f"compose up rc={rc}; project/service containers: rc={rc2} {ids} (exactly one expected)")
    if not wait_log(r"ISOLATION OK \(V0 startup\)", V0_WAIT_S):
        raise RuntimeError("compose worker did not log V0 OK within the wait")
    time.sleep(2)
    STATE["phase"] = "f5-before"
    f5_state("before")
    n_v0 = count_log(r"ISOLATION OK \(V0 startup\)")
    n_poll = count_log(r"Starting worker poller")
    (OUT / "f5-log-counts-before.json").write_text(json.dumps({"v0": n_v0, "poller": n_poll}))
    STATE["phase"] = "f5-restart"
    t_restart = time.time()
    rc, out = sh("f5-compose-restart", compose("restart", "-t", "10", COMPOSE["service"]), 180)
    (OUT / "f5-restart-time.txt").write_text(f"{t_restart}\n{time.time()}\n")
    if rc != 0:
        raise RuntimeError(f"compose restart rc={rc}")
    t_end = time.time() + V0_WAIT_S
    while time.time() < t_end and count_log(r"ISOLATION OK \(V0 startup\)") < 2:
        time.sleep(1)
    time.sleep(2)
    STATE["phase"] = "f5-after"
    f5_state("after")
    (OUT / "f5-log-counts-after.json").write_text(json.dumps({"v0": count_log(r"ISOLATION OK \(V0 startup\)"), "poller": count_log(r"Starting worker poller")}))
    others_snapshot("after")
    STATE["phase"] = "f5-done"




def main(argv):
    global OUT, LABEL
    mode, run_dir, LABEL, image, fixtures = argv[0], pathlib.Path(argv[1]), argv[2], argv[3], argv[4]
    literal = argv[5] if len(argv) > 5 else None
    OUT = run_dir
    OUT.mkdir(parents=True, exist_ok=False)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, on_signal)
    sha = lambda n: hashlib.sha256((HERE / n).read_bytes()).hexdigest() if (HERE / n).is_file() else None      # noqa: E731
    ident = {"schema": "ct01-flow-identity/2", "mode": mode, "label": LABEL, "image_id": image, "pid": os.getpid(), "started": now(),
             "manager_url": MGR_URL, "worker_name": WORKER_NAME, "worker_ip": WORKER_IP,
             "tree": {"manifest_sha256": sha("SHA256SUMS"), "manifest_literal": literal, "runner_sha256": sha("flow_lane.py"),
                      "evaluator_sha256": sha("evaluate_flow.py"), "pins_sha256": sha("pins.json"), "export_sha256": sha("export_run.py"),
                      "entry_sha256": sha("lane_entry.sh")}}
    (OUT / "identity.json").write_text(json.dumps(ident, indent=1))
    verdict_hint = {"completed": False, "abort_reason": None, "signal": None}
    try:
        if literal is not None and ident["tree"]["manifest_sha256"] != literal:
            raise RuntimeError("the staged tree manifest differs from the literal the entry was reviewed with")
        if mode not in ("success", "f3", "f4", "f5"):
            raise RuntimeError(f"unknown mode {mode!r}")
        sh("env-docker-version", [DOCKER, "version", "--format", "{{.Server.Version}}"], 30)
        rc, out = sh("env-image-id", [DOCKER, "image", "inspect", "--format", "{{.Id}}", "sandbox-worker:latest"], 30)
        if out.strip() != image:
            raise RuntimeError(f"image id {out.strip()!r} != pinned {image!r}")
        sh("env-manager-inspect", [DOCKER, "inspect", MANAGER], 30)
        sh("env-network-inspect", [DOCKER, "network", "inspect", NET], 30)
        sh("env-ps", [DOCKER, "ps", "-a", "--no-trunc", "--format", "{{.Names}} {{.State}} {{.Image}}"], 30)
        rc, out = sh("env-qemu", ["pgrep", "-a", "qemu-system"], 10)
        if rc == 0 and out.strip():
            raise RuntimeError("a qemu-system process is already running on the host")
        rc, out = sh("env-leftover", [DOCKER, "ps", "-a", "--filter", f"name={WORKER_NAME}", "--format", "{{.Names}}"], 30)
        if out.strip():
            raise RuntimeError(f"a container named {WORKER_NAME} already exists")
        code, _ = http("GET", "/healthcheck")
        if code != 200:
            raise RuntimeError(f"manager healthcheck from the host: {code}")
        host_snapshot("before")
        mgr_snapshot("before")
        # the real worker takes the NEXT queued task: nothing but this lane's fixtures may be waiting (queued/processing/in_memory_queue all 0)
        try:
            c0 = json.loads(json.loads((OUT / "manager-before-status.json").read_text())["body"])
        except Exception as e:                                   # noqa: BLE001
            raise RuntimeError(f"manager /status unreadable before the lane: {e}")
        if any(c0.get(k) not in (0,) for k in ("queued", "processing", "in_memory_queue")):
            raise RuntimeError(f"manager queue is not empty before the lane: {c0}")
        if mode == "f5":
            run_f5(image)
            verdict_hint["completed"] = True
            return finish(verdict_hint)
        STATE["phase"] = "worker-start"
        if not start_worker(image):
            raise RuntimeError("worker container could not be started")
        if not wait_log(r"ISOLATION OK \(V0 startup\)", V0_WAIT_S):
            raise RuntimeError("worker did not log V0 OK within the wait")
        STATE["phase"] = "t19"
        rc, out = sh("t19-manager-to-worker-health",
                     [DOCKER, "exec", MANAGER, "python3", "-c",
                      "import urllib.request,time;t=time.time();r=urllib.request.urlopen('http://%s:8011/healthcheck',timeout=5);"
                      "print(r.status, round(time.time()-t,3))" % WORKER_IP], 30)
        STATE["phase"] = "tasks"
        archs = ["ARM", "MIPS"] if mode == "success" else ["ARM"]
        results = []
        for index, arch in enumerate(archs):
            if mode == "f3":
                rc, out = sh("fault-f3-nft-delete", [DOCKER, "exec", WORKER_NAME, "nft", "delete", "table", "inet", "sandbox_guest"], 30)
                (OUT / "fault-f3-time.txt").write_text(f"{time.time()}\n")
            rec = submit(arch, fixtures)
            if not rec["task_id"]:
                raise RuntimeError(f"{arch}: submit failed ({rec['http']})")
            log(f"{arch}: task {rec['task_id']}")
            if mode == "f4":
                ok = wait_log(r"Got the executable inside QEMU", FAULT_WAIT_S)
                (OUT / "fault-f4-armed.txt").write_text(f"{ok} {time.time()}\n")
                if ok:
                    sh("fault-f4-nft-delete", [DOCKER, "exec", WORKER_NAME, "nft", "delete", "table", "inet", "sandbox_guest"], 30)
                    (OUT / "fault-f4-time.txt").write_text(f"{time.time()}\n")
            stop = threading.Event()
            smp = threading.Thread(target=sample_isolation, args=(arch, index, stop, rec["task_id"]), daemon=True) if mode == "success" else None
            if smp:
                smp.start()
            st = poll_task(rec, TASK_WAIT_S)
            stop.set()
            if smp:
                smp.join(90)
            log(f"{arch}: final status {st}")
            (OUT / f"final-{arch}.json").write_text(json.dumps(st))
            if st and st.get("status") == "COMPLETED":
                fetch_result(rec)
            worker_logs(f"worker-logs-after-{arch}")
            results.append((arch, st))
            if not st or st.get("status") not in ("COMPLETED", "FAILED"):
                break
        time.sleep(2)
        STATE["phase"] = "settle"
        host_snapshot("after-tasks")
        verdict_hint["completed"] = True
    except KeyboardInterrupt as e:
        verdict_hint["signal"] = STATE["signal"]
        verdict_hint["abort_reason"] = f"interrupted: {e}"
    except Exception as e:                                       # noqa: BLE001
        verdict_hint["abort_reason"] = f"{type(e).__name__}: {e} (phase {STATE['phase']})"
    finally:
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(s, signal.SIG_IGN)
        try:
            worker_logs("worker-logs-final")
            sh("worker-inspect", [DOCKER, "inspect", STATE["wref"]], 30)
            sh("manager-logs", [DOCKER, "logs", "--timestamps", "--tail", "400", MANAGER], 60)
            mgr_snapshot("after")
            if mode == "f5":
                cleanup_f5()
            else:
                cleanup()
            time.sleep(1)
            host_snapshot("after")
        finally:
            (OUT / "lane-status.json").write_text(json.dumps({"schema": "ct01-flow-lane-status/1", "mode": mode, "label": LABEL, "finished": now(), **verdict_hint}, indent=1))
    return exit_code(verdict_hint)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
