"""Fake manager + fake worker + fake docker CLI for the offline flow tests. NOTHING real: the worker's behaviour (log lines, V1/V2, upload) is a SIMULATION written
from service/analysis.py and poller.py; it proves the lane/evaluator wiring, not that Docker/QEMU/the worker behave so."""
import base64, io, json, os, pathlib, re, subprocess, sys, threading, time, uuid, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IMAGE = "sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153"
BASE = "/api/v1/sandbox-manager"
MANAGER = "cic-ynu-iotmal-sandbox-sandbox-manager-1"
MONGO = "mongo-db"
PROJECT = "cic-ynu-iotmal-sandbox"
SERVICE = "sandbox-worker-1"
CNAME = "cic-ynu-iotmal-sandbox-sandbox-worker-1-1"
CID = "c0ffee" + "0" * 58


class Sim:
    def __init__(self, fixtures, mode_opts=None):
        self.fx = {a: (pathlib.Path(fixtures) / f"busybox-{a}").read_bytes() for a in ("ARM", "MIPS")}
        self.opt = mode_opts or {}
        self.lock = threading.RLock()
        self.tasks = {}                 # id -> dict(status, filename, worker_id, failure_reason, data)
        self.worker = None              # dict(id, log[], faulted, start)
        self.zips = {}
        self.manager_logs = ["INFO: manager up"]
        for i in range(int(self.opt.get("preload_queued", 0))):
            self.tasks[f"pre{i}"] = {"status": "QUEUED", "filename": "other.elf"}
        self.ps_extra = ["cic-ynu-iotmal-sandbox-sandbox-manager-1 aaa Up", "mongo-db bbb Up"]
        self.proc_root = pathlib.Path(self.opt["proc_root"]) if self.opt.get("proc_root") else None
        self.cw = None                      # the Compose worker (F5): dict(id, log, pid, ns, started, restarts)
        self.qemu = False
        self.n_pid = 5000
        self.n_ns = 4026532000
        self.inspect_counts = {}
        self.started = {MANAGER: "2026-10-10T20:00:00.000000000Z", MONGO: "2026-10-10T19:59:00.000000000Z"}
        self.ids = {MANAGER: "m" * 64, MONGO: "d" * 64}

    def _new_ns(self, w):
        self.n_pid += 1
        w["pid"] = self.n_pid
        if "ns" not in w or not self.opt.get("restart_same_ns"):
            self.n_ns += 1
            w["ns"] = self.n_ns
        if self.proc_root is not None:
            d = self.proc_root / str(w["pid"]) / "ns"
            d.mkdir(parents=True, exist_ok=True)
            link = d / "net"
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(f"net:[{w['ns']}]")
        self.n_start = getattr(self, "n_start", 0) + 1
        w["started"] = f"2026-10-11T04:00:{self.n_start:02d}.000000000Z"

    def cwlog(self, line):
        with self.lock:
            self.cw["log"].append((("err" if line.startswith("[") else "out"), f"{time.strftime('%Y-%m-%dT%H:%M:%S')}.000000000Z {line}"))

    def _v0(self, inherited=False):
        # the real run.sh log (F5 run 20261011T040725Z): pristine namespace = ip_forward=1 and tap0=None before run.sh; run.sh leaves ip_forward=0, tap0 set
        pre = ("net.ipv4.ip_forward=0", "tap0=1") if inherited else ("net.ipv4.ip_forward=1", "tap0=None")
        for l in (f"SYSCTL REPORT (before run.sh): {pre[0]}",
                  f"SYSCTL REPORT (before run.sh): rp_filter [max] configured: all=2 default=2 {pre[1]} eth0=2 | effective: {pre[1]} eth0=2",
                  "SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0",
                  "ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route", "[INFO] __main__: Starting worker poller"):
            self.cwlog(l)

    def docker_compose(self, a):
        # [compose, -p, P, -f, F, --project-directory, D, <verb>, ...]
        verb = a[7]
        if a[2] != PROJECT:
            return 1, "", "no such project"
        if verb == "up":
            if self.cw is not None:
                return 0, "", "already running"
            if self.opt.get("up_fails"):
                return 1, "", "compose up failed"
            self.cw = {"id": CID, "log": [], "restarts": 0, "faulted": False}
            self._new_ns(self.cw)
            self._v0()
            return 0, "", f" Container {CNAME} Started\n"
        if verb == "restart":
            if self.cw is None or self.opt.get("restart_fails"):
                return 1, "", "restart failed"
            self.cw["restarts"] += 1
            self._new_ns(self.cw)
            if not self.opt.get("restart_no_v0"):
                self._v0(inherited=bool(self.opt.get("restart_same_ns")))
            else:
                self.cwlog("[INFO] __main__: Starting worker poller")
            if self.opt.get("restart_touches_manager"):
                self.started[MANAGER] = "2026-10-11T04:30:00.000000000Z"
            return 0, "", f" Container {CNAME} Started\n"
        return 127, "", f"unsupported compose {a}"

    def inspect_json(self, ref):
        if self.cw is not None and ref in (CID, CNAME):
            w = self.cw
            return [{"Id": CID, "Name": "/" + CNAME, "Image": self.opt.get("image_id", IMAGE), "RestartCount": 0,
                     "State": {"Running": True, "StartedAt": w["started"], "Pid": w["pid"]},
                     "Config": {"Labels": {"com.docker.compose.project": PROJECT, "com.docker.compose.service": self.opt.get("label_service", SERVICE),
                                           "com.docker.compose.version": "5.6.0"}},
                     "NetworkSettings": {"SandboxID": f"sb{w['ns']:x}", "SandboxKey": f"/var/run/docker/netns/sb{w['ns']:x}"[:40],
                                         "Networks": {PROJECT + "_sandboxnet": {"IPAddress": "192.168.60.2", "EndpointID": f"ep{w['ns']:x}"}}}}]
        if ref in (MANAGER, MONGO):
            return [{"Id": self.ids[ref], "Name": "/" + ref, "RestartCount": 0, "State": {"Running": True, "StartedAt": self.started[ref], "Pid": 1}, "Config": {"Labels": {}}}]
        return None

    # ---- worker log
    def wlog(self, line):
        with self.lock:
            self.worker["log"].append((("err" if line.startswith("[") else "out"), f"{time.strftime('%Y-%m-%dT%H:%M:%S')}.000000000Z {line}"))

    # ---- worker simulation for one task
    def run_task(self, tid):
        o, w = self.opt, self.worker
        t = self.tasks[tid]
        arch = "ARM" if t["filename"].endswith("ARM.elf") else "MIPS"
        time.sleep(0.15)
        with self.lock:
            t.update(status="PROCESSING", worker_id="ct01-flow-worker")
        self.wlog(f"[INFO] __main__: Received task: {tid}")
        self.wlog(f"[INFO] service.analysis: Starting task: {tid}")
        self.wlog(f"[INFO] service.analysis: Detected architecture: {arch}")
        if w["faulted"] and not o.get("ignore_fault"):
            return self.fail(tid, "network isolation check failed (V1 before phase 1): ruleset: table inet sandbox_guest missing")
        self.qemu = True
        for line in ("Starting QEMU...", "Started QEMU", "Set IP in QEMU", "Got the executable inside QEMU", "Started network capture"):
            self.wlog(f"[INFO] service.analysis: {line}")
            time.sleep(0.05)
        time.sleep(float(o.get("phase1_s", 4.0)))
        self.wlog("[INFO] service.analysis: Stopped network capture")
        self.qemu = False
        self.wlog("[INFO] service.analysis: QEMU shutdown complete (phase 1, pid 7, exitstatus=0, signalstatus=None)")
        if w["faulted"] and not o.get("ignore_fault"):
            return self.fail(tid, "network isolation check failed (V2 before phase 2): ruleset: table inet sandbox_guest missing")
        self.qemu = True
        for line in ("Starting QEMU...", "Started QEMU", "Uploading strace...", "Uploading sar..."):
            self.wlog(f"[INFO] service.analysis: {line}")
            time.sleep(0.05)
        time.sleep(float(o.get("phase2_s", 1.0)))
        self.qemu = False
        self.wlog("[INFO] service.analysis: QEMU shutdown complete (phase 2, pid 9, exitstatus=0, signalstatus=None)")
        if o.get("bad_zip"):
            files = {tid: b"not the fixture", "strace.log": b"", "sar.out": b"x", "network.pcap": b"p", "qemu.log": b"q"}
        else:
            files = {tid: self.fx[arch], "strace.log": b'1  execve("./exec", ["./exec"], 0x1) = 0\n', "sar.out": b"sar", "network.pcap": b"pcap", "qemu.log": b"qemu"}
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as z:
            for n, d in files.items():
                z.writestr(n, d)
        with self.lock:
            self.zips[tid] = bio.getvalue()
            t["status"] = "COMPLETED"
        self.wlog("[INFO] __main__: Upload response: 200")

    def fail(self, tid, reason):
        with self.lock:
            self.tasks[tid].update(status="FAILED", failure_reason=reason)
        self.wlog(f"[ERROR] __main__: Analysis failed for task {tid}")

    # ---- docker CLI
    def docker(self, a):
        if a[:1] == ["version"]:
            return 0, "29.8.2\n", ""
        if a[:2] == ["image", "inspect"]:
            return 0, self.opt.get("image_id", IMAGE) + "\n", ""
        if a[:1] == ["compose"]:
            return self.docker_compose(a)
        if a[:1] == ["inspect"]:
            j = self.inspect_json(a[1])
            if j is not None:
                return 0, json.dumps(j) + "\n", ""
            if a[1] == "ct01-flow-worker" and self.worker is None:
                return 1, "[]\n", "Error: No such object"
            return 0, "[{}]\n", ""
        if a[:2] == ["network", "inspect"]:
            return 0, "[{}]\n", ""
        if a[:1] == ["ps"]:
            with self.lock:
                names = list(self.ps_extra) + ([f"ct01-flow-worker {self.worker['id']} Up"] if self.worker else []) \
                + ([f"{CNAME} {CID} Up"] if self.cw is not None else [])
            if "--filter" in a and a[a.index("--filter") + 1].startswith("label=com.docker.compose.project"):
                return 0, (CID + "\n" if self.cw is not None else ""), ""
            if "--filter" in a and a[a.index("--filter") + 1].startswith("name="):
                return 0, ("ct01-flow-worker\n" if self.worker else ""), ""
            if "-aq" in a:
                return 0, (self.worker["id"] + "\n" if self.worker else ""), ""
            return 0, "\n".join(names) + "\n", ""
        if a[:1] == ["run"]:
            with self.lock:
                self.worker = {"id": uuid.uuid4().hex[:12], "log": [], "faulted": False, "start": time.time()}
            for l in ("SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=1", "ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route",
                      "[INFO] __main__: Starting worker poller"):
                self.wlog(l)
            return 0, self.worker["id"] + "\n", ""
        if a[:1] == ["logs"]:
            if a[-1] in (CID, CNAME) and self.cw is not None:
                with self.lock:
                    rows = self.cw["log"]
                    return 0, "".join(l + "\n" for s, l in rows if s == "out"), "".join(l + "\n" for s, l in rows if s == "err")
            if a[-1] == "ct01-flow-worker":
                with self.lock:
                    rows = self.worker["log"] if self.worker else []
                    return 0, "".join(l + "\n" for s, l in rows if s == "out"), "".join(l + "\n" for s, l in rows if s == "err")
            return 0, "\n".join(self.manager_logs) + "\n", ""
        if a[:1] == ["exec"]:
            tgt, rest = a[1], a[2:]
            if tgt in (CID, CNAME) and self.cw is not None:
                if rest[:3] == ["nft", "list", "table"]:
                    return (0, "table inet sandbox_guest {\n}\n", "") if not self.opt.get("f5_table_missing_after_restart") or self.cw["restarts"] == 0 \
                        else (1, "", "Error: No such file or directory")
                if rest[:4] == ["ip", "-o", "link", "show"]:
                    return 0, "7: tap0: <BROADCAST,MULTICAST,UP> mtu 1500\n", ""
                if rest[:3] == ["python3", "-m", "isolation.verify"]:
                    return 0, f"ISOLATION OK ({rest[rest.index('--phase') + 1]}): ruleset,sysctl,link,neighbor,route\n", ""
                return 127, "", "unsupported exec"
            if tgt == "ct01-flow-worker" and rest[:3] == ["pgrep", "-a", "qemu-system"]:
                if self.qemu and not self.opt.get("no_qemu_pid"):
                    return 0, "4242 qemu-system-arm -M virt\n", ""
                return 1, "", ""
            if tgt == "ct01-flow-worker" and rest[:3] == ["nft", "delete", "table"]:
                with self.lock:
                    self.worker["faulted"] = True
                return (0, "", "") if not self.opt.get("fault_cmd_fails") else (1, "", "Error: No such file or directory")
            if tgt == "ct01-flow-worker" and rest[:3] == ["python3", "-m", "isolation.verify"]:
                phase = rest[rest.index("--phase") + 1]
                if self.worker and self.worker["faulted"]:
                    return 1, "", f"ISOLATION FAIL ({phase}): ruleset: missing"
                return 0, f"ISOLATION OK ({phase}): ruleset,sysctl,link,neighbor,route\n", ""
            if tgt.startswith("cic-ynu") and rest[:1] == ["python3"] and (self.worker is not None or self.cw is not None):
                return (0, "200 0.004\n", "") if not self.opt.get("t19_fails") else (1, "", "URLError")
            return 127, "", "unsupported exec"
        if a[:1] == ["cp"]:
            m = re.match(r"[^:]+:/app/output/([0-9a-f-]+)\.zip", a[1])
            with self.lock:
                z = self.zips.get(m.group(1)) if m else None
            if z is None:
                return 1, "", "Error: No such container:path"
            return 0, "", "@@CP@@" + base64.b64encode(z).decode()
        if a[:1] == ["rm"]:
            with self.lock:
                if a[-1] in (CID, CNAME):
                    self.cw = None
                else:
                    self.worker = None
            return 0, "", ""
        return 127, "", f"unsupported docker {a}"

    # ---- manager API
    def status(self):
        with self.lock:
            c = {}
            for t in self.tasks.values():
                c[t["status"]] = c.get(t["status"], 0) + 1
        return {"queued": c.get("QUEUED", 0), "processing": c.get("PROCESSING", 0), "completed": c.get("COMPLETED", 0),
                "failed": c.get("FAILED", 0), "cancelled": c.get("CANCELLED", 0), "in_memory_queue": c.get("QUEUED", 0)}


def make_server(sim):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthcheck":
                return self._send(200, {"message": "Hello World"})
            if self.path == BASE + "/status":
                return self._send(200, sim.status())
            if self.path == BASE + "/tasks":
                with sim.lock:
                    return self._send(200, {"tasks": [{"task_id": k, "filename": v["filename"], "status": v["status"], "worker_id": v.get("worker_id", ""),
                                                       "failure_reason": v.get("failure_reason", "")} for k, v in sim.tasks.items()]})
            self._send(404, {})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            if self.path == "/__docker":
                rc, out, err = sim.docker(json.loads(body))
                return self._send(200, {"rc": rc, "out": out, "err": err})
            if self.path == BASE + "/submit-file":
                m = re.search(rb'filename="([^"]+)"', body)
                tid = str(uuid.uuid4())
                with sim.lock:
                    sim.tasks[tid] = {"status": "QUEUED", "filename": m.group(1).decode() if m else ""}
                if sim.worker is not None:
                    threading.Thread(target=sim.run_task, args=(tid,), daemon=True).start()
                return self._send(200, {"task_id": tid, "filename": sim.tasks[tid]["filename"], "status": "QUEUED"})
            self._send(404, {})
    return ThreadingHTTPServer(("127.0.0.1", 0), H)


FAKE_DOCKER = '''#!/usr/bin/env python3
import base64, json, os, sys, urllib.request
req = urllib.request.Request("http://127.0.0.1:%s/__docker" % os.environ["CT01_FAKE_PORT"], data=json.dumps(sys.argv[1:]).encode(), method="POST")
r = json.loads(urllib.request.urlopen(req, timeout=30).read())
err = r["err"]
if err.startswith("@@CP@@"):
    open(sys.argv[3], "wb").write(base64.b64decode(err[6:])); err = ""
sys.stdout.write(r["out"]); sys.stderr.write(err); sys.exit(r["rc"])
'''
