#!/usr/bin/env python3
"""06B-4F — offline test of the ICMP wiring (icmp_harness.py, probe_matrix.py CT01_SUITE=icmp, run-06b4f.sh).
No root, no Docker, no QEMU, no packet: the worker modules are stubs, the guest console, nft, tshark and the
host capture files are fakes. Every scenario runs the REAL probe_matrix.main() in its own python process,
importing ONLY the files that run-06b4f.sh mounts into /harness (plus the stubs): a missing mount fails.

    python3 selftest_icmp_wiring.py [--json FILE]
    (internal) python3 -I selftest_icmp_wiring.py --scenario NAME --dir DIR

Sections:
  U  icmp_harness units: service link parsing, GuardedRunner, check_record, arch_outcome, run_check, CLI
  S  scenarios through probe_matrix.main(): complete group, missing/duplicate case, capture lost
     (marker, stale heartbeat, tshark exit), leak alert, execution errors (tool missing, timeout, no
     packet), counter read error, mismatch, reply towards the guest, service link failures, drop statistics,
     unreadable capture, QEMU not exiting, cleanup not done; each also through icmp_harness --outcome and the
     run script's own outcome mapping (case block extracted from run-06b4f.sh)
  W  run-06b4f.sh: syntax, mounts, CT01_SUITE=icmp on the only probe_matrix call, self-tests before any
     container, run-level check, everything else identical to run-06b3b.sh
"""
import collections
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = {}
TAP = "7a:93:2a:f1:47:47"
CASE_IDS = ("T12-B1", "T12-B2", "T12-B4", "T13-I1", "T13-I2")


def t(name, fn):
    if name in RESULTS:
        raise SystemExit(f"duplicate test name {name}")
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    if not ok and not why:
        why = "returned False"
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""))


# ====================================================================== fake container (scenario process)
SCENARIOS = {
    # name: spec. ping: {case: behaviour}; events: {case: event after its ping}; see FakeGuest.
    "clean": {},
    "missing-case": {"cases": "missing"},
    "duplicate-case": {"cases": "duplicate"},
    "marker-after-B4": {"events": {"T12-B4": "marker"}},
    "heartbeat-stale-after-B1": {"events": {"T12-B1": "stale"}},
    "tshark-exit-after-I1": {"events": {"T13-I1": "tshark_dead"}},
    "leak-after-B2": {"events": {"T12-B2": "leak"}},
    "ping6-missing": {"ping": {"T13-I1": "missing", "T13-I2": "missing"}},
    "timeout-B2": {"ping": {"T12-B2": "timeout"}},
    "no-packet-B1": {"ping": {"T12-B1": "noframe"}},
    "counter-read-error-B4": {"nft_fail": "T12-B4 after"},
    "mismatch-B4": {"ping": {"T12-B4": "nocount"}},
    "reply-I1": {"ping": {"T13-I1": "reply"}},
    "link-before-http000": {"link": {"before": "http000"}},
    "link-after-bad-hash": {"link": {"after": "badhash"}},
    "link-after-stale-file": {"link": {"after": "stalefile"}},
    "tap0-drops": {"isb_drop": 2},
    "pcap-unreadable": {"pcap": "truncated"},
    "qemu-not-exiting": {"qemu_stuck": True},
    "cleanup-marker-left": {"marker_left": True},
    "marker-before-B2": {"nft_event": ("T12-B2 before", "marker")},   # capture dies between two cases
    "liveness-fails": {"liveness_fail": True},
    # 06B-4FR (P1): an alert / an unreadable alert file appears during the next case's counter read A
    "leak-before-B2": {"nft_event": ("T12-B2 before", "leak")},
    "alert-unreadable-before-B2": {"nft_event": ("T12-B2 before", "alert_dir")},
}


class World:
    pass


W = World()


def mounted_files(script):
    """Files run-06b4f.sh mounts into /harness: -v "$H/x:/harness/x:ro"."""
    return sorted(set(re.findall(r'-v "\$H/([\w.]+):/harness/\1:ro"', open(script).read())))


def write_stubs(sb, marker_file, marker_left):
    os.makedirs(os.path.join(sb, "isolation"))
    os.makedirs(os.path.join(sb, "service"))
    for p in ("isolation", "service"):
        open(os.path.join(sb, p, "__init__.py"), "w").close()
    open(os.path.join(sb, "isolation", "constants.py"), "w").write(
        'GUEST_MAC = "52:54:00:c7:00:02"; GUEST_IP = "10.200.0.2"; WORKER_GUEST_IP = "10.200.0.1"; SVC_PORT = 8011\n'
        f'GUEST_IF = "tap0"; GUEST_PREFIX = 30; CURRENT_TASK_FILE = {marker_file!r}\n')
    open(os.path.join(sb, "isolation", "current_task.py"), "w").write(
        "from isolation.constants import CURRENT_TASK_FILE as F\nimport os\n"
        "def set_current(t):\n    open(F, 'w').write(t)\n"
        + ("def clear():\n    pass\n" if marker_left else
           "def clear():\n    if os.path.exists(F):\n        os.remove(F)\n"))
    open(os.path.join(sb, "isolation", "verify.py"), "w").write("def verify_isolation(*a, **k):\n    pass\n")
    open(os.path.join(sb, "service", "analysis.py"), "w").write('''
import types
ARCH_CONFIGS = {}
STUCK = [False]
class FakeProc:
    pid = 4242
    def __init__(self):
        self.alive, self.exitstatus = True, None
    def isalive(self):
        return self.alive
def shutdown_qemu(proc, phase):
    if not STUCK[0]:
        proc.alive, proc.exitstatus = False, 0
class Analysis:
    def __init__(self, task, work, gip, wip, kernel, rootfs, extra):
        self.kernel_path, self.rootfs_path = kernel, rootfs
    def _start_qemu(self, cfg):
        return FakeProc()
    def _configure_network(self, proc, cfg):
        pass
''')


class TIMEOUT(Exception):
    """Stands in for pexpect.TIMEOUT."""


def pcapng_bytes(frames, drops):
    B = W.B
    data = B.shb() + B.idb(tsresol=9)
    for ts, fr in frames:
        data += B.epb(round(ts * 1e9), fr)
    opts = struct.pack("<HHQ", 4, 8, len(frames)) + struct.pack("<HHQ", 5, 8, drops) + struct.pack("<HH", 0, 0)
    t_ns = round(time.time() * 1e9)
    data += B._blk(5, struct.pack("<III", 0, t_ns >> 32, t_ns & 0xFFFFFFFF) + opts)
    return data


class FakeTshark:
    """tshark -i tap0 -w PCAP: the file exists while it runs; on SIGINT it writes every frame the fake guest
    emitted, followed by an interface statistics block, and exits 0."""

    def __init__(self, args, stdout=None, stderr=None):
        assert args[:2] == ["tshark", "-i"], args
        self.path, self.returncode = args[args.index("-w") + 1], None
        open(self.path, "wb").write(W.B.shb() + W.B.idb(tsresol=9))
        W.tshark = self

    def poll(self):
        if W.tshark_dead and self.returncode is None:
            self.returncode = 1
        return self.returncode

    def send_signal(self, sig):
        data = pcapng_bytes(W.frames, W.spec.get("isb_drop", 0))
        if W.spec.get("pcap") == "truncated":
            data = data[:-37]
        open(self.path, "wb").write(data)
        if self.returncode is None:
            self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def fake_run_checked(cmd):
    if cmd[:3] == ["nft", "-j", "list"] and W.spec.get("nft_event", (None,))[0] == W.label:
        kind = W.spec["nft_event"][1]
        if kind == "marker":
            open(W.pm.CAPTURE_DEAD, "a").write("12:00:00 capture bridge pid 78 exited during the test\n")
        elif kind == "leak":
            open(W.pm.ALERT, "a").write("12:00:02 IP 10.200.0.2 > 255.255.255.255: ICMP echo request, length 1209\n")
        elif kind == "alert_dir":       # unreadable even as root (the run script runs this test as root)
            os.remove(W.pm.ALERT)
            os.mkdir(W.pm.ALERT)
    if cmd[:3] == ["nft", "-j", "list"]:
        if W.spec.get("nft_fail") and W.label == W.spec["nft_fail"]:
            raise RuntimeError("command failed rc=1: nft -j list counters: simulated")
        return W.V.raw(W.counters)
    if cmd[:2] == ["tshark", "--version"]:
        return "TShark (Wireshark) 3.6.2 (fake)\n"
    raise RuntimeError(f"unexpected command in the fake container: {cmd}")


def emit(frames):
    """Frames the guest puts on tap0 now; each one hits the counter the ruleset would (l2frames.classify)."""
    time.sleep(0.06)
    for fr in frames:
        ts = time.time()
        W.frames.append((ts, fr))
        f = W.L.decode(ts, fr)
        _, cls, _ = W.L.classify(f, TAP)
        if cls in W.counters and not W.nocount:
            W.counters[cls] += 1
        time.sleep(0.01)
    time.sleep(0.06)


class FakeGuest:
    def __init__(self, proc):
        self.proc = proc

    def monitor(self, command, timeout=20):
        W.commands.append(("monitor", command))
        return ("info network\nnet0: index=0,type=nic,model=virtio-net-pci,macaddr=52:54:00:c7:00:02\n"
                " \\ hostnet0: index=0,type=tap,ifname=tap0,script=no,downscript=no\n")

    def run(self, cmd, timeout=60):
        W.commands.append(("run", cmd))
        if cmd == "ip addr":
            return 0, "2: eth1: <UP>\n    inet 10.200.0.2/30 brd 10.200.0.3 scope global eth1\n"
        if cmd == "ip route":
            return 0, "default via 10.200.0.1 dev eth1\n10.200.0.0/30 dev eth1\n"
        if cmd.startswith("for i in /sys/class/net/"):
            return 0, "eth1 52:54:00:c7:00:02\nlo 00:00:00:00:00:00\n"
        if cmd.startswith("for c in nslookup"):
            return 0, "/bin/nslookup\n/bin/nc\n/bin/wget\n/bin/ping\nmissing:arping\n"
        if cmd.startswith("curl --version"):
            return 0, "curl 7.88.1 (fake)\n"
        if "/get-task/" in cmd:
            W.links += 1
            which = "before" if W.links == 1 else "after"
            how = W.spec.get("link", {}).get(which, "ok")
            sha = hashlib.sha256(open(os.path.join(W.pm.DATA, W.pm.T, W.pm.T), "rb").read()).hexdigest()
            if how == "http000":
                return 0, "HTTP=000\nsha256sum: /tmp/r.out: No such file or directory\n"
            if how == "badhash":
                return 0, "HTTP=200\n" + "0" * 64 + "  /tmp/r.out\n"
            if how == "stalefile":      # curl failed, an earlier response file would still hash right
                return 0, f"HTTP=000\n{sha}  /tmp/r.out\n"
            return 0, f"HTTP=200\n{sha}  /tmp/r.out\n"
        m = re.fullmatch(r"ping6? -c 3 -s (\d+) -w 5 (?:-I \S+ )?(\S+)", cmd)
        if not m:
            raise RuntimeError(f"unexpected guest command: {cmd}")
        cid = W.by_cmd.get(cmd)
        if cid is None:
            return 2, "fake guest: command does not match a reviewed case\n"
        how = W.spec.get("ping", {}).get(cid, "ok")
        rc, out = 1, "3 packets transmitted, 0 packets received, 100% packet loss\n"
        if how == "missing":
            rc, out = 127, "sh: ping6: not found\n"
        elif how == "timeout":
            raise TIMEOUT("Timeout exceeded.")
        elif how == "noframe":
            rc, out = 2, "ping: sendto: Permission denied\n"
        else:
            W.nocount = how == "nocount"
            frames = W.SI.probe_frames(cid, 3)
            if how == "reply":
                frames = frames + [W.SI.reply_to_guest()]
            emit(frames)
            W.nocount = False
        ev = W.spec.get("events", {}).get(cid)
        if ev == "marker":
            open(W.pm.CAPTURE_DEAD, "a").write("12:00:00 capture ens33 pid 77 exited during the test\n")
        elif ev == "stale":
            W.hb_stop.set()
            W.hb_thread.join()
            open(W.pm.HEARTBEAT, "w").write(str(time.time() - 30))
        elif ev == "tshark_dead":
            W.tshark_dead = True
        elif ev == "leak":
            open(W.pm.ALERT, "a").write("12:00:01 IP 10.200.0.2 > 224.0.0.1: ICMP echo request, length 1210\n")
        return rc, out


def guest_rows():
    """probe_matrix.guest_frames() (tshark -T fields) from the same frames, for the session measurement."""
    rows = []
    for ts, fr in W.frames:
        f = W.L.decode(ts, fr)
        ip = f.get("ip") or {}
        rows.append({"t": ts, "src_mac": f.get("src", ""), "etype": "0x%04x" % f.get("etype", 0),
                     "ip_src": ip.get("src", ""), "ip_dst": ip.get("dst", "") or "0.0.0.0",
                     "proto": str(ip.get("proto", "")), "sport": "", "dport": "", "qname": ""})
    return rows


def scenario_main(name, d):
    spec = SCENARIOS[name]
    hdir, sb, out = os.path.join(d, "harness"), os.path.join(d, "stubs"), os.path.join(d, "out")
    for p in (hdir, out, os.path.join(d, "data"), os.path.join(d, "sys", "tap0"), os.path.join(d, "proc")):
        os.makedirs(p)
    for f in mounted_files(os.path.join(HERE, "run-06b4f.sh")) + ["probe_matrix.py"]:
        shutil.copy2(os.path.join(HERE, f), hdir)
    write_stubs(sb, os.path.join(d, "current_task"), spec.get("marker_left", False))
    with zipfile.ZipFile(os.path.join(d, "image.zip"), "w") as z:
        z.writestr("kernel", b"k")
    open(os.path.join(d, "sys", "tap0", "address"), "w").write(TAP + "\n")
    os.environ["CT01_TARGETS"] = json.dumps({"worker_ip": "192.168.60.2", "mongo_ip": "172.18.0.2",
                                             "manager_ip": "192.168.60.10", "ssh_ips": [],
                                             "lan_dns": "192.168.177.2"})
    os.environ["CT01_SUITE"] = "icmp"
    sys.path[:0] = [hdir, sb]
    sys.argv = ["probe_matrix.py", "ARM", out]
    import importlib.util
    spec_pm = importlib.util.spec_from_file_location("probe_matrix", os.path.join(hdir, "probe_matrix.py"))
    pm = importlib.util.module_from_spec(spec_pm)
    spec_pm.loader.exec_module(pm)          # imports icmp_harness & co. from the mounted files only
    import icmp_cases
    sys.path.append(HERE)                   # test helpers only (frame/counter builders)
    import selftest_l2 as B
    import selftest_l2eval as V
    import selftest_icmp as SI
    from service import analysis as A
    W.pm, W.B, W.V, W.SI, W.L = pm, B, V, SI, pm.icmp_harness.I.L
    W.spec, W.frames, W.commands, W.links, W.label = spec, [], [], 0, None
    W.counters, W.tshark_dead, W.nocount = dict(V.BASE), False, False
    W.by_cmd = {icmp_cases.command(c, "eth1"): c["id"] for c in icmp_cases.build_cases(TAP)}
    A.STUCK[0] = spec.get("qemu_stuck", False)
    A.ARCH_CONFIGS["ARM"] = type("Cfg", (), {"image_zip_path": os.path.join(d, "image.zip"), "image_kernel_path": "/kernel",
                                             "image_rootfs_path": "/rootfs", "net_iface": "eth1",
                                             "qemu_cmd_template": "qemu-system-arm -k {kernel} -r {rootfs} -m {mac}"})
    if spec.get("cases") in ("missing", "duplicate"):     # a defective wiring/case list
        real = icmp_cases.build_cases

        def build(tap_mac):
            cs = real(tap_mac)
            return cs[:-1] if spec["cases"] == "missing" else cs + [cs[0]]
        icmp_cases.build_cases = build
    hc = os.path.join(d, "hostcap")
    os.makedirs(hc)
    pm.ALERT, pm.CAPTURE_DEAD, pm.HEARTBEAT = (os.path.join(hc, f) for f in ("alert.txt", "capture-dead.txt", "hb"))
    open(pm.ALERT, "w").close()
    pm.CTL, pm.DATA, pm.WORK = os.path.join(d, "ctl.jsonl"), os.path.join(d, "data") + "/", os.path.join(d, "work")
    pm.SYS_NET, pm.PROC_ROOT = os.path.join(d, "sys"), os.path.join(d, "proc")
    pm.Guest, pm.run_checked, pm.guest_frames = FakeGuest, fake_run_checked, guest_rows
    pm.subprocess = type("SP", (), {"Popen": FakeTshark, "DEVNULL": subprocess.DEVNULL,
                                    "TimeoutExpired": subprocess.TimeoutExpired, "run": subprocess.run})
    def ctl_dns(server, qname):
        if spec.get("liveness_fail"):
            raise OSError("timed out (fake)")
        return "DNS response rcode=0 (fake)"
    pm.ctl_dns = ctl_dns
    pm.ctl_http = lambda ip, port, path="/healthcheck": "HTTP 200 (fake)"
    real_read = pm.counters_read

    def counters_read(label):
        W.label = label
        return real_read(label)
    pm.counters_read = counters_read
    W.hb_stop = threading.Event()

    def hb():
        while not W.hb_stop.is_set():
            open(pm.HEARTBEAT + ".tmp", "w").write(str(time.time()))
            os.replace(pm.HEARTBEAT + ".tmp", pm.HEARTBEAT)
            W.hb_stop.wait(0.3)
    open(pm.HEARTBEAT, "w").write(str(time.time()))   # first beat before main(): no start-up race
    W.hb_thread = threading.Thread(target=hb, daemon=True)
    W.hb_thread.start()
    with contextlib.redirect_stdout(io.StringIO()):
        rc = pm.main()
    W.hb_stop.set()
    final = rc if rc else (1 if [r for r in pm.results if not r["ok"]] else 0)
    json.dump({"rc": final, "commands": W.commands, "mounted": mounted_files(os.path.join(HERE, "run-06b4f.sh")),
               "modules": {m: getattr(sys.modules[m], "__file__", None)
                           for m in ("icmp_harness", "icmp_cases", "l2frames", "l2eval", "signatures",
                                     "counter_window", "pcapng_stats")}},
              open(os.path.join(d, "scenario.json"), "w"), indent=1)
    return 0


# ====================================================================== driver side


def run_scenario(name, tmp):
    d = os.path.join(tmp, name)
    os.makedirs(d)
    p = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--scenario", name, "--dir", d],
                       capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        raise RuntimeError(f"scenario {name} crashed: {(p.stderr or p.stdout).strip()[-600:]}")
    sc = json.load(open(os.path.join(d, "scenario.json")))
    od = os.path.join(d, "out", "ARM")
    load = lambda f: json.load(open(os.path.join(od, f))) if os.path.exists(os.path.join(od, f)) else None
    sc.update(dir=d, result=load("result.json"), eval=load("icmp-eval.json"), group=load("icmp-group.json"),
              session=load("session.json"))
    import icmp_harness as H
    sc["outcome"] = H.arch_outcome(sc["result"], sc["eval"], "ARM")
    sc["script"] = script_mapping(sc["rc"], sc["outcome"])
    return sc


def script_mapping(rc, outcome):
    """The per-architecture `case "$rc:$outcome" in ... esac` block of run-06b4f.sh, run by bash as is."""
    s = open(os.path.join(HERE, "run-06b4f.sh")).read()
    i = s.index('    case "$rc:$outcome" in')
    block = s[i:s.index("    esac\n", i) + len("    esac\n")]
    prog = ('pass() { echo "@@PASS"; }; fail() { echo "@@FAIL"; }; UNVERIFIED=(); ARCH=ARM\n'
            f'rc={rc}; outcome={sh(outcome)}\n' + block + 'echo "@@UNVERIFIED_COUNT=${#UNVERIFIED[@]}"\n')
    out = subprocess.run(["bash", "-c", prog], capture_output=True, text=True).stdout
    marks = [l for l in out.splitlines() if l.startswith("@@")]
    if marks == ["@@PASS", "@@UNVERIFIED_COUNT=0"]:
        return "PASS"
    if marks == ["@@FAIL", "@@UNVERIFIED_COUNT=0"]:
        return "FAIL"
    if marks == ["@@UNVERIFIED_COUNT=1"] and "[UNVERIFIED] ARM: " in out:
        return "UNVERIFIED"
    return f"UNEXPECTED {marks}"


def sh(s):
    return "'" + s.replace("'", "'\\''") + "'"


def cats(sc):
    return {c["id"]: c["category"] for c in (sc["eval"] or {}).get("cases", [])}


def pings(sc):
    return [c for k, c in sc["commands"] if k == "run" and c.startswith("ping")]


def failed_tests(sc):
    return [r["test"] for r in sc["result"]["results"] if not r["ok"]]


def sec_S(tmp):
    import concurrent.futures

    def one(name):
        try:
            return name, run_scenario(name, tmp)
        except Exception as e:
            print(f"SELFTEST-ERROR: {e}")
            return name, None
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        S = dict(ex.map(one, SCENARIOS))
    g = lambda n: S[n] or (_ for _ in ()).throw(RuntimeError(f"scenario {n} did not run"))

    c = g("clean")
    t("S1 clean: exit 0, status COMPLETED, outcome PASS, run script maps it to PASS",
      lambda: (c["rc"], c["result"]["status"], c["outcome"], c["script"]) == (0, "COMPLETED", "PASS", "PASS"))
    t("S2 clean: the five reviewed cases, each exactly once, all ĐẠT (kiểm quy tắc), evidence rule_check",
      lambda: sorted(cats(c)) == sorted(CASE_IDS) and len(c["eval"]["cases"]) == 5
      and all(x["verdict"] == "ĐẠT (kiểm quy tắc)" and x["evidence_kind"] == "rule_check" for x in c["eval"]["cases"]))
    t("S3 clean: guest commands = service link, 5 pings in case order, service link; no IPv4 probe, no listener",
      lambda: ["link" if "get-task" in x else "ping" for _, x in c["commands"] if "get-task" in x or x.startswith("ping")]
      == ["link"] + ["ping"] * 5 + ["link"]
      and not any("--local-port" in x or "nslookup ct01" in x for _, x in c["commands"])
      and not any("listener" in r["test"] for r in c["result"]["results"]))
    t("S4 clean: ping commands are exactly icmp_cases.command() for the probe interface, in CASE_IDS order",
      lambda: pings(c) == [__import__("icmp_cases").command(x, "eth1") for x in __import__("icmp_cases").build_cases(TAP)])
    t("S5 clean: service links before/after recorded with HTTP 200 and the fixture hash",
      lambda: all(c["group"][k]["ok"] is True and c["group"][k]["detail"]["http_code"] == "200"
                  and c["group"][k]["detail"]["sha256"] == c["group"]["fixture_sha256"]
                  for k in ("service_link_before", "service_link_after")))
    t("S6 clean: link labelled as precondition, not a live control; group evidence rule_check",
      lambda: "NOT a live control" in c["group"]["service_link_role"] and c["eval"]["evidence_kind"] == "rule_check")
    t("S7 clean: session-wide measurement still written separately (session.json), not in the case records",
      lambda: c["session"] is not None and not any(r["test"].startswith("SESSION") for r in c["result"]["results"]))
    t("S8 clean: QEMU exit, tap0 stop/drop statistics, cleanup and capture-liveness records present and ok",
      lambda: all(any(r["test"].startswith(p) and r["ok"] for r in c["result"]["results"]) for p in (
          "QEMU exit confirmed", "tap0 capture stopped cleanly", "tap0 capture drop statistics",
          "fixture, marker and temporary guest disk removed", "capture liveness traffic from the worker before",
          "capture liveness traffic from the worker after", "tap0 MAC unchanged")))
    t("S9 imports in the fake container came only from the files run-06b4f.sh mounts",
      lambda: all(p and os.path.dirname(p) == os.path.join(c["dir"], "harness") for p in c["modules"].values())
      and {"icmp_harness.py", "icmp_cases.py", "l2frames.py", "l2eval.py", "signatures.py"} <= set(c["mounted"]))

    for n, why in (("missing-case", "case(s) missing"), ("duplicate-case", "more than once")):
        x = g(n)
        t(f"S10 {n}: never PASS; outcome FAIL with the record problem; script FAIL",
          lambda x=x, why=why: x["outcome"].startswith("FAIL") and why in x["outcome"] and x["script"] == "FAIL"
          and any(r["test"].startswith("ICMP group record") and not r["ok"] for r in x["result"]["results"]))
    x = g("missing-case")
    t("S11 missing-case: the executed cases themselves pass, the group still does not",
      lambda: all(v == "DAT_KIEM_QUY_TAC" for v in cats(x).values() if v) and x["outcome"] != "PASS")

    for n, sent, why in (("marker-after-B4", 3, "host capture lost"), ("heartbeat-stale-after-B1", 1, "heartbeat"),
                         ("tshark-exit-after-I1", 4, "tap0 tshark exited")):
        x = g(n)
        t(f"S12 {n}: exit 98, CAPTURE LOST, only {sent} ping(s) reached the guest, no service link after",
          lambda x=x, sent=sent, why=why: x["rc"] == 98 and x["result"]["status"].startswith("CAPTURE LOST")
          and why in x["result"]["status"] and len(pings(x)) == sent
          and sum("get-task" in y for _, y in x["commands"]) == 1)
        t(f"S13 {n}: outcome FAIL, script FAIL, no evaluation (no case judged)",
          lambda x=x: x["outcome"].startswith("FAIL") and x["script"] == "FAIL" and x["eval"] is None)
        t(f"S14 {n}: QEMU shut down and cleanup still done after the stop",
          lambda x=x: all(any(r["test"].startswith(p) and r["ok"] for r in x["result"]["results"])
                          for p in ("QEMU exit confirmed", "fixture, marker and temporary guest disk removed")))
        t(f"S15 {n}: group record kept with the stop reason",
          lambda x=x: x["group"] is not None and x["group"].get("stopped"))
    x = g("leak-after-B2")
    t("S16 leak after T12-B2: exit 99, LEAK, no further ping, leak record, outcome FAIL",
      lambda: x["rc"] == 99 and x["result"]["status"].startswith("LEAK") and len(pings(x)) == 2
      and "NO probe packet seen on host interfaces (leak monitor)" in failed_tests(x) and x["script"] == "FAIL")

    x = g("ping6-missing")
    t("S17 ping6 missing (rc 127): T13 cases LOI_THUC_THI, T12 cases still ĐẠT; outcome UNVERIFIED, never PASS",
      lambda: cats(x) == {"T12-B1": "DAT_KIEM_QUY_TAC", "T12-B2": "DAT_KIEM_QUY_TAC", "T12-B4": "DAT_KIEM_QUY_TAC",
                          "T13-I1": "LOI_THUC_THI", "T13-I2": "LOI_THUC_THI"}
      and x["outcome"].startswith("UNVERIFIED") and x["rc"] == 1)
    t("S18 ping6 missing: the run script reports UNVERIFIED (not PASS, not a silent pass)", lambda: x["script"] == "UNVERIFIED")
    x = g("timeout-B2")
    t("S19 console timeout on T12-B2: LOI_THUC_THI (timeout is not evidence of blocking); later cases still run",
      lambda: cats(x)["T12-B2"] == "LOI_THUC_THI" and len(pings(x)) == 5 and cats(x)["T13-I2"] == "DAT_KIEM_QUY_TAC"
      and x["outcome"].startswith("UNVERIFIED"))
    x = g("no-packet-B1")
    t("S20 broadcast refused locally (no frame): KHONG_TAO_DUOC_GOI, never ĐẠT; outcome UNVERIFIED",
      lambda: cats(x)["T12-B1"] == "KHONG_TAO_DUOC_GOI" and x["outcome"].startswith("UNVERIFIED") and x["script"] == "UNVERIFIED")
    x = g("counter-read-error-B4")
    t("S21 counter read error on 'T12-B4 after': LOI_PHEP_DO, outcome FAIL (measurement error is never a pass)",
      lambda: cats(x)["T12-B4"] == "LOI_PHEP_DO" and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("mismatch-B4")
    t("S22 counter not incremented for T12-B4: FAIL", lambda: cats(x)["T12-B4"] == "FAIL" and x["outcome"].startswith("FAIL"))
    x = g("reply-I1")
    t("S23 a frame towards the guest during T13-I1: FAIL", lambda: cats(x)["T13-I1"] == "FAIL" and x["script"] == "FAIL")

    x = g("link-before-http000")
    t("S24 service link before fails: no ping sent, all cases CHƯA KIỂM CHỨNG, outcome FAIL",
      lambda: pings(x) == [] and set(cats(x).values()) == {"CHUA_KIEM_CHUNG"} and x["outcome"].startswith("FAIL")
      and any(r["test"].startswith("allowed service link before") and not r["ok"] for r in x["result"]["results"]))
    for n in ("link-after-bad-hash", "link-after-stale-file"):
        x = g(n)
        t(f"S25 {n}: link after not intact (HTTP code and hash both required): no case ĐẠT, outcome FAIL",
          lambda x=x: "DAT_KIEM_QUY_TAC" not in cats(x).values() and x["outcome"].startswith("FAIL")
          and any(r["test"].startswith("allowed service link after") and not r["ok"] for r in x["result"]["results"]))

    for n, rec in (("tap0-drops", "tap0 capture drop statistics"), ("qemu-not-exiting", "QEMU exit confirmed"),
                   ("cleanup-marker-left", "fixture, marker and temporary guest disk removed")):
        x = g(n)
        t(f"S26 {n}: every case ĐẠT, but the infrastructure check fails -> outcome FAIL, script FAIL",
          lambda x=x, rec=rec: set(cats(x).values()) == {"DAT_KIEM_QUY_TAC"} and x["outcome"].startswith("FAIL")
          and rec in x["outcome"] and x["script"] == "FAIL")
    x = g("pcap-unreadable")
    t("S27 tap0 capture unreadable: every case LOI_PHEP_DO, outcome FAIL",
      lambda: set(cats(x).values()) == {"LOI_PHEP_DO"} and x["outcome"].startswith("FAIL"))
    x = g("marker-before-B2")
    t("S33 capture lost between two cases (during the counter read): caught BEFORE the next ping, exit 98, 1 ping",
      lambda: x["rc"] == 98 and len(pings(x)) == 1 and "before guest command 'ping -c 3 -s 1202" in x["result"]["status"])
    x = g("liveness-fails")
    t("S34 capture-liveness traffic from the worker fails: every case ĐẠT, outcome FAIL",
      lambda: set(cats(x).values()) == {"DAT_KIEM_QUY_TAC"} and x["outcome"].startswith("FAIL")
      and "capture liveness traffic" in x["outcome"])
    x = g("leak-before-B2")
    t("S35 alert written during 'T12-B2 before' (read A): ping T12-B2 NOT sent, exit 99, LEAK before the command",
      lambda: x["rc"] == 99 and len(pings(x)) == 1 and x["result"]["status"].startswith("LEAK: before 'ping -c 3 -s 1202")
      and x["outcome"].startswith("FAIL") and x["script"] == "FAIL"
      and any(r["test"] == "NO probe packet seen on host interfaces (leak monitor)" and r.get("when") == "before"
              for r in x["result"]["results"]))
    t("S36 alert during read A: QEMU shut down and cleanup still done; no evaluation",
      lambda: x["eval"] is None and all(any(r["test"] == p and r["ok"] for r in x["result"]["results"])
                                        for p in ("QEMU exit confirmed", "fixture, marker and temporary guest disk removed")))
    x = g("alert-unreadable-before-B2")
    t("S37 alert file unreadable during read A: never read as 'no alert'; ping T12-B2 NOT sent, run stops (ERROR)",
      lambda: len(pings(x)) == 1 and x["rc"] == 1 and x["result"]["status"].startswith("ERROR: IsADirectoryError")
      and x["eval"] is None and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("qemu-not-exiting")
    t("S28 QEMU not exiting: no session final read (window not closed), recorded", lambda: x["session"]["verdict"] != "PASS")

    with tempfile.TemporaryDirectory(dir=tmp) as pd:
        for a in ("ARM", "MIPS"):
            os.makedirs(os.path.join(pd, a))
            shutil.copy(os.path.join(c["dir"], "out", "ARM", "icmp-eval.json"), os.path.join(pd, a))
        ev = json.load(open(os.path.join(pd, "MIPS", "icmp-eval.json")))
        ev["arch"] = "MIPS"
        json.dump(ev, open(os.path.join(pd, "MIPS", "icmp-eval.json"), "w"))
        p = subprocess.run([sys.executable, os.path.join(HERE, "icmp_harness.py"), "--run-check", pd, "ARM", "MIPS"],
                           capture_output=True, text=True)
        t("S29 run-check: ARM and MIPS each with the five cases -> exit 0", lambda: p.returncode == 0)
        os.remove(os.path.join(pd, "MIPS", "icmp-eval.json"))
        p = subprocess.run([sys.executable, os.path.join(HERE, "icmp_harness.py"), "--run-check", pd, "ARM", "MIPS"],
                           capture_output=True, text=True)
        t("S30 run-check: MIPS missing (e.g. loop stopped after ARM) -> exit 1", lambda: p.returncode == 1 and "MIPS" in p.stdout)
    p = subprocess.run([sys.executable, os.path.join(HERE, "icmp_harness.py"), "--outcome",
                        os.path.join(c["dir"], "out", "ARM", "result.json"),
                        os.path.join(c["dir"], "out", "ARM", "icmp-eval.json"), "ARM"], capture_output=True, text=True)
    t("S31 CLI --outcome on the clean scenario prints PASS", lambda: p.stdout.strip() == "PASS")
    p = subprocess.run([sys.executable, os.path.join(HERE, "icmp_harness.py"), "--outcome",
                        os.path.join(c["dir"], "out", "ARM", "result.json"),
                        os.path.join(c["dir"], "out", "ARM", "icmp-eval.json"), "MIPS"], capture_output=True, text=True)
    t("S32 CLI --outcome with the wrong architecture -> FAIL", lambda: p.stdout.startswith("FAIL"))
    try:
        sec_R(c, tmp)
    except Exception:
        t("R-INFRA section crashed", lambda: False)
        traceback.print_exc()


# ------------------------------------------------------------------ R. 06B-4FR: required infrastructure records
def sec_R(c, tmp):
    """P2 on the REAL clean output of probe_matrix.main(): records removed, duplicated, retyped or failed,
    judged by icmp_harness.arch_outcome() and by the CLI that run-06b4f.sh calls."""
    import icmp_harness as H
    res0 = json.load(open(os.path.join(c["dir"], "out", "ARM", "result.json")))
    ev = json.load(open(os.path.join(c["dir"], "out", "ARM", "icmp-eval.json")))
    names = collections.Counter(r["test"] for r in res0["results"])
    other = sorted(n for n in names if n not in H.REQUIRED_RECORDS and not n.startswith("info: ")
                   and not n.startswith("probe T1"))
    t("R1 every required confirmation is recorded exactly once by the real ICMP path (clean run)",
      lambda: all(names[n] == 1 for n in H.REQUIRED_RECORDS))
    t("R2 the real ICMP path records no other non-info, non-case check outside the required list", lambda: other == [])
    A = lambda r: H.arch_outcome(r, ev, "ARM")

    def without(pred):
        r = copy.deepcopy(res0)
        r["results"] = [x for x in r["results"] if not pred(x)]
        return r

    def edit(name, **kw):
        r = copy.deepcopy(res0)
        for x in r["results"]:
            if x["test"] == name:
                x.update(kw)
        return r

    def cli(r):
        f = os.path.join(tmp, "R-result.json")
        json.dump(r, open(f, "w"))
        e = os.path.join(c["dir"], "out", "ARM", "icmp-eval.json")
        return subprocess.run([sys.executable, os.path.join(HERE, "icmp_harness.py"), "--outcome", f, e, "ARM"],
                              capture_output=True, text=True).stdout.strip()
    t("R3 clean real output -> PASS (arch_outcome and CLI); case labels unchanged",
      lambda: A(res0) == "PASS" and cli(res0) == "PASS"
      and {x["verdict"] for x in ev["cases"]} == {"ĐẠT (kiểm quy tắc)"})
    for i, n in enumerate(H.REQUIRED_RECORDS):
        t(f"R4.{i + 1} required confirmation missing -> FAIL: {n[:60]}",
          lambda n=n: A(without(lambda x: x["test"] == n)).startswith("FAIL: required confirmation missing: " + n[:20]))
    allinfra = without(lambda x: x["test"] in H.REQUIRED_RECORDS)
    t("R5 every required confirmation missing (only info and case records left) -> FAIL, all listed (CLI)",
      lambda: cli(allinfra).startswith("FAIL") and all(n in A(allinfra) for n in H.REQUIRED_RECORDS))
    t("R6 no record at all -> FAIL", lambda: cli(without(lambda x: True)).startswith("FAIL"))
    for n in ("QEMU exit confirmed", "tap0 capture stopped cleanly", "fixture, marker and temporary guest disk removed"):
        r = copy.deepcopy(res0)
        r["results"].append({"test": n, "ok": True})
        t(f"R7 required confirmation recorded twice (both ok) -> FAIL (CLI): {n}",
          lambda r=r, n=n: cli(r).startswith("FAIL") and f"recorded 2 times: {n}" in A(r))
    for v in ("true", 1, None, [], {"ok": True}):
        t(f"R8 'ok' of a required confirmation is {v!r} (not a boolean) -> FAIL (CLI)",
          lambda v=v: cli(edit("QEMU exit confirmed", ok=v)).startswith("FAIL")
          and "boolean" in A(edit("QEMU exit confirmed", ok=v)))
    r = copy.deepcopy(res0)
    del [x for x in r["results"] if x["test"] == "tap0 capture stopped cleanly"][0]["ok"]
    t("R9 'ok' key missing on a required confirmation -> FAIL (never a default success)",
      lambda: cli(r).startswith("FAIL") and "boolean" in A(r))
    r = copy.deepcopy(res0)
    [x for x in r["results"] if x["test"] == "QEMU exit confirmed"][0]["test"] = ["QEMU exit confirmed"]
    t("R10 'test' not a string -> FAIL", lambda: cli(r).startswith("FAIL"))
    r = copy.deepcopy(res0)
    r["results"].insert(3, "QEMU exit confirmed")
    t("R11 a record that is not an object -> FAIL", lambda: cli(r).startswith("FAIL"))
    t("R12 each required confirmation with ok=False -> FAIL (named as not passed)",
      lambda: all(A(edit(n, ok=False)).startswith("FAIL") and f"not passed (ok=False): {n}" in A(edit(n, ok=False))
                  for n in H.REQUIRED_RECORDS))
    rr = edit("tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped", ok=False)
    t("R13 all five cases ĐẠT (kiểm quy tắc) do not hide a failed confirmation; labels unchanged",
      lambda: A(rr).startswith("FAIL") and all(x["ok"] for x in rr["results"] if x["test"].startswith("probe T1")))


# ------------------------------------------------------------------ U. icmp_harness units
class G:
    def __init__(self, fail=None):
        self.got, self.fail = [], fail

    def run(self, cmd, timeout=60):
        self.got.append(cmd)
        if self.fail:
            raise self.fail
        return 0, "ok"


def sec_U():
    import icmp_harness as H
    import icmp_cases as I
    sha = "a" * 64
    P = H.parse_service_link
    t("U1 link: HTTP 200 + right hash + rc 0 -> ok", lambda: P(0, f"HTTP=200\n{sha}  /tmp/r.out\n", sha)[0] is True)
    t("U2 link: HTTP 000 with the right hash (stale file) -> not ok", lambda: P(0, f"HTTP=000\n{sha}  /tmp/r.out", sha)[0] is False)
    t("U3 link: HTTP 200, other hash -> not ok", lambda: P(0, "HTTP=200\n" + "b" * 64 + "  /tmp/r.out", sha)[0] is False)
    t("U4 link: HTTP 200, no hash line -> not ok", lambda: P(0, "HTTP=200\nsha256sum: /tmp/r.out: No such file", sha)[0] is False)
    t("U5 link: two HTTP lines -> not ok", lambda: P(0, f"HTTP=200\nHTTP=200\n{sha}  /tmp/r.out", sha)[0] is False)
    t("U6 link: rc != 0 -> not ok", lambda: P(1, f"HTTP=200\n{sha}  /tmp/r.out", sha)[0] is False)
    t("U7 link: HTTP=2000 is not 200", lambda: P(0, f"HTTP=2000\n{sha}  /tmp/r.out", sha)[0] is False)
    t("U8 link: CRLF console output parsed; detail has code and hash",
      lambda: P(0, f"HTTP=200\r\n{sha}  /tmp/r.out\r\n", sha) == (True, {"rc": 0, "http_code": "200", "sha256": sha,
                                                                        "expected_sha256": sha,
                                                                        "output_tail": f"HTTP=200\r\n{sha}  /tmp/r.out"}))
    t("U9 link command removes the old response first and asks for code + hash",
      lambda: H.link_command("http://10.200.0.1:8011/b", "T").startswith("rm -f /tmp/r.out; curl ")
      and "HTTP=%{http_code}" in H.link_command("u", "T") and H.link_command("u", "T").endswith("sha256sum /tmp/r.out"))
    t("U10 link_valid needs ok True, code 200 and hash == fixture",
      lambda: H.link_valid({"ok": True, "detail": {"http_code": "200", "sha256": sha, "expected_sha256": sha}}, sha)
      and not H.link_valid({"ok": True, "detail": {"http_code": "200", "sha256": "b" * 64, "expected_sha256": sha}}, sha)
      and not H.link_valid({"ok": True, "detail": "HTTP=200"}, sha)
      and not H.link_valid({"ok": "true", "detail": {"http_code": "200", "sha256": sha, "expected_sha256": sha}}, sha)
      and not H.link_valid({"ok": True, "detail": {"http_code": "200", "sha256": sha, "expected_sha256": sha}}, None))

    calls = []

    def bad_before(cmd):
        calls.append(cmd)
        if len(calls) == 2:
            raise RuntimeError("capture lost")
    g = G()
    r = H.GuardedRunner(g, bad_before, lambda cmd: None)
    out = [r.run("a")]
    for cmd in ("b", "c"):
        try:
            r.run(cmd)
        except Exception as e:
            out.append(type(e).__name__)
    t("U11 GuardedRunner: a failing check stops the group; later commands never reach the guest",
      lambda: out == [(0, "ok"), "RuntimeError", "SuiteStopped"] and g.got == ["a"] and isinstance(r.stop, RuntimeError))
    g = G()
    r = H.GuardedRunner(g, lambda c: None, lambda c: (_ for _ in ()).throw(KeyError("leak")))
    try:
        r.run("a")
        res = "returned"
    except KeyError:
        res = "raised"
    t("U12 GuardedRunner: a failing after-check raises even though the command ran, and stops the group",
      lambda: res == "raised" and g.got == ["a"] and isinstance(r.stop, KeyError))
    g = G(fail=TIMEOUT("t"))
    r = H.GuardedRunner(g, lambda c: None, lambda c: None)
    try:
        r.run("a")
    except TIMEOUT:
        pass
    t("U13 GuardedRunner: a guest timeout is an execution error of that command, not a stop", lambda: r.stop is None)

    # run_suite with fakes: complete record, labels and commands from the reviewed cases
    reads = []

    class GG:
        def run(self, cmd, timeout=60):
            return (1, "0 received")
    rr = H.GuardedRunner(GG(), lambda c: None, lambda c: None)
    rec = H.run_suite(rr, reads.append, lambda: (True, {"http_code": "200", "sha256": sha, "expected_sha256": sha}),
                      TAP, "eth1", "ARM", sha)
    t("U14 run_suite: five cases in order, 10 counter reads, links recorded, annotated (arch, TAP, hash, rule_check)",
      lambda: [c["id"] for c in rec["cases"]] == list(I.CASE_IDS) and len(reads) == 10
      and (rec["arch"], rec["tap_mac"], rec["fixture_sha256"], rec["evidence_kind"]) == ("ARM", TAP, sha, "rule_check")
      and H.check_record(rec, "ARM", TAP, sha) == [])
    t("U15 check_record: wrong architecture", lambda: any("arch" in p for p in H.check_record(rec, "MIPS", TAP, sha)))
    r2 = copy.deepcopy(rec)
    r2["cases"].pop(1)
    t("U16 check_record: a missing case", lambda: any("missing: ['T12-B2']" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    r2 = copy.deepcopy(rec)
    r2["cases"].append(copy.deepcopy(r2["cases"][0]))
    t("U17 check_record: a duplicate case", lambda: any("more than once: ['T12-B1']" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    r2 = copy.deepcopy(rec)
    r2["cases"][2]["id"] = "T12-B3"
    t("U18 check_record: an unknown case id (and the missing one)",
      lambda: {"unknown", "missing"} <= {w for p in H.check_record(r2, "ARM", TAP, sha) for w in ("unknown", "missing") if w in p})
    r2 = copy.deepcopy(rec)
    r2["cases"][0]["command"] = r2["cases"][0]["command"].replace("-s 1201", "-s 1200")
    t("U19 check_record: a command that is not the reviewed one", lambda: any("T12-B1: command" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    r2 = copy.deepcopy(rec)
    r2["cases"][3]["after"] = "T13-I1 later"
    t("U20 check_record: counter labels not the reviewed ones", lambda: any("labels" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    r2 = copy.deepcopy(rec)
    r2["service_link_after"] = {"ok": True, "detail": {"http_code": "200", "sha256": "c" * 64, "expected_sha256": sha}}
    t("U21 check_record: link after with another hash", lambda: any("service_link_after" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    t("U22 check_record: invalid record types are problems, never exceptions",
      lambda: H.check_record([], "ARM", TAP, sha) and H.check_record({"arch": "ARM", "cases": "x"}, "ARM", TAP, sha)
      and H.check_record({"arch": "ARM", "cases": [1]}, "ARM", TAP, sha))
    r2 = copy.deepcopy(rec)
    r2["stopped"] = "CaptureLost: x"
    t("U23 check_record: a stopped group", lambda: any("stopped" in p for p in H.check_record(r2, "ARM", TAP, sha)))
    ev = H.evaluate("/nonexistent.pcapng", "/nonexistent.jsonl", TAP, {"arch": "ARM", "cases": "x"}, "ARM", sha)
    t("U24 evaluate: a record evaluate_group refuses -> no case, record problem, never raises",
      lambda: ev["cases"] == [] and ev["group_complete"] is False and any("refused" in p for p in ev["record_problems"]))

    ok_cases = [{"id": i, "category": "DAT_KIEM_QUY_TAC", "verdict": "ĐẠT (kiểm quy tắc)", "ok": True} for i in I.CASE_IDS]
    good_ev = {"arch": "ARM", "record_problems": [], "group_complete": True, "cases": ok_cases}
    infra = [{"test": n, "ok": True} for n in H.REQUIRED_RECORDS]   # 06B-4FR: every required confirmation
    n0 = len(infra)                                                   # index of the first case record
    good_res = {"status": "COMPLETED", "results": infra + [{"test": H.case_test_name(c), "ok": True} for c in ok_cases]}
    A = H.arch_outcome
    t("U25 arch_outcome: complete, all ok -> PASS", lambda: A(good_res, good_ev, "ARM") == "PASS")
    bad = copy.deepcopy(good_res)
    bad["results"][0]["ok"] = False
    t("U26 arch_outcome: all cases ĐẠT but an infrastructure check failed -> FAIL", lambda: A(bad, good_ev, "ARM").startswith("FAIL"))
    bad = copy.deepcopy(good_res)
    bad["status"] = "CAPTURE LOST: x"
    t("U27 arch_outcome: status not COMPLETED -> FAIL", lambda: A(bad, good_ev, "ARM").startswith("FAIL"))
    t("U28 arch_outcome: evaluation missing -> FAIL", lambda: A(good_res, None, "ARM").startswith("FAIL"))
    e2 = copy.deepcopy(good_ev)
    e2["cases"].pop()
    t("U29 arch_outcome: a case missing in the evaluation -> FAIL", lambda: A(good_res, e2, "ARM").startswith("FAIL"))
    e2 = copy.deepcopy(good_ev)
    e2["cases"].append(copy.deepcopy(e2["cases"][0]))
    t("U30 arch_outcome: a case twice in the evaluation -> FAIL", lambda: A(good_res, e2, "ARM").startswith("FAIL"))
    r3 = copy.deepcopy(good_res)
    r3["results"].append(copy.deepcopy(r3["results"][n0]))
    t("U31 arch_outcome: a case recorded twice in result.json -> FAIL", lambda: A(r3, good_ev, "ARM").startswith("FAIL"))
    r3 = copy.deepcopy(good_res)
    r3["results"].pop()
    t("U32 arch_outcome: a case not recorded in result.json -> FAIL", lambda: A(r3, good_ev, "ARM").startswith("FAIL"))
    e2 = copy.deepcopy(good_ev)
    e2["record_problems"] = ["service_link_after: not HTTP 200 with the fixture hash"]
    t("U33 arch_outcome: record problem -> FAIL", lambda: A(good_res, e2, "ARM").startswith("FAIL"))
    t("U34 arch_outcome: evaluation of another architecture -> FAIL", lambda: A(good_res, good_ev, "MIPS").startswith("FAIL"))
    t("U35 arch_outcome: result.json unreadable -> FAIL", lambda: A(None, good_ev, "ARM").startswith("FAIL"))
    e2, r3 = copy.deepcopy(good_ev), copy.deepcopy(good_res)
    e2["cases"][0].update(category="KHONG_TAO_DUOC_GOI", ok=False,
                          verdict="CHƯA KIỂM CHỨNG (không tạo được gói probe; ping rc 2 không phải bằng chứng chặn)")
    r3["results"][n0] = {"test": H.case_test_name(e2["cases"][0]), "ok": False}
    t("U36 arch_outcome: one case not judged, all else fine -> UNVERIFIED", lambda: A(r3, e2, "ARM").startswith("UNVERIFIED"))
    t("U37 run_check: same architecture twice is a problem", lambda: H.run_check("/nonexistent", ["ARM", "ARM"]))
    with contextlib.redirect_stderr(io.StringIO()):
        t("U38 CLI: bad usage -> exit 2", lambda: H.main(["--nope"]) == 2)


# ------------------------------------------------------------------ W. run script
def sec_W():
    p = os.path.join(HERE, "run-06b4f.sh")
    s = open(p).read()
    t("W1 bash -n run-06b4f.sh", lambda: subprocess.run(["bash", "-n", p]).returncode == 0)
    t("W2 H points to the 06B-4FR working copy", lambda: "\nH=/home/dathq/projects/ct01-06b4fr\n" in s)
    calls = [l for l in s.splitlines() if "probe_matrix.py $ARCH" in l]
    t("W3 exactly one probe_matrix call, with CT01_SUITE=icmp", lambda: len(calls) == 1 and "-e CT01_SUITE=icmp " in calls[0])
    first_docker = min(i for i in (s.find("\ndocker "), s.find("$(docker "), s.find(" docker ")) if i >= 0)

    def runs_before_docker(name):
        line = (f'python3 "$H/{name}" > "$OUT/{name[:-3].replace("_", "-")}.txt" 2>&1 || '
                f'{{ cat "$OUT/{name[:-3].replace("_", "-")}.txt"; echo "ABORT: ')
        return s.count("\n" + line) == 1 and s.index("\n" + line) < first_docker and \
            s[s.index("\n" + line):].split("\n")[1].endswith("exit 3; }")
    t("W4 self-tests (incl. ICMP + wiring) run before any docker command and abort the run if they fail",
      lambda: runs_before_docker("selftest_icmp.py") and runs_before_docker("selftest_icmp_wiring.py"))
    t("W5 every module probe_matrix imports in icmp mode is mounted read-only",
      lambda: {"icmp_harness.py", "icmp_cases.py", "l2frames.py", "l2eval.py", "signatures.py", "counter_window.py",
               "pcapng_stats.py", "probe_matrix.py"} <= set(mounted_files(p)))
    t("W6 per-architecture outcome comes from icmp_harness --outcome; run-check after the loop",
      lambda: '"$H/icmp_harness.py" --outcome' in s and s.index('"$H/icmp_harness.py" --run-check') > s.index("\nfor ARCH in ARM MIPS; do"))
    old = open(os.path.join(HERE, "run-06b3b.sh")).read().splitlines()
    new = s.splitlines()
    import difflib
    removed = [l[1:] for l in difflib.unified_diff(old, new, lineterm="", n=0)
               if l.startswith("-") and not l.startswith("---")]
    t("W7 compared with run-06b3b.sh only the H path, the copy list end, the probe_matrix call and the outcome "
      "line are replaced (nothing else removed)",
      lambda: removed == ["H=/home/dathq/projects/ct01-06b4b",
                          '    "$H/selftest_l2.py" "$H/mutation_l2.py" "$OUT/harness-copy/"',
                          '    timeout 1700 docker exec -e CT01_TARGETS="$TARGETS" "$ID" sh -c "cd /app && python3 /harness/probe_matrix.py $ARCH /harness-out"',
                          "    outcome=$(python3 -c 'import json, sys; sys.path.insert(0, sys.argv[1]); import counter_window as cw",
                          'print(cw.run_outcome(json.load(open(sys.argv[2]))["results"]))\' "$H" "$D/probe/$ARCH/result.json" 2>&1)'])
    t("W8 run-06b3b.sh (IPv4 matrix) itself is unchanged from 06B-4E (SHA-256 of the 06B-4B/4E copy)",
      lambda: hashlib.sha256(open(os.path.join(HERE, "run-06b3b.sh"), "rb").read()).hexdigest() ==
      "c83273d646a9f3e14ad8976b31dbe71ecf8075c1e40ad97810921eb6181a34a6")


def main(argv):
    if argv[:1] == ["--scenario"]:
        return scenario_main(argv[1], argv[argv.index("--dir") + 1])
    sys.path.insert(0, HERE)
    jpath = argv[argv.index("--json") + 1] if "--json" in argv else None
    if os.path.exists("/app"):
        print("SELFTEST-ERROR: /app exists on this host: the stub worker modules would be shadowed")
        return 3
    with tempfile.TemporaryDirectory(prefix="selftest-icmp-wiring.") as tmp:
        for name, fn in (("U", sec_U), ("S", lambda: sec_S(tmp)), ("W", sec_W)):
            print(f"== section {name}")
            try:
                fn()
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    if jpath:
        json.dump(RESULTS, open(jpath, "w"), indent=0, sort_keys=True)
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"SELFTEST-ICMP-WIRING: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed" + ("" if not bad else f"; FAILED: {bad}"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
