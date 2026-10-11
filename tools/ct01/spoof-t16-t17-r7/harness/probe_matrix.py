"""06B-3B: IPv4 block matrix from a REAL guest (one architecture per run), with controls.

Runs inside the throwaway worker test container (docker exec), from /app, after the real
run.sh (V0) with the real server.py and a sentinel poller. Reuses the real QEMU code
path (ARCH_CONFIGS, Analysis._start_qemu / _configure_network, shutdown_qemu). Only the
stock OS image and the guest's own curl / busybox tools are used; no ELF, no sample,
no dynamic_analysis. Only the listed IP/port pairs are probed (no scanning).

For every probe:  control-before -> guest probe -> control-after, nft counters before and
after, then (after the capture is stopped) every guest frame in the probe window is
classified with the same logic as the inet ruleset and compared with the counter deltas
(retransmissions and background traffic included). After each probe the host-side leak
alert file (/hostcap/alert.txt, tcpdump on all host interfaces for 10.200.0.0/30) must be
empty; otherwise every test stops immediately (exit 99).

06B-3C/3CR: before boot and before/after every probe the tap0 tshark must still run, the host
capture watcher marker (/hostcap/capture-dead.txt) must be empty and its heartbeat
(/hostcap/capture-watch.heartbeat) fresh; otherwise the probes stop (exit 98). tshark must exit 0,
and the drop statistics are taken from the pcapng interface statistics block (pcapng_stats.py):
missing statistics are a failed check, not "0 dropped".

06B-3DR: every nft counter read records the start and end of the call (raw JSON kept in
counters-raw.jsonl). counter_window.py splits the pcap into a certain zone between the two reads
and two ambiguous edge zones; any edge frame of a compared class makes the reconciliation
UNVERIFIED (CHƯA KIỂM CHỨNG), a delta outside [certain, certain + edges] is FAIL, and only an
unambiguous exact match passes. Nothing is widened or compensated.

06B-4F: CT01_SUITE=icmp runs, instead of the 20 IPv4 probes, ONLY the five reviewed ICMP cases of
icmp_cases.py (T12-B1, T12-B2, T12-B4, T13-I1, T13-I2) through icmp_harness.py, with the same boot,
topology gate, tap0 capture, host capture/heartbeat/alert checks, counter reads, session measurement,
QEMU shutdown and cleanup. Without CT01_SUITE (or "ipv4") nothing changes.
06B-4FR: the leak alerts are also checked before every guest command of the ICMP group.
06B-4I: CT01_SUITE=arp runs, instead of the 20 IPv4 probes, ONLY the four reviewed ARP cases of arp_cases.py
(T14-A1, T14-A2, T14-A3, T15-S1) through arp_harness.py: same boot, topology gate, captures, guard (alerts and
captures/heartbeat before AND after every guest command, guest_state snapshot/restore included), counter reads,
session measurement, QEMU shutdown and cleanup; plus the worker neighbour collector (ip -j neigh show in this
netns) and the live controls of T14-A1/A2. Prepared and tested offline only. (Corrected in 06B-4IR1: in 06B-4I the
guard covered only the ARP group's guest commands; the boot network configuration and the topology gate were not
guarded.)
06B-4IR1 (all suites): a startup guard (StartupGuard + GuardedConsole, local adapters; service/analysis.py is not
changed) covers the guest operations between QEMU boot and the end of the topology gate: every keystroke/command
sent by Analysis._configure_network and by the topology commands, Guest.monitor included, is preceded by a check
(leak alerts, then captures/heartbeat), and every wait for the guest's answer is followed by one. The first failure
latches: nothing more is sent to the guest; QEMU shutdown (raw console) and cleanup are unchanged.
06B-4IR2 (corrects 06B-4IR1, which disarmed the guard right after the topology gate, leaving the IPv4 service link
unguarded): the guard is handed over only to a guarded branch. ICMP/ARP disarm it right before run_icmp/run_arp
(GuardedRunner on every guest command); the IPv4 branch keeps it armed (phase "ipv4 group") and sends every service
link and probe through it, so every IPv4 guest command is checked before and after as well.
"""
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import http.client
import http.server

import pcapng_stats   # /harness/pcapng_stats.py, next to this script (06B-3CR)
import counter_window   # /harness/counter_window.py (06B-3DR)
from zipfile import ZipFile

sys.path.insert(0, "/app")
from isolation import constants as C                      # noqa: E402
from isolation import current_task                        # noqa: E402
from isolation.verify import verify_isolation             # noqa: E402
from service import analysis as A                         # noqa: E402

ARCH = sys.argv[1]
OUT = os.path.join(sys.argv[2], ARCH)
CFG = json.loads(os.environ["CT01_TARGETS"])   # worker_ip, mongo_ip, manager_ip, ssh_ips, lan_dns
BASE = "/api/v1/sandbox-worker"
URL = f"http://{C.WORKER_GUEST_IP}:{C.SVC_PORT}{BASE}"
T = f"06b3b-{ARCH.lower()}-task"
DATA = "/app/data/"
WORK = f"/tmp/g-{ARCH}"
PCAP = os.path.join(OUT, "tap0.pcapng")
ALERT = "/hostcap/alert.txt"
CAPTURE_DEAD = "/hostcap/capture-dead.txt"   # written by the host capture watcher (06B-3C)
HEARTBEAT = "/hostcap/capture-watch.heartbeat"   # epoch time, refreshed every 1 s by the watcher (06B-3CR)
HEARTBEAT_MAX_AGE = 5.0
CTL = "/ctl/ctl.jsonl"
LISTENER_PORT = 18080
SESSION_SETTLE_S = 0.5      # 06B-3F: wait before each final session read after QEMU exit (bounded)
SESSION_FINAL_READS = 2     # all kept; the first closes the session window, the rest check stability
DEADLINE_S = 1500
PRIVATE = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                                             "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")]
MCAST = ipaddress.ip_network("224.0.0.0/4")
CLASSES = ["allow_svc", "drop_spoof", "drop_non_ipv4", "drop_worker_other", "drop_private",
           "drop_bcast_mcast", "drop_public", "l2_bad_ethertype", "l2_bad_mac"]

SUITE = os.environ.get("CT01_SUITE", "ipv4")   # 06B-4F
if SUITE not in ("ipv4", "icmp", "arp"):
    sys.exit(f"unknown CT01_SUITE {SUITE!r}")
if SUITE == "icmp":
    import icmp_harness                         # /harness/icmp_harness.py (+ icmp_cases, l2frames, l2eval)
if SUITE == "arp":
    import arp_harness                          # /harness/arp_harness.py (+ arp_cases, guest_state, icmp_harness ...)
SYS_NET = "/sys/class/net"                      # 06B-4F: tap0 MAC (read only)
ICMP = {}                                       # 06B-4F: group record, TAP MAC and fixture hash for evaluate_icmp()
ARP = {}                                        # 06B-4I: the same for evaluate_arp()

os.makedirs(OUT, exist_ok=True)
results, probes = [], []
session = {}   # 06B-3F session-wide measurement; never part of `results`
log_f = open(os.path.join(OUT, "probe.log"), "w")


class LeakDetected(Exception):
    pass


class CaptureLost(Exception):
    pass


def captures_alive(tshark, where):
    """06B-3C/3CR: stop the probes (CaptureLost) unless the tap0 tshark runs, the host capture
    marker is absent or empty, and the host watcher heartbeat exists and is fresh. A dead watcher
    stops the probes even while every capture is still running."""
    if tshark is None or tshark.poll() is not None:
        raise CaptureLost(f"{where}: tap0 tshark exited rc={tshark and tshark.returncode}")
    try:
        dead = open(CAPTURE_DEAD).read().strip()
    except FileNotFoundError:
        dead = ""
    except OSError as e:
        raise CaptureLost(f"{where}: host capture marker unreadable: {e}")
    if dead:
        raise CaptureLost(f"{where}: host capture lost: {dead}")
    try:
        hb = float(open(HEARTBEAT).read().strip())
    except FileNotFoundError:
        raise CaptureLost(f"{where}: host watcher heartbeat missing (watcher not running)")
    except (OSError, ValueError) as e:
        raise CaptureLost(f"{where}: host watcher heartbeat unreadable: {e}")
    age = time.time() - hb
    if not -1.0 <= age <= HEARTBEAT_MAX_AGE:
        raise CaptureLost(f"{where}: host watcher heartbeat is {age:.1f} s old (limit {HEARTBEAT_MAX_AGE} s)")


def say(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    log_f.write(line + "\n")
    log_f.flush()


def record(name, ok, **detail):
    results.append({"arch": ARCH, "test": name, "ok": bool(ok), **detail})
    say(f"[{'PASS' if ok else 'FAIL'}] {ARCH}: {name} {json.dumps(detail, sort_keys=True, default=str)}")


def run_checked(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"command failed rc={r.returncode}: {' '.join(cmd)}: {r.stderr.strip()[:300]}")
    return r.stdout


PROC_ROOT = "/proc"   # 06B-3FR1: module-level so that the offline test can point qemu_pids() at a fake tree


class ProcessScanError(Exception):
    """The QEMU process state could not be verified."""


def qemu_pids():
    """06B-3F/3FR1: pids of qemu-system* processes visible in this container.
    A pid that vanished between listing and reading (comm gone AND /proc/<pid> gone) is skipped.
    Anything else that prevents reading (PermissionError, I/O errors, comm missing while the pid
    directory still exists, /proc not listable) raises ProcessScanError: never treated as "no QEMU"."""
    try:
        entries = os.listdir(PROC_ROOT)
    except OSError as e:
        raise ProcessScanError(f"cannot list {PROC_ROOT}: {type(e).__name__}: {e}")
    pids = []
    for d in entries:
        if not d.isdigit():
            continue
        path = f"{PROC_ROOT}/{d}/comm"
        try:
            with open(path) as f:
                comm = f.read()
        except (FileNotFoundError, ProcessLookupError) as e:
            if os.path.exists(f"{PROC_ROOT}/{d}"):
                raise ProcessScanError(f"{path} unreadable although the pid directory exists: "
                                       f"{type(e).__name__}: {e}")
            continue   # the process exited between listing and reading
        except OSError as e:
            raise ProcessScanError(f"cannot read {path}: {type(e).__name__}: {e}")
        if comm.startswith("qemu-system"):
            pids.append(int(d))
    return pids


def record_qemu_scan(when):
    """06B-3FR1: scan the QEMU process state into `session` ("before" or "after_exit").
    On a scan error the pid list is None and the error is kept; the caller continues (cleanup in
    `finally` keeps running) and session_reconcile() turns it into ERROR."""
    try:
        pids, err = qemu_pids(), None
    except Exception as e:   # ProcessScanError or anything unexpected: unverified, never "no QEMU"
        pids, err = None, f"{type(e).__name__}: {e}"
    session[f"qemu_pids_{when}"] = pids
    session[f"qemu_pids_{when}_error"] = err
    if when == "before":
        session["no_qemu_before"] = pids == []
    return pids, err


def counters_read(label):
    """06B-3DR: one nft counter read with the wall-clock start/end of the call. The raw JSON is kept
    in counters-raw.jsonl; the snapshot happened somewhere between t_start and t_end."""
    t_start = time.time()
    raw = run_checked(["nft", "-j", "list", "counters"])
    t_end = time.time()
    with open(os.path.join(OUT, "counters-raw.jsonl"), "a") as f:
        f.write(json.dumps({"label": label, "t_start": t_start, "t_end": t_end, "raw": raw}) + "\n")
    values = {o["counter"]["name"]: o["counter"]["packets"] for o in json.loads(raw)["nftables"] if "counter" in o}
    return {"label": label, "t_start": t_start, "t_end": t_end, "values": values}


def alert_lines():
    try:
        return [l for l in open(ALERT).read().splitlines() if l.strip()]
    except FileNotFoundError:
        raise RuntimeError("host alert file missing: host-side leak monitor not running")


# ------------------------------------------------------------------ 06B-4IR1: startup guard
class StartupGuard:
    """Leak alerts, then captures/heartbeat, before and after every startup guest operation (boot network
    configuration, topology gate). The first failure is kept in `stop` and re-raised by every later check, so that
    nothing more reaches the guest. A missing/unreadable alert file raises (never read as "no alert")."""

    def __init__(self, tshark):
        self.tshark, self.stop, self.armed, self.checks, self.sent = tshark, None, True, 0, []
        self.phase = "startup"     # 06B-4IR2: "ipv4 group" once the IPv4 branch has taken the guard over

    def check(self, when, what):
        if not self.armed:
            return
        if self.stop is not None:
            raise self.stop
        self.checks += 1
        try:
            found = alert_lines()
            if found:
                record("NO probe packet seen on host interfaces (leak monitor)", False, phase=self.phase, when=when,
                       operation=what, alerts=found[:5])
                raise LeakDetected(f"{self.phase}: {when} {what!r}: {len(found)} signature packet(s) seen on host "
                                   "interfaces")
            captures_alive(self.tshark, f"{self.phase}: {when} {what!r}")
        except Exception as e:
            self.stop = e
            raise

    def run(self, guest, cmd, timeout=None):
        """One guest command (topology gate; 06B-4IR2: every IPv4 service link and probe) through the guest console
        object, checked before and after."""
        self.check("before", cmd)
        self.sent.append(cmd)
        try:
            return guest.run(cmd) if timeout is None else guest.run(cmd, timeout=timeout)
        finally:
            self.check("after", cmd)

    def monitor(self, guest, command):
        self.check("before", f"monitor {command}")
        self.sent.append(f"monitor {command}")
        try:
            return guest.monitor(command)
        finally:
            self.check("after", f"monitor {command}")


class GuardedConsole:
    """Adapter around the pexpect console given to Analysis._configure_network and Guest: StartupGuard.check before
    every send/sendline and after every expect, so that an event between two commands of one function (e.g. after
    `ip addr add` and before `route add`, or between the keystrokes of Guest.monitor) stops before the next one.
    Everything else is forwarded unchanged. QEMU shutdown keeps using the raw console."""

    def __init__(self, proc, guard):
        self._proc, self._guard = proc, guard

    def send(self, s):
        self._guard.check("before", f"send {s!r}")
        self._guard.sent.append(f"send {s!r}")
        return self._proc.send(s)

    def sendline(self, s=""):
        self._guard.check("before", f"sendline {s!r}")
        self._guard.sent.append(f"sendline {s!r}")
        return self._proc.sendline(s)

    def expect(self, *a, **kw):
        try:
            return self._proc.expect(*a, **kw)
        finally:
            self._guard.check("after", "expect")

    def __getattr__(self, name):
        return getattr(self._proc, name)


# ------------------------------------------------------------------ guest console
class Guest:
    def __init__(self, proc):
        self.p, self.n = proc, 0

    def run(self, cmd, timeout=60):
        self.n += 1
        b, e = f"@@B{self.n}", f"@@E{self.n}"
        self.p.sendline(f"echo {b}; {cmd}; echo {e} rc=$?")
        self.p.expect(rf"{e} rc=(\d+)", timeout=timeout)
        rc = int(self.p.match.group(1))
        text = self.p.before.replace("\r", "")          # serial console: \r\r\n
        i = text.rfind(b + "\n")
        if i < 0:
            raise RuntimeError(f"begin marker {b} not found in guest output")
        self.p.expect("# ", timeout=timeout)
        return rc, text[i + len(b) + 1:]

    def monitor(self, command, timeout=20):
        self.p.send("\x01c")
        self.p.expect(r"\(qemu\) ", timeout=timeout)
        self.p.sendline(command)
        self.p.expect(r"\(qemu\) ", timeout=timeout)
        out = self.p.before.replace("\r", "")
        self.p.send("\x01c")
        time.sleep(0.5)
        self.p.sendline("")
        self.p.expect("# ", timeout=timeout)
        return out


def parse_info_network(text):
    """Return (entries, problems). An entry is a top-level line with its indented peer."""
    entries, problems = [], []
    ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
    for line in text.splitlines():
        line = ansi.sub("", line)
        # skip blank lines and the monitor's echo of the typed command (readline redraw)
        if not line.strip() or ("info network" in line and "type=" not in line):
            continue
        m = re.match(r"^(\s*\\\s+)?([\w.\-]+):\s+(.*)$", line)
        if not m:
            problems.append(f"unparsed line: {line!r}")
            continue
        peer, name, rest = bool(m.group(1)), m.group(2), m.group(3)
        tm = re.search(r"(?:^|,)type=([\w.\-]+)", rest)
        typ = tm.group(1) if tm else None
        if typ is None:
            problems.append(f"no type= in line: {line!r}")
        item = {"name": name, "type": typ, "raw": rest}
        if peer:
            if not entries:
                problems.append(f"peer line without parent: {line!r}")
            else:
                entries[-1]["peers"].append(item)
        else:
            item["peers"] = []
            entries.append(item)
    return entries, problems


def check_topology(entries, parse_problems):
    bad = list(parse_problems)
    all_types = [e["type"] for e in entries] + [p["type"] for e in entries for p in e["peers"]]
    for t in all_types:
        if t not in ("nic", "tap"):
            bad.append(f"backend/device type not allowed: {t}")
    taps = [p for e in entries for p in e["peers"] if p["type"] == "tap"] + [e for e in entries if e["type"] == "tap"]
    if len(taps) != 1 or not re.search(r"(?:^|,)ifname=tap0(?:,|$)", taps[0]["raw"]):
        bad.append(f"expected exactly one tap backend with ifname=tap0, got {[t['raw'] for t in taps]}")
    connected = [e for e in entries if e["peers"]]
    if len(connected) != 1:
        bad.append(f"expected exactly one NIC with a backend, got {[e['name'] for e in connected]}")
    else:
        nic = connected[0]
        if nic["type"] != "nic" or f"macaddr={C.GUEST_MAC}" not in nic["raw"]:
            bad.append(f"NIC connected to tap0 is not the pinned MAC: {nic['raw']}")
        if len(nic["peers"]) != 1 or nic["peers"][0]["type"] != "tap":
            bad.append(f"NIC peers unexpected: {nic['peers']}")
    return bad


# ------------------------------------------------------------------ controls (from the worker)
def ctl_tcp(ip, port, banner=None):
    s = socket.create_connection((ip, port), timeout=3)
    try:
        if banner:
            s.settimeout(3)
            data = s.recv(64)
            if not data.startswith(banner):
                raise RuntimeError(f"unexpected banner {data[:20]!r}")
            return f"connected, banner {data[:20]!r}"
        return "connected"
    finally:
        s.close()


def ctl_http(ip, port, path="/healthcheck"):
    c = http.client.HTTPConnection(ip, port, timeout=3)
    c.request("GET", path)
    st = c.getresponse().status
    c.close()
    if st != 200:
        raise RuntimeError(f"HTTP {st}")
    return "HTTP 200"


def ctl_dns(server, qname):
    qid = os.getpid() & 0xFFFF
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in qname.rstrip(".").split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(1500)
    finally:
        s.close()
    if struct.unpack(">H", data[:2])[0] != qid:
        raise RuntimeError("DNS id mismatch")
    return f"DNS response rcode={data[3] & 0x0F}"


def run_ctl(fn):
    t = time.time()
    try:
        return {"ts": t, "ok": True, "detail": fn()}
    except Exception as e:
        return {"ts": t, "ok": False, "detail": repr(e)}


def ctl_log_window(target_prefix, t0, t1, slack=3.0):
    """Remote controls from the ctl container: need an OK before t0 and an OK after t1."""
    before = after = False
    fails = 0
    with open(CTL) as f:
        for line in f:
            r = json.loads(line)
            if not r["target"].startswith(target_prefix) or not (t0 - slack <= r["ts"] <= t1 + slack):
                continue
            if not r["ok"]:
                fails += 1
            elif r["ts"] <= t0:
                before = True
            elif r["ts"] >= t1:
                after = True
    return {"ok_before": before, "ok_after": after, "fails_in_window": fails,
            "ok": before and after and fails == 0}


class Listener(threading.Thread):
    """Temporary HTTP listener on 10.200.0.1:18080 (inside the test container only)."""
    def __init__(self):
        super().__init__(daemon=True)

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"06b3b listener\n")

            def log_message(self, *a):
                pass
        self.srv = http.server.HTTPServer((C.WORKER_GUEST_IP, LISTENER_PORT), H)

    def run(self):
        self.srv.serve_forever()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------------ pcap classification
def guest_frames():
    out = run_checked(["tshark", "-r", PCAP, "-T", "fields", "-E", "separator=\t", "-e", "frame.time_epoch",
                       "-e", "eth.src", "-e", "eth.type", "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
                       "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
                       "-e", "dns.qry.name"])
    rows = []
    for line in out.splitlines():
        f = (line.split("\t") + [""] * 11)[:11]
        rows.append({"t": float(f[0]), "src_mac": f[1].lower(), "etype": f[2], "ip_src": f[3], "ip_dst": f[4],
                     "proto": f[5], "sport": f[6] or f[8], "dport": f[7] or f[9], "qname": f[10]})
    return rows


def classify(r):
    """Same order as guest.nft: netdev (MAC, ethertype) then inet prerouting."""
    if r["src_mac"] != C.GUEST_MAC:
        return None if r["src_mac"] else "unknown"   # frames towards the guest are not classified
    et = r["etype"].split(",")[0]
    if et not in ("0x0800", "0x00000800", "0x0806", "0x00000806"):
        return "l2_bad_ethertype"
    if et in ("0x0806", "0x00000806"):
        return "arp"
    src, dst = r["ip_src"].split(",")[0], ipaddress.ip_address(r["ip_dst"].split(",")[0])
    if src != C.GUEST_IP:
        return "drop_spoof"
    if str(dst) == C.WORKER_GUEST_IP:
        return "allow_svc" if r["proto"] == "6" and r["dport"] == str(C.SVC_PORT) else "drop_worker_other"
    if any(dst in n for n in PRIVATE):
        return "drop_private"
    if dst in MCAST or str(dst) == "255.255.255.255":
        return "drop_bcast_mcast"
    return "drop_public"


# ------------------------------------------------------------------ main
def main():
    signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("deadline exceeded")))
    signal.alarm(DEADLINE_S)
    cfg = A.ARCH_CONFIGS[ARCH]
    tshark = proc = listener = None
    status = "ERROR"
    try:
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with ZipFile(os.path.join("/app", cfg.image_zip_path)) as z:
            z.extractall(WORK)
        fixture = f"06B-3B {ARCH} harmless text fixture - not an ELF\n".encode()
        os.makedirs(DATA + T, exist_ok=True)
        open(DATA + T + "/" + T, "wb").write(fixture)
        current_task.clear()
        record("host leak monitor running and empty before boot", alert_lines() == [])

        if SUITE == "ipv4":   # 06B-4F: the listener is only a target of the IPv4 matrix
            listener = Listener()
            listener.start()
            record("temporary listener 10.200.0.1:18080 answers locally",
                   run_ctl(lambda: ctl_http(C.WORKER_GUEST_IP, LISTENER_PORT, "/"))["ok"])

        verify_isolation(f"06B-3B {ARCH} harness pre-boot check (not V1)")
        record("full isolation verify right before QEMU spawn (harness pre-boot, not V1)", True)

        record("info: tshark version", True, version=run_checked(["tshark", "--version"]).splitlines()[0])
        tshark = subprocess.Popen(["tshark", "-i", C.GUEST_IF, "-w", PCAP, "-q"], stdout=subprocess.DEVNULL,
                                  stderr=open(os.path.join(OUT, "tshark.stderr"), "w"))
        for _ in range(50):
            if os.path.exists(PCAP):
                break
            time.sleep(0.1)
        record("tshark capturing on tap0", tshark.poll() is None and os.path.exists(PCAP))

        captures_alive(tshark, "before boot")
        # 06B-3F: session-wide window opens here: captures alive (checked above), no QEMU yet
        record_qemu_scan("before")
        session.update(read_before=counters_read("session before boot"))
        an = A.Analysis(T, WORK, C.GUEST_IP, C.WORKER_GUEST_IP, WORK + cfg.image_kernel_path,
                        WORK + cfg.image_rootfs_path, {"worker_ip": "unused"})
        cmd = cfg.qemu_cmd_template.format(kernel=an.kernel_path, rootfs=an.rootfs_path, mac=C.GUEST_MAC)
        open(os.path.join(OUT, "qemu-command.txt"), "w").write(cmd + "\n")
        proc = an._start_qemu(cfg)
        # 06B-4IR1: startup guard from here to the end of the topology gate (raw `proc` stays for the shutdown)
        startup = StartupGuard(tshark)
        startup.check("after", "QEMU boot (console activated)")
        console = GuardedConsole(proc, startup)
        an._configure_network(console, cfg)
        if startup.stop is not None:         # an exception swallowed inside _configure_network still stops here
            raise startup.stop
        g = Guest(console)
        record("guest booted and network configured", True, qemu_pid=proc.pid)

        # ------------------------------------------------ strict topology gate
        topo = {k: startup.run(g, c)[1] for k, c in (
            ("ip_addr", "ip addr"), ("ip_route", "ip route"),
            ("ifaces_mac", "for i in /sys/class/net/*; do echo $(basename $i) $(cat $i/address); done"),
            ("tools", "for c in nslookup nc wget ping arping; do command -v $c || echo missing:$c; done"),
            ("curl", "curl --version | head -1"))}
        topo["info_network"] = startup.monitor(g, "info network")
        if startup.stop is not None:
            raise startup.stop
        # 06B-4IR2 (IR1-R1): the guard is NOT disarmed here. It is handed over only where the receiving branch is
        # already guarded: ICMP/ARP disarm it right before run_icmp/run_arp, whose GuardedRunner checks before and
        # after every guest command (no guest command is sent in between); the IPv4 branch keeps it armed and sends
        # every service-link and probe command through startup.run().
        json.dump(topo, open(os.path.join(OUT, "topology.json"), "w"), indent=1)
        entries, perr = parse_info_network(topo["info_network"])
        json.dump(entries, open(os.path.join(OUT, "info-network-parsed.json"), "w"), indent=1)
        bad = check_topology(entries, perr)
        macs = dict(l.split()[:2] for l in topo["ifaces_mac"].splitlines() if len(l.split()) >= 2)
        if macs.get(cfg.net_iface, "").lower() != C.GUEST_MAC:
            bad.append(f"probe interface {cfg.net_iface} MAC {macs.get(cfg.net_iface)} != {C.GUEST_MAC}")
        if not re.search(rf"inet {re.escape(C.GUEST_IP)}/{C.GUEST_PREFIX}\b.*{re.escape(cfg.net_iface)}", topo["ip_addr"]):
            bad.append(f"{C.GUEST_IP}/{C.GUEST_PREFIX} not on {cfg.net_iface}")
        if not re.search(rf"default via {re.escape(C.WORKER_GUEST_IP)} dev {re.escape(cfg.net_iface)}", topo["ip_route"]):
            bad.append("default route is not via 10.200.0.1 on the probe interface")
        record("topology gate: only nic/tap, one tap0 backend, pinned MAC on tap NIC and probe interface", not bad,
               problems=bad, entries=[(e["name"], e["type"], [p["type"] for p in e["peers"]]) for e in entries],
               probe_iface=cfg.net_iface, probe_iface_mac=macs.get(cfg.net_iface))
        if bad:
            status = "STOPPED_TOPOLOGY"
            say("topology differs from the design: no probes sent")
            return 1
        has_nslookup = "missing:nslookup" not in topo["tools"]
        record("info: guest network tools", True, tools=topo["tools"].split())

        # ------------------------------------------------ allowed service link: before
        current_task.set_current(T)
        if SUITE == "arp":    # 06B-4I: the four reviewed ARP cases instead of the IPv4 matrix
            startup.armed = False               # 06B-4IR2: handed over to run_arp's GuardedRunner
            run_arp(g, cfg, fixture, tshark)    # raises LeakDetected / CaptureLost like the probe loop
            current_task.clear()
            status = "COMPLETED"
            return 0
        if SUITE == "icmp":   # 06B-4F: the five reviewed ICMP cases instead of the IPv4 matrix
            startup.armed = False               # 06B-4IR2: handed over to run_icmp's GuardedRunner
            run_icmp(g, cfg, fixture, tshark)   # raises LeakDetected / CaptureLost like the probe loop
            current_task.clear()
            status = "COMPLETED"
            return 0

        startup.phase = "ipv4 group"          # 06B-4IR2: the startup guard stays armed for the whole IPv4 branch

        def service_link(label):
            rc, out = startup.run(g, f"curl -s -m 10 -o /tmp/r.out -w 'HTTP=%{{http_code}}\\n' {URL}/get-task/{T}/file; "
                            "sha256sum /tmp/r.out")
            ok = "HTTP=200" in out and __import__("hashlib").sha256(fixture).hexdigest() in out
            record(f"allowed service link {label}: GET get-task/T/file 200 + hash", ok, rc=rc, output=out.strip())
        service_link("before probes")

        # ------------------------------------------------ probes
        ssh_ips = CFG["ssh_ips"]
        plan = [("internet-tcp", "1.1.1.1", "tcp", 443, "drop_public", lambda: ctl_tcp("1.1.1.1", 443), None)]
        plan.append(("lan-dns-udp", CFG["lan_dns"], "udp", 53, "drop_private",
                     lambda: ctl_dns(CFG["lan_dns"], f"ct01-06b3b-ctl-{ARCH.lower()}.example"), None))
        plan.append(("lan-dns-tcp", CFG["lan_dns"], "tcp", 53, "drop_private",
                     lambda: ctl_tcp(CFG["lan_dns"], 53), None))
        for i, ip in enumerate(ssh_ips):
            plan.append((f"ssh-host-{ip}", ip, "tcp", 22, "drop_private", (lambda ip=ip: ctl_tcp(ip, 22, b"SSH-")), None))
        plan.append(("manager", CFG["manager_ip"], "tcp", 8011, "drop_private",
                     lambda: ctl_http(CFG["manager_ip"], 8011), "manager "))
        plan.append(("mongodb", CFG["mongo_ip"], "tcp", 27017, "drop_private", None, "mongo "))
        plan.append(("worker-eth0", CFG["worker_ip"], "tcp", 8011, "drop_private", None, "worker-eth0 "))
        plan.append(("tap0-other-port-listener", C.WORKER_GUEST_IP, "tcp", LISTENER_PORT, "drop_worker_other",
                     lambda: ctl_http(C.WORKER_GUEST_IP, LISTENER_PORT, "/"), None))

        for n, (pid, ip, proto, port, klass, local_ctl, remote_ctl) in enumerate(plan):
            lport = 41000 + n
            qname = f"ct01-06b3b-probe-{ARCH.lower()}-{n}.example"
            say(f"--- probe {pid}: {proto} {ip}:{port} (expected block point: {klass})")
            captures_alive(tshark, f"before probe {pid}")
            cb = run_ctl(local_ctl) if local_ctl else None
            ra = counters_read(f"{pid} before")
            if proto == "tcp":
                rc, out = startup.run(g, f"curl -s -o /dev/null --local-port {lport} --connect-timeout 4 -m 5 "
                                f"-w 'HTTP=%{{http_code}}\\n' http://{ip}:{port}/ct01-06b3b-{pid}", timeout=30)
                guest_failed = rc in (7, 28) and "HTTP=000" in out
            elif has_nslookup:
                rc, out = startup.run(g, f"nslookup {qname} {ip}", timeout=60)
                guest_failed = rc != 0 and not re.search(r"Name:\s+" + re.escape(qname), out)
            else:
                rc, out, guest_failed = None, "TOOL_MISSING: nslookup not available in guest", False
            time.sleep(1.0)
            rb = counters_read(f"{pid} after")
            c0, c1, t0, t1 = ra["values"], rb["values"], ra["t_start"], rb["t_end"]
            ca = run_ctl(local_ctl) if local_ctl else None
            remote = {"prefix": remote_ctl} if remote_ctl else None   # evaluated in evaluate()
            alerts = alert_lines()
            p = {"probe": pid, "dst": ip, "proto": proto, "port": port, "lport": lport if proto == "tcp" else None,
                 "qname": qname if proto == "udp" else None, "expected_class": klass, "t0": t0, "t1": t1,
                 "read_before": {k: ra[k] for k in ("t_start", "t_end")},
                 "read_after": {k: rb[k] for k in ("t_start", "t_end")},
                 "guest_rc": rc, "guest_output": (out or "").strip()[-300:], "guest_failed": guest_failed,
                 "control_before": cb, "control_after": ca, "remote_control": remote,
                 "counter_delta": {k: c1.get(k, 0) - c0.get(k, 0) for k in c1 if c1.get(k, 0) != c0.get(k, 0)},
                 "host_alert_lines": len(alerts)}
            probes.append(p)
            say(f"    guest rc={rc} failed={guest_failed}; control before={cb and cb['ok']} after={ca and ca['ok']} "
                f"remote={remote}; counters={p['counter_delta']}; host alerts={len(alerts)}")
            if alerts:
                record("NO probe packet seen on host interfaces (leak monitor)", False, probe=pid, alerts=alerts[:5])
                raise LeakDetected(f"probe {pid}: {len(alerts)} packet(s) of 10.200.0.0/30 seen on host interfaces")
            captures_alive(tshark, f"after probe {pid}")

        record("all planned probes executed with captures alive", len(probes) == len(plan),
               planned=len(plan), executed=len(probes))

        service_link("after probes")
        current_task.clear()
        status = "COMPLETED"
        return 0
    except LeakDetected as e:
        status = f"LEAK: {e}"
        return 99
    except CaptureLost as e:
        status = f"CAPTURE LOST: {e}"
        record("captures alive for the whole test (probes stopped)", False, error=str(e), executed=len(probes))
        return 98
    except Exception as e:
        status = f"ERROR: {type(e).__name__}: {e}"
        record("harness completed without error", False, error=status)
        return 1
    finally:
        signal.alarm(0)
        if proc is not None:
            try:
                A.shutdown_qemu(proc, f"06B-3B {ARCH}")
                record("QEMU exit confirmed", not proc.isalive(), exitstatus=proc.exitstatus)
            except Exception as e:
                record("QEMU exit confirmed", False, error=str(e))
            # 06B-3F: final session reads, only after QEMU exit was confirmed, while tshark still runs
            if "read_before" in session:
                session["exit_confirmed"] = not proc.isalive()
                session["exit_confirmed_t"] = time.time()
                record_qemu_scan("after_exit")   # 06B-3FR1: errors are kept, never swallowed
                session["finals"] = []
                if session["exit_confirmed"]:
                    try:
                        for i in range(SESSION_FINAL_READS):
                            time.sleep(SESSION_SETTLE_S)
                            session["finals"].append(counters_read(f"session final {i + 1}"))
                    except Exception as e:
                        session["final_read_error"] = f"{type(e).__name__}: {e}"
        if tshark is not None:
            tshark.send_signal(signal.SIGINT)
            try:
                tshark.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tshark.kill()
                tshark.wait(timeout=5)
            record("tap0 capture stopped cleanly", tshark.returncode == 0, returncode=tshark.returncode)
            # 06B-3CR: tshark prints no drop line when nothing was dropped, so stderr cannot prove
            # "0 dropped". The pcapng interface statistics block written by dumpcap is used instead;
            # missing statistics are UNVERIFIED (a failed check), never "0 dropped".
            err = open(os.path.join(OUT, "tshark.stderr")).read()
            try:
                st = pcapng_stats.read_stats(PCAP)
                verdict, reason = pcapng_stats.drop_verdict(st)
            except Exception as e:   # PcapngError, OSError, or a bug: never PASS, never crash finally
                st, verdict, reason = None, "FAIL", f"pcapng statistics unreadable: {type(e).__name__}: {e}"
            record("tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped",
                   verdict == "PASS", verdict={"PASS": "ĐẠT", "FAIL": "FAIL",
                                               "UNVERIFIED": "CHƯA KIỂM CHỨNG"}[verdict],
                   reason=reason, stats=st, tshark_stderr_tail=err.strip()[-200:])
            session["capture"] = {"tshark_rc": tshark.returncode, "drop_verdict": verdict, "drop_reason": reason}
        if listener is not None:
            listener.stop()
            gone = not run_ctl(lambda: ctl_http(C.WORKER_GUEST_IP, LISTENER_PORT, "/"))["ok"]
            record("temporary listener stopped", gone)
        try:
            shutil.copy(WORK + "/qemu.log", os.path.join(OUT, "console.log"))
        except OSError:
            pass
        current_task.clear()
        shutil.rmtree(DATA + T, ignore_errors=True)
        shutil.rmtree(WORK, ignore_errors=True)
        record("fixture, marker and temporary guest disk removed",
               not os.path.exists(WORK) and not os.path.exists(C.CURRENT_TASK_FILE) and not os.path.exists(DATA + T))
        if "read_before" in session:
            evaluate_session()   # 06B-3F: reported separately, whatever the status
        if status == "COMPLETED" and SUITE == "arp":
            evaluate_arp()
        elif status == "COMPLETED":
            evaluate_icmp() if SUITE == "icmp" else evaluate()
        json.dump({"status": status, "results": results, "probes": probes},
                  open(os.path.join(OUT, "result.json"), "w"), indent=1, default=str)
        failed = [r for r in results if not r["ok"]]
        say(f"== {ARCH}: status={status}; {len(results) - len(failed)}/{len(results)} checks passed")


# ------------------------------------------------------------------ 06B-4F: ICMP suite
def read_tap_mac():
    """MAC of the worker's tap0 (read only). Needed to classify frames towards the worker and to build T13-I2."""
    with open(os.path.join(SYS_NET, C.GUEST_IF, "address")) as f:
        return icmp_harness.I.L._norm_mac(f.read())


def capture_liveness(label, suite="ICMP"):
    """Traffic FROM THE WORKER that the host captures must see (veth/ens33 positive checks, control_qname of
    sigscan.sh): the same calls as the IPv4 matrix's local controls. It is NOT a control for the ICMP
    destinations; it only shows that the host captures and the payload scan are not blind."""
    r = {"lan_dns_udp": run_ctl(lambda: ctl_dns(CFG["lan_dns"], f"ct01-06b3b-ctl-{ARCH.lower()}.example")),
         "manager_http": run_ctl(lambda: ctl_http(CFG["manager_ip"], 8011))}
    record(f"capture liveness traffic from the worker {label} (host captures; not a control for the {suite} "
           "destinations)", all(v["ok"] for v in r.values()), **r)


def run_icmp(g, cfg, fixture, tshark):
    """The five reviewed cases, once, through icmp_cases.run_group(). Every guest command (service links
    and pings) goes through a GuardedRunner: leak alerts and captures/heartbeat checked before AND after
    (06B-4FR: alerts also before); the first failure stops the group (no further command reaches the guest)
    and is re-raised here, so the existing LeakDetected (99) / CaptureLost (98) handling applies unchanged."""
    import hashlib
    tap_mac = read_tap_mac()
    sha = hashlib.sha256(fixture).hexdigest()
    ICMP.update(tap_mac=tap_mac, sha=sha)
    record("info: ICMP suite (06B-4F): five reviewed cases, rule check only", True, tap_mac=tap_mac,
           probe_iface=cfg.net_iface, fixture_sha256=sha, service_link_role=icmp_harness.LINK_ROLE)
    capture_liveness("before the ICMP group")

    def check_alerts(cmd, when):
        # 06B-4FR: alert_lines() raises when the alert file is missing or unreadable; that exception stops the
        # group like any guard failure (status ERROR), it is never read as "no alert".
        alerts = alert_lines()
        if alerts:
            record("NO probe packet seen on host interfaces (leak monitor)", False, command=cmd, when=when,
                   alerts=alerts[:5])
            raise LeakDetected(f"{when} {cmd!r}: {len(alerts)} signature packet(s) seen on host interfaces")

    def before(cmd):
        # 06B-4FR: alerts are checked BEFORE every command too, so that an alert that appeared after the previous
        # check (e.g. during the next case's counter read A) stops the group before that command is sent.
        check_alerts(cmd, "before")
        captures_alive(tshark, f"before guest command {cmd!r}")

    def after(cmd):
        check_alerts(cmd, "after")
        captures_alive(tshark, f"after guest command {cmd!r}")

    runner = icmp_harness.GuardedRunner(g, before, after)
    labels = iter(("before", "after"))

    def service_link():
        label = next(labels, "extra")
        try:
            rc, out = runner.run(icmp_harness.link_command(URL, T))
        except Exception as e:
            record(f"allowed service link {label} the ICMP group: GET get-task/T/file HTTP 200 + fixture hash",
                   False, error=f"{type(e).__name__}: {e}")
            raise
        ok, detail = icmp_harness.parse_service_link(rc, out, sha)
        record(f"allowed service link {label} the ICMP group: GET get-task/T/file HTTP 200 + fixture hash", ok, **detail)
        return ok, detail

    say(f"--- ICMP group: {', '.join(icmp_harness.I.CASE_IDS)} on {cfg.net_iface}")
    rec = icmp_harness.run_suite(runner, counters_read, service_link, tap_mac, cfg.net_iface, ARCH, sha)
    ICMP["record"] = rec
    with open(os.path.join(OUT, icmp_harness.RECORD_FILE), "w") as f:
        json.dump(rec, f, indent=1, default=str)
    say(f"    ICMP group record: {len(rec['cases'])} case(s), sent {len(runner.sent)} guest command(s)"
        + (f", stopped: {rec['stopped']}" if rec.get("stopped") else ""))
    if runner.stop is not None:
        raise runner.stop
    tap_after = read_tap_mac()
    record("tap0 MAC unchanged during the ICMP group", tap_after == tap_mac, before=tap_mac, after=tap_after)
    record("all five ICMP cases executed with captures alive",
           [c["id"] for c in rec["cases"]] == list(icmp_harness.I.CASE_IDS) and not rec.get("skipped"),
           planned=list(icmp_harness.I.CASE_IDS), executed=[c["id"] for c in rec["cases"]],
           skipped=rec.get("skipped"))
    capture_liveness("after the ICMP group")


def evaluate_icmp():
    """06B-4F: icmp_harness.evaluate() on the tap0 capture and counters-raw.jsonl -> icmp-eval.json, one
    record per case (named "probe <id> ... -> <verdict>") and one record for the group's completeness."""
    try:
        res = icmp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), ICMP["tap_mac"],
                                    ICMP["record"], ARCH, ICMP["sha"])
    except Exception as e:   # a bug must never pass, nor crash the cleanup in main()'s finally
        record("ICMP group evaluated", False, error=f"{type(e).__name__}: {e}")
        return
    with open(os.path.join(OUT, icmp_harness.EVAL_FILE), "w") as f:
        json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False, default=str)
    record("ICMP group record: each reviewed case exactly once, service link before/after HTTP 200 + fixture hash",
           not res["record_problems"], problems=res["record_problems"])
    for c in res["cases"]:
        record(icmp_harness.case_test_name(c), c["ok"], category=c["category"], evidence_kind=c["evidence_kind"],
               probe_frames=c.get("probe_frames"), probe_frames_certain=c.get("probe_frames_certain"),
               replies_to_guest=c.get("replies_to_guest"), failed=c.get("failed"),
               reconciliation=(c.get("reconciliation") or {}).get("verdict"))


# ------------------------------------------------------------------ 06B-4I: ARP suite
def read_iface_mac(name):
    """MAC of an interface of the worker netns (read only): tap0 (frame directions) and eth0 (T14-A1 control)."""
    with open(os.path.join(SYS_NET, name, "address")) as f:
        return arp_harness.norm_mac(f.read())


def run_arp(g, cfg, fixture, tshark):
    """The four reviewed ARP cases, once, through arp_cases.run_group() (arp_harness.run_suite). Every guest command
    (service links, guest_state snapshot and restore, setup/trigger/settle) goes through the reviewed GuardedRunner:
    leak alerts, then captures/heartbeat, before AND after the command; the first failure stops the group (no
    further command reaches the guest, the restore included: the guest is then shut down and its disk removed) and
    is re-raised here, so LeakDetected (99) / CaptureLost (98) / other errors (1) are handled as before.
    Worker side, not guest commands: the neighbour collector (ip -j neigh show in this netns) and the T14-A1/A2
    live controls (arp_harness.make_control)."""
    import hashlib
    tap_mac = read_iface_mac(C.GUEST_IF)
    sha = hashlib.sha256(fixture).hexdigest()
    try:
        eth0_mac = read_iface_mac("eth0")
    except (OSError, ValueError) as e:      # the T14-A1 control then fails; it never passes without it
        eth0_mac = None
        say(f"    worker eth0 MAC not readable: {type(e).__name__}: {e}")
    ARP.update(tap_mac=tap_mac, sha=sha, iface=cfg.net_iface)
    record("info: ARP suite (06B-4I): T14-A1/A2 live control, T14-A3/T15-S1 rule check", True, tap_mac=tap_mac,
           probe_iface=cfg.net_iface, fixture_sha256=sha, worker_eth0_mac=eth0_mac,
           neigh_command=list(arp_harness.NEIGH_CMD), service_link_role=arp_harness.LINK_ROLE)
    capture_liveness("before the ARP group", "ARP")

    def leak_guard(cmd, phase):
        found = alert_lines()               # raises when the alert file is missing/unreadable: never "no alert"
        if found:
            record("NO probe packet seen on host interfaces (leak monitor)", False, suite="arp", when=phase,
                   command=cmd, alerts=found[:5])
            raise LeakDetected(f"{phase} ARP guest command {cmd!r}: {len(found)} signature packet(s) seen on host "
                               "interfaces")

    def guard_before(cmd):
        leak_guard(cmd, "before")
        captures_alive(tshark, f"before ARP guest command {cmd!r}")

    def guard_after(cmd):
        leak_guard(cmd, "after")
        captures_alive(tshark, f"after ARP guest command {cmd!r}")

    runner = arp_harness.IH.GuardedRunner(g, guard_before, guard_after)
    windows, current, links = {}, {"case": None}, {"n": 0}

    def read_counters(label):               # "<case id> before|after": remembers the case window for its control
        cid, _, which = label.rpartition(" ")
        current["case"] = cid
        r = counters_read(label)
        windows.setdefault(cid, {})[which] = (r["t_start"], r["t_end"])
        return r

    def service_link():                     # before the group, then after every restored case (arp_cases)
        name = arp_harness.LINK_BEFORE_NAME if links["n"] == 0 else arp_harness.link_after_name(current["case"])
        links["n"] += 1
        try:
            rc, out = runner.run(arp_harness.IH.link_command(URL, T))
        except Exception as e:
            record(name, False, error=f"{type(e).__name__}: {e}")
            raise
        ok, detail = arp_harness.IH.parse_service_link(rc, out, sha)
        record(name, ok, **detail)
        return ok, detail

    def worker_neigh():                     # this container = the worker netns; rc != 0 raises (recorded by run_group)
        return run_checked(list(arp_harness.NEIGH_CMD))

    def ctl_text():
        with open(CTL) as f:
            return f.read()

    control = arp_harness.make_control(windows, ctl_text, CFG, eth0_mac,
                                       lambda: run_ctl(lambda: ctl_http(CFG["manager_ip"], 8011)), worker_neigh,
                                       time.time, time.sleep, slack=arp_harness.CTL_SLACK_S)
    say(f"--- ARP group: {', '.join(arp_harness.A.CASE_IDS)} on {cfg.net_iface}")
    rec = arp_harness.run_suite(runner, read_counters, service_link, worker_neigh, control, cfg.net_iface, ARCH,
                                tap_mac, sha, anchor=lambda: counters_read(arp_harness.A.ANCHOR_LABEL))
    ARP["record"] = rec
    with open(os.path.join(OUT, arp_harness.RECORD_FILE), "w") as f:
        json.dump(rec, f, indent=1, default=str)
    say(f"    ARP group record: {len(rec['cases'])} case(s), sent {len(runner.sent)} guest command(s)"
        + (f", guard stop: {rec['guard_stopped']}" if rec.get("guard_stopped") else "")
        + (f", stopped: {rec['stopped']}" if rec.get("stopped") else ""))
    stop = runner.stop
    if stop is not None:
        raise stop
    for c in rec["cases"]:
        gs = c.get("guest_state") or {}
        if gs.get("before") is not None:    # the case changed (or may have changed) the guest: restore confirmed?
            rs = gs.get("restore") if isinstance(gs.get("restore"), dict) else {}
            record(arp_harness.restore_name(c["id"]), rs.get("restored") is True, diffs=rs.get("diffs"),
                   error=rs.get("error"), restore_commands=len(rs.get("commands") or []))
    ran = [c for c in rec["cases"] if not c.get("not_run")]
    errs = {c["id"]: [c[k] for k in ("neigh_before_error", "neigh_after_error") if c.get(k)] for c in ran}
    record(arp_harness.NEIGH_READ_NAME, bool(ran) and not any(errs.values())
           and all(isinstance(c.get("neigh_before"), str) and isinstance(c.get("neigh_after"), str) for c in ran),
           cases=[c["id"] for c in ran], errors={k: v for k, v in errs.items() if v})
    tap_after = read_iface_mac(C.GUEST_IF)
    record("tap0 MAC unchanged during the ARP group", tap_after == tap_mac, before=tap_mac, after=tap_after)
    record(arp_harness.ALL_CASES_NAME,
           [c["id"] for c in rec["cases"]] == list(arp_harness.A.CASE_IDS) and not rec.get("skipped"),
           planned=list(arp_harness.A.CASE_IDS), recorded=[c["id"] for c in rec["cases"]],
           not_run=[c["id"] for c in rec["cases"] if c.get("not_run")], skipped=rec.get("skipped"))
    capture_liveness("after the ARP group", "ARP")


def evaluate_arp():
    """06B-4I: arp_harness.evaluate() on the tap0 capture and counters-raw.jsonl -> arp-eval.json, one record per
    case ("probe <id> (arp, ...) -> <verdict>") and one for the group record."""
    try:
        res = arp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), ARP["tap_mac"], ARP["record"],
                                   ARCH, ARP["sha"], ARP["iface"])
    except Exception as e:   # a bug must never pass, nor crash the cleanup in main()'s finally
        record("ARP group evaluated", False, error=f"{type(e).__name__}: {e}")
        return
    with open(os.path.join(OUT, arp_harness.EVAL_FILE), "w") as f:
        json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False, default=str)
    record(arp_harness.GROUP_RECORD_NAME, res["group_complete"] is True, problems=res["record_problems"],
           group_exit=res["group_exit"])
    for c in res["cases"]:
        record(arp_harness.case_test_name(c), c["ok"], category=c["category"], evidence_kind=c.get("evidence_kind"),
               probe_frames=c.get("probe_frames"), probe_frames_certain=c.get("probe_frames_certain"),
               failure_evidence=c.get("failure_evidence"), measurement_errors=c.get("measurement_errors"),
               execution_problems=c.get("execution_problems"), not_started=c.get("not_started"),
               not_run=c.get("not_run"), reconciliation=(c.get("reconciliation") or {}).get("verdict"))


def evaluate_session():
    """06B-3F: session-wide counter/pcap reconciliation for this architecture. Written to session.json
    and printed on its own line; it is NOT recorded in `results`, so it changes no probe verdict and
    neither run_outcome() nor the exit code."""
    capture = dict(session.get("capture") or {"tshark_rc": None, "drop_verdict": "MISSING"})
    try:
        rows = guest_frames()
        capture["pcap_readable"] = True
    except Exception as e:
        rows = []
        capture["pcap_readable"] = False
        capture["pcap_error"] = str(e)[:300]
    frames = [{"t": r["t"], "cls": classify(r)} for r in rows]
    qemu = {"no_qemu_before": session.get("no_qemu_before", False),
            "pids_before": session.get("qemu_pids_before"),
            "pids_before_error": session.get("qemu_pids_before_error"),
            "exit_confirmed": session.get("exit_confirmed", False),
            "exit_confirmed_t": session.get("exit_confirmed_t"),
            "pids_after_exit": session.get("qemu_pids_after_exit"),
            "pids_after_exit_error": session.get("qemu_pids_after_exit_error")}
    res = counter_window.session_reconcile(frames, session.get("read_before"), session.get("finals", []),
                                           CLASSES, qemu, capture, required_finals=SESSION_FINAL_READS,
                                           final_read_error=session.get("final_read_error"))
    res["assumption"] = ("guard %.3f s covers the delay from capture timestamp to nft counter hit; "
                         "NOT measured" % counter_window.GUARD_S)
    json.dump(res, open(os.path.join(OUT, "session.json"), "w"), indent=1, default=str)
    say(f"== {ARCH}: SESSION-WIDE reconciliation (reported separately; changes no probe verdict and not the "
        f"exit code): {res['verdict']}" + (f" — {'; '.join(res['reasons'])}" if res["reasons"] else ""))
    return res


def evaluate():
    try:
        rows = guest_frames()
    except Exception as e:
        record("tap0 pcap readable by tshark (exit 0)", False, error=str(e))
        return
    record("tap0 pcap readable by tshark (exit 0)", True, frames=len(rows))
    if not rows:
        record("tap0 pcap is not empty", False)
        return
    time.sleep(4)   # make sure the control log has entries after the last probe window
    table = []
    for p in probes:
        if p["remote_control"] is not None:
            p["remote_control"] = ctl_log_window(p["remote_control"]["prefix"], p["t0"], p["t1"])
        # 06B-3DR: zones from the timed counter reads; no widening, no compensation
        ra, rb = p["read_before"], p["read_after"]
        span = [r for r in rows if ra["t_start"] - counter_window.GUARD_S <= r["t"] <= rb["t_end"]]
        frames = [{"t": r["t"], "cls": classify(r)} for r in span]
        dl = p["counter_delta"]
        recon = counter_window.reconcile(frames, ra, rb, dl, CLASSES)
        cls = {k: v["certain"] for k, v in recon["per_class"].items() if v["certain"]}
        mismatch = {k: {"delta": v["delta"], "certain": v["lo"], "with_edges": v["hi"], "status": v["status"],
                        "edge_start_t": v["edge_start"], "edge_end_t": v["edge_end"]}
                    for k, v in recon["per_class"].items() if v["status"] != "PASS"}
        if p["proto"] == "tcp":
            mine = [r for r in span if r["src_mac"] == C.GUEST_MAC and r["sport"] == str(p["lport"])]
        else:
            mine = [r for r in span if r["src_mac"] == C.GUEST_MAC and r["qname"] == p["qname"]]
        mine_cls = sorted({classify(r) for r in mine})
        local_ok = p["control_before"] is None or (p["control_before"]["ok"] and p["control_after"]["ok"])
        remote_ok = p["remote_control"] is None or p["remote_control"]["ok"]
        control_alive = local_ok and remote_ok and (p["control_before"] is not None or p["remote_control"] is not None)
        checks = {
            "guest_connection_failed": p["guest_failed"],
            "control_alive_same_dst_proto_port": control_alive,
            "probe_packets_in_tap0_pcap": len(mine) > 0,
            "probe_packets_hit_expected_counter": mine_cls == [p["expected_class"]],
            "no_host_alert": p["host_alert_lines"] == 0,
        }
        verdict, ok = counter_window.probe_verdict(
            checks, recon, p["expected_class"], tool_missing=p["guest_output"].startswith("TOOL_MISSING"),
            control_alive=control_alive)
        row = {"probe": p["probe"], "dst": f"{p['proto']} {p['dst']}:{p['port']}", "verdict": verdict,
               "probe_packets": len(mine), "expected_class": p["expected_class"],
               "counter_delta": dl, "pcap_certain": cls, "mismatch": mismatch, "checks": checks,
               "counter_reconciliation": recon,
               "determined_failures": counter_window.determined_failures(
                   checks, recon, p["expected_class"], tool_missing=p["guest_output"].startswith("TOOL_MISSING")),
               "guest_rc": p["guest_rc"], "control_before": p["control_before"], "control_after": p["control_after"],
               "remote_control": p["remote_control"]}
        table.append(row)
        record(f"probe {p['probe']} ({row['dst']}) -> {verdict}", ok,
               probe_packets=len(mine), expected=p["expected_class"], counter=dl.get(p["expected_class"], 0),
               pcap_certain=cls.get(p["expected_class"], 0), reconciliation=recon["verdict"], mismatch=mismatch,
               failed_checks=[k for k, v in checks.items() if not v],
               determined_failures=row["determined_failures"], measurement_error=recon.get("error"))
    json.dump(table, open(os.path.join(OUT, "matrix.json"), "w"), indent=1, default=str)
    with open(os.path.join(OUT, "matrix.md"), "w") as f:
        f.write("| probe | dst | probe pkts | expected counter = delta | pcap certain (same class) | "
                "reconciliation (all classes) | verdict |\n|---|---|---|---|---|---|---|\n")
        for r in table:
            f.write(f"| {r['probe']} | {r['dst']} | {r['probe_packets']} | {r['expected_class']}="
                    f"{r['counter_delta'].get(r['expected_class'], 0)} | {r['pcap_certain'].get(r['expected_class'], 0)} | "
                    f"{r['counter_reconciliation']['verdict']} | {r['verdict']} |\n")


if __name__ == "__main__":
    rc = main()
    failed = [r for r in results if not r["ok"]]
    sys.exit(rc if rc else (1 if failed else 0))
