#!/usr/bin/env python3
"""06B-4I — offline test of the ARP wiring (arp_harness.py, probe_matrix.py CT01_SUITE=arp, ctl_loop.py --arp-worker,
run-06b4i.sh). No root, no Docker, no QEMU, no packet, no network: the worker modules are stubs; the guest console,
nft, `ip -j neigh show`, tshark, the control-container log and the host capture files are fakes. Every scenario runs
the REAL probe_matrix.main() in its own python process, importing ONLY the files that run-06b4i.sh mounts into
/harness (plus the stubs): a missing mount fails.

The guest is selftest_arp.SimGuest (06B-4H..4HR2): guest_state snapshot/restore commands, ping/sleep, frames and
counters SIMULATED with l2frames.classify. Real kernel/netifd/busybox behaviour, the real `ip -j neigh` JSON,
real operstate values, the live controls on a real sandboxnet and the 20 ms guard are NOT verified here.

    python3 selftest_arp_wiring.py [--json FILE]
    (internal) python3 -I selftest_arp_wiring.py --scenario NAME --dir DIR

Sections:
  U  arp_harness units: ctl log, live controls A1/A2, check_record, case requirements, arch_outcome, run_check,
     CLI; ctl_loop.py arp_entry (extracted with ast) and its --arp-worker switch
  S  scenarios through probe_matrix.main(): clean group, wiring defects, service links, neighbour collector,
     live controls, guard stops (capture, heartbeat, tshark, leak, unreadable alert), execution errors, not
     started, restore failure, FAIL + measurement error, infrastructure, errors outside the group; each also through
     arp_harness --outcome and the run script's own outcome mapping (case block extracted from run-06b4i.sh)
  R  required confirmations in sync with the real ARP path; R1 (PERMANENT flag in neigh_dynamic, key in both groups)
     through arp_harness.evaluate / --outcome on the record of the clean run
  W  run-06b4i.sh: syntax, mounts, CT01_SUITE=arp on the only probe_matrix call, self-tests before any container,
     ctl --arp-worker, manager MAC, outcome/run-check through arp_harness, everything else as run-06b4f.sh
"""
import ast
import contextlib
import copy
import difflib
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
TAP = "7a:93:2a:f1:47:47"          # selftest_l2.TAP
ETH0_MAC = "02:42:c0:a8:3c:02"
OTHER_MAC = "02:42:c0:a8:3c:99"
MANAGER_MAC = "8a:d3:09:b5:72:af"  # selftest_arp.MANAGER_MAC (manager row of selftest_arp.NEIGH)
CTL_MAC = "02:42:c0:a8:3c:05"      # ctl's sandboxnet endpoint MAC (docker inspect in the run script; fake here)
ANALYSIS_SRC = "/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/sandbox-worker/service/analysis.py"
CASE_IDS = ("T14-A1", "T14-A2", "T14-A3", "T15-S1")
RS, RS_OLD = "run-06b4i.sh", "run-06b4f.sh"
CFG = {"worker_ip": "192.168.60.2", "mongo_ip": "172.18.0.2", "manager_ip": "192.168.60.10",
       "manager_mac": MANAGER_MAC, "ctl_mac": CTL_MAC, "ssh_ips": [], "lan_dns": "192.168.177.2"}


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
# neigh: {(counter label current at the call or None, index of the call under that label): kind}
# events: [(substring of a guest command, event after it)]; nft_event: (label, event during that counter read)
SCENARIOS = {
    "clean": {},
    "missing-case": {"cases": "missing"},
    "duplicate-case": {"cases": "duplicate"},
    "link-before-http000": {"link": {1: "http000"}},
    "link-after-A1-badhash": {"link": {2: "badhash"}},
    "neigh-error-A2-after": {"neigh": {("T14-A2 after", 0): "error"}},
    "neigh-notjson-A1-before": {"neigh": {("session before boot", 0): "notjson"}},
    "neigh-exception-A3-after": {"neigh": {("T14-A3 after", 0): "keyerror"}},
    "fail-and-measure-A3": {"neigh": {("T14-A3 after", 0): "guest_mac_eth0"}, "nft_fail": "T14-A3 after"},
    "notstarted-A3": {"snap_fail": ("T14-A2 after", 2)},
    "notstarted-A3-neigh-fail": {"snap_fail": ("T14-A2 after", 2), "neigh": {("T14-A2 after", 3): "guest_mac_eth0"}},
    "exec-error-A1": {"guest": {"fail_cmds": ["ip route add 192.168.60.2/32 dev eth1"]}},
    "timeout-A3": {"guest": {"raise_on": "ping -c 1 -W 2 -s 1403"}},
    "no-frame": {"guest": {"emit": False}},
    "counter-read-error-A3": {"nft_fail": "T14-A3 after"},
    "restore-fail-A2": {"guest": {"fail_cmds": ["ip route del 192.168.60.10/32 dev eth1"]}},
    "marker-after-A2-ping": {"events": [("-s 1402 192.168.60.10", "marker")]},
    "heartbeat-stale-after-A1-setup": {"events": [("ip route add 192.168.60.2/32", "stale")]},
    "tshark-exit-after-S1-down": {"events": [("ip link set dev eth1 down", "tshark_dead")]},
    "leak-after-A3-ping": {"events": [("-s 1403 10.200.0.6", "leak")]},
    "leak-before-S1": {"nft_event": ("T15-S1 before", "leak")},
    "alert-unreadable-before-A2": {"nft_event": ("T14-A2 before", "alert_dir")},
    "marker-before-A2": {"nft_event": ("T14-A2 before", "marker")},
    "ctl-arp-wrong-mac": {"ctl": "arp_wrong_mac"},
    "ctl-no-arp": {"ctl": "no_arp"},
    "ctl-worker-fail-in-A1": {"ctl": "worker_fail_A1"},
    "ctl-missing": {"ctl": "missing"},
    "ctl-malformed": {"ctl": "malformed"},
    "a2-manager-neigh-missing": {"neigh": {("T14-A2 after", 1): "manager_missing"}},
    "a2-manager-other-mac": {"neigh": {("T14-A2 after", 1): "manager_other_mac"}},
    "a2-worker-http-fail": {"worker_http_fail": True},
    "cfg-no-manager-mac": {"cfg": {"manager_mac": None}},
    "cfg-worker-ip-other": {"cfg": {"worker_ip": "192.168.60.3"}},
    "eth0-mac-missing": {"no_eth0": True},
    "tap0-drops": {"isb_drop": 2},
    "pcap-unreadable": {"pcap": "truncated"},
    "qemu-not-exiting": {"qemu_stuck": True},
    "cleanup-marker-left": {"marker_left": True},
    "liveness-fails": {"liveness_fail": True},
    "error-after-group": {"events": [("ip link set dev eth1 up", "tap0_gone")]},
    "callback-errors": {"ctl": "dir", "worker_http_fail": True, "neigh": {("T14-A3 after", 0): "keyerror"}},
    # 06B-4IR1 (I1): events during the startup (real Analysis._configure_network body) and the topology gate
    "boot-leak": {"boot": "leak"},
    "boot-capture": {"boot": "marker"},
    "boot-leak-swallowed": {"boot": "leak", "boot_swallow": True},
    "unit-console": {"unit": "console"},
    "icmp-topology-leak": {"suite": "icmp", "events": [("ip addr", "leak")], "exact_event": True},
    # 06B-4IR2 (IR1-R1): handoff from the startup guard to each branch (event right after the topology gate)
    "ipv4-clean": {"suite": "ipv4"},
    "ipv4-handoff-capture": {"suite": "ipv4", "record_event": ("topology gate:", "marker")},
    "ipv4-handoff-leak": {"suite": "ipv4", "record_event": ("topology gate:", "leak")},
    "ipv4-handoff-alert-unreadable": {"suite": "ipv4", "record_event": ("topology gate:", "alert_dir")},
    "ipv4-handoff-heartbeat": {"suite": "ipv4", "record_event": ("topology gate:", "stale")},
    "ipv4-after-service-link": {"suite": "ipv4", "events": [("/get-task/", "marker")]},
    "ipv4-after-probe": {"suite": "ipv4", "events": [("--local-port 41000", "leak")]},
    "icmp-handoff-capture": {"suite": "icmp", "record_event": ("topology gate:", "marker")},
    "arp-handoff-capture": {"suite": "arp", "record_event": ("topology gate:", "marker")},
    "arp-handoff-leak": {"suite": "arp", "record_event": ("topology gate:", "leak")},
    # 06B-4IR2 (IR1-R2): endpoint MACs that cannot identify an interface (clean payload, one condition changed)
    "zero-mac-cfg": {"cfg": {"ctl_mac": "00:00:00:00:00:00"}},
    "zero-mac-payload": {"ctl": "device_mac=00:00:00:00:00:00"},
    "zero-mac-both": {"cfg": {"ctl_mac": "00:00:00:00:00:00"}, "ctl": "device_mac=00:00:00:00:00:00"},
    "broadcast-mac-both": {"cfg": {"ctl_mac": "ff:ff:ff:ff:ff:ff"}, "ctl": "device_mac=ff:ff:ff:ff:ff:ff"},
    "multicast-mac-both": {"cfg": {"ctl_mac": "01:00:5e:00:00:fb"}, "ctl": "device_mac=01:00:5e:00:00:fb"},
    "local-unicast-other-both": {"cfg": {"ctl_mac": "0a:11:22:33:44:55"}, "ctl": "device_mac=0a:11:22:33:44:55"},
    "topology-leak": {"events": [("ip addr", "leak")], "exact_event": True},
    "topology-capture": {"events": [("ip addr", "marker")], "exact_event": True},
    "topology-heartbeat": {"events": [("ip route", "stale")], "exact_event": True},
    "monitor-leak": {"monitor_event": "leak"},
    "startup-alert-unreadable": {"events": [("curl --version | head -1", "alert_dir")], "exact_event": True},
    # 06B-4IR1 (I2): interface of the ctl ARP entry
    "a1-wrong-interface": {"ctl": "arp_wrong_device_mac"},
    "a1-missing-interface": {"ctl": "arp_missing_device"},
    "a1-other-name-same-endpoint": {"ctl": "arp_other_name"},
    "a1-two-devices": {"ctl": "arp_two_devices"},
    "a1-entry-other-ip": {"ctl": "arp_other_ip"},
    "cfg-no-ctl-mac": {"cfg": {"ctl_mac": None}},
    # 06B-4IR1 (I3): quality of the ctl log
    "duplicate-control": {"ctl": "duplicate"},
    "http-missing-detail": {"ctl": "http_missing_detail"},
    "http-wrong-detail": {"ctl": "http_wrong_detail"},
    "ctl-extra-key": {"ctl": "extra_key"},
}


class World:
    pass


W = World()


def mounted_files(script):
    """Files run-06b4i.sh mounts into /harness: -v "$H/x:/harness/x:ro"."""
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
    """tshark -i tap0 -w PCAP: the file exists while it runs; on SIGINT it writes every frame the simulated guest
    emitted, then an interface statistics block, and exits 0."""

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


def neigh_text(kind):
    SA = W.SA
    if kind == "notjson":
        return "Object \"neigh\" is unknown"
    if kind == "guest_mac_eth0":
        return SA.NEIGH.replace(MANAGER_MAC, SA.GUEST)
    if kind == "manager_missing":
        return json.dumps([r for r in json.loads(SA.NEIGH) if r["dst"] != "192.168.60.10"])
    if kind == "manager_other_mac":
        return SA.NEIGH.replace(MANAGER_MAC, OTHER_MAC)
    return SA.NEIGH


def fake_run_checked(cmd):
    if cmd[:3] == ["nft", "-j", "list"] and W.spec.get("nft_event", (None,))[0] == W.label:
        kind = W.spec["nft_event"][1]
        if kind == "marker":
            open(W.pm.CAPTURE_DEAD, "a").write("12:00:00 capture bridge pid 78 exited during the test\n")
        elif kind == "leak":
            open(W.pm.ALERT, "a").write("12:00:02 ARP, Request who-has 10.200.0.1 tell 10.200.0.1, length 28\n")
        elif kind == "alert_dir":       # unreadable even as root (the run script runs this test as root)
            os.remove(W.pm.ALERT)
            os.mkdir(W.pm.ALERT)
    if cmd[:3] == ["nft", "-j", "list"]:
        if W.spec.get("nft_fail") and W.label == W.spec["nft_fail"]:
            raise RuntimeError("command failed rc=1: nft -j list counters: simulated")
        return W.V.raw(W.counters)
    if cmd[:2] == ["tshark", "--version"]:
        return "TShark (Wireshark) 3.6.2 (fake)\n"
    if cmd[:3] == ["ip", "-j", "neigh"]:
        W.worker_cmds.append(list(cmd))
        key = (W.label, W.neigh_n.get(W.label, 0))
        W.neigh_n[W.label] = key[1] + 1
        if W.spec.get("snap_fail") == key:
            W.snap_fail = True
        kind = W.spec.get("neigh", {}).get(key)
        if kind == "error":
            raise RuntimeError("command failed rc=1: ip -j neigh show: simulated")
        if kind == "keyerror":
            raise KeyError("simulated collector bug")
        return neigh_text(kind)
    raise RuntimeError(f"unexpected command in the fake container: {cmd}")


def guest_class(SA, GS):
    class FakeGuest(SA.SimGuest):
        """SimGuest (guest_state commands, ping/sleep, frames, counters) + the topology/service-link commands that
        probe_matrix sends + guard events."""

        def __init__(self, proc):
            kw = dict(W.spec.get("guest", {}))
            kw["fail_cmds"] = tuple(kw.get("fail_cmds", ()))
            super().__init__(W.counters, W.frames, **kw)

        def monitor(self, command, timeout=20):
            W.commands.append(("monitor", command))
            if W.spec.get("monitor_event"):
                fire(W.spec["monitor_event"])
            return ("info network\nnet0: index=0,type=nic,model=virtio-net-pci,macaddr=52:54:00:c7:00:02\n"
                    " \\ hostnet0: index=0,type=tap,ifname=tap0,script=no,downscript=no\n")

        def run(self, cmd, timeout=60):
            W.commands.append(("run", cmd))
            rc, out = self._answer(cmd, timeout)
            for sub, ev in W.spec.get("events", []):
                hit = cmd == sub if W.spec.get("exact_event") else sub in cmd
                if hit and (sub, ev) not in W.fired:
                    W.fired.add((sub, ev))
                    fire(ev)
            return rc, out

        def _answer(self, cmd, timeout):
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
                how = W.spec.get("link", {}).get(W.links, "ok")
                sha = hashlib.sha256(open(os.path.join(W.pm.DATA, W.pm.T, W.pm.T), "rb").read()).hexdigest()
                if how == "http000":
                    return 0, "HTTP=000\nsha256sum: /tmp/r.out: No such file or directory\n"
                if how == "badhash":
                    return 0, "HTTP=200\n" + "0" * 64 + "  /tmp/r.out\n"
                return 0, f"HTTP=200\n{sha}  /tmp/r.out\n"
            if W.snap_fail and cmd == GS.snapshot_cmd("eth1"):
                W.snap_fail = False
                return 0, "@@S mac\n52:54:00:c7:00:02\n@@RC 0\n"           # sections missing: unreadable state
            return super().run(cmd, timeout)
    return FakeGuest


def fire(ev):
    if ev == "marker":
        open(W.pm.CAPTURE_DEAD, "a").write("12:00:00 capture ens33 pid 77 exited during the test\n")
    elif ev == "stale":
        W.hb_stop.set()
        W.hb_thread.join()
        open(W.pm.HEARTBEAT, "w").write(str(time.time() - 30))
    elif ev == "tshark_dead":
        W.tshark_dead = True
    elif ev == "leak":
        open(W.pm.ALERT, "a").write("12:00:01 ARP, Request who-has 10.200.0.6 tell 10.200.0.2, length 28\n")
    elif ev == "alert_dir":
        os.remove(W.pm.ALERT)
        os.mkdir(W.pm.ALERT)
    elif ev == "tap0_gone":
        os.remove(os.path.join(W.pm.SYS_NET, "tap0", "address"))


def ctl_loop_thread(path, mode, stop):
    """Stands in for the ctl container (ctl_loop.py --arp-worker): one cycle every 0.15 s."""
    if mode == "missing":
        return
    if mode == "dir":
        os.mkdir(path)
        return
    wip, mip = W.cfg["worker_ip"], CFG["manager_ip"]
    with open(path, "a", buffering=1) as f:
        if mode == "malformed":
            f.write("{not json\n")
        while not stop.is_set():
            ts = time.time()
            W.ctl_cycle = getattr(W, "ctl_cycle", 0) + 1
            recs = [{"ts": ts, "target": "mongo 172.18.0.2:27017", "ok": True, "detail": "connected"},
                    {"ts": ts, "target": f"worker-eth0 {CFG['worker_ip']}:8011", "ok": True, "detail": "HTTP 200"}]
            if mode == "worker_fail_A1" and W.label in ("T14-A1 before", "T14-A1 after"):
                recs[1] = {**recs[1], "ok": False, "detail": "TimeoutError('timed out')"}
            if mode != "no_arp":
                hw = OTHER_MAC if mode == "arp_wrong_mac" else ETH0_MAC
                det = {"ip": CFG["worker_ip"], "hw": hw, "flags": "0x2", "device": "eth0", "device_mac": CTL_MAC}
                if mode == "arp_wrong_device_mac":           # another interface of ctl (e.g. its dbnet endpoint)
                    det.update(device="eth9", device_mac="02:42:ac:12:00:09")
                elif mode == "arp_missing_device":
                    det.pop("device")
                elif mode == "arp_other_name":               # same sandboxnet endpoint under another name: accepted
                    det["device"] = "eth7"
                elif mode == "arp_two_devices" and W.ctl_cycle % 2:
                    det["device"] = "eth7"
                elif mode == "arp_other_ip":
                    det["ip"] = "192.168.60.3"
                recs.append({"ts": ts, "target": f"arp worker-eth0 {CFG['worker_ip']}", "ok": True, "detail": det})
            recs.append({"ts": ts, "target": f"manager {mip}:8011", "ok": True, "detail": "HTTP 200"})
            if isinstance(mode, str) and mode.startswith("device_mac=") and mode != "no_arp":
                for r in recs:
                    if r["target"].startswith("arp "):
                        r["detail"]["device_mac"] = mode.split("=", 1)[1]
            if mode == "duplicate":                          # every line written twice (same target, ts, payload)
                recs = [r for r in recs for _ in (0, 1)]
            if mode == "http_missing_detail":
                recs = [{k: v for k, v in r.items() if k != "detail"} if not r["target"].startswith(("arp ", "mongo "))
                        else r for r in recs]
            if mode == "http_wrong_detail":
                recs = [dict(r, detail="HTTP 500") if r["target"].startswith(("worker-eth0 ", "manager ")) else r
                        for r in recs]
            if mode == "extra_key":
                recs = [dict(r, replayed=True) for r in recs]
            for r in recs:
                f.write(json.dumps(r) + "\n")
            stop.wait(0.15)
    del wip


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


def install_real_configure_network(A, spec):
    """06B-4IR1: the REAL body of Analysis._configure_network (extracted with ast from the repository's
    sandbox-worker/service/analysis.py, unchanged) on a fake pexpect console: every keystroke is logged; the startup
    event (leak alert / capture marker) is written while `ip addr add` is being sent. With boot_swallow the call is
    wrapped so that it swallows every exception (the main path must still stop)."""
    import ast as _ast
    import types
    src = open(ANALYSIS_SRC).read()
    W.analysis_sha = hashlib.sha256(src.encode()).hexdigest()
    tree = _ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, _ast.ClassDef) and n.name == "Analysis")
    fn = next(n for n in cls.body if isinstance(n, _ast.FunctionDef) and n.name == "_configure_network")
    ns = {"pexpect": types.SimpleNamespace(TIMEOUT="TIMEOUT", EOF="EOF", spawn=object),
          "guestnet": types.SimpleNamespace(GUEST_PREFIX=30), "ArchConfig": object,
          "logger": types.SimpleNamespace(info=lambda *a: None)}
    exec(compile(_ast.Module(body=[fn], type_ignores=[]), ANALYSIS_SRC, "exec"), ns)
    real = ns["_configure_network"]

    def sendline(self, cmd=""):
        W.boot_console.append(cmd)
        if cmd.startswith("ip addr add "):
            fire(spec["boot"])
    A.FakeProc.sendline = sendline
    A.FakeProc.send = lambda self, s: W.boot_console.append(s)
    A.FakeProc.expect = lambda self, *a, **k: 1

    def configure(self, proc, cfg):
        self.qemu_ip, self.qemu_gw = "10.200.0.2", "10.200.0.1"
        cfg.boot_ready_prompt, cfg.network_ready_prompt_optional, cfg.extra_prompt_after_dns = "# ", False, True
        if spec.get("boot_swallow"):
            try:
                return real(self, proc, cfg)
            except Exception:                                     # noqa: BLE001  a careless caller
                return None
        return real(self, proc, cfg)
    A.Analysis._configure_network = configure


def unit_console(d):
    """06B-4IR1: StartupGuard + GuardedConsole around the REAL probe_matrix.Guest on a fake pexpect object."""
    out = {}

    class P:
        def __init__(self):
            self.log, self.before, self.match = [], "", None

        def send(self, s):
            self.log.append(("send", s))
            if s == "\x01c" and W.fire_on_first_escape and len([x for x in self.log if x == ("send", "\x01c")]) == 1:
                fire("leak")

        def sendline(self, s=""):
            self.log.append(("sendline", s))
            m = re.search(r"echo (@@B\d+); (.*); echo (@@E\d+) rc", s)
            if m:
                self.before = f"{m.group(1)}\nout\n"
                self.match = re.match(r"(\d+)", "0")

        def expect(self, pat, timeout=None):
            self.log.append(("expect", pat))
            return 0

    class TS:
        returncode = None

        def poll(self):
            return None
    pm = W.pm
    W.fire_on_first_escape = True
    p = P()
    guard = pm.StartupGuard(TS())
    g = W.RealGuest(pm.GuardedConsole(p, guard))
    try:
        g.monitor("info network")
        out["monitor_raised"] = None
    except Exception as e:                                       # noqa: BLE001
        out["monitor_raised"] = type(e).__name__
    out["monitor_log"] = p.log[:]
    open(pm.ALERT, "w").close()          # the alert is gone again: only the latch can still stop the next command
    try:
        g.run("ip addr")
        out["after_stop"] = "sent"
    except Exception as e:                                       # noqa: BLE001
        out["after_stop"] = type(e).__name__
    out["log_after_stop"] = p.log[len(out["monitor_log"]):]
    # a clean console: real Guest.run goes through; disarmed guard does no check
    open(pm.ALERT, "w").close()
    W.fire_on_first_escape = False
    p2, guard2 = P(), pm.StartupGuard(TS())
    g2 = W.RealGuest(pm.GuardedConsole(p2, guard2))
    try:
        out["clean_run"] = list(g2.run("ip addr"))
    except Exception as e:                                       # noqa: BLE001
        out["clean_run"] = f"{type(e).__name__}: {e}"
    out["clean_checks"] = guard2.checks
    guard2.armed = False
    n = guard2.checks
    open(pm.ALERT, "a").write("late alert\n")
    try:
        g2.run("ip route")
        out["disarmed_run"] = "sent"
    except Exception as e:                                       # noqa: BLE001
        out["disarmed_run"] = type(e).__name__
    out["disarmed_checks"] = guard2.checks - n
    json.dump(out, open(os.path.join(d, "unit-console.json"), "w"), indent=1, default=str)


def scenario_main(name, d):
    spec = SCENARIOS[name]
    hdir, sb, out = os.path.join(d, "harness"), os.path.join(d, "stubs"), os.path.join(d, "out")
    for p in (hdir, out, os.path.join(d, "data"), os.path.join(d, "sys", "tap0"), os.path.join(d, "sys", "eth0"),
              os.path.join(d, "proc")):
        os.makedirs(p)
    for f in mounted_files(os.path.join(HERE, RS)) + ["probe_matrix.py"]:
        shutil.copy2(os.path.join(HERE, f), hdir)
    write_stubs(sb, os.path.join(d, "current_task"), spec.get("marker_left", False))
    with zipfile.ZipFile(os.path.join(d, "image.zip"), "w") as z:
        z.writestr("kernel", b"k")
    open(os.path.join(d, "sys", "tap0", "address"), "w").write(TAP + "\n")
    if not spec.get("no_eth0"):
        open(os.path.join(d, "sys", "eth0", "address"), "w").write(ETH0_MAC + "\n")
    cfg = dict(CFG)
    for k, v in spec.get("cfg", {}).items():
        if v is None:
            cfg.pop(k)
        else:
            cfg[k] = v
    os.environ["CT01_TARGETS"] = json.dumps(cfg)
    os.environ["CT01_SUITE"] = spec.get("suite", "arp")
    sys.path[:0] = [hdir, sb]
    sys.argv = ["probe_matrix.py", "ARM", out]
    import importlib.util
    spec_pm = importlib.util.spec_from_file_location("probe_matrix", os.path.join(hdir, "probe_matrix.py"))
    pm = importlib.util.module_from_spec(spec_pm)
    spec_pm.loader.exec_module(pm)          # imports arp_harness & co. from the mounted files only
    modules = {m: getattr(sys.modules.get(m), "__file__", None)
               for m in ("arp_harness", "arp_cases", "guest_state", "icmp_harness", "icmp_cases", "l2frames",
                         "l2eval", "signatures", "counter_window", "pcapng_stats")}
    import arp_cases
    import guest_state
    sys.path.append(HERE)                   # test helpers only (simulated guest, frame/counter builders)
    import selftest_l2 as B
    import selftest_l2eval as V
    import selftest_arp as SA
    from service import analysis as A
    W.pm, W.B, W.V, W.SA = pm, B, V, SA
    W.L = (pm.arp_harness.A.L if hasattr(pm, "arp_harness") else pm.icmp_harness.I.L if hasattr(pm, "icmp_harness")
           else __import__("l2frames"))
    W.spec, W.frames, W.commands, W.links, W.label, W.cfg = spec, [], [], 0, None, cfg
    W.counters, W.tshark_dead, W.worker_cmds, W.neigh_n, W.snap_fail, W.fired = dict(V.BASE), False, [], {}, False, set()
    A.STUCK[0] = spec.get("qemu_stuck", False)
    W.boot_console = []
    if spec.get("boot"):
        install_real_configure_network(A, spec)
    A.ARCH_CONFIGS["ARM"] = type("Cfg", (), {"image_zip_path": os.path.join(d, "image.zip"), "image_kernel_path": "/kernel",
                                             "image_rootfs_path": "/rootfs", "net_iface": "eth1",
                                             "qemu_cmd_template": "qemu-system-arm -k {kernel} -r {rootfs} -m {mac}"})
    if spec.get("cases") in ("missing", "duplicate"):     # a defective wiring/case list
        real = arp_cases.build_cases

        def build():
            cs = real()
            return cs[:-1] if spec["cases"] == "missing" else cs + [cs[0]]
        arp_cases.build_cases = build
    hc = os.path.join(d, "hostcap")
    os.makedirs(hc)
    pm.ALERT, pm.CAPTURE_DEAD, pm.HEARTBEAT = (os.path.join(hc, f) for f in ("alert.txt", "capture-dead.txt", "hb"))
    open(pm.ALERT, "w").close()
    pm.CTL, pm.DATA, pm.WORK = os.path.join(d, "ctl.jsonl"), os.path.join(d, "data") + "/", os.path.join(d, "work")
    pm.SYS_NET, pm.PROC_ROOT = os.path.join(d, "sys"), os.path.join(d, "proc")
    W.RealGuest = pm.Guest
    pm.Guest, pm.run_checked, pm.guest_frames = guest_class(SA, guest_state), fake_run_checked, guest_rows
    pm.subprocess = type("SP", (), {"Popen": FakeTshark, "DEVNULL": subprocess.DEVNULL,
                                    "TimeoutExpired": subprocess.TimeoutExpired, "run": subprocess.run})

    def ctl_dns(server, qname):
        if spec.get("liveness_fail"):
            raise OSError("timed out (fake)")
        return "DNS response rcode=0 (fake)"

    def ctl_http(ip, port, path="/healthcheck"):
        W.http_calls.append((ip, port, W.label))
        if spec.get("worker_http_fail") and W.label == "T14-A2 after":
            raise OSError("connection refused (fake)")
        if port == pm.LISTENER_PORT and W.listener_stopped:
            raise OSError("connection refused (fake listener stopped)")
        return "HTTP 200 (fake)"
    W.http_calls, W.listener_stopped = [], False
    pm.ctl_dns, pm.ctl_http = ctl_dns, ctl_http
    # 06B-4IR2: the IPv4 branch also uses a temporary listener and TCP controls: fakes, no socket is opened
    pm.ctl_tcp = lambda ip, port, banner=None: W.http_calls.append((ip, port, W.label)) or "connected (fake)"

    class FakeListener:
        def start(self):
            pass

        def stop(self):
            W.listener_stopped = True
    pm.Listener = FakeListener
    if spec.get("record_event"):        # fire an event right after a named check is recorded (handoff points)
        prefix, ev = spec["record_event"]
        real_record = pm.record

        def record(name, ok, **detail):
            real_record(name, ok, **detail)
            if name.startswith(prefix) and ("rec", prefix) not in W.fired:
                W.fired.add(("rec", prefix))
                fire(ev)
        pm.record = record
    real_read = pm.counters_read

    def counters_read(label):
        W.label = label
        return real_read(label)
    pm.counters_read = counters_read
    W.hb_stop, ctl_stop = threading.Event(), threading.Event()

    def hb():
        while not W.hb_stop.is_set():
            open(pm.HEARTBEAT + ".tmp", "w").write(str(time.time()))
            os.replace(pm.HEARTBEAT + ".tmp", pm.HEARTBEAT)
            W.hb_stop.wait(0.3)
    open(pm.HEARTBEAT, "w").write(str(time.time()))   # first beat before main(): no start-up race
    W.hb_thread = threading.Thread(target=hb, daemon=True)
    W.hb_thread.start()
    ctl_t = threading.Thread(target=ctl_loop_thread, args=(pm.CTL, spec.get("ctl"), ctl_stop), daemon=True)
    ctl_t.start()
    time.sleep(0.2)
    if spec.get("unit"):
        with contextlib.redirect_stdout(io.StringIO()):
            unit_console(d)
        W.hb_stop.set()
        ctl_stop.set()
        json.dump({"rc": None, "commands": [], "worker_cmds": [], "http_calls": [], "boot_console": [],
                   "mounted": [], "modules": modules, "fixture_sha": None, "out": os.path.join(out, "ARM")},
                  open(os.path.join(d, "scenario.json"), "w"), indent=1)
        return 0
    with contextlib.redirect_stdout(io.StringIO()):
        rc = pm.main()
    W.hb_stop.set()
    ctl_stop.set()
    final = rc if rc else (1 if [r for r in pm.results if not r["ok"]] else 0)
    json.dump({"rc": final, "commands": W.commands, "worker_cmds": W.worker_cmds, "http_calls": W.http_calls,
               "boot_console": W.boot_console, "analysis_sha": getattr(W, "analysis_sha", None),
               "mounted": mounted_files(os.path.join(HERE, RS)), "modules": modules,
               "fixture_sha": hashlib.sha256(f"06B-3B ARM harmless text fixture - not an ELF\n".encode()).hexdigest(),
               "out": os.path.join(out, "ARM")},
              open(os.path.join(d, "scenario.json"), "w"), indent=1)
    return 0


# ====================================================================== driver side
sys.path.insert(0, HERE)


def run_scenario(name, tmp):
    d = os.path.join(tmp, name)
    os.makedirs(d)
    p = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--scenario", name, "--dir", d],
                       capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        raise RuntimeError(f"scenario {name} crashed: {(p.stderr or p.stdout).strip()[-800:]}")
    sc = json.load(open(os.path.join(d, "scenario.json")))
    od = sc["out"]
    load = lambda f: json.load(open(os.path.join(od, f))) if os.path.exists(os.path.join(od, f)) else None  # noqa: E731
    sc.update(dir=d, result=load("result.json"), eval=load("arp-eval.json"), group=load("arp-group.json"),
              session=load("session.json"))
    import arp_harness as H
    sc["outcome"] = H.arch_outcome(sc["result"], sc["eval"], "ARM")
    sc["cli"] = cli_outcome(os.path.join(od, "result.json"), os.path.join(od, "arp-eval.json"))
    sc["script"] = script_mapping(sc["rc"], sc["cli"])
    return sc


def cli_outcome(result, ev, arch="ARM"):
    """arp_harness.py --outcome exactly as run-06b4i.sh calls it (`python3 "$H/arp_harness.py"`: the script's own
    directory provides arp_cases/icmp_harness)."""
    p = subprocess.run(["python3", os.path.join(HERE, "arp_harness.py"), "--outcome", result, ev, arch],
                       capture_output=True, text=True, timeout=60, cwd=os.path.dirname(result) or "/")
    return p.stdout.strip() if p.returncode == 0 else f"CLI-ERROR rc={p.returncode} {p.stderr.strip()[-200:]}"


def script_mapping(rc, outcome):
    """The per-architecture `case "$rc:$outcome" in ... esac` block of run-06b4i.sh, run by bash as is."""
    s = open(os.path.join(HERE, RS)).read()
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


def runs(sc):
    return [c for k, c in sc["commands"] if k == "run"]


def failed_tests(sc):
    return [r["test"] for r in sc["result"]["results"] if not r["ok"]]


def rec_of(sc, name):
    return [r for r in sc["result"]["results"] if r["test"] == name]


def gcase(sc, cid):
    return next(c for c in sc["group"]["cases"] if c["id"] == cid)


def ecase(sc, cid):
    return next(c for c in sc["eval"]["cases"] if c["id"] == cid)


def infra_ok(sc):
    return all(any(r["test"].startswith(p) and r["ok"] for r in sc["result"]["results"])
               for p in ("QEMU exit confirmed", "fixture, marker and temporary guest disk removed"))


def contract_cmds(cid):
    import arp_cases as A
    return [c for _, c in A.contract_steps(next(x for x in A.build_cases() if x["id"] == cid), "eth1")]


def own_cmds(cid):
    """The case's setup/trigger commands (the settle `sleep 3` is common to every case)."""
    return [c for c in contract_cmds(cid) if not c.startswith("sleep ")]


def sec_S(tmp):
    import concurrent.futures
    import arp_cases as A
    import arp_harness as H

    def one(name):
        try:
            return name, run_scenario(name, tmp)
        except Exception as e:                                   # noqa: BLE001
            print(f"SELFTEST-ERROR: {e}")
            return name, None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        S = dict(ex.map(one, SCENARIOS))
    g = lambda n: S[n] or {}   # a scenario that did not run fails every test that reads it  # noqa: E731

    # ---------------------------------------------------------------- clean
    c = g("clean")
    t("S1 clean: exit 0, status COMPLETED, outcome PASS (function and CLI), run script maps it to PASS",
      lambda: (c["rc"], c["result"]["status"], c["outcome"], c["cli"], c["script"])
      == (0, "COMPLETED", "PASS", "PASS", "PASS"))
    t("S2 clean: A1/A2 ĐẠT (live control), A3/S1 ĐẠT (kiểm quy tắc); labels and evidence kinds unchanged",
      lambda: [(x["id"], x["category"], x["verdict"], x["evidence_kind"]) for x in c["eval"]["cases"]]
      == [("T14-A1", "DAT", "ĐẠT", "live_control"), ("T14-A2", "DAT", "ĐẠT", "live_control"),
          ("T14-A3", "DAT_KIEM_QUY_TAC", "ĐẠT (kiểm quy tắc)", "rule_check"),
          ("T15-S1", "DAT_KIEM_QUY_TAC", "ĐẠT (kiểm quy tắc)", "rule_check")])
    t("S3 clean: every contract step of every case sent in order (arp_cases.contract_steps for eth1)",
      lambda: [x for x in runs(c) if x in sum((contract_cmds(i) for i in CASE_IDS), [])]
      == sum((contract_cmds(i) for i in CASE_IDS), []))
    t("S4 clean: no IPv4 probe, no ICMP case, no listener, no arping/raw tool sent to the guest",
      lambda: not any("--local-port" in x or "nslookup ct01" in x or x.startswith("ping6") or "-w 5" in x
                      or "arping" in x.split()[:1] for x in runs(c))
      and not any("listener" in r["test"] or "ICMP" in r["test"] for r in c["result"]["results"]))
    t("S5 clean: guest commands = link, then per case snapshot .. contract .. restore re-reads .. link (5 links)",
      lambda: sum("/get-task/" in x for x in runs(c)) == 5 and "/get-task/" in runs(c)[5]
      and runs(c)[-1].startswith("rm -f /tmp/r.out; curl"))
    t("S6 clean: neighbour collector = exactly `ip -j neigh show` in the worker, 2 per case + 1 for the A2 control",
      lambda: c["worker_cmds"] == [["ip", "-j", "neigh", "show"]] * 9
      and all(isinstance(x["neigh_before"], str) and isinstance(x["neigh_after"], str) for x in c["group"]["cases"]))
    t("S7 clean: worker -> manager HTTP for the A2 control after read B of A2 (plus the two liveness calls)",
      lambda: [x for x in c["http_calls"] if x[2] == "T14-A2 after"] == [["192.168.60.10", 8011, "T14-A2 after"]])
    t("S8 clean: live controls recorded with their evidence (A1: ctl ARP entry = worker eth0 MAC; A2: manager MAC "
      "on eth0); none for A3/S1",
      lambda: gcase(c, "T14-A1")["control"]["ok"] is True
      and gcase(c, "T14-A1")["control"]["detail"]["ctl_arp"]["ok"] is True
      and gcase(c, "T14-A1")["control"]["detail"]["worker_eth0_mac"] == ETH0_MAC
      and gcase(c, "T14-A2")["control"]["detail"]["worker_neighbour"]["lladdr"] == MANAGER_MAC
      and gcase(c, "T14-A3")["control"] is None and gcase(c, "T15-S1")["control"] is None)
    t("S9 clean: paths and parameters passed to the evaluator (tap0.pcapng, counters-raw.jsonl, TAP MAC, eth1)",
      lambda: c["eval"]["inputs"] == {"pcap": os.path.join(c["out"], "tap0.pcapng"),
                                      "counters": os.path.join(c["out"], "counters-raw.jsonl"),
                                      "tap_mac": TAP, "iface": "eth1"})
    t("S10 clean: group record JSON: arch, interface, TAP MAC, fixture hash, planned cases, collector command",
      lambda: (c["group"]["arch"], c["group"]["iface"], c["group"]["tap_mac"], c["group"]["fixture_sha256"],
               c["group"]["planned_case_ids"], c["group"]["neigh_command"])
      == ("ARM", "eth1", TAP, c["fixture_sha"], list(CASE_IDS), ["ip", "-j", "neigh", "show"])
      and c["group"]["stopped"] is None and "guard_stopped" not in c["group"])
    t("S11 clean: arp-eval.json: group_exit 0, group complete, no record problem, case requirements = 4 restores + "
      "4 links after",
      lambda: c["eval"]["group_exit"] == 0 and c["eval"]["group_complete"] is True and c["eval"]["record_problems"] == []
      and sorted(c["eval"]["case_requirements"]) == sorted([H.restore_name(i) for i in CASE_IDS]
                                                            + [H.link_after_name(i) for i in CASE_IDS]))
    t("S12 clean: one result record per case, named 'probe <id> (arp, ...) -> <verdict>'",
      lambda: sorted(r["test"] for r in c["result"]["results"] if r["test"].startswith("probe "))
      == sorted(H.case_test_name(x) for x in c["eval"]["cases"]))
    t("S13 imports in the fake container came only from the files run-06b4i.sh mounts",
      lambda: all(p and os.path.dirname(p) == os.path.join(c["dir"], "harness") for p in c["modules"].values())
      and {"arp_harness.py", "arp_cases.py", "guest_state.py", "icmp_harness.py", "icmp_cases.py", "l2frames.py",
           "l2eval.py", "signatures.py", "counter_window.py", "pcapng_stats.py"} <= set(c["mounted"]))
    t("S14 clean: session-wide measurement still written separately, QEMU exit/capture/cleanup records ok",
      lambda: c["session"] is not None and infra_ok(c) and rec_of(c, "tap0 capture stopped cleanly")[0]["ok"])

    # ---------------------------------------------------------------- wiring defects / service links
    for n, why in (("missing-case", "case missing: T15-S1"), ("duplicate-case", "more than once")):
        x = g(n)
        t(f"S15 {n}: never PASS; outcome FAIL naming the record problem; script FAIL; group record check FAIL in "
          "result.json",
          lambda x=x, why=why: x["outcome"].startswith("FAIL") and why in x["outcome"] and x["script"] == "FAIL"
          and H.GROUP_RECORD_NAME in failed_tests(x))
    x = g("link-before-http000")
    t("S16 service link before fails: no case command sent, every case CHƯA KIỂM CHỨNG, outcome FAIL",
      lambda: not any(y in runs(x) for y in sum((own_cmds(i) for i in CASE_IDS), []))
      and set(cats(x).values()) == {"CHUA_KIEM_CHUNG"} and x["outcome"].startswith("FAIL") and x["script"] == "FAIL"
      and H.LINK_BEFORE_NAME in failed_tests(x))
    x = g("link-after-A1-badhash")
    t("S17 service link after A1 with another hash: A1 CHƯA KIỂM CHỨNG, outcome FAIL (link record), later cases run",
      lambda: cats(x)["T14-A1"] == "CHUA_KIEM_CHUNG" and cats(x)["T15-S1"] == "DAT_KIEM_QUY_TAC"
      and H.link_after_name("T14-A1") in failed_tests(x) and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")

    # ---------------------------------------------------------------- neighbour collector
    x = g("neigh-error-A2-after")
    t("S18 collector fails (rc != 0) after A2: A2 LỖI PHÉP ĐO with the error kept, collector record FAIL, never PASS",
      lambda: cats(x)["T14-A2"] == "LOI_PHEP_DO" and "neigh_after_error" in gcase(x, "T14-A2")
      and H.NEIGH_READ_NAME in failed_tests(x) and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("neigh-notjson-A1-before")
    t("S19 collector output not JSON before A1: A1 LỖI PHÉP ĐO, outcome FAIL",
      lambda: cats(x)["T14-A1"] == "LOI_PHEP_DO" and x["outcome"].startswith("FAIL"))
    x = g("neigh-exception-A3-after")
    t("S20 collector raises an unexpected exception: recorded, A3 LỖI PHÉP ĐO, QEMU/cleanup done, outcome FAIL",
      lambda: "KeyError" in gcase(x, "T14-A3")["neigh_after_error"] and cats(x)["T14-A3"] == "LOI_PHEP_DO"
      and infra_ok(x) and x["outcome"].startswith("FAIL"))

    # ---------------------------------------------------------------- FAIL + measurement error, not started
    x = g("fail-and-measure-A3")
    t("S21 guest MAC on eth0 after A3 AND counter read error: A3 FAIL, measurement error kept beside the evidence",
      lambda: cats(x)["T14-A3"] == "FAIL" and ecase(x, "T14-A3")["failure_evidence"]
      and any("T14-A3 after" in m for m in ecase(x, "T14-A3")["measurement_errors"])
      and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("notstarted-A3")
    t("S22 guest state unreadable before A3: nothing sent for A3, not_started kept, LỖI THỰC THI, S1 still runs; "
      "outcome UNVERIFIED (no restore/link requirement for a case that changed nothing)",
      lambda: not any(y in runs(x) for y in own_cmds("T14-A3")) and ecase(x, "T14-A3")["not_started"] is True
      and cats(x)["T14-A3"] == "LOI_THUC_THI" and cats(x)["T15-S1"] == "DAT_KIEM_QUY_TAC"
      and H.restore_name("T14-A3") not in x["eval"]["case_requirements"]
      and x["outcome"].startswith("UNVERIFIED") and x["script"] == "UNVERIFIED")
    x = g("notstarted-A3-neigh-fail")
    t("S23 not started + guest MAC on a worker neighbour after it: FAIL wins, not_started and the evidence kept",
      lambda: cats(x)["T14-A3"] == "FAIL" and ecase(x, "T14-A3")["not_started"] is True
      and ecase(x, "T14-A3")["failure_evidence"] and x["outcome"].startswith("FAIL"))

    # ---------------------------------------------------------------- execution errors, restore
    x = g("exec-error-A1")
    t("S24 setup fails in A1: trigger not sent, restore still done, A1 LỖI THỰC THI, later cases ĐẠT; UNVERIFIED",
      lambda: "ping -c 1 -W 2 -s 1401 192.168.60.2" not in runs(x) and gcase(x, "T14-A1")["guest_state"]["restore"]["restored"]
      and cats(x)["T14-A1"] == "LOI_THUC_THI" and cats(x)["T14-A2"] == "DAT"
      and x["outcome"].startswith("UNVERIFIED") and x["script"] == "UNVERIFIED")
    x = g("timeout-A3")
    t("S25 console timeout on the A3 trigger: LỖI THỰC THI, restore done, S1 still runs; UNVERIFIED",
      lambda: cats(x)["T14-A3"] == "LOI_THUC_THI" and gcase(x, "T14-A3")["guest_state"]["restore"]["restored"]
      and cats(x)["T15-S1"] == "DAT_KIEM_QUY_TAC" and x["outcome"].startswith("UNVERIFIED"))
    x = g("no-frame")
    t("S26 the simulated kernel sends nothing: every case KHÔNG TẠO ĐƯỢC GÓI, never ĐẠT; UNVERIFIED",
      lambda: set(cats(x).values()) == {"KHONG_TAO_DUOC_GOI"} and x["outcome"].startswith("UNVERIFIED")
      and x["script"] == "UNVERIFIED")
    x = g("counter-read-error-A3")
    t("S27 counter read error on 'T14-A3 after': A3 LỖI PHÉP ĐO, outcome FAIL",
      lambda: cats(x)["T14-A3"] == "LOI_PHEP_DO" and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("restore-fail-A2")
    t("S28 restore fails after A2: A3/S1 not run and none of their commands sent (contract), A2 CHƯA KIỂM CHỨNG "
      "(khôi phục)",
      lambda: gcase(x, "T14-A3")["not_run"] and gcase(x, "T15-S1")["not_run"]
      and not any(y in runs(x) for y in own_cmds("T14-A3") + own_cmds("T15-S1"))
      and cats(x) == {"T14-A1": "DAT", "T14-A2": "CHUA_KIEM_CHUNG", "T14-A3": "CHUA_KIEM_CHUNG",
                      "T15-S1": "CHUA_KIEM_CHUNG"} and "khôi phục" in ecase(x, "T14-A2")["verdict"])
    t("S29 restore fails after A2: run outcome FAIL (restore confirmation), no service link after A2, script FAIL",
      lambda: H.restore_name("T14-A2") in failed_tests(x) and not rec_of(x, H.link_after_name("T14-A2"))
      and x["outcome"].startswith("FAIL") and x["script"] == "FAIL" and infra_ok(x))

    # ---------------------------------------------------------------- guard stops
    for n, rc, why, last in (("marker-after-A2-ping", 98, "host capture lost", "ping -c 1 -W 2 -s 1402 192.168.60.10"),
                             ("heartbeat-stale-after-A1-setup", 98, "heartbeat", "ip route add 192.168.60.2/32 dev eth1"),
                             ("tshark-exit-after-S1-down", 98, "tap0 tshark exited", "ip link set dev eth1 down"),
                             ("leak-after-A3-ping", 99, "LEAK", "ping -c 1 -W 2 -s 1403 10.200.0.6")):
        x = g(n)
        t(f"S30 {n}: exit {rc}, the command that tripped the guard is the LAST one sent (no restore, no link)",
          lambda x=x, rc=rc, last=last: x["rc"] == rc and runs(x)[-1] == last)
        t(f"S31 {n}: status names the cause, outcome FAIL, script FAIL, no evaluation",
          lambda x=x, why=why: why in x["result"]["status"] and x["outcome"].startswith("FAIL")
          and x["script"] == "FAIL" and x["eval"] is None)
        t(f"S32 {n}: QEMU shut down and cleanup done after the stop; group record kept with the guard stop",
          lambda x=x: infra_ok(x) and x["group"] is not None and x["group"].get("guard_stopped"))
    x = g("leak-before-S1")
    t("S33 alert written during 'T15-S1 before' (read A): S1 setup NOT sent, exit 99, leak record when=before",
      lambda: x["rc"] == 99 and not any(y in runs(x) for y in own_cmds("T15-S1"))
      and any(r["test"] == "NO probe packet seen on host interfaces (leak monitor)" and r.get("when") == "before"
              for r in x["result"]["results"]))
    x = g("alert-unreadable-before-A2")
    t("S34 alert file unreadable during 'T14-A2 before': never 'no alert'; A2 setup NOT sent; ERROR exit 1; FAIL",
      lambda: x["rc"] == 1 and x["result"]["status"].startswith("ERROR") and "IsADirectoryError" in x["result"]["status"]
      and not any(y in runs(x) for y in own_cmds("T14-A2")) and x["outcome"].startswith("FAIL") and infra_ok(x))
    x = g("marker-before-A2")
    t("S35 capture lost during 'T14-A2 before': A2 setup NOT sent, exit 98, the restore reaches no guest (not "
      "restored), A3/S1 not run",
      lambda: x["rc"] == 98 and not any(y in runs(x) for y in own_cmds("T14-A2"))
      and runs(x)[-1] == __import__("guest_state").snapshot_cmd("eth1")
      and gcase(x, "T14-A2")["guest_state"]["restore"]["restored"] is False
      and gcase(x, "T14-A3")["not_run"] and gcase(x, "T15-S1")["not_run"])

    # ---------------------------------------------------------------- live controls
    for n, cid, why in (("ctl-arp-wrong-mac", "T14-A1", "!= worker eth0 MAC"), ("ctl-no-arp", "T14-A1", "ok_before"),
                        ("ctl-worker-fail-in-A1", "T14-A1", "fails_in_window"),
                        ("cfg-worker-ip-other", "T14-A1", "not the worker eth0 address"),
                        ("eth0-mac-missing", "T14-A1", "worker eth0 MAC None"),
                        ("a2-manager-neigh-missing", "T14-A2", "0 valid row(s)"),
                        ("a2-manager-other-mac", "T14-A2", "not a usable binding"),
                        ("a2-worker-http-fail", "T14-A2", "worker -> manager HTTP not ok"),
                        ("cfg-no-manager-mac", "T14-A2", "manager MAC None")):
        x = g(n)
        other = "T14-A2" if cid == "T14-A1" else "T14-A1"
        t(f"S36 {n}: {cid} control not alive -> CHƯA KIỂM CHỨNG (không có đối chứng sống), {other} still ĐẠT; "
          "UNVERIFIED, never PASS",
          lambda x=x, cid=cid, other=other, why=why: cats(x)[cid] == "CHUA_KIEM_CHUNG"
          and ecase(x, cid)["verdict"] == "CHƯA KIỂM CHỨNG (không có đối chứng sống)" and cats(x)[other] == "DAT"
          and why in json.dumps(gcase(x, cid)["control"], ensure_ascii=False)
          and x["outcome"].startswith("UNVERIFIED") and x["script"] == "UNVERIFIED")
    for n in ("ctl-missing", "ctl-malformed"):
        x = g(n)
        t(f"S37 {n}: ctl log not usable -> A1 and A2 CHƯA KIỂM CHỨNG, A3/S1 ĐẠT (kiểm quy tắc); UNVERIFIED",
          lambda x=x: cats(x) == {"T14-A1": "CHUA_KIEM_CHUNG", "T14-A2": "CHUA_KIEM_CHUNG",
                                  "T14-A3": "DAT_KIEM_QUY_TAC", "T15-S1": "DAT_KIEM_QUY_TAC"}
          and "ctl log not readable" in json.dumps(gcase(x, "T14-A1")["control"]) and x["outcome"].startswith("UNVERIFIED"))

    # ---------------------------------------------------------------- infrastructure, errors outside the group
    for n, why in (("tap0-drops", "drop statistics"), ("qemu-not-exiting", "QEMU exit confirmed"),
                   ("cleanup-marker-left", "fixture, marker"), ("liveness-fails", "capture liveness")):
        x = g(n)
        t(f"S38 {n}: four cases ĐẠT, outcome still FAIL ({why}); script FAIL",
          lambda x=x, why=why: set(cats(x).values()) <= {"DAT", "DAT_KIEM_QUY_TAC"} and len(cats(x)) == 4
          and x["outcome"].startswith("FAIL") and why in x["outcome"] and x["script"] == "FAIL")
    x = g("pcap-unreadable")
    t("S39 tap0 capture unreadable: every case LỖI PHÉP ĐO, outcome FAIL",
      lambda: set(cats(x).values()) == {"LOI_PHEP_DO"} and x["outcome"].startswith("FAIL"))
    x = g("error-after-group")
    t("S40 an error after the group (tap0 address unreadable): ERROR exit 1, record kept, no evaluation, QEMU and "
      "cleanup done, FAIL",
      lambda: x["rc"] == 1 and x["result"]["status"].startswith("ERROR") and x["group"] is not None
      and x["eval"] is None and infra_ok(x) and x["outcome"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("callback-errors")
    t("S41 control/collector callbacks fail (ctl log is a directory, worker HTTP refused, collector KeyError): every "
      "error recorded, no case ĐẠT through them, QEMU/cleanup done, FAIL",
      lambda: cats(x)["T14-A1"] == "CHUA_KIEM_CHUNG" and cats(x)["T14-A2"] == "CHUA_KIEM_CHUNG"
      and cats(x)["T14-A3"] == "LOI_PHEP_DO" and infra_ok(x) and x["outcome"].startswith("FAIL"))
    t("S42 no scenario other than clean (and the two valid-endpoint controls) passes",
      lambda: [n for n in SCENARIOS if n not in ("clean", "a1-other-name-same-endpoint", "local-unicast-other-both") and S[n]
               and (S[n]["outcome"] == "PASS" or S[n]["script"] == "PASS")] == [])
    t("S43 function and CLI outcome agree in every scenario",
      lambda: all(S[n]["outcome"] == S[n]["cli"] for n in SCENARIOS if S[n]))
    sec_S_ir1(g, H)
    sec_S_ir2(g, H)
    return S


def after_topology(sc):
    """Guest commands sent after the last topology command (the handoff point), or None if it was never sent."""
    r = runs(sc)
    return r[r.index("curl --version | head -1") + 1:] if "curl --version | head -1" in r else None


def sec_S_ir2(g, H):
    """06B-4IR2: IR1-R1 handoff of the startup guard to the IPv4/ICMP/ARP branches; IR1-R2 unusable endpoint MACs."""
    x = g("ipv4-clean")
    link4 = ("curl -s -m 10 -o /tmp/r.out -w 'HTTP=%{http_code}\\n' http://10.200.0.1:8011/api/v1/sandbox-worker/"
             "get-task/06b3b-arm-task/file; sha256sum /tmp/r.out")
    t("R1.1 ipv4 clean: no stop; service link, the 7 probes (6 TCP + 1 nslookup; no ssh ip configured) and service link sent in order, "
      "status COMPLETED (shared path unchanged when nothing happens)",
      lambda: x["result"]["status"] == "COMPLETED" and after_topology(x)[0] == link4 and after_topology(x)[-1] == link4
      and len(after_topology(x)) == 9 and sum("--local-port 4100" in c for c in after_topology(x)) == 6
      and sum(c.startswith("nslookup ") for c in after_topology(x)) == 1)
    for n, rc, why in (("ipv4-handoff-capture", 98, "CAPTURE LOST: ipv4 group: before"),
                       ("ipv4-handoff-leak", 99, "LEAK: ipv4 group: before"),
                       ("ipv4-handoff-alert-unreadable", 1, "ERROR: IsADirectoryError"),
                       ("ipv4-handoff-heartbeat", 98, "CAPTURE LOST: ipv4 group: before")):
        x = g(n)
        t(f"R1.2 {n}: event right after the topology gate -> NO guest command after the handoff (the service link "
          f"'before probes' is not sent); exit {rc}",
          lambda x=x, rc=rc, why=why: after_topology(x) == [] and x["rc"] == rc and x["result"]["status"].startswith(why))
        t(f"R1.3 {n}: QEMU exit and cleanup still done; outcome FAIL",
          lambda x=x: infra_ok(x) and H.arch_outcome(x["result"], None, "ARM").startswith("FAIL"))
    x = g("ipv4-after-service-link")
    t("R1.4 ipv4: event during the service link 'before probes' -> it is the last guest command (no probe); exit 98",
      lambda: after_topology(x) == [link4] and x["rc"] == 98 and infra_ok(x))
    x = g("ipv4-after-probe")
    t("R1.5 ipv4: alert during the first probe -> that probe is the last guest command; leak record phase "
      "'ipv4 group'; exit 99",
      lambda: len(after_topology(x)) == 2 and "--local-port 41000" in after_topology(x)[1] and x["rc"] == 99
      and any(r["test"] == "NO probe packet seen on host interfaces (leak monitor)" and r.get("phase") == "ipv4 group"
              for r in x["result"]["results"]) and infra_ok(x))
    for n, rc in (("icmp-handoff-capture", 98), ("arp-handoff-capture", 98), ("arp-handoff-leak", 99)):
        x = g(n)
        t(f"R1.6 {n}: handoff to the GuardedRunner still blocks: no guest command after the topology gate; exit {rc}",
          lambda x=x, rc=rc: after_topology(x) == [] and x["rc"] == rc and infra_ok(x)
          and x["script"] == "FAIL")
    # IR1-R2
    for n, why in (("zero-mac-cfg", "all-zero"), ("zero-mac-payload", "all-zero"), ("zero-mac-both", "all-zero"),
                   ("broadcast-mac-both", "group"), ("multicast-mac-both", "group")):
        x = g(n)
        t(f"R2.1 {n}: A1 control not alive (endpoint MAC cannot identify the interface), reason and raw MAC kept; "
          "A2 ĐẠT; never PASS (function, CLI, Bash)",
          lambda x=x, why=why: cats(x)["T14-A1"] == "CHUA_KIEM_CHUNG" and cats(x)["T14-A2"] == "DAT"
          and why in json.dumps(gcase(x, "T14-A1")["control"]) and x["outcome"].startswith("UNVERIFIED")
          and x["cli"] == x["outcome"] and x["script"] == "UNVERIFIED")
    x = g("zero-mac-both")
    t("R2.2 zero-mac-both: the configured MAC is kept as given (not replaced) in the control record",
      lambda: gcase(x, "T14-A1")["control"]["detail"]["ctl_sandboxnet_mac"] == "00:00:00:00:00:00")
    x = g("local-unicast-other-both")
    t("R2.3 another locally administered unicast endpoint MAC (0a:…) on both sides -> PASS (U/L bit not forbidden)",
      lambda: x["script"] == "PASS" and cats(x)["T14-A1"] == "DAT")


def monitors(sc):
    return [c for k, c in sc["commands"] if k == "monitor"]


def sec_S_ir1(g, H):
    """06B-4IR1: I1 startup/topology guard, I2 ctl interface, I3 ctl log quality, through probe_matrix.main()."""
    boot_first = "ip addr add 10.200.0.2/30 brd + dev eth1"
    for n, rc, why in (("boot-leak", 99, "LEAK: startup: after 'expect'"), ("boot-capture", 98, "CAPTURE LOST: startup"),
                       ("boot-leak-swallowed", 99, "LEAK: startup")):
        x = g(n)
        t(f"I1.1 {n}: real _configure_network body: the event during `ip addr add` stops BEFORE `route add`/DNS; "
          f"exit {rc}",
          lambda x=x, rc=rc, why=why: x["boot_console"] == [boot_first] and x["rc"] == rc
          and x["result"]["status"].startswith(why) and x["analysis_sha"])
        t(f"I1.2 {n}: no topology command, no monitor call, no ARP command after the event, no 'guest booted' "
          "record; QEMU exit and cleanup done; outcome/CLI/script FAIL",
          lambda x=x: runs(x) == [] and monitors(x) == [] and infra_ok(x) and x["outcome"].startswith("FAIL")
          and not rec_of(x, "guest booted and network configured")
          and x["cli"].startswith("FAIL") and x["script"] == "FAIL")
    for n, rc, sent in (("topology-leak", 99, ["ip addr"]), ("topology-capture", 98, ["ip addr"]),
                        ("topology-heartbeat", 98, ["ip addr", "ip route"])):
        x = g(n)
        t(f"I1.3 {n}: the topology command that saw the event is the last guest operation (no further command, no "
          f"monitor); exit {rc}",
          lambda x=x, rc=rc, sent=sent: runs(x) == sent and monitors(x) == [] and x["rc"] == rc
          and "startup" in x["result"]["status"])
        t(f"I1.4 {n}: QEMU exit and cleanup done; no group record, no evaluation; outcome/CLI/script FAIL",
          lambda x=x: infra_ok(x) and x["group"] is None and x["eval"] is None and x["outcome"].startswith("FAIL")
          and x["cli"].startswith("FAIL") and x["script"] == "FAIL")
    x = g("topology-leak")
    t("I1.5 topology-leak: leak record names the startup phase and the operation",
      lambda: any(r["test"] == "NO probe packet seen on host interfaces (leak monitor)" and r.get("phase") == "startup"
                  and r.get("operation") == "ip addr" for r in x["result"]["results"]))
    x = g("monitor-leak")
    t("I1.6 monitor-leak: the event during `monitor info network` stops before the ARP group (no service link, no "
      "case command); exit 99",
      lambda: x["rc"] == 99 and monitors(x) == ["info network"] and not any("/get-task/" in c for c in runs(x))
      and x["result"]["status"].startswith("LEAK: startup: after 'monitor info network'")
      and len(runs(x)) == 5 and infra_ok(x) and x["script"] == "FAIL")
    x = g("startup-alert-unreadable")
    t("I1.7 alert file unreadable during the topology gate: never 'no alert'; monitor not sent; ERROR exit 1; FAIL",
      lambda: x["rc"] == 1 and "IsADirectoryError" in x["result"]["status"] and monitors(x) == []
      and infra_ok(x) and x["outcome"].startswith("FAIL"))
    x = g("icmp-topology-leak")
    t("I1.8 shared path, ICMP suite: the same startup guard stops after `ip addr` (no ping, no link); exit 99",
      lambda: x["rc"] == 99 and runs(x) == ["ip addr"] and monitors(x) == [] and infra_ok(x))
    try:
        u = json.load(open(os.path.join(g("unit-console")["dir"], "unit-console.json")))
    except (OSError, KeyError, ValueError):
        u = {}                                   # the unit scenario did not run: its tests fail below
    t("I1.9 real Guest.monitor over the guarded console: an event after the first escape keystroke stops before "
      "`info network` is typed (inside one multi-keystroke function)",
      lambda: u.get("monitor_raised") == "LeakDetected" and [x[0] for x in u["monitor_log"]] == ["send", "expect"]
      and not any(x[1] == "info network" for x in u["monitor_log"]))
    t("I1.10 after the stop every later send raises without reaching the console, even once the alert is gone "
      "(latched)",
      lambda: u["after_stop"] == "LeakDetected" and u["log_after_stop"] == [])
    t("I1.11 clean console: real Guest.run goes through with checks; a disarmed guard does no check",
      lambda: isinstance(u["clean_run"], list) and u["clean_run"][0] == 0 and u["clean_checks"] >= 3
      and u["disarmed_run"] == "sent" and u["disarmed_checks"] == 0)
    c = g("clean")
    t("I1.12 clean: the startup guard changes no result: PASS, A1 ctl device eth0 bound by the endpoint MAC",
      lambda: c["script"] == "PASS" and gcase(c, "T14-A1")["control"]["detail"]["ctl_devices"] == ["eth0"]
      and gcase(c, "T14-A1")["control"]["detail"]["ctl_sandboxnet_mac"] == CTL_MAC)
    # I2
    for n, why in (("a1-wrong-interface", "not ctl's sandboxnet endpoint MAC"),
                   ("a1-missing-interface", "is not an object with exactly"),
                   ("a1-two-devices", "more than one device"), ("a1-entry-other-ip", "!= worker address"),
                   ("cfg-no-ctl-mac", "cannot be identified")):
        x = g(n)
        t(f"I2.1 {n}: A1 control not alive -> CHƯA KIỂM CHỨNG, reason and raw entries kept; A2 ĐẠT; never PASS "
          "(function, CLI, Bash)",
          lambda x=x, why=why: cats(x)["T14-A1"] == "CHUA_KIEM_CHUNG" and cats(x)["T14-A2"] == "DAT"
          and gcase(x, "T14-A1")["control"]["ok"] is False and why in json.dumps(gcase(x, "T14-A1")["control"])
          and x["outcome"].startswith("UNVERIFIED") and x["cli"] == x["outcome"] and x["script"] == "UNVERIFIED")
    x = g("a1-other-name-same-endpoint")
    t("I2.2 the same sandboxnet endpoint under another interface name (eth7) is accepted: PASS",
      lambda: x["script"] == "PASS" and gcase(x, "T14-A1")["control"]["detail"]["ctl_devices"] == ["eth7"])
    # I3
    for n, why in (("duplicate-control", "duplicate record"), ("http-missing-detail", "ctl log not readable"),
                   ("http-wrong-detail", "HTTP 500"), ("ctl-extra-key", "ctl log not readable")):
        x = g(n)
        t(f"I3.1 {n}: A1 and A2 controls not alive -> CHƯA KIỂM CHỨNG, reason kept; A3/S1 unchanged; never PASS",
          lambda x=x, why=why: cats(x) == {"T14-A1": "CHUA_KIEM_CHUNG", "T14-A2": "CHUA_KIEM_CHUNG",
                                           "T14-A3": "DAT_KIEM_QUY_TAC", "T15-S1": "DAT_KIEM_QUY_TAC"}
          and why in json.dumps(gcase(x, "T14-A1")["control"]) and why in json.dumps(gcase(x, "T14-A2")["control"])
          and x["outcome"].startswith("UNVERIFIED") and x["script"] == "UNVERIFIED")


# ====================================================================== R: required confirmations, R1 through the wiring
def sec_R(S, tmp):
    import arp_harness as H
    c = S.get("clean")
    if not c or not c.get("eval") or not c.get("group"):
        t("R0 clean scenario available with its evaluation and group record", lambda: False)
        return
    names = [r["test"] for r in c["result"]["results"]]
    reqs = list(H.REQUIRED_RECORDS) + c["eval"]["case_requirements"]
    t("R1 the real ARP path records every required confirmation exactly once (static + per case)",
      lambda: all(names.count(n) == 1 for n in reqs))
    t("R2 the real ARP path records no other non-info, non-case check outside the required list",
      lambda: [n for n in names if not n.startswith("info:") and not n.startswith("probe ") and n not in reqs] == [])
    t("R3 a required confirmation missing / twice / ok 'true' -> FAIL",
      lambda: all(H.arch_outcome(v, c["eval"], "ARM").startswith("FAIL") for v in (
          {**c["result"], "results": [r for r in c["result"]["results"] if r["test"] != "QEMU exit confirmed"]},
          {**c["result"], "results": c["result"]["results"] + [rec_of(c, H.NEIGH_READ_NAME)[0]]},
          {**c["result"], "results": [dict(r, ok="true") if r["test"] == H.LINK_BEFORE_NAME else r
                                      for r in c["result"]["results"]]})))
    t("R4 a per-case confirmation missing (restore after S1 / link after A2) -> FAIL",
      lambda: all(H.arch_outcome({**c["result"], "results": [r for r in c["result"]["results"] if r["test"] != n]},
                                 c["eval"], "ARM").startswith("FAIL")
                  for n in (H.restore_name("T15-S1"), H.link_after_name("T14-A2"))))
    t("R5 case_requirements missing in arp-eval.json -> FAIL",
      lambda: H.arch_outcome(c["result"], {k: v for k, v in c["eval"].items() if k != "case_requirements"},
                             "ARM").startswith("FAIL"))
    t("R6 group_exit 2 in arp-eval.json -> FAIL; evaluation of another architecture -> FAIL",
      lambda: H.arch_outcome(c["result"], {**c["eval"], "group_exit": 2}, "ARM").startswith("FAIL")
      and H.arch_outcome(c["result"], c["eval"], "MIPS").startswith("FAIL"))

    # R1 (06B-4HR2) through the wiring: the record of the clean run, made contradictory, re-evaluated by
    # arp_harness.evaluate() on the same capture/counters, then --outcome and the script mapping
    od = c["out"]
    pcap, cnt = os.path.join(od, "tap0.pcapng"), os.path.join(od, "counters-raw.jsonl")

    def variant(name, change):
        rec = copy.deepcopy(c["group"])
        change(rec)
        rec0 = copy.deepcopy(rec)
        ev = H.evaluate(pcap, cnt, TAP, rec, "ARM", c["fixture_sha"], "eth1")
        d = os.path.join(tmp, "r1-" + name)
        os.makedirs(d)
        rp, ep = os.path.join(d, "result.json"), os.path.join(d, "arp-eval.json")
        res = copy.deepcopy(c["result"])
        res["results"] = [r for r in res["results"] if not r["test"].startswith("probe ")
                          and r["test"] != H.GROUP_RECORD_NAME]
        res["results"].append({"arch": "ARM", "test": H.GROUP_RECORD_NAME, "ok": ev["group_complete"] is True})
        res["results"] += [{"arch": "ARM", "test": H.case_test_name(x), "ok": x["ok"]} for x in ev["cases"]]
        json.dump(res, open(rp, "w"))
        json.dump(ev, open(ep, "w"), ensure_ascii=False, default=str)
        cli = cli_outcome(rp, ep)
        return ev, cli, script_mapping(0, cli), rec == rec0

    def a1(rec):
        return next(x for x in rec["cases"] if x["id"] == "T14-A1")

    def perm_dynamic(rec):      # baseline: flags 6 (ATF_PERM) in neigh_dynamic, entry lost in the re-read state
        a1(rec)["guest_state"]["before"]["neigh_dynamic"]["10.200.0.9 eth1"] = ["02:00:00:00:00:09", 6]

    def overlap(rec):           # the same key in both groups, baseline and re-read state
        for st in (a1(rec)["guest_state"]["before"], a1(rec)["guest_state"]["restore"]["after"]):
            k = next(iter(st["neigh_dynamic"]))
            st["neigh_static"][k] = st["neigh_dynamic"][k][0]

    def after_perm(rec):        # re-read state contradictory, baseline clean
        a1(rec)["guest_state"]["restore"]["after"]["neigh_dynamic"]["10.200.0.9 eth1"] = ["02:00:00:00:00:09", 4]

    def dyn_change(rec):        # control: a valid dynamic change is not forced (exit stays 0)
        a1(rec)["guest_state"]["restore"]["after"]["neigh_dynamic"] = {}
    for name, ch, word in (("perm-dynamic", perm_dynamic, "PERMANENT flag"), ("overlap", overlap, "in both"),
                           ("after-perm", after_perm, "PERMANENT flag")):
        ev, cli, scr, same = variant(name, ch)
        t(f"R7 R1 through the wiring ({name}): record problem, group exit 2, arp_harness --outcome FAIL, script FAIL, "
          "record not modified",
          lambda ev=ev, cli=cli, scr=scr, same=same, word=word: any(word in p for p in ev["record_problems"])
          and ev["group_exit"] == 2 and ev["group_complete"] is False and cli.startswith("FAIL") and scr == "FAIL"
          and same and ecase({"eval": ev}, "T14-A1")["category"] == "CHUA_KIEM_CHUNG")
    ev, cli, scr, same = variant("dyn-change", dyn_change)
    t("R8 control: a valid dynamic neighbour change in the re-read state is not forced: still PASS through the wiring",
      lambda: ev["record_problems"] == [] and ev["group_exit"] == 0 and cli == "PASS" and scr == "PASS")


# ====================================================================== U: units
def sec_U(tmp):
    import arp_cases as A
    import arp_harness as H
    T0, T1 = 1000.0, 1010.0

    def recs(target, times, ok=True, detail=None):
        return [{"ts": x, "target": target, "ok": ok, "detail": detail} for x in times]
    arp_ok = {"ip": "192.168.60.2", "hw": ETH0_MAC, "flags": "0x2", "device": "eth0", "device_mac": CTL_MAC}
    wt, at, mt = H.ctl_target_http_worker("192.168.60.2"), H.ctl_target_arp_worker("192.168.60.2"), \
        H.ctl_target_http_manager("192.168.60.10")
    good = recs(wt, [T0 - 1, T0 + 5, T1 + 1], detail="HTTP 200") + recs(at, [T0 - 1, T0 + 5, T1 + 1], detail=arp_ok) \
        + recs(mt, [T0 - 1, T1 + 1], detail="HTTP 200")
    t("U1 ctl_window: OK before and after, no failure -> ok",
      lambda: H.ctl_window(good, wt, T0, T1, 3.0)["ok"] is True)
    t("U2 ctl_window: nothing after read B (yet) -> not ok", lambda: not H.ctl_window(recs(wt, [T0 - 1]), wt, T0, T1, 3.0)["ok"])
    t("U3 ctl_window: OK records only outside the slack -> not ok",
      lambda: not H.ctl_window(recs(wt, [T0 - 5, T1 + 5]), wt, T0, T1, 3.0)["ok"])
    t("U4 ctl_window: one failure inside the span -> not ok, counted",
      lambda: (lambda rr: H.ctl_window(rr, wt, T0, T1, 3.0)["fails_in_window"] == 1
               and H.ctl_window(rr, wt, T0, T1, 3.0)["problems"] == []
               and not H.ctl_window(rr, wt, T0, T1, 3.0)["ok"])(
          sorted(good + recs(wt, [T0 + 2], ok=False, detail="TimeoutError('timed out')"), key=lambda r: r["ts"])))
    t("U5 ctl_window: another target (prefix of it) never counts",
      lambda: not H.ctl_window(recs(wt + "0", [T0 - 1, T1 + 1]), wt, T0, T1, 3.0)["ok"])
    t("U6 ctl_records: a malformed line raises (never skipped); ok must be a boolean",
      lambda: all(raises(ValueError, lambda s=s: H.ctl_records(s)) for s in
                  ("{x\n", json.dumps({"ts": 1, "target": "a", "ok": "true"}) + "\n", "[1]\n",
                   json.dumps({"ts": True, "target": "a", "ok": True}) + "\n")))
    case = {c["id"]: c for c in A.build_cases()}
    t("U7 control_a1: clean -> ok; ARP entry with another MAC / incomplete flag / not an object -> not ok",
      lambda: H.control_a1(case["T14-A1"], good, T0, T1, 3.0, "192.168.60.2", ETH0_MAC, CTL_MAC)[0] is True
      and all(not H.control_a1(case["T14-A1"], [r if r["target"] != at else dict(r, detail=d) for r in good], T0, T1,
                               3.0, "192.168.60.2", ETH0_MAC, CTL_MAC)[0]
              for d in ({**arp_ok, "hw": OTHER_MAC}, {**arp_ok, "flags": "0x0"}, {**arp_ok, "flags": "zz"}, "x", None)))
    good3 = [dict(r, target=r["target"].replace("192.168.60.2", "192.168.60.3"),
                  detail=dict(r["detail"], ip="192.168.60.3") if isinstance(r["detail"], dict) else r["detail"])
             for r in good]
    t("U8 control_a1: worker address differs from the case target (ctl log of that address all OK) / eth0 MAC "
      "unknown -> not ok",
      lambda: H.control_a1(dict(case["T14-A1"], dst="192.168.60.3"), good3, T0, T1, 3.0, "192.168.60.3", ETH0_MAC,
                           CTL_MAC)[0]
      and not H.control_a1(case["T14-A1"], good3, T0, T1, 3.0, "192.168.60.3", ETH0_MAC, CTL_MAC)[0]
      and not H.control_a1(case["T14-A1"], good, T0, T1, 3.0, "192.168.60.2", None, CTL_MAC)[0])
    t("U9 control_a1: HTTP of ctl missing after the case -> not ok",
      lambda: not H.control_a1(case["T14-A1"], [r for r in good if not (r["target"] == wt and r["ts"] > T1)],
                               T0, T1, 3.0, "192.168.60.2", ETH0_MAC, CTL_MAC)[0])
    neigh_ok = json.dumps([{"dst": "192.168.60.10", "dev": "eth0", "lladdr": MANAGER_MAC, "state": ["REACHABLE"]}])
    http_ok = lambda: {"ok": True, "detail": "HTTP 200"}  # noqa: E731

    def a2(neigh=neigh_ok, http=http_ok, mac=MANAGER_MAC, ip="192.168.60.10", records=good):
        return H.control_a2(case["T14-A2"], records, T0, T1, 3.0, ip, mac, http, lambda: neigh)[0]
    t("U10 control_a2: clean -> ok; STALE/DELAY/PROBE bindings are usable", lambda: a2() and all(
        a2(neigh_ok.replace("REACHABLE", s)) for s in ("STALE", "DELAY", "PROBE")))
    t("U11 control_a2: INCOMPLETE/FAILED/NOARP, other MAC, two rows, invalid row that may be it, not JSON -> not ok",
      lambda: not any(a2(n) for n in (
          neigh_ok.replace("REACHABLE", "FAILED"), neigh_ok.replace("REACHABLE", "NOARP"),
          json.dumps([{"dst": "192.168.60.10", "dev": "eth0", "state": ["INCOMPLETE"]}]),
          neigh_ok.replace(MANAGER_MAC, OTHER_MAC),
          json.dumps(json.loads(neigh_ok) * 2),
          json.dumps([{"dst": "192.168.60.10", "dev": "eth0", "lladdr": "zz", "state": ["REACHABLE"]}]),
          json.dumps(json.loads(neigh_ok) + [{"dst": "192.168.60.10", "dev": "eth0", "lladdr": "zz",
                                              "state": ["REACHABLE"]}]),
          "not json", "[]")))
    t("U12 control_a2: worker HTTP fails or raises / manager MAC missing / address differs / ctl HTTP missing -> not ok",
      lambda: not any((a2(http=lambda: {"ok": False, "detail": "x"}), a2(http=lambda: 1 / 0), a2(mac=None),
                       a2(mac="zz"), a2(ip="192.168.60.11"),
                       a2(records=[r for r in good if r["target"] != mt]))))
    t("U13 control_a2: the neighbour collector raising -> not ok, error kept",
      lambda: (lambda r: not r[0] and "not readable" in " ".join(r[1]["problems"]))(
          H.control_a2(case["T14-A2"], good, T0, T1, 3.0, "192.168.60.10", MANAGER_MAC, http_ok,
                       lambda: (_ for _ in ()).throw(RuntimeError("rc=1")))))
    slept = []
    ctl = make_ctl = lambda w, text, now=T1 + 0.1: H.make_control(  # noqa: E731
        w, lambda: text, CFG, ETH0_MAC, http_ok, lambda: neigh_ok, lambda: now, slept.append)
    win = {"T14-A1": {"before": (T0, T0 + 0.01), "after": (T1 - 0.01, T1)},
           "T14-A2": {"before": (T0, T0 + 0.01), "after": (T1 - 0.01, T1)}}
    text = "\n".join(json.dumps(r) for r in good)
    t("U14 make_control: waits until the ctl log can hold a record after the span, then judges A1/A2",
      lambda: ctl(win, text)(case["T14-A1"])[0] and ctl(win, text)(case["T14-A2"])[0]
      and abs(slept[0] - (H.CTL_SLACK_S + H.CTL_WAIT_MARGIN_S - 0.1)) < 1e-6)
    t("U15 make_control: window unknown (a counter read failed) / ctl unreadable / a rule-check case -> not ok",
      lambda: not ctl({}, text)(case["T14-A1"])[0] and not ctl(win, "{bad")(case["T14-A1"])[0]
      and not ctl(win, text)(case["T14-A3"])[0])

    # check_record / evaluate / outcome units on a minimal record built by run_group with the simulated guest
    import selftest_arp as SA
    g, rec, pc, cf = SA.run_sim(tmp, "u-rec", control=lambda c: (True, "fixture control"))
    sha = "ab" * 32
    link = {"ok": True, "detail": {"rc": 0, "http_code": "200", "sha256": sha, "expected_sha256": sha}}
    rec["service_link_before"] = copy.deepcopy(link)
    for x in rec["cases"]:
        x["service_link_after"] = copy.deepcopy(link)
    rec.update(arch="ARM", tap_mac=TAP, fixture_sha256=sha, planned_case_ids=list(CASE_IDS),
               neigh_command=list(H.NEIGH_CMD))
    cr = lambda r, **kw: H.check_record(r, kw.get("arch", "ARM"), kw.get("tap", TAP), kw.get("sha", sha),  # noqa: E731
                                        kw.get("iface", "eth1"))
    t("U16 check_record: complete record -> no problem", lambda: cr(rec) == [])
    t("U17 check_record: arch, interface, TAP MAC, fixture hash, planned cases, collector command, guard stop",
      lambda: all(cr(dict(rec, **{k: v})) for k, v in (("arch", "MIPS"), ("iface", "br-lan"), ("tap_mac", OTHER_MAC),
                                                       ("fixture_sha256", "cd" * 32), ("planned_case_ids", ["T14-A1"]),
                                                       ("neigh_command", ["ip", "neigh"]),
                                                       ("guard_stopped", "CaptureLost: x"))))
    t("U18 check_record: link before/after a restored case not HTTP 200 + fixture hash -> problem",
      lambda: cr(dict(rec, service_link_before={"ok": True, "detail": {**link["detail"], "http_code": "000"}}))
      and cr({**rec, "cases": [dict(rec["cases"][0], service_link_after={"ok": True, "detail": {
          **link["detail"], "sha256": "0" * 64}})] + rec["cases"][1:]}))
    t("U19 check_record: not an object / invalid TAP MAC -> problem, no exception",
      lambda: cr([]) and cr(rec, tap="zz") and cr(None))
    ev = H.evaluate(pc, cf, TAP, rec, "ARM", sha, "eth1")
    t("U20 evaluate: clean simulated record -> group complete, exit 0, requirements 4 + 4",
      lambda: ev["group_complete"] and ev["group_exit"] == 0 and len(ev["case_requirements"]) == 8)
    t("U21 evaluate: arp_cases record problems are kept (prefixed) and block the group",
      lambda: (lambda e: e["group_complete"] is False and any(p.startswith("arp_cases: case missing")
                                                             for p in e["record_problems"]))(
          H.evaluate(pc, cf, TAP, {**rec, "cases": rec["cases"][:3]}, "ARM", sha, "eth1")))
    t("U22 evaluate: a record that crashes evaluate_group never passes",
      lambda: (lambda e: e["group_complete"] is False and e["group_exit"] == 2)(
          H.evaluate(pc, cf, TAP, {**rec, "cases": [{"id": "T14-A1", "guest_state": 5, "steps": 7}]}, "ARM", sha,
                     "eth1")))
    t("U23 case_requirements: no baseline -> nothing; baseline, not restored -> restore only; restored -> both",
      lambda: H.case_requirements({"cases": [{"id": "T14-A1", "guest_state": {"before": None}},
                                             {"id": "T14-A2", "guest_state": {"before": {}, "restore": {"restored": False}}},
                                             {"id": "T14-A3", "guest_state": {"before": {}, "restore": {"restored": True}}}]})
      == [H.restore_name("T14-A2"), H.restore_name("T14-A3"), H.link_after_name("T14-A3")]
      and H.case_requirements(None) == [] and H.case_requirements({"cases": 3}) == [])
    t("U24 case_test_name: starts with 'probe '; CHƯA KIỂM CHỨNG stays undecided for run_outcome",
      lambda: H.case_test_name({"id": "T14-A1", "evidence_kind": "live_control", "verdict": "ĐẠT"})
      == "probe T14-A1 (arp, live control) -> ĐẠT"
      and A.counter_window.run_outcome([{"test": H.case_test_name({"id": "T14-A3", "verdict": "CHƯA KIỂM CHỨNG (x)"}),
                                         "ok": False}]).startswith("UNVERIFIED"))
    t("U25 arch_outcome: unreadable inputs / malformed record -> FAIL",
      lambda: all(H.arch_outcome(r, ev, "ARM").startswith("FAIL") for r in (None, {}, {"results": [1]},
                                                                           {"results": [{"test": "x", "ok": 1}]})))
    t("U26 run_check: missing/duplicate architecture, wrong arch, wrong cases -> problems; complete -> none", lambda: (
        _rc_fixture(tmp, H)))
    t("U27 CLI: usage error exit 2; --outcome prints FAIL for missing files and exits 0; --run-check exit 1",
      lambda: subprocess.run(["python3", os.path.join(HERE, "arp_harness.py")], capture_output=True, cwd=tmp).returncode == 2
      and cli_outcome(os.path.join(tmp, "none-r.json"), os.path.join(tmp, "none-e.json")).startswith("FAIL")
      and subprocess.run(["python3", os.path.join(HERE, "arp_harness.py"), "--run-check", tmp, "ARM"],
                         capture_output=True, cwd=tmp).returncode == 1)

    # ctl_loop.py: arp_entry (extracted with ast; the loop itself contacts the network and is not run here)
    src = open(os.path.join(HERE, "ctl_loop.py")).read()
    tree = ast.parse(src)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "arp_entry")
    ns = {"PROC_ARP": "/nonexistent"}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "ctl_loop.py", "exec"), ns)
    hdr = "IP address       HW type     Flags       HW address            Mask     Device\n"
    sysn = os.path.join(tmp, "ctl-sys-net")
    os.makedirs(os.path.join(sysn, "eth0"))
    open(os.path.join(sysn, "eth0", "address"), "w").write(CTL_MAC.upper() + "\n")

    def entry(body, ip="192.168.60.2"):
        p = os.path.join(tmp, "arp-%d" % abs(hash(body)))
        open(p, "w").write(body)
        return ns["arp_entry"](ip, p, sysn)
    t("U28 ctl_loop arp_entry: complete entry -> MAC, flags, device",
      lambda: entry(hdr + "192.168.60.2     0x1         0x2         02:42:C0:A8:3C:02     *        eth0\n")
      == {"ip": "192.168.60.2", "hw": "02:42:c0:a8:3c:02", "flags": "0x2", "device": "eth0", "device_mac": CTL_MAC})
    t("U29 ctl_loop arp_entry: incomplete (0x0), zero MAC, no row, two rows, bad header/row -> raises",
      lambda: all(raises(Exception, lambda b=b: entry(b)) for b in (
          hdr + "192.168.60.2     0x1         0x0         00:00:00:00:00:00     *        eth0\n",
          hdr + "192.168.60.2     0x1         0x0         02:42:c0:a8:3c:02     *        eth0\n",
          hdr + "192.168.60.2     0x1         0x2         00:00:00:00:00:00     *        eth0\n",
          hdr + "192.168.60.3     0x1         0x2         02:42:c0:a8:3c:02     *        eth0\n",
          hdr + ("192.168.60.2     0x1         0x2         02:42:c0:a8:3c:02     *        eth0\n" * 2),
          "garbage\n", hdr + "192.168.60.2 0x1 0x2\n",
          hdr + "192.168.60.2     0x1         0x2         02:42:c0:a8:3c:02     *        eth5\n",   # no such device
          hdr + "192.168.60.2     0x1         0x2         02:42:c0:a8:3c:02     *        ..\n")))
    t("U30 ctl_loop: the ARP check is added only with --arp-worker, right after the worker HTTP check; any other "
      "extra argument stops the loop",
      lambda: 'ARP_WORKER = sys.argv[5:] == ["--arp-worker"]' in src
      and "if ARP_WORKER:" in src and 'checks.insert(2, (f"arp worker-eth0 {worker_ip}"' in src
      and 'sys.exit(f"unknown argument(s)' in src)

    # 06B-4IR1 I2: the ctl interface is identified by ctl's sandboxnet endpoint MAC, never by its name
    def a1(records, ctl_mac=CTL_MAC):
        return H.control_a1(case["T14-A1"], records, T0, T1, 3.0, "192.168.60.2", ETH0_MAC, ctl_mac)

    def with_arp(**chg):
        return [r if r["target"] != at else dict(r, detail={**arp_ok, **chg}) for r in good]
    t("U31 I2 control_a1: device on another endpoint MAC (e.g. dbnet) / device missing / device_mac missing -> not ok, "
      "reason kept",
      lambda: all(not a1(rr)[0] and a1(rr)[1]["ctl_arp"]["problems"] for rr in (
          with_arp(device="eth9", device_mac="02:42:ac:12:00:09"),
          [r if r["target"] != at else dict(r, detail={k: v for k, v in arp_ok.items() if k != "device"}) for r in good],
          [r if r["target"] != at else dict(r, detail={k: v for k, v in arp_ok.items() if k != "device_mac"})
           for r in good])))
    t("U32 I2 control_a1: same endpoint MAC under another interface name -> ok (the name is not assumed)",
      lambda: a1(with_arp(device="eth7"))[0] is True and a1(with_arp(device="eth7"))[1]["ctl_devices"] == ["eth7"])
    t("U33 I2 control_a1: ctl endpoint MAC unknown/invalid -> not ok, even with a perfect log",
      lambda: not a1(good, None)[0] and not a1(good, "zz")[0] and "cannot be identified" in " ".join(a1(good, None)[1]["problems"]))
    t("U34 I2 control_a1: entry of another IP / two devices in the window / invalid device name / extra key -> not ok",
      lambda: not a1(with_arp(ip="192.168.60.3"))[0] and not a1(with_arp(device="eth 0"))[0]
      and not a1([r if not (r["target"] == at and r["ts"] == T0 + 5) else dict(r, detail={**arp_ok, "device": "eth7"})
                  for r in good])[0]
      and not a1([r if r["target"] != at else dict(r, detail={**arp_ok, "extra": 1}) for r in good])[0])
    # 06B-4IR1 I3: schema, payload per target type, duplicates
    hrec = lambda ts, d="HTTP 200", ok=True: {"ts": ts, "target": wt, "ok": ok, "detail": d}  # noqa: E731
    t("U35 I3 ctl_records: missing detail / extra key / NaN or infinite ts -> malformed (raises)",
      lambda: all(raises(ValueError, lambda x=x: H.ctl_records(x)) for x in (
          json.dumps({"ts": 1.0, "target": wt, "ok": True}) + "\n",
          json.dumps({"ts": 1.0, "target": wt, "ok": True, "detail": "HTTP 200", "x": 1}) + "\n",
          '{"ts": NaN, "target": "a", "ok": true, "detail": "x"}\n',
          '{"ts": Infinity, "target": "a", "ok": true, "detail": "x"}\n')))
    t("U36 I3 ctl_window HTTP: OK with detail None / 'HTTP 500' / '' / object -> not ok; 'HTTP 200' -> ok",
      lambda: all(not H.ctl_window([hrec(T0 - 1, d), hrec(T1 + 1, d)], wt, T0, T1, 3.0, H.http_detail_check)["ok"]
                  for d in (None, "HTTP 500", "", {"status": 200}))
      and H.ctl_window([hrec(T0 - 1), hrec(T1 + 1)], wt, T0, T1, 3.0, H.http_detail_check)["ok"])
    t("U37 I3 ctl_window: the same record twice (same target and ts) -> not ok, reported as duplicate, not removed",
      lambda: (lambda w: not w["ok"] and "duplicate" in w["problems"][0] and w["problem_count"] == 1)(
          H.ctl_window([hrec(T0 - 1), hrec(T0 - 1), hrec(T1 + 1)], wt, T0, T1, 3.0, H.http_detail_check)))
    t("U38 I3 ctl_window: a ts going back in file order -> not ok; independent valid reads (distinct ts) -> ok",
      lambda: not H.ctl_window([hrec(T0 - 1), hrec(T1 + 1), hrec(T0 - 0.5)], wt, T0, T1, 3.0, H.http_detail_check)["ok"]
      and H.ctl_window([hrec(T0 - 2), hrec(T0 - 1), hrec(T0 + 4), hrec(T1 + 1), hrec(T1 + 2)], wt, T0, T1, 3.0,
                       H.http_detail_check)["ok"])
    t("U39 I3 ctl_window: a failed record without a string detail -> problem (still not ok)",
      lambda: H.ctl_window([hrec(T0 - 1), hrec(T0 + 1, None, False), hrec(T1 + 1)], wt, T0, T1, 3.0,
                           H.http_detail_check)["problems"])
    t("U40 I3 duplicate check keeps the time rule: an old record (60 s before) never counts as 'after read B'",
      lambda: not H.ctl_window([hrec(T0 - 1), hrec(T0 - 60)], wt, T0, T1, 3.0, H.http_detail_check)["ok"])
    t("U41 I3 control_a2: manager HTTP record without payload / 'HTTP 500' -> not ok",
      lambda: all(not H.control_a2(case["T14-A2"], [r if r["target"] != mt else dict(r, detail=d) for r in good],
                                   T0, T1, 3.0, "192.168.60.10", MANAGER_MAC, http_ok, lambda: neigh_ok)[0]
                  for d in (None, "HTTP 500")))
    t("U42 IR1-R2 endpoint_mac_problem: zero, broadcast, multicast (I/G bit), malformed -> problem; locally "
      "administered and global unicast -> ok",
      lambda: all(H.endpoint_mac_problem(m) for m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
                                                       "33:33:00:00:00:01", "03:00:00:00:00:01", "zz", None, ""))
      and all(H.endpoint_mac_problem(m) is None for m in (CTL_MAC, "0a:11:22:33:44:55", "00:1a:2b:3c:4d:5e")))
    t("U43 IR1-R2 control_a1: zero/group MAC equal in config and payload -> not ok; payload zero with a valid config "
      "-> not ok (reason names the payload)",
      lambda: not a1(with_arp(device_mac="00:00:00:00:00:00"), "00:00:00:00:00:00")[0]
      and not a1(with_arp(device_mac="ff:ff:ff:ff:ff:ff"), "ff:ff:ff:ff:ff:ff")[0]
      and "device_mac unusable" in json.dumps(a1(with_arp(device_mac="00:00:00:00:00:00"))[1]))


def _rc_fixture(tmp, H):
    d = os.path.join(tmp, "runcheck")
    for a in ("ARM", "MIPS"):
        os.makedirs(os.path.join(d, a))
    full = [{"id": i} for i in CASE_IDS]
    json.dump({"arch": "ARM", "cases": full}, open(os.path.join(d, "ARM", H.EVAL_FILE), "w"))
    json.dump({"arch": "ARM", "cases": full[:3]}, open(os.path.join(d, "MIPS", H.EVAL_FILE), "w"))
    p = H.run_check(d, ["ARM", "MIPS"])
    return (H.run_check(d, ["ARM"]) == [] and any("evaluation is for" in x for x in p) and any("cases" in x for x in p)
            and H.run_check(d, ["ARM", "ARM"]) and H.run_check(d, ["ARM", "X"]) and H.run_check(d, []))


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# ====================================================================== W: run script
def sec_W(S):
    s = open(os.path.join(HERE, RS)).read()
    old = open(os.path.join(HERE, RS_OLD)).read()
    t("W1 run-06b4i.sh: bash -n", lambda: subprocess.run(["bash", "-n", os.path.join(HERE, RS)]).returncode == 0)
    t("W2 H is the 06B-4IR3 working copy", lambda: "\nH=/home/dathq/projects/ct01-06b4ir3\n" in s)
    calls = [l for l in s.splitlines() if "probe_matrix.py $ARCH" in l]
    code = "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))
    t("W3 exactly one probe_matrix call, with CT01_SUITE=arp (no icmp/ipv4 suite)",
      lambda: len(calls) == 1 and "-e CT01_SUITE=arp " in calls[0] and "CT01_SUITE=icmp" not in code)
    first_docker = min(i for i, l in enumerate(s.splitlines()) if re.match(r"\s*(ID=\$\(|CID=\$\()?docker ", l)
                       or "$(docker " in l)
    lines = s.splitlines()
    t("W4 selftest_arp.py and selftest_arp_wiring.py (and the ICMP/L2 ones) run before any docker command and abort",
      lambda: all(any(f'python3 "$H/{f}"' in l and "exit 3" in l for l in lines[:first_docker])
                  for f in ("selftest_arp.py", "selftest_arp_wiring.py", "selftest_icmp.py", "selftest_icmp_wiring.py",
                            "selftest_l2.py")))
    c = S.get("clean")
    t("W5 every module probe_matrix imports in arp mode is mounted read-only",
      lambda: c is not None and {os.path.basename(p) for p in c["modules"].values()} <= set(mounted_files(os.path.join(HERE, RS))))
    t("W6 outcome per architecture and run-level check through arp_harness.py on arp-eval.json",
      lambda: 'outcome=$(python3 "$H/arp_harness.py" --outcome "$D/probe/$ARCH/result.json" "$D/probe/$ARCH/arp-eval.json" "$ARCH" 2>&1)' in s
      and 'python3 "$H/arp_harness.py" --run-check "$D/probe" ARM MIPS' in s and "icmp_harness.py --" not in code)
    t("W7 ctl started with --arp-worker; its ARP target is checked alive like the others",
      lambda: '/ctl/ctl.jsonl --arp-worker)' in s and '"arp worker-eth0 $WORKER_IP"' in s)
    t("W8 manager MAC and ctl sandboxnet endpoint MAC passed to the worker in CT01_TARGETS",
      lambda: '"manager_mac":"%s","ctl_mac":"%s"' in s and '"$MANAGER_IP" "$MANAGER_MAC" "$CTL_MAC" "$SANDBOX_GW"' in s)
    t("W12 ctl endpoint MAC from docker inspect of the ctl container on sandboxnet, after it is created (I2)",
      lambda: 'CTL_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \\"$SANDBOXNET\\").MacAddress}}" "$CID")' in s
      and s.index("CTL_MAC=$(") > s.index('CID=$(docker run') and s.index("CTL_MAC=$(") < s.index("TARGETS=$("))
    t("W13 the inherited run-06b4f.sh header is marked historical (not a description of this script)",
      lambda: "HISTORICAL header of run-06b4f.sh" in s and "it does NOT describe what this" in s)
    removed = [l for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old.splitlines(), lines, autojunk=False).get_opcodes()
               if tag in ("replace", "delete") for l in old.splitlines()[i1:i2]]
    allowed = (r"^#!/bin/bash$", r"^# Nhiệm vụ 06B-4F — ICMP group", r"^H=/home/dathq/projects/ct01-06b4fr$",
               r'^    "\$H/selftest_icmp_wiring.py" "\$H/run-06b3b.sh" "\$OUT/harness-copy/"$',
               r'^    "\$IMAGE" /ctl_loop.py "\$WORKER_IP" "\$MONGO_IP" "\$MANAGER_IP" /ctl/ctl.jsonl\)',
               r'^for t in "mongo \$MONGO_IP:27017" "worker-eth0',
               r"^TARGETS=\$\(printf", r'^    "\$WORKER_IP" "\$MONGO_IP" "\$MANAGER_IP" "\$SANDBOX_GW"',
               r"CT01_SUITE=icmp", r"^    # 06B-4F: icmp_harness.py --outcome", r"^    # COMPLETED \+ each ICMP case",
               r'^    outcome=\$\(python3 "\$H/icmp_harness.py"', r"^# 06B-4F: both architectures evaluated",
               r'^python3 "\$H/icmp_harness.py" --run-check', r'^cat "\$OUT/icmp-run-check.txt"',
               r'^check "ICMP group evaluated',
               r'^    check "\$ARCH: no QEMU running before start \(sequential\)"', r'^$')   # 06B-4IR3 PC-1: `|| break` added
    t("W9 everything else is run-06b4f.sh unchanged: only the listed lines were replaced, the rest only added",
      lambda: removed and all(any(re.search(a, l) for a in allowed) for l in removed))
    t("W10 run-06b4f.sh and run-06b3b.sh unchanged (hashes of the 06B-4HR2 manifest)",
      lambda: _sha("run-06b4f.sh") == MANIFEST_4HR2["run-06b4f.sh"]
      and _sha("run-06b3b.sh") == MANIFEST_4HR2["run-06b3b.sh"])
    t("W11 the run script copies the ARP files (cases, harness, both self-tests) into harness-copy",
      lambda: all(f'"$H/{f}"' in s.split("harness-copy/")[0] for f in
                  ("arp_cases.py", "arp_harness.py", "guest_state.py", "selftest_arp.py", "selftest_arp_wiring.py",
                   "ctl_loop.py")))


# ====================================================================== PC1 (06B-4IR3): architecture stop policy
PC1_VARIANTS = {
    # name: (arch -> (rc, outcome)), extra flags
    "all-pass": {},
    "arm-fail": {"ARM": (1, "FAIL: probe T14-A2 (arp, live control) -> FAIL")},
    "arm-restore-fail": {"ARM": (1, "FAIL: required confirmation not passed (ok=False): guest configuration restored after T14-A2")},
    "arm-error": {"ARM": (1, "FAIL: status 'ERROR: RuntimeError: x'")},
    "arm-unverified": {"ARM": (1, "UNVERIFIED: probe T14-A1 (arp, live control) -> CHƯA KIỂM CHỨNG (x)")},
    "arm-leak": {"ARM": (99, "FAIL: status 'LEAK: x'")},
    "arm-capture": {"ARM": (98, "FAIL: status 'CAPTURE LOST: x'")},
    "arm-verify-after-fail": {"verify_fail": "ARM"},
    "arm-qemu-left": {"qemu_left": "ARM"},
    "noqemu-before-ARM": {"qemu_before": "ARM"},
    "noqemu-before-MIPS": {"qemu_before": "MIPS"},
    "mips-fail": {"MIPS": (1, "FAIL: probe T15-S1 (arp, rule check) -> FAIL")},
    "runcheck-fail": {"runcheck_rc": 1},
}


def pc1_run(tmp, name):
    """The REAL architecture loop, the block after it up to section 7 and the result block of run-06b4i.sh, run by
    bash; docker/timeout/python3/E/bash/watch_ok are inert shell functions (no container, no process check)."""
    src = open(os.path.join(HERE, RS)).read()
    i = src.index("for ARCH in ARM MIPS; do")
    j = src.index("# ------------------------------------------------------------------ 7.", i)
    k = src.index('log "result"')
    init = "\n".join(l for l in src.splitlines() if l.startswith(("CREATED_IDS=();", "ARCH_CALLED=();")))
    helpers = "\n".join(l for l in src.splitlines() if l.startswith(("fail()", "check()", "pass()")))
    v = PC1_VARIANTS[name]
    d = os.path.join(tmp, "pc1-" + name)
    os.makedirs(os.path.join(d, "hostcap"))
    open(os.path.join(d, "hostcap", "alert.txt"), "w").write("leak line\n" if name == "arm-leak" else "")
    open(os.path.join(d, "dead"), "w").write("")
    stubs = f"""set -u
{init}
LEAK=0
{helpers}
log() {{ :; }}; watch_ok() {{ return 0; }}
E() {{ if [ "$1" = ps ]; then :; else [ "$ARCH" != "{v.get('verify_fail', '-')}" ]; fi; }}
bash() {{ case "$2" in *pgrep*) [ "$ARCH" != "{v.get('qemu_before', '-')}" ];; *grep*) [ "$ARCH" != "{v.get('qemu_left', '-')}" ];; *) return 0;; esac; }}
timeout() {{ echo "@@SEND_ARCH $ARCH"; case "$ARCH" in ARM) return {v.get('ARM', (0, ''))[0]};; MIPS) return {v.get('MIPS', (0, ''))[0]};; esac; }}
python3() {{ case "${{2:-}}" in
  --outcome) case "$ARCH" in ARM) echo "{v.get('ARM', (0, 'PASS'))[1]}";; MIPS) echo "{v.get('MIPS', (0, 'PASS'))[1]}";; esac;;
  --run-check) echo "run-check stub"; return {v.get('runcheck_rc', 0)};;
  *) echo PASS;; esac; }}
H=fixture; ID=fixture; TARGETS='{{}}'; D="$P"; OUT="$P"; DEAD="$P/dead"
"""
    prog = stubs + src[i:j] + '\necho "@@AFTER_LOOP (teardown and host checks of sections 7-8 follow here)"\n' + src[k:]
    p = subprocess.run(["/bin/bash", "-c", prog], env={"P": d, "PATH": "/usr/bin:/bin"}, capture_output=True,
                       text=True, timeout=60)
    out = p.stdout + p.stderr
    open(os.path.join(d, "output.log"), "w").write(out)
    return {"exit": p.returncode, "out": out,
            "called": [l.split()[-1] for l in p.stdout.splitlines() if l.startswith("@@SEND_ARCH")],
            "stopped": "[STOPPED] architecture loop" in out, "after": "@@AFTER_LOOP" in out,
            "runcheck": "run-check stub" in out, "skipped": "[SKIPPED] ARP run-level check" in out}


def sec_PC1(tmp):
    R = {n: pc1_run(tmp, n) for n in PC1_VARIANTS}
    x = R["all-pass"]
    t("PC1.1 both architectures pass: harness called for ARM then MIPS, run-level check run, no stop, exit 0",
      lambda: x["called"] == ["ARM", "MIPS"] and x["runcheck"] and not x["stopped"] and x["exit"] == 0)
    for n, code in (("arm-fail", 1), ("arm-restore-fail", 1), ("arm-error", 1), ("arm-unverified", 4),
                    ("arm-verify-after-fail", 1), ("arm-qemu-left", 1), ("arm-leak", 1), ("arm-capture", 1)):
        x = R[n]
        t(f"PC1.2 {n}: MIPS harness NOT called (only ARM), loop stopped and reported, run-level check skipped, "
          f"control continues after the loop (teardown), exit {code} keeps the cause",
          lambda x=x, code=code: x["called"] == ["ARM"] and x["stopped"] and x["skipped"] and not x["runcheck"]
          and x["after"] and x["exit"] == code)
    x = R["noqemu-before-ARM"]
    t("PC1.3 QEMU already running before ARM: no harness call at all (not 'guest did not boot'), stop reason names "
      "it, exit 1",
      lambda: x["called"] == [] and x["stopped"] and "harness not called for ARM" in x["out"] and x["after"]
      and x["exit"] == 1)
    x = R["noqemu-before-MIPS"]
    t("PC1.4 QEMU running before MIPS: ARM called, MIPS harness not called, exit 1",
      lambda: x["called"] == ["ARM"] and "harness not called for MIPS" in x["out"] and x["exit"] == 1)
    x = R["mips-fail"]
    t("PC1.5 MIPS fails after a clean ARM: both called, no stop needed, run-level check run, exit 1",
      lambda: x["called"] == ["ARM", "MIPS"] and not x["stopped"] and x["runcheck"] and x["exit"] == 1)
    x = R["runcheck-fail"]
    t("PC1.6 both pass but the run-level check fails -> exit 1", lambda: x["called"] == ["ARM", "MIPS"] and x["exit"] == 1)
    x = R["arm-unverified"]
    t("PC1.7 ARM UNVERIFIED: the result names the stop and the UNVERIFIED cause; never 'ALL CHECKS PASSED'",
      lambda: "ARCHITECTURE LOOP STOPPED" in x["out"] and "UNVERIFIED (could not be decided)" in x["out"]
      and "ALL CHECKS PASSED" not in x["out"])


MANIFEST_4HR2 = {   # docs/evidence/task06b4hr2/harness-sha256.txt
    "run-06b4f.sh": "5bc5ce4ed82ae0bba7c710d8554f5c73cab8c7bac91d1c81b576d9451d60db92",
    "run-06b3b.sh": "c83273d646a9f3e14ad8976b31dbe71ecf8075c1e40ad97810921eb6181a34a6",
}


def _sha(f):
    return hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest()


def main(argv):
    if argv[:1] == ["--scenario"]:
        return scenario_main(argv[1], argv[3])
    jf = argv[argv.index("--json") + 1] if "--json" in argv else None
    with tempfile.TemporaryDirectory(prefix="selftest-arp-wiring.") as tmp:
        sec_U(tmp)
        S = sec_S(tmp)
        sec_R(S, tmp)
        sec_W(S)
        sec_PC1(tmp)
    n = sum(RESULTS.values())
    if jf:
        json.dump(RESULTS, open(jf, "w"), indent=1, ensure_ascii=False)
    print(f"SELFTEST-ARP-WIRING: {n}/{len(RESULTS)} passed")
    return 0 if n == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
