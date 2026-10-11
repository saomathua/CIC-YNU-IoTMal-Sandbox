"""06B-3A: boot ONE real guest (ARM or MIPS) and test only the worker service link.

Runs inside the throwaway test container (docker exec), from /app, AFTER the real
run.sh (V0) with the real server.py and a sentinel poller.

* Reuses the real QEMU code path: ARCH_CONFIGS, Analysis._start_qemu (pinned MAC,
  tap0), Analysis._configure_network (10.200.0.2/30, gw 10.200.0.1) and
  shutdown_qemu (confirmed exit). dynamic_analysis / poller are NOT used.
* The full isolation verify is run right before the QEMU spawn. This is the
  harness's own pre-boot check, NOT V1/V2 of the real analysis flow.
* Only the stock OS image (fresh copy extracted to /tmp per architecture) and
  harmless text fixtures are used. No ELF / sample is downloaded or executed:
  the guest uses its own curl against 10.200.0.1:8011 only.
* tap0 is captured with tshark; nft counters are read before/after every group.
* Stops before any probe if QEMU networking deviates from the design
  (user/slirp or any extra backend, wrong MAC, ...).

Exit 0 only if every check passed.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from zipfile import ZipFile

sys.path.insert(0, "/app")
import pexpect                                            # noqa: E402
from isolation import constants as C                      # noqa: E402
from isolation import current_task                        # noqa: E402
from isolation.verify import verify_isolation             # noqa: E402
from service import analysis as A                         # noqa: E402

ARCH = sys.argv[1]
OUT = os.path.join(sys.argv[2], ARCH)
BASE = "/api/v1/sandbox-worker"
URL = f"http://{C.WORKER_GUEST_IP}:{C.SVC_PORT}{BASE}"
T = f"06b3a-{ARCH.lower()}-task"
X = f"06b3a-{ARCH.lower()}-other"
DATA = "/app/data/"
STOP_FILE = "/tmp/sandbox_stop_requested"
WORK = f"/tmp/g-{ARCH}"
PCAP = os.path.join(OUT, "tap0.pcap")
ARCH_DEADLINE_S = 900

os.makedirs(OUT, exist_ok=True)
results = []
groups = []
log_f = open(os.path.join(OUT, "probe.log"), "w")


def say(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    log_f.write(line + "\n")
    log_f.flush()


def record(name, ok, **detail):
    results.append({"arch": ARCH, "test": name, "ok": bool(ok), **detail})
    say(f"[{'PASS' if ok else 'FAIL'}] {ARCH}: {name} {json.dumps(detail, sort_keys=True)}")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def counters():
    out = json.loads(subprocess.run(["nft", "-j", "list", "counters"], check=True,
                                    capture_output=True, text=True).stdout)
    return {f"{o['counter']['table']}.{o['counter']['name']}": o["counter"]["packets"]
            for o in out["nftables"] if "counter" in o}


class Guest:
    def __init__(self, proc):
        self.p = proc
        self.n = 0

    def run(self, cmd, timeout=60):
        """Run a shell command in the guest; return (rc, output) using unique markers."""
        self.n += 1
        b, e = f"@@B{self.n}", f"@@E{self.n}"
        self.p.sendline(f"echo {b}; {cmd}; echo {e} rc=$?")
        self.p.expect(rf"{e} rc=(\d+)", timeout=timeout)
        rc = int(self.p.match.group(1))
        # Serial console output ends lines with \r\r\n (guest tty + host pty): drop CRs first.
        text = self.p.before.replace("\r", "")
        i = text.rfind(b + "\n")
        if i < 0:
            raise RuntimeError(f"begin marker {b} not found in guest output")
        out = text[i + len(b) + 1:]
        self.p.expect("# ", timeout=timeout)
        return rc, out

    def monitor(self, command, timeout=20):
        """QEMU monitor via the -nographic mux (Ctrl-A c), then back to the console."""
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


class Group:
    """nft counters and time window around a group of probes."""
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self.c0, self.t0 = counters(), time.time()
        return self

    def __exit__(self, *exc):
        time.sleep(0.5)
        self.t1, self.c1 = time.time(), counters()
        delta = {k: self.c1[k] - self.c0.get(k, 0) for k in self.c1 if self.c1[k] != self.c0.get(k, 0)}
        groups.append({"group": self.name, "t0": self.t0, "t1": self.t1, "counter_delta": delta})
        say(f"group '{self.name}' counter delta: {delta}")
        return False


def curl_status(g, args):
    rc, out = g.run(f"curl -s -m 15 -o /tmp/r.out -w 'HTTP=%{{http_code}}\\n' {args}")
    m = re.search(r"HTTP=(\d{3})", out)
    st = int(m.group(1)) if m else None
    # A request that was never sent (curl error, HTTP=000) must not count as any status.
    if rc != 0 or not st:
        record("curl sent the request (exit 0, HTTP status present)", False, curl_rc=rc, args=args, output=out.strip())
    return st, rc, out


def tshark_count(display_filter):
    out = subprocess.run(["tshark", "-r", PCAP, "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True).stdout
    return len([l for l in out.splitlines() if l.strip()])


def on_alarm(signum, frame):
    raise TimeoutError(f"{ARCH}: harness deadline {ARCH_DEADLINE_S}s exceeded")


def main():
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(ARCH_DEADLINE_S)
    cfg = A.ARCH_CONFIGS[ARCH]
    tshark = proc = None
    c_boot = None
    status = "ERROR"
    try:
        # ---------------------------------------------------- fresh guest disk + fixtures
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with ZipFile(os.path.join("/app", cfg.image_zip_path), "r") as z:
            z.extractall(WORK)
        disk = WORK + cfg.image_rootfs_path
        record("fresh guest image extracted", os.path.exists(WORK + cfg.image_kernel_path) and os.path.exists(disk),
               zip=cfg.image_zip_path, rootfs_sha256=sha(open(disk, "rb").read()))
        fixture = f"06B-3A {ARCH} harmless text fixture - not an ELF\n".encode()
        for tid, content in ((T, fixture), (X, b"06B-3A other task fixture\n")):
            os.makedirs(DATA + tid, exist_ok=True)
            open(DATA + tid + "/" + tid, "wb").write(content)
        current_task.clear()
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)

        # ---------------------------------------------------- harness pre-boot check (not V1)
        verify_isolation(f"06B-3A {ARCH} harness pre-boot check (not V1)")
        record("full isolation verify right before QEMU spawn (harness pre-boot, not V1)", True)

        # ---------------------------------------------------- capture tap0
        tshark = subprocess.Popen(["tshark", "-i", C.GUEST_IF, "-w", PCAP, "-q"],
                                  stdout=subprocess.DEVNULL, stderr=open(os.path.join(OUT, "tshark.stderr"), "w"))
        for _ in range(50):
            if os.path.exists(PCAP):
                break
            time.sleep(0.1)
        record("tshark capturing on tap0", tshark.poll() is None and os.path.exists(PCAP))
        c_boot = counters()

        # ---------------------------------------------------- boot via the real code path
        an = A.Analysis(T, WORK, C.GUEST_IP, C.WORKER_GUEST_IP,
                        WORK + cfg.image_kernel_path, disk, {"worker_ip": "unused"})
        cmd = cfg.qemu_cmd_template.format(kernel=an.kernel_path, rootfs=an.rootfs_path, mac=C.GUEST_MAC)
        open(os.path.join(OUT, "qemu-command.txt"), "w").write(cmd + "\n")
        say(f"spawning: {cmd}")
        t_boot = time.time()
        proc = an._start_qemu(cfg)
        record("guest booted to shell", True, seconds=round(time.time() - t_boot, 1), qemu_pid=proc.pid)
        an._configure_network(proc, cfg)
        record("guest network configured by Analysis._configure_network", True)
        g = Guest(proc)

        # ---------------------------------------------------- topology
        topo = {}
        for k, c in (("ip_link", "ip link"), ("ip_addr", "ip addr"), ("ip_route", "ip route"),
                     ("ip6_route", "ip -6 route 2>&1"), ("ifaces_mac",
                      "for i in /sys/class/net/*; do echo $(basename $i) $(cat $i/address); done"),
                     ("resolv", "cat /etc/resolv.conf"), ("curl", "ls -l /usr/bin/curl; curl --version | head -1"),
                     ("hashtools", "command -v sha256sum md5sum")):
            topo[k] = g.run(c)[1]
        net_info = g.monitor("info network")
        topo["qemu_info_network"] = net_info
        json.dump(topo, open(os.path.join(OUT, "topology.json"), "w"), indent=1)
        for k, v in topo.items():
            open(os.path.join(OUT, f"topology-{k}.txt"), "w").write(v)
        say("info network:\n" + net_info)

        guest_if = cfg.net_iface
        mac_lines = dict(l.split()[:2] for l in topo["ifaces_mac"].splitlines() if len(l.split()) >= 2)
        backends = re.findall(r"type=(\w+)", net_info)
        tap_lines = [l for l in net_info.splitlines() if "type=tap" in l]
        bad = []
        if any(b in ("user", "socket", "vde", "l2tpv3", "stream", "dgram", "vhost-user", "bridge") for b in backends):
            bad.append(f"non-tap backend present: {sorted(set(backends))}")
        if len(tap_lines) != 1 or "ifname=tap0" not in tap_lines[0]:
            bad.append(f"expected exactly one tap backend ifname=tap0, got {tap_lines}")
        nic_lines = [l for l in net_info.splitlines() if "macaddr=" in l]
        tap_nic = [l for l in nic_lines if f"macaddr={C.GUEST_MAC}" in l]
        if len(tap_nic) != 1:
            bad.append(f"NIC with macaddr={C.GUEST_MAC} count={len(tap_nic)}")
        # any other NIC must not be connected to a backend (indented peer lines follow connected NICs)
        record("QEMU info network: only tap0 backend, no user/slirp/socket", not bad, problems=bad,
               backends=sorted(set(backends)))
        # guest-side: the interface carrying 10.200.0.2/30 and its MAC
        addr_ok = re.search(rf"inet {re.escape(C.GUEST_IP)}/{C.GUEST_PREFIX}\b.*{re.escape(guest_if)}", topo["ip_addr"]) is not None
        route_ok = re.search(rf"default via {re.escape(C.WORKER_GUEST_IP)} dev {re.escape(guest_if)}", topo["ip_route"]) is not None
        record(f"guest has {C.GUEST_IP}/{C.GUEST_PREFIX} on {guest_if}", addr_ok)
        record(f"guest default route via {C.WORKER_GUEST_IP} on {guest_if}", route_ok)
        mac_hit = [i for i, m in mac_lines.items() if m.lower() == C.GUEST_MAC]
        record(f"a guest NIC carries the pinned MAC {C.GUEST_MAC}", bool(mac_hit), interfaces=mac_hit, all_macs=mac_lines)
        if bad or not (addr_ok and route_ok and mac_hit):
            status = "STOPPED_TOPOLOGY"
            say("topology differs from the design: no probes are sent (report to reviewer)")
            return 1

        # ---------------------------------------------------- probes (10.200.0.1:8011 only)
        rc, _ = g.run("printf '06B-3A harmless dummy upload\\n' > /tmp/up_dummy; cat /tmp/up_dummy")
        record("harmless dummy upload file created in guest", rc == 0)
        with Group("1-no-current-task"):
            for m, path, extra in (("GET", f"get-task/{T}/file", ""),
                                   ("POST", f"update-task/{T}/strace", "-F file=@/tmp/up_dummy"),
                                   ("POST", f"update-task/{T}/sar", "-F file=@/tmp/up_dummy")):
                st, rc, out = curl_status(g, f"{'-X POST ' if m == 'POST' and not extra else ''}{extra} {URL}/{path}")
                record(f"no current_task: {m} {path} -> 403", st == 403, status=st)
            record("no current_task: nothing written",
                   not os.path.exists(DATA + T + "/strace.log") and not os.path.exists(DATA + T + "/sar.out"))

        current_task.set_current(T)
        with Group("2-download"):
            st, rc, out = curl_status(g, f"{URL}/get-task/{T}/file")
            record("GET get-task/T/file -> 200", st == 200, status=st)
            _, h = g.run("sha256sum /tmp/r.out 2>/dev/null || md5sum /tmp/r.out")
            got = h.split()[0] if h.split() else ""
            exp = sha(fixture) if len(got) == 64 else hashlib.md5(fixture).hexdigest()
            record("downloaded file hash (computed in guest) == fixture", got == exp, guest=got, expected=exp)

        with Group("3-upload"):
            for kind, fname in (("strace", "strace.log"), ("sar", "sar.out")):
                payload = f"06B-3A {ARCH} harmless {kind} upload\n"
                g.run(f"printf '{payload.rstrip()}\\n' > /tmp/up_{kind}")
                st, rc, out = curl_status(g, f"-F file=@/tmp/up_{kind} {URL}/update-task/{T}/{kind}")
                record(f"POST update-task/T/{kind} -> 200", st == 200, status=st)
                p = DATA + T + "/" + fname
                got = open(p, "rb").read() if os.path.exists(p) else b""
                record(f"received {fname} hash == payload", sha(got) == sha(payload.encode()),
                       got=sha(got), expected=sha(payload.encode()))

        data_before = sorted(os.listdir(DATA))
        with Group("4-forbidden"):
            for name, args in (("GET /healthcheck", f"http://{C.WORKER_GUEST_IP}:{C.SVC_PORT}/healthcheck"),
                               ("POST /stop", f"-X POST {URL}/stop"),
                               ("GET other task file", f"{URL}/get-task/{X}/file"),
                               ("POST other task strace", f"-F file=@/tmp/up_dummy {URL}/update-task/{X}/strace")):
                st, rc, out = curl_status(g, args)
                record(f"forbidden: {name} -> 403", st == 403, status=st)
        record("no stop file created", not os.path.exists(STOP_FILE))
        record("no task created / other task not written",
               sorted(os.listdir(DATA)) == data_before and not os.path.exists(DATA + X + "/strace.log"),
               data_dir=sorted(os.listdir(DATA)))

        current_task.clear()
        with Group("5-after-clear"):
            st, rc, out = curl_status(g, f"{URL}/get-task/{T}/file")
            record("after clearing current_task: GET get-task/T/file -> 403", st == 403, status=st)

        status = "COMPLETED"
        return 0
    except Exception as e:
        status = f"ERROR: {type(e).__name__}: {e}"
        record("harness completed without error", False, error=status)
        return 1
    finally:
        signal.alarm(0)
        if proc is not None:
            try:
                A.shutdown_qemu(proc, f"06B-3A {ARCH}")
                record("QEMU exit confirmed (shutdown_qemu)", not proc.isalive(),
                       exitstatus=proc.exitstatus, signalstatus=proc.signalstatus)
            except Exception as e:
                record("QEMU exit confirmed (shutdown_qemu)", False, error=str(e))
        if tshark is not None:
            tshark.send_signal(signal.SIGINT)
            try:
                tshark.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tshark.kill()
                tshark.wait(timeout=5)
            record("tshark capture stopped", tshark.poll() is not None, returncode=tshark.returncode)
        try:
            shutil.copy(WORK + "/qemu.log", os.path.join(OUT, "console.log"))
        except OSError:
            pass
        current_task.clear()
        for tid in (T, X):
            shutil.rmtree(DATA + tid, ignore_errors=True)
        shutil.rmtree(WORK, ignore_errors=True)
        record("fixtures, marker and temporary guest disk removed",
               not os.path.exists(WORK) and not os.path.exists(C.CURRENT_TASK_FILE)
               and not any(n.startswith("06b3a-") for n in os.listdir(DATA)))
        # ------------------------------------------------ capture vs counters
        if os.path.exists(PCAP) and status == "COMPLETED":
            mac = C.GUEST_MAC
            record("capture: guest frames seen on tap0", tshark_count(f"eth.src == {mac}") > 0,
                   frames_from_guest=tshark_count(f"eth.src == {mac}"))
            for gr in groups:
                win = f"frame.time_epoch >= {gr['t0']:.6f} && frame.time_epoch <= {gr['t1']:.6f}"
                pc = tshark_count(f"{win} && ip.src == {C.GUEST_IP} && ip.dst == {C.WORKER_GUEST_IP} && tcp.dstport == {C.SVC_PORT}")
                nf = gr["counter_delta"].get("sandbox_guest.allow_svc", 0)
                gr["pcap_guest_to_svc"] = pc
                record(f"group {gr['group']}: allow_svc delta == pcap guest->10.200.0.1:8011 packets",
                       pc == nf and pc > 0, allow_svc=nf, pcap=pc)
            http = subprocess.run(["tshark", "-r", PCAP, "-Y", "http.request || http.response", "-T", "fields",
                                   "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.method",
                                   "-e", "http.request.uri", "-e", "http.response.code"],
                                  capture_output=True, text=True).stdout
            open(os.path.join(OUT, "pcap-http.tsv"), "w").write(http)
            summary = subprocess.run(["tshark", "-r", PCAP, "-q", "-z", "conv,ip"], capture_output=True, text=True).stdout
            open(os.path.join(OUT, "pcap-conv-ip.txt"), "w").write(summary)
            other_l3 = tshark_count(f"eth.src == {mac} && ip && !(ip.dst == {C.WORKER_GUEST_IP})")
            record("info: guest IP packets to destinations other than 10.200.0.1 (not probed in 06B-3A)", True,
                   count=other_l3)
        json.dump({"status": status, "results": results, "groups": groups, "counters_at_boot": c_boot},
                  open(os.path.join(OUT, "result.json"), "w"), indent=1, default=str)
        failed = [r for r in results if not r["ok"]]
        say(f"== {ARCH}: status={status}; {len(results) - len(failed)}/{len(results)} checks passed")


if __name__ == "__main__":
    rc = main()
    failed = [r for r in results if not r["ok"]]
    sys.exit(1 if (rc or failed) else 0)
