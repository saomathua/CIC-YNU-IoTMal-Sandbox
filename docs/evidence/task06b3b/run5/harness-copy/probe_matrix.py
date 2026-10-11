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
CTL = "/ctl/ctl.jsonl"
LISTENER_PORT = 18080
DEADLINE_S = 1500
PRIVATE = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                                             "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")]
MCAST = ipaddress.ip_network("224.0.0.0/4")
CLASSES = ["allow_svc", "drop_spoof", "drop_non_ipv4", "drop_worker_other", "drop_private",
           "drop_bcast_mcast", "drop_public", "l2_bad_ethertype", "l2_bad_mac"]

os.makedirs(OUT, exist_ok=True)
results, probes = [], []
log_f = open(os.path.join(OUT, "probe.log"), "w")


class LeakDetected(Exception):
    pass


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


def counters():
    out = json.loads(run_checked(["nft", "-j", "list", "counters"]))
    return {o["counter"]["name"]: o["counter"]["packets"] for o in out["nftables"] if "counter" in o}


def alert_lines():
    try:
        return [l for l in open(ALERT).read().splitlines() if l.strip()]
    except FileNotFoundError:
        raise RuntimeError("host alert file missing: host-side leak monitor not running")


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

        listener = Listener()
        listener.start()
        record("temporary listener 10.200.0.1:18080 answers locally",
               run_ctl(lambda: ctl_http(C.WORKER_GUEST_IP, LISTENER_PORT, "/"))["ok"])

        verify_isolation(f"06B-3B {ARCH} harness pre-boot check (not V1)")
        record("full isolation verify right before QEMU spawn (harness pre-boot, not V1)", True)

        tshark = subprocess.Popen(["tshark", "-i", C.GUEST_IF, "-w", PCAP, "-q"], stdout=subprocess.DEVNULL,
                                  stderr=open(os.path.join(OUT, "tshark.stderr"), "w"))
        for _ in range(50):
            if os.path.exists(PCAP):
                break
            time.sleep(0.1)
        record("tshark capturing on tap0", tshark.poll() is None and os.path.exists(PCAP))

        an = A.Analysis(T, WORK, C.GUEST_IP, C.WORKER_GUEST_IP, WORK + cfg.image_kernel_path,
                        WORK + cfg.image_rootfs_path, {"worker_ip": "unused"})
        cmd = cfg.qemu_cmd_template.format(kernel=an.kernel_path, rootfs=an.rootfs_path, mac=C.GUEST_MAC)
        open(os.path.join(OUT, "qemu-command.txt"), "w").write(cmd + "\n")
        proc = an._start_qemu(cfg)
        an._configure_network(proc, cfg)
        g = Guest(proc)
        record("guest booted and network configured", True, qemu_pid=proc.pid)

        # ------------------------------------------------ strict topology gate
        topo = {k: g.run(c)[1] for k, c in (
            ("ip_addr", "ip addr"), ("ip_route", "ip route"),
            ("ifaces_mac", "for i in /sys/class/net/*; do echo $(basename $i) $(cat $i/address); done"),
            ("tools", "for c in nslookup nc wget ping arping; do command -v $c || echo missing:$c; done"),
            ("curl", "curl --version | head -1"))}
        topo["info_network"] = g.monitor("info network")
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

        def service_link(label):
            rc, out = g.run(f"curl -s -m 10 -o /tmp/r.out -w 'HTTP=%{{http_code}}\\n' {URL}/get-task/{T}/file; "
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
            cb = run_ctl(local_ctl) if local_ctl else None
            c0, t0 = counters(), time.time()
            if proto == "tcp":
                rc, out = g.run(f"curl -s -o /dev/null --local-port {lport} --connect-timeout 4 -m 5 "
                                f"-w 'HTTP=%{{http_code}}\\n' http://{ip}:{port}/ct01-06b3b-{pid}", timeout=30)
                guest_failed = rc in (7, 28) and "HTTP=000" in out
            elif has_nslookup:
                rc, out = g.run(f"nslookup {qname} {ip}", timeout=60)
                guest_failed = rc != 0 and not re.search(r"Name:\s+" + re.escape(qname), out)
            else:
                rc, out, guest_failed = None, "TOOL_MISSING: nslookup not available in guest", False
            time.sleep(1.0)
            t1, c1 = time.time(), counters()
            ca = run_ctl(local_ctl) if local_ctl else None
            remote = {"prefix": remote_ctl} if remote_ctl else None   # evaluated in evaluate()
            alerts = alert_lines()
            p = {"probe": pid, "dst": ip, "proto": proto, "port": port, "lport": lport if proto == "tcp" else None,
                 "qname": qname if proto == "udp" else None, "expected_class": klass, "t0": t0, "t1": t1,
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

        service_link("after probes")
        current_task.clear()
        status = "COMPLETED"
        return 0
    except LeakDetected as e:
        status = f"LEAK: {e}"
        return 99
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
        if tshark is not None:
            tshark.send_signal(signal.SIGINT)
            try:
                tshark.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tshark.kill()
                tshark.wait(timeout=5)
            record("tap0 capture stopped cleanly", tshark.returncode == 0, returncode=tshark.returncode)
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
        if status == "COMPLETED":
            evaluate()
        json.dump({"status": status, "results": results, "probes": probes},
                  open(os.path.join(OUT, "result.json"), "w"), indent=1, default=str)
        failed = [r for r in results if not r["ok"]]
        say(f"== {ARCH}: status={status}; {len(results) - len(failed)}/{len(results)} checks passed")


def evaluate():
    try:
        rows = guest_frames()
    except Exception as e:
        record("tap0 pcap readable by tshark (exit 0)", False, error=str(e))
        return
    record("tap0 pcap readable by tshark (exit 0)", True, frames=len(rows))
    time.sleep(4)   # make sure the control log has entries after the last probe window
    table = []
    for p in probes:
        if p["remote_control"] is not None:
            p["remote_control"] = ctl_log_window(p["remote_control"]["prefix"], p["t0"], p["t1"])
        win = [r for r in rows if p["t0"] <= r["t"] <= p["t1"]]
        cls = {}
        for r in win:
            c = classify(r)
            if c:
                cls[c] = cls.get(c, 0) + 1
        if p["proto"] == "tcp":
            mine = [r for r in win if r["src_mac"] == C.GUEST_MAC and r["sport"] == str(p["lport"])]
        else:
            mine = [r for r in win if r["src_mac"] == C.GUEST_MAC and r["qname"] == p["qname"]]
        mine_cls = sorted({classify(r) for r in mine})
        dl = p["counter_delta"]
        mismatch = {k: (dl.get(k, 0), cls.get(k, 0)) for k in CLASSES if dl.get(k, 0) != cls.get(k, 0)}
        local_ok = p["control_before"] is None or (p["control_before"]["ok"] and p["control_after"]["ok"])
        remote_ok = p["remote_control"] is None or p["remote_control"]["ok"]
        control_alive = local_ok and remote_ok and (p["control_before"] is not None or p["remote_control"] is not None)
        checks = {
            "guest_connection_failed": p["guest_failed"],
            "control_alive_same_dst_proto_port": control_alive,
            "probe_packets_in_tap0_pcap": len(mine) > 0,
            "probe_packets_hit_expected_counter": mine_cls == [p["expected_class"]],
            "expected_counter_delta_eq_pcap": dl.get(p["expected_class"], 0) == cls.get(p["expected_class"], 0) > 0,
            "all_counter_deltas_eq_pcap_classification": not mismatch,
            "no_host_alert": p["host_alert_lines"] == 0,
        }
        if p["guest_output"].startswith("TOOL_MISSING"):
            verdict = "CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)"
        elif not control_alive:
            verdict = "CHƯA KIỂM CHỨNG (không có đối chứng sống)"
        elif all(checks.values()):
            verdict = "ĐẠT"
        else:
            verdict = "FAIL"
        row = {"probe": p["probe"], "dst": f"{p['proto']} {p['dst']}:{p['port']}", "verdict": verdict,
               "probe_packets": len(mine), "expected_class": p["expected_class"],
               "counter_delta": dl, "pcap_classified": cls, "mismatch": mismatch, "checks": checks,
               "guest_rc": p["guest_rc"], "control_before": p["control_before"], "control_after": p["control_after"],
               "remote_control": p["remote_control"]}
        table.append(row)
        record(f"probe {p['probe']} ({row['dst']}) -> {verdict}", verdict == "ĐẠT",
               probe_packets=len(mine), expected=p["expected_class"], counter=dl.get(p["expected_class"], 0),
               pcap=cls.get(p["expected_class"], 0), mismatch=mismatch,
               failed_checks=[k for k, v in checks.items() if not v])
    json.dump(table, open(os.path.join(OUT, "matrix.json"), "w"), indent=1, default=str)
    with open(os.path.join(OUT, "matrix.md"), "w") as f:
        f.write("| probe | dst | probe pkts | expected counter = delta | pcap (same class) | verdict |\n|---|---|---|---|---|---|\n")
        for r in table:
            f.write(f"| {r['probe']} | {r['dst']} | {r['probe_packets']} | {r['expected_class']}="
                    f"{r['counter_delta'].get(r['expected_class'], 0)} | {r['pcap_classified'].get(r['expected_class'], 0)} | {r['verdict']} |\n")


if __name__ == "__main__":
    rc = main()
    failed = [r for r in results if not r["ok"]]
    sys.exit(rc if rc else (1 if failed else 0))
