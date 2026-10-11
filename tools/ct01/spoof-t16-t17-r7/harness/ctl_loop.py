"""06B-3B control loop (runs in its own container on sandboxnet + dbnet).

Every 0.5 s it checks, from a vantage point that IS allowed to reach them, the exact
destinations the guest probes are not allowed to reach:
  mongo  <mongo_ip>:27017  TCP connect
  worker <worker_ip>:8011  GET /healthcheck  (worker eth0 address)
  manager <manager_ip>:8011 GET /healthcheck
One JSON line per check: {"ts", "target", "ok", "detail"}. Stops on SIGTERM.
06B-4I: with the optional 5th argument --arp-worker, right after the worker check it also logs its own ARP
entry for the worker (target "arp worker-eth0 <worker_ip>", read-only /proc/net/arp of this container): the live
control of T14-A1 (ARP for 192.168.60.2 resolved on sandboxnet). Without it nothing changes.
06B-4IR1: the ARP payload also carries the entry's IP and the MAC of its device (read-only /sys/class/net).
"""
import http.client
import json
import signal
import socket
import sys
import time

worker_ip, mongo_ip, manager_ip, out = sys.argv[1:5]
ARP_WORKER = sys.argv[5:] == ["--arp-worker"]
if sys.argv[5:] and not ARP_WORKER:
    sys.exit(f"unknown argument(s) {sys.argv[5:]}")
PROC_ARP = "/proc/net/arp"
SYS_NET = "/sys/class/net"
running = True
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__("running", False))


def tcp(ip, port):
    s = socket.create_connection((ip, port), timeout=2)
    s.close()
    return "connected"


def http_health(ip):
    c = http.client.HTTPConnection(ip, 8011, timeout=2)
    c.request("GET", "/healthcheck")
    st = c.getresponse().status
    c.close()
    if st != 200:
        raise RuntimeError(f"HTTP {st}")
    return "HTTP 200"


def arp_entry(ip, path=None, sys_net=None):
    """06B-4I: this container's ARP entry for ip -> {"ip", "hw", "flags", "device", "device_mac"}; raises unless
    exactly one row with the complete flag (ATF_COM 0x2) and a non-zero MAC exists. 06B-4IR1: also the entry's IP
    and the MAC of its device (/sys/class/net/<device>/address, read only), so that the consumer can bind the device
    to ctl's sandboxnet endpoint by MAC instead of assuming an interface name."""
    rows = []
    with open(path or PROC_ARP) as f:
        lines = f.read().splitlines()
    if not lines or not lines[0].startswith("IP address"):
        raise RuntimeError("unexpected /proc/net/arp header")
    for line in lines[1:]:
        c = line.split()
        if len(c) != 6:
            raise RuntimeError(f"unexpected /proc/net/arp row {line!r}")
        if c[0] == ip:
            rows.append({"hw": c[3].lower(), "flags": c[2].lower(), "device": c[5]})
    if len(rows) != 1:
        raise RuntimeError(f"{len(rows)} ARP row(s) for {ip}")
    r = rows[0]
    if not int(r["flags"], 16) & 0x2 or r["hw"] == "00:00:00:00:00:00":
        raise RuntimeError(f"ARP entry for {ip} not complete: {r}")
    if "/" in r["device"] or r["device"] in (".", ".."):
        raise RuntimeError(f"unexpected device name {r['device']!r}")
    with open(f"{sys_net or SYS_NET}/{r['device']}/address") as f:
        dmac = f.read().strip().lower()
    return {"ip": ip, **r, "device_mac": dmac}


checks = [(f"mongo {mongo_ip}:27017", lambda: tcp(mongo_ip, 27017)),
          (f"worker-eth0 {worker_ip}:8011", lambda: http_health(worker_ip)),
          (f"manager {manager_ip}:8011", lambda: http_health(manager_ip))]
if ARP_WORKER:   # right after the worker HTTP check, so that the entry is the one that connection used
    checks.insert(2, (f"arp worker-eth0 {worker_ip}", lambda: arp_entry(worker_ip)))
with open(out, "a", buffering=1) as f:
    while running:
        for name, fn in checks:
            ts = time.time()
            try:
                f.write(json.dumps({"ts": ts, "target": name, "ok": True, "detail": fn()}) + "\n")
            except Exception as e:
                f.write(json.dumps({"ts": ts, "target": name, "ok": False, "detail": repr(e)}) + "\n")
        time.sleep(0.5)
