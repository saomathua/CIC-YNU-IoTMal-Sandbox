"""06B-3B control loop (runs in its own container on sandboxnet + dbnet).

Every 0.5 s it checks, from a vantage point that IS allowed to reach them, the exact
destinations the guest probes are not allowed to reach:
  mongo  <mongo_ip>:27017  TCP connect
  worker <worker_ip>:8011  GET /healthcheck  (worker eth0 address)
  manager <manager_ip>:8011 GET /healthcheck
One JSON line per check: {"ts", "target", "ok", "detail"}. Stops on SIGTERM.
"""
import http.client
import json
import signal
import socket
import sys
import time

worker_ip, mongo_ip, manager_ip, out = sys.argv[1:5]
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


checks = [(f"mongo {mongo_ip}:27017", lambda: tcp(mongo_ip, 27017)),
          (f"worker-eth0 {worker_ip}:8011", lambda: http_health(worker_ip)),
          (f"manager {manager_ip}:8011", lambda: http_health(manager_ip))]
with open(out, "a", buffering=1) as f:
    while running:
        for name, fn in checks:
            ts = time.time()
            try:
                f.write(json.dumps({"ts": ts, "target": name, "ok": True, "detail": fn()}) + "\n")
            except Exception as e:
                f.write(json.dumps({"ts": ts, "target": name, "ok": False, "detail": repr(e)}) + "\n")
        time.sleep(0.5)
