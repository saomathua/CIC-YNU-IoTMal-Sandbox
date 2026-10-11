"""06B-2B: HTTP/API allowlist tests against the REAL worker server.py (uvicorn on :8011).

Runs inside the throwaway test container via `docker exec`, from /app.

Guest traffic is SIMULATED: 10.200.0.2/32 is temporarily on `lo` and requests are
sent from that source address to 10.200.0.1:8011. This exercises the HTTP
middleware with a real TCP peer address; it does NOT exercise the tap0 /
nftables path (lo is outside every CT-01 filter rule).

Fixtures are harmless text files (not ELF). Exit code 0 only if every check passes.
"""
import hashlib
import http.client
import json
import os
import sys
import time

sys.path.insert(0, "/app")
from isolation import constants as C          # noqa: E402
from isolation import current_task            # noqa: E402

BASE = "/api/v1/sandbox-worker"
T = sys.argv[1]
X = sys.argv[2]
ETH0_IP = sys.argv[3]
OUT = sys.argv[4]
DATA = "/app/data/"
STOP_FILE = "/tmp/sandbox_stop_requested"

GUEST_SRC = (C.GUEST_IP, 0)
results = []


def sha(b):
    return hashlib.sha256(b).hexdigest()


def req(method, path, src, target, headers=None, body=None):
    c = http.client.HTTPConnection(target, C.SVC_PORT, timeout=10, source_address=src)
    h = dict(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def multipart(content, name="f.log"):
    b = "06b2bboundary"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{b}--\r\n".encode()
    return {"Content-Type": f"multipart/form-data; boundary={b}"}, body


def record(name, ok, **detail):
    results.append({"test": name, "ok": bool(ok), **detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {json.dumps(detail, sort_keys=True)}", flush=True)


def expect(name, method, path, status, src=GUEST_SRC, target=C.WORKER_GUEST_IP, headers=None, body=None):
    got, data = req(method, path, src, target, headers, body)
    record(name, got == status, method=method, path=path, source=src[0], target=target,
           headers=headers or {}, expected=status, status=got)
    return got, data


def main():
    # ---------------------------------------------------------- fixtures (harmless text)
    fixture = b"06B-2B harmless text fixture - not an ELF, not a sample\n"
    other = b"06B-2B other-task fixture\n"
    for tid, content in ((T, fixture), (X, other)):
        os.makedirs(DATA + tid, exist_ok=True)
        with open(DATA + tid + "/" + tid, "wb") as f:
            f.write(content)
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    current_task.clear()
    data_before = sorted(os.listdir(DATA))
    record("fixture created", data_before == sorted([T, X]), data_dir=data_before,
           fixture_sha256=sha(fixture), magic=fixture[:4].hex())

    task_routes = [("GET", f"{BASE}/get-task/{T}/file"),
                   ("POST", f"{BASE}/update-task/{T}/strace"),
                   ("POST", f"{BASE}/update-task/{T}/sar")]

    # ---------------------------------------------------------- 1. no current_task -> all three 403
    for m, p in task_routes:
        h, b = multipart(b"must-not-be-written") if m == "POST" else (None, None)
        expect("no current_task -> 403", m, p, 403, headers=h, body=b)
    record("no current_task: nothing written",
           not os.path.exists(DATA + T + "/strace.log") and not os.path.exists(DATA + T + "/sar.out"))

    # ---------------------------------------------------------- 2. current_task via real helper
    current_task.set_current(T)
    record("current_task set by isolation.current_task", current_task.get_current() == T,
           file=C.CURRENT_TASK_FILE)

    st, data = expect("GET get-task/T/file", "GET", f"{BASE}/get-task/{T}/file", 200)
    record("downloaded content hash", sha(data) == sha(fixture), got=sha(data), expected=sha(fixture))

    for kind, fname in (("strace", "strace.log"), ("sar", "sar.out")):
        payload = f"06B-2B harmless {kind} upload\n".encode()
        h, b = multipart(payload)
        expect(f"POST update-task/T/{kind}", "POST", f"{BASE}/update-task/{T}/{kind}", 200, headers=h, body=b)
        path = DATA + T + "/" + fname
        got = open(path, "rb").read() if os.path.exists(path) else b""
        record(f"received {fname} hash", sha(got) == sha(payload), got=sha(got), expected=sha(payload))

    # ---------------------------------------------------------- 3. forbidden from simulated guest
    h, b = multipart(b"must-not-be-written")
    forbidden = [
        ("GET", f"{BASE}/get-task/{X}/file", None, None),
        ("POST", f"{BASE}/update-task/{X}/strace", h, b),
        ("POST", f"{BASE}/get-task/{T}/file", None, None),
        ("HEAD", f"{BASE}/get-task/{T}/file", None, None),
        ("GET", f"{BASE}/update-task/{T}/strace", None, None),
        ("PUT", f"{BASE}/update-task/{T}/sar", h, b),
        ("GET", "/healthcheck", None, None),
        ("POST", f"{BASE}/stop", None, None),
        ("POST", f"{BASE}/submit-task/{X}", h, b),
        ("POST", f"{BASE}/submit-task/new-06b2b-task", h, b),
        ("GET", "/docs", None, None),
        ("GET", "/openapi.json", None, None),
        ("GET", f"{BASE}/get-task/{T}/file/", None, None),
    ]
    for m, p, hh, bb in forbidden:
        expect("guest forbidden -> 403", m, p, 403, headers=hh, body=bb)

    # ---------------------------------------------------------- 4. spoofed forwarding headers
    for hdr in ({"X-Forwarded-For": ETH0_IP}, {"X-Forwarded-For": "127.0.0.1"},
                {"Forwarded": f"for={ETH0_IP}"}, {"X-Real-IP": "127.0.0.1"}):
        expect("guest + forwarding header -> still 403", "GET", "/healthcheck", 403, headers=hdr)
        expect("guest + forwarding header -> other task still 403", "GET", f"{BASE}/get-task/{X}/file", 403, headers=hdr)

    # ---------------------------------------------------------- 5. side effects of forbidden routes
    record("no stop file created", not os.path.exists(STOP_FILE))
    data_after = sorted(os.listdir(DATA))
    record("no task created by forbidden routes", data_after == sorted([T, X]), data_dir=data_after)
    record("other task not written", not os.path.exists(DATA + X + "/strace.log"))

    # ---------------------------------------------------------- 6. peers outside the guest network
    expect("loopback peer healthcheck -> 200", "GET", "/healthcheck", 200, src=("127.0.0.1", 0), target="127.0.0.1")
    expect("eth0 peer healthcheck -> 200", "GET", "/healthcheck", 200, src=(ETH0_IP, 0), target=ETH0_IP)
    expect("non-guest + XFF 10.200.0.2 -> still 200", "GET", "/healthcheck", 200, src=("127.0.0.1", 0),
           target="127.0.0.1", headers={"X-Forwarded-For": C.GUEST_IP})

    # ---------------------------------------------------------- 7. clear marker -> denied again
    current_task.clear()
    record("current_task cleared", current_task.get_current() is None and not os.path.exists(C.CURRENT_TASK_FILE))
    expect("after clear: GET get-task/T/file -> 403", "GET", f"{BASE}/get-task/{T}/file", 403)

    # ---------------------------------------------------------- cleanup fixtures
    import shutil
    for tid in (T, X):
        shutil.rmtree(DATA + tid, ignore_errors=True)
    record("fixtures removed", os.listdir(DATA) == [] and not os.path.exists(C.CURRENT_TASK_FILE),
           data_dir=os.listdir(DATA))

    with open(os.path.join(OUT, "http-results.json"), "w") as f:
        json.dump(results, f, indent=1)
    failed = [r for r in results if not r["ok"]]
    print(f"== {len(results) - len(failed)}/{len(results)} passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
