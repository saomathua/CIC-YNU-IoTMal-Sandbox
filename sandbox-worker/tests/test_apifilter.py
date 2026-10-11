"""Guest API allowlist, exercised through the real worker FastAPI app (server.app)."""
import asyncio
import json
import os

import pytest

from conftest import BASE
from isolation import current_task

T = "11111111-2222-3333-4444-555555555555"
X = "99999999-8888-7777-6666-555555555555"
GUEST = ("10.200.0.2", 40000)
MANAGER = ("192.168.60.10", 40000)
STOP_FILE = "/tmp/sandbox_stop_requested"


def call(app, method, path, client=GUEST, headers=(), body=b""):
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "root_path": "", "query_string": b"", "server": ("10.200.0.1", 8011), "client": client,
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers]
                   + [(b"content-length", str(len(body)).encode())],
    }
    sent = []
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], data


def multipart(filename="f.log", content=b"log-content"):
    boundary = "testboundary123"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return [("content-type", f"multipart/form-data; boundary={boundary}")], body


@pytest.fixture
def app(current_task_file, data_dir):
    import server
    for tid in (T, X):
        os.makedirs(data_dir + tid)
        with open(data_dir + tid + "/" + tid, "wb") as f:
            f.write(b"sample-" + tid.encode())
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    yield server.app
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)


def test_no_current_task_denies_even_allowed_route(app):
    assert call(app, "GET", f"{BASE}/get-task/{T}/file")[0] == 403


def test_current_task_file_download_allowed(app):
    current_task.set_current(T)
    status, data = call(app, "GET", f"{BASE}/get-task/{T}/file")
    assert status == 200 and data == b"sample-" + T.encode()


@pytest.mark.parametrize("kind", ["strace", "sar"])
def test_current_task_log_upload_allowed(app, data_dir, kind):
    current_task.set_current(T)
    headers, body = multipart(content=b"payload-" + kind.encode())
    status, _ = call(app, "POST", f"{BASE}/update-task/{T}/{kind}", headers=headers, body=body)
    assert status == 200
    name = "strace.log" if kind == "strace" else "sar.out"
    assert open(data_dir + T + "/" + name, "rb").read() == b"payload-" + kind.encode()


@pytest.mark.parametrize("method,path", [
    ("GET", f"{BASE}/get-task/{X}/file"),            # other task
    ("POST", f"{BASE}/get-task/{T}/file"),           # wrong method
    ("HEAD", f"{BASE}/get-task/{T}/file"),
    ("GET", f"{BASE}/update-task/{T}/strace"),
    ("PUT", f"{BASE}/update-task/{T}/sar"),
    ("POST", f"{BASE}/update-task/{T}/other"),
    ("GET", f"{BASE}/get-task/{T}/file/"),           # path variants
    ("GET", f"{BASE}//get-task/{T}/file"),
    ("GET", f"{BASE}/../sandbox-worker/get-task/{T}/file"),
    ("GET", f"/get-task/{T}/file"),
    ("GET", "/healthcheck"),                          # management / other routes
    ("POST", f"{BASE}/stop"),
    ("GET", "/docs"),
    ("GET", "/openapi.json"),
])
def test_guest_denied(app, method, path):
    current_task.set_current(T)
    assert call(app, method, path)[0] == 403
    assert not os.path.exists(STOP_FILE)


def test_guest_cannot_upload_to_other_task(app, data_dir):
    current_task.set_current(T)
    headers, body = multipart()
    assert call(app, "POST", f"{BASE}/update-task/{X}/strace", headers=headers, body=body)[0] == 403
    assert not os.path.exists(data_dir + X + "/strace.log")


def test_guest_cannot_submit_task(app, data_dir):
    current_task.set_current(T)
    headers, body = multipart()
    assert call(app, "POST", f"{BASE}/submit-task/new-task", headers=headers, body=body)[0] == 403
    assert not os.path.exists(data_dir + "new-task")


@pytest.mark.parametrize("hdr", [
    ("X-Forwarded-For", "192.168.60.10"),
    ("Forwarded", "for=192.168.60.10"),
    ("X-Real-IP", "192.168.60.10"),
])
def test_forwarding_headers_do_not_bypass(app, hdr):
    current_task.set_current(T)
    assert call(app, "GET", "/healthcheck", headers=[hdr])[0] == 403
    assert call(app, "GET", f"{BASE}/get-task/{X}/file", headers=[hdr])[0] == 403


def test_forwarding_header_cannot_make_non_guest_a_guest(app):
    status, _ = call(app, "GET", "/healthcheck", client=MANAGER, headers=[("X-Forwarded-For", "10.200.0.2")])
    assert status == 200


def test_non_guest_management_routes_unaffected(app):
    assert call(app, "GET", "/healthcheck", client=MANAGER)[0] == 200
    assert call(app, "GET", f"{BASE}/get-task/{X}/file", client=MANAGER)[0] == 200


@pytest.mark.parametrize("client", [("::ffff:10.200.0.2", 1), None, ("not-an-ip", 1)])
def test_mapped_or_unknown_peer_is_treated_as_guest(app, client):
    assert call(app, "GET", "/healthcheck", client=client)[0] == 403


def test_stale_or_invalid_current_task_denies(app, current_task_file):
    os.makedirs(os.path.dirname(current_task_file), exist_ok=True)
    with open(current_task_file, "w") as f:
        f.write("../etc")
    assert call(app, "GET", f"{BASE}/get-task/../etc/file")[0] == 403


def test_uvicorn_does_not_trust_proxy_headers():
    import server
    opts = server.uvicorn_options()
    assert opts["proxy_headers"] is False
    assert opts["forwarded_allow_ips"] == ""


def test_denied_response_is_json_403(app):
    status, data = call(app, "GET", "/healthcheck")
    assert status == 403 and json.loads(data) == {"detail": "forbidden"}
