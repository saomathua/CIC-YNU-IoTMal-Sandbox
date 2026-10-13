"""Offline tests for P4 (manager). usage: check_manager_p4.py <base_manager_dir> <proposed_manager_dir>
Drives the REAL FastAPI app (router + multipart/Form parsing + UploadFile) through the ASGI interface with hand-built multipart bodies; the database is a recording fake,
the filesystem is a temp dir. No HTTP server, no Mongo, no network."""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid

S = tempfile.mkdtemp(prefix="ct04-mgr-")
M = S + "/sandbox-manager"
shutil.copytree(os.path.abspath(sys.argv[1]), M, ignore=shutil.ignore_patterns("__pycache__"))
for root, _d, files in os.walk(os.path.abspath(sys.argv[2])):
    for f in files:
        if f.endswith(".pyc"):
            continue
        src = os.path.join(root, f)
        dst = os.path.join(M, os.path.relpath(src, os.path.abspath(sys.argv[2])))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(src, dst)
sys.path.insert(0, M)
OUT = tempfile.mkdtemp(prefix="ct04-out-")
os.environ.update({"PORT": "8010", "APP_BASE_URL": "/api/v1/sandbox-manager", "MONGO_USERNAME": "u", "MONGO_PASSWORD": "p", "MALWARE_DIRECTORY": S,
                   "OUTPUT_DIR": OUT + "/", "UPLOAD_DIR": OUT + "/"})
from fastapi import FastAPI                         # noqa: E402
from router import sandbox_router as R             # noqa: E402

RES = []


def ok(name, cond, extra=""):
    RES.append(bool(cond))
    print(("[OK]   " if cond else "[FAIL] ") + name + ((" " + str(extra)) if (extra and not cond) else ""))


class Coll:
    def __init__(self):
        self.calls = []

    def update_one(self, flt, upd, **kw):
        self.calls.append((flt, upd))


app = FastAPI()
app.include_router(R.router)
BASE = os.environ["APP_BASE_URL"]


def post(task, fields, zip_bytes=b"PK-result-zip"):
    """-> (status_code, response json or None, db calls, zip path exists)"""
    coll = Coll()
    app.database = {"malware_queue": coll}
    b = "----ct04" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        for one in (v if isinstance(v, list) else [v]):          # a list value = the same field sent several times
            if isinstance(one, tuple) and one[0] == "__file__":   # the field sent as a FILE part instead of a form value
                parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="x.json"\r\nContent-Type: application/json\r\n\r\n%s\r\n' % (b, k, one[1])).encode("utf-8"))
            else:
                parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, one)).encode("utf-8"))
    parts.append(('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s.zip"\r\nContent-Type: application/zip\r\n\r\n' % (b, task)).encode() + zip_bytes + b"\r\n")
    parts.append(("--%s--\r\n" % b).encode())
    body = b"".join(parts)
    zpath = os.path.join(OUT, task + ".zip")
    if os.path.exists(zpath):
        os.remove(zpath)
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": BASE + "/submit-result/" + task, "raw_path": (BASE + "/submit-result/" + task).encode(),
             "query_string": b"", "root_path": "", "scheme": "http", "server": ("t", 80), "client": ("c", 1), "app": app,
             "headers": [(b"content-type", ("multipart/form-data; boundary=" + b).encode()), (b"content-length", str(len(body)).encode())]}
    crashed = None
    try:
        asyncio.run(app(scope, receive, send))
    except Exception as e:                                       # noqa: BLE001  (an unhandled error is a 500 in production)
        crashed = e
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), 500)
    if crashed is not None and status != 500:
        status = 500
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    try:
        js = json.loads(raw)
    except ValueError:
        js = None
    return status, js, coll.calls, os.path.exists(zpath)


def rep(task, **kw):
    d = {"schema": "ct04-execution-class/1", "task_id": task, "execution_class": "EXITED_NONZERO", "evidence": ["exit 127"], "flags": ["LOADER_ERROR_REPORTED"], "main_pid": 961}
    d.update(kw)
    return {k: v for k, v in d.items() if v is not ...}


# ---- control (valid) and old worker ----
st, js, calls, z = post("t-ok", {"execution_class": json.dumps(rep("t-ok"))})
s = calls[0][1]["$set"] if calls else {}
ok("M1 control: valid report => 200, ZIP written, status COMPLETED + class stored", st == 200 and z and s.get("status") == "COMPLETED" and s.get("execution_class") == "EXITED_NONZERO"
   and s.get("execution_evidence") == ["exit 127"] and s.get("execution_flags") == ["LOADER_ERROR_REPORTED"], (st, js, s))
ok("M1b response body unchanged", js == {"task_id": "t-ok", "status": "COMPLETED"}, js)
st, js, calls, z = post("t-old", {})
s = calls[0][1]["$set"] if calls else {}
ok("M2 older worker (field absent) => 200, COMPLETED and explicitly NOT_CLASSIFIED", st == 200 and z and s.get("status") == "COMPLETED" and s.get("execution_class") == "NOT_CLASSIFIED"
   and "NO_WORKER_REPORT" in s.get("execution_flags", []), (st, s))
st, js, calls, z = post("t-empty", {"execution_class": ""})
ok("M2b a field that is PRESENT but empty is NOT an older worker: 422, ZIP not written, database untouched", st == 422 and not z and calls == [], (st, js, calls))


def rejected(name, task, raw):
    st, js, calls, z = post(task, {"execution_class": raw})
    ok(name + " => 422, ZIP not written, database untouched", st == 422 and not z and calls == [], (st, js, calls, z))


rejected("M3 wrong schema", "t-s", json.dumps(rep("t-s", schema="ct04-execution-class/2")))
rejected("M3b missing schema", "t-s2", json.dumps(rep("t-s2", schema=...)))
rejected("M4 task_id of another task", "t-a", json.dumps(rep("t-other")))
rejected("M4b task_id missing", "t-a2", json.dumps(rep("t-a2", task_id=...)))
rejected("M5 wrong type: whole report is a list", "t-t1", json.dumps([1, 2]))
rejected("M5b wrong type: evidence is a string", "t-t2", json.dumps(rep("t-t2", evidence="exit 127")))
rejected("M5c wrong type: flags is an int", "t-t3", json.dumps(rep("t-t3", flags=3)))
rejected("M5d wrong type: execution_class is a number", "t-t4", json.dumps(rep("t-t4", execution_class=7)))
rejected("M5e wrong type: main_pid is a string", "t-t5", json.dumps(rep("t-t5", main_pid="961")))
rejected("M5f wrong type: main_pid is a bool", "t-t6", json.dumps(rep("t-t6", main_pid=True)))
rejected("M5g wrong type: evidence item is not a string", "t-t7", json.dumps(rep("t-t7", evidence=[1])))
_big = "t-" + "b" * 8300
rejected("M6 oversize (valid report > 8192 bytes: only allowed keys, long but matching task id)", _big, json.dumps(rep(_big)))
rejected("M6b evidence has 11 items", "t-e1", json.dumps(rep("t-e1", evidence=["x"] * 11)))
rejected("M6c evidence item longer than 200 chars", "t-e2", json.dumps(rep("t-e2", evidence=["x" * 201])))
rejected("M6d more than 20 flags", "t-f1", json.dumps(rep("t-f1", flags=["F"] * 21)))
rejected("M6e flag with lowercase / space", "t-f2", json.dumps(rep("t-f2", flags=["bad flag"])))
rejected("M7 unknown class", "t-c1", json.dumps(rep("t-c1", execution_class="TOTALLY_FINE")))
rejected("M7b MISSING_LIBRARY is reserved and never accepted", "t-c2", json.dumps(rep("t-c2", execution_class="MISSING_LIBRARY")))
rejected("M7c NOT_CLASSIFIED cannot be claimed by a worker", "t-c3", json.dumps(rep("t-c3", execution_class="NOT_CLASSIFIED")))
rejected("M8 not JSON", "t-j", "{oops")
rejected("M9 unknown key", "t-k", json.dumps(rep("t-k", extra="x")))
rejected("M10 whitespace-only (present but not a report)", "t-w", "   ")

rejected("M15 whitespace only", "t-w2", "\n\t ")
rejected("M15b JSON null", "t-n1", "null")
rejected("M15c JSON number", "t-n2", "7")
rejected("M15d JSON string", "t-n3", json.dumps("EXITED_0"))
rejected("M15e empty JSON object", "t-n4", "{}")
for nm, v in (("a list", ["EXITED_0"]), ("a dict", {"a": 1}), ("null", None), ("a number", 5), ("a bool", True), ("a nested list", [["EXITED_0"]])):
    t_ = "t-c-" + nm.replace(" ", "-")
    rejected("M16 execution_class inside the report is %s (unhashable / wrong type must be 422, not 500)" % nm, t_, json.dumps(rep(t_, execution_class=v)))
for nm, kw in (("schema is a list", {"schema": ["ct04-execution-class/1"]}), ("task_id is a list", {"task_id": ["t"]}), ("task_id is a number", {"task_id": 7}),
               ("evidence is a dict", {"evidence": {"a": 1}}), ("flags is a string", {"flags": "A"}), ("main_pid is a list", {"main_pid": [1]}), ("main_pid is 0", {"main_pid": 0}),
               ("main_pid is a float", {"main_pid": 1.5}), ("main_pid is NaN", {"main_pid": float("nan")})):
    t_ = "t-d-" + nm.replace(" ", "-")
    rejected("M17 %s" % nm, t_, json.dumps(rep(t_, **kw)))
rejected("M18 deeply nested array (RecursionError in the JSON parser) => 422, not 500", "t-deep", "[" * 4000 + "]" * 4000)
rejected("M18b deeply nested object", "t-deep2", '{"a":' * 1500 + "1" + "}" * 1500)
st, js, calls, z = post("t-file", {"execution_class": ("__file__", json.dumps(rep("t-file")))})
ok("M19 the field sent as a FILE part is not accepted as a value (422, not 500)", st == 422 and not z and calls == [], (st, js))
st, js, calls, z = post("t-dup", {"execution_class": [json.dumps(rep("t-dup")), json.dumps(rep("t-dup", execution_class="EXITED_0"))]})
ok("M20 a repeated field never causes a 500", st in (200, 422), st)

ok("M11 every class the worker can emit is accepted", all(R.validate_execution_class(json.dumps(rep("x", execution_class=k)), "x")[1] is None for k in (
    "EXITED_0", "EXITED_NONZERO", "CRASHED", "KILLED_BY_SIGNAL", "STOPPED_BY_SANDBOX", "SAMPLE_TIMEOUT", "EXEC_FORMAT_ERROR", "EXEC_NOT_FOUND",
    "EXEC_PERMISSION_DENIED", "EXEC_FAILED", "LOG_MISSING", "LOG_INVALID", "UNKNOWN_INCOMPLETE", "INCONSISTENT_EVIDENCE", "INFRA_TIMEOUT", "INFRA_FAILURE")))
ok("M12 validate_execution_class never raises on non-text input", all(R.validate_execution_class(v, "x")[0] is None for v in (None, 5, object(), ["x"], b"{}")))
ok("M13 a report whose main_pid is null is valid", R.validate_execution_class(json.dumps(rep("x", main_pid=None)), "x")[1] is None)

_dump = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "worker-reports.json")
if os.path.exists(_dump):
    reps = json.load(open(_dump))
    for k, v in reps.items():
        st_, js_, calls_, z_ = post(v["task_id"], {"execution_class": json.dumps(v)})
        ok("M14 report produced by the real worker code (%s) is accepted by the manager" % k, st_ == 200 and calls_ and calls_[0][1]["$set"]["execution_class"] == v["execution_class"], (st_, js_))
else:
    ok("M14 worker-generated reports present", False, "fixtures/worker-reports.json missing")
bad = RES.count(False)
print("SUMMARY: %d checks, %d FAIL" % (len(RES), bad))
sys.exit(1 if bad else 0)
