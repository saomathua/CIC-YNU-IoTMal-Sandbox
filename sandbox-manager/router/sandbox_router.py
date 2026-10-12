import json
import logging
import os
import re
from typing import Optional
import queue
import shutil
import urllib.request
import uuid

from fastapi import APIRouter, Form, Request, UploadFile, HTTPException
from starlette.responses import FileResponse

from config.settings import app_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix=app_settings.app_base_url)

file_queue = queue.Queue()
queued_ids: set = set()  # in-memory duplicate guard — mirrors what is currently in file_queue

# CT-04: execution classes a worker may report. `status` stays COMPLETED ("analysis finished"); the class says what happened to the sample and does NOT mean it
# exited successfully. A worker that sends the field must send a valid one: a present-but-wrong value is REJECTED (422) before the ZIP or the database is touched, so a
# defective report never becomes a silent COMPLETED-without-class. Only a field that is truly ABSENT (an older worker) is accepted and stored as NOT_CLASSIFIED; an empty value is a
# present-but-invalid report.
EXECUTION_CLASSES = frozenset((
    "EXITED_0", "EXITED_NONZERO", "CRASHED", "KILLED_BY_SIGNAL", "STOPPED_BY_SANDBOX", "SAMPLE_TIMEOUT", "EXEC_FORMAT_ERROR", "EXEC_NOT_FOUND",
    "EXEC_PERMISSION_DENIED", "EXEC_FAILED", "LOG_MISSING", "LOG_INVALID", "UNKNOWN_INCOMPLETE", "INCONSISTENT_EVIDENCE", "INFRA_TIMEOUT", "INFRA_FAILURE"))
EXECUTION_CLASS_SCHEMA = "ct04-execution-class/1"
EXECUTION_CLASS_MAX_BYTES = 8192
_FLAG_RE = re.compile(r"^[A-Z0-9_]{1,48}$")
_EXEC_KEYS = frozenset(("schema", "task_id", "execution_class", "evidence", "flags", "main_pid"))
NOT_CLASSIFIED = {"execution_class": "NOT_CLASSIFIED", "execution_evidence": ["the worker did not report an execution class"], "execution_flags": ["NO_WORKER_REPORT"]}


def validate_execution_class(raw, task_id: str):
    """-> (fields to store, None) or (None, reason). Strict: type of the field, schema, task binding, types, sizes and the class allowlist are all checked; nothing is repaired.
    NEVER raises (a hostile report must produce a 422, not a 500): any internal error is reported as a rejection."""
    try:
        return _validate_execution_class(raw, task_id)
    except Exception as e:                                           # noqa: BLE001  (RecursionError, MemoryError-like conditions of json, ...)
        return None, "report could not be validated (%s)" % type(e).__name__


def _validate_execution_class(raw, task_id: str):
    if not isinstance(raw, str):
        return None, "execution_class is not text"
    if len(raw.encode("utf-8")) > EXECUTION_CLASS_MAX_BYTES:
        return None, "execution_class larger than %d bytes" % EXECUTION_CLASS_MAX_BYTES
    try:
        d = json.loads(raw)
    except (ValueError, RecursionError):
        return None, "execution_class is not JSON (or nested too deeply)"
    if not isinstance(d, dict):
        return None, "execution_class is not an object"
    if set(d) - _EXEC_KEYS:
        return None, "unknown keys: %s" % sorted(str(k) for k in set(d) - _EXEC_KEYS)[:5]
    if not isinstance(d.get("schema"), str) or d["schema"] != EXECUTION_CLASS_SCHEMA:
        return None, "schema is not %s" % EXECUTION_CLASS_SCHEMA
    if not isinstance(d.get("task_id"), str) or d["task_id"] != task_id:
        return None, "task_id in the report does not match the task of the endpoint"
    klass = d.get("execution_class")
    if not isinstance(klass, str):                                  # a list/dict is unhashable: the allowlist lookup must never see it
        return None, "execution_class must be a string"
    if klass not in EXECUTION_CLASSES:
        return None, "unknown execution_class"
    ev, fl = d.get("evidence", []), d.get("flags", [])
    if not isinstance(ev, list) or len(ev) > 10 or not all(isinstance(x, str) and len(x) <= 200 for x in ev):
        return None, "evidence must be at most 10 strings of at most 200 characters"
    if not isinstance(fl, list) or len(fl) > 20 or not all(isinstance(x, str) and _FLAG_RE.match(x) for x in fl):
        return None, "flags must be at most 20 strings matching [A-Z0-9_]{1,48}"
    mp = d.get("main_pid")
    if mp is not None and (not isinstance(mp, int) or isinstance(mp, bool) or mp <= 0):
        return None, "main_pid must be a positive integer or null"
    return {"execution_class": klass, "execution_evidence": list(ev), "execution_flags": list(fl)}, None


def _enqueue(db, task_id: str, file_path: str, filename: str):
    """Add a task to the in-memory queue and upsert it in the database.
    No-op if the task_id is already queued."""
    if task_id in queued_ids:
        return
    file_queue.put((file_path, task_id))
    queued_ids.add(task_id)
    db["malware_queue"].update_one(
        {"_id": task_id},
        {"$set": {"_id": task_id, "filename": filename, "path": file_path, "status": "QUEUED"}},
        upsert=True
    )


@router.get("/status")
async def get_status(request: Request):
    """Return task counts grouped by status and the current in-memory queue depth."""
    pipeline = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
    counts = {
        doc["_id"]: doc["count"]
        for doc in request.app.database["malware_queue"].aggregate(pipeline)
    }
    return {
        "queued": counts.get("QUEUED", 0),
        "processing": counts.get("PROCESSING", 0),
        "completed": counts.get("COMPLETED", 0),
        "failed": counts.get("FAILED", 0),
        "cancelled": counts.get("CANCELLED", 0),
        "in_memory_queue": file_queue.qsize(),
    }


@router.get("/init-queue")
async def init_queue(request: Request):
    """Scan the malware directory and enqueue any files not already tracked."""
    if not os.path.exists(app_settings.malware_directory):
        logger.error(f"Malware directory not found: {app_settings.malware_directory}")
        raise HTTPException(status_code=500, detail='Malware directory not found')

    malware_dir = os.path.realpath(app_settings.malware_directory)
    all_files = []
    for dirpath, _, filenames in os.walk(malware_dir):
        for f in filenames:
            full_path = os.path.join(dirpath, f)
            if os.path.realpath(full_path).startswith(malware_dir + os.sep):
                all_files.append((full_path, f))

    added = 0
    skipped = 0
    for file_path, filename in all_files:
        # Skip if this path is already actively queued or being processed
        existing = request.app.database["malware_queue"].find_one(
            {"path": file_path, "status": {"$in": ["QUEUED", "PROCESSING"]}}
        )
        if existing:
            skipped += 1
            continue
        _enqueue(request.app.database, str(uuid.uuid4()), file_path, filename)
        added += 1

    logger.info(f"Queue initialised: {added} added, {skipped} skipped")
    return {"added": added, "skipped": skipped, "total": len(all_files)}


@router.post("/submit-file")
async def submit_file(request: Request, file: UploadFile):
    """Submit a single malware binary directly for analysis."""
    task_id = str(uuid.uuid4())
    os.makedirs(app_settings.upload_dir, exist_ok=True)
    file_path = os.path.join(app_settings.upload_dir, task_id)
    try:
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
    except Exception:
        raise HTTPException(status_code=500, detail='Failed to save uploaded file')
    finally:
        file.file.close()

    _enqueue(request.app.database, task_id, file_path, file.filename)
    logger.info(f"Submitted file '{file.filename}' as task {task_id}")
    return {"task_id": task_id, "filename": file.filename, "status": "QUEUED"}


@router.get("/get-file/{worker_id}")
async def get_file(request: Request, worker_id: str, worker_uri: str = ""):
    """Hand the next queued task to a worker."""
    try:
        file_path, task_id = file_queue.get(block=False)
        queued_ids.discard(task_id)
        request.app.database["malware_queue"].update_one(
            {"_id": task_id},
            {"$set": {"status": "PROCESSING", "worker_id": str(worker_id), "worker_uri": worker_uri}}
        )
        logger.info(f"Dispatching task {task_id} to worker {worker_id}")
        return FileResponse(file_path, media_type='application/octet-stream', filename=task_id)
    except queue.Empty:
        raise HTTPException(status_code=404, detail='No tasks available')


@router.post("/submit-result/{task_id}")
async def submit_result(request: Request, task_id: str, file: UploadFile, execution_class: Optional[str] = Form(default=None)):
    """Receive the completed analysis result zip from a worker (+ its execution class, CT-04)."""
    if execution_class is None:
        exec_fields = dict(NOT_CLASSIFIED)                 # the field is ABSENT (older worker): compatible, and said so explicitly. An empty value is NOT absence.
    else:
        exec_fields, why = validate_execution_class(execution_class, task_id)
        if why is not None:
            # rejected BEFORE the ZIP is written or the task is touched: the worker's upload fails and its existing failure path reports it
            logger.warning(f"Result for task {task_id} rejected: invalid execution_class report ({why})")
            file.file.close()
            raise HTTPException(status_code=422, detail="invalid execution_class report: " + why)
    result_path = os.path.join(app_settings.output_dir, task_id + ".zip")
    try:
        with open(result_path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
        fields = {"status": "COMPLETED", "result_path": result_path}
        fields.update(exec_fields)
        request.app.database["malware_queue"].update_one(
            {"_id": task_id},
            {"$set": fields}
        )
    except Exception:
        raise HTTPException(status_code=500, detail='Something went wrong')
    finally:
        file.file.close()
    logger.info(f"Received result for task: {task_id}")
    return {"task_id": task_id, "status": "COMPLETED"}


@router.post("/submit-failure/{task_id}")
async def submit_failure(request: Request, task_id: str, reason: str = ""):
    """Mark a task as FAILED. Called by a worker when analysis throws an unrecoverable error."""
    result = request.app.database["malware_queue"].update_one(
        {"_id": task_id},
        {"$set": {"status": "FAILED", "failure_reason": reason}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail='Task not found')
    logger.warning(f"Task {task_id} marked FAILED: {reason}")
    return {"task_id": task_id, "status": "FAILED"}


@router.post("/cancel/{task_id}")
async def cancel_task(request: Request, task_id: str):
    """Cancel a PROCESSING task. Marks it CANCELLED and signals the worker to stop."""
    task = request.app.database["malware_queue"].find_one({"_id": task_id})
    if not task:
        raise HTTPException(status_code=404, detail='Task not found')
    if task.get("status") != "PROCESSING":
        raise HTTPException(status_code=400, detail='Task is not currently being processed')

    request.app.database["malware_queue"].update_one(
        {"_id": task_id},
        {"$set": {"status": "CANCELLED"}}
    )
    logger.info(f"Task {task_id} marked CANCELLED")

    worker_uri = task.get("worker_uri", "")
    if worker_uri:
        try:
            urllib.request.urlopen(worker_uri + "/stop", data=b'', timeout=3)
        except Exception:
            logger.warning(f"Could not reach worker to stop task {task_id}")

    return {"task_id": task_id, "status": "CANCELLED"}


@router.get("/tasks")
async def list_tasks(request: Request, status: str = None):
    """List all tasks, optionally filtered by status (QUEUED, PROCESSING, COMPLETED, FAILED)."""
    query = {"status": status.upper()} if status else {}
    tasks = list(request.app.database["malware_queue"].find(
        query,
        {"_id": 1, "filename": 1, "status": 1, "worker_id": 1, "failure_reason": 1}
    ))
    return {
        "tasks": [
            {
                "task_id": t["_id"],
                "filename": t.get("filename", ""),
                "status": t.get("status", ""),
                "worker_id": t.get("worker_id", ""),
                "failure_reason": t.get("failure_reason", ""),
            }
            for t in tasks
        ]
    }


@router.get("/results")
async def list_results(request: Request):
    """List all completed analysis tasks."""
    completed = list(request.app.database["malware_queue"].find(
        {"status": "COMPLETED"},
        {"_id": 1, "filename": 1, "worker_id": 1}
    ))
    return {
        "results": [
            {"task_id": r["_id"], "filename": r.get("filename", ""), "worker_id": r.get("worker_id", "")}
            for r in completed
        ]
    }


@router.get("/results/{task_id}")
async def get_result(task_id: str):
    """Download the analysis result zip for a completed task."""
    result_path = os.path.join(app_settings.output_dir, task_id + ".zip")
    if not os.path.exists(result_path):
        raise HTTPException(status_code=404, detail='Result not found')
    return FileResponse(result_path, media_type='application/zip', filename=task_id + ".zip")
