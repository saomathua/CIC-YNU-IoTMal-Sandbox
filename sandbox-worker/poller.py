import logging
import json
import os
import re
import shutil
import socket
import sys
import time

import requests

from config.settings import app_settings
from isolation import current_task
from service.analysis import dynamic_analysis, clear_stop, AnalysisCancelled, UnsafeWorkerState
from service import execution_class

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


RAW_CONSOLE_LOG_MAX = 1024 * 1024


def _log_raw_console(fname, task_dir):
    """Failure evidence: the raw console bytes (no newline normalisation) as base64 lines in the worker log, with length and sha256 so that the bytes can be
    rebuilt and verified from `docker logs`. Never raises."""
    try:
        import base64
        import hashlib
        with open(task_dir + "/console.raw", "rb") as f:
            data = f.read(RAW_CONSOLE_LOG_MAX + 1)
        truncated = len(data) > RAW_CONSOLE_LOG_MAX
        data = data[:RAW_CONSOLE_LOG_MAX]
        b = base64.b64encode(data).decode("ascii")
        lines = [b[i:i + 76] for i in range(0, len(b), 76)]
        logger.error(f"RAW-CONSOLE-BEGIN task={fname} bytes={len(data)} truncated={truncated} sha256={hashlib.sha256(data).hexdigest()}")
        for l in lines:
            logger.error(f"RAW-CONSOLE {l}")
        logger.error(f"RAW-CONSOLE-END task={fname}")
    except FileNotFoundError:
        logger.warning(f"No raw console log for task {fname}")
    except Exception:                                                 # noqa: BLE001
        logger.exception(f"raw console log not written for task {fname}")



def startup_cleanup():
    """Remove a current_task marker left over from a previous run (crash, kill)."""
    current_task.clear()


REQUEST_TIMEOUT = (5, 30)          # (connect, read) seconds for every call to the manager
UPLOAD_TIMEOUT = (5, 300)
REPORT_ATTEMPTS = 3


class UnsafeWorker(RuntimeError):
    """The worker cannot guarantee a clean state for the next task (a child process not confirmed exited, or the task's own files could not be removed).
    The poller exits with status 3 and takes NO further task. Whether the container is then restarted (and V0 runs again) depends on the restart policy
    in force (Compose: `restart: on-failure`; a lane started with `--restart no` stays stopped). `reasons` keeps every error (analysis, cleanup, report)."""

    def __init__(self, task, reasons):
        super().__init__(f"worker unsafe after task {task}: " + "; ".join(reasons))
        self.task, self.reasons = task, list(reasons)


def _post(url, **kw):
    """-> (ok, detail). Never raises for transport errors; a non-200 answer is NOT ok."""
    kw.setdefault("timeout", REQUEST_TIMEOUT)
    try:
        resp = requests.post(url, **kw)
    except Exception as e:                                           # noqa: BLE001  (only this network call)
        return False, f"transport error: {e!r}"
    code = getattr(resp, "status_code", None)
    return code == 200, f"HTTP {code}"


def report_failure(fname, reason):
    """Tell the manager the task failed (bounded retries, request timeout, response checked). -> (ok, detail)"""
    url = app_settings.sandbox_manager_uri + "/submit-failure/" + fname
    detail = "no attempt"
    for n in range(REPORT_ATTEMPTS):
        ok, detail = _post(url, params={"reason": str(reason)[:500]})
        if ok:
            return True, detail
        logger.error(f"failure report for task {fname} not accepted (attempt {n + 1}/{REPORT_ATTEMPTS}): {detail}")
        if n + 1 < REPORT_ATTEMPTS:
            time.sleep(1)
    return False, detail


def _absent(path):
    """-> (True, '') only when `path` itself does not exist (lstat: a symlink is not followed); (False, why) when it exists or cannot be checked."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True, ""
    except OSError as e:
        return False, f"cannot verify that {path} is gone: {e!r}"
    return False, f"{path} is still present"


def remove_task_files(task_dir):
    """Remove the task's own directory and zip. The result is judged by the POSTCONDITION, not by the exception: a FileNotFoundError is accepted only when
    the owned target itself is then confirmed absent (no-follow); a descendant that vanished while the root remains, any other OSError, and an unreadable
    state are all cleanup failures. -> [error text] (empty = both targets confirmed gone)."""
    errors = []
    for path, fn in ((task_dir, shutil.rmtree), (task_dir + ".zip", os.remove)):
        removal_error = None
        try:
            fn(path)
        except FileNotFoundError as e:
            removal_error = e                       # meaning depends on the postcondition below
        except OSError as e:
            removal_error = e
        gone, why = _absent(path)
        if gone:
            continue
        if removal_error is not None:
            errors.append(f"cannot remove {path}: {removal_error!r} ({why})")
        else:
            errors.append(f"cannot remove {path}: {why}")
    return errors


def _unsafe_cause(exc):
    """True when `exc` or anything in its __cause__/__context__ chain is an UnsafeWorkerState (a wrapper can never hide the classification)."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, UnsafeWorkerState):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def _fail_task(fname, task_dir, reason, cause=None):
    """Common failure path: cleanup the task's files, report the failure, keep every error. Raises UnsafeWorker when the worker state cannot be vouched
    for (cleanup error or an unsafe cause); returns normally for a recoverable failure (reported or not: both are logged)."""
    errors = remove_task_files(task_dir)
    ok, detail = report_failure(fname, reason)
    reasons = [f"task failed: {reason}"] + errors
    if not ok:
        reasons.append(f"failure report not accepted: {detail}")
        logger.error(f"task {fname}: failure NOT reported to the manager ({detail}); the manager may keep it PROCESSING")
    if errors or _unsafe_cause(cause):
        raise UnsafeWorker(fname, reasons) from cause
    return ok


def run_analysis(fname, task_dir, worker, outcome=None):
    """Run one analysis with the guest API allowlist bound to this task. The current_task marker is removed on every exit path.
    Returns True (analysis done, result to upload) or False (failed/cancelled and handled: files removed, failure reported for a failure). When `outcome` is a dict
    it receives {"state": "done"|"cancelled"|"failed"} so that the caller can tell a cancel from a failure (the bool API is what tests/test_current_task.py asserts).
    Raises UnsafeWorker when the worker cannot take another task."""
    outcome = outcome if outcome is not None else {}
    clear_stop()
    try:
        current_task.set_current(fname)
        dynamic_analysis(fname, task_dir=task_dir, worker=worker)
        outcome["state"] = "done"
        return True
    except AnalysisCancelled:
        logger.warning(f"Task {fname} was cancelled")
        errors = remove_task_files(task_dir)
        if errors:
            raise UnsafeWorker(fname, ["task cancelled"] + errors)
        outcome["state"] = "cancelled"
        return False
    except Exception as e:
        logger.exception(f"Analysis failed for task {fname}")
        qemu_log = task_dir + app_settings.qemu_log_path
        try:
            with open(qemu_log, 'r', encoding='utf-8', errors='replace') as _lf:
                logger.error(f"QEMU log for task {fname}:\n{_lf.read()}")
        except FileNotFoundError:
            logger.warning(f"No QEMU log found for task {fname}")
        _log_raw_console(fname, task_dir)
        _fail_task(fname, task_dir, str(e), cause=e)
        outcome["state"] = "failed"
        return False
    finally:
        current_task.clear()


def submit_result(fname, task_dir):
    """Archive and upload the result. Every fault is handled here: the task ends 'completed', or failed + cleaned + reported (+ UnsafeWorker when the
    cleanup itself fails). Nothing is silently ignored and no transport exception reaches the poller loop."""
    time.sleep(0.5)
    reason = None
    try:
        shutil.rmtree(task_dir + "/image")
    except FileNotFoundError:
        reason = "task image directory missing before result upload"
    except OSError as e:
        reason = f"cannot remove the task image directory: {e!r}"
    exec_class = None
    if reason is None:
        # CT-04: classify from the files of THIS task (writes trace-meta.json bound to strace.log and execution-class.json into the task directory, so both are
        # inside the ZIP). Never raises; a classifier fault is reported as UNKNOWN_INCOMPLETE, it does not fail the task.
        try:
            exec_class = execution_class.classify_task(task_dir, fname)
        except Exception as e:                                       # noqa: BLE001  (classify_task is written not to raise; this is the belt for the braces)
            logger.exception(f"Task {fname}: execution classification failed")
            exec_class = {"schema": execution_class.EXEC_CLASS_SCHEMA, "task_id": fname, "execution_class": "UNKNOWN_INCOMPLETE",
                          "evidence": [f"classifier error: {e!r}"], "flags": ["CLASSIFIER_ERROR"], "main_pid": None}
        logger.info(f"Task {fname} execution class: {exec_class['execution_class']} flags={exec_class['flags']}")
        try:
            shutil.make_archive(task_dir, 'zip', task_dir)
        except OSError as e:
            reason = f"cannot archive the result: {e!r}"
    if reason is None:
        upload_url = app_settings.sandbox_manager_uri + "/submit-result/" + fname
        try:
            with open(task_dir + ".zip", 'rb') as f:
                ok, detail = _post(upload_url, files={"file": f}, data={"execution_class": json.dumps(exec_class)}, timeout=UPLOAD_TIMEOUT)
        except OSError as e:
            ok, detail = False, f"cannot read the result zip: {e!r}"
        logger.info(f"Upload response: {detail}")
        if not ok:
            reason = f"result upload failed ({detail})"
    if reason is not None:
        logger.warning(f"Task {fname}: {reason}")
        _fail_task(fname, task_dir, reason)
        return "failed"
    errors = remove_task_files(task_dir)
    if errors:
        raise UnsafeWorker(fname, ["result uploaded"] + errors)
    return "completed"


def serve_task(fname, task_dir, worker):
    """One task, analysis then upload. -> 'completed' | 'failed' | 'cancelled'; raises UnsafeWorker (the loop must stop)."""
    outcome = {}
    if run_analysis(fname, task_dir, worker, outcome):
        return submit_result(fname, task_dir)
    return outcome.get("state", "failed")


def poll_once(worker, worker_uri):
    """Ask the manager for one task and serve it. -> outcome string, or None when there was no task. Exits the process with status 3 (no further
    task is fetched) when the worker is unsafe or in an unknown state."""
    get_file_url = app_settings.sandbox_manager_uri + "/get-file/" + app_settings.app_name
    logger.debug(f"GET {get_file_url}")
    resp = requests.get(get_file_url, params={"worker_uri": worker_uri}, timeout=REQUEST_TIMEOUT)

    if resp.status_code != 200:
        logger.debug("No tasks available, retrying in 5s")
        time.sleep(5)
        return None
    fname = re.findall("filename=\"(.+)\"", resp.headers['content-disposition'])[0]
    logger.info(f"Received task: {fname}")

    task_dir = app_settings.data_dir + fname
    os.makedirs(task_dir)
    with open(task_dir + "/" + fname, 'wb') as f:
        f.write(resp.content)

    try:
        outcome = serve_task(fname, task_dir, worker)
        logger.info(f"Task {fname} outcome: {outcome}")
        return outcome
    except UnsafeWorker as e:
        logger.critical(str(e))
        sys.exit(3)           # fail closed: no further task; the restart policy decides whether V0 runs again
    except Exception as e:                                           # noqa: BLE001  (task boundary: unknown state => fail closed, report best effort)
        logger.critical(f"unexpected error while serving task {fname}: {e!r}", exc_info=True)
        remove_task_files(task_dir)
        report_failure(fname, f"worker error: {e!r}")
        sys.exit(3)


if __name__ == '__main__':
    logger.info("Starting worker poller")
    startup_cleanup()

    worker = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    worker["worker_ip"] = s.getsockname()[0]
    s.close()

    time.sleep(5)

    worker_uri = f"http://{worker['worker_ip']}:{app_settings.port}{app_settings.app_base_url}"

    while True:
        poll_once(worker, worker_uri)
