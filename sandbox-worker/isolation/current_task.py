"""Shared "current task" marker between poller.py and server.py.

The guest API allowlist (isolation/apifilter.py) only admits routes for the
task id stored here. The poller writes it atomically before phase 1 and removes
it on every exit path; a stale file is removed at poller startup.
"""
import os
import re
import tempfile
from typing import Optional

from isolation import constants as C

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def valid_task_id(task_id: str) -> bool:
    return bool(_TASK_ID_RE.match(task_id)) and task_id not in (".", "..")


def set_current(task_id: str, path: Optional[str] = None) -> None:
    path = path or C.CURRENT_TASK_FILE
    if not valid_task_id(task_id):
        raise ValueError(f"invalid task id: {task_id!r}")
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".current_task.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(task_id)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def clear(path: Optional[str] = None) -> None:
    try:
        os.unlink(path or C.CURRENT_TASK_FILE)
    except FileNotFoundError:
        pass


def get_current(path: Optional[str] = None) -> Optional[str]:
    try:
        with open(path or C.CURRENT_TASK_FILE) as f:
            task_id = f.read().strip()
    except FileNotFoundError:
        return None
    return task_id if valid_task_id(task_id) else None
