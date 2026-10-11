import os
import sys

import pytest

WORKER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKER_DIR)

# Settings required by config.settings (no .env is read in tests).
os.environ.setdefault("PORT", "8011")
os.environ.setdefault("APP_BASE_URL", "/api/v1/sandbox-worker")
os.environ.setdefault("SANDBOX_MANAGER_URI", "http://manager.invalid/api/v1/sandbox-manager")
os.environ.setdefault("ANALYSIS_DURATION", "0")
os.environ.setdefault("POST_ANALYSIS_WAIT", "0")

BASE = "/api/v1/sandbox-worker"


@pytest.fixture
def current_task_file(tmp_path, monkeypatch):
    from isolation import constants
    path = str(tmp_path / "run" / "sandbox" / "current_task")
    monkeypatch.setattr(constants, "CURRENT_TASK_FILE", path)
    return path


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    from config.settings import app_settings
    d = str(tmp_path / "data") + "/"
    os.makedirs(d)
    monkeypatch.setattr(app_settings, "data_dir", d)
    return d
