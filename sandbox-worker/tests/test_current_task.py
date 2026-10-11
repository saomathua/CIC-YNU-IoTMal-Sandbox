"""current_task marker: atomic write and cleanup on every poller exit path."""
import os

import pytest

from isolation import current_task

T = "11111111-2222-3333-4444-555555555555"


def test_set_get_clear(current_task_file):
    assert current_task.get_current() is None
    current_task.set_current(T)
    assert open(current_task_file).read() == T
    assert current_task.get_current() == T
    current_task.clear()
    current_task.clear()  # idempotent
    assert not os.path.exists(current_task_file)


def test_atomic_replace_never_exposes_partial_content(current_task_file, monkeypatch):
    current_task.set_current("old-task")
    seen = {}
    real_replace = os.replace

    def spy(src, dst):
        seen["tmp_content"] = open(src).read()
        seen["dst_before"] = open(dst).read()
        seen["same_dir"] = os.path.dirname(src) == os.path.dirname(dst)
        return real_replace(src, dst)
    monkeypatch.setattr(current_task.os, "replace", spy)
    current_task.set_current(T)
    assert seen == {"tmp_content": T, "dst_before": "old-task", "same_dir": True}


def test_failed_write_leaves_previous_value_and_no_temp_files(current_task_file, monkeypatch):
    current_task.set_current("old-task")

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(current_task.os, "replace", boom)
    with pytest.raises(OSError):
        current_task.set_current(T)
    d = os.path.dirname(current_task_file)
    assert os.listdir(d) == ["current_task"]
    assert current_task.get_current() == "old-task"


@pytest.mark.parametrize("bad", ["", "../x", "a/b", ".", "..", "x" * 200, "a b"])
def test_invalid_task_ids_rejected(current_task_file, bad):
    with pytest.raises(ValueError):
        current_task.set_current(bad)
    assert not os.path.exists(current_task_file)


# ------------------------------------------------------------------ poller integration

@pytest.fixture
def poller(current_task_file, data_dir, monkeypatch):
    import poller as p
    posts = []
    monkeypatch.setattr(p.requests, "post", lambda url, **kw: posts.append((url, kw)))
    p._posts = posts
    return p


def _task_dir(data_dir):
    d = data_dir + T
    os.makedirs(d)
    return d


def test_poller_marker_present_during_analysis_and_cleared_on_success(poller, data_dir, current_task_file, monkeypatch):
    seen = []
    monkeypatch.setattr(poller, "dynamic_analysis", lambda *a, **kw: seen.append(current_task.get_current()))
    assert poller.run_analysis(T, _task_dir(data_dir), {}) is True
    assert seen == [T]
    assert not os.path.exists(current_task_file)


def test_poller_marker_cleared_on_failure(poller, data_dir, current_task_file, monkeypatch):
    def fail(*a, **kw):
        assert current_task.get_current() == T
        raise RuntimeError("network isolation check failed (V1 before phase 1): x")
    monkeypatch.setattr(poller, "dynamic_analysis", fail)
    assert poller.run_analysis(T, _task_dir(data_dir), {}) is False
    assert not os.path.exists(current_task_file)
    assert poller._posts and poller._posts[0][0].endswith("/submit-failure/" + T)
    assert "isolation check failed" in poller._posts[0][1]["params"]["reason"]


def test_poller_marker_cleared_on_cancel(poller, data_dir, current_task_file, monkeypatch):
    def cancel(*a, **kw):
        raise poller.AnalysisCancelled("Stop requested by user")
    monkeypatch.setattr(poller, "dynamic_analysis", cancel)
    assert poller.run_analysis(T, _task_dir(data_dir), {}) is False
    assert not os.path.exists(current_task_file)


def test_poller_marker_cleared_on_base_exception(poller, data_dir, current_task_file, monkeypatch):
    def interrupted(*a, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(poller, "dynamic_analysis", interrupted)
    with pytest.raises(KeyboardInterrupt):
        poller.run_analysis(T, _task_dir(data_dir), {})
    assert not os.path.exists(current_task_file)


def test_poller_invalid_task_id_reports_failure_without_marker(poller, data_dir, current_task_file, monkeypatch):
    called = []
    monkeypatch.setattr(poller, "dynamic_analysis", lambda *a, **kw: called.append(1))
    os.makedirs(data_dir + "bad id")
    assert poller.run_analysis("bad id", data_dir + "bad id", {}) is False
    assert called == [] and not os.path.exists(current_task_file)
    assert poller._posts


def test_startup_cleanup_removes_stale_marker(poller, current_task_file):
    current_task.set_current("stale-task")
    poller.startup_cleanup()
    assert not os.path.exists(current_task_file)
