"""SYNTHETIC CT-04 cases (benign, hand-written strace text + trace metadata v2 + expected class). They model what the planned benign ELF fixtures would produce;
they are NOT captures of a real run (real captures: fixtures/real/). usage: make_fixtures.py <out_dir>"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TASK = "task-0001"
TRACE = "trace-0001"
EXEC = '300  10:00:00.000000 execve("./exec", ["./exec"], 0xbe855e94 /* 6 vars */) = 0 <0.001000>\n'


def L(ts, body, pid=300):
    return "%d  10:00:%s %s\n" % (pid, ts, body)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stat_raw(pid=300, state="S", start=12345, comm="exec", ppid=41):
    return "%d (%s) %s %d %d %d 0 -1 4194304 100 0 0 0 1 1 0 0 20 0 1 0 %d 4096 10 4294967295" % (pid, comm, state, ppid, pid, pid, start)


def probe(mono, pid=300, state="S", start=12345, raw=None, comm="exec", strace_pid=41, strace_start=700, ppid=None):
    """A probe record as the collector writes it: the sample's stat line (its parent must be the strace process) plus the strace process identity it was found under."""
    p = {"mono_s": mono, "pid": pid, "starttime_ticks": start, "state": state,
         "raw": raw if raw is not None else stat_raw(pid, state, start, comm, (41 if strace_pid is None else strace_pid) if ppid is None else ppid)}
    if strace_pid is not None:
        p["strace_pid"] = strace_pid
    if strace_start is not None:
        p["strace_starttime_ticks"] = strace_start
    return p


def meta(log=None, **kw):
    m = {"schema": "ct04-trace-meta/2", "task_id": TASK, "trace_id": TRACE, "analysis_duration_s": 30,
         "trace_started_mono_s": 1000.0, "trace_stopped_mono_s": 1030.4, "stop_reason": "window_elapsed",
         "strace_log_sha256": sha(log) if log is not None else None,
         "probes": {"start": probe(1001.0), "final": probe(1029.9)},
         "sample_signal_sent": None, "stop_check": stop_check("gone"), "collected_mono_s": 1031.0}
    m.update(kw)
    return m


def stop_body(kind="gone", pid=41, baseline=700):
    """The text between the BEGIN and END markers of the trace-stop check, as a guest would print it."""
    st = lambda state, start: "%d (strace) %s 1 %d %d 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 1 0 %d 4096 10 4294967295" % (pid, state, pid, pid, start)   # noqa: E731
    pf = "CT04-PIDFILE rc=0 pid=[%d]" % pid
    if kind == "gone":
        return "\n".join([pf, "CT04-STAT rc=1", "CT04-STATRAW []", "CT04-DIR rc=1", "CT04-KILL0 rc=1"]) + "\n"
    if kind == "zombie":
        return "\n".join([pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("Z", baseline), "CT04-DIR rc=0", "CT04-KILL0 rc=0"]) + "\n"
    if kind == "zombie-other-start":
        return "\n".join([pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("Z", baseline + 5), "CT04-DIR rc=0", "CT04-KILL0 rc=0"]) + "\n"
    if kind == "alive":
        return "\n".join([pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("S", baseline), "CT04-DIR rc=0", "CT04-KILL0 rc=0"]) + "\n"
    if kind == "stat-permission-error":      # the reviewer's counterexample: pid file says 123, stat unreadable and empty, the directory is there
        return "\n".join(["CT04-PIDFILE rc=0 pid=[%d]" % pid, "CT04-STAT rc=1", "CT04-STATRAW []", "CT04-DIR rc=0", "CT04-KILL0 rc=0"]) + "\n"
    raise ValueError(kind)


def stop_check(kind="gone", pid=41, baseline=700, **over):
    """A stop_check record consistent with its own raw answer (built by the classifier's parser)."""
    import execution_class as C
    body = stop_body(kind, pid, baseline)
    r = C.parse_stop_envelope(body, pid, baseline)
    rec = {"mono_s": 1030.6, "verdict": r["verdict"], "reason": r["reason"], "raw": body, "rcs": r["rcs"], "target_pid": r["target_pid"],
           "expected_pid": pid, "baseline_starttime": baseline}
    rec.update(over)
    return rec


def signal_record(**kw):
    s = {"signal": "SIGKILL", "target_pid": 300, "mono_s": 1030.1, "result": "sent", "trace_id": TRACE}
    s.update(kw)
    return s


SLEEP = L("00.020000", "nanosleep({tv_sec=3600, tv_nsec=0},  <unfinished ...>")
CASES = {}


def _add(name, log, m, want):
    CASES[name] = (log, m, want)


_add("exit0", EXEC + L("00.010000", "exit_group(0)   = ?") + L("00.011000", "+++ exited with 0 +++"), None, "EXITED_0")
_add("exit7", EXEC + L("00.010000", "exit_group(7)   = ?") + L("00.011000", "+++ exited with 7 +++"), None, "EXITED_NONZERO")
_add("run-to-window-end", EXEC + SLEEP, "meta", "SAMPLE_TIMEOUT")
_add("run-to-window-end-no-meta", EXEC + SLEEP, None, "UNKNOWN_INCOMPLETE")
_add("exec-enoexec", '300  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = -1 ENOEXEC (Exec format error) <0.000500>\n', None, "EXEC_FORMAT_ERROR")
_add("exec-enoent-interp", '300  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = -1 ENOENT (No such file or directory) <0.000500>\n', None, "EXEC_NOT_FOUND")
_add("log-garbage", "strace: ./exec: No such file or directory\n", None, "LOG_INVALID")
_add("log-empty", "", None, "LOG_MISSING")


def main(out):
    os.makedirs(out, exist_ok=True)
    idx = {}
    for name, (log, m, want) in CASES.items():
        mm = meta(log) if m == "meta" else m
        open(os.path.join(out, name + ".strace.log"), "w").write(log)
        open(os.path.join(out, name + ".meta.json"), "w").write(json.dumps(mm, indent=1) if mm is not None else "null")
        idx[name] = want
    open(os.path.join(out, "cases.json"), "w").write(json.dumps({"synthetic": True, "task_id": TASK, "expected": idx}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
