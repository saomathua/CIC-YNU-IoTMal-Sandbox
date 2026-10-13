"""CT-04 R3 offline checks. usage: python3 -I -B tests/check_classify.py (exit 0 = all OK). Mutation run: tests/run_mutants.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SERVICE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(ROOT))), "service")      # sandbox-worker/service
sys.path.insert(0, SERVICE)
sys.path.insert(0, ROOT)                      # a mutant copy placed next to the tests wins over the product module
import execution_class as C                  # noqa: E402
import make_fixtures as F                        # noqa: E402

FAILS = []
N = [0]


def check(name, got, klass, flags=(), no_flags=()):
    N[0] += 1
    ok = got["klass"] == klass and all(f in got["flags"] for f in flags) and not any(f in got["flags"] for f in no_flags)
    print(("[OK]   " if ok else "[FAIL] ") + name + "  -> " + got["klass"] + " " + str(got["flags"]) + ("" if ok else "   WANT " + klass))
    if not ok:
        FAILS.append(name)


def run(log, meta=None, task=F.TASK, bind=True, **kw):
    return C.classify(log, meta, task_id=task, log_sha256=F.sha(log) if (bind and log is not None) else None, **kw)


EX, L = F.EXEC, F.L
SLEEP = F.SLEEP
EXIT0 = L("00.030000", "exit_group(0)   = ?") + L("00.031000", "+++ exited with 0 +++")
M = lambda log, **kw: F.meta(log, **kw)                                           # noqa: E731
P = F.probe


def real(n):
    return open(os.path.join(ROOT, "fixtures", "real", n + ".strace.log"), encoding="utf-8").read()


def mod_probe(log, which, **kw):
    m = M(log)
    m["probes"][which] = dict(m["probes"][which], **kw)
    return m


# ---- real captures (historical fixtures untouched) ----
check("R1 real ARM busybox flow fixture: exit 127", run(real("flow-success-arm-busybox")), "EXITED_NONZERO", no_flags=["LOADER_ERROR_REPORTED"])
check("R2 real MIPS busybox flow fixture", run(real("flow-success-mips-busybox")), "EXITED_NONZERO")
check("R3 real ARM ct02 marker ELF", run(real("ct02-arm-a")), "EXITED_0")
check("R4 real MIPS ct02 marker ELF", run(real("ct02-mips-b")), "EXITED_0")
check("R5 real busybox log has optional lookups and exit 127: not a library verdict", run(real("flow-success-arm-busybox")), "EXITED_NONZERO")

# ---- synthetic benign set ----
for name, (log, m, want) in F.CASES.items():
    mm = M(log) if m == "meta" else m
    check("S " + name, run(log, mm), want)

# ---- reviewer counterexamples round 1 (kept) ----
check("X1 exit_group(0)garbage", run(EX + L("00.030000", "exit_group(0)garbage")), "LOG_INVALID")
check("X2 exit line before the exec", run(L("00.000000", "+++ exited with 0 +++") + EX), "LOG_INVALID")
check("X3 exit_group before the exec", run(L("00.000000", "exit_group(0)   = ?") + EX), "LOG_INVALID")
check("X4 only the exec, no trace end: UNKNOWN", run(EX), "UNKNOWN_INCOMPLETE")
check("X5 exec only + meta without probes: UNKNOWN", run(EX, M(EX, probes=None)), "UNKNOWN_INCOMPLETE")
check("X6 unparseable middle line never skipped", run(EX + "????\n" + EXIT0), "LOG_INVALID")
check("X7 partially garbled complete line", run(EX + L("00.010000", 'open("/x", O_RDONLY) = 3 <0.0') + EXIT0), "LOG_INVALID")
check("X8 timestamps going backwards", run(EX + L("00.030000", "getpid()          = 300 <0.000100>") + L("00.020000", "getpid()          = 300 <0.000100>") + EXIT0), "LOG_INVALID")
check("X9 events of main pid after exit", run(EX + EXIT0 + L("00.040000", "getpid()          = 300 <0.000100>")), "LOG_INVALID")
check("X16 trailing garbage after the return value", run(EX + L("00.030000", "exit_group(0)   = ?garbage")), "LOG_INVALID")
check("X10 exit_group(1) then exited with 0", run(EX + L("00.030000", "exit_group(1)   = ?") + L("00.031000", "+++ exited with 0 +++")), "LOG_INVALID")
check("X11 resumed without unfinished", run(EX + L("00.010000", '<... read resumed> "", 4) = 0 <0.1>')), "LOG_INVALID")
check("X12 nested unfinished", run(EX + L("00.010000", "read(0,  <unfinished ...>") + L("00.011000", 'write(1, "a", 1 <unfinished ...>')), "LOG_INVALID")
check("X13 NUL byte", run(EX + "\x00" + EXIT0), "LOG_INVALID")
check("X14 impossible timestamp", run('300  25:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 1 var */) = 0 <0.1>\n'), "LOG_INVALID")
check("X15 event after bare '+++ exited'", run(EX + L("00.030000", "+++ exited with 0 +++") + L("00.040000", "getpid()          = 300 <0.000100>")), "LOG_INVALID")

# ---- round 2 item 3: unterminated final line is never evidence ----
OPEN_EXIT = L("01.000000", "exit_group(0)   = ?")[:-1]
check("N1 exec + unterminated 'exit_group(0) = ?' is NOT an exit", run(EX + OPEN_EXIT), "UNKNOWN_INCOMPLETE", ["TRUNCATED_TAIL"])
check("N2 same with a perfect timeout meta: still UNKNOWN (the dropped line may be the exit)", run(EX + OPEN_EXIT, M(EX + OPEN_EXIT)), "UNKNOWN_INCOMPLETE", ["TRUNCATED_TAIL"])
check("N3 unterminated '+++ exited with 0 +++' is not an exit", run(EX + L("01.000000", "+++ exited with 0 +++")[:-1]), "UNKNOWN_INCOMPLETE")
check("N4 unterminated '+++ killed by SIGSEGV +++' is not a verdict", run(EX + L("01.000000", "+++ killed by SIGSEGV +++")[:-1]), "UNKNOWN_INCOMPLETE")
check("N5 complete exit_group line followed by an unterminated remainder keeps the flag", run(EX + L("00.010000", "exit_group(0)   = ?") + "300  10:00:00.011000 +++ exited wi"), "EXITED_0", ["TRUNCATED_TAIL", "EXIT_LINE_ONLY"])
check("N6 unterminated partial write line without exit", run(EX + L("00.020000", 'write(1, "x", 1) = 1 <0.0')[:-1], M(EX + L("00.020000", 'write(1, "x", 1) = 1 <0.0')[:-1])), "UNKNOWN_INCOMPLETE", ["TRUNCATED_TAIL"])

# ---- R6 (A3-ARM finding): a tracee blocked in a syscall leaves an unterminated syscall ENTRY as the last line when strace is killed ----
OPEN_SLEEP = L("00.020000", "nanosleep({tv_sec=3600, tv_nsec=0}, ")[:-1]
check("O1 exec + open nanosleep entry + full timeout proof => SAMPLE_TIMEOUT (tail is flagged, not evidence)", run(EX + OPEN_SLEEP, M(EX + OPEN_SLEEP)), "SAMPLE_TIMEOUT", ["TRUNCATED_TAIL", "TAIL_OPEN_SYSCALL"])
check("O2 same without metadata: still UNKNOWN (the tail alone proves nothing)", run(EX + OPEN_SLEEP), "UNKNOWN_INCOMPLETE", ["TRUNCATED_TAIL", "TAIL_OPEN_SYSCALL"])
check("O3 same with stop_reason error (window not elapsed cleanly): UNKNOWN", run(EX + OPEN_SLEEP, M(EX + OPEN_SLEEP, stop_reason="error")), "UNKNOWN_INCOMPLETE")
check("O4 open exit_group entry is not an open call (may be the exit)", run(EX + L("00.020000", "exit_group(0")[:-1], M(EX + L("00.020000", "exit_group(0")[:-1])), "UNKNOWN_INCOMPLETE", ["TRUNCATED_TAIL"])
check("O5 open exit entry", run(EX + L("00.020000", "exit(0")[:-1], M(EX + L("00.020000", "exit(0")[:-1])), "UNKNOWN_INCOMPLETE")
check("O6 only a timestamp prefix (cannot be told from an exit line)", run(EX + "300  10:00:00.020000 ", M(EX + "300  10:00:00.020000 ")), "UNKNOWN_INCOMPLETE")
check("O7 a prefix of '+++ exited' is not an open call", run(EX + "300  10:00:00.020000 +++ exi", M(EX + "300  10:00:00.020000 +++ exi")), "UNKNOWN_INCOMPLETE")
O8LOG = EX + L("00.030000", "getpid()          = 300 <0.000100>") + L("00.010000", "nanosleep({tv_sec=3600, tv_nsec=0}, ")[:-1]
check("O8 open entry whose time is BEFORE the last complete line (with a perfect proof)", run(O8LOG, M(O8LOG)), "UNKNOWN_INCOMPLETE")
check("O9 finished call cut inside its duration is not an open call", run(EX + L("00.020000", "nanosleep({tv_sec=1, tv_nsec=0}, NULL) = 0 <1.00")[:-1], M(EX + L("00.020000", "nanosleep({tv_sec=1, tv_nsec=0}, NULL) = 0 <1.00")[:-1])), "UNKNOWN_INCOMPLETE")
check("O10 open entry + dead sample at the final probe (contradiction stays)", run(EX + OPEN_SLEEP, M(EX + OPEN_SLEEP, probes={"start": F.probe(1001.0), "final": F.probe(1029.9, state="Z")})), "UNKNOWN_INCOMPLETE")
check("O11 open entry + hash mismatch is a contradiction", run(EX + OPEN_SLEEP, M(EX)), "INCONSISTENT_EVIDENCE")
check("O12 open entry for a call that carries a fake exit text inside a string is not an exit", run(EX + L("00.020000", 'write(1, "+++ exited with 0 +++')[:-1], M(EX + L("00.020000", 'write(1, "+++ exited with 0 +++')[:-1])), "UNKNOWN_INCOMPLETE")

# ---- exec across unfinished/resumed ----
EXU = L("00.000000", 'execve("./exec", ["./exec"], 0x1 /* 6 vars */ <unfinished ...>') + L("00.001000", "<... execve resumed>) = 0 <0.001000>")
check("U1 exec succeeded via unfinished/resumed", run(EXU + EXIT0), "EXITED_0")
check("U2 exec unfinished and never resumed", run(L("00.000000", 'execve("./exec", ["./exec"], 0x1 /* 6 vars */ <unfinished ...>')), "UNKNOWN_INCOMPLETE")
check("U3 exec failed via resumed", run(L("00.000000", 'execve("./exec", ["./exec"], 0x1 /* 6 vars */ <unfinished ...>') + L("00.001000", "<... execve resumed>) = -1 ENOEXEC (Exec format error) <0.0001>")), "EXEC_FORMAT_ERROR")

# ---- timeout needs bound proof (item 1) ----
LOG = EX + SLEEP
check("T1 proven timeout (bound task/log, start+final probe, same start time, raw agrees)", run(LOG, M(LOG)), "SAMPLE_TIMEOUT")
check("T2 no meta", run(LOG), "UNKNOWN_INCOMPLETE")
check("T3 stop_reason not window_elapsed", run(LOG, M(LOG, stop_reason="error")), "UNKNOWN_INCOMPLETE")
check("T4 traced less than the window", run(LOG, M(LOG, trace_stopped_mono_s=1010.0, probes={"start": P(1001.0), "final": P(1009.0)})), "UNKNOWN_INCOMPLETE")
m = M(LOG)
m["probes"]["final"] = None
check("T5b final probe null", run(LOG, m), "UNKNOWN_INCOMPLETE")
check("T6 no start probe: PID reuse cannot be excluded", run(LOG, dict(M(LOG), probes={"start": None, "final": P(1029.9)})), "UNKNOWN_INCOMPLETE")
check("T7 final probe is for another pid", run(LOG, dict(M(LOG), probes={"start": P(1001.0, pid=301), "final": P(1029.9, pid=301)})), "INCONSISTENT_EVIDENCE")
check("T8 final probe says zombie", run(LOG, mod_probe(LOG, "final", state="Z", raw=F.stat_raw(300, "Z", 12345))), "UNKNOWN_INCOMPLETE")
check("T9 final probe too old (taken 20 s before the stop)", run(LOG, mod_probe(LOG, "final", mono_s=1010.0)), "UNKNOWN_INCOMPLETE")
check("T10 final probe time after the stop", run(LOG, mod_probe(LOG, "final", mono_s=1031.0)), "UNKNOWN_INCOMPLETE")
check("T11 start probe taken long after the start", run(LOG, mod_probe(LOG, "start", mono_s=1020.0)), "UNKNOWN_INCOMPLETE")
check("T12 PID reused: start time differs between probes", run(LOG, dict(M(LOG), probes={"start": P(1001.0, start=12345), "final": P(1029.9, start=99999)})), "INCONSISTENT_EVIDENCE")
check("T13 REVIEWER: raw '999 (other) Z' while fields say pid=300 state=S", run(LOG, mod_probe(LOG, "final", raw="999 (other) Z 1 999 999 0 -1 4194304 100 0 0 0 1 1 0 0 20 0 1 0 12345 4096 10 4294967295")), "INCONSISTENT_EVIDENCE")
check("T14 raw says state Z, fields say S", run(LOG, mod_probe(LOG, "final", raw=F.stat_raw(300, "Z", 12345))), "INCONSISTENT_EVIDENCE")
check("T15 raw start time differs from the declared start time", run(LOG, mod_probe(LOG, "final", raw=F.stat_raw(300, "S", 555))), "INCONSISTENT_EVIDENCE")
check("T16 raw is not a /proc stat line", run(LOG, mod_probe(LOG, "final", raw="garbage")), "UNKNOWN_INCOMPLETE")
check("T17 meta belongs to another task", run(LOG, M(LOG, task_id="task-9999")), "INCONSISTENT_EVIDENCE")
check("T18 meta bound to a different log (hash)", run(LOG, M(LOG + "x")), "INCONSISTENT_EVIDENCE")
check("T18b hash mismatch is a contradiction even when the log has no exit and a cut tail", run(EX + OPEN_EXIT, M(EX)), "INCONSISTENT_EVIDENCE")
check("T18c task mismatch is a contradiction even for a log that exited", run(EX + EXIT0, M(EX + EXIT0, task_id="task-9999")), "INCONSISTENT_EVIDENCE")
check("T19 meta without log binding", run(LOG, M(None)), "UNKNOWN_INCOMPLETE")
check("T20 caller supplies no expected task id", run(LOG, M(LOG), task=None), "UNKNOWN_INCOMPLETE")
check("T21 wrong schema (v1)", run(LOG, dict(M(LOG), schema="ct04-trace-meta/1")), "UNKNOWN_INCOMPLETE", ["META_INVALID"])
check("T22 NaN stop time", run(LOG, M(LOG, trace_stopped_mono_s=float("nan"))), "UNKNOWN_INCOMPLETE")
check("T23 bool pid in probe", run(LOG, mod_probe(LOG, "final", pid=True)), "UNKNOWN_INCOMPLETE")
check("T24 child exits but main alive: proven timeout of the main pid", run(EX + L("00.020000", "+++ exited with 0 +++", pid=301) + SLEEP, M(EX + L("00.020000", "+++ exited with 0 +++", pid=301) + SLEEP)), "SAMPLE_TIMEOUT", ["CHILDREN_SEEN"])
check("T25 text 'exited with 0' printed by the sample is not an exit", run(EX + L("00.020000", 'write(1, "+++ exited with 0 +++", 21) = 21 <0.0001>') + SLEEP, M(EX + L("00.020000", 'write(1, "+++ exited with 0 +++", 21) = 21 <0.0001>') + SLEEP)), "SAMPLE_TIMEOUT")
check("T26 bare exit(0) (thread exit) is not process exit", run(EX + L("00.020000", "exit(0)           = ?"), M(EX + L("00.020000", "exit(0)           = ?"))), "SAMPLE_TIMEOUT")
check("T27 infra timeout never becomes a sample verdict", run(LOG, M(LOG), failure_reason="QEMU timed out waiting for boot prompt"), "INFRA_TIMEOUT")
check("T28 final probe earlier than the start probe", run(LOG, dict(M(LOG), probes={"start": P(1025.0), "final": P(1024.0)})), "UNKNOWN_INCOMPLETE")

# ---- loader messages are the sample's claim (item 4) ----
LIBENOENT = L("00.010000", 'open("/lib/libfoo.so.1", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.002>')
MSG = L("00.015000", 'write(2</dev/ttyS0<char 4:64>>, "Error loading shared library libfoo.so.1: No such file or directory (needed by ./exec)\\n", 87) = 87 <0.001>')
X127 = L("00.020000", "exit_group(127)   = ?") + L("00.021000", "+++ exited with 127 +++")
check("M1 lookup ENOENT + exit 127 alone: only an observation", run(EX + LIBENOENT + X127), "EXITED_NONZERO", ["LIB_LOOKUP_ENOENT_SEEN"], ["LOADER_ERROR_REPORTED"])
check("M2 REVIEWER: loader-style message + failed lookup is REPORTED, not certified", run(EX + LIBENOENT + MSG + X127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED", "LIB_LOOKUP_FAILED_SAME_NAME"])
check("M3 message only (a sample printing the text)", run(EX + MSG + X127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"], ["LIB_LOOKUP_FAILED_SAME_NAME"])
check("M4 same message but exit 0 is a plain exit", run(EX + MSG + EXIT0), "EXITED_0")
check("M5 ENOEXEC is EXEC_FORMAT_ERROR", run(F.CASES["exec-enoexec"][0]), "EXEC_FORMAT_ERROR")
check("M6 EACCES", run('300  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = -1 EACCES (Permission denied) <0.0001>\n'), "EXEC_PERMISSION_DENIED")
check("M7 other exec errno", run('300  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = -1 E2BIG (Argument list too long) <0.0001>\n'), "EXEC_FAILED")
N[0] += 1
ok = not any(C.classify(EX + LIBENOENT + MSG + X127, None, task_id=F.TASK)["klass"] == "MISSING_LIBRARY" for _ in (0,))
print(("[OK]   " if ok else "[FAIL] ") + "M8 MISSING_LIBRARY is reserved and never emitted")
if not ok:
    FAILS.append("M8")

# ---- signals (item 2) ----
SEGV_K = L("00.020000", "--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x0} ---")
SEGV_U = L("00.020000", "--- SIGSEGV {si_signo=SIGSEGV, si_code=SI_USER, si_pid=55, si_uid=0} ---")
K_SEGV = L("00.021000", "+++ killed by SIGSEGV (core dumped) +++")
K_KILL = L("00.020000", "+++ killed by SIGKILL +++")
SIGLOG = EX + K_KILL
check("G1 kernel SIGSEGV with a kernel si_code = CRASHED", run(EX + SEGV_K + K_SEGV), "CRASHED", ["SIGNAL_DELIVERY_SEEN"])
check("G2 REVIEWER: SIGSEGV with no delivery line is NOT a crash", run(EX + K_SEGV), "KILLED_BY_SIGNAL", ["DELIVERY_LINE_ABSENT", "SIGNAL_SOURCE_UNVERIFIED"])
check("G3 SIGSEGV sent by a process (SI_USER)", run(EX + SEGV_U + K_SEGV), "KILLED_BY_SIGNAL")
check("G4 SIGKILL, no sandbox record", run(SIGLOG), "KILLED_BY_SIGNAL")
GOOD = lambda **k: M(SIGLOG, sample_signal_sent=F.signal_record(**k))                  # noqa: E731
check("G5 SIGKILL recorded by the worker, bound, valid = STOPPED_BY_SANDBOX", run(SIGLOG, GOOD()), "STOPPED_BY_SANDBOX")
bad_meta = GOOD()
del bad_meta["schema"]
check("G6 REVIEWER: record present but metadata lacks schema", run(SIGLOG, bad_meta), "KILLED_BY_SIGNAL", ["META_INVALID"])
check("G7 REVIEWER: mono_s = NaN", run(SIGLOG, GOOD(mono_s=float("nan"))), "KILLED_BY_SIGNAL", ["META_INVALID"])
check("G8 record targets another pid", run(SIGLOG, GOOD(target_pid=301)), "KILLED_BY_SIGNAL", ["SANDBOX_SIGNAL_RECORD_NOT_APPLICABLE"])
check("G9 record result failed", run(SIGLOG, GOOD(result="failed")), "KILLED_BY_SIGNAL")
check("G10 record from another trace", run(SIGLOG, GOOD(trace_id="trace-other")), "KILLED_BY_SIGNAL", ["META_INVALID"])
check("G11 record time outside the trace window", run(SIGLOG, GOOD(mono_s=900.0)), "KILLED_BY_SIGNAL", ["META_INVALID"])
check("G12 record missing target_pid", run(SIGLOG, M(SIGLOG, sample_signal_sent={"signal": "SIGKILL", "mono_s": 1030.1, "result": "sent", "trace_id": F.TRACE})), "KILLED_BY_SIGNAL", ["META_INVALID"])
check("G13 record for another task: contradiction, not an attribution", run(SIGLOG, dict(GOOD(), task_id="task-9999")), "INCONSISTENT_EVIDENCE")
check("G14 worker signal differs from the observed one", run(SIGLOG, GOOD(signal="SIGTERM")), "KILLED_BY_SIGNAL")
check("G15 worker recorded SIGTERM but the sample died of a kernel SIGSEGV: CRASHED", run(EX + SEGV_K + K_SEGV, M(EX + SEGV_K + K_SEGV, sample_signal_sent=F.signal_record(signal="SIGTERM"))), "CRASHED")
check("G16 expected task id not supplied: sandbox attribution refused", run(SIGLOG, GOOD(), task=None), "KILLED_BY_SIGNAL")
check("G17 raise()/abort(): SIGABRT sent by itself (SI_TKILL, si_pid == main)", run(EX + L("00.020000", "--- SIGABRT {si_signo=SIGABRT, si_code=SI_TKILL, si_pid=300, si_uid=0} ---") + L("00.021000", "+++ killed by SIGABRT +++")), "KILLED_BY_SIGNAL", ["SELF_SENT"])


# ---- R4: the trace-stop envelope (never "empty output = gone") ----
SB = F.stop_body
SC = F.stop_check
env = lambda kind="gone", exp=41, base=700: C.parse_stop_envelope(SB(kind, 41, 700), exp, base)           # noqa: E731
def chk(name, cond):
    N[0] += 1
    print(("[OK]   " if cond else "[FAIL] ") + name)
    if not cond:
        FAILS.append(name)


chk("E1 gone needs positive evidence: pid file ok + stat rc1/empty + no dir + kill -0 rc1", env("gone")["verdict"] == "gone")
_e2 = C.parse_stop_envelope(SB("stat-permission-error", 123, 700), 123, 700)
chk("E2 REVIEWER: pid file 123, stat unreadable+empty, directory still there, final echo rc0 => NOT gone, reported as a read error", _e2["verdict"] == "unknown" and "read error" in _e2["reason"] and _e2["rcs"]["dir"] == 0)
chk("E3 an empty answer is unknown, not gone", C.parse_stop_envelope("", 41, 700)["verdict"] == "unknown")
chk("E4 only the markers' content missing (blank lines) is unknown", C.parse_stop_envelope("\n\n", 41, 700)["verdict"] == "unknown")
chk("E5 pid file read failed (rc 1) although its text looks valid => unknown", C.parse_stop_envelope("CT04-PIDFILE rc=1 pid=[41]\nCT04-STAT rc=1\nCT04-STATRAW []\nCT04-DIR rc=1\nCT04-KILL0 rc=1\n", None, None)["verdict"] == "unknown")
chk("E6 pid file empty with rc 0 is unknown", C.parse_stop_envelope("CT04-PIDFILE rc=0 pid=[]\nCT04-TARGET invalid\n", None, None)["verdict"] == "unknown")
chk("E7 pid file with several tokens / injection text is unknown", C.parse_stop_envelope("CT04-PIDFILE rc=0 pid=[12 34]\n", None, None)["verdict"] == "unknown")
chk("E8 pid file names another pid than the traced strace => unknown", C.parse_stop_envelope(SB("gone", 99, 700), 41, 700)["verdict"] == "unknown")
chk("E9 stat rc 127 (tool missing) is unknown even if everything else says absent", C.parse_stop_envelope(SB("gone").replace("CT04-STAT rc=1", "CT04-STAT rc=127"), 41, 700)["verdict"] == "unknown")
chk("E10 directory test tool error (rc 2) is unknown", C.parse_stop_envelope(SB("gone").replace("CT04-DIR rc=1", "CT04-DIR rc=2"), 41, 700)["verdict"] == "unknown")
_e11 = C.parse_stop_envelope(SB("gone").replace("CT04-KILL0 rc=1", "CT04-KILL0 rc=0"), 41, 700)
chk("E11 kill -0 succeeds although stat/dir say absent => unknown, and says so", _e11["verdict"] == "unknown" and "kill -0 says" in _e11["reason"])
chk("E12 truncated answer (kill0 line missing) is unknown", C.parse_stop_envelope("\n".join(SB("gone").split("\n")[:-2]), 41, 700)["verdict"] == "unknown")
chk("E13 repeated line is unknown", C.parse_stop_envelope(SB("gone") + "CT04-DIR rc=1\n", 41, 700)["verdict"] == "unknown")
chk("E14 stat succeeded with empty output is unknown", C.parse_stop_envelope(SB("gone").replace("CT04-STAT rc=1", "CT04-STAT rc=0"), 41, 700)["verdict"] == "unknown")
chk("E15 stat failed but printed text is unknown", C.parse_stop_envelope(SB("gone").replace("STATRAW []", "STATRAW [x]"), 41, 700)["verdict"] == "unknown")
chk("E16 alive process (state S) is alive", env("alive")["verdict"] == "alive")
chk("E17 valid zombie: same pid and start time as the baseline", env("zombie")["verdict"] == "zombie")
chk("E18 zombie with another start time (pid reused) is NOT accepted", env("zombie-other-start")["verdict"] == "unknown")
_e19 = C.parse_stop_envelope(SB("zombie"), 41, None)
chk("E19 zombie without a baseline is NOT accepted, for that reason", _e19["verdict"] == "unknown" and "baseline" in _e19["reason"])
chk("E20 stat line of another pid is unknown", C.parse_stop_envelope(SB("zombie").replace("41 (strace) Z", "42 (strace) Z"), 41, 700)["verdict"] == "unknown")
chk("E21 non-text input never raises", all(C.parse_stop_envelope(v, 1, 1)["verdict"] == "unknown" for v in (None, 5, [], {}, b"x")))
chk("E22 rcs are reported from the answer (kept for the reviewer)", env("gone")["rcs"] == {"pidfile": 0, "stat": 1, "dir": 1, "kill0": 1} and env("gone")["target_pid"] == 41)

LG2 = EX + SLEEP
check("E30 control: proven timeout with a gone stop_check", run(LG2, M(LG2)), "SAMPLE_TIMEOUT")
check("E31 valid zombie stop_check also proves the stop", run(LG2, M(LG2, stop_check=SC("zombie"))), "SAMPLE_TIMEOUT")
check("E32 no stop_check at all: not confirmed => UNKNOWN", run(LG2, M(LG2, stop_check=None)), "UNKNOWN_INCOMPLETE")
check("E33 stop_check verdict alive => UNKNOWN", run(LG2, M(LG2, stop_check=SC("alive"))), "UNKNOWN_INCOMPLETE")
check("E34 stop_check verdict unknown (permission-error answer, honest) => UNKNOWN", run(LG2, M(LG2, stop_check=SC("stat-permission-error"))), "UNKNOWN_INCOMPLETE")
fake = SC("stat-permission-error", verdict="gone")
check("E35 REVIEWER: stored verdict 'gone' but the raw answer is the permission-error case => INCONSISTENT_EVIDENCE", run(LG2, M(LG2, stop_check=fake)), "INCONSISTENT_EVIDENCE")
check("E36 honest verdict but stored rcs differ from the raw answer => INCONSISTENT_EVIDENCE", run(LG2, M(LG2, stop_check=SC("gone", rcs={"pidfile": 0, "stat": 1, "dir": 1, "kill0": 0}))), "INCONSISTENT_EVIDENCE")
check("E37 stored verdict zombie with a baseline that does not match the raw => INCONSISTENT_EVIDENCE", run(LG2, M(LG2, stop_check=SC("zombie", baseline_starttime=1))), "INCONSISTENT_EVIDENCE")
check("E38 malformed stop_check (rcs missing a key) => meta invalid => UNKNOWN", run(LG2, M(LG2, stop_check=dict(SC("gone"), rcs={"pidfile": 0}))), "UNKNOWN_INCOMPLETE", ["META_INVALID"])
check("E39 oversize raw in stop_check => meta invalid", run(LG2, M(LG2, stop_check=dict(SC("gone"), raw="x" * 2500))), "UNKNOWN_INCOMPLETE", ["META_INVALID"])


# ---- R5: binding between the probes, the stop check and the measured strace; time order of the stop check ----
def bm(**over):
    m = M(LG2)
    for k, v in over.items():
        if k in ("start", "final"):
            m["probes"][k] = v
        else:
            m[k] = v
    return m


check("B0 control: probes, stop check and strace identity all bound => SAMPLE_TIMEOUT", run(LG2, bm()), "SAMPLE_TIMEOUT")
check("B1 REVIEWER (a): probes say strace 41/700, stop_check is internally valid but for pid 999 => INCONSISTENT_EVIDENCE", run(LG2, bm(stop_check=SC("gone", pid=999))), "INCONSISTENT_EVIDENCE")
check("B2 REVIEWER (b): stop_check.mono_s = 1 while the trace started at 1000 => INCONSISTENT_EVIDENCE", run(LG2, bm(stop_check=SC("gone", mono_s=1))), "INCONSISTENT_EVIDENCE")
check("B3 stop_check baseline start time (701) differs from the measured strace start time (700)", run(LG2, bm(stop_check=SC("zombie", baseline=701))), "INCONSISTENT_EVIDENCE")
check("B4 start and final probe name different strace pids", run(LG2, bm(start=P(1001.0, strace_pid=42, ppid=42))), "INCONSISTENT_EVIDENCE")
check("B5 the strace start time differs between the probes", run(LG2, bm(start=P(1001.0, strace_start=699))), "INCONSISTENT_EVIDENCE")
check("B6 final probe: raw stat says parent 77 although the declared strace pid is 41", run(LG2, bm(final=P(1029.9, ppid=77, strace_pid=41))), "INCONSISTENT_EVIDENCE")
check("B7 start probe: raw stat says parent 77 although the declared strace pid is 41", run(LG2, bm(start=P(1001.0, ppid=77, strace_pid=41))), "INCONSISTENT_EVIDENCE")
check("B8 probes do not name the strace pid => UNKNOWN_INCOMPLETE", run(LG2, bm(start=P(1001.0, strace_pid=None), final=P(1029.9, strace_pid=None))), "UNKNOWN_INCOMPLETE")
check("B9 probes do not carry the strace start time => UNKNOWN_INCOMPLETE", run(LG2, bm(start=P(1001.0, strace_start=None), final=P(1029.9, strace_start=None))), "UNKNOWN_INCOMPLETE")
check("B10 stop_check.expected_pid absent => UNKNOWN_INCOMPLETE", run(LG2, bm(stop_check=SC("gone", expected_pid=None))), "UNKNOWN_INCOMPLETE")
check("B11 stop_check.baseline_starttime absent => UNKNOWN_INCOMPLETE", run(LG2, bm(stop_check=SC("gone", baseline_starttime=None))), "UNKNOWN_INCOMPLETE")
check("B12 stop check later than the end of the metadata collection => INCONSISTENT_EVIDENCE", run(LG2, bm(collected_mono_s=1030.5)), "INCONSISTENT_EVIDENCE")
mnc = bm()
del mnc["collected_mono_s"]
check("B13 end of the metadata collection not recorded => UNKNOWN_INCOMPLETE", run(LG2, mnc), "UNKNOWN_INCOMPLETE")
check("B14 boundary: stop check exactly at the stop request and exactly at the collection end holds", run(LG2, bm(stop_check=SC("gone", mono_s=1030.4), collected_mono_s=1030.4)), "SAMPLE_TIMEOUT")
check("B15 collected_mono_s before the trace stop => metadata invalid => UNKNOWN_INCOMPLETE", run(LG2, bm(collected_mono_s=1020.0)), "UNKNOWN_INCOMPLETE", ["META_INVALID"])
check("B16 stop_check just before the stop request (1030.399) => INCONSISTENT_EVIDENCE", run(LG2, bm(stop_check=SC("gone", mono_s=1030.399))), "INCONSISTENT_EVIDENCE")
check("B17 declared strace_pid of the probes is a bool => meta invalid", run(LG2, bm(final=P(1029.9, strace_pid=True))), "UNKNOWN_INCOMPLETE", ["META_INVALID"])
check("B18 stop check target_pid edited away from the raw answer => INCONSISTENT_EVIDENCE", run(LG2, bm(stop_check=SC("gone", target_pid=999))), "INCONSISTENT_EVIDENCE")

# ---- meta validation unit ----
LG = EX + SLEEP
for nm, mm, want in (("V1 valid", M(LG), True), ("V2 not a dict", [1], False), ("V3 negative duration", M(LG, analysis_duration_s=-1), False),
                     ("V4 stopped before started", M(LG, trace_stopped_mono_s=900.0), False), ("V5 bad signal name", M(LG, sample_signal_sent=F.signal_record(signal="kill")), False),
                     ("V6 missing task_id", dict((k, v) for k, v in M(LG).items() if k != "task_id"), False), ("V7 bad log hash", M(LG, strace_log_sha256="zz"), False)):
    N[0] += 1
    ok = C.validate_meta(mm)[0] is want
    print(("[OK]   " if ok else "[FAIL] ") + nm)
    if not ok:
        FAILS.append(nm)


# ---- hostile input never raises (deterministic fuzz) ----
import random
rnd = random.Random(20261011)
bad_exc = []
seeds = [real(n) for n in ("flow-success-arm-busybox", "ct02-mips-b")] + [EX + SLEEP, EX + EXIT0]
N_FUZZ = 0
for base in seeds:
    for _ in range(250):
        t = list(base)
        for _k in range(rnd.randint(1, 6)):
            op = rnd.randint(0, 3)
            i = rnd.randrange(len(t)) if t else 0
            if op == 0 and t:
                del t[i]
            elif op == 1:
                t.insert(i, rnd.choice("()<>=+-\n\"\\ 0aZ?"))
            elif op == 2 and t:
                t[i] = chr(rnd.randrange(32, 127))
            else:
                t = t[: rnd.randrange(len(t) + 1)]
        txt = "".join(t)
        N_FUZZ += 1
        try:
            r = C.classify(txt, F.meta(txt), task_id=F.TASK, log_sha256=F.sha(txt))
            if r["klass"] not in C.KLASSES:
                bad_exc.append("unknown class " + r["klass"])
        except Exception as e:                      # noqa: BLE001
            bad_exc.append(repr(e)[:100])
N[0] += 1
print(("[OK]   " if not bad_exc else "[FAIL] ") + "F1 %d mutated logs never raise and always yield a known class %s" % (N_FUZZ, bad_exc[:2]))
if bad_exc:
    FAILS.append("F1")
junk = [None, 0, "x", [], {}, {"schema": "ct04-trace-meta/2"}, {"schema": "ct04-trace-meta/2", "task_id": 1}, F.meta(EX, probes=[1]), F.meta(EX, probes={"start": "x", "final": 5}),
        F.meta(EX, sample_signal_sent=[1]), F.meta(EX, analysis_duration_s=float("inf")), F.meta(EX, trace_started_mono_s="1")]
bad2 = []
for jm in junk:
    for lg in (EX + SLEEP, EX + K_KILL):
        try:
            C.classify(lg, jm, task_id=F.TASK, log_sha256=F.sha(lg))
        except Exception as e:                      # noqa: BLE001
            bad2.append(repr(e)[:80])
N[0] += 1
print(("[OK]   " if not bad2 else "[FAIL] ") + "F2 malformed metadata never raises %s" % bad2[:2])
if bad2:
    FAILS.append("F2")

# ---- R7: REAL captures of the extra-class lanes A8-A11 (guest ARM/MIPS, 2026-10-12). Classification from strace.log alone; trace metadata is not needed for an end event ----
for a in ("ARM", "MIPS"):
    check("W1 real A8 %s SIGSEGV: CRASHED, kernel si_code" % a, run(real("ct04-lane-A8-" + a)), "CRASHED", ["SIGNAL_DELIVERY_SEEN"], ["SELF_SENT"])
    check("W2 real A9 %s self-sent SIGTERM: KILLED_BY_SIGNAL + SELF_SENT" % a, run(real("ct04-lane-A9-" + a)), "KILLED_BY_SIGNAL", ["SELF_SENT"])
    check("W3 real A10 %s missing interpreter: EXEC_NOT_FOUND" % a, run(real("ct04-lane-A10-" + a)), "EXEC_NOT_FOUND")
    check("W4 real A11 %s musl loader (writev in pieces): class EXITED_NONZERO, loader claim + same-name lookup, never MISSING_LIBRARY" % a, run(real("ct04-lane-A11-" + a)), "EXITED_NONZERO",
          ["LOADER_ERROR_REPORTED", "LIB_LOOKUP_FAILED_SAME_NAME"])
# writev handling: negative and boundary cases (synthetic, derived from the real record)
def WV(iov, fd="2</dev/ttyS0<char 4:64>>", ret=None):
    """one writev line; the return value defaults to the sum of the iov_len values (a complete write) so that the line is self-consistent"""
    if ret is None:
        ret = sum(int(x) for x in re.findall(r"iov_len=(\d+)", iov))
    return L("00.020000", "writev(%s, [%s], 2) = %s <0.001>" % (fd, iov, ret))

MSG = "Error loading shared library libx.so: No such file or directory"
PIECES = '{iov_base="%s", iov_len=%d}, {iov_base=" (needed by ", iov_len=12}' % (MSG, len(MSG))
E127 = L("00.030000", "exit_group(127)   = ?") + L("00.031000", "+++ exited with 127 +++")
LOOKUP = L("00.010000", 'open("/lib/libx.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory) <0.0001>')
check("W5 writev pieces + same-name ENOENT lookup + exit 127 => claim flags, class stays EXITED_NONZERO", run(EX + LOOKUP + WV(PIECES) + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED", "LIB_LOOKUP_FAILED_SAME_NAME"])
check("W6 message split across two writev calls is reassembled in order", run(EX + LOOKUP + WV('{iov_base="Error loading shared library libx.so: No such ", iov_len=46}') + WV('{iov_base="file or directory\\n", iov_len=18}') + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
check("W7 pieces in the WRONG order do not form the message", run(EX + LOOKUP + WV('{iov_base="file or directory", iov_len=17}, {iov_base="Error loading shared library libx.so: No such ", iov_len=46}') + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("W8 writev to another fd (3) is not text of the sample's stdout/stderr", run(EX + LOOKUP + WV(PIECES, fd="3</tmp/x>") + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("W9 unparseable iov list contributes nothing and does not break the classification", run(EX + WV("{iov_base=garbage") + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("W10 message without any lookup: claim flag only, no same-name flag", run(EX + WV(PIECES) + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"], ["LIB_LOOKUP_FAILED_SAME_NAME"])
check("W11 NULL iov_base and truncated string marker are tolerated", run(EX + LOOKUP + WV('{iov_base="Error loading shared library libx.so: No such file or directory"..., iov_len=73}, {iov_base=NULL, iov_len=0}') + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
check("W12 exit 0 with a loader-looking writev is EXITED_0 (the class is not driven by text)", run(EX + WV(PIECES) + L("00.030000", "exit_group(0)   = ?") + L("00.031000", "+++ exited with 0 +++")), "EXITED_0")

# ---- R8 (reviewer counterexamples): only bytes REALLY written count; fd streams are never joined; unknown/cut data is never assembled into a message ----
A11A, A11M = real("ct04-lane-A11-ARM"), real("ct04-lane-A11-MIPS")
for a, lg in (("ARM", A11A), ("MIPS", A11M)):
    check("V0 control: real A11 %s still reports the loader message and the same-name lookup" % a, run(lg), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED", "LIB_LOOKUP_FAILED_SAME_NAME"])
    eio = re.sub(r"\], 2\) = \d+ <", "], 2) = -1 EIO (Input/output error) <", lg)
    check("V1 reviewer counterexample: every writev of the real A11 %s log returns -1 EIO => NO loader claim" % a, run(eio), "EXITED_NONZERO", ["LIB_LOOKUP_ENOENT_SEEN"],
          ["LOADER_ERROR_REPORTED", "LIB_LOOKUP_FAILED_SAME_NAME"])
    zero = re.sub(r"\], 2\) = \d+ <", "], 2) = 0 <", lg)
    check("V2 every writev returns 0 (nothing written) => no claim (%s)" % a, run(zero), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    first_only = re.sub(r"\], 2\) = 85 <", "], 2) = -1 EIO (Input/output error) <", lg, count=1)
    check("V3 only the message-bearing writev fails (the later pieces succeed) => no claim (%s)" % a, run(first_only), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    check("V4 partial write inside the message (40 of 85 bytes) => no claim (%s)" % a, run(re.sub(r"\], 2\) = 85 <", "], 2) = 40 <", lg, count=1)), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    check("V5 partial write that cuts the last character of the message (72 bytes) => no claim (%s)" % a, run(re.sub(r"\], 2\) = 85 <", "], 2) = 72 <", lg, count=1)), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    check("V6 partial write of exactly the message text (73 of 85 bytes): the written prefix is the message => claim (%s)" % a, run(re.sub(r"\], 2\) = 85 <", "], 2) = 73 <", lg, count=1)),
          "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
    check("V7 iovec not understood (garbage) => nothing is assembled (%s)" % a, run(lg.replace('{iov_base="Error loading', '{iov_base=Error loading', 1)), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    check("V8 iovec cut (missing closing brace) => nothing is assembled (%s)" % a, run(lg.replace('iov_len=73}', 'iov_len=73', 1)), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
    check("V9 iov_len disagrees with the printed string and no truncation mark => not trusted (%s)" % a, run(lg.replace("iov_len=73}", "iov_len=99}", 1).replace("= 85 <", "= 111 <", 1)), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V7b the SECOND iovec element is garbage: the whole call is not understood, the first element is not used alone", run(EX + LOOKUP + L("00.020000",
      'writev(2</dev/ttyS0<char 4:64>>, [{iov_base="%s", iov_len=%d}, {iov_base=oops, iov_len=12}], 2) = %d <0.001>' % (MSG, len(MSG), len(MSG))) + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V10 return value larger than the sum of the iov_len values => not trusted", run(EX + LOOKUP + WV(PIECES, ret=999) + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V11 unknown result '?' => nothing", run(EX + LOOKUP + WV(PIECES, ret="?") + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V12 first half on fd 1 and second half on fd 2 are NOT joined into a message", run(EX + LOOKUP + WV('{iov_base="Error loading shared library libx.so: No such ", iov_len=46}', fd="1</dev/ttyS0<char 4:64>>")
      + WV('{iov_base="file or directory", iov_len=17}') + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V13 the whole message on fd 1 (stdout) is the sample's own text: still only a claim, same flags, no new class", run(EX + LOOKUP + WV(PIECES, fd="1</dev/ttyS0<char 4:64>>") + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
check("V14 a FAILED write between two successful halves of the same fd contributes nothing and breaks nothing: the written bytes are still one contiguous stream => claim",
      run(EX + LOOKUP + WV('{iov_base="Error loading shared library libx.so: No such ", iov_len=46}') + WV('{iov_base="x", iov_len=1}', ret="-1 EIO (Input/output error)")
          + WV('{iov_base="file or directory", iov_len=17}') + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
check("V14b an UNKNOWN-result write ('?') between the halves puts a gap into the stream => no claim", run(EX + LOOKUP + WV('{iov_base="Error loading shared library libx.so: No such ", iov_len=46}')
      + WV('{iov_base="x", iov_len=1}', ret="?") + WV('{iov_base="file or directory", iov_len=17}') + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
def WR(ret, fd=2, msg=MSG + "\\n", count=None):
    cnt = len(MSG) + 1 if count is None else count
    return L("00.020000", 'write(%d, "%s", %d) = %s <0.001>' % (fd, msg, cnt, ret))


check("V15 plain write(): return -1 => no claim", run(EX + LOOKUP + WR("-1 EIO (Input/output error)") + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V16 plain write(): partial (10 bytes) => no claim", run(EX + LOOKUP + WR(10) + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V17 plain write(): complete => claim (regression of the r6 behaviour)", run(EX + LOOKUP + WR(len(MSG) + 1) + E127), "EXITED_NONZERO", ["LOADER_ERROR_REPORTED"])
check("V17b plain write(): count disagrees with the printed string, no truncation mark => not trusted", run(EX + LOOKUP + WR(len(MSG) + 1, count=999) + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V17c plain write(): return larger than the count => not trusted", run(EX + LOOKUP + WR(len(MSG) + 50) + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V18 write with an octal escape: byte count is by decoded bytes, not by characters", run(EX + L("00.020000", 'write(2, "ab\\0cd", 5) = 5 <0.001>') + E127), "EXITED_NONZERO", [], ["LOADER_ERROR_REPORTED"])
check("V19 LIB_LOOKUP_FAILED_SAME_NAME needs the claim: no claim => only LIB_LOOKUP_ENOENT_SEEN", run(EX + LOOKUP + WV(PIECES, ret="-1 EIO (Input/output error)") + E127), "EXITED_NONZERO", ["LIB_LOOKUP_ENOENT_SEEN"],
      ["LIB_LOOKUP_FAILED_SAME_NAME", "LOADER_ERROR_REPORTED"])
# the lane classes A8/A9/A10 are unchanged by this work (real logs, W1..W3 above stay green)

print("SUMMARY: %d checks, %d FAIL" % (N[0], len(FAILS)))
sys.exit(1 if FAILS else 0)
