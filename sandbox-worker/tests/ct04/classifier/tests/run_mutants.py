"""Mutation run: every mutant of classify_strace.py must be CAUGHT, i.e. check_classify.py must fail, and the failing checks must include the named
discriminating checks (a mutant that only trips unrelated checks counts as NOT discriminated). usage: python3 -I -B tests/run_mutants.py"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(ROOT))), "service")
SRC = open(os.path.join(SERVICE, "execution_class.py"), encoding="utf-8").read()
# (name, old, new, [check-name prefixes that MUST fail])
MUTANTS = [
    ("write-neg-return-counted", '    if re.fullmatch(r"-\\d+", ret) or ret == "0":\n        return fd, b"", True                                # the call failed or wrote nothing: it contributes nothing and breaks nothing\n    if not re.fullmatch(r"\\d+", ret):', '    if not re.fullmatch(r"-?\\d+", ret):', ["V15"]),
    ("partial-write-whole-string", '            return fd, data[:n], True                       # only the n bytes the kernel reported as written', '            return fd, data, True', ["V16"]),
    ("partial-writev-whole-item", '        take = min(left, ln)\n', '        take = ln\n', ["V4", "V5"]),
    ("fd-streams-merged", '        if data:\n            st[fd].append(data.decode("utf-8", "replace"))\n        if not complete:\n            st[fd].append(_GAP)', '        if data:\n            st[2].append(data.decode("utf-8", "replace"))\n        if not complete:\n            st[2].append(_GAP)', ["V12"]),
    ("iov-garbage-tolerated", '        if not im:\n            return fd, None, False                     # not understood EXACTLY', '        if not im:\n            break                                      # not understood EXACTLY', ["V7b"]),
    ("iov-len-mismatch-trusted", '        if im["trunc"] is None and len(data) != ln:\n            return fd, bytes(out), False', '        if False:\n            return fd, bytes(out), False', ["V9"]),
    ("unknown-result-without-gap", '        if not complete:\n            st[fd].append(_GAP)', '        if False:\n            st[fd].append(_GAP)', ["V14b"]),
    ("return-larger-than-total-trusted", '    if n > total:\n        return fd, None, False\n', '', ["V10"]),

    ("writev-ignored", '        if x["kind"] != "call" or x["name"] not in ("write", "writev"):', '        if x["kind"] != "call" or x["name"] not in ("write",):', ["W4", "W5", "V0"]),
    ("writev-pieces-reordered", '    for im in items:\n        if left == 0:', '    for im in reversed(items):\n        if left == 0:', ["W7"]),
    ("loader-text-drives-class", '    if code == 0:\n        return _res("EXITED_0", ["exit 0"], flags, main)', '    if code == 0 and "Error loading" not in texts:\n        return _res("EXITED_0", ["exit 0"], flags, main)', ["W12"]),

    ("open-tail-accepts-exit_group", 'NOT_OPEN_NAMES = frozenset({"exit", "exit_group"})', 'NOT_OPEN_NAMES = frozenset()', ["O4", "O5"]),
    ("open-tail-accepts-finished-call", '    if ") = " in m["args"] or "<unfinished" in m["args"] or "+++" in text or "---" in text:\n        return False\n', '', ["O9", "N6"]),
    ("open-tail-ignores-time-order", '    return last_ts is None or ts >= last_ts or last_ts - ts > 12 * 3600\n', '    return True\n', ["O8"]),
    ("open-tail-accepts-any-text", '    if not m or m["name"] in NOT_OPEN_NAMES:\n        return False\n', '    if m and m["name"] in NOT_OPEN_NAMES:\n        return False\n', ["O6", "O7"]),
    ("open-tail-veto-removed-without-proof", '            if open_call_tail(tail, ev[-1]["ts"]):\n                flags.append("TAIL_OPEN_SYSCALL")\n            else:\n', '            if True:\n                flags.append("TAIL_OPEN_SYSCALL")\n            else:\n', ["O4", "O6", "N2"]),

    ("raw-ppid-not-compared", '            elif raw["ppid"] != p["strace_pid"]:\n', '            elif False:\n', ["B6", "B7"]),
    ("probe-strace-pid-not-compared", '        if st["strace_pid"] != fi["strace_pid"]:\n', '        if False:\n', ["B4"]),
    ("probe-strace-starttime-not-compared", '        if st["strace_starttime_ticks"] != fi["strace_starttime_ticks"]:\n', '        if False:\n', ["B5"]),
    ("stop-check-binding-values-not-compared", '            elif want is not None and v != want:\n', '            elif False:\n', ["B1", "B3"]),
    ("stop-check-before-stop-request-accepted", '        if sc["mono_s"] < t1:\n', '        if False:\n', ["B2", "B16"]),
    ("stop-check-after-collection-accepted", '        elif sc["mono_s"] > cm:\n', '        elif False:\n', ["B12"]),
    ("strace-identity-gap-ignored", '        if p.get("strace_pid") is None or p.get("strace_starttime_ticks") is None:\n', '        if False:\n', ["B8", "B9"]),
    ("stop-check-binding-gap-ignored", '            if v is None:\n                gap.append("stop_check.%s is absent', '            if False:\n                gap.append("stop_check.%s is absent', ["B10", "B11"]),
    ("binding-contradictions-ignored", '    inc, gap = _binding(meta, st, fi, sc)\n    if inc:\n', '    inc, gap = _binding(meta, st, fi, sc)\n    if False:\n', ["B1", "B2", "B3", "B4"]),
    ("collected-before-stop-accepted", '    if cm is not None and (not _num(cm) or cm < meta["trace_stopped_mono_s"]):\n', '    if cm is not None and (not _num(cm)):\n', ["B15"]),
    ("stat-error-with-dir-present-is-gone", '    if got["DIR"] == 0:\n        out["reason"] = "/proc/%d exists although', '    if False:\n        out["reason"] = "/proc/%d exists although', ["E2"]),
    ("kill0-ignored", '    if got["KILL0"] == 0:\n', '    if False:\n', ["E11"]),
    ("tool-rc-accepted", '    if got["STAT"] != 1:\n', '    if False:\n', ["E9"]),
    ("dir-tool-error-accepted", '    if got["DIR"] != 1:\n', '    if False:\n', ["E10"]),
    ("zombie-baseline-ignored", '        if st["starttime"] != baseline_starttime:\n', '        if False:\n', ["E18"]),
    ("zombie-without-baseline-ok", '        if baseline_starttime is None:\n', '        if False:\n', ["E19"]),
    ("state-not-checked", '        if st["state"] != "Z":\n', '        if False:\n', ["E16"]),
    ("pidfile-rc-ignored", '    if out["rcs"]["pidfile"] != 0:\n', '    if False:\n', ["E5"]),
    ("expected-pid-ignored", '    if expected_pid is not None and target != expected_pid:\n', '    if False:\n', ["E8"]),
    ("pidfile-syntax-ignored", '    if not _PID_TEXT.match(pf[0]["pid"]):\n', '    if False:\n', ["E7"]),
    ("stat-output-ignored-when-failed", '    if out["stat_raw"].strip() != "":\n', '    if False:\n', ["E15"]),
    ("stop-verdict-not-required", '    elif sc["verdict"] not in STOPPED_VERDICTS:\n', '    elif False:\n', ["E33", "E34"]),
    ("stop-check-not-required", '    if sc is None:\n        miss.append("no trace-stop check', '    if False:\n        miss.append("no trace-stop check', []),
    ("stop-check-not-reparsed", '    if again["verdict"] != sc["verdict"]:\n', '    if False:\n', ["E35"]),
    ("stop-check-rcs-not-compared", '    if again["rcs"] != rcs or again["target_pid"] != sc.get("target_pid"):\n', '    if False:\n', ["E36"]),
    ("skip-bad-lines", 'raise _Bad(f"line {n}: event not understood: {body[:80]!r}")', "continue", ["X7"]),
    ("skip-unmatched-lines", 'raise _Bad(f"line {n}: not \'<pid> <hh:mm:ss.ffffff> <event>\': {line[:80]!r}")', "continue", ["X6"]),
    ("no-timestamp-order", 'raise _Bad(f"line {n}: timestamp goes backwards")', "pass", ["X8"]),
    ("no-first-event-exec", "    if fe is None:\n", "    if False:\n", []),   # crashes on hostile input: a failure of the suite, accepted as caught
    ("tail-line-is-evidence", "        raw.pop()\n        tail_dropped = True\n", "        tail_dropped = True\n", ["N1", "N3", "N4"]),
    ("timeout-without-proof", '        if verdict == "PROVEN":', '        if True:', ["T2", "T3", "T12", "T13"]),
    ("no-raw-vs-fields", 'if (raw["pid"], raw["state"], raw["starttime"]) != (p["pid"], p["state"], p["starttime_ticks"]):', "if False:", ["T14", "T15"]),
    ("no-starttime-compare", 'if st["starttime_ticks"] != fi["starttime_ticks"]:', "if False:", ["T12"]),
    ("no-start-probe-required", '    if st is None:\n        miss.append("no start probe (PID reuse cannot be excluded)")', "    if False:\n        pass", ["T6"]),
    ("no-probe-age-limit", 'elif t1 - fi["mono_s"] > PROBE_MAX_AGE_S:', "elif False:", ["T9"]),
    ("no-probe-window", 'if not (t0 <= fi["mono_s"] <= t1):', "if False:", ["T10"]),
    ("no-pid-binding", 'if fi["pid"] != main_pid:', "if False:", ["T7"]),
    ("no-task-binding", '        if task_id is not None and meta["task_id"] != task_id:\n            return _res("INCONSISTENT_EVIDENCE", [f"meta task_id', '        if False:\n            return _res("INCONSISTENT_EVIDENCE", [f"meta task_id', ["T17"]),
    ("no-log-hash-binding", '        if meta.get("strace_log_sha256") is not None and log_sha256 is not None and meta["strace_log_sha256"] != log_sha256:\n            return _res("INCONSISTENT_EVIDENCE", ["meta strace', '        if False:\n            return _res("INCONSISTENT_EVIDENCE", ["meta strace', ["T18"]),
    ("no-log-binding-required", '    if meta.get("strace_log_sha256") is None:\n        miss.append("metadata is not bound', '    if False:\n        miss.append("metadata is not bound', ["T19"]),
    ("final-state-ignored", 'if fi["state"] not in ALIVE_STATES:', "if False:", ["T8"]),
    ("elapsed-ignored", 'if t1 - t0 < meta["analysis_duration_s"]:', "if False:", ["T4"]),
    ("stop-reason-ignored", 'if meta["stop_reason"] != "window_elapsed":', "if False:", ["T3"]),
    ("meta-not-validated-for-signal", "        if meta_ok and meta.get(\"sample_signal_sent\") is not None:", "        if meta is not None and meta.get(\"sample_signal_sent\") is not None:", ["G6", "G7", "G10", "G11"]),
    ("signal-target-ignored", 'ms["target_pid"] == main and ', "", ["G8"]),
    ("signal-result-ignored", 'and ms["result"] == "sent"', "", ["G9"]),
    ("segv-without-source-is-crash", "        if code is not None and KERNEL_SI_CODE.match(code):", "        if sig in ('SIGSEGV', 'SIGILL', 'SIGBUS', 'SIGFPE', 'SIGABRT') and not sent:", ["G2"]),
    ("self-sent-flag-dropped", '            flags.append("SELF_SENT")', "            pass", ["G17"]),
    ("loader-message-certified", '    ev_txt = [f"exit {code}"]\n', '    ev_txt = [f"exit {code}"]\n    if LOADER_MSG[0].search(texts):\n        return _res("MISSING_LIBRARY", ["x"], flags, main)\n', ["M2", "M3", "M8"]),
    ("enoexec-is-wrong-arch", '"ENOEXEC": "EXEC_FORMAT_ERROR"', '"ENOEXEC": "WRONG_ARCH"', ["M5", "S exec-enoexec"]),
    ("bare-exit-counts", 'e["name"] == "exit_group" and e["ret"] == "?"', 'e["name"] in ("exit_group", "exit") and e["ret"] == "?"', ["T26"]),
    ("trailing-garbage-ok", r'\)\s+= " + _RET + _REST + r"$")' + "\nUNFIN", r'\)\s+= " + _RET + _REST)' + "\nUNFIN", ["X16"]),
    ("infra-as-sample", 'k = "INFRA_TIMEOUT" if INFRA_TIMEOUT_RE.search(failure_reason) else "INFRA_FAILURE"', 'k = "SAMPLE_TIMEOUT"', ["T27"]),
    ("events-after-end-ok", '        elif later:\n            return _res("LOG_INVALID", [f"events of main pid {main} after its end (line {e[\'n\']})"], flags, main)', "        elif later:\n            pass", ["X15"]),
]
bad = 0
for name, a, b, must in MUTANTS:
    if SRC.count(a) != 1:
        print("[SETUP-ERROR]", name, "pattern count", SRC.count(a))
        bad += 1
        continue
    d = tempfile.mkdtemp()
    try:
        shutil.copytree(ROOT, d + "/t", ignore=shutil.ignore_patterns("__pycache__", "logs"))
        open(d + "/t/execution_class.py", "w", encoding="utf-8").write(SRC.replace(a, b))
        r = subprocess.run([sys.executable, "-I", "-B", "tests/check_classify.py"], cwd=d + "/t", capture_output=True, text=True)
        failed = [l.split("  ->")[0][7:] for l in r.stdout.splitlines() if l.startswith("[FAIL]")]
        hit = [m for m in must if any(f == m or f.startswith(m + " ") for f in failed)]
        miss = [m for m in must if m not in hit]
        if r.returncode == 0:
            print("[SURVIVED] " + name)
            bad += 1
        elif not failed:
            print("[CAUGHT] %s (by crash/non-zero exit)" % name)
        elif miss:
            print("[NOT-DISCRIMINATED] %s: expected %s to fail, failing=%s" % (name, miss, failed[:6]))
            bad += 1
        else:
            print("[CAUGHT] %s (by %s)" % (name, ", ".join(hit)))
    finally:
        shutil.rmtree(d, ignore_errors=True)
print("MUTANTS: %d total, %d not caught/discriminated" % (len(MUTANTS), bad))
sys.exit(1 if bad else 0)
