"""CT-04 execution classification (worker side): pure classifier (identical code to ct04-offline-r5/classify_strace.py), then the collector.

classify(strace_text, meta=None, failure_reason=None, task_id=None) -> {"klass", "evidence", "flags", "main_pid"}

Direction (reviewer): the WORKER classifies, the MANAGER stores; COMPLETED means "analysis finished"; `execution_class` is a separate field and does NOT mean
the sample exited successfully.

Principles
  * Every line is parsed completely against a closed grammar; a line that does not match is LOG_INVALID, never skipped.
  * An unterminated final line is NEVER evidence (it may be a prefix of a different line): it is dropped and flagged TRUNCATED_TAIL.
  * The only exit evidence of the MAIN pid is its own `+++ exited/killed +++` line or a complete `exit_group(N) = ?` line.
  * "No exit evidence" is UNKNOWN_INCOMPLETE unless trace metadata PROVES the window ended with the sample alive (SAMPLE_TIMEOUT, see _timeout_proof):
    task/trace/log binding, two probes of the same pid with the same start time, probe times inside the trace and close to the stop, raw probe text that
    agrees with the parsed fields. A contradiction between pieces of evidence is INCONSISTENT_EVIDENCE, a gap is UNKNOWN_INCOMPLETE.
  * A signal is attributed only from evidence: STOPPED_BY_SANDBOX needs a fully valid, bound worker record that targeted the main pid; CRASHED needs a
    delivery line with a KERNEL si_code; anything else is KILLED_BY_SIGNAL with the missing evidence flagged.
  * Text written by the sample is the sample's claim: a loader-style message is reported (LOADER_ERROR_REPORTED) and never certified as MISSING_LIBRARY.
    No rule emits MISSING_LIBRARY (reserved until a source of loader provenance exists).
"""
import re

KLASSES = ("EXITED_0", "EXITED_NONZERO", "CRASHED", "KILLED_BY_SIGNAL", "STOPPED_BY_SANDBOX", "SAMPLE_TIMEOUT",
           "EXEC_FORMAT_ERROR", "EXEC_NOT_FOUND", "EXEC_PERMISSION_DENIED", "EXEC_FAILED",
           "LOG_MISSING", "LOG_INVALID", "UNKNOWN_INCOMPLETE", "INCONSISTENT_EVIDENCE", "INFRA_TIMEOUT", "INFRA_FAILURE",
           "MISSING_LIBRARY")                                     # MISSING_LIBRARY: reserved, never emitted

META_SCHEMA = "ct04-trace-meta/2"
ALIVE_STATES = ("R", "S", "D", "T")
PROBE_MAX_AGE_S = 5.0            # the final probe must be at most this old when the trace is stopped
START_PROBE_MAX_DELAY_S = 10.0   # the start probe must be taken within this many seconds of the trace start
KERNEL_SI_CODE = re.compile(r"^(?:(?:SEGV|ILL|BUS|FPE|TRAP|SYS)_[A-Z0-9]+|SI_KERNEL)$")
SENT_CODES = ("SI_USER", "SI_TKILL", "SI_QUEUE", "SI_TIMER", "SI_MESGQ", "SI_ASYNCIO", "SI_SIGIO")

_TS = r"(?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)\.(?P<us>\d{6})"
LINE = re.compile(r"^(?P<pid>\d+)\s+" + _TS + r" (?P<body>.+)$")
_RET = r"(?P<ret>-?\d+|\?|0x[0-9a-fA-F]+)"
_REST = r"(?P<rest>(?:<[^\n]*?>)?(?: [A-Z][A-Z0-9_]+ \([^\n]*\))?(?: <\d+\.\d+>)?)"
CALL = re.compile(r"^(?P<name>[a-z_][a-z_0-9]*)\((?P<args>.*)\)\s+= " + _RET + _REST + r"$")
UNFIN = re.compile(r"^(?P<name>[a-z_][a-z_0-9]*)\((?P<args>.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (?P<name>[a-z_][a-z_0-9]*) resumed>(?P<args>.*)\)\s+= " + _RET + _REST + r"$")
EXITED = re.compile(r"^\+\+\+ exited with (?P<code>\d+) \+\+\+$")
KILLED = re.compile(r"^\+\+\+ killed by (?P<sig>SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
SIGDEL = re.compile(r"^--- (?P<sig>SIG[A-Z0-9]+) \{(?P<info>.*)\} ---$")
SI_CODE = re.compile(r"\bsi_code=(?P<code>[A-Z0-9_]+)")
SI_PID = re.compile(r"\bsi_pid=(?P<pid>\d+)")
ERRNO_AT_END = re.compile(r"^ (?P<err>[A-Z][A-Z0-9_]+) \(")
WRITE_ARGS = re.compile(r'^(?P<fd>[12])(?:<.*>)?, "(?P<txt>(?:[^"\\]|\\.)*)"(?:\.\.\.)?, \d+$')
WRITEV_ARGS = re.compile(r'^(?P<fd>[12])(?:<.*>)?, \[(?P<iov>.*)\], \d+$')
IOV_ITEM = re.compile(r'\{iov_base=(?:"(?P<txt>(?:[^"\\]|\\.)*)"(?P<trunc>\.\.\.)?|NULL), iov_len=(?P<len>\d+)\}')
LIBNAME_OPEN = re.compile(r'"(?P<p>[^"]*)"')
LOADER_MSG = (re.compile(r"Error loading shared library (?P<lib>[^\s:]+): No such file or directory"),
              re.compile(r"error while loading shared libraries: (?P<lib>[^\s:]+): cannot open shared object file: No such file or directory"))
INFRA_TIMEOUT_RE = re.compile(r"QEMU timed out|timed out waiting|timed out after")
STAT_RAW = re.compile(r"^(?P<pid>\d+) \((?P<comm>.*)\) (?P<state>[A-Za-z]) (?P<rest>.*)$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


_ESC = {"n": 10, "t": 9, "r": 13, "a": 7, "b": 8, "f": 12, "v": 11, "\\": 92, '"': 34, "'": 39}
_GAP = "\x00<gap>\x00"                          # inserted into a stream where bytes are unknown: no message can be assembled across it


def _c_bytes(txt):
    """Decode the C-style string strace prints (\\n, \\xHH, \\ooo, ...) into the BYTES it stands for; None when it cannot be decoded exactly."""
    out = bytearray()
    i, n = 0, len(txt)
    while i < n:
        c = txt[i]
        if c != "\\":
            if ord(c) > 127:
                return None
            out.append(ord(c))
            i += 1
            continue
        i += 1
        if i >= n:
            return None
        c = txt[i]
        if c in _ESC:
            out.append(_ESC[c])
            i += 1
        elif c == "x":
            h = txt[i + 1:i + 3]
            if len(h) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", h):
                return None
            out.append(int(h, 16))
            i += 3
        elif c in "01234567":
            o = re.match(r"[0-7]{1,3}", txt[i:])[0]
            v = int(o, 8)
            if v > 255:
                return None
            out.append(v)
            i += len(o)
        else:
            return None
    return bytes(out)


def _written_bytes(x):
    """-> (fd, bytes actually written or None, complete) for one traced write()/writev() call of the main pid.
    Only bytes the kernel reported as written are used: the return value n must be a plain positive integer; a partial write contributes its first n bytes only; a call
    that failed (-1/errno), wrote nothing (0), has an unknown result (?) or whose argument text is not understood EXACTLY contributes nothing (complete=False => the
    caller puts a gap in that stream). Nothing is guessed."""
    fm = re.match(r"(\d+)", x.get("args", ""))
    fd = int(fm[1]) if fm else None
    if x.get("resumed"):
        return fd, None, False                              # the first part of the call is not in this line: not understood exactly
    ret = x.get("ret", "")
    if re.fullmatch(r"-\d+", ret) or ret == "0":
        return fd, b"", True                                # the call failed or wrote nothing: it contributes nothing and breaks nothing
    if not re.fullmatch(r"\d+", ret):
        return fd, None, False                              # '?', hex, anything else: the result is unknown
    n = int(ret)
    if x["name"] == "write":
        m = WRITE_ARGS.match(x["args"])
        if not m:
            return fd, None, False
        data = _c_bytes(m["txt"])
        cnt = re.search(r", (\d+)$", x["args"])
        if data is None or not cnt:
            return fd, None, False
        count = int(cnt[1])
        truncated = bool(re.search(r'"\.\.\., \d+$', x["args"]))
        if n > count or (not truncated and len(data) != count):
            return fd, None, False                          # inconsistent record: not trusted
        if len(data) >= n:
            return fd, data[:n], True                       # only the n bytes the kernel reported as written
        return fd, data, False                              # truncated print: the shown prefix is known, what follows is not
    m = WRITEV_ARGS.match(x["args"])
    if not m:
        return None, None, False
    fd = int(m["fd"])
    iov = m["iov"]
    items = []
    pos = 0
    while pos < len(iov):
        im = IOV_ITEM.match(iov, pos)
        if not im:
            return fd, None, False                     # not understood EXACTLY (garbage, a trailing '...', a cut structure): nothing is used
        items.append(im)
        pos = im.end()
        if pos < len(iov):
            if iov[pos:pos + 2] != ", ":
                return fd, None, False
            pos += 2
    if not items:
        return fd, None, False
    total = sum(int(i["len"]) for i in items)
    if n > total:
        return fd, None, False
    left, out, complete = n, bytearray(), True
    for im in items:
        if left == 0:
            break
        ln = int(im["len"])
        take = min(left, ln)
        if im["txt"] is None:                        # iov_base=NULL with a non-zero length: unknown bytes
            if ln:
                return fd, bytes(out), False
            continue
        data = _c_bytes(im["txt"])
        if data is None:
            return fd, bytes(out), False
        if im["trunc"] is None and len(data) != ln:
            return fd, bytes(out), False                    # printed length disagrees with iov_len and nothing says it was truncated: not trusted
        if len(data) >= take:
            out += data[:take]
        else:
            out += data                                      # truncated print ('...'): the shown prefix only
            return fd, bytes(out), False
        left -= take
    return fd, bytes(out), complete


def _written_streams(mine):
    """{fd: text} for fd 1 and 2, in call order; the two streams are NEVER joined. A call whose bytes are unknown puts a gap marker into its stream."""
    st = {1: [], 2: []}
    for x in mine:
        if x["kind"] != "call" or x["name"] not in ("write", "writev"):
            continue
        fd, data, complete = _written_bytes(x)
        if fd not in st:
            continue
        if data:
            st[fd].append(data.decode("utf-8", "replace"))
        if not complete:
            st[fd].append(_GAP)
    return {fd: "".join(parts) for fd, parts in st.items()}


def _res(klass, evidence, flags=(), main_pid=None):
    return {"klass": klass, "evidence": list(evidence), "flags": list(flags), "main_pid": main_pid}


def _secs(m):
    return int(m["h"]) * 3600 + int(m["m"]) * 60 + int(m["s"]) + int(m["us"]) / 1e6


def _unescape(t):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m[1], m[1]), t)


class _Bad(Exception):
    pass


OPEN_CALL_TAIL = re.compile(r"^(?P<pid>\d+)\s+(?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)\.(?P<f>\d+) (?P<name>[a-z_][a-z0-9_]*)\((?P<args>.*)$", re.S)
NOT_OPEN_NAMES = frozenset({"exit", "exit_group"})


def open_call_tail(text, last_ts):
    """True only when the dropped, unterminated final line is provably the ENTRY of a system call that has not returned (`<pid> <time> name(args` with no
    result, name not exit/exit_group, time not before the last complete line). This is what a tracee blocked in a syscall leaves when strace is killed.
    It is never evidence of an exit or a signal; it only stops the blanket 'cut tail => unknown' veto, the SAMPLE_TIMEOUT proof (probes, stop check,
    binding) is still required in full."""
    if not text or "\n" in text:
        return False
    m = OPEN_CALL_TAIL.match(text)
    if not m or m["name"] in NOT_OPEN_NAMES:
        return False
    if int(m["h"]) > 23 or int(m["m"]) > 59 or int(m["s"]) > 59:
        return False
    if ") = " in m["args"] or "<unfinished" in m["args"] or "+++" in text or "---" in text:
        return False
    ts = int(m["h"]) * 3600 + int(m["m"]) * 60 + int(m["s"]) + float("0." + m["f"])
    return last_ts is None or ts >= last_ts or last_ts - ts > 12 * 3600


def parse(text):
    """-> (events, pending, tail_dropped). Raises _Bad(reason) on the first COMPLETE line that is not fully understood (never skips).
    The final line, when it has no newline, is dropped whatever it looks like (tail_dropped=True)."""
    if "\x00" in text:
        raise _Bad("NUL byte in log")
    raw = text.split("\n")
    tail_dropped = False
    if raw and raw[-1] == "":
        raw.pop()
    elif raw:
        raw.pop()
        tail_dropped = True
    ev, last_ts, wrapped, pending = [], None, False, {}
    for n, line in enumerate(raw, 1):
        m = LINE.match(line)
        if not m:
            raise _Bad(f"line {n}: not '<pid> <hh:mm:ss.ffffff> <event>': {line[:80]!r}")
        pid, body, ts = int(m["pid"]), m["body"], _secs(m)
        if int(m["h"]) > 23 or int(m["m"]) > 59 or int(m["s"]) > 59:
            raise _Bad(f"line {n}: impossible timestamp")
        if last_ts is not None and ts < last_ts:
            if last_ts - ts > 12 * 3600 and not wrapped:
                wrapped = True                              # a single midnight rollover
            else:
                raise _Bad(f"line {n}: timestamp goes backwards")
        last_ts = ts
        e = {"pid": pid, "ts": ts, "n": n, "body": body}
        x, k, s = EXITED.match(body), KILLED.match(body), SIGDEL.match(body)
        c, u, r = CALL.match(body), UNFIN.match(body), RESUMED.match(body)
        if x:
            e.update(kind="exited", code=int(x["code"]))
        elif k:
            e.update(kind="killed", sig=k["sig"])
        elif s:
            e.update(kind="signal", sig=s["sig"], info=s["info"])
        elif u:
            if pid in pending:
                raise _Bad(f"line {n}: pid {pid} starts a call while {pending[pid]!r} is unfinished")
            pending[pid] = u["name"]
            e.update(kind="unfinished", name=u["name"], args=u["args"])
        elif r:
            if pending.get(pid) != r["name"]:
                raise _Bad(f"line {n}: resumed {r['name']!r} does not match the unfinished call of pid {pid} ({pending.get(pid)!r})")
            del pending[pid]
            e.update(kind="call", name=r["name"], args=r["args"], ret=r["ret"], rest=r["rest"], resumed=True)
        elif c:
            if pid in pending:
                raise _Bad(f"line {n}: pid {pid} makes a call while {pending[pid]!r} is unfinished")
            e.update(kind="call", name=c["name"], args=c["args"], ret=c["ret"], rest=c["rest"], resumed=False)
        else:
            raise _Bad(f"line {n}: event not understood: {body[:80]!r}")
        ev.append(e)
    return ev, pending, tail_dropped


# ----------------------------------------------------------------------------------------------------------------- metadata
def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_stat_raw(raw):
    """-> dict(pid, comm, state, starttime) from a /proc/<pid>/stat line, or None."""
    if not isinstance(raw, str):
        return None
    m = STAT_RAW.match(raw.strip())
    if not m:
        return None
    rest = m["rest"].split(" ")
    if len(rest) < 19 or not rest[18].isdigit():
        return None
    return {"pid": int(m["pid"]), "comm": m["comm"], "state": m["state"], "starttime": int(rest[18]), "ppid": int(rest[0]) if rest[0].lstrip("-").isdigit() else None}


def validate_probe(p):
    """-> (ok, why). Strict types AND agreement between the declared fields and the raw /proc/<pid>/stat text."""
    if not isinstance(p, dict):
        return False, "probe not an object"
    if not _num(p.get("mono_s")):
        return False, "probe mono_s"
    if not _int(p.get("pid")) or p["pid"] <= 0:
        return False, "probe pid"
    if not _int(p.get("starttime_ticks")) or p["starttime_ticks"] < 0:
        return False, "probe starttime_ticks"
    if not isinstance(p.get("state"), str) or not re.fullmatch(r"[A-Za-z]", p["state"]):
        return False, "probe state"
    raw = parse_stat_raw(p.get("raw"))
    if raw is None:
        return False, "probe raw is not a /proc/<pid>/stat line"
    if (raw["pid"], raw["state"], raw["starttime"]) != (p["pid"], p["state"], p["starttime_ticks"]):
        return False, "CONTRADICTION: raw probe says pid=%d state=%s starttime=%d, fields say pid=%d state=%s starttime=%d" % (
            raw["pid"], raw["state"], raw["starttime"], p["pid"], p["state"], p["starttime_ticks"])
    for k in ("strace_pid", "strace_starttime_ticks"):
        v = p.get(k)
        if v is not None and not (_int(v) and v >= 0):
            return False, "probe " + k
    return True, ""


def validate_signal_record(s, meta):
    if s is None:
        return True, ""
    if not isinstance(s, dict):
        return False, "sample_signal_sent not an object"
    if not (isinstance(s.get("signal"), str) and re.fullmatch(r"SIG[A-Z0-9]+", s["signal"])):
        return False, "sample_signal_sent.signal"
    if not _int(s.get("target_pid")) or s["target_pid"] <= 0:
        return False, "sample_signal_sent.target_pid"
    if not _num(s.get("mono_s")):
        return False, "sample_signal_sent.mono_s"
    if s.get("result") not in ("sent", "failed"):
        return False, "sample_signal_sent.result"
    if s.get("trace_id") != meta.get("trace_id"):
        return False, "sample_signal_sent.trace_id does not match the trace"
    if not (meta["trace_started_mono_s"] <= s["mono_s"] <= meta["trace_stopped_mono_s"]):
        return False, "sample_signal_sent.mono_s outside the trace window"
    return True, ""


# ----------------------------------------------------------------------------------------------------------------- trace-stop envelope
STOP_VERDICTS = ("gone", "zombie", "alive", "unknown")
STOPPED_VERDICTS = ("gone", "zombie")
_ENV_PIDFILE = re.compile(r"^CT04-PIDFILE rc=(?P<rc>\d{1,3}) pid=\[(?P<pid>.*)\]$")
_ENV_RC = {"STAT": re.compile(r"^CT04-STAT rc=(?P<rc>\d{1,3})$"), "DIR": re.compile(r"^CT04-DIR rc=(?P<rc>\d{1,3})$"),
           "KILL0": re.compile(r"^CT04-KILL0 rc=(?P<rc>\d{1,3})$")}
_ENV_STATRAW = re.compile(r"^CT04-STATRAW \[(?P<raw>.*)\]$")
_PID_TEXT = re.compile(r"^[1-9][0-9]{0,8}$")


def parse_stop_envelope(body, expected_pid=None, baseline_starttime=None):
    """Judge the answer of the trace-stop check. `body` is the text BETWEEN the BEGIN and END markers.
    -> {"verdict": gone|zombie|alive|unknown, "reason", "target_pid", "rcs": {pidfile, stat, dir, kill0}, "stat_raw", "pidfile_text"}
    "gone" needs POSITIVE evidence of absence: a valid pid file, `cat /proc/<pid>/stat` rc 1 with empty output, `test -d /proc/<pid>` false (rc 1) AND `kill -0` failing (rc 1).
    Empty output, a read error that leaves /proc/<pid> in place, a tool error (rc 126/127), a bad or missing pid file and a truncated answer are all "unknown".
    A process that is still there counts as stopped only when it is the SAME process (pid and start time of the strace baseline) and its state is Z."""
    out = {"verdict": "unknown", "reason": "", "target_pid": None, "rcs": {"pidfile": None, "stat": None, "dir": None, "kill0": None}, "stat_raw": "", "pidfile_text": ""}
    if not isinstance(body, str):
        out["reason"] = "answer is not text"
        return out
    lines = [l for l in body.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip() != ""]
    pf = [m for m in (_ENV_PIDFILE.match(l.strip()) for l in lines) if m]
    if len(pf) != 1:
        out["reason"] = "pid file line missing or repeated (answer truncated?)"
        return out
    out["rcs"]["pidfile"] = int(pf[0]["rc"])
    out["pidfile_text"] = pf[0]["pid"][:32]
    if out["rcs"]["pidfile"] != 0:
        out["reason"] = "pid file could not be read (rc %d)" % out["rcs"]["pidfile"]
        return out
    if not _PID_TEXT.match(pf[0]["pid"]):
        out["reason"] = "pid file does not contain a single positive integer"
        return out
    target = int(pf[0]["pid"])
    out["target_pid"] = target
    if expected_pid is not None and target != expected_pid:
        out["reason"] = "pid file names %d but the traced strace pid is %d" % (target, expected_pid)
        return out
    got = {}
    for k, rx in _ENV_RC.items():
        ms = [m for m in (rx.match(l.strip()) for l in lines) if m]
        if len(ms) != 1:
            out["reason"] = "line CT04-%s missing or repeated (answer truncated or target rejected)" % k
            return out
        got[k] = int(ms[0]["rc"])
    sr = [m for m in (_ENV_STATRAW.match(l.strip()) for l in lines) if m]
    if len(sr) != 1:
        out["reason"] = "line CT04-STATRAW missing or repeated"
        return out
    out["rcs"].update(stat=got["STAT"], dir=got["DIR"], kill0=got["KILL0"])
    out["stat_raw"] = sr[0]["raw"][:400]
    if got["STAT"] == 0:
        st = _stat_envelope_line(out["stat_raw"])
        if st is None:
            out["reason"] = "stat read succeeded but the output is empty or not a /proc stat line"
            return out
        if st["pid"] != target:
            out["reason"] = "stat line is for pid %d, not %d" % (st["pid"], target)
            return out
        if st["state"] != "Z":
            out["verdict"], out["reason"] = "alive", "process %d is still in state %s" % (target, st["state"])
            return out
        if baseline_starttime is None:
            out["reason"] = "zombie seen but no start-time baseline of the strace process to prove it is the same process"
            return out
        if st["starttime"] != baseline_starttime:
            out["reason"] = "start time %d differs from the baseline %d: not the same process" % (st["starttime"], baseline_starttime)
            return out
        out["verdict"], out["reason"] = "zombie", "same process (pid %d, start time %d) in state Z" % (target, st["starttime"])
        return out
    if got["STAT"] != 1:
        out["reason"] = "reading /proc/%d/stat failed with rc %d (tool or permission error), process presence unproven" % (target, got["STAT"])
        return out
    if out["stat_raw"].strip() != "":
        out["reason"] = "stat read failed but produced output"
        return out
    if got["DIR"] == 0:
        out["reason"] = "/proc/%d exists although its stat could not be read (read error, not absence)" % target
        return out
    if got["DIR"] != 1:
        out["reason"] = "directory test failed with rc %d (tool error)" % got["DIR"]
        return out
    if got["KILL0"] == 0:
        out["reason"] = "kill -0 says pid %d exists although /proc/%d does not" % (target, target)
        return out
    if got["KILL0"] != 1:
        out["reason"] = "kill -0 failed with rc %d (tool error)" % got["KILL0"]
        return out
    out["verdict"], out["reason"] = "gone", "pid file ok; stat unreadable rc 1 with empty output; /proc/%d absent; kill -0 failed" % target
    return out


def _stat_envelope_line(raw):
    m = STAT_RAW.match(raw.strip())
    if not m:
        return None
    rest = m["rest"].split(" ")
    if len(rest) < 19 or not rest[18].isdigit():
        return None
    return {"pid": int(m["pid"]), "state": m["state"], "starttime": int(rest[18])}


def validate_stop_check(sc, trace_id):
    """-> (ok, why). Shape check AND re-judgement of the stored raw answer: the stored verdict must be what the parser concludes from the stored raw text and rcs."""
    if not isinstance(sc, dict):
        return False, "stop_check not an object"
    if sc.get("verdict") not in STOP_VERDICTS:
        return False, "stop_check.verdict"
    if not _num(sc.get("mono_s")):
        return False, "stop_check.mono_s"
    for k in ("reason", "raw"):
        if not isinstance(sc.get(k), str) or len(sc[k]) > 2000:
            return False, "stop_check." + k
    for k in ("target_pid", "expected_pid", "baseline_starttime"):
        v = sc.get(k)
        if v is not None and not (_int(v) and v >= 0):
            return False, "stop_check." + k
    rcs = sc.get("rcs")
    if not isinstance(rcs, dict) or set(rcs) != {"pidfile", "stat", "dir", "kill0"} or any(v is not None and not (_int(v) and 0 <= v <= 255) for v in rcs.values()):
        return False, "stop_check.rcs"
    again = parse_stop_envelope(sc["raw"], sc.get("expected_pid"), sc.get("baseline_starttime"))
    if again["verdict"] != sc["verdict"]:
        return False, "CONTRADICTION: stop_check says %s but its raw answer re-parses to %s (%s)" % (sc["verdict"], again["verdict"], again["reason"])
    if again["rcs"] != rcs or again["target_pid"] != sc.get("target_pid"):
        return False, "CONTRADICTION: stop_check rcs/target do not match its raw answer"
    return True, ""


def validate_meta(meta):
    """-> (ok, why). Strict types, bindings present, every nested record valid. A malformed meta supports NO conclusion."""
    if not isinstance(meta, dict) or meta.get("schema") != META_SCHEMA:
        return False, "schema"
    for k in ("task_id", "trace_id"):
        if not (isinstance(meta.get(k), str) and 0 < len(meta[k]) <= 128):
            return False, k
    d = meta.get("analysis_duration_s")
    if not (_int(d) and d > 0):
        return False, "analysis_duration_s"
    for k in ("trace_started_mono_s", "trace_stopped_mono_s"):
        if not _num(meta.get(k)):
            return False, k
    if meta["trace_stopped_mono_s"] < meta["trace_started_mono_s"]:
        return False, "trace_stopped before trace_started"
    if meta.get("stop_reason") not in ("window_elapsed", "cancelled", "error"):
        return False, "stop_reason"
    cm = meta.get("collected_mono_s")
    if cm is not None and (not _num(cm) or cm < meta["trace_stopped_mono_s"]):
        return False, "collected_mono_s (not a number or before the trace stop)"
    h = meta.get("strace_log_sha256")
    if h is not None and not (isinstance(h, str) and HEX64.match(h)):
        return False, "strace_log_sha256"
    pr = meta.get("probes")
    if pr is not None:
        if not isinstance(pr, dict):
            return False, "probes"
        for k in ("start", "final"):
            if pr.get(k) is not None:
                ok, why = validate_probe(pr[k])
                if not ok:
                    return False, f"probes.{k}: {why}"
    ok, why = validate_signal_record(meta.get("sample_signal_sent"), meta)
    if not ok:
        return False, why
    if meta.get("stop_check") is not None:
        ok, why = validate_stop_check(meta["stop_check"], meta["trace_id"])
        if not ok:
            return False, "stop_check: " + why
    return True, ""


def _binding(meta, st, fi, sc):
    """Binding between the probes, the stop check and the measured trace. -> (contradictions, gaps). A contradiction is INCONSISTENT_EVIDENCE, a gap is UNKNOWN_INCOMPLETE."""
    inc, gap = [], []
    t1 = meta["trace_stopped_mono_s"]
    for nm, p in (("start", st), ("final", fi)):
        if p is None:
            continue
        if p.get("strace_pid") is None or p.get("strace_starttime_ticks") is None:
            gap.append("%s probe does not name the strace process (strace_pid / strace_starttime_ticks missing)" % nm)
        else:
            raw = parse_stat_raw(p["raw"])
            if raw is None or raw["ppid"] is None:
                gap.append("%s probe raw stat has no parent pid" % nm)
            elif raw["ppid"] != p["strace_pid"]:
                inc.append("%s probe raw stat says the parent is %d but the declared strace pid is %d" % (nm, raw["ppid"], p["strace_pid"]))
    if st is not None and fi is not None and None not in (st.get("strace_pid"), fi.get("strace_pid"), st.get("strace_starttime_ticks"), fi.get("strace_starttime_ticks")):
        if st["strace_pid"] != fi["strace_pid"]:
            inc.append("start probe strace pid %d != final probe strace pid %d" % (st["strace_pid"], fi["strace_pid"]))
        if st["strace_starttime_ticks"] != fi["strace_starttime_ticks"]:
            inc.append("strace start time differs between the probes (%d -> %d)" % (st["strace_starttime_ticks"], fi["strace_starttime_ticks"]))
    sp = fi.get("strace_pid") if fi is not None else None
    ss = fi.get("strace_starttime_ticks") if fi is not None else None
    if sc is not None:
        for field, want, what in (("expected_pid", sp, "strace pid"), ("target_pid", sp, "strace pid"), ("baseline_starttime", ss, "strace start time")):
            v = sc.get(field)
            if v is None:
                gap.append("stop_check.%s is absent (the stop check is not bound to the measured strace)" % field)
            elif want is not None and v != want:
                inc.append("stop_check.%s is %d but the probes measured %s %d" % (field, v, what, want))
        if sc["mono_s"] < t1:
            inc.append("stop check time %.3f precedes the stop request %.3f" % (sc["mono_s"], t1))
        cm = meta.get("collected_mono_s")
        if cm is None:
            gap.append("no collected_mono_s: the end of the metadata collection is not recorded")
        elif sc["mono_s"] > cm:
            inc.append("stop check time %.3f is after the end of the metadata collection %.3f" % (sc["mono_s"], cm))
    return inc, gap


def _timeout_proof(meta, main_pid, task_id, log_sha256):
    """-> (verdict, [text]) with verdict "PROVEN" | "INCONSISTENT" | "MISSING"."""
    ok, why = validate_meta(meta)
    if not ok:
        return ("INCONSISTENT" if (why.startswith("probes.") or why.startswith("stop_check")) and "CONTRADICTION" in why else "MISSING"), [f"trace metadata invalid or absent ({why})"]
    miss = []   # task/log contradictions are rejected earlier, in classify()
    if task_id is None:
        miss.append("no expected task id supplied to bind the metadata")
    if meta.get("strace_log_sha256") is None:
        miss.append("metadata is not bound to the log (strace_log_sha256 absent)")
    if meta["stop_reason"] != "window_elapsed":
        miss.append(f"stop_reason is {meta['stop_reason']!r}, not window_elapsed")
    sc = meta.get("stop_check")
    if sc is None:
        miss.append("no trace-stop check recorded: the stop of the trace is not confirmed")
    elif sc["verdict"] not in STOPPED_VERDICTS:
        miss.append(f"trace-stop check verdict is {sc['verdict']!r} ({sc['reason'][:80]})")
    t0, t1 = meta["trace_started_mono_s"], meta["trace_stopped_mono_s"]
    if t1 - t0 < meta["analysis_duration_s"]:
        miss.append(f"traced {t1 - t0:.1f}s < analysis_duration_s {meta['analysis_duration_s']}")
    pr = meta.get("probes") or {}
    st, fi = pr.get("start"), pr.get("final")
    if st is None:
        miss.append("no start probe (PID reuse cannot be excluded)")
    if fi is None:
        miss.append("no final probe")
    if st is not None and fi is not None:
        if st["pid"] != fi["pid"]:
            return "INCONSISTENT", [f"start probe pid {st['pid']} != final probe pid {fi['pid']}"]
        if st["starttime_ticks"] != fi["starttime_ticks"]:
            return "INCONSISTENT", [f"process start time changed between probes ({st['starttime_ticks']} -> {fi['starttime_ticks']}): PID reused"]
        if fi["pid"] != main_pid:
            return "INCONSISTENT", [f"probed pid {fi['pid']} is not the traced main pid {main_pid}"]
        if not (t0 <= st["mono_s"] <= t0 + START_PROBE_MAX_DELAY_S):
            miss.append("start probe not taken within the first seconds of the trace")
        if st["state"] not in ALIVE_STATES:
            miss.append(f"start probe state {st['state']!r} is not a live state")
        if not (t0 <= fi["mono_s"] <= t1):
            miss.append("final probe time outside the trace window")
        elif t1 - fi["mono_s"] > PROBE_MAX_AGE_S:
            miss.append(f"final probe is {t1 - fi['mono_s']:.1f}s older than the stop (> {PROBE_MAX_AGE_S}s)")
        if fi["mono_s"] < st["mono_s"]:
            miss.append("final probe earlier than the start probe")
        if fi["state"] not in ALIVE_STATES:
            miss.append(f"final probe state {fi['state']!r} is not a live state")
    inc, gap = _binding(meta, st, fi, sc)
    if inc:
        return "INCONSISTENT", inc
    miss += gap
    if miss:
        return "MISSING", miss
    return "PROVEN", [f"window elapsed ({t1 - t0:.1f}s >= {meta['analysis_duration_s']}s); pid {main_pid} start time {fi['starttime_ticks']} state {fi['state']} "
                      f"{t1 - fi['mono_s']:.1f}s before the stop"]


# ----------------------------------------------------------------------------------------------------------------- classify
def classify(strace_text, meta=None, failure_reason=None, task_id=None, log_sha256=None):
    if failure_reason is not None:
        k = "INFRA_TIMEOUT" if INFRA_TIMEOUT_RE.search(failure_reason) else "INFRA_FAILURE"
        return _res(k, [f"failure_reason: {failure_reason[:120]}"])
    if strace_text is None:
        return _res("LOG_MISSING", ["strace.log absent"])
    if not strace_text.strip():
        return _res("LOG_MISSING", ["strace.log empty"])
    try:
        ev, pending, tail_dropped = parse(strace_text)
    except _Bad as b:
        return _res("LOG_INVALID", [str(b)])
    flags = ["TRUNCATED_TAIL"] if tail_dropped else []
    if not ev:
        return _res("UNKNOWN_INCOMPLETE", ["no complete line in the log"], flags)
    first = ev[0]
    fe = first if (first["kind"] in ("call", "unfinished") and first["name"] == "execve" and first["args"].startswith('"./exec"')) else None
    if fe is None:
        return _res("LOG_INVALID", [f"first event is not the exec of ./exec: line {first['n']}: {first['body'][:80]!r}"], flags)
    main = first["pid"]
    res_ev = first
    if first["kind"] == "unfinished":
        res_ev = next((e for e in ev[1:] if e["pid"] == main and e["kind"] == "call" and e.get("resumed") and e["name"] == "execve"), None)
        if res_ev is None:
            return _res("UNKNOWN_INCOMPLETE", ["exec of ./exec never completed in the log"], flags, main)
    if res_ev["ret"] != "0":
        em = ERRNO_AT_END.match(res_ev["rest"])
        err = em["err"] if em else ""
        k = {"ENOEXEC": "EXEC_FORMAT_ERROR", "ENOENT": "EXEC_NOT_FOUND", "EACCES": "EXEC_PERMISSION_DENIED"}.get(err, "EXEC_FAILED")
        return _res(k, [f"execve ./exec = {res_ev['ret']} {err}".strip()], flags, main)
    mine = [e for e in ev if e["pid"] == main]
    end = None
    for i, e in enumerate(mine):
        if e["kind"] in ("exited", "killed"):
            end = (i, e)
            break
        if e["kind"] == "call" and e["name"] == "exit_group" and e["ret"] == "?" and re.fullmatch(r"\d+", e["args"].strip()):
            end = (i, {"kind": "exited", "code": int(e["args"]), "exit_group_only": True, "n": e["n"]})
            break
    if end is not None:
        i, e = end
        later = mine[i + 1:]
        if e.get("exit_group_only"):
            if later and not (len(later) == 1 and later[0]["kind"] == "exited" and later[0]["code"] == e["code"]):
                return _res("LOG_INVALID", [f"events of main pid {main} after exit_group({e['code']}) that are not the matching exit line"], flags, main)
            if later:
                e = {"kind": "exited", "code": e["code"], "n": later[0]["n"]}
                end = (i, e)
        elif later:
            return _res("LOG_INVALID", [f"events of main pid {main} after its end (line {e['n']})"], flags, main)
    others = {x["pid"] for x in ev} - {main}
    if others:
        flags.append("CHILDREN_SEEN")
    streams = _written_streams(mine)
    meta_ok, meta_why = (validate_meta(meta) if meta is not None else (False, "absent"))
    if meta is not None and not meta_ok:
        flags.append("META_INVALID")
    if meta_ok:
        # metadata that belongs to another task or to another log is a contradiction whatever the log says
        if task_id is not None and meta["task_id"] != task_id:
            return _res("INCONSISTENT_EVIDENCE", [f"meta task_id {meta['task_id']!r} != task {task_id!r}"], flags, main)
        if meta.get("strace_log_sha256") is not None and log_sha256 is not None and meta["strace_log_sha256"] != log_sha256:
            return _res("INCONSISTENT_EVIDENCE", ["meta strace_log_sha256 does not match the log that is being classified"], flags, main)

    if end is None:
        if tail_dropped:
            tail = strace_text.rsplit("\n", 1)[-1]
            if open_call_tail(tail, ev[-1]["ts"]):
                flags.append("TAIL_OPEN_SYSCALL")
            else:
                return _res("UNKNOWN_INCOMPLETE", ["no exit evidence; the log ends inside an unterminated line (dropped)"], flags, main)
        verdict, why = _timeout_proof(meta, main, task_id, log_sha256)
        if verdict == "PROVEN":
            return _res("SAMPLE_TIMEOUT", why, flags, main)
        if verdict == "INCONSISTENT":
            return _res("INCONSISTENT_EVIDENCE", why, flags, main)
        return _res("UNKNOWN_INCOMPLETE", ["no exit evidence for the main pid", "timeout NOT proven: " + "; ".join(why)], flags, main)

    i, e = end
    if e["kind"] == "killed":
        sig = e["sig"]
        sdel = [x for x in mine[:i] if x["kind"] == "signal" and x["sig"] == sig]
        info = sdel[-1]["info"] if sdel else ""
        if sdel:
            flags.append("SIGNAL_DELIVERY_SEEN")
        code = SI_CODE.search(info)
        code = code["code"] if code else None
        sent = code in SENT_CODES
        sp = SI_PID.search(info)
        if sent and sp and int(sp["pid"]) == main:
            flags.append("SELF_SENT")
        if meta_ok and meta.get("sample_signal_sent") is not None:
            ms = meta["sample_signal_sent"]
            bound = ms["signal"] == sig and ms["target_pid"] == main and ms["result"] == "sent"      # task/log binding was enforced above
            if bound and task_id is not None:
                return _res("STOPPED_BY_SANDBOX", [f"{sig} sent by the worker to pid {main} (result {ms['result']}) at {ms['mono_s']}; the main pid was killed by it"],
                            flags, main)
            flags.append("SANDBOX_SIGNAL_RECORD_NOT_APPLICABLE")
        if code is not None and KERNEL_SI_CODE.match(code):
            return _res("CRASHED", [f"killed by {sig}, si_code {code} (kernel-generated)"], flags, main)
        if code is None:
            flags.append("SIGNAL_SOURCE_UNVERIFIED")
        if not sdel:
            flags.append("DELIVERY_LINE_ABSENT")
        return _res("KILLED_BY_SIGNAL", [f"killed by {sig}" + (f", si_code {code}" if code else ", no delivery line with a source")], flags, main)

    code = e["code"]
    if e.get("exit_group_only"):
        flags.append("EXIT_LINE_ONLY")
    if code == 0:
        return _res("EXITED_0", ["exit 0"], flags, main)
    ev_txt = [f"exit {code}"]
    for rx in LOADER_MSG:
        mm = next((r for r in (rx.search(streams[fd]) for fd in (2, 1)) if r), None)      # each stream on its own; fd 2 first
        if mm:
            flags.append("LOADER_ERROR_REPORTED")
            ev_txt.append(f"the sample wrote a loader-style message naming {mm['lib']} (a claim by the traced process, not verified)")
            lib = mm["lib"]
            failed = any(x["kind"] == "call" and x["name"] in ("open", "openat") and "ENOENT" in x["rest"] and lib in x["args"] for x in mine)
            if failed:
                flags.append("LIB_LOOKUP_FAILED_SAME_NAME")
            break
    if "LOADER_ERROR_REPORTED" not in flags and any(x["kind"] == "call" and x["name"] in ("open", "openat") and "ENOENT" in x["rest"]
                                                    and re.search(r"\.so[.0-9]*\"", x["args"]) for x in mine):
        flags.append("LIB_LOOKUP_ENOENT_SEEN")
    return _res("EXITED_NONZERO", ev_txt, flags, main)


# =================================================================================================================== collector (P0, worker side)
# Everything below is I/O-light glue around the pure classifier above. Nothing here raises into the analysis path: callers get (value, error) pairs.
import hashlib
import json
import os
import tempfile
import time
import uuid

TRACE_META_FILE = "trace-meta.json"
EXEC_CLASS_FILE = "execution-class.json"
EXEC_CLASS_SCHEMA = "ct04-execution-class/1"
PROBE_WAIT_S = 10


def probe_command(trace_id):
    """One guest command. The markers are built with a quoted fragment so that the literal marker text never appears in the echoed command line
    (the console echoes input; waiting on the marker would otherwise match the echo)."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", trace_id):
        raise ValueError("trace_id must be [A-Za-z0-9-]{1,64}")
    return ('echo CT04-PROBE-"BEGIN" %s; echo CT04-STRACE-"PID" $(cat strace_pid); cat /proc/[0-9]*/stat 2>/dev/null; echo CT04-PROBE-"END" %s'
            % (trace_id, trace_id))


def probe_end_pattern(trace_id):
    return r"\r*\nCT04-PROBE-END " + re.escape(trace_id) + r"\r*\n"


def _stat_full(line):
    m = STAT_RAW.match(line.strip())
    if not m:
        return None
    rest = m["rest"].split(" ")
    if len(rest) < 19 or not rest[0].lstrip("-").isdigit() or not rest[18].isdigit():
        return None
    return {"pid": int(m["pid"]), "comm": m["comm"], "state": m["state"], "ppid": int(rest[0]), "starttime": int(rest[18]), "raw": line.strip()}


def parse_probe_output(text, trace_id):
    """-> (result, error). result = {"strace_pid": int, "procs": [stat dicts]} taken from between the markers of THIS trace only."""
    if not isinstance(text, str):
        return None, "probe output is not text"
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    begin = "CT04-PROBE-BEGIN " + trace_id
    end = "CT04-PROBE-END " + trace_id
    lines = t.split("\n")
    try:
        b = max(i for i, l in enumerate(lines) if l.strip() == begin)
    except ValueError:
        return None, "begin marker not found"
    e = next((i for i in range(b + 1, len(lines)) if lines[i].strip() == end), None)
    if e is None:
        return None, "end marker not found"
    body = lines[b + 1:e]
    spid = None
    procs = []
    for l in body:
        if l.startswith("CT04-STRACE-PID "):
            v = l[len("CT04-STRACE-PID "):].strip()
            if not v.isdigit():
                return None, "strace pid is not a number"
            spid = int(v)
        elif l.strip():
            s = _stat_full(l)
            if s is not None:
                procs.append(s)
    if spid is None:
        return None, "strace pid line missing"
    return {"strace_pid": spid, "procs": procs}, None


def select_sample(result):
    """-> (probe fields or None, error). The traced sample is the single process whose parent is the strace process. None + no error = no such process (gone)."""
    cands = [p for p in result["procs"] if p["ppid"] == result["strace_pid"] and p["pid"] != result["strace_pid"]]
    if not cands:
        return None, None
    if len(cands) > 1:
        return None, "ambiguous: %d processes have the strace process as parent" % len(cands)
    return cands[0], None


def stop_check_command(trace_id):
    """One guest command that reports, with the exit status of EVERY read, whether the strace process is gone. Silence is never an answer: the worker needs
    the pid file status, the pid text, the stat read status and text, the /proc/<pid> existence test and a kill -0 status. The pid is used only if it is
    purely numeric (the sample can overwrite strace_pid, it is guest-controlled)."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", trace_id):
        raise ValueError("trace_id must be [A-Za-z0-9-]{1,64}")
    return ('echo CT04-STOP-"BEGIN" %s; P=$(cat strace_pid 2>/dev/null); R=$?; echo CT04-PIDFILE rc=$R pid=[$P]; '
            'case "$P" in ""|*[!0-9]*) echo CT04-TARGET invalid;; '
            '*) S=$(cat /proc/$P/stat 2>/dev/null); R=$?; echo CT04-STAT rc=$R; echo CT04-STATRAW "[$S]"; '
            '[ -d /proc/$P ]; echo CT04-DIR rc=$?; kill -0 $P 2>/dev/null; echo CT04-KILL0 rc=$?;; esac; '
            'echo CT04-STOP-"END" %s' % (trace_id, trace_id))


def stop_check_end_pattern(trace_id):
    return r"\r*\nCT04-STOP-END " + re.escape(trace_id) + r"\r*\n"


def extract_stop_body(text, trace_id):
    """-> (body between the markers of THIS trace, error). Both markers are required."""
    if not isinstance(text, str):
        return "", "not text"
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    try:
        b = max(i for i, l in enumerate(lines) if l.strip() == "CT04-STOP-BEGIN " + trace_id)
    except ValueError:
        return "", "begin marker not found"
    e = next((i for i in range(b + 1, len(lines)) if lines[i].strip() == "CT04-STOP-END " + trace_id), None)
    if e is None:
        return "\n".join(lines[b + 1:])[:2000], "end marker not found"
    return "\n".join(lines[b + 1:e])[:2000] + "\n", None


def judge_stop_check(console_text, trace_id, expected_pid, baseline_starttime, mono_s):
    """-> the stop_check record stored in the metadata (raw answer, every rc, target pid, verdict). Never raises."""
    body, err = extract_stop_body(console_text, trace_id)
    if err:
        r = {"verdict": "unknown", "reason": "answer incomplete: " + err, "target_pid": None, "rcs": {"pidfile": None, "stat": None, "dir": None, "kill0": None}}
    else:
        r = parse_stop_envelope(body, expected_pid, baseline_starttime)
    return {"mono_s": mono_s, "verdict": r["verdict"], "reason": r["reason"][:300], "raw": body[:2000], "rcs": r["rcs"], "target_pid": r["target_pid"],
            "expected_pid": expected_pid, "baseline_starttime": baseline_starttime}


class TraceRecorder:
    """Collects the metadata that the classifier needs. The caller owns the clock calls (worker monotonic clock)."""

    def __init__(self, task_id, analysis_duration_s, clock=time.monotonic, trace_id=None):
        self.task_id = str(task_id)
        self.trace_id = trace_id or uuid.uuid4().hex
        self.duration = int(analysis_duration_s)
        self.clock = clock
        self.started_at = None
        self.stopped_at = None
        self.probes = {"start": None, "final": None}
        self.probe_errors = []
        self.signal_sent = None
        self.strace_pid = None            # from the probes: the pid the guest's strace_pid file held
        self.strace_starttime = None      # start time (ticks) of that strace process, the baseline that lets a zombie be recognised as the same process
        self.stop_check = None

    def started(self):
        self.started_at = self.clock()

    def stopping(self):
        """Call immediately BEFORE the command that stops the trace is sent."""
        self.stopped_at = self.clock()

    def probe_command(self):
        return probe_command(self.trace_id)

    def add_probe(self, which, console_text):
        """Parse the console text of one probe. Records either a probe or an error; never raises."""
        t = self.clock()
        try:
            res, err = parse_probe_output(console_text, self.trace_id)
            if err:
                self.probe_errors.append("%s: %s" % (which, err))
                return None
            sel, err = select_sample(res)
            if err:
                self.probe_errors.append("%s: %s" % (which, err))
                return None
            if sel is None:
                self.probe_errors.append("%s: no process with the strace process as parent (sample not running)" % which)
                return None
            rec = {"mono_s": t, "pid": sel["pid"], "starttime_ticks": sel["starttime"], "state": sel["state"], "raw": sel["raw"],
                   "strace_pid": res["strace_pid"]}
            self.strace_pid = res["strace_pid"]
            own = [p for p in res["procs"] if p["pid"] == res["strace_pid"]]
            if len(own) == 1:
                self.strace_starttime = own[0]["starttime"]
                rec["strace_starttime_ticks"] = own[0]["starttime"]
            self.probes[which] = rec
            return rec
        except Exception as e:                                       # noqa: BLE001
            self.probe_errors.append("%s: collector error %r" % (which, e))
            return None

    def meta(self, stop_reason):
        stopped = self.stopped_at if self.stopped_at is not None else self.clock()
        started = self.started_at if self.started_at is not None else stopped
        return {"schema": META_SCHEMA, "task_id": self.task_id, "trace_id": self.trace_id, "analysis_duration_s": self.duration,
                "trace_started_mono_s": started, "trace_stopped_mono_s": stopped, "stop_reason": stop_reason,
                "strace_log_sha256": None, "probes": dict(self.probes), "sample_signal_sent": self.signal_sent,
                "stop_check": self.stop_check, "collected_mono_s": self.clock(), "probe_errors": list(self.probe_errors)}


def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=True, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_meta(task_dir, meta):
    """-> error text or None."""
    try:
        _atomic_write_json(os.path.join(task_dir, TRACE_META_FILE), meta)
        return None
    except Exception as e:                                           # noqa: BLE001
        return "cannot write %s: %r" % (TRACE_META_FILE, e)


def _read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def finalize_meta(task_dir):
    """Bind the metadata to the strace.log that is actually in the task directory (sha256 of its bytes). -> (meta or None, error or None)."""
    raw = _read_bytes(os.path.join(task_dir, TRACE_META_FILE))
    if raw is None:
        return None, "no %s" % TRACE_META_FILE
    try:
        meta = json.loads(raw.decode("utf-8"))
        if not isinstance(meta, dict):
            return None, "%s is not an object" % TRACE_META_FILE
    except (ValueError, UnicodeDecodeError) as e:
        return None, "%s unreadable: %r" % (TRACE_META_FILE, e)
    log = _read_bytes(os.path.join(task_dir, "strace.log"))
    meta["strace_log_sha256"] = hashlib.sha256(log).hexdigest() if log is not None else None
    err = write_meta(task_dir, meta)
    return (None, err) if err else (meta, None)


def classify_task(task_dir, task_id, failure_reason=None):
    """Classify one finished task from the files in its directory. NEVER raises: any internal error is UNKNOWN_INCOMPLETE with the reason as evidence.
    Writes execution-class.json next to the result files (so it is inside the ZIP). -> result dict."""
    try:
        log_raw = _read_bytes(os.path.join(task_dir, "strace.log"))
        log_text = None if log_raw is None else log_raw.decode("utf-8", errors="replace")
        meta, ferr = finalize_meta(task_dir)
        res = classify(log_text, meta, failure_reason=failure_reason, task_id=str(task_id),
                       log_sha256=(hashlib.sha256(log_raw).hexdigest() if log_raw is not None else None))
        if ferr and "META_UNAVAILABLE" not in res["flags"]:
            res["flags"].append("META_UNAVAILABLE")
            res["evidence"].append("metadata: " + ferr)
    except Exception as e:                                           # noqa: BLE001
        res = _res("UNKNOWN_INCOMPLETE", ["classifier error: %r" % (e,)], ["CLASSIFIER_ERROR"])
    # the report is bounded to the manager's contract (<= 10 evidence strings of <= 200 chars, <= 20 flags of [A-Z0-9_]{1,48})
    out = {"schema": EXEC_CLASS_SCHEMA, "task_id": str(task_id), "execution_class": res["klass"],
           "evidence": [str(x)[:200] for x in res["evidence"][:10]],
           "flags": [f for f in res["flags"] if isinstance(f, str) and re.fullmatch(r"[A-Z0-9_]{1,48}", f)][:20],
           "main_pid": res.get("main_pid") if _int(res.get("main_pid")) and res.get("main_pid") > 0 else None}
    try:
        _atomic_write_json(os.path.join(task_dir, EXEC_CLASS_FILE), out)
    except Exception as e:                                           # noqa: BLE001
        out["flags"] = out["flags"] + ["RESULT_FILE_NOT_WRITTEN"]
        out["evidence"] = out["evidence"] + ["cannot write %s: %r" % (EXEC_CLASS_FILE, e)]
    return out
