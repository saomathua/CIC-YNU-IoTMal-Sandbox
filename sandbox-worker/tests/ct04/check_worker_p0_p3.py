"""Offline tests for P0 (collector/classifier module), P1 (analysis.py collector hooks), P2/P3 (poller classification + upload).
usage: python3 -I -B tests/check_worker_p0_p3.py <base_worker_dir> <proposed_worker_dir>
The base worker tree (repo `sandbox-worker/`) is copied to a temp dir and the proposed files are laid over it. No pytest: plain asserts, exit 0 = all OK.
Uses the REAL /bin/sh and the REAL /proc of this machine for the probe collector (no emulation of /proc), and fakes only the guest console, tshark and manager."""
import hashlib
import importlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

W = tempfile.mkdtemp(prefix="ct04-stage-") + "/sandbox-worker"
shutil.copytree(os.path.abspath(sys.argv[1]), W, ignore=shutil.ignore_patterns("__pycache__", "tests", "ARM", "MIPS", "MIPSEL", "x86"))
for root, _d, files in os.walk(os.path.abspath(sys.argv[2])):
    for f in files:
        if f.endswith(".pyc"):
            continue
        src = os.path.join(root, f)
        dst = os.path.join(W, os.path.relpath(src, os.path.abspath(sys.argv[2])))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(src, dst)
sys.path.insert(0, W)
os.environ.update({"PORT": "8011", "APP_BASE_URL": "/api/v1/sandbox-worker", "SANDBOX_MANAGER_URI": "http://manager.invalid/api/v1/sandbox-manager",
                   "ANALYSIS_DURATION": "3", "POST_ANALYSIS_WAIT": "0"})
from service import execution_class as xc          # noqa: E402
from service import analysis as an                 # noqa: E402
import poller                                      # noqa: E402

RESULTS = []


def ok(name, cond, extra=""):
    RESULTS.append((name, bool(cond)))
    print(("[OK]   " if cond else "[FAIL] ") + name + ((" " + str(extra)) if (extra and not cond) else ""))


def meta_of(td):
    try:
        return json.load(open(os.path.join(td, "trace-meta.json")))
    except (OSError, ValueError):
        return {"stop_reason": None, "probes": {"start": None, "final": None}, "probe_errors": [], "_missing": True}


def sent_class(kw):
    try:
        return json.loads(kw["data"]["execution_class"])
    except Exception:                                  # noqa: BLE001
        return {"execution_class": None, "flags": [], "task_id": None, "schema": None}


def tmp():
    return tempfile.mkdtemp(prefix="ct04-")


# ------------------------------------------------------------------ P0: collector against the real shell and the real /proc
def run_probe_cmd(cmd, workdir):
    r = subprocess.run(["/bin/sh", "-c", cmd], cwd=workdir, capture_output=True, text=True, timeout=20)
    return r.stdout


def run_probe(trace_id, workdir):
    r = subprocess.run(["/bin/sh", "-c", xc.probe_command(trace_id)], cwd=workdir, capture_output=True, text=True, timeout=20)
    return r.stdout


def children_of(pid):
    out = []
    for n in os.listdir("/proc"):
        if n.isdigit():
            try:
                st = open("/proc/%s/stat" % n).read()
            except OSError:
                continue
            if int(st.rsplit(") ", 1)[1].split(" ")[1]) == pid:
                out.append(int(n))
    return out


def fake_strace(n_children, comm_path):
    """A parent shell that plays 'strace': its children are the traced sample(s). -> (parent Popen, [child pids])"""
    env = dict(os.environ, S=comm_path)
    cmd = " ".join(['"$S" 30 &'] * n_children) + " wait"
    par = subprocess.Popen(["/bin/sh", "-c", cmd], env=env)
    for _ in range(50):
        time.sleep(0.1)
        kids = [k for k in children_of(par.pid)]
        if len(kids) >= n_children:
            break
    return par, kids


d = tmp()
sleeper = os.path.join(d, "x) Z 1 (y")                 # adversarial comm: looks like the end of the comm field and a state
shutil.copy("/bin/sleep", sleeper)
par, kids = fake_strace(1, sleeper)
child_pid = kids[0]
open(os.path.join(d, "strace_pid"), "w").write(str(par.pid) + "\n")
out = run_probe("trace-abc", d)
res, err = xc.parse_probe_output(out, "trace-abc")
ok("C1 real probe output parses between the markers", res is not None and err is None, err)
sel, err = xc.select_sample(res)
ok("C2 the single child of the 'strace' pid is selected", sel is not None and sel["pid"] == child_pid and err is None, (sel, err))
with open("/proc/%d/stat" % child_pid) as f:
    want = f.read().strip()
ok("C3 raw probe line equals the kernel's /proc/<pid>/stat", sel is not None and sel["raw"].split(" ")[0] == want.split(" ")[0] and sel["state"] == want.rsplit(") ", 1)[1].split(" ")[0])
ok("C4 adversarial comm with ') Z 1 (' keeps the real state and pid", sel is not None and sel["state"] == "S" and sel["comm"].startswith("x) Z 1 ("), sel)
echoed = "root@OpenWrt:/# " + xc.probe_command("trace-abc") + "\r\n" + out.replace("\n", "\r\n")
ok("C5 the echoed command alone does NOT satisfy the end-marker pattern", __import__("re").search(xc.probe_end_pattern("trace-abc"), "root@OpenWrt:/# " + xc.probe_command("trace-abc") + "\r\n") is None)
_cmd = "root@OpenWrt:/# " + xc.probe_command("trace-abc")
_hit = None
for _w in range(5, 121):                                 # a console / line editor that wraps the echoed command at any width and phase
    for _off in range(_w):
        _wrapped = _cmd[:_off] + "".join("\r\n" + _cmd[i:i + _w] for i in range(_off, len(_cmd), _w)) + "\r\n"
        if __import__("re").search(xc.probe_end_pattern("trace-abc"), _wrapped):
            _hit = (_w, _off)
            break
    if _hit:
        break
ok("C5b no wrapping (width 5..120, any phase) of the echoed command satisfies the end-marker pattern", _hit is None, _hit)
ok("C6 the end-marker pattern matches the real output", __import__("re").search(xc.probe_end_pattern("trace-abc"), echoed) is not None)
res2, err2 = xc.parse_probe_output(echoed, "trace-abc")
ok("C7 parse works on echoed + CRLF console text", res2 is not None and xc.select_sample(res2)[0] is not None and xc.select_sample(res2)[0]["pid"] == child_pid, err2)
res3, err3 = xc.parse_probe_output(out, "trace-other")
ok("C8 markers of another trace are not accepted", res3 is None and "begin marker" in err3)
open(os.path.join(d, "strace_pid"), "w").write(str(os.getpid() + 7777) + "\n")
res4, _ = xc.parse_probe_output(run_probe("trace-abc", d), "trace-abc")
ok("C9 no process has the strace pid as parent => 'gone' (None, no error)", xc.select_sample(res4) == (None, None))
par2, kids2 = fake_strace(2, "/bin/sleep")
open(os.path.join(d, "strace_pid"), "w").write(str(par2.pid) + "\n")
res5, _ = xc.parse_probe_output(run_probe("trace-abc", d), "trace-abc")
sel5, err5 = xc.select_sample(res5)
ok("C10 two children of the strace pid => ambiguous, nothing selected", sel5 is None and err5 and "ambiguous" in err5, (sel5, err5))
os.remove(os.path.join(d, "strace_pid"))
res6, err6 = xc.parse_probe_output(run_probe("trace-abc", d), "trace-abc")
ok("C11 missing strace_pid file => error", res6 is None and "strace pid" in err6, (res6, err6))
try:
    xc.probe_command("bad id; rm -rf /")
    ok("C12 trace_id is restricted to [A-Za-z0-9-]", False)
except ValueError:
    ok("C12 trace_id is restricted to [A-Za-z0-9-]", True)
par2.kill()
par2.wait()


# ---- real trace-stop check: alive / zombie / missing and hostile pid files, with the real shell ----
dd = tmp()
sl = subprocess.Popen(["/bin/sleep", "30"])
open(os.path.join(dd, "strace_pid"), "w").write("%d\n" % sl.pid)
o = run_probe_cmd(xc.stop_check_command("trace-s"), dd)
j = xc.judge_stop_check(o, "trace-s", sl.pid, None, 1.0)
ok("C13 real: live process => alive (never gone)", j["verdict"] == "alive" and j["rcs"]["stat"] == 0, j)
sh = subprocess.Popen(["/bin/sh", "-c", "sleep 0.4"])
time.sleep(0.1)
base_st = int(open("/proc/%d/stat" % sh.pid).read().rsplit(") ", 1)[1].split(" ")[19])
time.sleep(0.8)                                          # exited, NOT reaped: a zombie
open(os.path.join(dd, "strace_pid"), "w").write("%d\n" % sh.pid)
oz = run_probe_cmd(xc.stop_check_command("trace-s"), dd)
jz = xc.judge_stop_check(oz, "trace-s", sh.pid, base_st, 1.0)
ok("C14 real: unreaped exited child with the right start-time baseline => zombie", jz["verdict"] == "zombie", jz)
jz2 = xc.judge_stop_check(oz, "trace-s", sh.pid, base_st + 1, 1.0)
ok("C15 real: same zombie but a different baseline start time => not accepted", jz2["verdict"] == "unknown", jz2)
sh.wait()
oz2 = run_probe_cmd(xc.stop_check_command("trace-s"), dd)
jg = xc.judge_stop_check(oz2, "trace-s", sh.pid, base_st, 1.0)
ok("C16 real: reaped process => gone, every rc 1", jg["verdict"] == "gone" and jg["rcs"] == {"pidfile": 0, "stat": 1, "dir": 1, "kill0": 1}, jg)
os.remove(os.path.join(dd, "strace_pid"))
jm = xc.judge_stop_check(run_probe_cmd(xc.stop_check_command("trace-s"), dd), "trace-s", 123, None, 1.0)
ok("C17 real: missing pid file => unknown (not gone)", jm["verdict"] == "unknown" and jm["rcs"]["pidfile"] == 1, jm)
open(os.path.join(dd, "strace_pid"), "w").write("1;touch INJECTED\n")
ji = xc.judge_stop_check(run_probe_cmd(xc.stop_check_command("trace-s"), dd), "trace-s", 123, None, 1.0)
ok("C18 real: hostile pid file is not executed and is unknown", ji["verdict"] == "unknown" and not os.path.exists(os.path.join(dd, "INJECTED")), ji)
open(os.path.join(dd, "strace_pid"), "w").write("12 34\n")
ji2 = xc.judge_stop_check(run_probe_cmd(xc.stop_check_command("trace-s"), dd), "trace-s", 123, None, 1.0)
ok("C19 real: pid file with two numbers => unknown", ji2["verdict"] == "unknown", ji2)
sl.kill()
sl.wait()
cut = o.split("CT04-KILL0")[0]
ok("C19b real: an answer cut before the last lines => unknown", xc.judge_stop_check(cut, "trace-s", sl.pid, None, 1.0)["verdict"] == "unknown")

# ------------------------------------------------------------------ P0: recorder + classify_task end to end with a REAL probe
open(os.path.join(d, "strace_pid"), "w").write(str(par.pid) + "\n")
clock_t = [1000.0]
clk = lambda: clock_t[0]                           # noqa: E731
rec = xc.TraceRecorder("task-p0", 3, clock=clk, trace_id="trace-p0")
rec.started()
clock_t[0] = 1000.6
p_start = rec.add_probe("start", run_probe("trace-p0", d))
clock_t[0] = 1003.2
p_final = rec.add_probe("final", run_probe("trace-p0", d))
rec.stopping()
# the REAL trace-stop check against the REAL shell/proc: kill the fake strace, reap it, then ask
par.kill()
par.wait()
clock_t[0] = 1003.4
stop_out = run_probe_cmd(xc.stop_check_command("trace-p0"), d)
rec.stop_check = xc.judge_stop_check(stop_out, "trace-p0", rec.strace_pid, rec.strace_starttime, clk())
ok("C20 real stop check of a killed+reaped process => gone with every rc recorded", rec.stop_check["verdict"] == "gone" and rec.stop_check["rcs"] == {"pidfile": 0, "stat": 1, "dir": 1, "kill0": 1},
   (rec.stop_check, stop_out))
td = os.path.join(d, "task")
os.makedirs(td)
ok("P0-1 recorder stored both probes", p_start is not None and p_final is not None and rec.probe_errors == [], rec.probe_errors)
ok("P0-2 write_meta ok", xc.write_meta(td, rec.meta("window_elapsed")) is None)
spid = p_final["pid"]
LOG = ('%d  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = 0 <0.001000>\n'
       '%d  10:00:00.020000 nanosleep({tv_sec=3600, tv_nsec=0},  <unfinished ...>\n') % (spid, spid)
open(os.path.join(td, "strace.log"), "w").write(LOG)
r = xc.classify_task(td, "task-p0")
ok("P0-3 real probes + unfinished sleep + bound log => SAMPLE_TIMEOUT", r["execution_class"] == "SAMPLE_TIMEOUT", r)
ok("P0-4 execution-class.json written next to the log", json.load(open(os.path.join(td, xc.EXEC_CLASS_FILE)))["execution_class"] == "SAMPLE_TIMEOUT")
meta_now = json.load(open(os.path.join(td, xc.TRACE_META_FILE)))
ok("P0-5 metadata is bound to the log bytes", meta_now["strace_log_sha256"] == hashlib.sha256(LOG.encode()).hexdigest())
ok("P0-6 same files, different task id => INCONSISTENT_EVIDENCE", xc.classify(LOG, meta_now, task_id="task-other", log_sha256=meta_now["strace_log_sha256"])["klass"] == "INCONSISTENT_EVIDENCE")
ok("P0-7 log changed after binding => INCONSISTENT_EVIDENCE", xc.classify(LOG + "x", meta_now, task_id="task-p0", log_sha256=hashlib.sha256((LOG + "x").encode()).hexdigest())["klass"] == "INCONSISTENT_EVIDENCE")
os.remove(os.path.join(td, "strace.log"))
r2 = xc.classify_task(td, "task-p0")
ok("P0-8 strace.log missing => LOG_MISSING (never a timeout)", r2["execution_class"] == "LOG_MISSING", r2)
open(os.path.join(td, "trace-meta.json"), "w").write("{not json")
open(os.path.join(td, "strace.log"), "w").write(LOG)
r3 = xc.classify_task(td, "task-p0")
ok("P0-9 corrupt metadata => UNKNOWN_INCOMPLETE + META_UNAVAILABLE", r3["execution_class"] == "UNKNOWN_INCOMPLETE" and "META_UNAVAILABLE" in r3["flags"], r3)
r4 = xc.classify_task(os.path.join(d, "does-not-exist"), "t")
ok("P0-10 missing task dir never raises", r4["execution_class"] == "LOG_MISSING" and "RESULT_FILE_NOT_WRITTEN" in r4["flags"], r4)

# ------------------------------------------------------------------ P1: analysis._run_analysis with a fake guest console and a fake tshark
class Violation(BaseException):
    """Raised by the fake console when the code under test uses a console it has already seen fail."""


class Console:
    """Fake guest console. Records every command; answers probes from `state`; can be told to fail the expect that follows a command (timeout=0 / EOF=2)."""
    def __init__(self, state):
        self.cmds, self.before, self.after, self.state, self.logfile = [], "", "", state, None
        self.fail = []                 # [[substring of the last command, 0|2, skip]]  -> the next expect returns that index (and the console is "lost" from then on)
        self.lost_at = None            # len(cmds) when the console failed
        self.no_prompt_after_probe = 0      # n: the prompt that should follow the n-th probe never arrives
        self.probes_seen = 0
        self._probe_answered = False
        self.strace_after_kill = "gone"

    def sendline(self, line=""):
        if self.lost_at is not None:
            raise Violation("COMMAND SENT AFTER THE CONSOLE WAS LOST: %r" % line)
        self.cmds.append(line)

    def _lose(self, idx):
        self.lost_at = len(self.cmds)
        self.before = self.after = ""
        return idx

    def expect(self, patterns, timeout=None):
        last = self.cmds[-1] if self.cmds else ""
        if self.lost_at is not None:
            raise Violation("EXPECT AFTER THE CONSOLE WAS LOST")
        marker_expect = any(isinstance(x, str) and ("CT04-PROBE-END" in x or "CT04-STOP-END" in x) for x in patterns)
        for ent in self.fail:
            if ent[0] in last and (marker_expect or not ent[0].startswith("echo CT04-")) and not (self._probe_answered and not marker_expect):
                if ent[2] > 0:
                    ent[2] -= 1
                    continue
                self.fail.remove(ent)
                return self._lose(ent[1])
        if self._probe_answered:
            self._probe_answered = False
            self.probes_seen += 1
            if self.no_prompt_after_probe == self.probes_seen:
                return self._lose(0)
            self.before = self.after = ""
            return 1
        if last.startswith("echo CT04-PROBE-"):
            tid = last.split("BEGIN\" ")[1].split(";")[0]
            body = "CT04-PROBE-BEGIN %s\r\nCT04-STRACE-PID 41\r\n" % tid
            if self.state.get("alive", True):
                body += "%d (exec) S 41 41 41 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 1 0 777 4096 10 4294967295\r\n" % self.state["pid"]
            body += "41 (strace) S 1 41 41 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 1 0 700 4096 10 4294967295\r\n"
            self.before, self.after = "\r\n" + body, "\r\nCT04-PROBE-END %s\r\n" % tid
            self._probe_answered = True
            return 1
        if last.startswith("echo CT04-STOP-"):
            tid = last.split('BEGIN" ')[1].split(";")[0]
            st = lambda state, start=700: "41 (strace) %s 1 41 41 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 1 0 %d 4096 10 4294967295" % (state, start)     # noqa: E731
            pf = "CT04-PIDFILE rc=0 pid=[41]"
            bodies = {
                "gone": [pf, "CT04-STAT rc=1", "CT04-STATRAW []", "CT04-DIR rc=1", "CT04-KILL0 rc=1"],
                "alive": [pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("S"), "CT04-DIR rc=0", "CT04-KILL0 rc=0"],
                "zombie": [pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("Z"), "CT04-DIR rc=0", "CT04-KILL0 rc=0"],
                "zombie-other-start": [pf, "CT04-STAT rc=0", "CT04-STATRAW [%s]" % st("Z", 999), "CT04-DIR rc=0", "CT04-KILL0 rc=0"],
                "stat-permission-error": [pf, "CT04-STAT rc=1", "CT04-STATRAW []", "CT04-DIR rc=0", "CT04-KILL0 rc=0"],
                "empty": [],
                "pidfile-unreadable": ["CT04-PIDFILE rc=1 pid=[]", "CT04-TARGET invalid"],
                "pidfile-other-pid": ["CT04-PIDFILE rc=0 pid=[77]", "CT04-STAT rc=1", "CT04-STATRAW []", "CT04-DIR rc=1", "CT04-KILL0 rc=1"],
                "truncated": [pf, "CT04-STAT rc=1", "CT04-STATRAW []"],
                "tool-error": [pf, "CT04-STAT rc=127", "CT04-STATRAW []", "CT04-DIR rc=1", "CT04-KILL0 rc=1"],
            }[self.strace_after_kill]
            self.before = "\r\nCT04-STOP-BEGIN %s\r\n%s" % (tid, "".join(l + "\r\n" for l in bodies))
            self.after = "\r\nCT04-STOP-END %s\r\n" % tid
            self._probe_answered = True
            return 1
        self.before, self.after = "", ""
        return 1

    def kill(self, sig):
        pass

    def isalive(self):
        return False

    def close(self, force=True):
        pass


class FakeTshark:
    def __init__(self, *a, **k):
        self.pid = 4242

    def isalive(self):
        return False

    def kill(self, sig):
        pass

    def close(self, force=True):
        pass


def setup_analysis(task_dir):
    a = an.Analysis("task-p1", task_dir, "192.168.60.3", "192.168.60.1", "k", "r", {"worker_ip": "192.168.60.2"})
    return a


an.pexpect.spawn = FakeTshark
an.time.sleep = lambda s: None
an._STOP_FILE = os.path.join(tmp(), "stop")
Orig = an.xc.TraceRecorder
ticks = [5000.0]


def fclock():
    ticks[0] += 1.0
    return ticks[0]


an.xc.TraceRecorder = lambda tid, dur: Orig(tid, 3, clock=fclock, trace_id="trace-p1")
arch = an.ARCH_CONFIGS["ARM"]
# a) normal run: sample alive for the whole window
td1 = tmp()
c = Console({"pid": 500, "alive": True})
a = setup_analysis(td1)
os.environ["ANALYSIS_DURATION"] = "3"
an.app_settings.analysis_duration = 0           # the loop does not iterate; the fake clock supplies a 3+ s window
try:
    a._run_analysis(c, arch)
except BaseException as e_:                      # noqa: BLE001
    print("      (P1-1 run raised %r)" % (e_,))
m = meta_of(td1)
ok("P1-1 meta written with window_elapsed", m["stop_reason"] == "window_elapsed" and m["schema"] == "ct04-trace-meta/2" and m["task_id"] == "task-p1", m)
ok("P1-2 start and final probes recorded for the sample pid (not strace)", (m["probes"]["start"] or {}).get("pid") == 500 and (m["probes"]["final"] or {}).get("pid") == 500 and m["probe_errors"] == [], m)
kill_i = max([i for i, x in enumerate(c.cmds) if x.startswith("kill -9 $(cat strace_pid")] or [-1])
probe_is = [i for i, x in enumerate(c.cmds) if x.startswith("echo CT04-PROBE-")]
ok("P1-3 exactly two probes; the final one is sent before the strace kill", len(probe_is) == 2 and probe_is[1] < kill_i, (probe_is, kill_i))
ok("P1-4 metadata window is ordered start <= probes <= stop", bool(m["probes"]["start"] and m["probes"]["final"]) and m["trace_started_mono_s"] <= m["probes"]["start"]["mono_s"] <= m["probes"]["final"]["mono_s"] <= m["trace_stopped_mono_s"])
# the resulting evidence supports a timeout only with the sample alive and a matching log
LOG1 = ('500  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = 0 <0.001000>\n'
        '500  10:00:00.020000 nanosleep({tv_sec=3600, tv_nsec=0},  <unfinished ...>\n')
h1 = hashlib.sha256(LOG1.encode()).hexdigest()
r15 = xc.classify(LOG1, dict(m, strace_log_sha256=h1), task_id="task-p1", log_sha256=h1)
ok("P1-5 metadata the analysis really collected + a log of the same pid => SAMPLE_TIMEOUT", r15["klass"] == "SAMPLE_TIMEOUT", r15)
LOG_OTHER_PID = LOG1.replace("500 ", "501 ")
h2 = hashlib.sha256(LOG_OTHER_PID.encode()).hexdigest()
r15b = xc.classify(LOG_OTHER_PID, dict(m, strace_log_sha256=h2), task_id="task-p1", log_sha256=h2)
ok("P1-5b same metadata but the log's main pid differs from the probed pid => INCONSISTENT_EVIDENCE", r15b["klass"] == "INCONSISTENT_EVIDENCE", r15b)
# b) cancelled
td2 = tmp()
open(an._STOP_FILE, "w").close()
an.app_settings.analysis_duration = 5
c = Console({"pid": 500})
cancelled = False
try:
    setup_analysis(td2)._run_analysis(c, arch)
except an.AnalysisCancelled:
    cancelled = True
os.remove(an._STOP_FILE)
m2 = meta_of(td2)
ok("P1-6 cancel: AnalysisCancelled still propagates and the meta says cancelled", cancelled and m2["stop_reason"] == "cancelled", m2["stop_reason"])
ok("P1-7 cancelled run has no final probe (nothing to prove)", m2["probes"]["final"] is None)
# d) sample not running at the probe (console still in sync)
td4 = tmp()
c = Console({"pid": 500, "alive": False})
try:
    setup_analysis(td4)._run_analysis(c, arch)
except BaseException as e_:                      # noqa: BLE001
    print("      (P1-9 run raised %r)" % (e_,))
m4 = meta_of(td4)
ok("P1-9 sample not running: probes null with an explanatory error (=> never a timeout)", m4["probes"]["final"] is None and any("not running" in e for e in m4["probe_errors"]), m4["probe_errors"])
# e) meta cannot be written: analysis outcome unchanged
td5 = os.path.join(tmp(), "missing-dir")
c = Console({"pid": 500})
raised = None
try:
    setup_analysis(td5)._run_analysis(c, arch)
except BaseException as e:                       # noqa: BLE001
    raised = e
ok("P1-10 unwritable metadata directory does not make the analysis fail", raised is None, repr(raised))
# f) an exception inside the trace window: original error propagates, meta says error
td6 = tmp()


class Boom(Console):
    def sendline(self, line=""):
        super().sendline(line)
        if line.startswith("strace "):
            raise RuntimeError("console exploded")


raised = None
try:
    setup_analysis(td6)._run_analysis(Boom({"pid": 500}), arch)
except RuntimeError as e:
    raised = e
m6 = meta_of(td6)
ok("P1-11 exception in the window: the same exception propagates, meta stop_reason=error", raised is not None and "exploded" in str(raised) and m6["stop_reason"] == "error")


# ---- console loss: nothing more is sent, host cleanup still runs, the original error survives, no window_elapsed without a confirmed stop ----
stop_calls = []
_orig_stop = an.stop_capture
an.stop_capture = lambda p_, label: (stop_calls.append(label), _orig_stop(p_, label))[1]


def lost_case(name, setup, want_exc, want_text, want_reason="error", expect_cmds_after=0):
    td = tmp()
    c = Console({"pid": 500})
    setup(c)
    stop_calls.clear()
    an.app_settings.analysis_duration = 0
    raised = None
    try:
        setup_analysis(td)._run_analysis(c, arch)
    except Violation as v:
        ok(name + " [VIOLATION: " + str(v) + "]", False)
        return
    except BaseException as e:                       # noqa: BLE001
        raised = e
    m = meta_of(td)
    good = (isinstance(raised, want_exc) and want_text in str(raised) and c.lost_at in (None, len(c.cmds)) and m["stop_reason"] == want_reason
            and stop_calls.count("finalizer") == 1)
    ok(name, good, (type(raised).__name__, str(raised)[:160], c.lost_at, len(c.cmds), m["stop_reason"], stop_calls))


CL, TS = an.ConsoleLost, an.TraceStopNotConfirmed
lost_case("L1 timeout waiting for the sar prompt", lambda c: c.fail.append(["sar -o", 0, 0]), CL, "sar start")
lost_case("L2 EOF waiting for the strace-start prompt", lambda c: c.fail.append(["strace -f", 2, 0]), CL, "strace start")
lost_case("L3 timeout waiting for the strace-start prompt", lambda c: c.fail.append(["strace -f", 0, 0]), CL, "strace start")
lost_case("L4 start probe: timeout before the end marker", lambda c: c.fail.append(["echo CT04-PROBE-", 0, 0]), CL, "start probe")
lost_case("L5 start probe: EOF before the end marker", lambda c: c.fail.append(["echo CT04-PROBE-", 2, 0]), CL, "start probe")
lost_case("L6 final probe: timeout before the end marker", lambda c: c.fail.append(["echo CT04-PROBE-", 0, 1]), CL, "final probe")
lost_case("L7 final probe: EOF before the end marker", lambda c: c.fail.append(["echo CT04-PROBE-", 2, 1]), CL, "final probe")
lost_case("L8 prompt missing after the start probe", lambda c: setattr(c, "no_prompt_after_probe", 1), CL, "prompt after the start probe")
lost_case("L9 prompt missing after the final probe", lambda c: setattr(c, "no_prompt_after_probe", 2), CL, "prompt after the final probe")
lost_case("L10 timeout waiting for the prompt after ls", lambda c: c.fail.append(["ls", 0, 0]), CL, "after ls")
lost_case("L11 EOF after the strace kill is sent", lambda c: c.fail.append(["kill -9 $(cat strace_pid", 2, 0]), CL, "strace kill")
lost_case("L12 trace-stop check unanswered (timeout)", lambda c: c.fail.append(["echo CT04-STOP-", 0, 0]), CL, "trace-stop check")
lost_case("L13 trace-stop check: strace still alive after kill -9 => not confirmed", lambda c: setattr(c, "strace_after_kill", "alive"), TS, "not confirmed")


class SarKillLost(Console):
    pass


lost_case("L14 sar kill prompt lost AFTER the trace stop was confirmed: window_elapsed stays true", lambda c: c.fail.append(["kill -9 $(cat sar_pid", 0, 0]), CL, "sar kill", want_reason="window_elapsed")


def zombie(c):
    c.strace_after_kill = "zombie"


td = tmp()
cz = Console({"pid": 500})
zombie(cz)
an.app_settings.analysis_duration = 0
try:
    setup_analysis(td)._run_analysis(cz, arch)
except BaseException as e_:                      # noqa: BLE001
    print("      (L15 run raised %r)" % (e_,))
mz = meta_of(td)
ok("L15 a zombie strace counts as stopped => window_elapsed", mz["stop_reason"] == "window_elapsed")
# probe finds no sample but the console is in sync: the analysis continues (distinct from a lost console)
td = tmp()
cn = Console({"pid": 500, "alive": False})
an.app_settings.analysis_duration = 0
try:
    setup_analysis(td)._run_analysis(cn, arch)
except BaseException as e_:                      # noqa: BLE001
    print("      (L16 run raised %r)" % (e_,))
mn = meta_of(td)
ok("L16 no sample found but console in sync: analysis completes with probe errors", mn["stop_reason"] == "window_elapsed" and len(mn["probe_errors"]) == 2 and cn.lost_at is None, mn["probe_errors"])
# original error survives a cleanup failure
td = tmp()
cc = Console({"pid": 500})
cc.fail.append(["strace -f", 0, 0])
_saved = an.stop_capture


def bad_stop(p_, label):
    if label == "finalizer":
        raise an.CaptureShutdownError("tshark did not exit after SIGKILL (finalizer)")


an.stop_capture = bad_stop
raised = None
try:
    setup_analysis(td)._run_analysis(cc, arch)
except BaseException as e:                           # noqa: BLE001
    raised = e
an.stop_capture = _saved
ok("L17 console lost + capture cleanup failure: UnsafeWorkerState lists BOTH, ConsoleLost is the cause",
   isinstance(raised, an.UnsafeWorkerState) and isinstance(raised.__cause__, CL) and any(isinstance(x, CL) for x in raised.errors) and "tshark did not exit" in str(raised), (type(raised), str(raised)[:200]))

# a pty-level error keeps its own type (the reviewed CT-03 contract: the original error propagates) and the host cleanup still runs
class PtyGone(Console):
    def sendline(self, line=""):
        if line.startswith("ls"):
            raise OSError(5, "Input/output error (pty gone)")
        super().sendline(line)


td = tmp()
stop_calls.clear()
an.app_settings.analysis_duration = 0
raised = None
try:
    setup_analysis(td)._run_analysis(PtyGone({"pid": 500}), arch)
except BaseException as e:                           # noqa: BLE001
    raised = e
ok("L19 a pty OSError propagates unchanged (not rewrapped) and the finalizer ran", type(raised) is OSError and stop_calls.count("finalizer") == 1, (type(raised), stop_calls))

# ---- the trace-stop envelope: silence/read errors are never "gone" (R5) ----
def stop_case(name, kind, alive=True, want_exc=None, want_reason="error", want_verdict=None, text_in_raw=None):
    td = tmp()
    c = Console({"pid": 500, "alive": alive})
    c.strace_after_kill = kind
    stop_calls.clear()
    an.app_settings.analysis_duration = 0
    raised = None
    try:
        setup_analysis(td)._run_analysis(c, arch)
    except Violation as v:
        ok(name + " [VIOLATION %s]" % v, False)
        return
    except BaseException as e:                       # noqa: BLE001
        raised = e
    m = meta_of(td)
    sc = m.get("stop_check") or {}
    good = ((want_exc is None and raised is None) or (want_exc is not None and isinstance(raised, want_exc))) and m["stop_reason"] == want_reason \
        and (want_verdict is None or sc.get("verdict") == want_verdict) and (text_in_raw is None or text_in_raw in sc.get("raw", "")) \
        and stop_calls.count("finalizer") == 1
    ok(name, good, (type(raised).__name__, str(raised)[:140], m["stop_reason"], sc.get("verdict"), sc.get("reason")))
    return m


S_OK = "window_elapsed"
mm = stop_case("S1 gone with positive evidence confirms the stop", "gone", want_reason=S_OK, want_verdict="gone", text_in_raw="CT04-PIDFILE rc=0 pid=[41]")
ok("S1b metadata keeps the raw answer and every rc", mm and mm["stop_check"]["rcs"] == {"pidfile": 0, "stat": 1, "dir": 1, "kill0": 1} and mm["stop_check"]["target_pid"] == 41
   and mm["stop_check"]["expected_pid"] == 41 and mm["stop_check"]["baseline_starttime"] == 700, mm and mm["stop_check"])
stop_case("S2 zombie of the SAME process (pid + start time baseline) confirms the stop", "zombie", want_reason=S_OK, want_verdict="zombie")
stop_case("S3 REVIEWER: pid file 41, stat unreadable+empty, directory present, last echo rc 0 => NOT confirmed", "stat-permission-error", want_exc=TS, want_verdict="unknown", text_in_raw="CT04-DIR rc=0")
stop_case("S4 silence between the markers => NOT confirmed", "empty", want_exc=TS, want_verdict="unknown")
stop_case("S5 pid file unreadable => NOT confirmed", "pidfile-unreadable", want_exc=TS, want_verdict="unknown")
stop_case("S6 pid file names another pid => NOT confirmed", "pidfile-other-pid", want_exc=TS, want_verdict="unknown")
stop_case("S7 truncated answer => NOT confirmed", "truncated", want_exc=TS, want_verdict="unknown")
stop_case("S8 tool error (rc 127) => NOT confirmed", "tool-error", want_exc=TS, want_verdict="unknown")
stop_case("S9 zombie with a different start time (pid reuse) => NOT confirmed", "zombie-other-start", want_exc=TS, want_verdict="unknown")
stop_case("S10 process still alive => NOT confirmed", "alive", want_exc=TS, want_verdict="alive")
stop_case("S11 sample not found by the probes (no baseline): positive 'gone' still confirms", "gone", alive=False, want_reason=S_OK, want_verdict="gone")
stop_case("S12 sample not found (no baseline): a zombie cannot be recognised as the same process => NOT confirmed", "zombie", alive=False, want_exc=TS, want_verdict="unknown")
# the stored record is judged again by the classifier: a doctored verdict is a contradiction
mm = meta_of(tmp())
td = tmp()
cD = Console({"pid": 500})
an.app_settings.analysis_duration = 0
setup_analysis(td)._run_analysis(cD, arch)
mD = meta_of(td)
LOGD = ('500  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = 0 <0.001000>\n500  10:00:00.020000 nanosleep({tv_sec=3600, tv_nsec=0},  <unfinished ...>\n')
hD = hashlib.sha256(LOGD.encode()).hexdigest()
mD["strace_log_sha256"] = hD
good_k = xc.classify(LOGD, mD, task_id="task-p1", log_sha256=hD)["klass"]
mDx = json.loads(json.dumps(mD))
mDx["stop_check"]["raw"] = mDx["stop_check"]["raw"].replace("CT04-STAT rc=1", "CT04-STAT rc=0").replace("CT04-DIR rc=1", "CT04-DIR rc=0")
bad_k = xc.classify(LOGD, mDx, task_id="task-p1", log_sha256=hD)["klass"]
ok("S14 collected metadata carries the binding: strace identity in both probes, stop_check bound to it, collection end after the stop check",
   all(mD["probes"][k] and mD["probes"][k].get("strace_pid") == 41 and mD["probes"][k].get("strace_starttime_ticks") == 700 for k in ("start", "final"))
   and mD["stop_check"]["expected_pid"] == 41 and mD["stop_check"]["target_pid"] == 41 and mD["stop_check"]["baseline_starttime"] == 700
   and mD["trace_stopped_mono_s"] <= mD["stop_check"]["mono_s"] <= mD["collected_mono_s"], {k: mD.get(k) for k in ("collected_mono_s", "trace_stopped_mono_s")})
mDy = json.loads(json.dumps(mD))
mDy["stop_check"]["mono_s"] = 1.0
ok("S15 real metadata with the stop check time moved before the trace => INCONSISTENT_EVIDENCE", xc.classify(LOGD, mDy, task_id="task-p1", log_sha256=hD)["klass"] == "INCONSISTENT_EVIDENCE")
ok("S13 the real metadata proves the timeout; the same metadata with its raw answer edited is INCONSISTENT_EVIDENCE", good_k == "SAMPLE_TIMEOUT" and bad_k == "INCONSISTENT_EVIDENCE", (good_k, bad_k))
# through behaviour_analysis: QEMU of phase 1 is shut down (reviewed path), phase 2 never starts
a2 = setup_analysis(tmp())
shut, started = [], []
a2._start_qemu = lambda arch_: (started.append("p1"), Console({"pid": 500}))[1]
a2._configure_network = lambda proc_, arch_: None
a2._start_qemu_phase2 = lambda arch_: started.append("p2")
_vi, _sq, _cs = an.verify_isolation, an.shutdown_qemu, an._check_stop
an.verify_isolation = lambda label: None
an.shutdown_qemu = lambda proc_, phase: shut.append(phase)
an._check_stop = lambda: None
orig_run = a2._run_analysis
a2._run_analysis = lambda proc_, arch_: (proc_.fail.append(["strace -f", 2, 0]), orig_run(proc_, arch_))[1]
raised = None
try:
    a2.behaviour_analysis(arch)
except BaseException as e:                           # noqa: BLE001
    raised = e
an.verify_isolation, an.shutdown_qemu, an._check_stop = _vi, _sq, _cs
ok("L18 behaviour_analysis: ConsoleLost propagates, phase-1 QEMU is shut down, phase 2 never starts", isinstance(raised, CL) and shut == ["phase 1"] and started == ["p1"], (raised, shut, started))
an.stop_capture = _orig_stop

# ---- the report respects the manager's contract even for hostile inputs (long ids, long reasons) and is dumped as manager-test input
import re as _re
LONGID = "t" * 120
tdl = tmp()
open(os.path.join(tdl, "strace.log"), "w").write("\x00garbage" * 40)
open(os.path.join(tdl, "strace.log"), "w").write('1  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = 0 <0.001>\n1  10:00:00.010000 exit_group(0)   = ?\n')
open(os.path.join(tdl, "trace-meta.json"), "w").write(json.dumps({"schema": "ct04-trace-meta/2", "task_id": "a" * 128, "trace_id": "tr", "analysis_duration_s": 3,
    "trace_started_mono_s": 1.0, "trace_stopped_mono_s": 5.0, "stop_reason": "window_elapsed", "strace_log_sha256": None, "probes": None, "sample_signal_sent": None}))
rl = xc.classify_task(tdl, LONGID, failure_reason=None)
ok("R-0 the long-id mismatch really produces an evidence line > 200 chars before trimming", rl["execution_class"] == "INCONSISTENT_EVIDENCE" and len(xc.classify(
    open(os.path.join(tdl, "strace.log")).read(), json.load(open(os.path.join(tdl, "trace-meta.json"))), task_id=LONGID)["evidence"][0]) > 200)
ok("R-1 evidence <= 10 items of <= 200 chars; flags match [A-Z0-9_]{1,48}; main_pid int|None",
   len(rl["evidence"]) <= 10 and all(len(e) <= 200 for e in rl["evidence"]) and len(rl["flags"]) <= 20 and all(_re.fullmatch(r"[A-Z0-9_]{1,48}", f) for f in rl["flags"])
   and (rl["main_pid"] is None or isinstance(rl["main_pid"], int)), rl)
_dump_dir = os.environ.get("CT04_REPORT_DUMP")
if _dump_dir:
    samples = {}
    for nm, (log, m_, want) in [("busybox-127", ("1  10:00:00.000000 execve(\"./exec\", [\"./exec\"], 0x1 /* 6 vars */) = 0 <0.001>\n1  10:00:00.010000 exit_group(127)   = ?\n1  10:00:00.011000 +++ exited with 127 +++\n", None, None)),
                                ("garbage", ("not strace\n", None, None)), ("empty", ("", None, None))]:
        tdx = tmp()
        open(os.path.join(tdx, "strace.log"), "w").write(log)
        samples[nm] = xc.classify_task(tdx, "dump-" + nm)
    samples["long-id"] = rl
    json.dump(samples, open(os.path.join(_dump_dir, "worker-reports.json"), "w"), indent=1)

# ------------------------------------------------------------------ P2/P3: poller.submit_result
posted = []


def fake_post(url, **kw):
    posted.append((url, {k: (v if k != "files" else "<files>") for k, v in kw.items()}))
    return True, "HTTP 200"


poller._post = fake_post
poller.time.sleep = lambda s: None
poller.app_settings.sandbox_manager_uri = "http://manager.invalid/m"


def make_task(name, log):
    base = tmp()
    poller.app_settings.data_dir = base + "/"
    tdir = base + "/" + name
    os.makedirs(tdir + "/image")
    open(tdir + "/strace.log", "w").write(log)
    return tdir


tdir = make_task("task-q1", '300  10:00:00.000000 execve("./exec", ["./exec"], 0x1 /* 6 vars */) = 0 <0.001000>\n300  10:00:00.010000 exit_group(0)   = ?\n300  10:00:00.011000 +++ exited with 0 +++\n')
r = poller.submit_result("task-q1", tdir)
url, kw = posted[-1]
sent = sent_class(kw)
ok("Q1 completed task uploads with the execution class", r == "completed" and url.endswith("/submit-result/task-q1") and sent["execution_class"] == "EXITED_0", (r, sent))
ok("Q2 the class travels with the task (COMPLETED path unchanged)", sent["task_id"] == "task-q1" and sent["schema"] == "ct04-execution-class/1")
# the ZIP that was archived contains both files (the poller removed the dir after upload: re-create the check on a failed upload so the dir survives?)
posted.clear()
orig_classify = poller.execution_class.classify_task


def boom(*a, **k):
    raise RuntimeError("classifier bug")


poller.execution_class.classify_task = boom
tdir = make_task("task-q2", "x\n")
r = poller.submit_result("task-q2", tdir)
sent = sent_class(posted[-1][1])
ok("Q3 a classifier exception neither kills the worker nor fails the task", r == "completed" and sent["execution_class"] == "UNKNOWN_INCOMPLETE" and "CLASSIFIER_ERROR" in sent["flags"], (r, sent))
poller.execution_class.classify_task = orig_classify
# zip content: capture by making the upload fail so the zip is left on disk? _fail_task removes it; so intercept make_archive instead
captured = {}
orig_make = shutil.make_archive


def spy_make(base_name, fmt, root_dir=None, **kw):
    out = orig_make(base_name, fmt, root_dir, **kw)
    captured["names"] = sorted(zipfile.ZipFile(out).namelist())
    return out


shutil.make_archive = spy_make
tdir = make_task("task-q4", "")
open(tdir + "/trace-meta.json", "w").write("{}")
poller.submit_result("task-q4", tdir)
shutil.make_archive = orig_make
ok("Q4 the archive contains strace.log, trace-meta.json and execution-class.json", {"strace.log", "trace-meta.json", "execution-class.json"} <= set(captured["names"]), captured)
# failed upload path stays as before (failure reported, class not stored)
posted.clear()


def fake_post_fail(url, **kw):
    posted.append((url, kw))
    return (False, "HTTP 500") if "submit-result" in url else (True, "HTTP 200")


poller._post = fake_post_fail
tdir = make_task("task-q5", "x\n")
r = poller.submit_result("task-q5", tdir)
ok("Q5 upload failure => failed + failure reported (unchanged contract)", r == "failed" and any("submit-failure" in u for u, _ in posted), (r, [u for u, _ in posted]))

bad = [n for n, c in RESULTS if not c]
print("SUMMARY: %d checks, %d FAIL" % (len(RESULTS), len(bad)))
sys.exit(1 if bad else 0)
