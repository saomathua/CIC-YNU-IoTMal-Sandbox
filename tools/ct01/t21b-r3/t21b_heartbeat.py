#!/usr/bin/env python3
"""CT-01 T21b — heartbeat that lives INSIDE the SSH session to be proven. Stdlib only. Run it by hand in that session (not through sudo, not through nohup/
tmux/screen: a detached process proves nothing about the session):

    python3 -I -B t21b_heartbeat.py <run_id> <out_dir> [--interval 1.0] [--max-seconds 3600]

Every <interval> seconds one line is printed to STDOUT (so it travels through the SSH channel and appears on the client terminal) and appended + fsync'ed to
<out_dir>/heartbeat-<run_id>.log (server side). A line: `HB <run_id> <seq> <utc-iso> <epoch.ns> <monotonic.ns> <gap_s>`.
The header line records what ties it to the session: SSH_CONNECTION/SSH_CLIENT/SSH_TTY, the tty of fd 0, the process chain up to sshd (pid, comm), the login
uid and session id from /proc/self/{loginuid,sessionid}. Each beat also re-reads the parent chain: if the sshd ancestor disappears or the stdout write fails the
process says so in the log and exits (nonzero). Ctrl-C writes a 'STOP' line (client side ended it). R2: every STOP/ABORT/END line carries `seq=`, `epoch_ns=` and `mono_ns=` so that an interruption AFTER the
window being judged is distinguishable from one inside it (the evaluator judges the window, not the whole file).
It changes nothing on the host: it writes only its own log file."""
import datetime, os, pathlib, sys, time


def chain():
    out, pid = [], os.getpid()
    for _ in range(12):
        try:
            st = pathlib.Path(f"/proc/{pid}/stat").read_text()
            comm = st[st.index("(") + 1: st.rindex(")")]
            ppid = int(st[st.rindex(")") + 2:].split()[1])
        except (OSError, ValueError):
            break
        out.append((pid, comm))
        if ppid <= 1:
            break
        pid = ppid
    return out


def rd(p):
    try:
        return pathlib.Path(p).read_text().strip()
    except OSError as e:
        return f"ERR {type(e).__name__}"


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    run_id, out_dir = argv[0], pathlib.Path(argv[1])
    iv = float(argv[argv.index("--interval") + 1]) if "--interval" in argv else 1.0
    mx = float(argv[argv.index("--max-seconds") + 1]) if "--max-seconds" in argv else 3600.0
    if not run_id.replace("-", "").replace("_", "").isalnum():
        print("bad run id")
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        log = open(out_dir / f"heartbeat-{run_id}.log", "x", buffering=1)      # R3: a log is never appended to (one invocation = one session = one log)
    except FileExistsError:
        print(f"STOP: heartbeat log for run id {run_id} already exists; use a new run id")
        return 6

    def emit(line):
        log.write(line + "\n"); log.flush(); os.fsync(log.fileno())
        try:
            sys.stdout.write(line + "\n"); sys.stdout.flush()
        except OSError:
            return False
        return True
    ch = chain()
    has_sshd = any(c == "sshd" or c.startswith("sshd") for _, c in ch)
    try:
        tty = os.ttyname(0)
    except OSError:
        tty = None
    hdr = {"run_id": run_id, "pid": os.getpid(), "SSH_CONNECTION": os.environ.get("SSH_CONNECTION"), "SSH_CLIENT": os.environ.get("SSH_CLIENT"),
           "SSH_TTY": os.environ.get("SSH_TTY"), "tty0": tty, "chain": ch, "sshd_ancestor": has_sshd, "loginuid": rd("/proc/self/loginuid"),
           "sessionid": rd("/proc/self/sessionid"), "interval": iv, "max_seconds": mx,
           "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    emit("HEADER " + repr(hdr))
    offline_test = os.environ.get("CT01_T21B_OFFLINE_TEST") == "1"       # unit tests only: the header still records sshd_ancestor=False, which the evaluator refuses
    if (not has_sshd or not os.environ.get("SSH_CONNECTION")) and not offline_test:
        emit(f"ABORT {run_id} seq=0 epoch_ns={time.time_ns()} mono_ns={time.monotonic_ns()} reason=not-inside-ssh sshd_ancestor={has_sshd}")
        return 3
    t0 = time.monotonic()
    prev = t0
    seq = 0
    try:
        while time.monotonic() - t0 < mx:
            now_m = time.monotonic()
            gap = now_m - prev
            prev = now_m
            if not offline_test and not any(c.startswith("sshd") for _, c in chain()):
                emit(f"ABORT {run_id} seq={seq} epoch_ns={time.time_ns()} mono_ns={time.monotonic_ns()} reason=sshd-ancestor-gone")
                return 4
            seq += 1
            e = time.time_ns()
            ok = emit(f"HB {run_id} {seq} {datetime.datetime.fromtimestamp(e / 1e9, datetime.timezone.utc).isoformat()} {e} {time.monotonic_ns()} {gap:.3f}")
            if not ok:
                log.write(f"ABORT {run_id} seq={seq} epoch_ns={time.time_ns()} mono_ns={time.monotonic_ns()} reason=stdout-failed\n"); log.flush()
                return 5
            time.sleep(max(0.0, iv - (time.monotonic() - now_m)))
        emit(f"END {run_id} seq={seq} epoch_ns={time.time_ns()} mono_ns={time.monotonic_ns()} reason=max-seconds")
        return 0
    except KeyboardInterrupt:
        emit(f"STOP {run_id} seq={seq} epoch_ns={time.time_ns()} mono_ns={time.monotonic_ns()} reason=interrupt")
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
