"""Regression for the A1-ARM finding: the guest console delivers "\\r\\r\\n" (the guest tty already writes CRLF and the host pty adds a CR again).
The end-marker patterns must match that. Uses a REAL pexpect.spawn on a REAL pty (the child writes CRLF lines; the pty's ONLCR makes them CR CR LF).
usage: python3 -I -B tests/check_console_crlf.py <path-to-execution_class.py>      exit 0 = all OK, 1 = at least one DEFECT"""
import importlib.util, re, sys, textwrap
import pexpect
spec = importlib.util.spec_from_file_location("xc", sys.argv[1]); xc = importlib.util.module_from_spec(spec); spec.loader.exec_module(xc)
FAIL = []
def ok(n, c, extra=""):
    print(("OK    " if c else "DEFECT"), n, extra); c or FAIL.append(n)
TID = "0edfd3ff14ba40bfa46c99973984c918"
def child(kind, eol):
    marker = {"probe": ("CT04-PROBE-BEGIN", "CT04-PROBE-END"), "stop": ("CT04-STOP-BEGIN", "CT04-STOP-END")}[kind]
    prog = textwrap.dedent('''
        import sys, time
        sys.stdout.write(%r + "root@OpenWrt:/# ")
        sys.stdout.flush(); time.sleep(0.2)
        body = ["%s %s", "CT04-STRACE-PID 944", "1 (procd) S 0 1 1 0 -1 4194560 665 30292 9 62 10 66 435 252 20 0 1 0 1 1355776 182 4294967295", "%s %s"]
        sys.stdout.write(%r + "".join(l + %r for l in body) + "root@OpenWrt:/# "); sys.stdout.flush(); time.sleep(0.3)
    ''') % ("", marker[0], TID, marker[1], TID, eol, eol)
    return prog
for eol, label in (("\r\n", "guest CRLF through the pty => CR CR LF (the real console)"), ("\n", "LF through the pty => CR LF")):
    for kind, patfn in (("probe", xc.probe_end_pattern), ("stop", xc.stop_check_end_pattern)):
        p = pexpect.spawn(sys.executable, ["-c", child(kind, eol)], encoding="utf-8", timeout=5)
        i = p.expect([pexpect.TIMEOUT, patfn(TID), pexpect.EOF], timeout=5)
        raw = (p.before or "") + (p.after if isinstance(p.after, str) else "")
        ok(f"{kind} end marker matched on {label}", i == 1, "idx=%s CRCRLF_in_stream=%s" % (i, "\r\r\n" in raw))
        if kind == "probe" and i == 1:
            res, err = xc.parse_probe_output(raw, TID)
            ok(f"{kind} output parses after the match ({label})", err is None and res is not None and res["strace_pid"] == 944 and len(res["procs"]) == 1, f"err={err!r}")
        p.close()
# the echoed command alone must still NOT satisfy the pattern (the quoted-fragment guard), also with CR CR LF line ends
echo = "root@OpenWrt:/# " + xc.probe_command(TID) + "\r\r\n"
ok("echoed probe command does not match the end pattern", re.search(xc.probe_end_pattern(TID), echo) is None)
echo = "root@OpenWrt:/# " + xc.stop_check_command(TID) + "\r\r\n"
ok("echoed stop-check command does not match the end pattern", re.search(xc.stop_check_end_pattern(TID), echo) is None)
sys.exit(1 if FAIL else 0)
