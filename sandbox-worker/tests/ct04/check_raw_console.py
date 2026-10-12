"""Offline tests of the raw console tap (analysis.attach_raw_console / RawTeeDecoder / RawConsoleLog) and poller._log_raw_console.
The tap sits in front of pexpect's UTF-8 decoder: the bytes recorded must equal the bytes os.read() returned (the source), not str.encode() of decoded text.
usage: python3 -I -B tests/check_raw_console.py <repo sandbox-worker dir> <proposed sandbox-worker dir>      exit 0 = all OK"""
import base64, hashlib, logging, os, shutil, sys, tempfile, time
import pexpect
W = tempfile.mkdtemp(prefix="ct04-raw-") + "/sandbox-worker"
shutil.copytree(os.path.abspath(sys.argv[1]), W, ignore=shutil.ignore_patterns("__pycache__", "tests", "ARM", "MIPS", "MIPSEL", "x86"))
for r, _d, fs in os.walk(os.path.abspath(sys.argv[2])):
    for f in fs:
        if f.endswith(".pyc"): continue
        s = os.path.join(r, f); d = os.path.join(W, os.path.relpath(s, os.path.abspath(sys.argv[2])))
        os.makedirs(os.path.dirname(d), exist_ok=True); shutil.copy(s, d)
sys.path.insert(0, W)
os.environ.update({"PORT": "8011", "APP_BASE_URL": "/api/v1/sandbox-worker", "SANDBOX_MANAGER_URI": "http://manager.invalid/api/v1/sandbox-manager"})
from service import analysis as an   # noqa: E402
import poller                        # noqa: E402
logging.disable(logging.CRITICAL)
FAIL = []
def ok(n, c, e=""):
    print(("OK    " if c else "DEFECT"), n, e); c or FAIL.append(n)
T = tempfile.mkdtemp()
def child(payload, raw_tty, gap=0.0, chunk=7):
    """a real child on a real pty that writes exactly `payload` (bytes) with os.write; raw_tty => the pty does no output translation"""
    prog = ("import os,sys,time%s\n" % (",tty" if raw_tty else "")) + ("tty.setraw(1)\n" if raw_tty else "") + \
           "p=%r\nfor i in range(0,len(p),%d):\n os.write(1,p[i:i+%d]); time.sleep(%r)\ntime.sleep(0.2)\n" % (payload, chunk, chunk, gap)
    return prog
def run(payload, raw_tty=True, maxread=2000, name="c", strict=True, gap=0.0, chunk=7):
    path = f"{T}/{name}.raw"
    p = pexpect.spawn(sys.executable, ["-c", child(payload, raw_tty, gap, chunk)], encoding="utf-8", timeout=5, maxread=maxread, codec_errors="strict" if strict else "replace")
    sink = an.attach_raw_console(p, path)
    exc = None; text = ""
    try:
        p.expect(pexpect.EOF); text = p.before
    except BaseException as e:                                        # noqa: BLE001
        exc = e
    sink.close()
    return open(path, "rb").read(), text, exc, sink
# 1. CR CR LF: the pty (ONLCR) turns the child's CRLF into CR CR LF; the tap must hold it. Expected is computed from the SOURCE bytes, not from the tap.
src = b"one\r\ntwo\r\nCT04-PROBE-END abc\r\n# "
got, text, exc, sink = run(src, raw_tty=False, name="crcrlf", chunk=len(src))
ok("CR CR LF reaches the evidence (source CRLF + pty ONLCR)", got == src.replace(b"\n", b"\r\n") and b"\r\r\n" in got and exc is None, repr(got))
# 2. exact source equality with a raw tty (no translation at all)
src = bytes(range(0, 256)) * 3
got, text, exc, sink = run(src, raw_tty=True, name="exact", strict=False)
ok("all 256 byte values, raw tty: tap == source", got == src and sink.sha.hexdigest() == hashlib.sha256(src).hexdigest(), f"len={len(got)}")
# 3. valid UTF-8 multi-byte characters split between reads (maxread=1 forces one byte per read)
src = "héllo → 日本語 😀\r\n# ".encode("utf-8")
got, text, exc, sink = run(src, raw_tty=True, maxread=1, name="split")
ok("multi-byte characters split between reads: tap == source", got == src, repr(got))
ok("the decoded text pexpect saw is the right characters (tap does not disturb decoding)", text == src.decode("utf-8"), repr(text))
# 4. invalid UTF-8 with the strict decoder: pexpect raises UnicodeDecodeError exactly as before; the tap already holds the offending byte
src = b"abc\xff\xfedef\r\n# "
got, text, exc, sink = run(src, raw_tty=True, maxread=1, name="invalid")
ok("invalid UTF-8: the analysis-side error is unchanged (UnicodeDecodeError) and not masked", isinstance(exc, UnicodeDecodeError), repr(exc))
ok("invalid UTF-8: the evidence holds the source bytes up to and including the offending byte", got == src[:4], repr(got))
# 5. same input, tolerant decoder: everything is recorded, byte-exact
got, text, exc, sink = run(src, raw_tty=True, maxread=1, name="invalid2", strict=False)
ok("invalid UTF-8 with a tolerant decoder: tap == source", got == src and exc is None)
# 6. append across phases, offset and cap
path = T + "/phases.raw"
class Fake:                                                           # a text-mode child stand-in with a real incremental decoder
    import codecs
    def __init__(s): s.encoding = "utf-8"; s._decoder = s.codecs.getincrementaldecoder("utf-8")("strict")
f1 = Fake(); s1 = an.attach_raw_console(f1, path); f1._decoder.decode(b"PHASE1\r\r\n"); s1.close()
f2 = Fake(); s2 = an.attach_raw_console(f2, path); f2._decoder.decode(b"PHASE2\r\r\n"); s2.close()
ok("phase 2 appends, offset recorded, phase hashes", open(path, "rb").read() == b"PHASE1\r\r\nPHASE2\r\r\n" and s2.start_offset == 9 and s2.sha.hexdigest() == hashlib.sha256(b"PHASE2\r\r\n").hexdigest())
an.RAW_CONSOLE_MAX = 10
f3 = Fake(); s3 = an.attach_raw_console(f3, T + "/cap.raw"); f3._decoder.decode(b"0123456789ABCDEF"); f3._decoder.decode(b"more"); s3.close()
ok("cap: file <= cap, dropped counted, decoding unaffected", os.path.getsize(T + "/cap.raw") == 10 and s3.dropped == 10)
an.RAW_CONSOLE_MAX = 4 * 1024 * 1024
# 7. evidence errors never change the analysis outcome
class BadFile:
    def write(self, b): raise OSError("disk full")
    def flush(self): raise OSError("x")
    def close(self): raise OSError("x")
f4 = Fake(); s4 = an.attach_raw_console(f4, T + "/bad.raw"); s4.f = BadFile()
out = f4._decoder.decode("é".encode("utf-8")[:1]) + f4._decoder.decode("é".encode("utf-8")[1:])
s4.close()
ok("write failure: decoded text unchanged, sink disabled, close contained", out == "é" and s4.failed)
try:
    Fake()._decoder.decode(b"")        # empty input is passed through
    f5 = Fake(); an.attach_raw_console(f5, T + "/e.raw"); e = f5._decoder.decode(b"", True); ok("empty/final decode passes through", e == "")
except BaseException as e:                                            # noqa: BLE001
    ok("empty/final decode passes through", False, repr(e))
class NoDec:
    encoding = None
ok("a bytes-mode child is refused cleanly (None, no raise)", an.attach_raw_console(NoDec(), T + "/n.raw") is None)
ok("an unwritable path is refused cleanly (None, no raise)", an.attach_raw_console(Fake(), "/nonexistent-dir/x.raw") is None)
# 8. cleanup is not affected by evidence errors: shutdown_qemu on a real child with a sink whose close() raises
p = pexpect.spawn("sleep", ["60"], encoding="utf-8", timeout=5)
class BadSink:
    def close(self): raise OSError("close failed")
p.ct04_raw_console = BadSink()
try:
    an.shutdown_qemu(p, "test"); done = True
except BaseException as e:                                            # noqa: BLE001
    done = False; print(repr(e))
ok("shutdown_qemu still finalises the child when the raw sink close fails", done and not p.isalive())
# 9. poller: worker-log block rebuilds the exact bytes (raw, incl. invalid UTF-8 and CR CR LF); sha256 binds them; missing file / truncation do not raise
class Cap(logging.Handler):
    def __init__(s): super().__init__(); s.lines = []
    def emit(s, r): s.lines.append(r.getMessage())
logging.disable(logging.NOTSET)
h = Cap(); poller.logger.addHandler(h); poller.logger.setLevel(logging.DEBUG)
d = T + "/task"; os.makedirs(d); raw = bytes(range(256)) * 20 + b"\xff\r\r\n"
open(d + "/console.raw", "wb").write(raw)
poller._log_raw_console("t1", d)
b = next(l for l in h.lines if l.startswith("RAW-CONSOLE-BEGIN"))
import re
sha = re.search(r"sha256=([0-9a-f]{64})", b)[1]
body = "".join(l[len("RAW-CONSOLE "):] for l in h.lines if l.startswith("RAW-CONSOLE "))
rebuilt = base64.b64decode(body)
ok("worker-log block rebuilds the exact bytes; sha256 and length match", rebuilt == raw and hashlib.sha256(rebuilt).hexdigest() == sha and f"bytes={len(raw)}" in b)
ok("block has an END line", any(l.startswith("RAW-CONSOLE-END") for l in h.lines))
h.lines.clear(); poller._log_raw_console("t2", T + "/nonexistent")
ok("missing raw log: warning only, no raise", any("No raw console log" in l for l in h.lines))
poller.RAW_CONSOLE_LOG_MAX = 100; h.lines.clear(); poller._log_raw_console("t1", d)
ok("truncation flagged", any("truncated=True" in l and "bytes=100" in l for l in h.lines))
sys.exit(1 if FAIL else 0)
