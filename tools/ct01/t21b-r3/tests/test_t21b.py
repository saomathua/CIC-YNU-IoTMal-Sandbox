#!/usr/bin/env python3
"""Offline tests R2 of the T21b heartbeat, evaluator and controller. No SSH: the heartbeat's offline switch makes its header say sshd_ancestor=False, which the
evaluator must refuse; the synthetic logs below carry the full server and client record formats (never a bare `HB run N x`). usage: python3 -I -B tests/test_t21b.py <tree>"""
import datetime, json, os, pathlib, subprocess, sys, tempfile, time
TREE = pathlib.Path(sys.argv[1]).resolve()
RES = {}
def t(n, ok, d=""):
    RES[n] = bool(ok); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"  -> {d}"), flush=True)
TMP = pathlib.Path(tempfile.mkdtemp(prefix="t21btest."))
HB, EV, CTL = TREE / "t21b_heartbeat.py", TREE / "t21b_evaluate.py", TREE / "t21b_wait_and_run.sh"
def py(*a, env=None):
    return subprocess.run([sys.executable, "-I", "-B", *map(str, a)], capture_output=True, text=True, env=dict(os.environ, **(env or {})))
# --- heartbeat
p = py(HB, "run0", TMP / "o0", "--max-seconds", "3", env={"SSH_CONNECTION": ""})
l0 = (TMP / "o0/heartbeat-run0.log").read_text()
t("H1 outside an SSH session: rc 3, ABORT line with seq/epoch_ns/mono_ns/reason in the log", p.returncode == 3 and "ABORT run0 seq=0 epoch_ns=" in l0 and "reason=not-inside-ssh" in l0, l0[-200:])
t0 = time.time()
p = py(HB, "run1", TMP / "o1", "--interval", "0.2", "--max-seconds", "2", env={"CT01_T21B_OFFLINE_TEST": "1"})
t1 = time.time()
l1 = (TMP / "o1/heartbeat-run1.log").read_text()
t("H2 offline run: beats on stdout and in the log, END with epoch/mono, rc 0", p.returncode == 0 and p.stdout.count("HB run1 ") >= 8 and "END run1 seq=" in l1 and "epoch_ns=" in l1.split("END run1")[1])
win = TMP / "w1.json"; win.write_text(json.dumps({"start_epoch": t0 + 0.5, "end_epoch": t1 - 0.5, "lane": "x", "source": "test"}))
py(EV, TMP / "o1/heartbeat-run1.log", "run1", win, "--max-gap", "1.0", "--out", TMP / "v1.json")
v = json.loads((TMP / "v1.json").read_text())
fails = [c["name"] for c in v["checks"] if not c["ok"]]
t("H3 the evaluator refuses that offline log ONLY for the header (no sshd ancestor)", fails and all("header present" in f for f in fails) and v["verdict"] == "NOT_MET", fails)
# --- synthetic full-format logs
base = 1_800_000_000.0
HDR = {"run_id": "r", "pid": 1, "SSH_CONNECTION": "10.0.0.1 5000 10.0.0.2 22", "SSH_CLIENT": "10.0.0.1 5000 22", "SSH_TTY": "/dev/pts/1", "tty0": "/dev/pts/1",
       "chain": [(5, "python3"), (4, "bash"), (3, "sshd")], "sshd_ancestor": True, "loginuid": "1000", "sessionid": "7", "interval": 1.0, "max_seconds": 300}
def server(n=90, hole=None, hdr=None, events=(), start=base, bad_event=False):
    h = "HEADER " + repr(hdr or HDR)
    L, HBS, mono = [h], {}, 5_000_000_000
    for i in range(1, n + 1):
        if hole and i == hole:
            continue
        e = int((start + i) * 1e9)
        line = f"HB r {i} 2026-10-11T00:00:00+00:00 {e} {mono + i * 10**9} 1.000"
        L.append(line); HBS[i] = line
    for kind, seq, off in events:
        L.append(f"{kind} r seq={seq} epoch_ns={int((start + off) * 1e9)} mono_ns=1 reason=interrupt")
    return L, HBS, h
def client(lines, rx_gap_at=None, drop=(), dup=(), swap=None, bare=False, mutate=None):
    out, ms = [], 1000.0
    for l in lines:
        if l.startswith("HB r "):
            seq = int(l.split()[2])
            if seq in drop:
                continue
            if mutate and seq == mutate:
                l = l.replace("1.000", "9.999")
            ms += 6000.0 if (rx_gap_at and seq == rx_gap_at) else 1000.0
            rec = f"RX 2026-10-11T00:00:{seq % 60:02d}.000000Z {ms:.3f} {l}" if not bare else l
            out.append(rec)
            if seq in dup:
                out.append(rec)
        else:
            out.append(f"RX 2026-10-11T00:00:00.000000Z {ms:.3f} {l}" if not bare else l)
    if swap:
        a, b = swap
        ia = next(i for i, x in enumerate(out) if f" r {a} " in x); ib = next(i for i, x in enumerate(out) if f" r {b} " in x)
        out[ia], out[ib] = out[ib], out[ia]
    return out
W = TMP / "w.json"; W.write_text(json.dumps({"start_epoch": base + 20, "end_epoch": base + 60, "lane": "f5x", "source": "synthetic"}))
n = [0]
def ev(srv, cli=None, win=W):
    n[0] += 1
    sp = TMP / f"s{n[0]}.log"; sp.write_text("\n".join(srv) + "\n")
    a = [EV, sp, "r", win, "--out", TMP / f"v{n[0]}.json"]
    if cli is not None:
        cp = TMP / f"c{n[0]}.log"; cp.write_text("\n".join(cli) + "\n"); a += ["--client-log", cp]
    p = py(*a)
    return p.returncode, json.loads((TMP / f"v{n[0]}.json").read_text())
def bad(v, key):
    return any(key in c["name"] and not c["ok"] for c in v["checks"])
S, _, _ = server(90)
rc, v = ev(S)
t("E1 server only, clean: SERVER_SIDE_ONLY, not all_ok (no client proof)", v["verdict"] == "SERVER_SIDE_ONLY" and rc == 1 and not v["all_ok"])
rc, v = ev(S, client(S))
t("E2 clean full-payload client log: T21B_TWO_SIDED_HELD, rc 0, client gap ~1 s, header equal", rc == 0 and v["verdict"] == "T21B_TWO_SIDED_HELD" and v["client"]["max_client_gap_s"] <= 1.01, v["client"])
rc, v = ev(S, [f"HB r {i} x" for i in range(1, 91)])
t("E3 the old 'HB run N x' client file is NOT accepted (no receiver prefix, no payload)", rc == 1 and v["verdict"] == "NOT_MET" and bad(v, "receiver prefix"))
rc, v = ev(S, client(S, drop=(40,)))
t("E4 a beat of the window missing on the client: NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "every beat of the window present"))
rc, v = ev(S, client(S, mutate=40))
t("E5 a client beat whose content differs from the server's (same run/seq): NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "every beat of the window present"))
rc, v = ev(S, client(S, swap=(40, 41)))
t("E6 client beats out of order: NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "increasing sequence"))
rc, v = ev(S, client(S, dup=(40,)))
t("E7 a duplicated client beat: NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "increasing sequence"))
rc, v = ev(S, client(S, rx_gap_at=40))
t("E8 a 6 s receive gap at the client with an intact sequence: NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "receive gap"))
c = client(S); c[0] = c[0].replace("'sessionid': '7'", "'sessionid': '8'")
rc, v = ev(S, c)
t("E9 client HEADER differs from the server's (another session): NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "exactly one session HEADER"))
S2, _, _ = server(90, events=[("STOP", 40, 40.5)])
rc, v = ev(S2, client(S2))
t("E10 STOP inside the window (at +40 s of 20..60): NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "no STOP/ABORT/END before"))
S3, _, _ = server(90, events=[("STOP", 90, 90.5)])
rc, v = ev(S3, client(S3))
t("E11 STOP after the window end (the user's Ctrl-C at seq 90): held; the event is recorded, not held against the window", rc == 0 and v["verdict"] == "T21B_TWO_SIDED_HELD", v["verdict"])
S4 = [l for l in S3 if not l.startswith("STOP")] + ["STOP r seq=90 reason=interrupt"]
rc, v = ev(S4, client(S4))
t("E12 a STOP without epoch cannot be placed: NOT_MET", v["verdict"] == "NOT_MET")
S5, _, _ = server(90, hole=40)
t("E13 hole in the server sequence: NOT_MET", ev(S5)[1]["verdict"] == "NOT_MET")
S6, _, _ = server(45)
t("E14 beats end before the window end: coverage fails", bad(ev(S6)[1], "coverage"))
S7, _, _ = server(90, hdr=dict(HDR, sshd_ancestor=False))
t("E15 header without an sshd ancestor: NOT_MET", ev(S7)[1]["verdict"] == "NOT_MET")
W2 = TMP / "w2.json"; W2.write_text(json.dumps({"start_epoch": base + 60, "end_epoch": base + 20, "lane": "bad", "source": "inverted"}))
t("E16 an inverted window is refused", ev(S, client(S), win=W2)[1]["verdict"] == "NOT_MET")
# window from a flow run directory incl. the restart interval
iso = lambda e: datetime.datetime.fromtimestamp(e, datetime.timezone.utc).isoformat()    # noqa: E731
def rundir(name, restart):
    d = TMP / name; d.mkdir()
    (d / "identity.json").write_text(json.dumps({"started": iso(base + 20), "label": "L"}))
    (d / "lane-status.json").write_text(json.dumps({"finished": iso(base + 60)}))
    (d / "f5-restart-time.txt").write_text(f"{restart[0]}\n{restart[1]}\n")
    return d
rc, v = ev(S, client(S), win=rundir("rd", (base + 35, base + 40)))
t("E17 window derived from a flow run directory, restart interval inside the beats: held", rc == 0 and v["verdict"] == "T21B_TWO_SIDED_HELD")
rc, v = ev(S, client(S), win=rundir("rd2", (base + 35, base + 400)))
t("E18 a restart interval outside the covered beats: NOT_MET", v["verdict"] == "NOT_MET" and bad(v, "restart interval"))
# UTF-16 client file (PowerShell 5 default) is decoded
cp = TMP / "c16.log"; cp.write_bytes(("\r\n".join(client(S)) + "\r\n").encode("utf-16")); sp = TMP / "s16.log"; sp.write_text("\n".join(S) + "\n")
p = py(EV, sp, "r", W, "--client-log", cp, "--out", TMP / "v16.json")
t("E19 a UTF-16 (BOM) client file with CRLF is decoded and held", p.returncode == 0)
# --- R3: boundary (review H3) fixtures and mutations
FX = TREE / "tests" / "fixtures"
def run_fx(srv, cli, win):
    n[0] += 1
    out = TMP / f"fx{n[0]}.json"
    p_ = py(EV, srv, "review-r", win, "--client-log", cli, "--out", out)
    return p_.returncode, json.loads(out.read_text())
rc, v = run_fx(FX / "boundary-server.log", FX / "boundary-client.log", FX / "boundary-window.json")
t("B1 review fixture (22 s silence cutting the window start, seq intact, full client matching): NOT held, rc 1, the span interval check names it",
  rc == 1 and v["verdict"] == "NOT_MET" and any("every interval of the bracketed span" in c["name"] and not c["ok"] for c in v["checks"]), [c["name"] for c in v["checks"] if not c["ok"]])
def tail_gap(a, b):
    """beats every 1 s from +1 .. +a and +b .. +100 (seq contiguous): a silence between +a and +b"""
    L = ["HEADER " + repr(HDR)]
    seq = 0
    for off in list(range(1, a + 1)) + list(range(b, 101)):
        seq += 1
        L.append(f"HB r {seq} 2026-10-11T00:00:00+00:00 {int((base + off) * 1e9)} {5_000_000_000 + off * 10**9} 1.000")
    return L
Lc = tail_gap(10, 11)
rc, v = ev(Lc, client(Lc))
t("B2 clean beats every second (window 20..60): held", rc == 0 and v["verdict"] == "T21B_TWO_SIDED_HELD", [c["name"] for c in v["checks"] if not c["ok"]])
for nm, (ga, gb) in (("middle gap 30..45", (30, 45)), ("gap cutting the START 15..25", (15, 25)), ("gap cutting the END 55..66", (55, 66))):
    L = tail_gap(ga, gb)
    rc, v = ev(L, client(L))
    t(f"B3 {nm}: NOT_MET although sequence and client matching are intact", v["verdict"] == "NOT_MET" and any("every interval" in c["name"] and not c["ok"] for c in v["checks"]))
L2 = [l for l in Lc if not l.startswith("HB r ") or int(l.split()[4]) / 1e9 > base + 21]
rc, v = ev(L2, client(L2))
t("B4 no beat at or before the window start (missing start bracket): NOT_MET", v["verdict"] == "NOT_MET" and any("bracket" in c["name"] and not c["ok"] for c in v["checks"]))
L3 = [l for l in Lc if not l.startswith("HB r ") or int(l.split()[4]) / 1e9 < base + 59]
rc, v = ev(L3, client(L3))
t("B5 no beat at or after the window end (missing end bracket): NOT_MET", v["verdict"] == "NOT_MET" and any("bracket" in c["name"] and not c["ok"] for c in v["checks"]))
rc, v = ev(Lc, client(Lc, rx_gap_at=21))
t("B6 client receive gap in the first interval of the window with an intact server log: NOT_MET", v["verdict"] == "NOT_MET" and any("receive gap" in c["name"] and not c["ok"] for c in v["checks"]))
two = ["HEADER " + repr(HDR)] + Lc[1:20] + ["STOP r seq=19 epoch_ns=1 mono_ns=1 reason=interrupt", "HEADER " + repr(HDR)] + Lc[1:]
rc, v = ev(two)
t("B7 two HEADERs (several invocations appended to one log): NOT_MET", v["verdict"] == "NOT_MET" and any("exactly one HEADER" in c["name"] and not c["ok"] for c in v["checks"]))
ch = [l.replace(".000 HB", ",000 HB") for l in client(Lc)]
rc, v = ev(Lc, ch)
t("B8 client receive times with a decimal COMMA are not accepted", v["verdict"] == "NOT_MET" and any("receiver prefix" in c["name"] and not c["ok"] for c in v["checks"]))
src = (TREE / "t21b_evaluate.py").read_text()
old = '    inw = [b for b in beats if b0 is not None and b1 is not None and b0["seq"] <= b["seq"] <= b1["seq"]]'
assert old in src
mp = TMP / "mut_evaluate.py"; mp.write_text(src.replace(old, '    inw = [b for b in beats if s <= b["epoch"] <= e]'))
pm = subprocess.run([sys.executable, "-I", "-B", str(mp), str(FX / "boundary-server.log"), "review-r", str(FX / "boundary-window.json"), "--client-log", str(FX / "boundary-client.log"),
                     "--out", str(TMP / "mut.json")], capture_output=True, text=True)
vm = json.loads((TMP / "mut.json").read_text()) if (TMP / "mut.json").exists() else {}
t("B9 MUTATION (judge only beats inside the window): the review fixture becomes a false PASS, so B1 distinguishes the fix", pm.returncode == 0 and vm.get("verdict") == "T21B_TWO_SIDED_HELD", pm.stdout[-200:])
p1 = py(HB, "runx", TMP / "ox", "--interval", "0.2", "--max-seconds", "1", env={"CT01_T21B_OFFLINE_TEST": "1"})
p2 = py(HB, "runx", TMP / "ox", "--interval", "0.2", "--max-seconds", "1", env={"CT01_T21B_OFFLINE_TEST": "1"})
t("H4 a second invocation with the same run id is refused (rc 6) and leaves the log with one HEADER", p1.returncode == 0 and p2.returncode == 6 and (TMP / "ox/heartbeat-runx.log").read_text().count("HEADER") == 1)
# --- controller
env = dict(os.environ, CT01_T21B_OFFLINE_TEST="1", CT01_T21B_PY=sys.executable)
tree = TMP / "lanetree"; tree.mkdir(); (tree / "SHA256SUMS").write_text("abc  x\n")
import hashlib
man = hashlib.sha256((tree / "SHA256SUMS").read_bytes()).hexdigest()
stub = tree / "root-command-f5.txt"
rd2 = TMP / "stub-run"; rd2.mkdir()
(rd2 / "identity.json").write_text(json.dumps({"started": iso(time.time()), "label": "stub"})); (rd2 / "lane-status.json").write_text(json.dumps({"finished": iso(time.time() + 1)}))
stub.write_text(f"#!/bin/bash\nMAN={man}\necho EXPORT VERIFIED: {rd2} {{}}\nexit 0\n")
def ctl(run, wait, pin=man):
    return subprocess.run(["/bin/bash", str(CTL), run, str(TMP / ("hb-" + run)), str(stub), str(TMP / ("res-" + run)), pin, str(wait)], capture_output=True, text=True, env=env)
r = ctl("c1", 4)
t("C1 no heartbeat within the wait: rc 3, NO_HEARTBEAT, the lane was not run", r.returncode == 3 and (TMP / "res-c1/outcome.txt").read_text().strip() == "NO_HEARTBEAT" and not (TMP / "res-c1/lane-console.log").exists())
r = ctl("c2", 4, pin="0" * 64)
t("C2 a wrong pinned manifest: rc 7, nothing started", r.returncode == 7 and not (TMP / "res-c2").exists())
hbp = subprocess.Popen([sys.executable, "-I", "-B", str(HB), "c3", str(TMP / "hb-c3"), "--interval", "0.5", "--max-seconds", "60"], stdout=subprocess.DEVNULL, env=env)
r = ctl("c3", 30)
hbp.terminate(); hbp.wait()
t("C3 live heartbeat: the stub lane ran once, DONE, window from the run dir, server verdict written", r.returncode == 0 and (TMP / "res-c3/outcome.txt").read_text().startswith("DONE")
  and (TMP / "res-c3/lane-console.log").read_text().count("EXPORT VERIFIED") == 1 and (TMP / "res-c3/t21b-server-side-verdict.json").exists(), r.stdout[-200:])
r = ctl("c3", 4)
t("C4 the same run id again is refused (rc 6): no log/result reuse", r.returncode == 6)
nn = sum(RES.values()); print(f"TEST-T21B-R3: {nn}/{len(RES)} passed")
sys.exit(0 if nn == len(RES) else 1)
