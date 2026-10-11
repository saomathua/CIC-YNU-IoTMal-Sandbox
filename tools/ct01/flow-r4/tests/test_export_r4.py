#!/usr/bin/env python3
"""R4 narrow tests: export_run.py (X1 manifest hashes, X2 receipts) and the lane_entry.sh exit priority with STUB lane/evaluator. No docker/network/root.
usage: python3 -I -B tests/test_export_r4.py <tree>"""
import importlib.util, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time
TREE = pathlib.Path(sys.argv[1]).resolve()
RES = {}
def t(n, ok, d=""):
    RES[n] = bool(ok); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"  -> {d}"), flush=True)
TMP = pathlib.Path(tempfile.mkdtemp(prefix="exp4."))
XR = TREE / "export_run.py"
spec = importlib.util.spec_from_file_location("xr", XR); XM = importlib.util.module_from_spec(spec); spec.loader.exec_module(XM)

def mkrun(name):
    st = TMP / name; run = st / "run"; (run / "sub").mkdir(parents=True)
    (run / "identity.json").write_text('{"a":1}\n'); (run / "data.txt").write_text("payload\n"); (run / "sub" / "x.log").write_text("x\n")
    os.symlink("data.txt", run / "link")
    return st, run

def export(run, out, lane=0, ev=0, sig=0, stage=None, env=None):
    cmd = [sys.executable, "-I", "-B", str(XR), str(run), str(out), "--uid", str(os.getuid()), "--gid", str(os.getgid()), "--lane-rc", str(lane), "--eval-rc", str(ev),
           "--signal", str(sig)] + (["--stage", str(stage)] if stage else [])
    p = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, **(env or {})))
    return p.returncode, p.stdout, p.stderr

st, run = mkrun("c"); rc, so, se = export(run, TMP / "c-out", stage=st)
rcp = json.loads((st / "export-receipt.json").read_text())
t("C clean control: rc 0, verified, symlink kept, both receipts, every manifest line hashed", rc == 0 and "EXPORT VERIFIED" in so and rcp["export_status"] == "verified"
  and os.path.islink(TMP / "c-out/link") and (TMP / "c-out.export-receipt.json").exists() and rcp["steps"]["verify"]["detail"]["files"] >= 4, so + se)
T = {"CT01_EXPORT_TESTING": "1"}
st, run = mkrun("m1"); rc, so, se = export(run, TMP / "m1-out", stage=st, env=dict(T, CT01_EXPORT_FAULT="mutate-after-manifest:data.txt"))
rcp = json.loads((st / "export-receipt.json").read_text())
t("X1a review fixture: data.txt changed AFTER the manifest and BEFORE the copy (stage==copy, manifest stale): NOT verified, rc 4, names the file",
  rc == 4 and "EXPORT NOT VERIFIED" in so and rcp["steps"]["verify"]["ok"] is False and "data.txt" in rcp["steps"]["verify"]["detail"], so + str(rcp["steps"]["verify"]))
st, run = mkrun("m2"); rc, so, se = export(run, TMP / "m2-out", stage=st, env=dict(T, CT01_EXPORT_FAULT="mutate-after-copy:sub/x.log"))
t("X1b a copy file that differs from its manifest line after the copy: NOT verified, rc 4", rc == 4 and "NOT VERIFIED" in so)
# manifest well-formedness
d = TMP / "mf"; d.mkdir(); (d / "a").write_text("1"); h = XM.sha(d / "a")
(d / "MANIFEST-SYMLINKS").write_text("")
def mf(text):
    (d / "MANIFEST-SHA256").write_text(text)
    try:
        XM.check_tree(d); return True
    except ValueError:
        return False
ok_line = f"{h}  a\n{XM.sha(d / 'MANIFEST-SYMLINKS')}  MANIFEST-SYMLINKS\n"
t("X1c manifest forms: well-formed passes; duplicate, blank, missing file line, bad hash, absolute and '..' paths are refused",
  mf(ok_line) and not mf(ok_line + ok_line) and not mf(ok_line + "\n") and not mf("") and not mf(ok_line.replace(h, "0" * 64, 1)) and not mf(ok_line + f"{h}  /a\n") and not mf(ok_line + f"{h}  ../a\n"))
(d / "MANIFEST-SHA256").write_text(ok_line); (d / "b").write_text("2")
try:
    XM.check_tree(d); extra = False
except ValueError:
    extra = True
t("X1d a file present in the tree but not in the manifest is refused", extra)
# receipts (X2)
st, run = mkrun("r1"); st.chmod(0o500)
rc, so, se = export(run, TMP / "r1-out", stage=st)
st.chmod(0o700)
t("X2a stage receipt cannot be written: rc 4, stderr says RECEIPT WRITE FAILED, never EXPORT VERIFIED, the stage kept", rc == 4 and "RECEIPT WRITE FAILED (receipt_stage)" in se
  and "EXPORT VERIFIED" not in so and "EXPORT NOT VERIFIED" in so and (run / "identity.json").exists(), so + se)
st, run = mkrun("r2"); (TMP / "r2-out.export-receipt.json").mkdir()
rc, so, se = export(run, TMP / "r2-out", stage=st)
t("X2b sidecar receipt cannot be written (path is a directory): rc 4, RECEIPT WRITE FAILED (receipt_sidecar), not verified", rc == 4 and "receipt_sidecar" in se and "EXPORT VERIFIED" not in so, so + se)
st, run = mkrun("r3"); rc, so, se = export(run, TMP / "r3-out", uid=None, stage=st) if False else (None, None, None)
cmd = [sys.executable, "-I", "-B", str(XR), str(run), str(TMP / "r3-out"), "--uid", "0" if os.getuid() else "1", "--gid", "0", "--lane-rc", "0", "--eval-rc", "0", "--signal", "0", "--stage", str(st)]
p = subprocess.run(cmd, capture_output=True, text=True)
t("X2c chown (also of the sidecar) not permitted: rc 4, not verified", p.returncode == 4 and "EXPORT VERIFIED" not in p.stdout)
# priority through lane_entry.sh with stub lane/evaluator
def entry(name, lane_rc, eval_rc, pre=None, sig_after=None, lane_sleep=0):
    stg = TMP / ("e-" + name); (stg / "tree").mkdir(parents=True)
    shutil.copy(TREE / "export_run.py", stg / "tree"); shutil.copy(TREE / "lane_entry.sh", stg / "tree")
    (stg / "tree" / "flow_lane.py").write_text(f"import sys,time,pathlib\nr=pathlib.Path(sys.argv[2]); r.mkdir(parents=True)\n(r/'identity.json').write_text('{{}}')\ntime.sleep({lane_sleep})\nsys.exit({lane_rc})\n")
    (stg / "tree" / "evaluate_flow.py").write_text(f"import sys\nsys.exit({eval_rc})\n")
    (stg / "tree" / "pins.json").write_text("{}"); (stg / "tree" / "fixtures").mkdir()
    out = TMP / ("eo-" + name)
    if pre:
        pre(out)
    env = dict(os.environ, CT01_FLOW_PY=sys.executable, SUDO_UID=str(os.getuid()), SUDO_GID=str(os.getgid()))
    p = subprocess.Popen(["/bin/bash", str(stg / "tree" / "lane_entry.sh"), "f5", str(stg), str(out), "sha256:x", "m"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if sig_after:
        time.sleep(sig_after); p.send_signal(signal.SIGTERM)
    o, _ = p.communicate(timeout=60)
    rcp = json.loads((stg / "export-receipt.json").read_text()) if (stg / "export-receipt.json").exists() else None
    return p.returncode, o, rcp
rc, o, r = entry("ok", 0, 0)
t("P1 clean: exit 0, verified", rc == 0 and r["export_status"] == "verified", o)
rc, o, r = entry("x", 0, 0, pre=lambda out: out.mkdir())
t("P2 export fails only: exit 4", rc == 4 and r["export_status"] == "not_verified", o)
rc, o, r = entry("l", 3, 0, pre=lambda out: out.mkdir())
t("P3 lane rc 3 + export fails: exit 3", rc == 3 and r["final_rc"] == 3, o)
rc, o, r = entry("v", 0, 1, pre=lambda out: out.mkdir())
t("P4 evaluator rc 1 + export fails: exit 1", rc == 1 and r["final_rc"] == 1, o)
rc, o, r = entry("s", 0, 0, sig_after=1.5, lane_sleep=4)
t("P5 SIGTERM during the lane: finalised once, exit 143, receipt carries the signal", rc == 143 and r and r["signal"] == 15, o)
n = sum(RES.values()); print(f"TEST-EXPORT-R4: {n}/{len(RES)} passed")
sys.exit(0 if n == len(RES) else 1)
