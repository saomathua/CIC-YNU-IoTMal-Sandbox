"""R3: the SAME counterexample against the R2 runner/evaluator ("before": accepted) and the R3 ones ("after": refused). Both trees are only read; every run is a
fresh temp stage with the FAKE docker/host tools of the tests. usage: python3 -I -B tests/before_after.py <R2_TREE> <R3_TREE> <OUT_JSON>"""
import importlib.util, json, os, pathlib, shutil, subprocess, sys, tempfile

R2, R3, OUT = map(pathlib.Path, sys.argv[1:4])


def load(tree, name):
    sp = importlib.util.spec_from_file_location(name, tree / "tests/test_orchestration.py")
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


T2, T3 = load(R2, "t2"), load(R3, "t3")
orig = T2.bins


def bins_plus(tmp, *a, **k):          # R2's fake host tools + the chown/cp stubs of the R3 tests (so that D3 can be provoked against R2 too)
    b = orig(tmp, *a, **k)
    for n in ("chown", "cp"):
        shutil.copy(T3_BINS[n], b / n)
    return b


tb = pathlib.Path(tempfile.mkdtemp(prefix="ba-bins."))
T3.bins(tb)
T3_BINS = {n: tb / "bin" / n for n in ("chown", "cp")}
T2.bins = bins_plus
results = {}


def record(key, before, after, note=""):
    results[key] = {"R2_before": before, "R3_after": after, "note": note}
    print(f"{key}: R2 {before}  |  R3 {after}", flush=True)


def evaluator_verdict(T, tree, S, mutate):
    """-> 'ACCEPTED' / 'REFUSED rc=…' of the tree's own evaluator on a mutated copy of the run directory."""
    rc, v, _ = T.cli_eval(S, mutate)
    return ("ACCEPTED (rc 0, all_ok true)" if rc == 0 and v and v.get("all_ok") is True else f"REFUSED (rc {rc})")


r2 = T2.run()
S2 = r2[2]
r3 = T3.run()
S3 = r3[2]
print("clean runs: R2 rc", r2[0].returncode, " R3 rc", r3[0].returncode)
assert r2[0].returncode == 0 and r3[0].returncode == 0

# ---- D1 (host measurements)
def rows2(d):
    return [l.split("\t") for l in (d / "measure-rc.tsv").read_text().splitlines()]


def mk(fn3):
    """the same logical mutation for the 3-column (R2) and the 5-column (R3) table"""
    def m(d):
        R = rows2(d)
        R = fn3(R)
        n = len(R[0])
        (d / "measure-rc.tsv").write_text("".join("\t".join((r + [""] * 5)[:n]) + "\n" for r in R))
    return m


def renum(R):
    return [r[:4] + [str(i)] if len(r) == 5 else r for i, r in enumerate(R, 1)]


MUT = {
    "D1.nft-measurement-missing-both-sides": lambda R: renum([r for r in R if r[0] not in ("h-before:nft", "h-after:nft")]),
    "D1.duplicate-name-conflicting-rc": lambda R: renum([r[:1] + ["17"] + r[2:] if r[0] == "h-before:ip-route" else r for r in R]) and
                                            renum([next(x for x in R if x[0] == "h-before:ip-route")[:1] + ["17"] + next(x for x in R if x[0] == "h-before:ip-route")[2:]] + R),
    "D1.row-points-at-another-file": lambda R: [r[:2] + ["host-before/ip6-route.txt"] + r[3:] if r[0] == "h-before:ip-route" else r for r in R],
    "D1.unknown-row-name-on-both-sides": lambda R: renum(R + [["h-before:cheat", "0", "host-before/ip-route.txt"] + R[0][3:], ["h-after:cheat", "0", "host-after/ip-route.txt"] + R[0][3:]]),
}
for key, fn in MUT.items():
    record(key, evaluator_verdict(T2, R2, S2, mk(fn)), evaluator_verdict(T3, R3, S3, mk(fn)))

# ---- D2 (final-status)
def fs(**kw):
    def m(d):
        f = json.loads((d / "final-status.json").read_text())
        f.update(kw)
        (d / "final-status.json").write_text(json.dumps(f))
    return m


for key, kw in {"D2.completed-with-stage-f6": dict(stage_reached="f6"), "D2.completed-with-signal-TERM": dict(signal="TERM"),
                "D2.other-run-label": dict(label="20200101T000000Z-1")}.items():
    record(key, evaluator_verdict(T2, R2, S2, fs(**kw)), evaluator_verdict(T3, R3, S3, fs(**kw)))

# ---- D3 (export failures)
def export_status(T, tree, env):
    tmp, S, exp, e, cmd = T.start("ok", env_extra=env)
    r = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=240)
    rc = json.loads((S / "export-receipt.json").read_text()) if (S / "export-receipt.json").is_file() else {}
    return f"exit {r.returncode}, receipt status {rc.get('status')!r}, EXPORT-RECEIPT.json {'present' if (exp / 'EXPORT-RECEIPT.json').exists() else 'absent'}"


for key, env in {"D3.chown-of-the-exported-receipt-fails": {"FAKE_CHOWN_FAIL_ON": "EXPORT-RECEIPT.json"}, "D3.copy-of-the-exported-receipt-fails": {"FAKE_CP_FAIL_ON": "EXPORT-RECEIPT.json"}}.items():
    record(key, export_status(T2, R2, env), export_status(T3, R3, env), "R2: unchecked `cp && chown` after the status 'verified' was decided")

# ---- D4 (frozen run directory)
def stage_manifest(S):
    r = subprocess.run(["sha256sum", "--strict", "--check", "--quiet", "EVIDENCE-SHA256SUMS"], cwd=S / "run", capture_output=True, text=True)
    return f"stage manifest check after the exit: rc {r.returncode}" + (f" ({r.stdout.strip()[:80]})" if r.returncode else "")


record("D4.stage-manifest-verifies-after-exit", stage_manifest(S2), stage_manifest(S3), "R2 appended export.err/run.log lines after the manifest was computed")
record("D4.extra-writers-into-run-dir", f"export.err in run dir: {(S2 / 'run/export.err').exists()}", f"export.err in run dir: {(S3 / 'run/export.err').exists()}; finalize.log/export.log outside: {(S3 / 'finalize.log').exists()}")
OUT.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
