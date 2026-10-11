#!/usr/bin/env python3
"""06B-4IR3 — targeted mutation test of the precheck collector/evaluator/root snippet (PC-2, PC-4), offline.
Each mutant runs selftest_precheck.py on a mktemp copy; every replacement must occur exactly once (else INVALID).
A mutant counts only if the TARGET test fails (DETECTED); ERROR/timeout never count as detected.
    python3 -I -B mutation_precheck.py
"""
import hashlib, os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("collector.py", "evaluate_precheck.py", "RUN-PROCEDURE.md", "selftest_precheck.py")
CO, EVL, RP = "collector.py", "evaluate_precheck.py", "RUN-PROCEDURE.md"
C5 = ("C5 permission-denied: harness containers UNKNOWN (never 'absent'), manager UNKNOWN (never 'not running'), exec "
      "skipped as 'state unknown', collector exit 3, evaluator UNKNOWN (2), no FAIL invented")
M = [
    ("P1", EVL, [('            item(items, f"harness container {c} absent", "UNKNOWN", reason=err)',
                  '            item(items, f"harness container {c} absent", "PASS", reason=err)')], C5),
    ("P2", CO, [('        status = "OK" if error is None and rc in ok_rcs else', '        status = "OK" if True else')], C5),
    ("P3", CO, [('os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)', 'os.O_RDONLY | os.O_DIRECTORY)')],
     "O1b symlink to an EMPTY directory with the right owner/mode -> still refused (only O_NOFOLLOW stops it)"),
    ("P4", CO, [('os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600', 'os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600')],
     "O4 a symlink planted under an output name -> creation fails (O_EXCL|O_NOFOLLOW), target untouched"),
    ("P5", CO, [('r = subprocess.run(argv, env=dict(ENV),', 'r = subprocess.run(argv, env=None,')],
     "O7 subprocess environment is exactly the fixed minimal one (nothing inherited)"),
    ("P6", EVL, [('"PASS" if out.strip() == EXPECTED_IMAGE_ID else "FAIL"', '"PASS"')],
     "C6 image id differs from the reviewed one -> FAIL (compared automatically), evaluator exit 1 path"),
    ("P7", CO, [('        elif len(names) != 1:', '        elif len(names) < 1:')],
     "C8 network-ambiguous: network not inspected (SKIPPED, reason kept), collector exit 3, evaluator UNKNOWN"),
    ("P8", CO, [('    running = m["status"] == "OK" and', '    running = True or')],
     "C4 manager exited -> no docker exec at all (SKIPPED with the reason)"),
    ("P9", RP, [('if ! echo "$HASH  $T/collector.py" | /usr/bin/sha256sum -c --quiet - ; then',
                 'if false; then')],
     "L2 snippet with a wrong hash (file swapped/changed): nothing run, the copy removed, exit 1"),
    ("P10", CO, [('ok_rcs=(0, 1))       # 1 = no process', 'ok_rcs=(0, 1, 2))       # 1 = no process')],
     "C14 pgrep-error: pgrep rc 1 = none, rc 0 = present (FAIL), other rc = read error (UNKNOWN), never 'none'"),
    ("P11", EVL, [('"UNKNOWN" if any(i["status"] == "UNKNOWN" for i in req) else "PASS"', '"PASS"')],
     "E3 evaluator CLI exit 2 on missing/failed reads"),
    ("P12", CO, [('    complete = all(r["status"] == "OK" for r in c.reads if r["required"])', '    complete = True')],
     "C15 nft read error -> UNKNOWN + collector exit 3"),
    ("X1", CO, [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", "selftest_precheck.py", [("import json\n", "import json(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def suite(d):
    try:
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(d, "selftest_precheck.py")], capture_output=True,
                           text=True, timeout=300, cwd=d)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    res = {l[7:].split("  (")[0]: l.startswith("[PASS]") for l in p.stdout.splitlines() if l[:7] in ("[PASS] ", "[FAIL] ")}
    if not any(l.startswith("SELFTEST-PRECHECK:") for l in p.stdout.splitlines()):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    h0 = {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest() for f in FILES}
    good = bad = 0
    with tempfile.TemporaryDirectory(prefix="mutation-precheck.") as tmp:
        def copy():
            d = tempfile.mkdtemp(dir=tmp)
            for f in FILES:
                shutil.copy2(os.path.join(HERE, f), d)
            return d
        base, err = suite(copy())
        if base is None or not all(base.values()):
            print("BASELINE FAILED", err)
            return 2
        print(f"baseline: {len(base)}/{len(base)} tests pass")
        for mid, fname, reps, target in M:
            if target is not None and target not in base:
                print(f"BAD {mid} BAD-TARGET {target!r}"); bad += 1; continue
            d = copy(); src = open(os.path.join(d, fname)).read(); klass = None
            for old, new in reps:
                if src.count(old) != 1:
                    klass = "INVALID"; break
                src = src.replace(old, new)
            failed = []
            if klass is None:
                open(os.path.join(d, fname), "w").write(src)
                res, err = suite(d)
                if res is None:
                    klass = "ERROR"
                else:
                    failed = sorted(k for k, v in res.items() if not v)
                    klass = "DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED"
            ok = klass == EXPECT.get(mid, "DETECTED")
            good += ok; bad += not ok
            print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}" + ("" if ok else f" failed={failed[:4]}"))
    same = h0 == {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest() for f in FILES}
    print(f"MUTATION-PRECHECK: {good} OK, {bad} not as expected; files {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
