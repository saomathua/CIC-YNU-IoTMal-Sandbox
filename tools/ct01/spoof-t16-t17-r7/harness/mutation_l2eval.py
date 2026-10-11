#!/usr/bin/env python3
"""06B-4D1 — mutation test of l2eval.py (offline). Each mutant is built in its own mktemp copy; every
replacement text must occur exactly once (else INVALID). Classification as in mutation_l2.py:
DETECTED (target test failed), DETECTED-ELSEWHERE, MISSED, INVALID, ERROR. Baseline must pass first;
expected: every behavioural mutation DETECTED, controls X1 INVALID and X2 ERROR; harness hash unchanged.
    python3 mutation_l2eval.py
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("l2eval.py", "selftest_l2eval.py", "selftest_l2.py", "l2frames.py", "counter_window.py", "signatures.py",
         "sigscan_l2.py", "guest_state.py", "run-06b3b.sh")
M = [
    ("V1", [('            raise InputError(f"{path}:{n}: duplicate label {label!r}")', '            pass')],
     "M2 duplicate label -> ERROR from the measurement-data check"),
    ("V2", [('            if lbl not in reads:', '            if False:')], "M1 read label 'B' missing -> ERROR from the measurement-data check"),
    ("V3", [('            if not isinstance(pk, int) or isinstance(pk, bool) or pk < 0:', '            if not isinstance(pk, int) or pk < 0:')],
     "M6 counter packets is a bool -> ERROR from the measurement-data check"),
    ("V4", [('        if not (_finite(t0) and _finite(t1)):', '        if False:')], "M5 read time not finite -> ERROR from the measurement-data check"),
    ("V5", [('        if not values:\n            raise InputError', '        if False:\n            raise InputError')],
     "M8 read without any counter -> ERROR from the measurement-data check"),
    ("V6", [('            res["not_compared"][k] = {"delta": None, "missing_in": "before" if a is None else "after", "reason": why}',
             '            res["not_compared"][k] = {"delta": 0, "reason": why}')],
     "M13 a NOT compared counter missing in one read is reported missing (delta null), never 0"),
    ("V7", [('    except L.FrameReadError as e:\n        res["error"] = f"capture read error: {e}"',
             '    except L.FrameReadError as e:\n        frames = []')],
     "X1 missing capture -> ERROR (capture read error), not 0 frames"),
    ("V8", [('EXIT = {"PASS": 0, "FAIL": 1, "UNVERIFIED": 4, "ERROR": 2}', 'EXIT = {"PASS": 0, "FAIL": 1, "UNVERIFIED": 0, "ERROR": 2}')],
     "C4 UNVERIFIED -> exit 4"),
    ("V9", [('            if counter_window.zone(f["t"], ra, rb, guard) == "outside":', '            if False:')],
     "S3 frames counted by direction/class inside the window; the outside frame is counted apart"),
    ("V10", [('    if rec.get("no_counter_frames"):\n        kinds', '    if False:\n        kinds')],
     "S10 UNVERIFIED: a frame without a counter mapping inside the window, listed"),
    ("V11", [('    if a.out:\n        with open(a.out, "w") as f:', '    if a.out and res["verdict"] != "ERROR":\n        with open(a.out, "w") as f:')],
     "C3 ERROR -> exit 2, JSON still written with the error"),
    ("V12", [('    except ValueError as e:                       # e.g. a malformed TAP MAC\n        res["error"] = f"invalid argument: {e}"',
              '    except ValueError as e:                       # e.g. a malformed TAP MAC\n        res["error"] = f"capture read error: {e}"')],
     "X5 malformed TAP MAC -> ERROR (invalid argument)"),
    ("V13", [('            raise InputError(f"{path}:{n}: counter {name} listed twice")', '            pass')],
     "M16 a counter listed twice in one read -> ERROR"),
    # ---- 06B-4D1R
    ("W1", [('    if not classes:\n        raise ValueError("empty list', '    if False:\n        raise ValueError("empty list')],
     "N1 classes=[] -> ERROR (nothing compared is never PASS)"),
    ("W2", [('    if dup:\n        raise ValueError', '    if False:\n        raise ValueError')], "N2 duplicate class name -> ERROR"),
    ("W3", [('    bad = [c for c in classes if not isinstance(c, str) or c not in L.COUNTER_CLASSES]', '    bad = []')],
     "N4 unobservable class (arp_out_drop) -> ERROR before reading anything"),
    ("W4", [('    if isinstance(classes, str) or not isinstance(classes, (list, tuple)):',
             '    if not isinstance(classes, (list, tuple, str)):')], "N5 classes given as a string -> ERROR"),
    ("W5", [('([] if a.classes == "" else a.classes.split(","))', '[c for c in a.classes.split(",") if c]')],
     'C7 --classes "a,,b" (empty name) -> exit 2, not filtered'),
    ("W6", [('            if not isinstance(c, dict):\n                raise InputError', '            if False:\n                raise InputError')],
     "J1 nftables=[{counter: null}] -> ERROR with reason (evaluate)"),
    ("W7", [('        if not isinstance(objs, list):\n            raise InputError', '        if False:\n            raise InputError')],
     "J2 nftables=null -> ERROR with reason (evaluate)"),
    ("W8", [('            if not isinstance(o, dict):\n                raise InputError', '            if not isinstance(o, dict):\n                continue\n                raise InputError')],
     "J6 a non-object element among valid counters (not skipped) -> ERROR with reason (evaluate)"),
    ("W9", [('            if "name" not in c or "packets" not in c:\n                raise InputError', '            if False:\n                raise InputError')],
     "J7 counter without packets -> ERROR with reason (evaluate)"),
    ("W10", [('        if not isinstance(raw, str):\n            raise InputError', '        if False:\n            raise InputError')],
     "J11 raw is an object, not text -> ERROR with reason (evaluate)"),
    ("W11", [('        if not isinstance(doc, dict) or "nftables" not in doc:', '        if "nftables" not in doc:')],
     "J4 nft output is a list -> ERROR with reason (evaluate)"),
    ("W12", [('        if not isinstance(rec, dict):\n            raise InputError', '        if False:\n            raise InputError')],
     "J9 record line is a JSON list -> ERROR with reason (evaluate)"),
    ("W13", [('            if not isinstance(name, str) or not name:', '            if not isinstance(name, str):')],
     "J12 counter name empty -> ERROR with reason (evaluate)"),
    ("X1", [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", [("import argparse\n", "import argparse(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def suite(d):
    p = subprocess.run([sys.executable, os.path.join(d, "selftest_l2eval.py"), "--offline-only"],
                       capture_output=True, text=True, timeout=600, cwd=d)
    lines = p.stdout.splitlines()
    res = {}
    for l in lines:
        if l.startswith("[PASS] ") or l.startswith("[FAIL] "):
            res[l[7:].split("  (")[0]] = l.startswith("[PASS]")
    if not any(l.startswith("SELFTEST-L2EVAL:") for l in lines):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    h0 = sha(HERE)
    good = bad = 0
    with tempfile.TemporaryDirectory(prefix="mutation-l2eval.") as tmp:
        def copy():
            d = tempfile.mkdtemp(dir=tmp)
            for f in FILES:
                shutil.copy2(os.path.join(HERE, f), d)
            return d
        base, err = suite(copy())
        if base is None or not all(base.values()):
            print("BASELINE FAILED", err or [k for k, v in base.items() if not v])
            return 2
        print(f"baseline: {len(base)}/{len(base)} tests pass")
        for mid, reps, target in M:
            if target is not None and target not in base:
                print(f"BAD-TARGET {mid}: {target!r}")
                bad += 1
                continue
            d = copy()
            src = open(os.path.join(d, "l2eval.py")).read()
            klass, failed = None, []
            for old, new in reps:
                if src.count(old) != 1:
                    klass = "INVALID"
                    break
                src = src.replace(old, new)
            if klass is None:
                open(os.path.join(d, "l2eval.py"), "w").write(src)
                res, err = suite(d)
                if res is None:
                    klass = "ERROR"
                else:
                    failed = sorted(k for k, v in res.items() if not v)
                    klass = "DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED"
            exp = EXPECT.get(mid, "DETECTED")
            ok = klass == exp
            good += ok
            bad += not ok
            print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}" + ("" if klass in ("DETECTED", "INVALID", "MISSED") else f" failed={failed[:5]} {err or ''}"))
    same = sha(HERE) == h0
    print(f"MUTATION-L2EVAL: {good} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
