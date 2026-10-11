#!/usr/bin/env python3
"""06B-4F (+ 06B-4FR W28-W34) — mutation test of the ICMP wiring (icmp_harness.py, probe_matrix.py icmp branch, run-06b4f.sh),
offline. Each mutant runs selftest_icmp_wiring.py in its own mktemp copy of every harness file; every
replacement must occur exactly once (else INVALID). DETECTED / DETECTED-ELSEWHERE / MISSED / INVALID / ERROR
as in mutation_icmp.py. Baseline must pass; harness hash checked before/after.
    python3 mutation_icmp_wiring.py
"""
import concurrent.futures
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(HERE, "*.py")) + glob.glob(os.path.join(HERE, "*.sh")))
IH, PM, RS = "icmp_harness.py", "probe_matrix.py", "run-06b4f.sh"
M = [
    # ---- icmp_harness.py
    ("W1", IH, [('    ok = rc == 0 and http == "200" and sha is not None and sha == expected_sha',
                 '    ok = rc == 0 and sha is not None and sha == expected_sha')],
     "U2 link: HTTP 000 with the right hash (stale file) -> not ok"),
    ("W2", IH, [('    ok = rc == 0 and http == "200" and sha is not None and sha == expected_sha',
                 '    ok = rc == 0 and http == "200"')], "U3 link: HTTP 200, other hash -> not ok"),
    ("W3", IH, [('    return (f"rm -f /tmp/r.out; curl', '    return (f"curl')],
     "U9 link command removes the old response first and asks for code + hash"),
    ("W4", IH, [('        if self.stop is not None:\n            raise SuiteStopped', '        if False:\n            raise SuiteStopped')],
     "U11 GuardedRunner: a failing check stops the group; later commands never reach the guest"),
    ("W5", IH, [('                if self.stop is None:\n                    self.stop = e\n', '                pass\n')],
     "U12 GuardedRunner: a failing after-check raises even though the command ran, and stops the group"),
    ("W6", IH, [('    if missing:\n        p.append', '    if False:\n        p.append')], "U16 check_record: a missing case"),
    ("W7", IH, [('    if dup:\n        p.append', '    if False:\n        p.append')], "U17 check_record: a duplicate case"),
    ("W8", IH, [('        if not link_valid(record.get(k), fixture_sha):', '        if False:')],
     "U21 check_record: link after with another hash"),
    ("W9", IH, [('    if result.get("status") != "COMPLETED":', '    if False:')],
     "U27 arch_outcome: status not COMPLETED -> FAIL"),
    ("W10", IH, [('            if isinstance(c, dict) and "verdict" in c and names[case_test_name(c)] != 1:',
                  '            if False:')], "U31 arch_outcome: a case recorded twice in result.json -> FAIL"),
    ("W11", IH, [('    if hard:\n        rest', '    if False:\n        rest')],
     "U29 arch_outcome: a case missing in the evaluation -> FAIL"),
    ("W12", IH, [('        if icmp_eval.get("arch") != arch:', '        if False:')],
     "U34 arch_outcome: evaluation of another architecture -> FAIL"),
    ("W13", IH, [('            p.append(f"{a}: {EVAL_FILE} missing or unreadable")', '            pass')],
     "S30 run-check: MIPS missing (e.g. loop stopped after ARM) -> exit 1"),
    ("W14", IH, [('    return f"probe {case_result', '    return f"icmp {case_result')],
     "S17 ping6 missing (rc 127): T13 cases LOI_THUC_THI, T12 cases still ĐẠT; outcome UNVERIFIED, never PASS"),
    # ---- probe_matrix.py (icmp branch only)
    ("W16", PM, [('    if runner.stop is not None:\n        raise runner.stop', '    if False:\n        raise runner.stop')],
     "S12 marker-after-B4: exit 98, CAPTURE LOST, only 3 ping(s) reached the guest, no service link after"),
    ("W17", PM, [('        if alerts:\n            record("NO probe packet seen on host interfaces (leak monitor)", False, command=cmd, when=when',
                  '        if False:\n            record("NO probe packet seen on host interfaces (leak monitor)", False, command=cmd, when=when')],
     "S16 leak after T12-B2: exit 99, LEAK, no further ping, leak record, outcome FAIL"),
    ("W18", PM, [('        captures_alive(tshark, f"before guest command {cmd!r}")', '        pass')],
     "S33 capture lost between two cases (during the counter read): caught BEFORE the next ping, exit 98, 1 ping"),
    ("W19", PM, [('            evaluate_icmp() if SUITE == "icmp" else evaluate()', '            evaluate()')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS, run script maps it to PASS"),
    ("W20", PM, [('"destinations)", all(v["ok"] for v in r.values()), **r)', '"destinations)", True, **r)')],
     "S34 capture-liveness traffic from the worker fails: every case ĐẠT, outcome FAIL"),
    ("W21", PM, [('        if SUITE == "ipv4":   # 06B-4F: the listener', '        if True:   # 06B-4F: the listener')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS, run script maps it to PASS"),
    ("W22", PM, [('        res = icmp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), ICMP["tap_mac"],',
                  '        res = icmp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), "02:00:00:00:00:01",')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS, run script maps it to PASS"),
    ("W23", PM, [('           not res["record_problems"], problems=res["record_problems"])', '           True, problems=res["record_problems"])')],
     "S10 missing-case: never PASS; outcome FAIL with the record problem; script FAIL"),
    # ---- run-06b4f.sh
    ("W24", RS, [('-e CT01_SUITE=icmp "$ID"', '"$ID"')], "W3 exactly one probe_matrix call, with CT01_SUITE=icmp"),
    ("W25", RS, [(' -v "$H/l2eval.py:/harness/l2eval.py:ro"', '')],
     "W5 every module probe_matrix imports in icmp mode is mounted read-only"),
    ("W26", RS, [('    0:PASS) pass', '    0:PASS|1:UNVERIFIED*) pass')],
     "S18 ping6 missing: the run script reports UNVERIFIED (not PASS, not a silent pass)"),
    ("W27", RS, [('python3 "$H/selftest_icmp_wiring.py" > "$OUT/selftest-icmp-wiring.txt" 2>&1 || { cat "$OUT/selftest-icmp-wiring.txt"; echo "ABORT: ICMP wiring self-test failed"; exit 3; }\n', '')],
     "W4 self-tests (incl. ICMP + wiring) run before any docker command and abort the run if they fail"),
    # ---- 06B-4FR
    ("W28", PM, [('        check_alerts(cmd, "before")\n', '')],
     "S35 alert written during 'T12-B2 before' (read A): ping T12-B2 NOT sent, exit 99, LEAK before the command"),
    ("W29", PM, [('        alerts = alert_lines()\n        if alerts:',
                  '        try:\n            alerts = alert_lines()\n        except Exception:\n            alerts = []\n        if alerts:')],
     "S37 alert file unreadable during read A: never read as 'no alert'; ping T12-B2 NOT sent, run stops (ERROR)"),
    ("W30", IH, [('            p.append(f"required confirmation missing: {name}")', '            pass')],
     "R5 every required confirmation missing (only info and case records left) -> FAIL, all listed (CLI)"),
    ("W31", IH, [('        elif len(recs) > 1:', '        elif False:')],
     "R7 required confirmation recorded twice (both ok) -> FAIL (CLI): QEMU exit confirmed"),
    ("W32", IH, [('or not isinstance(r.get("ok"), bool)]', ']')],
     "R8 'ok' of a required confirmation is 'true' (not a boolean) -> FAIL (CLI)"),
    ("W33", IH, [('    "QEMU exit confirmed",\n', '')],
     "R2 the real ICMP path records no other non-info, non-case check outside the required list"),
    ("W34", IH, [('    hard += record_problems(result["results"])', '    pass')],
     "R4.15 required confirmation missing -> FAIL: fixture, marker and temporary guest disk removed"),
    ("X1", IH, [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", "selftest_icmp_wiring.py", [("import collections\n", "import collections(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def suite(d):
    p = subprocess.run([sys.executable, os.path.join(d, "selftest_icmp_wiring.py")], capture_output=True, text=True,
                       timeout=900, cwd=d)
    res = {}
    for l in p.stdout.splitlines():
        if l.startswith("[PASS] ") or l.startswith("[FAIL] "):
            res[l[7:].split("  (")[0]] = l.startswith("[PASS]")
    if not any(l.startswith("SELFTEST-ICMP-WIRING:") for l in p.stdout.splitlines()):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    h0 = sha(HERE)
    with tempfile.TemporaryDirectory(prefix="mutation-icmp-wiring.") as tmp:
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

        def one(entry):
            mid, fname, reps, target = entry
            if target is not None and target not in base:
                return mid, "BAD-TARGET", target, [], None
            d = copy()
            src = open(os.path.join(d, fname)).read()
            for old, new in reps:
                if src.count(old) != 1:
                    return mid, "INVALID", target, [], None
                src = src.replace(old, new)
            open(os.path.join(d, fname), "w").write(src)
            res, err = suite(d)
            if res is None:
                return mid, "ERROR", target, [], err
            failed = sorted(k for k, v in res.items() if not v)
            return mid, ("DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED"), target, failed, None
        good = bad = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            for mid, klass, target, failed, err in ex.map(one, M):
                ok = klass == EXPECT.get(mid, "DETECTED")
                good += ok
                bad += not ok
                print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}"
                      + ("" if klass in ("DETECTED", "INVALID", "MISSED") else f" failed={failed[:5]} {err or ''}"))
    same = sha(HERE) == h0
    print(f"MUTATION-ICMP-WIRING: {good} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
