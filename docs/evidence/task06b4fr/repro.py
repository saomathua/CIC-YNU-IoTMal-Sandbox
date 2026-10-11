#!/usr/bin/env python3
"""06B-4FR — before/after reproduction of the two review findings, offline (fake container, no packet).
For each harness version (06B-4F, 06B-4FR) the version's own probe_matrix.py / icmp_harness.py / run-06b4f.sh
are used; only the scenario driver (selftest_icmp_wiring.py) is taken from 06B-4FR, because the two P1
scenarios exist only there.
    python3 repro.py /home/dathq/projects/ct01-06b4f /home/dathq/projects/ct01-06b4fr
"""
import copy
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile


def prepare(version_dir, driver, tmp, tag):
    d = os.path.join(tmp, tag)
    os.makedirs(d)
    for f in glob.glob(os.path.join(version_dir, "*.py")) + glob.glob(os.path.join(version_dir, "*.sh")):
        shutil.copy2(f, d)
    shutil.copy2(driver, os.path.join(d, "selftest_icmp_wiring.py"))
    return d


def scenario(d, name):
    out = os.path.join(d, "sc-" + name)
    subprocess.run([sys.executable, "-I", os.path.join(d, "selftest_icmp_wiring.py"), "--scenario", name, "--dir", out],
                   check=True, capture_output=True, text=True, timeout=300)
    sc = json.load(open(os.path.join(out, "scenario.json")))
    res = json.load(open(os.path.join(out, "out", "ARM", "result.json")))
    pings = [c for k, c in sc["commands"] if k == "run" and c.startswith("ping")]
    return {"rc": sc["rc"], "status": res["status"], "pings": [p.split(" -s ")[1].split()[0] for p in pings], "dir": out}


def outcome(d, res, ev_path, tmp):
    f = os.path.join(tmp, "variant.json")
    json.dump(res, open(f, "w"))
    p = subprocess.run([sys.executable, os.path.join(d, "icmp_harness.py"), "--outcome", f, ev_path, "ARM"],
                       capture_output=True, text=True)
    return p.stdout.strip() or f"(no output, rc={p.returncode}, {p.stderr.strip()[-120:]})"


def variants(res0, required):
    def without(pred):
        r = copy.deepcopy(res0)
        r["results"] = [x for x in r["results"] if not pred(x)]
        return r

    def edit(name, **kw):
        r = copy.deepcopy(res0)
        for x in r["results"]:
            if x["test"] == name:
                x.update(kw)
        return r
    v = [("clean fixture (real clean run)", res0)]
    v += [(f"missing: {n}", without(lambda x, n=n: x["test"] == n)) for n in required]
    v.append(("missing: ALL required confirmations", without(lambda x: x["test"] in required)))
    for n in ("QEMU exit confirmed", "tap0 capture stopped cleanly"):
        r = copy.deepcopy(res0)
        r["results"].append({"test": n, "ok": True})
        v.append((f"duplicate (both ok): {n}", r))
    for val in ("true", 1, None):
        v.append((f"wrong type ok={val!r}: QEMU exit confirmed", edit("QEMU exit confirmed", ok=val)))
    r = copy.deepcopy(res0)
    del [x for x in r["results"] if x["test"] == "tap0 capture stopped cleanly"][0]["ok"]
    v.append(("'ok' key missing: tap0 capture stopped cleanly", r))
    v.append(("not passed ok=False: QEMU exit confirmed", edit("QEMU exit confirmed", ok=False)))
    v.append(("not passed ok=False: fixture, marker and temporary guest disk removed",
              edit("fixture, marker and temporary guest disk removed", ok=False)))
    return v


def short(o):
    return o if len(o) <= 110 else o[:107] + "..."


def main(old, new):
    sys.path.insert(0, new)
    import icmp_harness as H_new
    driver = os.path.join(new, "selftest_icmp_wiring.py")
    with tempfile.TemporaryDirectory(prefix="repro-06b4fr.") as tmp:
        dirs = {"06B-4F": prepare(old, driver, tmp, "06b4f"), "06B-4FR": prepare(new, driver, tmp, "06b4fr")}
        print("== P1: alert / unreadable alert file appears during the counter read 'T12-B2 before'")
        for name in ("leak-before-B2", "alert-unreadable-before-B2"):
            for tag, d in dirs.items():
                s = scenario(d, name)
                print(f"{name:28s} {tag:8s} rc={s['rc']:<3d} pings sent (sizes)={s['pings']}  status={s['status'][:90]}")
        print()
        print("== P2: required infrastructure confirmations (variants of the REAL clean run of each version,")
        print("        judged by that version's `icmp_harness.py --outcome`, the call made by run-06b4f.sh)")
        rows = {}
        for tag, d in dirs.items():
            c = scenario(d, "clean")
            res0 = json.load(open(os.path.join(c["dir"], "out", "ARM", "result.json")))
            ev = os.path.join(c["dir"], "out", "ARM", "icmp-eval.json")
            for label, r in variants(res0, H_new.REQUIRED_RECORDS):
                rows.setdefault(label, {})[tag] = outcome(d, r, ev, tmp)
        wrong = 0
        for label, o in rows.items():
            want_pass = label.startswith("clean")
            bad_before = o["06B-4F"].startswith("PASS") != want_pass
            bad_after = o["06B-4FR"].startswith("PASS") != want_pass
            wrong += bad_after
            print(f"- {label}")
            print(f"    06B-4F : {'WRONG ' if bad_before else 'ok    '}{short(o['06B-4F'])}")
            print(f"    06B-4FR: {'WRONG ' if bad_after else 'ok    '}{short(o['06B-4FR'])}")
        before_wrong = sum(o["06B-4F"].startswith("PASS") != l.startswith("clean") for l, o in rows.items())
        print(f"\nP2 summary: {len(rows)} variants; wrong conclusion 06B-4F: {before_wrong}, 06B-4FR: {wrong}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
