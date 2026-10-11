#!/usr/bin/env python3
"""06B-4I — export the outputs of selected offline wiring scenarios (selftest_arp_wiring.run_scenario: the REAL
probe_matrix.main() with CT01_SUITE=arp, simulated guest, stub worker) as evidence fixtures.
    python3 export_fixtures.py HARNESS_DIR RUN_DIR FIXTURE_DIR
Copies, per scenario: scenario.json (exit code, guest/worker commands, modules), result.json, arp-group.json,
arp-eval.json, counters-raw.jsonl, tap0.pcapng, session.json, plus the outcome of arp_harness --outcome and the run
script mapping. Everything here is SIMULATED; nothing was sent to a guest or a network."""
import json
import os
import shutil
import sys

harness, run_dir, fx = sys.argv[1:4]
sys.path.insert(0, harness)
import selftest_arp_wiring as T   # noqa: E402

NAMES = ("clean", "restore-fail-A2", "marker-after-A2-ping", "leak-before-S1", "fail-and-measure-A3",
         "notstarted-A3-neigh-fail", "ctl-no-arp", "a2-manager-other-mac", "neigh-error-A2-after", "error-after-group")
os.makedirs(run_dir)
summary = {}
for n in NAMES:
    sc = T.run_scenario(n, os.path.abspath(run_dir))
    d = os.path.join(fx, n)
    os.makedirs(d)
    shutil.copy2(os.path.join(sc["dir"], "scenario.json"), d)
    for f in ("result.json", "arp-group.json", "arp-eval.json", "counters-raw.jsonl", "tap0.pcapng", "session.json"):
        p = os.path.join(sc["out"], f)
        if os.path.exists(p):
            shutil.copy2(p, d)
    summary[n] = {"probe_matrix_exit": sc["rc"], "status": sc["result"]["status"],
                  "cases": {c["id"]: c["category"] for c in (sc["eval"] or {}).get("cases", [])},
                  "arp_harness_outcome": sc["cli"], "run_script_mapping": sc["script"],
                  "spec": repr(T.SCENARIOS[n])}
json.dump(summary, open(os.path.join(fx, "fixtures-summary.json"), "w"), indent=1, ensure_ascii=False, default=str)
for n, v in summary.items():
    print(f"{n}: exit {v['probe_matrix_exit']}, {v['run_script_mapping']}, {v['cases']}")
