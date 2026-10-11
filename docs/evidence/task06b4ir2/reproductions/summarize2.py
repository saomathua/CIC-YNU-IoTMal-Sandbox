#!/usr/bin/env python3
"""Summarise fixtures/ir1-*/review.json of Codex targeted.py: rc, status, outcome/CLI/Bash, categories, guest commands
after the topology gate (the handoff point)."""
import json, os, sys
root = sys.argv[1]
TOPO_LAST = "curl --version | head -1"
for v in sys.argv[2:]:
    p = os.path.join(root, "fixtures", f"ir1-{v}", "review.json")
    if not os.path.exists(p):
        print(f"{v}: no review.json"); continue
    r = json.load(open(p))
    cmds = [c for k, c in r["commands"] if k == "run"]
    mons = [c for k, c in r["commands"] if k == "monitor"]
    after = cmds[cmds.index(TOPO_LAST) + 1:] if TOPO_LAST in cmds else None
    a1 = next((c for c in r["case_results"] if c["id"] == "T14-A1"), None)
    print(f"{v}: rc={r['rc']} status={r['status'][:70]!r} cli={r['cli'][:60]!r} bash={r['mapping']} "
          f"cats={r['categories']} monitor={len(mons)} guest_cmds_after_topology={after}"
          + (f" A1={a1['category']}" if a1 else ""))
