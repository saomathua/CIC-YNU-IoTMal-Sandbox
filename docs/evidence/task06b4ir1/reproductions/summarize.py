#!/usr/bin/env python3
"""Summarise review-result.json of the Codex reproductions (before/after table)."""
import json, sys, os
root = sys.argv[1]
TRIG = {"topology-leak": "ip addr", "topology-capture": "ip addr"}
for v in sys.argv[2:]:
    p = os.path.join(root, v, "review-result.json")
    if not os.path.exists(p):
        print(f"{v}: no review-result.json"); continue
    r = json.load(open(p))
    cmds = r["commands"]
    after = None
    if v in TRIG:
        after = len(cmds) - (cmds.index(TRIG[v]) + 1) if TRIG[v] in cmds else None
    boot = r.get("boot_console")
    a1 = r.get("control_A1") or {}
    print(f"{v}: rc={r['rc']} status={r['status'][:60]!r} cli={r['cli'][:70]!r} bash={r['script_mapping']} "
          f"cats={r['categories']} guest_cmds={len(cmds)}"
          + (f" cmds_after_event={after}" if after is not None else "")
          + (f" boot_console={boot}" if boot else "")
          + (f" A1.control.ok={a1.get('ok')}" if a1 else ""))
