#!/usr/bin/env python3
"""Same steps as the reviewer's mips-extra.py (custom S1 -> A1 order, Guest with `ip link set up` failing), but
records the observed values instead of asserting the old behaviour. Run in a directory holding harness/, inputs/
and the reviewer's mips-fixtures.py (its Guest class is imported the same way mips-extra.py does)."""
from pathlib import Path
import json
W = Path.cwd()
s = (W / "mips-fixtures.py").read_text(); ns = {"__file__": str(W / "mips-fixtures.py")}
exec(compile(s[:s.index("\nmatrix=[]")], "fixture-Guest-definition", "exec"), ns)
GS, A, SA, Guest = ns["GS"], ns["A"], ns["SA"], ns["Guest"]
link_calls = []
g = Guest(fail_up=True)
def link():
    link_calls.append({"admin_up": g.admin, "operstate": g.oper}); return True, {"fixture": "not real liveness"}
cases = [A.build_cases()[-1], A.build_cases()[0]]
rec = A.run_group(g, lambda lbl: {"values": {}}, link, lambda: SA.NEIGH, lambda c: (True, {}), cases, "br-lan")
s1 = rec["cases"][0]
out = {"note": "custom S1->A1 order (NOT production order)",
       "s1_restored": s1["guest_state"]["restore"]["restored"], "s1_diffs": s1["guest_state"]["restore"]["diffs"],
       "s1_restore_commands": [(c["cmd"], c["rc"]) for c in s1["guest_state"]["restore"]["commands"]],
       "second_case_started": bool(rec["cases"][1]["steps"]), "second_case_not_run": rec["cases"][1]["not_run"],
       "link_calls": link_calls, "admin_up_at_end": g.admin}
print(json.dumps(out, ensure_ascii=False))
