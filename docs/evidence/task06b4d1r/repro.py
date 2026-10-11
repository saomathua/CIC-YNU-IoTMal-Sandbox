"""06B-4D1R repro (offline): the reviewer's four inputs, against the l2eval.py in argv[1]."""
import json, os, sys, tempfile, traceback
sys.path.insert(0, sys.argv[1]); sys.path.insert(1, "/home/dathq/projects/ct01-06b4d1")
import l2eval as E
import selftest_l2eval as T
tmp = tempfile.mkdtemp()
p = T.pcapng(os.path.join(tmp, "f.pcapng"), T.frames_std())
good = T.std_recs(**T.STD_DELTA)
def case(name, recs, classes=None):
    c = T.write_counters(os.path.join(tmp, "c.jsonl"), recs)
    try:
        r = E.evaluate(p, c, T.TAP, "A", "B", classes)
        print(f"{name}: verdict={r['verdict']} per_class={len(r['per_class'])} reason={r['reasons'][:1]}")
    except Exception as e:
        print(f"{name}: EXCEPTION {type(e).__name__}: {e}")
case("classes=[]", good, [])
for nm, raw in (('{"nftables":[{"counter":null}]}', {"nftables": [{"counter": None}]}),
                ('{"nftables":null}', {"nftables": None}),
                ('{"nftables":[{"counter":[]}]}', {"nftables": [{"counter": []}]})):
    case(nm, [good[0], {"label": "B", "t_start": T.B0, "t_end": T.B1, "raw": json.dumps(raw)}])
