#!/usr/bin/env python3
"""06B-4C side analysis (read-only, after the run): the 06B-4BR module l2frames.py applied to the SAVED
tap0 pcaps of this run. This is an OBSERVATION of the traffic that already exists in the 20-probe IPv4
run (guest background ARP/IPv6/DHCP/DNS and the probes); it is NOT a new L2/ARP/IPv6 probe matrix.
    python3 l2_observation.py <harness dir> <run out dir>"""
import collections, json, os, re, sys
sys.path.insert(0, sys.argv[1])
import l2frames as L
R = sys.argv[2]
txt = open(os.path.join(R, "container", "netns-before.txt")).read()
tap = re.search(r"\d+: tap0: .*?\n\s+link/ether ([0-9a-f:]{17})", txt).group(1)
print(f"TAP_MAC (netns-before.txt) = {tap}")
for arch in ("ARM", "MIPS"):
    p = os.path.join(R, "container", "probe", arch)
    fr = L.classified_frames(os.path.join(p, "tap0.pcapng"), tap)
    print(f"== {arch}: {len(fr)} frames; truncated (snaplen) = {sum(f['truncated'] for f in fr)}")
    print("   by direction/class:", dict(collections.Counter((f["direction"], f["cls"]) for f in fr)))
    s = json.load(open(os.path.join(p, "session.json")))
    a, f1 = s["reads"]["before"], s["reads"]["finals"][0]
    r = L.reconcile_l2(fr, a, f1, L.COUNTER_CLASSES)
    print(f"   session window, 13 frame-mapped classes: {r['verdict']} {r.get('error', '')}")
    for k, v in r["per_class"].items():
        print(f"      {k:18s} frames(certain)={v['certain']:3d} delta={v['delta']:3d} {v['status']}")
    print(f"      frames without a counter in the window: {r['no_counter_frames']}")
    old = s["reconciliation"]["per_class"]
    same = all(r["per_class"][k]["certain"] == old[k]["certain"] for k in s["classes_compared"])
    print(f"   9 legacy classes: certain counts equal session.json: {same}")
    raw = {x["label"]: x for x in map(json.loads, open(os.path.join(p, "counters-raw.jsonl")))}
    def vals(x):
        return {"t_start": x["t_start"], "t_end": x["t_end"], "values": {o["counter"]["name"]: o["counter"]["packets"]
                for o in json.loads(x["raw"])["nftables"] if "counter" in o}}
    for pr in json.load(open(os.path.join(p, "matrix.json"))):
        rr = L.reconcile_l2(fr, vals(raw[pr["probe"] + " before"]), vals(raw[pr["probe"] + " after"]), L.COUNTER_CLASSES)
        arp = {k: (rr["per_class"][k]["certain"], rr["per_class"][k]["delta"]) for k in ("arp_in_ok", "arp_in_drop", "arp_out_ok")}
        edges = {k: v["edge_start"] + v["edge_end"] for k, v in rr["per_class"].items() if v["edge_start"] or v["edge_end"]}
        print(f"   probe {pr['probe']:26s} 13-class {rr['verdict']:10s} (recorded 9-class {pr['counter_reconciliation']['verdict']}); "
              f"ARP (frames, delta) {arp}" + (f"; edges {edges}" if edges else ""))
