#!/usr/bin/env python3
"""06B-3G side check (read-only, not part of the harness): parse the raw nft JSON in counters-raw.jsonl
independently and compare the A/F1/F2 values recorded in session.json; report nft read durations."""
import json, statistics, sys
ok = True
for arch in sys.argv[1:]:
    rows = [json.loads(l) for l in open(f"{arch}/counters-raw.jsonl")]
    by = {r["label"]: r for r in rows}
    def parse(r):
        return {c["counter"]["name"]: c["counter"]["packets"] for c in json.loads(r["raw"])["nftables"] if "counter" in c}
    s = json.load(open(f"{arch}/session.json"))
    pairs = [("session before boot", s["reads"]["before"]), ("session final 1", s["reads"]["finals"][0]),
             ("session final 2", s["reads"]["finals"][1])]
    print(f"== {arch}: {len(rows)} raw reads")
    for label, rec in pairs:
        raw = by[label]
        same = parse(raw) == rec["values"] and raw["t_start"] == rec["t_start"] and raw["t_end"] == rec["t_end"]
        ok &= same
        print(f"   {label}: raw nft JSON == session.json values and times: {same}")
    dur = [1000 * (r["t_end"] - r["t_start"]) for r in rows]
    print(f"   nft read duration ms: min {min(dur):.1f} median {statistics.median(dur):.1f} max {max(dur):.1f} (n={len(dur)})")
    print(f"   F1 -> F2 gap: {s['reads']['finals'][1]['t_start'] - s['reads']['finals'][0]['t_end']:.3f} s")
sys.exit(0 if ok else 1)
