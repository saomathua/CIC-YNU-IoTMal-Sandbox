#!/usr/bin/env python3
"""06B-3G side check (read-only, not part of the harness), host tcpdump only:
 1. every probe's own frames (fixed source port 41000+n, or UDP to the probe dst) vs. that probe's
    read window: all must lie after A.end and before B.start - guard (certain zone);
 2. for every UNVERIFIED probe: the edge frame(s) decoded, with the position relative to the reads."""
import json, subprocess, sys
GUARD = 0.020
def lines(pcap, flt):
    p = subprocess.run(["tcpdump", "-n", "-tt", "-r", pcap, flt], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"READ ERROR {pcap} {flt}: rc={p.returncode}")
    return [l for l in p.stdout.splitlines() if l.strip()]
for arch in sys.argv[1:]:
    m = json.load(open(f"{arch}/matrix.json")); pc = f"{arch}/tap0.pcapng"
    print(f"== {arch}")
    for n, r in enumerate(m):
        rd = r["counter_reconciliation"]["reads"]; a_end = rd["before"]["t_end"]; b_start = rd["after"]["t_start"]
        proto, hp = r["dst"].split(); host, port = hp.rsplit(":", 1)
        flt = (f"src host 10.200.0.2 and dst host {host} and udp dst port {port}" if proto == "udp"
               else f"src host 10.200.0.2 and src port {41000 + n} and dst host {host} and tcp dst port {port}")
        ts = [float(l.split()[0]) for l in lines(pc, flt)]
        inside = all(a_end < t < b_start - GUARD for t in ts)
        print(f"  {r['probe']}: {len(ts)} probe frames, all in certain zone: {inside}; "
              f"first +{min(ts) - a_end:.3f} s after A.end, last {b_start - max(ts):.3f} s before B.start; verdict {r['verdict']}")
        for cls, mm in r.get("mismatch", {}).items():
            for side in ("edge_start_t", "edge_end_t"):
                for t in mm.get(side, []):
                    hit = [l for l in lines(pc, "") if abs(float(l.split()[0]) - t) < 5e-6]
                    rel = (f"A=[{rd['before']['t_start']:.6f}, {a_end:.6f}]: {'INSIDE read A' if rd['before']['t_start'] <= t <= a_end else f'{1000 * (rd['before']['t_start'] - t):.1f} ms before A.start'}"
                           if side == "edge_start_t" else
                           f"B=[{b_start:.6f}, {rd['after']['t_end']:.6f}]: {1000 * (b_start - t):.1f} ms before B.start")
                    print(f"    EDGE {cls} ({side}) t={t:.7f}; {rel}; delta={mm['delta']} certain={mm['certain']} with_edges={mm['with_edges']}")
                    for l in hit:
                        print(f"      frame: {l}")
        if n > 0:
            prev = m[n - 1]["counter_reconciliation"]["reads"]["after"]
            if r.get("mismatch"):
                print(f"    previous probe {m[n - 1]['probe']}: read B ended {prev['t_end']:.6f}; its delta of the edge class: "
                      f"{ {c: m[n - 1]['counter_delta'].get(c) for c in r['mismatch']} } (observation only)")
