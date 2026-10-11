#!/usr/bin/env python3
"""06B-3G side check (read-only, not part of the harness): cross-check each session.json against the
tap0 pcap using only the host's tcpdump (not the harness's tshark/classifier).
 * guest-sourced frames (ether src = guest MAC) must equal the sum of the compared session deltas
   plus the ARP-in delta (ARP is not compared by the harness, but every guest ARP frame hits arp_in);
 * frames towards the guest must equal allow_out_svc + arp_out_ok deltas;
 * every guest frame must lie strictly after A.end and before F1.start (no frame outside the window).
Every tcpdump read is exit-code checked."""
import json, subprocess, sys
GUEST_MAC = "52:54:00:c7:00:02"
def frames(pcap, flt):
    p = subprocess.run(["tcpdump", "-n", "-tt", "-r", pcap, flt], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"READ ERROR {pcap} {flt}: rc={p.returncode}")
    return [float(l.split()[0]) for l in p.stdout.splitlines() if l.strip()]
ok = True
for arch in sys.argv[1:]:
    s = json.load(open(f"{arch}/session.json"))
    a, f1, f2 = s["reads"]["before"], s["reads"]["finals"][0], s["reads"]["finals"][1]
    d = lambda k: f1["values"][k] - a["values"][k]
    pc = f"{arch}/tap0.pcapng"
    allf = frames(pc, "")
    src = frames(pc, f"ether src {GUEST_MAC}")
    arp = frames(pc, f"ether src {GUEST_MAC} and arp")
    dst = frames(pc, f"ether dst {GUEST_MAC}")
    comp = sum(d(k) for k in s["classes_compared"])
    exp_src = comp + d("arp_in_ok") + d("arp_in_drop")
    exp_dst = d("allow_out_svc") + d("arp_out_ok") + d("arp_out_drop") + d("drop_out")
    print(f"== {arch}: tap0 frames={len(allf)} guest-sourced={len(src)} (ARP {len(arp)}) to-guest={len(dst)}")
    print(f"   sum of compared deltas A->F1 = {comp}; + arp_in = {exp_src}  -> {'MATCH' if exp_src == len(src) else 'MISMATCH'}")
    print(f"   allow_out_svc + arp_out (+drop_out) = {exp_dst} -> {'MATCH' if exp_dst == len(dst) else 'MISMATCH'}")
    print(f"   F1 == F2 on every counter: {f1['values'] == f2['values']}")
    first, last = min(src), max(src)
    print(f"   A.end={a['t_end']:.6f}  first guest frame={first:.6f} (+{first - a['t_end']:.3f} s after A.end)")
    print(f"   last guest frame={last:.6f}  QEMU exit confirmed={s['qemu']['exit_confirmed_t']:.6f}  F1.start={f1['t_start']:.6f} "
          f"({f1['t_start'] - last:.3f} s after the last guest frame)")
    print(f"   frames (any) before A.end: {sum(t <= a['t_end'] for t in allf)}; frames at/after F1.start: {sum(t >= f1['t_start'] for t in allf)}")
    print(f"   qemu: {s['qemu']}")
    good = exp_src == len(src) and exp_dst == len(dst) and len(src) + len(dst) == len(allf) and a["t_end"] < first and last < f1["t_start"]
    print(f"   cross-check: {'CONSISTENT' if good else 'INCONSISTENT'} (session.json verdict {s['verdict']})")
    ok &= good
sys.exit(0 if ok else 1)
