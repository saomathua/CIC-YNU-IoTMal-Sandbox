#!/usr/bin/env python3
"""06B-4G — independent cross-check of the saved run output. Does NOT import the harness modules:
counter values come from the raw nft JSON in counters-raw.jsonl, frames from `tcpdump -r` (BPF filters
written here), windows from the recorded read times. Read only.
    python3 crosscheck.py /home/dathq/projects/ct01-06b4fr/out
"""
import ipaddress
import json
import os
import subprocess
import sys

GUEST = "52:54:00:c7:00:02"
GUARD = 0.020          # the harness guard (20 ms): an UNMEASURED assumption, used here only to name zones
SIZES = {"T12-B1": ("255.255.255.255", 1201 + 28), "T12-B2": ("224.0.0.1", 1202 + 28), "T12-B4": ("10.200.0.3", 1204 + 28)}


def eui64(mac):
    b = bytearray(bytes.fromhex(mac.replace(":", "")))
    b[0] ^= 2
    return ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + bytes(b[:3]) + b"\xff\xfe" + bytes(b[3:]))


def times(pcap, flt):
    p = subprocess.run(["tcpdump", "-n", "-tt", "-r", pcap, flt], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"tcpdump error {p.returncode}: {p.stderr.strip()}")
    return [float(l.split()[0]) for l in p.stdout.splitlines() if l.strip()]


def reads(path):
    out = {}
    for line in open(path):
        r = json.loads(line)
        vals = {o["counter"]["name"]: o["counter"]["packets"] for o in json.loads(r["raw"])["nftables"] if "counter" in o}
        out[r["label"]] = (r["t_start"], r["t_end"], vals)
    return out


def zone(t, a, b):
    if t < a[0] - GUARD or t > b[1]:
        return "outside"
    if t <= a[1] + GUARD:
        return "edge_start"
    if t >= b[0] - GUARD:
        return "edge_end"
    return "certain"


def main(out):
    ok_all = True
    for arch in ("ARM", "MIPS"):
        d = os.path.join(out, "container", "probe", arch)
        pcap, R = os.path.join(d, "tap0.pcapng"), reads(os.path.join(d, "counters-raw.jsonl"))
        grp = json.load(open(os.path.join(d, "icmp-group.json")))
        ev = {c["id"]: c for c in json.load(open(os.path.join(d, "icmp-eval.json")))["cases"]}
        tap = grp["tap_mac"]
        ll = eui64(tap)
        group = ipaddress.IPv6Address(bytes.fromhex("ff0200000000000000000001ff") + ll.packed[13:])
        w = [int.from_bytes(ll.packed[i:i + 4], "big") for i in range(0, 16, 4)]
        flts = {cid: f"ether src {GUEST} and icmp and dst host {dst} and ip[2:2] = {ln} and icmp[0] = 8"
                for cid, (dst, ln) in SIZES.items()}
        flts["T13-I1"] = f"ether src {GUEST} and icmp6 and dst host ff02::1 and ip6[4:2] = 1309 and ip6[40] = 128"
        flts["T13-I2"] = (f"ether src {GUEST} and icmp6 and dst host {group} and ip6[40] = 135 and "
                          + " and ".join(f"ip6[{48 + 4 * i}:4] = 0x{x:08x}" for i, x in enumerate(w)))
        all_guest = times(pcap, f"ether src {GUEST}")
        v6_guest = times(pcap, f"ether src {GUEST} and ip6")
        to_guest = times(pcap, f"ether dst {GUEST} and (icmp or icmp6)")
        print(f"== {arch}: TAP_MAC {tap}, T13-I2 target {ll}, group {group}; tap0 frames from guest {len(all_guest)}")
        print(f"{'case':7s} {'probe(all)':>10s} {'certain':>7s} {'edge':>4s}  expected-class delta  "
              f"guest-IPv6 in window (certain/edge) vs l2_bad_ethertype delta  harness verdict")
        for cid in ("T12-B1", "T12-B2", "T12-B4", "T13-I1", "T13-I2"):
            a, b = R[f"{cid} before"], R[f"{cid} after"]
            exp = "l2_bad_ethertype" if cid.startswith("T13") else ("drop_private" if cid == "T12-B4" else "drop_bcast_mcast")
            delta = {k: b[2][k] - a[2].get(k, 0) for k in b[2] if b[2][k] != a[2].get(k, 0)}
            pz = [zone(t, a, b) for t in times(pcap, flts[cid])]
            pz_in = [z for z in pz if z != "outside"]
            v6z = [zone(t, a, b) for t in v6_guest]
            v6c, v6e = v6z.count("certain"), v6z.count("edge_start") + v6z.count("edge_end")
            rep = [zone(t, a, b) for t in to_guest if zone(t, a, b) != "outside"]
            print(f"{cid:7s} {len(pz_in):>10d} {pz_in.count('certain'):>7d} {len(pz_in) - pz_in.count('certain'):>4d}  "
                  f"{exp}={delta.get(exp, 0):<3d} all deltas={delta}  v6 {v6c}/{v6e}  replies-to-guest={len(rep)}  "
                  f"-> {ev[cid]['verdict']}")
            mine = ev[cid]
            same = (mine["probe_frames"] == len(pz_in) and mine["probe_frames_certain"] == pz_in.count("certain")
                    and mine["replies_to_guest"] == len(rep))
            ok_all &= same
            if pz_in.count("certain") != len(pz_in):
                for t in times(pcap, flts[cid]):
                    if zone(t, a, b) not in ("outside", "certain"):
                        print(f"        edge probe frame t={t:.6f}: read A end {a[1]:.6f} (+guard {a[1] + GUARD:.6f}), "
                              f"read B start {b[0]:.6f} (-guard {b[0] - GUARD:.6f}); zone {zone(t, a, b)}")
            print(f"        independent counts == harness icmp-eval.json: {same}")
        for lbl in ("before", "after"):
            s = grp[f"service_link_{lbl}"]
            print(f"   service link {lbl}: ok={s['ok']} http={s['detail']['http_code']} "
                  f"sha256==fixture: {s['detail']['sha256'] == grp['fixture_sha256']}")
        print()
    print("INDEPENDENT CROSS-CHECK:", "counts agree with the harness" if ok_all else "DIFFERENCES FOUND")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
