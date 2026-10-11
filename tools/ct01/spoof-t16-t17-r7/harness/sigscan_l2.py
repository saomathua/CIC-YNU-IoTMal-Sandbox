"""06B-4B — signature scanner for HOST-side Ethernet pcaps (veth, bridge, ens33), L2/ARP/IPv6/spoof
signatures from signatures.py. Read-only, no root. Complements sigscan.sh (06B-3C, unchanged), which
keeps the IPv4-matrix signatures.

    python3 sigscan_l2.py <pcap> --manager-mac <mac>|--no-manager-mac

Prints key=value (counts are FRAMES), exit 0; exit 2 on any read problem (never "0").
    frames                 all frames
    guest_mac              src or dst MAC = guest MAC
    spoof_mac              src or dst MAC = a chosen spoof MAC
    guest_net_ip           IPv4 src or dst in 10.200.0.0/30
    arp_guest_sha          ARP sender MAC = guest MAC
    arp_spoof_sha          ARP sender MAC = a chosen spoof MAC
    arp_guest_net          ARP sender or target IP in 10.200.0.0/30
    arp_spoof_spa_manager  ARP sender IP 192.168.60.10 with a sender MAC other than the manager's
                           (needs --manager-mac; "skipped" with --no-manager-mac)
    ipv6_guest             IPv6 with src/dst = guest link-local, or IPv6 frame from guest/spoof MAC
    spoof_src_ip           IPv4 src 10.200.0.5 / 10.200.0.1; src 192.168.60.10 only with a probe
                           SOURCE port or a probe ICMP size (it is a real host on sandboxnet)
    probe_port             TCP/UDP src or dst port = one of the exact new probe ports (all below the
                           ephemeral range, see signatures.py)
    icmp_size              ICMPv4 total length / ICMPv6 payload length of a probe size
    probe_qname            bytes "ct01-06b4-" anywhere, except matched B1 DNS control pairs
    control_qname          B1 query/reply frames bound to saved control+worker/NAT identity (optional context)
    truncated_frames       frames cut by the capture's snaplen (information, not a signature)
    unscannable_truncated  a signature-bearing header (Ethernet, ARP, IPv4/IPv6, TCP/UDP ports, or the
                           payload of DNS) is missing because the capture cut the frame
    unscannable_undecoded  the same header is missing or unusable on the wire (malformed), or the frame
                           is an encapsulation the scanner does not decode (VLAN)
06B-4BR: signatures are read from every header that was captured in full; a frame cut by snaplen is
scanned as far as its headers go (e.g. an ICMP size from the IPv4 total length), and what could not be
seen is counted, never reported as 0.
"""
import ipaddress
import argparse
import json
import pathlib
import re
import struct
import sys

import l2frames as L
import signatures as S

KEYS = ("frames", "guest_mac", "spoof_mac", "guest_net_ip", "arp_guest_sha", "arp_spoof_sha", "arp_guest_net",
        "arp_spoof_spa_manager", "ipv6_guest", "spoof_src_ip", "probe_port", "icmp_size", "probe_qname",
        "truncated_frames", "unscannable_truncated", "unscannable_undecoded")
# truncated_frames is information (ens33 is captured with a snaplen); every other key must be 0 on a host
# capture. A frame whose signature-bearing header is missing is never counted as "no signature": it is
# counted as unscannable_truncated (cut by the capture's snaplen) or unscannable_undecoded (malformed on
# the wire, or an encapsulation the scanner does not decode, e.g. VLAN).
DNS_PORT = 53


def scan(path, manager_mac, dns_context=None):
    net = ipaddress.ip_network(S.GUEST_NET)
    guest, spoof = S.GUEST_MAC, set(S.SPOOF_MACS)
    ports = set(S.PROBE_PORTS.values())
    lens4, lens6 = set(S.ip4_lens()), set(S.ip6_plens())
    own_spoof = {ip for ip in S.SPOOF_SRC_IPS if ip not in S.SPOOF_SRC_SHARED}
    qn = S.QNAME_PREFIX.encode()
    c = {k: 0 for k in KEYS}
    if manager_mac is None:
        c["arp_spoof_spa_manager"] = "skipped"

    def blind(cut):
        c["unscannable_truncated" if cut else "unscannable_undecoded"] += 1

    records = list(L.read_records(path))
    controls = matched_dns_controls(records, dns_context) if dns_context is not None else set()
    c["control_qname"] = len(controls)
    for index, (t, raw, orig) in enumerate(records):
        f = L.decode(t, raw, orig)
        c["frames"] += 1
        c["truncated_frames"] += f["truncated"]
        if f.get("etype") is None:                        # not even an Ethernet header
            blind(f["truncated"])
            continue
        macs = {f.get("src"), f.get("dst")}
        c["guest_mac"] += guest in macs
        c["spoof_mac"] += bool(macs & spoof)
        ip, a, v6 = f.get("ip"), f.get("arp"), f.get("ip6")
        et = f["etype"]
        if et == L.ETH_IPV4:
            if not ip.get("hdr_ok"):
                blind(ip.get("hdr_cut", False))
            else:
                # header present: use it even if the payload was cut by snaplen or the packet is malformed
                src, dst = ipaddress.IPv4Address(ip["src"]), ipaddress.IPv4Address(ip["dst"])
                c["guest_net_ip"] += src in net or dst in net
                probe_port = ip["sport"] in ports or ip["dport"] in ports
                probe_icmp = ip["proto"] == 1 and ip["tot_len"] in lens4
                c["probe_port"] += probe_port
                c["icmp_size"] += probe_icmp
                c["spoof_src_ip"] += (ip["src"] in own_spoof
                                      or (ip["src"] in S.SPOOF_SRC_SHARED and (ip["sport"] in ports or probe_icmp)))
                if ip.get("ports_missing"):
                    blind(ip.get("ports_cut", False))     # TCP/UDP ports not visible
                elif (DNS_PORT in (ip["sport"], ip["dport"]) and not ip["payload_complete"]):
                    blind(True)                           # DNS name may lie beyond the snaplen
        elif et == L.ETH_ARP:
            if "sha" in a:
                c["arp_guest_sha"] += a["sha"] == guest
                c["arp_spoof_sha"] += a["sha"] in spoof
                c["arp_guest_net"] += ipaddress.IPv4Address(a["spa"]) in net or ipaddress.IPv4Address(a["tpa"]) in net
                if manager_mac is not None:
                    c["arp_spoof_spa_manager"] += a["spa"] == "192.168.60.10" and a["sha"] != manager_mac
            else:
                blind(a.get("cut", False))
        elif et == L.ETH_IPV6:
            hit = f.get("src") == guest or f.get("src") in spoof
            if v6.get("hdr_ok"):
                hit = hit or S.GUEST_LL6 in (v6["src"], v6["dst"])
                c["icmp_size"] += v6["nh"] == 58 and v6["plen"] in lens6
            else:
                blind(v6.get("hdr_cut", False))
            c["ipv6_guest"] += hit
        elif et in L.ETH_VLAN:
            blind(False)                                  # inner frame not decoded
        c["probe_qname"] += qn in raw and index not in controls
    return c


def _json(path):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out
    return json.loads(pathlib.Path(path).read_text(), object_pairs_hook=unique)


def load_dns_context(probe_dir, worker_ip, worker_mac, host_ip, host_link, role):
    """Recorded B1 controls only. No live reads and no exemption from qname alone.

    Validate the actual group binding + raw A/B windows with the same real validator.
    NAT identity on ens33 is the recorded host IPv4/MAC; veth/bridge use worker identity.
    A missing/failed control is not exempted. Broken or duplicate source data is a read error.
    """
    import b1_cases as B
    worker_ip, host_ip = str(ipaddress.IPv4Address(worker_ip)), str(ipaddress.IPv4Address(host_ip))
    worker_mac = L._norm_mac(worker_mac)
    lines = [l.split() for l in pathlib.Path(host_link).read_text().splitlines() if l.split() and l.split()[0] == "ens33"]
    if len(lines) != 1 or len(lines[0]) < 3:
        raise ValueError("host ens33 MAC missing/duplicate in mandatory host-state")
    host_mac = L._norm_mac(lines[0][2])
    if worker_mac == S.GUEST_MAC or worker_mac in S.SPOOF_MACS or host_mac == S.GUEST_MAC or host_mac in S.SPOOF_MACS:
        raise ValueError("control identity collides with guest/spoof MAC")
    phases = []
    dirs = [p for p in pathlib.Path(probe_dir).iterdir() if p.name in ("ARM", "MIPS") and p.is_dir()]
    if not dirs:
        raise ValueError("no actual architecture control records")
    for p in dirs:
        rec = _json(p / "b1-group.json")
        case = next(c for c in B.build_guest_cases(p.name, lan_other="192.168.177.250") if c["id"] == "T05-DNS-8888")
        reads = {}
        for line in (p / "counters-raw.jsonl").read_text().splitlines():
            r = json.loads(line)
            if not isinstance(r, dict) or not isinstance(r.get("label"), str) or r["label"] in reads:
                raise ValueError("counter snapshot malformed/duplicate")
            reads[r["label"]] = r
        rows = [r for r in rec["guest_cases"] if r.get("id") == case["id"]]
        if len(rows) != 1 or rec["arch"] != p.name:
            raise ValueError("DNS case/architecture missing/duplicate")
        row = rows[0]
        ra, rb = reads[row["before"]], reads[row["after"]]
        if row["before"] != case["id"] + " before" or row["after"] != case["id"] + " after":
            raise ValueError("DNS read binding wrong")
        if not all(B._fin(r.get(k)) for r in (ra, rb) for k in ("t_start", "t_end")) or not ra["t_start"] <= ra["t_end"] <= rb["t_start"] <= rb["t_end"]:
            raise ValueError("DNS read timing invalid")
        state, why = B.control_state(case, row, ra, rb)
        if state == "invalid":
            raise ValueError("DNS control schema/binding: " + str(why))
        if state != "alive":
            continue
        for phase in ("before", "after"):
            c = row["control_" + phase]
            phases.append({"ts": c["ts"], "qname": case["control_qname"], "server": case["dst"],
                           "detail": c["detail"], "binding": c["binding"]})
    return {"ip": host_ip if role == "ens33" else worker_ip, "mac": host_mac if role == "ens33" else worker_mac, "phases": phases}


def matched_dns_controls(records, context):
    """Only complete query/reply pairs with actual recorded name/time/peer identity.

    IP+MAC/port/id/question/source windows bind these control frames. This does not
    distinguish a guest spoofing ALL of those identities; other leak signatures remain active.
    """
    import b1_cases as B
    exempt = set()
    decoded = [L.decode(t, raw, orig) for t, raw, orig in records]
    def payload(f):
        ip = f.get("ip") or {}
        udp = ip.get("payload", b"")
        if {f.get("src"), f.get("dst")} & ({S.GUEST_MAC} | set(S.SPOOF_MACS)):
            return None
        if any(ipaddress.IPv4Address(ip[k]) in ipaddress.ip_network(S.GUEST_NET) for k in ("src", "dst") if k in ip):
            return None
        if f.get("truncated") or not ip.get("hdr_ok") or not ip.get("csum_ok") or ip.get("frag_offset") or ip.get("proto") != 17 or not ip.get("payload_complete") or len(udp) < 8:
            return None
        if struct.unpack_from("!H", udp, 4)[0] != len(udp):
            return None
        return udp[8:]
    for c in context["phases"]:
        lo, hi = c["ts"], c["ts"] + B.W_TIMEOUT_S
        for i, (t, raw, orig) in enumerate(records):
            f = decoded[i]; ip = f.get("ip") or {}; data = payload(f)
            if data is None or not lo <= t <= hi or f.get("src") != context["mac"] or ip.get("src") != context["ip"] or ip.get("dst") != c["server"] or ip.get("dport") != 53 or len(data) < 12:
                continue
            qid = int.from_bytes(data[:2], "big")
            if data != B.dns_query(qid, c["qname"]):
                continue
            for j, (rt, rr, ro) in enumerate(records):
                rf = decoded[j]; ri = rf.get("ip") or {}; reply = payload(rf)
                if reply is None or not t <= rt <= hi or rf.get("dst") != context["mac"] or ri.get("dst") != context["ip"] or ri.get("src") != c["server"] or ri.get("sport") != 53 or ri.get("dport") != ip.get("sport"):
                    continue
                try:
                    rcode = B.parse_dns_reply(reply, qid, c["qname"])
                except (ValueError, RuntimeError):
                    continue
                if c["detail"] != f"DNS response rcode={rcode} from {c['server']}:53":
                    continue
                exempt.update((i, j))
    return exempt


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--manager-mac")
    g.add_argument("--no-manager-mac", action="store_true")
    ap.add_argument("--b1-records")
    ap.add_argument("--worker-ip")
    ap.add_argument("--worker-mac")
    ap.add_argument("--host-ip")
    ap.add_argument("--host-link")
    ap.add_argument("--capture-role", choices=("veth", "bridge", "ens33"))
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 64
    try:
        mm = L._norm_mac(a.manager_mac) if a.manager_mac else None
        ctx = None
        args = [a.b1_records, a.worker_ip, a.worker_mac, a.host_ip, a.host_link, a.capture_role]
        if any(v is not None for v in args):
            if not all(v is not None for v in args):
                raise ValueError("complete recorded B1 control context required")
            ctx = load_dns_context(*args)
        c = scan(a.pcap, mm, ctx)
    except (L.FrameReadError, OSError, ValueError, TypeError, KeyError, StopIteration, AttributeError, IndexError) as e:
        print(f"READ ERROR: {e}", file=sys.stderr)
        return 2
    for k in (*KEYS, "control_qname") if ctx is not None else KEYS:
        print(f"{k}={c[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
