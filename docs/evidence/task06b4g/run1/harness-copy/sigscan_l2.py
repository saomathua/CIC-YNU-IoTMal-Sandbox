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
    spoof_src_ip           IPv4 src 10.200.0.3 / 10.200.0.1; src 192.168.60.10 only with a probe
                           SOURCE port or a probe ICMP size (it is a real host on sandboxnet)
    probe_port             TCP/UDP src or dst port = one of the exact new probe ports (all below the
                           ephemeral range, see signatures.py)
    icmp_size              ICMPv4 total length / ICMPv6 payload length of a probe size
    probe_qname            bytes "ct01-06b4-" anywhere in the captured frame
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


def scan(path, manager_mac):
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

    for t, raw, orig in L.read_records(path):
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
        c["probe_qname"] += qn in raw
    return c


def main(argv):
    if len(argv) == 3 and argv[1] == "--manager-mac":
        mm = L._norm_mac(argv[2])
    elif len(argv) == 2 and argv[1] == "--no-manager-mac":
        mm = None
    else:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 64
    try:
        c = scan(argv[0], mm)
    except L.FrameReadError as e:
        print(f"READ ERROR: {e}", file=sys.stderr)
        return 2
    for k in KEYS:
        print(f"{k}={c[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
