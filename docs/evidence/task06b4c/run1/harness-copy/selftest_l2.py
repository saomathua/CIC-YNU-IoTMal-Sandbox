#!/usr/bin/env python3
"""06B-4B — offline self-test of signatures.py, l2frames.py, guest_state.py, sigscan_l2.py and the
06B-4B changes in run-06b3b.sh. No packet is sent; tcpdump is only used to READ generated fixture
files (filter compilation and matching). Every test has a unique name (mutation_l2.py targets them).

    python3 selftest_l2.py --offline-only               sections A-I
    python3 selftest_l2.py --regression <06B-3G run>    A-I + R (read-only replay of the 06B-3G pcaps)
    add --json <file> to write {test name: true/false}

Exit 0 only if every test passes. A crash inside a test is a FAIL of that test, never a pass.
"""
import contextlib
import io
import ipaddress
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import counter_window as CW     # noqa: E402
import guest_state as GS        # noqa: E402
import l2frames as L            # noqa: E402
import signatures as S          # noqa: E402
import sigscan_l2 as SL         # noqa: E402

RESULTS = {}
TAP = "7a:93:2a:f1:47:47"
GUEST = S.GUEST_MAC
SPOOF = S.SPOOF_MACS[0]
MANAGER_MAC = "1a:1d:4c:ca:65:aa"
OTHER = "02:42:00:00:bb:02"


def t(name, fn):
    if name in RESULTS:
        raise SystemExit(f"duplicate test name {name}")
    try:
        ok = bool(fn())
        why = "" if ok else "returned False"
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""))


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------ frame builders
def mac(m):
    return bytes.fromhex(m.replace(":", ""))


def ip4(a):
    return ipaddress.IPv4Address(a).packed


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def arp(op, sha, spa, tha, tpa, htype=1, ptype=0x0800, hlen=6, plen=4):
    hw = lambda m: (mac(m) + b"\0" * hlen)[:hlen]           # noqa: E731
    pr = lambda a: (ip4(a) + b"\0" * plen)[:plen]           # noqa: E731
    return struct.pack("!HHBBH", htype, ptype, hlen, plen, op) + hw(sha) + pr(spa) + hw(tha) + pr(tpa)


def ipv4(src, dst, proto, l4, frag=0, bad_csum=False, ihl=5, tot=None):
    tot = 4 * ihl + len(l4) if tot is None else tot
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, tot, 1, frag, 64, proto, 0, ip4(src), ip4(dst))
    h += b"\0" * (4 * ihl - 20)
    c = csum(h) ^ (0x1111 if bad_csum else 0)
    h = h[:10] + struct.pack("!H", c) + h[12:]
    return h + l4


def tcp(sport, dport):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 64240, 0, 0)


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(size):
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\xab" * size


def ipv6(src, dst, nh, payload):
    return (struct.pack("!IHBB", 0x60000000, len(payload), nh, 255) + ipaddress.IPv6Address(src).packed
            + ipaddress.IPv6Address(dst).packed + payload)


def icmp6(size, typ=128):
    return struct.pack("!BBHHH", typ, 0, 0, 1, 1) + b"\xcd" * size


def sll2(frame):
    """Ethernet frame -> LINUX_SLL2 record (protocol, ifindex, ARPHRD_ETHER, PACKET_HOST, src MAC)."""
    return (frame[12:14] + b"\0\0" + struct.pack("!IHBB", 2, 1, 0, 6) + frame[6:12] + b"\0\0") + frame[14:]


def write_pcap(path, frames, linktype=1, endian="<", nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for rec in frames:
        ts, fr = rec[0], rec[1]
        orig = rec[2] if len(rec) > 2 else len(fr)       # 06B-4BR: original length (> captured = snaplen cut)
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nano else 1e6))
        out += struct.pack(endian + "IIII", sec, frac, len(fr), orig) + fr
    open(path, "wb").write(out)


def _blk(btype, body, e="<"):
    body += b"\0" * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack(e + "II", btype, n) + body + struct.pack(e + "I", n)


def shb(e="<"):
    return _blk(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)


def idb(linktype=1, tsresol=None, e="<"):
    body = struct.pack(e + "HHI", linktype, 0, 262144)
    if tsresol is not None:
        body += struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\0\0\0" + struct.pack(e + "HH", 0, 0)
    return _blk(1, body, e)


def epb(ts_units, frame, ifid=0, e="<", orig=None):
    orig = len(frame) if orig is None else orig
    return _blk(6, struct.pack(e + "IIIII", ifid, ts_units >> 32, ts_units & 0xFFFFFFFF, len(frame), orig)
                + frame, e)


# Canonical frames ----------------------------------------------------------
def F_arp_ok(op=1, dst="ff:ff:ff:ff:ff:ff"):
    return eth(dst, GUEST, 0x0806, arp(op, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1"))


def F_ip(src="10.200.0.2", dst="1.1.1.1", proto=6, l4=None, dmac=TAP, smac=GUEST, **kw):
    return eth(dmac, smac, 0x0800, ipv4(src, dst, proto, tcp(31000, 443) if l4 is None else l4, **kw))


# ------------------------------------------------------------------ A. registry and filters
def sec_A(tmp):
    t("A1 registry check() reports no problem", lambda: S.check() == [])
    t("A2 every new probe port is outside the Linux ephemeral range",
      lambda: all(not 32768 <= p <= 60999 for p in S.PROBE_PORTS.values()))
    t("A3 plan ports T17-P1..P4 present and unique",
      lambda: [S.PROBE_PORTS[f"T17-P{i}"] for i in (1, 2, 3, 4)] == [31171, 31172, 31173, 31174])
    t("A4 GUEST_LL6 is the EUI-64 address of the guest MAC", lambda: S.eui64_ll(GUEST) == S.GUEST_LL6)
    t("A5 check() catches a probe port inside the ephemeral range",
      lambda: _with(S.PROBE_PORTS, "X", 42172, lambda: any("ephemeral" in p for p in S.check())))
    t("A6 check() catches a duplicate ICMP size",
      lambda: _with(S.ICMP4_SIZES, "X", 1201, lambda: any("duplicate ICMP" in p for p in S.check())))
    en, sl = os.path.join(tmp, "en.pcap"), os.path.join(tmp, "sll2.pcap")
    write_pcap(en, [], 1)
    write_pcap(sl, [], 276)

    def comp(f, flt):
        return subprocess.run(["tcpdump", "-r", f, "-d", flt], capture_output=True, text=True).returncode == 0
    t("A7 alert_any filter compiles on LINUX_SLL2 (tcpdump -i any)", lambda: comp(sl, S.alert_any_filter()))
    t("A8 alert_eth filter compiles on Ethernet (veth)", lambda: comp(en, S.alert_eth_filter()))
    t("A9 alert_eth filter does NOT compile on LINUX_SLL2 (why there are two alerts)",
      lambda: not comp(sl, S.alert_eth_filter()))
    # matching: positives one per clause (MAC-only first: they carry no network-layer signature),
    # negatives look-alikes
    mac_only = [eth(OTHER, GUEST, 0x0800, ipv4("192.168.60.99", "192.168.60.1", 6, tcp(5000, 22))),
                eth(OTHER, SPOOF, 0x0800, ipv4("192.168.60.99", "192.168.60.1", 6, tcp(5000, 22)))]
    pos = mac_only + [
           eth("ff:ff:ff:ff:ff:ff", OTHER, 0x0806, arp(1, OTHER, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.9")),
           eth(OTHER, OTHER, 0x0806, arp(2, GUEST, "192.168.60.99", OTHER, "192.168.60.1")),  # ARP sha guest
           eth(OTHER, OTHER, 0x86DD, ipv6(S.GUEST_LL6, "ff02::1", 58, icmp6(1))),              # guest LL6
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "10.200.0.1", 6, tcp(31172, 8011))),
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.177.128", "224.0.0.1", 1, icmp(1202))),     # ICMP size
           eth(OTHER, OTHER, 0x86DD, ipv6("fe80::1", "ff02::1", 58, icmp6(1301)))]             # ICMPv6 size
    neg = [eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.3", "192.168.60.10", 6, tcp(42172, 8011))),  # 06B-3G
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "192.168.60.3", 6, tcp(8011, 31172))),  # dst port only
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "192.168.60.1", 1, icmp(100))),
           eth(OTHER, OTHER, 0x0806, arp(2, MANAGER_MAC, "192.168.60.10", OTHER, "192.168.60.2")),
           eth(OTHER, OTHER, 0x86DD, ipv6("fe80::2", "ff02::1", 58, icmp6(10)))]
    pe, ne = os.path.join(tmp, "pos-en.pcap"), os.path.join(tmp, "neg-en.pcap")
    ps, ns = os.path.join(tmp, "pos-sll2.pcap"), os.path.join(tmp, "neg-sll2.pcap")
    write_pcap(pe, [(1.0 + i, f) for i, f in enumerate(pos)])
    write_pcap(ne, [(1.0 + i, f) for i, f in enumerate(neg)])
    write_pcap(ps, [(1.0 + i, sll2(f)) for i, f in enumerate(pos[len(mac_only):])], 276)
    write_pcap(ns, [(1.0 + i, sll2(f)) for i, f in enumerate(neg)], 276)

    def nmatch(f, flt):
        r = subprocess.run(["tcpdump", "-n", "-r", f, flt], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        return len([x for x in r.stdout.splitlines() if x.strip()])
    t("A10 alert_eth matches every Ethernet positive fixture", lambda: nmatch(pe, S.alert_eth_filter()) == len(pos))
    t("A11 alert_eth matches no negative fixture (incl. 06B-3G ctl port 42172)",
      lambda: nmatch(ne, S.alert_eth_filter()) == 0)
    t("A12 alert_any matches every network-layer positive on LINUX_SLL2",
      lambda: nmatch(ps, S.alert_any_filter()) == len(pos) - len(mac_only))
    t("A14 alert_any does not match the MAC-only positives (the reason for the veth alert)",
      lambda: nmatch(pe, S.alert_any_filter()) == len(pos) - len(mac_only))
    t("A13 alert_any matches no negative on LINUX_SLL2", lambda: nmatch(ns, S.alert_any_filter()) == 0)


def _with(d, k, v, fn):
    d[k] = v
    try:
        return fn()
    finally:
        del d[k]


# ------------------------------------------------------------------ B. readers
def sec_B(tmp):
    fr = [F_arp_ok(), F_ip()]
    p = os.path.join(tmp, "b")
    write_pcap(p + "le.pcap", [(10.25, fr[0]), (11.5, fr[1])])
    write_pcap(p + "be.pcap", [(10.25, fr[0])], endian=">")
    write_pcap(p + "ns.pcap", [(10.000000123, fr[0])], nano=True)
    t("B1 pcap little-endian: frames and times", lambda: [(round(a, 6), b) for a, b in L.read_frames(p + "le.pcap")]
      == [(10.25, fr[0]), (11.5, fr[1])])
    t("B2 pcap big-endian", lambda: L.read_frames(p + "be.pcap")[0][1] == fr[0])
    t("B3 pcap nanosecond magic", lambda: abs(L.read_frames(p + "ns.pcap")[0][0] - 10.000000123) < 1e-8)
    us = 1791389689323083
    open(p + "a.pcapng", "wb").write(shb() + idb() + epb(us, fr[0]) + epb(us + 1, fr[1]))
    t("B4 pcapng default microsecond resolution",
      lambda: abs(L.read_frames(p + "a.pcapng")[0][0] - 1791389689.323083) < 2e-6)
    open(p + "b.pcapng", "wb").write(shb() + idb(tsresol=9) + epb(us * 1000 + 7, fr[0]))
    t("B5 pcapng if_tsresol 9 (nanoseconds)",
      lambda: abs(L.read_frames(p + "b.pcapng")[0][0] - 1791389689.323083) < 2e-6)
    open(p + "c.pcapng", "wb").write(shb(">") + idb(e=">") + epb(us, fr[0], e=">"))
    t("B6 pcapng big-endian section", lambda: L.read_frames(p + "c.pcapng")[0][1] == fr[0])
    open(p + "d.pcapng", "wb").write(shb() + idb() + epb(us, fr[0]) + shb() + idb() + epb(us, fr[1]))
    t("B7 pcapng two sections", lambda: len(L.read_frames(p + "d.pcapng")) == 2)
    cases = {
        "B8 empty file is a read error": b"",
        "B9 unknown magic is a read error": b"\x00\x01\x02\x03" * 8,
        "B10 truncated pcap record is a read error": open(p + "le.pcap", "rb").read()[:-5],
        "B11 truncated pcapng block is a read error": open(p + "a.pcapng", "rb").read()[:-6],
        "B12 pcapng block trailer mismatch is a read error":
            open(p + "a.pcapng", "rb").read()[:-4] + struct.pack("<I", 999),
        "B13 EPB for an undefined interface is a read error": shb() + epb(us, fr[0]),
        "B14 simple packet block (no timestamp) is a read error": shb() + idb() + _blk(3, struct.pack("<I", 3) + b"abc"),
        "B15 pcapng non-Ethernet interface is a read error": shb() + idb(276) + epb(us, fr[0]),
    }
    for name, data in cases.items():
        q = p + re.sub(r"\W", "", name)[:12]
        open(q, "wb").write(data)
        t(name, lambda q=q: raises(L.FrameReadError, lambda: L.read_frames(q)))
    write_pcap(p + "sll.pcap", [(1.0, fr[0])], 276)
    t("B16 pcap non-Ethernet link type is a read error", lambda: raises(L.FrameReadError, lambda: L.read_frames(p + "sll.pcap")))
    t("B17 missing file is a read error", lambda: raises(L.FrameReadError, lambda: L.read_frames(p + "nope")))


# ------------------------------------------------------------------ C/D. decoder and classifier
def cls(frame, tap=TAP):
    return L.classify(L.decode(1.0, frame), tap)


def sec_D():
    # direction
    t("D1 guest frame -> guest", lambda: cls(F_ip())[0] == "guest")
    t("D2 chosen spoof MAC -> l2_bad_mac (any ethertype)",
      lambda: cls(eth(TAP, SPOOF, 0x86DD, ipv6("fe80::1", "ff02::1", 58, icmp6(1))))[:2] == ("guest_spoof_mac", "l2_bad_mac"))
    t("D3 TAP_MAC source -> worker direction", lambda: cls(eth(GUEST, TAP, 0x0806, arp(2, TAP, "10.200.0.1", GUEST, "10.200.0.2")))[:2]
      == ("worker", "arp_out_ok"))
    t("D4 other source MAC -> unknown_src / unmapped (never l2_bad_mac)",
      lambda: cls(F_ip(smac=OTHER))[:2] == ("unknown_src", "unmapped"))
    t("D5 TAP_MAC equal to the guest MAC is refused", lambda: raises(ValueError, lambda: cls(F_ip(), tap=GUEST)))
    t("D6 malformed TAP_MAC is refused", lambda: raises(ValueError, lambda: cls(F_ip(), tap="7a:93")))
    t("D7 frame shorter than Ethernet header -> unmapped", lambda: cls(b"\x01\x02\x03")[1] == "unmapped")
    # L2 ethertype
    t("D8 IPv6 from guest -> l2_bad_ethertype (IPv6 recognised)",
      lambda: cls(eth(TAP, GUEST, 0x86DD, ipv6(S.GUEST_LL6, "ff02::1", 58, icmp6(1301))))[1:] == ("l2_bad_ethertype", "IPv6"))
    t("D9 LLDP from guest -> l2_bad_ethertype", lambda: cls(eth(TAP, GUEST, 0x88CC, b"\0" * 30))[1] == "l2_bad_ethertype")
    t("D10 802.3 length field -> l2_bad_ethertype", lambda: cls(eth(TAP, GUEST, 0x0040, b"\0" * 64))[1] == "l2_bad_ethertype")
    t("D11 VLAN-tagged -> unmapped (not claimed)", lambda: cls(eth(TAP, GUEST, 0x8100, b"\x00\x05\x08\x00" + b"\0" * 40))[1] == "unmapped")
    f6 = L.decode(1.0, eth(TAP, GUEST, 0x86DD, ipv6(S.GUEST_LL6, "ff02::1", 58, icmp6(1301))))
    t("D12 IPv6 decode: plen, next header, ICMPv6 type",
      lambda: (f6["ip6"]["plen"], f6["ip6"]["nh"], f6["ip6"]["icmp6_type"], f6["ip6"]["src"]) == (1309, 58, 128, S.GUEST_LL6))
    # ARP mapping
    t("D13 ARP request guest -> 10.200.0.1, broadcast -> arp_in_ok", lambda: cls(F_arp_ok())[1] == "arp_in_ok")
    t("D14 ARP reply to TAP_MAC -> arp_in_ok", lambda: cls(eth(TAP, GUEST, 0x0806, arp(2, GUEST, "10.200.0.2", TAP, "10.200.0.1")))[1]
      == "arp_in_ok")
    arp_drop = {
        "D15 ARP target 192.168.60.2 -> arp_in_drop": arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "192.168.60.2"),
        "D16 gratuitous (spa = tpa = 10.200.0.2) -> arp_in_drop": arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.2"),
        "D17 spoofed sender IP 10.200.0.1 -> arp_in_drop": arp(1, GUEST, "10.200.0.1", "00:00:00:00:00:00", "10.200.0.1"),
        "D18 sender MAC field differs from guest -> arp_in_drop": arp(2, SPOOF, "10.200.0.2", TAP, "10.200.0.1"),
        "D19 opcode 3 -> arp_in_drop": arp(3, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1"),
        "D20 htype 6 -> arp_in_drop": arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1", htype=6),
        "D21 ptype 0x86dd -> arp_in_drop": arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1", ptype=0x86DD),
    }
    for name, payload in arp_drop.items():
        t(name, lambda payload=payload: cls(eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0806, payload))[1] == "arp_in_drop")
    t("D22 ARP to another unicast MAC (OTHERHOST) -> arp_not_hooked",
      lambda: cls(F_arp_ok(op=2, dst=MANAGER_MAC))[1] == "arp_not_hooked")
    t("D23 ARP to a multicast MAC is hooked", lambda: cls(F_arp_ok(dst="01:00:5e:00:00:01"))[1] == "arp_in_ok")
    t("D24 ARP hlen 8 -> arp_not_hooked", lambda: cls(eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0806,
      arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1", hlen=8)))[1] == "arp_not_hooked")
    t("D25 ARP plen 16 -> arp_not_hooked", lambda: cls(eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0806,
      arp(1, GUEST, "10.200.0.2", "00:00:00:00:00:00", "10.200.0.1", plen=16)))[1] == "arp_not_hooked")
    t("D26 ARP payload shorter than 28 bytes -> arp_not_hooked",
      lambda: cls(eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0806, arp(1, GUEST, "10.200.0.2", "0:0:0:0:0:0", "10.200.0.1")[:20]))[1]
      == "arp_not_hooked")
    t("D27 ARP payload shorter than 8 bytes -> arp_not_hooked", lambda: cls(eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0806, b"\0\1"))[1]
      == "arp_not_hooked")
    # IPv4, same order as guest.nft prerouting
    ipcases = [("D28 spoofed source wins over the allowed service -> drop_spoof",
                F_ip(src="10.200.0.3", dst="10.200.0.1", l4=tcp(31171, 8011)), "drop_spoof"),
               ("D29 tcp 10.200.0.1:8011 -> allow_svc", F_ip(dst="10.200.0.1", l4=tcp(40000, 8011)), "allow_svc"),
               ("D30 udp 10.200.0.1:8011 -> drop_worker_other", F_ip(dst="10.200.0.1", proto=17, l4=udp(40000, 8011)),
                "drop_worker_other"),
               ("D31 non-first fragment to 8011 -> drop_worker_other (no ports)",
                F_ip(dst="10.200.0.1", l4=tcp(40000, 8011), frag=100), "drop_worker_other"),
               ("D32 subnet broadcast 10.200.0.3 -> drop_private", F_ip(dst="10.200.0.3", proto=1, l4=icmp(1204),
                dmac="ff:ff:ff:ff:ff:ff"), "drop_private"),
               ("D33 255.255.255.255 -> drop_bcast_mcast", F_ip(dst="255.255.255.255", proto=1, l4=icmp(1201),
                dmac="ff:ff:ff:ff:ff:ff"), "drop_bcast_mcast"),
               ("D34 224.0.0.1 -> drop_bcast_mcast", F_ip(dst="224.0.0.1", proto=1, l4=icmp(1202), dmac="01:00:5e:00:00:01"),
                "drop_bcast_mcast"),
               ("D35 DHCP 0.0.0.0 -> 255.255.255.255 -> drop_spoof", F_ip(src="0.0.0.0", dst="255.255.255.255", proto=17,
                l4=udp(68, 67), dmac="ff:ff:ff:ff:ff:ff"), "drop_spoof"),
               ("D36 192.168.60.10 -> drop_private", F_ip(dst="192.168.60.10"), "drop_private"),
               ("D37 1.1.1.1 -> drop_public", F_ip(), "drop_public"),
               ("D38 IPv4 to another unicast MAC (OTHERHOST) -> ip_not_hooked", F_ip(dmac=MANAGER_MAC), "ip_not_hooked"),
               ("D39 IPv4 bad header checksum -> ip_not_hooked", F_ip(bad_csum=True), "ip_not_hooked"),
               ("D40 IPv4 total length beyond frame -> ip_not_hooked", F_ip(tot=1500), "ip_not_hooked")]
    for name, frame, want in ipcases:
        t(name, lambda frame=frame, want=want: cls(frame)[1] == want)
    t("D41 worker tcp sport 8011 -> allow_out_svc",
      lambda: cls(eth(GUEST, TAP, 0x0800, ipv4("10.200.0.1", "10.200.0.2", 6, tcp(8011, 40000))))[1] == "allow_out_svc")
    t("D42 worker ICMP to guest -> worker_unexpected",
      lambda: cls(eth(GUEST, TAP, 0x0800, ipv4("10.200.0.1", "10.200.0.2", 1, icmp(8))))[1] == "worker_unexpected")
    t("D43 worker ARP outside the allow rule -> worker_unexpected",
      lambda: cls(eth(GUEST, TAP, 0x0806, arp(1, TAP, "10.200.0.1", GUEST, "192.168.60.2")))[1] == "worker_unexpected")
    t("D44 every class produced is a counter class or a declared no-counter class",
      lambda: all(c in L.COUNTER_CLASSES + L.NO_COUNTER for c in ("arp_not_hooked", "ip_not_hooked", "unmapped",
                                                                  "worker_unexpected")))


# ------------------------------------------------------------------ E. strict deltas and reconcile_l2
def rd(t0, t1, **v):
    return {"t_start": t0, "t_end": t1, "values": v}


def sec_E():
    A = rd(100.0, 100.01, arp_in_ok=5, arp_in_drop=0, l2_bad_mac=0)
    B = rd(110.0, 110.01, arp_in_ok=7, arp_in_drop=3, l2_bad_mac=1)
    fr = ([{"t": 105.0, "cls": "arp_in_ok"}] * 2 + [{"t": 105.1, "cls": "arp_in_drop"}] * 3
          + [{"t": 106.0, "cls": "l2_bad_mac"}])
    comp = ("arp_in_ok", "arp_in_drop", "l2_bad_mac")
    t("E1 exact match -> PASS", lambda: L.reconcile_l2(fr, A, B, comp)["verdict"] == "PASS")
    t("E2 missing counter in read A -> ERROR, not 0",
      lambda: "missing" in L.reconcile_l2(fr, rd(100, 100.01, arp_in_ok=5, l2_bad_mac=0), B, comp).get("error", ""))
    t("E3 missing counter in read B -> ERROR",
      lambda: L.reconcile_l2(fr, A, rd(110, 110.01, arp_in_ok=7, arp_in_drop=3), comp)["verdict"] == "ERROR")
    t("E4 bool counter value -> ERROR",
      lambda: L.reconcile_l2(fr, A, rd(110, 110.01, arp_in_ok=7, arp_in_drop=True, l2_bad_mac=1), comp)["verdict"] == "ERROR")
    t("E5 counter decreased -> ERROR",
      lambda: "decreased" in L.reconcile_l2(fr, A, rd(110, 110.01, arp_in_ok=4, arp_in_drop=3, l2_bad_mac=1), comp)["error"])
    t("E6 values missing entirely -> ERROR", lambda: L.reconcile_l2(fr, {"t_start": 1, "t_end": 2}, B, comp)["verdict"] == "ERROR")
    t("E7 one frame too many -> FAIL", lambda: L.reconcile_l2(fr + [{"t": 107.0, "cls": "arp_in_drop"}], A, B, comp)["verdict"] == "FAIL")
    t("E8 edge frame -> UNVERIFIED",
      lambda: L.reconcile_l2(fr[:5] + [{"t": 109.99, "cls": "l2_bad_mac"}], A, B, comp)["verdict"] == "UNVERIFIED")
    r = L.reconcile_l2(fr + [{"t": 105.5, "cls": "arp_not_hooked", "reason": "OTHERHOST"}], A, B, comp)
    t("E9 not-hooked frame inside the window -> UNVERIFIED, listed",
      lambda: r["verdict"] == "UNVERIFIED" and r["no_counter_frames"][0]["cls"] == "arp_not_hooked")
    t("E10 unmapped frame inside the window -> UNVERIFIED",
      lambda: L.reconcile_l2(fr + [{"t": 105.5, "cls": "unmapped"}], A, B, comp)["verdict"] == "UNVERIFIED")
    t("E11 no-counter frame outside the window does not count",
      lambda: L.reconcile_l2(fr + [{"t": 50.0, "cls": "unmapped"}], A, B, comp)["verdict"] == "PASS")
    t("E12 a real mismatch stays FAIL even with no-counter frames",
      lambda: L.reconcile_l2(fr[:-1] + [{"t": 105.5, "cls": "unmapped"}], A, B, comp)["verdict"] == "FAIL")
    A2, B2 = dict(A, values=dict(A["values"], arp_out_drop=0)), dict(B, values=dict(B["values"], arp_out_drop=0))
    t("E13 comparing an unobservable counter (arp_out_drop) -> ERROR even with the counter present",
      lambda: "not a frame-mapped" in L.reconcile_l2(fr, A2, B2, comp + ("arp_out_drop",)).get("error", ""))
    t("E14 invalid read times -> ERROR (counter_window.validate)",
      lambda: L.reconcile_l2(fr, A, rd(90.0, 90.01, arp_in_ok=7, arp_in_drop=3, l2_bad_mac=1), comp)["verdict"] == "ERROR")
    t("E15 worker_unexpected frame inside the window -> UNVERIFIED",
      lambda: L.reconcile_l2(fr + [{"t": 105.5, "cls": "worker_unexpected"}], A, B, comp)["verdict"] == "UNVERIFIED")


# ------------------------------------------------------------------ F. verdict labels (D6)
def sec_F():
    ok_checks = {"guest_connection_failed": True, "probe_packets_in_tap0_pcap": True,
                 "probe_packets_hit_expected_counter": True}
    rec = {"verdict": "PASS", "per_class": {"arp_in_drop": {"status": "PASS", "delta": 3}}}
    t("F1 live control alive + PASS -> ĐẠT", lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "live", True) == ("ĐẠT", True))
    t("F2 live control dead -> CHƯA KIỂM CHỨNG",
      lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "live", False)[0].startswith("CHƯA KIỂM CHỨNG"))
    t("F3 rule check + PASS -> ĐẠT (kiểm quy tắc)",
      lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "rule_check") == ("ĐẠT (kiểm quy tắc)", True))
    t("F4 rule check with a control value is refused",
      lambda: raises(ValueError, lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "rule_check", True)))
    t("F5 live control without a bool is refused",
      lambda: raises(ValueError, lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "live")))
    t("F6 unknown control kind is refused",
      lambda: raises(ValueError, lambda: L.probe_verdict_l2(ok_checks, rec, "arp_in_drop", "none")))
    t("F7 rule check never hides a FAIL",
      lambda: L.probe_verdict_l2(dict(ok_checks, guest_connection_failed=False), rec, "arp_in_drop", "rule_check")
      == ("FAIL", False))
    unv = {"verdict": "UNVERIFIED", "per_class": {"arp_in_drop": {"status": "PASS", "delta": 3}},
           "no_counter_frames": [{"t": 1.0, "cls": "arp_not_hooked"}]}
    t("F8 no-counter frames are named as the cause, not as an edge",
      lambda: L.probe_verdict_l2(ok_checks, unv, "arp_in_drop", "rule_check")[0]
      == "CHƯA KIỂM CHỨNG (khung không có bộ đếm trong cửa sổ)")
    t("F9 run_outcome counts ĐẠT (kiểm quy tắc) as passed",
      lambda: CW.run_outcome([{"test": "probe x -> ĐẠT (kiểm quy tắc)", "ok": True}]) == "PASS")


# ------------------------------------------------------------------ G. guest state save / restore
ARP_HDR = "IP address       HW type     Flags       HW address            Mask     Device"


class FakeGuest:
    """Minimal simulation of the commands guest_state emits. [Kernel] behaviour simulated, NOT verified:
    link down removes every route through the device and flushes ALL its neighbours (permanent too);
    link up re-adds the connected routes; a /32 address has no connected route."""

    def __init__(self, iface="eth1", netifd_extra=None, fail=(), bad_section=None):
        self.iface, self.netifd_extra, self.fail, self.bad_section = iface, netifd_extra, set(fail), bad_section
        self.mac, self.oper, self.notify = GUEST, "up", 0
        self.addrs = {"10.200.0.2/30"}
        self.routes = {f"default via 10.200.0.1 dev {iface}", f"10.200.0.0/30 dev {iface} scope link src 10.200.0.2",
                       "192.168.1.0/24 dev br-lan scope link src 192.168.1.1"}
        self.neigh = {("10.200.0.1", iface): (TAP, 0x2), ("192.168.1.5", "br-lan"): ("00:11:22:33:44:55", 0x2)}
        self.log = []

    def _conn(self, a):
        n = ipaddress.ip_interface(a)
        return None if n.network.prefixlen == 32 else f"{n.network} dev {self.iface} scope link src {n.ip}"

    def run(self, cmd, timeout=60):
        self.log.append(cmd)
        if cmd == GS.snapshot_cmd(self.iface):
            return 0, self._snap()
        if cmd in self.fail:
            return 2, "RTNETLINK answers: Operation not supported"
        i = self.iface
        m = re.fullmatch(rf"ip link set dev {i} (down|up|address (\S+))", cmd)
        if m:
            if m.group(1) == "down":
                self.oper = "down"
                self.routes = {r for r in self.routes if f" dev {i}" not in r}
                self.neigh = {k: v for k, v in self.neigh.items() if k[1] != i}
            elif m.group(1) == "up":
                self.oper = "up"
                self.routes |= {c for c in map(self._conn, self.addrs) if c}
                if self.netifd_extra:
                    self.addrs.add(self.netifd_extra)
            else:
                self.mac = m.group(2)
            return 0, ""
        m = re.fullmatch(rf"ip addr (add|del) (\S+)(?: brd \+)? dev {i}", cmd)
        if m:
            a, c = m.group(2), self._conn(m.group(2))
            if m.group(1) == "add":
                if a in self.addrs:
                    return 2, "RTNETLINK answers: File exists"
                self.addrs.add(a)
                if c and self.oper == "up":
                    self.routes.add(c)
            else:
                if a not in self.addrs:
                    return 2, "RTNETLINK answers: Cannot assign"
                self.addrs.discard(a)
                self.routes.discard(c)
            return 0, ""
        m = re.fullmatch(r"ip route (add|del) (.+)", cmd)
        if m:
            r = " ".join(m.group(2).split())
            if m.group(1) == "add":
                if r in self.routes:
                    return 2, "RTNETLINK answers: File exists"
                self.routes.add(r)
            else:
                if r not in self.routes:
                    return 2, "RTNETLINK answers: No such process"
                self.routes.discard(r)
            return 0, ""
        m = re.fullmatch(r"arp -i (\S+) (-d (\S+)|-s (\S+) (\S+))", cmd)
        if m:
            if m.group(3):
                return (0, "") if self.neigh.pop((m.group(3), m.group(1)), None) else (1, "No ARP entry")
            self.neigh[(m.group(4), m.group(1))] = (m.group(5), 0x6)
            return 0, ""
        m = re.fullmatch(rf"echo (\d+) > /proc/sys/net/ipv4/conf/{i}/arp_notify", cmd)
        if m:
            self.notify = int(m.group(1))
            return 0, ""
        return 127, f"sh: unknown command in simulation: {cmd}"

    def _snap(self):
        def sec(name, body, rc=0):
            if self.bad_section == name:
                rc = 1
            if self.bad_section == name + "-missing":
                return ""
            return f"@@S {name}\n{body}\n@@RC {rc}\n"
        addr = "\n".join(f"    inet {a} brd x scope global {self.iface}" for a in sorted(self.addrs))
        arpt = "\n".join([ARP_HDR] + [f"{ip:<16} 0x1         {fl:#x}         {mc}     *        {dev}"
                                      for (ip, dev), (mc, fl) in sorted(self.neigh.items())])
        return (sec("mac", self.mac) + sec("operstate", self.oper)
                + sec("addr", f"3: {self.iface}: <BROADCAST,UP>\n{addr}") + sec("route", "\n".join(sorted(self.routes)))
                + sec("arp", arpt) + sec("arp_notify", str(self.notify)))


def sec_G():
    # parser on the real busybox text recorded in 06B-3G topology.json (ARM)
    real_addr = ("3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000\n"
                 "    link/ether 52:54:00:c7:00:02 brd ff:ff:ff:ff:ff:ff\n"
                 "    inet 10.200.0.2/30 brd 10.200.0.3 scope global eth1\n       valid_lft forever preferred_lft forever")
    real_route = "default via 10.200.0.1 dev eth1 \n10.200.0.0/30 dev eth1 scope link  src 10.200.0.2 \n"
    text = (f"@@S mac\n52:54:00:c7:00:02\n@@RC 0\n@@S operstate\nup\n@@RC 0\n@@S addr\n{real_addr}\n@@RC 0\n"
            f"@@S route\n{real_route}@@RC 0\n@@S arp\n{ARP_HDR}\n10.200.0.1       0x1         0x2         "
            f"{TAP}     *        eth1\n@@RC 0\n@@S arp_notify\n0\n@@RC 0\n")
    st = GS.parse_snapshot(text)
    t("G1 parse real busybox ip addr / ip route text",
      lambda: st["addrs"] == ["10.200.0.2/30"] and "10.200.0.0/30 dev eth1 scope link src 10.200.0.2" in st["routes"])
    t("G2 /proc/net/arp: complete entry is dynamic, not static",
      lambda: st["neigh_static"] == {} and st["neigh_dynamic"][("10.200.0.1", "eth1")] == (TAP, 2))
    # valid-looking content but a failed command: the rc alone must make it an error
    t("G3 section with rc != 0 -> StateReadError",
      lambda: raises(GS.StateReadError, lambda: GS.parse_snapshot(text.replace("@@S arp_notify\n0\n@@RC 0", "@@S arp_notify\n0\n@@RC 1"))))
    t("G4 missing section -> StateReadError",
      lambda: raises(GS.StateReadError, lambda: GS.parse_snapshot(text.split("@@S arp_notify")[0])))
    t("G5 bad interface name refused", lambda: raises(ValueError, lambda: GS.snapshot_cmd("eth1; reboot")))

    def scenario(change, **kw):
        g = FakeGuest(**kw)
        before = GS.read_state(g, "eth1")
        change(g)
        return g, before, GS.restore(g, "eth1", before)
    # 1 MAC change through down/address/up: default route lost, neighbours flushed
    g, b, r = scenario(lambda g: [g.run(c) for c in ("ip link set dev eth1 down", f"ip link set dev eth1 address {SPOOF}",
                                                       "ip link set dev eth1 up")])
    t("G6 MAC change: restored, MAC back, default route re-added",
      lambda: r["restored"] and g.mac == GUEST and "default via 10.200.0.1 dev eth1" in g.routes)
    t("G7 MAC change: lost dynamic neighbour is reported, not forced",
      lambda: any("10.200.0.1" in d for d in r["dynamic_changes"]) and not any("arp -i eth1 -s" in c["cmd"] for c in r["commands"]))
    # 2 extra /32 addresses and an on-link route
    g, b, r = scenario(lambda g: [g.run("ip addr add 10.200.0.3/32 brd + dev eth1"),
                                  g.run("ip route add 192.168.60.2 dev eth1 scope link")])
    t("G8 extra /32 address and on-link route removed", lambda: r["restored"] and g.addrs == {"10.200.0.2/30"}
      and "192.168.60.2 dev eth1 scope link" not in g.routes)
    # 3 static neighbour added by the probe -> deleted
    g, b, r = scenario(lambda g: g.run(f"arp -i eth1 -s 10.200.0.1 {TAP}"))
    t("G9 static neighbour added by the probe is deleted", lambda: r["restored"] and ("10.200.0.1", "eth1") not in g.neigh)
    # 4/5 static neighbour that existed BEFORE: lost by a link down / changed -> re-created with its old MAC

    def pre_static(g):
        g.neigh[("10.200.0.1", "eth1")] = (TAP, 0x6)
    g = FakeGuest()
    pre_static(g)
    b = GS.read_state(g, "eth1")
    g.run("ip link set dev eth1 down")
    g.run("ip link set dev eth1 up")
    r = GS.restore(g, "eth1", b)
    t("G10 pre-existing static neighbour flushed by link down is re-created",
      lambda: r["restored"] and g.neigh[("10.200.0.1", "eth1")] == (TAP, 0x6))
    g = FakeGuest()
    pre_static(g)
    b = GS.read_state(g, "eth1")
    g.run("arp -i eth1 -s 10.200.0.1 00:00:00:00:00:99")
    r = GS.restore(g, "eth1", b)
    t("G11 pre-existing static neighbour with a changed MAC is set back",
      lambda: r["restored"] and g.neigh[("10.200.0.1", "eth1")][0] == TAP)
    # 6 arp_notify
    g, b, r = scenario(lambda g: g.run("echo 1 > /proc/sys/net/ipv4/conf/eth1/arp_notify"))
    t("G12 arp_notify restored", lambda: r["restored"] and g.notify == 0)
    # 7 netifd adds an address on link up
    g, b, r = scenario(lambda g: [g.run("ip link set dev eth1 down"), g.run("ip link set dev eth1 up")],
                       netifd_extra="192.168.99.7/24")
    t("G13 address added by netifd on link up is removed", lambda: r["restored"] and "192.168.99.7/24" not in g.addrs)
    # 8 a restore command fails -> not restored, diffs listed
    g, b, r = scenario(lambda g: [g.run("ip link set dev eth1 down"), g.run(f"ip link set dev eth1 address {SPOOF}"),
                                  g.run("ip link set dev eth1 up")], fail=(f"ip link set dev eth1 address {GUEST}",))
    t("G14 failed restore command -> restored False, MAC diff listed",
      lambda: not r["restored"] and any(d.startswith("mac:") for d in r["diffs"]))
    # 9 state cannot be read during restore -> restored False with the error
    g = FakeGuest()
    b = GS.read_state(g, "eth1")
    g.bad_section = "route"
    r = GS.restore(g, "eth1", b)
    t("G15 unreadable state during restore -> restored False, error kept", lambda: not r["restored"] and "route" in r["error"])
    # 10 GuestChange restores after an exception
    g = FakeGuest()
    rec = {}
    with contextlib.suppress(RuntimeError):
        with GS.GuestChange(g, "eth1") as rec:
            g.run("ip addr add 10.200.0.3/32 brd + dev eth1")
            raise RuntimeError("probe crashed")
    t("G16 GuestChange restores even when the probe raises", lambda: rec["restore"]["restored"] and g.addrs == {"10.200.0.2/30"})
    g, b, r = scenario(lambda g: None)
    t("G17 nothing changed -> no command, restored", lambda: r["restored"] and r["commands"] == [])


# ------------------------------------------------------------------ H. sigscan_l2
def sec_H(tmp):
    pos = [F_arp_ok(),                                                                         # guest_mac, arp_guest_sha, arp_guest_net
           eth(TAP, SPOOF, 0x0806, arp(1, SPOOF, "10.200.0.2", "0:0:0:0:0:0", "10.200.0.1")),   # spoof_mac, arp_spoof_sha, arp_guest_net
           eth(OTHER, OTHER, 0x0806, arp(2, OTHER, "192.168.60.10", OTHER, "192.168.60.2")),    # arp_spoof_spa_manager
           eth(OTHER, OTHER, 0x86DD, ipv6(S.GUEST_LL6, "ff02::1", 58, icmp6(1301))),            # ipv6_guest, icmp_size
           eth(OTHER, OTHER, 0x0800, ipv4("10.200.0.3", "1.1.1.1", 6, tcp(31174, 443))),       # guest_net_ip, spoof_src_ip, probe_port
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "10.200.0.1", 6, tcp(31172, 8011))),  # spoof (shared+sport), probe_port, guest_net_ip
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.177.128", "8.8.8.8", 17, udp(5353, 53, b"\x07ct01-06b4-t12-arm-3"))),
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.177.128", "224.0.0.1", 1, icmp(1202)))]     # icmp_size
    want = {"frames": 8, "guest_mac": 1, "spoof_mac": 1, "guest_net_ip": 2, "arp_guest_sha": 1, "arp_spoof_sha": 1,
            "arp_guest_net": 2, "arp_spoof_spa_manager": 1, "ipv6_guest": 1, "spoof_src_ip": 2, "probe_port": 2,
            "icmp_size": 2, "probe_qname": 1, "truncated_frames": 0, "unscannable_truncated": 0,
            "unscannable_undecoded": 0}
    neg = [eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.3", "192.168.60.10", 6, tcp(42172, 8011))),
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "192.168.60.3", 6, tcp(8011, 40000))),
           eth(OTHER, OTHER, 0x0806, arp(2, MANAGER_MAC, "192.168.60.10", OTHER, "192.168.60.2")),
           eth(OTHER, OTHER, 0x86DD, ipv6("fe80::2", "ff02::1", 58, icmp6(10))),
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "192.168.60.1", 1, icmp(56))),
           eth(OTHER, OTHER, 0x0800, ipv4("192.168.177.128", "8.8.8.8", 17, udp(5353, 53, b"\x0bct01-06b3b-ctl-arm")))]
    pp, nn = os.path.join(tmp, "h-pos.pcap"), os.path.join(tmp, "h-neg.pcap")
    write_pcap(pp, [(1.0 + i, f) for i, f in enumerate(pos)])
    write_pcap(nn, [(1.0 + i, f) for i, f in enumerate(neg)])
    got = SL.scan(pp, MANAGER_MAC)
    for k in SL.KEYS:
        t(f"H-pos {k} = {want[k]}", lambda k=k: got[k] == want[k])
    gn = SL.scan(nn, MANAGER_MAC)
    t("H-neg every signature key = 0 on look-alikes (06B-3G ctl port 42172, manager traffic, real manager ARP)",
      lambda: all(gn[k] == 0 for k in SL.KEYS if k != "frames") and gn["frames"] == len(neg))
    # the real manager answering on a probe port as DESTINATION: a probe-port hit, but not a spoofed source
    pm = os.path.join(tmp, "h-mgr.pcap")
    write_pcap(pm, [(1.0, eth(OTHER, OTHER, 0x0800, ipv4("192.168.60.10", "192.168.60.3", 6, tcp(8011, 31172))))])
    t("H6 shared spoofed source (192.168.60.10) is matched only with a probe SOURCE port",
      lambda: (lambda c: c["spoof_src_ip"] == 0 and c["probe_port"] == 1)(SL.scan(pm, MANAGER_MAC)))
    t("H1 --no-manager-mac reports the manager check as skipped, not 0",
      lambda: SL.scan(nn, None)["arp_spoof_spa_manager"] == "skipped")

    def cli(*args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = SL.main(list(args))
        return rc, out.getvalue()
    open(os.path.join(tmp, "h-empty.pcap"), "wb").close()
    t("H2 empty file -> exit 2, nothing printed", lambda: cli(os.path.join(tmp, "h-empty.pcap"), "--no-manager-mac") == (2, ""))
    t("H3 truncated file -> exit 2", lambda: _trunc(pp, tmp) and cli(os.path.join(tmp, "h-trunc.pcap"), "--no-manager-mac")[0] == 2)
    t("H4 missing manager option -> usage error", lambda: cli(pp)[0] == 64)
    t("H5 normal run -> exit 0 and one line per key",
      lambda: (lambda r: r[0] == 0 and len(r[1].splitlines()) == len(SL.KEYS))(cli(pp, "--manager-mac", MANAGER_MAC)))


def _trunc(src, tmp):
    open(os.path.join(tmp, "h-trunc.pcap"), "wb").write(open(src, "rb").read()[:-7])
    return True


# ------------------------------------------------------------------ K. snaplen cut vs damaged file vs malformed packet (06B-4BR)
HOST_MAC, GW_MAC, HOST_IP = "00:0c:29:42:ad:4c", "00:50:56:e0:00:01", "192.168.177.128"


def nat(l3):
    """A frame as it leaves ens33 after NAT: host MAC/IP, nothing of the guest left."""
    return eth(GW_MAC, HOST_MAC, 0x0800, l3)


def sec_K(tmp):
    def one(name, frame, cap=None, orig=None, ng=False):
        path = os.path.join(tmp, "k-" + name + (".pcapng" if ng else ".pcap"))
        data = frame if cap is None else frame[:cap]
        o = len(frame) if orig is None else orig
        if ng:
            open(path, "wb").write(shb() + idb() + epb(10**6 * 100, data, orig=o))
        else:
            write_pcap(path, [(100.0, data, o)])
        return path

    def sc(path):
        return SL.scan(path, MANAGER_MAC)
    icmp_nat = nat(ipv4(HOST_IP, "1.1.1.1", 1, icmp(1705)))
    tcp_nat = nat(ipv4(HOST_IP, "1.1.1.1", 6, tcp(31174, 443) + b"\x17" * 1400))
    udp_nat = nat(ipv4(HOST_IP, "1.1.1.1", 17, udp(31020, 9999, b"x" * 1400)))
    dns_nat = nat(ipv4(HOST_IP, "8.8.8.8", 17, udp(40000, 53, b"\0" * 12 + b"\x0bct01-06b4-t12-arm-3" + b"\0" * 600)))
    v6 = eth(OTHER, OTHER, 0x86DD, ipv6("fe80::1", "ff02::1", 58, icmp6(1301)))
    # reviewer's case: ICMP payload 1705 after NAT, full vs. cut to 512 bytes with the original length kept
    full, cut = sc(one("icmp-full", icmp_nat)), sc(one("icmp-512", icmp_nat, 512))
    t("K1 NATed ICMP 1705 B, full capture -> icmp_size 1", lambda: full["icmp_size"] == 1 and full["truncated_frames"] == 0)
    t("K2 NATed ICMP 1705 B cut at 512 (orig kept) -> icmp_size 1 from the IPv4 header",
      lambda: cut["icmp_size"] == 1 and cut["truncated_frames"] == 1 and cut["unscannable_truncated"] == 0)
    ng = sc(one("icmp-512", icmp_nat, 512, ng=True))
    t("K3 same cut in pcapng (EPB original length) -> icmp_size 1, truncated_frames 1",
      lambda: ng["icmp_size"] == 1 and ng["truncated_frames"] == 1)
    for nm, fr in (("tcp", tcp_nat), ("udp", udp_nat)):
        a, b = sc(one(nm + "-full", fr)), sc(one(nm + "-512", fr, 512))
        t(f"K4 NATed {nm.upper()} probe port, full and cut at 512 -> probe_port 1 both",
          lambda a=a, b=b: a["probe_port"] == 1 and b["probe_port"] == 1 and b["unscannable_truncated"] == 0)
    d1, d2 = sc(one("dns-full", dns_nat)), sc(one("dns-cut", dns_nat, 14 + 20 + 8 + 5))
    t("K5 DNS name found when captured in full", lambda: d1["probe_qname"] == 1 and d1["unscannable_truncated"] == 0)
    t("K6 DNS payload cut before the name -> unscannable_truncated 1, not a silent 0",
      lambda: d2["probe_qname"] == 0 and d2["unscannable_truncated"] == 1)
    h = sc(one("ip-hdr-cut", icmp_nat, 14 + 6))
    t("K7 IPv4 header cut by snaplen -> unscannable_truncated 1, no signature claimed",
      lambda: h["unscannable_truncated"] == 1 and h["icmp_size"] == 0 and h["truncated_frames"] == 1)
    pc = sc(one("ports-cut", tcp_nat, 14 + 20 + 2))
    t("K8 TCP ports cut by snaplen -> unscannable_truncated 1", lambda: pc["unscannable_truncated"] == 1)
    e = sc(one("eth-cut", icmp_nat, 10))
    t("K9 Ethernet header cut by snaplen -> unscannable_truncated 1", lambda: e["unscannable_truncated"] == 1)
    ar = sc(one("arp-cut", F_arp_ok(), 14 + 20))
    t("K10 ARP cut below 28 bytes -> unscannable_truncated 1, guest MAC still seen",
      lambda: ar["unscannable_truncated"] == 1 and ar["guest_mac"] == 1 and ar["arp_guest_sha"] == 0)
    v = sc(one("v6-cut", v6, 14 + 40 + 10))
    t("K11 ICMPv6 1301 cut by snaplen -> icmp_size 1 from the IPv6 header", lambda: v["icmp_size"] == 1 and v["unscannable_truncated"] == 0)
    v2 = sc(one("v6-hdr-cut", v6, 14 + 30))
    t("K12 IPv6 header cut by snaplen -> unscannable_truncated 1", lambda: v2["unscannable_truncated"] == 1)
    # malformed on the wire (complete capture): header still read, but the frame is not "cut"
    mal = nat(ipv4(HOST_IP, "1.1.1.1", 1, icmp(100), tot=1733))
    m = sc(one("malformed", mal))
    fm = L.decode(1.0, mal)
    t("K13 malformed (total length beyond the wire frame): header read, not counted as truncated",
      lambda: m["icmp_size"] == 1 and m["truncated_frames"] == 0 and fm["ip"]["hdr_ok"] and not fm["ip"]["valid"]
      and "on the wire" in fm["ip"]["why"])
    m2 = sc(one("malformed-short", nat(ipv4(HOST_IP, "1.1.1.1", 1, b""))[:14 + 12]))
    t("K14 IPv4 header shorter than 20 B on the wire -> unscannable_undecoded 1",
      lambda: m2["unscannable_undecoded"] == 1 and m2["unscannable_truncated"] == 0)
    vl = sc(one("vlan", eth(OTHER, OTHER, 0x8100, b"\x00\x05\x08\x00" + b"\0" * 40)))
    t("K15 VLAN frame -> unscannable_undecoded 1", lambda: vl["unscannable_undecoded"] == 1)
    # damaged files: read errors, never 0
    bad = os.path.join(tmp, "k-incl-gt-orig.pcap")
    write_pcap(bad, [(1.0, icmp_nat, 100)])
    t("K16 pcap record with captured > original length -> read error",
      lambda: raises(L.FrameReadError, lambda: SL.scan(bad, MANAGER_MAC)))
    badng = os.path.join(tmp, "k-cap-gt-orig.pcapng")
    open(badng, "wb").write(shb() + idb() + epb(10**8, icmp_nat, orig=100))
    t("K17 pcapng EPB with captured > original length -> read error",
      lambda: raises(L.FrameReadError, lambda: SL.scan(badng, MANAGER_MAC)))
    cutfile = os.path.join(tmp, "k-file-cut.pcap")
    open(cutfile, "wb").write(open(one("icmp-512b", icmp_nat, 512), "rb").read()[:-40])
    t("K18 file cut inside a record (damaged, not snaplen) -> read error",
      lambda: raises(L.FrameReadError, lambda: SL.scan(cutfile, MANAGER_MAC)))
    # tap0 classifier stays strict
    g_ip = F_ip(l4=tcp(31000, 443) + b"\0" * 600)

    def cl(frame, cap):
        return L.classify(L.decode(1.0, frame[:cap], len(frame)), TAP)
    t("K19 tap0: guest IPv4 cut by snaplen -> unmapped (not drop_public)",
      lambda: cl(g_ip, 100)[1] == "unmapped" and L.classify(L.decode(1.0, g_ip), TAP)[1] == "drop_public")
    t("K20 tap0: guest ARP cut by snaplen -> unmapped", lambda: cl(F_arp_ok() + b"\0" * 18, 50)[1] == "unmapped")
    t("K21 tap0: spoofed-MAC frame cut by snaplen is still l2_bad_mac (L2 decision)",
      lambda: cl(eth(TAP, SPOOF, 0x0800, ipv4("10.200.0.2", "1.1.1.1", 6, tcp(1, 2) + b"\0" * 100)), 40)[1] == "l2_bad_mac")
    t("K22 tap0: worker frame cut by snaplen -> unmapped",
      lambda: cl(eth(GUEST, TAP, 0x0800, ipv4("10.200.0.1", "10.200.0.2", 6, tcp(8011, 4000) + b"\0" * 100)), 40)[1] == "unmapped")
    rd_a, rd_b = rd(100.0, 100.01, drop_public=0), rd(110.0, 110.01, drop_public=0)
    fr = [{"t": 105.0, "cls": cl(g_ip, 100)[1], "reason": "cut"}]
    t("K23 tap0: a snaplen-cut guest frame inside the window -> UNVERIFIED",
      lambda: L.reconcile_l2(fr, rd_a, rd_b, ("drop_public",))["verdict"] == "UNVERIFIED")
    t("K24 decode: payload cut by snaplen keeps header, valid False, payload_complete False",
      lambda: (lambda f: f["truncated"] and f["ip"]["hdr_ok"] and not f["ip"]["valid"]
               and not f["ip"]["payload_complete"] and "snaplen" in f["ip"]["why"])(L.decode(1.0, icmp_nat[:512], len(icmp_nat))))


# ------------------------------------------------------------------ I. run-06b3b.sh (06B-4B changes, static)
def sec_I():
    s = open(os.path.join(HERE, "run-06b3b.sh")).read()
    ens = [l for l in s.splitlines() if re.search(r"tcpdump .*-i ens33", l)]
    t("I1 exactly one ens33 capture", lambda: len(ens) == 1)
    t("I2 ens33 capture: snaplen and packet limit from the registry, no filter expression",
      lambda: '-s "$SIG_ENS33_SNAPLEN"' in ens[0] and '-c "$SIG_ENS33_MAX_PACKETS"' in ens[0]
      and re.search(r"-w - \\$", ens[0]) is not None)
    t("I3 alert on any uses the registry filter", lambda: re.search(r'tcpdump -Z root -l -n -i any "\$SIG_ALERT_ANY"', s) is not None)
    t("I4 Ethernet alert on the worker veth uses the registry filter",
      lambda: re.search(r'tcpdump -Z root -l -n -e -i "\$VETH" "\$SIG_ALERT_ETH"', s) is not None)
    t("I5 no hard-coded alert filter left", lambda: '-i any "net 10.200.0.0/30"' not in s)
    m = re.search(r"for k in (guest_mac[^;]*); do", s.replace("\\\n", " "))
    t("I6 run script checks every sigscan_l2 key except frames and truncated_frames (information)",
      lambda: m is not None and m.group(1).split() == [k for k in SL.KEYS if k not in ("frames", "truncated_frames")])
    t("I7 harness path is the 06B-4B copy", lambda: "\nH=/home/dathq/projects/ct01-06b4b\n" in s)
    t("I8 new modules are copied into the run evidence",
      lambda: all(f'"$H/{f}"' in s for f in ("signatures.py", "l2frames.py", "guest_state.py", "sigscan_l2.py")))
    t("I9 L2 self-test runs before anything touches a container",
      lambda: s.index("selftest_l2.py\" --offline-only") < s.index('log "1. preparation"'))
    t("I10 ens33 packet limit reached is a failed check",
      lambda: "ens33 capture did not reach its packet limit" in s)
    t("I11 both alerts are listed as captures that must exit 0",
      lambda: "for f in veth bridge ens33 alert alert_eth; do\n    check \"tcpdump $f: exit 0 on stop\"" in s)


# ------------------------------------------------------------------ R. regression on 06B-3G (read-only)
def tap_mac_of(run):
    txt = open(os.path.join(run, "container", "netns-before.txt")).read()
    m = re.search(r"\d+: tap0: .*?\n\s+link/ether ([0-9a-f:]{17})", txt)
    if not m:
        raise RuntimeError("tap0 MAC not found in netns-before.txt")
    return m.group(1)


def sec_R(run):
    tap = tap_mac_of(run)
    t("R0 TAP_MAC read from the 06B-3G netns record", lambda: tap == "7a:93:2a:f1:47:47")
    for arch, n in (("ARM", 97), ("MIPS", 125)):
        p = os.path.join(run, "container", "probe", arch)
        fr = L.classified_frames(os.path.join(p, "tap0.pcapng"), tap)
        t(f"R1 {arch}: all {n} frames decoded", lambda fr=fr, n=n: len(fr) == n)
        td = subprocess.run(["tcpdump", "-n", "-e", "-tt", "-r", os.path.join(p, "tap0.pcapng")], capture_output=True, text=True)
        rows = [(float(l.split()[0]), l.split()[1]) for l in td.stdout.splitlines() if l.strip()]
        # tcpdump prints microseconds TRUNCATED; the pcapng holds nanoseconds. A float near 1.79e9 has a
        # spacing of 2.4e-7 s, so the comparison allows that much on both sides of [0, 1 us).
        t(f"R2 {arch}: time (within 1 us) and source MAC of every frame equal tcpdump's",
          lambda fr=fr, rows=rows, td=td: td.returncode == 0 and len(rows) == len(fr)
          and all(-2.5e-7 <= f["t"] - r[0] < 1e-6 + 2.5e-7 and f["src"] == r[1] for f, r in zip(fr, rows)))
        sess = json.load(open(os.path.join(p, "session.json")))
        a, f1 = sess["reads"]["before"], sess["reads"]["finals"][0]
        old9 = sess["classes_compared"]
        r9 = L.reconcile_l2(fr, a, f1, old9)
        t(f"R3 {arch}: session window, 9 legacy classes: certain counts equal session.json",
          lambda r9=r9, sess=sess: all(r9["per_class"][k]["certain"] == sess["reconciliation"]["per_class"][k]["certain"]
                                       for k in sess["classes_compared"]))
        r13 = L.reconcile_l2(fr, a, f1, L.COUNTER_CLASSES)
        t(f"R4 {arch}: session window, 13 frame-mapped classes (ARP and allow_out_svc added) -> PASS",
          lambda r13=r13: r13["verdict"] == "PASS" and r13["no_counter_frames"] == [])
        t(f"R5 {arch}: ARP frames equal the ARP counter deltas (arp_in_ok, arp_out_ok, arp_in_drop 0)",
          lambda r13=r13: (r13["per_class"]["arp_in_ok"]["certain"], r13["per_class"]["arp_out_ok"]["certain"],
                           r13["per_class"]["arp_in_drop"]["delta"]) == (2, 2, 0))
        mx = json.load(open(os.path.join(p, "matrix.json")))
        raw = [json.loads(l) for l in open(os.path.join(p, "counters-raw.jsonl"))]
        reads = {x["label"]: x for x in raw}

        def vals(x):
            return {"t_start": x["t_start"], "t_end": x["t_end"],
                    "values": {o["counter"]["name"]: o["counter"]["packets"] for o in json.loads(x["raw"])["nftables"]
                               if "counter" in o}}
        same, verd, ext = True, [], []
        for pr in mx:
            ra, rb = vals(reads[pr["probe"] + " before"]), vals(reads[pr["probe"] + " after"])
            r = L.reconcile_l2(fr, ra, rb, old9)
            old = pr["counter_reconciliation"]["per_class"]
            for k in old9:
                # edge times: tshark text (matrix.json) vs. nanosecond integers here -> within 1 us
                if r["per_class"][k]["certain"] != old[k]["certain"] or any(
                        len(r["per_class"][k][z]) != len(old[k][z])
                        or any(abs(x - y) > 1e-6 for x, y in zip(r["per_class"][k][z], old[k][z]))
                        for z in ("edge_start", "edge_end")):
                    same = False
            verd.append((pr["probe"], r["verdict"], pr["counter_reconciliation"]["verdict"]))
            ext.append((pr["probe"], L.reconcile_l2(fr, ra, rb, L.COUNTER_CLASSES)["verdict"]))
        t(f"R6 {arch}: per probe, 9 legacy classes: certain and edge frames equal matrix.json", lambda same=same: same)
        t(f"R7 {arch}: per probe verdicts equal matrix.json", lambda verd=verd: all(v[1] == v[2] for v in verd))
        print(f"      {arch} per-probe verdict with 13 classes (observation): {ext}")
    for f in ("veth", "bridge", "ens33"):
        c = SL.scan(os.path.join(run, "hostcap", f + ".pcap"), _manager_mac(run))
        t(f"R8 {f}.pcap (06B-3G): every sigscan_l2 signature = 0", lambda c=c: all(c[k] == 0 for k in SL.KEYS if k != "frames"))
    for arch in ("ARM", "MIPS"):
        c = SL.scan(os.path.join(run, "container", "probe", arch, "tap0.pcapng"), _manager_mac(run))
        t(f"R9 {arch} tap0 (positive on real data): guest MAC, guest ARP and guest IPv6 found",
          lambda c=c: c["guest_mac"] > 0 and c["arp_guest_sha"] > 0 and c["ipv6_guest"] > 0)


def _manager_mac(run):
    m = re.search(r"192\.168\.60\.10 dev eth0 lladdr ([0-9a-f:]{17})", open(os.path.join(run, "container", "netns-after.txt")).read())
    if not m:
        raise RuntimeError("manager MAC not found")
    return m.group(1)


def main(argv):
    jpath = None
    if "--json" in argv:
        jpath = argv[argv.index("--json") + 1]
        del argv[argv.index("--json"):argv.index("--json") + 2]
    reg = None
    if argv == ["--offline-only"]:
        pass
    elif len(argv) == 2 and argv[0] == "--regression":
        reg = argv[1]
    else:
        print(__doc__)
        return 64
    with tempfile.TemporaryDirectory(prefix="selftest-l2.") as tmp:
        for name, fn in (("A", lambda: sec_A(tmp)), ("B", lambda: sec_B(tmp)), ("D", sec_D), ("E", sec_E),
                         ("F", sec_F), ("G", sec_G), ("H", lambda: sec_H(tmp)), ("K", lambda: sec_K(tmp)), ("I", sec_I)) + \
                ((("R", lambda: sec_R(reg)),) if reg else ()):
            print(f"== section {name}")
            try:
                fn()
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    if jpath:
        json.dump(RESULTS, open(jpath, "w"), indent=0, sort_keys=True)
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"SELFTEST-L2: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed" + ("" if not bad else f"; FAILED: {bad}"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
