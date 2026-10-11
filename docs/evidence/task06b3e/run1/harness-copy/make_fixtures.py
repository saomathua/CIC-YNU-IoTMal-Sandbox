"""06B-3C — build pcap fixtures for the signature scanner self-test (offline, no packet is sent).

  python3 make_fixtures.py <dir>

positive.pcap   one frame per leak signature; payload signatures are carried by NATed addresses
                (no guest MAC / 10.200.0.0/30), so they prove payload matching works on its own
negative.pcap   look-alikes that must NOT match (control qname, near-miss URLs, port 41021, ...)
truncated.pcap  positive.pcap cut inside the last frame -> reader must report an error
empty.pcap      0 bytes (what a crashed tcpdump left in 06B-3B run 1) -> reader must report an error
ng-*.pcapng     pcapng drop-statistics cases for pcapng_stats.py (drop=0, drop>0, osdrop>0,
                ifrecv mismatch, no statistics, statistics without ifdrop, truncated, not pcapng)
counter-window-cases.json  counter/pcap reconciliation cases for counter_window.py (06B-3DR; invalid
                measurement data added in 06B-3DR1 -> ERROR). Contains NaN/Infinity: Python json only.
expected.json   exact counts sigscan.sh must print for positive.pcap and negative.pcap, and the
                expected pcapng_stats verdict of every ng-*.pcapng
"""
import json
import os
import struct
import sys

GUEST_MAC = bytes.fromhex("525400c70002")
HOST_MAC = bytes.fromhex("02420000aa01")
OTHER_MAC = bytes.fromhex("02420000bb02")


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


def ipv4(src, dst, proto, payload):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload


def l4(src, dst, proto, hdr, payload):
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    off = 16 if proto == 6 else 6
    return hdr[:off] + struct.pack("!H", c) + hdr[off + 2:] + payload


def tcp(src, sport, dst, dport, payload=b"", flags=0x18):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 64240, 0, 0)
    return ipv4(src, dst, 6, l4(src, dst, 6, hdr, payload))


def udp(src, sport, dst, dport, payload):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ipv4(src, dst, 17, l4(src, dst, 17, hdr, payload))


def dns_query(qname, qid=0x1234):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in qname.rstrip(".").split(".")) + b"\0"
    return q + struct.pack("!HH", 1, 1)


def icmp_echo(src, dst):
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"06b3c-fixture"
    body = body[:2] + struct.pack("!H", csum(body)) + body[4:]
    return ipv4(src, dst, 1, body)


def eth(src_mac, ip_packet, dst_mac=OTHER_MAC, ethertype=0x0800):
    return dst_mac + src_mac + struct.pack("!H", ethertype) + ip_packet


def arp_request(sha, spa, tpa):
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, sha, ip4(spa), b"\0" * 6, ip4(tpa))
    return eth(sha, body, dst_mac=b"\xff" * 6, ethertype=0x0806)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1791300000 + i, 0, len(fr), len(fr)) + fr)


def http_get(path):
    return f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()


positive = [
    # payload signatures from NATed/worker addresses: found only by payload matching
    eth(HOST_MAC, tcp("192.168.177.128", 50000, "1.1.1.1", 443, http_get("/ct01-06b3b-internet-tcp"))),
    eth(HOST_MAC, tcp("192.168.60.2", 50001, "192.168.60.1", 22, http_get("/ct01-06b3b-ssh-host-192.168.60.1"))),
    eth(HOST_MAC, udp("192.168.177.128", 50002, "192.168.177.2", 53, dns_query("ct01-06b3b-probe-mips-1.example"))),
    # probe source port seen after a hypothetical NAT that keeps ports
    eth(HOST_MAC, tcp("192.168.60.2", 41003, "192.168.60.1", 22, flags=0x02)),
    # original guest MAC / address and guest ARP
    eth(GUEST_MAC, icmp_echo("10.200.0.2", "8.8.8.8")),
    arp_request(GUEST_MAC, "10.200.0.2", "10.200.0.1"),
]
negative = [
    eth(HOST_MAC, udp("192.168.177.128", 50003, "192.168.177.2", 53, dns_query("ct01-06b3b-ctl-arm.example"))),
    eth(HOST_MAC, tcp("192.168.60.3", 50004, "192.168.60.2", 8011, http_get("/api/v1/sandbox-worker/healthcheck"))),
    eth(HOST_MAC, tcp("192.168.60.3", 50005, "192.168.60.2", 8011, http_get("/ct01-06b3b-ctl-arm"))),
    eth(HOST_MAC, tcp("192.168.60.3", 50006, "192.168.60.2", 8011, http_get("/ct01-06b3b-managerx"))),
    eth(HOST_MAC, tcp("192.168.60.3", 50007, "192.168.60.2", 8011, http_get("/ct01-06b3c-internet-tcp"))),
    eth(HOST_MAC, tcp("192.168.177.128", 52914, "1.1.1.1", 443, flags=0x02)),
    eth(HOST_MAC, tcp("192.168.60.2", 41021, "192.168.60.1", 22, flags=0x02)),
    eth(HOST_MAC, icmp_echo("10.200.0.6", "8.8.8.8")),
]

# ---------------------------------------------------------------- pcapng drop-statistics fixtures
def pcapng(frames, isb=None, e="<"):
    """SHB + IDB (Ethernet) + one EPB per frame [+ ISB with the given 64-bit options]."""
    def block(btype, body):
        body += b"\0" * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack(e + "II", btype, n) + body + struct.pack(e + "I", n)

    def opt(code, value):
        v = value if isinstance(value, bytes) else struct.pack(e + "Q", value)
        return struct.pack(e + "HH", code, len(v)) + v + b"\0" * (-len(v) % 4)
    out = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack(e + "HHI", 1, 0, 262144))
    for i, fr in enumerate(frames):
        out += block(0x00000006, struct.pack(e + "IIIII", 0, 0, i, len(fr), len(fr)) + fr)
    if isb is not None:
        opts = opt(1, b"Counters provided by dumpcap") + b"".join(opt(c, v) for c, v in isb) + opt(0, b"")
        out += block(0x00000005, struct.pack(e + "III", 0, 0, 99) + opts)
    return out


three = positive[:3]
PCAPNG = {   # name: (bytes, expected verdict of pcapng_stats.drop_verdict, or "ERROR" for PcapngError)
    "ng-drop0.pcapng": (pcapng(three, [(4, 3), (5, 0)]), "PASS"),
    "ng-drop0-bigendian.pcapng": (pcapng(three, [(4, 3), (5, 0)], e=">"), "PASS"),
    "ng-drop3.pcapng": (pcapng(three, [(4, 3), (5, 3)]), "FAIL"),            # ifrecv == stored: only ifdrop fails
    "ng-drop3-recv6.pcapng": (pcapng(three, [(4, 6), (5, 3)]), "FAIL"),      # libpcap-style ifrecv incl. drops
    "ng-osdrop2.pcapng": (pcapng(three, [(4, 3), (5, 0), (7, 2)]), "FAIL"),
    "ng-recv-mismatch.pcapng": (pcapng(three, [(4, 5), (5, 0)]), "FAIL"),
    "ng-no-stats.pcapng": (pcapng(three), "UNVERIFIED"),
    "ng-isb-without-ifdrop.pcapng": (pcapng(three, [(4, 3)]), "UNVERIFIED"),
}
PCAPNG["ng-truncated.pcapng"] = (PCAPNG["ng-drop0.pcapng"][0][:-6], "ERROR")          # cut inside the ISB
PCAPNG["ng-truncated-in-packet.pcapng"] = (PCAPNG["ng-no-stats.pcapng"][0][:-10], "ERROR")  # capture cut mid-packet
PCAPNG["ng-not-pcapng.pcapng"] = (b"\xd4\xc3\xb2\xa1" + b"\0" * 40, "ERROR")

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, "positive.pcap"), positive)
write_pcap(os.path.join(out, "negative.pcap"), negative)
data = open(os.path.join(out, "positive.pcap"), "rb").read()
open(os.path.join(out, "truncated.pcap"), "wb").write(data[:-10])
open(os.path.join(out, "empty.pcap"), "wb").close()
for name, (blob, _) in PCAPNG.items():
    open(os.path.join(out, name), "wb").write(blob)
# ---------------------------------------------------------------- counter-window cases (06B-3DR)
# Read A runs 100.000-100.020, read B 105.000-105.020, guard 0.020 (counter_window.GUARD_S).
# "old" is what the 06B-3B/3D method (window [A.t_end, B.t_start], plain equality) would have said.
RA, RB = {"t_start": 100.000, "t_end": 100.020}, {"t_start": 105.000, "t_end": 105.020}
CLEAN = [(101.0, "drop_public"), (102.0, "drop_public"), (103.0, "drop_public"),
         (101.5, "l2_bad_ethertype"), (104.0, "l2_bad_ethertype")]
D0 = {"drop_public": 3, "l2_bad_ethertype": 2}
CW = [  # name, frames, delta, expected verdict, old-method verdict
    ("clean", CLEAN, D0, "PASS", "PASS"),
    ("edge-start-counted", CLEAN + [(100.010, "l2_bad_ethertype")], {**D0, "l2_bad_ethertype": 3}, "UNVERIFIED", "FAIL"),
    ("edge-start-not-counted", CLEAN + [(99.990, "l2_bad_ethertype")], D0, "UNVERIFIED", "PASS"),
    ("edge-end", CLEAN + [(105.010, "l2_bad_ethertype")], D0, "UNVERIFIED", "PASS"),
    ("guard-zone-before-read-b", CLEAN + [(104.990, "l2_bad_ethertype")], {**D0, "l2_bad_ethertype": 3}, "UNVERIFIED", "PASS"),
    ("real-mismatch", CLEAN, {**D0, "drop_public": 2}, "FAIL", "FAIL"),
    ("real-mismatch-despite-edges", CLEAN + [(100.010, "drop_public")], {**D0, "drop_public": 5}, "FAIL", "FAIL"),
    ("two-errors-cancel", [(100.005, "l2_bad_ethertype"), (102.0, "l2_bad_ethertype"), (104.990, "l2_bad_ethertype"),
                           (101.0, "drop_public")], {"l2_bad_ethertype": 2, "drop_public": 1}, "UNVERIFIED", "PASS"),
    ("outside-frames-ignored", CLEAN + [(99.900, "l2_bad_ethertype"), (105.100, "l2_bad_ethertype")], D0, "PASS", "PASS"),
    ("class-not-compared-at-edge", CLEAN + [(100.010, "arp")], {**D0, "arp_in_ok": 1}, "PASS", "PASS"),
    ("counter-without-frames", CLEAN, {**D0, "drop_spoof": 1}, "FAIL", "FAIL"),
]
NAN, INF = float("nan"), float("inf")
# 06B-3DR1: invalid measurement data -> "ERROR" (never PASS). name, overrides, expected
CW_INVALID = [
    ("read-a-reversed", {"read_before": {"t_start": 100.020, "t_end": 100.000}}),
    ("reads-reversed", {"read_before": RB, "read_after": RA}),
    ("reads-overlap", {"read_after": {"t_start": 100.010, "t_end": 105.020}}),
    ("read-time-nan", {"read_before": {"t_start": NAN, "t_end": 100.020}}),
    ("read-time-infinity", {"read_after": {"t_start": 105.000, "t_end": INF}}),
    ("read-time-missing", {"read_after": {"t_start": 105.000}}),
    ("frame-time-nan", {"extra_frames": [(NAN, "drop_public")]}),
    ("guard-negative", {"guard": -0.001}),
    ("guard-nan", {"guard": NAN}),
    ("guard-infinity", {"guard": INF}),
    ("delta-negative", {"delta": {**D0, "drop_spoof": -1}}),
]
# boundary that IS valid input: reads touching (A.end == B.start) and guard 0. The certain zone is then
# empty, so the case has no frames and no delta; it only shows that the validation accepts equality.
CW_VALID_EDGE = [("reads-touching-guard-zero",
                  {"read_before": {"t_start": 100.000, "t_end": 100.020},
                   "read_after": {"t_start": 100.020, "t_end": 100.040}, "guard": 0.0})]
json.dump({"read_before": RA, "read_after": RB, "classes": ["drop_public", "l2_bad_ethertype", "drop_spoof"],
           "cases": [{"name": n, "frames": [{"t": t, "cls": c} for t, c in fr], "delta": d,
                      "expected": e, "old_method": o} for n, fr, d, e, o in CW]
                    + [{"name": n, "frames": [{"t": t, "cls": c} for t, c in CLEAN + ov.get("extra_frames", [])],
                        "delta": ov.get("delta", D0), "expected": "ERROR", "old_method": None,
                        **{k: v for k, v in ov.items() if k in ("read_before", "read_after", "guard")}}
                       for n, ov in CW_INVALID]
                    + [{"name": n, "frames": [], "delta": {}, "expected": "PASS", "old_method": None,
                        **{k: v for k, v in ov.items() if k in ("read_before", "read_after", "guard")}}
                       for n, ov in CW_VALID_EDGE]},
          open(os.path.join(out, "counter-window-cases.json"), "w"), indent=1)
json.dump({
    "pcapng_verdicts": {name: verdict for name, (_, verdict) in PCAPNG.items()},
    "positive.pcap": {"frames": 6, "guest_l2l3": 2, "probe_sport": 1, "probe_qname": 1, "probe_url": 2,
                      "control_qname": 0},
    "negative.pcap": {"frames": 8, "guest_l2l3": 0, "probe_sport": 0, "probe_qname": 0, "probe_url": 0,
                      "control_qname": 2},   # control DNS query + /ct01-06b3b-ctl-arm URL
}, open(os.path.join(out, "expected.json"), "w"), indent=1)
