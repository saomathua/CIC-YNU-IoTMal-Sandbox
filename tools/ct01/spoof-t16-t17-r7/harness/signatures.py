"""06B-4B — single registry of probe ports, ICMP sizes, spoofed MAC/IP values and the host-side
capture/alert filters derived from them. Offline module: nothing here sends a packet.

Every port, size and address that a later L2/ARP/IPv6/T20 probe may use is listed ONCE here; the
capture filters, the leak alerts, the post-run scanner (sigscan_l2.py) and the plan
(docs/ct01-remaining-tests-plan.md, "Danh sách cổng và chữ ký") are all derived from / checked against
this table. No probe is defined here (06B-4B prepares the measurement only).

    python3 signatures.py --shell     shell assignments used by run-06b3b.sh
    python3 signatures.py --check     validate the registry (exit 1 on any problem)
"""
import ipaddress
import json
import sys

GUEST_MAC = "52:54:00:c7:00:02"
GUEST_IP = "10.200.0.2"
WORKER_GUEST_IP = "10.200.0.1"
GUEST_NET = "10.200.0.0/30"
# EUI-64 link-local of GUEST_MAC (U/L bit flipped): what the guest uses as IPv6 source on tap0.
GUEST_LL6 = "fe80::5054:ff:fec7:2"

# MAC chosen for the T16 MAC-change probe. Only THIS value is recognised as "guest with a spoofed
# MAC". A guest that spoofs TAP_MAC (the worker's random tap0 MAC) cannot be told apart from the
# worker's own frames in the tap0 pcap (no direction flags): that case is NOT covered (D5).
SPOOF_MACS = ("52:54:00:de:ad:01",)

# Spoofed IPv4 sources of T17 (the plan's P1..P5). 10.200.0.1 is reserved for P3, which is postponed.
SPOOF_SRC_IPS = {"10.200.0.5": "T17-P1/P4", "192.168.60.10": "T17-P2/P5", "10.200.0.1": "T17-P3 (hoãn)"}
# A spoofed source that also appears legitimately on sandboxnet: only matched together with a probe
# port or a probe ICMP size, never alone.
SPOOF_SRC_SHARED = ("192.168.60.10",)

# Legacy IPv4 matrix (06B-3B): source port 41000 + n, scanned as a range.
LEGACY_PORT_RANGE = (41000, 41020)
# New probes: exact ports, all inside NEW_PORT_RANGE. Reserved even when the probe is postponed.
# 06B-4B: the plan's 42000-42299 lies inside the Linux ephemeral range (32768-60999 on host, worker,
# ctl and manager by default) and the 06B-3G bridge pcap really contains a control connection
# 192.168.60.3:42172 -> manager:8011, i.e. a port-only signature there is a false positive.
# New ports are therefore below 32768 (0 frames on 31000-31299 in every 06B-3G host pcap, no host
# listener there). Old plan number -> new number: 420xx -> 310xx, 4217x -> 3117x, 4220x -> 3120x.
EPHEMERAL_RANGE = (32768, 60999)
NEW_PORT_RANGE = (31000, 31299)
PROBE_PORTS = {
    "T13-I3": 31013,          # curl -6 to the EUI-64 address of TAP_MAC (only NS expected on the wire)
    "T16-M1": 31016,          # service link with the spoofed MAC
    "T20-N3": 31020,          # UDP worker -> guest
    "T17-P1": 31171,          # src 10.200.0.5 -> 10.200.0.1:8011
    "T17-P2": 31172,          # src 192.168.60.10 -> 10.200.0.1:8011
    "T17-P3": 31173,          # src 10.200.0.1 (POSTPONED, port reserved)
    "T17-P4": 31174,          # src 10.200.0.5 -> 1.1.1.1:443
    "T20-N2-22": 31201,       # worker -> guest tcp/22, fixed source port
    "T20-N2-80": 31202,       # worker -> guest tcp/80, fixed source port
    # B1 (first batch of the missing probes): guest -> ... with a fixed source port
    "T06-L2": 31060,          # guest -> an unused LAN IP, tcp/80 (rule check)
    "T11-P22": 31110,         # guest -> 10.200.0.1:22
    "T11-P80": 31111,         # guest -> 10.200.0.1:80
}
# ICMP payload sizes (ping -s). On the wire: IPv4 total length = size + 28, IPv6 payload length = size + 8.
ICMP4_SIZES = {"T12-B1": 1201, "T12-B2": 1202, "T12-B4": 1204, "T14-A1": 1401, "T14-A2": 1402,
               "T14-A3": 1403,
               "T17-P5": 1405,    # R2/S3: IPv4 total length 1433 (< MTU 1500: one unfragmented datagram per echo); was 1705 (total 1733 -> two fragments at MTU 1500)
               "T06-B": 1406,     # B1: guest ping to the LAN DNS (192.168.177.2): IPv4 total length 1434 (< MTU 1500: one unfragmented datagram per echo)
               "T11-C": 1111}     # B1: guest ping to 10.200.0.1: IPv4 total length 1139
ICMP6_SIZES = {"T13-I1": 1301, "T13-I2": 1302}
QNAME_PREFIX = "ct01-06b4-"     # nslookup names of new probes: ct01-06b4-<test>-<arch>-<n>

# D7: ens33 is captured WITHOUT a filter, bounded. Reaching the packet limit makes tcpdump exit, which
# the capture watcher reports as a dead capture (the probes stop; never a silent truncation).
ENS33_SNAPLEN = 512
ENS33_MAX_PACKETS = 200000


def ip4_lens():
    return sorted(s + 28 for s in ICMP4_SIZES.values())


def ip6_plens():
    return sorted(s + 8 for s in ICMP6_SIZES.values())


def _hex_ip(ip):
    return "0x%08x" % int(ipaddress.IPv4Address(ip))


def _mac_words(mac):
    b = bytes.fromhex(mac.replace(":", ""))
    return "0x" + b[:4].hex(), "0x" + b[4:].hex()


def _ports_expr(ports):
    return " or ".join(f"port {p}" for p in sorted(ports))


def _src_ports_expr(ports):
    # a shared spoofed source (a real host) is only a signature with the probe's own SOURCE port
    return " or ".join(f"src port {p}" for p in sorted(ports))


def arp_sha_expr(mac):
    hi, lo = _mac_words(mac)
    return f"(arp and arp[8:4] = {hi} and arp[12:2] = {lo})"


def alert_any_filter():
    """Leak alert on `-i any` (link type LINUX_SLL2: `ether host` does not compile there, so only
    network-layer signatures). Every clause is specific to the guest or to a spoofed value."""
    parts = [f"net {GUEST_NET}"]                                   # IPv4 and ARP spa/tpa of the guest net
    parts += [f"(ip6 and host {GUEST_LL6})"]
    parts += [arp_sha_expr(m) for m in (GUEST_MAC,) + SPOOF_MACS]
    # pcap-filter: `and` and `or` have EQUAL precedence (left to right), so every group is bracketed.
    parts += [f"(src host {ip} and (((tcp or udp) and ({_src_ports_expr(PROBE_PORTS.values())})) or "
              f"(icmp and ({' or '.join(f'ip[2:2] = {n}' for n in ip4_lens())}))))" for ip in SPOOF_SRC_SHARED]
    parts += [f"(icmp and ({' or '.join(f'ip[2:2] = {n}' for n in ip4_lens())}))"]
    parts += [f"(icmp6 and ({' or '.join(f'ip6[4:2] = {n}' for n in ip6_plens())}))"]
    return " or ".join(parts)


def alert_eth_filter():
    """Leak alert on the worker's host-side veth (Ethernet): MAC signatures + everything above.
    The veth is the only way out of the worker netns (checked by the harness), so a frame with the
    guest or a spoofed MAC that leaves the worker crosses it."""
    macs = " or ".join(f"ether host {m}" for m in (GUEST_MAC,) + SPOOF_MACS)
    return f"{macs} or {alert_any_filter()}"


def check():
    """Registry consistency; returns a list of problems (empty = OK)."""
    p = []
    lo, hi = NEW_PORT_RANGE
    for k, v in PROBE_PORTS.items():
        if not lo <= v <= hi:
            p.append(f"{k}: port {v} outside {lo}-{hi}")
        if LEGACY_PORT_RANGE[0] <= v <= LEGACY_PORT_RANGE[1]:
            p.append(f"{k}: port {v} inside the legacy range")
        if EPHEMERAL_RANGE[0] <= v <= EPHEMERAL_RANGE[1]:
            p.append(f"{k}: port {v} inside the Linux ephemeral range {EPHEMERAL_RANGE}")
    if len(set(PROBE_PORTS.values())) != len(PROBE_PORTS):
        p.append("duplicate probe port")
    sizes = list(ICMP4_SIZES.values()) + list(ICMP6_SIZES.values())
    if len(set(sizes)) != len(sizes):
        p.append("duplicate ICMP size")
    for m in SPOOF_MACS:
        if m == GUEST_MAC:
            p.append("spoof MAC equals guest MAC")
        if int(m.split(":")[0], 16) & 1:
            p.append(f"spoof MAC {m} is a multicast address")
    for ip in SPOOF_SRC_IPS:
        if ip == GUEST_IP:
            p.append("spoofed source equals the guest IP")
    if ipaddress.IPv6Address(GUEST_LL6) != _eui64_ll(GUEST_MAC):
        p.append("GUEST_LL6 is not the EUI-64 address of GUEST_MAC")
    return p


def _eui64_ll(mac):
    b = bytearray(bytes.fromhex(mac.replace(":", "")))
    b[0] ^= 0x02
    return ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + bytes(b[:3]) + b"\xff\xfe" + bytes(b[3:]))


def eui64_ll(mac):
    """Link-local address the given MAC would have (used for T13-I2/I3 towards TAP_MAC)."""
    return str(_eui64_ll(mac))


def registry():
    return {"guest_mac": GUEST_MAC, "spoof_macs": list(SPOOF_MACS), "guest_net": GUEST_NET,
            "guest_ll6": GUEST_LL6, "spoof_src_ips": SPOOF_SRC_IPS, "legacy_port_range": LEGACY_PORT_RANGE,
            "new_port_range": NEW_PORT_RANGE, "probe_ports": PROBE_PORTS, "icmp4_sizes": ICMP4_SIZES,
            "icmp6_sizes": ICMP6_SIZES, "qname_prefix": QNAME_PREFIX, "ens33_snaplen": ENS33_SNAPLEN,
            "ens33_max_packets": ENS33_MAX_PACKETS}


if __name__ == "__main__":
    if sys.argv[1:] == ["--shell"]:
        def q(s):
            return "'" + s.replace("'", "'\\''") + "'"
        print(f"SIG_ALERT_ANY={q(alert_any_filter())}")
        print(f"SIG_ALERT_ETH={q(alert_eth_filter())}")
        print(f"SIG_ENS33_SNAPLEN={ENS33_SNAPLEN}")
        print(f"SIG_ENS33_MAX_PACKETS={ENS33_MAX_PACKETS}")
        print(f"SIG_SPOOF_MACS={q(' '.join(SPOOF_MACS))}")
    elif sys.argv[1:] == ["--check"]:
        probs = check()
        print("\n".join(probs) if probs else "registry OK")
        sys.exit(1 if probs else 0)
    elif sys.argv[1:] == ["--json"]:
        print(json.dumps(registry(), indent=1, sort_keys=True))
    else:
        sys.exit("usage: signatures.py --shell | --check | --json")
