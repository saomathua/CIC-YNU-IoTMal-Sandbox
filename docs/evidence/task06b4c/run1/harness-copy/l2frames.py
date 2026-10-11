"""06B-4B — tap0 frame decoder and classifier for the L2 / ARP / IPv6 measurements. Offline module.

Reads pcap and pcapng (Ethernet only) with the standard library, so it runs on the host as well as in
the worker container, and decodes Ethernet, ARP, IPv4 (+TCP/UDP ports), IPv6 (+ICMPv6 type).
Any problem reading the file raises FrameReadError: a read error is never "0 frames".

Direction of a frame on tap0, by source MAC (the pcapng written by dumpcap carries no direction flag:
0/97 and 0/125 EPB flags in the 06B-3G pcaps):
    guest            src == GUEST_MAC
    guest_spoof_mac  src in the CHOSEN spoof MACs (signatures.SPOOF_MACS)          -> l2_bad_mac
    worker           src == TAP_MAC (the worker's own tap0)
    unknown_src      anything else                                                  -> unmapped
A guest that spoofs TAP_MAC is classified as "worker": that case is NOT covered and is never claimed.

Class of a guest frame, in the order of guest.nft and the kernel receive path:
    netdev ingress   ethertype not IPv4/ARP          -> l2_bad_ethertype (IPv6 recognised, detail kept)
                     VLAN 0x8100/0x88a8               -> unmapped (nft `ether type` vs. VLAN untagging
                                                         before the ingress hook: not verified)
    ARP              arp_rcv drops BEFORE NF_ARP_IN: pkt_type OTHERHOST (dst MAC not TAP_MAC, not
                     broadcast/multicast), header shorter than 28 bytes, hlen != 6, plen != 4
                                                      -> arp_not_hooked   (no counter)
                     exact allow rule                 -> arp_in_ok
                     any other ARP                    -> arp_in_drop
    IPv4             ip_rcv drops BEFORE PRE_ROUTING: OTHERHOST, bad version/IHL/total length/header
                     checksum                          -> ip_not_hooked    (no counter)
                     then the inet prerouting order    -> drop_spoof, allow_svc, drop_worker_other,
                                                         drop_private, drop_bcast_mcast, drop_public
Worker frames: ARP 10.200.0.1 -> 10.200.0.2 request/reply -> arp_out_ok; TCP 10.200.0.1:8011 ->
10.200.0.2 -> allow_out_svc (ct state cannot be seen in a pcap); anything else -> worker_unexpected.
arp_out_drop and drop_out can never be seen on tap0 (dropped before the capture point).

[Kernel]: the arp_rcv / ip_rcv drop points and the capture point after the output hooks are read from
upstream Linux v6.8 source; they are NOT verified on the host kernel 6.8.0-146.
"""
import ipaddress
import struct

import counter_window
import signatures as S

ETH_IPV4, ETH_ARP, ETH_IPV6 = 0x0800, 0x0806, 0x86DD
ETH_VLAN = (0x8100, 0x88A8)
BROADCAST = "ff:ff:ff:ff:ff:ff"
ARP_HDR_LEN = 28          # arp_hdr_len(dev) for Ethernet/IPv4: 8 + 2 * (6 + 4)
SVC_PORT = 8011

# Classes that have an nft counter, and pseudo-classes that do not.
COUNTER_CLASSES = ("allow_svc", "drop_spoof", "drop_non_ipv4", "drop_worker_other", "drop_private",
                   "drop_bcast_mcast", "drop_public", "l2_bad_ethertype", "l2_bad_mac",
                   "arp_in_ok", "arp_in_drop", "arp_out_ok", "allow_out_svc")
NO_COUNTER = ("arp_not_hooked", "ip_not_hooked", "unmapped", "worker_unexpected")
# Counters that exist in guest.nft but can never be matched by a frame on tap0.
UNOBSERVABLE = {"arp_out_drop": "dropped at NF_ARP_OUT before the tap0 capture point [Kernel]",
                "drop_out": "dropped at the inet output hook before the tap0 capture point [Kernel]",
                "drop_input_backstop": "input hook after prerouting: no frame-level mapping",
                "drop_forward": "forward hook after prerouting: no frame-level mapping"}
PRIVATE = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                                             "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")]
MCAST = ipaddress.ip_network("224.0.0.0/4")


class FrameReadError(Exception):
    """The capture file cannot be read completely: never treated as an empty capture."""


# ------------------------------------------------------------------ readers
def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def read_frames(path):
    """[(t, bytes)] for every packet of a pcap/pcapng file with Ethernet link type."""
    return [(t, raw) for t, raw, _orig in read_records(path)]


def read_records(path):
    """[(t, captured bytes, original length on the wire)]. 06B-4BR: the original length is kept so that
    a frame cut by the capture's snaplen (captured < original) is told apart from a damaged file
    (captured > original, or a record/block running past the end: FrameReadError) and from a packet
    that is malformed on the wire (complete capture whose headers do not add up)."""
    try:
        data = open(path, "rb").read()
    except OSError as e:
        raise FrameReadError(f"cannot read {path}: {e}") from e
    if len(data) < 4:
        raise FrameReadError(f"{path}: empty or not a capture file ({len(data)} bytes)")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(data, path)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _read_pcap(data, path)
    raise FrameReadError(f"{path}: unknown capture format (magic {magic.hex()})")


def _read_pcap(data, path):
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    else:
        e = ">"
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24:
        raise FrameReadError(f"{path}: truncated pcap header")
    linktype = struct.unpack_from(e + "I", data, 20)[0] & 0x0FFFFFFF
    if linktype != 1:
        raise FrameReadError(f"{path}: link type {linktype} is not Ethernet")
    out, i = [], 24
    while i < len(data):
        if i + 16 > len(data):
            raise FrameReadError(f"{path}: truncated record header at offset {i}")
        sec, frac, incl, orig = struct.unpack_from(e + "IIII", data, i)
        if incl > orig:
            raise FrameReadError(f"{path}: captured length {incl} > original length {orig} at offset {i}")
        if i + 16 + incl > len(data):
            raise FrameReadError(f"{path}: truncated packet at offset {i}")
        out.append((sec + frac / (1e9 if nano else 1e6), data[i + 16:i + 16 + incl], orig))
        i += 16 + incl
    return out


def _read_pcapng(data, path):
    out, i, e, ifaces = [], 0, "<", []
    while i < len(data):
        if i + 12 > len(data):
            raise FrameReadError(f"{path}: truncated block header at offset {i}")
        if data[i:i + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[i + 8:i + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                e = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                e = ">"
            else:
                raise FrameReadError(f"{path}: bad byte-order magic at offset {i}")
            ifaces = []   # interface ids are per section
        btype, blen = struct.unpack_from(e + "II", data, i)
        if blen < 12 or blen % 4 or i + blen > len(data):
            raise FrameReadError(f"{path}: bad or truncated block (type {btype:#x}, length {blen}) at offset {i}")
        if struct.unpack_from(e + "I", data, i + blen - 4)[0] != blen:
            raise FrameReadError(f"{path}: block length trailer mismatch at offset {i}")
        body = data[i + 8:i + blen - 4]
        if btype == 1:                                   # interface description
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            div = 10 ** 6                                # units per second (default microseconds)
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(e + "HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    div = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                o += 4 + ((ln + 3) // 4) * 4
            ifaces.append((linktype, div))
        elif btype == 6:                                 # enhanced packet
            if len(body) < 20:
                raise FrameReadError(f"{path}: truncated EPB at offset {i}")
            ifid, hi, lo, cap, orig = struct.unpack_from(e + "IIIII", body, 0)
            if cap > orig:
                raise FrameReadError(f"{path}: EPB captured length {cap} > original length {orig} at offset {i}")
            if ifid >= len(ifaces):
                raise FrameReadError(f"{path}: EPB for undefined interface {ifid} at offset {i}")
            linktype, div = ifaces[ifid]
            if linktype != 1:
                raise FrameReadError(f"{path}: interface {ifid} link type {linktype} is not Ethernet")
            if 20 + cap > len(body):
                raise FrameReadError(f"{path}: EPB captured length beyond block at offset {i}")
            units = (hi << 32) | lo
            # integer split first: a float cannot hold 1.79e18 ns exactly (error would be ~0.2 us)
            out.append((units // div + (units % div) / div, body[20:20 + cap], orig))
        elif btype == 3:                                 # simple packet: no timestamp
            raise FrameReadError(f"{path}: simple packet block without timestamp at offset {i}")
        i += blen
    return out


# ------------------------------------------------------------------ decoder
def _csum_ok(hdr):
    if len(hdr) % 2:
        return False
    s = sum(struct.unpack(f"!{len(hdr) // 2}H", hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def decode(t, raw, orig_len=None):
    """One frame -> dict. Never raises for malformed content: problems are recorded in `err`/`why`.
    06B-4BR: header fields are parsed whenever the header BYTES are present (`hdr_ok`), independently of
    validity. `valid` stays strict (complete on the wire AND in the capture, correct checksum/lengths):
    the tap0 classifier uses `valid`; the host-side scanner uses `hdr_ok` and reports what it could not
    see. `truncated` is True only when the capture holds fewer bytes than the original frame (snaplen)."""
    orig = len(raw) if orig_len is None else orig_len
    f = {"t": t, "len": len(raw), "caplen": len(raw), "orig_len": orig, "truncated": orig > len(raw), "err": None}
    if len(raw) < 14:
        f.update(dst=None, src=None, etype=None,
                 err="Ethernet header cut by snaplen" if f["truncated"] else "frame shorter than an Ethernet header")
        return f
    f["dst"], f["src"] = _mac(raw[0:6]), _mac(raw[6:12])
    et = struct.unpack_from("!H", raw, 12)[0]
    f["etype"] = et
    p = raw[14:]
    wire = orig - 14                     # bytes after the Ethernet header on the wire
    if et == ETH_ARP:
        if len(p) < 8:
            f["arp"] = {"short": True, "len": len(p), "cut": wire >= 8}
            return f
        htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", p, 0)
        a = {"htype": htype, "ptype": ptype, "hlen": hlen, "plen": plen, "op": op, "len": len(p), "short": False,
             "cut": len(p) < ARP_HDR_LEN <= wire}
        if hlen == 6 and plen == 4 and len(p) >= ARP_HDR_LEN:
            a.update(sha=_mac(p[8:14]), spa=str(ipaddress.IPv4Address(p[14:18])),
                     tha=_mac(p[18:24]), tpa=str(ipaddress.IPv4Address(p[24:28])))
        f["arp"] = a
    elif et == ETH_IPV4:
        ip = {"valid": False, "hdr_ok": False}
        f["ip"] = ip
        if len(p) < 20:
            ip["why"] = "IPv4 header cut by snaplen" if wire >= 20 else "shorter than an IPv4 header"
            ip["hdr_cut"] = wire >= 20
            return f
        ver, ihl = p[0] >> 4, (p[0] & 0x0F) * 4
        if ver != 4 or ihl < 20:
            ip["why"] = f"bad version/IHL ({ver}, {ihl})"
            return f
        if len(p) < ihl:
            ip["why"] = "IPv4 options cut by snaplen" if wire >= ihl else "IPv4 header longer than the frame"
            ip["hdr_cut"] = wire >= ihl
            return f
        tot = struct.unpack_from("!H", p, 2)[0]
        fragoff = struct.unpack_from("!H", p, 6)[0] & 0x1FFF
        csum_ok = _csum_ok(p[:ihl])
        ip.update(hdr_ok=True, src=str(ipaddress.IPv4Address(p[12:16])), dst=str(ipaddress.IPv4Address(p[16:20])),
                  proto=p[9], tot_len=tot, frag_offset=fragoff, sport=None, dport=None, csum_ok=csum_ok,
                  payload_complete=tot <= len(p))
        l4 = p[ihl:min(tot, len(p))] if tot >= ihl else b""
        if fragoff == 0 and p[9] in (6, 17):
            if len(l4) >= 4:
                ip["sport"], ip["dport"] = struct.unpack_from("!HH", l4, 0)
            else:
                ip["ports_missing"] = True
                ip["ports_cut"] = tot >= ihl + 4 and wire >= ihl + 4
        ip["payload"] = bytes(l4)
        if tot < ihl:
            ip["why"] = f"bad total length {tot} < header {ihl}"
        elif tot > wire:
            ip["why"] = f"total length {tot} beyond the frame on the wire ({wire})"
        elif tot > len(p):
            ip["why"] = f"payload cut by snaplen (total length {tot}, captured {len(p)})"
        elif not csum_ok:
            ip["why"] = "bad header checksum"
        else:
            ip["valid"] = True
    elif et == ETH_IPV6:
        v6 = {"valid": False, "hdr_ok": False}
        f["ip6"] = v6
        if len(p) < 40 or p[0] >> 4 != 6:
            cut = len(p) < 40 <= wire
            v6["why"] = "IPv6 header cut by snaplen" if cut else "shorter than an IPv6 header or version != 6"
            v6["hdr_cut"] = cut
            return f
        plen, nh = struct.unpack_from("!HB", p, 4)
        v6.update(hdr_ok=True, plen=plen, nh=nh, src=str(ipaddress.IPv6Address(p[8:24])),
                  dst=str(ipaddress.IPv6Address(p[24:40])), icmp6_type=None, payload_complete=40 + plen <= len(p))
        if nh == 58 and len(p) >= 41:
            v6["icmp6_type"] = p[40]
        if 40 + plen > wire:
            v6["why"] = "payload length beyond the frame on the wire"
        elif 40 + plen > len(p):
            v6["why"] = "payload cut by snaplen"
        else:
            v6["valid"] = True
    elif et in ETH_VLAN:
        f["vlan"] = struct.unpack_from("!H", p, 0)[0] & 0x0FFF if len(p) >= 2 else None
    return f


# ------------------------------------------------------------------ classifier
def _norm_mac(m):
    if not isinstance(m, str):
        raise ValueError(f"MAC expected, got {m!r}")
    m = m.strip().lower()
    b = bytes.fromhex(m.replace(":", ""))
    if len(b) != 6:
        raise ValueError(f"not a MAC address: {m!r}")
    return _mac(b)


def _hooked_l2_dst(dst, tap_mac):
    """pkt_type != OTHERHOST: our MAC, broadcast or a multicast (group bit) address."""
    return dst == tap_mac or dst == BROADCAST or int(dst[:2], 16) & 1 == 1


def classify(f, tap_mac, spoof_macs=S.SPOOF_MACS):
    """-> (direction, cls, reason). `tap_mac` is mandatory: without it the worker's frames cannot be
    told apart from unexplained ones."""
    tap_mac = _norm_mac(tap_mac)
    guest = _norm_mac(S.GUEST_MAC)
    spoof = {_norm_mac(m) for m in spoof_macs}
    if tap_mac == guest or tap_mac in spoof:
        raise ValueError("TAP_MAC must differ from the guest MAC and the chosen spoof MACs")
    if f.get("src") is None:
        return "unknown_src", "unmapped", f.get("err") or "no source MAC"
    src = f["src"]
    if src in spoof:
        return "guest_spoof_mac", "l2_bad_mac", f"source MAC {src} is the chosen spoof MAC"
    if src == tap_mac:
        if f.get("truncated"):
            return "worker", "unmapped", "frame cut by snaplen: worker frame not verifiable"
        return ("worker",) + _classify_worker(f)
    if src != guest:
        return "unknown_src", "unmapped", f"source MAC {src} is neither the guest, a chosen spoof MAC nor TAP_MAC"
    et = f["etype"]
    if et in ETH_VLAN:
        return "guest", "unmapped", "VLAN-tagged frame: nft ether type vs. VLAN untagging not verified"
    if et not in (ETH_IPV4, ETH_ARP):
        why = "IPv6" if et == ETH_IPV6 else f"ethertype {et:#06x}"
        return "guest", "l2_bad_ethertype", why
    # 06B-4BR: tap0 is captured in full; a frame cut by snaplen cannot be checked against the ARP/IPv4
    # rules (lengths, checksum, fields): never guessed, never counted under a counter class.
    if f.get("truncated"):
        return "guest", "unmapped", "frame cut by snaplen: ARP/IPv4 checks not verifiable"
    if et == ETH_ARP:
        return ("guest",) + _classify_arp_in(f, tap_mac)
    return ("guest",) + _classify_ip_in(f, tap_mac)


def _classify_arp_in(f, tap_mac):
    a = f.get("arp") or {"short": True, "len": 0}
    if not _hooked_l2_dst(f["dst"], tap_mac):
        return "arp_not_hooked", f"destination MAC {f['dst']} is not TAP_MAC, broadcast or multicast (OTHERHOST)"
    if a["short"] or a["len"] < ARP_HDR_LEN:
        return "arp_not_hooked", f"ARP payload {a['len']} bytes < arp_hdr_len {ARP_HDR_LEN}"
    if a["hlen"] != 6 or a["plen"] != 4:
        return "arp_not_hooked", f"hlen {a['hlen']} / plen {a['plen']} (need 6 / 4)"
    ok = (a["htype"] == 1 and a["ptype"] == ETH_IPV4 and a["sha"] == _norm_mac(S.GUEST_MAC)
          and a["spa"] == S.GUEST_IP and a["tpa"] == S.WORKER_GUEST_IP and a["op"] in (1, 2))
    if ok:
        return "arp_in_ok", "request/reply guest -> 10.200.0.1"
    return "arp_in_drop", (f"op {a['op']} htype {a['htype']} ptype {a['ptype']:#06x} sha {a['sha']} "
                           f"spa {a['spa']} tpa {a['tpa']}")


def _classify_ip_in(f, tap_mac):
    ip = f.get("ip") or {"valid": False, "why": "no IPv4 header"}
    if not _hooked_l2_dst(f["dst"], tap_mac):
        return "ip_not_hooked", f"destination MAC {f['dst']} is OTHERHOST"
    if not ip["valid"]:
        return "ip_not_hooked", ip.get("why", "invalid IPv4 header")
    src, dst = ip["src"], ipaddress.IPv4Address(ip["dst"])
    if src != S.GUEST_IP:
        return "drop_spoof", f"source {src}"
    if str(dst) == S.WORKER_GUEST_IP:
        if ip["proto"] == 6 and ip["dport"] == SVC_PORT:
            return "allow_svc", "tcp 10.200.0.1:8011"
        return "drop_worker_other", f"proto {ip['proto']} dport {ip['dport']}"
    if any(dst in n for n in PRIVATE):
        return "drop_private", str(dst)
    if dst in MCAST or str(dst) == "255.255.255.255":
        return "drop_bcast_mcast", str(dst)
    return "drop_public", str(dst)


def _classify_worker(f):
    et = f["etype"]
    if et == ETH_ARP:
        a = f.get("arp") or {}
        if (not a.get("short") and a.get("spa") == S.WORKER_GUEST_IP and a.get("tpa") == S.GUEST_IP
                and a.get("op") in (1, 2)):
            return "arp_out_ok", "ARP 10.200.0.1 -> 10.200.0.2"
        return "worker_unexpected", "worker ARP outside the allow rule (should have been dropped)"
    if et == ETH_IPV4:
        ip = f.get("ip") or {}
        if (ip.get("valid") and ip["src"] == S.WORKER_GUEST_IP and ip["dst"] == S.GUEST_IP and ip["proto"] == 6
                and ip.get("sport") == SVC_PORT):
            return "allow_out_svc", "tcp 10.200.0.1:8011 -> guest (ct state not visible in a pcap)"
        return "worker_unexpected", "worker IPv4 outside the allow rule"
    return "worker_unexpected", f"worker ethertype {et:#06x}" if et is not None else "worker frame without ethertype"


def classified_frames(path, tap_mac, spoof_macs=S.SPOOF_MACS):
    """Read + decode + classify a capture file. Raises FrameReadError on any read problem."""
    out = []
    for t, raw, orig in read_records(path):
        f = decode(t, raw, orig)
        d, cls, why = classify(f, tap_mac, spoof_macs)
        f.update(direction=d, cls=cls, reason=why)
        out.append(f)
    return out


# ------------------------------------------------------------------ strict reconciliation
def strict_delta(read_a, read_b, counters):
    """Deltas of exactly `counters`. Returns (delta, None) or (None, reason). A counter missing in
    either read, a non-integer value, or a counter that went DOWN is an error, never 0."""
    va, vb = (read_a or {}).get("values"), (read_b or {}).get("values")
    if not isinstance(va, dict) or not isinstance(vb, dict):
        return None, "counter values missing in a read"
    missing = sorted({k for k in counters if k not in va} | {k for k in counters if k not in vb})
    if missing:
        return None, f"counter(s) missing in a read: {missing} (a missing counter is not 0)"
    delta = {}
    for k in counters:
        a, b = va[k], vb[k]
        for v in (a, b):
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                return None, f"counter {k} is not a non-negative integer: {v!r}"
        if b < a:
            return None, f"counter {k} decreased ({a} -> {b})"
        delta[k] = b - a
    return delta, None


def reconcile_l2(frames, read_a, read_b, compared, guard=counter_window.GUARD_S):
    """Counter/pcap reconciliation for the new measurements.
    1. strict deltas (no default 0) -> ERROR on missing data;
    2. counter_window.reconcile for the compared counter classes (zones, FAIL/UNVERIFIED/PASS);
    3. any frame of a class WITHOUT a counter (not hooked, unmapped, unexpected worker frame) inside
       the window makes the result at best UNVERIFIED, with every such frame listed."""
    bad = [k for k in compared if k not in COUNTER_CLASSES]
    if bad:
        return {"verdict": "ERROR", "error": f"not a frame-mapped counter class: {bad}", "per_class": {},
                "no_counter_frames": [], "guard_s": guard}
    delta, err = strict_delta(read_a, read_b, compared)
    if err:
        return {"verdict": "ERROR", "error": err, "per_class": {}, "no_counter_frames": [], "guard_s": guard}
    base = counter_window.reconcile(frames, read_a, read_b, delta, list(compared), guard)
    if base["verdict"] == "ERROR":
        base["no_counter_frames"] = []
        return base
    extra = []
    for fr in frames:
        if fr.get("cls") in NO_COUNTER:
            z = counter_window.zone(fr["t"], read_a, read_b, guard)
            if z != "outside":
                extra.append({"t": fr["t"], "cls": fr["cls"], "zone": z, "reason": fr.get("reason")})
    base["no_counter_frames"] = extra
    if base["verdict"] == "PASS" and extra:
        base["verdict"] = "UNVERIFIED"
        base["unverified_reason"] = "frames without a counter mapping inside the window"
    return base


# ------------------------------------------------------------------ verdict label (D6)
CONTROL_KINDS = ("live", "rule_check")


def probe_verdict_l2(checks, recon, expected_class, control_kind, control_alive=None, tool_missing=False):
    """counter_window.probe_verdict + the D6 label. control_kind:
       live        a live control on the same IP/protocol/port exists; control_alive must be a bool
       rule_check  no live control exists; control_alive must be None. A pass is reported as
                   "ĐẠT (kiểm quy tắc)": the rule matched and dropped at the right place, nothing is
                   claimed about reachability of a service.
    The precedence FAIL > LỖI PHÉP ĐO > CHƯA KIỂM CHỨNG > ĐẠT is unchanged."""
    if control_kind == "live":
        if not isinstance(control_alive, bool):
            raise ValueError("a live-control probe needs control_alive True/False")
        text, ok = counter_window.probe_verdict(checks, recon, expected_class, tool_missing, control_alive)
    elif control_kind == "rule_check":
        if control_alive is not None:
            raise ValueError("a rule-check probe has no live control")
        text, ok = counter_window.probe_verdict(checks, recon, expected_class, tool_missing, True)
        if ok:
            return "ĐẠT (kiểm quy tắc)", True
    else:
        raise ValueError(f"control_kind must be one of {CONTROL_KINDS}")
    # counter_window words every UNVERIFIED reconciliation as an edge effect; name the real cause.
    if text == "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)" and recon.get("no_counter_frames"):
        edges = any(v.get("status") == "UNVERIFIED" for v in recon.get("per_class", {}).values())
        text = ("CHƯA KIỂM CHỨNG (khung không có bộ đếm trong cửa sổ"
                + ("; gói ở biên cửa sổ bộ đếm" if edges else "") + ")")
    return text, ok
