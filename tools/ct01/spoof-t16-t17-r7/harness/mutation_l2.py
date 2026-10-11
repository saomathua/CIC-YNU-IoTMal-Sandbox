#!/usr/bin/env python3
"""06B-4B — mutation test of the NEW parts (signatures.py, l2frames.py, guest_state.py, sigscan_l2.py,
the 06B-4B lines of run-06b3b.sh). Offline; each mutant runs in its own mktemp copy.

    python3 mutation_l2.py [--only ID,...]

Each mutation changes one behaviour (one or more exact text replacements; every `old` must occur
exactly once) and names the self-test that must catch it. Classification:
    DETECTED            the targeted test failed
    DETECTED-ELSEWHERE  only other tests failed (the targeted test did not isolate the change)
    MISSED              every test still passed
    INVALID             a replacement text was not found exactly once (mutant not built)
    ERROR               the self-test did not produce a result (crash/import error/timeout)
Baseline (no mutation) must pass every test first. Expected: every behavioural mutation DETECTED;
the two controls INVALID and ERROR. The harness files are hashed before and after the run.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("signatures.py", "l2frames.py", "guest_state.py", "sigscan_l2.py", "counter_window.py",
         "selftest_l2.py", "run-06b3b.sh")

M = [
    # ---- signatures.py
    ("SG1", "signatures.py", [('_src_ports_expr(PROBE_PORTS.values())})) or "', '_ports_expr(PROBE_PORTS.values())})) or "')],
     "A11 alert_eth matches no negative fixture (incl. 06B-3G ctl port 42172)"),
    ("SG2", "signatures.py", [('    parts += [f"(ip6 and host {GUEST_LL6})"]\n', '')],
     "A12 alert_any matches every network-layer positive on LINUX_SLL2"),
    ("SG3", "signatures.py", [('        if EPHEMERAL_RANGE[0] <= v <= EPHEMERAL_RANGE[1]:', '        if False:')],
     "A5 check() catches a probe port inside the ephemeral range"),
    ("SG4", "signatures.py", [('    "T17-P2": 31172,', '    "T17-P2": 42172,')],
     "A2 every new probe port is outside the Linux ephemeral range"),
    ("SG5", "signatures.py", [('    macs = " or ".join(f"ether host {m}" for m in (GUEST_MAC,) + SPOOF_MACS)',
                               '    macs = " or ".join(f"ether host {m}" for m in (GUEST_MAC,))')],
     "A10 alert_eth matches every Ethernet positive fixture"),
    # ---- l2frames.py: direction
    ("LD1", "l2frames.py", [('return "guest_spoof_mac", "l2_bad_mac", f"source MAC {src} is the chosen',
                             'return "unknown_src", "unmapped", f"source MAC {src} is the chosen')],
     "D2 chosen spoof MAC -> l2_bad_mac (any ethertype)"),
    ("LD2", "l2frames.py", [('return "unknown_src", "unmapped", f"source MAC {src} is neither',
                             'return "guest_spoof_mac", "l2_bad_mac", f"source MAC {src} is neither')],
     "D4 other source MAC -> unknown_src / unmapped (never l2_bad_mac)"),
    # ---- l2frames.py: ARP mapping
    ("LA1", "l2frames.py", [('    if not _hooked_l2_dst(f["dst"], tap_mac):\n        return "arp_not_hooked"',
                             '    if False:\n        return "arp_not_hooked"')],
     "D22 ARP to another unicast MAC (OTHERHOST) -> arp_not_hooked"),
    ("LA2", "l2frames.py", [(' or int(dst[:2], 16) & 1 == 1', '')], "D23 ARP to a multicast MAC is hooked"),
    ("LA3", "l2frames.py", [('    if a["hlen"] != 6 or a["plen"] != 4:', '    if a["plen"] != 4:')],
     "D24 ARP hlen 8 -> arp_not_hooked"),
    ("LA4", "l2frames.py", [('    if a["short"] or a["len"] < ARP_HDR_LEN:', '    if a["short"]:')],
     "D26 ARP payload shorter than 28 bytes -> arp_not_hooked"),
    ("LA5", "l2frames.py", [('\n          and a["spa"] == S.GUEST_IP and a["tpa"] == S.WORKER_GUEST_IP',
                             '\n          and a["spa"] == S.GUEST_IP')],
     "D15 ARP target 192.168.60.2 -> arp_in_drop"),
    ("LA6", "l2frames.py", [('and a["sha"] == _norm_mac(S.GUEST_MAC)\n', '\n')],
     "D18 sender MAC field differs from guest -> arp_in_drop"),
    ("LA7", "l2frames.py", [('return "arp_not_hooked", f"hlen', 'return "arp_in_drop", f"hlen')],
     "D25 ARP plen 16 -> arp_not_hooked"),
    ("LA8", "l2frames.py", [('and a["op"] in (1, 2))\n    if ok:', ')\n    if ok:')], "D19 opcode 3 -> arp_in_drop"),
    ("LA9", "l2frames.py", [('and a.get("tpa") == S.GUEST_IP\n', '\n')],
     "D43 worker ARP outside the allow rule -> worker_unexpected"),
    # ---- l2frames.py: ethertypes / IPv4
    ("LE1", "l2frames.py", [('ETH_VLAN = (0x8100, 0x88A8)', 'ETH_VLAN = (0x8100, 0x88A8, 0x86DD)')],
     "D8 IPv6 from guest -> l2_bad_ethertype (IPv6 recognised)"),
    ("LE2", "l2frames.py", [('ETH_VLAN = (0x8100, 0x88A8)', 'ETH_VLAN = ()')], "D11 VLAN-tagged -> unmapped (not claimed)"),
    ("LI1", "l2frames.py", [('        elif not csum_ok:', '        elif False:')],   # 06B-4BR: line moved
     "D39 IPv4 bad header checksum -> ip_not_hooked"),
    ("LI2", "l2frames.py", [('    if not _hooked_l2_dst(f["dst"], tap_mac):\n        return "ip_not_hooked"',
                             '    if False:\n        return "ip_not_hooked"')],
     "D38 IPv4 to another unicast MAC (OTHERHOST) -> ip_not_hooked"),
    ("LI3", "l2frames.py", [('        if fragoff == 0 and p[9] in (6, 17)', '        if p[9] in (6, 17)')],
     "D31 non-first fragment to 8011 -> drop_worker_other (no ports)"),
    ("LI4", "l2frames.py", [('    if src != S.GUEST_IP:\n        return "drop_spoof"', '    if False:\n        return "drop_spoof"')],
     "D28 spoofed source wins over the allowed service -> drop_spoof"),
    # ---- l2frames.py: readers
    ("LR1", "l2frames.py", [('                    div = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v', '                    div = 10 ** 6')],
     "B5 pcapng if_tsresol 9 (nanoseconds)"),
    ("LR2", "l2frames.py", [('        elif btype == 3:', '        elif btype == -3:')],
     "B14 simple packet block (no timestamp) is a read error"),
    ("LR3", "l2frames.py", [('            raise FrameReadError(f"{path}: truncated packet at offset {i}")', '            break')],
     "B10 truncated pcap record is a read error"),
    ("LR4", "l2frames.py", [('        if struct.unpack_from(e + "I", data, i + blen - 4)[0] != blen:', '        if False:')],
     "B12 pcapng block trailer mismatch is a read error"),
    # ---- l2frames.py: strict reconciliation and labels
    ("LS1", "l2frames.py", [('    if missing:\n        return None, f"counter(s) missing', '    if False:\n        return None, f"counter(s) missing'),
                            ('        a, b = va[k], vb[k]', '        a, b = va.get(k, 0), vb.get(k, 0)')],
     "E2 missing counter in read A -> ERROR, not 0"),
    ("LS2", "l2frames.py", [('        if b < a:', '        if False:')], "E5 counter decreased -> ERROR"),
    ("LS3", "l2frames.py", [('            if not isinstance(v, int) or isinstance(v, bool) or v < 0:',
                             '            if not isinstance(v, int) or v < 0:')], "E4 bool counter value -> ERROR"),
    ("LS4", "l2frames.py", [('    if base["verdict"] == "PASS" and extra:', '    if False:')],
     "E9 not-hooked frame inside the window -> UNVERIFIED, listed"),
    ("LS5", "l2frames.py", [('            if z != "outside":', '            if True:')],
     "E11 no-counter frame outside the window does not count"),
    ("LS6", "l2frames.py", [('    bad = [k for k in compared if k not in COUNTER_CLASSES]', '    bad = []')],
     "E13 comparing an unobservable counter (arp_out_drop) -> ERROR even with the counter present"),
    ("LV1", "l2frames.py", [('            return "ĐẠT (kiểm quy tắc)", True', '            return "ĐẠT", True')],
     "F3 rule check + PASS -> ĐẠT (kiểm quy tắc)"),
    ("LV2", "l2frames.py", [('        if control_alive is not None:\n            raise ValueError("a rule-check probe has no live control")',
                             '        if False:\n            raise ValueError("a rule-check probe has no live control")')],
     "F4 rule check with a control value is refused"),
    ("LV3", "l2frames.py", [('    if text == "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)" and recon.get("no_counter_frames"):',
                             '    if False:')],
     "F8 no-counter frames are named as the cause, not as an edge"),
    # ---- guest_state.py
    ("GS1", "guest_state.py", [('    if now["mac"] != before["mac"]:', '    if False:')],
     "G6 MAC change: restored, MAC back, default route re-added"),
    ("GS2", "guest_state.py", [('    return [f"ip route del {x}" for x in sorted(a - b)] + [f"ip route add {x}" for x in sorted(b - a)]',
                                '    return []')], "G8 extra /32 address and on-link route removed"),
    ("GS3", "guest_state.py", [('            out.append(f"arp -i {dev} -s {ip} {mac}")', '            pass')],
     "G10 pre-existing static neighbour flushed by link down is re-created"),
    ("GS4", "guest_state.py", [('    for (ip, dev) in sorted(set(a) - set(b)):', '    for (ip, dev) in []:')],
     "G9 static neighbour added by the probe is deleted"),
    ("GS5", "guest_state.py", [('        if flags & 0x4:', '        if flags & 0x2:')],
     "G2 /proc/net/arp: complete entry is dynamic, not static"),
    ("GS6", "guest_state.py", [('    if now["arp_notify"] != before["arp_notify"]:', '    if False:')], "G12 arp_notify restored"),
    ("GS7", "guest_state.py", [('    log["restored"] = not log["diffs"]', '    log["restored"] = True')],
     "G14 failed restore command -> restored False, MAC diff listed"),
    ("GS8", "guest_state.py", [('    for k in ("mac", "operstate", "arp_notify"):', '    for k in ("operstate", "arp_notify"):')],
     "G14 failed restore command -> restored False, MAC diff listed"),
    ("GS9", "guest_state.py", [('        if rcs[name] != 0:', '        if False:')], "G3 section with rc != 0 -> StateReadError"),
    ("GS10", "guest_state.py", [('        self.rec["restore"] = restore(self.runner, self.iface, self.rec["before"], self.timeout)\n',
                                 '        self.rec["restore"] = {"restored": True}\n')],
     "G16 GuestChange restores even when the probe raises"),
    ("GS11", "guest_state.py", [('    return ([f"ip addr del {x} dev {iface}" for x in sorted(a - b)]', '    return ([]')],
     "G13 address added by netifd on link up is removed"),
    # ---- sigscan_l2.py
    ("SS1", "sigscan_l2.py", [('(ip["src"] in S.SPOOF_SRC_SHARED and (ip["sport"] in ports or probe_icmp))',
                               '(ip["src"] in S.SPOOF_SRC_SHARED and (probe_port or probe_icmp))')],
     "H6 shared spoofed source (192.168.60.10) is matched only with a probe SOURCE port"),
    ("SS2", "sigscan_l2.py", [('a["spa"] == "192.168.60.10" and a["sha"] != manager_mac', 'a["spa"] == "192.168.60.10"')],
     "H-neg every signature key = 0 on look-alikes (06B-3G ctl port 42172, manager traffic, real manager ARP)"),
    ("SS3", "sigscan_l2.py", [('        print(f"READ ERROR: {e}", file=sys.stderr)\n        return 2',
                               '        print(f"READ ERROR: {e}", file=sys.stderr)\n        return 0')],
     "H2 empty file -> exit 2, nothing printed"),
    ("SS4", "sigscan_l2.py", [('        c["arp_spoof_spa_manager"] = "skipped"', '        c["arp_spoof_spa_manager"] = 0')],
     "H1 --no-manager-mac reports the manager check as skipped, not 0"),
    ("SS5", "sigscan_l2.py", [('                hit = hit or S.GUEST_LL6 in (v6["src"], v6["dst"])', '                hit = hit')],
     "H-pos ipv6_guest = 1"),
    ("SS6", "sigscan_l2.py", [('        c["probe_qname"] += qn in raw', '        c["probe_qname"] += 0')], "H-pos probe_qname = 1"),
    # ---- run-06b3b.sh (06B-4B lines)
    ("RS1", "run-06b3b.sh", [('-c "$SIG_ENS33_MAX_PACKETS" -w - \\', '-c "$SIG_ENS33_MAX_PACKETS" -w - "net 10.200.0.0/30" \\')],
     "I2 ens33 capture: snaplen and packet limit from the registry, no filter expression"),
    ("RS2", "run-06b3b.sh", [('-i any "$SIG_ALERT_ANY"', '-i any "net 10.200.0.0/30"')],
     "I3 alert on any uses the registry filter"),
    ("RS3", "run-06b3b.sh", [('             ipv6_guest spoof_src_ip', '             spoof_src_ip')],
     "I6 run script checks every sigscan_l2 key except frames and truncated_frames (information)"),
    ("RS4", "run-06b3b.sh", [('for f in veth bridge ens33 alert alert_eth; do\n    check "tcpdump $f: exit 0 on stop"',
                              'for f in veth bridge ens33 alert; do\n    check "tcpdump $f: exit 0 on stop"')],
     "I11 both alerts are listed as captures that must exit 0"),
    # ---- 06B-4BR: snaplen cut vs damaged file vs malformed packet
    ("TR1", "sigscan_l2.py", [('            if not ip.get("hdr_ok"):', '            if not ip.get("valid"):')],
     "K2 NATed ICMP 1405 B cut at 512 (orig kept) -> icmp_size 1 from the IPv4 header"),
    ("TR2", "sigscan_l2.py", [('            if not ip.get("hdr_ok"):\n                blind(ip.get("hdr_cut", False))',
                               '            if not ip.get("hdr_ok"):\n                pass')],
     "K7 IPv4 header cut by snaplen -> unscannable_truncated 1, no signature claimed"),
    ("TR3", "sigscan_l2.py", [('                elif (DNS_PORT in (ip["sport"], ip["dport"]) and not ip["payload_complete"]):',
                               '                elif False:')],
     "K6 DNS payload cut before the name -> unscannable_truncated 1, not a silent 0"),
    ("TR4", "l2frames.py", [('    if f.get("truncated"):\n        return "guest", "unmapped"', '    if False:\n        return "guest", "unmapped"')],
     "K19 tap0: guest IPv4 cut by snaplen -> unmapped (not drop_public)"),
    ("TR5", "l2frames.py", [('        if incl > orig:', '        if False:')],
     "K16 pcap record with captured > original length -> read error"),
    ("TR6", "l2frames.py", [('            if cap > orig:', '            if False:')],
     "K17 pcapng EPB with captured > original length -> read error"),
    ("TR7", "l2frames.py", [('body[20:20 + cap], orig))', 'body[20:20 + cap], cap))')],
     "K3 same cut in pcapng (EPB original length) -> icmp_size 1, truncated_frames 1"),
    ("TR8", "sigscan_l2.py", [('                    blind(ip.get("ports_cut", False))', '                    pass')],
     "K8 TCP ports cut by snaplen -> unscannable_truncated 1"),
    ("TR9", "l2frames.py", [('            ip["hdr_cut"] = wire >= 20', '            ip["hdr_cut"] = True')],
     "K14 IPv4 header shorter than 20 B on the wire -> unscannable_undecoded 1"),
    ("TR10", "run-06b3b.sh", [(' probe_qname unscannable_truncated unscannable_undecoded; do', ' probe_qname; do')],
     "I6 run script checks every sigscan_l2 key except frames and truncated_frames (information)"),
    ("TR11", "l2frames.py", [('        if f.get("truncated"):\n            return "worker", "unmapped"',
                              '        if False:\n            return "worker", "unmapped"')],
     "K22 tap0: worker frame cut by snaplen -> unmapped"),
    ("TR12", "l2frames.py", [('        elif tot > wire:', '        elif tot > wire + 65536:')],
     "K13 malformed (total length beyond the wire frame): header read, not counted as truncated"),
    ("TR13", "sigscan_l2.py", [('            blind(f["truncated"])', '            blind(False)')],
     "K9 Ethernet header cut by snaplen -> unscannable_truncated 1"),
    # ---- 06B-4IR3 (PC-3): administrative link state in guest_state.py
    ("GS12", "guest_state.py", [('    if before["admin_up"] is not after["admin_up"]:', '    if False:')],
     "GA5 only the admin flag differs (both operstate down) -> diff reports admin_up"),
    ("GS13", "guest_state.py", [('    if now["admin_up"] is not before["admin_up"]:          # 06B-4IR3',
                                 '    if False:          # 06B-4IR3')],
     "GA6 baseline admin UP + operstate down, case leaves admin DOWN -> restore sends `ip link set up`, admin UP again, restored True (operstate still down, as recorded)"),
    ("GS14", "guest_state.py", [('    admin_up = "UP" in flags', '    admin_up = oper in ("up", "unknown")')],
     "GA2 real MIPS br-lan header (06B-4G: NO-CARRIER, state DOWN) -> admin_up True, operstate kept as read (down)"),
    ("GS15", "guest_state.py", [('                + ([f"ip link set dev {iface} up"] if before["admin_up"] else []))',
                                 '                + [f"ip link set dev {iface} up"])')],
     "GA10 MAC changed while the baseline is admin DOWN -> down + address, no `up`; restored True"),
    ("GS16", "guest_state.py", [('    if len(hdrs) != 1:', '    if not hdrs:')],
     "GA4 no header / two headers / header of another interface / malformed flags -> StateReadError"),
    ("GS17", "guest_state.py", [("{'up' if before['admin_up'] else 'down'}", "up")],
     "GA8 baseline admin DOWN, case brings it UP -> restore sets it DOWN again (baseline kept), restored True"),
    ("GS18", "guest_state.py", [('    if iface is not None and m.group(1) != iface:', '    if False:')],
     "GA4 no header / two headers / header of another interface / malformed flags -> StateReadError"),
    # ---- controls
    ("X1", "l2frames.py", [("THIS TEXT DOES NOT EXIST IN THE FILE", "x")], None),
    ("X2", "l2frames.py", [("import struct\n", "import struct(\n")], None),
]
CONTROL_EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def run_suite(d):
    j = os.path.join(d, "result.json")
    try:
        p = subprocess.run([sys.executable, os.path.join(d, "selftest_l2.py"), "--offline-only", "--json", j],
                           capture_output=True, text=True, timeout=600, cwd=d)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if p.returncode not in (0, 1) or not os.path.exists(j):
        return None, f"rc {p.returncode}: {(p.stderr or p.stdout).strip().splitlines()[-1:]}"
    return json.load(open(j)), None


def copy_tree(tmp):
    d = tempfile.mkdtemp(prefix="mut.", dir=tmp)
    for f in FILES:
        shutil.copy2(os.path.join(HERE, f), d)
    return d


def main(argv):
    only = set(argv[1].split(",")) if len(argv) == 2 and argv[0] == "--only" else None
    h0 = sha(HERE)
    print("harness sha256 before:", json.dumps(h0, sort_keys=True))
    ok_lines, bad = 0, 0
    with tempfile.TemporaryDirectory(prefix="mutation-l2.") as tmp:
        base, err = run_suite(copy_tree(tmp))
        if base is None or not all(base.values()):
            print(f"BASELINE FAILED ({err or [k for k, v in base.items() if not v]}): no mutation is meaningful")
            return 2
        print(f"baseline: {len(base)}/{len(base)} tests pass")
        names = set(base)
        for mid, fname, reps, target in M:
            if only and mid not in only:
                continue
            if target is not None and target not in names:
                print(f"BAD-TARGET {mid}: no test named {target!r}")
                bad += 1
                continue
            d = copy_tree(tmp)
            path = os.path.join(d, fname)
            src = open(path).read()
            klass, failed = None, []
            for old, new in reps:
                if src.count(old) != 1:
                    klass = "INVALID"
                    break
                src = src.replace(old, new)
            if klass is None:
                open(path, "w").write(src)
                res, err = run_suite(d)
                if res is None:
                    klass = "ERROR"
                else:
                    failed = sorted(k for k, v in res.items() if not v)
                    klass = ("DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED")
            expect = CONTROL_EXPECT.get(mid, "DETECTED")
            good = klass == expect
            ok_lines += good
            bad += not good
            print(f"{'OK ' if good else 'BAD'} {mid:5s} {klass:18s} target={target!r}"
                  + ("" if klass in ("DETECTED", "INVALID") else f" failed={failed[:6]}" + (f" ({err})" if klass == "ERROR" else "")))
    h1 = sha(HERE)
    same = h0 == h1
    print("harness sha256 after: ", "unchanged" if same else json.dumps(h1, sort_keys=True))
    print(f"MUTATION-L2: {ok_lines} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
