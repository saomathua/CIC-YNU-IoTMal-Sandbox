#!/usr/bin/env python3
"""CT-01 batch B1 — the first batch of the missing probes (matrix rows T05b, T06b, T06c, T11b, T11c and the T20 core/coverage).
Prepared and tested OFFLINE; not run against a guest by the delivery that introduces it.

Cases (per architecture, ARM then MIPS, each in its own counter window, sequential):
  guest -> ... (guest console, busybox tools only):
    T05-DNS-8888    nslookup <qname> 8.8.8.8          UDP/53  -> drop_public        live control: worker -> 8.8.8.8 DNS before AND after
    T06-ICMP-LANDNS ping -s 1406 192.168.177.2        ICMP    -> drop_private       live control: worker -> same IP ICMP echo before AND after
    T06-TCP-LAN2    curl --local-port 31060 <unused LAN IP>:80 TCP -> drop_private  rule check (no machine)
    T11-TCP22       curl --local-port 31110 10.200.0.1:22   TCP -> drop_worker_other  rule check
    T11-TCP80       curl --local-port 31111 10.200.0.1:80   TCP -> drop_worker_other  rule check
    T11-ICMP        ping -s 1111 10.200.0.1           ICMP    -> drop_worker_other  rule check
  worker -> guest (T20, executed in the worker netns by the harness process; nothing is sent by manager/host, decision D3):
    T20-N1-ICMP     3 echo requests to 10.200.0.2          \\
    T20-N2-TCP22   connect() 10.200.0.2:22, sport 31201    |  evidence: drop_out delta, every call failed with errno, NO frame
    T20-N2-TCP80   connect() 10.200.0.2:80, sport 31202    |  worker -> guest outside the allowlist on tap0, NO reply of the guest;
    T20-N3-UDP     3 datagrams to 10.200.0.2:31020, sport 31020 /  live control (N2-22): the guest answers nc 10.200.0.2 22 with a dropbear banner
  Route lookups T20-N4 (manager container, /proc/net/route) and T20-N5 (host `ip route get`) are READ-ONLY and collected by the run script
  (evaluated by evaluate_routes()).

Verdict rules (design §7.1, plan §1.3/§2; precedence FAIL > LOI_PHEP_DO > CHUA_KIEM_CHUNG > DAT):
  * a probe frame is identified by destination + protocol + (source port | ICMP size | DNS label); the criterion is delta == frames in the
    pcap of the SAME window (retransmissions included), never the number of attempts the tool intended;
  * a guest probe needs: the guest tool failed, >= 1 probe frame in tap0, every certain probe frame in the expected class, a reconciliation
    of ALL frame-mapped classes (FAIL beats everything; an edge frame is UNVERIFIED), no reply frame to the guest, service links OK;
  * live control missing/failed/one side only -> CHUA_KIEM_CHUNG ("không có đối chứng sống"), never DAT; no live control exists -> the
    reported label is "ĐẠT (kiểm quy tắc)" (D6);
  * T20: drop_out delta > 0 is the ONLY evidence that a packet reached the hook (drop_out is dropped before the tap0 capture point and is
    not reconciled with the pcap); delta 0 is CHUA_KIEM_CHUNG; a call that did not fail is CHUA_KIEM_CHUNG; a connect()
    that succeeds, a worker frame outside the allowlist or a guest reply is FAIL;
  * a read error, a missing/non-finite/decreasing counter, an unreadable pcap/counter file, a malformed record: LOI_PHEP_DO, never DAT;
  * R13 (review of R12): a worker case is guarded before read A AND again right before the dispatch: an alert that appears while read A runs
    stops the group with nothing sent for that case (recorded not_sent, reason kept, later cases not run, cleanup unchanged);
  * R13: a live control counts only with the exact schema {ts, ok, detail, binding}, the binding run_group wrote for THIS case/phase/destination/name,
    finite times, 'before' within CONTROL_MAX_AGE_S before read A, 'after' within CONTROL_MAX_AGE_S after read B, before < after: missing/failed/
    stale/reversed -> not alive (CHUA_KIEM_CHUNG), wrong schema/binding -> LOI_PHEP_DO; the DNS control needs a well-formed response to OUR query from
    the SAME IP:53;
  * R13: the T20 call record must be bound to its case, have exactly `count` records of the right operation, finite non-decreasing times inside the
    window between read A and read B, boolean ok and a positive integer errno for a failed call (or ONE well-formed setup_error record);
    otherwise LOI_PHEP_DO. The banner record has its own schema/states (alive / valid negative / missing / tool missing / invalid);
  * R13: an independent FAIL (guest tool reached the destination, connect() succeeded, reconciliation FAIL, frame/reply violation) is never hidden
    by a measurement error: the case is FAIL and `measurement_errors` keeps the error next to it;
  * R13: a guest ICMP probe must fit one unfragmented datagram (size + 28 <= MTU 1500); the signature is the IPv4 total length of that datagram;
  * a tool that is missing or a command that could not run: LOI_THUC_THI (CHUA KIEM CHUNG), never DAT; no probe frame: KHONG_TAO_DUOC_GOI;
  * closure: NOT used for the verdict. For an UNVERIFIED case the result carries `derived_closure`, an annotation computed by the unchanged
    counter_window.close_edges on a copy; the coordinator has not accepted closure for this suite.
No port, size or name is invented here: ports/sizes are in signatures.py (extended in this delivery, checked by signatures.py --check).
"""
import argparse
import copy
import ipaddress
import json
import math
import os
import random
import re
import socket as _socket
import struct
import sys
import time

import counter_window
import l2eval
import l2frames as L
import signatures as S

SCHEMA = "ct01-b1-group/1"
GUARD_S = counter_window.GUARD_S          # 20 ms, unmeasured assumption (unchanged)
COUNT = 3                                 # attempts per probe (a hint only)
DEADLINE_S = 5                            # busybox ping -w
SETTLE_S = 1.0                            # late frames land before read B (as the IPv4 matrix does)
W_TIMEOUT_S = 3.0
MTU = 1500                                # IPv4 MTU of the guest probe interface (ARM eth1, MIPS br-lan), observed in 06B-4G console logs
CONTROL_MAX_AGE_S = 15.0                  # a live control must be taken within this span before read A / after read B
CALL_TOLERANCE_S = 0.05
# T20 plan §3 and §6 disagree on a guest service that is NOT alive (rule check vs not judged). Until the coordinator fixes the label, a VALID
# negative banner record is NOT judged (CHUA_KIEM_CHUNG); set True to report "ĐẠT (kiểm quy tắc)" for it. A missing/invalid record is never judged.
BANNER_DEAD_AS_RULE_CHECK = False
LAN_DNS_DEFAULT = "192.168.177.2"
GUEST_IP = S.GUEST_IP
WORKER_IP = S.WORKER_GUEST_IP
CATEGORIES = ("DAT", "DAT_KIEM_QUY_TAC", "FAIL", "LOI_PHEP_DO", "LOI_THUC_THI", "KHONG_TAO_DUOC_GOI", "CHUA_KIEM_CHUNG")
OK_CATEGORIES = ("DAT", "DAT_KIEM_QUY_TAC")
GUEST_CASE_IDS = ("T05-DNS-8888", "T06-ICMP-LANDNS", "T06-TCP-LAN2", "T11-TCP22", "T11-TCP80", "T11-ICMP")
W_CASE_IDS = ("T20-N1-ICMP", "T20-N2-TCP22", "T20-N2-TCP80", "T20-N3-UDP")
ALL_CASE_IDS = GUEST_CASE_IDS + W_CASE_IDS
ROUTE_IDS = ("T20-N4", "T20-N5")
# Minimal BusyBox nc has no -w. One nc process, a bounded shell watchdog, no retry.
# The watchdog is cancelled/awaited after nc; the nc process is always awaited.
# Minimal BusyBox nc has no -w; the guest has no od (hexdump -v -e is used). One nc process, a bounded shell watchdog, no retry.
# This is a SCRIPT (newline separated, every line <= 100 ASCII chars, no single quote): the console cannot take it in one sendline.
# It is uploaded in short confirmed steps by Guest.run_script and executed as `sh <file>`; see b1_harness.B1GuardedRunner.run_banner.
BANNER_COMMAND = (
    'umask 077\n'
    'for ct01_tool in nc sleep mktemp wc head hexdump tr rm mkfifo; do\n'
    '  command -v "$ct01_tool" >/dev/null || exit 127\n'
    'done\n'
    'ct01_dir=$(mktemp -d /tmp/ct01-banner.XXXXXX) || exit 127\n'
    'ct01_nc=\n'
    'ct01_timer=\n'
    'ct01_input=\n'
    'ct01_clean() {\n'
    '  if [ -n "$ct01_input" ]; then kill -TERM "$ct01_input" 2>/dev/null; wait "$ct01_input" 2>/dev/null; fi\n'
    '  if [ -n "$ct01_nc" ]; then kill -TERM "$ct01_nc" 2>/dev/null; wait "$ct01_nc" 2>/dev/null; fi\n'
    '  if [ -n "$ct01_timer" ]; then kill -TERM "$ct01_timer" 2>/dev/null; wait "$ct01_timer" 2>/dev/null; fi\n'
    '  rm -rf -- "$ct01_dir" || exit 125\n'
    '}\n'
    'ct01_tclean() {\n'
    '  if [ -n "$ct01_ts" ]; then kill -TERM "$ct01_ts" 2>/dev/null; wait "$ct01_ts" 2>/dev/null; fi\n'
    '}\n'
    'trap ct01_clean 0\n'
    'trap "exit 125" HUP INT TERM\n'
    'mkfifo "$ct01_dir/stdin" || exit 125\n'
    'sleep 3 >"$ct01_dir/stdin" &\n'
    'ct01_input=$!\n'
    '( ulimit -f 16 || exit 125; exec nc 10.200.0.2 22 <"$ct01_dir/stdin" ) >"$ct01_dir/stdout" 2>"$ct01_dir/stderr" &\n'
    'ct01_nc=$!\n'
    '(\n'
    '  ct01_ts=\n'
    '  trap ct01_tclean 0\n'
    '  trap "exit 0" HUP INT TERM\n'
    '  sleep 3 &\n'
    '  ct01_ts=$!\n'
    '  wait "$ct01_ts" 2>/dev/null\n'
    '  ct01_trc=$?\n'
    '  ct01_ts=\n'
    '  if [ "$ct01_trc" -ne 0 ]; then : >"$ct01_dir/timer-error"; fi\n'
    '  : >"$ct01_dir/timeout"\n'
    '  kill -TERM "$ct01_nc" 2>/dev/null\n'
    ') &\n'
    'ct01_timer=$!\n'
    'wait "$ct01_nc" 2>/dev/null\n'
    'ct01_rc=$?\n'
    'ct01_nc=\n'
    'kill -TERM "$ct01_timer" 2>/dev/null\n'
    'wait "$ct01_timer" 2>/dev/null\n'
    'ct01_timer=\n'
    'kill -TERM "$ct01_input" 2>/dev/null\n'
    'wait "$ct01_input" 2>/dev/null\n'
    'ct01_input=\n'
    'ct01_timed=0\n'
    'ct01_te=0\n'
    '[ ! -f "$ct01_dir/timeout" ] || ct01_timed=1\n'
    '[ ! -f "$ct01_dir/timer-error" ] || ct01_te=1\n'
    'ct01_o=$(wc -c <"$ct01_dir/stdout") || exit 125\n'
    'ct01_e=$(wc -c <"$ct01_dir/stderr") || exit 125\n'
    'printf "CT01-BANNER-HEX/1\\nNC_RC=%s\\nTIMED_OUT=%s\\n" "$ct01_rc" "$ct01_timed"\n'
    'printf "TIMER_ERROR=%s\\nSTDOUT_BYTES=%s\\n" "$ct01_te" "$ct01_o"\n'
    'printf "STDERR_BYTES=%s\\nSTDOUT_HEX=" "$ct01_e"\n'
    'head -c 4096 "$ct01_dir/stdout" | hexdump -v -e "1/1 \\"%02x\\""\n'
    'printf "\\nSTDERR_HEX="\n'
    'head -c 2048 "$ct01_dir/stderr" | hexdump -v -e "1/1 \\"%02x\\""\n'
    'printf "\\nEND-CT01-BANNER-HEX/1\\n"\n'
    '[ "$ct01_te" -eq 0 ] || exit 125\n'
    '[ "$ct01_timed" -eq 0 ] || { [ "$ct01_rc" -ne 143 ] || exit 124; }\n'
    'exit "$ct01_rc"\n'
)
BANNER_RE = re.compile(r"SSH-2\.0-")


def _ip(x):
    return str(ipaddress.IPv4Address(x))


def lan_other_problem(ip, lan_dns=LAN_DNS_DEFAULT):
    """The unused LAN IP of T06-TCP-LAN2 must be a private LAN address that is NOT one of the addresses used elsewhere in the matrix."""
    try:
        a = ipaddress.IPv4Address(ip)
    except (ValueError, TypeError):
        return f"not an IPv4 address: {ip!r}"
    if not a.is_private or a in ipaddress.ip_network(S.GUEST_NET) or a.is_loopback or a.is_link_local:
        return f"{ip} is not a private LAN address outside the guest net"
    if str(a) in (lan_dns, "192.168.177.1", "192.168.177.128", "192.168.177.254", "192.168.60.1", "192.168.60.2", "192.168.60.3", "192.168.60.10",
                  "172.18.0.1", "172.18.0.2", "172.18.0.3"):
        return f"{ip} is an address already used by the harness/host"
    return None


def build_guest_cases(arch, lan_dns=LAN_DNS_DEFAULT, lan_other=None):
    if arch not in ("ARM", "MIPS"):
        raise ValueError(f"unknown architecture {arch!r}")
    if lan_other is None or lan_other_problem(lan_other, lan_dns):
        raise ValueError(f"lan_other_ip invalid: {lan_other_problem(lan_other, lan_dns) if lan_other is not None else 'missing'}")
    lan_dns = _ip(lan_dns)
    a = arch.lower()
    cases = [
        {"id": "T05-DNS-8888", "req": "T05b", "kind": "dns", "dst": "8.8.8.8", "port": 53, "expected": "drop_public", "control": "w_dns",
         "qname": f"{S.QNAME_PREFIX}t05-{a}-1.example", "control_qname": f"{S.QNAME_PREFIX}t05-ctl-{a}-1.example"},
        {"id": "T06-ICMP-LANDNS", "req": "T06b", "kind": "icmp", "dst": lan_dns, "port": None, "expected": "drop_private", "control": "w_icmp",
         "size": S.ICMP4_SIZES["T06-B"]},
        {"id": "T06-TCP-LAN2", "req": "T06c", "kind": "tcp", "dst": _ip(lan_other), "port": 80, "expected": "drop_private", "control": None,
         "lport": S.PROBE_PORTS["T06-L2"]},
        {"id": "T11-TCP22", "req": "T11b", "kind": "tcp", "dst": WORKER_IP, "port": 22, "expected": "drop_worker_other", "control": None,
         "lport": S.PROBE_PORTS["T11-P22"]},
        {"id": "T11-TCP80", "req": "T11b", "kind": "tcp", "dst": WORKER_IP, "port": 80, "expected": "drop_worker_other", "control": None,
         "lport": S.PROBE_PORTS["T11-P80"]},
        {"id": "T11-ICMP", "req": "T11c", "kind": "icmp", "dst": WORKER_IP, "port": None, "expected": "drop_worker_other", "control": None,
         "size": S.ICMP4_SIZES["T11-C"]},
    ]
    for c in cases:                     # F5: one unfragmented IPv4 datagram per echo (signature = total length), never beyond the observed MTU
        if c["kind"] == "icmp" and int(c["size"]) + 28 > MTU:
            raise ValueError(f"{c['id']}: ICMP size {c['size']} gives IPv4 total length {int(c['size']) + 28} > MTU {MTU}")
    return cases


def build_w_cases():
    return [
        {"id": "T20-N1-ICMP", "req": "T20-N1", "kind": "w_icmp", "dst": GUEST_IP, "port": None, "count": COUNT, "size": 1220},
        {"id": "T20-N2-TCP22", "req": "T20-N2", "kind": "w_tcp", "dst": GUEST_IP, "port": 22, "sport": S.PROBE_PORTS["T20-N2-22"], "count": 1,
         "banner_control": True},
        {"id": "T20-N2-TCP80", "req": "T20-N2", "kind": "w_tcp", "dst": GUEST_IP, "port": 80, "sport": S.PROBE_PORTS["T20-N2-80"], "count": 1},
        {"id": "T20-N3-UDP", "req": "T20-N3", "kind": "w_udp", "dst": GUEST_IP, "port": S.PROBE_PORTS["T20-N3"], "sport": S.PROBE_PORTS["T20-N3"],
         "count": COUNT},
    ]


def command(case):
    """Exact guest command of a guest case (busybox). Every interpolated value is validated first."""
    k, dst = case["kind"], _ip(case["dst"])
    if k == "dns":
        if not re.fullmatch(r"[a-z0-9.-]{3,80}", case["qname"]):
            raise ValueError("bad qname")
        return f"nslookup {case['qname']} {dst}"
    if k == "icmp":
        return f"ping -c {COUNT} -s {int(case['size'])} -w {DEADLINE_S} {dst}"
    if k == "tcp":
        return (f"curl -s -o /dev/null --local-port {int(case['lport'])} --connect-timeout 4 -m 5 "
                f"-w 'HTTP=%{{http_code}}\\n' http://{dst}:{int(case['port'])}/ct01-b1-{case['id']}")
    raise ValueError(f"not a guest case: {case['id']}")


def guest_failed(case, rc, out):
    """Did the guest tool FAIL to reach the destination? (tool failure is necessary, never sufficient)."""
    out = out or ""
    k = case["kind"]
    if k == "tcp":
        return rc in (7, 28) and "HTTP=000" in out
    if k == "dns":
        return rc is not None and rc != 0 and not re.search(r"Name:\s+" + re.escape(case["qname"]), out)
    if k == "icmp":
        return rc is not None and rc != 0 and "bytes from" not in out
    raise ValueError(k)


# ------------------------------------------------------------------ worker side (control and T20 probes); sockets are injectable
def icmp_checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def icmp_echo(ident, seq, payload):
    head = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    csum = icmp_checksum(head + payload)
    return struct.pack("!BBHHH", 8, 0, csum, ident & 0xFFFF, seq & 0xFFFF) + payload


def parse_echo_reply(packet, ident, src):
    """Raw IPv4 packet -> True only for an ICMP echo REPLY from `src` with our identifier and a valid checksum."""
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return False
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 8 or packet[9] != 1:
        return False
    if str(ipaddress.IPv4Address(packet[12:16])) != src:
        return False
    icmp = packet[ihl:]
    if icmp[0] != 0 or icmp[1] != 0 or icmp_checksum(icmp) != 0:
        return False
    return struct.unpack_from("!H", icmp, 4)[0] == (ident & 0xFFFF)


def icmp_control(ip, sock=_socket, timeout=W_TIMEOUT_S, now=time.time, count=2, payload=b"ct01-b1-control" + bytes(18)):
    """Live control of an ICMP destination: the WORKER (an allowed source) sends echo requests and must receive an echo reply from the same IP.
    Returns a detail string or raises (probe_matrix.run_ctl turns a raise into ok=False). Needs CAP_NET_RAW (the worker test container is privileged)."""
    ip = _ip(ip)
    ident = random.getrandbits(16)
    s = sock.socket(sock.AF_INET, sock.SOCK_RAW, sock.IPPROTO_ICMP)
    try:
        s.settimeout(timeout)
        for seq in range(1, count + 1):
            s.sendto(icmp_echo(ident, seq, payload), (ip, 0))
            end = now() + timeout
            while now() < end:
                try:
                    data, addr = s.recvfrom(2048)
                except sock.timeout:
                    break
                if parse_echo_reply(data, ident, ip):
                    return f"ICMP echo reply from {ip}"
        raise RuntimeError(f"no ICMP echo reply from {ip}")
    finally:
        s.close()


def dns_query(qid, qname):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in qname.rstrip(".").split("."):
        b = label.encode("ascii")
        if not 0 < len(b) < 64:
            raise ValueError("bad DNS label")
        q += bytes([len(b)]) + b
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def _dns_name(data, off):
    """Decode one bounded DNS name, returning (labels, end of its wire encoding).

    Compression points to an earlier name in this message; loops, reserved label
    encodings, truncated names and expanded names over 255 bytes are rejected.
    """
    labels, end, seen, size = [], None, set(), 1
    while True:
        if off < 12 or off >= len(data) or off in seen:
            raise RuntimeError("invalid DNS name offset or compression loop")
        seen.add(off)
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 2 > len(data):
                raise RuntimeError("truncated DNS name pointer")
            target = ((n & 0x3F) << 8) | data[off + 1]
            if target >= off:
                raise RuntimeError("DNS name pointer is not backwards")
            if end is None:
                end = off + 2
            off = target
            continue
        if n & 0xC0 or off + 1 + n > len(data):
            raise RuntimeError("invalid or truncated DNS label")
        off += 1
        if n == 0:
            return labels, off if end is None else end
        size += n + 1
        if size > 255:
            raise RuntimeError("DNS name exceeds 255 bytes")
        labels.append(data[off:off + n])
        off += n


def _dns_rr_end(data, off):
    """Check one complete RR including bounded RDATA; return the next wire offset.

    Known address/name/SOA/TXT/EDNS encodings are checked. Unknown RDATA types
    remain opaque, but their declared length must be present in full.
    """
    _, off = _dns_name(data, off)
    if off + 10 > len(data):
        raise RuntimeError("truncated DNS resource record header")
    typ, _, _, length = struct.unpack_from("!HHIH", data, off)
    start, end = off + 10, off + 10 + length
    if end > len(data):
        raise RuntimeError("truncated DNS resource record data")
    if (typ == 1 and length != 4) or (typ == 28 and length != 16):
        raise RuntimeError("invalid DNS address RDATA length")
    if typ in (2, 5, 12, 15, 6, 33):
        pos = start + (2 if typ == 15 else 6 if typ == 33 else 0)
        if pos >= end:
            raise RuntimeError("truncated DNS name RDATA")
        _, pos = _dns_name(data, pos)
        if typ == 6:
            if pos >= end:
                raise RuntimeError("truncated DNS SOA")
            _, pos = _dns_name(data, pos)
            pos += 20
        if pos != end:
            raise RuntimeError("DNS name/SOA RDATA length mismatch")
    elif typ == 16:
        pos = start
        if pos == end:
            raise RuntimeError("empty DNS TXT RDATA")
        while pos < end:
            pos += 1 + data[pos]
        if pos != end:
            raise RuntimeError("truncated DNS TXT string")
    elif typ == 41:
        pos = start
        while pos < end:
            if pos + 4 > end:
                raise RuntimeError("truncated EDNS option header")
            opt_len = struct.unpack_from("!H", data, pos + 2)[0]
            pos += 4 + opt_len
        if pos != end:
            raise RuntimeError("truncated EDNS option data")
    return end


def parse_dns_reply(data, qid, qname):
    """-> rcode for a complete response to our single A/IN question.

    All declared sections and EOF must match the received bytes. NOERROR and
    NXDOMAIN are controls; TC or malformed messages cannot prove a live control.
    """
    if len(data) < 12 + len(qname) + 2:
        raise RuntimeError(f"DNS reply too short ({len(data)} bytes)")
    rid, flags, qd, an, ns, ar = struct.unpack_from("!6H", data, 0)
    if rid != qid:
        raise RuntimeError("DNS id mismatch")
    if not flags & 0x8000 or (flags >> 11) & 0xF != 0:
        raise RuntimeError("not a standard DNS response")
    if flags & 0x0200:
        raise RuntimeError("truncated DNS response (TC)")
    if qd != 1:
        raise RuntimeError("response must echo exactly our one question")
    labels, off = _dns_name(data, 12)
    expected_labels = [label.lower().encode("ascii") for label in qname.rstrip(".").split(".")]
    if [label.lower() for label in labels] != expected_labels:
        raise RuntimeError("question name differs from the query")
    if off + 4 > len(data) or struct.unpack_from("!HH", data, off) != (1, 1):
        raise RuntimeError("question type/class differs from the query")
    off += 4
    for _ in range(an + ns + ar):
        off = _dns_rr_end(data, off)
    if off != len(data):
        raise RuntimeError("DNS trailing bytes outside declared sections")
    rcode = flags & 0xF
    if rcode not in (0, 3):
        raise RuntimeError(f"DNS rcode {rcode}")
    return rcode


def dns_control(server, qname, sock=_socket, timeout=W_TIMEOUT_S, now=time.time):
    """Live control of the UDP/53 destination: the worker queries the SAME IP:53 and must receive a valid response to that query FROM that IP:53
    (datagrams from another sender are ignored, never accepted). Returns a detail string or raises."""
    server = _ip(server)
    qid = random.getrandbits(16)
    s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(dns_query(qid, qname), (server, 53))
        end = now() + timeout
        while now() < end:
            data, addr = s.recvfrom(1500)
            if tuple(addr) != (server, 53):
                continue
            return f"DNS response rcode={parse_dns_reply(data, qid, qname)} from {server}:53"
        raise RuntimeError(f"no DNS response from {server}:53")
    finally:
        s.close()


def _call_record(op, now, exc=None, timeout=False):
    if exc is None:
        return {"op": op, "ts": now(), "ok": True, "errno": None}
    if timeout:
        return {"op": op, "ts": now(), "ok": False, "errno": 110, "exc": "timeout"}
    return {"op": op, "ts": now(), "ok": False, "errno": getattr(exc, "errno", None), "exc": type(exc).__name__}


def w_send(case, sock=_socket, now=time.time, timeout=W_TIMEOUT_S):
    """Execute one T20 case from the worker netns. Returns a list of per-call records {op, ts, ok, errno, exc}. Never raises.
    A setup failure (cannot create the socket) is recorded as op='socket' with setup_error True: the case is then LOI_THUC_THI, not evidence."""
    calls = []
    k, dst = case["kind"], _ip(case["dst"])
    try:
        if k == "w_icmp":
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_RAW, sock.IPPROTO_ICMP)
            except OSError as e:
                return [{**_call_record("socket", now, e), "setup_error": True}]
            try:
                ident = random.getrandbits(16)
                for seq in range(1, int(case["count"]) + 1):
                    pkt = icmp_echo(ident, seq, b"ct01-b1-t20-n1" + bytes(int(case["size"]) - 14))
                    try:
                        s.sendto(pkt, (dst, 0))
                        calls.append(_call_record("sendto", now))
                    except OSError as e:
                        calls.append(_call_record("sendto", now, e))
            finally:
                s.close()
        elif k == "w_tcp":
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
                s.bind((WORKER_IP, int(case["sport"])))
                s.settimeout(timeout)
            except OSError as e:
                return [{**_call_record("socket", now, e), "setup_error": True}]
            try:
                s.connect((dst, int(case["port"])))
                calls.append(_call_record("connect", now))
            except sock.timeout as e:
                calls.append(_call_record("connect", now, e, timeout=True))
            except OSError as e:
                calls.append(_call_record("connect", now, e))
            finally:
                s.close()
        elif k == "w_udp":
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
                s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
                s.bind((WORKER_IP, int(case["sport"])))
            except OSError as e:
                return [{**_call_record("socket", now, e), "setup_error": True}]
            try:
                for _ in range(int(case["count"])):
                    try:
                        s.sendto(b"ct01-b1-t20-n3", (dst, int(case["port"])))
                        calls.append(_call_record("sendto", now))
                    except OSError as e:
                        calls.append(_call_record("sendto", now, e))
            finally:
                s.close()
        else:
            return [{"op": "unknown", "ts": now(), "ok": False, "errno": None, "exc": "unknown case kind", "setup_error": True}]
    except Exception as e:                                        # noqa: BLE001  (never raises; recorded)
        calls.append({"op": "error", "ts": now(), "ok": False, "errno": None, "exc": f"{type(e).__name__}: {e}", "setup_error": True})
    return calls


# ------------------------------------------------------------------ execution (prepared, not run here)
def run_group(runner, read_counters, service_link, guest_cases, w_cases, iface, arch, tap_mac, w_control=None, send=None,
              guard_before=None, guard_after=None, sleep=time.sleep, timeout=60, stop_box=None, now=time.time):
    """runner.run(cmd, timeout) -> (rc, text) (a GuardedRunner: every guest command is guarded before AND after);
    read_counters(label) appends the read to counters-raw.jsonl; service_link() -> (ok, detail);
    w_control(case) -> {"ts","ok","detail"} for the live control kinds 'w_dns'/'w_icmp'; send(case) -> list of call records (w_send);
    guard_before/after(label) raise to stop the group (the exception is put into stop_box for the caller to re-raise).
    F1: a worker case is guarded BEFORE read A, and AGAIN right before the dispatch (after read A, with nothing but the check in between);
    a stop at that point sends nothing, keeps the reason and runs no later case.
    F2: every control record carries a binding made by THIS function (case, control kind, destination, port, name, phase); the banner record has a
    fixed schema and identifies the N2-22 case/read A it immediately precedes. F3: the call list carries the binding of the case it belongs to.
    Returns the group record consumed by evaluate_group(). Never raises: every failure is recorded."""
    stop_box = stop_box if stop_box is not None else []
    send0 = send or (lambda c: w_send(c))

    def send(c):                                                  # a failing sender is recorded, never raised
        try:
            return send0(c)
        except Exception as e:                                    # noqa: BLE001
            return [{"op": "error", "ts": now(), "ok": False, "errno": None, "exc": f"{type(e).__name__}: {e}", "setup_error": True}]

    def control(c, phase):                                        # a failing control is a control that is not alive
        try:
            res = w_control(c)
        except Exception as e:                                    # noqa: BLE001
            res = {"ts": now(), "ok": False, "detail": f"{type(e).__name__}: {e}"}
        rec_c = dict(res) if isinstance(res, dict) else {"ts": None, "ok": False, "detail": f"control returned {type(res).__name__}"}
        rec_c["binding"] = control_binding(c, phase)
        return rec_c

    rec = {"schema": SCHEMA, "arch": arch, "iface": iface, "tap_mac": tap_mac, "service_link_before": None, "service_link_after": None,
           "guest_banner_control": None, "guest_cases": [], "w_cases": [], "stopped": None}

    def link():
        try:
            ok, detail = service_link()
        except Exception as e:                                    # noqa: BLE001
            ok, detail = False, f"{type(e).__name__}: {e}"
        return {"ok": ok is True, "detail": detail}

    def guard(fn, label):
        if fn is None or stop_box:
            return
        try:
            fn(label)
        except Exception as e:                                    # noqa: BLE001
            stop_box.append(e)
            rec["stopped"] = f"{type(e).__name__}: {e}"

    rec["service_link_before"] = link()
    if not rec["service_link_before"]["ok"]:
        rec["skipped"] = "service link before the group failed: no case was run"
        return rec
    for c in guest_cases:
        if stop_box:
            rec["guest_cases"].append({"id": c["id"], "not_run": rec["stopped"]})
            continue
        r = {"id": c["id"], "before": f"{c['id']} before", "after": f"{c['id']} after", "command": None, "exec": None, "read_error": None,
             "control_before": None, "control_after": None}
        try:
            r["command"] = command(c)
        except ValueError as e:
            r["exec"] = {"error": f"command not built: {e}"}
            rec["guest_cases"].append(r)
            continue
        if c.get("control") and w_control is not None:
            r["control_before"] = control(c, "before")
        try:
            read_counters(r["before"])
        except Exception as e:                                    # noqa: BLE001
            r["read_error"] = f"read {r['before']!r}: {type(e).__name__}: {e}"
        try:
            rc, out = runner.run(r["command"], timeout=timeout)
            r["exec"] = {"rc": rc, "output_tail": (out or "")[-300:], "guest_failed": guest_failed(c, rc, out)}
            if rc == 127 or "not found" in (out or ""):
                r["exec"]["error"] = "tool missing in the guest"
        except Exception as e:                                    # noqa: BLE001
            r["exec"] = {"error": f"{type(e).__name__}: {e}"}
        sleep(SETTLE_S)
        try:
            read_counters(r["after"])
        except Exception as e:                                    # noqa: BLE001
            r["read_error"] = (r["read_error"] + "; " if r["read_error"] else "") + f"read {r['after']!r}: {type(e).__name__}: {e}"
        if c.get("control") and w_control is not None:
            r["control_after"] = control(c, "after")
        rec["guest_cases"].append(r)
        if getattr(runner, "stop", None) is not None and not stop_box:
            stop_box.append(runner.stop)
            rec["stopped"] = f"{type(runner.stop).__name__}: {runner.stop}"
    for c in w_cases:
        if stop_box:
            rec["w_cases"].append({"id": c["id"], "not_run": rec["stopped"]})
            continue
        r = {"id": c["id"], "before": f"{c['id']} before", "after": f"{c['id']} after", "read_error": None, "calls": None, "send_binding": send_binding(c)}
        guard(guard_before, f"before {c['id']}")
        if stop_box:
            rec["w_cases"].append({"id": c["id"], "not_run": rec["stopped"]})
            continue
        if c.get("banner_control"):
            # Exactly one fresh guest-local control, through GuardedRunner, right before THIS case's A.
            # No old group-level control is collected or used as a fallback.
            binding = banner_binding(c)
            out = None
            rc = None
            try:
                banner_run = getattr(runner, "run_banner", None)    # real console: short confirmed upload steps, then `sh file`
                rc, out = (banner_run if banner_run is not None else runner.run)(BANNER_COMMAND, timeout=timeout)
                out = out or ""
                transport = parse_banner_transport(rc, out)
                rec["guest_banner_control"] = {"command": BANNER_COMMAND, "rc": rc, "ok": transport["state"] == "alive",
                                               "output_tail": transport["output_tail"], "transport_output": out,
                                               "ts": now(), "binding": binding}
                if transport["state"] == "execution_error":
                    rec["guest_banner_control"]["error"] = "banner execution diagnostic/rc failure; binary channels retained in transport_output"
            except Exception as e:                                # noqa: BLE001
                rec["guest_banner_control"] = {"command": BANNER_COMMAND, "ok": False, "error": f"{type(e).__name__}: {e}",
                                               "ts": now(), "binding": binding}
                if type(rc) is int:
                    rec["guest_banner_control"]["rc"] = rc
                if isinstance(out, str):
                    rec["guest_banner_control"]["transport_output"] = out[:13000]
                    rec["guest_banner_control"]["transport_output_truncated"] = len(out) > 13000
            if getattr(runner, "stop", None) is not None and not stop_box:
                stop_box.append(runner.stop)
                rec["stopped"] = f"{type(runner.stop).__name__}: {runner.stop}"
            if stop_box:
                rec["w_cases"].append({"id": c["id"], "not_run": rec["stopped"], "not_sent": True})
                continue
        try:
            read_counters(r["before"])
        except Exception as e:                                    # noqa: BLE001
            r["read_error"] = f"read {r['before']!r}: {type(e).__name__}: {e}"
        # F1: the read above can take time and can coincide with a leak/capture event: check AGAIN, immediately before the dispatch
        guard(guard_before, f"pre-send {c['id']}")
        if stop_box:
            rec["w_cases"].append({"id": c["id"], "before": r["before"], "read_error": r["read_error"], "calls": None, "not_sent": True,
                                   "not_run": f"stopped after read A, nothing sent: {rec['stopped']}"})
            continue
        r["calls"] = send(c)
        sleep(SETTLE_S)
        try:
            read_counters(r["after"])
        except Exception as e:                                    # noqa: BLE001
            r["read_error"] = (r["read_error"] + "; " if r["read_error"] else "") + f"read {r['after']!r}: {type(e).__name__}: {e}"
        guard(guard_after, f"after {c['id']}")
        rec["w_cases"].append(r)
    rec["service_link_after"] = link()
    return rec


def control_binding(case, phase):
    """What a live control of `case` must be bound to (made by run_group, checked by the evaluator)."""
    return {"case": case["id"], "control": case["control"], "dst": case["dst"], "port": 53 if case["control"] == "w_dns" else None,
            "qname": case.get("control_qname") if case["control"] == "w_dns" else None, "phase": phase}


def banner_binding(case):
    """Bind the guest-local TCP/22 control to the worker case and the exact read A it precedes."""
    return {"case": case["id"], "kind": "guest_banner", "dst": case["dst"], "port": case["port"],
            "phase": "before", "read_label": f"{case['id']} before"}


def send_binding(case):
    return {"case": case["id"], "kind": case["kind"], "dst": case["dst"], "port": case.get("port"), "sport": case.get("sport"),
            "count": int(case.get("count", 1))}


# ------------------------------------------------------------------ evaluation
def _result(cid, category, text, **kw):
    assert category in CATEGORIES
    out = {"id": cid, "category": category, "verdict": text, "ok": category in OK_CATEGORIES}
    out.update(kw)
    return out


def link_ok(state):
    return isinstance(state, dict) and state.get("ok") is True


def _fin(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def control_state(case, crec, ra, rb):
    """-> (state, why). state: 'alive' | 'not_alive' (missing, failed, stale, reversed: the control did not prove the destination alive in THIS
    window) | 'invalid' (schema or binding wrong: a measurement error). A control is trusted only with the exact schema, the binding made by
    run_group for THIS case and phase, finite times, and a time inside [read A start - MAX_AGE, read A start] / [read B end, read B end + MAX_AGE]."""
    recs = {"before": crec.get("control_before"), "after": crec.get("control_after")}
    why = []
    for phase, c in recs.items():
        if c is None:
            return "not_alive", f"control {phase} missing"
        if not isinstance(c, dict) or set(c) != {"ts", "ok", "detail", "binding"}:
            return "invalid", f"control {phase}: schema (keys {sorted(c) if isinstance(c, dict) else type(c).__name__})"
        if not _fin(c["ts"]) or type(c["ok"]) is not bool or not isinstance(c["detail"], str):
            return "invalid", f"control {phase}: field types (ts finite number, ok bool, detail str)"
        if c["binding"] != control_binding(case, phase):
            return "invalid", f"control {phase}: binding {c['binding']!r} is not this case/phase"
    b, a = recs["before"], recs["after"]
    if not (ra["t_start"] - CONTROL_MAX_AGE_S <= b["ts"] <= ra["t_start"] + CALL_TOLERANCE_S):
        why.append(f"control before ts {b['ts']} outside [{ra['t_start'] - CONTROL_MAX_AGE_S}, {ra['t_start']}]")
    if not (rb["t_end"] - CALL_TOLERANCE_S <= a["ts"] <= rb["t_end"] + CONTROL_MAX_AGE_S):
        why.append(f"control after ts {a['ts']} outside [{rb['t_end']}, {rb['t_end'] + CONTROL_MAX_AGE_S}]")
    if b["ts"] >= a["ts"]:
        why.append("controls not in order (before >= after)")
    if why:
        return "not_alive", "; ".join(why)
    if not (b["ok"] and a["ok"]):
        return "not_alive", "control reported failure"
    return "alive", None



def parse_banner_transport(rc, out):
    """Bounded ASCII envelope; preserve both binary channels, never decode SSH payload as UTF-8."""
    if type(rc) is not int or not isinstance(out, str) or len(out) > 13000 or not out.isascii():
        raise ValueError("banner transport type/ASCII/size")
    pattern = (r"CT01-BANNER-HEX/1\nNC_RC=([0-9]{1,3})\nTIMED_OUT=([01])\nTIMER_ERROR=([01])\n"
               r"STDOUT_BYTES=([0-9]{1,6})\nSTDERR_BYTES=([0-9]{1,6})\n"
               r"STDOUT_HEX=([0-9a-f]*)\nSTDERR_HEX=([0-9a-f]*)\nEND-CT01-BANNER-HEX/1")
    m = re.fullmatch(pattern, out.strip().replace("\r\n", "\n"))
    if not m:
        raise ValueError("banner transport malformed/incomplete")
    nrc, timed, timer_error, no, ne = map(int, m.groups()[:5])
    if nrc > 255 or no > 4096 or ne > 2048:
        raise ValueError("banner transport oversize/rc")
    try:
        stdout, stderr = bytes.fromhex(m[6]), bytes.fromhex(m[7])
    except ValueError as e:
        raise ValueError("banner transport hex") from e
    if len(stdout) != no or len(stderr) != ne:
        raise ValueError("banner transport truncated/channel size")
    if timer_error or rc != (124 if timed and nrc == 143 else nrc):
        raise ValueError("banner transport timer/rc mismatch")
    if any(x > 127 for x in stderr):
        raise ValueError("banner stderr is not ASCII diagnostic")
    diagnostic = banner_execution_error(stderr.decode('ascii')) or bool(re.search(
        rb"(?im)usage:|(?:invalid|illegal|unrecognized|unsupported) option|not found|permission denied", stdout))
    line = stdout.split(b'\n', 1)[0].rstrip(b'\r') if stdout else b''
    valid_banner = (b'\n' in stdout and 0 < len(line) <= 255 and
                    all(32 <= x <= 126 for x in line) and line.startswith(b'SSH-2.0-') and len(line) > 8)
    if diagnostic or stderr or not (nrc == 0 or timed and nrc == 143):
        state = 'execution_error'
    elif valid_banner:
        state = 'alive'
    elif stdout:
        raise ValueError("banner identification missing/incomplete/non-ASCII")
    else:
        state = 'not_alive' if rc == 124 else 'dead_valid'
    return {'state': state, 'output_tail': line.decode('ascii') if valid_banner else '',
            'stdout_hex': stdout.hex(), 'stderr_hex': stderr.hex(), 'nc_rc': nrc,
            'timed_out': bool(timed), 'stdout_bytes': no, 'stderr_bytes': ne}


def banner_execution_error(out):
    """Usage/unsupported options/timer failure never prove service absence, even alongside a banner."""
    return bool(re.search(r"(?im)usage:|(?:invalid|illegal|unrecognized|unsupported) option|CT01_BANNER_TIMER_ERROR|not found|permission denied", out))


def banner_state(b, read_before=None, case=None):
    """Validate schema; with read_before also require a fresh control before A.

    -> alive | dead_valid | missing | tool_missing | invalid | not_alive.
    The evaluator always passes read A. Schema-only callers cannot use this as
    evidence of freshness. No guest command or retry is added here.
    """
    if b is None:
        return "missing", "no banner control record"
    if not isinstance(b, dict) or not set(b) <= {"command", "rc", "ok", "output_tail", "ts", "error", "binding", "transport_output", "transport_output_truncated"}:
        return "invalid", "banner record schema"
    if "transport_output_truncated" in b and b["transport_output_truncated"] is not False:
        return "invalid", "banner transport was truncated or truncation field malformed"
    if isinstance(b.get("output_tail"), str) and banner_execution_error(b["output_tail"]):
        return "tool_missing", "banner command execution failed (Usage/option, missing tool, permission or timer error); source record kept"
    if b.get("command") != BANNER_COMMAND or not _fin(b.get("ts")) or type(b.get("ok")) is not bool:
        return "invalid", "banner record: command/ts/ok"
    if "error" in b:
        return ("tool_missing", f"banner command could not run: {b['error']}") if isinstance(b["error"], str) and b["ok"] is False else ("invalid", "banner error field")
    rc, out = b.get("rc"), b.get("output_tail")
    try:
        transport = parse_banner_transport(rc, b.get("transport_output"))
    except ValueError as e:
        return "invalid", f"banner transport: {e}"
    if out != transport["output_tail"] or b["ok"] != (transport["state"] == "alive"):
        return "invalid", "banner record contradicts transport"
    if transport["state"] == "execution_error":
        return "tool_missing", "banner command execution failed; raw channels retained"
    if type(rc) is not int or not isinstance(out, str):
        return "invalid", "banner record: rc/output_tail types"
    if rc == 127 or banner_execution_error(out):
        return "tool_missing", "banner command execution failed (missing tool, Usage/option, permission or timer error)"
    if case is not None and b.get("binding") != banner_binding(case):
        return "invalid", "banner binding does not identify this case/read A"
    if rc in (0, 124) and BANNER_RE.search(out):
        if not b["ok"]:
            return "invalid", "banner ok contradicts rc/output"
        state = "alive"
    else:
        if b["ok"]:
            return "invalid", "banner ok contradicts rc/output"
        if rc == 124:
            state = "not_alive"
        elif rc != 0:
            return "tool_missing", f"banner command execution failed rc={rc} (not proof of absent service)"
        else:
            state = "dead_valid"
    if read_before is not None:
        start = read_before.get("t_start")
        if not _fin(start):
            return "invalid", "banner window has no finite read A start"
        if not start - CONTROL_MAX_AGE_S <= b["ts"] <= start:
            return "not_alive", f"banner ts {b['ts']} outside [{start - CONTROL_MAX_AGE_S}, {start}] before read A"
    return state, "bounded banner read reached deadline without SSH banner" if state == "not_alive" else None


def validate_calls(case, crec, ra, rb):
    """-> (problems, setup_error). Exact schema, count, operation, order and window of the T20 syscall record; bound to the case."""
    p = []
    calls = crec.get("calls")
    if crec.get("send_binding") != send_binding(case):
        p.append(f"send_binding {crec.get('send_binding')!r} is not this case")
    if not isinstance(calls, list) or not all(isinstance(c, dict) for c in calls):
        return p + ["calls missing or not a list of objects"], False
    if any(c.get("setup_error") is True for c in calls):
        ok = (len(calls) == 1 and set(calls[0]) <= {"op", "ts", "ok", "errno", "exc", "setup_error"} and calls[0].get("op") in ("socket", "error", "unknown")
              and _fin(calls[0].get("ts")) and calls[0].get("ok") is False and isinstance(calls[0].get("exc"), str))
        return (p if ok else p + ["setup_error record has an invalid shape"]), True
    op = {"w_icmp": "sendto", "w_tcp": "connect", "w_udp": "sendto"}[case["kind"]]
    n = int(case.get("count", 1))
    if len(calls) != n:
        p.append(f"{len(calls)} call record(s), expected exactly {n}")
    last = None
    for i, c in enumerate(calls):
        if not set(c) <= {"op", "ts", "ok", "errno", "exc"} or not {"op", "ts", "ok", "errno"} <= set(c):
            p.append(f"call {i}: keys {sorted(c)}")
            continue
        if c["op"] != op:
            p.append(f"call {i}: op {c['op']!r} != {op!r}")
        if not _fin(c["ts"]):
            p.append(f"call {i}: ts not finite")
            continue
        if type(c["ok"]) is not bool:
            p.append(f"call {i}: ok not boolean")
        elif c["ok"] is False and not (type(c["errno"]) is int and c["errno"] > 0):
            p.append(f"call {i}: failed call without a positive integer errno")
        elif c["ok"] is True and c["errno"] is not None:
            p.append(f"call {i}: ok call with an errno")
        if "exc" in c and not isinstance(c["exc"], str):
            p.append(f"call {i}: exc not a string")
        if last is not None and c["ts"] < last:
            p.append(f"call {i}: ts goes backwards")
        last = c["ts"]
        if not (ra["t_end"] - CALL_TOLERANCE_S <= c["ts"] <= rb["t_start"] + CALL_TOLERANCE_S):
            p.append(f"call {i}: ts {c['ts']} outside the window between read A and read B")
    return p, False


def is_probe_frame(f, case):
    if f.get("direction") != "guest":
        return False
    ip = f.get("ip") or {}
    if not (ip.get("hdr_ok") and ip.get("src") == GUEST_IP and ip.get("dst") == case["dst"]):
        return False
    k = case["kind"]
    if k == "icmp":
        return ip.get("proto") == 1 and ip.get("tot_len") == int(case["size"]) + 28
    if k == "tcp":
        return ip.get("proto") == 6 and ip.get("sport") == case["lport"] and ip.get("dport") == case["port"]
    if k == "dns":
        label = case["qname"].split(".")[0].encode()
        return ip.get("proto") == 17 and ip.get("dport") == 53 and label in (ip.get("payload") or b"")
    return False


def is_reply_to_guest(f, case):
    """A frame addressed to the guest that comes from the probe's destination IP. From 10.200.0.1 only the allowed service traffic
    (TCP source port 8011) is exempt."""
    if f.get("dst") != S.GUEST_MAC:
        return False
    ip = f.get("ip") or {}
    if not (ip.get("hdr_ok") and ip.get("src") == case["dst"]):
        return False
    if case["dst"] == WORKER_IP and ip.get("proto") == 6 and ip.get("sport") == L.SVC_PORT:
        return False
    return True


def _window(frames, ra, rb, guard):
    return [f for f in frames if counter_window.zone(f["t"], ra, rb, guard) != "outside"]


def _derived_closure(recon, frames, reads, labels, before, after, guard):
    """Annotation only (never used for the verdict): the unchanged R4 closure on a copy."""
    try:
        r2 = copy.deepcopy(recon)
        seq = [reads[x] for x in labels]
        counter_window.close_edges(r2, frames, seq, labels, labels.index(before), labels.index(after), guard)
        cl = r2.get("closure") or {}
        return {"verdict": r2.get("verdict"), "applied": cl.get("applied"), "measurement_errors": cl.get("measurement_errors"),
                "classes": {k: {"state": v.get("state"), "resolved": v.get("resolved"), "reads_used": v.get("reads_used")}
                            for k, v in (cl.get("classes") or {}).items()},
                "note": "annotation under H0; not used for the verdict"}
    except Exception as e:                                        # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def _common_inputs(crec, reads):
    if not isinstance(crec, dict):
        return "record entry is not an object"
    if crec.get("read_error"):
        return f"{crec['read_error']}"
    missing = [lbl for lbl in (crec.get("before"), crec.get("after")) if lbl not in reads]
    if missing:
        return f"counter read(s) {missing} not found"
    return None


def _independent_guest_failures(crec):
    ex = crec.get("exec") if isinstance(crec, dict) else None
    if isinstance(ex, dict) and not ex.get("error") and ex.get("guest_failed") is False:
        return ["guest_connection_failed"]
    return []


def _meas_result(cid, case, crec, meas, indep, **kw):
    """F6: a measurement error never hides an independent FAIL; both are kept (failed + measurement_errors, record fields retained)."""
    keep = {"req": case["req"], "measurement_errors": list(meas), "exec": (crec or {}).get("exec") if isinstance(crec, dict) else None,
            "command": (crec or {}).get("command") if isinstance(crec, dict) else None,
            "control_before": (crec or {}).get("control_before") if isinstance(crec, dict) else None,
            "control_after": (crec or {}).get("control_after") if isinstance(crec, dict) else None}
    keep.update(kw)
    if indep:
        return _result(cid, "FAIL", "FAIL (kèm LỖI PHÉP ĐO: " + "; ".join(meas) + ")", failed=sorted(set(indep)), **keep)
    return _result(cid, "LOI_PHEP_DO", "LỖI PHÉP ĐO (" + "; ".join(meas) + ")", **keep)


def evaluate_guest_case(frames, reads, case, crec, link_before_ok, link_after_ok, guard=GUARD_S):
    cid = case["id"]
    indep = _independent_guest_failures(crec)
    err = _common_inputs(crec, reads)
    if err:
        return _meas_result(cid, case, crec, [err], indep)
    ra, rb = reads[crec["before"]], reads[crec["after"]]
    classes = l2eval.check_classes(None)
    recon = L.reconcile_l2(frames, ra, rb, classes, guard)
    if recon["verdict"] == "ERROR":
        return _meas_result(cid, case, crec, [str(recon.get("error"))], indep, reconciliation=recon)
    window = _window(frames, ra, rb, guard)
    probe = [f for f in window if is_probe_frame(f, case)]
    certain = [f for f in probe if counter_window.zone(f["t"], ra, rb, guard) == "certain"]
    replies = [f for f in window if is_reply_to_guest(f, case)]
    ex = crec.get("exec") if isinstance(crec.get("exec"), dict) else {"error": "not executed"}
    tool_missing = bool(ex.get("error"))
    checks = {
        "probe_packets_hit_expected_counter": all(f["cls"] == case["expected"] for f in certain),
        "no_reply_to_guest": not replies,
    }
    if not tool_missing:
        checks["guest_connection_failed"] = ex.get("guest_failed") is True
    live = case.get("control") is not None
    cstate, cwhy = control_state(case, crec, ra, rb) if live else (None, None)
    detail = {"req": case["req"], "dst": f"{case['kind']} {case['dst']}" + (f":{case['port']}" if case.get("port") else ""),
              "probe_frames": len(probe), "probe_frames_certain": len(certain), "replies_to_guest": len(replies),
              "probe_frame_classes": sorted({f["cls"] for f in probe}), "checks": checks, "control_kind": "live" if live else "rule_check",
              "control_before": crec.get("control_before"), "control_after": crec.get("control_after"), "control_state": cstate, "control_problem": cwhy,
              "reconciliation": {k: recon.get(k) for k in ("verdict", "per_class", "no_counter_frames", "guard_s")},
              "exec": ex, "command": crec.get("command"), "expected_class": case["expected"]}
    # 1. determined failures win over everything that only prevents judging (an invalid control is kept next to them)
    if recon["verdict"] == "FAIL" or not all(checks.values()):
        why = [k for k, v in checks.items() if not v] + (["counter_reconciliation"] if recon["verdict"] == "FAIL" else [])
        if cstate == "invalid":
            detail["measurement_errors"] = [cwhy]
        return _result(cid, "FAIL", "FAIL", failed=why, **detail)
    # 2. the guest could not run the probe
    if tool_missing:
        return _result(cid, "LOI_THUC_THI", f"CHƯA KIỂM CHỨNG (lỗi thực thi: {ex.get('error')})", **detail)
    # 3. no probe frame
    if not probe:
        return _result(cid, "KHONG_TAO_DUOC_GOI", "CHƯA KIỂM CHỨNG (không tạo được gói probe; kết quả công cụ không phải bằng chứng chặn)", **detail)
    # 3b. a control record that is malformed or not bound to this case is a measurement error, never a pass
    if cstate == "invalid":
        return _result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({cwhy})", **detail)
    # 4. verdict function (live or rule-check), D6 label
    pv = {"probe_packets_in_tap0_pcap": True, **checks, "guest_connection_failed": checks.get("guest_connection_failed", True)}
    text, ok = L.probe_verdict_l2(pv, recon, case["expected"], "live" if live else "rule_check", control_alive=(cstate == "alive") if live else None)
    if text == "FAIL":
        return _result(cid, "FAIL", "FAIL", failed=["probe_verdict"], **detail)
    if not ok:
        if recon["verdict"] == "UNVERIFIED":
            detail["derived_closure"] = _derived_closure(recon, frames, reads, list(reads), crec["before"], crec["after"], guard)
        return _result(cid, "CHUA_KIEM_CHUNG", text, **detail)
    if not link_before_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ trước nhóm thử thiếu/không đạt)", **detail)
    if not link_after_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ sau nhóm thử không đạt)", **detail)
    return _result(cid, "DAT" if live else "DAT_KIEM_QUY_TAC", text, **detail)


def is_guest_reply_to_w(f, case):
    """Frame from the guest to the worker that answers a T20 probe (echo reply / SYN-ACK / RST / UDP back)."""
    if f.get("direction") != "guest":
        return False
    ip = f.get("ip") or {}
    if not (ip.get("hdr_ok") and ip.get("src") == GUEST_IP and ip.get("dst") == WORKER_IP):
        return False
    k = case["kind"]
    if k == "w_icmp":
        return ip.get("proto") == 1
    if k == "w_tcp":
        return ip.get("proto") == 6 and ip.get("sport") == case["port"] and ip.get("dport") == case["sport"]
    if k == "w_udp":
        return ip.get("proto") == 17 and ip.get("sport") == case["port"] and ip.get("dport") == case["sport"]
    return False


def evaluate_w_case(frames, reads, case, crec, banner, link_before_ok, link_after_ok, guard=GUARD_S):
    """`banner` is the group's guest_banner_control RECORD (or None); it is validated here (banner_state)."""
    cid = case["id"]
    if isinstance(crec, dict) and crec.get("not_run"):
        return _result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG (không chạy: {crec['not_run']})", req=case["req"], not_sent=bool(crec.get("not_sent")))
    calls = crec.get("calls") if isinstance(crec, dict) else None
    indep = ["connect_succeeded"] if isinstance(calls, list) and any(isinstance(c, dict) and c.get("op") == "connect" and c.get("ok") is True for c in calls) else []
    err = _common_inputs(crec, reads)
    if err:
        return _meas_result(cid, case, crec, [err], indep, calls=calls)
    ra, rb = reads[crec["before"]], reads[crec["after"]]
    recon = L.reconcile_l2(frames, ra, rb, l2eval.check_classes(None), guard)
    if recon["verdict"] == "ERROR":
        return _meas_result(cid, case, crec, [str(recon.get("error"))], indep, calls=calls, reconciliation=recon)
    delta, derr = L.strict_delta(ra, rb, ["drop_out"])
    if derr:
        return _meas_result(cid, case, crec, [derr], indep, calls=calls)
    drop_out = delta["drop_out"]
    problems, setup = validate_calls(case, crec, ra, rb)
    window = _window(frames, ra, rb, guard)
    outside = [f for f in window if f.get("direction") == "worker" and f.get("cls") == "worker_unexpected"]
    replies = [f for f in window if is_guest_reply_to_w(f, case)]
    detail = {"req": case["req"], "calls": calls, "calls_count": len(calls) if isinstance(calls, list) else None, "drop_out_delta": drop_out,
              "worker_frames_outside_allowlist": len(outside), "replies_from_guest": len(replies), "call_record_problems": problems,
              "reconciliation": {k: recon.get(k) for k in ("verdict", "per_class", "no_counter_frames", "guard_s")},
              "evidence_kind": "rule_check", "note": "drop_out is dropped before the tap0 capture point: not reconciled with the pcap; the evidence is the counter, "
              "the recorded calls and the ABSENCE of frames"}
    bstate, bwhy = (None, None)
    if case.get("banner_control"):
        bstate, bwhy = banner_state(banner, ra, case)
        detail.update(banner_state=bstate, banner_problem=bwhy, guest_banner_control=banner)
    failed = list(indep)
    if outside:
        failed.append("worker_frame_outside_allowlist_on_tap0")
    if replies:
        failed.append("guest_replied_to_worker")
    if recon["verdict"] == "FAIL":
        failed.append("counter_reconciliation")
    if failed:
        errors = problems + ([bwhy] if bstate in ("invalid", "not_alive", "tool_missing") else [])
        if errors:
            detail["measurement_errors"] = errors
        return _result(cid, "FAIL", "FAIL", failed=sorted(set(failed)), **detail)
    if problems and not setup:
        return _result(cid, "LOI_PHEP_DO", "LỖI PHÉP ĐO (hồ sơ lần gọi: " + "; ".join(problems) + ")", **detail)
    if setup:
        if problems:
            return _result(cid, "LOI_PHEP_DO", "LỖI PHÉP ĐO (hồ sơ lỗi thiết lập: " + "; ".join(problems) + ")", **detail)
        return _result(cid, "LOI_THUC_THI", "CHƯA KIỂM CHỨNG (công cụ phía worker không gửi được: " + str(calls[0].get("exc")) + ")", **detail)
    if drop_out <= 0:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (drop_out không tăng: không chứng minh gói đã tới hook)", **detail)
    if any(c.get("ok") is not False for c in calls):
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (có lần gọi không thất bại)", **detail)
    if recon["verdict"] == "UNVERIFIED":
        detail["derived_closure"] = _derived_closure(recon, frames, reads, list(reads), crec["before"], crec["after"], guard)
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm hoặc khung không có bộ đếm)", **detail)
    if not link_before_ok or not link_after_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ trước/sau nhóm thử không đạt)", **detail)
    label_live = False
    if case.get("banner_control"):
        if bstate == "invalid":
            return _result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO (đối chứng banner: {bwhy})", **detail)
        if bstate == "tool_missing":
            return _result(cid, "LOI_THUC_THI", f"CHƯA KIỂM CHỨNG (đối chứng banner không chạy được: {bwhy})", **detail)
        if bstate == "missing":
            return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (thiếu hồ sơ đối chứng banner của guest)", **detail)
        if bstate == "not_alive":
            return _result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG (đối chứng banner không đúng cửa sổ: {bwhy})", **detail)
        if bstate == "dead_valid" and not BANNER_DEAD_AS_RULE_CHECK:
            return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (dịch vụ guest không trả banner: nhãn kiểm quy tắc chưa được điều phối chốt)", **detail)
        label_live = bstate == "alive"
    return _result(cid, "DAT" if label_live else "DAT_KIEM_QUY_TAC", "ĐẠT" if label_live else "ĐẠT (kiểm quy tắc)",
                   control_kind="guest_banner" if label_live else "rule_check", **detail)


def _validate_record(record, arch, tap_mac):
    p = []
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        return ["record schema missing/unknown"]
    for k in ("guest_cases", "w_cases"):
        if not isinstance(record.get(k), list) or not all(isinstance(c, dict) for c in record[k]):
            p.append(f"{k} must be a list of objects")
    if p:
        return p
    if arch is not None and record.get("arch") != arch:
        p.append(f"record arch {record.get('arch')!r} != {arch!r}")
    try:
        if L._norm_mac(record.get("tap_mac")) != L._norm_mac(tap_mac):
            p.append("record tap_mac differs from the evaluated TAP MAC")
    except ValueError:
        p.append("record tap_mac invalid")
    seen = [c.get("id") for c in record["guest_cases"] + record["w_cases"]]
    for cid in ALL_CASE_IDS:
        n = seen.count(cid)
        if n != 1:
            p.append(f"case {cid} recorded {n} times")
    p += [f"unknown case id {i!r}" for i in seen if i not in ALL_CASE_IDS]
    return p


def evaluate_group(pcap, counters_file, tap_mac, record, lan_dns=LAN_DNS_DEFAULT, lan_other=None, guard=GUARD_S):
    """-> {"cases": [...], "record_problems": [...], "group_exit": int, ...}. Capture/counter-file/record problems make cases LOI_PHEP_DO."""
    out = {"schema": "ct01-b1-eval/1", "guard_s": guard, "assumption": l2eval.ASSUMPTION, "closure_used_for_verdict": False,
           "record_problems": [], "cases": []}
    arch = record.get("arch") if isinstance(record, dict) else None
    probs = _validate_record(record, arch, tap_mac)
    out["record_problems"] = probs
    out["arch"] = arch
    if probs and not (isinstance(record, dict) and isinstance(record.get("guest_cases"), list) and isinstance(record.get("w_cases"), list)):
        out["cases"] = [_result(cid, "LOI_PHEP_DO", "LỖI PHÉP ĐO (hồ sơ nhóm không hợp lệ)") for cid in ALL_CASE_IDS]
        out["group_exit"] = group_exit(out)
        return out
    try:
        guest_cases = {c["id"]: c for c in build_guest_cases(arch, lan_dns, lan_other)}
    except ValueError as e:
        out["cases"] = [_result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({e})") for cid in ALL_CASE_IDS]
        out["group_exit"] = group_exit(out)
        return out
    w_cases = {c["id"]: c for c in build_w_cases()}
    out["service_link_before"], out["service_link_after"] = record.get("service_link_before"), record.get("service_link_after")
    if record.get("skipped"):
        out["cases"] = [_result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG ({record['skipped']})") for cid in ALL_CASE_IDS]
        out["group_exit"] = group_exit(out)
        return out
    err = None
    try:
        frames = L.classified_frames(pcap, tap_mac)
        reads = l2eval.load_reads(counters_file)
    except L.FrameReadError as e:
        err = f"capture read error: {e}"
    except l2eval.InputError as e:
        err = f"invalid measurement data: {e}"
    except ValueError as e:
        err = f"invalid argument: {e}"
    if err:
        # Reading the capture/counter file is not a prerequisite to retaining
        # a guest/connect failure already recorded independently of that file.
        for cid in ALL_CASE_IDS:
            sources = [c for c in record["guest_cases"] + record["w_cases"] if isinstance(c, dict) and c.get("id") == cid]
            case = (guest_cases if cid in guest_cases else w_cases)[cid]
            indep = []
            for source in sources:
                if cid in guest_cases:
                    indep.extend(_independent_guest_failures(source))
                elif isinstance(source.get("calls"), list) and any(isinstance(c, dict) and c.get("op") == "connect" and c.get("ok") is True for c in source["calls"]):
                    indep.append("connect_succeeded")
            first = sources[0] if sources else {}
            keep = {"source_records": sources}
            if cid in w_cases:
                keep.update(calls=first.get("calls"), guest_banner_control=record.get("guest_banner_control"))
            out["cases"].append(_meas_result(cid, case, first, [err], indep, **keep))
        out["group_exit"] = group_exit(out)
        return out
    lb, la = link_ok(record.get("service_link_before")), link_ok(record.get("service_link_after"))
    banner = record.get("guest_banner_control")
    done = set()
    for crec in record["guest_cases"]:
        cid = crec.get("id")
        if cid in guest_cases and cid not in done:
            done.add(cid)
            if crec.get("not_run"):
                out["cases"].append(_result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG (không chạy: {crec['not_run']})", req=guest_cases[cid]["req"]))
            else:
                out["cases"].append(evaluate_guest_case(frames, reads, guest_cases[cid], crec, lb, la, guard))
        else:
            out["cases"].append(_result(str(cid), "LOI_PHEP_DO", "LỖI PHÉP ĐO (case id không hợp lệ hoặc lặp)"))
    for crec in record["w_cases"]:
        cid = crec.get("id")
        if cid in w_cases and cid not in done:
            done.add(cid)
            out["cases"].append(evaluate_w_case(frames, reads, w_cases[cid], crec, banner, lb, la, guard))
        else:
            out["cases"].append(_result(str(cid), "LOI_PHEP_DO", "LỖI PHÉP ĐO (case id không hợp lệ hoặc lặp)"))
    for cid in ALL_CASE_IDS:
        if cid not in done:
            out["cases"].append(_result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (ca không có trong hồ sơ)"))
    out["group_complete"] = not probs and all(c["category"] in OK_CATEGORIES or c["category"] == "CHUA_KIEM_CHUNG" for c in out["cases"])
    out["group_exit"] = group_exit(out)
    return out


def group_exit(result):
    """FAIL 1 > LOI_PHEP_DO 2 > not judged 4 > all DAT 0; any record problem forbids 0."""
    cats = {c["category"] for c in result.get("cases", [])}
    if not result.get("cases"):
        return 2
    if "FAIL" in cats:
        return 1
    if "LOI_PHEP_DO" in cats:
        return 2
    if result.get("record_problems"):
        return 4
    return 4 if cats - set(OK_CATEGORIES) else 0


# ------------------------------------------------------------------ T20 N4/N5: route lookups (read-only, D3)
def parse_proc_net_route(text):
    """/proc/net/route -> [(iface, dest_int, gw_int, mask_int, flags)]; raises ValueError on a malformed table."""
    rows = []
    lines = text.splitlines()
    if not lines or not lines[0].startswith("Iface"):
        raise ValueError("not a /proc/net/route table")
    for l in lines[1:]:
        f = l.split()
        if len(f) < 8:
            raise ValueError(f"short route row: {l!r}")
        d, g, m = (int.from_bytes(bytes.fromhex(x), "little") for x in (f[1], f[2], f[7]))
        rows.append((f[0], d, g, m, int(f[3], 16)))
    return rows


def lookup(rows, ip):
    a = int(ipaddress.IPv4Address(ip))
    best = None
    for iface, d, g, m, flags in rows:
        if flags & 1 and (a & m) == d:                    # RTF_UP
            plen = bin(m).count("1")
            if best is None or plen > best[0]:
                best = (plen, iface, str(ipaddress.IPv4Address(g)) if g else None, str(ipaddress.IPv4Address(d)), m)
    return best


def _rc_problem(rc, what):
    if type(rc) is not int or isinstance(rc, bool):
        return f"{what}: exit status {rc!r} is not an integer"
    if rc != 0:
        return f"{what}: command returned rc {rc} (output is not accepted as a snapshot)"
    return None


def evaluate_routes(n4_text, n5_text, worker_ip, sandbox_gw, sandbox_bridge, target=GUEST_IP, n4_rc=None, n5_rc=None):
    """-> list of two result dicts. Both lookups are configuration evidence (D3), NOT a live control, and no packet is sent.
    N4 (manager main-table snapshot): a unique longest-prefix route must NOT be via the worker nor connected.
    Equal-prefix choices all violating this predicate are FAIL; unresolved choices are UNVERIFIED.
    A fixed sandbox gateway is contextual topology, not a mandatory design criterion.
    This /proc/net/route lookup does not verify RPDB/policy routing or reachability;
    N5 (host): `ip route get` must not go via the worker nor out of the sandboxnet bridge."""
    res = []
    try:
        problem = _rc_problem(n4_rc, "manager `cat /proc/net/route`")
        if problem:
            raise ValueError(problem)
        rows = parse_proc_net_route(n4_text)
        best = lookup(rows, target)
        if best is None:
            r4 = _result("T20-N4", "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (không có route khớp trong bảng của manager)", evidence_kind="route_lookup")
        else:
            plen, iface, gw, dest, mask = best
            bad = gw is None or gw == worker_ip
            r4 = _result("T20-N4", "FAIL" if bad else "DAT_KIEM_QUY_TAC", "FAIL" if bad else "ĐẠT (lookup bảng main không qua worker; chưa kiểm policy routing/reachability)",
                         evidence_kind="route_lookup", lookup_scope="proc_net_route_main_only",
                         policy_routing_verified=False, reachability_verified=False, matched={"iface": iface, "gateway": gw, "prefix_len": plen, "dest": dest},
                         sandbox_gateway_context=sandbox_gw, worker_ip_context=worker_ip)
            # /proc/net/route cannot resolve equal-prefix selection (metric/multipath/policy).
            # Do not choose the first non-worker row and silently certify the others.
            target_int = int(ipaddress.IPv4Address(target))
            candidates = [r for r in rows if r[4] & 1 and target_int & r[3] == r[1] and bin(r[3]).count("1") == plen]
            if len(candidates) != 1:
                worker_int = int(ipaddress.IPv4Address(worker_ip))
                choices = [{"iface": r[0], "gateway": str(ipaddress.IPv4Address(r[2])) if r[2] else None,
                            "prefix_len": plen, "dest": str(ipaddress.IPv4Address(r[1])),
                            "violates_predicate": r[2] == 0 or r[2] == worker_int} for r in candidates]
                all_bad = all(r["violates_predicate"] for r in choices)
                r4.update(category="FAIL" if all_bad else "CHUA_KIEM_CHUNG", ok=False,
                          verdict="FAIL (mọi route cùng prefix đều qua worker hoặc connected guest)" if all_bad else
                          "CHƯA KIỂM CHỨNG (nhiều route cùng prefix; không xác định lựa chọn từ bảng main)",
                          matched=None, route_candidates=choices, selection_verified=False)
    except ValueError as e:
        r4 = _result("T20-N4", "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({e})", evidence_kind="route_lookup")
    res.append(r4)
    t = (n5_text or "").strip().splitlines()
    m = re.match(r"^" + re.escape(target) + r"\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)", t[0]) if t else None
    problem5 = _rc_problem(n5_rc, "host `ip route get`")
    if problem5:
        r5 = _result("T20-N5", "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({problem5})", evidence_kind="route_lookup", raw=(t[:1] or [""])[0][:200])
    elif not m:
        r5 = _result("T20-N5", "LOI_PHEP_DO", "LỖI PHÉP ĐO (đầu ra `ip route get` không đọc được)", evidence_kind="route_lookup", raw=(t[:1] or [""])[0][:200])
    else:
        via, dev = m.group(1), m.group(2)
        bad = via == worker_ip or dev == sandbox_bridge or via is None and dev == sandbox_bridge
        r5 = _result("T20-N5", "FAIL" if bad else "DAT_KIEM_QUY_TAC", "FAIL" if bad else "ĐẠT (tra route, không phải đối chứng sống)",
                     evidence_kind="route_lookup", matched={"via": via, "dev": dev}, sandbox_bridge=sandbox_bridge)
    res.append(r5)
    return res


# ------------------------------------------------------------------ CLI
def main(argv):
    ap = argparse.ArgumentParser(description="evaluate a recorded B1 group (offline)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--counters", required=True)
    ap.add_argument("--tap-mac", required=True)
    ap.add_argument("--record", required=True)
    ap.add_argument("--lan-other", required=True)
    ap.add_argument("--lan-dns", default=LAN_DNS_DEFAULT)
    ap.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        record = json.load(open(a.record))
        if not isinstance(record, dict):
            raise ValueError("group record is not an object")
        res = evaluate_group(a.pcap, a.counters, a.tap_mac, record, a.lan_dns, a.lan_other)
    except (OSError, ValueError) as e:
        res = {"error": f"{type(e).__name__}: {e}", "cases": [], "group_exit": 2}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False, default=str)
            f.write("\n")
    for c in res["cases"]:
        print(f"{c['id']}: {c['verdict']}")
    if res.get("error"):
        print(f"ERROR: {res['error']}")
        return 2
    return res["group_exit"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
