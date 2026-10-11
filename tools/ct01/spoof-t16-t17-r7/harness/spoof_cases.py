#!/usr/bin/env python3
"""R1 — T16/T17 cases: MAC change in the guest and spoofed source IPv4 (prepared OFFLINE; not executed; derived from arp_cases.py, same record/restore/evaluation contract).

Scope (plan docs/ct01-remaining-tests-plan.md T16, T17; decision D2 = temporary guest changes with restore from the state recorded before):
    T16-M1  guest NIC gets MAC 52:54:00:de:ad:01, then the service link (T01) is tried with --local-port 31016   expected l2_bad_mac
            control: T01 from the real MAC immediately before the change (same IP/protocol/port) + service link after the restore
    T17-P1  source 10.200.0.5 (secondary /32, outside 10.200.0.0/30) -> 10.200.0.1:8011, --local-port 31171   expected drop_spoof
    T17-P2  source 192.168.60.10 -> 10.200.0.1:8011, --local-port 31172                                         expected drop_spoof
    T17-P4  source 10.200.0.5 -> 1.1.1.1:443, --local-port 31174                                                expected drop_spoof (before drop_public)
    T17-P5  ping -c 3 -s 1405 -I 192.168.60.10 192.168.60.1  (IPv4 total length 1433 < MTU 1500: ONE datagram per echo)   expected drop_spoof +3
            P1/P2: control = T01 from 10.200.0.2 immediately before; P4/P5: live control from the controller side (callback)
Review R2 (S1-S3): the controls are schema/binding/window checked and re-validated by the evaluator (control_problems); a probe frame must match the case's
whole tuple (is_probe_frame); T17-P5 uses ICMP payload 1405 (registry value; 1705 gave IPv4 total length 1733 > MTU 1500, i.e. two fragments whose first one is not
unique), as B1 did for 1606 -> 1406.
R7 (launch 43ef2bc6..., R6, ARM): the spoofed source of P1/P4 was 10.200.0.3 = the BROADCAST address of the guest's own 10.200.0.0/30. With it the real
identity 10.200.0.2 (not the spoofed address) left on the wire (P1 HTTP 200, P4 three real SYNs; P2/P5 with 192.168.60.10 put the spoofed source on the wire, the NAT
bypass and the restore worked). The source of P1/P4 is now 10.200.0.5: a secondary /32 outside the /30, like the proven 192.168.60.10. The design text names .3; this
is the choice of the assistant (documented, to be confirmed by the reviewer).
NOT covered: T17-P3 (postponed, D1), spoofing TAP_MAC (D5), raw packets (no tool is added), IP options, fragmentation.
Not measured by this harness: server.py request log and /tmp/sandbox_stop_requested (stated as limits in every result).
Every guest/kernel behaviour above is an ASSUMPTION; the offline tests only SIMULATE it. The commands need the worker-side tap MAC and the
architecture (record["tap_mac"], record["arch"]): the contract is recomputed from those two validated values.

Layers (all injectable for offline tests):
  build_cases()                         case definitions (commands built from the case, sizes from signatures.py)
  run_group(runner, read_counters, service_link, worker_neigh, control, cases, iface)
        service link before the group -> per case: worker neighbours (before) -> guest_state.GuestChange
        [state saved] -> read A -> setup -> trigger -> settle -> read B -> [state restored, ALSO after an
        error] -> worker neighbours (after) -> live control (A1/A2) -> service link after the case.
        Execution contract (06B-4HR): setup/settle/`ip link` rc 0; ping rc 0 or 1 only; anything else, rc 127,
        "not found" or a console exception is an execution error that stops the case's remaining steps (read B
        and the restore still happen). A failed restore stops the group: the remaining cases are not run.
  evaluate_group(pcap, counters_file, tap_mac, record)
        reviewed l2frames.classified_frames / reconcile_l2 / probe_verdict_l2 and l2eval.load_reads.

ĐẠT only with: the right probe frames (ARP request fields), the expected counter (all compared classes
reconciled), a complete execution record (every step, rc within the contract, valid guest baseline, restore
evidence), service link before AND after the case, a successful restore, worker neighbours valid and unchanged,
and (A1/A2) a live control. No probe frame -> CHƯA KIỂM CHỨNG (never evidence of blocking).
Precedence FAIL > LỖI PHÉP ĐO > CHƯA KIỂM CHỨNG > ĐẠT (06B-4HR: failure evidence is collected BEFORE any
measurement error can end the evaluation, and both are kept in the result). Guard 20 ms (unmeasured).
"""
import argparse
import collections
import ipaddress
import json
import re
import sys
import time

import counter_window
import guest_state as GS
import l2eval
import l2frames as L
import signatures as S

GUARD_S = counter_window.GUARD_S
SETTLE_S = 3            # after the trigger: kernel ARP retries (mcast_solicit 3 x 1 s [GĐ G7]) end before read B
PING_WAIT_S = 2         # busybox ping -W
PING_RC_OK = (0, 1)     # 06B-4HR: the only ping outcomes accepted by the contract (1 = no reply, expected)
CASE_IDS = ("T16-M1", "T17-P1", "T17-P2", "T17-P4", "T17-P5")
FAKE_MAC = S.SPOOF_MACS[0]
SVC_URL = f"http://{S.WORKER_GUEST_IP}:{L.SVC_PORT}/api/v1/sandbox-worker"
CURL_TIMEOUT_S = 4
CURL_MAX_S = 6
CATEGORIES = ("DAT", "DAT_KIEM_QUY_TAC", "FAIL", "LOI_PHEP_DO", "LOI_THUC_THI", "KHONG_TAO_DUOC_GOI",
              "CHUA_KIEM_CHUNG")
NOT_RUN = "CHƯA KIỂM CHỨNG (cấu hình guest chưa khôi phục ở ca trước: ca này không chạy)"
PHASES = ("setup", "trigger", "settle")
_TAP_MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
_ARCH = ("ARM", "MIPS")


def _iface_ok(iface):
    if not isinstance(iface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface):
        raise ValueError(f"bad interface name {iface!r}")
    return iface


MTU = 1500       # IPv4 MTU of the guest probe interface (ARM eth1, MIPS br-lan), observed in 06B-4G console logs (same constant as b1_cases.MTU)


def build_cases():
    cases = _build_cases()
    for c in cases:
        if c["kind"] == "t17_icmp" and int(c["size"]) + 28 > MTU:      # one unfragmented datagram per echo, never beyond the observed MTU
            raise ValueError(f"{c['id']}: ICMP size {c['size']} gives IPv4 total length {int(c['size']) + 28} > MTU {MTU}")
    return cases


def _build_cases():
    return [
        {"id": "T16-M1", "kind": "t16", "expected": "l2_bad_mac", "control_kind": "service_link", "port": S.PROBE_PORTS["T16-M1"],
         "mac": FAKE_MAC, "tier": "mandatory"},
        {"id": "T17-P1", "kind": "t17_svc", "src": "10.200.0.5", "expected": "drop_spoof", "control_kind": "service_link",
         "port": S.PROBE_PORTS["T17-P1"], "tier": "mandatory"},
        {"id": "T17-P2", "kind": "t17_svc", "src": "192.168.60.10", "expected": "drop_spoof", "control_kind": "service_link",
         "port": S.PROBE_PORTS["T17-P2"], "tier": "coverage"},
        {"id": "T17-P4", "kind": "t17_out", "src": "10.200.0.5", "dst": "1.1.1.1", "dport": 443, "expected": "drop_spoof",
         "control_kind": "live", "port": S.PROBE_PORTS["T17-P4"], "tier": "coverage"},
        {"id": "T17-P5", "kind": "t17_icmp", "src": "192.168.60.10", "dst": "192.168.60.1", "size": S.ICMP4_SIZES["T17-P5"],
         "expected": "drop_spoof", "control_kind": "live", "tier": "coverage"},
    ]


# Tier (matrix MATRIX-CORRECTED §4): T16 and T17-P1 are the design requirements (mandatory); T17-P2/P4/P5 are plan-level coverage (valuable, NOT a
# requirement of acceptance). Postponed and NOT built: T17-P3 (D1), spoofing TAP_MAC (D5).
# GATE POLICY (stated, not hidden): this suite's run outcome is conservative: every one of the five cases must be DAT for "PASS", and a coverage case that is
# not DAT makes the run UNVERIFIED, which stops MIPS in the runner. That is a property of the run gate, NOT a statement that coverage is mandatory:
# the evaluation reports the mandatory and the coverage verdicts separately (spoof_harness: tiers, gate_policy). A FAIL anywhere is a FAIL; a coverage
# case without a live control is "not known", not "no defect".
MANDATORY_IDS = ("T16-M1", "T17-P1")
COVERAGE_IDS = ("T17-P2", "T17-P4", "T17-P5")


def ctx_problem(ctx):
    if not isinstance(ctx, dict) or ctx.get("arch") not in _ARCH or not isinstance(ctx.get("tap_mac"), str) \
            or not _TAP_MAC.fullmatch(ctx["tap_mac"]) or ctx["tap_mac"] in (L._norm_mac(S.GUEST_MAC), L._norm_mac(FAKE_MAC)):
        return "context needs arch (ARM|MIPS) and a tap_mac that differs from the guest and the chosen spoof MAC"
    return None


def task_name(ctx):
    return f"06b3b-{ctx['arch'].lower()}-task"


def _curl(case, ctx, extra=""):
    if case["kind"] == "t17_out":
        url = f"http://{case['dst']}:{int(case['dport'])}/ct01-t17-{case['id']}"
    else:
        url = f"{SVC_URL}/get-task/{task_name(ctx)}/file"
    return (f"curl -s -o /dev/null {extra}--local-port {int(case['port'])} --connect-timeout {CURL_TIMEOUT_S} -m {CURL_MAX_S} "
            f"-w 'HTTP=%{{http_code}}\\n' {url}")


def commands(case, iface, ctx=None):
    """-> {"setup": [...], "trigger": [...], "settle": [...]}: the exact busybox commands, nothing else."""
    _iface_ok(iface)
    bad = ctx_problem(ctx)
    if bad:
        raise ValueError(bad)
    k = case["kind"]
    settle = [f"sleep {SETTLE_S}"]
    if k == "t16":
        return {"setup": [f"ip link set dev {iface} down", f"ip link set dev {iface} address {case['mac']}", f"ip link set dev {iface} up"],
                "trigger": [_curl(case, ctx)], "settle": settle}
    src = str(ipaddress.IPv4Address(case["src"]))
    # a static neighbour for the gateway with the worker's TAP MAC: the guest kernel then sends no ARP with the spoofed spa (that ARP would be
    # arp_in_drop and would block the IP packet before it exists); the entry is removed/restored by guest_state from the recorded baseline
    setup = [f"ip addr add {src}/32 dev {iface}", f"arp -i {iface} -s {S.WORKER_GUEST_IP} {ctx['tap_mac']}"]
    if ctx["arch"] == "ARM":
        # R5: R4 run b745b9be put the REAL address 10.200.0.2 on the wire for P1/P2/P4/P5: the ARM image's firewall zone wan (eth1, the probe interface) has
        # masq=1, so a locally chosen source is rewritten. A guest-only, baseline-recorded and restored rule exempts exactly the spoofed /32 from NAT.
        # Whether the spoofed source then really appears on the wire is decided ONLY by the capture (is_probe_frame), never by this command.
        setup.append(f"iptables -t nat -I POSTROUTING 1 -s {src}/32 -j ACCEPT")
    if k in ("t17_svc", "t17_out"):
        trig = [_curl(case, ctx, f"--interface {src} ")]
    elif k == "t17_icmp":
        trig = [f"ping -c 3 -W {PING_WAIT_S} -s {int(case['size'])} -I {src} {str(ipaddress.IPv4Address(case['dst']))}"]
    else:
        raise ValueError(f"unknown case kind {k!r}")
    return {"setup": setup, "trigger": trig, "settle": settle}


def owned_nat_rules(case, ctx):
    """R6: the `iptables -t nat -S POSTROUTING` lines the setup of this case inserts (the restore may delete exactly these, never anything else)."""
    if case["kind"] == "t16" or (ctx or {}).get("arch") != "ARM":
        return []
    return [f"-A POSTROUTING -s {ipaddress.IPv4Address(case['src'])}/32 -j ACCEPT"]


def contract_steps(case, iface, ctx=None):
    """[(phase, cmd)] in execution order."""
    c = commands(case, iface, ctx)
    return [(ph, cmd) for ph in PHASES for cmd in c[ph]]


def rc_ok(phase, cmd, rc):
    """Execution contract for one step. The trigger is EXPECTED to fail on the wire: curl rc != 0 (timeout 28, refused 7, no route 7/6, ...) and
    ping rc 0 or 1 are inside the contract; rc 127 or a console exception are not. An HTTP 200 in the output is failure evidence, not a contract
    problem (see determined_problems)."""
    if not isinstance(rc, int) or isinstance(rc, bool):
        return False
    if phase == "trigger" and cmd.startswith("ping "):
        return rc in PING_RC_OK
    if phase == "trigger" and cmd.startswith("curl "):
        return 0 <= rc <= 126 or 128 <= rc <= 255        # anything but 127 (not found); a killed curl is still a curl outcome
    return rc == 0


# ------------------------------------------------------------------ worker neighbours (read in the worker)
NUD_STATES = {"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "NONE"}
NUD_NO_BINDING = {"INCOMPLETE", "FAILED", "NONE"}     # no usable MAC binding: valid kernel states, but say nothing


class NeighReadError(Exception):
    """The worker neighbour table could not be read/parsed: never treated as 'unchanged'."""


def parse_neigh(text):
    """`ip -j neigh show` (worker netns) -> (rows, problems); see parse_neigh_full()."""
    rows, problems, _ = parse_neigh_full(text)
    return rows, problems


def parse_neigh_full(text):
    """-> (rows, problems, unknown). Every row is kept (duplicates are NOT merged);
    rows: [{"dst", "dev", "lladdr" (MAC or None), "states", "binding" (bool)}] for the VALID rows; problems: what
    makes the table unusable as a whole (invalid rows, duplicate (dst, dev)); unknown (06B-4HR1): for every INVALID
    row, (dst or None, dev or None) as far as they can be read - the part of the table whose content is unknown.
    Raises NeighReadError only if the text is not a JSON list (nothing at all can be used)."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as e:
        raise NeighReadError(f"not JSON: {e}") from e
    if not isinstance(data, list):
        raise NeighReadError("not a JSON list")
    rows, problems, unknown = [], [], []
    for i, r in enumerate(data):
        why = _row_problem(r)
        if why:
            problems.append(f"row {i}: {why}: {r!r}")
            unknown.append(_row_identity(r))
            continue
        states = list(r["state"])
        mac = r["lladdr"].lower() if "lladdr" in r else None
        rows.append({"dst": r["dst"], "dev": r["dev"], "lladdr": mac, "states": states,
                     "binding": mac is not None and not (set(states) & NUD_NO_BINDING)})
    seen = collections.Counter((r["dst"], r["dev"]) for r in rows)
    problems += [f"duplicate entry {k[0]} dev {k[1]} ({n} rows)" for k, n in sorted(seen.items()) if n > 1]
    return rows, problems, unknown


def _row_identity(r):
    """(dst, dev) of an invalid row as far as each can be read, else None: what the unknown row may stand for."""
    if not isinstance(r, dict):
        return (None, None)
    dst, dev = r.get("dst"), r.get("dev")
    try:
        dst = str(ipaddress.ip_address(dst)) if isinstance(dst, str) else None
    except ValueError:
        dst = None
    dev = dev if isinstance(dev, str) and re.fullmatch(r"[A-Za-z0-9_.@-]{1,32}", dev) else None
    return (dst, dev)


def _maybe(unknown, dst=None, dev=None):
    """Could one of the unknown (invalid) rows be an entry for this dst/dev?"""
    return any((u_dst is None or dst is None or u_dst == dst) and (u_dev is None or dev is None or u_dev == dev)
               for u_dst, u_dev in unknown)


def _row_problem(r):
    if not isinstance(r, dict):
        return "not an object"
    dst, dev = r.get("dst"), r.get("dev")
    if not isinstance(dst, str):
        return "dst missing or not a string"
    try:
        ipaddress.ip_address(dst)
    except ValueError:
        return "dst is not an IP address"
    if not isinstance(dev, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,32}", dev):
        return "dev missing or invalid"
    st = r.get("state")
    if not isinstance(st, list) or not st or not all(isinstance(x, str) and x in NUD_STATES for x in st):
        return "state missing, empty or not a list of known NUD states"
    if len(st) != 1:
        # 06B-4HR1: a neighbour entry is in exactly ONE NUD state [Kernel, not verified on real data]; a combination
        # such as PERMANENT+FAILED is contradictory data, never a usable binding
        return "more than one NUD state (contradictory combination)"
    if "lladdr" in r:
        if not isinstance(r["lladdr"], str) or not re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", r["lladdr"]):
            return "lladdr present but not a MAC address"
    elif not set(st) & NUD_NO_BINDING:
        return "lladdr missing for a state that needs a MAC binding"
    return None


def neigh_check(before_text, after_text, watch):
    """-> {"fail": [...], "invalid": [...], "inconclusive": [...]}. Evidence is collected from every VALID row
    even when the table also has problems (a valid abnormal row is never hidden by a duplicate or a bad row).
    fail:          guest MAC on a device other than tap0 (after); tap0 entries differ before/after; the MANDATORY
                   entry 10.200.0.2 on tap0 is, in a valid row, not a usable binding in the single state PERMANENT
                   with the guest MAC, or is absent from a table that has no unreadable row that could be it; a
                   watched IP that had a binding before has, after, a binding on another device or with another MAC.
    invalid:       before/after not readable, invalid rows (incl. contradictory state combinations), duplicate
                   entries (-> LỖI PHÉP ĐO unless fail). 06B-4HR1: unreadable rows are kept as UNKNOWN; nothing about
                   an entry they could stand for is inferred from the filtered list (no "missing", no "changed").
    inconclusive:  a watched IP that had a binding before is missing after, or is left without a binding
                   (INCOMPLETE/FAILED/NONE): not enough to conclude (-> CHƯA KIỂM CHỨNG).
    Dynamic state changes of a binding that keeps device and MAC (REACHABLE <-> STALE <-> DELAY <-> PROBE) are
    normal and not reported."""
    guest = L._norm_mac(S.GUEST_MAC)
    out = {"fail": [], "invalid": [], "inconclusive": []}
    parsed, unk = {}, {}
    for name, text in (("before", before_text), ("after", after_text)):
        try:
            rows, probs, unknown = parse_neigh_full(text)
            parsed[name], unk[name] = rows, unknown
            out["invalid"] += [f"{name}: {p}" for p in probs]
        except NeighReadError as e:
            parsed[name], unk[name] = None, [(None, None)]
            out["invalid"].append(f"{name}: not readable: {e}")
    b, a = parsed["before"], parsed["after"]
    if a is not None:
        for r in a:
            if r["dev"] != "tap0" and r["lladdr"] == guest:
                out["fail"].append(f"neighbour {r['dst']} dev {r['dev']} has the guest MAC")
        # mandatory entry: 10.200.0.2 on tap0, PERMANENT, guest MAC, usable binding (06B-4HR1)
        tap_after = [r for r in a if r["dev"] == "tap0" and r["dst"] == S.GUEST_IP]
        wrong = [r for r in tap_after if not (r["lladdr"] == guest and r["states"] == ["PERMANENT"] and r["binding"])]
        if wrong:
            out["fail"].append(f"tap0 neighbour {S.GUEST_IP} is not a usable PERMANENT {guest} after the case: {wrong}")
        elif not tap_after:
            if _maybe(unk["after"], S.GUEST_IP, "tap0"):     # HR4: an unreadable row may be it: unknown, not missing
                out["invalid"].append(f"after: mandatory tap0 neighbour {S.GUEST_IP} not readable (unknown, not missing)")
            else:
                out["fail"].append(f"tap0 neighbour {S.GUEST_IP} missing after the case (valid table)")
    if a is not None and b is not None:
        if _maybe(unk["before"], dev="tap0") or _maybe(unk["after"], dev="tap0"):
            out["invalid"].append("tap0 neighbours not comparable before/after: unreadable rows")
        else:
            key = lambda rows: sorted((r["dst"], r["lladdr"] or "", tuple(r["states"]) == ("PERMANENT",),  # noqa: E731
                                       r["binding"]) for r in rows if r["dev"] == "tap0")
            if key(b) != key(a):
                out["fail"].append(f"tap0 neighbours changed: {key(b)} -> {key(a)}")
        for ip in watch:
            if _maybe(unk["before"], ip) or _maybe(unk["after"], ip):
                out["invalid"].append(f"watched {ip}: not comparable before/after: unreadable rows")
                continue
            bb = {(r["dev"], r["lladdr"]) for r in b if r["dst"] == ip and r["binding"]}
            if not bb:
                continue                      # nothing known before: nothing to compare
            aa = [r for r in a if r["dst"] == ip]
            ab = {(r["dev"], r["lladdr"]) for r in aa if r["binding"]}
            if not aa:
                out["inconclusive"].append(f"watched {ip}: entry {sorted(bb)} missing after the case")
                continue
            for dev, mac in sorted(ab - bb):      # another MAC, or the same/another MAC on another device
                out["fail"].append(f"watched {ip}: binding {mac} dev {dev} after the case, before {sorted(bb)}")
            if not ab:
                out["inconclusive"].append(f"watched {ip}: no usable binding after the case "
                                           f"({[r['states'] for r in aa]}; before {sorted(bb)})")
            elif bb - ab:
                out["inconclusive"].append(f"watched {ip}: binding(s) {sorted(bb - ab)} missing after the case")
    return out

def watch_ips(case):
    return [S.WORKER_GUEST_IP] + ([case["src"]] if case["kind"] != "t16" else [])


# ------------------------------------------------------------------ execution (prepared, not run here)
def _call(fn, *a):
    try:
        return fn(*a), None
    except Exception as e:                                       # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


SERVICE_BINDING_KEYS = {"case", "role", "arch", "src", "dst", "port", "proto", "request"}
CONTROL_KEYS = {"ok", "detail", "ts_start", "ts_end", "binding"}
LINK_DETAIL_KEYS = {"rc", "http_code", "sha256", "expected_sha256", "output_tail"}
_HEX64 = re.compile(r"[0-9a-f]{64}")


def service_binding(cid, arch, role):
    """Made by run_group (never by a callback): which request, from which identity, to which destination, for which case/phase."""
    return {"case": cid, "role": role, "arch": arch, "src": S.GUEST_IP, "dst": S.WORKER_GUEST_IP, "port": L.SVC_PORT, "proto": "tcp",
            "request": "GET get-task/T/file"}


def live_binding(case, arch):
    return {"case": case["id"], "role": "live_control", "arch": arch, "src": "worker", "dst": case.get("dst"),
            "port": case.get("dport"), "proto": "tcp" if case["kind"] == "t17_out" else "icmp",
            "kind": "tcp_connect" if case["kind"] == "t17_out" else "icmp_echo"}


def _finite_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and counter_window._finite(v)


def _timed(rec):
    return _finite_num(rec.get("ts_start")) and _finite_num(rec.get("ts_end")) and rec["ts_start"] <= rec["ts_end"]


def _link(service_link, *args, binding=None):
    """service_link(role, case_id): role None = before the group, "control" = T01 right before a case's change, "after" = after its restore.
    The record carries the time span of the call and the binding made here."""
    t0 = time.time()
    try:
        ok, detail = service_link(*args)
    except Exception as e:                                       # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    return {"ok": ok is True, "detail": detail, "ts_start": t0, "ts_end": time.time(), "binding": binding}


def service_state_problems(state, want_binding, fixture_sha):
    """-> (problems, alive). Shape and binding of one service-link record (control, before the group, after a restore).
    alive only with ok True AND the detail proving it: HTTP 200, rc 0, the response hash equal to the fixture hash."""
    if not isinstance(state, dict) or set(state) != CONTROL_KEYS:
        return [f"service-link record is not an object with exactly {sorted(CONTROL_KEYS)}"], False
    p = []
    if not isinstance(state["ok"], bool):
        p.append("ok is not a boolean")
    if not _timed(state):
        p.append("ts_start/ts_end missing, not finite or out of order")
    if state["binding"] != want_binding:
        p.append(f"binding {state['binding']!r} != {want_binding!r}")
    d = state["detail"]
    if state["ok"] is True:
        if not isinstance(d, dict) or set(d) != LINK_DETAIL_KEYS:
            p.append(f"ok=true without a detail object with exactly {sorted(LINK_DETAIL_KEYS)}")
        else:
            if not (isinstance(fixture_sha, str) and _HEX64.fullmatch(fixture_sha)):
                p.append("fixture hash of the record missing/invalid")
            elif not (d["rc"] == 0 and type(d["rc"]) is int and d["http_code"] == "200" and d["sha256"] == fixture_sha == d["expected_sha256"]):
                p.append(f"ok=true but the evidence is not HTTP 200 + the fixture hash: {{rc:{d['rc']!r}, http:{d['http_code']!r}}}")
    return p, (state["ok"] is True and not p)


def live_state_problems(case, state, arch):
    """-> (problems, alive) for a live control (T17-P4: TCP connect, T17-P5: ICMP echo) made by the worker."""
    if not isinstance(state, dict) or set(state) != CONTROL_KEYS:
        return [f"live control record is not an object with exactly {sorted(CONTROL_KEYS)}"], False
    p = []
    if not isinstance(state["ok"], bool):
        p.append("ok is not a boolean")
    if not _timed(state):
        p.append("ts_start/ts_end missing, not finite or out of order")
    want = live_binding(case, arch)
    if state["binding"] != want:
        p.append(f"binding {state['binding']!r} != {want!r}")
    d = state["detail"]
    if state["ok"] is True:
        if not isinstance(d, dict):
            return p + ["ok=true without a detail object"], False
        keys = {"kind", "dst", "dport", "detail", "ts"} | ({"peer"} if want["kind"] == "tcp_connect" else {"reply_from"})
        if set(d) != keys:
            return p + [f"ok=true detail keys {sorted(d)} != {sorted(keys)}"], False
        if d["kind"] != want["kind"] or d["dst"] != want["dst"] or d["dport"] != want["port"]:
            p.append(f"detail kind/dst/dport {(d['kind'], d['dst'], d['dport'])!r} != the case's {(want['kind'], want['dst'], want['port'])!r}")
        if want["kind"] == "tcp_connect" and d["peer"] != [want["dst"], want["port"]]:
            p.append(f"connect peer {d['peer']!r} != {[want['dst'], want['port']]!r}")
        if want["kind"] == "icmp_echo" and (d["reply_from"] != want["dst"] or d["detail"] != f"ICMP echo reply from {want['dst']}"):
            p.append(f"echo reply evidence {d['reply_from']!r}/{d['detail']!r} does not show a reply from {want['dst']}")
        if want["kind"] == "tcp_connect" and not (isinstance(d["detail"], str) and d["detail"].startswith(f"TCP connect to {want['dst']}:{want['port']} completed")):
            p.append(f"connect evidence {d['detail']!r} does not show a completed handshake")
        if not _finite_num(d["ts"]) or (_timed(state) and not state["ts_start"] <= d["ts"] <= state["ts_end"]):
            p.append("detail ts outside the span of the control call")
    return p, (state["ok"] is True and not p)


def _run_steps(runner, steps, r, timeout):
    """Runs the contract steps in order; the first step outside the contract (exception, rc 127 / "not found",
    rc not allowed for that step) is recorded as an execution error and ends the case's steps."""
    for phase, cmd in steps:
        try:
            rc, out = runner.run(cmd, timeout=timeout)
        except Exception as e:                                   # noqa: BLE001
            r["steps"].append({"phase": phase, "cmd": cmd, "rc": None, "out": ""})
            r["exec_error"] = f"{phase} {cmd!r}: {type(e).__name__}: {e}"
            return
        out = out or ""
        r["steps"].append({"phase": phase, "cmd": cmd, "rc": rc, "out": out[-300:]})
        if rc == 127 or "not found" in out:
            r["exec_error"] = f"{phase} {cmd!r}: tool missing in the guest"
            return
        if not rc_ok(phase, cmd, rc):
            r["exec_error"] = f"{phase} {cmd!r}: rc {rc} outside the contract"
            return


# R8: the first case of the group has no earlier counter read within counter_window.CLOSURE_DEADLINE_S (the previous read is the session read
# before boot, taken before boot/topology/service link), so an edge frame at its before-read could never be corroborated (open_boundary).
# ONE extra snapshot is taken inside the first case's guest-state context, right before its own before-read, and separated from it by
# ANCHOR_GAP_S (> the 20 ms guard plus a read, << the 10 s closure deadline). It is only a candidate neighbour read: counter_window.close_edges and
# evaluate_group apply every normal check to it (time order, finite times, class counter present, edge-free for the class, per-segment equations);
# an anchor that fails any of them leaves the case UNVERIFIED / measurement error exactly as before. No guest command is involved.
ANCHOR_LABEL = "spoof group anchor"
ANCHOR_GAP_S = 0.25


def run_group(runner, read_counters, service_link, worker_neigh, control, cases, iface, ctx, timeout=60, anchor=None, sleep=None):
    """runner.run(cmd, timeout) -> (rc, text); read_counters(label); service_link() -> (ok, detail);
    worker_neigh() -> `ip -j neigh show` text of the worker netns; control(case) -> (ok, detail) for live-control
    cases; anchor() takes the ANCHOR_LABEL counter read (optional; once, before the first executed case's before-read). Returns the group
    record. Never raises: every failure is recorded."""
    _iface_ok(iface)
    bad = ctx_problem(ctx)
    rec = {"iface": iface, "arch": (ctx or {}).get("arch"), "tap_mac": (ctx or {}).get("tap_mac"), "cases": [],
           "service_link_before": _link(service_link, binding=service_binding(None, (ctx or {}).get("arch"), "before_group"))
           if not bad else {"ok": False, "detail": bad, "ts_start": None, "ts_end": None, "binding": None}, "stopped": None}
    if bad:
        rec["skipped"] = f"context invalid: {bad}: no case was run"
        return rec
    if not rec["service_link_before"]["ok"]:
        rec["skipped"] = "service link before the group failed: no case was run"
        return rec
    for c in cases:
        r = {"id": c["id"], "iface": iface, "before": f"{c['id']} before", "after": f"{c['id']} after", "steps": [],
             "exec_error": None, "read_error": None, "guest_state": None, "neigh_before": None, "neigh_after": None,
             "control": None, "service_link_after": None, "not_run": None}
        if rec["stopped"]:
            r["not_run"] = rec["stopped"]
            rec["cases"].append(r)
            continue
        try:
            steps = contract_steps(c, iface, ctx)
        except ValueError as e:
            r["exec_error"] = f"commands not built: {e}"
            rec["cases"].append(r)
            continue
        r["neigh_before"], err = _call(worker_neigh)
        if err:
            r["neigh_before_error"] = err
        if c["control_kind"] == "service_link":
            r["control"] = _link(service_link, "control", c["id"], binding=service_binding(c["id"], ctx["arch"], "control"))   # T01 immediately before the change
        gc = GS.GuestChange(runner, iface, nat=(ctx["arch"] == "ARM"), owned_nat=owned_nat_rules(c, ctx))
        restore_exc = None
        try:
            with gc:
                if anchor is not None and "anchor" not in rec:
                    rec["anchor"] = {"label": ANCHOR_LABEL, "gap_s": ANCHOR_GAP_S, "before_case": c["id"]}
                    _, ae = _call(anchor)
                    rec["anchor"]["error"] = ae
                    if ae is None:
                        _call(sleep or time.sleep, ANCHOR_GAP_S)
                _, e1 = _call(read_counters, r["before"])
                _run_steps(runner, steps, r, timeout)
                _, e2 = _call(read_counters, r["after"])
                errs = [f"read {lbl!r}: {e}" for lbl, e in ((r["before"], e1), (r["after"], e2)) if e]
                r["read_error"] = "; ".join(errs) or None
        except GS.StateReadError as e:      # before-state unreadable: nothing changed, nothing to restore
            r["exec_error"] = r["exec_error"] or f"guest state not readable before the case: {e}"
        except Exception as e:                                   # noqa: BLE001
            if gc.rec["before"] is not None:                     # the body catches everything: this is the restore
                restore_exc = f"{type(e).__name__}: {e}"
            r["exec_error"] = r["exec_error"] or f"{type(e).__name__}: {e}"
        restore = gc.rec["restore"]
        if gc.rec["before"] is not None and restore is None:
            restore = {"restored": False, "commands": [], "diffs": [], "dynamic_changes": [],
                       "error": f"restore raised: {restore_exc or 'unknown'}"}
        r["guest_state"] = {"before": _jsonable(gc.rec["before"]), "restore": _jsonable(restore)}
        restored = bool(restore and restore.get("restored") is True)
        if gc.rec["before"] is not None and not restored:
            rec["stopped"] = NOT_RUN
        r["neigh_after"], err = _call(worker_neigh)
        if err:
            r["neigh_after_error"] = err
        if c["control_kind"] == "live":
            t0 = time.time()
            res, err = _call(control, c)
            t1 = time.time()
            # a malformed payload is a recorded failed control, never an exception that loses the case record; ok is only kept when the callback said
            # True AND returned a structured detail (the evaluator re-validates the whole record)
            if err:
                ok_, det = False, err
            elif isinstance(res, (tuple, list)) and len(res) == 2:
                ok_, det = res[0] is True, res[1]
            else:
                ok_, det = False, f"control callback returned {type(res).__name__} {res!r}: expected (ok, detail)"
            r["control"] = {"ok": ok_, "detail": det, "ts_start": t0, "ts_end": t1, "binding": live_binding(c, ctx["arch"])}
        if restored:
            r["service_link_after"] = _link(service_link, "after", c["id"], binding=service_binding(c["id"], ctx["arch"], "after"))
        rec["cases"].append(r)
    return rec


def _jsonable(x):
    """guest_state uses tuple keys for neighbours; the record is JSON."""
    if isinstance(x, dict):
        return {(" ".join(k) if isinstance(k, tuple) else k): _jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_jsonable(v) for v in x]
    return x


# ------------------------------------------------------------------ execution record contract (06B-4HR)
BASELINE_KEYS = {"mac": str, "operstate": str, "admin_up": bool, "addrs": list, "routes": list, "neigh_static": dict,
                 "neigh_dynamic": dict, "arp_notify": int}
# 06B-4IR3 (PC-3): admin_up (administrative link state from the `ip link` header, guest_state) is required in the
# baseline and in restore.after; a record without it never counts as a confirmed restore.


def baseline_problem(before, need_nat=False):
    if not isinstance(before, dict):
        return "guest baseline missing"
    nat = before.get("nat_postrouting")
    if need_nat and nat is None:
        return "guest baseline field 'nat_postrouting' missing (ARM: the NAT-bypass rule needs its baseline)"
    if nat is not None and (not isinstance(nat, list) or not nat or any(not isinstance(x, str) for x in nat)
                            or not nat[0].startswith("-P POSTROUTING ") or any(not x.startswith("-A POSTROUTING ") for x in nat[1:])):
        return "guest baseline field 'nat_postrouting' is not an ordered list (policy line first, then POSTROUTING rules)"
    for k, t in BASELINE_KEYS.items():
        if not isinstance(before.get(k), t) or (t is int and isinstance(before.get(k), bool)):
            return f"guest baseline field {k!r} missing or not {t.__name__}"
    if not _MAC.fullmatch(before["mac"]):
        return "guest baseline MAC invalid"
    # 06B-4HR1: content, not only the container types
    if before["operstate"] not in OPERSTATES:
        return f"guest baseline operstate {before['operstate']!r} not a kernel operstate"
    for a in before["addrs"]:
        if not isinstance(a, str) or "/" not in a or not _ipv4_iface(a):
            return f"guest baseline address {a!r} is not an IPv4 address/prefix"
    for r in before["routes"]:
        if not isinstance(r, str) or not r.strip():
            return f"guest baseline route {r!r} is not a non-empty route line"
    for k, mac in before["neigh_static"].items():
        if not _neigh_key(k) or not isinstance(mac, str) or not _MAC.fullmatch(mac):
            return f"guest baseline static neighbour {k!r}: {mac!r} invalid"
    for k, v in before["neigh_dynamic"].items():
        if not _neigh_key(k) or not isinstance(v, (list, tuple)) or len(v) != 2 or not isinstance(v[0], str) \
                or not _MAC.fullmatch(v[0]) or not isinstance(v[1], int) or isinstance(v[1], bool) or v[1] < 0:
            return f"guest baseline dynamic neighbour {k!r}: {v!r} invalid"
        # 06B-4HR2 (R1): guest_state puts every /proc/net/arp row with ATF_PERM (0x4) in neigh_static; a "dynamic"
        # entry with that bit is a contradictory record (diff() would skip a lost permanent neighbour). Rejected,
        # never moved to the other group.
        if v[1] & GS_ATF_PERM:
            return f"guest baseline dynamic neighbour {k!r} has the PERMANENT flag ({v[1]:#x}): belongs to neigh_static"
    both = sorted(set(before["neigh_static"]) & set(before["neigh_dynamic"]))
    if both:
        return f"guest baseline neighbour(s) {both} in both neigh_static and neigh_dynamic"
    if before["arp_notify"] < 0:
        return f"guest baseline arp_notify {before['arp_notify']} negative"
    return None


_MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
GS_ATF_PERM = 0x4     # the flag guest_state.parse_snapshot() uses to put a neighbour in neigh_static
OPERSTATES = {"unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up"}


def _ipv4_iface(a):
    try:
        return ipaddress.ip_interface(a).version == 4
    except ValueError:
        return False


def _neigh_key(k):
    """'ip dev' as written by _jsonable from guest_state's (ip, dev) keys."""
    if not isinstance(k, str) or len(k.split(" ")) != 2:
        return None
    ip, dev = k.split(" ")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    return (ip, dev) if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", dev) else None


def _gs_state(st):
    """JSON form of a guest_state snapshot -> the form guest_state.diff() expects (tuple keys)."""
    return {**st, "neigh_static": {_neigh_key(k): v for k, v in st["neigh_static"].items()},
            "neigh_dynamic": {_neigh_key(k): tuple(v) for k, v in st["neigh_dynamic"].items()}}


def restore_problem(restore, before=None, need_nat=False):
    """06B-4HR1: the evidence must be complete and consistent. restored=True needs: no error, a valid re-read
    state 'after', and guest_state.diff(baseline, after) == [] recomputed HERE (the stored flag and 'diffs' are not
    trusted). Dynamic neighbours are not compared (guest_state rule)."""
    if not isinstance(restore, dict):
        return "restore evidence missing"
    if not isinstance(restore.get("restored"), bool):
        return "restore evidence without a boolean 'restored'"
    for k in ("commands", "diffs"):
        if not isinstance(restore.get(k), list):
            return f"restore evidence without a list {k!r}"
    for c in restore["commands"]:
        if not isinstance(c, dict) or not isinstance(c.get("cmd"), str) or not isinstance(c.get("step"), str) \
                or not (c.get("rc") is None or (isinstance(c.get("rc"), int) and not isinstance(c.get("rc"), bool))):
            return f"restore command record invalid: {c!r}"
    if not all(isinstance(d, str) for d in restore["diffs"]):
        return "restore 'diffs' is not a list of strings"
    if restore.get("error") is not None and not isinstance(restore.get("error"), str):
        return "restore 'error' is not a string"
    if not restore["restored"]:
        return None
    if restore["diffs"]:
        return "restore says restored although differences remain"
    if restore.get("error"):
        return f"restore says restored but reports an error: {restore['error']}"
    after = restore.get("after")
    if after is None:
        return "restore says restored without the re-read state 'after'"
    bad = baseline_problem(after, need_nat)
    if bad:
        return f"restore 'after' state invalid: {bad.replace('guest baseline', 'after')}"
    if baseline_problem(before, need_nat) is None:
        d = GS.diff(_gs_state(before), _gs_state(after))
        if d:
            return f"restore says restored but the re-read state differs from the baseline: {d}"
    return None


def execution_problems(case, crec, iface, ctx=None):
    """Is the case's execution record complete and inside the contract?
    COMPLETED case (no exec_error): steps == every contract step, in order, phase and command exact, rc within the
    contract; valid guest baseline; restore evidence.
    STOPPED case (exec_error): steps are a prefix of the contract; every step but the last within the contract and
    the last one outside it (or rc None = exception), unless the case stopped before any step (baseline unreadable:
    no step, no baseline, no restore) or after them; baseline + restore evidence whenever a baseline was taken."""
    if crec.get("not_run"):
        return [] if not crec.get("steps") else ["case marked not run but has steps"]
    try:
        want = contract_steps(case, iface, ctx)
    except ValueError as e:
        return [f"commands not built: {e}"]
    steps = crec.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        return ["steps missing or not a list of objects"]
    got = [(s.get("phase"), s.get("cmd")) for s in steps]
    gs = crec.get("guest_state") if isinstance(crec.get("guest_state"), dict) else {}
    before, restore = gs.get("before"), gs.get("restore")
    need_nat = (ctx or {}).get("arch") == "ARM"
    p = []
    err = crec.get("exec_error")
    if err is not None and not isinstance(err, str):
        return ["exec_error is not a string"]
    if not err:
        if got != want:
            p.append(f"completed case without the full contract: steps {got} != {want}")
        bad = [s for s in steps if not rc_ok(s.get("phase"), s.get("cmd") or "", s.get("rc"))]
        if bad:
            p.append(f"completed case with rc outside the contract: {[(s.get('cmd'), s.get('rc')) for s in bad]}")
        for x in (baseline_problem(before, need_nat), restore_problem(restore, before, need_nat)):
            if x:
                p.append(x)
        return p
    # stopped case
    if got != want[:len(got)]:
        p.append(f"stopped case: steps {got} are not a prefix of the contract {want}")
    for s in steps[:-1]:
        if not rc_ok(s.get("phase"), s.get("cmd") or "", s.get("rc")):
            p.append(f"stopped case: step {s.get('cmd')!r} rc {s.get('rc')!r} outside the contract but not last")
    if before is None:
        if steps or restore is not None:
            p.append("stopped case without a guest baseline but with steps or a restore")
        return p
    for x in (baseline_problem(before, need_nat), restore_problem(restore, before, need_nat)):
        if x:
            p.append(x)
    return p


# ------------------------------------------------------------------ evaluation
def _ip(f):
    ip = f.get("ip") or {}
    return ip if ip.get("valid") else None


def _tcp_flags(ip):
    pl = ip.get("payload") or b""
    return pl[13] if len(pl) >= 14 else None


def is_probe_frame(f, case):
    """Frames sent by the guest for THIS case, identified by the whole tuple the case sends (never by the counter class):
    T16-M1: Ethernet source = the chosen spoof MAC AND (a TCP SYN to 10.200.0.1:8011 from source port 31016, OR an ARP request whose sender MAC is the
            spoof MAC and whose target is 10.200.0.1). Any other frame with the spoof MAC is background: it is reconciled and can prove a failure,
            but it is not a probe frame.
    T17 svc/out: guest MAC, valid IPv4, source = the spoofed address, destination = the case's destination, TCP SYN (no ACK), source port = the case's
            port, destination port = the case's destination port (10.200.0.1:8011 for P1/P2, 1.1.1.1:443 for P4).
    T17-P5: guest MAC, valid unfragmented IPv4, source = the spoofed address, destination = 192.168.60.1, ICMP echo request (type 8, code 0), total
            length = size + 28 (one datagram per echo: size + 28 <= MTU is enforced in build_cases)."""
    k = case["kind"]
    if k == "t16":
        if f.get("direction") != "guest_spoof_mac" or f.get("src") != L._norm_mac(FAKE_MAC):
            return False
        if f.get("etype") == L.ETH_ARP:
            a = f.get("arp") or {}
            return (not a.get("short") and a.get("op") == 1 and a.get("sha") == L._norm_mac(FAKE_MAC) and a.get("tpa") == S.WORKER_GUEST_IP)
        ip = _ip(f)
        return (f.get("etype") == L.ETH_IPV4 and ip is not None and ip.get("src") == S.GUEST_IP and ip.get("dst") == S.WORKER_GUEST_IP
                and ip.get("proto") == 6 and ip.get("frag_offset") == 0 and ip.get("sport") == case["port"] and ip.get("dport") == L.SVC_PORT
                and (_tcp_flags(ip) is not None and _tcp_flags(ip) & 0x12 == 0x02))
    if f.get("direction") != "guest" or f.get("etype") != L.ETH_IPV4:
        return False
    ip = _ip(f)
    if ip is None or ip.get("src") != case["src"] or ip.get("frag_offset") != 0:
        return False
    if k in ("t17_svc", "t17_out"):
        dst, dport = (S.WORKER_GUEST_IP, L.SVC_PORT) if k == "t17_svc" else (case["dst"], case["dport"])
        fl = _tcp_flags(ip)
        return (ip.get("proto") == 6 and ip.get("dst") == dst and ip.get("sport") == case["port"] and ip.get("dport") == dport
                and fl is not None and fl & 0x12 == 0x02)
    pl = ip.get("payload") or b""
    return (ip.get("proto") == 1 and ip.get("dst") == case["dst"] and ip.get("tot_len") == case["size"] + 28
            and len(pl) >= 2 and pl[0] == 8 and pl[1] == 0)


def success_outputs(case, steps):
    """R5: tool outputs that report a success (HTTP 2xx / ping rc 0) of the trigger. By itself such an output says nothing about WHICH source address
    the packets carried (R4: HTTP 200 from the REAL 10.200.0.2): it becomes spoof evidence only when bound to the wire (determined_problems)."""
    out = []
    for s_ in steps or []:
        if s_.get("phase") == "trigger" and isinstance(s_.get("out"), str) and re.search(r"HTTP=2\d\d\b", s_["out"]):
            out.append(f"HTTP success from {('the service' if case['kind'] != 't17_out' else case['dst'])}: {s_['out'].strip()[-60:]!r}")
        if s_.get("phase") == "trigger" and case["kind"] == "t17_icmp" and s_.get("rc") == 0:
            out.append("ping rc 0 (a reply)")
    return out


def real_identity_frames(window, case):
    """R5: frames of the case tuple (destination, ports/size, SYN or echo request) from the guest whose source is NOT the spoofed address."""
    k, res = case["kind"], []
    if k == "t16":
        return res
    for f in window:
        if f.get("direction") != "guest" or f.get("etype") != L.ETH_IPV4:
            continue
        ip = _ip(f)
        if ip is None or ip.get("src") == case["src"] or ip.get("frag_offset") != 0:
            continue
        if k in ("t17_svc", "t17_out"):
            dst, dport = (S.WORKER_GUEST_IP, L.SVC_PORT) if k == "t17_svc" else (case["dst"], case["dport"])
            fl = _tcp_flags(ip)
            hit = ip.get("proto") == 6 and ip.get("dst") == dst and ip.get("sport") == case["port"] and ip.get("dport") == dport and fl is not None and fl & 0x12 == 0x02
        else:
            pl = ip.get("payload") or b""
            hit = ip.get("proto") == 1 and ip.get("dst") == case["dst"] and ip.get("tot_len") == case["size"] + 28 and len(pl) >= 2 and pl[0] == 8 and pl[1] == 0
        if hit:
            res.append({"t": f["t"], "src": ip.get("src")})
    return res[:6]


def reply_frames(window, case):
    """R6: frames of the WORKER addressed to the spoofed identity (a reply/leak produced for it). Each entry says whether it also matches the case's
    flow tuple (TCP: ports reversed; ICMP: echo reply), so the evidence can be read as flow-bound or as a generic packet to the fake identity."""
    res, fake = [], L._norm_mac(FAKE_MAC)
    for f in window:
        if f.get("direction") != "worker":
            continue
        if case["kind"] == "t16":
            if f.get("dst") == fake:
                res.append({"t": f["t"], "to": fake, "flow_bound": False})
            continue
        ip = _ip(f)
        if ip and ip.get("dst") == case["src"]:
            if case["kind"] == "t17_icmp":
                bound = ip.get("proto") == 1 and (ip.get("payload") or b"")[:1] == b"\x00"
            else:
                bound = ip.get("proto") == 6 and ip.get("sport") == (L.SVC_PORT if case["kind"] == "t17_svc" else case["dport"]) and ip.get("dport") == case["port"]
            res.append({"t": f["t"], "to": ip.get("dst"), "flow_bound": bool(bound)})
    return res


def determined_problems(window, case, steps=None, wire_bound=False):
    """Frames that prove a failure for this case (independent of counters). R6: only what is ON THE WIRE for the fake identity counts: a worker frame
    addressed to the spoof MAC (T16) or to the spoofed source (T17). A tool success output (HTTP 2xx / ping rc 0) is NEVER failure evidence by itself,
    not even next to a fake SYN: it carries no flow identity (R5 review S2: a fake SYN plus a real-identity HTTP 200 is two different flows). It is
    kept as `success_outputs` and judged by evaluate_case against fake/real frames. `steps`/`wire_bound` are kept for the signature only."""
    p = []
    for r in reply_frames(window, case):
        if case["kind"] == "t16":
            p.append(f"worker frame addressed to the spoof MAC at t={r['t']:.6f}")
        else:
            p.append(f"worker packet addressed to the spoofed source {case['src']} at t={r['t']:.6f} (a reply was generated"
                     + ("; matches the case flow" if r["flow_bound"] else "; not the case's flow tuple") + ")")
    return p


EVIDENCE_FIELDS = {"failure_evidence": list, "measurement_errors": list, "execution_problems": list,
                   "neighbour_inconclusive": list, "not_started": bool, "not_run": bool}


def _result(cid, category, text, **kw):
    """06B-4HR1: every branch carries the same evidence/error fields (empty when not applicable)."""
    assert category in CATEGORIES
    out = {"id": cid, "category": category, "verdict": text, "ok": category in ("DAT", "DAT_KIEM_QUY_TAC")}
    out.update(kw)
    for k, t in EVIDENCE_FIELDS.items():
        out.setdefault(k, t())
    out.setdefault("probe_frames", None)
    out.setdefault("probe_frames_certain", None)
    return out


def link_ok(state):
    return isinstance(state, dict) and state.get("ok") is True


def _window_ok(ra, rb):
    vals = [ra.get("t_start"), ra.get("t_end"), rb.get("t_start"), rb.get("t_end")]
    if not all(counter_window._finite(v) for v in vals):
        return False
    return vals[0] <= vals[1] < vals[2] <= vals[3]


def evaluate_case(frames, reads, case, crec, link_before_ok, guard=GUARD_S, iface=None, input_error=None, ctx=None, fixture_sha=None, bounds=None):
    """frames: l2frames.classified_frames() or None (capture unreadable); reads: l2eval.load_reads() or None.
    06B-4HR order: (1) collect failure evidence that does not depend on the failed measurement (worker
    neighbours from valid rows; frames only inside a VALID window; counter reconciliation only with valid
    counters); (2) FAIL if any, keeping the measurement errors; (3) LỖI PHÉP ĐO; (4) the rest."""
    cid = case["id"]
    kind = case["control_kind"]
    iface = iface if iface is not None else crec.get("iface")
    ek = {"evidence_kind": "rule_check" if kind == "rule_check" else "live_control",
          "control_source": {"service_link": "T01 from the guest's real identity immediately before the change", "live": "controller-side live control"}.get(kind),
          "not_measured": ["server.py request log", "/tmp/sandbox_stop_requested"]}
    if crec.get("not_run"):
        return _result(cid, "CHUA_KIEM_CHUNG", crec["not_run"], not_run=True, **ek)
    gs = crec.get("guest_state") if isinstance(crec.get("guest_state"), dict) else {}
    # 06B-4HR1 (HR3): a case that never started (state unreadable / commands not built: nothing sent, no counter
    # read expected) is NOT returned early: independent evidence (worker neighbours, input errors) is still
    # collected, a determined failure still wins, and the result keeps the "not started" state.
    not_started = bool(crec.get("exec_error") and gs.get("before") is None and not crec.get("steps"))
    failure, measure = [], []
    if input_error:
        measure.append(input_error)
    # (1a) worker neighbours: valid rows are evidence even when other rows/reads are bad
    nc = neigh_check(crec.get("neigh_before"), crec.get("neigh_after"), watch_ips(case))
    failure += nc["fail"]
    measure += [f"worker neighbours: {x}" for x in nc["invalid"]]
    # (1b) window and frames
    if crec.get("read_error"):
        measure.append(crec["read_error"])
    ra = rb = None
    if reads is not None and not not_started:
        missing = [lbl for lbl in (crec.get("before"), crec.get("after")) if lbl not in reads]
        if missing:
            measure.append(f"counter read(s) {missing} not found")
        else:
            ra, rb = reads[crec["before"]], reads[crec["after"]]
            if not _window_ok(ra, rb):
                measure.append("counter read times invalid or out of order: window not usable")
                ra = rb = None
    window = probe = certain = []
    recon = None
    if frames is not None and ra is not None:
        window = [f for f in frames if counter_window.zone(f["t"], ra, rb, guard) != "outside"]
        probe = [f for f in window if is_probe_frame(f, case)]
        certain = [f for f in probe if counter_window.zone(f["t"], ra, rb, guard) == "certain"]
        failure += determined_problems(window, case, crec.get("steps"))
    # (1c) counters: only with valid counters (no read error) and a valid window
    out_drop = None
    if frames is not None and ra is not None and not crec.get("read_error"):
        recon = L.reconcile_l2(frames, ra, rb, l2eval.check_classes(None), guard)
        if recon["verdict"] in ("UNVERIFIED", "FAIL"):
            # R4-C1: validate closure reads even alongside FAIL; only UNVERIFIED classes may be resolved under H0.
            labels = list(reads)
            counter_window.close_edges(recon, frames, [reads[x] for x in labels], labels, labels.index(crec["before"]), labels.index(crec["after"]), guard)
            measure.extend("counter closure: " + error for error in recon["closure"].get("measurement_errors", []))
        if recon["verdict"] == "ERROR":
            measure.append(f"reconciliation: {recon.get('error')}")
        else:
            if recon["verdict"] == "FAIL":
                failure.append("counter reconciliation FAIL")
            counted = [f for f in certain if f["cls"] in L.COUNTER_CLASSES]
            wrong = sorted({f["cls"] for f in counted if f["cls"] != case["expected"]})
            if wrong:
                failure.append(f"probe frames hit counter class(es) {wrong} instead of {case['expected']}")
        d, err = L.strict_delta(ra, rb, ["arp_out_drop"])
        if err:
            measure.append(err)
        else:
            out_drop = d["arp_out_drop"]
    # S1: the control and the service link after the case are validated HERE (shape, binding, evidence, window); the callback's `ok` alone proves nothing
    arch = (ctx or {}).get("arch")
    bounds = bounds or {}
    ctl = crec.get("control")
    cprob, calive = [], False
    if ctl is None:
        cprob = ["control record missing"]
    elif kind == "service_link":
        cprob, calive = service_state_problems(ctl, service_binding(cid, arch, "control"), fixture_sha)
        if not cprob and ra is not None:
            if ctl["ts_end"] > ra["t_start"]:
                cprob.append("the control finished after the case's before-read: not taken immediately before the change")
            nb = bounds.get("not_before")
            if nb is not None and ctl["ts_start"] < nb:
                cprob.append("the control started before the previous step ended: not bound to this case's window")
    else:
        cprob, calive = live_state_problems(case, ctl, arch)
        if not cprob and rb is not None:
            if ctl["ts_start"] < rb["t_end"]:
                cprob.append("the live control started before the case's after-read: not taken for this window")
            na = bounds.get("not_after")
            if na is not None and ctl["ts_end"] > na:
                cprob.append("the live control ended after the next case's before-read")
    if cprob:
        calive = False
        measure += [f"control: {x}" for x in cprob]
    after_state = crec.get("service_link_after")
    after_alive = False
    if after_state is not None:
        aprob, after_alive = service_state_problems(after_state, service_binding(cid, arch, "after"), fixture_sha)
        if aprob:
            after_alive = False
            measure += [f"service link after: {x}" for x in aprob]
    exec_probs = execution_problems(case, crec, iface, ctx) if iface is not None else ["record interface unknown"]
    # R5: a tool success is bound to the wire or it is not evidence of a spoof. Without a usable capture/window it cannot be bound: a measurement error
    # (never PASS, never an unbound FAIL); with a usable capture and no spoofed-source frame it is the REAL identity that succeeded.
    # R6: fake and real frames are ALWAYS reported; a success output is attributed to the fake identity only by a reply to it on the wire (a FAIL above).
    succ = success_outputs(case, crec.get("steps"))
    unbound = [] if probe else succ
    realid = real_identity_frames(window, case) if (frames is not None and ra is not None) else []
    replies = reply_frames(window, case)
    if succ and (frames is None or ra is None):
        measure.append("tool success output cannot be bound to the spoofed identity (capture/window unusable): " + "; ".join(succ))
    elif succ and probe and not replies:
        if realid:
            measure.append("tool success output cannot be attributed: frames of the case tuple carry BOTH the spoofed source and the real identity "
                           f"{sorted({x['src'] for x in realid})}, and nothing on the wire answered the spoofed identity (two different flows; no leak inferred): "
                           + "; ".join(succ))
        else:
            measure.append("tool success output is not explained by the wire: spoofed-source frames only, no reply to the spoofed identity and no real-identity "
                           "frame of the tuple in the window: " + "; ".join(succ))
    detail = {"probe_frames": len(probe), "probe_frames_certain": len(certain),
              "probe_frame_classes": sorted({f["cls"] for f in probe}),
              "failure_evidence": failure, "measurement_errors": measure, "execution_problems": exec_probs,
              "neighbour_inconclusive": nc["inconclusive"], "arp_out_drop_delta": out_drop,
              "reconciliation": None if recon is None else
              {k: recon.get(k) for k in ("verdict", "per_class", "no_counter_frames", "guard_s", "closure")},
              "unbound_success_output": unbound, "real_identity_frames": realid,
              "success_outputs": succ, "reply_frames": replies[:6],
              "fake_frames": [{"t": f["t"], "src": (_ip(f) or {}).get("src"), "mac": f.get("src"), "cls": f.get("cls")} for f in probe[:6]],
              "not_started": not_started, "steps": crec.get("steps"), "restore": (gs.get("restore") or {}).get("restored")
              if isinstance(gs.get("restore"), dict) else None, **ek}
    # (2) determined failures win, measurement errors are kept alongside
    if failure:
        return _result(cid, "FAIL", "FAIL", **detail)
    # (3) measurement errors
    if measure:
        return _result(cid, "LOI_PHEP_DO", "LỖI PHÉP ĐO (" + "; ".join(measure) + ")", **detail)
    # (4) the guest could not run the probe / the execution record is not complete
    if crec.get("exec_error"):
        return _result(cid, "LOI_THUC_THI", f"CHƯA KIỂM CHỨNG (lỗi thực thi: {crec['exec_error']})", **detail)
    if exec_probs:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (hồ sơ thực thi không đầy đủ/không hợp lệ: "
                       + "; ".join(exec_probs) + ")", **detail)
    # (5) no probe frame: never evidence of blocking
    if not probe:
        extra = ""
        if unbound or realid:
            extra = (" [R5: tool success output without a frame carrying the spoofed source: the real identity "
                     f"{sorted({x['src'] for x in realid}) or 'unknown'} was on the wire, so this is not evidence of a spoof FAIL nor of blocking]")
        return _result(cid, "KHONG_TAO_DUOC_GOI", "CHƯA KIỂM CHỨNG (không tạo được khung probe; không phải "
                       "bằng chứng chặn)" + extra, **detail)
    # (6) the reviewed verdict function (determined failures were handled above)
    pv = {"probe_packets_in_tap0_pcap": True, "probe_packets_hit_expected_counter": True,
          "no_frame_proving_failure": True, "worker_neighbours_unchanged": True}
    if kind in ("live", "service_link"):
        text, ok = L.probe_verdict_l2(pv, recon, case["expected"], "live", control_alive=calive)
    else:
        text, ok = L.probe_verdict_l2(pv, recon, case["expected"], "rule_check")
    if text == "FAIL":
        return _result(cid, "FAIL", "FAIL", **detail)
    if not ok:
        return _result(cid, "CHUA_KIEM_CHUNG", text, **detail)
    # (7) conditions that only prevent judging
    if nc["inconclusive"]:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (neighbor worker không đủ để kết luận: "
                       + "; ".join(nc["inconclusive"]) + ")", **detail)
    if out_drop != 0:
        return _result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG (arp_out_drop tăng {out_drop}: worker đã định gửi "
                       "ARP tới guest; khung không quan sát được trên tap0)", **detail)
    if detail["restore"] is not True:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (cấu hình guest không khôi phục được)", **detail)
    if not link_before_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ trước nhóm thử thiếu, không đạt "
                       "hoặc không hợp lệ)", **detail)
    if not after_alive:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ sau ca thử không đạt)", **detail)
    return _result(cid, "DAT" if kind in ("live", "service_link") else "DAT_KIEM_QUY_TAC", text, **detail)


def record_problems(record):
    """Structure/completeness of a group record: every case exactly once, labels as built, and (06B-4HR) every
    case's execution record inside the contract (execution_problems)."""
    if not isinstance(record, dict) or not isinstance(record.get("cases"), list) \
            or not all(isinstance(c, dict) for c in record["cases"]):
        return ["group record must be an object whose 'cases' is a list of objects"]
    p = []
    n = collections.Counter(c.get("id") for c in record["cases"])
    if record.get("skipped"):
        p.append(f"group skipped: {record['skipped']}")
    else:
        p += [f"case missing: {cid}" for cid in CASE_IDS if n[cid] == 0]
    p += [f"case recorded more than once: {cid}" for cid, k in sorted(n.items(), key=str) if k > 1]
    p += [f"unknown case id: {cid!r}" for cid in n if cid not in CASE_IDS]
    ctx = {"arch": record.get("arch"), "tap_mac": record.get("tap_mac")}
    bad_ctx = ctx_problem(ctx)
    if bad_ctx and not record.get("skipped"):
        p.append(bad_ctx)
        ctx = None
    defs = {c["id"]: c for c in build_cases()}
    for c in record["cases"]:
        d = defs.get(c.get("id"))
        if d is None:
            continue
        if not c.get("not_run") and (c.get("before") != f"{d['id']} before" or c.get("after") != f"{d['id']} after"):
            p.append(f"{d['id']}: counter read labels differ from the reviewed ones")
        p += [f"{d['id']}: {x}" for x in execution_problems(d, c, record.get("iface"), ctx)]
    return p


def anchor_assessment(record, reads):
    """R9: may the counters-file read ANCHOR_LABEL be offered to the closure? -> (usable, reason). reason is kept in the evaluation output.
    The record must carry an `anchor` object with: label == ANCHOR_LABEL, an `error` key that is explicitly None, and a `before_case` equal to the
    id of the first case that was ACTUALLY executed according to the case records (first case, in record order, not `not_run`, whose
    before-read is in the counters file); the read must sit in the file immediately before that case's before-read. A self-declared value alone
    is never trusted. Nothing here weighs the read's times or counters: counter_window.close_edges does that exactly as for any neighbour read."""
    present = isinstance(reads, dict) and ANCHOR_LABEL in reads
    if not isinstance(record, dict) or "anchor" not in record:
        return False, ("counters file has an anchor read but the group record has no anchor entry" if present else None)
    anc = record["anchor"]
    if not isinstance(anc, dict):
        return False, f"group record anchor is {type(anc).__name__}, expected an object"
    if "error" not in anc:
        return False, "group record anchor has no 'error' field"
    if anc["error"] is not None:
        return False, f"group record anchor.error is not null ({anc['error']!r}): the anchor read is not vouched for"
    if type(anc.get("label")) is not str or anc["label"] != ANCHOR_LABEL:
        return False, f"group record anchor.label is {anc.get('label')!r}, expected {ANCHOR_LABEL!r}"
    if not present:
        return False, "group record claims an anchor read but the counters file has none"
    first = None
    for c in record.get("cases") if isinstance(record.get("cases"), list) else []:
        if isinstance(c, dict) and not c.get("not_run") and isinstance(c.get("before"), str) and c["before"] in reads:
            first = c
            break
    if first is None:
        return False, "no executed case with a before-read in the counters file: nothing to attach the anchor to"
    bc = anc.get("before_case")
    if type(bc) is not str or bc != first.get("id"):
        return False, f"group record anchor.before_case is {bc!r}, the first executed case is {first.get('id')!r}"
    labels = list(reads)
    i = labels.index(ANCHOR_LABEL)
    if i + 1 >= len(labels) or labels[i + 1] != first["before"]:
        return False, f"the anchor read is not immediately before {first['before']!r} in the counters file"
    return True, None


def evaluate_group(pcap, counters_file, tap_mac, record, guard=GUARD_S):
    """-> {"cases": [...], "record_problems": [...], ...}. Never concludes for an invalid/incomplete record.
    06B-4HR: a capture or counter-file error no longer ends the evaluation early: every case is still evaluated
    with what is valid (worker neighbours, the other input), so a determined failure is not hidden."""
    probs = record_problems(record)
    out = {"guard_s": guard, "assumption": l2eval.ASSUMPTION, "record_problems": probs, "cases": []}
    if probs and "group record must be" in probs[0]:
        return out
    out["service_link_before"] = record.get("service_link_before")
    cases = {c["id"]: c for c in build_cases()}
    if record.get("skipped"):
        out["cases"] = [_result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG ({record['skipped']})") for cid in CASE_IDS]
        return out
    frames = reads = None
    errs = []
    try:
        frames = L.classified_frames(pcap, tap_mac)
    except L.FrameReadError as e:
        errs.append(f"capture read error: {e}")
    except ValueError as e:
        errs.append(f"invalid argument: {e}")
    try:
        reads = l2eval.load_reads(counters_file)
    except l2eval.InputError as e:
        errs.append(f"invalid measurement data: {e}")
    input_error = "; ".join(errs) or None
    anchor_ok, anchor_reason = anchor_assessment(record, reads)
    out["anchor"] = {"used": anchor_ok, "reason": anchor_reason}
    if reads is not None and ANCHOR_LABEL in reads and not anchor_ok:
        reads = {k: v for k, v in reads.items() if k != ANCHOR_LABEL}      # a read that the group record does not vouch for is no evidence
    fixture_sha = record.get("fixture_sha256")
    arch = record.get("arch")
    lprob, lb = service_state_problems(record.get("service_link_before"), service_binding(None, arch, "before_group"), fixture_sha)
    if lprob:
        out["record_problems"] = list(out["record_problems"]) + [f"service_link_before: {x}" for x in lprob]
    # control windows (S1): a case's control is bound to the reads around it
    order = [c for c in record["cases"] if isinstance(c, dict) and not c.get("not_run")]
    def rd_(label, key):
        r = reads.get(label) if isinstance(reads, dict) else None
        return r.get(key) if isinstance(r, dict) else None
    sl = record.get("service_link_before") if isinstance(record.get("service_link_before"), dict) else {}
    bounds = {}
    for i, c in enumerate(order):
        nb = (rd_(order[i - 1].get("after"), "t_end") if i > 0 else sl.get("ts_end"))
        na = rd_(order[i + 1].get("before"), "t_start") if i + 1 < len(order) else None
        bounds[id(c)] = {"not_before": nb if _finite_num(nb) else None, "not_after": na if _finite_num(na) else None}
    for crec in record["cases"]:
        if crec.get("id") not in cases:
            out["cases"].append(_result(str(crec.get("id")), "LOI_PHEP_DO", "LỖI PHÉP ĐO (unknown case id)"))
            continue
        out["cases"].append(evaluate_case(frames, reads, cases[crec["id"]], crec, lb, guard,
                                          iface=record.get("iface"), input_error=input_error,
                                          ctx={"arch": arch, "tap_mac": record.get("tap_mac")}, fixture_sha=fixture_sha,
                                          bounds=bounds.get(id(crec))))
    return out


def group_exit(result):
    """Exit code of the group, by precedence: any FAIL -> 1 (FAIL wins over everything); else any LỖI PHÉP ĐO, no
    case at all, or a record problem -> 2; else anything not judged ĐẠT -> 4; else 0. An incomplete/invalid record is
    never 0."""
    cats = {c["category"] for c in result["cases"]}
    if "FAIL" in cats:
        return 1
    if not result["cases"] or "LOI_PHEP_DO" in cats:
        return 2
    if result.get("record_problems"):
        return 2
    return 4 if cats - {"DAT", "DAT_KIEM_QUY_TAC"} else 0


def main(argv):
    ap = argparse.ArgumentParser(description="evaluate a recorded T16/T17 spoof group (offline)")
    for a in ("--pcap", "--counters", "--tap-mac", "--record"):
        ap.add_argument(a, required=True)
    ap.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        res = evaluate_group(a.pcap, a.counters, a.tap_mac, json.load(open(a.record)))
    except (OSError, ValueError) as e:
        res = {"error": f"{type(e).__name__}: {e}", "cases": [], "record_problems": []}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
    for c in res["cases"]:
        print(f"{c['id']}: {c['verdict']}")
    for p in res.get("record_problems", []):
        print(f"RECORD: {p}")
    if res.get("error"):
        print(f"ERROR: {res['error']}")
        return 2
    return group_exit(res)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
