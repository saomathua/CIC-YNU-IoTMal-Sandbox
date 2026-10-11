#!/usr/bin/env python3
"""R1 — wiring of the T16/T17 cases (spoof_cases.py) into the harness. Copied from arp_harness.py (06B-4I..IR3, reviewed) with the ARP-specific live
controls replaced. Prepared and tested OFFLINE only.

Used in two places:
  * inside the worker test container by probe_matrix.py when CT01_SUITE=spoof: run_suite (-> spoof_cases.run_group) with the worker neighbour
    collector (NEIGH_CMD), the live controls of T17-P4/P5 (make_control: WORKER side, an allowed source) and evaluate (-> spoof_cases.evaluate_group);
  * on the host by run-ct01-spoof.sh:  --outcome <result.json> <spoof-eval.json> <ARCH>   and   --run-check <probe dir> ARM MIPS
No case, command, address, size, tool or ruleset is added here. Reused from icmp_harness.py (reviewed): GuardedRunner, the service link command/parser.

Controls: T16-M1, T17-P1, T17-P2: T01 from the guest's real identity immediately before the change (spoof_cases.run_group), same IP/protocol/port as
the probe. T17-P4: the worker completes a TCP connect to 1.1.1.1:443 (real network: one connect per architecture). T17-P5: the worker's ICMP echo to
192.168.60.1 is answered (b1_cases.icmp_control). A control that is not alive makes the case at best CHƯA KIỂM CHỨNG (spoof_cases rule).
"""
import collections
import json
import math
import os
import re
import sys

import spoof_cases as A
import icmp_harness as IH

RECORD_FILE = "spoof-group.json"
EVAL_FILE = "spoof-eval.json"
NEIGH_CMD = ("ip", "-j", "neigh", "show")     # worker netns, whole table (with "-j ... dev X" iproute2 omits "dev")
LINK_ROLE = ("guest-worker service link: precondition before the group and after every restored case; for T16-M1/T17-P1/P2 "
             "the same request from the real identity immediately before the change is the control")
CTL_SLACK_S = 3.0          # same span as probe_matrix.ctl_log_window (06B-3B)
CTL_WAIT_MARGIN_S = 0.6    # ctl writes a cycle about every 0.5 s: wait for one beyond the span
CTL_WAIT_MAX_S = 10.0
BOUND_STATES = ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT")
_MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
ATF_COM = 0x2


def norm_mac(m):
    return A.L._norm_mac(m)


# ------------------------------------------------------------------ live controls (T17-P4, T17-P5): worker side, an ALLOWED source
CONTROL_DEADLINE_S = 3.0


def tcp_connect_control(ip, port, sock=None, timeout=CONTROL_DEADLINE_S, now=None):
    """Live control of a TCP destination: the WORKER (an allowed source) connects to the SAME IP:port the spoofed probe targets and must complete the
    handshake. Returns a structured detail (kind, dst, dport, peer, detail, ts) or raises. One connect, closed at once; nothing is sent."""
    import socket as _socket
    import time as _time
    sock = sock or _socket
    now = now or _time.time
    ok_dst = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", str(ip)) and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536
    if not ok_dst:
        raise ValueError(f"bad control destination {ip!r}:{port!r}")
    t0 = now()
    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
        peer = s.getpeername()
        return {"kind": "tcp_connect", "dst": ip, "dport": port, "peer": [str(peer[0]), int(peer[1])],
                "detail": f"TCP connect to {ip}:{port} completed in {now() - t0:.3f}s", "ts": t0}
    finally:
        s.close()


def icmp_echo_control(ip, icmp_control, now=None):
    """Structured form of b1_cases.icmp_control (which raises unless an echo REPLY from `ip` matching its identifier arrived)."""
    import time as _time
    now = now or _time.time
    t0 = now()
    text = icmp_control(ip)
    if text != f"ICMP echo reply from {ip}":
        raise RuntimeError(f"unexpected ICMP control result {text!r}")
    return {"kind": "icmp_echo", "dst": ip, "dport": None, "reply_from": ip, "detail": text, "ts": t0}


def make_control(tcp_control, icmp_control, now=None):
    """-> control(case) for spoof_cases.run_group(): (ok, detail), never raises. ok is True only when the callback returned a STRUCTURED detail (a dict);
    None / False / {} / a string are failed controls with the value kept. run_group wraps the result with the time span and the binding, and the evaluator
    validates the whole record again (kind, destination, peer/reply source, span): this function is not the authority."""
    import time as _time
    now = now or _time.time

    def control(case):
        t = now()
        try:
            if case.get("id") == "T17-P4":
                d = tcp_control(case["dst"], case["dport"])
            elif case.get("id") == "T17-P5":
                d = icmp_control(case["dst"])
            else:
                return False, {"problems": [f"no live control defined for {case.get('id')}"], "ts": t}
        except Exception as e:                                   # noqa: BLE001
            return False, {"problems": [f"{type(e).__name__}: {e}"], "ts": t}
        if not isinstance(d, dict) or not d:
            return False, {"problems": [f"control callback returned {d!r}: a structured, non-empty detail is required"], "ts": t}
        return True, d
    return control


# ------------------------------------------------------------------ worker side
def run_suite(runner, read_counters, service_link, worker_neigh, control, iface, arch, tap_mac, fixture_sha, anchor=None):
    """Runs the four reviewed cases once (spoof_cases.run_group) and annotates the record. Does not raise; the caller
    re-raises runner.stop. rec["stopped"] keeps the spoof_cases meaning (a failed restore stopped the group); a stop
    of the guard is kept apart in rec["guard_stopped"]."""
    cases = A.build_cases()
    ctx = {"arch": arch, "tap_mac": norm_mac(tap_mac)}
    rec = A.run_group(runner, read_counters, service_link, worker_neigh, control, cases, iface, ctx, anchor=anchor)
    rec.update(arch=arch, tap_mac=norm_mac(tap_mac), fixture_sha256=fixture_sha,
               planned_case_ids=[c["id"] for c in cases], service_link_role=LINK_ROLE, neigh_command=list(NEIGH_CMD))
    if runner.stop is not None:
        rec["guard_stopped"] = f"{type(runner.stop).__name__}: {runner.stop}"
    return rec


def restore_name(cid):
    return f"guest configuration restored after {cid} (re-read state equals the baseline)"


def link_after_name(cid):
    return f"allowed service link after {cid} (guest restored): GET get-task/T/file HTTP 200 + fixture hash"


def control_name(cid):
    return f"allowed service link before {cid} (control: the same request from the real identity, immediately before the change)"


LINK_BEFORE_NAME = "allowed service link before the spoof group: GET get-task/T/file HTTP 200 + fixture hash"
NEIGH_READ_NAME = "worker neighbour table read (ip -j neigh show) before and after every spoof case"
ALL_CASES_NAME = "all five T16/T17 cases recorded exactly once with captures alive"
GROUP_RECORD_NAME = ("spoof group record: each reviewed case exactly once, execution contract, service links "
                     "HTTP 200 + fixture hash")


def case_requirements(record):
    """Per-case confirmations a PASS needs, derived from the group record: a case that took a guest baseline must
    have its restore confirmed; a restored case must have its service link after it confirmed."""
    req = []
    cases = record.get("cases") if isinstance(record, dict) else None
    for c in cases if isinstance(cases, list) else []:
        if not isinstance(c, dict) or c.get("id") not in A.CASE_IDS:
            continue
        gs = c.get("guest_state") if isinstance(c.get("guest_state"), dict) else {}
        if c.get("control") is not None and next((d["control_kind"] for d in A.build_cases() if d["id"] == c["id"]), None) == "service_link":
            req.append(control_name(c["id"]))
        if gs.get("before") is not None:
            req.append(restore_name(c["id"]))
            if isinstance(gs.get("restore"), dict) and gs["restore"].get("restored") is True:
                req.append(link_after_name(c["id"]))
    return req


# ------------------------------------------------------------------ evaluation
def check_record(record, arch, tap_mac, fixture_sha, iface):
    """Wiring-level problems that forbid concluding the group (spoof_cases.record_problems() is added by evaluate()):
    architecture, interface, TAP MAC, fixture hash, planned cases, guard stop, service links HTTP 200 + fixture
    hash (before the group; after every restored case), neighbour collector command."""
    if not isinstance(record, dict):
        return [f"group record is {type(record).__name__}, not an object"]
    p = []
    if record.get("arch") != arch:
        p.append(f"record arch {record.get('arch')!r} != {arch!r}")
    if record.get("iface") != iface:
        p.append(f"record interface {record.get('iface')!r} != probe interface {iface!r}")
    try:
        want_tap = norm_mac(tap_mac)
    except ValueError as e:
        return p + [f"TAP MAC invalid: {e}"]
    if record.get("tap_mac") != want_tap:
        p.append("record TAP MAC differs from the evaluated one")
    if record.get("fixture_sha256") != fixture_sha:
        p.append("record fixture hash differs from the expected one")
    if record.get("planned_case_ids") != list(A.CASE_IDS):
        p.append(f"planned cases {record.get('planned_case_ids')!r} != {list(A.CASE_IDS)}")
    if record.get("neigh_command") != list(NEIGH_CMD):
        p.append(f"neighbour collector command {record.get('neigh_command')!r} != {list(NEIGH_CMD)}")
    if record.get("guard_stopped"):
        p.append(f"group stopped by the guard: {record['guard_stopped']}")
    if not IH.link_valid(record.get("service_link_before"), fixture_sha):
        p.append("service_link_before: not HTTP 200 with the fixture hash")
    for c in record.get("cases") if isinstance(record.get("cases"), list) else []:
        if not isinstance(c, dict):
            continue
        gs = c.get("guest_state") if isinstance(c.get("guest_state"), dict) else {}
        restored = isinstance(gs.get("restore"), dict) and gs["restore"].get("restored") is True
        if restored and not IH.link_valid(c.get("service_link_after"), fixture_sha):
            p.append(f"{c.get('id')}: service_link_after not HTTP 200 with the fixture hash")
    return p


def evaluate(pcap, counters_file, tap_mac, record, arch, fixture_sha, iface):
    """spoof_cases.evaluate_group() + the wiring checks -> the object written to spoof-eval.json. Never raises."""
    problems = check_record(record, arch, tap_mac, fixture_sha, iface)
    try:
        res = A.evaluate_group(pcap, counters_file, tap_mac, record)
    except Exception as e:                                       # noqa: BLE001  a bug must never pass
        res = {"error": f"{type(e).__name__}: {e}", "cases": [], "record_problems": []}
        problems.append(f"evaluate_group refused the record: {res['error']}")
    case_probs = list(res.get("record_problems") or [])
    gx = A.group_exit(res) if res.get("cases") else 2
    problems += [f"spoof_cases: {x}" for x in case_probs]
    ids = collections.Counter(c.get("id") for c in res["cases"])
    if sorted(ids.elements()) != sorted(A.CASE_IDS):
        problems.append(f"evaluated cases {sorted(ids.elements())} are not each of {list(A.CASE_IDS)} exactly once")
    def tier_summary(ids):
        cs = [c for c in res["cases"] if c.get("id") in ids]
        cats = {c["id"]: c.get("category") for c in cs}
        return {"cases": cats, "all_dat": len(cs) == len(ids) and all(c.get("ok") for c in cs), "any_fail": any(c.get("category") == "FAIL" for c in cs)}
    res["gate_policy"] = ("The run outcome is conservative: PASS needs all five cases DAT; a coverage case that is not DAT makes the run UNVERIFIED (and stops "
                          "MIPS). This is not a statement that T17-P2/P4/P5 are acceptance requirements. Mandatory and coverage verdicts are reported "
                          "separately below; a FAIL anywhere is a FAIL; coverage without a live control is 'not known', not 'no defect'.")
    res["tiers"] = {"mandatory": tier_summary(A.MANDATORY_IDS), "coverage": tier_summary(A.COVERAGE_IDS),
                    "postponed_not_built": ["T17-P3 (D1: raw packet tool)", "spoofing TAP_MAC (D5: inbound capture)"]}
    res.update(arch=arch, case_record_problems=case_probs, record_problems=problems, group_complete=not problems,
               group_exit=gx, service_link_role=LINK_ROLE, case_requirements=case_requirements(record),
               inputs={"pcap": pcap, "counters": counters_file, "tap_mac": tap_mac, "iface": iface})
    return res


def case_test_name(case_result):
    """Name of the per-case record in result.json; starts with "probe " so that counter_window.run_outcome()
    treats a CHƯA KIỂM CHỨNG case as undecided and anything else not passed as hard."""
    kind = "live control" if case_result.get("evidence_kind") == "live_control" else "rule check"
    return f"probe {case_result['id']} (spoof, {kind}) -> {case_result['verdict']}"


# ------------------------------------------------------------------ host side
# Confirmations that probe_matrix.py records on the real spoof path (main() + run_spoof() + evaluate_spoof()) and that a
# PASS needs, each EXACTLY ONCE with ok exactly True (06B-4FR rule). Per-case confirmations (restore, service link
# after a restored case) come from spoof-eval.json "case_requirements" and follow the same rule.
REQUIRED_RECORDS = (
    "host leak monitor running and empty before boot",
    "full isolation verify right before QEMU spawn (harness pre-boot, not V1)",
    "tshark capturing on tap0",
    "guest booted and network configured",
    "topology gate: only nic/tap, one tap0 backend, pinned MAC on tap NIC and probe interface",
    "capture liveness traffic from the worker before the spoof group (host captures; not a control for the spoof "
    "destinations)",
    LINK_BEFORE_NAME,
    NEIGH_READ_NAME,
    "tap0 MAC unchanged during the spoof group",
    ALL_CASES_NAME,
    "capture liveness traffic from the worker after the spoof group (host captures; not a control for the spoof "
    "destinations)",
    "QEMU exit confirmed",
    "tap0 capture stopped cleanly",
    "tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped",
    "fixture, marker and temporary guest disk removed",
    GROUP_RECORD_NAME,
)


def required_problems(results, names):
    p = []
    by_name = collections.defaultdict(list)
    for r in results:
        if isinstance(r, dict) and isinstance(r.get("test"), str):
            by_name[r["test"]].append(r)
    for name in names:
        recs = by_name.get(name, [])
        if not recs:
            p.append(f"required confirmation missing: {name}")
        elif len(recs) > 1:
            p.append(f"required confirmation recorded {len(recs)} times: {name}")
        elif recs[0].get("ok") is not True:
            p.append(f"required confirmation not passed (ok={recs[0].get('ok')!r}): {name}")
    return p


def arch_outcome(result, spoof_eval, arch):
    """One architecture -> "PASS" | "UNVERIFIED: ..." | "FAIL: ...". counter_window.run_outcome() on every record
    plus: well-formed records, every REQUIRED_RECORDS and per-case confirmation exactly once with ok True, status
    COMPLETED, an evaluation of this architecture with each case exactly once (also in result.json), no record
    problem, and spoof_cases.group_exit() not 1/2. A passed case never hides another failed or missing check."""
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        return "FAIL: result.json unreadable or without results"
    bad = IH.malformed_records(result["results"])
    if bad:
        return f"FAIL: result record(s) {bad[:5]} not an object with a string 'test' and a boolean 'ok'"
    hard = required_problems(result["results"], REQUIRED_RECORDS)
    if result.get("status") != "COMPLETED":
        hard.append(f"status {result.get('status')!r}")
    if not isinstance(spoof_eval, dict):
        hard.append("spoof-eval.json missing or unreadable")
    else:
        if spoof_eval.get("arch") != arch:
            hard.append(f"spoof-eval arch {spoof_eval.get('arch')!r} != {arch!r}")
        if spoof_eval.get("record_problems") or spoof_eval.get("group_complete") is not True:
            hard.append(f"group record not complete/valid: {spoof_eval.get('record_problems')}")
        if spoof_eval.get("group_exit") not in (0, 4):
            hard.append(f"spoof_cases group exit {spoof_eval.get('group_exit')!r}")
        reqs = spoof_eval.get("case_requirements")
        if not isinstance(reqs, list) or not all(isinstance(x, str) for x in reqs):
            hard.append("spoof-eval case_requirements missing or invalid")
        else:
            hard += required_problems(result["results"], reqs)
        ids = collections.Counter(c.get("id") for c in spoof_eval.get("cases") or [] if isinstance(c, dict))
        if sorted(ids.elements()) != sorted(A.CASE_IDS):
            hard.append(f"spoof-eval cases {sorted(ids.elements())} are not each case exactly once")
        names = collections.Counter(r.get("test") for r in result["results"] if isinstance(r, dict))
        for c in spoof_eval.get("cases") or []:
            if isinstance(c, dict) and "verdict" in c and names[case_test_name(c)] != 1:
                hard.append(f"{c.get('id')}: not recorded exactly once in result.json")
    try:
        base = A.counter_window.run_outcome(result["results"])
    except (KeyError, TypeError) as e:
        return f"FAIL: results malformed ({type(e).__name__}: {e})"
    if hard:
        rest = base[len("FAIL: "):] if base.startswith("FAIL: ") else ""
        return "FAIL: " + "; ".join(hard + ([rest] if rest else []))
    return base


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def run_check(probe_dir, archs):
    """Run level: every architecture evaluated exactly once, each with the four cases once. -> problems."""
    p = []
    if not archs:
        p.append("no architecture given")
    if len(set(archs)) != len(archs):
        p.append(f"architecture listed twice: {archs}")
    for a in archs:
        ev = _load(os.path.join(probe_dir, a, EVAL_FILE))
        if not isinstance(ev, dict):
            p.append(f"{a}: {EVAL_FILE} missing or unreadable")
            continue
        if ev.get("arch") != a:
            p.append(f"{a}: evaluation is for {ev.get('arch')!r}")
        ids = sorted(str(c.get("id")) for c in ev.get("cases") or [] if isinstance(c, dict))
        if ids != sorted(A.CASE_IDS):
            p.append(f"{a}: cases {ids} are not each case exactly once")
    return p


def main(argv):
    if len(argv) == 4 and argv[0] == "--outcome":
        print(arch_outcome(_load(argv[1]), _load(argv[2]), argv[3]))
        return 0
    if len(argv) >= 3 and argv[0] == "--run-check":
        p = run_check(argv[1], argv[2:])
        print("\n".join(p) if p else "spoof groups complete: " + " ".join(argv[2:]))
        return 1 if p else 0
    print("usage: spoof_harness.py --outcome RESULT SPOOF_EVAL ARCH | --run-check PROBE_DIR ARCH...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
