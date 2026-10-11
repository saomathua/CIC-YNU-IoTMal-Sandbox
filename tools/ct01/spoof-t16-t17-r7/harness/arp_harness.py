#!/usr/bin/env python3
"""06B-4I — wiring of the reviewed ARP cases (arp_cases.py, 06B-4HR2: T14-A1, T14-A2, T14-A3, T15-S1) into the
harness. Prepared and tested OFFLINE only (selftest_arp_wiring.py); not run against a guest in 06B-4I.

Used in two places:
  * inside the worker test container by probe_matrix.py when CT01_SUITE=arp: run_suite (-> arp_cases.run_group)
    with the worker neighbour collector (NEIGH_CMD, run in the worker netns), the live controls of T14-A1/A2
    (make_control) and evaluate (-> arp_cases.evaluate_group);
  * on the host by run-06b4i.sh:  --outcome <result.json> <arp-eval.json> <ARCH>
                                  --run-check <probe dir> ARM MIPS
No case, command, address, size, tool or ruleset is added here: the cases and their commands come only from
arp_cases.build_cases()/commands(). arp_cases.py is used unchanged.

Reused from icmp_harness.py (06B-4F/4FR, reviewed): GuardedRunner (every guest command, including the
guest_state snapshot/restore commands, is checked before AND after; the first failure stops the group and no
further command reaches the guest), the service link command/parser (HTTP 200 + fixture hash) and
malformed_records().

Live controls (plan T14 §3), evaluated by the callback that arp_cases.run_group() calls after the case:
  T14-A1 (192.168.60.2 = worker eth0): the control container ct01-06b3b-ctl on sandboxnet logs, every cycle,
         its HTTP check of worker-eth0:8011 and right after it its own ARP entry for the worker
         (ctl_loop.py --arp-worker: /proc/net/arp, complete flag, MAC). Needed: both OK at or before read A and
         at or after read B (within CTL_SLACK_S), no failure in that span, every ARP entry with the MAC of the
         worker's eth0, and the case target equal to the worker's eth0 address.
  T14-A2 (192.168.60.10 = manager): ctl HTTP check of manager:8011 OK before/after the case window with no
         failure; then the worker calls the manager (HTTP 200) and its own neighbour table must hold exactly one
         usable entry 192.168.60.10 dev eth0 with the manager's MAC (from the run script), and the case target
         must equal the manager address.
  06B-4IR1: the ARP payload must be exactly {ip, hw, flags, device, device_mac} with ip = worker address, complete
  flag, hw = worker eth0 MAC, and device_mac = ctl's sandboxnet endpoint MAC (docker inspect in the run script,
  CT01_TARGETS.ctl_mac): the interface is identified by that MAC, its name is NOT assumed; one device in the window.
  06B-4IR2: both MACs must be usable unicast endpoint MACs (not all-zero, not multicast/broadcast); equal unusable
  values are rejected.
  Every ctl line must have exactly the producer's keys; an OK HTTP record must carry "HTTP 200"; duplicate records
  (same target and ts) or a ts not after the previous one of that target are reported, never removed.
  (Corrected in 06B-4IR1: in 06B-4I a wrong/missing device, duplicate lines and HTTP records without a payload
  were accepted.) Anything missing, unreadable, malformed or different -> the control is not alive -> the case is
  at best CHƯA KIỂM CHỨNG (arp_cases rule); this holds for the conditions checked here and tested offline. A control says nothing about the guest; it only shows that the same IP answers ARP on
  sandboxnet while the guest's request is dropped at tap0.
"""
import collections
import json
import math
import os
import re
import sys

import arp_cases as A
import icmp_harness as IH

RECORD_FILE = "arp-group.json"
EVAL_FILE = "arp-eval.json"
NEIGH_CMD = ("ip", "-j", "neigh", "show")     # worker netns, whole table (with "-j ... dev X" iproute2 omits "dev")
LINK_ROLE = ("guest-worker service link: precondition before the group and after every restored case, NOT a "
             "live control for the ARP targets")
CTL_SLACK_S = 3.0          # same span as probe_matrix.ctl_log_window (06B-3B)
CTL_WAIT_MARGIN_S = 0.6    # ctl writes a cycle about every 0.5 s: wait for one beyond the span
CTL_WAIT_MAX_S = 10.0
BOUND_STATES = ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT")
_MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}")
ATF_COM = 0x2


def norm_mac(m):
    return A.L._norm_mac(m)


# ------------------------------------------------------------------ live controls (T14-A1, T14-A2)
def ctl_target_http_worker(ip):
    return f"worker-eth0 {ip}:8011"


def ctl_target_arp_worker(ip):
    return f"arp worker-eth0 {ip}"


def ctl_target_http_manager(ip):
    return f"manager {ip}:8011"


CTL_KEYS = {"ts", "target", "ok", "detail"}                  # ctl_loop.py writes exactly these keys
HTTP_OK_DETAIL = "HTTP 200"                                    # ctl_loop.http_health() return value on success
ARP_DETAIL_KEYS = {"ip", "hw", "flags", "device", "device_mac"}  # ctl_loop.arp_entry() (06B-4IR1)
_IFNAME = re.compile(r"[A-Za-z0-9_.@-]{1,15}")


def endpoint_mac_problem(mac):
    """06B-4IR2 (IR1-R2): a MAC that can identify one Ethernet endpoint: 6 lower-case hex octets, not all zero (no
    address) and not a group address (I/G bit 0x01 of the first octet: multicast, broadcast). A locally administered
    unicast MAC (U/L bit 0x02, as Docker assigns) is valid. -> problem text or None."""
    if not isinstance(mac, str) or not _MAC.fullmatch(mac):
        return f"{mac!r} is not a MAC address"
    if mac == "00:00:00:00:00:00":
        return f"{mac} is the all-zero MAC (no endpoint address)"
    if int(mac[:2], 16) & 0x01:
        return f"{mac} is a group (multicast/broadcast) MAC, not one endpoint"
    return None


def ctl_records(text):
    """ctl.jsonl -> list of {"ts", "target", "ok", "detail"}. 06B-4IR1: every line must be an object with exactly
    the producer's keys, a finite numeric ts, a string target and a boolean ok; anything else raises ValueError
    (never skipped). Payloads are checked per target type by ctl_window()."""
    out = []
    for i, line in enumerate((text or "").splitlines()):
        if not line.strip():
            continue
        r = json.loads(line)
        if not isinstance(r, dict) or set(r) != CTL_KEYS or not isinstance(r["target"], str) \
                or not isinstance(r["ok"], bool) or not isinstance(r["ts"], (int, float)) or isinstance(r["ts"], bool) \
                or not math.isfinite(r["ts"]):
            raise ValueError(f"ctl line {i + 1} malformed: {line[:120]!r}")
        out.append(r)
    return out


def http_detail_check(d):
    """06B-4IR1: an OK HTTP control record carries exactly the producer's success payload."""
    return None if d == HTTP_OK_DETAIL else f"HTTP control detail {d!r} != {HTTP_OK_DETAIL!r}"


def ctl_window(records, target, t0, t1, slack, check=None):
    """One exact ctl target around the case window [t0, t1]: an OK record in [t0 - slack, t0] and one in
    [t1, t1 + slack], no failed record in [t0 - slack, t1 + slack]; check(detail) -> problem or None for every
    OK record in that span. Same rule as probe_matrix.ctl_log_window (06B-3B) plus the per-record check.
    06B-4IR1: a failed record must carry a string detail (the producer's repr of the error); two records of the
    target with the same ts (duplicate identity) or a ts not after the previous one of that target, in file order,
    are reported and never removed: the window is then not ok."""
    before = after = False
    fails, problems, last = 0, [], None
    for r in records:
        if r["target"] != target or not (t0 - slack <= r["ts"] <= t1 + slack):
            continue
        if last is not None and r["ts"] <= last:
            problems.append(f"t={r['ts']:.6f}: {'duplicate record (same target and ts)' if r['ts'] == last else 'ts not after the previous record of this target'}")
        last = r["ts"] if last is None else max(last, r["ts"])
        if not r["ok"]:
            fails += 1
            if not isinstance(r["detail"], str):
                problems.append(f"t={r['ts']:.3f}: failed record without a string detail: {r['detail']!r}")
            continue
        p = check(r["detail"]) if check else None
        if p:
            problems.append(f"t={r['ts']:.3f}: {p}")
            continue
        if r["ts"] <= t0:
            before = True
        elif r["ts"] >= t1:
            after = True
    return {"target": target, "ok_before": before, "ok_after": after, "fails_in_window": fails,
            "problems": problems[:5], "problem_count": len(problems),
            "ok": before and after and fails == 0 and not problems}


def _arp_detail_check(mac, ip, ctl_mac, devices):
    """ctl_loop.arp_entry() payload: exactly ip/hw/flags/device/device_mac; the entry of the worker address, complete
    (ATF_COM), with the worker eth0 MAC, on the ctl interface whose MAC is ctl's sandboxnet endpoint MAC (from
    docker inspect, run script) - the interface NAME is not assumed. `devices` collects the names seen."""
    def check(d):
        if not isinstance(d, dict) or set(d) != ARP_DETAIL_KEYS:
            return f"ARP detail {d!r} is not an object with exactly {sorted(ARP_DETAIL_KEYS)}"
        if d["ip"] != ip:
            return f"ARP entry for {d['ip']!r} != worker address {ip!r}"
        try:
            flags = int(d["flags"], 16) if isinstance(d["flags"], str) else None
        except ValueError:
            flags = None
        if flags is None or not flags & ATF_COM:
            return f"ARP entry not complete (flags {d['flags']!r})"
        if d["hw"] != mac:
            return f"ARP entry MAC {d['hw']!r} != worker eth0 MAC {mac!r}"
        if not isinstance(d["device"], str) or not _IFNAME.fullmatch(d["device"]):
            return f"ARP entry device {d['device']!r} missing or invalid"
        bad = endpoint_mac_problem(d["device_mac"])
        if bad:
            return f"ARP entry device_mac unusable to identify the ctl interface: {bad}"
        if d["device_mac"] != ctl_mac:
            return (f"ARP entry device {d['device']!r} has MAC {d['device_mac']!r}, not ctl's sandboxnet endpoint MAC "
                    f"{ctl_mac!r}")
        devices.add(d["device"])
        return None
    return check


def control_a1(case, records, t0, t1, slack, worker_ip, eth0_mac, ctl_mac=None):
    problems = []
    if case.get("dst") != worker_ip:
        problems.append(f"case target {case.get('dst')} is not the worker eth0 address {worker_ip!r}")
    if not isinstance(eth0_mac, str) or not _MAC.fullmatch(eth0_mac):
        problems.append(f"worker eth0 MAC {eth0_mac!r} unknown or invalid")
    cmac = ctl_mac.lower() if isinstance(ctl_mac, str) else None
    bad = endpoint_mac_problem(cmac)
    if bad:      # 06B-4IR2: also all-zero / group MACs, never accepted because the payload carries the same value
        problems.append(f"ctl sandboxnet endpoint MAC {ctl_mac!r} unknown or invalid ({bad}): the ctl interface cannot "
                        "be identified")
    devices = set()
    http = ctl_window(records, ctl_target_http_worker(worker_ip), t0, t1, slack, http_detail_check)
    arp = ctl_window(records, ctl_target_arp_worker(worker_ip), t0, t1, slack,
                     _arp_detail_check(eth0_mac, worker_ip, cmac, devices))
    if len(devices) > 1:
        problems.append(f"ctl ARP entries on more than one device in the window: {sorted(devices)}")
    ok = not problems and http["ok"] and arp["ok"]
    return ok, {"control": "T14-A1: ctl on sandboxnet resolves the worker eth0 address by ARP (ctl /proc/net/arp, on "
                           "its sandboxnet interface) and reaches it (HTTP 200), before and after the case",
                "worker_ip": worker_ip, "worker_eth0_mac": eth0_mac, "ctl_sandboxnet_mac": cmac,
                "ctl_devices": sorted(devices), "window": [t0, t1], "ctl_http": http, "ctl_arp": arp,
                "problems": problems}


def control_a2(case, records, t0, t1, slack, manager_ip, manager_mac, worker_http, read_neigh):
    problems = []
    if case.get("dst") != manager_ip:
        problems.append(f"case target {case.get('dst')} is not the manager address {manager_ip!r}")
    mac = manager_mac.lower() if isinstance(manager_mac, str) else None
    if mac is None or not _MAC.fullmatch(mac):
        problems.append(f"manager MAC {manager_mac!r} unknown or invalid")
    ctl = ctl_window(records, ctl_target_http_manager(manager_ip), t0, t1, slack, http_detail_check)
    try:
        wh = worker_http()
    except Exception as e:                                       # noqa: BLE001
        wh = {"ok": False, "detail": f"{type(e).__name__}: {e}"}
    if not (isinstance(wh, dict) and wh.get("ok") is True):
        problems.append(f"worker -> manager HTTP not ok: {wh!r}")
    entry = None
    try:
        rows, probs, unknown = A.parse_neigh_full(read_neigh())
        mine = [r for r in rows if r["dst"] == manager_ip and r["dev"] == "eth0"]
        if A._maybe(unknown, manager_ip, "eth0"):
            problems.append(f"worker neighbour table has unreadable row(s) that may be {manager_ip} dev eth0")
        if len(mine) != 1:
            problems.append(f"worker neighbour {manager_ip} dev eth0: {len(mine)} valid row(s), expected exactly 1")
        else:
            entry = mine[0]
            if not (entry["binding"] and len(entry["states"]) == 1 and entry["states"][0] in BOUND_STATES
                    and entry["lladdr"] == mac):
                problems.append(f"worker neighbour {manager_ip} dev eth0 is not a usable binding to the manager "
                                f"MAC {mac}: {entry}")
    except Exception as e:                                       # noqa: BLE001  (NeighReadError, collector error)
        problems.append(f"worker neighbour table not readable: {type(e).__name__}: {e}")
    ok = not problems and ctl["ok"]
    return ok, {"control": "T14-A2: the manager answers on sandboxnet (ctl HTTP before/after the case) and the "
                           "worker resolves it by ARP on eth0 (ip -j neigh show after a worker HTTP call)",
                "manager_ip": manager_ip, "manager_mac": mac, "window": [t0, t1], "ctl_http": ctl,
                "worker_http": wh, "worker_neighbour": entry, "problems": problems}


def make_control(windows, read_ctl, cfg, eth0_mac, worker_http, read_neigh, now, sleep, slack=CTL_SLACK_S):
    """-> control(case) for arp_cases.run_group(). windows: {case id: {"before": (t_start, t_end), "after": ...}}
    filled by the counter-read wrapper; read_ctl() -> ctl.jsonl text. Never raises: arp_cases records an exception
    as a failed control anyway, but the detail is kept here."""
    def control(case):
        w = windows.get(case.get("id")) or {}
        if "before" not in w or "after" not in w:
            return False, {"problems": [f"counter read window of {case.get('id')} unknown: no control window"]}
        t0, t1 = w["before"][0], w["after"][1]
        wait = t1 + slack + CTL_WAIT_MARGIN_S - now()
        if wait > 0:
            sleep(min(wait, CTL_WAIT_MAX_S))
        try:
            records = ctl_records(read_ctl())
        except Exception as e:                                   # noqa: BLE001
            return False, {"problems": [f"ctl log not readable: {type(e).__name__}: {e}"], "window": [t0, t1]}
        if case.get("id") == "T14-A1":
            return control_a1(case, records, t0, t1, slack, cfg.get("worker_ip"), eth0_mac, cfg.get("ctl_mac"))
        if case.get("id") == "T14-A2":
            return control_a2(case, records, t0, t1, slack, cfg.get("manager_ip"), cfg.get("manager_mac"),
                              worker_http, read_neigh)
        return False, {"problems": [f"no live control defined for {case.get('id')}"]}
    return control


# ------------------------------------------------------------------ worker side
def run_suite(runner, read_counters, service_link, worker_neigh, control, iface, arch, tap_mac, fixture_sha, anchor=None):
    """Runs the four reviewed cases once (arp_cases.run_group) and annotates the record. Does not raise; the caller
    re-raises runner.stop. rec["stopped"] keeps the arp_cases meaning (a failed restore stopped the group); a stop
    of the guard is kept apart in rec["guard_stopped"]."""
    cases = A.build_cases()
    rec = A.run_group(runner, read_counters, service_link, worker_neigh, control, cases, iface, anchor=anchor)
    rec.update(arch=arch, tap_mac=norm_mac(tap_mac), fixture_sha256=fixture_sha,
               planned_case_ids=[c["id"] for c in cases], service_link_role=LINK_ROLE, neigh_command=list(NEIGH_CMD))
    if runner.stop is not None:
        rec["guard_stopped"] = f"{type(runner.stop).__name__}: {runner.stop}"
    return rec


def restore_name(cid):
    return f"guest configuration restored after {cid} (re-read state equals the baseline)"


def link_after_name(cid):
    return f"allowed service link after {cid} (guest restored): GET get-task/T/file HTTP 200 + fixture hash"


LINK_BEFORE_NAME = "allowed service link before the ARP group: GET get-task/T/file HTTP 200 + fixture hash"
NEIGH_READ_NAME = "worker neighbour table read (ip -j neigh show) before and after every ARP case"
ALL_CASES_NAME = "all four ARP cases recorded exactly once with captures alive"
GROUP_RECORD_NAME = ("ARP group record: each reviewed case exactly once, execution contract, service links "
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
        if gs.get("before") is not None:
            req.append(restore_name(c["id"]))
            if isinstance(gs.get("restore"), dict) and gs["restore"].get("restored") is True:
                req.append(link_after_name(c["id"]))
    return req


# ------------------------------------------------------------------ evaluation
def check_record(record, arch, tap_mac, fixture_sha, iface):
    """Wiring-level problems that forbid concluding the group (arp_cases.record_problems() is added by evaluate()):
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
    """arp_cases.evaluate_group() + the wiring checks -> the object written to arp-eval.json. Never raises."""
    problems = check_record(record, arch, tap_mac, fixture_sha, iface)
    try:
        res = A.evaluate_group(pcap, counters_file, tap_mac, record)
    except Exception as e:                                       # noqa: BLE001  a bug must never pass
        res = {"error": f"{type(e).__name__}: {e}", "cases": [], "record_problems": []}
        problems.append(f"evaluate_group refused the record: {res['error']}")
    case_probs = list(res.get("record_problems") or [])
    gx = A.group_exit(res) if res.get("cases") else 2
    problems += [f"arp_cases: {x}" for x in case_probs]
    ids = collections.Counter(c.get("id") for c in res["cases"])
    if sorted(ids.elements()) != sorted(A.CASE_IDS):
        problems.append(f"evaluated cases {sorted(ids.elements())} are not each of {list(A.CASE_IDS)} exactly once")
    res.update(arch=arch, case_record_problems=case_probs, record_problems=problems, group_complete=not problems,
               group_exit=gx, service_link_role=LINK_ROLE, case_requirements=case_requirements(record),
               inputs={"pcap": pcap, "counters": counters_file, "tap_mac": tap_mac, "iface": iface})
    return res


def case_test_name(case_result):
    """Name of the per-case record in result.json; starts with "probe " so that counter_window.run_outcome()
    treats a CHƯA KIỂM CHỨNG case as undecided and anything else not passed as hard."""
    kind = "live control" if case_result.get("evidence_kind") == "live_control" else "rule check"
    return f"probe {case_result['id']} (arp, {kind}) -> {case_result['verdict']}"


# ------------------------------------------------------------------ host side
# Confirmations that probe_matrix.py records on the real ARP path (main() + run_arp() + evaluate_arp()) and that a
# PASS needs, each EXACTLY ONCE with ok exactly True (06B-4FR rule). Per-case confirmations (restore, service link
# after a restored case) come from arp-eval.json "case_requirements" and follow the same rule.
REQUIRED_RECORDS = (
    "host leak monitor running and empty before boot",
    "full isolation verify right before QEMU spawn (harness pre-boot, not V1)",
    "tshark capturing on tap0",
    "guest booted and network configured",
    "topology gate: only nic/tap, one tap0 backend, pinned MAC on tap NIC and probe interface",
    "capture liveness traffic from the worker before the ARP group (host captures; not a control for the ARP "
    "destinations)",
    LINK_BEFORE_NAME,
    NEIGH_READ_NAME,
    "tap0 MAC unchanged during the ARP group",
    ALL_CASES_NAME,
    "capture liveness traffic from the worker after the ARP group (host captures; not a control for the ARP "
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


def arch_outcome(result, arp_eval, arch):
    """One architecture -> "PASS" | "UNVERIFIED: ..." | "FAIL: ...". counter_window.run_outcome() on every record
    plus: well-formed records, every REQUIRED_RECORDS and per-case confirmation exactly once with ok True, status
    COMPLETED, an evaluation of this architecture with each case exactly once (also in result.json), no record
    problem, and arp_cases.group_exit() not 1/2. A passed case never hides another failed or missing check."""
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        return "FAIL: result.json unreadable or without results"
    bad = IH.malformed_records(result["results"])
    if bad:
        return f"FAIL: result record(s) {bad[:5]} not an object with a string 'test' and a boolean 'ok'"
    hard = required_problems(result["results"], REQUIRED_RECORDS)
    if result.get("status") != "COMPLETED":
        hard.append(f"status {result.get('status')!r}")
    if not isinstance(arp_eval, dict):
        hard.append("arp-eval.json missing or unreadable")
    else:
        if arp_eval.get("arch") != arch:
            hard.append(f"arp-eval arch {arp_eval.get('arch')!r} != {arch!r}")
        if arp_eval.get("record_problems") or arp_eval.get("group_complete") is not True:
            hard.append(f"group record not complete/valid: {arp_eval.get('record_problems')}")
        if arp_eval.get("group_exit") not in (0, 4):
            hard.append(f"arp_cases group exit {arp_eval.get('group_exit')!r}")
        reqs = arp_eval.get("case_requirements")
        if not isinstance(reqs, list) or not all(isinstance(x, str) for x in reqs):
            hard.append("arp-eval case_requirements missing or invalid")
        else:
            hard += required_problems(result["results"], reqs)
        ids = collections.Counter(c.get("id") for c in arp_eval.get("cases") or [] if isinstance(c, dict))
        if sorted(ids.elements()) != sorted(A.CASE_IDS):
            hard.append(f"arp-eval cases {sorted(ids.elements())} are not each case exactly once")
        names = collections.Counter(r.get("test") for r in result["results"] if isinstance(r, dict))
        for c in arp_eval.get("cases") or []:
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
        print("\n".join(p) if p else "ARP groups complete: " + " ".join(argv[2:]))
        return 1 if p else 0
    print("usage: arp_harness.py --outcome RESULT ARP_EVAL ARCH | --run-check PROBE_DIR ARCH...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
