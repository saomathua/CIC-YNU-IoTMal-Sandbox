#!/usr/bin/env python3
"""06B-4H/06B-4HR — T14/T15 ARP cases (prepared OFFLINE; not executed, not wired into a run script).

Scope (plan docs/ct01-remaining-tests-plan.md T14, T15 level 1; reviewer decisions D1, D2, D6):
    T14-A1  ARP request for 192.168.60.2 (worker eth0)   expected arp_in_drop   live control (ARP on sandboxnet)
    T14-A2  ARP request for 192.168.60.10 (manager)      expected arp_in_drop   live control (ARP on sandboxnet)
    T14-A3  ARP request for 10.200.0.6 (no host)         expected arp_in_drop   rule check
            meant to be made by the GUEST KERNEL: an on-link /32 route + one ping (sizes from signatures.py);
            the guest has no arping, and no ICMP is sent while the ARP does not resolve.
    T15-S1  gratuitous ARP REQUEST meant to be made by the GUEST KERNEL (arp_notify=1, secondary /32 addresses
            10.200.0.1, 192.168.60.10, 192.168.60.1, link down/up)   expected arp_in_drop   rule check + worker
            neighbour check
NOT covered (D1): forged ARP replies, gratuitous replies, wrong htype/hlen/plen; no tool is added, no raw packet.
Every guest/kernel behaviour above is an ASSUMPTION; the offline tests only SIMULATE it.

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
CASE_IDS = ("T14-A1", "T14-A2", "T14-A3", "T15-S1")
T15_SPOOF_IPS = ("10.200.0.1", "192.168.60.10", "192.168.60.1")
CATEGORIES = ("DAT", "DAT_KIEM_QUY_TAC", "FAIL", "LOI_PHEP_DO", "LOI_THUC_THI", "KHONG_TAO_DUOC_GOI",
              "CHUA_KIEM_CHUNG")
NOT_RUN = "CHƯA KIỂM CHỨNG (cấu hình guest chưa khôi phục ở ca trước: ca này không chạy)"
PHASES = ("setup", "trigger", "settle")


def _iface_ok(iface):
    if not isinstance(iface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface):
        raise ValueError(f"bad interface name {iface!r}")
    return iface


def build_cases():
    return [
        {"id": "T14-A1", "kind": "t14", "dst": "192.168.60.2", "size": S.ICMP4_SIZES["T14-A1"],
         "expected": "arp_in_drop", "control_kind": "live"},
        {"id": "T14-A2", "kind": "t14", "dst": "192.168.60.10", "size": S.ICMP4_SIZES["T14-A2"],
         "expected": "arp_in_drop", "control_kind": "live"},
        {"id": "T14-A3", "kind": "t14", "dst": "10.200.0.6", "size": S.ICMP4_SIZES["T14-A3"],
         "expected": "arp_in_drop", "control_kind": "rule_check"},
        {"id": "T15-S1", "kind": "t15", "spoof": list(T15_SPOOF_IPS), "expected": "arp_in_drop",
         "control_kind": "rule_check"},
    ]


def commands(case, iface):
    """-> {"setup": [...], "trigger": [...], "settle": [...]}: the exact busybox commands, nothing else."""
    _iface_ok(iface)
    if case["kind"] == "t14":
        dst = str(ipaddress.IPv4Address(case["dst"]))
        return {"setup": [f"ip route add {dst}/32 dev {iface}"],
                "trigger": [f"ping -c 1 -W {PING_WAIT_S} -s {int(case['size'])} {dst}"],
                "settle": [f"sleep {SETTLE_S}"]}
    if case["kind"] == "t15":
        ips = [str(ipaddress.IPv4Address(a)) for a in case["spoof"]]
        return {"setup": [f"echo 1 > /proc/sys/net/ipv4/conf/{iface}/arp_notify"]
                + [f"ip addr add {a}/32 dev {iface}" for a in ips],
                "trigger": [f"ip link set dev {iface} down", f"ip link set dev {iface} up"],
                "settle": [f"sleep {SETTLE_S}"]}
    raise ValueError(f"unknown case kind {case.get('kind')!r}")


def contract_steps(case, iface):
    """[(phase, cmd)] in execution order."""
    c = commands(case, iface)
    return [(ph, cmd) for ph in PHASES for cmd in c[ph]]


def rc_ok(phase, cmd, rc):
    """06B-4HR execution contract for one step."""
    if not isinstance(rc, int) or isinstance(rc, bool):
        return False
    if phase == "trigger" and cmd.startswith("ping "):
        return rc in PING_RC_OK
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
    return [case["dst"]] if case["kind"] == "t14" else list(case["spoof"])


# ------------------------------------------------------------------ execution (prepared, not run here)
def _call(fn, *a):
    try:
        return fn(*a), None
    except Exception as e:                                       # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def _link(service_link):
    try:
        ok, detail = service_link()
    except Exception as e:                                       # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    return {"ok": ok is True, "detail": detail}


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
ANCHOR_LABEL = "ARP group anchor"
ANCHOR_GAP_S = 0.25


def run_group(runner, read_counters, service_link, worker_neigh, control, cases, iface, timeout=60, anchor=None, sleep=None):
    """runner.run(cmd, timeout) -> (rc, text); read_counters(label); service_link() -> (ok, detail);
    worker_neigh() -> `ip -j neigh show` text of the worker netns; control(case) -> (ok, detail) for live-control
    cases; anchor() takes the ANCHOR_LABEL counter read (optional; once, before the first executed case's before-read). Returns the group
    record. Never raises: every failure is recorded."""
    _iface_ok(iface)
    rec = {"iface": iface, "cases": [], "service_link_before": _link(service_link), "stopped": None}
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
            steps = contract_steps(c, iface)
        except ValueError as e:
            r["exec_error"] = f"commands not built: {e}"
            rec["cases"].append(r)
            continue
        r["neigh_before"], err = _call(worker_neigh)
        if err:
            r["neigh_before_error"] = err
        gc = GS.GuestChange(runner, iface)
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
            res, err = _call(control, c)
            # 06B-4HR1 (HR5): check the payload shape before using it; a malformed payload is a recorded failed
            # control, never an exception that loses the case record
            if err:
                r["control"] = {"ok": False, "detail": err}
            elif isinstance(res, (tuple, list)) and len(res) == 2:
                r["control"] = {"ok": res[0] is True, "detail": res[1]}
            else:
                r["control"] = {"ok": False, "detail": f"control callback returned {type(res).__name__} {res!r}: "
                                                       "expected (ok, detail)"}
        if restored:
            r["service_link_after"] = _link(service_link)
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


def baseline_problem(before):
    if not isinstance(before, dict):
        return "guest baseline missing"
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


def restore_problem(restore, before=None):
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
    bad = baseline_problem(after)
    if bad:
        return f"restore 'after' state invalid: {bad.replace('guest baseline', 'after')}"
    if baseline_problem(before) is None:
        d = GS.diff(_gs_state(before), _gs_state(after))
        if d:
            return f"restore says restored but the re-read state differs from the baseline: {d}"
    return None


def execution_problems(case, crec, iface):
    """Is the case's execution record complete and inside the contract?
    COMPLETED case (no exec_error): steps == every contract step, in order, phase and command exact, rc within the
    contract; valid guest baseline; restore evidence.
    STOPPED case (exec_error): steps are a prefix of the contract; every step but the last within the contract and
    the last one outside it (or rc None = exception), unless the case stopped before any step (baseline unreadable:
    no step, no baseline, no restore) or after them; baseline + restore evidence whenever a baseline was taken."""
    if crec.get("not_run"):
        return [] if not crec.get("steps") else ["case marked not run but has steps"]
    try:
        want = contract_steps(case, iface)
    except ValueError as e:
        return [f"commands not built: {e}"]
    steps = crec.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        return ["steps missing or not a list of objects"]
    got = [(s.get("phase"), s.get("cmd")) for s in steps]
    gs = crec.get("guest_state") if isinstance(crec.get("guest_state"), dict) else {}
    before, restore = gs.get("before"), gs.get("restore")
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
        for x in (baseline_problem(before), restore_problem(restore, before)):
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
    for x in (baseline_problem(before), restore_problem(restore, before)):
        if x:
            p.append(x)
    return p


# ------------------------------------------------------------------ evaluation
def _arp(f):
    a = f.get("arp") or {}
    return None if a.get("short") or "spa" not in a else a


def is_probe_frame(f, case):
    """Guest ARP REQUEST frames of this case, identified by their ARP fields (never by the counter class):
    Ethernet/IPv4 ARP (htype 1, ptype 0x0800, hlen 6, plen 4), opcode 1, sender MAC = guest.
    T14: spa 10.200.0.2, tpa = target. T15 (06B-4HR): gratuitous REQUEST, spa = tpa, broadcast destination; an
    opcode 2/99 frame is never a probe (forged/gratuitous replies are out of scope, D1)."""
    if f.get("direction") != "guest" or f.get("etype") != L.ETH_ARP:
        return False
    a = _arp(f)
    if a is None or a.get("sha") != L._norm_mac(S.GUEST_MAC):
        return False
    if (a.get("htype"), a.get("ptype"), a.get("hlen"), a.get("plen"), a.get("op")) != (1, L.ETH_IPV4, 6, 4, 1):
        return False
    if case["kind"] == "t14":
        return a["spa"] == S.GUEST_IP and a["tpa"] == case["dst"]
    return (a["spa"] == a["tpa"] and a["spa"] in (S.GUEST_IP,) + tuple(case["spoof"])
            and f.get("dst") == L.BROADCAST)


def determined_problems(window, case):
    """Frames that prove a failure for this case (independent of counters)."""
    p = []
    for f in window:
        a = _arp(f) if f.get("etype") == L.ETH_ARP else None
        if f.get("direction") == "worker" and a:
            ips = {a.get("spa"), a.get("tpa")}
            if case["kind"] == "t14" and a.get("spa") == case["dst"]:
                p.append(f"ARP reply/announcement for {case['dst']} towards the guest at t={f['t']:.6f}")
            if case["kind"] == "t15" and ips & set(case["spoof"]):
                p.append(f"worker ARP about a spoofed IP {sorted(ips & set(case['spoof']))} at t={f['t']:.6f}")
        if case["kind"] == "t14" and f.get("direction") == "guest":
            ip = f.get("ip") or {}
            if ip.get("hdr_ok") and ip.get("dst") == case["dst"] and ip.get("proto") == 1 \
                    and ip.get("tot_len") == case["size"] + 28:
                p.append(f"probe IPv4 packet to {case['dst']} sent at t={f['t']:.6f}: the ARP was resolved")
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


def evaluate_case(frames, reads, case, crec, link_before_ok, guard=GUARD_S, iface=None, input_error=None):
    """frames: l2frames.classified_frames() or None (capture unreadable); reads: l2eval.load_reads() or None.
    06B-4HR order: (1) collect failure evidence that does not depend on the failed measurement (worker
    neighbours from valid rows; frames only inside a VALID window; counter reconciliation only with valid
    counters); (2) FAIL if any, keeping the measurement errors; (3) LỖI PHÉP ĐO; (4) the rest."""
    cid = case["id"]
    kind = case["control_kind"]
    iface = iface if iface is not None else crec.get("iface")
    ek = {"evidence_kind": "rule_check" if kind == "rule_check" else "live_control"}
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
        failure += determined_problems(window, case)
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
    exec_probs = execution_problems(case, crec, iface) if iface is not None else ["record interface unknown"]
    detail = {"probe_frames": len(probe), "probe_frames_certain": len(certain),
              "probe_frame_classes": sorted({f["cls"] for f in probe}),
              "failure_evidence": failure, "measurement_errors": measure, "execution_problems": exec_probs,
              "neighbour_inconclusive": nc["inconclusive"], "arp_out_drop_delta": out_drop,
              "reconciliation": None if recon is None else
              {k: recon.get(k) for k in ("verdict", "per_class", "no_counter_frames", "guard_s", "closure")},
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
    # (5) no probe frame (or, T15, no gratuitous request for some spoofed IP): never evidence of blocking
    if not probe:
        return _result(cid, "KHONG_TAO_DUOC_GOI", "CHƯA KIỂM CHỨNG (không tạo được khung ARP probe; không phải "
                       "bằng chứng chặn)", **detail)
    if case["kind"] == "t15":
        seen = {(f.get("arp") or {}).get("spa") for f in probe}
        lack = [a for a in case["spoof"] if a not in seen]
        if lack:
            return _result(cid, "KHONG_TAO_DUOC_GOI", f"CHƯA KIỂM CHỨNG (không có gratuitous ARP request cho {lack})",
                           **detail)
    # (6) the reviewed verdict function (determined failures were handled above)
    pv = {"probe_packets_in_tap0_pcap": True, "probe_packets_hit_expected_counter": True,
          "no_frame_proving_failure": True, "worker_neighbours_unchanged": True}
    if kind == "live":
        text, ok = L.probe_verdict_l2(pv, recon, case["expected"], "live", control_alive=link_ok(crec.get("control")))
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
    if not link_ok(crec.get("service_link_after")):
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ sau ca thử không đạt)", **detail)
    return _result(cid, "DAT" if kind == "live" else "DAT_KIEM_QUY_TAC", text, **detail)


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
    defs = {c["id"]: c for c in build_cases()}
    for c in record["cases"]:
        d = defs.get(c.get("id"))
        if d is None:
            continue
        if not c.get("not_run") and (c.get("before") != f"{d['id']} before" or c.get("after") != f"{d['id']} after"):
            p.append(f"{d['id']}: counter read labels differ from the reviewed ones")
        p += [f"{d['id']}: {x}" for x in execution_problems(d, c, record.get("iface"))]
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
    lb = link_ok(record.get("service_link_before"))
    for crec in record["cases"]:
        if crec.get("id") not in cases:
            out["cases"].append(_result(str(crec.get("id")), "LOI_PHEP_DO", "LỖI PHÉP ĐO (unknown case id)"))
            continue
        out["cases"].append(evaluate_case(frames, reads, cases[crec["id"]], crec, lb, guard,
                                          iface=record.get("iface"), input_error=input_error))
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
    ap = argparse.ArgumentParser(description="evaluate a recorded T14/T15 ARP group (offline)")
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
