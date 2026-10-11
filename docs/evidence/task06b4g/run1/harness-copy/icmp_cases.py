#!/usr/bin/env python3
"""06B-4E — T12/T13 ICMP cases (prepared OFFLINE; not executed in this task).

Scope: firewall rule checks with the guest's OWN busybox `ping` / `ping6` only:
    T12-B1  ICMP echo to 255.255.255.255   expected drop_bcast_mcast
    T12-B2  ICMP echo to 224.0.0.1         expected drop_bcast_mcast
    T12-B4  ICMP echo to 10.200.0.3        expected drop_private   (subnet broadcast, see plan L3)
    T13-I1  ICMPv6 echo to ff02::1         expected l2_bad_ethertype
    T13-I2  ICMPv6 echo to the EUI-64 link-local of TAP_MAC: tap0 has no IPv6, so only Neighbor
            Solicitations to its solicited-node group are expected; expected l2_bad_ethertype
Nothing here spoofs, changes the guest configuration, builds raw packets or adds a tool.
Sizes come ONLY from signatures.py (ICMP4_SIZES / ICMP6_SIZES).

There is NO live control for these destinations: a pass is reported only as "ĐẠT (kiểm quy tắc)"
(rule matched and dropped at the right place) and evidence_kind is always "rule_check".

Three layers, all injectable for offline tests:
  build_cases(tap_mac)                       case definitions
  run_group(runner, read_counters, service_link, cases, iface)
                                             executes in a guest (NOT called in this task): service link
                                             before -> per case: read A, ping, read B -> service link after
  evaluate_group(pcap, counters_file, tap_mac, record)
                                             capture + counters-raw.jsonl -> per-case verdicts, using the
                                             reviewed l2frames.reconcile_l2 / l2eval.load_reads / check_classes

Categories (never mixed):
  LOI_THUC_THI          the ping could not be run in the guest (console error/timeout, tool missing)
  KHONG_TAO_DUOC_GOI    it ran but no probe frame is in the tap0 capture (e.g. broadcast refused locally)
  LOI_PHEP_DO           capture unreadable, counter read failed/missing/invalid
  FAIL                  a determined failure (counter mismatch, probe frame in another class, a reply
                        towards the guest)
  CHUA_KIEM_CHUNG       edge frames, frames without a counter, service link not intact
  DAT_KIEM_QUY_TAC      "ĐẠT (kiểm quy tắc)"
A ping that times out / gets no reply is NEVER evidence of blocking; only the counter/pcap reconciliation is.
"""
import argparse
import ipaddress
import json
import re
import sys

import counter_window
import l2eval
import l2frames as L
import signatures as S

GUARD_S = counter_window.GUARD_S      # 20 ms, unmeasured assumption (unchanged)
COUNT = 3                             # echo requests per case (only a hint: the criterion is delta == frames)
DEADLINE_S = 5                        # busybox -w: overall deadline of one ping
CASE_IDS = ("T12-B1", "T12-B2", "T12-B4", "T13-I1", "T13-I2")
CATEGORIES = ("DAT_KIEM_QUY_TAC", "FAIL", "LOI_PHEP_DO", "LOI_THUC_THI", "KHONG_TAO_DUOC_GOI", "CHUA_KIEM_CHUNG")
EXIT = {"DAT_KIEM_QUY_TAC": 0, "FAIL": 1, "CHUA_KIEM_CHUNG": 4, "KHONG_TAO_DUOC_GOI": 4, "LOI_THUC_THI": 4,
        "LOI_PHEP_DO": 2}


def _iface_ok(iface):
    if not isinstance(iface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface):
        raise ValueError(f"bad interface name {iface!r}")
    return iface


def solicited_node(addr):
    a = ipaddress.IPv6Address(addr).packed
    return str(ipaddress.IPv6Address(bytes.fromhex("ff02" + "0000" * 4 + "0001" + "ff") + a[13:]))


def build_cases(tap_mac):
    tap = L._norm_mac(tap_mac)
    tap_ll = S.eui64_ll(tap)
    return [
        {"id": "T12-B1", "family": 4, "dst": "255.255.255.255", "size": S.ICMP4_SIZES["T12-B1"], "expected": "drop_bcast_mcast"},
        {"id": "T12-B2", "family": 4, "dst": "224.0.0.1", "size": S.ICMP4_SIZES["T12-B2"], "expected": "drop_bcast_mcast"},
        {"id": "T12-B4", "family": 4, "dst": "10.200.0.3", "size": S.ICMP4_SIZES["T12-B4"], "expected": "drop_private"},
        {"id": "T13-I1", "family": 6, "dst": "ff02::1", "size": S.ICMP6_SIZES["T13-I1"], "expected": "l2_bad_ethertype"},
        {"id": "T13-I2", "family": 6, "dst": tap_ll, "size": S.ICMP6_SIZES["T13-I2"], "expected": "l2_bad_ethertype",
         "ns_group": solicited_node(tap_ll)},
    ]


def command(case, iface):
    """The exact guest command (busybox ping / ping6). Sizes and addresses come from the case."""
    _iface_ok(iface)
    size, dst = int(case["size"]), case["dst"]
    if case["family"] == 4:
        ipaddress.IPv4Address(dst)
        return f"ping -c {COUNT} -s {size} -w {DEADLINE_S} {dst}"
    ipaddress.IPv6Address(dst)
    return f"ping6 -c {COUNT} -s {size} -w {DEADLINE_S} -I {iface} {dst}"


# ------------------------------------------------------------------ execution (prepared, not run here)
def run_group(runner, read_counters, service_link, cases, iface, timeout=60):
    """runner.run(cmd, timeout) -> (rc, text); read_counters(label) -> anything (it must append the read
    to counters-raw.jsonl under `label`); service_link() -> (ok: bool, detail: str).
    Returns the group record consumed by evaluate_group(). Never raises: every failure is recorded."""
    rec = {"iface": iface, "cases": [], "service_link_before": None, "service_link_after": None}
    try:
        ok, detail = service_link()
    except Exception as e:                                       # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    rec["service_link_before"] = {"ok": bool(ok), "detail": detail}
    if not ok:
        rec["skipped"] = "service link before the group failed: no case was run"
        return rec
    for c in cases:
        r = {"id": c["id"], "before": f"{c['id']} before", "after": f"{c['id']} after", "command": None,
             "exec": None, "read_error": None}
        try:
            r["command"] = command(c, iface)
        except ValueError as e:
            r["exec"] = {"error": f"command not built: {e}"}
            rec["cases"].append(r)
            continue
        try:
            read_counters(r["before"])
        except Exception as e:                                   # noqa: BLE001
            r["read_error"] = f"read {r['before']!r}: {type(e).__name__}: {e}"
        try:
            rc, out = runner.run(r["command"], timeout=timeout)
            r["exec"] = {"rc": rc, "output_tail": (out or "")[-300:]}
            if rc == 127 or "not found" in (out or ""):
                r["exec"]["error"] = "tool missing in the guest"
        except Exception as e:                                   # noqa: BLE001
            r["exec"] = {"error": f"{type(e).__name__}: {e}"}
        try:
            read_counters(r["after"])
        except Exception as e:                                   # noqa: BLE001
            r["read_error"] = (r["read_error"] + "; " if r["read_error"] else "") + \
                f"read {r['after']!r}: {type(e).__name__}: {e}"
        rec["cases"].append(r)
    try:
        ok, detail = service_link()
    except Exception as e:                                       # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    rec["service_link_after"] = {"ok": bool(ok), "detail": detail}
    return rec


# ------------------------------------------------------------------ evaluation
def is_probe_frame(f, case):
    """Frames sent by the guest for this case (identified by destination and on-wire size)."""
    if f.get("direction") != "guest":
        return False
    if case["family"] == 4:
        ip = f.get("ip") or {}
        return (ip.get("hdr_ok") and ip.get("src") == S.GUEST_IP and ip.get("dst") == case["dst"]
                and ip.get("proto") == 1 and ip.get("tot_len") == case["size"] + 28)
    v6 = f.get("ip6") or {}
    if not v6.get("hdr_ok") or v6.get("nh") != 58:
        return False
    if v6.get("icmp6_type") == 128 and v6.get("dst") == case["dst"] and v6.get("plen") == case["size"] + 8:
        return True
    # 06B-4ER: an NS counts only if its decoded TARGET is this case's address (the solicited-node group is
    # shared by every address with the same low 24 bits, so the group alone identifies nothing), and it
    # is sent to that target's group. A missing/undecodable target is never a probe frame.
    return (bool(case.get("ns_group")) and v6.get("icmp6_type") == 135 and v6.get("ns_target") is not None
            and v6.get("ns_target") == case["dst"] and v6.get("dst") == case["ns_group"])


def is_reply_to_guest(f):
    """Any ICMP/ICMPv6 frame addressed to the guest: a reply must never reach it in these cases."""
    if f.get("dst") != S.GUEST_MAC:
        return False
    ip, v6 = f.get("ip") or {}, f.get("ip6") or {}
    return (ip.get("hdr_ok") and ip.get("proto") == 1) or (v6.get("hdr_ok") and v6.get("nh") == 58)


def _result(case_id, category, text, **kw):
    assert category in CATEGORIES
    out = {"id": case_id, "category": category, "verdict": text, "ok": category == "DAT_KIEM_QUY_TAC",
           "evidence_kind": "rule_check"}
    out.update(kw)
    return out


def link_ok(state):
    """06B-4ER: a service-link state counts only if it is an object whose "ok" is exactly True.
    Missing, False, None, "true", 1, a list ... are all "not intact"."""
    return isinstance(state, dict) and state.get("ok") is True


def evaluate_case(frames, reads, case, crec, link_after_ok, guard=GUARD_S, link_before_ok=False):
    """One case. `frames` are l2frames.classified_frames() output, `reads` l2eval.load_reads() output."""
    cid = case["id"]
    classes = l2eval.check_classes(None)           # every frame-mapped counter class
    if crec.get("read_error"):
        return _result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({crec['read_error']})")
    missing = [lbl for lbl in (crec["before"], crec["after"]) if lbl not in reads]
    if missing:
        return _result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO (counter read(s) {missing} not found)")
    ra, rb = reads[crec["before"]], reads[crec["after"]]
    recon = L.reconcile_l2(frames, ra, rb, classes, guard)
    if recon["verdict"] == "ERROR":
        return _result(cid, "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({recon.get('error')})", reconciliation=recon)
    window = [f for f in frames if counter_window.zone(f["t"], ra, rb, guard) != "outside"]
    probe = [f for f in window if is_probe_frame(f, case)]
    certain = [f for f in probe if counter_window.zone(f["t"], ra, rb, guard) == "certain"]
    replies = [f for f in window if is_reply_to_guest(f)]
    checks = {
        "probe_packets_hit_expected_counter": all(f["cls"] == case["expected"] for f in certain),
        "no_reply_to_guest": not replies,
    }
    detail = {"probe_frames": len(probe), "probe_frames_certain": len(certain), "replies_to_guest": len(replies),
              "probe_frame_classes": sorted({f["cls"] for f in probe}), "checks": checks,
              "reconciliation": {k: recon.get(k) for k in ("verdict", "per_class", "no_counter_frames", "guard_s")},
              "exec": crec.get("exec"), "command": crec.get("command")}
    # 1. determined failures win over everything that only prevents judging
    if recon["verdict"] == "FAIL" or not all(checks.values()):
        why = [k for k, v in checks.items() if not v] + (["counter_reconciliation"] if recon["verdict"] == "FAIL" else [])
        return _result(cid, "FAIL", "FAIL", failed=why, **detail)
    # 2. the guest could not run the probe
    ex = crec.get("exec") or {"error": "not executed"}
    if ex.get("error"):
        return _result(cid, "LOI_THUC_THI", f"CHƯA KIỂM CHỨNG (lỗi thực thi: {ex['error']})", **detail)
    # 3. no probe frame: a failed/timed-out ping is NOT evidence of blocking
    if not probe:
        return _result(cid, "KHONG_TAO_DUOC_GOI", "CHƯA KIỂM CHỨNG (không tạo được gói probe; ping rc "
                       f"{ex.get('rc')} không phải bằng chứng chặn)", **detail)
    # 4. the reviewed verdict function, rule-check kind (no live control exists for these targets)
    pv_checks = {"probe_packets_in_tap0_pcap": True, **checks}
    text, ok = L.probe_verdict_l2(pv_checks, recon, case["expected"], "rule_check")
    if text == "FAIL":
        return _result(cid, "FAIL", "FAIL", failed=["probe_verdict"], **detail)
    if not ok:
        return _result(cid, "CHUA_KIEM_CHUNG", text, **detail)
    if not link_before_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ trước nhóm thử thiếu, "
                       "không đạt hoặc không hợp lệ)", **detail)
    if not link_after_ok:
        return _result(cid, "CHUA_KIEM_CHUNG", "CHƯA KIỂM CHỨNG (liên kết dịch vụ sau nhóm thử không đạt)", **detail)
    assert text == "ĐẠT (kiểm quy tắc)"
    return _result(cid, "DAT_KIEM_QUY_TAC", text, **detail)


def evaluate_group(pcap, counters_file, tap_mac, record, guard=GUARD_S):
    """-> {"cases": [...], "group": {...}}. A capture/counter-file problem makes every case LOI_PHEP_DO."""
    cases = {c["id"]: c for c in build_cases(tap_mac)}
    if not isinstance(record, dict) or not isinstance(record.get("cases", []), list) or \
            not all(isinstance(c, dict) for c in record.get("cases", [])):
        raise ValueError("group record must be an object whose 'cases' is a list of objects")
    out = {"guard_s": guard, "assumption": l2eval.ASSUMPTION, "evidence_kind": "rule_check",
           "service_link_before": record.get("service_link_before"),
           "service_link_after": record.get("service_link_after"), "cases": []}
    if record.get("skipped"):
        out["cases"] = [_result(cid, "CHUA_KIEM_CHUNG", f"CHƯA KIỂM CHỨNG ({record['skipped']})") for cid in CASE_IDS]
        return out
    try:
        frames = L.classified_frames(pcap, tap_mac)
        reads = l2eval.load_reads(counters_file)
        err = None
    except L.FrameReadError as e:
        err = f"capture read error: {e}"
    except l2eval.InputError as e:
        err = f"invalid measurement data: {e}"
    if err:
        out["cases"] = [_result(c["id"], "LOI_PHEP_DO", f"LỖI PHÉP ĐO ({err})") for c in record.get("cases", [])]
        return out
    # 06B-4ER: both links are judged from the record itself, never only from the "skipped" marker.
    link_before, link_after = link_ok(record.get("service_link_before")), link_ok(record.get("service_link_after"))
    for crec in record.get("cases", []):
        if crec.get("id") not in cases:
            out["cases"].append(_result(str(crec.get("id")), "LOI_PHEP_DO", "LỖI PHÉP ĐO (unknown case id)"))
            continue
        out["cases"].append(evaluate_case(frames, reads, cases[crec["id"]], crec, link_after, guard, link_before))
    return out


def group_exit(result):
    """Worst category of the group: LOI_PHEP_DO 2 > FAIL 1 > not judged 4 > DAT 0."""
    cats = {c["category"] for c in result["cases"]}
    if not result["cases"]:
        return 2
    for cat, code in (("FAIL", 1), ("LOI_PHEP_DO", 2)):
        if cat in cats:
            return code
    return 4 if cats - {"DAT_KIEM_QUY_TAC"} else 0


def main(argv):
    ap = argparse.ArgumentParser(description="evaluate a recorded T12/T13 ICMP group (offline)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--counters", required=True)
    ap.add_argument("--tap-mac", required=True)
    ap.add_argument("--record", required=True, help="group record JSON written by run_group()")
    ap.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        record = json.load(open(a.record))
        if not isinstance(record, dict):
            raise ValueError("group record is not an object")
        res = evaluate_group(a.pcap, a.counters, a.tap_mac, record)
    except (OSError, ValueError) as e:                 # unreadable/invalid record, malformed TAP MAC
        res = {"error": f"{type(e).__name__}: {e}", "cases": []}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
    for c in res["cases"]:
        print(f"{c['id']}: {c['verdict']}")
    if res.get("error"):
        print(f"ERROR: {res['error']}")
        return 2
    return group_exit(res)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
