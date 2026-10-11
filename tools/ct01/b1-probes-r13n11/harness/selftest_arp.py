#!/usr/bin/env python3
"""06B-4H/06B-4HR/06B-4HR1/06B-4HR2 — offline tests of arp_cases.py (T14 A1/A2/A3, T15 S1) on SYNTHETIC captures/counter files and a
SIMULATED guest (selftest_l2.FakeGuest, extended with ping/sleep and frame emission). Sends nothing.

    python3 selftest_arp.py [--json FILE]

Sections:
  D  definitions and commands (sizes from signatures.py; only ip/ping/sleep/echo; no arping, no raw tool)
  N  worker neighbour parsing and comparison
  P  evaluate_group on fixtures: clean A1/A2/A3/S1; wrong ARP fields; no frame; measurement errors; edge frame;
     execution error; restore failure; service link; live control; determined failures
  X  run_group with the simulated guest: order, restore also after an error, a failed restore stops the group,
     state read error, service link before/after, control, record completeness
  E  end to end: run_group on the simulated guest that emits frames + counters, then evaluate_group
  F  06B-4HR: the five review findings (F1 opcode, F2 neighbours, F3 execution record, F4 ping rc through
     run_group, F5 failure evidence vs measurement errors) and the 40-case restore matrix
  H  06B-4HR1: HR1 baseline/restore content, HR2 mandatory binding, HR3 not-started branch, HR4 unreadable
     neighbour rows, HR5 control callback payloads, and the evidence fields of every JSON branch
  R1 06B-4HR2: neigh_static/neigh_dynamic consistency of baseline and restore 'after' (PERMANENT flag in the dynamic
     group, a key in both groups), static loss blocked, valid dynamic changes not forced
  C  CLI
"""
import contextlib
import copy
import io
import json
import os
import re
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import arp_cases as A          # noqa: E402
import guest_state as GS       # noqa: E402
import l2frames as L           # noqa: E402
import signatures as S         # noqa: E402
import selftest_l2 as B        # noqa: E402  (frame builders, FakeGuest)
import selftest_l2eval as V    # noqa: E402  (counter-file builders)

RESULTS = {}
TAP, GUEST = B.TAP, B.GUEST
CASES = {c["id"]: c for c in A.build_cases()}
IF = "eth1"
BC = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"
MANAGER_MAC = "8a:d3:09:b5:72:af"


def t(name, fn):
    if name in RESULTS:
        raise SystemExit(f"duplicate test name {name}")
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    if not ok and not why:
        why = "returned False"
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""))


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------ frames
def req(tpa, sha=GUEST, spa=S.GUEST_IP, dmac=BC, **kw):
    return B.eth(dmac, GUEST, 0x0806, B.arp(1, sha, spa, ZERO, tpa, **kw))


def grat(ip, op=1):
    return B.eth(BC, GUEST, 0x0806, B.arp(op, GUEST, ip, ZERO, ip))


def worker_arp(spa, tpa=S.GUEST_IP, op=2):
    return B.eth(GUEST, TAP, 0x0806, B.arp(op, TAP, spa, GUEST, tpa))


def icmp_to(dst, size):
    return B.eth(TAP, GUEST, 0x0800, B.ipv4(S.GUEST_IP, dst, 1, B.icmp(size)))


def dhcp():
    return B.eth(BC, GUEST, 0x0800, B.ipv4("0.0.0.0", "255.255.255.255", 17, B.udp(68, 67)))


def mld():
    return B.eth("33:33:00:00:00:16", GUEST, 0x86DD, B.ipv6(S.GUEST_LL6, "ff02::16", 58, B.icmp6(20, typ=143)))


def probe_frames(cid, n=3):
    c = CASES[cid]
    if c["kind"] == "t14":
        return [req(c["dst"])] * n
    return [grat(ip) for ip in (S.GUEST_IP,) + tuple(c["spoof"])]


# ------------------------------------------------------------------ worker neighbours
def neigh_json(extra=(), tap_entry=True, guest_mac=GUEST):
    rows = []
    if tap_entry:
        rows.append({"dst": S.GUEST_IP, "dev": "tap0", "lladdr": guest_mac, "state": ["PERMANENT"]})
    rows += [{"dst": "192.168.60.10", "dev": "eth0", "lladdr": MANAGER_MAC, "state": ["REACHABLE"]},
             {"dst": "192.168.60.1", "dev": "eth0", "lladdr": "fe:69:25:9f:7e:e9", "state": ["STALE"]}]
    rows += list(extra)
    return json.dumps(rows)


NEIGH = neigh_json()


# ------------------------------------------------------------------ scenario builder
def _baseline():
    """A real guest_state baseline (read from the simulated guest), JSON form as run_group records it."""
    g = B.FakeGuest()
    return A._jsonable(GS.read_state(g, IF))


BASELINE = _baseline()
RESTORED = {"restored": True, "commands": [], "diffs": [], "dynamic_changes": [], "error": None,
            "after": copy.deepcopy(BASELINE)}         # 06B-4HR1: restored=True needs the re-read state


def crec_for(cid, **over):
    c = CASES[cid]
    steps = [{"phase": ph, "cmd": cmd, "rc": (1 if ph == "trigger" and cmd.startswith("ping") else 0), "out": ""}
             for ph in ("setup", "trigger", "settle") for cmd in A.commands(c, IF)[ph]]
    r = {"id": cid, "iface": IF, "before": f"{cid} before", "after": f"{cid} after", "steps": steps, "exec_error": None,
         "read_error": None, "guest_state": {"before": copy.deepcopy(BASELINE), "restore": copy.deepcopy(RESTORED)},
         "neigh_before": NEIGH, "neigh_after": NEIGH,
         "control": {"ok": True, "detail": "ARP resolved on sandboxnet"} if c["control_kind"] == "live" else None,
         "service_link_after": {"ok": True, "detail": "HTTP 200 + hash"}, "not_run": None}
    r.update(over)
    return r


def scenario(tmp, name, specs, link_before=True, counters_override=None, skip_ids=()):
    """specs: [(case id, [(dt, frame), ...], crec overrides, {counter: extra increment})]. Window of case i:
    A=[t0, t0+0.01], B=[t0+10, t0+10.01], t0 = 100 + 20 i. Counters follow the l2frames class of each frame
    inside [A.t_start, B.t_end] (frames hit the ruleset), plus the extra increments."""
    values = dict(V.BASE)
    recs, frames, cases = [], [], []
    for i, (cid, fr, over, extra) in enumerate(specs):
        t0 = 100.0 + 20 * i
        recs.append(V.rec(f"{cid} before", t0, t0 + 0.01, values))
        values = dict(values)
        for dt, f in fr:
            frames.append((t0 + dt, f))
            cls = L.classify(L.decode(t0 + dt, f), TAP)[1]
            if cls in values and 0 <= dt <= 10.01:
                values[cls] += 1
        for k, n in (extra or {}).items():
            values[k] += n
        recs.append(V.rec(f"{cid} after", t0 + 10, t0 + 10.01, values))
        cases.append(crec_for(cid, **(over or {})))
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames)
    cf = V.write_counters(os.path.join(tmp, name + ".jsonl"), counters_override if counters_override is not None else recs)
    record = {"iface": IF, "cases": cases, "service_link_before": {"ok": link_before, "detail": "x"}, "stopped": None}
    return pc, cf, record


def spaced(frames, start=1.0, step=0.5):
    return [(start + step * k, f) for k, f in enumerate(frames)]


def one(tmp, name, cid, frames, over=None, extra=None, **kw):
    pc, cf, rec = scenario(tmp, name, [(cid, frames, over, extra)], **kw)
    rec_cases = rec["cases"]
    res = A.evaluate_case(L.classified_frames(pc, TAP), __import__("l2eval").load_reads(cf), CASES[cid], rec_cases[0],
                          A.link_ok(rec["service_link_before"]))
    return res


# ------------------------------------------------------------------ D
def sec_D():
    t("D1 four cases as planned (T14 A1/A2/A3, T15 S1), expected arp_in_drop",
      lambda: [c["id"] for c in A.build_cases()] == list(A.CASE_IDS) and {c["expected"] for c in A.build_cases()} == {"arp_in_drop"})
    t("D2 T14 sizes come from signatures.py (T14-A1..A3)",
      lambda: all(CASES[c]["size"] == S.ICMP4_SIZES[c] for c in ("T14-A1", "T14-A2", "T14-A3")))
    t("D3 T14 commands: on-link /32 route, one ping, settle",
      lambda: A.commands(CASES["T14-A1"], IF) == {"setup": ["ip route add 192.168.60.2/32 dev eth1"],
                                                 "trigger": ["ping -c 1 -W 2 -s 1401 192.168.60.2"],
                                                 "settle": [f"sleep {A.SETTLE_S}"]})
    t("D4 T15-S1 commands: arp_notify=1, three /32 spoofed addresses, link down/up, settle",
      lambda: A.commands(CASES["T15-S1"], IF) == {
          "setup": ["echo 1 > /proc/sys/net/ipv4/conf/eth1/arp_notify", "ip addr add 10.200.0.1/32 dev eth1",
                    "ip addr add 192.168.60.10/32 dev eth1", "ip addr add 192.168.60.1/32 dev eth1"],
          "trigger": ["ip link set dev eth1 down", "ip link set dev eth1 up"], "settle": [f"sleep {A.SETTLE_S}"]})
    allc = [x for c in A.build_cases() for ph in A.commands(c, IF).values() for x in ph]
    t("D5 D1: only ip / ping / sleep / echo-to-proc; no arping, no raw-packet tool, no forged reply",
      lambda: all(re.match(r"(ip |ping |sleep |echo 1 > /proc/sys/net/ipv4/conf/)", x) for x in allc)
      and not any(w in x for x in allc for w in ("arping", "nc ", "python", "-U", "-A")))
    t("D6 live control only for A1/A2; A3, S1 rule check",
      lambda: [c["control_kind"] for c in A.build_cases()] == ["live", "live", "rule_check", "rule_check"])
    t("D7 bad interface name refused", lambda: raises(ValueError, lambda: A.commands(CASES["T14-A1"], "eth1; reboot")))
    t("D8 a registry change changes the command (single source)",
      lambda: _with(S.ICMP4_SIZES, "T14-A1", 1499, lambda: " -s 1499 " in A.commands(A.build_cases()[0], IF)["trigger"][0]))
    t("D9 T14 targets are outside 10.200.0.0/30 (on-link route needed; 10.200.0.3 is the broadcast, plan L2)",
      lambda: all(not __import__("ipaddress").ip_address(CASES[c]["dst"]) in __import__("ipaddress").ip_network(S.GUEST_NET)
                  or CASES[c]["dst"] == "10.200.0.6" for c in ("T14-A1", "T14-A2", "T14-A3"))
      and "10.200.0.3" not in [CASES[c]["dst"] for c in ("T14-A1", "T14-A2", "T14-A3")])


def _with(d, k, v, fn):
    old = d[k]
    d[k] = v
    try:
        return fn()
    finally:
        d[k] = old


# ------------------------------------------------------------------ N
def sec_N():
    W = ["192.168.60.10"]
    NC = lambda after, before=NEIGH, w=W: A.neigh_check(before, after, w)            # noqa: E731
    rows, probs = A.parse_neigh(NEIGH)
    t("N1 parse ip -j neigh: rows kept with device, MAC, states, binding",
      lambda: probs == [] and {"dst": S.GUEST_IP, "dev": "tap0", "lladdr": GUEST, "states": ["PERMANENT"],
                               "binding": True} in rows)
    t("N2 unchanged -> nothing", lambda: NC(NEIGH) == {"fail": [], "invalid": [], "inconclusive": []})
    t("N3 dynamic state change of a kept binding (REACHABLE -> STALE) is normal, not reported",
      lambda: NC(NEIGH.replace("REACHABLE", "STALE")) == {"fail": [], "invalid": [], "inconclusive": []})
    t("N4 new entry (unwatched IP) on tap0 -> fail",
      lambda: NC(neigh_json([{"dst": "192.168.60.77", "dev": "tap0", "lladdr": "02:00:00:00:00:77", "state": ["STALE"]}]))["fail"])
    t("N5 tap0 permanent entry lost -> fail", lambda: NC(neigh_json(tap_entry=False))["fail"])
    t("N6 manager entry on eth0 now carries the guest MAC -> fail", lambda: NC(NEIGH.replace(MANAGER_MAC, GUEST))["fail"])
    t("N7 watched IP changes its MAC on eth0 -> fail", lambda: NC(NEIGH.replace(MANAGER_MAC, "02:00:00:00:00:99"))["fail"])
    t("N8 unreadable neighbour output -> invalid (never 'unchanged')",
      lambda: all(NC(x)["invalid"] for x in (None, "", "{}", "not json")) and NC(NEIGH, before=None)["invalid"])
    t("N9 a NEW, unwatched eth0 entry carrying the guest MAC -> fail",
      lambda: NC(neigh_json([{"dst": "192.168.60.99", "dev": "eth0", "lladdr": GUEST, "state": ["STALE"]}]))["fail"])


# ------------------------------------------------------------------ P
def sec_P(tmp):
    for cid in A.CASE_IDS:
        t(f"P1 {cid}: clean fixture -> " + ("ĐẠT (live control)" if CASES[cid]["control_kind"] == "live" else "ĐẠT (kiểm quy tắc)"),
          lambda cid=cid: (lambda r: r["category"] == ("DAT" if CASES[cid]["control_kind"] == "live" else "DAT_KIEM_QUY_TAC")
                           and r["verdict"] == ("ĐẠT" if CASES[cid]["control_kind"] == "live" else "ĐẠT (kiểm quy tắc)")
                           and r["probe_frames"] == len(probe_frames(cid)))(
              one(tmp, f"p1-{cid}", cid, spaced(probe_frames(cid)))))
    t("P2 clean with background (DHCP, MLD) reconciled -> still ĐẠT",
      lambda: one(tmp, "p2", "T15-S1", spaced(probe_frames("T15-S1") + [dhcp(), mld(), mld()]))["category"] == "DAT_KIEM_QUY_TAC")
    # wrong ARP fields: never a probe frame
    for n, fr in (("sender MAC field not the guest", req("192.168.60.2", sha="02:00:00:00:00:77")),
                  ("other target IP", req("192.168.60.3")),
                  ("opcode 2 (reply) instead of a request", B.eth(BC, GUEST, 0x0806, B.arp(2, GUEST, S.GUEST_IP, ZERO, "192.168.60.2"))),
                  ("hlen 8 (not hooked)", req("192.168.60.2", hlen=8))):
        t(f"P3 T14-A1 wrong ARP field ({n}) -> no probe frame, never ĐẠT",
          lambda fr=fr: (lambda r: r["category"] in ("KHONG_TAO_DUOC_GOI", "CHUA_KIEM_CHUNG") and r["probe_frames"] == 0)(
              one(tmp, "p3-" + re.sub(r"\W", "", n), "T14-A1", spaced([fr] * 3))))
    t("P4 a unicast probe to a MAC other than TAP_MAC (OTHERHOST): arp_not_hooked -> CHƯA KIỂM CHỨNG, not ĐẠT",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "khung không có bộ đếm" in r["verdict"])(
          one(tmp, "p4", "T14-A1", spaced([req("192.168.60.2", dmac="02:00:00:00:00:88")] + [req("192.168.60.2")] * 2))))
    t("P5 T15: gratuitous only for 10.200.0.2 (no spoofed address announced) -> KHÔNG TẠO ĐƯỢC GÓI",
      lambda: one(tmp, "p5", "T15-S1", spaced([grat(S.GUEST_IP)]))["category"] == "KHONG_TAO_DUOC_GOI")
    t("P6 T15: one spoofed address missing -> KHÔNG TẠO ĐƯỢC GÓI naming it",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and "192.168.60.1" in r["verdict"])(
          one(tmp, "p6", "T15-S1", spaced([grat(S.GUEST_IP), grat("10.200.0.1"), grat("192.168.60.10")]))))
    t("P7 no frame at all (ping rc 1) -> KHÔNG TẠO ĐƯỢC GÓI, never evidence of blocking",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and "không phải bằng chứng chặn" in r["verdict"])(
          one(tmp, "p7", "T14-A3", [])))
    # measurement errors
    t("P8 counter read failed during execution -> LỖI PHÉP ĐO",
      lambda: one(tmp, "p8", "T14-A1", spaced(probe_frames("T14-A1")), over={"read_error": "read 'T14-A1 after': rc 1"})["category"] == "LOI_PHEP_DO")
    t("P9 counter read 'after' missing -> LỖI PHÉP ĐO",
      lambda: (lambda pc, cf, rec: A.evaluate_group(pc, cf, TAP, rec)["cases"][0]["category"] == "LOI_PHEP_DO")(
          *scenario(tmp, "p9", [("T14-A1", spaced(probe_frames("T14-A1")), None, None)],
                    counters_override=[V.rec("T14-A1 before", 100, 100.01, V.BASE)])))
    t("P10 counter decreased -> LỖI PHÉP ĐO",
      lambda: (lambda pc, cf, rec: A.evaluate_group(pc, cf, TAP, rec)["cases"][0]["category"] == "LOI_PHEP_DO")(
          *scenario(tmp, "p10", [("T14-A1", [], None, None)],
                    counters_override=[V.rec("T14-A1 before", 100, 100.01, V.after(arp_in_drop=3)),
                                       V.rec("T14-A1 after", 110, 110.01, V.BASE)])))
    t("P11 arp_out_drop missing in a read -> LỖI PHÉP ĐO (never 0)",
      lambda: (lambda pc, cf, rec: A.evaluate_group(pc, cf, TAP, rec)["cases"][0]["category"] == "LOI_PHEP_DO")(
          *scenario(tmp, "p11", [("T14-A1", spaced(probe_frames("T14-A1")), None, None)],
                    counters_override=[V.rec("T14-A1 before", 100, 100.01, {k: v for k, v in V.BASE.items() if k != "arp_out_drop"}),
                                       V.rec("T14-A1 after", 110, 110.01, {**{k: v for k, v in V.BASE.items() if k != "arp_out_drop"},
                                                                           "arp_in_drop": 3})])))
    t("P12 capture unreadable -> every case LỖI PHÉP ĐO",
      lambda: (lambda pc, cf, rec: {c["category"] for c in A.evaluate_group(pc + ".missing", cf, TAP, rec)["cases"]} == {"LOI_PHEP_DO"})(
          *scenario(tmp, "p12", [("T14-A1", [], None, None), ("T14-A2", [], None, None)])))
    t("P13 neighbour table not readable -> LỖI PHÉP ĐO",
      lambda: one(tmp, "p13", "T14-A1", spaced(probe_frames("T14-A1")), over={"neigh_after": None})["category"] == "LOI_PHEP_DO")
    # edge frame
    t("P14 probe frame at the edge of read A -> CHƯA KIỂM CHỨNG (gói ở biên)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "biên" in r["verdict"])(
          one(tmp, "p14", "T14-A1", [(0.005, req("192.168.60.2")), (1.0, req("192.168.60.2")), (2.0, req("192.168.60.2"))])))
    t("P15 probe frame at the edge of read B -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p15", "T14-A1", [(1.0, req("192.168.60.2")), (9.995, req("192.168.60.2"))])["category"] == "CHUA_KIEM_CHUNG")
    # execution errors
    t("P16 route add failed (setup) -> LỖI THỰC THI, not ĐẠT, even with frames",
      lambda: one(tmp, "p16", "T14-A1", spaced(probe_frames("T14-A1")),
                  over={"exec_error": "setup 'ip route add ...': rc 2"})["category"] == "LOI_THUC_THI")
    t("P17 tool missing -> LỖI THỰC THI",
      lambda: one(tmp, "p17", "T14-A2", [], over={"exec_error": "trigger: tool missing in the guest"})["category"] == "LOI_THUC_THI")
    t("P18 guest state unreadable before the case (nothing ran, no reads) -> LỖI THỰC THI (not LỖI PHÉP ĐO)",
      lambda: (lambda pc, cf, rec: A.evaluate_group(pc, cf, TAP, rec)["cases"][0]["category"] == "LOI_THUC_THI")(
          *scenario(tmp, "p18", [("T14-A1", [], {"exec_error": "guest state not readable", "guest_state":
                                                 {"before": None, "restore": None}, "steps": []}, None)],
                    counters_override=[V.rec("session before boot", 50, 50.01, V.BASE)])))
    # restore
    t("P19 restore failed -> CHƯA KIỂM CHỨNG (cấu hình guest không khôi phục được), never ĐẠT",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "khôi phục" in r["verdict"])(
          one(tmp, "p19", "T15-S1", spaced(probe_frames("T15-S1")),
              over={"guest_state": {"before": copy.deepcopy(BASELINE), "restore": {"restored": False, "commands": [], "diffs": ["addrs: extra '192.168.60.10/32'"], "dynamic_changes": [], "error": None}}})))
    t("P20 restore record missing -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p20", "T14-A1", spaced(probe_frames("T14-A1")),
                  over={"guest_state": {"before": copy.deepcopy(BASELINE), "restore": None}})["category"] == "CHUA_KIEM_CHUNG")
    t("P21 case not run after an earlier restore failure -> CHƯA KIỂM CHỨNG (not run)",
      lambda: "không chạy" in one(tmp, "p21", "T14-A2", [], over={"not_run": A.NOT_RUN})["verdict"])
    # service link and control
    t("P22 service link after the case failed -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p22", "T14-A3", spaced(probe_frames("T14-A3")),
                  over={"service_link_after": {"ok": False, "detail": "HTTP=000"}})["category"] == "CHUA_KIEM_CHUNG")
    t("P23 service link after missing -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p23", "T14-A3", spaced(probe_frames("T14-A3")), over={"service_link_after": None})["category"] == "CHUA_KIEM_CHUNG")
    t("P24 service link before the group not ok (no 'skipped' marker) -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p24", "T14-A3", spaced(probe_frames("T14-A3")), link_before=False)["category"] == "CHUA_KIEM_CHUNG")
    t("P25 A1 live control not alive -> CHƯA KIỂM CHỨNG (đối chứng)",
      lambda: one(tmp, "p25", "T14-A1", spaced(probe_frames("T14-A1")),
                  over={"control": {"ok": False, "detail": "no ARP entry"}})["category"] == "CHUA_KIEM_CHUNG")
    t("P26 A2 live control missing -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p26", "T14-A2", spaced(probe_frames("T14-A2")), over={"control": None})["category"] == "CHUA_KIEM_CHUNG")
    t("P27 arp_out_drop increased in the window -> CHƯA KIỂM CHỨNG (not observable, not ĐẠT)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "arp_out_drop" in r["verdict"])(
          one(tmp, "p27", "T14-A1", spaced(probe_frames("T14-A1")), extra={"arp_out_drop": 1})))
    # determined failures
    t("P28 worker ARP reply for the probed IP towards the guest -> FAIL",
      lambda: one(tmp, "p28", "T14-A2", spaced(probe_frames("T14-A2") + [worker_arp("192.168.60.10")]))["category"] == "FAIL")
    t("P29 probe ICMP packet seen (ARP was resolved) -> FAIL",
      lambda: one(tmp, "p29", "T14-A1", spaced(probe_frames("T14-A1") + [icmp_to("192.168.60.2", 1401)]))["category"] == "FAIL")
    t("P30 worker neighbour on tap0 changed -> FAIL",
      lambda: one(tmp, "p30", "T15-S1", spaced(probe_frames("T15-S1")),
                  over={"neigh_after": neigh_json([{"dst": "10.200.0.1", "dev": "tap0", "lladdr": GUEST,
                                                    "state": ["STALE"]}])})["category"] == "FAIL")
    t("P31 manager entry on eth0 got the guest MAC -> FAIL",
      lambda: one(tmp, "p31", "T15-S1", spaced(probe_frames("T15-S1")),
                  over={"neigh_after": NEIGH.replace(MANAGER_MAC, GUEST)})["category"] == "FAIL")
    t("P32 counter delta lower than the probe frames -> FAIL",
      lambda: one(tmp, "p32", "T14-A3", spaced(probe_frames("T14-A3")), extra={"arp_in_drop": -1})["category"] == "FAIL")
    t("P33 a determined failure is reported even when the restore also failed",
      lambda: one(tmp, "p33", "T14-A2", spaced(probe_frames("T14-A2") + [worker_arp("192.168.60.10")]),
                  over={"guest_state": {"before": copy.deepcopy(BASELINE), "restore": {"restored": False, "commands": [], "diffs": ["addrs: extra '192.168.60.10/32'"], "dynamic_changes": [], "error": None}}})["category"] == "FAIL")
    t("P34 a determined failure is reported even with an execution error",
      lambda: one(tmp, "p34", "T14-A1", spaced(probe_frames("T14-A1") + [icmp_to("192.168.60.2", 1401)]),
                  over={"exec_error": "settle: rc 1"})["category"] == "FAIL")
    t("P35 worker ARP about a spoofed IP during T15 -> FAIL",
      lambda: one(tmp, "p35", "T15-S1", spaced(probe_frames("T15-S1") + [worker_arp("10.200.0.1", tpa="192.168.60.1", op=1)]))["category"] == "FAIL")

    t("P36 T15: ARP with a spoofed sender IP but another target (not gratuitous) is not a probe frame",
      lambda: one(tmp, "p36", "T15-S1", spaced([B.eth(BC, GUEST, 0x0806, B.arp(1, GUEST, ip, ZERO, S.GUEST_IP))
                                                for ip in ("10.200.0.1", "192.168.60.10", "192.168.60.1")]))["category"]
      == "KHONG_TAO_DUOC_GOI")
    t("P37 service link after with ok \"true\" (not the boolean) -> CHƯA KIỂM CHỨNG",
      lambda: one(tmp, "p37", "T14-A3", spaced(probe_frames("T14-A3")),
                  over={"service_link_after": {"ok": "true", "detail": "x"}})["category"] == "CHUA_KIEM_CHUNG")


# ------------------------------------------------------------------ simulated guest for run_group
class SimGuest(B.FakeGuest):
    """selftest_l2.FakeGuest + ping/sleep. Frames are emitted with real timestamps into `frames`, and the
    counters follow l2frames.classify (the ruleset is simulated, NOT verified). Kernel behaviour simulated:
    an unresolved on-link destination -> 3 ARP requests; link up with arp_notify=1 -> one gratuitous request per
    IPv4 address of the interface."""

    def __init__(self, counters, frames, fail_cmds=(), restore_fail=False, raise_on=None, emit=True, **kw):
        super().__init__(**kw)
        self.counters, self.frames, self.fail_cmds, self.restore_fail = counters, frames, set(fail_cmds), restore_fail
        self.raise_on, self.emit = raise_on, emit

    def _emit(self, fr):
        ts = time.time()
        self.frames.append((ts, fr))
        cls = L.classify(L.decode(ts, fr), TAP)[1]
        if cls in self.counters:
            self.counters[cls] += 1
        time.sleep(0.005)

    def run(self, cmd, timeout=60):
        if self.raise_on and self.raise_on in cmd:      # once: the console recovers afterwards
            self.raise_on = None
            self.log.append(cmd)
            raise TimeoutError("Timeout exceeded (simulated console)")
        if cmd in self.fail_cmds:
            self.log.append(cmd)
            return 2, "RTNETLINK answers: Operation not permitted"
        if self.restore_fail and cmd.startswith("ip addr del 192.168.60.10/32"):
            self.log.append(cmd)
            return 2, "RTNETLINK answers: Cannot assign"
        m = re.fullmatch(r"ping -c 1 -W \d+ -s (\d+) (\S+)", cmd)
        if m:
            self.log.append(cmd)
            time.sleep(0.03)
            if self.emit:
                for _ in range(3):
                    self._emit(req(m.group(2)))
            return 1, "1 packets transmitted, 0 packets received, 100% packet loss"
        if re.fullmatch(r"sleep \d+", cmd):
            self.log.append(cmd)
            time.sleep(0.03)
            return 0, ""
        was_down = self.oper == "down"
        rc, out = super().run(cmd, timeout)
        if cmd == f"ip link set dev {self.iface} up" and was_down and self.notify == 1 and self.emit:
            time.sleep(0.03)
            for a in sorted(self.addrs):
                self._emit(grat(a.split("/")[0]))
        return rc, out


def fake_counters_reader(counters, path):
    def read(label):
        t0 = time.time()
        line = json.dumps({"label": label, "t_start": t0, "t_end": t0 + 0.001, "raw": V.raw(counters)})
        with open(path, "a") as f:
            f.write(line + "\n")
        time.sleep(0.03)
    return read


def run_sim(tmp, name, guest_kw=None, link=lambda: (True, "HTTP=200 + hash"), neigh=lambda: NEIGH,
            control=lambda c: (True, "ARP resolved on sandboxnet"), cases=None, reader=None, guest_cls=None,
            guest_extra=None):
    counters, frames = dict(V.BASE), []
    g = (guest_cls or SimGuest)(counters, frames, **(guest_kw or {}), **(guest_extra or {}))
    cf = os.path.join(tmp, name + ".jsonl")
    open(cf, "w").close()
    rec = A.run_group(g, reader or fake_counters_reader(counters, cf), link, neigh, control,
                      cases or A.build_cases(), IF)
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames)
    json.loads(json.dumps(rec))           # the record is JSON
    return g, rec, pc, cf


def sec_X(tmp):
    g, rec, pc, cf = run_sim(tmp, "x1")
    cmds = [c for c in g.log if c != GS.snapshot_cmd(IF)]
    t("X1 run_group: order per case = state saved, setup, trigger, settle, restore; 4 cases, record is JSON",
      lambda: [c["id"] for c in rec["cases"]] == list(A.CASE_IDS)
      and cmds[:3] == ["ip route add 192.168.60.2/32 dev eth1", "ping -c 1 -W 2 -s 1401 192.168.60.2", f"sleep {A.SETTLE_S}"]
      and cmds[3] == "ip route del 192.168.60.2/32 dev eth1")
    t("X2 every case restored, route/addresses/arp_notify back to the before-state",
      lambda: all(c["guest_state"]["restore"]["restored"] is True for c in rec["cases"])
      and g.notify == 0 and g.addrs == {"10.200.0.2/30"} and f"default via 10.200.0.1 dev {IF}" in g.routes)
    t("X3 T15 restore re-adds the default route lost by the link down; the flushed DYNAMIC neighbour is only reported",
      lambda: any(c["cmd"].startswith("ip route add default via 10.200.0.1") for c in rec["cases"][3]["guest_state"]["restore"]["commands"])
      and any("10.200.0.1" in d for d in rec["cases"][3]["guest_state"]["restore"]["dynamic_changes"])
      and rec["cases"][3]["guest_state"]["restore"]["restored"] is True)
    t("X4 service link checked before the group and after every case; neighbours before/after; control for A1/A2 only",
      lambda: rec["service_link_before"]["ok"] and all(c["service_link_after"]["ok"] for c in rec["cases"])
      and all(c["neigh_before"] and c["neigh_after"] for c in rec["cases"])
      and [c["control"] is not None for c in rec["cases"]] == [True, True, False, False])
    t("X5 group record complete (each case once, reviewed commands)", lambda: A.record_problems(rec) == [])
    # restore failure stops the group
    g, rec, pc, cf = run_sim(tmp, "x6", cases=[CASES["T15-S1"], CASES["T14-A3"]], guest_kw={"restore_fail": True})
    t("X6 restore failure: the next case is not run (not_run), no service link after the failed case",
      lambda: rec["cases"][0]["guest_state"]["restore"]["restored"] is False and rec["cases"][1]["not_run"] == A.NOT_RUN
      and rec["cases"][0]["service_link_after"] is None and "ping -c 1 -W 2 -s 1403 10.200.0.6" not in g.log)
    # an exception in the middle of the case: still restored
    g, rec, pc, cf = run_sim(tmp, "x7", cases=[CASES["T15-S1"]], guest_kw={"raise_on": "link set dev eth1 up"})
    t("X7 console timeout after 'link down': exec error recorded, read B taken, guest still restored (link up, addresses)",
      lambda: "TimeoutError" in rec["cases"][0]["exec_error"] and rec["cases"][0]["read_error"] is None
      and rec["cases"][0]["guest_state"]["restore"]["restored"] is True and g.oper == "up" and g.addrs == {"10.200.0.2/30"})
    g, rec, pc, cf = run_sim(tmp, "x8", cases=[CASES["T14-A1"]], guest_kw={"fail": ["ip route add 192.168.60.2/32 dev eth1"]})
    t("X8 setup failed: trigger not sent, exec error, still restored",
      lambda: "rc 2" in rec["cases"][0]["exec_error"] and not any(c.startswith("ping") for c in g.log)
      and rec["cases"][0]["guest_state"]["restore"]["restored"] is True)
    g, rec, pc, cf = run_sim(tmp, "x9", cases=[CASES["T14-A1"], CASES["T14-A2"]], guest_kw={"bad_section": "arp"})
    t("X9 guest state unreadable: no command sent, exec error, nothing to restore, group not stopped",
      lambda: all("guest state not readable" in c["exec_error"] for c in rec["cases"])
      and not any(c.startswith(("ip route add", "ping")) for c in g.log) and rec["stopped"] is None)
    g, rec, pc, cf = run_sim(tmp, "x10", link=lambda: (False, "HTTP=000"))
    t("X10 service link before fails: no case run, group skipped",
      lambda: rec.get("skipped") and rec["cases"] == [] and not any(c.startswith(("ip ", "ping")) for c in g.log))
    g, rec, pc, cf = run_sim(tmp, "x11", neigh=lambda: (_ for _ in ()).throw(OSError("ip: not found")))
    t("X11 worker neighbour read error recorded (never 'unchanged')",
      lambda: all(c["neigh_before"] is None and "OSError" in c["neigh_before_error"] for c in rec["cases"]))
    g, rec, pc, cf = run_sim(tmp, "x12", control=lambda c: (_ for _ in ()).throw(RuntimeError("ctl down")))
    t("X12 control error -> control not ok (A1/A2)", lambda: rec["cases"][0]["control"]["ok"] is False)
    g, rec, pc, cf = run_sim(tmp, "x13", reader=lambda lbl: (_ for _ in ()).throw(RuntimeError("nft: rc 1")))
    t("X13 counter read failure recorded as read_error, case still restored",
      lambda: all("nft: rc 1" in c["read_error"] for c in rec["cases"])
      and all(c["guest_state"]["restore"]["restored"] for c in rec["cases"]))
    g, rec, pc, cf = run_sim(tmp, "x18", cases=[CASES["T15-S1"]], guest_kw={"fail": ["ip link set dev eth1 down"]})
    t("X18 link down failed (trigger): exec error, 'link up' not sent, still restored",
      lambda: "rc 2" in rec["cases"][0]["exec_error"]
      and [x["cmd"] for x in rec["cases"][0]["steps"] if x["phase"] == "trigger"] == ["ip link set dev eth1 down"]
      and rec["cases"][0]["guest_state"]["restore"]["restored"] is True)
    g, rec, pc, cf = run_sim(tmp, "x19", link=lambda: (1, "truthy but not True"))
    t("X19 service link returning a truthy non-True value is not ok: group skipped", lambda: rec.get("skipped") and rec["cases"] == [])
    r2 = copy.deepcopy(run_sim(tmp, "x14")[1])
    r2["cases"].append(copy.deepcopy(r2["cases"][0]))
    t("X14 record_problems: duplicate case", lambda: any("more than once" in p for p in A.record_problems(r2)))
    r2["cases"] = r2["cases"][1:4]
    t("X15 record_problems: missing case", lambda: any("case missing: T14-A1" in p for p in A.record_problems(r2)))
    r3 = copy.deepcopy(run_sim(tmp, "x16")[1])
    r3["cases"][0]["steps"][0]["cmd"] = "ip route add 192.168.60.3/32 dev eth1"
    t("X16 record_problems: a guest command that is not the reviewed one",
      lambda: any(p.startswith("T14-A1:") and "contract" in p for p in A.record_problems(r3)))
    t("X17 record_problems: invalid structure", lambda: A.record_problems({"cases": "x"}) and A.record_problems([]))


# ------------------------------------------------------------------ E (end to end on the simulation)
def sec_E(tmp):
    g, rec, pc, cf = run_sim(tmp, "e1")
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E1 end to end clean: A1, A2 ĐẠT (live control), A3, S1 ĐẠT (kiểm quy tắc); exit 0",
      lambda: [c["category"] for c in res["cases"]] == ["DAT", "DAT", "DAT_KIEM_QUY_TAC", "DAT_KIEM_QUY_TAC"]
      and A.group_exit(res) == 0)
    t("E2 end to end: probe frames = 3 per T14 case, 4 gratuitous for S1 (10.200.0.2 + 3 spoofed)",
      lambda: [c["probe_frames"] for c in res["cases"]] == [3, 3, 3, 4])
    g, rec, pc, cf = run_sim(tmp, "e3", guest_kw={"emit": False})
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E3 end to end: kernel sends nothing -> all KHÔNG TẠO ĐƯỢC GÓI, exit 4 (never 0)",
      lambda: {c["category"] for c in res["cases"]} == {"KHONG_TAO_DUOC_GOI"} and A.group_exit(res) == 4)
    g, rec, pc, cf = run_sim(tmp, "e4", cases=[CASES["T15-S1"], CASES["T14-A3"]], guest_kw={"restore_fail": True})
    rec["cases"] = rec["cases"]
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E4 end to end restore failure: S1 CHƯA KIỂM CHỨNG (khôi phục), A3 not run; record incomplete -> never exit 0",
      lambda: [c["category"] for c in res["cases"]] == ["CHUA_KIEM_CHUNG", "CHUA_KIEM_CHUNG"]
      and "khôi phục" in res["cases"][0]["verdict"] and A.group_exit(res) != 0)
    g, rec, pc, cf = run_sim(tmp, "e5", neigh=iter([NEIGH, NEIGH, NEIGH, NEIGH.replace(MANAGER_MAC, GUEST)] + [NEIGH] * 4).__next__)
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E5 end to end: manager neighbour gets the guest MAC during A2 -> A2 FAIL, exit 1",
      lambda: res["cases"][1]["category"] == "FAIL" and A.group_exit(res) == 1)


# ------------------------------------------------------------------ F (06B-4HR: the five review findings)
class PingRc(SimGuest):
    """ping returns `rc` AFTER the simulated kernel emitted its ARP requests (residual frames)."""
    def __init__(self, *a, ping_rc=2, **kw):
        super().__init__(*a, **kw)
        self.ping_rc = ping_rc

    def run(self, cmd, timeout=60):
        rc, out = super().run(cmd, timeout)
        if cmd.startswith("ping "):
            return self.ping_rc, "ping: simulated rc"
        return rc, out


class RichGuest(SimGuest):
    """Baseline with pre-existing configuration: arp_notify=1, an extra /32 address, an extra route, static
    neighbours on IF and on another interface. Injects one console exception before/after a command; after the
    command it may also change the MAC (restore must undo it)."""
    def __init__(self, *a, fail_before=None, fail_after=None, mutate_mac=False, **kw):
        super().__init__(*a, **kw)
        self.notify = 1
        self.addrs.add("192.0.2.99/32")
        self.routes.add(f"198.51.100.0/24 via 10.200.0.1 dev {self.iface}")
        self.neigh[("10.200.0.9", self.iface)] = ("00:11:22:33:44:99", 0x6)
        self.neigh[("192.168.1.9", "br-lan")] = ("00:11:22:33:44:88", 0x6)
        self.fail_before, self.fail_after, self.mutate_mac = fail_before, fail_after, mutate_mac

    def run(self, cmd, timeout=60):
        if cmd == self.fail_before:
            self.fail_before = None
            self.log.append(cmd)
            raise TimeoutError("console timeout before the command (simulated)")
        r = super().run(cmd, timeout)
        if cmd == self.fail_after:
            self.fail_after = None
            if self.mutate_mac:
                self.mac = "52:54:00:de:ad:01"
            raise TimeoutError("console timeout after the command (simulated)")
        return r


def rows_with(change):
    rows = json.loads(NEIGH)
    change(rows)
    return json.dumps(rows)


def mgr(rows):
    return [r for r in rows if r["dst"] == "192.168.60.10"][0]


def sec_F(tmp):
    # ---- F1: S1 accepts only the approved gratuitous ARP REQUEST
    t("F1.1 S1 clean gratuitous requests -> ĐẠT (kiểm quy tắc)",
      lambda: one(tmp, "f11", "T15-S1", spaced(probe_frames("T15-S1")))["category"] == "DAT_KIEM_QUY_TAC")
    for op in (2, 99):
        t(f"F1.2 S1 with gratuitous frames of opcode {op} only -> not a probe, KHÔNG TẠO ĐƯỢC GÓI, never ĐẠT",
          lambda op=op: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and r["probe_frames"] == 0)(
              one(tmp, f"f12-{op}", "T15-S1", spaced([grat(ip, op) for ip in (S.GUEST_IP,) + A.T15_SPOOF_IPS]))))
    t("F1.3 S1 gratuitous request sent unicast (not broadcast) -> not a probe",
      lambda: one(tmp, "f13", "T15-S1", spaced([B.eth(TAP, GUEST, 0x0806, B.arp(1, GUEST, ip, ZERO, ip))
                                                for ip in A.T15_SPOOF_IPS]))["probe_frames"] == 0)
    t("F1.4 S1 gratuitous request with htype 6 / ptype 0x86dd -> not a probe",
      lambda: one(tmp, "f14", "T15-S1", spaced([B.eth(BC, GUEST, 0x0806, B.arp(1, GUEST, ip, ZERO, ip, htype=6))
                                                for ip in A.T15_SPOOF_IPS] +
                                               [B.eth(BC, GUEST, 0x0806, B.arp(1, GUEST, ip, ZERO, ip, ptype=0x86DD))
                                                for ip in A.T15_SPOOF_IPS]))["probe_frames"] == 0)
    t("F1.5 S1 mix: requests for two IPs + an opcode-2 frame for the third -> KHÔNG TẠO ĐƯỢC GÓI naming the third",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and "192.168.60.1" in r["verdict"])(
          one(tmp, "f15", "T15-S1", spaced([grat(S.GUEST_IP), grat("10.200.0.1"), grat("192.168.60.10"),
                                            grat("192.168.60.1", 2)]))))
    # ---- F2: worker neighbours
    F2 = [("manager entry removed after", lambda rows: rows.remove(mgr(rows)), "CHUA_KIEM_CHUNG"),
          ("manager moved to eth9 with another MAC", lambda rows: mgr(rows).update(dev="eth9", lladdr="00:11:22:33:44:66"), "FAIL"),
          ("manager moved to eth9 with the same MAC", lambda rows: mgr(rows).update(dev="eth9"), "FAIL"),
          ("manager entry FAILED (MAC kept)", lambda rows: mgr(rows).update(state=["FAILED"]), "CHUA_KIEM_CHUNG"),
          ("manager entry INCOMPLETE without MAC", lambda rows: (mgr(rows).pop("lladdr"), mgr(rows).update(state=["INCOMPLETE"])), "CHUA_KIEM_CHUNG"),
          ("manager REACHABLE -> STALE (normal)", lambda rows: mgr(rows).update(state=["STALE"]), "DAT_KIEM_QUY_TAC"),
          ("manager REACHABLE -> DELAY (normal)", lambda rows: mgr(rows).update(state=["DELAY"]), "DAT_KIEM_QUY_TAC")]
    for v in (None, 1, True, [], {}):
        F2.append((f"manager lladdr {v!r}", lambda rows, v=v: mgr(rows).update(lladdr=v), "LOI_PHEP_DO"))
    F2 += [("manager state missing", lambda rows: mgr(rows).pop("state"), "LOI_PHEP_DO"),
           ("manager state items [1, True, {}]", lambda rows: mgr(rows).update(state=[1, True, {}]), "LOI_PHEP_DO"),
           ("manager state empty", lambda rows: mgr(rows).update(state=[]), "LOI_PHEP_DO"),
           ("manager state unknown string", lambda rows: mgr(rows).update(state=["WEIRD"]), "LOI_PHEP_DO"),
           ("row with a bad dst", lambda rows: rows.append({"dst": "x", "dev": "eth0", "lladdr": MANAGER_MAC, "state": ["STALE"]}), "LOI_PHEP_DO"),
           ("duplicate row hides a guest MAC (guest MAC row first)",
            lambda rows: rows.extend([{"dst": "192.168.60.99", "dev": "eth0", "lladdr": GUEST, "state": ["REACHABLE"]},
                                      {"dst": "192.168.60.99", "dev": "eth0", "lladdr": MANAGER_MAC, "state": ["REACHABLE"]}]), "FAIL"),
           ("duplicate identical normal rows", lambda rows: rows.append(dict(mgr(rows))), "LOI_PHEP_DO"),
           ("guest MAC row + an invalid row: the valid abnormal row is kept",
            lambda rows: rows.extend([{"dst": "192.168.60.99", "dev": "eth0", "lladdr": GUEST, "state": ["STALE"]},
                                      {"dst": "192.168.60.98", "dev": "eth0", "lladdr": None, "state": ["STALE"]}]), "FAIL")]
    for n, ch, want in F2:
        t(f"F2 S1 worker neighbour after: {n} -> {want}",
          lambda ch=ch, want=want, n=n: one(tmp, "f2-" + re.sub(r"\W", "", n), "T15-S1", spaced(probe_frames("T15-S1")),
                                           over={"neigh_after": rows_with(ch)})["category"] == want)
    t("F2.b before-table invalid (lladdr null) -> LỖI PHÉP ĐO",
      lambda: one(tmp, "f2b", "T15-S1", spaced(probe_frames("T15-S1")),
                  over={"neigh_before": rows_with(lambda rows: mgr(rows).update(lladdr=None))})["category"] == "LOI_PHEP_DO")
    t("F2.c A2 target entry lost -> CHƯA KIỂM CHỨNG (not ĐẠT)",
      lambda: one(tmp, "f2c", "T14-A2", spaced(probe_frames("T14-A2")),
                  over={"neigh_after": rows_with(lambda rows: rows.remove(mgr(rows)))})["category"] == "CHUA_KIEM_CHUNG")
    # ---- F3: execution record contract
    specs = [(cid, spaced(probe_frames(cid)), None, None) for cid in A.CASE_IDS]
    pc, cf, rec = scenario(tmp, "f3", specs)
    rec["iface"] = IF

    def grp(change):
        r = copy.deepcopy(rec)
        for c in r["cases"]:
            change(c)
        res = A.evaluate_group(pc, cf, TAP, r)
        return res, A.group_exit(res)
    t("F3.0 complete clean group -> exit 0, labels DAT/DAT/DAT_KIEM_QUY_TAC/DAT_KIEM_QUY_TAC",
      lambda: (lambda res, e: e == 0 and [c["category"] for c in res["cases"]] == ["DAT", "DAT", "DAT_KIEM_QUY_TAC", "DAT_KIEM_QUY_TAC"]
               and res["record_problems"] == [])(*grp(lambda c: None)))
    F3 = [("empty steps", lambda c: c.update(steps=[])),
          ("setup only", lambda c: c.update(steps=c["steps"][:1])),
          ("settle missing", lambda c: c.update(steps=c["steps"][:-1])),
          ("phase renamed 'unknown'", lambda c: [x.update(phase="unknown") for x in c["steps"]]),
          ("every rc 2", lambda c: [x.update(rc=2) for x in c["steps"]]),
          ("rc not an integer", lambda c: [x.update(rc="0") for x in c["steps"]]),
          ("steps reordered", lambda c: c.update(steps=c["steps"][::-1])),
          ("guest baseline missing (restore says restored)", lambda c: c["guest_state"].update(before=None)),
          ("guest baseline incomplete", lambda c: c["guest_state"].update(before={"mac": GUEST})),
          ("restore evidence missing", lambda c: c["guest_state"].update(restore=None)),
          ("restore 'restored' not boolean", lambda c: c["guest_state"]["restore"].update(restored="true")),
          ("restore says restored with diffs", lambda c: c["guest_state"]["restore"].update(diffs=["mac"]))]
    for n, ch in F3:
        t(f"F3 group with {n} -> never exit 0, no case ĐẠT, record problem",
          lambda ch=ch: (lambda res, e: e != 0 and not any(c["ok"] for c in res["cases"]) and res["record_problems"])(*grp(ch)))
    t("F3.s a STOPPED case with a valid record (steps up to the failing one, exec_error, restore) -> LỖI THỰC THI, "
      "no record problem",
      lambda: (lambda res, e: res["cases"][0]["category"] == "LOI_THUC_THI" and res["record_problems"] == [] and e == 4)(
          *grp_one(rec, pc, cf, lambda c: c.update(steps=[dict(c["steps"][0], rc=2)], exec_error="setup 'ip route add': rc 2"))))
    t("F3.t a STOPPED case whose earlier step is outside the contract -> record problem",
      lambda: grp_one(rec, pc, cf, lambda c: c.update(steps=[dict(c["steps"][0], rc=2), c["steps"][1]],
                                                     exec_error="trigger: rc 9"))[0]["record_problems"])
    # ---- F4: ping rc outside {0, 1}, through run_group then evaluate_group
    for rc, want_err in ((2, True), (3, True), (0, False), (1, False)):
        t(f"F4 run_group: ping rc {rc} -> " + ("execution error recorded, read B taken, restored, settle not run"
                                               if want_err else "inside the contract"),
          lambda rc=rc, want_err=want_err: (lambda rec: all(
              (("rc %d outside the contract" % rc) in (c["exec_error"] or "")) == want_err
              and c["read_error"] is None and c["guest_state"]["restore"]["restored"] is True
              and (("sleep %d" % A.SETTLE_S) in [x["cmd"] for x in c["steps"]]) != want_err
              for c in rec["cases"] if c["id"].startswith("T14")))(
              run_sim(tmp, f"f4-{rc}", guest_kw=None, cases=None, guest_cls=PingRc, guest_extra={"ping_rc": rc})[1]))
    g, rec4, pc4, cf4 = run_sim(tmp, "f4e", guest_cls=PingRc, guest_extra={"ping_rc": 2})
    res4 = A.evaluate_group(pc4, cf4, TAP, rec4)
    t("F4.e evaluate_group after ping rc 2 (frames present): T14 LỖI THỰC THI, no record problem, exit 4 (never 0)",
      lambda: [c["category"] for c in res4["cases"]][:3] == ["LOI_THUC_THI"] * 3 and res4["record_problems"] == []
      and A.group_exit(res4) == 4)
    # ---- F5: measurement errors never hide a determined failure
    bad = spaced(probe_frames("T14-A2") + [worker_arp("192.168.60.10")])
    t("F5.1 known frame violation, clean reads -> FAIL with the frame evidence",
      lambda: (lambda r: r["category"] == "FAIL" and r["failure_evidence"] and not r["measurement_errors"])(
          one(tmp, "f51", "T14-A2", bad)))
    t("F5.2 known frame violation + read_error (raw rows kept) -> FAIL, JSON keeps BOTH the failure and the measurement error",
      lambda: (lambda r: r["category"] == "FAIL" and any("192.168.60.10" in x for x in r["failure_evidence"])
               and any("second read failed" in x for x in r["measurement_errors"]))(
          one(tmp, "f52", "T14-A2", bad, over={"read_error": "OSError: second read failed after raw row was saved"})))
    t("F5.3 neighbour violation (valid rows) + read_error -> FAIL, both kept",
      lambda: (lambda r: r["category"] == "FAIL" and r["failure_evidence"] and r["measurement_errors"])(
          one(tmp, "f53", "T15-S1", spaced(probe_frames("T15-S1")),
              over={"neigh_after": NEIGH.replace(MANAGER_MAC, "02:00:00:00:00:66"), "read_error": "OSError: nft read failed"})))
    t("F5.4 frame violation but read times overlap (A ends after B starts: window not valid) -> no FAIL inferred from "
      "frame positions; LỖI PHÉP ĐO",
      lambda: (lambda pc, cf, rec: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["failure_evidence"])(
          A.evaluate_group(pc, cf, TAP, rec)["cases"][0]))(
          *scenario(tmp, "f54", [("T14-A2", bad, None, None)],
                    counters_override=[V.rec("T14-A2 before", 100, 112, V.BASE),
                                       V.rec("T14-A2 after", 110, 120, V.after(arp_in_drop=3))])))
    t("F5.5 neighbour violation with the capture unreadable -> FAIL (neighbour evidence kept), capture error kept",
      lambda: (lambda pc, cf, rec: (lambda r: r["category"] == "FAIL" and any("capture" in x for x in r["measurement_errors"]))(
          A.evaluate_group(pc + ".missing", cf, TAP, rec)["cases"][0]))(
          *scenario(tmp, "f55", [("T15-S1", spaced(probe_frames("T15-S1")),
                                  {"neigh_after": NEIGH.replace(MANAGER_MAC, GUEST)}, None)])))
    t("F5.6 neighbour violation with the counter file invalid -> FAIL, counter error kept",
      lambda: (lambda pc, cf, rec: (lambda r: r["category"] == "FAIL" and any("invalid measurement" in x for x in r["measurement_errors"]))(
          A.evaluate_group(pc, cf, TAP, rec)["cases"][0]))(
          *scenario(tmp, "f56", [("T15-S1", spaced(probe_frames("T15-S1")),
                                  {"neigh_after": NEIGH.replace(MANAGER_MAC, GUEST)}, None)], counters_override=["not json"])))
    t("F5.7 group_exit: FAIL wins over LỖI PHÉP ĐO in the same group",
      lambda: A.group_exit({"cases": [{"category": "LOI_PHEP_DO"}, {"category": "FAIL"}], "record_problems": []}) == 1)
    # ---- restore matrix with a pre-configured baseline (40 cases)
    probs = []
    n = 0
    for iface in ("eth1", "br-lan"):
        for cid in ("T14-A2", "T15-S1"):
            cmds = [x for _, x in A.contract_steps(CASES[cid], iface)]
            for where in ("before", "after"):
                for cmd in cmds:
                    n += 1
                    counters, frames = dict(V.BASE), []
                    g = RichGuest(counters, frames, iface=iface, **{"fail_" + where: cmd}, mutate_mac=(where == "after"))
                    before = GS.read_state(g, iface)
                    cfx = os.path.join(tmp, f"m-{n}.jsonl")
                    open(cfx, "w").close()
                    rr = A.run_group(g, fake_counters_reader(counters, cfx), lambda: (True, "link"), lambda: NEIGH,
                                     lambda c: (True, "ctl"), [CASES[cid]], iface)
                    d = GS.diff(before, GS.read_state(g, iface))
                    c = rr["cases"][0]
                    if d or not c["exec_error"] or c["guest_state"]["restore"]["restored"] is not True \
                            or A.execution_problems(CASES[cid], c, iface):
                        probs.append((iface, cid, where, cmd, d, c["exec_error"], A.execution_problems(CASES[cid], c, iface)))
    t(f"F6 restore matrix with a pre-configured baseline: {n} console failures (before/after every step, both "
      "interfaces) -> state restored exactly, execution error recorded, record inside the contract",
      lambda: n == 40 and probs == [])


def grp_one(rec, pc, cf, change):
    r = copy.deepcopy(rec)
    change(r["cases"][0])
    res = A.evaluate_group(pc, cf, TAP, r)
    return res, A.group_exit(res)


# ------------------------------------------------------------------ H (06B-4HR1: HR1-HR5 of the 06B-4HR review)
def tap_rows(change):
    """NEIGH with a change applied to the MANDATORY row (10.200.0.2 tap0)."""
    def ch(rows):
        change([r for r in rows if r["dst"] == S.GUEST_IP and r["dev"] == "tap0"][0])
    return rows_with(ch)


def sec_H(tmp):
    S1 = lambda name, **over: one(tmp, name, "T15-S1", spaced(probe_frames("T15-S1")), over=over)   # noqa: E731
    # ---- HR1: baseline content and restore evidence checked against the baseline
    g, rec, pc, cf = run_sim(tmp, "h1")

    def grp(change, case=0):
        r = copy.deepcopy(rec)
        change(r["cases"][case])
        res = A.evaluate_group(pc, cf, TAP, r)
        return res, A.group_exit(res)
    t("H1.0 real run_group record (restore with its re-read 'after') -> exit 0, labels unchanged",
      lambda: (lambda res, e: e == 0 and [c["category"] for c in res["cases"]] == ["DAT", "DAT", "DAT_KIEM_QUY_TAC", "DAT_KIEM_QUY_TAC"])(*grp(lambda c: None)))
    H1 = [("restore 'after' MAC differs from the baseline (restored=True, diffs=[])",
           lambda c: c["guest_state"]["restore"]["after"].update(mac="52:54:00:de:ad:01")),
          ("restore 'after' missing", lambda c: c["guest_state"]["restore"].pop("after")),
          ("restore 'after' with an invalid address", lambda c: c["guest_state"]["restore"]["after"].update(addrs=[42])),
          ("restore 'after' route missing vs baseline", lambda c: c["guest_state"]["restore"]["after"]["routes"].pop()),
          ("restore 'after' arp_notify differs", lambda c: c["guest_state"]["restore"]["after"].update(arp_notify=1)),
          ("restored=True with an error", lambda c: c["guest_state"]["restore"].update(error="snapshot state read failed")),
          ("restore commands [42]", lambda c: c["guest_state"]["restore"].update(commands=[42])),
          ("restore command rc 'x'", lambda c: c["guest_state"]["restore"].update(commands=[{"step": "routes", "cmd": "ip route del x", "rc": "x", "out": ""}])),
          ("baseline addrs [42]", lambda c: c["guest_state"]["before"].update(addrs=[42])),
          ("baseline route object", lambda c: c["guest_state"]["before"].update(routes=[{"invalid": "route"}])),
          ("baseline static neighbour not a MAC", lambda c: c["guest_state"]["before"].update(neigh_static={"10.200.0.77 eth1": "not a MAC"})),
          ("baseline static neighbour bad key", lambda c: c["guest_state"]["before"].update(neigh_static={"invalid": "00:11:22:33:44:55"})),
          ("baseline dynamic neighbour malformed", lambda c: c["guest_state"]["before"].update(neigh_dynamic={"10.200.0.1 eth1": ["x"]})),
          ("baseline operstate ''", lambda c: c["guest_state"]["before"].update(operstate="")),
          ("baseline operstate 'weird'", lambda c: c["guest_state"]["before"].update(operstate="weird")),
          ("baseline arp_notify -1", lambda c: c["guest_state"]["before"].update(arp_notify=-1))]
    def both(ch):                     # same invalid content in the baseline AND the re-read state: diff() sees nothing
        def f(c):
            ch(c["guest_state"]["before"])
            ch(c["guest_state"]["restore"]["after"])
        return f
    H1 += [("baseline AND after addrs [42]", both(lambda st: st.update(addrs=[42]))),
           ("baseline AND after route object", both(lambda st: st.update(routes=[{"invalid": "route"}]))),
           ("baseline AND after static neighbour not a MAC", both(lambda st: st.update(neigh_static={"10.200.0.77 eth1": "not a MAC"}))),
           ("baseline AND after operstate 'weird'", both(lambda st: st.update(operstate="weird"))),
           ("baseline AND after arp_notify -1", both(lambda st: st.update(arp_notify=-1))),
           ("restore 'after' with a malformed dynamic neighbour (diff() ignores dynamic)",
            lambda c: c["guest_state"]["restore"]["after"].update(neigh_dynamic={"bad": "x"}))]
    for n, ch in H1:
        t(f"H1 {n} -> not ĐẠT, record problem, never exit 0",
          lambda ch=ch: (lambda res, e: e != 0 and not res["cases"][0]["ok"] and res["record_problems"])(*grp(ch)))
    t("H1.d dynamic neighbours differing between baseline and 'after' are NOT forced (still exit 0)",
      lambda: (lambda res, e: e == 0)(*grp(lambda c: c["guest_state"]["restore"]["after"].update(neigh_dynamic={}))))
    t("H1.c CLI on a real record whose 'after' contradicts the baseline -> exit 2",
      lambda: _cli_exit(tmp, pc, cf, rec, lambda c: c["guest_state"]["restore"]["after"].update(mac="52:54:00:de:ad:01")) == 2)
    # ---- HR2: mandatory binding must be usable; contradictory states are invalid
    for st in (["PERMANENT", "FAILED"], ["PERMANENT", "INCOMPLETE"], ["PERMANENT", "NONE"], ["PERMANENT", "REACHABLE"]):
        t(f"H2.1 mandatory tap0 row with states {st} -> LỖI PHÉP ĐO, never ĐẠT",
          lambda st=st: S1("h21" + "".join(st), neigh_after=tap_rows(lambda r: r.update(state=st)))["category"] == "LOI_PHEP_DO")
    t("H2.2 contradictory row is not returned as a valid row (unknown instead)",
      lambda: not [r for r in A.parse_neigh(tap_rows(lambda r: r.update(state=["PERMANENT", "FAILED"])))[0]
                   if r["dst"] == S.GUEST_IP] and A.parse_neigh_full(tap_rows(lambda r: r.update(state=["PERMANENT", "FAILED"])))[2]
      == [(S.GUEST_IP, "tap0")])
    for n, ch in (("REACHABLE (not PERMANENT)", lambda r: r.update(state=["REACHABLE"])),
                  ("FAILED with the guest MAC (no usable binding)", lambda r: r.update(state=["FAILED"])),
                  ("FAILED without MAC", lambda r: (r.pop("lladdr"), r.update(state=["FAILED"]))),
                  ("another MAC", lambda r: r.update(lladdr=MANAGER_MAC))):
        t(f"H2.3 valid mandatory row {n} -> FAIL",
          lambda ch=ch, n=n: S1("h23" + re.sub(r"\W", "", n), neigh_after=tap_rows(ch))["category"] == "FAIL")
    t("H2.4 mandatory row REACHABLE both before and after (no tap0 change) -> still FAIL (binding must be PERMANENT)",
      lambda: S1("h24", neigh_before=tap_rows(lambda r: r.update(state=["REACHABLE"])),
                 neigh_after=tap_rows(lambda r: r.update(state=["REACHABLE"])))["category"] == "FAIL")
    # ---- HR3: not-started case keeps independent evidence
    bad_after = tap_rows(lambda r: r.update(lladdr=MANAGER_MAC))
    cnt = [0]

    def neigh_seq():
        cnt[0] += 1
        return NEIGH if cnt[0] == 1 else bad_after
    g3, rec3, pc3, cf3 = run_sim(tmp, "h3", guest_kw={"bad_section": "route"}, neigh=neigh_seq, cases=[CASES["T14-A2"]])
    r3 = A.evaluate_group(pc3, cf3, TAP, rec3)["cases"][0]
    t("H3.1 not started (state unreadable) + valid mandatory neighbour change -> FAIL, not_started kept, no command sent",
      lambda: r3["category"] == "FAIL" and r3["not_started"] is True and r3["failure_evidence"]
      and not any(x.startswith(("ip route add", "ping")) for x in g3.log))
    r3b = A.evaluate_group(pc3 + ".missing", cf3, TAP, rec3)["cases"][0]
    t("H3.2 same + capture missing -> FAIL with the capture error kept in measurement_errors",
      lambda: r3b["category"] == "FAIL" and any("capture" in x for x in r3b["measurement_errors"]) and r3b["not_started"])
    g3c, rec3c, pc3c, cf3c = run_sim(tmp, "h3c", guest_kw={"bad_section": "route"}, cases=[CASES["T14-A2"]])
    r3c = A.evaluate_group(pc3c + ".missing", cf3c, TAP, rec3c)["cases"][0]
    t("H3.3 not started + capture missing, neighbours clean -> LỖI PHÉP ĐO (precedence), not_started and exec_error kept",
      lambda: r3c["category"] == "LOI_PHEP_DO" and r3c["not_started"] and r3c["measurement_errors"])
    with open(cf3c, "a") as f:            # a real counter file always holds the session reads
        f.write(json.dumps(V.rec("session before boot", 50, 50.01, V.BASE)) + "\n")
    r3d = A.evaluate_group(pc3c, cf3c, TAP, rec3c)["cases"][0]
    t("H3.4 not started, inputs readable, neighbours clean -> LỖI THỰC THI with every evidence field present",
      lambda: r3d["category"] == "LOI_THUC_THI" and r3d["not_started"] and r3d["measurement_errors"] == []
      and all(k in r3d for k in A.EVIDENCE_FIELDS))
    r3e = A.evaluate_case(L.classified_frames(scenario(tmp, "h3e", [("T14-A2", spaced(probe_frames("T14-A2") + [worker_arp("192.168.60.10")]), None, None)])[0], TAP),
                          None, CASES["T14-A2"], crec_for("T14-A2", exec_error="state read failed", steps=[],
                                                          guest_state={"before": None, "restore": None}), True, iface=IF)
    t("H3.5 not started, no counter window: frame positions are not used to infer a FAIL",
      lambda: r3e["category"] != "FAIL" and not r3e["failure_evidence"])
    # ---- HR4: unreadable rows are unknown, not missing
    for n, ch in (("lladdr 1", lambda r: r.update(lladdr=1)), ("state missing", lambda r: r.pop("state")),
                  ("state 'PERMANENT' (string)", lambda r: r.update(state="PERMANENT"))):
        t(f"H4.1 mandatory row unreadable ({n}) after -> LỖI PHÉP ĐO, no FAIL inferred",
          lambda ch=ch, n=n: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["failure_evidence"])(
              S1("h41" + re.sub(r"\W", "", n), neigh_after=tap_rows(ch))))
    t("H4.2 mandatory row unreadable BEFORE, after clean -> LỖI PHÉP ĐO, not 'tap0 changed'",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["failure_evidence"])(
          S1("h42", neigh_before=tap_rows(lambda r: r.update(lladdr=1)))))
    t("H4.3 valid table truly without the mandatory row -> FAIL",
      lambda: S1("h43", neigh_after=rows_with(lambda rows: rows.remove([r for r in rows if r["dev"] == "tap0"][0])))["category"] == "FAIL")
    t("H4.4 mandatory row unreadable + a valid row with the guest MAC on eth0 -> FAIL kept",
      lambda: S1("h44", neigh_after=rows_with(lambda rows: ([r for r in rows if r["dev"] == "tap0"][0].update(lladdr=1),
                                                            rows.append({"dst": "192.168.60.99", "dev": "eth0", "lladdr": GUEST, "state": ["STALE"]}))))["category"] == "FAIL")
    t("H4.5 an unidentifiable row (no dst) -> LỖI PHÉP ĐO, no 'missing'/'changed' inferred for any entry",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["failure_evidence"] and not r["neighbour_inconclusive"])(
          S1("h45", neigh_after=rows_with(lambda rows: (rows.remove(mgr(rows)), rows.append({"dev": "eth0", "lladdr": MANAGER_MAC}))))))
    t("H4.6 watched IP row unreadable BEFORE, after valid with another MAC -> no FAIL from the comparison (LỖI PHÉP ĐO)",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["failure_evidence"])(
          S1("h46", neigh_before=rows_with(lambda rows: mgr(rows).update(lladdr=None)),
             neigh_after=NEIGH.replace(MANAGER_MAC, "02:00:00:00:00:66"))))
    t("H4.7 watched IP: valid before, row unreadable after -> LỖI PHÉP ĐO and NOT reported as 'missing'",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["neighbour_inconclusive"] and not r["failure_evidence"])(
          S1("h47", neigh_after=rows_with(lambda rows: mgr(rows).update(lladdr=None)))))
    # ---- HR5: control callback payloads
    for v in (True, 1, "true", {"ok": True}, [True], [True, "x", 3], (1, "x"), ("true", "x"), None):
        t(f"H5 control callback returns {v!r} -> record kept, control not ok, case not ĐẠT",
          lambda v=v: (lambda rec: rec["cases"][0]["control"]["ok"] is False and
                       A.evaluate_case(None, None, CASES["T14-A2"], rec["cases"][0], True)["category"] != "DAT")(
              run_sim(tmp, "h5", control=lambda c, v=v: v, cases=[CASES["T14-A2"]])[1]))
    t("H5.ok control callback returns (True, detail) -> control ok",
      lambda: run_sim(tmp, "h5ok", control=lambda c: (True, "ARP seen"), cases=[CASES["T14-A2"]])[1]["cases"][0]["control"]["ok"] is True)
    # ---- every branch carries the same evidence/error fields
    branches = {"normal": one(tmp, "h6a", "T14-A3", spaced(probe_frames("T14-A3"))),
                "not_run": one(tmp, "h6b", "T14-A2", [], over={"not_run": A.NOT_RUN}),
                "not_started": r3d, "fail": r3}
    pcs, cfs, recs = scenario(tmp, "h6c", [("T14-A1", [], None, None)])
    branches["unknown_id"] = A.evaluate_group(pcs, cfs, TAP, {**recs, "cases": recs["cases"] + [dict(recs["cases"][0], id="X")]})["cases"][1]
    branches["skipped"] = A.evaluate_group(pcs, cfs, TAP, {"iface": IF, "cases": [], "skipped": "link failed"})["cases"][0]
    branches["input_error"] = A.evaluate_group(pcs + ".missing", cfs, TAP, recs)["cases"][0]
    for n, r in branches.items():
        t(f"H6 JSON branch '{n}' has every evidence/error field with the right type",
          lambda r=r: all(isinstance(r.get(k), tt) for k, tt in A.EVIDENCE_FIELDS.items()) and "probe_frames" in r)


def _cli_exit(tmp, pc, cf, rec, change):
    r = copy.deepcopy(rec)
    change(r["cases"][0])
    rp = os.path.join(tmp, "h1c.json")
    json.dump(r, open(rp, "w"))
    with contextlib.redirect_stdout(io.StringIO()):
        return A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp])


# ------------------------------------------------------------------ R1 (06B-4HR2: static/dynamic consistency)
def sec_R1(tmp):
    g, rec, pc, cf = run_sim(tmp, "r1")
    K, MACX = "10.200.0.9 eth1", "00:11:22:33:44:99"

    def grp(change):
        r = copy.deepcopy(rec)
        change(r["cases"][0]["guest_state"])
        res = A.evaluate_group(pc, cf, TAP, r)
        return res, A.group_exit(res), r

    def cli(change):
        r = copy.deepcopy(rec)
        change(r["cases"][0]["guest_state"])
        return _cli_exit(tmp, pc, cf, r, lambda c: None)
    bad = lambda res, e: e != 0 and not res["cases"][0]["ok"] and res["record_problems"]   # noqa: E731

    def dyn_perm(flags):
        def ch(gs):
            gs["before"]["neigh_dynamic"][K] = [MACX, flags]       # baseline claims a permanent row is dynamic
            gs["restore"]["after"]["neigh_dynamic"].pop(K, None)   # ... and it is gone after the restore
        return ch
    for fl in (6, 4, 0xC):
        t(f"R1.1 baseline neigh_dynamic entry with flags {fl:#x} (PERMANENT bit), lost after restore -> rejected (exit != 0)",
          lambda fl=fl: bad(*grp(dyn_perm(fl))[:2]))
    t("R1.2 same record through the CLI -> exit 2", lambda: cli(dyn_perm(6)) == 2)

    def overlap(gs):
        gs["before"]["neigh_static"][K] = MACX
        gs["before"]["neigh_dynamic"][K] = [MACX, 2]
        gs["restore"]["after"]["neigh_static"][K] = MACX
        gs["restore"]["after"]["neigh_dynamic"][K] = [MACX, 2]
    t("R1.3 same neighbour key in neigh_static AND neigh_dynamic -> rejected (evaluate_group and CLI)",
      lambda: bad(*grp(overlap)[:2]) and cli(overlap) == 2)

    def after_contradictory(gs):
        gs["restore"]["after"]["neigh_dynamic"][K] = [MACX, 6]
    t("R1.4 restore 'after' contradictory (dynamic entry with the PERMANENT flag), baseline clean -> rejected",
      lambda: bad(*grp(after_contradictory)[:2]) and cli(after_contradictory) == 2)

    def after_overlap(gs):
        gs["restore"]["after"]["neigh_static"][K] = MACX
        gs["restore"]["after"]["neigh_dynamic"][K] = [MACX, 2]
        gs["before"]["neigh_static"][K] = MACX
    t("R1.5 restore 'after' with a key in both groups -> rejected", lambda: bad(*grp(after_overlap)[:2]))

    def static_lost(gs):
        gs["before"]["neigh_static"][K] = MACX                     # properly static, missing after
    t("R1.6 static neighbour (proper group) lost after the restore -> rejected (evaluate_group and CLI)",
      lambda: bad(*grp(static_lost)[:2]) and cli(static_lost) == 2)

    def dyn_changed(gs):
        gs["before"]["neigh_dynamic"][K] = [MACX, 2]                # valid dynamic entry (no PERMANENT bit)...
        gs["restore"]["after"]["neigh_dynamic"].pop(K, None)        # ...gone after: kernel-managed, not forced
    t("R1.7 valid dynamic neighbour (flags 0x2) changed/removed after the restore -> still exit 0 (not forced)",
      lambda: (lambda res, e, r: e == 0 and res["record_problems"] == [])(*grp(dyn_changed))
      and cli(dyn_changed) == 0)
    r = copy.deepcopy(rec)
    dyn_perm(6)(r["cases"][0]["guest_state"])
    snap = copy.deepcopy(r)
    A.evaluate_group(pc, cf, TAP, r)
    t("R1.8 contradictory record is reported, never repaired: the input is unchanged, the entry is not moved",
      lambda: r == snap and any("belongs to neigh_static" in p for p in A.evaluate_group(pc, cf, TAP, r)["record_problems"]))
    fg = B.FakeGuest()
    fg.neigh[("10.200.0.9", "eth1")] = (MACX, 6)
    st = GS.read_state(fg, "eth1")
    t("R1.9 guest_state contract (real read_state on the simulated /proc/net/arp): flags 6 -> neigh_static, never dynamic;"
      " the validator accepts that state",
      lambda: st["neigh_static"][("10.200.0.9", "eth1")] == MACX and ("10.200.0.9", "eth1") not in st["neigh_dynamic"]
      and A.baseline_problem(A._jsonable(st)) is None)

    class StaticGuest(SimGuest):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.neigh[("10.200.0.9", self.iface)] = (MACX, 0x6)
    g2, rec2, pc2, cf2 = run_sim(tmp, "r1e", guest_cls=StaticGuest)
    res2 = A.evaluate_group(pc2, cf2, TAP, rec2)
    t("R1.10 end to end: guest with a static neighbour on IF (flags 6), run_group + evaluate_group -> exit 0, labels unchanged",
      lambda: A.group_exit(res2) == 0 and res2["record_problems"] == []
      and [c["category"] for c in res2["cases"]] == ["DAT", "DAT", "DAT_KIEM_QUY_TAC", "DAT_KIEM_QUY_TAC"])


# ------------------------------------------------------------------ C (CLI)
def sec_C(tmp):
    g, rec, pc, cf = run_sim(tmp, "c1")
    rp = os.path.join(tmp, "c1.json")
    json.dump(rec, open(rp, "w"))
    out = os.path.join(tmp, "c1-out.json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp, "--out", out])
    t("C1 CLI clean -> exit 0, JSON written", lambda: rc == 0 and len(json.load(open(out))["cases"]) == 4)
    rec2 = copy.deepcopy(rec)
    rec2["cases"] = rec2["cases"][:3]
    json.dump(rec2, open(rp, "w"))
    with contextlib.redirect_stdout(io.StringIO()):
        rc = A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp])
    t("C2 CLI: a case missing in the record -> exit 2 even though the 3 others pass", lambda: rc == 2)
    open(rp, "w").write("[1, 2]")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp])
    t("C3 CLI: invalid record -> exit 2", lambda: rc == 2)
    open(rp, "w").write("not json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp])
    t("C4 CLI: unreadable record -> exit 2", lambda: rc == 2)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = A.main(["--pcap", pc])
    t("C5 CLI: missing arguments -> exit 2", lambda: rc == 2)


# ------------------------------------------------------------------ PC3 (06B-4IR3): administrative link state
class FailUpOnce(SimGuest):
    """`ip link set dev IF up` fails ONCE (the T15 trigger), later attempts (the restore) succeed."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.up_failed = False

    def run(self, cmd, timeout=60):
        if cmd == f"ip link set dev {self.iface} up" and not self.up_failed:
            self.up_failed = True
            self.log.append(cmd)
            return 2, "RTNETLINK answers: simulated failure"
        return super().run(cmd, timeout)


def sec_PC3(tmp):
    g, rec, pc, cf = run_sim(tmp, "pc3")
    t("PC3.1 the record carries admin_up in every baseline and restore.after (bool)",
      lambda: all(isinstance(c["guest_state"]["before"]["admin_up"], bool)
                  and isinstance(c["guest_state"]["restore"]["after"]["admin_up"], bool) for c in rec["cases"]))

    def grp(change):
        r = copy.deepcopy(rec)
        change(r["cases"][3]["guest_state"])
        res = A.evaluate_group(pc, cf, TAP, r)
        return res, A.group_exit(res)
    for name, ch in (("baseline without admin_up", lambda gs: gs["before"].pop("admin_up")),
                     ("restore.after without admin_up", lambda gs: gs["restore"]["after"].pop("admin_up")),
                     ("baseline admin_up 'true' (string)", lambda gs: gs["before"].__setitem__("admin_up", "true")),
                     ("restore.after admin_up differs from the baseline although restored=True",
                      lambda gs: gs["restore"]["after"].__setitem__("admin_up", False))):
        t(f"PC3.2 {name} -> S1 never ĐẠT, record problem, group exit 2 (a record without a confirmed admin state "
          "is not a confirmed restore)",
          lambda ch=ch: (lambda r: r[0]["cases"][3]["category"] != "DAT_KIEM_QUY_TAC" and r[0]["record_problems"]
                         and r[1] == 2)(grp(ch)))
    t("PC3.3 production order: T14-A1, T14-A2, T14-A3, T15-S1 (S1 is the last case)",
      lambda: [c["id"] for c in A.build_cases()] == ["T14-A1", "T14-A2", "T14-A3", "T15-S1"])
    links = []

    def link():
        links.append(1)
        return True, "HTTP=200 + hash"
    g, rec, pc, cf = run_sim(tmp, "pc3-upfail", link=link, guest_kw={"fail_cmds": ["ip link set dev eth1 up"]})
    s1 = rec["cases"][3]
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("PC3.4 production order, `ip link set up` fails in the S1 trigger AND in the restore -> restore not confirmed "
      "(admin_up True -> False), NO service link after S1, S1 not ĐẠT",
      lambda: s1["guest_state"]["restore"]["restored"] is False
      and "admin_up: True -> False" in s1["guest_state"]["restore"]["diffs"] and s1["service_link_after"] is None
      and len(links) == 1 + 3 and res["cases"][3]["category"] != "DAT_KIEM_QUY_TAC" and not g.admin)
    links.clear()
    g, rec, pc, cf = run_sim(tmp, "pc3-upfail-once", link=link, guest_cls=FailUpOnce)
    s1 = rec["cases"][3]
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("PC3.5 production order, the S1 trigger `up` fails once, the restore `up` succeeds -> restored True with "
      "admin UP re-read, service link after S1 sent, S1 LỖI THỰC THI (never ĐẠT)",
      lambda: s1["guest_state"]["restore"]["restored"] is True and s1["guest_state"]["restore"]["after"]["admin_up"]
      and any(c["cmd"] == "ip link set dev eth1 up" and c["rc"] == 0 for c in s1["guest_state"]["restore"]["commands"])
      and len(links) == 1 + 4 and res["cases"][3]["category"] == "LOI_THUC_THI" and g.admin)
    g, rec, pc, cf = run_sim(tmp, "pc3-nocarrier", guest_kw={"carrier": False})
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("PC3.6 SIMULATED MIPS-like link (admin UP, no carrier, operstate down): T15 down/up keeps admin UP and operstate "
      "down -> every restore confirmed, group exit 0 (operstate rule unchanged; not a statement about the real guest)",
      lambda: all(c["guest_state"]["before"]["operstate"] == "down" and c["guest_state"]["before"]["admin_up"]
                  and c["guest_state"]["restore"]["restored"] for c in rec["cases"]) and A.group_exit(res) == 0)


def main(argv):
    jpath = argv[argv.index("--json") + 1] if "--json" in argv else None
    with tempfile.TemporaryDirectory(prefix="selftest-arp.") as tmp:
        for name, fn in (("D", sec_D), ("N", sec_N), ("P", lambda: sec_P(tmp)), ("X", lambda: sec_X(tmp)),
                         ("E", lambda: sec_E(tmp)), ("F", lambda: sec_F(tmp)), ("H", lambda: sec_H(tmp)), ("R1", lambda: sec_R1(tmp)), ("PC3", lambda: sec_PC3(tmp)), ("C", lambda: sec_C(tmp))):
            print(f"== section {name}")
            try:
                fn()
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    if jpath:
        json.dump(RESULTS, open(jpath, "w"), indent=0, sort_keys=True)
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"SELFTEST-ARP: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed" + ("" if not bad else f"; FAILED: {bad}"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
