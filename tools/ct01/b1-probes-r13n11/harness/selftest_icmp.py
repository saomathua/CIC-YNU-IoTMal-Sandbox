#!/usr/bin/env python3
"""06B-4E — offline tests of icmp_cases.py on SYNTHETIC captures/counter files generated here.
Sends nothing, runs nothing in a guest (the guest, the counter reader and the service link are fakes).

    python3 selftest_icmp.py [--json FILE]
"""
import contextlib
import io
import ipaddress
import json
import struct
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import icmp_cases as I         # noqa: E402
import signatures as S         # noqa: E402
import selftest_l2 as B        # noqa: E402  (frame builders only)
import selftest_l2eval as V    # noqa: E402  (counter-file builders only)

RESULTS = {}
TAP, GUEST = B.TAP, B.GUEST
CASES = {c["id"]: c for c in I.build_cases(TAP)}
DMAC = {"255.255.255.255": "ff:ff:ff:ff:ff:ff", "10.200.0.3": "ff:ff:ff:ff:ff:ff", "224.0.0.1": "01:00:5e:00:00:01"}


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


# ------------------------------------------------------------------ synthetic frames
def probe_frames(cid, n=3):
    c = CASES[cid]
    if c["family"] == 4:
        return [B.eth(DMAC[c["dst"]], GUEST, 0x0800, B.ipv4(S.GUEST_IP, c["dst"], 1, B.icmp(c["size"])))] * n
    if cid == "T13-I1":
        return [B.eth("33:33:00:00:00:01", GUEST, 0x86DD, B.ipv6(S.GUEST_LL6, "ff02::1", 58, B.icmp6(c["size"])))] * n
    return [ns_frame(c["dst"])] * n


def ns_frame(target, group=None, with_target=True, smac=GUEST):
    """06B-4ER: a well-formed Neighbor Solicitation (RFC 4861 §4.3): type 135, code 0, checksum (left 0:
    not verified by the decoder), 4 reserved bytes, the 16-byte target, then a source link-layer address
    option (type 1, length 1 = 8 bytes, MAC). Sent to the target's solicited-node group unless `group`."""
    tgt = ipaddress.IPv6Address(target)
    grp = group or I.solicited_node(str(tgt))
    body = struct.pack("!BBHI", 135, 0, 0, 0)
    if with_target:
        body += tgt.packed + bytes([1, 1]) + B.mac(smac)
    mac = "33:33:" + ":".join(f"{b:02x}" for b in ipaddress.IPv6Address(grp).packed[12:])
    return B.eth(mac, smac, 0x86DD, B.ipv6(S.GUEST_LL6, grp, 58, body))


def dhcp():
    return B.eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0800, B.ipv4("0.0.0.0", "255.255.255.255", 17, B.udp(68, 67)))


def reply_to_guest():
    return B.eth(GUEST, TAP, 0x0800, B.ipv4("10.200.0.1", "10.200.0.2", 1, B.icmp(8)))


# ------------------------------------------------------------------ scenario builder
def scenario(tmp, name, specs, link_before=True, link_after=True, counters_override=None, frames_override=None):
    """specs: [(case id, [(dt, frame), ...] frames relative to the case window, {counter: increment}, exec)].
    Case i window: A=[t0, t0+0.01], B=[t0+10, t0+10.01] with t0 = 100 + 20 i. Counters are cumulative."""
    values = dict(V.BASE)
    recs, frames, cases = [], [], []
    for i, (cid, fr, inc, ex) in enumerate(specs):
        t0 = 100.0 + 20 * i
        recs.append(V.rec(f"{cid} before", t0, t0 + 0.01, values))
        values = dict(values)
        for k, n in inc.items():
            values[k] += n
        recs.append(V.rec(f"{cid} after", t0 + 10, t0 + 10.01, values))
        frames += [(t0 + dt, f) for dt, f in fr]
        cases.append({"id": cid, "before": f"{cid} before", "after": f"{cid} after",
                      "command": I.command(CASES[cid], "eth1"), "exec": ex, "read_error": None})
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames_override if frames_override is not None else frames)
    cf = V.write_counters(os.path.join(tmp, name + ".jsonl"), counters_override if counters_override is not None else recs)
    record = {"iface": "eth1", "cases": cases, "service_link_before": {"ok": link_before, "detail": "x"},
              "service_link_after": {"ok": link_after, "detail": "x"}}
    if not link_before:
        record = {"iface": "eth1", "cases": [], "service_link_before": {"ok": False, "detail": "x"},
                  "service_link_after": None, "skipped": "service link before the group failed: no case was run"}
    return pc, cf, record


OK_EXEC = {"rc": 1, "output_tail": "3 packets transmitted, 0 received"}


def spaced(frames, start=1.0, step=0.5):
    return [(start + step * k, f) for k, f in enumerate(frames)]


def one(tmp, name, cid, frames, inc, ex=OK_EXEC, **kw):
    pc, cf, rec = scenario(tmp, name, [(cid, frames, inc, ex)], **kw)
    res = I.evaluate_group(pc, cf, TAP, rec)
    return res, res["cases"][0] if res["cases"] else None


# ------------------------------------------------------------------ D. definitions and commands
def sec_D():
    t("D1 five cases, ids as planned", lambda: [c["id"] for c in I.build_cases(TAP)] == list(I.CASE_IDS))
    t("D2 every size comes from signatures.py",
      lambda: all(c["size"] == (S.ICMP4_SIZES if c["family"] == 4 else S.ICMP6_SIZES)[c["id"]] for c in I.build_cases(TAP)))
    t("D3 a registry change changes the command (single source)",
      lambda: _with(S.ICMP4_SIZES, "T12-B1", 1999, lambda: " -s 1999 " in I.command(I.build_cases(TAP)[0], "eth1")))
    t("D4 expected classes: broadcast/multicast -> drop_bcast_mcast, subnet broadcast -> drop_private, IPv6 -> l2_bad_ethertype",
      lambda: [CASES[k]["expected"] for k in I.CASE_IDS] ==
      ["drop_bcast_mcast", "drop_bcast_mcast", "drop_private", "l2_bad_ethertype", "l2_bad_ethertype"])
    t("D5 T13-I2 target is the EUI-64 link-local of TAP_MAC, NS group derived from it",
      lambda: CASES["T13-I2"]["dst"] == S.eui64_ll(TAP) and CASES["T13-I2"]["ns_group"].startswith("ff02::1:ff"))
    t("D6 commands are plain busybox ping/ping6 with count, size and deadline",
      lambda: I.command(CASES["T12-B2"], "eth1") == "ping -c 3 -s 1202 -w 5 224.0.0.1"
      and I.command(CASES["T13-I1"], "br-lan") == "ping6 -c 3 -s 1301 -w 5 -I br-lan ff02::1")
    t("D7 bad interface name refused", lambda: _raises(ValueError, lambda: I.command(CASES["T13-I1"], "eth1; reboot")))
    t("D8 bad TAP MAC refused", lambda: _raises(ValueError, lambda: I.build_cases("7a:93")))


def _with(d, k, v, fn):
    old = d[k]
    d[k] = v
    try:
        return fn()
    finally:
        d[k] = old


def _raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------ P/F/U/K/E/M. evaluation through evaluate_group()
def sec_P(tmp):
    for cid, cls in (("T12-B1", "drop_bcast_mcast"), ("T12-B2", "drop_bcast_mcast"), ("T12-B4", "drop_private"),
                     ("T13-I1", "l2_bad_ethertype"), ("T13-I2", "l2_bad_ethertype")):
        t(f"P {cid}: 3 probe frames = {cls} delta 3 -> ĐẠT (kiểm quy tắc), rule_check only",
          lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["verdict"] == "ĐẠT (kiểm quy tắc)"
          and r["evidence_kind"] == "rule_check" and r["probe_frames"] == 3)(one(tmp, "p-" + cid, cid, spaced(probe_frames(cid)), {cls: 3})[1]))
    t("P6 background frame (DHCP -> drop_spoof) reconciled separately, still ĐẠT (kiểm quy tắc)",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["probe_frames"] == 3)(one(tmp, "p-bg", "T12-B1", spaced(probe_frames("T12-B1") + [dhcp()]), {"drop_bcast_mcast": 3, "drop_spoof": 1})[1]))


def sec_F(tmp):
    t("F1 counter delta 2 for 3 probe frames -> FAIL (counter_reconciliation)",
      lambda: (lambda r: r["category"] == "FAIL" and "counter_reconciliation" in r["failed"])(one(tmp, "f-delta", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 2})[1]))
    t("F2 an ICMP frame towards the guest in the window -> FAIL (no_reply_to_guest)",
      lambda: (lambda r: r["category"] == "FAIL" and "no_reply_to_guest" in r["failed"] and r["replies_to_guest"] == 1)(one(tmp, "f-reply", "T12-B2", spaced(probe_frames("T12-B2") + [reply_to_guest()]), {"drop_bcast_mcast": 3})[1]))
    other = [B.eth(B.MANAGER_MAC, GUEST, 0x0800, B.ipv4(S.GUEST_IP, "10.200.0.3", 1, B.icmp(CASES["T12-B4"]["size"])))]
    t("F3 a probe frame that does not reach the expected counter (OTHERHOST) -> FAIL",
      lambda: (lambda r: r["category"] == "FAIL" and "probe_packets_hit_expected_counter" in r["failed"])(one(tmp, "f-class", "T12-B4", spaced(probe_frames("T12-B4", 2) + other), {"drop_private": 2})[1]))
    t("F4 a determined failure is reported even when execution also failed",
      lambda: (lambda r: r["category"] == "FAIL")(one(tmp, "f-exec", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 1},
               ex={"error": "TIMEOUT: console"})[1]))


def sec_U(tmp):
    t("U1 a probe frame at the window edge -> CHƯA KIỂM CHỨNG (edge)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "biên" in r["verdict"])(one(tmp, "u-edge", "T12-B1", spaced(probe_frames("T12-B1")) + [(9.995, probe_frames("T12-B1", 1)[0])],
               {"drop_bcast_mcast": 4})[1]))
    unk = B.eth("ff:ff:ff:ff:ff:ff", "02:42:00:00:bb:02", 0x0800, B.ipv4("10.200.0.2", "1.1.1.1", 6, B.tcp(1, 2)))
    t("U2 a frame without a counter mapping in the window -> CHƯA KIỂM CHỨNG (named as such)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "không có bộ đếm" in r["verdict"])(one(tmp, "u-nocounter", "T12-B2", spaced(probe_frames("T12-B2") + [unk]), {"drop_bcast_mcast": 3})[1]))
    t("U3 service link after the group not intact -> CHƯA KIỂM CHỨNG, never ĐẠT",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and "liên kết dịch vụ sau" in r["verdict"])(one(tmp, "u-linkafter", "T13-I1", spaced(probe_frames("T13-I1")), {"l2_bad_ethertype": 3}, link_after=False)[1]))
    res, _ = one(tmp, "u-linkbefore", "T13-I1", spaced(probe_frames("T13-I1")), {"l2_bad_ethertype": 3}, link_before=False)
    t("U4 service link before the group failed -> every case CHƯA KIỂM CHỨNG, none judged",
      lambda: [c["category"] for c in res["cases"]] == ["CHUA_KIEM_CHUNG"] * 5)


def sec_K(tmp):
    t("K1 no probe frame (broadcast refused locally), counters unchanged -> KHÔNG TẠO ĐƯỢC GÓI, not ĐẠT",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and not r["ok"] and "không phải bằng chứng chặn" in r["verdict"])(one(tmp, "k-none", "T12-B1", [], {}, ex={"rc": 1, "output_tail": "ping: permission denied (are you root?)"})[1]))
    t("K2 ping timed out with no frame on tap0 -> KHÔNG TẠO ĐƯỢC GÓI (timeout is not evidence)",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(one(tmp, "k-timeout", "T13-I1", [], {}, ex={"rc": 1, "output_tail": "3 packets transmitted, 0 received"})[1]))
    t("K3 only background traffic in the window -> KHÔNG TẠO ĐƯỢC GÓI (background never replaces a probe)",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(one(tmp, "k-bgonly", "T12-B2", spaced([dhcp()]), {"drop_spoof": 1})[1]))


def bg_icmp(cid, size=56):
    c = CASES[cid]
    return B.eth(DMAC[c["dst"]], GUEST, 0x0800, B.ipv4(S.GUEST_IP, c["dst"], 1, B.icmp(size)))


def sec_K2(tmp):
    t("K4 an ICMP echo to the same destination with another size is NOT a probe frame -> KHÔNG TẠO ĐƯỢC GÓI",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and r["probe_frames"] == 0)(
          one(tmp, "k-othersize", "T12-B2", spaced([bg_icmp("T12-B2")]), {"drop_bcast_mcast": 1})[1]))


def sec_N(tmp):
    c = CASES["T13-I2"]
    tap_ll = ipaddress.IPv6Address(c["dst"])
    # same low 24 bits -> same solicited-node group, different address
    other = str(ipaddress.IPv6Address(int(tap_ll) ^ (0xABCD << 64)))
    t("N0 the 'other' target shares the solicited-node group of the case target",
      lambda: other != c["dst"] and I.solicited_node(other) == c["ns_group"])
    t("N1 decode: ns_target of a well-formed NS is the target address",
      lambda: B.L.decode(1.0, ns_frame(c["dst"]))["ip6"]["ns_target"] == c["dst"])
    t("N2 decode: NS without the target bytes -> ns_target None",
      lambda: B.L.decode(1.0, ns_frame(c["dst"], with_target=False))["ip6"]["ns_target"] is None)
    padded = ns_frame(c["dst"], with_target=False) + ipaddress.IPv6Address(c["dst"]).packed + b"\0" * 8
    t("N10 decode: NS whose IPv6 payload ends before the target, followed by trailing bytes -> ns_target None",
      lambda: B.L.decode(1.0, padded)["ip6"]["ns_target"] is None and B.L.decode(1.0, padded)["ip6"]["plen"] == 8)
    t("N3 NS with the right target -> probe frames counted, ĐẠT (kiểm quy tắc)",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["probe_frames"] == 3)(
          one(tmp, "n-ok", "T13-I2", spaced([ns_frame(c["dst"])] * 3), {"l2_bad_ethertype": 3})[1]))
    t("N4 NS to the same group but another target is NOT a probe -> KHÔNG TẠO ĐƯỢC GÓI",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and r["probe_frames"] == 0)(
          one(tmp, "n-other", "T13-I2", spaced([ns_frame(other, group=c["ns_group"])] * 3), {"l2_bad_ethertype": 3})[1]))
    t("N5 NS without a target is NOT a probe -> KHÔNG TẠO ĐƯỢC GÓI",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(
          one(tmp, "n-notgt", "T13-I2", spaced([ns_frame(c["dst"], with_target=False)] * 3), {"l2_bad_ethertype": 3})[1]))
    old = B.eth("33:33:" + ":".join(f"{b:02x}" for b in ipaddress.IPv6Address(c["ns_group"]).packed[12:]), GUEST, 0x86DD,
                B.ipv6(S.GUEST_LL6, c["ns_group"], 58, B.icmp6(16, typ=135)))
    t("N6 the 06B-4E fixture (target bytes cdcd...) is NOT a probe",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(
          one(tmp, "n-cdcd", "T13-I2", spaced([old] * 3), {"l2_bad_ethertype": 3})[1]))
    mld = B.eth("33:33:00:00:00:16", GUEST, 0x86DD, B.ipv6(S.GUEST_LL6, "ff02::16", 58, B.icmp6(20, typ=143)))
    t("N7 background IPv6 (MLD report) only -> KHÔNG TẠO ĐƯỢC GÓI, never a probe",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(
          one(tmp, "n-mld", "T13-I2", spaced([mld] * 2), {"l2_bad_ethertype": 2})[1]))
    t("N8 right-target NS sent to the wrong multicast group is NOT a probe",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI")(
          one(tmp, "n-grp", "T13-I2", spaced([ns_frame(c["dst"], group="ff02::1")] * 3), {"l2_bad_ethertype": 3})[1]))
    t("N9 mixed: 3 real probe NS + other-target NS + MLD -> only the 3 counted, ĐẠT (kiểm quy tắc)",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["probe_frames"] == 3)(
          one(tmp, "n-mix", "T13-I2", spaced([ns_frame(c["dst"])] * 3 + [ns_frame(other, group=c["ns_group"]), mld]),
              {"l2_bad_ethertype": 5})[1]))


def link_case(tmp, name, before, frames=None, inc=None):
    pc, cf, rec = scenario(tmp, name, [("T12-B1", frames if frames is not None else spaced(probe_frames("T12-B1")),
                                        inc if inc is not None else {"drop_bcast_mcast": 3}, OK_EXEC)])
    if before == "absent":
        del rec["service_link_before"]
    else:
        rec["service_link_before"] = before
    return pc, cf, rec


def sec_B(tmp):
    for name, before in (("B1 ok=False", {"ok": False, "detail": "HTTP 000"}), ("B2 state missing", "absent"),
                         ("B3 state null", None), ("B4 ok is the string 'true'", {"ok": "true"}),
                         ("B5 ok is 1", {"ok": 1}), ("B6 state is a list", [True]), ("B7 ok key missing", {"detail": "200"})):
        t(f"{name}, cases present, no 'skipped' -> evaluate_group gives CHƯA KIỂM CHỨNG, never ĐẠT",
          lambda before=before, name=name: (lambda res: res["cases"][0]["category"] == "CHUA_KIEM_CHUNG"
              and "trước nhóm" in res["cases"][0]["verdict"])(
              I.evaluate_group(*link_case(tmp, "b-" + name[:2], before)[:2], TAP, link_case(tmp, "b-" + name[:2], before)[2])))
    t("B8 link before ok=True -> ĐẠT (kiểm quy tắc) still possible",
      lambda: (lambda a: I.evaluate_group(a[0], a[1], TAP, a[2])["cases"][0]["category"] == "DAT_KIEM_QUY_TAC")(
          link_case(tmp, "b-ok", {"ok": True, "detail": "200"})))
    t("B9 link before failed but the counters prove a mismatch -> FAIL is still reported",
      lambda: (lambda a: I.evaluate_group(a[0], a[1], TAP, a[2])["cases"][0]["category"] == "FAIL")(
          link_case(tmp, "b-fail", {"ok": False}, inc={"drop_bcast_mcast": 1})))
    t("B10 link before failed and a reply reaches the guest -> FAIL",
      lambda: (lambda a: I.evaluate_group(a[0], a[1], TAP, a[2])["cases"][0]["category"] == "FAIL")(
          link_case(tmp, "b-reply", {"ok": False}, frames=spaced(probe_frames("T12-B1") + [reply_to_guest()]))))

    def cli(name, before):
        pc, cf, rec = link_case(tmp, name, before)
        rp, out = os.path.join(tmp, name + "-rec.json"), os.path.join(tmp, name + "-out.json")
        json.dump(rec, open(rp, "w"))
        with contextlib.redirect_stdout(io.StringIO()):
            rc = I.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp, "--out", out])
        return rc, json.load(open(out))
    t("B11 CLI: link before ok=False -> exit 4, case CHƯA KIỂM CHỨNG",
      lambda: (lambda r: r[0] == 4 and r[1]["cases"][0]["category"] == "CHUA_KIEM_CHUNG")(cli("b-cli1", {"ok": False})))
    t("B12 CLI: link before state missing -> exit 4", lambda: cli("b-cli2", "absent")[0] == 4)
    t("B13 evaluate_group: 'cases' not a list -> ValueError (CLI exit 2)",
      lambda: _raises(ValueError, lambda: I.evaluate_group("x", "y", TAP, {"cases": "T12-B1"})))


def sec_E(tmp):
    t("E1 console error during the ping -> LỖI THỰC THI (not ĐẠT even if counters match)",
      lambda: (lambda r: r["category"] == "LOI_THUC_THI" and not r["ok"])(one(tmp, "e-exc", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3},
               ex={"error": "TIMEOUT: console did not answer"})[1]))
    t("E2 tool missing -> LỖI THỰC THI",
      lambda: (lambda r: r["category"] == "LOI_THUC_THI")(one(tmp, "e-127", "T13-I2", [], {}, ex={"rc": 127, "output_tail": "sh: ping6: not found", "error": "tool missing in the guest"})[1]))
    t("E3 no execution record -> LỖI THỰC THI",
      lambda: (lambda r: r["category"] == "LOI_THUC_THI")(one(tmp, "e-none", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3}, ex=None)[1]))


def sec_M(tmp):
    pc, cf, rec = scenario(tmp, "m-ok", [("T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3}, OK_EXEC)])
    res = I.evaluate_group(os.path.join(tmp, "nope.pcapng"), cf, TAP, rec)
    t("M1 capture missing -> every case LỖI PHÉP ĐO", lambda: [c["category"] for c in res["cases"]] == ["LOI_PHEP_DO"])
    res = I.evaluate_group(pc, os.path.join(tmp, "nope.jsonl"), TAP, rec)
    t("M2 counter file missing -> LỖI PHÉP ĐO", lambda: res["cases"][0]["category"] == "LOI_PHEP_DO")
    t("M3 counter read 'after' missing -> LỖI PHÉP ĐO (never 0)",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO")(one(tmp, "m-label", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3},
               counters_override=[V.rec("T12-B1 before", 100.0, 100.01, V.BASE)])[1]))
    vals = {k: v for k, v in V.BASE.items() if k != "drop_bcast_mcast"}
    t("M4 compared counter missing in read B -> LỖI PHÉP ĐO",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO" and "missing" in r["verdict"])(one(tmp, "m-ctr", "T12-B1", spaced(probe_frames("T12-B1")), {},
               counters_override=[V.rec("T12-B1 before", 100.0, 100.01, V.BASE), V.rec("T12-B1 after", 110.0, 110.01, vals)])[1]))
    t("M5 malformed counter file -> LỖI PHÉP ĐO",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO")(one(tmp, "m-bad", "T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3},
               counters_override=[V.rec("T12-B1 before", 100.0, 100.01, V.BASE), "{broken"])[1]))
    pc, cf, rec = scenario(tmp, "m-rerr", [("T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3}, OK_EXEC)])
    rec["cases"][0]["read_error"] = "read 'T12-B1 after': RuntimeError: nft failed"
    res = I.evaluate_group(pc, cf, TAP, rec)
    t("M6 a counter read that failed during execution -> LỖI PHÉP ĐO", lambda: res["cases"][0]["category"] == "LOI_PHEP_DO")
    t("M7 malformed TAP MAC -> ValueError raised to the caller (CLI turns it into exit 2)",
      lambda: _raises(ValueError, lambda: I.evaluate_group(pc, cf, "7a:93", rec)))


# ------------------------------------------------------------------ L. labels and limits
def sec_L(tmp):
    specs = [(cid, spaced(probe_frames(cid)), {CASES[cid]["expected"]: 3}, OK_EXEC) for cid in I.CASE_IDS]
    pc, cf, rec = scenario(tmp, "l-all", specs)
    res = I.evaluate_group(pc, cf, TAP, rec)
    t("L1 a full group passes as ĐẠT (kiểm quy tắc) x5",
      lambda: [c["verdict"] for c in res["cases"]] == ["ĐẠT (kiểm quy tắc)"] * 5)
    t("L2 no result is ever plain 'ĐẠT' or a live-control kind", lambda: all(
        c["verdict"] != "ĐẠT" and c["evidence_kind"] == "rule_check" for c in res["cases"]) and res["evidence_kind"] == "rule_check")
    t("L3 guard 20 ms recorded with the unmeasured assumption",
      lambda: res["guard_s"] == 0.02 and "NOT measured" in res["assumption"])
    t("L4 group exit 0 for a full pass", lambda: I.group_exit(res) == 0)
    t("L5 group exit: FAIL 1, measurement error 2, not judged 4", lambda: (
        I.group_exit({"cases": [{"category": "DAT_KIEM_QUY_TAC"}, {"category": "FAIL"}]}),
        I.group_exit({"cases": [{"category": "LOI_PHEP_DO"}]}),
        I.group_exit({"cases": [{"category": "KHONG_TAO_DUOC_GOI"}]}), I.group_exit({"cases": []})) == (1, 2, 4, 2))
    t("L6 group exit: FAIL wins over a measurement error in the same group (FAIL > LỖI PHÉP ĐO)",
      lambda: I.group_exit({"cases": [{"category": "LOI_PHEP_DO"}, {"category": "FAIL"}]}) == 1)


# ------------------------------------------------------------------ R. run_group() with fakes (no guest)
class FakeGuest:
    def __init__(self, fail_on=None, rc=1):
        self.calls, self.fail_on, self.rc = [], fail_on, rc

    def run(self, cmd, timeout=60):
        self.calls.append(cmd)
        if self.fail_on and self.fail_on in cmd:
            raise TimeoutError("console did not answer")
        return self.rc, "3 packets transmitted, 0 received\n"


def sec_R(tmp):
    log = []
    g = FakeGuest()
    rec = I.run_group(g, lambda lbl: log.append(("read", lbl)), lambda: (log.append(("link",)) or (True, "200")),
                      I.build_cases(TAP), "eth1")
    t("R1 order: link before, then per case read A / ping / read B, link after",
      lambda: log[0] == ("link",) and log[-1] == ("link",) and [x[1] for x in log[1:-1]] ==
      [f"{c} {w}" for c in I.CASE_IDS for w in ("before", "after")] and len(g.calls) == 5)
    t("R2 commands recorded exactly as built", lambda: [c["command"] for c in rec["cases"]] ==
      [I.command(c, "eth1") for c in I.build_cases(TAP)])
    g = FakeGuest()
    rec = I.run_group(g, lambda lbl: None, lambda: (False, "HTTP 000"), I.build_cases(TAP), "eth1")
    t("R3 link before fails -> no ping is run, group skipped", lambda: g.calls == [] and "skipped" in rec)
    g = FakeGuest(fail_on="224.0.0.1")
    rec = I.run_group(g, lambda lbl: None, lambda: (True, "200"), I.build_cases(TAP), "eth1")
    t("R4 a console error is recorded for that case, the group continues",
      lambda: "TimeoutError" in rec["cases"][1]["exec"]["error"] and len(g.calls) == 5 and not rec["cases"][2]["exec"].get("error"))

    def bad_read(lbl):
        if lbl == "T12-B4 after":
            raise RuntimeError("nft failed")
    rec = I.run_group(FakeGuest(), bad_read, lambda: (True, "200"), I.build_cases(TAP), "eth1")
    t("R5 a failed counter read is recorded as read_error", lambda: "nft failed" in rec["cases"][2]["read_error"])
    rec = I.run_group(FakeGuest(rc=127), lambda lbl: None, lambda: (True, "200"), I.build_cases(TAP), "eth1")
    t("R6 rc 127 -> 'tool missing' execution error", lambda: all(c["exec"]["error"] == "tool missing in the guest" for c in rec["cases"]))
    rec = I.run_group(FakeGuest(), lambda lbl: None, lambda: (_ for _ in ()).throw(OSError("down")), I.build_cases(TAP), "eth1")
    t("R7 an exception in the service link check counts as failed", lambda: "skipped" in rec)
    # end to end: run_group (fakes) -> counter file -> evaluate_group
    values = dict(V.BASE)
    clock = {"t": 100.0}
    lines = []

    def reader(lbl):
        cid, when = lbl.rsplit(" ", 1)
        if when == "after":
            values[CASES[cid]["expected"]] += 3
        lines.append(V.rec(lbl, clock["t"], clock["t"] + 0.01, dict(values)))
        clock["t"] += 10.0
    rec = I.run_group(FakeGuest(), reader, lambda: (True, "200"), I.build_cases(TAP), "eth1")
    frames = []
    for i, cid in enumerate(I.CASE_IDS):
        frames += [(100.0 + 20 * i + 1.0 + 0.5 * k, f) for k, f in enumerate(probe_frames(cid))]
    pc = V.pcapng(os.path.join(tmp, "r-e2e.pcapng"), frames)
    cf = V.write_counters(os.path.join(tmp, "r-e2e.jsonl"), lines)
    res = I.evaluate_group(pc, cf, TAP, rec)
    t("R8 end to end (fake guest -> counters file -> evaluate_group) -> ĐẠT (kiểm quy tắc) x5",
      lambda: [c["category"] for c in res["cases"]] == ["DAT_KIEM_QUY_TAC"] * 5)


# ------------------------------------------------------------------ C. command line
def sec_C(tmp):
    def cli(name, specs, **kw):
        pc, cf, rec = scenario(tmp, name, specs, **kw)
        rp, out = os.path.join(tmp, name + "-rec.json"), os.path.join(tmp, name + "-out.json")
        json.dump(rec, open(rp, "w"))
        with contextlib.redirect_stdout(io.StringIO()):
            rc = I.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", rp, "--out", out])
        return rc, json.load(open(out))
    rc, j = cli("c-pass", [("T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 3}, OK_EXEC)])
    t("C1 CLI: pass -> exit 0", lambda: rc == 0 and j["cases"][0]["category"] == "DAT_KIEM_QUY_TAC")
    rc, j = cli("c-fail", [("T12-B1", spaced(probe_frames("T12-B1")), {"drop_bcast_mcast": 1}, OK_EXEC)])
    t("C2 CLI: fail -> exit 1", lambda: rc == 1)
    rc, j = cli("c-none", [("T12-B1", [], {}, OK_EXEC)])
    t("C3 CLI: no probe frame -> exit 4", lambda: rc == 4 and j["cases"][0]["category"] == "KHONG_TAO_DUOC_GOI")
    rp = os.path.join(tmp, "c-badrec.json")
    open(rp, "w").write("[1, 2]")
    out = os.path.join(tmp, "c-badrec-out.json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = I.main(["--pcap", "x", "--counters", "y", "--tap-mac", TAP, "--record", rp, "--out", out])
    t("C4 CLI: invalid group record -> exit 2, JSON written with the error", lambda: rc == 2 and "error" in json.load(open(out)))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = I.main(["--pcap", "x"])
    t("C5 CLI: missing arguments -> exit 2", lambda: rc == 2)


def main(argv):
    jpath = argv[argv.index("--json") + 1] if "--json" in argv else None
    with tempfile.TemporaryDirectory(prefix="selftest-icmp.") as tmp:
        for name, fn in (("D", sec_D), ("P", lambda: sec_P(tmp)), ("F", lambda: sec_F(tmp)), ("U", lambda: sec_U(tmp)),
                         ("K", lambda: sec_K(tmp)), ("K2", lambda: sec_K2(tmp)),
                         ("N", lambda: sec_N(tmp)), ("B", lambda: sec_B(tmp)), ("E", lambda: sec_E(tmp)), ("M", lambda: sec_M(tmp)),
                         ("L", lambda: sec_L(tmp)), ("R", lambda: sec_R(tmp)), ("C", lambda: sec_C(tmp))):
            print(f"== section {name}")
            try:
                fn()
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    if jpath:
        json.dump(RESULTS, open(jpath, "w"), indent=0, sort_keys=True)
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"SELFTEST-ICMP: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed" + ("" if not bad else f"; FAILED: {bad}"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
