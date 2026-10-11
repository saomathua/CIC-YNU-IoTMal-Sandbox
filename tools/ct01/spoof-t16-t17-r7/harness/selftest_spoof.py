#!/usr/bin/env python3
"""R2 — offline tests of spoof_cases.py / spoof_harness.py (T16-M1, T17-P1/P2/P4/P5) on SYNTHETIC captures/counter files and a SIMULATED guest
(selftest_arp.SimGuest extended with curl/ping that emit the frames a spoofing guest would). Sends nothing; the ruleset is SIMULATED with
l2frames.classify (not verified).

    python3 selftest_spoof.py [--json FILE]

D definitions/commands/contract/tiers/registry; P evaluate fixtures (clean, wrong class, HTTP success, worker reply, no frame, restore, errors);
S1 control counterexamples (schema/binding/evidence/window, callbacks returning None/False/{}); S2 probe-tuple counterexamples; S3 P5 layout (MTU);
X run_group on the simulated guest; E end to end; F precedence and exit codes; G reporting (tiers, gate policy); C CLI/record problems.
"""
import copy
import json
import os
import re
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import spoof_cases as A          # noqa: E402
import spoof_harness as SH       # noqa: E402
import selftest_arp as SA        # noqa: E402
import guest_state as GS         # noqa: E402
import l2eval                    # noqa: E402
import l2frames as L             # noqa: E402
import signatures as S           # noqa: E402
import selftest_l2 as B          # noqa: E402
import selftest_l2eval as V      # noqa: E402

RESULTS = {}
TAP, GUEST = B.TAP, B.GUEST
IF = "eth1"
FAKE = A.FAKE_MAC
CTX = {"arch": "ARM", "tap_mac": TAP}
CASES = {c["id"]: c for c in A.build_cases()}
URL = A.SVC_URL
TASK = A.task_name(CTX)
FIX = "ab" * 32            # fixture sha256 of the synthetic records
LINK_BEFORE_END = 91.0


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
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""), flush=True)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------ frames a spoofing guest emits
def syn(src_mac, src_ip, dst_ip, sport, dport):
    return B.eth(TAP, src_mac, 0x0800, B.ipv4(src_ip, dst_ip, 6, B.tcp(sport, dport)))


def echo(src_ip, dst_ip, size):
    return B.eth(TAP, GUEST, 0x0800, B.ipv4(src_ip, dst_ip, 1, B.icmp(size)))


def arp_req_fake(tpa=S.WORKER_GUEST_IP):
    return B.eth("ff:ff:ff:ff:ff:ff", FAKE, 0x0806, B.arp(1, FAKE, S.GUEST_IP, "00:00:00:00:00:00", tpa))


def probe_frames(cid, n=3):
    c = CASES[cid]
    k = c["kind"]
    if k == "t16":
        return [syn(FAKE, S.GUEST_IP, S.WORKER_GUEST_IP, c["port"], 8011)] * n
    if k == "t17_svc":
        return [syn(GUEST, c["src"], S.WORKER_GUEST_IP, c["port"], 8011)] * n
    if k == "t17_out":
        return [syn(GUEST, c["src"], c["dst"], c["port"], c["dport"])] * n
    return [echo(c["src"], c["dst"], c["size"])] * n


def spaced(frames, start=1.0, step=0.5):
    return [(start + step * k, f) for k, f in enumerate(frames)]


def reply_to(cid, t=5.0):
    """R6: a frame of the worker answering the identity of case `cid` on its own flow (SYN-ACK to the spoofed source / port, echo reply, ARP to the fake MAC)."""
    c = CASES[cid]
    if c["kind"] == "t16":
        return (t, B.eth(FAKE, TAP, 0x0806, b"\x00" * 28))
    if c["kind"] == "t17_icmp":
        return (t, B.eth(GUEST, TAP, 0x0800, B.ipv4(c["dst"], c["src"], 1, b"\x00\x00\x00\x00\x00\x01\x00\x01" + b"\xab" * c["size"])))
    dst = S.WORKER_GUEST_IP if c["kind"] == "t17_svc" else c["dst"]
    dport = 8011 if c["kind"] == "t17_svc" else c["dport"]
    return (t, B.eth(GUEST, TAP, 0x0800, B.ipv4(dst, c["src"], 6, B.tcp(dport, c["port"]))))


# ------------------------------------------------------------------ control / link records as run_group writes them
def link_detail(**over):
    d = {"rc": 0, "http_code": "200", "sha256": FIX, "expected_sha256": FIX, "output_tail": "HTTP=200"}
    d.update(over)
    return d


def svc_state(cid, role, ts_start, ts_end, ok=True, detail=None, arch="ARM", **over):
    r = {"ok": ok, "detail": link_detail() if detail is None else detail, "ts_start": ts_start, "ts_end": ts_end,
         "binding": A.service_binding(cid, arch, role)}
    r.update(over)
    return r


def live_detail(cid, ts, **over):
    c = CASES[cid]
    if c["kind"] == "t17_out":
        d = {"kind": "tcp_connect", "dst": c["dst"], "dport": c["dport"], "peer": [c["dst"], c["dport"]],
             "detail": f"TCP connect to {c['dst']}:{c['dport']} completed in 0.010s", "ts": ts}
    else:
        d = {"kind": "icmp_echo", "dst": c["dst"], "dport": None, "reply_from": c["dst"], "detail": f"ICMP echo reply from {c['dst']}", "ts": ts}
    d.update(over)
    return d


def live_state(cid, ts_start, ts_end, ok=True, detail=None, arch="ARM", **over):
    r = {"ok": ok, "detail": live_detail(cid, (ts_start + ts_end) / 2) if detail is None else detail, "ts_start": ts_start, "ts_end": ts_end,
         "binding": A.live_binding(CASES[cid], arch)}
    r.update(over)
    return r


# R5: ARM guests carry the NAT baseline (`iptables -t nat -S POSTROUTING`) next to the link state
NAT0 = ["-P POSTROUTING ACCEPT", "-A POSTROUTING -j zone_wan_postrouting"]
BASELINE = {**copy.deepcopy(SA.BASELINE), "nat_postrouting": list(NAT0)}
RESTORED = {**copy.deepcopy(SA.RESTORED), "after": {**copy.deepcopy(SA.RESTORED["after"]), "nat_postrouting": list(NAT0)}}
NEIGH = SA.NEIGH


def crec_for(cid, i=0, **over):
    """A complete clean case record; window of case i: read A [t0, t0+.01], read B [t0+10, t0+10.01], t0 = 100 + 20 i."""
    c = CASES[cid]
    t0 = 100.0 + 20 * i
    steps = []
    for ph, cmds in A.commands(c, IF, CTX).items():
        for cmd in cmds:
            if ph == "trigger" and cmd.startswith("ping"):
                steps.append({"phase": ph, "cmd": cmd, "rc": 1, "out": "3 packets transmitted, 0 packets received, 100% packet loss"})
            elif ph == "trigger":
                steps.append({"phase": ph, "cmd": cmd, "rc": 28, "out": "HTTP=000\n"})
            else:
                steps.append({"phase": ph, "cmd": cmd, "rc": 0, "out": ""})
    ctl = svc_state(cid, "control", t0 - 3, t0 - 2) if c["control_kind"] == "service_link" else live_state(cid, t0 + 11, t0 + 12)
    r = {"id": cid, "iface": IF, "before": f"{cid} before", "after": f"{cid} after", "steps": steps, "exec_error": None, "read_error": None,
         "guest_state": {"before": copy.deepcopy(BASELINE), "restore": copy.deepcopy(RESTORED)}, "neigh_before": NEIGH, "neigh_after": NEIGH,
         "control": ctl, "service_link_after": svc_state(cid, "after", t0 + 13, t0 + 14), "not_run": None}
    r.update(over)
    return r


def scenario(tmp, name, specs, link_before=True, counters_override=None):
    """specs: [(cid, [(dt, frame)], crec overrides, {counter: extra})]."""
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
        cases.append(crec_for(cid, i, **(over or {})))
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames)
    cf = V.write_counters(os.path.join(tmp, name + ".jsonl"), counters_override if counters_override is not None else recs)
    sl = svc_state(None, "before_group", 90.0, LINK_BEFORE_END, ok=link_before)
    record = {"iface": IF, "arch": "ARM", "tap_mac": TAP, "fixture_sha256": FIX, "cases": cases, "service_link_before": sl, "stopped": None}
    return pc, cf, record


def one(tmp, name, cid, frames, over=None, extra=None, **kw):
    pc, cf, rec = scenario(tmp, name, [(cid, frames, over, extra)], **kw)
    sl = A.service_state_problems(rec["service_link_before"], A.service_binding(None, "ARM", "before_group"), FIX)[1]
    return A.evaluate_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), CASES[cid], rec["cases"][0], sl, iface=IF, ctx=CTX, fixture_sha=FIX,
                           bounds={"not_before": LINK_BEFORE_END, "not_after": None})


def eval_group(tmp, name, specs, **kw):
    pc, cf, rec = scenario(tmp, name, specs, **kw)
    return A.evaluate_group(pc, cf, TAP, rec), rec


# ------------------------------------------------------------------ simulated guest
class SpoofGuest(SA.SimGuest):
    """SimGuest + curl/ping with a spoofed identity. Kernel behaviour simulated (NOT verified): the guest sends 3 SYNs / 3 echoes with the identity it
    was told; nothing ever answers (the ruleset drops them). `answer` makes the tools succeed (a hole)."""

    def __init__(self, counters, frames, answer=False, nat_masq=False, nat_ignore_insert=False, **kw):
        super().__init__(counters, frames, **kw)
        self.answer = answer
        # R5: the ARM firewall zone wan masquerades a locally chosen source unless an exempting rule exists (assumption from the image config, SIMULATED)
        self.nat_masq, self.nat_ignore_insert = nat_masq, nat_ignore_insert
        self.nat = list(NAT0)

    def _wire_src(self, src_ip):
        if self.nat_masq and src_ip != S.GUEST_IP and f"-A POSTROUTING -s {src_ip}/32 -j ACCEPT" not in self.nat:
            return S.GUEST_IP
        return src_ip

    def run(self, cmd, timeout=60):
        if self.raise_on and self.raise_on in cmd:
            self.raise_on = None
            self.log.append(cmd)
            raise TimeoutError("Timeout exceeded (simulated console)")
        if cmd == GS.NAT_CMD:
            self.log.append(cmd)
            return 0, "@@S nat\n" + "\n".join(self.nat) + "\n@@RC 0"
        m = re.fullmatch(r"iptables -t nat -I POSTROUTING 1 -s (\S+)/32 -j ACCEPT", cmd)
        if m:
            self.log.append(cmd)
            if cmd in self.fail_cmds:
                return 1, "iptables: simulated failure"
            if not self.nat_ignore_insert:
                self.nat.insert(1, f"-A POSTROUTING -s {m.group(1)}/32 -j ACCEPT")      # rule number 1 = right after the policy line, like iptables -I
            return 0, ""
        m = re.fullmatch(r"iptables -t nat -D POSTROUTING (\d+)", cmd)
        if m:
            self.log.append(cmd)
            if cmd in self.fail_cmds:
                return 1, "iptables: simulated failure"
            n = int(m.group(1))
            if not 1 <= n < len(self.nat):
                return 1, "iptables: Index of deletion too big."
            del self.nat[n]
            return 0, ""
        m = re.match(r"curl -s -o /dev/null (?:--interface (\S+) )?--local-port (\d+) --connect-timeout \d+ -m \d+ -w 'HTTP=%\{http_code\}\\n' (\S+)$", cmd)
        if m:
            self.log.append(cmd)
            src_ip, port, url = self._wire_src(m.group(1) or S.GUEST_IP), int(m.group(2)), m.group(3)
            dst = re.match(r"http://([\d.]+):(\d+)/", url)
            time.sleep(0.03)
            if self.emit:
                for _ in range(3):
                    self._emit(syn(self.mac, src_ip, dst.group(1), port, int(dst.group(2))))
                if self.answer:        # R6: a real answer is a frame of the worker addressed to the identity the SYN carried
                    self._emit(B.eth(self.mac, TAP, 0x0800, B.ipv4(dst.group(1), src_ip, 6, B.tcp(int(dst.group(2)), port))))
            return (0, "HTTP=200\n") if self.answer else (28, "HTTP=000\n")
        m = re.fullmatch(r"ping -c 3 -W \d+ -s (\d+) -I (\S+) (\S+)", cmd)
        if m:
            self.log.append(cmd)
            time.sleep(0.03)
            if self.emit:
                wsrc = self._wire_src(m.group(2))
                for _ in range(3):
                    self._emit(echo(wsrc, m.group(3), int(m.group(1))))
                if self.answer:
                    self._emit(B.eth(self.mac, TAP, 0x0800, B.ipv4(m.group(3), wsrc, 1, b"\x00\x00\x00\x00\x00\x01\x00\x01" + b"\xab" * int(m.group(1)))))
            return (0, "3 packets received") if self.answer else (1, "3 packets transmitted, 0 packets received, 100% packet loss")
        return super().run(cmd, timeout)


def sim_control(case):
    t_ = time.time()
    if case["id"] == "T17-P4":
        return True, {"kind": "tcp_connect", "dst": "1.1.1.1", "dport": 443, "peer": ["1.1.1.1", 443], "detail": "TCP connect to 1.1.1.1:443 completed in 0.010s", "ts": t_}
    return True, {"kind": "icmp_echo", "dst": "192.168.60.1", "dport": None, "reply_from": "192.168.60.1", "detail": "ICMP echo reply from 192.168.60.1", "ts": t_}


def sim_link(*a):
    return True, link_detail()


def run_sim(tmp, name, guest_kw=None, link=sim_link, neigh=lambda: NEIGH, control=sim_control, cases=None):
    counters, frames = dict(V.BASE), []
    g = SpoofGuest(counters, frames, **(guest_kw or {}))
    g.iface = IF
    cf = os.path.join(tmp, name + ".jsonl")
    open(cf, "w").close()
    rec = A.run_group(g, SA.fake_counters_reader(counters, cf), link, neigh, control, cases or A.build_cases(), IF, CTX)
    rec["fixture_sha256"] = FIX
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames)
    json.loads(json.dumps(rec))
    return g, rec, pc, cf


# ------------------------------------------------------------------ D
def sec_D():
    t("D1 five cases with the reviewed ids, expected classes, ports and size from signatures.py",
      lambda: [c["id"] for c in A.build_cases()] == list(A.CASE_IDS) and {c["id"]: c["expected"] for c in A.build_cases()} ==
      {"T16-M1": "l2_bad_mac", "T17-P1": "drop_spoof", "T17-P2": "drop_spoof", "T17-P4": "drop_spoof", "T17-P5": "drop_spoof"}
      and CASES["T16-M1"]["port"] == 31016 and CASES["T17-P1"]["port"] == 31171 and CASES["T17-P2"]["port"] == 31172
      and CASES["T17-P4"]["port"] == 31174 and CASES["T17-P5"]["size"] == S.ICMP4_SIZES["T17-P5"] == 1405)
    t("D1b tiers: T16-M1 and T17-P1 mandatory, T17-P2/P4/P5 coverage (matrix), every case has exactly one tier",
      lambda: A.MANDATORY_IDS == ("T16-M1", "T17-P1") and A.COVERAGE_IDS == ("T17-P2", "T17-P4", "T17-P5")
      and {c["id"]: c["tier"] for c in A.build_cases()} == {"T16-M1": "mandatory", "T17-P1": "mandatory", "T17-P2": "coverage", "T17-P4": "coverage", "T17-P5": "coverage"})
    t("D2 T16 commands: link down, address FAKE, link up, curl --local-port 31016 (no --interface), sleep",
      lambda: A.commands(CASES["T16-M1"], IF, CTX) == {
          "setup": [f"ip link set dev {IF} down", f"ip link set dev {IF} address {FAKE}", f"ip link set dev {IF} up"],
          "trigger": [f"curl -s -o /dev/null --local-port 31016 --connect-timeout 4 -m 6 -w 'HTTP=%{{http_code}}\\n' {URL}/get-task/{TASK}/file"],
          "settle": ["sleep 3"]})
    t("D3 T17-P1: /32 secondary address, static gateway neighbour with the TAP MAC on the interface, curl --interface 10.200.0.5 --local-port 31171",
      lambda: A.commands(CASES["T17-P1"], IF, CTX) == {
          "setup": [f"ip addr add 10.200.0.5/32 dev {IF}", f"arp -i {IF} -s 10.200.0.1 {TAP}", "iptables -t nat -I POSTROUTING 1 -s 10.200.0.5/32 -j ACCEPT"],
          "trigger": [f"curl -s -o /dev/null --interface 10.200.0.5 --local-port 31171 --connect-timeout 4 -m 6 -w 'HTTP=%{{http_code}}\\n' {URL}/get-task/{TASK}/file"],
          "settle": ["sleep 3"]})
    t("D4 T17-P4 goes to 1.1.1.1:443 and P5 is ping -c 3 -s 1405 -I 192.168.60.10 192.168.60.1 (IPv4 total length 1433 < MTU)",
      lambda: A.commands(CASES["T17-P4"], IF, CTX)["trigger"][0].endswith("http://1.1.1.1:443/ct01-t17-T17-P4")
      and A.commands(CASES["T17-P5"], IF, CTX)["trigger"] == ["ping -c 3 -W 2 -s 1405 -I 192.168.60.10 192.168.60.1"])
    t("D5 only ip/arp/curl/ping/sleep (+ iptables for the ARM NAT bypass); no raw tool, no arping, no sudo, no nc",
      lambda: all(re.match(r"(ip |arp |curl |ping |sleep |iptables -t nat -I POSTROUTING 1 -s [0-9.]+/32 -j ACCEPT$)", cmd) for c in A.build_cases() for ph in A.commands(c, IF, CTX).values() for cmd in ph))
    t("D6 the context is validated: arch, tap_mac (not the guest MAC, not the spoof MAC); a bad one builds no command",
      lambda: all(raises(ValueError, lambda x=x: A.commands(CASES["T16-M1"], IF, x)) for x in (None, {}, {"arch": "X86", "tap_mac": TAP}, {"arch": "ARM", "tap_mac": "zz"},
                                                                                              {"arch": "ARM", "tap_mac": GUEST}, {"arch": "ARM", "tap_mac": FAKE})))
    t("D7 rc contract: curl any rc but 127, ping rc 0/1, other steps rc 0; bools and None rejected",
      lambda: A.rc_ok("trigger", "curl x", 28) and A.rc_ok("trigger", "curl x", 7) and not A.rc_ok("trigger", "curl x", 127) and A.rc_ok("trigger", "ping x", 1)
      and not A.rc_ok("trigger", "ping x", 2) and not A.rc_ok("setup", "ip addr add", 2) and not A.rc_ok("setup", "ip", True) and not A.rc_ok("setup", "ip", None))
    t("D8 the interface name is validated before any command is built", lambda: raises(ValueError, lambda: A.commands(CASES["T16-M1"], "eth1; rm", CTX)))

    def d9():
        ok = True
        with tempfile.TemporaryDirectory() as d:
            for cid in A.CASE_IDS:
                p = V.pcapng(os.path.join(d, cid + ".pcapng"), [(1.0, probe_frames(cid, 1)[0])])
                ok = ok and A.is_probe_frame(L.classified_frames(p, TAP)[0], CASES[cid])
                for other in A.CASE_IDS:
                    if other != cid:
                        p2 = V.pcapng(os.path.join(d, cid + other + ".pcapng"), [(1.0, probe_frames(other, 1)[0])])
                        ok = ok and not A.is_probe_frame(L.classified_frames(p2, TAP)[0], CASES[cid])
        return ok
    t("D9 every case's frame is its own probe frame and no other case's", d9)
    t("D10 registry: T17-P5 size 1405 is unique in ICMP4_SIZES and its IPv4 total length 1433 <= MTU 1500; signatures --check holds",
      lambda: sorted(S.ICMP4_SIZES.values()).count(1405) == 1 and 1405 + 28 <= A.MTU == 1500)


def sec_P(tmp):
    for cid in A.CASE_IDS:
        r = one(tmp, f"p-{cid}", cid, spaced(probe_frames(cid)))
        t(f"P1.{cid} clean: DAT with its validated control, {r['probe_frames']} probe frames, class {CASES[cid]['expected']}",
          lambda r=r, cid=cid: r["category"] == "DAT" and r["probe_frames"] == 3 and r["probe_frame_classes"] == [CASES[cid]["expected"]])
    t("P2 the counters show allow_svc +3 for the spoofed frames (the ruleset let them through): FAIL",
      lambda: one(tmp, "p2", "T17-P1", spaced(probe_frames("T17-P1")), extra={"allow_svc": 3})["category"] == "FAIL")
    t("P3 T17-P1 whose frames carry the real source IP (not the spoofed one): not a probe -> KHONG_TAO_DUOC_GOI, never DAT",
      lambda: one(tmp, "p3", "T17-P1", spaced([syn(GUEST, S.GUEST_IP, S.WORKER_GUEST_IP, 31171, 8011)] * 3))["category"] == "KHONG_TAO_DUOC_GOI")
    hit = lambda cid: [dict(s, rc=0, out="HTTP=200\n") if s["phase"] == "trigger" else s for s in crec_for(cid)["steps"]]    # noqa: E731
    r4_ = one(tmp, "p4", "T17-P1", spaced(probe_frames("T17-P1")), over={"steps": hit("T17-P1")})
    t("P4 (R6) HTTP 200 from the tool + fake SYNs only, no reply to the fake identity: NOT a FAIL (no flow binding), LOI_PHEP_DO, never DAT; fake frames reported",
      lambda: r4_["category"] == "LOI_PHEP_DO" and not r4_["failure_evidence"] and r4_["probe_frames"] == 3 and len(r4_["fake_frames"]) == 3
      and r4_["real_identity_frames"] == [] and any("not explained by the wire" in m for m in r4_["measurement_errors"]))
    r4b_ = one(tmp, "p4b", "T17-P1", spaced(probe_frames("T17-P1")) + [reply_to("T17-P1")], over={"steps": hit("T17-P1")})
    t("P4b (R6) the same plus a SYN-ACK to the fake identity on its own flow: FAIL, flow-bound",
      lambda: r4b_["category"] == "FAIL" and any("matches the case flow" in x for x in r4b_["failure_evidence"]) and r4b_["reply_frames"][0]["flow_bound"] is True)
    r5_ = one(tmp, "p5", "T16-M1", spaced(probe_frames("T16-M1")), over={"steps": hit("T16-M1")})
    t("P5 (R6) T16: HTTP 200 with fake-MAC SYNs and no worker frame to the fake MAC: LOI_PHEP_DO, no FAIL",
      lambda: r5_["category"] == "LOI_PHEP_DO" and not r5_["failure_evidence"])
    t("P5b T16: HTTP 200 plus a worker frame to the fake MAC: FAIL",
      lambda: one(tmp, "p5b", "T16-M1", spaced(probe_frames("T16-M1")) + [reply_to("T16-M1")], over={"steps": hit("T16-M1")})["category"] == "FAIL")
    t("P6 a worker frame addressed to the fake MAC is a FAIL",
      lambda: one(tmp, "p6", "T16-M1", spaced(probe_frames("T16-M1")) + [(5.0, B.eth(FAKE, TAP, 0x0806, b"\x00" * 28))])["category"] == "FAIL")
    t("P7 a SYN-ACK to the spoofed source 10.200.0.5 is a FAIL",
      lambda: one(tmp, "p7", "T17-P1", spaced(probe_frames("T17-P1")) + [(5.0, B.eth(GUEST, TAP, 0x0800, B.ipv4(S.WORKER_GUEST_IP, "10.200.0.5", 6, B.tcp(8011, 31171))))])["category"] == "FAIL")
    ps_ = {"steps": [dict(s, rc=0) if s["phase"] == "trigger" else s for s in crec_for("T17-P5")["steps"]]}
    r8_ = one(tmp, "p8", "T17-P5", spaced(probe_frames("T17-P5")), over=ps_)
    t("P8 (R6) ping rc 0 with fake-source echoes and no echo reply to the fake identity: LOI_PHEP_DO, no FAIL",
      lambda: r8_["category"] == "LOI_PHEP_DO" and not r8_["failure_evidence"])
    t("P8b ping rc 0 plus an echo reply to the spoofed source: FAIL (flow-bound)",
      lambda: one(tmp, "p8b", "T17-P5", spaced(probe_frames("T17-P5")) + [reply_to("T17-P5")], over=ps_)["category"] == "FAIL")
    t("P9 no probe frame at all: KHONG_TAO_DUOC_GOI, never DAT", lambda: one(tmp, "p9", "T17-P2", [])["category"] == "KHONG_TAO_DUOC_GOI")
    t("P10 control well-formed but not alive (ok=false): CHUA_KIEM_CHUNG (never DAT, not a measurement error)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and not r["measurement_errors"])(
          one(tmp, "p10", "T17-P1", spaced(probe_frames("T17-P1")), over={"control": svc_state("T17-P1", "control", 97.0, 98.0, ok=False, detail="no 200")})))
    t("P11 service link after the case failed (well-formed, ok=false): CHUA_KIEM_CHUNG",
      lambda: one(tmp, "p11", "T17-P1", spaced(probe_frames("T17-P1")), over={"service_link_after": svc_state("T17-P1", "after", 113.0, 114.0, ok=False, detail="x")})["category"] == "CHUA_KIEM_CHUNG")
    t("P12 restore not confirmed: CHUA_KIEM_CHUNG or LOI_THUC_THI, never DAT",
      lambda: one(tmp, "p12", "T16-M1", spaced(probe_frames("T16-M1")),
                  over={"guest_state": {"before": copy.deepcopy(BASELINE), "restore": {"restored": False, "commands": [], "diffs": ["mac"], "dynamic_changes": [], "error": None}}})["category"]
      in ("CHUA_KIEM_CHUNG", "LOI_THUC_THI"))
    t("P13 tool missing (rc 127): LOI_THUC_THI, not a verdict about the rules",
      lambda: one(tmp, "p13", "T17-P1", spaced(probe_frames("T17-P1")),
                  over={"exec_error": "trigger 'curl': tool missing in the guest",
                        "steps": [dict(s, rc=127, out="curl: not found") if s["phase"] == "trigger" else s for s in crec_for("T17-P1")["steps"]]})["category"] == "LOI_THUC_THI")
    t("P14 counter delta different from the frames (extra l2_bad_mac): FAIL (reconciliation)",
      lambda: one(tmp, "p14", "T16-M1", spaced(probe_frames("T16-M1")), extra={"l2_bad_mac": 2})["category"] == "FAIL")
    t("P15 result states what is NOT measured (server log, stop file) and the control source",
      lambda: (lambda r: "server.py request log" in r["not_measured"] and r["control_source"])(one(tmp, "p15", "T17-P1", spaced(probe_frames("T17-P1")))))
    t("P16 a restore that raised and a corrupt baseline are not DAT",
      lambda: one(tmp, "p16", "T17-P1", spaced(probe_frames("T17-P1")), over={"guest_state": {"before": None, "restore": None}})["category"] != "DAT")


def sec_S1(tmp):
    """Reviewer S1: controls that used to pass with a missing/null detail, a bad timestamp or the wrong peer."""
    def ev(cid, ctl, i=0, key="control"):
        return one(tmp, f"s1-{cid}-{abs(hash(json.dumps(ctl, default=str))) % 10**6}", cid, spaced(probe_frames(cid)), over={key: ctl})

    c = {"T17-P1": lambda **o: svc_state("T17-P1", "control", 97.0, 98.0, **o), "T17-P4": lambda **o: live_state("T17-P4", 111.0, 112.0, **o),
         "T17-P5": lambda **o: live_state("T17-P5", 111.0, 112.0, **o)}
    bad = {
        "no detail key": lambda cid: {k: v for k, v in c[cid]().items() if k != "detail"},
        "detail null": lambda cid: c[cid](detail=None) if False else dict(c[cid](), detail=None),
        "detail {}": lambda cid: dict(c[cid](), detail={}),
        "ok not bool (1)": lambda cid: dict(c[cid](), ok=1),
        "extra key": lambda cid: dict(c[cid](), extra=1),
        "ts_start missing": lambda cid: {k: v for k, v in c[cid]().items() if k != "ts_start"},
        "ts = 1 (before everything)": lambda cid: dict(c[cid](), ts_start=1.0, ts_end=1.0),
        "ts = 1e12 (after everything)": lambda cid: dict(c[cid](), ts_start=1e12, ts_end=1e12),
        "ts NaN": lambda cid: dict(c[cid](), ts_start=float("nan"), ts_end=float("nan")),
        "binding of another case": lambda cid: dict(c[cid](), binding=dict(c[cid]()["binding"], case="T16-M1")),
        "binding of another arch": lambda cid: dict(c[cid](), binding=dict(c[cid]()["binding"], arch="MIPS")),
        "binding without the destination": lambda cid: dict(c[cid](), binding={k: v for k, v in c[cid]()["binding"].items() if k != "dst"}),
    }
    n = 0
    for cid in ("T17-P1", "T17-P4", "T17-P5"):
        for name, mk in bad.items():
            r = ev(cid, mk(cid))
            n += 1
            t(f"S1.{cid}.{name}: not DAT and the malformed/mis-bound control is kept as a measurement error",
              lambda r=r: r["category"] == "LOI_PHEP_DO" and any("control" in m for m in r["measurement_errors"]))
    # evidence-level counterexamples (well-formed shape, wrong content)
    t("S1.E1 service control ok=true with http_code 500", lambda: ev("T17-P1", svc_state("T17-P1", "control", 97.0, 98.0, detail=link_detail(http_code="500")))["category"] == "LOI_PHEP_DO")
    t("S1.E2 service control ok=true with a hash that is not the fixture", lambda: ev("T17-P1", svc_state("T17-P1", "control", 97.0, 98.0, detail=link_detail(sha256="cd" * 32)))["category"] == "LOI_PHEP_DO")
    t("S1.E3 service control ok=true with rc != 0", lambda: ev("T17-P1", svc_state("T17-P1", "control", 97.0, 98.0, detail=link_detail(rc=1)))["category"] == "LOI_PHEP_DO")
    t("S1.E4 service control taken AFTER the case's before-read (not immediately before the change)",
      lambda: ev("T17-P1", svc_state("T17-P1", "control", 100.5, 101.0))["category"] == "LOI_PHEP_DO")
    t("S1.E5 service control taken before the service link before the group ended (not bound to this window)",
      lambda: ev("T17-P1", svc_state("T17-P1", "control", 80.0, 85.0))["category"] == "LOI_PHEP_DO")
    t("S1.E6 P4 live control: wrong peer (connected to another address)",
      lambda: ev("T17-P4", live_state("T17-P4", 111.0, 112.0, detail=live_detail("T17-P4", 111.5, peer=["8.8.8.8", 443])))["category"] == "LOI_PHEP_DO")
    t("S1.E7 P4 live control: wrong destination/port in the detail",
      lambda: ev("T17-P4", live_state("T17-P4", 111.0, 112.0, detail=live_detail("T17-P4", 111.5, dst="8.8.8.8")))["category"] == "LOI_PHEP_DO"
      and ev("T17-P4", live_state("T17-P4", 111.0, 112.0, detail=live_detail("T17-P4", 111.5, dport=80)))["category"] == "LOI_PHEP_DO")
    t("S1.E8 P5 live control: echo reply from another IP",
      lambda: ev("T17-P5", live_state("T17-P5", 111.0, 112.0, detail=live_detail("T17-P5", 111.5, reply_from="203.0.113.7")))["category"] == "LOI_PHEP_DO")
    t("S1.E9 live control started BEFORE the case's after-read", lambda: ev("T17-P4", live_state("T17-P4", 105.0, 106.0))["category"] == "LOI_PHEP_DO")
    t("S1.E10 live control detail ts outside the call span", lambda: ev("T17-P4", live_state("T17-P4", 111.0, 112.0, detail=live_detail("T17-P4", 50.0)))["category"] == "LOI_PHEP_DO")
    t("S1.E11 live control with ok=false and a well-formed record: CHUA_KIEM_CHUNG (not a measurement error)",
      lambda: ev("T17-P4", live_state("T17-P4", 111.0, 112.0, ok=False, detail="timed out"))["category"] == "CHUA_KIEM_CHUNG")
    t("S1.E12 a FAIL (HTTP 200) wins over a malformed control, both kept",
      lambda: (lambda r: r["category"] == "FAIL" and r["measurement_errors"])(
          one(tmp, "s1e12", "T17-P1", spaced(probe_frames("T17-P1")) + [reply_to("T17-P1")], over={"control": {"ok": True}, "steps": [dict(s, rc=0, out="HTTP=200\n") if s["phase"] == "trigger" else s for s in crec_for("T17-P1")["steps"]]})))
    # the harness: callbacks returning nothing useful are not alive controls
    mc = SH.make_control(lambda ip, port: None, lambda ip: False)
    t("S1.H1 make_control: a callback returning None / False / {} / a string is NOT alive (value kept in the detail)",
      lambda: all(SH.make_control(lambda ip, port, v=v: v, lambda ip, v=v: v)(CASES[cid])[0] is False for v in (None, False, {}, "", "ok") for cid in ("T17-P4", "T17-P5")))
    t("S1.H2 make_control: a structured detail is passed on (the evaluator validates it); an exception is a failed control",
      lambda: SH.make_control(lambda ip, port: {"kind": "tcp_connect"}, lambda ip: {"x": 1})(CASES["T17-P4"])[0] is True
      and SH.make_control(lambda ip, port: 1 / 0, lambda ip: 1 / 0)(CASES["T17-P5"])[0] is False)
    t("S1.H3 a structured-but-wrong detail from make_control still does not give DAT (evaluator re-validation)",
      lambda: one(tmp, "s1h3", "T17-P4", spaced(probe_frames("T17-P4")), over={"control": live_state("T17-P4", 111.0, 112.0, detail={"kind": "tcp_connect"})})["category"] == "LOI_PHEP_DO")
    t("S1.H4 icmp_echo_control accepts only the exact reply text of b1_cases.icmp_control and records the reply source",
      lambda: SH.icmp_echo_control("192.168.60.1", lambda ip: f"ICMP echo reply from {ip}")["reply_from"] == "192.168.60.1"
      and raises(RuntimeError, lambda: SH.icmp_echo_control("192.168.60.1", lambda ip: "something else")))

    class FakeSock:
        AF_INET, SOCK_STREAM = 2, 1

        class _S:
            def settimeout(self, v): pass
            def connect(self, a): self.a = a
            def getpeername(self): return ("1.1.1.1", 443)
            def close(self): pass
        def socket(self, *a): return FakeSock._S()
    t("S1.H5 tcp_connect_control returns the structured detail with the peer taken from the socket, and rejects a bad destination",
      lambda: SH.tcp_connect_control("1.1.1.1", 443, sock=FakeSock())["peer"] == ["1.1.1.1", 443] and raises(ValueError, lambda: SH.tcp_connect_control("1.1.1.1", True, sock=FakeSock())))
    def s1g():
        pc, cf, rec = scenario(tmp, "s1g", [("T17-P1", spaced(probe_frames("T17-P1")), None, None)])
        rec["service_link_before"]["detail"]["sha256"] = "cd" * 32          # ok=true but the evidence is not the fixture
        res = A.evaluate_group(pc, cf, TAP, rec)
        return any("service_link_before" in p for p in res["record_problems"]) and all(x["category"] != "DAT" for x in res["cases"]) and A.group_exit(res) != 0
    t("S1.G the service link before the group is validated too: ok=true with another hash is a record problem and the case is not DAT", s1g)


def sec_S2(tmp):
    def cat(cid, frames, **kw):
        return one(tmp, f"s2-{cid}-{abs(hash(str(frames))) % 10**6}", cid, spaced(frames), **kw)
    c1, c4, c5, c16 = CASES["T17-P1"], CASES["T17-P4"], CASES["T17-P5"], CASES["T16-M1"]
    cases = {
        "P1 wrong destination IP (203.0.113.250:8011)": ("T17-P1", [syn(GUEST, c1["src"], "203.0.113.250", c1["port"], 8011)] * 3),
        "P1 wrong destination port (10.200.0.1:9)": ("T17-P1", [syn(GUEST, c1["src"], S.WORKER_GUEST_IP, c1["port"], 9)] * 3),
        "P4 wrong destination IP (203.0.113.250:443)": ("T17-P4", [syn(GUEST, c4["src"], "203.0.113.250", c4["port"], 443)] * 3),
        "P4 wrong destination port (1.1.1.1:80)": ("T17-P4", [syn(GUEST, c4["src"], "1.1.1.1", c4["port"], 80)] * 3),
        "P5 echo of the right size to 203.0.113.250": ("T17-P5", [echo(c5["src"], "203.0.113.250", c5["size"])] * 3),
        "P1 TCP ACK (not a SYN)": ("T17-P1", [B.eth(TAP, GUEST, 0x0800, B.ipv4(c1["src"], S.WORKER_GUEST_IP, 6,
                                                                              __import__("struct").pack("!HHIIBBHHH", c1["port"], 8011, 1, 1, 0x50, 0x10, 64240, 0, 0)))] * 3),
        "P5 ICMP echo REPLY (type 0), right size/dst": ("T17-P5", [B.eth(TAP, GUEST, 0x0800, B.ipv4(c5["src"], c5["dst"], 1,
                                                                                                    b"\x00\x00\x00\x00\x00\x01\x00\x01" + b"\xab" * c5["size"]))] * 3),
        "T16 only background frames with the fake MAC (IPv6 RS)": ("T16-M1", [B.eth("33:33:00:00:00:02", FAKE, 0x86DD, B.ipv6(S.GUEST_LL6, "ff02::2", 58, B.icmp6(8, typ=133)))] * 3),
        "T16 ARP request for another target": ("T16-M1", [arp_req_fake("10.200.0.99")] * 3),
        "T16 SYN with the fake MAC to another destination": ("T16-M1", [syn(FAKE, S.GUEST_IP, "203.0.113.250", c16["port"], 8011)] * 3),
    }
    for name, (cid, frames) in cases.items():
        r = cat(cid, frames)
        t(f"S2.{name}: probe_frames 0 -> KHONG_TAO_DUOC_GOI (counters/reconciliation stay clean, never DAT)", lambda r=r: r["probe_frames"] == 0 and r["category"] == "KHONG_TAO_DUOC_GOI")
    t("S2.OK1 the right tuple (P1 SYN to 10.200.0.1:8011 from 10.200.0.5:31171) is still a probe and DAT", lambda: cat("T17-P1", probe_frames("T17-P1"))["category"] == "DAT")
    t("S2.OK2 T16 accepts the SYN to the service OR the ARP request for 10.200.0.1 from the fake MAC",
      lambda: cat("T16-M1", probe_frames("T16-M1"))["category"] == "DAT" and cat("T16-M1", [arp_req_fake()] * 3)["category"] == "DAT")
    t("S2.F a wrong-tuple frame never becomes the 'probe' while the right one is also present: only the right frames are counted as probes",
      lambda: cat("T17-P1", probe_frames("T17-P1", 2) + [syn(GUEST, c1["src"], "203.0.113.250", c1["port"], 8011)])["probe_frames"] == 2)


def sec_S3(tmp):
    c5 = CASES["T17-P5"]
    t("S3.1 build_cases refuses an ICMP size whose IPv4 total length exceeds the MTU (the old 1705 -> 1733)",
      lambda: (lambda old: (S.ICMP4_SIZES.__setitem__("T17-P5", 1705), raises(ValueError, A.build_cases), S.ICMP4_SIZES.__setitem__("T17-P5", old))[1])(S.ICMP4_SIZES["T17-P5"]))
    t("S3.2 P5 sends one unfragmented datagram per echo: total length size+28 = 1433 <= 1500", lambda: c5["size"] + 28 == 1433 <= A.MTU)
    import struct as _st
    l4 = B.icmp(1705)
    frag1 = B.eth(TAP, GUEST, 0x0800, B.ipv4(c5["src"], c5["dst"], 1, l4[:1480], frag=0x2000))
    frag2 = B.eth(TAP, GUEST, 0x0800, B.ipv4(c5["src"], c5["dst"], 1, l4[1480:], frag=185))
    t("S3.3 the old fragmented layout (1500 + 253) is not a probe of this case and never DAT",
      lambda: (lambda r: r["probe_frames"] == 0 and r["category"] != "DAT")(one(tmp, "s3-frag", "T17-P5", spaced([frag1, frag2] * 3))))
    t("S3.4 the registry value is what the harness sends and what the host signature scan counts (sizes list contains 1433)", lambda: 1433 in S.ip4_lens() and 1733 not in S.ip4_lens())


def sec_X(tmp):
    g, rec, pc, cf = run_sim(tmp, "x1")
    t("X1 run_group: five cases in order, each with its validated control record, restore evidence and service link after",
      lambda: [c["id"] for c in rec["cases"]] == list(A.CASE_IDS) and all((c["guest_state"]["restore"] or {}).get("restored") is True for c in rec["cases"])
      and all(set(c["control"]) == A.CONTROL_KEYS and c["control"]["ok"] is True for c in rec["cases"])
      and all(c["control"]["binding"]["case"] == c["id"] and c["control"]["binding"]["arch"] == "ARM" for c in rec["cases"])
      and all(set(c["service_link_after"]) == A.CONTROL_KEYS and c["service_link_after"]["binding"]["role"] == "after" for c in rec["cases"]))
    t("X2 after the group the guest is exactly as before: MAC, addresses, routes, static neighbours (link up)",
      lambda: g.mac == GUEST and g.addrs == {"10.200.0.2/30"} and g.admin is True and not [k for k in g.neigh if k[0] == "10.200.0.1" and g.neigh[k][0] != TAP])
    t("X3 the T16 case really changed the MAC (log shows address FAKE) and the capture holds spoof-MAC frames",
      lambda: any(f"address {FAKE}" in c for c in g.log) and any(f["direction"] == "guest_spoof_mac" for f in L.classified_frames(pc, TAP)))
    t("X4 the service-link control and the live control are taken in the window the evaluator expects (end-to-end DAT shows it)",
      lambda: [c["category"] for c in A.evaluate_group(pc, cf, TAP, rec)["cases"]] == ["DAT"] * 5)
    g2, rec2, pc2, cf2 = run_sim(tmp, "x2", guest_kw={"fail_cmds": [f"ip link set dev {IF} address {FAKE}"]})
    t("X5 a failing setup command is an execution error; the state is still restored",
      lambda: rec2["cases"][0]["exec_error"] and (rec2["cases"][0]["guest_state"]["restore"] or {}).get("restored") is True and g2.mac == GUEST)
    g3, rec3, pc3, cf3 = run_sim(tmp, "x3", guest_kw={"raise_on": "curl"})
    t("X6 a console exception in the trigger: exec_error recorded, restore still runs, no exception escapes",
      lambda: rec3["cases"][0]["exec_error"] and (rec3["cases"][0]["guest_state"]["restore"] or {}).get("restored") is True)
    g4, rec4, pc4, cf4 = run_sim(tmp, "x4", link=lambda *a: (False, "no 200"))
    t("X7 service link before the group failed: no case is run (skipped), nothing sent to the guest", lambda: rec4.get("skipped") and not rec4["cases"] and not g4.log)
    counters, frames = dict(V.BASE), []
    gg = SpoofGuest(counters, frames)
    r5 = A.run_group(gg, lambda l: None, sim_link, lambda: NEIGH, sim_control, A.build_cases(), IF, {"arch": "X", "tap_mac": TAP})
    t("X8 an invalid context stops before any guest command", lambda: r5.get("skipped") and not gg.log)
    g6, rec6, pc6, cf6 = run_sim(tmp, "x6", control=lambda c: (True, None))
    res6 = A.evaluate_group(pc6, cf6, TAP, rec6)
    cats = {c["id"]: c["category"] for c in res6["cases"]}
    t("X9 live callbacks returning ok=True with detail None are caught by the evaluator: P4/P5 not DAT, the four service-link cases still DAT",
      lambda: cats["T17-P4"] == "LOI_PHEP_DO" and cats["T17-P5"] == "LOI_PHEP_DO" and [cats[i] for i in ("T16-M1", "T17-P1", "T17-P2")] == ["DAT"] * 3)


def sec_E(tmp):
    g, rec, pc, cf = run_sim(tmp, "e1")
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E1 end to end on the simulated guest: every case DAT, exit 0, no record problem",
      lambda: [c["category"] for c in res["cases"]] == ["DAT"] * 5 and not res["record_problems"] and A.group_exit(res) == 0)
    g, rec, pc, cf = run_sim(tmp, "e2", guest_kw={"answer": True})
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E2 a guest whose tools get an answer (a hole): every case FAIL, exit 1", lambda: all(c["category"] == "FAIL" for c in res["cases"]) and A.group_exit(res) == 1)
    g, rec, pc, cf = run_sim(tmp, "e3", guest_kw={"emit": False})
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("E3 a guest that emits nothing: KHONG_TAO_DUOC_GOI everywhere, never exit 0", lambda: all(c["category"] != "DAT" for c in res["cases"]) and A.group_exit(res) != 0)


def sec_F(tmp):
    steps = [dict(s, rc=0, out="HTTP=200\n") if s["phase"] == "trigger" else s for s in crec_for("T17-P1")["steps"]]
    res, rec = eval_group(tmp, "f1", [("T17-P1", spaced(probe_frames("T17-P1")) + [reply_to("T17-P1")], {"read_error": "boom", "steps": steps}, None)])
    t("F1 HTTP success + a reply to the fake identity + a counter read error: FAIL kept with the measurement error",
      lambda: res["cases"][0]["category"] == "FAIL" and res["cases"][0]["measurement_errors"])
    t("F2 group exit codes: FAIL 1, measurement error 2, anything not DAT 4, all DAT 0",
      lambda: A.group_exit({"cases": [{"category": "FAIL"}], "record_problems": []}) == 1
      and A.group_exit({"cases": [{"category": "LOI_PHEP_DO"}], "record_problems": []}) == 2
      and A.group_exit({"cases": [{"category": "CHUA_KIEM_CHUNG"}], "record_problems": []}) == 4
      and A.group_exit({"cases": [{"category": "DAT"}], "record_problems": []}) == 0)
    res, rec = eval_group(tmp, "f3", [("T17-P1", spaced(probe_frames("T17-P1")) + [reply_to("T17-P1")], {"steps": steps, "control": {"ok": True, "detail": None}}, None)])
    t("F3 FAIL (HTTP 200) beats a malformed control in the same case (precedence FAIL > LOI_PHEP_DO)", lambda: res["cases"][0]["category"] == "FAIL")


def sec_G(tmp):
    g, rec, pc, cf = run_sim(tmp, "g1")
    rec.update(arch="ARM", tap_mac=TAP, fixture_sha256=FIX, planned_case_ids=list(A.CASE_IDS), service_link_role=SH.LINK_ROLE, neigh_command=list(SH.NEIGH_CMD))
    # the harness checks the link records with IH.link_valid: same detail layout
    ev = SH.evaluate(pc, cf, TAP, rec, "ARM", FIX, IF)
    t("G1 harness evaluation: tiers reported separately, gate policy stated, group complete and exit 0 on the clean simulated run",
      lambda: ev["group_complete"] is True and ev["group_exit"] == 0 and ev["tiers"]["mandatory"]["all_dat"] and ev["tiers"]["coverage"]["all_dat"]
      and "not a statement that T17-P2/P4/P5 are acceptance requirements" in ev["gate_policy"] and ev["tiers"]["postponed_not_built"])
    g, rec, pc, cf = run_sim(tmp, "g2", control=lambda c: (False, "timed out") if c["id"] == "T17-P4" else sim_control(c))
    rec.update(arch="ARM", tap_mac=TAP, fixture_sha256=FIX, planned_case_ids=list(A.CASE_IDS), service_link_role=SH.LINK_ROLE, neigh_command=list(SH.NEIGH_CMD))
    ev = SH.evaluate(pc, cf, TAP, rec, "ARM", FIX, IF)
    t("G2 a coverage case without a live control: mandatory still all DAT, coverage not all DAT, the run exit stays 4 (UNVERIFIED), no FAIL",
      lambda: ev["tiers"]["mandatory"]["all_dat"] and not ev["tiers"]["coverage"]["all_dat"] and not ev["tiers"]["coverage"]["any_fail"] and ev["group_exit"] == 4)
    g, rec, pc, cf = run_sim(tmp, "g3", guest_kw={"answer": True})
    rec.update(arch="ARM", tap_mac=TAP, fixture_sha256=FIX, planned_case_ids=list(A.CASE_IDS), service_link_role=SH.LINK_ROLE, neigh_command=list(SH.NEIGH_CMD))
    ev = SH.evaluate(pc, cf, TAP, rec, "ARM", FIX, IF)
    t("G3 a FAIL in a coverage case is a FAIL of the run (any_fail true, exit 1)", lambda: ev["tiers"]["coverage"]["any_fail"] and ev["group_exit"] == 1)


def sec_C(tmp):
    pc, cf, rec = scenario(tmp, "c1", [(cid, spaced(probe_frames(cid)), None, None) for cid in A.CASE_IDS])
    bad = dict(rec)
    bad.pop("tap_mac")
    t("C1 a record without tap_mac has a record problem and is never exit 0", lambda: A.record_problems(bad) and A.group_exit(A.evaluate_group(pc, cf, TAP, bad)) != 0)
    t("C2 a complete clean record has no record problem", lambda: A.record_problems(rec) == [])
    miss = dict(rec, cases=rec["cases"][:-1])
    t("C3 a missing case is a record problem", lambda: any("T17-P5" in p for p in A.record_problems(miss)))
    wrong = copy.deepcopy(rec)
    wrong["cases"][0]["steps"][3]["cmd"] = wrong["cases"][0]["steps"][3]["cmd"].replace("31016", "31999")
    t("C4 a recorded command that differs from the contract is a problem", lambda: any("contract" in p or "steps" in p for p in A.record_problems(wrong)))
    out = os.path.join(tmp, "c5.json")
    json.dump(rec, open(os.path.join(tmp, "c5-rec.json"), "w"))
    t("C5 CLI exit 0 on the clean record", lambda: A.main(["--pcap", pc, "--counters", cf, "--tap-mac", TAP, "--record", os.path.join(tmp, "c5-rec.json"), "--out", out]) == 0)
    nofix = dict(rec)
    nofix.pop("fixture_sha256")
    t("C6 a record without the fixture hash never gives DAT (the control evidence cannot be bound)",
      lambda: all(c["category"] != "DAT" for c in A.evaluate_group(pc, cf, TAP, nofix)["cases"]))



def sec_N(tmp):
    """R5: the R4 counterexample (real IP 10.200.0.2 on the wire + HTTP 200), the NAT bypass with baseline/restore, and the independent FAIL."""
    real = S.GUEST_IP
    # N1 the ARM masquerade WITHOUT the bypass reaching the guest (R4 behaviour): every probe leaves with the real source
    g, rec, pc, cf = run_sim(tmp, "n1", guest_kw={"nat_masq": True, "nat_ignore_insert": True, "answer": True})
    res = A.evaluate_group(pc, cf, TAP, rec)
    cats = {c["id"]: c["category"] for c in res["cases"]}
    t("N1 R4 counterexample: real-IP SYN/echo + HTTP 200/ping rc 0: P1/P2/P4/P5 are KHONG_TAO_DUOC_GOI (never FAIL, never DAT); T16-M1 unaffected",
      lambda: all(cats[i] == "KHONG_TAO_DUOC_GOI" for i in ("T17-P1", "T17-P2", "T17-P4", "T17-P5")) and A.group_exit(res) != 0
      and all(c["unbound_success_output"] and c["real_identity_frames"] and {x["src"] for x in c["real_identity_frames"]} == {real}
              for c in res["cases"] if c["id"] != "T16-M1"))
    t("N1b the explanation names the real identity and says it is neither a spoof FAIL nor blocking evidence",
      lambda: "real identity" in [c for c in res["cases"] if c["id"] == "T17-P1"][0]["verdict"] and "10.200.0.2" in [c for c in res["cases"] if c["id"] == "T17-P1"][0]["verdict"])
    # N2 the bypass rule is applied (setup rc 0 + rule in the guest) and the spoofed address is really on the wire: DAT
    g, rec, pc, cf = run_sim(tmp, "n2", guest_kw={"nat_masq": True})
    res = A.evaluate_group(pc, cf, TAP, rec)
    srcs = {A._ip(f).get("src") for f in L.classified_frames(pc, TAP) if f.get("direction") == "guest" and A._ip(f)}
    t("N2 ARM masquerade + the bypass: the spoofed sources are on the wire (10.200.0.5, 192.168.60.10) and every case is DAT",
      lambda: {"10.200.0.5", "192.168.60.10"} <= srcs and [c["category"] for c in res["cases"]] == ["DAT"] * 5 and A.group_exit(res) == 0)
    t("N3 the bypass rules are removed again: the guest NAT table equals the baseline after the group and every restore says so",
      lambda: g.nat == NAT0 and all((c["guest_state"]["restore"] or {}).get("restored") is True for c in rec["cases"])
      and all(c["guest_state"]["before"].get("nat_postrouting") == NAT0 for c in rec["cases"]))
    # N4 a true leak is a FAIL, wire-bound
    g, rec, pc, cf = run_sim(tmp, "n4", guest_kw={"nat_masq": True, "answer": True})
    res = A.evaluate_group(pc, cf, TAP, rec)
    t("N4 true leak (spoofed source on the wire, the worker answers it, the tool succeeds): FAIL for the four T17 cases, exit 1",
      lambda: all(c["category"] == "FAIL" and "a reply was generated" in " ".join(c["failure_evidence"]) for c in res["cases"] if c["id"] != "T16-M1") and A.group_exit(res) == 1)
    # N5 true leak + measurement error: FAIL kept (a read error does not hide it)
    steps = [dict(s_, rc=0, out="HTTP=200\n") if s_["phase"] == "trigger" else s_ for s_ in crec_for("T17-P1")["steps"]]
    res5, _ = eval_group(tmp, "n5", [("T17-P1", spaced(probe_frames("T17-P1")) + [reply_to("T17-P1")], {"read_error": "boom", "steps": steps}, None)])
    t("N5 spoofed-source frame + reply to it + HTTP 200 + a counter read error: FAIL kept with the measurement error",
      lambda: res5["cases"][0]["category"] == "FAIL" and res5["cases"][0]["measurement_errors"])
    # N6 HTTP 200 from the real identity (real source frames) and a read error: not a FAIL, a measurement error; never PASS
    realfr = [echo_or_syn for echo_or_syn in [syn(GUEST, real, S.WORKER_GUEST_IP, CASES["T17-P1"]["port"], 8011)] * 3]
    res6, _ = eval_group(tmp, "n6", [("T17-P1", spaced(realfr), {"read_error": "boom", "steps": steps}, None)])
    t("N6 real-source frames + HTTP 200 + read error: LOI_PHEP_DO (the success is not evidence of the spoof), never DAT and never an unbound FAIL",
      lambda: res6["cases"][0]["category"] == "LOI_PHEP_DO" and not res6["cases"][0]["failure_evidence"])
    # N7 HTTP 200 with NO usable capture window at all: cannot be bound -> measurement error, not FAIL, not PASS
    c7 = crec_for("T17-P1", steps=steps)
    r7 = A.evaluate_case(None, None, CASES["T17-P1"], c7, True, iface=IF, ctx=CTX, fixture_sha=FIX, bounds={"not_before": LINK_BEFORE_END, "not_after": None})
    t("N7 success output with no capture: LOI_PHEP_DO naming the unbound success; no FAIL from the unbound output",
      lambda: r7["category"] == "LOI_PHEP_DO" and not r7["failure_evidence"] and any("cannot be bound" in m for m in r7["measurement_errors"]))
    # N8 a worker packet addressed to the spoofed source is still independent failure evidence (reply generated), whatever the tool printed
    wf = [(1.2, B.eth(GUEST, TAP, 0x0800, B.ipv4(S.WORKER_GUEST_IP, "10.200.0.5", 6, B.tcp(8011, 31171))))]
    res8, _ = eval_group(tmp, "n8", [("T17-P1", spaced(probe_frames("T17-P1")) + wf, None, None)])
    t("N8 a worker packet to the spoofed source: FAIL (independent of the tool output)", lambda: res8["cases"][0]["category"] == "FAIL")
    # N9 ARM record without the NAT baseline can never be DAT
    bad = copy.deepcopy(BASELINE)
    bad.pop("nat_postrouting")
    r9 = one(tmp, "n9", "T17-P1", spaced(probe_frames("T17-P1")), over={"guest_state": {"before": bad, "restore": copy.deepcopy(RESTORED)}})
    t("N9 an ARM guest baseline without nat_postrouting: CHUA_KIEM_CHUNG naming the missing baseline, never DAT",
      lambda: r9["category"] == "CHUA_KIEM_CHUNG" and any("nat_postrouting" in x for x in r9["execution_problems"]))
    # N10 restore failure of the NAT rule stops the group and is not a pass
    cmd = "iptables -t nat -D POSTROUTING 1"
    g10, rec10, pc10, cf10 = run_sim(tmp, "n10", guest_kw={"nat_masq": True, "fail_cmds": [cmd]})
    res10 = A.evaluate_group(pc10, cf10, TAP, rec10)
    t("N10 the NAT rule cannot be deleted: restore False, later cases not run, no DAT after it, exit != 0",
      lambda: (rec10["cases"][1]["guest_state"]["restore"] or {}).get("restored") is False and rec10["stopped"]
      and all(c["category"] != "DAT" for c in res10["cases"][1:]) and A.group_exit(res10) != 0)
    # N12 session-wide classification (R4 ARM: 20 spoof-MAC frames, counter delta 20, certain 0)
    src = open(os.path.join(HERE, "probe_matrix_launch.py")).read()
    m_ = re.search(r"^def classify\(r\):.*?(?=^def )", src, re.S | re.M)
    mac_const = re.search(r'^SPOOF_SESSION_MACS = \(([^)]*)\)', src, re.M)

    def mk(suite):
        ns = {"C": type("C", (), {"GUEST_MAC": GUEST, "GUEST_IP": S.GUEST_IP, "WORKER_GUEST_IP": S.WORKER_GUEST_IP, "SVC_PORT": 8011}),
              "SUITE": suite, "SPOOF_SESSION_MACS": tuple(re.findall(r'"([^"]+)"', mac_const.group(1))), "ipaddress": __import__("ipaddress"),
              "PRIVATE": [], "MCAST": []}
        exec(m_.group(0), ns)
        return ns["classify"]
    rowf = {"t": 1.0, "src_mac": FAKE, "etype": "0x0800", "ip_src": S.GUEST_IP, "ip_dst": S.WORKER_GUEST_IP, "proto": "6", "sport": "31016", "dport": "8011", "qname": ""}
    t("N12 session classify (spoof suite): the configured spoof MAC maps to l2_bad_mac; another foreign MAC and other suites stay unclassified; the constant mirrors signatures",
      lambda: mk("spoof")(rowf) == "l2_bad_mac" and mk("spoof")(dict(rowf, src_mac="02:00:00:00:00:99")) is None and mk("ipv4")(rowf) is None
      and mk("spoof")(dict(rowf, src_mac=GUEST)) != "l2_bad_mac" and tuple(re.findall(r'"([^"]+)"', mac_const.group(1))) == tuple(m.lower() for m in S.SPOOF_MACS))
    # N11 unit: parse_nat / diff / restore commands
    t("N11 guest_state: nat read errors are never an empty set; extra rules diff and are deleted by restore; MIPS (nat off) is unchanged",
      lambda: raises(GS.StateReadError, lambda: GS.parse_nat("@@S nat\n@@RC 1\n")) and raises(GS.StateReadError, lambda: GS.parse_nat("nothing"))
      and raises(GS.StateReadError, lambda: GS.parse_nat("@@S nat\n@@RC 0\n")) and GS.parse_nat("@@S nat\n-P POSTROUTING ACCEPT\n@@RC 0\n") == ["-P POSTROUTING ACCEPT"]
      and GS.diff({**BASELINE}, {**BASELINE, "nat_postrouting": NAT0 + ["-A POSTROUTING -s 1.2.3.4/32 -j ACCEPT"]}) == ["nat_postrouting: extra '-A POSTROUTING -s 1.2.3.4/32 -j ACCEPT' (x1)"]
      and GS._nat_cmds("eth1", BASELINE, {**BASELINE, "nat_postrouting": NAT0 + ["-A POSTROUTING -s 1.2.3.4/32 -j ACCEPT"]}) == ["iptables -t nat -D POSTROUTING 2"]
      and "iptables" not in " ".join(c for ph in A.commands(CASES["T17-P1"], "br-lan", {"arch": "MIPS", "tap_mac": TAP}).values() for c in ph))


class NatGuest:
    """Minimal guest for the NAT restore unit tests: only `iptables -t nat -S POSTROUTING` / `-D POSTROUTING n` / `-I POSTROUTING 1 ...` and the
    interface state of SA.SimGuest are needed, so it reuses SpoofGuest with a preset table."""


def sec_R6(tmp):
    """R6 (review S1/S2): the NAT baseline keeps order, policy and multiplicity; a success output is attributed to the fake identity only by what the
    wire shows for it (fake SYN + a real-identity HTTP 200 are two flows)."""
    rule = "-A POSTROUTING -s 10.200.0.5/32 -j ACCEPT"
    jump = "-A POSTROUTING -j zone_wan_postrouting"
    P = "-P POSTROUTING ACCEPT"
    base = {**BASELINE, "nat_postrouting": [P, rule, jump]}        # a pre-existing ACCEPT for the spoofed /32 BEFORE the jump (the reviewer's baseline)

    def st(rules):
        return {**base, "nat_postrouting": list(rules)}
    # -- unit: order/multiplicity are state
    t("R1 NAT parse keeps the guest order (no sorting): two orders give two different snapshots; policy line must be first",
      lambda: GS.parse_nat("@@S nat\n" + "\n".join([P, rule, jump]) + "\n@@RC 0") == [P, rule, jump]
      and GS.parse_nat("@@S nat\n" + "\n".join([P, jump, rule]) + "\n@@RC 0") == [P, jump, rule]
      and raises(GS.StateReadError, lambda: GS.parse_nat("@@S nat\n" + "\n".join([rule, P]) + "\n@@RC 0"))
      and raises(GS.StateReadError, lambda: GS.parse_nat("@@S nat\n" + "\n".join([P, P, rule]) + "\n@@RC 0")))
    dup = [P, rule, rule, jump]
    t("R2 S1 counterexample 1: one extra identical ACCEPT is a difference (it was []), and is removed by NUMBER only up to what the case owns",
      lambda: GS.diff(base, st(dup)) == ["nat_postrouting: extra '" + rule + "' (x1)"]
      and GS._nat_cmds("eth1", base, st(dup)) == ["iptables -t nat -D POSTROUTING 2"]
      and GS._nat_cmds("eth1", base, st(dup), owned=[rule]) == ["iptables -t nat -D POSTROUTING 2"]
      and GS._nat_cmds("eth1", base, st(dup), owned=[]) == []
      and A.restore_problem({**copy.deepcopy(RESTORED), "restored": True, "diffs": [], "after": st(dup)}, base, need_nat=True) is not None)
    swap = [P, jump, rule]
    t("R3 S1 counterexample 2: ACCEPT and jump swapped is a difference, nothing is 'restored' by a delete, evaluator refuses restored=True",
      lambda: GS.diff(base, st(swap)) and GS._nat_cmds("eth1", base, st(swap)) == []
      and "different order" in GS.diff(base, st(swap))[0]
      and A.restore_problem({**copy.deepcopy(RESTORED), "restored": True, "diffs": [], "after": st(swap)}, base, need_nat=True) is not None)
    t("R4 a missing rule or a changed policy: diff reports it, no delete command, never restorable by this module",
      lambda: GS.diff(base, st([P, jump])) and GS._nat_cmds("eth1", base, st([P, jump])) == []
      and GS.diff(base, st(["-P POSTROUTING DROP", rule, jump])) and GS._nat_cmds("eth1", base, st(["-P POSTROUTING DROP", rule, rule, jump])) == [])
    t("R5 clean restore: equal sequences give no diff and no command; two inserted rules are deleted highest number first",
      lambda: GS.diff(base, st([P, rule, jump])) == [] and GS._nat_cmds("eth1", base, st([P, rule, jump])) == []
      and GS._nat_cmds("eth1", base, st([P, "-A POSTROUTING -s 1.1.1.1/32 -j ACCEPT", rule, "-A POSTROUTING -s 2.2.2.2/32 -j ACCEPT", jump]))
      == ["iptables -t nat -D POSTROUTING 3", "iptables -t nat -D POSTROUTING 1"])
    t("R6 a rule the case does not own is never deleted even when it is the extra one",
      lambda: GS._nat_cmds("eth1", base, st([P, "-A POSTROUTING -s 9.9.9.9/32 -j DROP", rule, jump]), owned=[rule]) == [])
    # -- through the real restore() with a simulated guest: duplicate added by someone else is not owned -> restore stays False and stops
    def run_nat(rules, owned, name):
        g = SpoofGuest([], [], emit=False)
        g.nat = list(base["nat_postrouting"])
        before = GS.read_state(g, IF, nat=True)
        g.nat = list(rules)
        return g, GS.restore(g, IF, before, owned_nat=owned)
    g, r = run_nat([P, rule, rule, jump], [rule], "r7a")
    t("R7 restore() of an owned duplicate: the table equals the baseline again, restored True, the command is a delete by number",
      lambda: r["restored"] is True and g.nat == [P, rule, jump] and [c["cmd"] for c in r["commands"] if c["step"] == "nat"] == ["iptables -t nat -D POSTROUTING 2"])
    g, r = run_nat([P, rule, rule, jump], [], "r7b")
    t("R7b restore() when the extra rule is not owned: no command, restored False (the table is left alone)",
      lambda: r["restored"] is False and g.nat == [P, rule, rule, jump] and not [c for c in r["commands"] if c["step"] == "nat"])
    g, r = run_nat([P, jump, rule], [rule], "r7c")
    t("R7c restore() of a reordered table: restored False, table untouched, no flush", lambda: r["restored"] is False and g.nat == [P, jump, rule])
    t("R0 R7: no spoofed source of a case lies inside the guest's own 10.200.0.0/30 (R6 run: .3 = its broadcast address left the real identity on the wire)",
      lambda: all(__import__("ipaddress").ip_address(c["src"]) not in __import__("ipaddress").ip_network("10.200.0.0/30") for c in A.build_cases() if c["kind"].startswith("t17")))
    # -- S2: fake and real flows
    mixed = [syn(GUEST, "10.200.0.5", S.WORKER_GUEST_IP, 31171, 8011), syn(GUEST, S.GUEST_IP, S.WORKER_GUEST_IP, 31171, 8011),
             B.eth(GUEST, TAP, 0x0800, B.ipv4(S.WORKER_GUEST_IP, S.GUEST_IP, 6, B.tcp(8011, 31171)))]
    steps = [dict(s_, rc=0, out="HTTP=200\n") if s_["phase"] == "trigger" else s_ for s_ in crec_for("T17-P1")["steps"]]
    rm = one(tmp, "r8", "T17-P1", spaced(mixed, step=0.2), over={"steps": steps})
    t("R8 S2 counterexample: one fake SYN + a real-identity flow with HTTP 200, no answer to the fake: not FAIL, LOI_PHEP_DO naming both flows; fake AND real frames reported",
      lambda: rm["category"] == "LOI_PHEP_DO" and not rm["failure_evidence"] and len(rm["fake_frames"]) == 1 and rm["fake_frames"][0]["src"] == "10.200.0.5"
      and {x["src"] for x in rm["real_identity_frames"]} == {S.GUEST_IP} and any("BOTH" in m for m in rm["measurement_errors"]) and rm["success_outputs"])
    rm2 = one(tmp, "r8b", "T17-P1", spaced(mixed, step=0.2) + [reply_to("T17-P1")], over={"steps": steps})
    t("R9 the same plus a SYN-ACK to the fake identity: FAIL kept, real frames still reported",
      lambda: rm2["category"] == "FAIL" and any("matches the case flow" in x for x in rm2["failure_evidence"]) and rm2["real_identity_frames"] and rm2["fake_frames"])
    rm3 = one(tmp, "r8c", "T17-P1", spaced(mixed, step=0.2) + [reply_to("T17-P1")], over={"steps": steps, "read_error": "boom"})
    t("R10 the same plus a counter read error: FAIL is kept next to the measurement error (a read error never hides a reply to the fake identity)",
      lambda: rm3["category"] == "FAIL" and rm3["measurement_errors"] and rm3["failure_evidence"])
    r11 = one(tmp, "r8d", "T17-P1", spaced(probe_frames("T17-P1")))
    t("R11 no success output, fake SYNs, no reply: DAT as before; fake frames reported, no real frames",
      lambda: r11["category"] == "DAT" and len(r11["fake_frames"]) == 3 and r11["real_identity_frames"] == [] and r11["success_outputs"] == [])
    r12 = one(tmp, "r8e", "T17-P1", [], over={"steps": steps})
    t("R12 success output and no frame of the case at all: KHONG_TAO_DUOC_GOI, never FAIL/DAT",
      lambda: r12["category"] == "KHONG_TAO_DUOC_GOI" and not r12["failure_evidence"])
    r13 = one(tmp, "r8f", "T17-P1", spaced(probe_frames("T17-P1")) + [(5.0, B.eth(GUEST, TAP, 0x0800, B.ipv4(S.WORKER_GUEST_IP, S.GUEST_IP, 6, B.tcp(8011, 31171))))],
              over={"steps": steps})
    t("R13 fake SYNs + HTTP 200 + a worker reply only to the REAL identity (no real SYN in the window): LOI_PHEP_DO, no FAIL inferred from two flows",
      lambda: r13["category"] == "LOI_PHEP_DO" and not r13["failure_evidence"])

def main(argv):
    with tempfile.TemporaryDirectory(prefix="spoof-selftest.") as tmp:
        sec_D()
        sec_P(tmp)
        sec_S1(tmp)
        sec_S2(tmp)
        sec_S3(tmp)
        sec_X(tmp)
        sec_E(tmp)
        sec_F(tmp)
        sec_G(tmp)
        sec_N(tmp)
        sec_R6(tmp)
        sec_C(tmp)
    n = sum(RESULTS.values())
    print(f"SELFTEST-SPOOF: {n}/{len(RESULTS)} passed")
    if "--json" in argv:
        json.dump(RESULTS, open(argv[argv.index("--json") + 1], "w"), indent=1)
    return 0 if n == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
