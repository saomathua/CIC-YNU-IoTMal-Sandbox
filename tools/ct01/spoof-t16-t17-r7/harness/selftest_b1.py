#!/usr/bin/env python3
"""CT-01 batch B1 — offline tests of b1_cases.py / b1_harness.py on SYNTHETIC captures and counter files and stubbed runners/sockets.
Nothing is sent, no guest, no network. The ruleset behaviour is SIMULATED with l2frames.classify (not verified).

    python3 selftest_b1.py [--json FILE]

Sections:
  D  definitions: cases, commands, ports/sizes from signatures.py, registry check, lan_other validation
  P  guest cases on fixtures: clean live/rule-check, controls, replies, no frame, tool errors, measurement errors, edge frame (annotation only)
  W  T20 worker cases: clean, delta 0, failed calls, call succeeded, worker frame on tap0, guest reply, setup error, banner control
  R  route lookups N4/N5
  X  run_group with a stub runner, a fake clock and stub controls/sockets: order, controls around the window, guard stop, never raises
  S  w_send / icmp_control with a FAKE socket module (no real socket)
  E  end to end: run_group -> pcap + counters -> evaluate_group
  H  b1_harness: outcome mapping, run-check, route-check
"""
import copy
import hashlib
import ipaddress
import json
import os
import struct
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import b1_cases as C            # noqa: E402
import b1_harness as H          # noqa: E402
import l2eval                   # noqa: E402
import l2frames as L            # noqa: E402
import signatures as S          # noqa: E402
import selftest_l2 as B         # noqa: E402  (frame builders)
import selftest_l2eval as V     # noqa: E402  (counter-file builders)
import sigscan_l2 as SC         # noqa: E402  (host signature scanner, unchanged)

RESULTS = {}
TAP, GUEST = B.TAP, B.GUEST
LAN_OTHER = "192.168.177.250"
CASES = {c["id"]: c for c in C.build_guest_cases("ARM", "192.168.177.2", LAN_OTHER)}
WCASES = {c["id"]: c for c in C.build_w_cases()}
OK = {"ts": 100.0, "ok": True, "detail": "x"}


def ctl(cid, phase, ts=None, **over):
    """A control record as run_group writes it (bound to the case and the phase). Single-case scenario: read A at 100.0, read B at 110.0."""
    r = {"ts": (99.0 if phase == "before" else 110.5) if ts is None else ts, "ok": True, "detail": "x", "binding": C.control_binding(CASES[cid], phase)}
    r.update(over)
    return r


def calls_for(cid, ok=False, errno=None, t0=100.0, n=None, op=None, **kw):
    """Call records as w_send writes them for case `cid` in the window [t0, t0+10]."""
    c = WCASES[cid]
    n = c.get("count", 1) if n is None else n
    op = op or {"w_icmp": "sendto", "w_tcp": "connect", "w_udp": "sendto"}[c["kind"]]
    if errno is None and ok is False:
        errno = 110 if c["kind"] == "w_tcp" else 1
    return [dict({"op": op, "ts": t0 + 0.5 + 0.1 * k, "ok": ok, "errno": None if ok else errno}, **kw) for k in range(n)]


def banner_wire(data=b"SSH-2.0-dropbear_2020.81\r\n\x00\xaf", rc=0):
    return (f"CT01-BANNER-HEX/1\nNC_RC={rc}\nTIMED_OUT=0\nTIMER_ERROR=0\n"
            f"STDOUT_BYTES={len(data)}\nSTDERR_BYTES=0\nSTDOUT_HEX={data.hex()}\nSTDERR_HEX=\nEND-CT01-BANNER-HEX/1\n")


def good_banner(**over):
    r = {"command": C.BANNER_COMMAND, "binding": {"case": "T20-N2-TCP22", "kind": "guest_banner", "dst": "10.200.0.2", "port": 22, "phase": "before", "read_label": "T20-N2-TCP22 before"}, "rc": 0, "ok": True, "output_tail": "SSH-2.0-dropbear_2020.81", "transport_output": banner_wire(), "ts": 99.5}
    r.update(over)
    return r


def dead_banner():
    return {"command": C.BANNER_COMMAND, "binding": {"case": "T20-N2-TCP22", "kind": "guest_banner", "dst": "10.200.0.2", "port": 22, "phase": "before", "read_label": "T20-N2-TCP22 before"}, "rc": 0, "ok": False, "output_tail": "", "transport_output": banner_wire(b""), "ts": 99.5}


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
def probe_frames(cid, n=3):
    c = CASES[cid]
    k = c["kind"]
    if k == "icmp":
        return [B.eth(TAP, GUEST, 0x0800, B.ipv4(S.GUEST_IP, c["dst"], 1, B.icmp(c["size"])))] * n
    if k == "tcp":
        return [B.eth(TAP, GUEST, 0x0800, B.ipv4(S.GUEST_IP, c["dst"], 6, B.tcp(c["lport"], c["port"])))] * n
    label = c["qname"].split(".")[0].encode()
    return [B.eth(TAP, GUEST, 0x0800, B.ipv4(S.GUEST_IP, c["dst"], 17, B.udp(40000, 53, b"\x00\x01" + bytes([len(label)]) + label + b"\x00")))] * n


def v6():
    return B.eth("33:33:00:00:00:16", GUEST, 0x86DD, B.ipv6(S.GUEST_LL6, "ff02::16", 58, B.icmp6(20, typ=143)))


def dhcp():
    return B.eth("ff:ff:ff:ff:ff:ff", GUEST, 0x0800, B.ipv4("0.0.0.0", "255.255.255.255", 17, B.udp(68, 67)))


def reply_to_guest(src, proto=1):
    return B.eth(GUEST, TAP, 0x0800, B.ipv4(src, S.GUEST_IP, proto, B.icmp(8) if proto == 1 else B.tcp(53, 40000)))


def spaced(frames, start=1.0, step=0.5):
    return [(start + step * k, f) for k, f in enumerate(frames)]


GOOD_EXEC = {"rc": 1, "output_tail": "", "guest_failed": True}


def grec(cid, t0=100.0, **over):
    c = CASES[cid]
    live = c.get("control") is not None
    r = {"id": cid, "before": f"{cid} before", "after": f"{cid} after", "command": C.command(c), "exec": dict(GOOD_EXEC), "read_error": None,
         "control_before": ctl(cid, "before", t0 - 1.0) if live else None, "control_after": ctl(cid, "after", t0 + 10.5) if live else None}
    r.update(over)
    return r


def wrec(cid, calls=None, t0=100.0, **over):
    c = WCASES[cid]
    calls = calls if calls is not None else calls_for(cid, t0=t0)
    r = {"id": cid, "before": f"{cid} before", "after": f"{cid} after", "read_error": None, "calls": calls, "send_binding": C.send_binding(c)}
    r.update(over)
    return r


def scenario(tmp, name, gspecs=(), wspecs=(), banner_ok=True, link_before=True, link_after=True, reads_override=None, arch="ARM"):
    """gspecs: [(case id, [(dt, frame)...], rec overrides, {counter: extra})]; wspecs: [(case id, [(dt, frame)...], rec overrides, {counter: extra})].
    Case i window: A=[t0, t0+0.01], B=[t0+10, t0+10.01], t0 = 100 + 20 i. Counters follow l2frames.classify of each frame inside [A.t_start, B.t_end]."""
    values = dict(V.BASE)
    recs, frames, gcs, wcs = [], [], [], []
    for i, (kind, cid, fr, over, extra) in enumerate([("g",) + s for s in gspecs] + [("w",) + s for s in wspecs]):
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
        (gcs if kind == "g" else wcs).append(grec(cid, t0=t0, **(over or {})) if kind == "g" else wrec(cid, t0=t0, **(over or {})))
    pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), frames)
    cf = V.write_counters(os.path.join(tmp, name + ".jsonl"), reads_override if reads_override is not None else recs)
    record = {"schema": C.SCHEMA, "arch": arch, "iface": "eth1", "tap_mac": TAP, "service_link_before": {"ok": link_before, "detail": "x"},
              "service_link_after": {"ok": link_after, "detail": "x"}, "guest_banner_control": (good_banner() if banner_ok is True else dead_banner() if banner_ok is False else banner_ok), "guest_cases": gcs,
              "w_cases": wcs, "stopped": None}
    return pc, cf, record


def one_guest(tmp, name, cid, frames, over=None, extra=None, **kw):
    pc, cf, rec = scenario(tmp, name, [(cid, frames, over, extra)], **kw)
    return C.evaluate_guest_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), CASES[cid], rec["guest_cases"][0],
                                 C.link_ok(rec["service_link_before"]), C.link_ok(rec["service_link_after"]))


def one_w(tmp, name, cid, frames=(), over=None, extra=None, banner_ok=True, **kw):
    pc, cf, rec = scenario(tmp, name, [], [(cid, list(frames), over, extra)], banner_ok=banner_ok, **kw)
    return C.evaluate_w_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), WCASES[cid], rec["w_cases"][0], rec["guest_banner_control"],
                             C.link_ok(rec["service_link_before"]), C.link_ok(rec["service_link_after"]))


def _d5d():
    import re as _re
    src = open(os.path.join(HERE, "probe_matrix_launch.py")).read()
    ns = {"time": __import__("time"), "re": _re}
    exec(compile(src[src.index("class Guest:"):src.index("def parse_info_network")], "Guest", "exec"), ns)
    G = ns["Guest"]

    class P:
        def __init__(self, eol, corrupt=False):
            self.eol, self.corrupt, self.buf, self.match, self.before = eol, corrupt, "", None, ""

        def sendline(self, line):
            m = _re.search(r"B (\w\w);", line) or _re.search(r"echo @@B(\w\w);", line)
            i = m.group(1)
            end = f"@@E{i}:" + ("" if self.corrupt else "0") + self.eol
            self.buf = line + self.eol + f"@@B{i}" + self.eol + "out" + self.eol + end + "# "

        def expect(self, pat, timeout=None):
            m = _re.search(pat, self.buf)
            if not m:
                raise TimeoutError("no match")
            self.before, self.match, self.buf = self.buf[:m.start()], m, self.buf[m.end():]

    for eol in ("\n", "\r\n", "\r\r\n"):
        for mode in ("exec", "run"):
            g = G(P(eol))
            g.cap = G.MAX_SEND if mode == "run" else None
            rc, out = g._exec("echo x") if mode == "exec" else g.run("echo x")
            if rc != 0 or out != "out\n" or g.broken:
                return False
    for mode in ("exec", "run"):
        g = G(P("\r\r\n", corrupt=True))
        g.cap = G.MAX_SEND
        try:
            g._exec("echo x") if mode == "exec" else g.run("echo x")
            return False
        except TimeoutError:
            pass
        if not g.broken:
            return False
        try:
            g.run("echo y")
            return False
        except RuntimeError:
            pass
    return True


def _d5c():
    """R13N8: the REAL Guest's upload plan: every sent line (wrapper included) <= MAX_SEND (the longest console line known to be accepted, 194),
    the chunks rebuild the script byte for byte, a long line is split, a longer sent line is refused before sending."""
    src = open(os.path.join(HERE, "probe_matrix_launch.py")).read()
    ns = {"time": __import__("time"), "re": __import__("re")}
    exec(compile(src[src.index("class Guest:"):src.index("def parse_info_network")], "Guest", "exec"), ns)
    G = ns["Guest"]
    if G.MAX_SEND != 194:
        return False

    def rebuilt(steps):
        out = ""
        for c in steps[1:]:
            m = __import__("re").fullmatch(r"printf '(%s\\n|%s)' '([^']*)'>>/tmp/ct01b\.sh", c)
            if not m:
                return None
            out += m.group(2) + ("\n" if m.group(1) != "%s" else "")
        return out
    g = G(None)
    for script in (C.BANNER_COMMAND, "a" * 700 + "\n\nb" * 5 + "\n" + "c" * 114):
        steps, body = g.upload_plan(script)
        if any(len(g._wire(c, "zz")) > G.MAX_SEND for c in steps) or rebuilt(steps) != body:
            return False
    if len(g.upload_plan("a" * 700)[0]) < 6:                  # a 700-char line is really split
        return False

    class P:
        def __init__(self):
            self.lines = []

        def sendline(self, s):
            self.lines.append(s)
            raise RuntimeError("stop after the first line")
    q = P()
    g2 = G(q)
    try:
        g2._exec("x" * 400, 5)
    except RuntimeError as e:
        return "refused before sending" in str(e) and not q.lines
    return False


# ------------------------------------------------------------------ D
def sec_D():
    t("D1 six guest cases and four worker cases as planned, ids unique",
      lambda: [c["id"] for c in C.build_guest_cases("ARM", lan_other=LAN_OTHER)] == list(C.GUEST_CASE_IDS)
      and [c["id"] for c in C.build_w_cases()] == list(C.W_CASE_IDS) and len(set(C.ALL_CASE_IDS)) == 10)
    t("D2 ports/sizes come from signatures.py; registry check passes",
      lambda: CASES["T06-ICMP-LANDNS"]["size"] == S.ICMP4_SIZES["T06-B"] and CASES["T11-ICMP"]["size"] == S.ICMP4_SIZES["T11-C"]
      and CASES["T06-TCP-LAN2"]["lport"] == S.PROBE_PORTS["T06-L2"] and CASES["T11-TCP22"]["lport"] == S.PROBE_PORTS["T11-P22"]
      and CASES["T11-TCP80"]["lport"] == S.PROBE_PORTS["T11-P80"] and WCASES["T20-N2-TCP22"]["sport"] == S.PROBE_PORTS["T20-N2-22"]
      and WCASES["T20-N3-UDP"]["sport"] == S.PROBE_PORTS["T20-N3"] and S.check() == [])
    t("D3 expected classes: public DNS drop_public, LAN drop_private, worker ports/ICMP drop_worker_other",
      lambda: {c["id"]: c["expected"] for c in CASES.values()} == {"T05-DNS-8888": "drop_public", "T06-ICMP-LANDNS": "drop_private",
                                                                   "T06-TCP-LAN2": "drop_private", "T11-TCP22": "drop_worker_other",
                                                                   "T11-TCP80": "drop_worker_other", "T11-ICMP": "drop_worker_other"})
    t("D4 live controls only for the DNS and ICMP-LAN probes; the others are rule checks",
      lambda: {c["id"]: c["control"] for c in CASES.values()} == {"T05-DNS-8888": "w_dns", "T06-ICMP-LANDNS": "w_icmp", "T06-TCP-LAN2": None,
                                                                  "T11-TCP22": None, "T11-TCP80": None, "T11-ICMP": None})
    t("D5 commands: exact probes + pinned bounded nc file/ASCII transport",
      lambda: C.command(CASES["T05-DNS-8888"]) == "nslookup ct01-06b4-t05-arm-1.example 8.8.8.8"
      and C.command(CASES["T06-ICMP-LANDNS"]) == "ping -c 3 -s 1406 -w 5 192.168.177.2"
      and C.command(CASES["T11-ICMP"]) == "ping -c 3 -s 1111 -w 5 10.200.0.1"
      and C.command(CASES["T11-TCP22"]).startswith("curl -s -o /dev/null --local-port 31110 ")
      and C.command(CASES["T11-TCP22"]).endswith("http://10.200.0.1:22/ct01-b1-T11-TCP22")
      and hashlib.sha256(C.BANNER_COMMAND.encode("ascii")).hexdigest() == "a94376f5ee7a562b7071b4bd5e2bc775520fceff47658bfecfd9ba2ff6df541a"
      and C.BANNER_COMMAND.count('exec nc 10.200.0.2 22 <"$ct01_dir/stdin"') == 1
      and '>"$ct01_dir/stdout" 2>"$ct01_dir/stderr"' in C.BANNER_COMMAND
      and "CT01-BANNER-HEX/1" in C.BANNER_COMMAND and "head -c 4096" in C.BANNER_COMMAND
      and "head -c 2048" in C.BANNER_COMMAND and "sleep 3" in C.BANNER_COMMAND and "nc -w" not in C.BANNER_COMMAND)
    t("D5b R13N6 transport contract: script lines <=120 ASCII chars, no single quote/CR/non-ASCII, no od (absent in both guest BusyBox), hexdump -v -e used, "
      "exactly one nc exec, every tool used is in the presence loop",
      lambda: all(len(l) <= 120 and l.isascii() for l in C.BANNER_COMMAND.split("\n")) and "'" not in C.BANNER_COMMAND and "\r" not in C.BANNER_COMMAND
      and " od " not in C.BANNER_COMMAND and "hexdump -v -e" in C.BANNER_COMMAND and C.BANNER_COMMAND.count("exec nc ") == 1
      and "for ct01_tool in nc sleep mktemp wc head hexdump tr rm mkfifo;" in C.BANNER_COMMAND and len(C.BANNER_COMMAND.encode()) > 2048
      and '( ulimit -f 16 || exit 125; exec nc 10.200.0.2 22 <"$ct01_dir/stdin" )' in C.BANNER_COMMAND and "ulimit -f 16 2>/dev/null" not in C.BANNER_COMMAND)
    t("D5c upload plan: every sent line incl. wrapper <= 194, chunks rebuild the script byte for byte, a longer line is refused before sending",
      lambda: _d5c())
    t("D5d R13N9 Guest._exec/run read the end marker terminated by LF, CRLF and CRCRLF; a corrupted/missing marker stops and marks the console broken",
      lambda: _d5d())
    t("D6 lan_other must be a private LAN address not used elsewhere",
      lambda: all(C.lan_other_problem(x) for x in ("8.8.8.8", "10.200.0.2", "192.168.177.2", "192.168.60.10", "127.0.0.1", "169.254.1.1", "x", None))
      and C.lan_other_problem("192.168.177.250") is None and raises(ValueError, lambda: C.build_guest_cases("ARM", lan_other=None))
      and raises(ValueError, lambda: C.build_guest_cases("ARM", lan_other="8.8.8.8")))
    t("D7 unknown architecture / bad command values refused",
      lambda: raises(ValueError, lambda: C.build_guest_cases("X86", lan_other=LAN_OTHER))
      and raises(ValueError, lambda: C.command(dict(CASES["T05-DNS-8888"], qname="a b; reboot")))
      and raises(ValueError, lambda: C.command(dict(CASES["T11-ICMP"], dst="10.200.0.1; reboot"))))
    t("D8 guest_failed: tcp rc 7/28+HTTP=000, dns rc!=0 without answer, icmp rc!=0 without 'bytes from'",
      lambda: C.guest_failed(CASES["T11-TCP22"], 28, "HTTP=000") and not C.guest_failed(CASES["T11-TCP22"], 0, "HTTP=403")
      and C.guest_failed(CASES["T05-DNS-8888"], 1, "") and not C.guest_failed(CASES["T05-DNS-8888"], 0, "Name: ct01-06b4-t05-arm-1.example")
      and C.guest_failed(CASES["T11-ICMP"], 1, "0 packets received") and not C.guest_failed(CASES["T11-ICMP"], 0, "64 bytes from 10.200.0.1"))
    t("D9 T20 N1 payload does not collide with a registered ICMP size and fits an MTU",
      lambda: WCASES["T20-N1-ICMP"]["size"] + 28 < 1500 and WCASES["T20-N1-ICMP"]["size"] not in S.ICMP4_SIZES.values())


# ------------------------------------------------------------------ P
def sec_P(tmp):
    for cid in C.GUEST_CASE_IDS:
        live = CASES[cid]["control"] is not None
        t(f"P1 {cid}: clean fixture -> " + ("ĐẠT (live control)" if live else "ĐẠT (kiểm quy tắc)"),
          lambda cid=cid, live=live: (lambda r: r["category"] == ("DAT" if live else "DAT_KIEM_QUY_TAC")
                                      and r["verdict"] == ("ĐẠT" if live else "ĐẠT (kiểm quy tắc)") and r["probe_frames"] == 3)(
              one_guest(tmp, f"p1-{cid}", cid, spaced(probe_frames(cid)))))
    t("P2 clean with DHCP/MLD background reconciled -> still ĐẠT",
      lambda: one_guest(tmp, "p2", "T11-TCP22", spaced(probe_frames("T11-TCP22") + [dhcp(), v6()]))["category"] == "DAT_KIEM_QUY_TAC")
    t("P3 retransmissions count: 5 SYN frames -> delta = 5 frames, ĐẠT",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["probe_frames"] == 5)(
          one_guest(tmp, "p3", "T11-TCP80", spaced(probe_frames("T11-TCP80", 5)))))
    # live control
    T5 = "T05-DNS-8888"
    for n, over in (("missing before", {"control_before": None}), ("missing after", {"control_after": None}),
                    ("failed before", {"control_before": ctl(T5, "before", ok=False)}),
                    ("failed after", {"control_after": ctl(T5, "after", ok=False)}),
                    ("stale before (older than the freshness bound)", {"control_before": ctl(T5, "before", 99.0 - C.CONTROL_MAX_AGE_S - 1)}),
                    ("stale after (later than the freshness bound)", {"control_after": ctl(T5, "after", 110.5 + C.CONTROL_MAX_AGE_S + 1)}),
                    ("after taken before read B ended", {"control_after": ctl(T5, "after", 105.0)}),
                    ("reversed order (after earlier than before)", {"control_before": ctl(T5, "before", 100.0), "control_after": ctl(T5, "after", 99.99)})):
        t(f"P4 T05 live control {n} -> CHƯA KIỂM CHỨNG, never ĐẠT",
          lambda n=n, over=over: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and not r["ok"] and r["control_state"] in ("not_alive",))(
              one_guest(tmp, "p4-" + n.split()[0] + str(abs(hash(n)) % 997), T5, spaced(probe_frames(T5)), over)))
    for n, over in (("non-finite ts", {"control_before": ctl(T5, "before", float("nan"))}),
                    ("ok not boolean", {"control_after": ctl(T5, "after", ok="true")}),
                    ("ts a string", {"control_before": ctl(T5, "before", "99.0")}),
                    ("without binding", {"control_before": {"ts": 99.0, "ok": True, "detail": "x"}}),
                    ("extra field", {"control_after": ctl(T5, "after", note="x")}),
                    ("not an object", {"control_before": [99.0, True]}),
                    ("bound to another case", {"control_before": dict(ctl(T5, "before"), binding=C.control_binding(CASES["T06-ICMP-LANDNS"], "before"))}),
                    ("bound to another phase", {"control_before": ctl(T5, "after", 99.0)}),
                    ("bound to another destination", {"control_after": dict(ctl(T5, "after"), binding=dict(C.control_binding(CASES[T5], "after"), dst="1.1.1.1"))}),
                    ("bound to another name", {"control_after": dict(ctl(T5, "after"), binding=dict(C.control_binding(CASES[T5], "after"), qname="other.example"))})):
        t(f"P4b T05 live control {n} -> LỖI PHÉP ĐO, never ĐẠT",
          lambda n=n, over=over: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["ok"] and r["control_state"] == "invalid")(
              one_guest(tmp, "p4b-" + n.split()[0] + str(abs(hash(n)) % 997), T5, spaced(probe_frames(T5)), over)))
    t("P5 a rule-check case ignores controls (none required) but stays 'kiểm quy tắc'",
      lambda: one_guest(tmp, "p5", "T11-ICMP", spaced(probe_frames("T11-ICMP")), {"control_before": {"ok": False}})["verdict"] == "ĐẠT (kiểm quy tắc)")
    t("P5b a live control that is only a bound COPY of the other phase's time is not alive (before == after ts)",
      lambda: one_guest(tmp, "p5b", "T05-DNS-8888", spaced(probe_frames("T05-DNS-8888")),
                        {"control_before": ctl("T05-DNS-8888", "before", 100.0), "control_after": ctl("T05-DNS-8888", "after", 100.0)})["category"] == "CHUA_KIEM_CHUNG")
    # guest side
    t("P6 guest reached the destination (tool succeeded) -> FAIL",
      lambda: one_guest(tmp, "p6", "T11-TCP22", spaced(probe_frames("T11-TCP22")), {"exec": {"rc": 0, "output_tail": "HTTP=200", "guest_failed": False}})["category"] == "FAIL")
    t("P7 a reply frame addressed to the guest from the probe destination -> FAIL",
      lambda: (lambda r: r["category"] == "FAIL" and "no_reply_to_guest" in r["failed"])(
          one_guest(tmp, "p7", "T05-DNS-8888", spaced(probe_frames("T05-DNS-8888") + [reply_to_guest("8.8.8.8", 17)]))))
    t("P8 a worker frame from 10.200.0.1 to the guest that is not the service (T11 ICMP reply) -> FAIL",
      lambda: one_guest(tmp, "p8", "T11-ICMP", spaced(probe_frames("T11-ICMP") + [reply_to_guest("10.200.0.1")]))["category"] == "FAIL")
    t("P9 no probe frame (tool failed, nothing on tap0) -> CHƯA KIỂM CHỨNG (không tạo được gói), not a block proof",
      lambda: (lambda r: r["category"] == "KHONG_TAO_DUOC_GOI" and not r["ok"])(one_guest(tmp, "p9", "T11-TCP22", [])))
    t("P10 tool missing / command not run -> LOI_THUC_THI, never ĐẠT, never FAIL from guest_connection_failed",
      lambda: (lambda r: r["category"] == "LOI_THUC_THI" and not r["ok"])(
          one_guest(tmp, "p10", "T05-DNS-8888", spaced(probe_frames("T05-DNS-8888")), {"exec": {"error": "tool missing in the guest"}})))
    t("P11 exec record missing -> LOI_THUC_THI",
      lambda: one_guest(tmp, "p11", "T11-TCP22", spaced(probe_frames("T11-TCP22")), {"exec": None})["category"] == "LOI_THUC_THI")
    def wrong_class():
        pc, cf, rec = scenario(tmp, "p12", [("T11-TCP22", spaced(probe_frames("T11-TCP22")), None, None)])
        case = dict(CASES["T11-TCP22"], expected="drop_private")        # the ruleset puts 10.200.0.1 into drop_worker_other: another expectation must FAIL
        return C.evaluate_guest_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), case, rec["guest_cases"][0], True, True)
    t("P12 probe frames classified in another class than expected -> FAIL", lambda: wrong_class()["category"] == "FAIL")
    # measurement errors
    t("P13 read_error in the record -> LỖI PHÉP ĐO",
      lambda: one_guest(tmp, "p13", "T11-TCP22", spaced(probe_frames("T11-TCP22")), {"read_error": "read 'x': RuntimeError: nft"})["category"] == "LOI_PHEP_DO")
    t("P14 a counter read missing from the file -> LỖI PHÉP ĐO",
      lambda: one_guest(tmp, "p14", "T11-TCP22", spaced(probe_frames("T11-TCP22")), {"after": "T11-TCP22 vanished"})["category"] == "LOI_PHEP_DO")

    def decreasing():
        recs = [V.rec("T11-TCP22 before", 100.0, 100.01, dict(V.BASE, drop_worker_other=5)), V.rec("T11-TCP22 after", 110.0, 110.01, dict(V.BASE, drop_worker_other=2))]
        pc, cf, rec = scenario(tmp, "p15", [("T11-TCP22", spaced(probe_frames("T11-TCP22")), None, None)], reads_override=recs)
        return C.evaluate_guest_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), CASES["T11-TCP22"], rec["guest_cases"][0], True, True)
    t("P15 a counter that decreased -> LỖI PHÉP ĐO, never ĐẠT", lambda: decreasing()["category"] == "LOI_PHEP_DO")

    def nonfinite():
        recs = [V.rec("T11-TCP22 before", float("inf"), 100.01, V.BASE), V.rec("T11-TCP22 after", 110.0, 110.01, V.BASE)]
        pc, cf, rec = scenario(tmp, "p16", [("T11-TCP22", spaced(probe_frames("T11-TCP22")), None, None)], reads_override=[
            json.dumps(recs[0]).replace("Infinity", "Infinity"), recs[1]])
        try:
            reads = l2eval.load_reads(cf)
        except l2eval.InputError:
            return True
        return False
    t("P16 non-finite read time refused by the counter loader (input error)", nonfinite)
    t("P17 service link before missing -> CHƯA KIỂM CHỨNG, not ĐẠT",
      lambda: one_guest(tmp, "p17", "T11-TCP22", spaced(probe_frames("T11-TCP22")), link_before=False)["category"] == "CHUA_KIEM_CHUNG")
    t("P18 service link after failed -> CHƯA KIỂM CHỨNG, not ĐẠT",
      lambda: one_guest(tmp, "p18", "T11-TCP22", spaced(probe_frames("T11-TCP22")), link_after=False)["category"] == "CHUA_KIEM_CHUNG")
    # counter mismatch
    t("P19 counter delta without a matching frame (extra drop_worker_other) -> FAIL (reconciliation)",
      lambda: one_guest(tmp, "p19", "T11-TCP22", spaced(probe_frames("T11-TCP22")), extra={"drop_worker_other": 1})["category"] == "FAIL")
    t("P20 independent FAIL is kept with a control problem present (FAIL beats CHƯA KIỂM CHỨNG)",
      lambda: one_guest(tmp, "p20", "T05-DNS-8888", spaced(probe_frames("T05-DNS-8888")), {"control_before": None}, extra={"drop_public": 1})["category"] == "FAIL")

    def edge():
        # the probe is complete, but an IPv6 background frame sits inside the guard of read B: UNVERIFIED -> CHƯA KIỂM CHỨNG + annotation
        fr = spaced(probe_frames("T11-TCP22")) + [(10.0 - 0.005, v6())]
        pc, cf, rec = scenario(tmp, "p21", [("T11-TCP22", fr, None, {"l2_bad_ethertype": 0})])
        reads = l2eval.load_reads(cf)
        return C.evaluate_guest_case(L.classified_frames(pc, TAP), reads, CASES["T11-TCP22"], rec["guest_cases"][0], True, True)
    t("P21 edge frame -> CHƯA KIỂM CHỨNG; closure is only an ANNOTATION (verdict unchanged), never PASS",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and not r["ok"] and "derived_closure" in r)(edge()))


# ------------------------------------------------------------------ W
def sec_W(tmp):
    for cid in C.W_CASE_IDS:
        banner = cid == "T20-N2-TCP22"
        t(f"W1 {cid}: clean (drop_out > 0, calls failed, no frame) -> " + ("ĐẠT with the guest banner control" if banner else "ĐẠT (kiểm quy tắc)"),
          lambda cid=cid, banner=banner: (lambda r: r["category"] == ("DAT" if banner else "DAT_KIEM_QUY_TAC") and r["drop_out_delta"] == 3)(
              one_w(tmp, f"w1-{cid}", cid, extra={"drop_out": 3})))
    t("W2 N2-22 with a VALID negative banner record -> CHƯA KIỂM CHỨNG while the coordinator has not fixed the label (never ĐẠT)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and r["banner_state"] == "dead_valid")(one_w(tmp, "w2", "T20-N2-TCP22", extra={"drop_out": 3}, banner_ok=False)))
    def dead_as_rule():
        C.BANNER_DEAD_AS_RULE_CHECK = True
        try:
            return one_w(tmp, "w2b", "T20-N2-TCP22", extra={"drop_out": 3}, banner_ok=False)
        finally:
            C.BANNER_DEAD_AS_RULE_CHECK = False
    t("W2b the same record with the label decision set to rule check -> ĐẠT (kiểm quy tắc), never the live label",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["verdict"] == "ĐẠT (kiểm quy tắc)")(dead_as_rule()))
    t("W3 drop_out did not increase -> CHƯA KIỂM CHỨNG (packet not proven to reach the hook)",
      lambda: (lambda r: r["category"] == "CHUA_KIEM_CHUNG" and not r["ok"])(one_w(tmp, "w3", "T20-N1-ICMP", extra={})))
    t("W4 a call that did not fail -> CHƯA KIỂM CHỨNG (errno missing)",
      lambda: one_w(tmp, "w4", "T20-N1-ICMP", over={"calls": calls_for("T20-N1-ICMP", ok=True)}, extra={"drop_out": 3})["category"] == "CHUA_KIEM_CHUNG")
    t("W5 a call failed without an integer errno -> LỖI PHÉP ĐO (a record that cannot prove the failure), never ĐẠT",
      lambda: one_w(tmp, "w5", "T20-N3-UDP", over={"calls": [dict(c, errno=None) for c in calls_for("T20-N3-UDP")]}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO")
    t("W6 connect() succeeded -> FAIL (the guest accepted a connection)",
      lambda: one_w(tmp, "w6", "T20-N2-TCP80", over={"calls": calls_for("T20-N2-TCP80", ok=True)}, extra={"drop_out": 1})["category"] == "FAIL")
    t("W7 a worker frame to the guest outside the allowlist on tap0 -> FAIL",
      lambda: (lambda r: r["category"] == "FAIL" and "worker_frame_outside_allowlist_on_tap0" in r["failed"])(
          one_w(tmp, "w7", "T20-N1-ICMP", [(2.0, B.eth(GUEST, TAP, 0x0800, B.ipv4(S.WORKER_GUEST_IP, S.GUEST_IP, 1, B.icmp(16))))], extra={"drop_out": 3})))
    t("W8 an allowed worker frame (ARP .1 -> .2) is not a violation",
      lambda: one_w(tmp, "w8", "T20-N1-ICMP", [(2.0, B.eth(GUEST, TAP, 0x0806, B.arp(2, TAP, "10.200.0.1", GUEST, "10.200.0.2")))], extra={"drop_out": 3})["category"] == "DAT_KIEM_QUY_TAC")
    t("W9 the guest answered the worker (TCP RST/SYN-ACK from 22 to sport 31201) -> FAIL",
      lambda: one_w(tmp, "w9", "T20-N2-TCP22", [(2.0, B.eth(TAP, GUEST, 0x0800, B.ipv4(S.GUEST_IP, "10.200.0.1", 6, B.tcp(22, 31201))))], extra={"drop_out": 1})["category"] == "FAIL")
    t("W10 socket setup error -> LOI_THUC_THI, never ĐẠT",
      lambda: one_w(tmp, "w10", "T20-N1-ICMP", over={"calls": [{"op": "socket", "ts": 100.5, "ok": False, "errno": 1, "exc": "PermissionError", "setup_error": True}]},
                    extra={"drop_out": 3})["category"] == "LOI_THUC_THI")
    t("W11 no calls recorded where three were required -> LỖI PHÉP ĐO, never ĐẠT",
      lambda: one_w(tmp, "w11", "T20-N3-UDP", over={"calls": []}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO")
    t("W12 calls missing/not a list -> LỖI PHÉP ĐO",
      lambda: one_w(tmp, "w12", "T20-N3-UDP", over={"calls": "garbage"}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO")
    t("W13 read error -> LỖI PHÉP ĐO", lambda: one_w(tmp, "w13", "T20-N3-UDP", over={"read_error": "read x: boom"}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO")
    t("W14 drop_out missing from the counter reads -> LỖI PHÉP ĐO (a missing counter is not 0)",
      lambda: (lambda r: r["category"] == "LOI_PHEP_DO")(_w_without_drop_out(tmp)))
    t("W15 an unrelated counter moved without a frame (allow_out_svc +1) -> FAIL (reconciliation)",
      lambda: one_w(tmp, "w15", "T20-N1-ICMP", extra={"drop_out": 3, "allow_out_svc": 1})["category"] == "FAIL")
    t("W16 worker case not run (group stopped) -> CHƯA KIỂM CHỨNG",
      lambda: C.evaluate_w_case([], {}, WCASES["T20-N1-ICMP"], {"id": "T20-N1-ICMP", "not_run": "LeakDetected: x"}, True, True, True)["category"] == "CHUA_KIEM_CHUNG")


def _w_without_drop_out(tmp):
    base = {k: v for k, v in V.BASE.items() if k != "drop_out"}
    recs = [V.rec("T20-N1-ICMP before", 100.0, 100.01, base), V.rec("T20-N1-ICMP after", 110.0, 110.01, base)]
    pc, cf, rec = scenario(tmp, "w14", [], [("T20-N1-ICMP", [], None, None)], reads_override=recs)
    return C.evaluate_w_case(L.classified_frames(pc, TAP), l2eval.load_reads(cf), WCASES["T20-N1-ICMP"], rec["w_cases"][0], True, True, True)


# ------------------------------------------------------------------ R
PROC_ROUTE_OK = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                 "eth1\t00000000\t013CA8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                 "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
                 "eth1\t003CA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")


def ER(n4, n5, wk, gw, br, n4_rc=0, n5_rc=0):
    return C.evaluate_routes(n4, n5, wk, gw, br, n4_rc=n4_rc, n5_rc=n5_rc)


def sec_R():
    gw, wk, br = "192.168.60.1", "192.168.60.2", "br-1d86fe3e8bbe"
    t("R1 manager table: default via the sandboxnet gateway -> ĐẠT (route lookup, not a live control)",
      lambda: ER(PROC_ROUTE_OK, "10.200.0.2 via 192.168.177.2 dev ens33 src 192.168.177.128 uid 0\n", wk, gw, br)[0]["category"] == "DAT_KIEM_QUY_TAC")
    bad = PROC_ROUTE_OK.replace("013CA8C0", "023CA8C0")                               # default via 192.168.60.2 (the worker)
    t("R2 manager routes 10.200.0.2 via the worker eth0 -> FAIL",
      lambda: ER(bad, "10.200.0.2 via 192.168.177.2 dev ens33\n", wk, gw, br)[0]["category"] == "FAIL")
    t("R3 host route leaves through the sandboxnet bridge -> FAIL",
      lambda: ER(PROC_ROUTE_OK, "10.200.0.2 dev br-1d86fe3e8bbe src 192.168.60.1\n", wk, gw, br)[1]["category"] == "FAIL")
    t("R4 host route via the worker -> FAIL",
      lambda: ER(PROC_ROUTE_OK, "10.200.0.2 via 192.168.60.2 dev br-1d86fe3e8bbe\n", wk, gw, br)[1]["category"] == "FAIL")
    t("R5 unreadable tables -> LỖI PHÉP ĐO, never ĐẠT",
      lambda: [r["category"] for r in ER("garbage", "", wk, gw, br)] == ["LOI_PHEP_DO", "LOI_PHEP_DO"])
    t("R6 no matching route in the manager table -> CHƯA KIỂM CHỨNG",
      lambda: ER("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n", "10.200.0.2 dev ens33\n", wk, gw, br)[0]["category"] == "CHUA_KIEM_CHUNG")
    t("R7 another non-worker gateway -> main-table lookup only, not policy routing/reachability",
      lambda: (lambda r: r["category"] == "DAT_KIEM_QUY_TAC" and r["lookup_scope"] == "proc_net_route_main_only" and r["policy_routing_verified"] is False and r["reachability_verified"] is False)(ER(PROC_ROUTE_OK.replace("013CA8C0", "0A3CA8C0"), "10.200.0.2 dev ens33\n", wk, gw, br)[0]))


    header = PROC_ROUTE_OK.splitlines()[0] + "\n"
    worker_row = "eth1\t00000000\t023CA8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    guest_row = "eth1\t0000C80A\t00000000\t0001\t0\t0\t0\tFCFFFFFF\t0\t0\t0\n"
    safe_row = "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    t("R8 equal-prefix routes all via worker -> FAIL",
      lambda: ER(header + worker_row + worker_row.replace("eth1", "eth2"), "10.200.0.2 dev ens33\n", wk, gw, br)[0]["category"] == "FAIL")
    t("R9 equal-prefix routes all connected guest -> FAIL",
      lambda: ER(header + guest_row + guest_row.replace("eth1", "eth2"), "10.200.0.2 dev ens33\n", wk, gw, br)[0]["category"] == "FAIL")
    t("R10 mixed safe/violating choices -> UNVERIFIED in either row order",
      lambda: all(ER(header + body, "10.200.0.2 dev ens33\n", wk, gw, br)[0]["category"] == "CHUA_KIEM_CHUNG" for body in (safe_row + worker_row, worker_row + safe_row)))


# ------------------------------------------------------------------ S
class FakeSock:
    """Records calls; behaviour chosen by the module-level script."""
    def __init__(self, mod, kind):
        self.mod, self.kind = mod, kind
        self.sent, self.opts = [], []
        self.timeout_value = None
        self.closed = False

    def settimeout(self, v):
        self.timeout_value = v

    def setsockopt(self, *a):
        self.opts.append(a)

    def bind(self, addr):
        if self.mod.bind_error:
            raise OSError(98, "bind failed")
        self.bound = addr

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        if self.mod.send_error:
            raise OSError(self.mod.send_error, "send failed")
        return len(data)

    def connect(self, addr):
        self.connected = addr
        if self.mod.connect_error == "timeout":
            raise self.mod.timeout("timed out")
        if self.mod.connect_error:
            raise OSError(self.mod.connect_error, "connect failed")

    def recvfrom(self, n):
        if self.mod.replies:
            r = self.mod.replies.pop(0)
            return r if isinstance(r, tuple) else (r, ("1.1.1.1", 0))
        raise self.mod.timeout("timed out")

    def close(self):
        self.closed = True


class FakeSocketModule:
    AF_INET, SOCK_RAW, SOCK_STREAM, SOCK_DGRAM, IPPROTO_ICMP, SOL_SOCKET, SO_REUSEADDR = 2, 3, 1, 2, 1, 1, 2
    timeout = type("timeout", (OSError,), {})

    def __init__(self, send_error=0, connect_error=None, create_error=0, bind_error=False, replies=()):
        self.send_error, self.connect_error, self.create_error, self.bind_error = send_error, connect_error, create_error, bind_error
        self.replies = list(replies)
        self.made = []

    def socket(self, fam, kind, proto=0):
        if self.create_error:
            raise OSError(self.create_error, "cannot create")
        s = FakeSock(self, kind)
        self.made.append(s)
        return s


def sec_S():
    now = iter(range(1000, 2000)).__next__
    t("S1 w_send ICMP: 3 sendto, each failure recorded with its errno, nothing real sent",
      lambda: (lambda m: (lambda calls: [c["errno"] for c in calls] == [1, 1, 1] and all(c["ok"] is False for c in calls)
                          and len(m.made[0].sent) == 3 and m.made[0].closed)(C.w_send(WCASES["T20-N1-ICMP"], m, now)))(FakeSocketModule(send_error=1)))
    t("S2 w_send ICMP: send that succeeds is recorded ok True (not hidden)",
      lambda: all(c["ok"] is True and c["errno"] is None for c in C.w_send(WCASES["T20-N1-ICMP"], FakeSocketModule(), now)))
    t("S3 w_send TCP: timeout -> errno 110 recorded as a failed connect; source port bound to 10.200.0.1:31201",
      lambda: (lambda m: (lambda calls: calls[0]["errno"] == 110 and calls[0]["exc"] == "timeout" and m.made[0].bound == ("10.200.0.1", 31201)
                          and m.made[0].connected == ("10.200.0.2", 22))(C.w_send(WCASES["T20-N2-TCP22"], m, now)))(FakeSocketModule(connect_error="timeout")))
    t("S4 w_send TCP: connect OK is recorded ok True (evaluated as FAIL later)",
      lambda: C.w_send(WCASES["T20-N2-TCP80"], FakeSocketModule(), now)[0]["ok"] is True)
    t("S5 w_send UDP: 3 datagrams from 10.200.0.1:31020 to 10.200.0.2:31020",
      lambda: (lambda m: (lambda calls: len(calls) == 3 and m.made[0].bound == ("10.200.0.1", 31020)
                          and all(a == ("10.200.0.2", 31020) for _, a in m.made[0].sent))(C.w_send(WCASES["T20-N3-UDP"], m, now)))(FakeSocketModule(send_error=1)))
    t("S6 w_send: socket creation refused -> one setup_error record, never raises",
      lambda: (lambda calls: len(calls) == 1 and calls[0].get("setup_error") is True and calls[0]["errno"] == 1)(
          C.w_send(WCASES["T20-N1-ICMP"], FakeSocketModule(create_error=1), now)))
    t("S7 w_send: bind failure -> setup_error",
      lambda: C.w_send(WCASES["T20-N2-TCP22"], FakeSocketModule(bind_error=True), now)[0].get("setup_error") is True)
    t("S8 w_send: unknown kind -> setup_error record",
      lambda: C.w_send({"kind": "weird", "dst": "10.200.0.2"}, FakeSocketModule(), now)[0].get("setup_error") is True)
    # icmp_control
    ident = [0]
    def echo_reply_for(m, src):
        pkt = m.made[0].sent[-1][0] if m.made and m.made[0].sent else None
        return pkt

    def control_with(reply_builder):
        m = FakeSocketModule()
        orig_send = FakeSock.sendto
        replies = []

        def sendto(self, data, addr):
            orig_send(self, data, addr)
            r = reply_builder(data, addr)
            if r is not None:
                m.replies.append(r)
        FakeSock.sendto = sendto
        try:
            return C.icmp_control("192.168.177.2", m, timeout=0.3, now=iter([0.0] + [0.1 * i for i in range(1, 400)]).__next__)
        finally:
            FakeSock.sendto = orig_send

    def reply_packet(data, src="192.168.177.2", bad_csum=False, typ=0):
        icmp = bytearray(data)
        icmp[0] = typ
        icmp[2:4] = b"\0\0"
        c = C.icmp_checksum(bytes(icmp)) ^ (0x1111 if bad_csum else 0)
        icmp[2:4] = struct.pack("!H", c)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address("192.168.60.2").packed)
        return ip + bytes(icmp)
    t("S9 icmp_control: a valid echo reply from the same IP is alive",
      lambda: "echo reply" in control_with(lambda d, a: reply_packet(d)))
    t("S10 icmp_control: no reply -> raises (control not alive)", lambda: raises(RuntimeError, lambda: control_with(lambda d, a: None)))
    t("S11 icmp_control: reply from ANOTHER IP / bad checksum / wrong type does not count",
      lambda: all(raises(RuntimeError, lambda r=r: control_with(r)) for r in (lambda d, a: reply_packet(d, "1.1.1.1"), lambda d, a: reply_packet(d, bad_csum=True),
                                                                                lambda d, a: reply_packet(d, typ=8))))


# ------------------------------------------------------------------ X / E: run_group with a stub runner and a fake clock
class Clock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


class StubRunner:
    """Stands for GuardedRunner(guest): records commands, answers, EMITS the frames a real guest would put on tap0 and moves the simulated counters."""
    def __init__(self, clock, frames, counters, answers=None, fail_on=None):
        self.clock, self.frames, self.counters, self.answers, self.fail_on = clock, frames, counters, answers or {}, fail_on
        self.sent, self.stop = [], None

    def _emit(self, fr):
        self.frames.append((self.clock.t, fr))
        cls = L.classify(L.decode(self.clock.t, fr), TAP)[1]
        if cls in self.counters:
            self.counters[cls] += 1
        self.clock.t += 0.005

    def run(self, cmd, timeout=60):
        self.sent.append(cmd)
        self.clock.t += 0.2
        if self.fail_on and self.fail_on in cmd:
            self.stop = RuntimeError("guard: simulated leak")
            raise self.stop
        if cmd == C.BANNER_COMMAND:
            return 0, banner_wire()
        if "/get-task/" in cmd:
            return 0, "HTTP=200\nabc\n"
        for cid, c in CASES.items():
            if cmd == C.command(c):
                for fr in probe_frames(cid):
                    self._emit(fr)
                if c["kind"] == "tcp":
                    return 28, "HTTP=000\n"
                return 1, ""
        return 127, "not found"


def build_world(tmp, name, runner_kw=None, w_control=None, send=None, links=(True, True), stop_on=None):
    clock, frames, counters = Clock(), [], dict(V.BASE)
    reads_path = os.path.join(tmp, name + ".jsonl")
    open(reads_path, "w").close()
    order = []

    def read_counters(label):
        t0 = clock.t
        order.append(("read", label))
        with open(reads_path, "a") as f:
            f.write(json.dumps({"label": label, "t_start": t0, "t_end": t0 + 0.002, "raw": V.raw(counters)}) + "\n")
        clock.t += 0.01

    runner = StubRunner(clock, frames, counters, **(runner_kw or {}))
    n = {"link": 0}

    def service_link():
        ok = links[n["link"]] if n["link"] < len(links) else True
        n["link"] += 1
        return ok, "HTTP 200"

    def default_control(c):
        order.append(("control", c["id"]))
        return {"ts": clock.t, "ok": True, "detail": "stub"}

    def default_send(c):
        order.append(("send", c["id"]))
        counters["drop_out"] += int(c.get("count", 1))
        return [{"op": "connect" if c["kind"] == "w_tcp" else "sendto", "ts": clock.t, "ok": False, "errno": 110 if c["kind"] == "w_tcp" else 1}
                for _ in range(int(c.get("count", 1)))]

    stop_box = []
    guard = None
    if stop_on:
        def guard(label):
            if stop_on in label:
                raise RuntimeError("guard stop " + label)
    return dict(clock=clock, frames=frames, counters=counters, reads=reads_path, runner=runner, read_counters=read_counters, service_link=service_link,
                w_control=w_control or default_control, send=send or default_send, order=order, stop_box=stop_box, guard=guard)


def run_world(w, **kw):
    gcases = C.build_guest_cases("ARM", "192.168.177.2", LAN_OTHER)
    wcases = C.build_w_cases()
    return C.run_group(w["runner"], w["read_counters"], w["service_link"], gcases, wcases, "eth1", "ARM", TAP, w_control=w["w_control"], send=w["send"],
                       guard_before=w["guard"], guard_after=w["guard"], sleep=w["clock"].sleep, stop_box=w["stop_box"], now=w["clock"].now, **kw)


def sec_X(tmp):
    w = build_world(tmp, "x1")
    rec = run_world(w)
    labels = [json.loads(l)["label"] for l in open(w["reads"])]
    t("X1 order: link, six guest cases, worker cases (banner immediately before N2-22 A), link",
      lambda: [c["id"] for c in rec["guest_cases"]] == list(C.GUEST_CASE_IDS) and [c["id"] for c in rec["w_cases"]] == list(C.W_CASE_IDS)
      and labels == [x for cid in C.ALL_CASE_IDS for x in (f"{cid} before", f"{cid} after")] and w["runner"].sent[6] == C.BANNER_COMMAND
      and rec["service_link_before"]["ok"] and rec["service_link_after"]["ok"])
    t("X2 live controls are taken BEFORE the read A and AFTER the read B of their own case only",
      lambda: [e for e in w["order"] if e[0] == "control"] == [("control", "T05-DNS-8888")] * 2 + [("control", "T06-ICMP-LANDNS")] * 2
      and w["order"].index(("control", "T05-DNS-8888")) < w["order"].index(("read", "T05-DNS-8888 before"))
      and w["order"].index(("read", "T05-DNS-8888 after")) < max(i for i, e in enumerate(w["order"]) if e == ("control", "T05-DNS-8888")))
    t("X3b every control record is bound to its case and phase, every call list to its case",
      lambda: all(g["control_before"]["binding"] == C.control_binding(CASES[g["id"]], "before")
                  and g["control_after"]["binding"] == C.control_binding(CASES[g["id"]], "after") for g in rec["guest_cases"] if g["id"] in ("T05-DNS-8888", "T06-ICMP-LANDNS"))
      and all(wc["send_binding"] == C.send_binding(WCASES[wc["id"]]) for wc in rec["w_cases"]))
    t("X3 guest banner control recorded; commands are exactly those of the cases",
      lambda: rec["guest_banner_control"]["ok"] is True
      and [x for x in w["runner"].sent if x != C.BANNER_COMMAND and "/get-task/" not in x] == [C.command(CASES[c]) for c in C.GUEST_CASE_IDS])
    t("X4 service link before failed -> skipped, no command, no read, no control, no send",
      lambda: (lambda w2, r2: r2.get("skipped") and not w2["runner"].sent and not w2["order"])(*(lambda w2: (w2, run_world(w2)))(build_world(tmp, "x4", links=(False,)))))
    w3 = build_world(tmp, "x5", w_control=lambda c: (_ for _ in ()).throw(RuntimeError("control exploded")))
    r3 = run_world(w3)
    t("X5 a control callback that raises -> run_group never raises; the control is recorded as NOT alive (live cases will not be judged)",
      lambda: r3["guest_cases"][0]["control_before"]["ok"] is False and "control exploded" in r3["guest_cases"][0]["control_before"]["detail"])
    w3b = build_world(tmp, "x5b", send=lambda c: (_ for _ in ()).throw(RuntimeError("send exploded")))
    r3b = run_world(w3b)
    t("X5b a sender that raises -> recorded as a setup error (LOI_THUC_THI later), never raised",
      lambda: r3b["w_cases"][0]["calls"][0].get("setup_error") is True and "send exploded" in r3b["w_cases"][0]["calls"][0]["exc"])
    w4 = build_world(tmp, "x6", runner_kw={"fail_on": C.command(CASES["T06-TCP-LAN2"])})
    r4 = run_world(w4)
    t("X6 a guard stop during a guest command: the case is recorded, the following cases (guest and worker) are not run, stop is kept",
      lambda: w4["runner"].stop is not None and r4["stopped"] and all(c.get("not_run") for c in r4["guest_cases"][3:] + r4["w_cases"])
      and w4["stop_box"] and not [e for e in w4["order"] if e[0] == "send"])
    w5 = build_world(tmp, "x7", stop_on="before T20-N2-TCP22")
    r5 = run_world(w5)
    t("X7 a guard stop before a worker case: that case and later ones are not sent; earlier results kept",
      lambda: [e for e in w5["order"] if e[0] == "send"] == [("send", "T20-N1-ICMP")] and r5["w_cases"][1].get("not_run") and r5["w_cases"][2].get("not_run")
      and w5["stop_box"] and "guard stop" in r5["stopped"])
    # F1: an alert that appears during read A (after the guard before it) must stop the case before anything is sent
    def alert_in_read(label_hit, sender_log):
        w = build_world(tmp, "x10-" + label_hit.replace(" ", "_"))
        state = {"alert": False}
        orig = w["read_counters"]

        def reading(label):
            orig(label)
            if label == label_hit:
                state["alert"] = True                      # the leak monitor wrote its alert while read A was running

        def guard(label):
            if state["alert"]:
                raise RuntimeError("LeakDetected: alert during " + label)
        w["read_counters"], w["guard"] = reading, guard
        w["send"] = lambda c: (sender_log.append(c["id"]), [{"op": "sendto", "ts": w["clock"].t, "ok": False, "errno": 1}] * int(c.get("count", 1)))[1]
        return w, run_world(w)
    sent10 = []
    w10, r10 = alert_in_read("T20-N2-TCP22 before", sent10)
    t("X10 an alert raised in read A of T20-N2-TCP22: NOTHING is sent for it or later; stop reason kept; earlier cases kept; cleanup path reached (record returned)",
      lambda: sent10 == ["T20-N1-ICMP"] and w10["stop_box"] and "alert during" in r10["stopped"] and r10["w_cases"][1].get("not_sent") is True
      and "alert during" in r10["w_cases"][1]["not_run"] and all(c.get("not_run") for c in r10["w_cases"][2:]) and r10["w_cases"][0].get("calls")
      and r10["service_link_after"] is not None)
    ev10 = C.evaluate_w_case([], {}, WCASES["T20-N2-TCP22"], r10["w_cases"][1], r10["guest_banner_control"], True, True)
    t("X10b the evaluator reports that case as CHƯA KIỂM CHỨNG with not_sent, never a result",
      lambda: ev10["category"] == "CHUA_KIEM_CHUNG" and ev10["not_sent"] is True and "alert during" in ev10["verdict"])
    sent10b = []
    w10b, r10b = alert_in_read("T20-N1-ICMP before", sent10b)
    t("X10c an alert raised in read A of the FIRST worker case: no worker case sends anything",
      lambda: sent10b == [] and all(c.get("not_run") for c in r10b["w_cases"]) and w10b["stop_box"])
    sent10c = []
    w10c, r10c = alert_in_read("T11-TCP22 before", sent10c)
    t("X10d an alert raised in read A of a guest case: its command is not the subject (guarded by the runner); no worker case sends",
      lambda: sent10c == [] and w10c["stop_box"] and all(c.get("not_run") for c in r10c["w_cases"]))
    t("X8 read_counters that raises is recorded as read_error (no retry), command still runs",
      lambda: _read_error(tmp))
    t("X9 service link raises -> recorded failed, group skipped, never raises",
      lambda: (lambda r: r.get("skipped") and r["service_link_before"]["ok"] is False)(
          C.run_group(StubRunner(Clock(), [], {}), lambda l: None, lambda: (_ for _ in ()).throw(RuntimeError("curl")), [], [], "eth1", "ARM", TAP)))


def _never_raises(w):
    try:
        rec = run_world(w)
    except Exception:
        return False
    # the control exception propagates through run_group (it is the CALLER's callback contract: probe_matrix.run_ctl never raises)
    return True


def _read_error(tmp):
    w = build_world(tmp, "x8")
    cnt = {"n": 0}
    orig = w["read_counters"]

    def flaky(label):
        cnt["n"] += 1
        if label == "T11-TCP22 before":
            raise RuntimeError("nft exploded")
        return orig(label)
    w["read_counters"] = flaky
    rec = run_world(w)
    c = [x for x in rec["guest_cases"] if x["id"] == "T11-TCP22"][0]
    return "nft exploded" in c["read_error"] and c["exec"]["rc"] == 28 and sum(1 for e in w["runner"].sent if e == C.command(CASES["T11-TCP22"])) == 1


def sec_E(tmp):
    w = build_world(tmp, "e1")
    rec = run_world(w)
    pc = V.pcapng(os.path.join(tmp, "e1.pcapng"), w["frames"])
    res = C.evaluate_group(pc, w["reads"], TAP, rec, "192.168.177.2", LAN_OTHER)
    cats = {c["id"]: c["category"] for c in res["cases"]}
    t("E1 end to end clean: live DNS/ICMP -> DAT, the rest -> DAT_KIEM_QUY_TAC, T20-N2-22 with the banner -> DAT; group exit 0, closure not used",
      lambda: res["record_problems"] == [] and res["group_exit"] == 0 and res["closure_used_for_verdict"] is False
      and cats == {"T05-DNS-8888": "DAT", "T06-ICMP-LANDNS": "DAT", "T06-TCP-LAN2": "DAT_KIEM_QUY_TAC", "T11-TCP22": "DAT_KIEM_QUY_TAC",
                   "T11-TCP80": "DAT_KIEM_QUY_TAC", "T11-ICMP": "DAT_KIEM_QUY_TAC", "T20-N1-ICMP": "DAT_KIEM_QUY_TAC", "T20-N2-TCP22": "DAT",
                   "T20-N2-TCP80": "DAT_KIEM_QUY_TAC", "T20-N3-UDP": "DAT_KIEM_QUY_TAC"})
    # failing DNS control -> only that case is not judged
    w2 = build_world(tmp, "e2")
    w2["w_control"] = lambda c: {"ts": w2["clock"].t, "ok": c["control"] != "w_dns", "detail": "no answer" if c["control"] == "w_dns" else "x"}
    rec2 = run_world(w2)
    r2 = C.evaluate_group(V.pcapng(os.path.join(tmp, "e2.pcapng"), w2["frames"]), w2["reads"], TAP, rec2, "192.168.177.2", LAN_OTHER)
    t("E2 failed live control for T05 -> that case CHUA_KIEM_CHUNG, group exit 4 (never 0)",
      lambda: {c["id"]: c["category"] for c in r2["cases"]}["T05-DNS-8888"] == "CHUA_KIEM_CHUNG" and r2["group_exit"] == 4)
    # delta without frame (drop_out never moved) -> T20 not judged
    w3 = build_world(tmp, "e3")
    w3["send"] = lambda c: [{"op": "connect" if c["kind"] == "w_tcp" else "sendto", "ts": w3["clock"].t, "ok": False, "errno": 110 if c["kind"] == "w_tcp" else 1}
                            for _ in range(int(c.get("count", 1)))]
    rec3 = run_world(w3)
    r3 = C.evaluate_group(V.pcapng(os.path.join(tmp, "e3.pcapng"), w3["frames"]), w3["reads"], TAP, rec3, "192.168.177.2", LAN_OTHER)
    t("E3 drop_out never increased -> every T20 case CHUA_KIEM_CHUNG, group exit 4",
      lambda: all(c["category"] == "CHUA_KIEM_CHUNG" for c in r3["cases"] if c["id"].startswith("T20")) and r3["group_exit"] == 4)
    # missing counters file / pcap -> measurement error
    r4 = C.evaluate_group(os.path.join(tmp, "nope.pcapng"), w["reads"], TAP, rec, "192.168.177.2", LAN_OTHER)
    t("E4 unreadable pcap -> every case LOI_PHEP_DO, exit 2, never PASS",
      lambda: r4["group_exit"] == 2 and all(c["category"] == "LOI_PHEP_DO" for c in r4["cases"]))
    r5 = C.evaluate_group(pc, os.path.join(tmp, "nope.jsonl"), TAP, rec, "192.168.177.2", LAN_OTHER)
    t("E5 unreadable counters -> every case LOI_PHEP_DO, exit 2",
      lambda: r5["group_exit"] == 2 and all(c["category"] == "LOI_PHEP_DO" for c in r5["cases"]))
    bad = copy.deepcopy(rec)
    bad["guest_cases"] = bad["guest_cases"][:-1]
    r6 = C.evaluate_group(pc, w["reads"], TAP, bad, "192.168.177.2", LAN_OTHER)
    t("E6 a case missing from the record -> record problem, that case CHUA_KIEM_CHUNG, exit 4, never 0",
      lambda: r6["record_problems"] and r6["group_exit"] == 4 and {c["id"]: c["category"] for c in r6["cases"]}["T11-ICMP"] == "CHUA_KIEM_CHUNG")
    dup = copy.deepcopy(rec)
    dup["guest_cases"].append(copy.deepcopy(dup["guest_cases"][0]))
    r7 = C.evaluate_group(pc, w["reads"], TAP, dup, "192.168.177.2", LAN_OTHER)
    t("E7 a duplicated case id -> record problem and a LOI_PHEP_DO row, never 0",
      lambda: r7["record_problems"] and r7["group_exit"] != 0)
    wrong = dict(copy.deepcopy(rec), arch="MIPS")
    r8 = C.evaluate_group(pc, w["reads"], TAP, wrong, "192.168.177.2", LAN_OTHER)
    t("E8 record for the other architecture's names still evaluated, but the caller's arch check (outcome) rejects a mismatch",
      lambda: H.arch_outcome({"results": [], "status": "COMPLETED"}, {"arch": "ARM", "record_problems": [], "group_exit": 0, "cases": []}, "MIPS").startswith("FAIL"))
    r9 = C.evaluate_group(pc, w["reads"], TAP, dict(rec, tap_mac="02:00:00:00:00:99"), "192.168.177.2", LAN_OTHER)
    t("E9 record TAP MAC differs from the evaluated TAP MAC -> record problem, never 0",
      lambda: r9["record_problems"] and r9["group_exit"] != 0)
    r10 = C.evaluate_group(pc, w["reads"], TAP, {"not": "a record"}, "192.168.177.2", LAN_OTHER)
    t("E10 a record of the wrong schema -> every case LOI_PHEP_DO, exit 2", lambda: r10["group_exit"] == 2 and all(c["category"] == "LOI_PHEP_DO" for c in r10["cases"]))
    # service link failed after the group
    rec_l = copy.deepcopy(rec)
    rec_l["service_link_after"] = {"ok": False, "detail": "HTTP=000"}
    r11 = C.evaluate_group(pc, w["reads"], TAP, rec_l, "192.168.177.2", LAN_OTHER)
    t("E11 service link after failed -> no case is ĐẠT, exit 4",
      lambda: r11["group_exit"] == 4 and not any(c["ok"] for c in r11["cases"]))
    # CLI
    import subprocess
    rf = os.path.join(tmp, "e1.record.json")
    json.dump(rec, open(rf, "w"))
    p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "b1_cases.py"), "--pcap", pc, "--counters", w["reads"], "--tap-mac", TAP, "--record", rf,
                        "--lan-other", LAN_OTHER, "--out", os.path.join(tmp, "e1.out.json")], capture_output=True, text=True)
    t("E12 CLI exit 0 on the clean group; nonexistent pcap -> exit 2",
      lambda: p.returncode == 0 and subprocess.run([sys.executable, "-B", os.path.join(HERE, "b1_cases.py"), "--pcap", "/nonexistent", "--counters", w["reads"], "--tap-mac", TAP,
                                                    "--record", rf, "--lan-other", LAN_OTHER], capture_output=True, text=True).returncode == 2)


# ------------------------------------------------------------------ H
def sec_H(tmp):
    def result_for(res, extra_fail=None, status="COMPLETED", drop=None):
        recs = [{"test": n, "ok": True} for n in H.REQUIRED_RECORDS]
        for c in res["cases"]:
            recs.append({"test": H.case_test_name(c), "ok": c["ok"]})
        if extra_fail:
            recs.append({"test": extra_fail, "ok": False})
        if drop:
            recs = [r for r in recs if r["test"] != drop]
        return {"status": status, "results": recs}
    w = build_world(tmp, "h1")
    rec = run_world(w)
    res = C.evaluate_group(V.pcapng(os.path.join(tmp, "h1.pcapng"), w["frames"]), w["reads"], TAP, rec, "192.168.177.2", LAN_OTHER)
    res["arch"] = "ARM"
    t("H1 clean group + required records -> PASS", lambda: H.arch_outcome(result_for(res), res, "ARM") == "PASS")
    t("H2 a required record missing -> FAIL", lambda: H.arch_outcome(result_for(res, drop=H.ALL_CASES_NAME), res, "ARM").startswith("FAIL"))
    t("H3 status not COMPLETED -> FAIL", lambda: H.arch_outcome(result_for(res, status="ERROR: x"), res, "ARM").startswith("FAIL"))
    t("H4 b1-eval missing -> FAIL", lambda: H.arch_outcome(result_for(res), None, "ARM").startswith("FAIL"))
    t("H5 arch mismatch -> FAIL", lambda: H.arch_outcome(result_for(res), res, "MIPS").startswith("FAIL"))
    r_un = copy.deepcopy(res)
    r_un["cases"][0].update(category="CHUA_KIEM_CHUNG", ok=False, verdict="CHƯA KIỂM CHỨNG (không có đối chứng sống)")
    r_un["group_exit"] = 4
    t("H6 one CHƯA KIỂM CHỨNG case -> UNVERIFIED (not PASS)", lambda: H.arch_outcome(result_for(r_un), r_un, "ARM").startswith("UNVERIFIED"))
    r_fail = copy.deepcopy(res)
    r_fail["cases"][1].update(category="FAIL", ok=False, verdict="FAIL")
    r_fail["group_exit"] = 1
    t("H7 one FAIL case -> FAIL", lambda: H.arch_outcome(result_for(r_fail), r_fail, "ARM").startswith("FAIL"))
    r_me = copy.deepcopy(res)
    r_me["cases"][2].update(category="LOI_PHEP_DO", ok=False, verdict="LỖI PHÉP ĐO (x)")
    r_me["group_exit"] = 2
    t("H8 a measurement error -> FAIL outcome, never PASS", lambda: H.arch_outcome(result_for(r_me), r_me, "ARM").startswith("FAIL"))
    r_dup = copy.deepcopy(res)
    r_dup["cases"].append(copy.deepcopy(r_dup["cases"][0]))
    t("H9 duplicated case in the evaluation -> FAIL", lambda: H.arch_outcome(result_for(r_dup), r_dup, "ARM").startswith("FAIL"))
    pd = os.path.join(tmp, "probe")
    for a in ("ARM", "MIPS"):
        os.makedirs(os.path.join(pd, a), exist_ok=True)
        json.dump(dict(res, arch=a), open(os.path.join(pd, a, H.EVAL_FILE), "w"))
    t("H10 run-check: both architectures with every case once -> no problem; a missing file/arch/case is a problem",
      lambda: H.run_check(pd, ["ARM", "MIPS"]) == [] and H.run_check(pd, ["ARM", "MIPS", "X"]) and H.run_check(pd, ["ARM", "ARM"]) and H.run_check(pd, []))
    n4, n5 = os.path.join(tmp, "n4.txt"), os.path.join(tmp, "n5.txt")
    open(n4, "w").write(PROC_ROUTE_OK)
    open(n5, "w").write("10.200.0.2 via 192.168.177.2 dev ens33 src 192.168.177.128 uid 0\n")
    rc0, rc1, rcbad = os.path.join(tmp, "rc0.txt"), os.path.join(tmp, "rc1.txt"), os.path.join(tmp, "rcbad.txt")
    open(rc0, "w").write("0\n")
    open(rc1, "w").write("1\n")
    open(rcbad, "w").write("0 and more\n")
    args = ("192.168.60.2", "192.168.60.1", "br-1d86fe3e8bbe")
    t("H11 route-check: clean -> rc 0 PASS; missing file -> rc 2 LOI_PHEP_DO; via worker -> rc 1",
      lambda: H.route_check(n4, n5, *args, rc0, rc0)[1] == 0
      and H.route_check(n4, os.path.join(tmp, "none"), *args, rc0, rc0)[1] == 2
      and H.route_check(n4, (open(n5, "w").write("10.200.0.2 via 192.168.60.2 dev br-1d86fe3e8bbe\n"), n5)[1], *args, rc0, rc0)[1] == 1)
    open(n5, "w").write("10.200.0.2 via 192.168.177.2 dev ens33 src 192.168.177.128 uid 0\n")
    t("H12 route-check: clean evidence but the manager read returned rc 1 -> rc 2 LOI_PHEP_DO, never PASS",
      lambda: (lambda r: r[1] == 2 and r[0].startswith("LOI_PHEP_DO") and "rc 1" in r[0])(H.route_check(n4, n5, *args, rc1, rc0)))
    t("H13 route-check: clean evidence but the host `ip route get` returned rc 1 -> rc 2 LOI_PHEP_DO, never PASS",
      lambda: (lambda r: r[1] == 2 and r[0].startswith("LOI_PHEP_DO"))(H.route_check(n4, n5, *args, rc0, rc1)))
    t("H14 route-check: rc file missing / not exactly one integer -> rc 2, never PASS",
      lambda: H.route_check(n4, n5, *args, os.path.join(tmp, "none.rc"), rc0)[1] == 2 and H.route_check(n4, n5, *args, rc0, rcbad)[1] == 2)
    t("H15 route-check: an N4 FAIL (via the worker) stays FAIL (rc 1) next to an N5 read error (both kept in the text)",
      lambda: (lambda r: r[1] == 1 and "T20-N4" in r[0] and "T20-N5" in r[0])(
          H.route_check((open(n4, "w").write(PROC_ROUTE_OK.replace("013CA8C0", "023CA8C0")), n4)[1], n5, *args, rc0, rc1)))
    open(n4, "w").write(PROC_ROUTE_OK)


# ------------------------------------------------------------------ F: findings of the independent review of R12
def _dns_reply(q, flags=0x8183, qd=1, name=None, qtype=1, qclass=1, ancount=0, idxor=0, cut=None):
    qid = struct.unpack("!H", q[:2])[0] ^ idxor
    question = q[12:] if name is None else C.dns_query(0, name)[12:]
    question = question[:-4] + struct.pack("!HH", qtype, qclass)
    r = struct.pack("!HHHHHH", qid, flags, qd, ancount, 0, 0) + question
    # A positive answer-count control must contain the declared RR bytes.
    # Previously F2-2 used ANCOUNT=1 with no answer, the R13-N2 failure.
    r += (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01") * ancount
    return r[:cut] if cut is not None else r


def _dns_control(builder, server="8.8.8.8", qname="ct01-06b3b-ctl-arm.example"):
    m = FakeSocketModule()
    orig = FakeSock.sendto
    seen = {}

    def sendto(self, data, addr):
        orig(self, data, addr)
        seen["query"], seen["addr"] = data, addr
        for r in builder(data):
            m.replies.append(r)
    FakeSock.sendto = sendto
    try:
        out = C.dns_control(server, qname, m, timeout=0.3, now=iter([0.0] + [0.01 * i for i in range(1, 400)]).__next__)
        return out, seen
    finally:
        FakeSock.sendto = orig


def sec_F(tmp):
    SRV = ("8.8.8.8", 53)
    # --- F2: DNS control
    t("F2-1 dns_control: a well-formed response (NXDOMAIN) to our query from 8.8.8.8:53 is alive; the query goes to 8.8.8.8:53",
      lambda: (lambda r: "rcode=3" in r[0] and r[1]["addr"] == ("8.8.8.8", 53))(_dns_control(lambda q: [(_dns_reply(q), SRV)])))
    t("F2-2 dns_control: NOERROR with an answer count is alive", lambda: "rcode=0" in _dns_control(lambda q: [(_dns_reply(q, flags=0x8180, ancount=1), SRV)])[0])
    t("F2-3 dns_control: a datagram from another IP/port is ignored, a later valid one from the server is accepted",
      lambda: "rcode=3" in _dns_control(lambda q: [(_dns_reply(q), ("203.0.113.9", 53)), (_dns_reply(q), ("8.8.8.8", 9999)), (_dns_reply(q), SRV)])[0])
    for n, build in (("reply only from another IP", lambda q: [(_dns_reply(q), ("203.0.113.9", 53))]),
                     ("reply only from another port", lambda q: [(_dns_reply(q), ("8.8.8.8", 9999))]),
                     ("the 4-byte id-only reply the review used (other endpoint)", lambda q: [(q[:2] + b"\x00\x00", ("203.0.113.9", 9999))]),
                     ("4-byte id-only reply from the server", lambda q: [(q[:2] + b"\x00\x00", SRV)]),
                     ("id mismatch", lambda q: [(_dns_reply(q, idxor=1), SRV)]),
                     ("QR bit clear (a query echoed back)", lambda q: [(_dns_reply(q, flags=0x0100), SRV)]),
                     ("non-standard opcode", lambda q: [(_dns_reply(q, flags=0x9183), SRV)]),
                     ("question name differs", lambda q: [(_dns_reply(q, name="other.example"), SRV)]),
                     ("no question echoed", lambda q: [(_dns_reply(q, qd=0), SRV)]),
                     ("question type differs", lambda q: [(_dns_reply(q, qtype=28), SRV)]),
                     ("question class differs", lambda q: [(_dns_reply(q, qclass=3), SRV)]),
                     ("truncated inside the question", lambda q: [(_dns_reply(q, cut=20), SRV)]),
                     ("header only", lambda q: [(_dns_reply(q, cut=12), SRV)]),
                     ("declared answer missing", lambda q: [(_dns_reply(q, ancount=1)[:-16], SRV)]),
                     ("rcode SERVFAIL", lambda q: [(_dns_reply(q, flags=0x8182), SRV)]),
                     ("rcode REFUSED", lambda q: [(_dns_reply(q, flags=0x8185), SRV)]),
                     ("no reply at all", lambda q: [])):
        t(f"F2-4 dns_control: {n} -> not alive (raises)", lambda build=build: raises(Exception, lambda: _dns_control(build)))
    # --- F2: banner record
    BS = C.banner_state
    t("F2-5 banner_state: valid alive / valid dead / missing / tool missing, each distinguished",
      lambda: BS(good_banner())[0] == "alive" and BS(dead_banner())[0] == "dead_valid" and BS(None)[0] == "missing"
      and BS({"command": C.BANNER_COMMAND, "ok": False, "error": "OSError: x", "ts": 1.0})[0] == "tool_missing"
      and BS(good_banner(rc=127, ok=False, output_tail="sh: nc: not found"))[0] == "tool_missing")
    for n, b in (("not an object", [1]), ("extra key", good_banner(extra=1)), ("other command", good_banner(command="echo | nc 1.1.1.1 22")),
                 ("ts NaN", good_banner(ts=float("nan"))), ("ts missing", {k: v for k, v in good_banner().items() if k != "ts"}),
                 ("ok not boolean", good_banner(ok="true")), ("ok true but rc 1", good_banner(rc=1)),
                 ("ok true but no banner text", good_banner(output_tail="hello")), ("ok false but rc 0 and a banner", good_banner(ok=False)),
                 ("rc a string", good_banner(rc="0")), ("rc a boolean", good_banner(rc=False)), ("output not a string", good_banner(output_tail=None)),
                 ("error with ok true", {"command": C.BANNER_COMMAND, "ok": True, "error": "x", "ts": 1.0})):
        t(f"F2-6 banner_state: {n} -> invalid", lambda b=b: C.banner_state(b)[0] == "invalid")
    for n, banner, cat in (("missing", None, "CHUA_KIEM_CHUNG"), ("malformed", good_banner(ts=float("nan")), "LOI_PHEP_DO"),
                           ("tool missing", {"command": C.BANNER_COMMAND, "ok": False, "error": "RuntimeError: x", "ts": 1.0}, "LOI_THUC_THI")):
        t(f"F2-7 T20-N2-TCP22 with a {n} banner record -> {cat}, never ĐẠT",
          lambda banner=banner, cat=cat, n=n: (lambda r: r["category"] == cat and not r["ok"])(
              one_w(tmp, "f27" + n.replace(" ", ""), "T20-N2-TCP22", extra={"drop_out": 1}, banner_ok=banner)))
    # --- F3: call-record schema, binding, order, window
    pid = "T20-N1-ICMP"
    cf = calls_for(pid)
    BAD = {
        "review object (op not-a-send, ts NaN, errno true)": [{"op": "not-a-send", "ts": float("nan"), "ok": False, "errno": True}],
        "one record where three are required": cf[:1], "four records": cf + cf[:1], "empty list": [],
        "wrong op": [dict(c, op="connect") for c in cf],
        "errno boolean": [dict(c, errno=True) for c in cf], "errno zero": [dict(c, errno=0) for c in cf],
        "errno negative": [dict(c, errno=-1) for c in cf], "errno string": [dict(c, errno="1") for c in cf],
        "errno missing": [{k: v for k, v in c.items() if k != "errno"} for c in cf],
        "ok string": [dict(c, ok="false") for c in cf], "ok success with an errno": [dict(c, ok=True, errno=1) for c in cf],
        "ts NaN": [dict(cf[0], ts=float("nan"))] + cf[1:], "ts string": [dict(cf[0], ts="100.5")] + cf[1:],
        "ts before read A": [dict(c, ts=c["ts"] - 5) for c in cf], "ts after read B": [dict(c, ts=c["ts"] + 20) for c in cf],
        "ts goes backwards": [cf[1], cf[0], cf[2]],
        "extra key": [dict(cf[0], note="x")] + cf[1:], "exc not a string": [dict(cf[0], exc=5)] + cf[1:],
        "setup_error plus more records": [{"op": "socket", "ts": 100.5, "ok": False, "errno": 1, "exc": "x", "setup_error": True}] + cf,
        "setup_error with ok true": [{"op": "socket", "ts": 100.5, "ok": True, "errno": None, "exc": "x", "setup_error": True}],
        "setup_error without exc": [{"op": "socket", "ts": 100.5, "ok": False, "errno": 1, "setup_error": True}],
        "not a list": "garbage", "list of non-objects": [1, 2, 3],
    }
    for k, (n, calls) in enumerate(BAD.items()):
        t(f"F3-1 {pid} drop_out +3 with call record '{n}' -> never ĐẠT (LỖI PHÉP ĐO)",
          lambda calls=calls, k=k: (lambda r: r["category"] == "LOI_PHEP_DO" and not r["ok"])(
              one_w(tmp, f"f31-{k}", pid, over={"calls": calls}, extra={"drop_out": 3})))
    t("F3-2 send_binding of another case / missing -> LỖI PHÉP ĐO",
      lambda: one_w(tmp, "f32a", pid, over={"send_binding": C.send_binding(WCASES["T20-N3-UDP"])}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO"
      and one_w(tmp, "f32b", pid, over={"send_binding": None}, extra={"drop_out": 3})["category"] == "LOI_PHEP_DO")
    t("F3-3 a valid setup-error record (one socket record, PermissionError) -> LOI_THUC_THI with the record kept",
      lambda: (lambda r: r["category"] == "LOI_THUC_THI" and r["calls"][0]["exc"] == "PermissionError")(
          one_w(tmp, "f33", pid, over={"calls": [{"op": "socket", "ts": 100.5, "ok": False, "errno": 1, "exc": "PermissionError", "setup_error": True}]},
                extra={"drop_out": 3})))
    t("F3-4 a valid record with every call failed and drop_out +3 stays ĐẠT (kiểm quy tắc): the validation is not blanket rejection",
      lambda: one_w(tmp, "f34", pid, extra={"drop_out": 3})["category"] == "DAT_KIEM_QUY_TAC")
    # --- F5: sizes against the MTU, scanner unchanged
    t("F5-1 T06 ICMP size 1406 -> IPv4 total length 1434 <= MTU 1500; every ICMP guest case fits one datagram",
      lambda: CASES["T06-ICMP-LANDNS"]["size"] == 1406 and S.ICMP4_SIZES["T06-B"] + 28 == 1434
      and all(int(c["size"]) + 28 <= C.MTU for c in CASES.values() if c["kind"] == "icmp"))

    def oversize():
        old = S.ICMP4_SIZES["T06-B"]
        S.ICMP4_SIZES["T06-B"] = 1606
        try:
            return raises(ValueError, lambda: C.build_guest_cases("ARM", lan_other=LAN_OTHER))
        finally:
            S.ICMP4_SIZES["T06-B"] = old
    t("F5-2 a size that would be fragmented at MTU 1500 (1606) is refused when the cases are built", oversize)

    def scan_frames(frames, name):
        pc = V.pcapng(os.path.join(tmp, name + ".pcapng"), spaced(frames))
        return SC.scan(pc, None)
    src_mac = "02:00:00:00:00:01"
    g06 = [B.eth(TAP, src_mac, 0x0800, B.ipv4("192.168.60.2", "192.168.177.2", 1, B.icmp(1406))) for _ in range(3)]
    g11 = [B.eth(TAP, src_mac, 0x0800, B.ipv4("192.168.60.2", "10.200.0.1", 1, B.icmp(1111))) for _ in range(3)]
    sc = scan_frames(g06 + g11, "f5-scan")
    t("F5-3 the unchanged host scanner recognizes the T06 (1434) and T11 (1139) echo frames as built by the probe, nothing unscannable",
      lambda: sc["icmp_size"] == 6 and sc["unscannable_truncated"] == 0 and sc["unscannable_undecoded"] == 0)
    body = B.icmp(1606)
    frag = [B.eth(TAP, src_mac, 0x0800, B.ipv4("192.168.60.2", "192.168.177.2", 1, p, frag=f)) for p, f in [(body[:1480], 0x2000), (body[1480:], 185)]]
    t("F5-4 scanner NOT relaxed: fragments of a 1606 echo are still not recognized (that is why the size changed, not the scanner)",
      lambda: scan_frames(frag, "f5-frag")["icmp_size"] == 0)
    t("F5-5 evaluator: three unfragmented 1434-byte echo frames -> probe frames identified, ĐẠT with a live control",
      lambda: (lambda r: r["category"] == "DAT" and r["probe_frames"] == 3)(
          one_guest(tmp, "f55", "T06-ICMP-LANDNS", spaced(probe_frames("T06-ICMP-LANDNS")))))

    def worker_icmp_lengths():
        m = FakeSocketModule(send_error=1)
        C.w_send(WCASES["T20-N1-ICMP"], m, iter(range(1000, 2000)).__next__)
        return [len(d) + 20 for d, _ in m.made[0].sent]
    t("F5-6 real bytes made by w_send (T20-N1): three echoes of IPv4 length 1248 <= MTU", lambda: worker_icmp_lengths() == [1248] * 3)

    # --- F6: an independent FAIL is kept next to a measurement error
    def guest_ok_exec():
        return {"exec": {"rc": 0, "output_tail": "HTTP=200", "guest_failed": False}}
    t("F6-1 guest reached the destination + control record invalid -> FAIL, the measurement error kept next to it",
      lambda: (lambda r: r["category"] == "FAIL" and "guest_connection_failed" in r["failed"] and r["measurement_errors"] and r["control_state"] == "invalid")(
          one_guest(tmp, "f61", "T05-DNS-8888", spaced(probe_frames("T05-DNS-8888")),
                    dict(guest_ok_exec(), control_before=ctl("T05-DNS-8888", "before", ok="yes")))))
    t("F6-2 guest reached the destination + read error -> FAIL (not LỖI PHÉP ĐO), the read error and the guest record kept",
      lambda: (lambda r: r["category"] == "FAIL" and "guest_connection_failed" in r["failed"] and "nft" in r["measurement_errors"][0] and r["exec"]["rc"] == 0)(
          one_guest(tmp, "f62", "T11-TCP22", spaced(probe_frames("T11-TCP22")), dict(guest_ok_exec(), read_error="read 'x': RuntimeError: nft"))))

    def recon_error():
        recs = [V.rec("T11-TCP22 before", 100.0, 100.01, dict(V.BASE, drop_worker_other=5)),
                V.rec("T11-TCP22 after", 110.0, 110.01, dict(V.BASE, drop_worker_other=2))]
        pc, cfile, rec = scenario(tmp, "f63", [("T11-TCP22", spaced(probe_frames("T11-TCP22")), guest_ok_exec(), None)], reads_override=recs)
        return C.evaluate_guest_case(L.classified_frames(pc, TAP), l2eval.load_reads(cfile), CASES["T11-TCP22"], rec["guest_cases"][0], True, True)
    t("F6-3 guest reached the destination + a decreasing counter (measurement error) -> FAIL kept with the error",
      lambda: (lambda r: r["category"] == "FAIL" and "guest_connection_failed" in r["failed"] and r["measurement_errors"])(recon_error()))
    t("F6-4 the same measurement error WITHOUT an independent failure stays LỖI PHÉP ĐO",
      lambda: one_guest(tmp, "f64", "T11-TCP22", spaced(probe_frames("T11-TCP22")), {"read_error": "read 'x': RuntimeError: nft"})["category"] == "LOI_PHEP_DO")
    t("F6-5 connect() succeeded + read error -> FAIL (connect_succeeded) with the error and the calls kept",
      lambda: (lambda r: r["category"] == "FAIL" and "connect_succeeded" in r["failed"] and r["measurement_errors"] and r["calls"])(
          one_w(tmp, "f65", "T20-N2-TCP80", over={"calls": calls_for("T20-N2-TCP80", ok=True), "read_error": "read x: boom"}, extra={"drop_out": 1})))
    t("F6-6 connect() succeeded + a malformed field in the same record -> FAIL kept with the record problems",
      lambda: (lambda r: r["category"] == "FAIL" and "connect_succeeded" in r["failed"] and r["measurement_errors"])(
          one_w(tmp, "f66", "T20-N2-TCP80", over={"calls": calls_for("T20-N2-TCP80", ok=True, extra_field=1)}, extra={"drop_out": 1})))
    t("F6-7 connect() succeeded + drop_out counter missing -> FAIL kept",
      lambda: (lambda r: r["category"] == "FAIL" and "connect_succeeded" in r["failed"])(_w_connect_without_drop_out(tmp)))
    t("F6-8 FAIL + measurement error in one group -> group exit 1 (FAIL), never 0/2",
      lambda: C.group_exit({"cases": [{"category": "FAIL"}, {"category": "LOI_PHEP_DO"}], "record_problems": []}) == 1)


def _w_connect_without_drop_out(tmp):
    base = {k: v for k, v in V.BASE.items() if k != "drop_out"}
    recs = [V.rec("T20-N2-TCP80 before", 100.0, 100.01, base), V.rec("T20-N2-TCP80 after", 110.0, 110.01, base)]
    pc, cfile, rec = scenario(tmp, "f67", [], [("T20-N2-TCP80", [], {"calls": calls_for("T20-N2-TCP80", ok=True)}, None)], reads_override=recs)
    return C.evaluate_w_case(L.classified_frames(pc, TAP), l2eval.load_reads(cfile), WCASES["T20-N2-TCP80"], rec["w_cases"][0], rec["guest_banner_control"], True, True)


def main(argv):
    jf = argv[argv.index("--json") + 1] if "--json" in argv else None
    with tempfile.TemporaryDirectory(prefix="selftest-b1.") as tmp:
        sec_D()
        sec_P(tmp)
        sec_W(tmp)
        sec_R()
        sec_S()
        sec_X(tmp)
        sec_E(tmp)
        sec_H(tmp)
        sec_F(tmp)
    n = sum(RESULTS.values())
    if jf:
        json.dump(RESULTS, open(jf, "w"), indent=1, ensure_ascii=False)
    print(f"SELFTEST-B1: {n}/{len(RESULTS)} passed")
    return 0 if n == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
