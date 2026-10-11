#!/usr/bin/env python3
"""06B-4I (+ 06B-4IR1 V38-V61, 06B-4IR2 V62-V68) — mutation test of the ARP wiring (arp_harness.py, probe_matrix.py arp branch, ctl_loop.py --arp-worker,
run-06b4i.sh), offline. Each mutant runs selftest_arp_wiring.py in its own mktemp copy of every harness file; every
replacement must occur exactly once (else INVALID). DETECTED / DETECTED-ELSEWHERE / MISSED / INVALID / ERROR as in
mutation_icmp_wiring.py. Baseline must pass; harness hash checked before/after.
    python3 mutation_arp_wiring.py
"""
import concurrent.futures
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(HERE, "*.py")) + glob.glob(os.path.join(HERE, "*.sh")))
AH, PM, RS, CL = "arp_harness.py", "probe_matrix.py", "run-06b4i.sh", "ctl_loop.py"
M = [
    # ---- arp_harness.py
    ("V1", AH, [('"ok": before and after and fails == 0 and not problems}', '"ok": before and after and not problems}')],
     "U4 ctl_window: one failure inside the span -> not ok, counted"),
    ("V2", AH, [('"ok": before and after and fails == 0 and not problems}', '"ok": before and fails == 0 and not problems}')],
     "U2 ctl_window: nothing after read B (yet) -> not ok"),
    ("V3", AH, [('        if d["hw"] != mac:', '        if False:')],
     "U7 control_a1: clean -> ok; ARP entry with another MAC / incomplete flag / not an object -> not ok"),
    ("V4", AH, [('    if case.get("dst") != worker_ip:', '    if False:')],
     "U8 control_a1: worker address differs from the case target (ctl log of that address all OK) / eth0 MAC unknown -> not ok"),
    ("V5", AH, [('                    and entry["lladdr"] == mac):', '                    ):')],
     "U11 control_a2: INCOMPLETE/FAILED/NOARP, other MAC, two rows, invalid row that may be it, not JSON -> not ok"),
    ("V6", AH, [('        if A._maybe(unknown, manager_ip, "eth0"):', '        if False:')],
     "U11 control_a2: INCOMPLETE/FAILED/NOARP, other MAC, two rows, invalid row that may be it, not JSON -> not ok"),
    ("V7", AH, [('        if wait > 0:\n', '        if False:\n')],
     "U14 make_control: waits until the ctl log can hold a record after the span, then judges A1/A2"),
    ("V8", AH, [('        rec["guard_stopped"] = ', '        rec["stopped"] = ')],
     "S32 marker-after-A2-ping: QEMU shut down and cleanup done after the stop; group record kept with the guard stop"),
    ("V9", AH, [('        if restored and not IH.link_valid(', '        if False and not IH.link_valid(')],
     "U18 check_record: link before/after a restored case not HTTP 200 + fixture hash -> problem"),
    ("V10", AH, [('    problems += [f"arp_cases: {x}" for x in case_probs]', '    pass')],
     "U21 evaluate: arp_cases record problems are kept (prefixed) and block the group"),
    ("V11", AH, [('            hard += required_problems(result["results"], reqs)', '            pass')],
     "R4 a per-case confirmation missing (restore after S1 / link after A2) -> FAIL"),
    ("V12", AH, [('        if arp_eval.get("group_exit") not in (0, 4):', '        if False:')],
     "R6 group_exit 2 in arp-eval.json -> FAIL; evaluation of another architecture -> FAIL"),
    ("V13", AH, [('    NEIGH_READ_NAME,\n', '')],
     "R2 the real ARP path records no other non-info, non-case check outside the required list"),
    ("V14", AH, [('                req.append(link_after_name(c["id"]))', '                pass')],
     "R4 a per-case confirmation missing (restore after S1 / link after A2) -> FAIL"),
    ("V15", AH, [('    return f"probe {case_result[\'id\']} (arp, {kind})', '    return f"arp {case_result[\'id\']} (arp, {kind})')],
     "S36 ctl-no-arp: T14-A1 control not alive -> CHƯA KIỂM CHỨNG (không có đối chứng sống), T14-A2 still ĐẠT; UNVERIFIED, never PASS"),
    ("V16", AH, [('NEIGH_CMD = ("ip", "-j", "neigh", "show")', 'NEIGH_CMD = ("ip", "-j", "neigh", "show", "dev", "tap0")')],
     "S6 clean: neighbour collector = exactly `ip -j neigh show` in the worker, 2 per case + 1 for the A2 control"),
    # ---- probe_matrix.py (arp branch only)
    ("V17", PM, [('    if stop is not None:\n        raise stop', '    if False:\n        raise stop')],
     "S30 marker-after-A2-ping: exit 98, the command that tripped the guard is the LAST one sent (no restore, no link)"),
    ("V18", PM, [('        leak_guard(cmd, "before")\n', '')],
     "S33 alert written during 'T15-S1 before' (read A): S1 setup NOT sent, exit 99, leak record when=before"),
    ("V19", PM, [('        captures_alive(tshark, f"before ARP guest command {cmd!r}")', '        pass')],
     "S35 capture lost during 'T14-A2 before': A2 setup NOT sent, exit 98, the restore reaches no guest (not restored), A3/S1 not run"),
    ("V20", PM, [('        found = alert_lines()               # raises',
                  '        try:\n            found = alert_lines()\n        except Exception:\n            found = []  # raises')],
     "S34 alert file unreadable during 'T14-A2 before': never 'no alert'; A2 setup NOT sent; ERROR exit 1; FAIL"),
    ("V21", PM, [('            evaluate_arp()\n', '            evaluate_icmp()\n')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS (function and CLI), run script maps it to PASS"),
    ("V22", PM, [('            record(arp_harness.restore_name(c["id"]), rs.get("restored") is True,',
                  '            record(arp_harness.restore_name(c["id"]), True,')],
     "S29 restore fails after A2: run outcome FAIL (restore confirmation), no service link after A2, script FAIL"),
    ("V23", PM, [('    record(arp_harness.NEIGH_READ_NAME, bool(ran) and not any(errs.values())',
                  '    record(arp_harness.NEIGH_READ_NAME, True or not any(errs.values())')],
     "S18 collector fails (rc != 0) after A2: A2 LỖI PHÉP ĐO with the error kept, collector record FAIL, never PASS"),
    ("V24", PM, [('        return run_checked(list(arp_harness.NEIGH_CMD))', '        return run_checked(["ip", "-j", "neigh", "show", "dev", "tap0"])')],
     "S6 clean: neighbour collector = exactly `ip -j neigh show` in the worker, 2 per case + 1 for the A2 control"),
    ("V25", PM, [('        name = arp_harness.LINK_BEFORE_NAME if links["n"] == 0 else arp_harness.link_after_name(current["case"])',
                  '        name = arp_harness.LINK_BEFORE_NAME')],
     "R1 the real ARP path records every required confirmation exactly once (static + per case)"),
    ("V26", PM, [('        res = arp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), ARP["tap_mac"], ARP["record"],',
                  '        res = arp_harness.evaluate(PCAP, os.path.join(OUT, "counters-raw.jsonl"), "02:00:00:00:00:01", ARP["record"],')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS (function and CLI), run script maps it to PASS"),
    ("V27", PM, [('        windows.setdefault(cid, {})[which] = (r["t_start"], r["t_end"])', '        pass')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS (function and CLI), run script maps it to PASS"),
    ("V28", PM, [('    record(arp_harness.GROUP_RECORD_NAME, res["group_complete"] is True,',
                  '    record(arp_harness.GROUP_RECORD_NAME, True,')],
     "S15 missing-case: never PASS; outcome FAIL naming the record problem; script FAIL; group record check FAIL in result.json"),
    ("V29", PM, [('if SUITE == "arp":\n    import arp_harness', 'if SUITE == "arp":\n    import icmp_harness as arp_harness')],
     "S13 imports in the fake container came only from the files run-06b4i.sh mounts"),
    # ---- ctl_loop.py
    ("V30", CL, [('    if not int(r["flags"], 16) & 0x2 or r["hw"] == "00:00:00:00:00:00":', '    if r["hw"] == "00:00:00:00:00:00":')],
     "U29 ctl_loop arp_entry: incomplete (0x0), zero MAC, no row, two rows, bad header/row -> raises"),
    ("V31", CL, [('    if len(rows) != 1:', '    if not rows:')],
     "U29 ctl_loop arp_entry: incomplete (0x0), zero MAC, no row, two rows, bad header/row -> raises"),
    # ---- run-06b4i.sh
    ("V32", RS, [('-e CT01_SUITE=arp "$ID"', '"$ID"')], "W3 exactly one probe_matrix call, with CT01_SUITE=arp (no icmp/ipv4 suite)"),
    ("V33", RS, [('    -v "$H/guest_state.py:/harness/guest_state.py:ro" \\\n', '')],
     "W5 every module probe_matrix imports in arp mode is mounted read-only"),
    ("V34", RS, [('    0:PASS) pass', '    0:PASS|1:UNVERIFIED*) pass')],
     "S36 ctl-no-arp: T14-A1 control not alive -> CHƯA KIỂM CHỨNG (không có đối chứng sống), T14-A2 still ĐẠT; UNVERIFIED, never PASS"),
    ("V35", RS, [('python3 "$H/selftest_arp_wiring.py" > "$OUT/selftest-arp-wiring.txt" 2>&1 || { cat "$OUT/selftest-arp-wiring.txt"; echo "ABORT: ARP wiring self-test failed"; exit 3; }\n', '')],
     "W4 selftest_arp.py and selftest_arp_wiring.py (and the ICMP/L2 ones) run before any docker command and abort"),
    ("V36", RS, [('/ctl/ctl.jsonl --arp-worker)', '/ctl/ctl.jsonl)')],
     "W7 ctl started with --arp-worker; its ARP target is checked alive like the others"),
    ("V37", RS, [('"$MANAGER_IP" "$MANAGER_MAC" "$CTL_MAC" "$SANDBOX_GW"', '"$MANAGER_IP" "" "$CTL_MAC" "$SANDBOX_GW"')],
     "W8 manager MAC and ctl sandboxnet endpoint MAC passed to the worker in CT01_TARGETS"),
    # ---- 06B-4IR1: I1 startup/topology guard (probe_matrix.py)
    ("V38", PM, [('        an._configure_network(console, cfg)', '        an._configure_network(proc, cfg)')],
     "I1.1 boot-leak: real _configure_network body: the event during `ip addr add` stops BEFORE `route add`/DNS; exit 99"),
    ("V39", PM, [('        self._guard.check("before", f"sendline {s!r}")\n', '')],
     "I1.10 after the stop every later send raises without reaching the console, even once the alert is gone (latched)"),
    ("V40", PM, [('            self._guard.check("after", "expect")', '            pass')],
     "I1.1 boot-leak: real _configure_network body: the event during `ip addr add` stops BEFORE `route add`/DNS; exit 99"),
    ("V41", PM, [('        topo = {k: startup.run(g, c)[1] for k, c in (', '        topo = {k: g.run(c)[1] for k, c in (')],
     "I1.3 topology-leak: the topology command that saw the event is the last guest operation (no further command, no monitor); exit 99"),
    ("V42", PM, [('        topo["info_network"] = startup.monitor(g, "info network")', '        topo["info_network"] = g.monitor("info network")')],
     "I1.6 monitor-leak: the event during `monitor info network` stops before the ARP group (no service link, no case command); exit 99"),
    ("V43", PM, [('        if startup.stop is not None:         # an exception swallowed', '        if False:         # an exception swallowed')],
     "I1.2 boot-leak-swallowed: no topology command, no monitor call, no ARP command after the event, no 'guest booted' record; QEMU exit and cleanup done; outcome/CLI/script FAIL"),
    ("V44", PM, [('        if self.stop is not None:\n            raise self.stop\n        self.checks += 1',
                  '        self.checks += 1')],
     "I1.10 after the stop every later send raises without reaching the console, even once the alert is gone (latched)"),
    ("V45", PM, [('            found = alert_lines()\n            if found:\n                record("NO probe packet seen on host interfaces (leak monitor)", False, phase=self.phase',
                  '            found = []\n            if found:\n                record("NO probe packet seen on host interfaces (leak monitor)", False, phase=self.phase')],
     "I1.5 topology-leak: leak record names the startup phase and the operation"),
    ("V46", PM, [('            captures_alive(self.tshark, f"{self.phase}: {when} {what!r}")', '            pass')],
     "I1.3 topology-capture: the topology command that saw the event is the last guest operation (no further command, no monitor); exit 98"),
    # ---- 06B-4IR1: I2 ctl interface (arp_harness.py, ctl_loop.py, run script)
    ("V48", AH, [('        if d["device_mac"] != ctl_mac:', '        if False:')],
     "U31 I2 control_a1: device on another endpoint MAC (e.g. dbnet) / device missing / device_mac missing -> not ok, reason kept"),
    ("V49", AH, [('        if not isinstance(d, dict) or set(d) != ARP_DETAIL_KEYS:', '        if not isinstance(d, dict):')],
     "U31 I2 control_a1: device on another endpoint MAC (e.g. dbnet) / device missing / device_mac missing -> not ok, reason kept"),
    ("V50", AH, [('    bad = endpoint_mac_problem(cmac)\n    if bad:', '    bad = endpoint_mac_problem(cmac)\n    if False:')],
     "U33 I2 control_a1: ctl endpoint MAC unknown/invalid -> not ok, even with a perfect log"),
    ("V51", AH, [('    if len(devices) > 1:', '    if False:')],
     "U34 I2 control_a1: entry of another IP / two devices in the window / invalid device name / extra key -> not ok"),
    ("V52", AH, [('        if d["ip"] != ip:', '        if False:')],
     "U34 I2 control_a1: entry of another IP / two devices in the window / invalid device name / extra key -> not ok"),
    ("V53", AH, [('cfg.get("worker_ip"), eth0_mac, cfg.get("ctl_mac"))', 'cfg.get("worker_ip"), eth0_mac, eth0_mac)')],
     "S1 clean: exit 0, status COMPLETED, outcome PASS (function and CLI), run script maps it to PASS"),
    ("V54", CL, [('    return {"ip": ip, **r, "device_mac": dmac}', '    return {"ip": ip, **r}')],
     "U28 ctl_loop arp_entry: complete entry -> MAC, flags, device"),
    ("V55", RS, [('CTL_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \\"$SANDBOXNET\\").MacAddress}}" "$CID")',
                  'CTL_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \\"$DBNET\\").MacAddress}}" "$CID")')],
     "W12 ctl endpoint MAC from docker inspect of the ctl container on sandboxnet, after it is created (I2)"),
    # ---- 06B-4IR1: I3 ctl log quality (arp_harness.py)
    ("V56", AH, [('        if not isinstance(r, dict) or set(r) != CTL_KEYS or not isinstance(r["target"], str) \\',
                  '        if not isinstance(r, dict) or not CTL_KEYS - {"detail"} <= set(r) or not isinstance(r["target"], str) \\')],
     "U35 I3 ctl_records: missing detail / extra key / NaN or infinite ts -> malformed (raises)"),
    ("V57", AH, [('    return None if d == HTTP_OK_DETAIL else', '    return None if True else')],
     "U36 I3 ctl_window HTTP: OK with detail None / 'HTTP 500' / '' / object -> not ok; 'HTTP 200' -> ok"),
    ("V58", AH, [('        if last is not None and r["ts"] <= last:', '        if last is not None and r["ts"] < last:')],
     "U37 I3 ctl_window: the same record twice (same target and ts) -> not ok, reported as duplicate, not removed"),
    ("V59", AH, [('    ctl = ctl_window(records, ctl_target_http_manager(manager_ip), t0, t1, slack, http_detail_check)',
                  '    ctl = ctl_window(records, ctl_target_http_manager(manager_ip), t0, t1, slack)')],
     "U41 I3 control_a2: manager HTTP record without payload / 'HTTP 500' -> not ok"),
    ("V60", AH, [('                or not math.isfinite(r["ts"]):', '                or False:')],
     "U35 I3 ctl_records: missing detail / extra key / NaN or infinite ts -> malformed (raises)"),
    ("V61", AH, [('            if not isinstance(r["detail"], str):', '            if False:')],
     "U39 I3 ctl_window: a failed record without a string detail -> problem (still not ok)"),
    # ---- 06B-4IR2: IR1-R1 handoff of the startup guard (probe_matrix.py)
    ("V62", PM, [('            rc, out = startup.run(g, f"curl -s -m 10', '            rc, out = g.run(f"curl -s -m 10')],
     "R1.2 ipv4-handoff-capture: event right after the topology gate -> NO guest command after the handoff (the service link 'before probes' is not sent); exit 98"),
    ("V63", PM, [('                rc, out = startup.run(g, f"curl -s -o /dev/null', '                rc, out = g.run(f"curl -s -o /dev/null')],
     "R1.5 ipv4: alert during the first probe -> that probe is the last guest command; leak record phase 'ipv4 group'; exit 99"),
    ("V64", PM, [('        # 06B-4IR2 (IR1-R1): the guard is NOT disarmed here.', '        startup.armed = False  # the guard is NOT disarmed here.')],
     "R1.2 ipv4-handoff-capture: event right after the topology gate -> NO guest command after the handoff (the service link 'before probes' is not sent); exit 98"),
    # ---- 06B-4IR2: IR1-R2 unusable endpoint MACs (arp_harness.py)
    ("V65", AH, [('    if mac == "00:00:00:00:00:00":', '    if False:')],
     "R2.1 zero-mac-both: A1 control not alive (endpoint MAC cannot identify the interface), reason and raw MAC kept; A2 ĐẠT; never PASS (function, CLI, Bash)"),
    ("V66", AH, [('    if int(mac[:2], 16) & 0x01:', '    if False:')],
     "R2.1 broadcast-mac-both: A1 control not alive (endpoint MAC cannot identify the interface), reason and raw MAC kept; A2 ĐẠT; never PASS (function, CLI, Bash)"),
    ("V67", AH, [('        if bad:\n            return f"ARP entry device_mac unusable', '        if False:\n            return f"ARP entry device_mac unusable')],
     "U43 IR1-R2 control_a1: zero/group MAC equal in config and payload -> not ok; payload zero with a valid config -> not ok (reason names the payload)"),
    ("V68", AH, [('    bad = endpoint_mac_problem(cmac)\n', '    bad = None if cmac and _MAC.fullmatch(cmac) else "invalid"\n')],
     "R2.1 zero-mac-cfg: A1 control not alive (endpoint MAC cannot identify the interface), reason and raw MAC kept; A2 ĐẠT; never PASS (function, CLI, Bash)"),
    # ---- 06B-4IR3 (PC-1): architecture stop policy in run-06b4i.sh
    ("V69", RS, [('        || { ARCH_STOP="$ARCH: QEMU already running before start: harness not called for $ARCH"; break; }\n', '')],
     "PC1.3 QEMU already running before ARM: no harness call at all (not 'guest did not boot'), stop reason names it, exit 1"),
    ("V70", RS, [('    if [ "$ARCH" != MIPS ] && { [ ${#FAILS[@]} -ne "$nf0" ]', '    if false && { [ ${#FAILS[@]} -ne "$nf0" ]')],
     "PC1.2 arm-fail: MIPS harness NOT called (only ARM), loop stopped and reported, run-level check skipped, control continues after the loop (teardown), exit 1 keeps the cause"),
    ("V71", RS, [(' || [ ${#UNVERIFIED[@]} -ne "$nu0" ]; }; then', '; }; then')],
     "PC1.2 arm-unverified: MIPS harness NOT called (only ARM), loop stopped and reported, run-level check skipped, control continues after the loop (teardown), exit 4 keeps the cause"),
    ("V72", RS, [('    if [ "$ARCH" != MIPS ] && { [ ${#FAILS[@]}', '    if { [ ${#FAILS[@]}')],
     "PC1.5 MIPS fails after a clean ARM: both called, no stop needed, run-level check run, exit 1"),
    ("V73", RS, [('if [ -n "$ARCH_STOP" ]; then\n    echo "[STOPPED]', 'if false; then\n    echo "[STOPPED]')],
     "PC1.2 arm-fail: MIPS harness NOT called (only ARM), loop stopped and reported, run-level check skipped, control continues after the loop (teardown), exit 1 keeps the cause"),
    ("V74", RS, [('    ARCH_CALLED+=("$ARCH")\n', '')],
     "PC1.1 both architectures pass: harness called for ARM then MIPS, run-level check run, no stop, exit 0"),
    # ---- controls
    ("X1", AH, [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", "selftest_arp_wiring.py", [("import ast\n", "import ast(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def suite(d):
    p = subprocess.run([sys.executable, os.path.join(d, "selftest_arp_wiring.py")], capture_output=True, text=True,
                       timeout=1200, cwd=d)
    res = {}
    for l in p.stdout.splitlines():
        if l.startswith("[PASS] ") or l.startswith("[FAIL] "):
            res[l[7:].split("  (")[0]] = l.startswith("[PASS]")
    if not any(l.startswith("SELFTEST-ARP-WIRING:") for l in p.stdout.splitlines()):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    only = set(sys.argv[2].split(",")) if sys.argv[1:2] == ["--only"] else None   # 06B-4IR3: targeted runs
    h0 = sha(HERE)
    with tempfile.TemporaryDirectory(prefix="mutation-arp-wiring.") as tmp:
        def copy():
            d = tempfile.mkdtemp(dir=tmp)
            for f in FILES:
                shutil.copy2(os.path.join(HERE, f), d)
            return d
        base, err = suite(copy())
        if base is None or not all(base.values()):
            print("BASELINE FAILED", err or [k for k, v in base.items() if not v])
            return 2
        print(f"baseline: {len(base)}/{len(base)} tests pass")

        def one(entry):
            mid, fname, reps, target = entry
            if target is not None and target not in base:
                return mid, "BAD-TARGET", target, [], None
            d = copy()
            src = open(os.path.join(d, fname)).read()
            for old, new in reps:
                if src.count(old) != 1:
                    return mid, "INVALID", target, [], None
                src = src.replace(old, new)
            open(os.path.join(d, fname), "w").write(src)
            res, err = suite(d)
            if res is None:
                return mid, "ERROR", target, [], err
            failed = sorted(k for k, v in res.items() if not v)
            return mid, ("DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED"), target, failed, None
        good = bad = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            for mid, klass, target, failed, err in ex.map(one, [m for m in M if not only or m[0] in only]):
                ok = klass == EXPECT.get(mid, "DETECTED")
                good += ok
                bad += not ok
                print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}"
                      + ("" if klass in ("DETECTED", "INVALID", "MISSED") else f" failed={failed[:5]} {err or ''}"),
                      flush=True)
    same = sha(HERE) == h0
    print(f"MUTATION-ARP-WIRING: {good} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
