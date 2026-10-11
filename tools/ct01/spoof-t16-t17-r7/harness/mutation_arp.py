#!/usr/bin/env python3
"""06B-4H/06B-4HR/06B-4HR1/06B-4HR2 — mutation test of arp_cases.py (offline). Each mutant runs selftest_arp.py in its own mktemp copy;
every replacement must occur exactly once (else INVALID). DETECTED / DETECTED-ELSEWHERE / MISSED / INVALID /
ERROR as in mutation_icmp.py. Baseline must pass; harness hash checked before/after.
    python3 mutation_arp.py
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
AC = "arp_cases.py"
M = [
    # ---- probe identification (F1 included)
    ("A1", AC, [('    if a is None or a.get("sha") != L._norm_mac(S.GUEST_MAC):', '    if a is None:')],
     "P3 T14-A1 wrong ARP field (sender MAC field not the guest) -> no probe frame, never ĐẠT"),
    ("A2", AC, [('        return a["spa"] == S.GUEST_IP and a["tpa"] == case["dst"]', '        return a["spa"] == S.GUEST_IP')],
     "P3 T14-A1 wrong ARP field (other target IP) -> no probe frame, never ĐẠT"),
    ("A3", AC, [('!= (1, L.ETH_IPV4, 6, 4, 1):', '!= (1, L.ETH_IPV4, 6, 4, a.get("op")):')],
     "F1.2 S1 with gratuitous frames of opcode 2 only -> not a probe, KHÔNG TẠO ĐƯỢC GÓI, never ĐẠT"),
    ("A4", AC, [('    return (a["spa"] == a["tpa"] and a["spa"] in', '    return (a["spa"] in')],
     "P36 T15: ARP with a spoofed sender IP but another target (not gratuitous) is not a probe frame"),
    ("A4b", AC, [('            and f.get("dst") == L.BROADCAST)', '            )')],
     "F1.3 S1 gratuitous request sent unicast (not broadcast) -> not a probe"),
    ("A4c", AC, [('(a.get("htype"), a.get("ptype"), a.get("hlen"), a.get("plen"), a.get("op")) != (1, L.ETH_IPV4, 6, 4, 1)',
                  'a.get("op") != 1')],
     "F1.4 S1 gratuitous request with htype 6 / ptype 0x86dd -> not a probe"),
    # ---- verdict conditions
    ("A5", AC, [('        if lack:\n            return _result', '        if False:\n            return _result')],
     "P6 T15: one spoofed address missing -> KHÔNG TẠO ĐƯỢC GÓI naming it"),
    ("A6", AC, [('    if not probe:\n        return _result', '    if False:\n        return _result')],
     "P7 no frame at all (ping rc 1) -> KHÔNG TẠO ĐƯỢC GÓI, never evidence of blocking"),
    ("A7", AC, [('    if crec.get("exec_error"):\n        return _result(cid, "LOI_THUC_THI"',
                 '    if False:\n        return _result(cid, "LOI_THUC_THI"')],
     "P16 route add failed (setup) -> LỖI THỰC THI, not ĐẠT, even with frames"),
    ("A8", AC, [('    if detail["restore"] is not True:', '    if False:')],
     "P19 restore failed -> CHƯA KIỂM CHỨNG (cấu hình guest không khôi phục được), never ĐẠT"),
    ("A9", AC, [('    if not link_ok(crec.get("service_link_after")):', '    if False:')],
     "P22 service link after the case failed -> CHƯA KIỂM CHỨNG"),
    ("A10", AC, [('    return isinstance(state, dict) and state.get("ok") is True',
                  '    return isinstance(state, dict) and bool(state.get("ok"))')],
     "P37 service link after with ok \"true\" (not the boolean) -> CHƯA KIỂM CHỨNG"),
    ("A11", AC, [('    if out_drop != 0:', '    if False:')],
     "P27 arp_out_drop increased in the window -> CHƯA KIỂM CHỨNG (not observable, not ĐẠT)"),
    ("A12", AC, [('    measure += [f"worker neighbours: {x}" for x in nc["invalid"]]', '    pass')],
     "P13 neighbour table not readable -> LỖI PHÉP ĐO"),
    ("A13", AC, [('    not_started = bool(crec.get("exec_error") and gs.get("before") is None and not crec.get("steps"))',
                  '    not_started = False')],
     "P18 guest state unreadable before the case (nothing ran, no reads) -> LỖI THỰC THI (not LỖI PHÉP ĐO)"),
    ("A14", AC, [('control_alive=link_ok(crec.get("control")))', 'control_alive=True)')],
     "P25 A1 live control not alive -> CHƯA KIỂM CHỨNG (đối chứng)"),
    # ---- determined failures from frames
    ("A15", AC, [('            if case["kind"] == "t14" and a.get("spa") == case["dst"]:', '            if False:')],
     "P28 worker ARP reply for the probed IP towards the guest -> FAIL"),
    ("A16", AC, [('                    and ip.get("tot_len") == case["size"] + 28:', '                    and False:')],
     "P29 probe ICMP packet seen (ARP was resolved) -> FAIL"),
    ("A17", AC, [('            if case["kind"] == "t15" and ips & set(case["spoof"]):', '            if False:')],
     "P35 worker ARP about a spoofed IP during T15 -> FAIL"),
    # ---- worker neighbours (F2)
    ("A18", AC, [('        if key(b) != key(a):', '        if False:')], "N4 new entry (unwatched IP) on tap0 -> fail"),
    ("A19", AC, [('            if r["dev"] != "tap0" and r["lladdr"] == guest:', '            if False:')],
     "N9 a NEW, unwatched eth0 entry carrying the guest MAC -> fail"),
    ("A20", AC, [('            for dev, mac in sorted(ab - bb):', '            for dev, mac in []:')],
     "F2 S1 worker neighbour after: manager moved to eth9 with the same MAC -> FAIL"),
    ("A20b", AC, [('    if nc["inconclusive"]:', '    if False:')],
     "F2 S1 worker neighbour after: manager entry removed after -> CHUA_KIEM_CHUNG"),
    ("A20c", AC, [('"binding": mac is not None and not (set(states) & NUD_NO_BINDING)}', '"binding": mac is not None}')],
     "F2 S1 worker neighbour after: manager entry FAILED (MAC kept) -> CHUA_KIEM_CHUNG"),
    ("A21", AC, [('        raise NeighReadError("not a JSON list")', '        data = []')],
     "N8 unreadable neighbour output -> invalid (never 'unchanged')"),
    ("A21b", AC, [('            return "lladdr present but not a MAC address"', '            return None')],
     "F2 S1 worker neighbour after: manager lladdr 1 -> LOI_PHEP_DO"),
    ("A21c", AC, [('    if not isinstance(st, list) or not st or not all(isinstance(x, str) and x in NUD_STATES for x in st):',
                   '    if not isinstance(st, list):')],
     "F2 S1 worker neighbour after: manager state unknown string -> LOI_PHEP_DO"),
    ("A21d", AC, [('    problems += [f"duplicate entry {k[0]} dev {k[1]} ({n} rows)" for k, n in sorted(seen.items()) if n > 1]',
                   '    pass')],
     "F2 S1 worker neighbour after: duplicate identical normal rows -> LOI_PHEP_DO"),
    ("A21e", AC, [('    if a is not None:\n        for r in a:', '    if a is not None and not out["invalid"]:\n        for r in a:')],
     "F2 S1 worker neighbour after: duplicate row hides a guest MAC (guest MAC row first) -> FAIL"),
    # ---- execution (F4)
    ("A22", AC, [('            rec["stopped"] = NOT_RUN', '            pass')],
     "X6 restore failure: the next case is not run (not_run), no service link after the failed case"),
    ("A23", AC, [('PING_RC_OK = (0, 1)', 'PING_RC_OK = (0, 1, 2)')],
     "F4 run_group: ping rc 2 -> execution error recorded, read B taken, restored, settle not run"),
    ("A23b", AC, [('        if not rc_ok(phase, cmd, rc):\n            r["exec_error"]', '        if False:\n            r["exec_error"]')],
     "X8 setup failed: trigger not sent, exec error, still restored"),
    ("A24", AC, [('    return rc == 0\n', '    return rc == 0 or phase == "trigger"\n')],
     "X18 link down failed (trigger): exec error, 'link up' not sent, still restored"),
    ("A25", AC, [('    return {"ok": ok is True, "detail": detail}', '    return {"ok": bool(ok), "detail": detail}')],
     "X19 service link returning a truthy non-True value is not ok: group skipped"),
    # ---- record completeness (F3)
    ("A26", AC, [('        p += [f"case missing: {cid}" for cid in CASE_IDS if n[cid] == 0]', '        pass')],
     "X15 record_problems: missing case"),
    ("A27", AC, [('    if result.get("record_problems"):\n        return 2', '    if False:\n        return 2')],
     "C2 CLI: a case missing in the record -> exit 2 even though the 3 others pass"),
    ("A28", AC, [('        if got != want:\n', '        if False:\n')],
     "F3 group with empty steps -> never exit 0, no case ĐẠT, record problem"),
    ("A28b", AC, [('        bad = [s for s in steps if not rc_ok(s.get("phase"), s.get("cmd") or "", s.get("rc"))]', '        bad = []')],
     "F3 group with every rc 2 -> never exit 0, no case ĐẠT, record problem"),
    ("A28c", AC, [('    for k, t in BASELINE_KEYS.items():', '    for k, t in []:')],
     "F3 group with guest baseline incomplete -> never exit 0, no case ĐẠT, record problem"),
    ("A28d", AC, [('    if restore["diffs"]:\n        return "restore says restored although', '    if False:\n        return "restore says restored although')],
     "F3 group with restore says restored with diffs -> never exit 0, no case ĐẠT, record problem"),
    ("A28e", AC, [('    for s in steps[:-1]:', '    for s in []:')],
     "F3.t a STOPPED case whose earlier step is outside the contract -> record problem"),
    ("A29", AC, [('"trigger": [f"ping -c 1 -W {PING_WAIT_S} -s {int(case[\'size\'])} {dst}"]',
                  '"trigger": [f"ping -c 1 -W {PING_WAIT_S} -s 1401 {dst}"]')],
     "D8 a registry change changes the command (single source)"),
    # ---- failure evidence vs measurement errors (F5)
    ("B1", AC, [('    if failure:\n        return _result(cid, "FAIL", "FAIL", **detail)\n    # (3) measurement errors\n    if measure:',
                 '    if measure:\n        return _result(cid, "LOI_PHEP_DO", "x", **detail)\n    if failure:\n'
                 '        return _result(cid, "FAIL", "FAIL", **detail)\n    # (3) measurement errors\n    if measure:')],
     "F5.2 known frame violation + read_error (raw rows kept) -> FAIL, JSON keeps BOTH the failure and the measurement error"),
    ("B2", AC, [('            if not _window_ok(ra, rb):', '            if False:')],
     "F5.4 frame violation but read times overlap (A ends after B starts: window not valid) -> no FAIL inferred from "
     "frame positions; LỖI PHÉP ĐO"),
    ("B3", AC, [('        failure += determined_problems(window, case)',
                 '        failure += determined_problems(window, case) if not crec.get("read_error") else []')],
     "F5.2 known frame violation + read_error (raw rows kept) -> FAIL, JSON keeps BOTH the failure and the measurement error"),
    ("B4", AC, [('    input_error = "; ".join(errs) or None\n', '    input_error = "; ".join(errs) or None\n    if input_error:\n        return out\n')],
     "F5.5 neighbour violation with the capture unreadable -> FAIL (neighbour evidence kept), capture error kept"),
    ("B5", AC, [('    if "FAIL" in cats:\n        return 1\n    if not result["cases"] or "LOI_PHEP_DO" in cats:\n        return 2\n',
                 '    if not result["cases"] or "LOI_PHEP_DO" in cats:\n        return 2\n    if "FAIL" in cats:\n        return 1\n')],
     "F5.7 group_exit: FAIL wins over LỖI PHÉP ĐO in the same group"),
    ("B6", AC, [('    failure += nc["fail"]', '    failure += nc["fail"] if not crec.get("read_error") else []')],
     "F5.3 neighbour violation (valid rows) + read_error -> FAIL, both kept"),
    # ---- 06B-4HR1: HR1 baseline/restore
    ("C1", AC, [('        d = GS.diff(_gs_state(before), _gs_state(after))\n        if d:', '        d = []\n        if d:')],
     "H1 restore 'after' MAC differs from the baseline (restored=True, diffs=[]) -> not ĐẠT, record problem, never exit 0"),
    ("C2", AC, [('    bad = baseline_problem(after)\n', '    bad = None\n')],
     "H1 restore 'after' with a malformed dynamic neighbour (diff() ignores dynamic) -> not ĐẠT, record problem, never exit 0"),
    ("C3", AC, [('    if restore.get("error"):\n        return f"restore says restored but reports',
                 '    if False:\n        return f"restore says restored but reports')],
     "H1 restored=True with an error -> not ĐẠT, record problem, never exit 0"),
    ("C4", AC, [('    for c in restore["commands"]:', '    for c in []:')],
     "H1 restore commands [42] -> not ĐẠT, record problem, never exit 0"),
    ("C5", AC, [('    for a in before["addrs"]:', '    for a in []:')],
     "H1 baseline AND after addrs [42] -> not ĐẠT, record problem, never exit 0"),
    ("C6", AC, [('    if before["operstate"] not in OPERSTATES:', '    if False:')],
     "H1 baseline AND after operstate 'weird' -> not ĐẠT, record problem, never exit 0"),
    ("C7", AC, [('    for k, mac in before["neigh_static"].items():', '    for k, mac in []:')],
     "H1 baseline AND after static neighbour not a MAC -> not ĐẠT, record problem, never exit 0"),
    ("C8", AC, [('    for k, v in before["neigh_dynamic"].items():\n        if not _neigh_key(k)', '    for k, v in []:\n        if not _neigh_key(k)')],
     "H1 baseline dynamic neighbour malformed -> not ĐẠT, record problem, never exit 0"),
    ("C9", AC, [('    if before["arp_notify"] < 0:', '    if False:')],
     "H1 baseline AND after arp_notify -1 -> not ĐẠT, record problem, never exit 0"),
    ("C10", AC, [('    for r in before["routes"]:', '    for r in []:')],
     "H1 baseline AND after route object -> not ĐẠT, record problem, never exit 0"),
    ("C11", AC, [('        for x in (baseline_problem(before), restore_problem(restore, before)):',
                  '        for x in (baseline_problem(before), restore_problem(restore)):')],
     "H1 restore 'after' MAC differs from the baseline (restored=True, diffs=[]) -> not ĐẠT, record problem, never exit 0"),
    # ---- HR2 mandatory binding
    ("C12", AC, [('    if len(st) != 1:', '    if False:')],
     "H2.1 mandatory tap0 row with states ['PERMANENT', 'FAILED'] -> LỖI PHÉP ĐO, never ĐẠT"),
    ("C13", AC, [('(r["lladdr"] == guest and r["states"] == ["PERMANENT"] and r["binding"])', '(r["lladdr"] == guest and r["binding"])')],
     "H2.4 mandatory row REACHABLE both before and after (no tap0 change) -> still FAIL (binding must be PERMANENT)"),
    # ---- HR3 not-started branch
    ("C14", AC, [('    failure, measure = [], []\n', '    if not_started:\n        return _result(cid, "LOI_THUC_THI", "x", **ek)\n    failure, measure = [], []\n')],
     "H3.1 not started (state unreadable) + valid mandatory neighbour change -> FAIL, not_started kept, no command sent"),
    ("C15", AC, [('    if reads is not None and not not_started:', '    if reads is not None:')],
     "H3.4 not started, inputs readable, neighbours clean -> LỖI THỰC THI with every evidence field present"),
    # ---- HR4 unreadable rows are unknown
    ("C16", AC, [('            if _maybe(unk["after"], S.GUEST_IP, "tap0"):', '            if False:')],
     "H4.1 mandatory row unreadable (lladdr 1) after -> LỖI PHÉP ĐO, no FAIL inferred"),
    ("C17", AC, [('        if _maybe(unk["before"], dev="tap0") or _maybe(unk["after"], dev="tap0"):', '        if False:')],
     "H4.2 mandatory row unreadable BEFORE, after clean -> LỖI PHÉP ĐO, not 'tap0 changed'"),
    ("C18", AC, [('            if _maybe(unk["before"], ip) or _maybe(unk["after"], ip):', '            if False:')],
     "H4.7 watched IP: valid before, row unreadable after -> LỖI PHÉP ĐO and NOT reported as 'missing'"),
    ("C19", AC, [('            unknown.append(_row_identity(r))', '            pass')],
     "H4.1 mandatory row unreadable (lladdr 1) after -> LỖI PHÉP ĐO, no FAIL inferred"),
    ("C20", AC, [('(u_dst is None or dst is None or u_dst == dst)', '(dst is None or u_dst == dst)')],
     "H4.5 an unidentifiable row (no dst) -> LỖI PHÉP ĐO, no 'missing'/'changed' inferred for any entry"),
    # ---- HR5 control payload
    ("C21", AC, [('            elif isinstance(res, (tuple, list)) and len(res) == 2:', '            elif True:')],
     "H5 control callback returns True -> record kept, control not ok, case not ĐẠT"),
    ("C22", AC, [('                r["control"] = {"ok": res[0] is True, "detail": res[1]}', '                r["control"] = {"ok": bool(res[0]), "detail": res[1]}')],
     "H5 control callback returns (1, 'x') -> record kept, control not ok, case not ĐẠT"),
    # ---- every JSON branch
    ("C23", AC, [('        out.setdefault(k, t())', '        pass')],
     "H6 JSON branch 'not_run' has every evidence/error field with the right type"),
    # ---- 06B-4HR2: R1 static/dynamic consistency
    ("D1", AC, [('        if v[1] & GS_ATF_PERM:', '        if False:')],
     "R1.1 baseline neigh_dynamic entry with flags 0x6 (PERMANENT bit), lost after restore -> rejected (exit != 0)"),
    ("D2", AC, [('    if both:\n        return f"guest baseline neighbour(s)', '    if False:\n        return f"guest baseline neighbour(s)')],
     "R1.3 same neighbour key in neigh_static AND neigh_dynamic -> rejected (evaluate_group and CLI)"),
    ("D3", AC, [('GS_ATF_PERM = 0x4 ', 'GS_ATF_PERM = 0x8 ')],
     "R1.1 baseline neigh_dynamic entry with flags 0x4 (PERMANENT bit), lost after restore -> rejected (exit != 0)"),
    ("D4", AC, [('    bad = baseline_problem(after)\n', '    bad = None\n')],
     "R1.4 restore 'after' contradictory (dynamic entry with the PERMANENT flag), baseline clean -> rejected"),
    # ---- 06B-4IR3 (PC-3): admin_up required in the baseline / restore.after record
    ("D5", AC, [('"operstate": str, "admin_up": bool, "addrs"', '"operstate": str, "addrs"')],
     "PC3.2 baseline without admin_up -> S1 never ĐẠT, record problem, group exit 2 (a record without a confirmed admin state is not a confirmed restore)"),
    ("X1", AC, [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", "selftest_arp.py", [("import contextlib\n", "import contextlib(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def suite(d):
    p = subprocess.run([sys.executable, os.path.join(d, "selftest_arp.py")], capture_output=True, text=True,
                       timeout=600, cwd=d)
    res = {}
    for l in p.stdout.splitlines():
        if l.startswith("[PASS] ") or l.startswith("[FAIL] "):
            res[l[7:].split("  (")[0]] = l.startswith("[PASS]")
    if not any(l.startswith("SELFTEST-ARP:") for l in p.stdout.splitlines()):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    only = set(sys.argv[2].split(",")) if sys.argv[1:2] == ["--only"] else None   # 06B-4IR3: targeted runs
    h0 = sha(HERE)
    with tempfile.TemporaryDirectory(prefix="mutation-arp.") as tmp:
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for mid, klass, target, failed, err in ex.map(one, [m for m in M if not only or m[0] in only]):
                ok = klass == EXPECT.get(mid, "DETECTED")
                good += ok
                bad += not ok
                print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}"
                      + ("" if klass in ("DETECTED", "INVALID", "MISSED") else f" failed={failed[:5]} {err or ''}"))
    same = sha(HERE) == h0
    print(f"MUTATION-ARP: {good} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
