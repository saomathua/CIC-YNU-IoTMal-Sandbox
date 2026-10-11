#!/usr/bin/env python3
"""06B-4E — mutation test of icmp_cases.py (offline). Each mutant runs selftest_icmp.py in its own
mktemp copy; every replacement must occur exactly once (else INVALID). DETECTED / DETECTED-ELSEWHERE /
MISSED / INVALID / ERROR as in mutation_l2.py. Baseline must pass; harness hash checked before/after.
    python3 mutation_icmp.py
"""
import hashlib, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("icmp_cases.py", "selftest_icmp.py", "l2eval.py", "selftest_l2eval.py", "selftest_l2.py", "l2frames.py",
         "counter_window.py", "signatures.py", "sigscan_l2.py", "guest_state.py", "run-06b3b.sh")
M = [
    ("C1", [('    if not probe:\n        return _result(cid, "KHONG_TAO_DUOC_GOI"', '    if False:\n        return _result(cid, "KHONG_TAO_DUOC_GOI"')],
     "K1 no probe frame (broadcast refused locally), counters unchanged -> KHÔNG TẠO ĐƯỢC GÓI, not ĐẠT"),
    ("C2", [('    if ex.get("error"):\n        return _result(cid, "LOI_THUC_THI"', '    if False:\n        return _result(cid, "LOI_THUC_THI"')],
     "E1 console error during the ping -> LỖI THỰC THI (not ĐẠT even if counters match)"),
    ("C3", [('    if not link_after_ok:', '    if False:')],
     "U3 service link after the group not intact -> CHƯA KIỂM CHỨNG, never ĐẠT"),
    ("C4", [('        "no_reply_to_guest": not replies,', '        "no_reply_to_guest": True,')],
     "F2 an ICMP frame towards the guest in the window -> FAIL (no_reply_to_guest)"),
    ("C5", [('        "probe_packets_hit_expected_counter": all(f["cls"] == case["expected"] for f in certain),',
             '        "probe_packets_hit_expected_counter": True,')],
     "F3 a probe frame that does not reach the expected counter (OTHERHOST) -> FAIL"),
    ("C6", [('    return _result(cid, "DAT_KIEM_QUY_TAC", text, **detail)', '    return _result(cid, "DAT_KIEM_QUY_TAC", "ĐẠT", **detail)')],
     "P T12-B1: 3 probe frames = drop_bcast_mcast delta 3 -> ĐẠT (kiểm quy tắc), rule_check only"),
    ("C7", [('    if recon["verdict"] == "FAIL" or not all(checks.values()):', '    if False:')],
     "F4 a determined failure is reported even when execution also failed"),
    ("C8", [('"size": S.ICMP4_SIZES["T12-B1"]', '"size": 1201')], "D3 a registry change changes the command (single source)"),
    ("C9", [('    if crec.get("read_error"):\n        return', '    if False:\n        return')],
     "M6 a counter read that failed during execution -> LỖI PHÉP ĐO"),
    ("C10", [('    if missing:\n        return _result(cid, "LOI_PHEP_DO"', '    if False:\n        return _result(cid, "LOI_PHEP_DO"')],
     "M3 counter read 'after' missing -> LỖI PHÉP ĐO (never 0)"),
    ("C11", [('    if not ok:\n        rec["skipped"]', '    if False:\n        rec["skipped"]')],
     "R3 link before fails -> no ping is run, group skipped"),
    ("C12", [('            if rc == 127 or "not found" in (out or ""):', '            if False:')],
     "R6 rc 127 -> 'tool missing' execution error"),
    ("C13", [('    return (bool(case.get("ns_group")) and v6.get("icmp6_type") == 135', '    return (False and v6.get("icmp6_type") == 135')],   # 06B-4ER: line moved
     "P T13-I2: 3 probe frames = l2_bad_ethertype delta 3 -> ĐẠT (kiểm quy tắc), rule_check only"),
    ("C14", [('and ip.get("proto") == 1 and ip.get("tot_len") == case["size"] + 28)', 'and ip.get("proto") == 1)')],
     "K4 an ICMP echo to the same destination with another size is NOT a probe frame -> KHÔNG TẠO ĐƯỢC GÓI"),
    ("C15", [('    if record.get("skipped"):', '    if False:')],
     "U4 service link before the group failed -> every case CHƯA KIỂM CHỨNG, none judged"),
    ("C16", [('    except L.FrameReadError as e:\n        err = f"capture read error: {e}"',
              '    except L.FrameReadError as e:\n        frames, reads, err = [], l2eval.load_reads(counters_file), None')],
     "M1 capture missing -> every case LỖI PHÉP ĐO"),
    ("C17", [('            r["read_error"] = (r["read_error"] + "; " if r["read_error"] else "") + \\\n                f"read {r[\'after\']!r}: {type(e).__name__}: {e}"',
              '            pass')], "R5 a failed counter read is recorded as read_error"),
    ("C18", [('    for cat, code in (("FAIL", 1), ("LOI_PHEP_DO", 2)):', '    for cat, code in (("LOI_PHEP_DO", 2), ("FAIL", 1)):')],
     "L6 group exit: FAIL wins over a measurement error in the same group (FAIL > LỖI PHÉP ĐO)"),
    ("C19", [('        raise ValueError(f"bad interface name {iface!r}")', '        pass')], "D7 bad interface name refused"),
    # ---- 06B-4ER
    ("C20", [('    if not link_before_ok:\n        return _result', '    if False:\n        return _result')],
     "B1 ok=False, cases present, no 'skipped' -> evaluate_group gives CHƯA KIỂM CHỨNG, never ĐẠT"),
    ("C21", [('    return isinstance(state, dict) and state.get("ok") is True', '    return isinstance(state, dict) and bool(state.get("ok"))')],
     "B4 ok is the string 'true', cases present, no 'skipped' -> evaluate_group gives CHƯA KIỂM CHỨNG, never ĐẠT"),
    ("C22", [('    return isinstance(state, dict) and state.get("ok") is True', '    return state is not None and state.get("ok") is True')],
     "B6 state is a list, cases present, no 'skipped' -> evaluate_group gives CHƯA KIỂM CHỨNG, never ĐẠT"),
    ("C23", [('            and v6.get("ns_target") == case["dst"] and v6.get("dst") == case["ns_group"])',
              '            and v6.get("dst") == case["ns_group"])')],
     "N4 NS to the same group but another target is NOT a probe -> KHÔNG TẠO ĐƯỢC GÓI"),
    ("C24", [('            and v6.get("ns_target") == case["dst"] and v6.get("dst") == case["ns_group"])',
              '            and v6.get("ns_target") == case["dst"])')],
     "N8 right-target NS sent to the wrong multicast group is NOT a probe"),
    ("C25", [("    if not isinstance(record, dict) or not isinstance(record.get(\"cases\", []), list) or \\\n",
              "    if False and \\\n")],
     "B13 evaluate_group: 'cases' not a list -> ValueError (CLI exit 2)"),
    ("C26", [('    link_before, link_after = link_ok(record.get("service_link_before")), link_ok(record.get("service_link_after"))',
              '    link_before, link_after = not record.get("skipped"), link_ok(record.get("service_link_after"))')],
     "B1 ok=False, cases present, no 'skipped' -> evaluate_group gives CHƯA KIỂM CHỨNG, never ĐẠT"),
    ("C27", [('str(ipaddress.IPv6Address(p[48:64])) if len(p) >= 64 and plen >= 24 else None',
              'str(ipaddress.IPv6Address(p[40:56])) if len(p) >= 64 and plen >= 24 else None')],
     "N1 decode: ns_target of a well-formed NS is the target address", "l2frames.py"),
    ("C28", [('if len(p) >= 64 and plen >= 24 else None', 'if len(p) >= 64 else None')],
     "N10 decode: NS whose IPv6 payload ends before the target, followed by trailing bytes -> ns_target None", "l2frames.py"),
    ("X1", [("THIS TEXT IS NOT IN THE FILE", "x")], None),
    ("X2", [("import argparse\n", "import argparse(\n")], None),
]
EXPECT = {"X1": "INVALID", "X2": "ERROR"}


def sha(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in FILES}


def suite(d):
    p = subprocess.run([sys.executable, os.path.join(d, "selftest_icmp.py")], capture_output=True, text=True,
                       timeout=600, cwd=d)
    res = {}
    for l in p.stdout.splitlines():
        if l.startswith("[PASS] ") or l.startswith("[FAIL] "):
            res[l[7:].split("  (")[0]] = l.startswith("[PASS]")
    if not any(l.startswith("SELFTEST-ICMP:") for l in p.stdout.splitlines()):
        return None, (p.stderr or p.stdout).strip().splitlines()[-1:]
    return res, None


def main():
    h0 = sha(HERE)
    good = bad = 0
    with tempfile.TemporaryDirectory(prefix="mutation-icmp.") as tmp:
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
        for entry in M:
            mid, reps, target = entry[:3]
            fname = entry[3] if len(entry) > 3 else "icmp_cases.py"
            if target is not None and target not in base:
                print(f"BAD-TARGET {mid}: {target!r}")
                bad += 1
                continue
            d = copy()
            src = open(os.path.join(d, fname)).read()
            klass, failed = None, []
            for old, new in reps:
                if src.count(old) != 1:
                    klass = "INVALID"
                    break
                src = src.replace(old, new)
            if klass is None:
                open(os.path.join(d, fname), "w").write(src)
                res, err = suite(d)
                if res is None:
                    klass = "ERROR"
                else:
                    failed = sorted(k for k, v in res.items() if not v)
                    klass = "DETECTED" if target in failed else "DETECTED-ELSEWHERE" if failed else "MISSED"
            exp = EXPECT.get(mid, "DETECTED")
            ok = klass == exp
            good += ok
            bad += not ok
            print(f"{'OK ' if ok else 'BAD'} {mid:4s} {klass:18s} target={target!r}"
                  + ("" if klass in ("DETECTED", "INVALID", "MISSED") else f" failed={failed[:5]} {err or ''}"))
    same = sha(HERE) == h0
    print(f"MUTATION-ICMP: {good} OK, {bad} not as expected; harness {'unchanged' if same else 'CHANGED'}")
    return 0 if bad == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
