#!/bin/bash
# 06B-3C / 06B-3CR — does selftest.sh catch broken helpers? No root, no Docker, no network, deletes nothing.
#
#   bash mutation_test.sh
#
# 1. Baseline: an unmodified copy must pass the syntax checks and selftest.sh; otherwise stop.
# 2. Each mutation edits a COPY (new mktemp dir) and is classified:
#      INVALID   the mutated file fails bash -n / Python parsing (syntax), selftest not run
#      ERROR     selftest could not run (SELFTEST-ERROR: missing tool, import, extraction)
#      MISSED    selftest still passes
#      DETECTED-ELSEWHERE  selftest fails, but not in the check this mutation targets
#      DETECTED  selftest fails in the targeted check (behaviour caught)
#    Behavioural mutations must be DETECTED. Two control mutations (a syntax error, a missing
#    dependency) must be INVALID and ERROR: they show that such failures are never counted as
#    "caught". Exit 0 only if every mutation got its expected class.
set -uo pipefail
H=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/ct01-06b3c-mut.XXXXXX")
echo "work dir (left in place for inspection): $W"
FILES=(run-06b3b.sh harness_lib.sh sigscan.sh selftest.sh mutation_test.sh independent_check.sh
       probe_matrix.py pcapng_stats.py make_fixtures.py ctl_loop.py counter_window.py)

copy() { local d; d=$(mktemp -d "$W/$1.XXXXXX"); cp "${FILES[@]/#/$H/}" "$d/"; echo "$d"; }
syntax_ok() {  # dir -> 0 if every file parses
    local d=$1 f
    for f in "$d"/*.sh; do bash -n "$f" 2>/dev/null || { echo "bash -n: ${f##*/}"; return 1; }; done
    for f in "$d"/*.py; do
        python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$f" 2>/dev/null || { echo "python: ${f##*/}"; return 1; }
    done
}
classify() {  # dir expected-check-substring -> prints class
    local d=$1 want=$2 out rc why
    why=$(syntax_ok "$d") || { echo "INVALID ($why)"; return; }
    out=$(bash "$d/selftest.sh" "$d/out" 2>&1); rc=$?
    echo "$out" > "$d/selftest.log"
    if grep -q '^SELFTEST-ERROR' <<< "$out"; then echo "ERROR ($(grep -m1 '^SELFTEST-ERROR' <<< "$out"))"; return; fi
    if [ $rc -eq 0 ]; then echo "MISSED"; return; fi
    if grep -E '^\[FAIL\]' <<< "$out" | grep -qF -- "$want"; then
        echo "DETECTED ($(grep -E '^\[FAIL\]' <<< "$out" | grep -F -m1 -- "$want"))"
    else
        echo "DETECTED-ELSEWHERE (rc=$rc; $(grep -E '^\[FAIL\]' <<< "$out" | head -2 | tr '\n' ' '))"
    fi
}

echo "== baseline (unmodified copy)"
B=$(copy baseline)
why=$(syntax_ok "$B") || { echo "BASELINE INVALID: $why"; exit 2; }
bash "$B/selftest.sh" "$B/out" > "$B/selftest.log" 2>&1; rc=$?
tail -1 "$B/selftest.log"
[ $rc -eq 0 ] || { echo "BASELINE FAILED (rc=$rc): mutation results would be meaningless"; exit 2; }

BAD=0
# mut <name> <expected class> <check substring> <file> <old> <new> [<old> <new> ...]
mut() {
    local name=$1 exp=$2 want=$3 file=$4 d res
    shift 4
    d=$(copy "$name")
    python3 - "$d/$file" "$@" <<'EOF' || { echo "[BAD] $name: mutation could not be applied"; BAD=$((BAD + 1)); return; }
import sys
p, pairs = sys.argv[1], sys.argv[2:]
s = open(p).read()
for old, new in zip(pairs[::2], pairs[1::2]):
    assert s.count(old) == 1, f"pattern found {s.count(old)} times: {old[:60]!r}"
    s = s.replace(old, new)
open(p, "w").write(s)
EOF
    res=$(classify "$d" "$want")
    if [ "${res%% *}" = "$exp" ]; then echo "[OK]  $name -> $res"; else echo "[BAD] $name -> $res (expected $exp)"; BAD=$((BAD + 1)); fi
}

echo "== behavioural mutations (must be DETECTED in the targeted check)"
mut S1-06b3b-url-regex DETECTED "positive.pcap: counts equal" sigscan.sh \
    'URL_RE="/ct01-06b3b-($NAMES)([^A-Za-z0-9.-]|\$)"' 'URL_RE="/ct01-06b3b-[0-9]"'
mut S2-count-lines-not-packets DETECTED "positive.pcap: counts equal" sigscan.sh \
    'P=$(printf '"'"'%s\n'"'"' "$A" | per_packet)' 'P=$A'
mut S3-read-error-ignored DETECTED "truncated.pcap: read error" sigscan.sh \
    'if [ $rc -ne 0 ] || grep -qv' 'if false && grep -qv'
mut W1-zombie-counts-as-alive DETECTED "watcher treats a zombie capture as dead" harness_lib.sh \
    '[ -n "$s" ] && [ "${s:0:1}" != Z ]' 'kill -0 "$1" 2>/dev/null'
mut W2-no-heartbeat-written DETECTED "heartbeat present and fresh" harness_lib.sh \
    'date +%s.%N > "$hb.tmp" && mv -f "$hb.tmp" "$hb"' ':'
mut W3-heartbeat-age-ignored-host DETECTED "heartbeat_fresh: 30 s old -> stale" harness_lib.sh \
    'exit !(age >= -1 && age <= max)' 'exit 0'
mut P1-heartbeat-age-ignored DETECTED "heartbeat 30 s old -> CaptureLost" probe_matrix.py \
    'if not -1.0 <= age <= HEARTBEAT_MAX_AGE:' 'if False:'
mut P2-missing-heartbeat-tolerated DETECTED "heartbeat missing -> CaptureLost" probe_matrix.py \
    'raise CaptureLost(f"{where}: host watcher heartbeat missing (watcher not running)")' 'hb = time.time()'
mut P3-killed-watcher-not-noticed DETECTED "real watcher killed while the capture still runs" probe_matrix.py \
    'if not -1.0 <= age <= HEARTBEAT_MAX_AGE:' 'if age < -1.0:'
mut P4-host-marker-ignored DETECTED "host marker present -> CaptureLost" probe_matrix.py \
    '    if dead:' '    if False:'
mut P5-unreadable-marker-tolerated DETECTED "marker unreadable" probe_matrix.py \
    'raise CaptureLost(f"{where}: host capture marker unreadable: {e}")' 'dead = ""'
mut P6-tshark-exit-ignored DETECTED "tshark exited -> CaptureLost" probe_matrix.py \
    'if tshark is None or tshark.poll() is not None:' 'if tshark is None:'
# with up rc ignored, C6 still fails later ("returned 0 but exited"); C7 (up fails after starting) is the case
mut M1-compose-up-rc-ignored DETECTED "C7 compose up fails after starting it" harness_lib.sh \
    'if [ $rc -ne 0 ]; then
        echo "compose up failed' 'if false; then
        echo "compose up failed'
mut M2-marked-started-before-confirmation DETECTED "NOT marked started" harness_lib.sh \
    'MANAGER_UP_ATTEMPTED=1
    out=' 'MANAGER_UP_ATTEMPTED=1; MANAGER_STARTED=1
    out='
mut M3-replacement-not-checked-before-stop DETECTED "C9 started by us, replaced" harness_lib.sh \
    'if [ "$id" != "$MANAGER_ID_BEFORE" ]; then
        echo "manager container was replaced' 'if false; then
        echo "manager container was replaced'
mut M4-stop-by-service-not-by-id DETECTED "C2 exited: exactly one compose up" harness_lib.sh \
    'docker stop -t 10 "$MANAGER_ID_BEFORE"' '"${COMPOSE[@]}" stop sandbox-manager'
mut M5-created-accepted DETECTED "C11 created" harness_lib.sh \
    '    exited) ;;' '    exited | created) ;;'
mut M6-running-manager-restarted DETECTED "C1 running: no compose up" harness_lib.sh \
    'echo "manager already running: used as is, will be left running"
        return 0' '"${COMPOSE[@]}" up -d sandbox-manager; echo "manager already running"'
mut M7-restart-not-detected DETECTED "C3 running, restarted" harness_lib.sh \
    '[ "$at" != "$MANAGER_STARTED_AT_BEFORE" ]' 'false'
mut N1-ifdrop-ignored DETECTED "ng-drop3.pcapng" pcapng_stats.py \
    'if isb["isb_ifdrop"] > 0:' 'if False:'
mut N2-missing-statistics-pass DETECTED "ng-no-stats.pcapng" pcapng_stats.py \
    'return "UNVERIFIED", "no interface statistics block: drop count unknown"' 'return "PASS", "assumed 0"'
mut N3-missing-ifdrop-as-zero DETECTED "ng-isb-without-ifdrop.pcapng" pcapng_stats.py \
    'if "isb_ifdrop" not in isb:' 'if False:' \
    'if isb["isb_ifdrop"] > 0:' 'if isb.get("isb_ifdrop", 0) > 0:'
mut N4-osdrop-ignored DETECTED "ng-osdrop2.pcapng" pcapng_stats.py \
    'if isb.get("isb_osdrop", 0) > 0:' 'if False:'
mut N5-ifrecv-mismatch-ignored DETECTED "ng-recv-mismatch.pcapng" pcapng_stats.py \
    'if "isb_ifrecv" in isb and isb["isb_ifrecv"] != stored:' 'if False:'
# ng-truncated.pcapng (cut inside the ISB) is still caught through struct.error -> PcapngError, so the
# length checks are targeted with ng-truncated-in-packet.pcapng (cut inside the last packet, no ISB)
mut N6-truncation-not-detected DETECTED "ng-truncated-in-packet.pcapng" pcapng_stats.py \
    'if blen < 12 or blen % 4 or off + blen > len(data):' 'if blen < 12 or blen % 4:' \
    'if struct.unpack_from(E + "I", data, off + blen - 4)[0] != blen:' 'if off + blen <= len(data) and struct.unpack_from(E + "I", data, off + blen - 4)[0] != blen:' \
    '        off += blen
    if st["interfaces"] == 0:' '        off += blen
        if off > len(data): break
    if st["interfaces"] == 0:'

echo "== 06B-3DR mutations (counter window, verdicts, capture stop, statistics)"
mut CW1-edges-ignored DETECTED "counter window edge-start-not-counted" counter_window.py \
    'elif hi > lo:' 'elif False:'
mut CW2-no-guard DETECTED "counter window guard-zone-before-read-b" counter_window.py \
    'GUARD_S = 0.020' 'GUARD_S = 0.0'
mut CW3-edges-as-certain DETECTED "counter window two-errors-cancel: expected" counter_window.py \
    'if z == "certain":' 'if z in ("certain", "edge_start", "edge_end"):'
mut CW4-ambiguity-hides-real-mismatch DETECTED "counter window real-mismatch-despite-edges" counter_window.py \
    'if d < lo or d > hi:
            v["status"] = "FAIL"
        elif hi > lo:
            v["status"] = "UNVERIFIED"' 'if hi > lo:
            v["status"] = "UNVERIFIED"
        elif d < lo or d > hi:
            v["status"] = "FAIL"'
mut V1-unverified-counted-as-ok DETECTED "reconciliation UNVERIFIED -> CHƯA KIỂM CHỨNG, not ok" counter_window.py \
    'return "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False' 'return "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", True'
mut V2-failed-check-hidden-by-unverified DETECTED "a real failure wins" counter_window.py \
    '        if v or k in PRECONDITION_CHECKS:
            continue' '        if True:
            continue'
mut V3-run-outcome-softens-failures DETECTED "failed non-probe check + undecided probe -> FAIL" counter_window.py \
    'hard = [r["test"] for r in bad if not (r["test"].startswith("probe ") and "-> CHƯA KIỂM CHỨNG" in r["test"])]' \
    'hard = [r["test"] for r in bad if r["test"].endswith("-> FAIL")]'
mut T1-no-kill-at-deadline DETECTED "stop_captures_deadline returned (no hang" harness_lib.sh \
    'kill -KILL "$p" 2>/dev/null; wait "$p" 2>/dev/null' 'wait "$p" 2>/dev/null'
mut T2-exit-code-not-kept DETECTED "capture exiting 3 on SIGINT recorded" harness_lib.sh \
    'wait "$p" 2>/dev/null; rc=$?' 'wait "$p" 2>/dev/null; rc=0'
mut G1-missing-statistic-as-zero DETECTED "missing 'dropped by kernel' line -> failure" harness_lib.sh \
    'END { if (nc != 1 || nr != 1 || nd != 1) exit 1; print c, r, d }' 'END { if (nc != 1) exit 1; print c, r, d + 0 }'

mut E1-evaluate-uses-old-window DETECTED "IPv6 frame inside read A (06B-3D shape)" probe_matrix.py \
    'span = [r for r in rows if ra["t_start"] - counter_window.GUARD_S <= r["t"] <= rb["t_end"]]' \
    'span = [r for r in rows if ra["t_end"] <= r["t"] <= rb["t_start"]]'
mut E2-undecided-probe-recorded-ok DETECTED "record of the undecided probe is not ok" probe_matrix.py \
    'record(f"probe {p['"'"'probe'"'"']} ({row['"'"'dst'"'"']}) -> {verdict}", ok,' \
    'record(f"probe {p['"'"'probe'"'"']} ({row['"'"'dst'"'"']}) -> {verdict}", True,'

echo "== 06B-3DR1 mutations (verdict precedence, measurement-data validation)"
mut PV1-old-precedence DETECTED "reconciliation FAIL + control missing -> FAIL" counter_window.py \
    '    if determined_failures(checks, recon, expected_class, tool_missing):
        return "FAIL", False
' '    if tool_missing:
        return "CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)", False
    if not control_alive:
        return "CHƯA KIỂM CHỨNG (không có đối chứng sống)", False
    if determined_failures(checks, recon, expected_class, tool_missing):
        return "FAIL", False
'
mut PV2-host-alert-as-precondition DETECTED "host alert + tool missing -> FAIL" counter_window.py \
    'PRECONDITION_CHECKS = ("control_alive_same_dst_proto_port",)' \
    'PRECONDITION_CHECKS = ("control_alive_same_dst_proto_port", "no_host_alert")'
mut PV3-guest-checks-skipped-with-tool DETECTED "guest reached the target (tool present) + control missing" counter_window.py \
    'if k in GUEST_SIDE_CHECKS and tool_missing:' 'if k in GUEST_SIDE_CHECKS:'
mut PV4-tool-missing-excuses-counter-fail DETECTED "reconciliation FAIL + tool missing -> FAIL" counter_window.py \
    'if recon.get("verdict") == "FAIL" or exp.get("status") == "FAIL":' \
    'if not tool_missing and (recon.get("verdict") == "FAIL" or exp.get("status") == "FAIL"):'
mut PV5-window-checks-on-invalid-data DETECTED "reversed read times -> LỖI PHÉP ĐO" counter_window.py \
    'if k in WINDOW_DERIVED_CHECKS and recon.get("verdict") == "ERROR":' 'if False:'
mut PV6-no-measurement-error-verdict DETECTED "measurement error -> LỖI PHÉP ĐO" counter_window.py \
    '    if recon.get("verdict") == "ERROR":
        return f"LỖI PHÉP ĐO' '    if False:
        return f"LỖI PHÉP ĐO'
mut VAL1-order-not-checked DETECTED "counter window reads-overlap" counter_window.py \
    'if not ts[0] <= ts[1] <= ts[2] <= ts[3]:' 'if False:'
mut VAL2-finiteness-not-checked DETECTED "counter window read-time-infinity" counter_window.py \
    'return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)' \
    'return isinstance(x, (int, float)) and not isinstance(x, bool)'
mut VAL3-negative-guard-accepted DETECTED "counter window guard-negative" counter_window.py \
    'if not _finite(guard) or guard < 0:' 'if not _finite(guard):'
mut VAL4-negative-delta-accepted DETECTED "counter window delta-negative" counter_window.py \
    'if not isinstance(d, int) or isinstance(d, bool) or d < 0:' 'if not isinstance(d, int) or isinstance(d, bool):'
mut VAL5-frame-time-not-checked DETECTED "counter window frame-time-nan" counter_window.py \
    'if not _finite(fr.get("t")):' 'if False:'

echo "== 06B-3F mutations (session-wide reconciliation)"
# 06B-3FR: the start edge is now also covered by the pre-window guest-frame rule, so the edge-end case is
# the one that isolates the edge handling of the session window
mut SE1-session-edges-ignored DETECTED "session edge-end" counter_window.py \
    '    if recon["verdict"] == "UNVERIFIED":
        out["reasons"].append("frames in the edge zones' '    if False:
        out["reasons"].append("frames in the edge zones'
mut SE2-capture-completeness-ignored DETECTED "session capture-incomplete-counter-above" counter_window.py \
    'capture_ok = (capture.get("tshark_rc") == 0 and capture.get("drop_verdict") == "PASS"
                  and capture.get("pcap_readable") is True)' 'capture_ok = True'
mut SE3-late-guest-frames-ignored DETECTED "session late-guest-frame" counter_window.py \
    '    if late:' '    if False:'
mut SE4-instability-after-exit-ignored DETECTED "session unstable-after-exit" counter_window.py \
    '    if unstable:' '    if False:'
mut SE5-qemu-before-not-checked DETECTED "session qemu-running-before" counter_window.py \
    '    if not qemu.get("no_qemu_before") or qemu.get("pids_before") != [] or qemu.get("pids_before_error"):' '    if False:'
mut SE6-time-order-not-checked DETECTED "session exit-after-final-read" counter_window.py \
    '    if any(a > b for a, b in zip(seq, seq[1:])):' '    if False:'
mut SE7-low-counter-softened-by-capture DETECTED "session capture-incomplete-counter-below" counter_window.py \
    'if recon["verdict"] == "FAIL" and (capture_ok or low):' 'if recon["verdict"] == "FAIL" and capture_ok:'
mut SE8-not-compared-hidden DETECTED "session clean: not-compared counters listed" counter_window.py \
    '    out["not_compared"] = nc' '    out["not_compared"] = {}'
mut SE9-session-enters-results DETECTED "session result does not enter results" probe_matrix.py \
    '    json.dump(res, open(os.path.join(OUT, "session.json"), "w"), indent=1, default=str)' \
    '    json.dump(res, open(os.path.join(OUT, "session.json"), "w"), indent=1, default=str)
    record("session-wide reconciliation", res["verdict"] == "PASS")'
mut SE10-final-reads-after-tshark-stop DETECTED "session step order" probe_matrix.py \
    'session["finals"].append(counters_read(f"session final {i + 1}"))' 'pass' \
    '            session["capture"] = {"tshark_rc"' '            session.setdefault("finals", []).append(counters_read("session final after tshark stop"))
            session["capture"] = {"tshark_rc"'
mut SE11-session-read-after-spawn DETECTED "session step order" probe_matrix.py \
    '        record_qemu_scan("before")
        session.update(read_before=counters_read("session before boot"))
' '' \
    '        proc = an._start_qemu(cfg)
' '        proc = an._start_qemu(cfg)
        record_qemu_scan("before"); session.update(read_before=counters_read("session before boot"))
'
mut SE12-session-read-missing DETECTED "required step missing" probe_matrix.py \
    '        record_qemu_scan("before")
        session.update(read_before=counters_read("session before boot"))
' ''

echo "== 06B-3FR mutations (session completeness: pre-window frames, QEMU state, F1+F2, counters)"
mut PW1-pre-window-frames-ignored DETECTED "session pre-window-guest-frame" counter_window.py \
    'for fr in frames if fr.get("cls") is not None and fr["t"] <= a_end]' 'for fr in frames if False]'
mut PW2-pre-window-compared-classes-only DETECTED "session pre-window-arp: expected" counter_window.py \
    'for fr in frames if fr.get("cls") is not None and fr["t"] <= a_end]' 'for fr in frames if fr.get("cls") in classes and fr["t"] <= a_end]'
mut PW3-pre-window-details-dropped DETECTED "frame recorded with timestamp, class and reason" counter_window.py \
    '    out["guest_frames_before_window"] = pre' '    out["guest_frames_before_window"] = [x["t"] for x in pre]'
mut QP1-qemu-after-exit-ignored DETECTED "session qemu-left-after-exit" counter_window.py \
    '    if pa:
        return done("ERROR", f"QEMU process(es) still present' '    if False:
        return done("ERROR", f"QEMU process(es) still present'
mut QP2-unverifiable-qemu-state-accepted DETECTED "session qemu-state-unverifiable" counter_window.py \
    'if not isinstance(pa, list) or qemu.get("pids_after_exit_error"):' 'if False:'
mut QP3-evaluate-session-drops-pids DETECTED "3FR replay 2: QEMU left after exit" probe_matrix.py \
    '"pids_after_exit": session.get("qemu_pids_after_exit"),' '"pids_after_exit": [],'
mut QP4-pids-before-not-checked DETECTED "session qemu-pids-before-inconsistent" counter_window.py \
    'if not qemu.get("no_qemu_before") or qemu.get("pids_before") != [] or qemu.get("pids_before_error"):' \
    'if not qemu.get("no_qemu_before") or qemu.get("pids_before_error"):'
mut FR1-f2-not-required DETECTED "session missing-F2" counter_window.py \
    'if not isinstance(final_reads, list) or len(final_reads) < required_finals:' 'if not final_reads:'
mut FR2-final-read-error-ignored DETECTED "session final-read-error" counter_window.py \
    '    if final_read_error:
        return done("ERROR", f"a final counter read failed' '    if False:
        return done("ERROR", f"a final counter read failed'
mut FR3-evaluate-session-drops-read-error DETECTED "3FR replay 3: final read error" probe_matrix.py \
    'final_read_error=session.get("final_read_error"))' 'final_read_error=None)'
mut CC1-missing-counter-as-zero DETECTED "session class-missing-in-A" counter_window.py \
    '        if missing:
            return done("ERROR", f"counter read {name} lacks' '        if False:
            return done("ERROR", f"counter read {name} lacks' \
    'delta = {k: first["values"][k] - read_before["values"][k] for k in classes}' \
    'delta = {k: first["values"].get(k, 0) - read_before["values"].get(k, 0) for k in classes}'

echo "== 06B-3FR1 mutations (QEMU process scan errors)"
mut Q1-scan-swallows-oserror DETECTED "3FR1 4: PermissionError on /proc/2/comm" probe_matrix.py \
    '        except OSError as e:
            raise ProcessScanError(f"cannot read {path}' '        except OSError as e:
            continue
            raise ProcessScanError(f"cannot read {path}'
mut Q2-vanished-pid-is-error DETECTED "3FR1 3: pid listed then vanished" probe_matrix.py \
    '            continue   # the process exited between listing and reading' \
    '            raise ProcessScanError("vanished pid treated as an error")'
mut Q3-no-pid-dir-check DETECTED "3FR1 3b: comm missing although /proc/4 exists" probe_matrix.py \
    '            if os.path.exists(f"{PROC_ROOT}/{d}"):' '            if False:'
mut Q4-record-swallows-error DETECTED "3FR1 4: PermissionError on /proc/2/comm" probe_matrix.py \
    '        pids, err = None, f"{type(e).__name__}: {e}"' '        pids, err = [], None'
mut Q5-unlistable-proc-swallowed DETECTED "3FR1 4: /proc not listable" probe_matrix.py \
    '        raise ProcessScanError(f"cannot list {PROC_ROOT}: {type(e).__name__}: {e}")' '        return []'

echo "== control mutations (must NOT be counted as caught)"
mut X1-syntax-error INVALID "-" pcapng_stats.py 'def drop_verdict(st):' 'def drop_verdict(st:'
mut X2-missing-dependency ERROR "-" selftest.sh 'import pcapng_stats as P' 'import pcapng_stats_missing as P'

echo
[ $BAD -eq 0 ] && { echo "MUTATION TEST: every mutation got its expected class"; exit 0; }
echo "MUTATION TEST: $BAD mutation(s) not as expected"; exit 1
