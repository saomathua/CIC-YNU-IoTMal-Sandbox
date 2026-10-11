set -u
FAILS=(); UNVERIFIED=(); SESSION_RESULTS=(); LEAK=0
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS+=("$*"); }
check() { local msg=$1; shift; if "$@"; then pass "$msg"; else fail "$msg"; return 1; fi; }
log(){ :; }; watch_ok(){ return 0; }; E(){ if [ "$1" = ps ]; then :; else [ "$V" != after-arm-verify-fail ] || [ "$ARCH" != ARM ]; fi; }
# bash -c commands here are only no-process checks: inert function, never launch them.
bash(){ return 0; }
timeout(){ echo "@@SEND_ARCH $ARCH"; if [ "$ARCH" = ARM ]; then case "$V" in arm-leak) return 99;; arm-capture) return 98;; arm-fail|arm-restore-fail) return 1;; esac; fi; return 0; }
# CLI and session reader replaced with deterministic stdout, no evaluator or network invoked here.
python3(){ if [ "${2:-}" = --outcome ]; then if [ "$ARCH" = ARM ] && [[ "$V" = arm-* ]]; then echo "FAIL: ${V#arm-}"; else echo PASS; fi; else echo PASS; fi; }
H=fixture; ID=fixture; TARGETS='{}'; D="$P"; OUT="$P"; DEAD="$P/dead"

for ARCH in ARM MIPS; do
    log "6. guest $ARCH"
    check "$ARCH: no QEMU running before start (sequential)" bash -c "! pgrep qemu-system >/dev/null"
    check "$ARCH: all host captures alive before start" test ! -s "$DEAD" || break
    check "$ARCH: capture watcher alive with a fresh heartbeat before start" watch_ok || break
    timeout 1700 docker exec -e CT01_TARGETS="$TARGETS" -e CT01_SUITE=arp "$ID" sh -c "cd /app && python3 /harness/probe_matrix.py $ARCH /harness-out"
    rc=$?
    echo "probe_matrix $ARCH exit=$rc"
    if [ $rc -eq 99 ] || grep -q . "$OUT/hostcap/alert.txt"; then
        LEAK=1; fail "$ARCH: PROBE PACKET SEEN ON HOST — all tests stopped"; break
    fi
    if [ $rc -eq 98 ] || [ -s "$DEAD" ] || ! watch_ok; then
        fail "$ARCH: capture or watcher lost during the test (probe_matrix rc=$rc; $(cat "$DEAD" 2>/dev/null)) — probes stopped"; break
    fi
    # 06B-3DR: separate real failures from probes that could not be decided (counter-window edges,
    # missing tool, no live control). Either way the run does not pass.
    # 06B-4I: arp_harness.py --outcome = run_outcome on every record (infrastructure included) + required and
    # per-case confirmations + status COMPLETED + each ARP case exactly once + group record valid. Any other
    # output is a FAIL below.
    outcome=$(python3 "$H/arp_harness.py" --outcome "$D/probe/$ARCH/result.json" "$D/probe/$ARCH/arp-eval.json" "$ARCH" 2>&1)
    echo "$ARCH: probe_matrix outcome: $outcome"
    case "$rc:$outcome" in
    0:PASS) pass "$ARCH: probe_matrix exit 0 (all checks and probes passed)" ;;
    1:UNVERIFIED*) UNVERIFIED+=("$ARCH: $outcome"); echo "[UNVERIFIED] $ARCH: $outcome" ;;
    *) fail "$ARCH: probe_matrix exit $rc, outcome: $outcome" ;;
    esac
    # 06B-3F: session-wide reconciliation, reported on its own; it is NOT added to FAILS/UNVERIFIED
    # and does not change the exit code of the run.
    sess=$(python3 -c 'import json, sys; s = json.load(open(sys.argv[1]))
print(s["verdict"] + ("" if not s["reasons"] else " — " + "; ".join(s["reasons"])))' "$D/probe/$ARCH/session.json" 2>&1) \
        || sess="not available (no session.json)"
    SESSION_RESULTS+=("$ARCH: $sess"); echo "[SESSION] $ARCH: $sess"
    E ps -eo pid,args > "$D/ps-after-$ARCH.txt"
    check "$ARCH: no qemu-system/tshark left in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps-after-$ARCH.txt'"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-3B after '"$ARCH"'"' > "$D/verify-after-$ARCH.txt" 2>&1
    check "$ARCH: full verify after guest shutdown" test $? -eq 0
done

printf "@@FAIL_COUNT=%s\n" "${#FAILS[@]}"
