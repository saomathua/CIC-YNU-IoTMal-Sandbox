#!/bin/bash
# 06B-3C / 06B-3CR — offline self-test of the harness helpers.
# No root, no Docker, no QEMU, no network traffic. Deletes nothing (it runs as root inside run-06b3b.sh).
#
#   bash selftest.sh [outdir]
#
#  0. prerequisites (tools); a missing tool is a SELFTEST-ERROR, not a behavioural failure
#  A. sigscan.sh against generated pcap fixtures; every real probe URL must match
#  A2. pcapng_stats.py: drop=0, drop>0, osdrop>0, ifrecv mismatch, no statistics, statistics without
#      ifdrop, truncated, not pcapng; plus the two real 06B-3B run 5 tap0.pcapng if present
#  B. capture watcher (harness_lib.sh): heartbeat refreshed; marker when a capture dies; heartbeat
#     goes stale when the watcher is killed while the captures still run; heartbeat_fresh cases
#  B2. probe_matrix.py captures_alive (extracted with ast): tshark, marker and heartbeat cases, and a
#      real watcher killed while captures run -> CaptureLost
#  C. manager handling (harness_lib.sh) with a fake docker/compose, 12 scenarios
# Lines "[FAIL] ..." are behavioural failures; "SELFTEST-ERROR: ..." means the test itself could not
# run (missing tool, fixture build, extraction). Exit 0 only if every check passes.
set -uo pipefail
H=$(cd "$(dirname "$0")" && pwd)
OUTD=${1:-$(mktemp -d)}
mkdir -p "$OUTD"
FAILS=0
ok()  { echo "[PASS] $*"; }
bad() { echo "[FAIL] $*"; FAILS=$((FAILS + 1)); }
t()   { local m=$1; shift; if "$@"; then ok "$m"; else bad "$m"; fi; }
infra() { echo "SELFTEST-ERROR: $*"; exit 3; }

echo "== 0. prerequisites"
for c in tcpdump python3 ps awk grep mktemp sleep date; do command -v "$c" > /dev/null || infra "missing tool: $c"; done
echo "tcpdump: $(tcpdump --version 2>&1 | head -1); python3: $(python3 --version 2>&1)"

echo "== A. signature scanner"
python3 "$H/make_fixtures.py" "$OUTD/fx" || infra "fixture build failed"
sha256sum "$OUTD"/fx/*.pcap "$OUTD"/fx/*.pcapng
for f in positive.pcap negative.pcap; do
    got=$(bash "$H/sigscan.sh" "$OUTD/fx/$f"); rc=$?
    echo "-- $f (rc=$rc)"; echo "$got"
    t "$f: sigscan exit 0" test $rc -eq 0
    want=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1]))[sys.argv[2]]; print('\n'.join(f'{k}={v}' for k,v in d.items()))" \
        "$OUTD/fx/expected.json" "$f") || infra "expected.json unreadable"
    t "$f: counts equal expected.json" test "$got" = "$want"
done
for f in truncated.pcap empty.pcap; do
    bash "$H/sigscan.sh" "$OUTD/fx/$f" > /dev/null 2> "$OUTD/fx/$f.err"; rc=$?
    echo "-- $f: rc=$rc $(head -c 200 "$OUTD/fx/$f.err")"
    t "$f: read error reported (exit 2), never counted as 0 packets" test $rc -eq 2
done
bash "$H/sigscan.sh" "$OUTD/fx/missing.pcap" > /dev/null 2>&1
t "missing file: read error reported (exit 2)" test $? -eq 2
names=$(python3 - "$H/probe_matrix.py" <<'EOF'
import re, sys
src = open(sys.argv[1]).read()
fixed = re.findall(r'plan(?:\.append\(\(| = \[\()"([a-z0-9-]+)"', src)
assert 'f"ssh-host-{ip}"' in src
print("\n".join(fixed + ["ssh-host-192.168.60.1", "ssh-host-192.168.177.128", "ssh-host-172.18.0.1"]))
EOF
) || infra "probe names not extracted from probe_matrix.py"
echo "probe names from probe_matrix.py: $(echo $names)"
t "probe_matrix.py plan has 7 fixed names + 3 ssh-host" test "$(echo "$names" | wc -l)" -eq 10
URL_RE=$(bash -c 'source <(sed -n "/^NAMES=/p;/^URL_RE=/p" "$1"); echo "$URL_RE"' _ "$H/sigscan.sh")
[ -n "$URL_RE" ] || infra "URL_RE not found in sigscan.sh"
miss=0
for n in $names; do
    printf 'GET /ct01-06b3b-%s HTTP/1.1\n' "$n" | grep -qE "$URL_RE" || { echo "no match: $n"; miss=1; }
done
t "every real probe URL matches the scanner regex" test $miss -eq 0
t "06B-3B regex /ct01-06b3b-[0-9] matched none of them (the defect fixed in 06B-3C)" \
    bash -c "! printf '%s\n' $(echo $names | sed 's|[^ ]*|/ct01-06b3b-&|g') | grep -qE '/ct01-06b3b-[0-9]'"

echo "== A2. pcapng drop statistics (pcapng_stats.py)"
python3 - "$H" "$OUTD/fx" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[1])
try:
    import pcapng_stats as P
except Exception as e:
    print(f"SELFTEST-ERROR: import pcapng_stats: {e}"); sys.exit(3)
fx = sys.argv[2]
want = json.load(open(os.path.join(fx, "expected.json")))["pcapng_verdicts"]
fails = 0
for name, verdict in want.items():
    try:
        got = P.drop_verdict(P.read_stats(os.path.join(fx, name)))
    except P.PcapngError as e:
        got = ("ERROR", str(e))
    except Exception as e:   # anything else is a reader bug: report it against this fixture
        got = ("EXCEPTION", f"{type(e).__name__}: {e}")
    good = got[0] == verdict
    fails += not good
    print(f"[{'PASS' if good else 'FAIL'}] {name}: expected {verdict}, got {got[0]} ({got[1]})")
real = "/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/docs/evidence/task06b3b/run5/container/probe"
for arch, n in (("ARM", 97), ("MIPS", 125)):
    f = f"{real}/{arch}/tap0.pcapng"
    if not os.path.exists(f):
        print(f"[SKIP] real 06B-3B {arch} tap0.pcapng not present"); continue
    st = P.read_stats(f); v = P.drop_verdict(st); isb = st["isb"].get(0, {})
    good = v[0] == "PASS" and isb.get("isb_ifrecv") == n and isb.get("isb_ifdrop") == 0 and st["epb"].get(0) == n
    fails += not good
    print(f"[{'PASS' if good else 'FAIL'}] real 06B-3B {arch} tap0.pcapng: {v[0]}, isb={isb}, stored={st['epb']}")
sys.exit(1 if fails else 0)
EOF
rc=$?
[ $rc -eq 3 ] && infra "pcapng_stats test could not run"
t "pcapng_stats verdicts as expected" test $rc -eq 0

echo "== B. capture watcher with heartbeat"
source "$H/harness_lib.sh" || infra "harness_lib.sh not sourceable"
WD=$(mktemp -d "$OUTD/watch.XXXXXX"); M=$WD/capture-dead.txt; HBF=$WD/heartbeat
sleep 60 & P1=$!
sleep 60 & P2=$!
start_capture_watch "$M" "$HBF" 0.2 "p1:$P1" "p2:$P2"
sleep 1
t "watcher quiet while captures run" test ! -e "$M"
t "heartbeat present and fresh" heartbeat_fresh "$HBF" 1
h1=$(cat "$HBF"); sleep 0.6; h2=$(cat "$HBF")
t "heartbeat refreshed ($h1 -> $h2)" test "$h1" != "$h2"
# watcher killed while both captures still run: no marker, but the heartbeat must go stale
kill "$WATCH_PID"; wait "$WATCH_PID" 2>/dev/null
t "captures still alive after the watcher was killed" bash -c "kill -0 $P1 && kill -0 $P2"
sleep 1.6
t "heartbeat stale 1.6 s after the watcher died (limit 1 s)" bash -c "! { source '$H/harness_lib.sh'; heartbeat_fresh '$HBF' 1; }"
# capture death: marker names it
WD2=$(mktemp -d "$OUTD/watch.XXXXXX"); M2=$WD2/capture-dead.txt
start_capture_watch "$M2" "$WD2/heartbeat" 0.2 "p1:$P1" "p2:$P2"
sleep 0.5
kill "$P2"; wait "$P2" 2>/dev/null
for i in $(seq 1 20); do [ -s "$M2" ] && break; sleep 0.2; done
echo "marker: $(cat "$M2" 2>/dev/null)"
t "watcher writes marker naming the dead capture" grep -q "p2 pid $P2 exited" "$M2"
t "watcher ends after a capture died" bash -c "sleep 0.5; ! kill -0 $WATCH_PID 2>/dev/null"
# A real zombie: a parent (python) that never reaps its killed child. kill -0 still succeeds on a
# zombie, so the watcher must treat it as dead. (06B-3C's test killed a child of this shell, which
# bash reaps at once, so no zombie ever existed; found by mutation W1 in 06B-3CR.)
python3 -c 'import os, subprocess, time
p = subprocess.Popen(["sleep", "60"]); print(p.pid, flush=True); os.kill(p.pid, 9); time.sleep(30)' > "$WD2/zpid" &
ZP=$!
for i in $(seq 1 20); do [ -s "$WD2/zpid" ] && break; sleep 0.1; done; sleep 0.3
Z=$(cat "$WD2/zpid")
[ "$(ps -o stat= -p "$Z" 2>/dev/null | cut -c1)" = Z ] || infra "could not create a zombie for the watcher test (pid $Z)"
t "precondition: pid $Z is a zombie and kill -0 still succeeds on it" kill -0 "$Z"
M3=$WD2/zombie-marker.txt
start_capture_watch "$M3" "$WD2/heartbeat-z" 0.2 "p1:$P1" "z:$Z"
for i in $(seq 1 20); do [ -s "$M3" ] && break; sleep 0.2; done
t "watcher treats a zombie capture as dead (marker written)" grep -q "z pid $Z exited" "$M3"
stop_capture_watch
kill "$ZP" "$P1"; wait "$ZP" "$P1" 2>/dev/null
echo "$(date +%s.%N)" > "$WD/hb-now"; echo "$(( $(date +%s) - 30 )).0" > "$WD/hb-old"; echo "garbage" > "$WD/hb-bad"
echo "$(( $(date +%s) + 60 )).0" > "$WD/hb-future"
t "heartbeat_fresh: current -> fresh" heartbeat_fresh "$WD/hb-now" 5
t "heartbeat_fresh: 30 s old -> stale" bash -c "! { source '$H/harness_lib.sh'; heartbeat_fresh '$WD/hb-old' 5; }"
t "heartbeat_fresh: unparsable -> stale" bash -c "! { source '$H/harness_lib.sh'; heartbeat_fresh '$WD/hb-bad' 5; }"
t "heartbeat_fresh: 60 s in the future -> stale" bash -c "! { source '$H/harness_lib.sh'; heartbeat_fresh '$WD/hb-future' 5; }"
t "heartbeat_fresh: missing file -> stale" bash -c "! { source '$H/harness_lib.sh'; heartbeat_fresh '$WD/none' 5; }"

echo "== B2. probe_matrix.py captures_alive (extracted with ast; sleep stands in for tshark/tcpdump)"
WD3=$(mktemp -d "$OUTD/pm.XXXXXX")
sleep 60 & C1=$!
start_capture_watch "$WD3/capture-dead.txt" "$WD3/heartbeat" 0.2 "c1:$C1"
sleep 0.5
python3 - "$H/probe_matrix.py" "$WD3" "$WATCH_PID" <<'EOF'
import ast, os, signal, subprocess, sys, time
src, wd, watcher = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    tree = ast.parse(open(src).read())
    keep = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
            and n.name in ("CaptureLost", "captures_alive")]
    assert len(keep) == 2, "captures_alive / CaptureLost not found"
except Exception as e:
    print(f"SELFTEST-ERROR: extraction: {e}"); sys.exit(3)
fails = 0
def run(msg, marker, hb, tshark, lost, max_age=5.0):
    global fails
    ns = {"time": time, "CAPTURE_DEAD": marker, "HEARTBEAT": hb, "HEARTBEAT_MAX_AGE": max_age}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "probe_matrix.py", "exec"), ns)
    try:
        ns["captures_alive"](tshark, "t"); got, why = False, ""
    except ns["CaptureLost"] as e:
        got, why = True, str(e)
    good = got == lost
    fails += not good
    print(f"[{'PASS' if good else 'FAIL'}] {msg}" + (f" ({why})" if why else ""))
def w(name, text):
    p = os.path.join(wd, name); open(p, "w").write(text); return p
none = os.path.join(wd, "absent")
fresh = w("hb-fresh", f"{time.time()}\n"); old = w("hb-old", f"{time.time() - 30}\n")
bad = w("hb-bad", "xyz\n"); future = w("hb-future", f"{time.time() + 60}\n")
dead = w("marker-dead", "12:00:00 capture ens33 pid 1 exited during the test\n"); empty = w("marker-empty", "")
os.mkdir(os.path.join(wd, "marker-dir"))
p = subprocess.Popen(["sleep", "60"])
run("tshark alive, no marker, fresh heartbeat -> continue", none, fresh, p, False)
run("empty marker file -> continue", empty, fresh, p, False)
run("host marker present -> CaptureLost", dead, fresh, p, True)
run("marker unreadable (a directory) -> CaptureLost", os.path.join(wd, "marker-dir"), fresh, p, True)
run("heartbeat missing -> CaptureLost", none, none, p, True)
run("heartbeat 30 s old -> CaptureLost", none, old, p, True)
run("heartbeat unparsable -> CaptureLost", none, bad, p, True)
run("heartbeat in the future -> CaptureLost", none, future, p, True)
live = os.path.join(wd, "heartbeat")
run("real watcher running -> continue", os.path.join(wd, "capture-dead.txt"), live, p, False, 1.0)
os.kill(watcher, signal.SIGTERM)
time.sleep(1.6)
run("real watcher killed while the capture still runs -> CaptureLost", os.path.join(wd, "capture-dead.txt"), live, p, True, 1.0)
p.kill(); p.wait()
run("tshark exited -> CaptureLost", none, fresh, p, True)
run("tshark never started -> CaptureLost", none, fresh, None, True)
sys.exit(1 if fails else 0)
EOF
rc=$?
wait "$WATCH_PID" 2>/dev/null; kill "$C1"; wait "$C1" 2>/dev/null
[ $rc -eq 3 ] && infra "captures_alive test could not run"
t "probe_matrix.py captures_alive behaves as specified" test $rc -eq 0

echo "== C. manager handling (fake docker)"
# Fake docker. State in $FAKE_STATE: status, id, started, calls; behaviour: up_mode, stop_mode.
#   up_mode:  ok | fail (nothing changes, rc 1) | fail-started (container runs, rc 1) | recreate (new id)
#   stop_mode: ok | fail
docker() {
    case "$1" in
    inspect) case "$3" in
        *State.Status*) cat "$FAKE_STATE/status" ;;
        *State.StartedAt*) cat "$FAKE_STATE/started" ;;
        *.Id*) cat "$FAKE_STATE/id" ;;
        esac ;;
    compose)
        case " $* " in
        *" up "*)
            echo up >> "$FAKE_STATE/calls"
            case $(cat "$FAKE_STATE/up_mode") in
            ok) echo running > "$FAKE_STATE/status"; date +%s%N > "$FAKE_STATE/started" ;;
            fail) echo "compose: error" >&2; return 1 ;;
            fail-started) echo running > "$FAKE_STATE/status"; date +%s%N > "$FAKE_STATE/started"; return 1 ;;
            recreate) echo cid-new > "$FAKE_STATE/id"; echo running > "$FAKE_STATE/status"; date +%s%N > "$FAKE_STATE/started" ;;
            esac ;;
        *) echo "other-compose" >> "$FAKE_STATE/calls" ;;
        esac ;;
    stop)
        echo "stop ${*: -1}" >> "$FAKE_STATE/calls"
        [ "$(cat "$FAKE_STATE/stop_mode")" = ok ] || return 1
        [ "${*: -1}" = "$(cat "$FAKE_STATE/id")" ] || return 1
        echo exited > "$FAKE_STATE/status" ;;
    *) echo "other-docker $1" >> "$FAKE_STATE/calls" ;;
    esac
}
COMPOSE=(docker compose -f fake.yml); MANAGER=fake-manager
# scenario <initial status> <up_mode> <stop_mode> [tamper during the test]
# sets PREP_RC, REST_RC, STARTED; calls/status are read from $FAKE_STATE afterwards
scenario() {
    FAKE_STATE=$(mktemp -d "$OUTD/fake-manager.XXXXXX")
    MANAGER_STARTED=0; MANAGER_UP_ATTEMPTED=0; MANAGER_RESTORED=0; MANAGER_RESTORE_RC=0; unset MANAGER_STATE_BEFORE
    echo "$1" > "$FAKE_STATE/status"; echo T0 > "$FAKE_STATE/started"; echo cid1 > "$FAKE_STATE/id"; : > "$FAKE_STATE/calls"
    echo "$2" > "$FAKE_STATE/up_mode"; echo "$3" > "$FAKE_STATE/stop_mode"
    manager_prepare > "$FAKE_STATE/prepare.out" 2>&1; PREP_RC=$?
    STARTED=$MANAGER_STARTED
    [ -n "${4:-}" ] && eval "$4"
    manager_restore > "$FAKE_STATE/restore.out" 2>&1; REST_RC=$?
}
calls() { tr '\n' ' ' < "$FAKE_STATE/calls"; }
st() { cat "$FAKE_STATE/status"; }

scenario running ok ok
t "C1 running: prepare 0, restore 0, still running" test $PREP_RC -eq 0 -a $REST_RC -eq 0 -a "$(st)" = running
t "C1 running: no compose up and no stop (never restarted)" test -z "$(calls)"
scenario exited ok ok
t "C2 exited: prepare 0, marked started, restore 0, exited again" test $PREP_RC -eq 0 -a "$STARTED" = 1 -a $REST_RC -eq 0 -a "$(st)" = exited
t "C2 exited: exactly one compose up, then docker stop of the same id" test "$(calls)" = "up stop cid1 "
scenario running ok ok 'date +%s%N > "$FAKE_STATE/started"'
t "C3 running, restarted during the test: restore fails, nothing stopped" test $REST_RC -ne 0 -a -z "$(calls)"
scenario running ok ok 'echo cid2 > "$FAKE_STATE/id"'
t "C4 running, container replaced: restore fails, replacement not stopped" test $REST_RC -ne 0 -a -z "$(calls)" -a "$(st)" = running
scenario running ok ok 'echo exited > "$FAKE_STATE/status"'
t "C5 running, stopped by someone else: restore fails" test $REST_RC -ne 0
scenario exited fail ok
t "C6 compose up fails: prepare non-zero, NOT marked started" test $PREP_RC -ne 0 -a "$STARTED" = 0
t "C6 compose up fails: restore 0, nothing stopped, still exited" test $REST_RC -eq 0 -a "$(calls)" = "up " -a "$(st)" = exited
scenario exited fail-started ok
t "C7 compose up fails after starting it: prepare non-zero, NOT marked started" test $PREP_RC -ne 0 -a "$STARTED" = 0
t "C7 ... restore stops that same container and returns 0" test $REST_RC -eq 0 -a "$(calls)" = "up stop cid1 " -a "$(st)" = exited
scenario exited recreate ok
t "C8 compose up replaced the container: prepare non-zero, NOT marked started" test $PREP_RC -ne 0 -a "$STARTED" = 0
t "C8 ... restore fails and does not stop the replacement" test $REST_RC -ne 0 -a "$(calls)" = "up " -a "$(st)" = running
scenario exited ok ok 'echo cid2 > "$FAKE_STATE/id"'
t "C9 started by us, replaced during the test: restore fails, replacement not stopped" \
    test $REST_RC -ne 0 -a "$(calls)" = "up " -a "$(st)" = running
scenario exited ok fail
t "C10 docker stop fails: restore fails" test $REST_RC -ne 0 -a "$(calls)" = "up stop cid1 "
scenario created ok ok
t "C11 created: refused before any change (no docker call that changes state)" test $PREP_RC -ne 0 -a -z "$(calls)" -a "$(st)" = created
scenario paused ok ok
t "C12 paused: refused before any change" test $PREP_RC -ne 0 -a -z "$(calls)" -a "$(st)" = paused
unset -f docker

echo
[ $FAILS -eq 0 ] && { echo "SELFTEST: ALL PASSED"; exit 0; }
echo "SELFTEST: $FAILS FAILED"; exit 1
