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
#  D. counter window reconciliation (counter_window.py): 11 cases incl. edges, guard zone, real
#     mismatch and two errors that cancel (the old 06B-3B/3D method gives a false PASS there)
#  E. probe verdict and run outcome: UNVERIFIED is never a pass; a real failure wins over UNVERIFIED
#  F. capture stop with deadline: exit 0, exit 3, SIGINT ignored -> killed at the deadline
#  G. tcpdump statistics parsing: a missing line is a failure, never 0
#  H. probe_matrix.py evaluate() replayed offline with stub worker modules: clean -> ĐẠT,
#     IPv6 frame inside read A (06B-3D shape) -> CHƯA KIỂM CHỨNG, real mismatch -> FAIL
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

echo "== D. counter window reconciliation (counter_window.py, 06B-3DR)"
python3 - "$H" "$OUTD/fx/counter-window-cases.json" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[1])
try:
    import counter_window as cw
    F = json.load(open(sys.argv[2]))
except Exception as e:
    print(f"SELFTEST-ERROR: counter_window / cases: {e}"); sys.exit(3)
def old(c):   # the 06B-3B/3D method: window [A.t_end, B.t_start], plain equality
    cnt = {}
    for f in c["frames"]:
        if F["read_before"]["t_end"] <= f["t"] <= F["read_after"]["t_start"]:
            cnt[f["cls"]] = cnt.get(f["cls"], 0) + 1
    return "PASS" if all(c["delta"].get(k, 0) == cnt.get(k, 0) for k in F["classes"]) else "FAIL"
fails = 0
for c in F["cases"]:
    ra, rb = c.get("read_before", F["read_before"]), c.get("read_after", F["read_after"])
    r = cw.reconcile(c["frames"], ra, rb, c["delta"], F["classes"], guard=c.get("guard", cw.GUARD_S))
    good = r["verdict"] == c["expected"]
    fails += not good
    extra = f"old method would say {old(c)}" if c["old_method"] else f"error: {r.get('error')}"
    print(f"[{'PASS' if good else 'FAIL'}] counter window {c['name']}: expected {c['expected']}, got {r['verdict']} ({extra})")
    if c["name"] == "two-errors-cancel":
        g2 = old(c) == "PASS" and r["verdict"] == "UNVERIFIED"
        fails += not g2
        print(f"[{'PASS' if g2 else 'FAIL'}] counter window two-errors-cancel: old method gives a false PASS, new gives UNVERIFIED")
sys.exit(1 if fails else 0)
EOF
rc=$?; [ $rc -eq 3 ] && infra "counter window test could not run"
t "counter_window reconciliation as expected" test $rc -eq 0

echo "== E. probe verdict and run outcome (counter_window.py)"
python3 - "$H" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
try:
    import counter_window as cw
except Exception as e:
    print(f"SELFTEST-ERROR: import counter_window: {e}"); sys.exit(3)
ok_checks = {"guest_connection_failed": True, "control_alive_same_dst_proto_port": True,
             "probe_packets_in_tap0_pcap": True, "probe_packets_hit_expected_counter": True, "no_host_alert": True}
# what probe_matrix records when the guest lacks the tool: the guest-side checks are False (not performed)
G_TOOL_MISSING = {**ok_checks, "guest_connection_failed": False, "probe_packets_in_tap0_pcap": False,
                  "probe_packets_hit_expected_counter": False}
def rc(verdict, exp_status="PASS", exp_delta=3):
    return {"verdict": verdict, "per_class": {"drop_public": {"status": exp_status, "delta": exp_delta}}}
cases = [
    ("all checks, reconciliation PASS -> ĐẠT", (ok_checks, rc("PASS")), {}, ("ĐẠT", True)),
    ("reconciliation UNVERIFIED -> CHƯA KIỂM CHỨNG, not ok", (ok_checks, rc("UNVERIFIED", "UNVERIFIED")), {},
     ("CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False)),
    ("expected class PASS but another class UNVERIFIED -> CHƯA KIỂM CHỨNG", (ok_checks, rc("UNVERIFIED")), {},
     ("CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False)),
    ("reconciliation FAIL -> FAIL", (ok_checks, rc("FAIL", "FAIL")), {}, ("FAIL", False)),
    ("failed check + UNVERIFIED -> FAIL (a real failure wins)", ({**ok_checks, "guest_connection_failed": False},
     rc("UNVERIFIED", "UNVERIFIED")), {}, ("FAIL", False)),
    ("expected counter did not move -> FAIL", (ok_checks, rc("PASS", "PASS", 0)), {}, ("FAIL", False)),
    ("tool missing -> CHƯA KIỂM CHỨNG", (ok_checks, rc("PASS")), {"tool_missing": True},
     ("CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)", False)),
    # 06B-3DR1: determined failures are kept before missing tool / missing control
    ("reconciliation FAIL + control missing -> FAIL", ({**ok_checks, "control_alive_same_dst_proto_port": False},
     rc("FAIL", "FAIL")), {"control_alive": False}, ("FAIL", False)),
    ("reconciliation FAIL + tool missing -> FAIL", (G_TOOL_MISSING, rc("FAIL", "FAIL")), {"tool_missing": True}, ("FAIL", False)),
    ("host alert + tool missing -> FAIL", ({**G_TOOL_MISSING, "no_host_alert": False}, rc("PASS", "PASS", 0)),
     {"tool_missing": True}, ("FAIL", False)),
    ("host alert + control missing -> FAIL", ({**ok_checks, "control_alive_same_dst_proto_port": False, "no_host_alert": False},
     rc("PASS")), {"control_alive": False}, ("FAIL", False)),
    ("guest reached the target (tool present) + control missing -> FAIL",
     ({**ok_checks, "guest_connection_failed": False, "control_alive_same_dst_proto_port": False}, rc("PASS")),
     {"control_alive": False}, ("FAIL", False)),
    ("only control missing (nothing failed) -> CHƯA KIỂM CHỨNG (đối chứng)",
     ({**ok_checks, "control_alive_same_dst_proto_port": False}, rc("PASS")), {"control_alive": False},
     ("CHƯA KIỂM CHỨNG (không có đối chứng sống)", False)),
    ("only tool missing (guest-side checks not performed) -> CHƯA KIỂM CHỨNG (công cụ)",
     (G_TOOL_MISSING, rc("PASS", "PASS", 0)), {"tool_missing": True}, ("CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)", False)),
    ("tool missing + counter-window edges -> CHƯA KIỂM CHỨNG (công cụ)",
     (G_TOOL_MISSING, rc("UNVERIFIED", "UNVERIFIED", 0)), {"tool_missing": True}, ("CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)", False)),
    ("measurement error -> LỖI PHÉP ĐO (not PASS, not CHƯA KIỂM CHỨNG)",
     (ok_checks, {"verdict": "ERROR", "error": "read times out of order", "per_class": {}}), {},
     ("LỖI PHÉP ĐO (read times out of order)", False)),
    ("measurement error + host alert -> FAIL",
     ({**ok_checks, "no_host_alert": False}, {"verdict": "ERROR", "error": "x", "per_class": {}}), {}, ("FAIL", False)),
]
fails = 0
for name, (checks, recon), kw, want in cases:
    got = cw.probe_verdict(checks, recon, "drop_public", **kw)
    good = got == want; fails += not good
    print(f"[{'PASS' if good else 'FAIL'}] probe verdict: {name} (got {got})")
P = lambda t, ok: {"test": t, "ok": ok}
outs = [
    ("all ok -> PASS", [P("x", True), P("probe a (tcp) -> ĐẠT", True)], "PASS"),
    ("one undecided probe -> UNVERIFIED", [P("x", True), P("probe a (tcp) -> CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False)], "UNVERIFIED"),
    ("one failed probe -> FAIL", [P("probe a (tcp) -> FAIL", False)], "FAIL"),
    ("probe with a measurement error -> FAIL", [P("probe a (tcp) -> LỖI PHÉP ĐO (read times out of order)", False)], "FAIL"),
    ("failed non-probe check + undecided probe -> FAIL",
     [P("tap0 capture stopped cleanly", False), P("probe a (tcp) -> CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False)], "FAIL"),
]
for name, res, want in outs:
    got = cw.run_outcome(res)
    good = got.split(":")[0] == want; fails += not good
    print(f"[{'PASS' if good else 'FAIL'}] run outcome: {name} (got {got})")
sys.exit(1 if fails else 0)
EOF
rc=$?; [ $rc -eq 3 ] && infra "verdict test could not run"
t "probe verdict and run outcome as expected" test $rc -eq 0

echo "== F. capture stop with deadline (harness_lib.sh stop_captures_deadline; python fakes)"
FK=$(mktemp -d "$OUTD/stop.XXXXXX")
cat > "$FK/fake_capture.py" <<'EOF'
import signal, sys, time
mode = sys.argv[1]   # ok: exit 0 shortly after SIGINT | rc3: exit 3 on SIGINT | ignore: ignore SIGINT
def on_int(*a):
    if mode == "ignore":
        return
    time.sleep(0.3)
    sys.exit(3 if mode == "rc3" else 0)
signal.signal(signal.SIGINT, on_int)
while True:
    time.sleep(0.05)
EOF
timeout 30 bash -c '
    source "$1/harness_lib.sh"; FK=$2
    python3 "$FK/fake_capture.py" ok & A=$!
    python3 "$FK/fake_capture.py" rc3 & B=$!
    python3 "$FK/fake_capture.py" ignore & C=$!
    sleep 0.5
    t0=$EPOCHREALTIME
    stop_captures_deadline 2 "$FK/exit.txt" "$FK/timeline.txt" "a:$A" "b:$B" "c:$C"; echo "rc=$?" > "$FK/rc.txt"
    awk -v a="$t0" -v b="$EPOCHREALTIME" "BEGIN { printf \"%.2f\n\", b - a }" > "$FK/elapsed.txt"
    for p in $A $B $C; do if kill -0 $p 2>/dev/null; then echo "alive $p"; fi; done > "$FK/left.txt"
    echo completed > "$FK/completed.txt"
' _ "$H" "$FK"
trc=$?   # 124 = killed by timeout (a hang)
echo "exit file: $(tr '\n' ' ' < "$FK/exit.txt" 2>/dev/null); $(cat "$FK/rc.txt" 2>/dev/null); elapsed $(cat "$FK/elapsed.txt" 2>/dev/null) s"
cat "$FK/timeline.txt" 2>/dev/null
t "stop_captures_deadline returned (no hang: not killed by timeout, ran to the end)" bash -c "[ $trc -ne 124 ] && grep -qx completed '$FK/completed.txt'"
t "capture exiting 0 on SIGINT recorded as 'a 0'" grep -qx "a 0" "$FK/exit.txt"
t "capture exiting 3 on SIGINT recorded as 'b 3'" grep -qx "b 3" "$FK/exit.txt"
t "capture ignoring SIGINT killed at the deadline and recorded" grep -qx "c KILLED_AT_DEADLINE" "$FK/exit.txt"
t "stop_captures_deadline returns non-zero when a capture misbehaved" grep -qx "rc=1" "$FK/rc.txt"
t "deadline respected (elapsed < 3.5 s for a 2 s deadline)" awk -v e="$(cat "$FK/elapsed.txt" 2>/dev/null)" 'BEGIN { exit !(e != "" && e < 3.5) }'
t "no fake capture left running" test ! -s "$FK/left.txt"
t "timeline has SIGINT, exit and SIGKILL entries" bash -c "grep -q 'a pid .*SIGINT sent' '$FK/timeline.txt' && grep -q 'b pid .*exited rc=3' '$FK/timeline.txt' && grep -q 'c pid .*SIGKILL' '$FK/timeline.txt'"
timeout 30 bash -c '
    source "$1/harness_lib.sh"; FK=$2
    python3 "$FK/fake_capture.py" ok & A=$!
    sleep 0.5
    stop_captures_deadline 2 "$FK/exit2.txt" "$FK/timeline2.txt" "a:$A"; echo "rc=$?" > "$FK/rc2.txt"
' _ "$H" "$FK"
t "all captures well-behaved -> stop_captures_deadline returns 0" grep -qx "rc=0" "$FK/rc2.txt"

echo "== G. tcpdump statistics parsing (harness_lib.sh capture_stats)"
printf 'tcpdump: listening on x\n10 packets captured\n12 packets received by filter\n0 packets dropped by kernel\n' > "$FK/st-ok.err"
printf 'tcpdump: listening on x\n10 packets captured\n12 packets received by filter\n' > "$FK/st-nodrop.err"
printf 'tcpdump: listening on x\n' > "$FK/st-none.err"
printf '5 packets captured\n5 packets received by filter\n3 packets dropped by kernel\n' > "$FK/st-drop.err"
t "statistics parsed exactly (10 12 0)" test "$(capture_stats "$FK/st-ok.err")" = "10 12 0"
t "missing 'dropped by kernel' line -> failure, not 0" bash -c "! { source '$H/harness_lib.sh'; capture_stats '$FK/st-nodrop.err'; }"
t "no statistics at all -> failure" bash -c "! { source '$H/harness_lib.sh'; capture_stats '$FK/st-none.err'; }"
t "dropped by kernel > 0 is reported as such (5 5 3)" test "$(capture_stats "$FK/st-drop.err")" = "5 5 3"

echo "== H. probe_matrix.py evaluate() wiring, replayed offline with stub worker modules"
[ -e /app ] && infra "/app exists on this host: the stub worker modules would be shadowed"
SB=$(mktemp -d "$OUTD/stubs.XXXXXX"); mkdir -p "$SB/isolation" "$SB/service" "$SB/out"
: > "$SB/isolation/__init__.py"; : > "$SB/service/__init__.py"
cat > "$SB/isolation/constants.py" <<'EOF'
GUEST_MAC = "52:54:00:c7:00:02"; GUEST_IP = "10.200.0.2"; WORKER_GUEST_IP = "10.200.0.1"; SVC_PORT = 8011
GUEST_IF = "tap0"; GUEST_PREFIX = 30; CURRENT_TASK_FILE = "/nonexistent/current_task"
EOF
echo 'def clear(): pass
def set_current(t): pass' > "$SB/isolation/current_task.py"
echo 'def verify_isolation(*a, **k): pass' > "$SB/isolation/verify.py"
echo 'ARCH_CONFIGS = {}
def shutdown_qemu(*a, **k): pass
class Analysis: pass' > "$SB/service/analysis.py"
CT01_TARGETS='{"worker_ip":"192.168.60.2","mongo_ip":"172.18.0.2","manager_ip":"192.168.60.10","ssh_ips":[],"lan_dns":"192.168.177.2"}' \
python3 - "$H" "$SB" <<'EOF'
import importlib.util, json, os, sys, time, types
H, SB = sys.argv[1], sys.argv[2]
sys.path[:0] = [H, SB]
sys.argv = ["probe_matrix.py", "ARM", os.path.join(SB, "out")]
try:
    spec = importlib.util.spec_from_file_location("probe_matrix", os.path.join(H, "probe_matrix.py"))
    pm = importlib.util.module_from_spec(spec); spec.loader.exec_module(pm)
    import counter_window as cw
except Exception as e:
    print(f"SELFTEST-ERROR: probe_matrix import with stubs: {type(e).__name__}: {e}"); sys.exit(3)
pm.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time, strftime=time.strftime)
MAC = "52:54:00:c7:00:02"
def syn(t, sport):
    return {"t": t, "src_mac": MAC, "etype": "0x0800", "ip_src": "10.200.0.2", "ip_dst": "1.1.1.1", "proto": "6",
            "sport": str(sport), "dport": "443", "qname": ""}
def v6(t):
    return {"t": t, "src_mac": MAC, "etype": "0x86dd", "ip_src": "", "ip_dst": "", "proto": "", "sport": "",
            "dport": "", "qname": ""}
def probe(name, lport, base, delta, read_a_end=0.020):
    return {"probe": name, "dst": "1.1.1.1", "proto": "tcp", "port": 443, "lport": lport, "qname": None,
            "expected_class": "drop_public", "t0": base, "t1": base + 5.02,
            "read_before": {"t_start": base, "t_end": base + read_a_end},
            "read_after": {"t_start": base + 5.0, "t_end": base + 5.02},
            "guest_rc": 28, "guest_output": "HTTP=000", "guest_failed": True,
            "control_before": {"ok": True}, "control_after": {"ok": True}, "remote_control": None,
            "counter_delta": delta, "host_alert_lines": 0}
rows = [syn(101, 41000), syn(102, 41000), syn(104, 41000),                       # clean
        syn(201, 41001), syn(202, 41001), syn(204, 41001), v6(200.025), v6(202.5),  # 06B-3D shape
        syn(301, 41002), syn(302, 41002), syn(304, 41002)]                       # real mismatch
pm.guest_frames = lambda: rows
fails = 0
def check(msg, cond):
    global fails
    fails += not cond
    print(f"[{'PASS' if cond else 'FAIL'}] evaluate replay: {msg}")
pm.probes[:] = [probe("clean", 41000, 100.0, {"drop_public": 3}),
                probe("ipv6-during-read-a", 41001, 200.0, {"drop_public": 3, "l2_bad_ethertype": 2}, 0.030),
                probe("real-mismatch", 41002, 300.0, {"drop_public": 2})]
pm.evaluate()
m = json.load(open(os.path.join(pm.OUT, "matrix.json")))
v = {r["probe"]: r["verdict"] for r in m}
print("verdicts:", v)
check("clean probe -> ĐẠT", v.get("clean") == "ĐẠT")
check("IPv6 frame inside read A (06B-3D shape) -> CHƯA KIỂM CHỨNG", v.get("ipv6-during-read-a", "").startswith("CHƯA KIỂM CHỨNG (gói ở biên"))
check("real mismatch -> FAIL", v.get("real-mismatch") == "FAIL")
r2 = [r for r in m if r["probe"] == "ipv6-during-read-a"][0]
check("edge frame listed with its timestamp and class", r2["mismatch"].get("l2_bad_ethertype", {}).get("edge_start_t") == [200.025])
check("raw reads kept in the matrix row", r2["counter_reconciliation"]["reads"]["before"] == {"t_start": 200.0, "t_end": 200.03})
check("record of the undecided probe is not ok", [x["ok"] for x in pm.results if x["test"].startswith("probe ipv6")] == [False])
check("run outcome with a real mismatch -> FAIL", cw.run_outcome(pm.results).startswith("FAIL"))
pm.results.clear()
bad_reads = probe("reads-reversed", 41003, 400.0, {"drop_public": 3})
bad_reads["read_before"], bad_reads["read_after"] = bad_reads["read_after"], bad_reads["read_before"]
alert_noctl = probe("host-alert-no-control", 41004, 500.0, {"drop_public": 3})
alert_noctl["host_alert_lines"] = 2
alert_noctl["control_before"] = alert_noctl["control_after"] = {"ok": False}
rows += [syn(401, 41003), syn(402, 41003), syn(404, 41003), syn(501, 41004), syn(502, 41004), syn(504, 41004)]
pm.probes[:] = [bad_reads, alert_noctl]
pm.evaluate()
m = json.load(open(os.path.join(pm.OUT, "matrix.json")))
v = {r["probe"]: r["verdict"] for r in m}
print("verdicts:", v)
check("reversed read times -> LỖI PHÉP ĐO", v.get("reads-reversed", "").startswith("LỖI PHÉP ĐO (read times out of order"))
check("host alert with no live control -> FAIL (not CHƯA KIỂM CHỨNG)", v.get("host-alert-no-control") == "FAIL")
check("determined failure recorded", [r["determined_failures"] for r in m if r["probe"] == "host-alert-no-control"] == [["no_host_alert"]])
check("run outcome with a measurement error -> FAIL", cw.run_outcome(pm.results).startswith("FAIL"))
pm.results.clear()
pm.probes[:] = [probe("clean", 41000, 100.0, {"drop_public": 3}),
                probe("ipv6-during-read-a", 41001, 200.0, {"drop_public": 3, "l2_bad_ethertype": 2}, 0.030)]
pm.evaluate()
check("run outcome with only an undecided probe -> UNVERIFIED (not PASS)", cw.run_outcome(pm.results).startswith("UNVERIFIED"))
check("matrix.md written with a reconciliation column", "reconciliation" in open(os.path.join(pm.OUT, "matrix.md")).read())
sys.exit(1 if fails else 0)
EOF
rc=$?; [ $rc -eq 3 ] && infra "evaluate replay could not run"
t "probe_matrix.py evaluate() wiring as expected" test $rc -eq 0

echo
[ $FAILS -eq 0 ] && { echo "SELFTEST: ALL PASSED"; exit 0; }
echo "SELFTEST: $FAILS FAILED"; exit 1
