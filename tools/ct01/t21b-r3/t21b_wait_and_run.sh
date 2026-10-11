#!/bin/bash
# CT-01 T21b controller (runs as the normal user in the coordinator's session, NOT in the SSH session under test).
# usage: t21b_wait_and_run.sh <run_id> <heartbeat_dir> <lane_root_command_file> <result_dir> <expected_lane_manifest_sha256> [<wait_s>]
# R2: the lane is pinned (the root command's tree manifest must hash to the literal AND the root command must contain it); the run id / heartbeat log / result
# directory must be NEW (no append/reuse); one controller per run id (flock).
# 1. waits (default 1800 s) until <heartbeat_dir>/heartbeat-<run_id>.log has a HEADER with sshd_ancestor=True and SSH_CONNECTION, and a beat younger than 5 s;
# 2. waits 12 s more (>= 12 beats BEFORE the window), then runs the pinned lane root command (ONE lane, no retry) and captures its console;
# 3. waits 12 s after the lane, records window + evaluator verdict (server side) into <result_dir>.
# It never touches the heartbeat process and never ends the SSH session. The client-side proof needs the file the user's terminal tee'd (see RUNBOOK).
RUN=$1; HBD=$2; LANECMD=$3; RES=$4; MANPIN=$5; WAIT=${6:-3600}
PY=${CT01_T21B_PY:-/usr/bin/python3}
HERE=$(cd "$(dirname "$0")" && pwd)
LOG="$HBD/heartbeat-$RUN.log"
[ -n "$MANPIN" ] || { echo "no expected lane manifest given"; exit 2; }
[ ! -e "$RES" ] || { echo "STOP: result dir $RES already exists (run id reuse)"; exit 6; }
[ ! -e "$LOG" ] || { echo "STOP: heartbeat log $LOG already exists (run id reuse)"; exit 6; }
LT=$(dirname "$LANECMD")
[ "$(sha256sum "$LT/SHA256SUMS" | cut -d' ' -f1)" = "$MANPIN" ] || { echo "STOP: lane tree manifest differs from the pinned literal"; exit 7; }
grep -q "^MAN=$MANPIN\$" "$LANECMD" || { echo "STOP: lane root command does not carry the pinned manifest literal"; exit 7; }
mkdir -p "$RES" || exit 2
exec 9>"$RES/.controller.lock"; flock -n 9 || { echo "STOP: another controller holds this run"; exit 8; }
note() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$*" | tee -a "$RES/controller.log"; }
fresh() {   # last HB line younger than 5 s (wall clock of the file's own epoch field)
    "$PY" -I -B - "$LOG" "$RUN" <<'PYEOF'
import re, sys, time
log, run = sys.argv[1], sys.argv[2]
hdr_ok, last = False, None
try:
    for l in open(log, errors="replace"):
        if l.startswith("HEADER "):
            hdr_ok = "'sshd_ancestor': True" in l and "'SSH_CONNECTION': None" not in l
        m = re.fullmatch(r"HB (\S+) (\d+) \S+ (\d+) \d+ [0-9.]+", l.strip())
        if m and m.group(1) == run:
            last = int(m.group(3)) / 1e9
except OSError:
    sys.exit(1)
import os
ok = (hdr_ok or os.environ.get("CT01_T21B_OFFLINE_TEST") == "1") and last is not None and time.time() - last < 5
sys.exit(0 if ok else 1)
PYEOF
}
note "controller start run=$RUN log=$LOG wait=${WAIT}s"
t_end=$(( $(date +%s) + WAIT ))
until fresh; do
    if [ "$(date +%s)" -ge "$t_end" ]; then note "TIMEOUT: no fresh in-session heartbeat for $RUN within ${WAIT}s; no lane was started"; echo "NO_HEARTBEAT" > "$RES/outcome.txt"; exit 3; fi
    sleep 2
done
note "heartbeat is live; lead-in 12 s"
sleep 12
fresh || { note "heartbeat stopped during the lead-in; no lane started"; echo "HEARTBEAT_LOST_BEFORE_LANE" > "$RES/outcome.txt"; exit 4; }
note "starting the lane: $LANECMD"
bash "$LANECMD" > "$RES/lane-console.log" 2>&1
lrc=$?
note "lane exit=$lrc"
sleep 12
DIR=$(sed -n 's/^EXPORT VERIFIED: \([^ ]*\).*/\1/p' "$RES/lane-console.log" | tail -1)
echo "$lrc" > "$RES/lane-rc.txt"
if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then note "no verified export directory found in the lane console"; echo "LANE_NO_EXPORT" > "$RES/outcome.txt"; exit 5; fi
echo "$DIR" > "$RES/lane-run-dir.txt"
"$PY" -I -B "$HERE/t21b_evaluate.py" "$LOG" "$RUN" "$DIR" --out "$RES/t21b-server-side-verdict.json" > "$RES/t21b-server-side-verdict.txt" 2>&1
erc=$?
cp "$LOG" "$RES/heartbeat-$RUN.server.log"
note "server-side evaluation rc=$erc (rc 1 with SERVER_SIDE_ONLY is expected until the client terminal log is evaluated)"
echo "DONE lane_rc=$lrc" > "$RES/outcome.txt"
exit 0
