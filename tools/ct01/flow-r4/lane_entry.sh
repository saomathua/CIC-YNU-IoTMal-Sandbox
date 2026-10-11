#!/bin/bash
# CT-01 flow lane entry tail (runs as root from the STAGED tree, after the root command verified the manifest literal and copied the tree).
# usage: lane_entry.sh <mode> <stage> <out> <image_id> <manifest_literal>
# One lane, one evaluation, ONE export; the stage is kept whatever happens. Final exit (the same rule as export_run.py's receipt):
#   signal (128+n)  >  lane rc != 0  >  evaluator rc != 0  >  export not verified (4)  >  0
# 0 means: every criterion of THIS lane held and the evidence copy was verified. It is not CT-01 PASS.
MODE=$1; STAGE=$2; OUT=$3; IMG=$4; MAN=$5
PY=${CT01_FLOW_PY:-/usr/bin/python3}
SIG=0
trap 'SIG=2' INT
trap 'SIG=15' TERM
trap 'SIG=1' HUP
LABEL=$(basename "$STAGE")
set +e
"$PY" -I -B "$STAGE/tree/flow_lane.py" "$MODE" "$STAGE/run" "$LABEL" "$IMG" "$STAGE/tree/fixtures" "$MAN" > "$STAGE/lane.stdout" 2>&1
lrc=$?
if [ -d "$STAGE/run" ]; then
    "$PY" -I -B "$STAGE/tree/evaluate_flow.py" "$STAGE/run" "$STAGE/tree/pins.json" --out "$STAGE/run/verdicts.json" > "$STAGE/run/evaluate.log" 2>&1
    erc=$?
else
    erc=2
    mkdir -p "$STAGE/run"
fi
echo "lane_rc=$lrc evaluator_rc=$erc signal=$SIG" > "$STAGE/run/rc.txt"
cp "$STAGE/lane.stdout" "$STAGE/run/lane.stdout" 2>/dev/null
"$PY" -I -B "$STAGE/tree/export_run.py" "$STAGE/run" "$OUT" --uid "${SUDO_UID:-0}" --gid "${SUDO_GID:-0}" --lane-rc "$lrc" --eval-rc "$erc" --signal "$SIG" --stage "$STAGE"
xrc=$?
final=0
if [ "$SIG" -ne 0 ]; then final=$((128 + SIG))
elif [ "$lrc" -ne 0 ]; then final=$lrc
elif [ "$erc" -ne 0 ]; then final=$erc
elif [ "$xrc" -ne 0 ]; then final=4
fi
echo "stage=$STAGE lane_rc=$lrc evaluator_rc=$erc signal=$SIG export_rc=$xrc final=$final  (0 = every criterion of THIS lane held and the copy verified; NOT CT-01 PASS)"
exit "$final"
