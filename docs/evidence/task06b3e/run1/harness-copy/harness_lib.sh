# 06B-3C / 06B-3CR — helpers sourced by run-06b3b.sh and exercised offline by selftest.sh.

# ---------------------------------------------------------------- capture watcher
# alive <pid>: process exists and is not a zombie (an exited child that was not reaped yet).
alive() {
    local s
    s=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
    [ -n "$s" ] && [ "${s:0:1}" != Z ]
}

# start_capture_watch <marker> <heartbeat> <interval-s> <name:pid>...
# Background loop. Every <interval> it checks the watched processes:
#   all alive -> writes the current epoch time to <heartbeat> (temp file + rename, never partial);
#   one gone  -> appends it to <marker> and ends (the heartbeat then goes stale as well).
# probe_matrix.py stops the probes (CaptureLost) when the marker is non-empty or unreadable, or the
# heartbeat is missing, unparsable or older than its limit. A dead watcher therefore stops the probes
# even while every capture still runs. run-06b3b.sh checks the same after each guest and at the end.
start_capture_watch() {
    local marker=$1 hb=$2 interval=$3
    shift 3
    (
        trap - EXIT INT TERM
        while :; do
            for e in "$@"; do
                if ! alive "${e##*:}"; then
                    echo "$(date -u +%H:%M:%S) capture ${e%%:*} pid ${e##*:} exited during the test" >> "$marker"
                    exit 0
                fi
            done
            date +%s.%N > "$hb.tmp" && mv -f "$hb.tmp" "$hb"
            sleep "$interval"
        done
    ) &
    WATCH_PID=$!
}

# Stop the watcher BEFORE stopping the captures on purpose, so a normal stop is not reported.
stop_capture_watch() {
    if [ -n "${WATCH_PID:-}" ]; then
        kill "$WATCH_PID" 2>/dev/null
        wait "$WATCH_PID" 2>/dev/null
    fi
    return 0
}

# heartbeat_fresh <heartbeat> <max-age-s>: 0 if the file holds an epoch time at most <max-age> old.
heartbeat_fresh() {
    local hb now
    hb=$(cat "$1" 2>/dev/null) || return 1
    now=$(date +%s.%N)
    awk -v hb="$hb" -v now="$now" -v max="$2" \
        'BEGIN { if (hb !~ /^[0-9]+(\.[0-9]+)?$/) exit 1; age = now - hb; exit !(age >= -1 && age <= max) }'
}

# ---------------------------------------------------------------- manager
# Needs MANAGER (container name) and COMPOSE (array).
#  * running  -> used as is; never started, stopped or restarted by this run.
#  * exited   -> `compose up --no-deps --no-build --no-recreate`; its exit code is kept: on failure
#                prepare returns non-zero and the harness aborts. MANAGER_STARTED=1 only after the
#                same container (same id) is confirmed running.
#  * created  -> refused before any change: start + stop would leave it "exited", not "created".
#  * other    -> refused.
# restore stops only the container this run used (id checked right before `docker stop <id>`);
# a replacement container is never stopped and is reported as a failure.
MANAGER_STARTED=0
MANAGER_UP_ATTEMPTED=0
MANAGER_RESTORED=0

manager_inspect() { docker inspect -f "$1" "$MANAGER" 2>/dev/null; }

manager_prepare() {
    MANAGER_STATE_BEFORE=$(manager_inspect '{{.State.Status}}') || { echo "manager container not found"; return 2; }
    MANAGER_ID_BEFORE=$(manager_inspect '{{.Id}}') || return 2
    MANAGER_STARTED_AT_BEFORE=$(manager_inspect '{{.State.StartedAt}}') || return 2
    echo "manager before: state=$MANAGER_STATE_BEFORE id=${MANAGER_ID_BEFORE:0:12} startedAt=$MANAGER_STARTED_AT_BEFORE"
    case "$MANAGER_STATE_BEFORE" in
    running)
        echo "manager already running: used as is, will be left running"
        return 0
        ;;
    exited) ;;
    created)
        echo "manager is 'created': refused before any change (start+stop cannot restore 'created')"
        return 2
        ;;
    *)
        echo "manager in state '$MANAGER_STATE_BEFORE': refused before any change"
        return 2
        ;;
    esac
    local out rc st id
    MANAGER_UP_ATTEMPTED=1
    out=$("${COMPOSE[@]}" up -d --no-deps --no-build --no-recreate sandbox-manager 2>&1); rc=$?
    printf '%s\n' "$out" | tail -3
    if [ $rc -ne 0 ]; then
        echo "compose up failed (rc=$rc)"
        return 3
    fi
    id=$(manager_inspect '{{.Id}}'); st=$(manager_inspect '{{.State.Status}}')
    if [ "$id" != "$MANAGER_ID_BEFORE" ]; then
        echo "compose up replaced the manager container (${id:0:12} != ${MANAGER_ID_BEFORE:0:12})"
        return 3
    fi
    if [ "$st" != running ]; then
        echo "compose up returned 0 but the manager is '$st'"
        return 3
    fi
    MANAGER_STARTED=1
    echo "manager started by this run (same container): will be stopped again"
}

# Returns 0 only if the manager ends in its initial state, as the same container, and (if it was
# running) was not restarted. Safe to call twice (teardown, then the EXIT trap).
manager_restore() {
    [ "$MANAGER_RESTORED" = 1 ] && return "${MANAGER_RESTORE_RC:-0}"
    MANAGER_RESTORED=1
    MANAGER_RESTORE_RC=0
    [ -n "${MANAGER_STATE_BEFORE:-}" ] || return 0   # prepare never ran: nothing was touched
    local st id at rc=0 src
    id=$(manager_inspect '{{.Id}}'); st=$(manager_inspect '{{.State.Status}}')
    if [ "$id" != "$MANAGER_ID_BEFORE" ]; then
        echo "manager container was replaced (${id:0:12} != ${MANAGER_ID_BEFORE:0:12}): not stopped"
        rc=1
    elif [ "$MANAGER_STATE_BEFORE" = exited ] && [ "$st" = running ] && [ "$MANAGER_UP_ATTEMPTED" = 1 ]; then
        # started by this run (also if compose up failed after starting it): stop exactly that id
        docker stop -t 10 "$MANAGER_ID_BEFORE" > /dev/null 2>&1; src=$?
        [ $src -eq 0 ] || { echo "docker stop failed (rc=$src)"; rc=1; }
    fi
    st=$(manager_inspect '{{.State.Status}}'); id=$(manager_inspect '{{.Id}}'); at=$(manager_inspect '{{.State.StartedAt}}')
    echo "manager after: state=$st id=${id:0:12} startedAt=$at (before: $MANAGER_STATE_BEFORE ${MANAGER_ID_BEFORE:0:12} $MANAGER_STARTED_AT_BEFORE; started by this run: $MANAGER_STARTED)"
    [ "$st" = "$MANAGER_STATE_BEFORE" ] || { echo "manager state differs"; rc=1; }
    [ "$id" = "$MANAGER_ID_BEFORE" ] || { echo "manager container differs"; rc=1; }
    if [ "$MANAGER_STATE_BEFORE" = running ] && [ "$at" != "$MANAGER_STARTED_AT_BEFORE" ]; then
        echo "manager was restarted during the test"; rc=1
    fi
    MANAGER_RESTORE_RC=$rc
    return $rc
}

# ---------------------------------------------------------------- capture teardown (06B-3DR)
# now_us: wall clock in microseconds (bash 5 EPOCHREALTIME)
now_us() { local t=$EPOCHREALTIME; echo "${t/./}"; }

# timeline <file> <text>: append "<epoch.us> <UTC time> <text>"
timeline() { echo "$EPOCHREALTIME $(date -u +%H:%M:%S.%N | cut -c1-12) $2" >> "$1"; }

# stop_captures_deadline <deadline-s> <exit-file> <timeline-file> <name:pid>...
# Sends SIGINT to every capture, then waits for each until one common deadline. A capture still
# running at the deadline is killed (SIGKILL) and recorded as "<name> KILLED_AT_DEADLINE";
# otherwise "<name> <exit code>". Every step goes to the timeline. Returns 1 if any capture had to
# be killed or exited non-zero. The captures must be children of the calling shell (for wait).
stop_captures_deadline() {
    local deadline_s=$1 exitf=$2 tl=$3 e p n rc bad=0 end_us
    shift 3
    for e in "$@"; do
        kill -INT "${e##*:}" 2>/dev/null
        timeline "$tl" "${e%%:*} pid ${e##*:}: SIGINT sent"
    done
    end_us=$(( $(now_us) + deadline_s * 1000000 ))
    for e in "$@"; do
        n=${e%%:*}; p=${e##*:}
        while alive "$p" && [ "$(now_us)" -lt "$end_us" ]; do sleep 0.05; done
        if alive "$p"; then
            kill -KILL "$p" 2>/dev/null; wait "$p" 2>/dev/null
            timeline "$tl" "$n pid $p: still running at the ${deadline_s} s deadline -> SIGKILL"
            echo "$n KILLED_AT_DEADLINE" >> "$exitf"; bad=1
        else
            wait "$p" 2>/dev/null; rc=$?
            timeline "$tl" "$n pid $p: exited rc=$rc"
            echo "$n $rc" >> "$exitf"
            [ "$rc" -eq 0 ] || bad=1
        fi
    done
    return $bad
}

# capture_stats <tcpdump stderr file>: prints "captured received_by_filter dropped_by_kernel".
# Returns 1 (and prints nothing) if any of the three statistics lines is missing: a missing line is
# never read as 0.
capture_stats() {
    awk '/^[0-9]+ packets captured$/ {c=$1; nc++}
         /^[0-9]+ packets received by filter$/ {r=$1; nr++}
         /^[0-9]+ packets dropped by kernel$/ {d=$1; nd++}
         END { if (nc != 1 || nr != 1 || nd != 1) exit 1; print c, r, d }' "$1"
}
