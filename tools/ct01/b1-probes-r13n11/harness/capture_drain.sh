# ARP-only helpers; source after harness_lib.sh. No Docker, guest or network commands.
# Stop marker is created by parent ONLY at intentional teardown, never during probes.
start_drain_capture_watch() {
    local marker=$1 hb=$2 interval=$3 stopping=$4
    shift 4
    (
        trap - EXIT INT TERM HUP
        while :; do
            for e in "$@"; do
                if ! alive "${e##*:}"; then
                    if [ -f "$stopping" ] && [ ! -L "$stopping" ]; then
                        # Keep the watcher/heartbeat live through EVERY parent's capture wait.
                        # Stop/await helper separately records signal errors, rc and deadline.
                        continue
                    fi
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

# Children MUST belong to calling shell. Success requires actual signal delivery + wait0.
# Unlike old stop helper, a capture already dead (even rc0) cannot silently qualify.
stop_drain_captures_deadline() {
    local deadline_s=$1 exitf=$2 tl=$3 stopping=$4 e p n rc bad=0 all_live=1 end_us
    local -a signal_errors=() dead_before_stop=()
    shift 4
    [[ "$deadline_s" =~ ^[0-9]+$ ]] && [ "$deadline_s" -ge 1 ] && [ "$deadline_s" -le 10 ] || return 1
    for e in "$@"; do alive "${e##*:}" || { bad=1; all_live=0; dead_before_stop+=("$e"); }; done
    if [ "$all_live" -eq 1 ]; then
        printf '%s intentional capture stop requested\n' "$EPOCHREALTIME" > "$stopping" || return 1
    fi
    for e in "$@"; do
        if ! kill -INT "${e##*:}" 2>/dev/null; then signal_errors+=("$e");bad=1; fi
        timeline "$tl" "${e%%:*} pid ${e##*:}: SIGINT attempted"
    done
    end_us=$(( $(now_us) + deadline_s * 1000000 ))
    for e in "$@"; do
        n=${e%%:*}; p=${e##*:}
        while alive "$p" && [ "$(now_us)" -lt "$end_us" ]; do sleep 0.05; done
        if alive "$p"; then
            kill -KILL "$p" 2>/dev/null; wait "$p" 2>/dev/null
            echo "$n KILLED_AT_DEADLINE" >> "$exitf";bad=1
            timeline "$tl" "$n pid $p: killed at deadline"
        else
            wait "$p" 2>/dev/null;rc=$?
            if [[ " ${signal_errors[*]} " == *" $e "* ]]; then
                echo "$n SIGNAL_ERROR" >> "$exitf"
                timeline "$tl" "$n pid $p: signal error, wait rc=$rc"
            elif [[ " ${dead_before_stop[*]} " == *" $e "* ]]; then
                echo "$n ALREADY_DEAD" >> "$exitf"
                timeline "$tl" "$n pid $p: already dead before stop, wait rc=$rc"
            else
                echo "$n $rc" >> "$exitf"
                timeline "$tl" "$n pid $p: awaited rc=$rc"
            fi
            [ "$rc" -eq 0 ] || bad=1
        fi
    done
    return "$bad"
}
