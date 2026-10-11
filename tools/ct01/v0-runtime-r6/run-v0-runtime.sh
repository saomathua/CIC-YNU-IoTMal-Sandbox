#!/bin/bash
# CT-01 V0 runtime, branches F1b (nft does not RESOLVE via PATH) and F6 (structural ruleset difference). PREPARED FOR REVIEW — NOT EXECUTED.
# Started ONLY by the staged entry (root-command.txt): the tree, the repo inputs and the fixtures were copied into a root-owned 0700 stage and verified there.
#   control : unchanged image + sentinel server/poller        -> V0 OK, sentinels called after V0, real kernel ruleset == expected
#   f1b     : same, PATH=/ct01-path (ip, python3 only)        -> run.sh stops at `nft -f`: exit 127 `nft: command not found`, no V0, no sentinel
#   f6      : same, guest-f6.nft mounted read-only            -> nft accepts, V0 rejects the structural diff: exit 1, no sentinel
# F1b scope: the executable does not RESOLVE in the restricted PATH; /usr/sbin/nft is still in the image (the preflight shows it). Not "image without nft".
# Container state is NOT evidence about the manager /status endpoint.
# Every measurement keeps its exit code (measure-rc.tsv); an unreadable measurement is a failed criterion, never "unchanged".
set -uo pipefail

S=${CT01_V0RT_STAGE:-}
[ -n "$S" ] && [ "$(readlink -f "$0")" = "$S/tree/run-v0-runtime.sh" ] || { echo "ABORT: not started through the staged entry"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ "$(stat -c '%u %a' "$S")" = "0 700" ] || { echo "ABORT: stage is not root-owned 0700"; exit 2; }
P=$S/tree
IN=$S/inputs
RUN=$S/run
EXPECTED_IMAGE_ID=${1:-}
EXPORT_TO=${CT01_V0RT_EXPORT_TO:-}
[[ "$EXPECTED_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "usage: image id"; exit 2; }
[ ! -e "$RUN" ] || { echo "ABORT: $RUN exists - one run directory per decision"; exit 3; }
/usr/bin/python3 -I -B "$P/verify_pins.py" "$S" || { echo "ABORT: pins/files differ (stage copy)"; exit 3; }
PIN_IMAGE=$(/usr/bin/python3 -I -B -c "import json,sys;print(json.load(open(sys.argv[1]))['image_id'])" "$P/pins.json") || exit 3
[ "$PIN_IMAGE" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: argument image id != pins.json image id"; exit 3; }
IMAGE_ID=$EXPECTED_IMAGE_ID

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LABEL="$STAMP-$$"
mkdir -m 700 "$RUN" || exit 3
# R3 (D4): the logger is an ordinary child of this shell reading a FIFO outside the run directory: the finalizer closes the writer side, AWAITS the
# logger, and only then hashes/copies the run directory. Everything the finalizer logs afterwards goes to $S/finalize.log / $S/export.log (outside).
exec 3>&1
mkfifo -m 600 "$S/run.fifo" || exit 3
( trap '' INT TERM HUP PIPE; exec tee "$RUN/run.log" < "$S/run.fifo" ) &
TEE_PID=$!
exec > "$S/run.fifo" 2>&1
trap '' PIPE
echo "$LABEL" > "$RUN/run-label.txt"
/usr/bin/python3 -I -B -c "
import hashlib, json, pathlib, sys
S = pathlib.Path(sys.argv[1])
json.dump({'schema': 'ct01-v0rt-run-identity/1', 'label': sys.argv[2], 'stage': str(S), 'pid': int(sys.argv[3]), 'image_id': sys.argv[4],
           'tree_manifest_sha256': hashlib.sha256((S / 'tree/SHA256SUMS').read_bytes()).hexdigest(),
           'runner_sha256': hashlib.sha256((S / 'tree/run-v0-runtime.sh').read_bytes()).hexdigest()},
          open(S / 'run/run-identity.json', 'w'), indent=1)" "$S" "$LABEL" "$$" "$IMAGE_ID" || exit 3
: > "$RUN/docker-commands.log"
: > "$RUN/measure-rc.tsv"
: > "$RUN/cleanup.log"

CREATED_IDS=()
EV_PID=""
SEQ=0
SIGNAL=""
ABORT_REASON=""
STAGE_REACHED="start"
BEFORE_DONE=0
AFTER_DONE=0
FINALIZED=0
log() { echo; echo "===== $* ($(date -u +%H:%M:%S))"; }
D() { echo "$*" >> "$RUN/docker-commands.log"; docker "$@"; }
M() {   # M <name> <stdout-file> -- cmd...   : runs the command, keeps stderr next to it and the exit code in measure-rc.tsv (never aborts)
    local name=$1 out=$2; shift 3
    "$@" > "$out" 2> "$out.err"
    local rc=$?
    SEQ=$((SEQ + 1))
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$rc" "${out#$RUN/}" "$LABEL" "$SEQ" >> "$RUN/measure-rc.tsv"      # name rc relpath run-label seq (R3: bound, ordered)
    return 0
}
rc_of() { awk -F'\t' -v n="$1" '$1==n{r=$2} END{print r}' "$RUN/measure-rc.tsv"; }
abort() { ABORT_REASON="$*"; echo "ABORT: $*"; exit 3; }

reap() {   # every container carrying THIS run's label (also one whose id the CLI never returned), then the three names only if they carry the label
    local ids i n l rc
    ids=$(D ps -aq --no-trunc --filter "label=ct01-v0rt=$LABEL" 2> "$RUN/cleanup-ps.err"); rc=$?
    echo "ps-by-label rc=$rc" >> "$RUN/cleanup.log"
    for i in $ids; do
        D logs --timestamps "$i" > "$RUN/final-logs-${i:0:12}.txt" 2>&1 || true
        D rm -f "$i" >/dev/null 2>> "$RUN/cleanup.err"; rc=$?
        echo "rm-by-label $i rc=$rc" >> "$RUN/cleanup.log"
    done
    for n in ct01-v0rt-control ct01-v0rt-f1b ct01-v0rt-f6; do
        l=$(D inspect -f '{{index .Config.Labels "ct01-v0rt"}}' "$n" 2>/dev/null) || continue
        if [ "$l" = "$LABEL" ]; then
            D rm -f "$n" >/dev/null 2>> "$RUN/cleanup.err"; rc=$?
            echo "rm-by-name $n rc=$rc" >> "$RUN/cleanup.log"
        fi
    done
}

host_state() {  # $1 = before|after ; every measurement: stdout, stderr, rc
    local d="$RUN/host-$1" k dev a c
    mkdir -p "$d"
    M "h-$1:ip-route" "$d/ip-route.txt" -- ip route
    M "h-$1:ip6-route" "$d/ip6-route.txt" -- ip -6 route
    M "h-$1:tap0" "$d/host-tap0.txt" -- ip link show tap0
    M "h-$1:nft" "$d/nft-ruleset-stateless.txt" -- nft -s list ruleset
    M "h-$1:iptables" "$d/iptables-save.txt" -- iptables-save
    : > "$d/sysctl.txt"
    for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 \
             net.ipv4.conf.{all,default,ens33}.{rp_filter,arp_ignore,arp_announce,arp_accept,forwarding}; do
        M "h-$1:sysctl:$k" "$d/sysctl-$k.txt" -- sysctl -n "$k"
        echo "$k=$(cat "$d/sysctl-$k.txt" 2>/dev/null)" >> "$d/sysctl.txt"
    done
    M "h-$1:ss" "$d/listen-tcp-raw.txt" -- ss -ltnH
    awk '{print $4}' "$d/listen-tcp-raw.txt" | sort > "$d/listen-tcp.txt"
    M "h-$1:pgrep" "$d/qemu.txt" -- pgrep -a qemu-system
    M "h-$1:image-inspect" "$d/image-id.txt" -- D image inspect -f '{{.Id}}' "$IMAGE_ID"
    M "h-$1:image-ls" "$d/image-ls.txt" -- D image ls -q --no-trunc
    M "h-$1:ps-all" "$d/ps-all.txt" -- D ps -aq --no-trunc
    : > "$d/docker-others.txt"
    for c in $(sort "$d/ps-all.txt"); do
        M "h-$1:inspect:${c:0:12}" "$d/inspect-${c:0:12}.txt" -- D inspect -f '{{.Name}} {{.Id}} {{.State.Status}} {{.State.StartedAt}} {{.State.ExitCode}}' "$c"
        cat "$d/inspect-${c:0:12}.txt" >> "$d/docker-others.txt"
    done
    sort -o "$d/docker-others.txt" "$d/docker-others.txt"
    [ "$1" = before ] && BEFORE_DONE=1
    [ "$1" = after ] && AFTER_DONE=1
}

stop_events() {
    if [ -n "$EV_PID" ]; then
        kill "$EV_PID" 2>/dev/null
        wait "$EV_PID" 2>/dev/null
        EV_PID=""
    fi
}

close_logs() {   # -> 0 only when the logger has really exited (nothing can write into $RUN any more)
    exec >> "$S/finalize.log" 2>&1
    local i logger_rc
    for i in $(seq 1 100); do
        kill -0 "$TEE_PID" 2>/dev/null || { wait "$TEE_PID" 2>/dev/null; logger_rc=$?; TEE_PID=""; return "$logger_rc"; }
        sleep 0.1
    done
    kill "$TEE_PID" 2>/dev/null
    return 1
}

tree_listing() {   # regular files and symlinks of a directory, sorted: the set that the manifest must cover exactly
    ( cd "$1" && find . \( -type f -o -type l \) -print0 | LC_ALL=C sort -z | tr '\0' '\n' )
}

finalize() {
    local rc=$? code=$?
    trap '' INT TERM HUP
    [ "$FINALIZED" = 1 ] && return
    FINALIZED=1
    set +e
    stop_events
    reap
    if [ "$BEFORE_DONE" = 1 ] && [ "$AFTER_DONE" = 0 ]; then
        log "host state after (taken in the finalizer: the run did not reach step 4)"
        host_state after
    fi
    D ps -a -q --no-trunc --filter "label=ct01-v0rt=$LABEL" > "$RUN/leftover-containers.txt" 2> "$RUN/leftover-containers.err"
    echo $? > "$RUN/leftover-containers.rc"
    echo "created ids: ${CREATED_IDS[*]:-none}" > "$RUN/created-ids.txt"
    local completed=false
    [ "$STAGE_REACHED" = "evaluating" ] && [ -z "$SIGNAL" ] && [ -z "$ABORT_REASON" ] && completed=true
    /usr/bin/python3 -I -B -c "
import json,sys
json.dump({'completed': sys.argv[1]=='true', 'stage_reached': sys.argv[2], 'signal': sys.argv[3] or None, 'abort_reason': sys.argv[4] or None,
           'exit_code_at_finalize': int(sys.argv[5]), 'label': sys.argv[6]}, open(sys.argv[7],'w'), indent=1)" \
        "$completed" "$STAGE_REACHED" "$SIGNAL" "$ABORT_REASON" "$code" "$LABEL" "$RUN/final-status.json"
    local fsrc=$?
    log "evaluation (offline evaluator on the artefacts)"
    /usr/bin/python3 -I -B "$P/evaluate_v0_runtime.py" "$RUN" "$P/pins.json" --root "$S" --out "$RUN/verdicts.json"
    local erc=$?
    if [ "$erc" = 2 ] && [ ! -e "$RUN/verdicts.json" ]; then
        printf '{"all_ok": false, "incomplete": true, "reason": "evaluator rc 2: the run directory is incomplete (see final-status.json)"}\n' > "$RUN/verdicts.json"
    fi
    [ "$fsrc" != 0 ] && erc=$([ "$erc" = 0 ] && echo 1 || echo "$erc")
    echo "evaluator exit $erc (0 = all criteria held; this is not CT-01 PASS)"

    # ------------------------------------------------------------------ FREEZE: from here nothing is written into $RUN except the two listings below
    local xstatus=not_attempted xdetail="" freeze_ok=0
    close_logs && freeze_ok=1
    local mrc=0 symrc=0
    if [ "$freeze_ok" = 1 ]; then
        ( set -o pipefail; cd "$RUN" && find . -type l -printf '%p -> %l\n' | LC_ALL=C sort > EVIDENCE-SYMLINKS ) 2>> "$S/export.log"; symrc=$?
        ( set -o pipefail; cd "$RUN" && find . -type f ! -name EVIDENCE-SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > EVIDENCE-SHA256SUMS ) 2>> "$S/export.log"; mrc=$?
    fi
    if [ "$freeze_ok" != 1 ]; then
        xstatus=freeze_failed; xdetail="the log writer is still running or exited unsuccessfully: the evidence cannot be verified"
    elif [ "$symrc" != 0 ] || [ "$mrc" != 0 ]; then
        xstatus=manifest_failed; xdetail="evidence manifest/symlink listing failed (rc $mrc/$symrc)"
    elif [ -z "$EXPORT_TO" ] || [ -e "$EXPORT_TO" ]; then
        xstatus=refused; xdetail="EXPORT_TO missing or exists"
    elif ! cp -a "$RUN" "$EXPORT_TO" 2>> "$S/export.log"; then
        xstatus=copy_failed; xdetail="cp failed"
    elif ! chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$EXPORT_TO" 2>> "$S/export.log"; then
        xstatus=chown_failed; xdetail="chown failed"
    elif ! ( cd "$EXPORT_TO" && sha256sum --strict --check --quiet EVIDENCE-SHA256SUMS ) >> "$S/export.log" 2>&1 \
         || [ "$(tree_listing "$RUN" | sha256sum)" != "$(tree_listing "$EXPORT_TO" | sha256sum)" ] \
         || [ "$( cd "$EXPORT_TO" && find . -type l -printf '%p -> %l\n' | LC_ALL=C sort | sha256sum)" != "$(sha256sum < "$RUN/EVIDENCE-SYMLINKS")" ]; then
        xstatus=mismatch; xdetail="copied files differ from the stage manifest or the file set/symlinks differ"
    else
        xstatus=verified
    fi
    write_receipt() {   # $1 status $2 detail -> $S/export-receipt.json (rc)
        /usr/bin/python3 -I -B -c "
import hashlib, json, pathlib, sys
S = pathlib.Path(sys.argv[1]); run = S / 'run'
h = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
man = run / 'EVIDENCE-SHA256SUMS'
r = {'schema': 'ct01-v0rt-export-receipt/2', 'status': sys.argv[2], 'detail': sys.argv[3] or None, 'label': sys.argv[4],
     'evidence_manifest_sha256': h(man) if man.exists() else None, 'evidence_files': len(man.read_text().splitlines()) if man.exists() else None,
     'symlinks_sha256': h(run / 'EVIDENCE-SYMLINKS') if (run / 'EVIDENCE-SYMLINKS').exists() else None,
     'tree_manifest_sha256': h(S / 'tree/SHA256SUMS'), 'pins_sha256': h(S / 'tree/pins.json'), 'runner_sha256': h(S / 'tree/run-v0-runtime.sh'),
     'evaluator_sha256': h(S / 'tree/evaluate_v0_runtime.py'), 'verdicts_sha256': h(run / 'verdicts.json') if (run / 'verdicts.json').exists() else None,
     'identity_sha256': h(run / 'run-identity.json') if (run / 'run-identity.json').exists() else None,
     'stage': str(S), 'export_dir': sys.argv[5] or None,
     'note': 'the run directory was frozen (log writer awaited) before the manifest; the manifest covers every file of it except EVIDENCE-SHA256SUMS; this receipt and exit-status.json are outside it'}
(S / 'export-receipt.json').write_text(json.dumps(r, indent=1) + '\n')
" "$S" "$1" "$2" "$LABEL" "$EXPORT_TO" 2>> "$S/export.log"
    }
    if [ "$xstatus" = verified ]; then
        if ! write_receipt verified ""; then
            xstatus=receipt_failed; xdetail="the export receipt could not be written"
        elif ! cp -a "$S/export-receipt.json" "$EXPORT_TO/EXPORT-RECEIPT.json" 2>> "$S/export.log" \
             || ! chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$EXPORT_TO/EXPORT-RECEIPT.json" 2>> "$S/export.log" \
             || ! cmp -s "$S/export-receipt.json" "$EXPORT_TO/EXPORT-RECEIPT.json"; then
            xstatus=receipt_copy_failed; xdetail="the receipt could not be copied/chowned/verified next to the evidence"
            rm -f "$EXPORT_TO/EXPORT-RECEIPT.json" 2>> "$S/export.log"
        fi
    fi
    if [ "$xstatus" != verified ]; then
        write_receipt "$xstatus" "$xdetail" || echo "receipt for status $xstatus could not be written" >> "$S/export.log"
    fi
    # final exit code: signal > abort > evaluator > export (4)
    final_exit() {
        local f=$erc
        [ "$xstatus" != verified ] && [ "$f" = 0 ] && f=4
        [ -n "$ABORT_REASON" ] && f=3
        [ -n "$SIGNAL" ] && f=$((128 + $(kill -l "$SIGNAL")))
        echo "$f"
    }
    write_exit_status() {
        /usr/bin/python3 -I -B -c "
import json, pathlib, sys
S = pathlib.Path(sys.argv[1])
(S / 'exit-status.json').write_text(json.dumps({'schema': 'ct01-v0rt-exit-status/1', 'label': sys.argv[2], 'signal': sys.argv[3] or None,
    'abort_reason': sys.argv[4] or None, 'evaluator_rc': int(sys.argv[5]), 'export_status': sys.argv[6], 'final_exit': int(sys.argv[7]),
    'rule': 'signal(128+n) > abort(3) > evaluator rc != 0 > export not verified (4) > 0'}, indent=1) + '\n')
" "$S" "$LABEL" "$SIGNAL" "$ABORT_REASON" "$erc" "$xstatus" "$(final_exit)" 2>> "$S/export.log"
    }
    retract_claims() {   # a claim of "verified" that turned out false must not stay next to the evidence
        rm -f "$EXPORT_TO/EXPORT-RECEIPT.json" "$EXPORT_TO/EXIT-STATUS.json" 2>> "$S/export.log"
    }
    if ! write_exit_status; then
        if [ "$xstatus" = verified ]; then
            xstatus=exit_status_failed; xdetail="exit-status.json could not be written"
            retract_claims
            write_receipt "$xstatus" "$xdetail"
        fi
    elif [ "$xstatus" = verified ]; then
        if ! cp -a "$S/exit-status.json" "$EXPORT_TO/EXIT-STATUS.json" 2>> "$S/export.log" \
           || ! chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$EXPORT_TO/EXIT-STATUS.json" 2>> "$S/export.log" \
           || ! cmp -s "$S/exit-status.json" "$EXPORT_TO/EXIT-STATUS.json"; then
            xstatus=exit_status_copy_failed; xdetail="exit-status.json could not be copied/chowned/verified next to the evidence"
            retract_claims
            write_exit_status
            write_receipt "$xstatus" "$xdetail"
        fi
    fi
    local final
    final=$(final_exit)
    if [ "$xstatus" = verified ]; then
        echo "evidence copied to $EXPORT_TO, frozen run directory verified against its manifest in the stage and in the export (stage copy $RUN kept); exit $final" >&3
    else
        echo "EXPORT NOT VERIFIED ($xstatus: $xdetail); the evidence stays in $RUN; exit $final (see $S/export.log)" >&3
    fi
    cat "$S/export-receipt.json" "$S/exit-status.json" >&3 2>/dev/null
    exit "$final"
}
trap finalize EXIT
trap 'SIGNAL=INT; exit 130' INT
trap 'SIGNAL=TERM; exit 143' TERM
trap 'SIGNAL=HUP; exit 129' HUP

# ------------------------------------------------------------------ 1. guards (nothing is created before all of them hold)
STAGE_REACHED="guards"
log "1. guards"
echo "host=$(hostname) user=${SUDO_USER:-root} label=$LABEL stage=$S"
echo "repo inputs are the staged copies under $IN (verified in the stage); nothing is read from the user tree"
M image-inspect "$RUN/image-inspect.txt" -- D image inspect -f '{{.Id}}' "$IMAGE_ID"
[ "$(rc_of image-inspect)" = 0 ] || abort "pinned image id not present locally (no pull is allowed)"
[ "$(cat "$RUN/image-inspect.txt")" = "$IMAGE_ID" ] || abort "image id mismatch"
echo "image $IMAGE_ID"
M names "$RUN/running-names.txt" -- D ps --format '{{.Names}}'
[ "$(rc_of names)" = 0 ] || abort "cannot list running containers"
if grep -Eq 'sandbox-worker|^ct01-06b3b-' "$RUN/running-names.txt"; then abort "a worker or a B1 container (sandbox-worker / ct01-06b3b-*) is running"; fi
M pgrep0 "$RUN/qemu-guard.txt" -- pgrep -a qemu-system
case "$(rc_of pgrep0)" in 1) ;; 0) abort "qemu-system running on the host";; *) abort "pgrep failed (rc $(rc_of pgrep0))";; esac
for c in ct01-v0rt-control ct01-v0rt-f1b ct01-v0rt-f6; do
    M "exists:$c" "$RUN/exists-$c.txt" -- D inspect "$c"
    [ "$(rc_of "exists:$c")" = 1 ] || abort "pre-existing container $c or inspect failed (left untouched)"
done
M network-ls "$RUN/network-ls.txt" -- D network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}'
[ "$(rc_of network-ls)" = 0 ] && [ "$(wc -l < "$RUN/network-ls.txt")" = 1 ] && [ -s "$RUN/network-ls.txt" ] || abort "sandboxnet not found/unique"
NET=$(cat "$RUN/network-ls.txt")
M network-inspect "$RUN/sandboxnet.txt" -- D network inspect -f 'name={{.Name}} id={{.Id}} driver={{.Driver}} internal={{.Internal}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} containers=[{{range .Containers}}{{.Name}} {{end}}]' "$NET"
[ "$(rc_of network-inspect)" = 0 ] || abort "network inspect failed"
cat "$RUN/sandboxnet.txt"
grep -q 'subnet=192.168.60.0/24 gw=192.168.60.1' "$RUN/sandboxnet.txt" || abort "unexpected sandboxnet"
echo "$NET" > "$RUN/network-name.txt"
cp "$P/pins.json" "$RUN/pins.json"
( cd "$S" && sha256sum tree/SHA256SUMS tree/run-v0-runtime.sh tree/evaluate_v0_runtime.py tree/verify_pins.py tree/pins.json tree/files/guest-f6.nft tree/files/sentinel/server.py tree/files/sentinel/poller.py ) | tee "$RUN/harness-sha256.txt"
host_state before
# fail closed: a host measurement that did not succeed is not a baseline (nothing is created before every one of them returned usable data)
for n in ip-route ip6-route nft ss image-inspect image-ls ps-all; do
    [ "$(rc_of "h-before:$n")" = 0 ] || abort "host measurement $n failed before the run (rc $(rc_of "h-before:$n")); no baseline"
done
for n in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; do
    [ "$(rc_of "h-before:sysctl:$n")" = 0 ] || abort "host sysctl $n unreadable before the run"
done
case "$(rc_of h-before:pgrep)" in 0|1) ;; *) abort "pgrep failed before the run";; esac
awk -F'\t' '$1 ~ /^h-before:inspect:/ && $2 != 0 {bad=1} END{exit bad}' "$RUN/measure-rc.tsv" || abort "docker inspect of another container failed before the run"
echo "$P/files/guest-f6.nft" > "$RUN/f6-guest-path.txt"
T0=$(date +%s)
echo "events --since $T0 --filter label=ct01-v0rt=$LABEL" >> "$RUN/docker-commands.log"
timeout 1800 docker events --since "$T0" --filter "label=ct01-v0rt=$LABEL" --format '{{json .}}' > "$RUN/events.jsonl" 2>/dev/null &
EV_PID=$!
sleep 1

# ------------------------------------------------------------------ 2. preflight
STAGE_REACHED="preflight"
log "2. preflight (containers with --rm, no network)"
PRE="$RUN/preflight"; mkdir -p "$PRE"
RESOLVE='for c in nft ip python3; do p=$(command -v $c) && echo "$c=$p" || echo "$c=NONE"; done'
M pre:resolve-default "$PRE/resolve-default-path.txt" -- D run --rm --network none --label "ct01-v0rt=$LABEL" --entrypoint /bin/sh "$IMAGE_ID" -c "$RESOLVE"
cat "$PRE/resolve-default-path.txt"
[ "$(rc_of pre:resolve-default)" = 0 ] || abort "preflight resolve (default PATH) failed"
IP_PATH=$(sed -n 's/^ip=//p' "$PRE/resolve-default-path.txt"); PY_PATH=$(sed -n 's/^python3=//p' "$PRE/resolve-default-path.txt")
[[ "$IP_PATH" == /* && "$PY_PATH" == /* ]] || abort "cannot resolve ip/python3 in the image"
mkdir -p "$RUN/ct01-path"
ln -s "$IP_PATH" "$RUN/ct01-path/ip"; ln -s "$PY_PATH" "$RUN/ct01-path/python3"
M pre:resolve-nonft "$PRE/resolve-nonft-path.txt" -- D run --rm --network none --label "ct01-v0rt=$LABEL" --entrypoint /bin/sh -e PATH=/ct01-path -v "$RUN/ct01-path:/ct01-path:ro" "$IMAGE_ID" -c "$RESOLVE"
cat "$PRE/resolve-nonft-path.txt"
[ "$(rc_of pre:resolve-nonft)" = 0 ] || abort "preflight resolve (restricted PATH) failed"
M pre:sha "$PRE/sha256-in-image.txt" -- D run --rm --network none --label "ct01-v0rt=$LABEL" --entrypoint /bin/sh "$IMAGE_ID" -c \
    'cd /app && sha256sum run.sh isolation/verify.py isolation/constants.py isolation/expected-ruleset.json isolation/load.nft isolation/guest.nft'
cat "$PRE/sha256-in-image.txt"
[ "$(rc_of pre:sha)" = 0 ] || abort "preflight sha256 in image failed"
# R5: the netdev ingress chain is bound to device "tap0" (guest.nft:12); a --network none container has no tap0, so `nft -c` failed even for the pinned
# guest.nft (R4 run 20261010T161816Z, probe r5-probe). A dummy tap0 is created INSIDE this throw-away container's own netns only (nothing on the host).
M pre:nftc "$PRE/f6-nft-check.txt" -- D run --rm --network none --cap-add NET_ADMIN --label "ct01-v0rt=$LABEL" --entrypoint /bin/sh \
    -v "$P/files/guest-f6.nft:/app/isolation/guest.nft:ro" "$IMAGE_ID" -c 'cd /app && { ip link add tap0 type dummy || { echo "TAP0-CREATE-FAILED"; echo "RC=97"; exit 0; }; ip -o link show tap0; }; nft -c -f /app/isolation/load.nft; echo "RC=$?"'
grep -o 'RC=[0-9]*' "$PRE/f6-nft-check.txt" | tail -1 | cut -d= -f2 > "$PRE/f6-nft-check.rc"
echo "nft -c rc=$(cat "$PRE/f6-nft-check.rc")"
[ "$(rc_of pre:nftc)" = 0 ] || abort "preflight nft -c container failed"
grep -q '^nft=NONE$' "$PRE/resolve-nonft-path.txt" || abort "nft still resolves under the restricted PATH"
grep -q '^nft=/' "$PRE/resolve-default-path.txt" || abort "nft does not resolve under the image's default PATH"
[ "$(cat "$PRE/f6-nft-check.rc")" = 0 ] || abort "nft -c rejected guest-f6.nft (see $PRE/f6-nft-check.txt)"
/usr/bin/python3 -I -B - "$P/pins.json" "$PRE/sha256-in-image.txt" <<'CT01_V0RT_IMG' || abort "the image does not hold the pinned bytes"
import json, sys
pins = json.load(open(sys.argv[1]))["sources"]
got = {}
for l in open(sys.argv[2]):
    h, _, f = l.partition("  ")
    got[f.strip()] = h
bad = [r for r, m in pins.items() if r != "isolation/__init__.py" and got.get(r) != m["sha256"]]
print("image bytes equal the pins" if not bad else f"image bytes differ from the pins: {bad}")
sys.exit(1 if bad else 0)
CT01_V0RT_IMG

# ------------------------------------------------------------------ 3. branches
SD() { local d="$RUN/$1/sentinel"; mkdir -p "$d"; chmod 777 "$d"; echo "$d"; }
LAST_ID=""
start_case() {  # case name extra-docker-args...  -> LAST_ID
    local case=$1 name=$2; shift 2
    local sd id rc
    sd=$(SD "$case")
    LAST_ID=""
    id=$(D run -d --name "$name" --label "ct01-v0rt=$LABEL" --restart no --privileged --network "$NET" \
        -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$name" \
        -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
        -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
        -v "$P/files/sentinel/server.py:/app/server.py:ro" -v "$P/files/sentinel/poller.py:/app/poller.py:ro" -v "$sd:/sentinel-out" \
        "$@" "$IMAGE_ID"); rc=$?
    echo "$rc" > "$RUN/$case/create.rc"
    [ "$rc" = 0 ] && [[ "$id" =~ ^[0-9a-f]{64}$ ]] || return 1
    CREATED_IDS+=("$id"); LAST_ID=$id
    echo "$id" > "$RUN/$case/container-id.txt"
}

STAGE_REACHED="control"
log "3a. control: unchanged image, sentinels"
mkdir -p "$RUN/control"
start_case control ct01-v0rt-control || abort "control could not be created"
CID=$LAST_ID
for i in $(seq 1 60); do
    [ -e "$RUN/control/sentinel/poller-called" ] && [ -e "$RUN/control/sentinel/server-called" ] && break
    [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" = true ] || break
    sleep 0.5
done
M ctl:state "$RUN/control/state-before-stop.json" -- D inspect -f '{{json .State}}' "$CID"
M ctl:logs "$RUN/control/docker-logs.txt" -- D logs --timestamps "$CID"
X="$RUN/control/exec"; mkdir -p "$X"
E() { D exec "$CID" "$@"; }
M ctl:running "$X/running.txt" -- D inspect -f '{{.State.Running}}' "$CID"
[ "$(cat "$X/running.txt")" = true ] || abort "control container is not running before the read-only commands"
M ctl:verify "$X/verify-recheck.txt" -- E sh -c 'cd /app && python3 -m isolation.verify --phase "ct01-v0rt control recheck"'
echo "$(rc_of ctl:verify)" > "$X/verify-recheck.rc"
M ctl:ps "$X/ps.txt" -- E ps -eo pid,ppid,args
M ctl:grep "$X/sentinel-grep.txt" -- E sh -c 'grep -q SENTINEL /app/poller.py /app/server.py'
echo "$(rc_of ctl:grep)" > "$X/sentinel-grep.rc"
M ctl:sha "$X/sha256-in-container.txt" -- E sh -c 'cd /app && sha256sum run.sh isolation/verify.py isolation/constants.py isolation/expected-ruleset.json isolation/load.nft isolation/guest.nft'
M ctl:norm "$X/normalized-runtime.json" -- E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized'
M ctl:nftver "$X/nft-version.txt" -- E nft --version
M ctl:nft "$X/nft-ruleset-stateless.txt" -- E nft -s list ruleset
M ctl:iplink "$X/ip-d-link.txt" -- E ip -d link show
M ctl:stop "$RUN/control/stop.txt" -- D stop -t 10 "$CID"
M ctl:inspect "$RUN/control/inspect.json" -- D inspect "$CID"
M ctl:logsfinal "$RUN/control/docker-logs-final.txt" -- D logs --timestamps "$CID"
M ctl:rm "$RUN/control/rm.txt" -- D rm "$CID"

run_negative() {  # case name extra-args...
    local case=$1 name=$2; shift 2
    STAGE_REACHED="$case"
    log "3. $case: $name"
    mkdir -p "$RUN/$case"
    start_case "$case" "$name" "$@" || abort "$case could not be created"
    local id=$LAST_ID code wp wrc
    echo "wait $id" >> "$RUN/docker-commands.log"
    timeout 60 docker wait "$id" > "$RUN/$case/wait.txt" 2> "$RUN/$case/wait.err" &
    wp=$!
    wait "$wp"; wrc=$?                      # `wait` is interruptible by a trapped signal; the foreground docker CLI would not be
    code=$(cat "$RUN/$case/wait.txt" 2>/dev/null)
    if [ "$wrc" -ne 0 ] || ! [[ "$code" =~ ^[0-9]+$ ]]; then code=TIMEOUT; fi
    echo "exit code: $code" | tee "$RUN/$case/exit-code.txt"
    echo "$wrc" > "$RUN/$case/wait.rc"
    M "$case:logs" "$RUN/$case/docker-logs.txt" -- D logs --timestamps "$id"
    M "$case:inspect" "$RUN/$case/inspect.json" -- D inspect "$id"
    tail -6 "$RUN/$case/docker-logs.txt"
    M "$case:rm" "$RUN/$case/rm.txt" -- D rm "$id"
}
run_negative f1b ct01-v0rt-f1b -e PATH=/ct01-path -v "$RUN/ct01-path:/ct01-path:ro"
run_negative f6 ct01-v0rt-f6 -v "$P/files/guest-f6.nft:/app/isolation/guest.nft:ro"

# ------------------------------------------------------------------ 4. host state after
STAGE_REACHED="host-after"
log "4. host state after"
sleep 2
host_state after
for f in $(ls "$RUN/host-before" | grep -v '\.err$'); do
    if diff -u "$RUN/host-before/$f" "$RUN/host-after/$f" > "$RUN/host-diff-$f.diff"; then rm "$RUN/host-diff-$f.diff"; echo "unchanged: $f"; else echo "CHANGED: $f"; fi
done
sleep 1
STAGE_REACHED="evaluating"
exit 0
