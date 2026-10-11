#!/bin/bash
# CT-01 T16/T17 (derived from run-ct01-b1.sh): guest MAC change and spoofed source IPv4 (spoof_cases.py), ARM then MIPS.
# Prepared offline; use only the reviewed bootstrap/launcher after separate operational approval. All gates, drain, cleanup and
# host checks of the B1 runner are kept; only the suite, the outcome evaluator and the (removed) T20 route lookups differ.
# B1/B2 offline candidate: use only the reviewed bootstrap/launcher after separate operational approval.
# Root-staged ARP entry, based on 4IR3. All 35 baseline harness files are preserved separately.
# Eight prerequisites plus mandatory rc/identity checks gate ARM; ARM nonPASS/postcheck failure gates MIPS.
# ENTRY/SETUP/ARM/MIPS use the same approved collection/window; worker rechecks freshness before QEMU.
# Manager MUST already run: automatic startup/requeue of Mongo PROCESSING rows is deliberately disabled.
# Worker/control/captures are created for this session; cleanup is attempted and checked where recorded.
# rc98/99 skip per-architecture process/isolation postchecks; resource/host teardown still runs.
# Output stays root-owned under the private runtime stage, including early failure. No automatic chown.
# timeout 1700 bounds the Docker client; worker DEADLINE_S=1500 is a separate deadline.
# Guard 20 ms and real guest/kernel/netifd behavior remain unmeasured. CT-01 is not achieved.
set -uo pipefail

EXPECTED_IMAGE_ID=sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153
H=$(cd -- "$(dirname -- "$0")" && pwd)
OUT=$H/out
REPO=$(cd -- "$H/../repo" && pwd)
: "${CT01_LAUNCH_RECEIPT:?Use the reviewed pinned root launcher; no direct run}"
: "${CT01_LAUNCH_ID:?Launch UUID required for resource ownership}"
IMAGE=sandbox-worker:latest
NAME=ct01-06b3b-guest
CTL=ct01-06b3b-ctl
MANAGER=cic-ynu-iotmal-sandbox-sandbox-manager-1
GUEST_MAC=52:54:00:c7:00:02
LAN_DNS=192.168.177.2
# T16/T17: LAN_OTHER is not used by this suite (kept only because the TARGETS record format is shared with B1).
LAN_OTHER=192.168.177.250

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ -e "$OUT" ] && { echo "ABORT: $OUT exists (keep previous evidence; move it first)"; exit 2; }
mkdir -p "$OUT/hostcap" "$OUT/ctl" "$OUT/harness-copy"
# Regular-file logging: no tee process whose death can SIGPIPE the EXIT trap.
exec >> "$OUT/run.log" 2>&1
trap '' PIPE
INTERRUPT_CODE=0
remember_signal() {
    local number=$1 name=$2
    [ "$INTERRUPT_CODE" -ne 0 ] && return 0
    INTERRUPT_CODE=$((128+number))
    printf '{"schema":"ct01-arp-interruption/1","number":%s,"signal":"%s","source":"script"}\n' "$number" "$name" > "$OUT/interruption.json"
    echo "[INTERRUPTED] $name; no next guest; cleanup is awaited"
}
signal_stop() {
    remember_signal "$1" "$2"
    exit "$INTERRUPT_CODE"
}
# During cleanup, record signals in the shell but isolate external recovery commands from its PGID.
run_cleanup_command() {
    ( trap '' INT TERM HUP PIPE; exec /usr/bin/setsid --wait "$@" ) &
    local recovery_pid=$! recovery_rc
    while :; do
        wait "$recovery_pid"; recovery_rc=$?
        kill -0 "$recovery_pid" 2>/dev/null && continue
        return "$recovery_rc"
    done
}
trap 'signal_stop 2 SIGINT' INT
trap 'signal_stop 15 SIGTERM' TERM
trap 'signal_stop 1 SIGHUP' HUP
cp "$0" "$H/probe_matrix.py" "$H/ctl_loop.py" "$H/sentinel/poller.py" "$H/harness_lib.sh" "$H/sigscan.sh" \
    "$H/make_fixtures.py" "$H/selftest.sh" "$H/independent_check.sh" "$H/pcapng_stats.py" "$H/mutation_test.sh" \
    "$H/counter_window.py" "$H/signatures.py" "$H/l2frames.py" "$H/guest_state.py" "$H/sigscan_l2.py" \
    "$H/selftest_l2.py" "$H/mutation_l2.py" \
    "$H/icmp_cases.py" "$H/icmp_harness.py" "$H/l2eval.py" "$H/selftest_icmp.py" "$H/selftest_l2eval.py" \
    "$H/selftest_icmp_wiring.py" "$H/run-06b3b.sh" \
    "$H/arp_cases.py" "$H/arp_harness.py" "$H/selftest_arp.py" "$H/selftest_arp_wiring.py" "$H/run-06b4f.sh" \
    "$H/spoof_cases.py" "$H/spoof_harness.py" "$H/selftest_spoof.py" \
    "$H/b1_cases.py" "$H/b1_harness.py" "$H/selftest_b1.py" "$H/probe_matrix_launch.py" "$H/worker_guard.py" "$H/capture_drain.py" "$H/cumulative_anchor.py" "$H/capture_drain.sh" "$OUT/harness-copy/" || { echo "ABORT: copy-list failed; no guest called"; exit 3; }
sha256sum "$OUT"/harness-copy/* | tee "$OUT/harness-sha256.txt" || { echo "ABORT: copy-list hashes unavailable; no guest called"; exit 3; }
# R3b: the self-tests' inner python subprocesses (stripped environment) write bytecode into "$H/__pycache__". The launcher's closed stage layout
# rejects unmanifested files at the SETUP checkpoint, so remove EXACTLY that cache directory - only regular cpython .pyc files in it, never via a
# symlink, never anything else. Names and types are read NUL-delimited (a name may contain a newline); the WHOLE list is validated before the first
# removal and any unexpected entry (symlink, other type, other name) aborts with everything kept. Does not relax the layout.
clean_selftest_bytecode() {
    local d="$H/__pycache__" listing="$OUT/selftest-bytecode-listing.nul" i type name
    local -a fields=()
    [ -e "$d" ] || [ -L "$d" ] || return 0
    [ ! -L "$d" ] || { echo "cache dir $d is a symlink; not touching it"; return 1; }
    [ -d "$d" ] || { echo "cache path $d is not a directory"; return 1; }
    /usr/bin/find "$d" -mindepth 1 -maxdepth 1 -printf '%y\0%f\0' > "$listing" || { echo "cannot list $d"; return 1; }
    mapfile -d '' -t fields < "$listing" || { echo "cannot read the listing of $d"; return 1; }
    [ $(( ${#fields[@]} % 2 )) -eq 0 ] || { echo "malformed listing of $d; nothing removed"; return 1; }
    for (( i = 0; i < ${#fields[@]}; i += 2 )); do
        type=${fields[i]}; name=${fields[i+1]}
        [ "$type" = f ] && [[ "$name" =~ ^[A-Za-z0-9_]+\.cpython-3[0-9]+\.pyc$ ]] || { echo "unexpected entry in $d (type $type, name $(printf '%q' "$name")); nothing removed"; return 1; }
    done
    for (( i = 0; i < ${#fields[@]}; i += 2 )); do
        /usr/bin/rm -f -- "$d/${fields[i+1]}" || { echo "cannot remove $d/${fields[i+1]}"; return 1; }
    done
    /usr/bin/rmdir -- "$d" || { echo "cannot remove cache dir $d"; return 1; }
}
# Offline self-test of the scanner, the capture watcher and the manager handling; nothing runs if it fails.
bash "$H/selftest.sh" "$OUT/selftest" > "$OUT/selftest.txt" 2>&1 || { cat "$OUT/selftest.txt"; echo "ABORT: harness self-test failed"; exit 3; }
tail -1 "$OUT/selftest.txt"
# 06B-4B: offline self-test of the new modules (no regression section: that needs the 06B-3G evidence)
python3 "$H/selftest_l2.py" --offline-only > "$OUT/selftest-l2.txt" 2>&1 || { cat "$OUT/selftest-l2.txt"; echo "ABORT: L2 self-test failed"; exit 3; }
tail -1 "$OUT/selftest-l2.txt"
# 06B-4F: offline self-tests of the ICMP cases and of their wiring; nothing runs if either fails.
python3 "$H/selftest_icmp.py" > "$OUT/selftest-icmp.txt" 2>&1 || { cat "$OUT/selftest-icmp.txt"; echo "ABORT: ICMP self-test failed"; exit 3; }
tail -1 "$OUT/selftest-icmp.txt"
python3 "$H/selftest_icmp_wiring.py" > "$OUT/selftest-icmp-wiring.txt" 2>&1 || { cat "$OUT/selftest-icmp-wiring.txt"; echo "ABORT: ICMP wiring self-test failed"; exit 3; }
tail -1 "$OUT/selftest-icmp-wiring.txt"
# 06B-4I: offline self-tests of the ARP cases and of their wiring; nothing runs if either fails.
python3 "$H/selftest_arp.py" > "$OUT/selftest-arp.txt" 2>&1 || { cat "$OUT/selftest-arp.txt"; echo "ABORT: ARP self-test failed"; exit 3; }
tail -1 "$OUT/selftest-arp.txt"
python3 "$H/selftest_arp_wiring.py" > "$OUT/selftest-arp-wiring.txt" 2>&1 || { cat "$OUT/selftest-arp-wiring.txt"; echo "ABORT: ARP wiring self-test failed"; exit 3; }
tail -1 "$OUT/selftest-arp-wiring.txt"
# CT-01 B1: offline self-test of the B1 cases and their outcome mapping; nothing runs if it fails.
python3 "$H/selftest_b1.py" > "$OUT/selftest-b1.txt" 2>&1 || { cat "$OUT/selftest-b1.txt"; echo "ABORT: B1 self-test failed"; exit 3; }
tail -1 "$OUT/selftest-b1.txt"
# CT-01 T16/T17: offline self-test of the spoof cases and their outcome mapping; nothing runs if it fails.
python3 "$H/selftest_spoof.py" > "$OUT/selftest-spoof.txt" 2>&1 || { cat "$OUT/selftest-spoof.txt"; echo "ABORT: spoof self-test failed"; exit 3; }
tail -1 "$OUT/selftest-spoof.txt"
clean_selftest_bytecode || { echo "ABORT: self-test bytecode cleanup failed; no guest called"; exit 3; }
python3 "$H/signatures.py" --check || { echo "ABORT: signature registry invalid"; exit 3; }
eval "$(python3 "$H/signatures.py" --shell)" || { echo "ABORT: signature registry not loadable"; exit 3; }
source "$H/harness_lib.sh"   # existing consumers unchanged
source "$H/capture_drain.sh" # ARP-only bounded stop + watcher
CAPTURE_STOPPING="$OUT/hostcap/capture-stopping.txt"

CREATED_IDS=(); FAILS=(); UNVERIFIED=(); OPEN_ITEMS=(); SESSION_RESULTS=(); TCPDUMP_PIDS=(); TCPDUMP_NAMES=(); WATCH_PID=""
ARCH_CALLED=(); ARCH_STOP=""   # 06B-4IR3 (PC-1): architectures whose harness was called; why the loop stopped
DRAIN_S=3           # 06B-3DR: after the controls stop, captures get this long to process what is left
CAP_DEADLINE_S=10   # then SIGINT; a capture still running after this many seconds is killed (FAIL)
log()  { echo; echo "===== $* ($(date -u +%H:%M:%S))"; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS+=("$*"); }
check() { local msg=$1; shift; if "$@"; then pass "$msg"; else fail "$msg"; return 1; fi; }
# Remove the temporary capture dir only if it is exactly the mktemp path this run created.
rm_capd() { [[ "${CAPD:-}" == /tmp/ct01-06b3b-cap.?????? ]] && [ -d "$CAPD" ] && rm -r -- "$CAPD"; }
COMPOSE=(docker compose --project-directory "$REPO" -f "$REPO/docker-compose.yml")

# Stops the host captures with a deadline (harness_lib.sh: stop_captures_deadline). Exit codes go to
# hostcap/tcpdump-exit.txt ("<name> <rc>" or "<name> KILLED_AT_DEADLINE"), every step to the timeline.
stop_tcpdumps() {
    local i e=() rc
    [ ${#TCPDUMP_PIDS[@]} -gt 0 ] || return 0
    for i in "${!TCPDUMP_PIDS[@]}"; do e+=("${TCPDUMP_NAMES[$i]}:${TCPDUMP_PIDS[$i]}"); done
    stop_drain_captures_deadline "$CAP_DEADLINE_S" "$OUT/hostcap/tcpdump-exit.txt" "$OUT/hostcap/teardown-timeline.txt" "$CAPTURE_STOPPING" "${e[@]}"
    rc=$?
    TCPDUMP_PIDS=(); TCPDUMP_NAMES=()
    return $rc
}
# First-run manager policy overrides prepare, never starts a container or mutates Mongo queue.
manager_prepare() {
    MANAGER_STATE_BEFORE=$(manager_inspect '{{.State.Status}}') || return 2
    MANAGER_ID_BEFORE=$(manager_inspect '{{.Id}}') || return 2
    MANAGER_STARTED_AT_BEFORE=$(manager_inspect '{{.State.StartedAt}}') || return 2
    echo "manager before: state=$MANAGER_STATE_BEFORE id=$MANAGER_ID_BEFORE startedAt=$MANAGER_STARTED_AT_BEFORE"
    [ "$MANAGER_STATE_BEFORE" = running ] || { echo "first-run policy: manager must already run; no queue-changing startup"; return 2; }
    return 0
}
MANAGER_STATE_BEFORE=""; MANAGER_ID_BEFORE=""; MANAGER_STARTED_AT_BEFORE=""
WORKER_RUN_ATTEMPTED=0; CTL_RUN_ATTEMPTED=0
CAPD=""; ID=""; CID=""; D=""; DEAD=""; HB=""; HOST_BEFORE_OK=0; CAPTURE_STARTED=0
cleanup() {
    # Repeated terminal signals must not interrupt resource recovery or depend on a console pipe.
    trap 'remember_signal 2 SIGINT' INT
    trap 'remember_signal 15 SIGTERM' TERM
    trap 'remember_signal 1 SIGHUP' HUP
    trap '' PIPE
    printf '{"schema":"ct01-arp-cleanup/1","attempts_completed":false,"command_errors":null}\n' > "$OUT/cleanup-status.json"
    local cleanup_errors=0 id seen=" "
    stop_tcpdumps || cleanup_errors=1
    stop_capture_watch || cleanup_errors=1
    if [[ "${CAPD:-}" == /tmp/ct01-06b3b-cap.?????? ]] && [ -d "$CAPD" ]; then
        run_cleanup_command rm -r -- "$CAPD" || cleanup_errors=1
    fi
    # Include IDs already assigned even if a signal arrived before appending CREATED_IDS.
    local ids=("${CREATED_IDS[@]}" "${ID:-}" "${CID:-}")
    # Reconcile an interrupted docker run that created a container but did not return its ID.
    local role name label found_id attempted
    for role in WORKER CTL; do
        if [ "$role" = WORKER ]; then name=$NAME; attempted=$WORKER_RUN_ATTEMPTED; else name=$CTL; attempted=$CTL_RUN_ATTEMPTED; fi
        [ "$attempted" -eq 1 ] || continue
        label=$(run_cleanup_command docker inspect -f '{{index .Config.Labels "ct01.launch_id"}}' "$name" 2>/dev/null) || continue
        [ "$label" = "$CT01_LAUNCH_ID" ] || continue # never delete a container owned by a different launch
        found_id=$(run_cleanup_command docker inspect -f '{{.Id}}' "$name" 2>/dev/null) || { cleanup_errors=1; continue; }
        [[ "$found_id" =~ ^[0-9a-f]{64}$ ]] || { cleanup_errors=1; continue; }
        ids+=("$found_id")
    done
    for id in "${ids[@]}"; do
        [ -n "$id" ] || continue
        [[ "$seen" == *" $id "* ]] && continue
        seen+="$id "
        if run_cleanup_command docker inspect "$id" >/dev/null 2>&1; then
            run_cleanup_command docker logs --timestamps "$id" > "$OUT/final-logs-${id:0:12}.txt" 2>&1 || true
            run_cleanup_command docker rm -f "$id" >/dev/null 2>&1 || cleanup_errors=1
        fi
    done
    manager_restore >> "$OUT/manager-state.txt" 2>&1 || cleanup_errors=1   # no-op if prepare never ran/already restored
    printf '{"schema":"ct01-arp-cleanup/1","attempts_completed":true,"command_errors":%s}\n' "$([ "$cleanup_errors" -eq 0 ] && echo false || echo true)" > "$OUT/cleanup-status.json"
    [ "$INTERRUPT_CODE" -eq 0 ] || exit "$INTERRUPT_CODE"
    return "$cleanup_errors"
}
trap cleanup EXIT

proc_state() {
    local pattern=$1 dst=$2 empty=$3 prc
    pgrep -a "$pattern" > "$dst" 2>&1; prc=$?
    if [ "$prc" -eq 1 ]; then printf '%s\n' "$empty" > "$dst"; return 0; fi
    [ "$prc" -eq 0 ] && test -s "$dst"
}
host_state() {
    local d="$OUT/host-$1" trc
    mkdir -p "$d" || return 1
    ip -br link > "$d/ip-link.txt" || return 1
    ip -br addr > "$d/ip-addr.txt" || return 1
    ip route > "$d/ip-route.txt" || return 1
    ip -6 route > "$d/ip6-route.txt" || return 1
    for required in ip-link.txt ip-addr.txt ip-route.txt; do test -s "$d/$required" || return 1; done
    ip link show tap0 > "$d/host-tap0.txt" 2>&1; trc=$?
    [ "$trc" -le 1 ] || return 1 # absent host tap0 rc1 is evidence, read error rc2 is not absence
    nft -s list ruleset > "$d/nft-ruleset-stateless.txt" 2>&1 || return 1
    test -s "$d/nft-ruleset-stateless.txt" || return 1
    lsmod > "$d/lsmod-raw.txt" || return 1
    test -s "$d/lsmod-raw.txt" || return 1
    awk 'NR>1{print $1}' "$d/lsmod-raw.txt" | awk '/^(nf_|nft_|xt_|br_netfilter|bridge|tun|veth|ip_tables|ip6_tables|x_tables|iptable_|ip6table_|nfnetlink)/' | sort > "$d/lsmod-net.txt" || return 1
    {
        for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 net.core.devconf_inherit_init_net; do
            v=$(sysctl -n "$k") || return 1; [[ "$v" =~ ^[0-9]+$ ]] || return 1; echo "$k=$v"
        done
        for dev in all default ens33; do for attr in rp_filter arp_ignore arp_announce arp_accept forwarding; do
            k="net.ipv4.conf.$dev.$attr"; v=$(sysctl -n "$k") || return 1; [[ "$v" =~ ^[0-9]+$ ]] || return 1; echo "$k=$v"
        done; done
    } > "$d/sysctl.txt" || return 1
    ss -ltnH | awk '{print $4}' | sort > "$d/listen-tcp.txt" || return 1
    docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | sort > "$d/docker-ps.txt" || return 1
    test -s "$d/docker-ps.txt" || return 1 # existing manager/Mongo must be represented
    proc_state qemu-system "$d/qemu.txt" 'no qemu-system' || return 1
    proc_state 'tshark|dumpcap|tcpdump' "$d/capture-procs.txt" 'no capture processes' || return 1
}
no_process() { pgrep "$1" >/dev/null; local prc=$?; [ "$prc" -eq 1 ]; }
valid_ip() { python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); sys.exit(0 if not (a.is_unspecified or a.is_multicast or int(a)==4294967295) else 1)' "$1"; }
valid_mac() { python3 -c 'import re,sys; m=sys.argv[1]; sys.exit(0 if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",m) and m!="00:00:00:00:00:00" and not int(m[:2],16)&1 else 1)' "$1"; }
current_gate() {
    /usr/bin/python3 -I -B "$H/../launcher.py" checkpoint "$CT01_LAUNCH_RECEIPT" "$1"
    local grc=$?
    if [ "$grc" -ne 0 ]; then fail "current gate $1 rejected (rc=$grc); guest not called for $1"; return 1; fi
}
pre_guest_setup() {
    current_gate SETUP || return 3
# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
cat "$REPO/source-provenance.json" || { fail "runtime provenance unreadable"; return 3; }
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
[ "$IMAGE_ID" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: image id is not the reviewed image"; return 3; }
pass "image id equals reviewed full id"
docker ps -a --format '{{.Names}} {{.Status}}'
docker ps --format '{{.Names}}' | grep -q 'sandbox-worker' && { echo "ABORT: a worker container is running"; return 3; }
pgrep -a qemu-system && { echo "ABORT: qemu running"; return 3; }
pgrep -a 'tcpdump|tshark|dumpcap' && { echo "ABORT: capture process already running on host"; return 3; }
for c in "$NAME" "$CTL"; do docker inspect "$c" >/dev/null 2>&1 && { echo "ABORT: pre-existing container $c (left untouched)"; return 3; }; done
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}') || { fail "reading SANDBOXNET failed; guest not called"; return 3; }
DBNET=$(docker network ls --filter label=com.docker.compose.network=dbnet --format '{{.Name}}') || { fail "reading DBNET failed; guest not called"; return 3; }
[[ "$SANDBOXNET" =~ ^[A-Za-z0-9_.-]+$ ]] && [[ "$DBNET" =~ ^[A-Za-z0-9_.-]+$ ]] && [ "$SANDBOXNET" != "$DBNET" ] || { echo "ABORT: networks not found"; return 3; }
BR="br-$(docker network inspect -f '{{.Id}}' "$SANDBOXNET" | cut -c1-12)" || { fail "reading BR failed; guest not called"; return 3; }
MONGO_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$DBNET\").IPAddress}}" mongo-db) || { fail "reading MONGO_IP failed; guest not called"; return 3; }
SANDBOX_GW=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$SANDBOXNET") || { fail "reading SANDBOX_GW failed; guest not called"; return 3; }
DB_GW=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$DBNET") || { fail "reading DB_GW failed; guest not called"; return 3; }
ENS_IP=$(ip -4 -o addr show dev ens33 | awk '{print $4}' | cut -d/ -f1) || { fail "reading ENS_IP failed; guest not called"; return 3; }
echo "sandboxnet=$SANDBOXNET bridge=$BR dbnet=$DBNET mongo=$MONGO_IP host-ips=$SANDBOX_GW,$ENS_IP,$DB_GW lan-dns=$LAN_DNS" | tee "$OUT/targets-env.txt"
check "mandatory host-state before readable" host_state before || return 3
HOST_BEFORE_OK=1
for ipvar in MONGO_IP SANDBOX_GW DB_GW ENS_IP LAN_DNS LAN_OTHER; do
    check "$ipvar valid" valid_ip "${!ipvar}" || return 3
done
# First-run policy: manager must already run before snapshot; no queue-mutating startup here.
mstate=$(manager_inspect '{{.State.Status}}') || { fail "manager state unreadable"; return 3; }
check "manager already running (no automatic queue-changing startup)" test "$mstate" = running || return 3

# ------------------------------------------------------------------ 2. manager (controls only)
log "2. existing running manager for controls (no startup/restart)"
[ "$(manager_inspect '{{.State.Status}}')" = running ] || { fail "manager changed before prepare; no automatic start"; return 3; }
manager_prepare > "$OUT/manager-state.txt" 2>&1; rc=$?
cat "$OUT/manager-state.txt"
[ $rc -eq 0 ] || { echo "ABORT: manager prepare failed (rc=$rc); see manager-state.txt"; return 3; }
ok=0; for i in $(seq 1 30); do
    python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status==200 else 1)' 2>/dev/null && { ok=1; break; }; sleep 1; done
check "manager healthy (127.0.0.1:8011/healthcheck)" test $ok -eq 1 || return 3
docker inspect -f 'manager: {{.State.Status}} ip={{(index .NetworkSettings.Networks "'"$SANDBOXNET"'").IPAddress}}' "$MANAGER" | tee -a "$OUT/manager-state.txt"
MANAGER_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$MANAGER") || { fail "reading MANAGER_IP failed; guest not called"; return 3; }
# 06B-4B: the manager's real MAC on sandboxnet, so that an ARP claiming 192.168.60.10 with another MAC
# is a signature (sigscan_l2.py arp_spoof_spa_manager)
MANAGER_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").MacAddress}}" "$MANAGER") || { fail "reading MANAGER_MAC failed; guest not called"; return 3; }

check "manager IP valid" valid_ip "$MANAGER_IP" || return 3
check "T14-A2 manager endpoint is 192.168.60.10" test "$MANAGER_IP" = 192.168.60.10 || return 3
check "manager MAC valid" valid_mac "$MANAGER_MAC" || return 3
# ------------------------------------------------------------------ 3. worker test container
log "3. worker test container"
D="$OUT/container"; mkdir -p "$D/sentinel" "$D/probe"; chmod 777 "$D/sentinel" "$D/probe" "$OUT/ctl" "$OUT/hostcap"
WORKER_RUN_ATTEMPTED=1
ID=$(docker run -d --name "$NAME" --label "ct01.launch_id=$CT01_LAUNCH_ID" --restart no --privileged --network "$SANDBOXNET" \
    -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$NAME" \
    -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
    -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
    -v "$H/sentinel/poller.py:/app/poller.py:ro" -v "$H/probe_matrix_launch.py:/harness/probe_matrix.py:ro" -v "$H/worker_guard.py:/harness/worker_guard.py:ro" -v "$H/../launch-proof:/launch-proof:ro" \
    -v "$H/pcapng_stats.py:/harness/pcapng_stats.py:ro" \
    -v "$H/counter_window.py:/harness/counter_window.py:ro" \
    -v "$H/icmp_harness.py:/harness/icmp_harness.py:ro" -v "$H/icmp_cases.py:/harness/icmp_cases.py:ro" \
    -v "$H/l2frames.py:/harness/l2frames.py:ro" -v "$H/l2eval.py:/harness/l2eval.py:ro" \
    -v "$H/signatures.py:/harness/signatures.py:ro" \
    -v "$H/arp_harness.py:/harness/arp_harness.py:ro" -v "$H/arp_cases.py:/harness/arp_cases.py:ro" \
    -v "$H/guest_state.py:/harness/guest_state.py:ro" \
    -v "$H/b1_cases.py:/harness/b1_cases.py:ro" -v "$H/b1_harness.py:/harness/b1_harness.py:ro" \
    -v "$H/spoof_cases.py:/harness/spoof_cases.py:ro" -v "$H/spoof_harness.py:/harness/spoof_harness.py:ro" \
    -v "$D/sentinel:/sentinel-out" -v "$D/probe:/harness-out" \
    -v "$OUT/hostcap:/hostcap:ro" -v "$OUT/ctl:/ctl:ro" \
    "$IMAGE") || { echo "ABORT: docker run failed"; return 3; }
CREATED_IDS+=("$ID"); echo "worker test container: $ID"
E() { docker exec "$ID" "$@"; }
# Network state of the worker netns: full record, plus short forms that are compared before/after.
netns_state() {
    { for c in "ip -d link show" "ip addr show" "ip route show table all" "ip -6 route show table all" \
               "ip neigh show" "ip rule show"; do echo "## $c"; E $c; echo; done; } > "$D/netns-$1.txt" 2>&1
    E ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | sort | tr '\n' ' ' > "$D/netns-$1-ifnames.txt"
    E ip -br addr show > "$D/netns-$1-addr-br.txt"
    E ip route show > "$D/netns-$1-route-main.txt"
}
ok=0; for i in $(seq 1 30); do
    E python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status==200 else 1)' 2>/dev/null && { ok=1; break; }; sleep 1; done
check "worker server ready" test $ok -eq 1 || return 3
docker logs --timestamps "$ID" > "$D/docker-logs-startup.txt" 2>&1
check "V0 passed" grep -q 'ISOLATION OK (V0 startup)' "$D/docker-logs-startup.txt" || return 3
WORKER_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$ID") || { fail "reading WORKER_IP failed; guest not called"; return 3; }
IFIDX=$(E cat /sys/class/net/eth0/iflink | tr -d '\r') || { fail "reading IFIDX failed; guest not called"; return 3; }
VETH=$(ip -o link | awk -F': ' -v i="$IFIDX" '$1==i{print $2}' | cut -d@ -f1) || { fail "reading VETH failed; guest not called"; return 3; }
echo "worker eth0=$WORKER_IP host veth=$VETH (ifindex $IFIDX)" | tee -a "$OUT/targets-env.txt"
[ -n "$VETH" ] || { echo "ABORT: worker veth not found"; return 3; }
FILES="run.sh server.py service/analysis.py isolation/apifilter.py isolation/verify.py isolation/guest.nft isolation/expected-ruleset.json ARM/image.zip MIPS/image.zip"
E sh -c "cd /app && sha256sum $FILES" > "$D/sha256-in-container.txt"; rc=$?
check "runtime hashes in container read successfully" test "$rc" -eq 0 || return 3
( cd "$REPO/sandbox-worker" && sha256sum $FILES ) > "$D/sha256-repo.txt"; rc=$?
check "staged repository hashes read successfully" test "$rc" -eq 0 || return 3
check "code and guest images in container equal working tree" diff -q "$D/sha256-in-container.txt" "$D/sha256-repo.txt" || return 3
check "worker IP valid" valid_ip "$WORKER_IP" || return 3
check "T14-A1 worker endpoint is 192.168.60.2" test "$WORKER_IP" = 192.168.60.2 || return 3
WORKER_MAC=$(E cat /sys/class/net/eth0/address) || { fail "worker eth0 MAC unreadable"; return 3; }
TAP_MAC=$(E cat /sys/class/net/tap0/address) || { fail "worker tap0 MAC unreadable"; return 3; }
check "worker eth0 MAC valid" valid_mac "$WORKER_MAC" || return 3
check "worker tap0 MAC valid" valid_mac "$TAP_MAC" || return 3
check "worker IFIDX valid" bash -c '[[ "$1" =~ ^[1-9][0-9]*$ ]]' -- "$IFIDX" || return 3
check "worker VETH valid" bash -c '[[ "$1" =~ ^[A-Za-z0-9_.-]+$ ]]' -- "$VETH" || return 3
netns_state before
echo "worker netns interfaces: $(cat "$D/netns-before-ifnames.txt")"; cat "$D/netns-before-addr-br.txt" "$D/netns-before-route-main.txt"
check "worker netns has exactly lo, eth0, tap0 (eth0 is the only way out besides tap0)" test "$(cat "$D/netns-before-ifnames.txt")" = "eth0 lo tap0 " \
    || { echo "ABORT: the veth capture would not cover every way out of the worker netns"; return 3; }

# ------------------------------------------------------------------ 4. control container
log "4. control container (sandboxnet + dbnet)"
CTL_RUN_ATTEMPTED=1
CID=$(docker run -d --name "$CTL" --label "ct01.launch_id=$CT01_LAUNCH_ID" --restart no --network "$SANDBOXNET" --entrypoint python3 \
    -v "$H/ctl_loop.py:/ctl_loop.py:ro" -v "$OUT/ctl:/ctl" \
    "$IMAGE" /ctl_loop.py "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" /ctl/ctl.jsonl --arp-worker) || { echo "ABORT: ctl run failed"; return 3; }
CREATED_IDS+=("$CID")
check "ctl connected to dbnet" docker network connect "$DBNET" "$CID" || return 3
# 06B-4IR1: ctl's endpoint MAC on sandboxnet, so that the T14-A1 control can bind the ctl ARP entry's interface to
# sandboxnet by MAC (the interface name inside ctl is not assumed)
CTL_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").MacAddress}}" "$CID") || { fail "reading CTL_MAC failed; guest not called"; return 3; }
check "ctl MAC valid" valid_mac "$CTL_MAC" || return 3
CTL_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$CID") || { fail "ctl IP unreadable"; return 3; }
check "ctl IP valid" valid_ip "$CTL_IP" || return 3
check "sandboxnet endpoint IP/MAC identities distinct" bash -c '[ "$1" != "$2" ] && [ "$1" != "$3" ] && [ "$2" != "$3" ] && [ "$4" != "$5" ] && [ "$4" != "$6" ] && [ "$5" != "$6" ]' -- "$WORKER_IP" "$MANAGER_IP" "$CTL_IP" "$WORKER_MAC" "$MANAGER_MAC" "$CTL_MAC" || return 3
echo "ctl sandboxnet endpoint MAC=$CTL_MAC" | tee -a "$OUT/targets-env.txt"
sleep 4
for t in "mongo $MONGO_IP:27017" "worker-eth0 $WORKER_IP:8011" "arp worker-eth0 $WORKER_IP" "manager $MANAGER_IP:8011"; do
    check "control '$t' alive" bash -c "grep -F '\"target\": \"$t\"' '$OUT/ctl/ctl.jsonl' | tail -3 | grep -q '\"ok\": true'" || return 3
done


# ------------------------------------------------------------------ 5. host captures (read-only)
log "5. host captures on $VETH, $BR, ens33 + leak alert"
tcpdump --version > "$OUT/hostcap/versions.txt" 2>&1; cat "$OUT/hostcap/versions.txt"   # tcpdump + libpcap
# Runs 1-3: tcpdump 4.99.4 / libpcap 1.10.4 segfaults ("segfault at 0 ... in libc.so.6") whenever
# `-Z root` is combined with `-w` (file or stdout); run 3's diagnosis on lo showed `-w <file>` and
# `-w -` without -Z, and `-Z root -l` (text), all work. Pcap captures therefore run without -Z;
# tcpdump writes pcap to stdout and the root shell opens the file in a root-owned mktemp dir
# under /tmp; files are copied back after stop. The text-mode leak alert keeps `-Z root -l`.
CAPD=$(mktemp -d /tmp/ct01-06b3b-cap.XXXXXX); chmod 700 "$CAPD"; echo "capture dir: $CAPD"
tcpdump -U -n -i "$VETH" -w - > "$CAPD/veth.pcap" 2>"$OUT/hostcap/veth.err" & TCPDUMP_PIDS+=($!); TCPDUMP_NAMES+=(veth)
tcpdump -U -n -i "$BR" -w - > "$CAPD/bridge.pcap" 2>"$OUT/hostcap/bridge.err" & TCPDUMP_PIDS+=($!); TCPDUMP_NAMES+=(bridge)
# 06B-4B (D7): ens33 without a filter, bounded by snaplen and a packet limit (see signatures.py).
tcpdump -U -n -i ens33 -s "$SIG_ENS33_SNAPLEN" -c "$SIG_ENS33_MAX_PACKETS" -w - \
    > "$CAPD/ens33.pcap" 2>"$OUT/hostcap/ens33.err" & TCPDUMP_PIDS+=($!); TCPDUMP_NAMES+=(ens33)
: > "$OUT/hostcap/alert.txt"; chmod 644 "$OUT/hostcap/alert.txt"
printf '%s\n' "$SIG_ALERT_ANY" > "$OUT/hostcap/alert-filter-any.txt"
printf '%s\n' "$SIG_ALERT_ETH" > "$OUT/hostcap/alert-filter-eth.txt"
tcpdump -Z root -l -n -i any "$SIG_ALERT_ANY" >> "$OUT/hostcap/alert.txt" 2>"$OUT/hostcap/alert.err" & TCPDUMP_PIDS+=($!); TCPDUMP_NAMES+=(alert)
tcpdump -Z root -l -n -e -i "$VETH" "$SIG_ALERT_ETH" >> "$OUT/hostcap/alert.txt" 2>"$OUT/hostcap/alert_eth.err" & TCPDUMP_PIDS+=($!); TCPDUMP_NAMES+=(alert_eth)
sleep 3
cap_ok=1
for p in "${TCPDUMP_PIDS[@]}"; do check "host tcpdump pid $p running" kill -0 "$p" || cap_ok=0; done
for f in veth bridge ens33 alert alert_eth; do
    check "host capture $f: tcpdump reports listening" grep -qE '^(tcpdump: )?listening on ' "$OUT/hostcap/$f.err" || cap_ok=0
done
# veth/bridge carry the control loop every 0.5 s, so their pcap must already hold data.
# ens33 (unfiltered since 06B-4B) may still be empty this early; its liveness is checked after the run.
for f in veth bridge; do check "host capture $f.pcap being written" test -s "$CAPD/$f.pcap" || cap_ok=0; done
if [ $cap_ok -ne 1 ]; then
    # Read-only diagnosis on lo (3 s each, no files outside $CAPD), then abort before any guest.
    DIAG="$OUT/hostcap/tcpdump-diag.txt"
    { tcpdump --version 2>&1
      for v in "-w $CAPD/d1.pcap" "-Z root -w $CAPD/d2.pcap" "-w -" "-Z root -w -" "-Z root -l"; do
          timeout --foreground -s INT 3 tcpdump -n -i lo $v > "$CAPD/diag.out" 2>"$CAPD/diag.err"; r=$?
          echo "variant [$v] rc=$r stderr: $(tr '\n' ' ' < "$CAPD/diag.err")"
      done
      journalctl -k --since "-2min" --no-pager 2>&1 | grep -E 'tcpdump|apparmor' | tail -20
    } > "$DIAG" 2>&1
    cat "$DIAG"
    echo "ABORT: host-side capture not running; no guest is booted without it"; return 3
fi
# Watch the four captures for the whole test (1 s). The marker is visible to probe_matrix.py as
# /hostcap/capture-dead.txt; it stops the probes when the marker appears.
DEAD="$OUT/hostcap/capture-dead.txt"
W=(); for i in "${!TCPDUMP_PIDS[@]}"; do W+=("${TCPDUMP_NAMES[$i]}:${TCPDUMP_PIDS[$i]}"); done
HB="$OUT/hostcap/capture-watch.heartbeat"   # /hostcap/capture-watch.heartbeat in the container
start_drain_capture_watch "$DEAD" "$HB" 1 "$CAPTURE_STOPPING" "${W[@]}"
for i in $(seq 1 30); do [ -s "$HB" ] && break; sleep 0.1; done
watch_ok() { alive "$WATCH_PID" && heartbeat_fresh "$HB" 5; }
check "capture watcher running with a fresh heartbeat" watch_ok \
    || { echo "ABORT: capture watcher not running; no guest is booted without it"; return 3; }
echo "capture watcher pid $WATCH_PID on ${W[*]}"


    [ ${#FAILS[@]} -eq 0 ] && [ ${#UNVERIFIED[@]} -eq 0 ] || return 3
    return 0
}
pre_guest_setup; setup_rc=$?
if [ "$setup_rc" -ne 0 ]; then
    [ ${#FAILS[@]} -gt 0 ] || fail "pre-guest setup rejected (rc=$setup_rc)"
    ARCH_STOP="pre-guest setup rejected: ARM/MIPS harness not called (rc=$setup_rc)"
fi
# ------------------------------------------------------------------ 6. guests, one at a time
if [ "$setup_rc" -eq 0 ]; then
TARGETS=$(printf '{"worker_ip":"%s","mongo_ip":"%s","manager_ip":"%s","manager_mac":"%s","ctl_mac":"%s","ssh_ips":["%s","%s","%s"],"lan_dns":"%s","lan_other_ip":"%s"}' \
    "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" "$MANAGER_MAC" "$CTL_MAC" "$SANDBOX_GW" "$ENS_IP" "$DB_GW" "$LAN_DNS" "$LAN_OTHER")
echo "$TARGETS" > "$OUT/targets.json"
LEAK=0
# 06B-4IR3 (PC-1) stop policy of the first run: the next architecture's harness is called ONLY if the previous one
# passed every required check of its iteration (outcome PASS, post-checks ok). Any FAIL, UNVERIFIED or ERROR (and a
# failed no-QEMU check before an architecture) stops the loop with `break`; the cause stays in FAILS/UNVERIFIED and
# the teardown and host checks below still run (no early exit). "Harness not called" is recorded in ARCH_STOP; it is
# not the same as "guest did not boot" (that is decided inside probe_matrix.py).
for ARCH in ARM MIPS; do
    log "6. guest $ARCH"
    nf0=${#FAILS[@]}; nu0=${#UNVERIFIED[@]}
    check "$ARCH: no QEMU running before start (sequential)" no_process qemu-system \
        || { ARCH_STOP="$ARCH: QEMU already running before start: harness not called for $ARCH"; break; }
    check "$ARCH: all host captures alive before start" test ! -s "$DEAD" || break
    check "$ARCH: capture watcher alive with a fresh heartbeat before start" watch_ok || break
    current_gate "$ARCH" || { ARCH_STOP="$ARCH: current gate rejected; harness not called for $ARCH"; break; }
    ARCH_CALLED+=("$ARCH")
    timeout --foreground 1700 docker exec -e CT01_TARGETS="$TARGETS" -e CT01_SUITE=spoof -e CT01_USE_PROOF=/launch-proof/use.json -e CT01_LAUNCH_ID="$CT01_LAUNCH_ID" "$ID" sh -c "cd /app && python3 /harness/probe_matrix.py $ARCH /harness-out"
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
    outcome=$(python3 "$H/spoof_harness.py" --outcome "$D/probe/$ARCH/result.json" "$D/probe/$ARCH/spoof-eval.json" "$ARCH" 2>&1)
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
    E ps -eo pid,args > "$D/ps-after-$ARCH.txt"; prc=$?
    check "$ARCH: post-guest process list readable" test "$prc" -eq 0
    check "$ARCH: no qemu-system/tshark left in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps-after-$ARCH.txt'"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-3B after '"$ARCH"'"' > "$D/verify-after-$ARCH.txt" 2>&1
    check "$ARCH: full verify after guest shutdown" test $? -eq 0
    # 06B-4IR3 (PC-1): stop before the NEXT architecture; after the last one (MIPS) there is nothing to stop
    if [ "$ARCH" != MIPS ] && { [ ${#FAILS[@]} -ne "$nf0" ] || [ ${#UNVERIFIED[@]} -ne "$nu0" ]; }; then
        ARCH_STOP="$ARCH did not pass every required check (see FAIL/UNVERIFIED above): the next architecture is not started"
        break
    fi
done
fi # pre-guest setup succeeded
LEAK=${LEAK:-0}
[ -z "$ARCH_STOP" ] && [ ${#ARCH_CALLED[@]} -lt 2 ] && ARCH_STOP="loop left after ${ARCH_CALLED[*]:-no architecture} (stop above)"
if [ -n "$ARCH_STOP" ]; then
    echo "[STOPPED] architecture loop: $ARCH_STOP; harness called for: ${ARCH_CALLED[*]:-none}"
    # never a pass: the loop only stops after a recorded FAIL/UNVERIFIED; this guards the invariant
    [ ${#FAILS[@]} -eq 0 ] && [ ${#UNVERIFIED[@]} -eq 0 ] && fail "architecture loop stopped without a recorded cause: $ARCH_STOP"
    echo "[SKIPPED] spoof run-level check (ARM and MIPS each evaluated): not every architecture was run" | tee "$OUT/spoof-run-check.txt"
else
# 06B-4I: both architectures evaluated, each with the four reviewed ARP cases exactly once
python3 "$H/spoof_harness.py" --run-check "$D/probe" ARM MIPS > "$OUT/spoof-run-check.txt" 2>&1; rc=$?
cat "$OUT/spoof-run-check.txt"
check "spoof group evaluated for ARM and MIPS, each case exactly once per architecture" test $rc -eq 0
fi

# ------------------------------------------------------------------ 7. stop captures, analyse host side
if [ -n "$ID" ]; then
netns_state after
check "worker netns interfaces unchanged after the guests" diff -q "$D/netns-before-ifnames.txt" "$D/netns-after-ifnames.txt"
check "worker netns addresses unchanged after the guests" diff -u "$D/netns-before-addr-br.txt" "$D/netns-after-addr-br.txt"
check "worker netns main routes unchanged after the guests" diff -u "$D/netns-before-route-main.txt" "$D/netns-after-route-main.txt"
diff -u "$D/netns-before.txt" "$D/netns-after.txt" > "$D/netns-diff.txt" && echo "worker netns full record: unchanged" \
    || echo "worker netns full record: differences in container/netns-diff.txt (reported, e.g. neighbor states)"

fi # worker was created

log "7. teardown of controls and captures (drain ${DRAIN_S} s, capture deadline ${CAP_DEADLINE_S} s)"
TL="$OUT/hostcap/teardown-timeline.txt"
timeline "$TL" "guests finished (last probe_matrix returned)"
if [ -n "$CID" ]; then
docker stop -t 5 "$CID" > /dev/null 2>&1; rc=$?
timeline "$TL" "control container stopped (docker stop rc=$rc)"
check "control container stopped after the guests" test $rc -eq 0
fi # ctl was created
if [ ${#TCPDUMP_PIDS[@]} -gt 0 ]; then
sleep "$DRAIN_S"
timeline "$TL" "existing drain period of ${DRAIN_S} s ended"
check "capture watcher live before bounded drain" watch_ok
check "no host capture exited before bounded drain" test ! -s "$DEAD"
DRAIN_ARGS=()
for i in "${!TCPDUMP_PIDS[@]}"; do
    f=${TCPDUMP_NAMES[$i]}
    case "$f" in
        veth) iface=$VETH ;; bridge) iface=$BR ;; ens33) iface=ens33 ;; *) continue ;;
    esac
    DRAIN_ARGS+=(--capture "$f" "${TCPDUMP_PIDS[$i]}" "$iface" "$OUT/hostcap/$f.err" "$CAPD/$f.pcap")
done
# Shared 10s observation budget, distinct from existing 10s stop/await deadline.
python3 -I -B "$H/capture_drain.py" observe --budget-s "$CAP_DEADLINE_S" "${DRAIN_ARGS[@]}" --output "$OUT/hostcap/drain-observation.json"
drain_rc=$?
if [ "$drain_rc" -ne 0 ]; then
    OPEN_ITEMS+=("capture drain observation incomplete (rc=$drain_rc); see drain-observation.json")
fi
check "capture watcher live through drain/flush" watch_ok
check "no capture exited before intentional stop" test ! -s "$DEAD"
# Stop helper marks intentional shutdown, checks actual signal rc, awaits ALL captures.
stop_tcpdumps; stop_rc=$?
check "all host captures signalled and awaited with exit0 within deadline" test "$stop_rc" -eq 0
check "capture watcher stayed live until all captures awaited" watch_ok
stop_capture_watch
timeline "$TL" "watcher stopped AFTER capture await"
# Capture files are closed now. Original stderr remains byte-for-byte; final segment is separate.
python3 -I -B "$H/capture_drain.py" finalize --observation "$OUT/hostcap/drain-observation.json" --exit-file "$OUT/hostcap/tcpdump-exit.txt" --final-stats-dir "$OUT/hostcap" --output "$OUT/hostcap/drain-result.json"
drain_final_rc=$?
if [ "$drain_final_rc" -ne 0 ]; then
    OPEN_ITEMS+=("capture coverage OPEN/UNKNOWN (rc=$drain_final_rc); see drain-result.json")
fi
cat "$TL" "$OUT/hostcap/tcpdump-exit.txt"
printf 'capture\tcaptured\treceived_by_filter\tdropped_by_kernel\n' > "$OUT/hostcap/capture-stats.tsv"
for f in veth bridge ens33 alert alert_eth; do
    check "tcpdump $f: exit0 on stop" grep -qx "$f 0" "$OUT/hostcap/tcpdump-exit.txt"
    case "$f" in
        # R5: the helper's separate final segment when it exists; if the helper produced nothing (it failed), the original stderr is judged exactly as before
        veth|bridge|ens33) stats_file="$OUT/hostcap/$f.final-stats.err"; [ -f "$stats_file" ] || stats_file="$OUT/hostcap/$f.err" ;;
        *) stats_file="$OUT/hostcap/$f.err" ;;
    esac
    st=$(capture_stats "$stats_file")
    check "tcpdump $f: complete final statistics" test -n "$st" || continue
    read -r cap rcv drp <<< "$st"
    printf '%s\t%s\t%s\t%s\n' "$f" "$cap" "$rcv" "$drp" >> "$OUT/hostcap/capture-stats.tsv"
    check "tcpdump $f: no kernel drops" test "$drp" -eq 0
    if [ "$rcv" -ne "$cap" ]; then
        OPEN_ITEMS+=("tcpdump $f: final R-C=$((rcv-cap)), unresolved")
    fi
done
# tcpdump prints a bare newline on SIGINT: only non-empty lines are packets
check "leak alerts: no signature packet line (any: network layer; veth: + MAC)" bash -c "! grep -q . '$OUT/hostcap/alert.txt'"
for a in alert alert_eth; do
    grep -E 'packets (captured|received by filter)' "$OUT/hostcap/$a.err" | sed "s/^/$a: /" | tee -a "$OUT/hostcap/summary.txt"
    check "leak alert tcpdump $a: 0 packets captured" grep -q '^0 packets captured' "$OUT/hostcap/$a.err"
done
check "ens33 capture did not reach its packet limit ($SIG_ENS33_MAX_PACKETS)" \
    bash -c "! grep -qE '^$SIG_ENS33_MAX_PACKETS packets captured' '$OUT/hostcap/ens33.err'"
count() {  # file filter -> echoes count, returns tcpdump exit code
    local out rc
    out=$(tcpdump -n -r "$1" "$2" 2>>"$OUT/hostcap/read.err"); rc=$?
    [ $rc -eq 0 ] || { echo "ERR"; return $rc; }
    [ -z "$out" ] && echo 0 || echo "$out" | wc -l
}
SIG="ether host $GUEST_MAC or net 10.200.0.0/30"
for f in veth bridge ens33; do cp "$CAPD/$f.pcap" "$OUT/hostcap/$f.pcap"; done
for f in veth bridge ens33; do
    n=$(count "$CAPD/$f.pcap" "$SIG"); rc=$?
    echo "$f: probe-signature packets=$n (tcpdump rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
    check "$f.pcap readable (tcpdump exit 0)" test $rc -eq 0
    check "$f.pcap: 0 packets with guest MAC / 10.200.0.0/30" test "$n" = 0
    bash "$H/sigscan.sh" "$CAPD/$f.pcap" > "$OUT/hostcap/sigscan-$f.txt" 2>&1; rc=$?
    echo "$f sigscan (rc=$rc): $(tr '\n' ' ' < "$OUT/hostcap/sigscan-$f.txt")" | tee -a "$OUT/hostcap/summary.txt"
    check "$f.pcap: sigscan read OK (exit 0)" test $rc -eq 0
    for k in guest_l2l3 probe_sport probe_qname probe_url; do
        check "$f.pcap: $k = 0" grep -qx "$k=0" "$OUT/hostcap/sigscan-$f.txt"
    done
    # 06B-4B: L2/ARP/IPv6/spoof signatures (sigscan_l2.py; a read error is exit 2, never 0)
    python3 "$H/sigscan_l2.py" "$CAPD/$f.pcap" --manager-mac "$MANAGER_MAC" > "$OUT/hostcap/sigscan-l2-$f.txt" 2>&1; rc=$?
    echo "$f sigscan_l2 (rc=$rc): $(tr '\n' ' ' < "$OUT/hostcap/sigscan-l2-$f.txt")" | tee -a "$OUT/hostcap/summary.txt"
    check "$f.pcap: sigscan_l2 read OK (exit 0)" test $rc -eq 0
    # 06B-4BR: frames whose signature headers were cut (snaplen) or not decodable are a failed check, never 0
    for k in guest_mac spoof_mac guest_net_ip arp_guest_sha arp_spoof_sha arp_guest_net arp_spoof_spa_manager \
             ipv6_guest spoof_src_ip probe_port icmp_size probe_qname unscannable_truncated unscannable_undecoded; do
        check "$f.pcap: $k = 0" grep -qx "$k=0" "$OUT/hostcap/sigscan-l2-$f.txt"
    done
done
# Positive on real data: the worker's control DNS queries (ct01-06b3b-ctl-<arch>) cross ens33, so the
# payload scan must find them; 0 here means the scan is blind and every 0 above proves nothing.
check "ens33.pcap: payload scan finds the control DNS queries (control_qname > 0)" \
    bash -c "grep -qE '^control_qname=[1-9]' '$OUT/hostcap/sigscan-ens33.txt'"
n=$(count "$CAPD/veth.pcap" "src host $WORKER_IP and (dst host 1.1.1.1 or dst host $LAN_DNS or dst port 22 or dst host $MANAGER_IP)"); rc=$?
echo "veth: control packets from worker=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "veth capture live: worker control packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"
n=$(count "$CAPD/ens33.pcap" "host 1.1.1.1 or host $LAN_DNS"); rc=$?
echo "ens33: NATed control packets=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "ens33 capture live: NATed control packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"
n=$(count "$CAPD/bridge.pcap" "src host $WORKER_IP"); rc=$?
echo "bridge: packets from worker=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "bridge capture live: worker packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"

fi # captures were started: otherwise their analysis is skipped, never a PASS

# ------------------------------------------------------------------ 8. teardown
rm_capd
[ -z "$CAPD" ] || check "temporary capture dir removed" test ! -e "$CAPD"

log "8. teardown"
if [ -n "$ID" ]; then
E sh -c 'test ! -e /run/sandbox/current_task && test -z "$(ls -A /app/data)" && ! ls -d /tmp/g-* >/dev/null 2>&1'
check "no marker, fixture or guest disk left in worker container" test $? -eq 0
E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
check "normalized runtime ruleset identical to expected" bash -c "diff <(python3 -m json.tool '$D/normalized-runtime.json') <(python3 -m json.tool '$REPO/sandbox-worker/isolation/expected-ruleset.json') >/dev/null"
docker logs --timestamps "$ID" > "$D/docker-logs-final.txt" 2>&1
fi # worker created
for id in "${CREATED_IDS[@]}"; do docker stop -t 10 "$id" >/dev/null; docker rm "$id" >/dev/null; done
left=0; for id in "${CREATED_IDS[@]}"; do docker inspect "$id" >/dev/null 2>&1 && left=1; done
check "all containers created by this run removed" test $left -eq 0
manager_restore > "$OUT/manager-restore.txt" 2>&1; rc=$?
cat "$OUT/manager-restore.txt"; cat "$OUT/manager-restore.txt" >> "$OUT/manager-state.txt"
if [ -n "$MANAGER_STATE_BEFORE" ]; then
    check "manager back to its initial state ($MANAGER_STATE_BEFORE; same container; not restarted if it was running)" test $rc -eq 0
else
    echo "[SKIPPED] manager baseline not recorded; no manager prepare/start occurred"
fi
check "no qemu-system on host" no_process qemu-system
check "no capture process left on host" no_process 'tcpdump|tshark|dumpcap'
sleep 2
HOST_AFTER_OK=0
check "mandatory host-state after readable" host_state after && HOST_AFTER_OK=1
if [ "$HOST_BEFORE_OK" = 1 ] && [ "$HOST_AFTER_OK" = 1 ]; then
echo "-- host differences (all reported; evaluated in the summary):"
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"; fi
done
for f in sysctl.txt nft-ruleset-stateless.txt ip-route.txt listen-tcp.txt qemu.txt capture-procs.txt host-tap0.txt; do
    check "host $f unchanged" test ! -e "$OUT/host-diff-$f.diff"
done
else
    echo "[SKIPPED] host before/after equality: baseline unreadable/not acquired; original setup failure retained"
fi
echo "created ids: ${CREATED_IDS[*]}" | tee "$OUT/created-ids.txt"
# Root launcher retains root-owned evidence under the trusted 0700 stage, including early exits.

log "result"
[ -n "$ARCH_STOP" ] && echo "ARCHITECTURE LOOP STOPPED (06B-4IR3 stop policy): $ARCH_STOP; harness called for: ${ARCH_CALLED[*]:-none}"
[ $LEAK -eq 1 ] && echo "!!! LEAK DETECTED — tests were stopped; report to reviewer immediately"
[ ${#OPEN_ITEMS[@]} -gt 0 ] && { echo "OPEN ITEMS (reported, not explained):"; printf ' - %s\n' "${OPEN_ITEMS[@]}"; }
[ ${#UNVERIFIED[@]} -gt 0 ] && { echo "UNVERIFIED (could not be decided):"; printf ' - %s\n' "${UNVERIFIED[@]}"; }
[ ${#SESSION_RESULTS[@]} -gt 0 ] && { echo "SESSION-WIDE reconciliation (reported separately; does not change the exit code):"
    printf ' - %s\n' "${SESSION_RESULTS[@]}"; }
if [ ${#FAILS[@]} -gt 0 ]; then
    echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
fi
[ ${#UNVERIFIED[@]} -gt 0 ] && { echo "NOT PASSED: no check failed, but some results are UNVERIFIED"; exit 4; }
[ ${#OPEN_ITEMS[@]} -gt 0 ] && { echo "CHECKS PASSED, INCONCLUSIVE: open items above are not explained"; exit 5; }
echo "ALL CHECKS PASSED"; exit 0
