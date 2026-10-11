#!/bin/bash
# Nhiệm vụ 06B-3B — IPv4 block matrix from real guests (ARM, then MIPS) with live controls.
#
#   sudo bash /home/dathq/projects/ct01-06b3b/run-06b3b.sh
#
#  * Worker test container ct01-06b3b-guest: reviewed image (full id pinned), real run.sh (V0),
#    REAL server.py, sentinel poller. sandboxnet, --privileged like compose, --restart no,
#    no published ports, no host network, no lab-data / docker.sock mounts.
#  * The existing sandbox-manager container is started ONLY for controls:
#    `docker compose up -d --no-deps --no-build sandbox-manager`; it is stopped again at the end.
#    The compose worker service is never started.
#  * Control container ct01-06b3b-ctl (sandboxnet + dbnet) continuously checks MongoDB:27017,
#    worker eth0:8011 and manager:8011.
#  * Host side is READ-ONLY: tcpdump on the worker veth, the sandboxnet bridge and ens33, plus a
#    leak alert (tcpdump -i any 'net 10.200.0.0/30'). If any probe packet appears on the host,
#    everything stops immediately.
#  * Only fixed IP/port pairs are probed; guest uses its own curl / busybox nslookup.
#  * Cleanup removes only containers created by this run and host tcpdumps started by it.
#    Every criterion is a hard check; exit != 0 on failure. No env printing.
set -uo pipefail

EXPECTED_IMAGE_ID=sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153
H=/home/dathq/projects/ct01-06b3b
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
NAME=ct01-06b3b-guest
CTL=ct01-06b3b-ctl
MANAGER=cic-ynu-iotmal-sandbox-sandbox-manager-1
GUEST_MAC=52:54:00:c7:00:02
LAN_DNS=192.168.177.2

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ -e "$OUT" ] && { echo "ABORT: $OUT exists (keep previous evidence; move it first)"; exit 2; }
mkdir -p "$OUT/hostcap" "$OUT/ctl" "$OUT/harness-copy"
exec > >(tee "$OUT/run.log") 2>&1
cp "$0" "$H/probe_matrix.py" "$H/ctl_loop.py" "$H/sentinel/poller.py" "$OUT/harness-copy/"
sha256sum "$OUT"/harness-copy/* | tee "$OUT/harness-sha256.txt"

CREATED_IDS=(); FAILS=(); TCPDUMP_PIDS=(); MANAGER_STARTED=0
log()  { echo; echo "===== $* ($(date -u +%H:%M:%S))"; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS+=("$*"); }
check() { local msg=$1; shift; if "$@"; then pass "$msg"; else fail "$msg"; return 1; fi; }
# Remove the temporary capture dir only if it is exactly the mktemp path this run created.
rm_capd() { [[ "${CAPD:-}" == /tmp/ct01-06b3b-cap.?????? ]] && [ -d "$CAPD" ] && rm -r -- "$CAPD"; }
COMPOSE=(docker compose --project-directory "$REPO" -f "$REPO/docker-compose.yml")

stop_tcpdumps() {
    local p
    for p in "${TCPDUMP_PIDS[@]:-}"; do [ -n "$p" ] && kill -INT "$p" 2>/dev/null; done
    for p in "${TCPDUMP_PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
    TCPDUMP_PIDS=()
}
CAPD=""
cleanup() {
    stop_tcpdumps
    rm_capd || true
    local id
    for id in "${CREATED_IDS[@]:-}"; do
        [ -n "$id" ] || continue
        if docker inspect "$id" >/dev/null 2>&1; then
            docker logs --timestamps "$id" > "$OUT/final-logs-${id:0:12}.txt" 2>&1 || true
            docker rm -f "$id" >/dev/null 2>&1 || true
        fi
    done
    if [ "$MANAGER_STARTED" = 1 ] && [ "$(docker inspect -f '{{.State.Running}}' "$MANAGER" 2>/dev/null)" = true ]; then
        "${COMPOSE[@]}" stop sandbox-manager >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

host_state() {
    local d="$OUT/host-$1"; mkdir -p "$d"
    ip -br link > "$d/ip-link.txt"; ip -br addr > "$d/ip-addr.txt"
    ip route > "$d/ip-route.txt"; ip -6 route > "$d/ip6-route.txt"
    ip link show tap0 > "$d/host-tap0.txt" 2>&1 || true
    nft -s list ruleset > "$d/nft-ruleset-stateless.txt" 2>&1
    lsmod | awk 'NR>1{print $1}' | grep -E '^(nf_|nft_|xt_|br_netfilter|bridge|tun|veth|ip_tables|ip6_tables|x_tables|iptable_|ip6table_|nfnetlink)' | sort > "$d/lsmod-net.txt"
    {
        for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 net.core.devconf_inherit_init_net; do
            echo "$k=$(sysctl -n "$k" 2>&1)"; done
        for dev in all default ens33; do for a in rp_filter arp_ignore arp_announce arp_accept forwarding; do
            echo "net.ipv4.conf.$dev.$a=$(sysctl -n "net.ipv4.conf.$dev.$a" 2>&1)"; done; done
    } > "$d/sysctl.txt"
    ss -ltnH | awk '{print $4}' | sort > "$d/listen-tcp.txt"
    docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | sort > "$d/docker-ps.txt"
    pgrep -a qemu-system > "$d/qemu.txt" 2>&1 || echo "no qemu-system" > "$d/qemu.txt"
    pgrep -a 'tshark|dumpcap|tcpdump' > "$d/capture-procs.txt" 2>&1 || echo "no capture processes" > "$d/capture-procs.txt"
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
[ "$IMAGE_ID" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: image id is not the reviewed image"; exit 3; }
pass "image id equals reviewed full id"
docker ps -a --format '{{.Names}} {{.Status}}'
docker ps --format '{{.Names}}' | grep -q 'sandbox-worker' && { echo "ABORT: a worker container is running"; exit 3; }
pgrep -a qemu-system && { echo "ABORT: qemu running"; exit 3; }
pgrep -a 'tcpdump|tshark|dumpcap' && { echo "ABORT: capture process already running on host"; exit 3; }
for c in "$NAME" "$CTL"; do docker inspect "$c" >/dev/null 2>&1 && { echo "ABORT: pre-existing container $c (left untouched)"; exit 3; }; done
MANAGER_STATE_BEFORE=$(docker inspect -f '{{.State.Status}}' "$MANAGER")
echo "manager state before: $MANAGER_STATE_BEFORE" | tee "$OUT/manager-state.txt"
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
DBNET=$(docker network ls --filter label=com.docker.compose.network=dbnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] && [ -n "$DBNET" ] || { echo "ABORT: networks not found"; exit 3; }
BR="br-$(docker network inspect -f '{{.Id}}' "$SANDBOXNET" | cut -c1-12)"
MONGO_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$DBNET\").IPAddress}}" mongo-db)
SANDBOX_GW=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$SANDBOXNET")
DB_GW=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$DBNET")
ENS_IP=$(ip -4 -o addr show dev ens33 | awk '{print $4}' | cut -d/ -f1)
echo "sandboxnet=$SANDBOXNET bridge=$BR dbnet=$DBNET mongo=$MONGO_IP host-ips=$SANDBOX_GW,$ENS_IP,$DB_GW lan-dns=$LAN_DNS" | tee "$OUT/targets-env.txt"
host_state before

# ------------------------------------------------------------------ 2. manager (controls only)
log "2. start existing manager for controls (--no-deps --no-build)"
"${COMPOSE[@]}" up -d --no-deps --no-build sandbox-manager 2>&1 | tail -3
MANAGER_STARTED=1
ok=0; for i in $(seq 1 30); do
    python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status==200 else 1)' 2>/dev/null && { ok=1; break; }; sleep 1; done
check "manager healthy (127.0.0.1:8011/healthcheck)" test $ok -eq 1
docker inspect -f 'manager: {{.State.Status}} ip={{(index .NetworkSettings.Networks "'"$SANDBOXNET"'").IPAddress}}' "$MANAGER" | tee -a "$OUT/manager-state.txt"
MANAGER_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$MANAGER")

# ------------------------------------------------------------------ 3. worker test container
log "3. worker test container"
D="$OUT/container"; mkdir -p "$D/sentinel" "$D/probe"; chmod 777 "$D/sentinel" "$D/probe" "$OUT/ctl" "$OUT/hostcap"
ID=$(docker run -d --name "$NAME" --restart no --privileged --network "$SANDBOXNET" \
    -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$NAME" \
    -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
    -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
    -v "$H/sentinel/poller.py:/app/poller.py:ro" -v "$H/probe_matrix.py:/harness/probe_matrix.py:ro" \
    -v "$D/sentinel:/sentinel-out" -v "$D/probe:/harness-out" \
    -v "$OUT/hostcap:/hostcap:ro" -v "$OUT/ctl:/ctl:ro" \
    "$IMAGE") || { echo "ABORT: docker run failed"; exit 3; }
CREATED_IDS+=("$ID"); echo "worker test container: $ID"
E() { docker exec "$ID" "$@"; }
ok=0; for i in $(seq 1 30); do
    E python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status==200 else 1)' 2>/dev/null && { ok=1; break; }; sleep 1; done
check "worker server ready" test $ok -eq 1
docker logs --timestamps "$ID" > "$D/docker-logs-startup.txt" 2>&1
check "V0 passed" grep -q 'ISOLATION OK (V0 startup)' "$D/docker-logs-startup.txt"
WORKER_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$ID")
IFIDX=$(E cat /sys/class/net/eth0/iflink | tr -d '\r')
VETH=$(ip -o link | awk -F': ' -v i="$IFIDX" '$1==i{print $2}' | cut -d@ -f1)
echo "worker eth0=$WORKER_IP host veth=$VETH (ifindex $IFIDX)" | tee -a "$OUT/targets-env.txt"
[ -n "$VETH" ] || { echo "ABORT: worker veth not found"; exit 3; }
FILES="run.sh server.py service/analysis.py isolation/apifilter.py isolation/verify.py isolation/guest.nft isolation/expected-ruleset.json ARM/image.zip MIPS/image.zip"
E sh -c "cd /app && sha256sum $FILES" > "$D/sha256-in-container.txt"
( cd "$REPO/sandbox-worker" && sha256sum $FILES ) > "$D/sha256-repo.txt"
check "code and guest images in container equal working tree" diff -q "$D/sha256-in-container.txt" "$D/sha256-repo.txt"

# ------------------------------------------------------------------ 4. control container
log "4. control container (sandboxnet + dbnet)"
CID=$(docker run -d --name "$CTL" --restart no --network "$SANDBOXNET" --entrypoint python3 \
    -v "$H/ctl_loop.py:/ctl_loop.py:ro" -v "$OUT/ctl:/ctl" \
    "$IMAGE" /ctl_loop.py "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" /ctl/ctl.jsonl) || { echo "ABORT: ctl run failed"; exit 3; }
CREATED_IDS+=("$CID")
docker network connect "$DBNET" "$CID"
sleep 4
for t in "mongo $MONGO_IP:27017" "worker-eth0 $WORKER_IP:8011" "manager $MANAGER_IP:8011"; do
    check "control '$t' alive" bash -c "grep -F '\"target\": \"$t\"' '$OUT/ctl/ctl.jsonl' | tail -3 | grep -q '\"ok\": true'"
done

# ------------------------------------------------------------------ 5. host captures (read-only)
log "5. host captures on $VETH, $BR, ens33 + leak alert"
# Runs 1 and 2: every `tcpdump -w <file>` segfaulted at start (kernel: "segfault at 0 ... in
# libc.so.6"), both under /home (run 1, with an AppArmor dac_read_search denial) and under /tmp
# (run 2, no denial), while the alert tcpdump writing text to a shell-redirected stdout worked.
# So tcpdump never opens a file here: it writes pcap to stdout (`-w -`) and the root shell opens
# the file in a root-owned mktemp dir under /tmp; files are copied back after stop.
CAPD=$(mktemp -d /tmp/ct01-06b3b-cap.XXXXXX); chmod 700 "$CAPD"; echo "capture dir: $CAPD"
tcpdump -Z root -U -n -i "$VETH" -w - > "$CAPD/veth.pcap" 2>"$OUT/hostcap/veth.err" & TCPDUMP_PIDS+=($!)
tcpdump -Z root -U -n -i "$BR" -w - > "$CAPD/bridge.pcap" 2>"$OUT/hostcap/bridge.err" & TCPDUMP_PIDS+=($!)
tcpdump -Z root -U -n -i ens33 -w - \
    "ether host $GUEST_MAC or net 10.200.0.0/30 or host 1.1.1.1 or host $LAN_DNS" > "$CAPD/ens33.pcap" 2>"$OUT/hostcap/ens33.err" & TCPDUMP_PIDS+=($!)
: > "$OUT/hostcap/alert.txt"; chmod 644 "$OUT/hostcap/alert.txt"
tcpdump -Z root -l -n -i any "net 10.200.0.0/30" >> "$OUT/hostcap/alert.txt" 2>"$OUT/hostcap/alert.err" & TCPDUMP_PIDS+=($!)
sleep 3
cap_ok=1
for p in "${TCPDUMP_PIDS[@]}"; do check "host tcpdump pid $p running" kill -0 "$p" || cap_ok=0; done
for f in veth bridge ens33; do
    check "host capture $f: tcpdump reports listening" grep -q '^listening on' "$OUT/hostcap/$f.err" || cap_ok=0
done
# veth/bridge carry the control loop every 0.5 s, so their pcap must already hold data.
# ens33 is filtered and may legitimately be empty here; its liveness is checked after the run.
for f in veth bridge; do check "host capture $f.pcap being written" test -s "$CAPD/$f.pcap" || cap_ok=0; done
if [ $cap_ok -ne 1 ]; then
    # Read-only diagnosis on lo (3 s each, no files outside $CAPD), then abort before any guest.
    D="$OUT/hostcap/tcpdump-diag.txt"
    { tcpdump --version 2>&1
      for v in "-w $CAPD/d1.pcap" "-Z root -w $CAPD/d2.pcap" "-w -" "-Z root -w -" "-Z root -l"; do
          timeout -s INT 3 tcpdump -n -i lo $v > "$CAPD/diag.out" 2>"$CAPD/diag.err"; r=$?
          echo "variant [$v] rc=$r stderr: $(tr '\n' ' ' < "$CAPD/diag.err")"
      done
      journalctl -k --since "-2min" --no-pager 2>&1 | grep -E 'tcpdump|apparmor' | tail -20
    } > "$D" 2>&1
    cat "$D"
    echo "ABORT: host-side capture not running; no guest is booted without it"; exit 3
fi

# ------------------------------------------------------------------ 6. guests, one at a time
TARGETS=$(printf '{"worker_ip":"%s","mongo_ip":"%s","manager_ip":"%s","ssh_ips":["%s","%s","%s"],"lan_dns":"%s"}' \
    "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" "$SANDBOX_GW" "$ENS_IP" "$DB_GW" "$LAN_DNS")
echo "$TARGETS" > "$OUT/targets.json"
LEAK=0
for ARCH in ARM MIPS; do
    log "6. guest $ARCH"
    check "$ARCH: no QEMU running before start (sequential)" bash -c "! pgrep qemu-system >/dev/null"
    timeout 1700 docker exec -e CT01_TARGETS="$TARGETS" "$ID" sh -c "cd /app && python3 /harness/probe_matrix.py $ARCH /harness-out"
    rc=$?
    echo "probe_matrix $ARCH exit=$rc"
    if [ $rc -eq 99 ] || grep -q . "$OUT/hostcap/alert.txt"; then
        LEAK=1; fail "$ARCH: PROBE PACKET SEEN ON HOST — all tests stopped"; break
    fi
    check "$ARCH: probe_matrix exit 0 (all checks and probes passed)" test $rc -eq 0
    E ps -eo pid,args > "$D/ps-after-$ARCH.txt"
    check "$ARCH: no qemu-system/tshark left in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps-after-$ARCH.txt'"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-3B after '"$ARCH"'"' > "$D/verify-after-$ARCH.txt" 2>&1
    check "$ARCH: full verify after guest shutdown" test $? -eq 0
done

# ------------------------------------------------------------------ 7. stop captures, analyse host side
log "7. host capture analysis"
stop_tcpdumps
# tcpdump prints a bare newline on SIGINT: only non-empty lines are packets
check "leak alert: no 10.200.0.0/30 packet line on any host interface" bash -c "! grep -q . '$OUT/hostcap/alert.txt'"
grep -E 'packets (captured|received by filter)' "$OUT/hostcap/alert.err" | tee -a "$OUT/hostcap/summary.txt"
check "leak alert tcpdump: 0 packets captured" grep -q '^0 packets captured' "$OUT/hostcap/alert.err"
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
done
n=$(count "$CAPD/veth.pcap" "src host $WORKER_IP and (dst host 1.1.1.1 or dst host $LAN_DNS or dst port 22 or dst host $MANAGER_IP)"); rc=$?
echo "veth: control packets from worker=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "veth capture live: worker control packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"
n=$(count "$CAPD/ens33.pcap" "host 1.1.1.1 or host $LAN_DNS"); rc=$?
echo "ens33: NATed control packets=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "ens33 capture live: NATed control packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"
n=$(count "$CAPD/bridge.pcap" "src host $WORKER_IP"); rc=$?
echo "bridge: packets from worker=$n (rc=$rc)" | tee -a "$OUT/hostcap/summary.txt"
check "bridge capture live: worker packets seen" bash -c "[ $rc -eq 0 ] && [ '$n' != ERR ] && [ '$n' -gt 0 ]"

# ------------------------------------------------------------------ 8. teardown
rm_capd
check "temporary capture dir removed" test ! -e "$CAPD"

log "8. teardown"
E sh -c 'test ! -e /run/sandbox/current_task && test -z "$(ls -A /app/data)" && ! ls -d /tmp/g-* >/dev/null 2>&1'
check "no marker, fixture or guest disk left in worker container" test $? -eq 0
E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
check "normalized runtime ruleset identical to expected" bash -c "diff <(python3 -m json.tool '$D/normalized-runtime.json') <(python3 -m json.tool '$REPO/sandbox-worker/isolation/expected-ruleset.json') >/dev/null"
docker logs --timestamps "$ID" > "$D/docker-logs-final.txt" 2>&1
for id in "${CREATED_IDS[@]}"; do docker stop -t 10 "$id" >/dev/null; docker rm "$id" >/dev/null; done
left=0; for id in "${CREATED_IDS[@]}"; do docker inspect "$id" >/dev/null 2>&1 && left=1; done
check "all containers created by this run removed" test $left -eq 0
"${COMPOSE[@]}" stop sandbox-manager 2>&1 | tail -2
MANAGER_STATE_AFTER=$(docker inspect -f '{{.State.Status}}' "$MANAGER")
echo "manager state after: $MANAGER_STATE_AFTER (before: $MANAGER_STATE_BEFORE)" | tee -a "$OUT/manager-state.txt"
check "manager back to its previous state ($MANAGER_STATE_BEFORE)" test "$MANAGER_STATE_AFTER" = "$MANAGER_STATE_BEFORE"
check "no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"
check "no capture process left on host" bash -c "! pgrep 'tcpdump|tshark|dumpcap' >/dev/null"
sleep 2; host_state after
echo "-- host differences (all reported; evaluated in the summary):"
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"; fi
done
for f in sysctl.txt nft-ruleset-stateless.txt ip-route.txt listen-tcp.txt qemu.txt capture-procs.txt host-tap0.txt; do
    check "host $f unchanged" test ! -e "$OUT/host-diff-$f.diff"
done
echo "created ids: ${CREATED_IDS[*]}" | tee "$OUT/created-ids.txt"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true

log "result"
[ $LEAK -eq 1 ] && echo "!!! LEAK DETECTED — tests were stopped; report to reviewer immediately"
if [ ${#FAILS[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
