#!/bin/bash
# Nhiệm vụ 06B-3A — boot real guests (ARM, then MIPS) and test ONLY the worker service link.
#
#   sudo bash /home/dathq/projects/ct01-06b3a/run-06b3a.sh
#
#  * One throwaway container ct01-06b3a-guest from the reviewed image (full id pinned), real
#    run.sh (V0) and REAL server.py; only /app/poller.py is a read-only sentinel.
#    sandboxnet, --privileged like compose, --restart no, no published ports, no host network,
#    no lab-data / docker.sock mounts.
#  * guest_probe.py (docker exec) boots each architecture in turn with the real QEMU code path,
#    a fresh copy of the stock OS image, and only curl inside the guest against
#    10.200.0.1:8011 (fixtures are harmless text). No dynamic_analysis, no ELF/sample,
#    no Internet/LAN/SSH/MongoDB probes, no netprobe.
#  * ARM and MIPS never run at the same time (checked).
#  * Cleanup removes only container IDs created by this run; every criterion is a hard check;
#    exit != 0 on any failure. No host network/firewall/sysctl writes. No env printing.
set -uo pipefail

EXPECTED_IMAGE_ID=sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153
H=/home/dathq/projects/ct01-06b3a
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
NAME=ct01-06b3a-guest

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

CREATED_IDS=(); FAILS=()
log()  { echo; echo "===== $* ($(date -u +%H:%M:%S))"; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS+=("$*"); }
check() { local msg=$1; shift; if "$@"; then pass "$msg"; else fail "$msg"; fi; }
cleanup() {
    local id
    for id in "${CREATED_IDS[@]:-}"; do
        [ -n "$id" ] || continue
        if docker inspect "$id" >/dev/null 2>&1; then
            docker logs --timestamps "$id" > "$OUT/final-logs-${id:0:12}.txt" 2>&1 || true
            docker rm -f "$id" >/dev/null 2>&1 || true
        fi
    done
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
    pgrep -a tshark > "$d/tshark.txt" 2>&1 || echo "no tshark" > "$d/tshark.txt"
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
[ "$IMAGE_ID" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: image id is not the reviewed 06B-2BR image"; exit 3; }
pass "image id equals reviewed full id"
docker ps -a --format '{{.Names}} {{.Status}}'
docker ps --format '{{.Names}}' | grep -q 'sandbox-worker' && { echo "ABORT: a worker container is running"; exit 3; }
pgrep -a qemu-system && { echo "ABORT: qemu running"; exit 3; }
docker inspect "$NAME" >/dev/null 2>&1 && { echo "ABORT: pre-existing container $NAME (left untouched)"; exit 3; }
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] || { echo "ABORT: sandboxnet not found"; exit 3; }
docker network inspect -f 'name={{.Name}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} containers=[{{range .Containers}}{{.Name}}:{{.IPv4Address}} {{end}}]' "$SANDBOXNET" | tee "$OUT/sandboxnet.txt"
sha256sum "$0" "$H/guest_probe.py" "$H/sentinel/poller.py" | tee "$OUT/harness-sha256.txt"
host_state before

# ------------------------------------------------------------------ 2. startup
log "2. startup: real run.sh + real server.py, poller sentinel"
D="$OUT/container"; mkdir -p "$D/sentinel" "$D/probe"; chmod 777 "$D/sentinel" "$D/probe"
ID=$(docker run -d --name "$NAME" --restart no --privileged --network "$SANDBOXNET" \
    -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$NAME" \
    -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
    -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
    -v "$H/sentinel/poller.py:/app/poller.py:ro" \
    -v "$H/guest_probe.py:/harness/guest_probe.py:ro" \
    -v "$D/sentinel:/sentinel-out" -v "$D/probe:/harness-out" \
    "$IMAGE") || { echo "ABORT: docker run failed"; exit 3; }
CREATED_IDS+=("$ID"); echo "container id: $ID"
E() { docker exec "$ID" "$@"; }
ready=0
for i in $(seq 1 30); do
    E python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status == 200 else 1)' 2>/dev/null && { ready=1; break; }
    sleep 1
done
check "server ready (healthcheck 200 from 127.0.0.1)" test $ready -eq 1
docker logs --timestamps "$ID" > "$D/docker-logs-startup.txt" 2>&1
grep -E 'ISOLATION|SENTINEL|Started server process' "$D/docker-logs-startup.txt"
check "V0 passed" grep -q 'ISOLATION OK (V0 startup)' "$D/docker-logs-startup.txt"
FILES="run.sh server.py service/analysis.py router/sandbox_router.py router/healthcheck.py isolation/apifilter.py isolation/current_task.py isolation/constants.py isolation/verify.py isolation/guest.nft isolation/load.nft isolation/expected-ruleset.json ARM/image.zip MIPS/image.zip"
E sh -c "cd /app && sha256sum $FILES" > "$D/sha256-in-container.txt"
( cd "$REPO/sandbox-worker" && sha256sum $FILES ) > "$D/sha256-repo.txt"
check "code and guest images in container equal working tree" diff -q "$D/sha256-in-container.txt" "$D/sha256-repo.txt"
E ps -eo pid,ppid,args > "$D/ps-startup.txt"
check "real server.py running, poller is sentinel, no qemu" bash -c "grep -q 'python3 server.py' '$D/ps-startup.txt' && docker exec '$ID' grep -q SENTINEL /app/poller.py && ! grep -q qemu-system '$D/ps-startup.txt'"

# ------------------------------------------------------------------ 3. guests, one at a time
for ARCH in ARM MIPS; do
    log "3. guest $ARCH"
    check "$ARCH: no QEMU running before start (sequential)" bash -c "! pgrep qemu-system >/dev/null"
    timeout 1000 docker exec "$ID" sh -c "cd /app && python3 /harness/guest_probe.py $ARCH /harness-out"
    rc=$?
    echo "guest_probe $ARCH exit=$rc"
    check "$ARCH: all guest checks passed (guest_probe exit 0)" test $rc -eq 0
    E ps -eo pid,args > "$D/ps-after-$ARCH.txt"
    check "$ARCH: no qemu-system/tshark left in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps-after-$ARCH.txt'"
    check "$ARCH: no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-3A after '"$ARCH"'"' > "$D/verify-after-$ARCH.txt" 2>&1
    check "$ARCH: full verify after guest shutdown" test $? -eq 0
done

# ------------------------------------------------------------------ 4. final state, teardown
log "4. final verify and teardown"
E sh -c 'test ! -e /run/sandbox/current_task && test -z "$(ls -A /app/data)" && test ! -e /tmp/sandbox_stop_requested && ! ls -d /tmp/g-* >/dev/null 2>&1'
check "no marker, fixture, stop file or guest disk left in container" test $? -eq 0
E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
check "normalized runtime ruleset identical to expected" bash -c "diff <(python3 -m json.tool '$D/normalized-runtime.json') <(python3 -m json.tool '$REPO/sandbox-worker/isolation/expected-ruleset.json') >/dev/null"
docker logs --timestamps "$ID" > "$D/docker-logs-final.txt" 2>&1
docker stop -t 10 "$ID" >/dev/null; check "docker stop exit 0" test $? -eq 0
docker rm "$ID" >/dev/null; check "docker rm exit 0" test $? -eq 0
check "test container removed" bash -c "! docker inspect '$ID' >/dev/null 2>&1"
sleep 2; host_state after
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"; fi
done
for f in sysctl.txt nft-ruleset-stateless.txt ip-route.txt listen-tcp.txt qemu.txt tshark.txt; do
    check "host $f unchanged" test ! -e "$OUT/host-diff-$f.diff"
done
# ip-addr: the only explained change is an IPv6 link-local appearing on the sandboxnet bridge
# (kernel autoconf when Docker first attaches a port after a host reboot; seen in 06B-2A).
BR="br-$(docker network inspect -f '{{.Id}}' "$SANDBOXNET" | cut -c1-12)"
strip_ll() { sed -E "/^$BR /s# fe80::[0-9a-f:]+/64##" "$1"; }
check "host ip-addr unchanged except IPv6 link-local on $BR" diff -q <(strip_ll "$OUT/host-before/ip-addr.txt") <(strip_ll "$OUT/host-after/ip-addr.txt")
echo "created ids: ${CREATED_IDS[*]}" | tee "$OUT/created-ids.txt"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true

log "result"
if [ ${#FAILS[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
