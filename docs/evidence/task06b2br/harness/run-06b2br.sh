#!/bin/bash
# Nhiệm vụ 06B-2BR — verify must detect guest-network addresses on the wrong interface.
#
#   sudo bash /home/dathq/projects/ct01-06b2br/run-06b2br.sh <FULL_EXPECTED_IMAGE_ID>
#
#  A. ct01-06b2br-valid: real run.sh, sentinel server.py + poller.py. After V0, addresses are
#     added/removed ONE AT A TIME inside the container netns and verify is run after each:
#       10.200.0.2/32 on lo, 10.200.0.3/32 on eth0, 10.200.1.5/16 on lo (overlap) -> must FAIL
#       192.0.2.10/32 on lo (ordinary)                                          -> must PASS
#     then a final full verify must pass with no leftover address.
#  B. ct01-06b2br-startup-bad: 10.200.0.2/32 is put on lo BEFORE the unmodified run.sh starts
#     (entrypoint wrapper) -> V0 must fail, exit 1, no sentinel called.
#  Same guarantees as 06B-2AR/2B: full image id, cleanup only of created IDs, hard checks,
#  exit != 0 on failure; no compose service, no real server/poller, no QEMU/guest/sample,
#  no host changes, no env printing.
set -uo pipefail

EXPECTED_IMAGE_ID=${1:-}
H=/home/dathq/projects/ct01-06b2br
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
VALID=ct01-06b2br-valid
BAD=ct01-06b2br-startup-bad

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[[ "$EXPECTED_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "usage: $0 sha256:<64 hex>"; exit 2; }
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

CREATED_IDS=(); FAILS=(); LAST_ID=""
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
}

run_container() {  # name extra-args... ; sets LAST_ID
    local name=$1; shift
    local sd="$OUT/$name/sentinel"; rm -rf "$sd"; mkdir -p "$sd"; chmod 777 "$sd"
    LAST_ID=""
    local id
    id=$(docker run -d --name "$name" --restart no --privileged --network "$SANDBOXNET" \
        -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$name" \
        -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
        -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
        -v "$H/sentinel/server.py:/app/server.py:ro" -v "$H/sentinel/poller.py:/app/poller.py:ro" \
        -v "$sd:/sentinel-out" "$@") || return 1
    CREATED_IDS+=("$id"); LAST_ID=$id
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
[ "$IMAGE_ID" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: image id does not match the 06B-2BR build"; exit 3; }
pass "image id equals full expected id"
docker ps -a --format '{{.Names}} {{.Status}}'
docker ps --format '{{.Names}}' | grep -q 'sandbox-worker' && { echo "ABORT: a worker container is running"; exit 3; }
pgrep -a qemu-system && { echo "ABORT: qemu running"; exit 3; }
for c in "$VALID" "$BAD"; do docker inspect "$c" >/dev/null 2>&1 && { echo "ABORT: pre-existing container $c (left untouched)"; exit 3; }; done
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] || { echo "ABORT: sandboxnet not found"; exit 3; }
sha256sum "$0" "$H/sentinel/server.py" "$H/sentinel/poller.py" | tee "$OUT/harness-sha256.txt"
host_state before

# ------------------------------------------------------------------ 2. A: valid start, then wrong/right addresses
log "2. A: valid start"
D="$OUT/$VALID"
run_container "$VALID" "$IMAGE" || { echo "ABORT: docker run failed"; exit 3; }
VID=$LAST_ID; echo "container id: $VID"
sleep 6
docker inspect -f 'state: {{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}' "$VID" | tee "$D/state.txt"
docker logs --timestamps "$VID" > "$D/docker-logs-startup.txt" 2>&1
grep -E 'ISOLATION|SENTINEL' "$D/docker-logs-startup.txt"
check "A: container running, 0 restarts" grep -q 'state: running exit=0 restarts=0' "$D/state.txt"
check "A: V0 passed" grep -q 'ISOLATION OK (V0 startup)' "$D/docker-logs-startup.txt"
check "A: both sentinels called" test -s "$D/sentinel/server-called" -a -s "$D/sentinel/poller-called"
E() { docker exec "$VID" "$@"; }
check "A: in-image verify.py equals working tree" bash -c "[ \"\$(docker exec '$VID' sha256sum /app/isolation/verify.py | cut -d' ' -f1)\" = \"\$(sha256sum '$REPO/sandbox-worker/isolation/verify.py' | cut -d' ' -f1)\" ]"

verify_case() {  # label expect(pass|fail) needle
    local label=$1 expect=$2 needle=${3:-}
    E sh -c "cd /app && python3 -m isolation.verify --phase '06B-2BR $label'" > "$D/verify-$label.txt" 2>&1
    local rc=$?
    echo "-- $label: verify exit=$rc"; cat "$D/verify-$label.txt"
    if [ "$expect" = pass ]; then
        check "A/$label: verify passes" test $rc -eq 0
    else
        check "A/$label: verify fails (exit 1)" test $rc -eq 1
        check "A/$label: failure names the address" grep -qF "$needle" "$D/verify-$label.txt"
    fi
}
with_addr() {  # label expect addr dev needle
    local label=$1 expect=$2 addr=$3 dev=$4 needle=${5:-}
    E ip addr add "$addr" dev "$dev" || { fail "A/$label: could not add $addr on $dev"; return; }
    E ip -o -4 addr show > "$D/ip-addr-$label.txt"
    verify_case "$label" "$expect" "$needle"
    E ip addr del "$addr" dev "$dev"
    check "A/$label: $addr removed from $dev" bash -c "! docker exec '$VID' ip -o -4 addr show dev '$dev' | grep -qF ' ${addr%/*}/'"
}

verify_case "1-correct" pass
with_addr "2-guest-ip-on-lo"       fail 10.200.0.2/32 lo   "10.200.0.2/32 on lo"
with_addr "3-guest-ip-on-eth0"     fail 10.200.0.3/32 eth0 "10.200.0.3/32 on eth0"
with_addr "3b-overlap-prefix-on-lo" fail 10.200.1.5/16 lo  "10.200.1.5/16 on lo"
with_addr "4-ordinary-on-lo"       pass 192.0.2.10/32 lo
verify_case "5-final-correct" pass
E ip -o -4 addr show > "$D/ip-addr-final.txt"; cat "$D/ip-addr-final.txt"
check "A: only tap0 holds a 10.200.0.0/30 address at the end" bash -c "[ \"\$(grep -c 'inet 10\.200\.' '$D/ip-addr-final.txt')\" = 1 ] && grep -q 'tap0 .*inet 10.200.0.1/30' '$D/ip-addr-final.txt'"
E ps -eo pid,args > "$D/ps.txt"
check "A: no qemu/tshark in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps.txt'"
docker logs --timestamps "$VID" > "$D/docker-logs-final.txt" 2>&1
docker stop -t 10 "$VID" >/dev/null; check "A: docker stop exit 0" test $? -eq 0
docker rm "$VID" >/dev/null; check "A: docker rm exit 0" test $? -eq 0

# ------------------------------------------------------------------ 3. B: fail-closed at startup
log "3. B: guest address on lo before run.sh"
D="$OUT/$BAD"
run_container "$BAD" --entrypoint /bin/bash "$IMAGE" -c 'ip addr add 10.200.0.2/32 dev lo && exec bash /app/run.sh' \
    || { fail "B: docker run failed"; }
BID=$LAST_ID
code=$(timeout 60 docker wait "$BID"); [ $? -eq 0 ] || code=TIMEOUT
echo "exit code: $code" | tee "$D/exit-code.txt"
docker logs --timestamps "$BID" > "$D/docker-logs.txt" 2>&1
grep -E 'ISOLATION|SENTINEL' "$D/docker-logs.txt"
check "B: exit code exactly 1" test "$code" = 1
check "B: V0 failed naming 10.200.0.2/32 on lo" grep -qF "10.200.0.2/32 on lo" "$D/docker-logs.txt"
check "B: no sentinel called" bash -c "[ -z \"\$(ls -A '$D/sentinel')\" ]"
check "B: 0 restarts" test "$(docker inspect -f '{{.RestartCount}}' "$BID")" = 0
docker rm -f "$BID" >/dev/null

# ------------------------------------------------------------------ 4. host + cleanup
log "4. host state and cleanup"
check "no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"
left=0; for id in "${CREATED_IDS[@]}"; do docker inspect "$id" >/dev/null 2>&1 && left=1; done
check "all containers created by this run are removed" test $left -eq 0
sleep 2; host_state after
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"; fi
done
for f in sysctl.txt nft-ruleset-stateless.txt ip-route.txt ip-addr.txt listen-tcp.txt; do
    check "host $f unchanged" test ! -e "$OUT/host-diff-$f.diff"
done
echo "created ids: ${CREATED_IDS[*]}" | tee "$OUT/created-ids.txt"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true

log "result"
if [ ${#FAILS[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
