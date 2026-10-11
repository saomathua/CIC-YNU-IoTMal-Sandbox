#!/bin/bash
# Nhiệm vụ 06B-2AR — re-run of the 06B-2A startup/V0 harness with effective-sysctl checks.
#
#   sudo bash /home/dathq/projects/ct01-06b2ar/run-06b2ar.sh <FULL_EXPECTED_IMAGE_ID>
#
# Changes vs. 06B-2A harness (review):
#  * cleanup removes ONLY the container IDs created by this run; pre-existing
#    containers (even with the same name) are never touched;
#  * the image ID must equal the full expected ID (from the 06B-2AR build log), else ABORT;
#  * every acceptance criterion is a hard check; the script exits non-zero if any fails.
# Unchanged guarantees: no compose service, no real server/poller (sentinels), no QEMU,
# no samples, no host network/firewall/sysctl writes, no env printing.
set -uo pipefail

EXPECTED_IMAGE_ID=${1:-}
H=/home/dathq/projects/ct01-06b2ar
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
PREFIX=ct01-06b2ar
VALID=$PREFIX-valid
ALLOW=$PREFIX-allow-true
BROKEN=$PREFIX-broken-nft

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[[ "$EXPECTED_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "usage: $0 sha256:<64 hex> (full expected image id)"; exit 2; }
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

CREATED_IDS=()
FAILS=()
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

host_state() {  # $1 = label
    local d="$OUT/host-$1"; mkdir -p "$d"
    ip -br link        > "$d/ip-link.txt"
    ip -br addr        > "$d/ip-addr.txt"
    ip route           > "$d/ip-route.txt"
    ip -6 route        > "$d/ip6-route.txt"
    ip link show tap0  > "$d/host-tap0.txt" 2>&1 || true
    nft -s list ruleset > "$d/nft-ruleset-stateless.txt" 2>&1
    lsmod | awk 'NR>1{print $1}' | grep -E '^(nf_|nft_|xt_|br_netfilter|bridge|tun|veth|ip_tables|ip6_tables|x_tables|iptable_|ip6table_|nfnetlink)' | sort > "$d/lsmod-net.txt"
    {
        for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 \
                 net.ipv6.conf.default.disable_ipv6 net.core.devconf_inherit_init_net; do
            echo "$k=$(sysctl -n "$k" 2>&1)"
        done
        for dev in all default ens33; do
            for a in rp_filter arp_ignore arp_announce arp_accept forwarding; do
                echo "net.ipv4.conf.$dev.$a=$(sysctl -n "net.ipv4.conf.$dev.$a" 2>&1)"
            done
        done
    } > "$d/sysctl.txt"
    ls /proc/sys/net/bridge > "$d/proc-sys-net-bridge.txt" 2>&1 || true
    ss -ltnH | awk '{print $4}' | sort > "$d/listen-tcp.txt"
    docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | sort > "$d/docker-ps.txt"
    docker network ls --format '{{.Name}} {{.Driver}}' | sort > "$d/docker-networks.txt"
    pgrep -a qemu-system > "$d/qemu.txt" 2>&1 || echo "no qemu-system" > "$d/qemu.txt"
}

sentinel_dir() { local d="$OUT/$1/sentinel"; rm -rf "$d"; mkdir -p "$d"; chmod 777 "$d"; echo "$d"; }

LAST_ID=""
run_container() {  # name allow_internet extra-docker-args...  -> sets LAST_ID (no subshell, so
    local name=$1 allow=$2; shift 2   # CREATED_IDS is updated in this shell)
    local sd; sd=$(sentinel_dir "$name")
    local id
    LAST_ID=""
    id=$(docker run -d --name "$name" --restart no --privileged \
        --network "$SANDBOXNET" \
        -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$name" \
        -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
        -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET="$allow" \
        -v "$H/sentinel/server.py:/app/server.py:ro" \
        -v "$H/sentinel/poller.py:/app/poller.py:ro" \
        -v "$sd:/sentinel-out" \
        "$@" "$IMAGE") || return 1
    CREATED_IDS+=("$id")
    LAST_ID=$id
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image $IMAGE id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
if [ "$IMAGE_ID" != "$EXPECTED_IMAGE_ID" ]; then echo "ABORT: image id does not match the 06B-2AR build"; exit 3; fi
pass "image id equals full expected id"
docker ps -a --format '{{.Names}} {{.Status}}'
if docker ps --format '{{.Names}}' | grep -q 'sandbox-worker'; then echo "ABORT: a worker container is running"; exit 3; fi
if pgrep -a qemu-system; then echo "ABORT: qemu running on host"; exit 3; fi
for c in "$VALID" "$ALLOW" "$BROKEN"; do
    if docker inspect "$c" >/dev/null 2>&1; then echo "ABORT: pre-existing container named $c (left untouched)"; exit 3; fi
done
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] || { echo "ABORT: sandboxnet not found"; exit 3; }
docker network inspect -f 'name={{.Name}} id={{.Id}} driver={{.Driver}} internal={{.Internal}} ipv6={{.EnableIPv6}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} containers=[{{range .Containers}}{{.Name}}:{{.IPv4Address}} {{end}}]' "$SANDBOXNET" | tee "$OUT/sandboxnet.txt"
grep -q 'subnet=192.168.60.0/24 gw=192.168.60.1' "$OUT/sandboxnet.txt" || { echo "ABORT: unexpected sandboxnet subnet"; exit 3; }
sha256sum "$0" "$H/sentinel/server.py" "$H/sentinel/poller.py" "$H/broken-guest.nft" | tee "$OUT/harness-sha256.txt"
host_state before

# ------------------------------------------------------------------ 2. valid start
log "2. valid start: ALLOW_VM_INTERNET=false"
D="$OUT/$VALID"
run_container "$VALID" false || fail "valid container could not be created"; VID=$LAST_ID
echo "container id: $VID"
sleep 8
if [ -n "$VID" ]; then
    docker inspect -f 'state: {{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} pid={{.State.Pid}}' "$VID" | tee "$D/state.txt"
    docker logs --timestamps "$VID" > "$D/docker-logs.txt" 2>&1
    cat "$D/docker-logs.txt"
    echo "-- sentinel markers:"; ls -l "$D/sentinel"; cat "$D/sentinel/"* 2>/dev/null
    check "valid container running, 0 restarts" grep -q 'state: running exit=0 restarts=0' "$D/state.txt"

    # V0 must pass before any sentinel was called (timestamps from docker logs and marker files)
    python3 - "$D/docker-logs.txt" "$D/sentinel" > "$D/v0-order.txt" <<'PY'
import datetime, os, re, sys
logs, sdir = sys.argv[1], sys.argv[2]
def ts(s):
    s = s.rstrip("Z")
    if "." in s:
        a, b = s.split("."); s = a + "." + b[:6]
    return datetime.datetime.fromisoformat(s)
v0 = [ts(l.split()[0]) for l in open(logs) if "ISOLATION OK (V0 startup)" in l]
marks = []
for f in ("server-called", "poller-called"):
    p = os.path.join(sdir, f)
    if os.path.exists(p):
        marks += [ts(l.split()[0]) for l in open(p) if l.strip()]
ok = len(v0) == 1 and len(marks) == 2 and all(m > v0[0] for m in marks)
print(f"v0={v0} sentinels={sorted(marks)} ok={ok}")
sys.exit(0 if ok else 1)
PY
    check "V0 passed before both sentinels were called" test $? -eq 0
    cat "$D/v0-order.txt"
    check "no ISOLATION FAIL in logs" bash -c "! grep -q 'ISOLATION FAIL' '$D/docker-logs.txt'"
    grep 'SYSCTL REPORT' "$D/docker-logs.txt" > "$D/sysctl-report-run-sh.txt" || true

    if docker inspect -f '{{.State.Running}}' "$VID" | grep -q true; then
        E() { docker exec "$VID" "$@"; }
        E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-2AR recheck"' > "$D/verify-recheck.txt" 2>&1
        rc=$?; echo "verify exit=$rc" >> "$D/verify-recheck.txt"; cat "$D/verify-recheck.txt"
        check "verify recheck exit 0" test $rc -eq 0
        E sh -c 'cd /app && python3 -m isolation.verify --sysctl-report "06B-2AR exec"' | tee "$D/sysctl-report-exec.txt"
        E sh -c 'for d in all default tap0 eth0; do for a in rp_filter arp_ignore arp_announce arp_accept forwarding; do printf "net.ipv4.conf.%s.%s=" $d $a; cat /proc/sys/net/ipv4/conf/$d/$a; done; done; for k in net/ipv4/ip_forward net/ipv6/conf/all/forwarding net/ipv6/conf/default/disable_ipv6 net/ipv6/conf/tap0/disable_ipv6; do printf "%s=" $k; cat /proc/sys/$k 2>&1; done' | tee "$D/sysctl-raw.txt"
        E nft --version > "$D/nft-version.txt"
        E ip -d link show > "$D/ip-d-link.txt"
        E ip addr show    > "$D/ip-addr.txt"
        E ip neigh show   > "$D/ip-neigh.txt"
        E ip route show   > "$D/ip-route.txt"
        E ip -6 route show > "$D/ip6-route.txt" 2>&1
        E ip -d link show type bridge > "$D/bridges.txt" 2>&1
        E nft -s list ruleset > "$D/nft-ruleset-stateless.txt"
        E nft list tables > "$D/nft-tables.txt"
        grep -v -E '^table (netdev sandbox_guest_l2|arp sandbox_guest_arp|inet sandbox_guest)$' "$D/nft-tables.txt" > "$D/nft-tables-other.txt" || true
        echo "-- tables outside CT-01 (review only):"; cat "$D/nft-tables-other.txt"
        E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
        if diff <(python3 -m json.tool "$D/normalized-runtime.json") <(python3 -m json.tool "$REPO/sandbox-worker/isolation/expected-ruleset.json") > "$D/normalized-diff.txt"; then
            pass "normalized runtime ruleset identical to expected (working tree)"
        else fail "normalized runtime ruleset differs from expected"; fi
        E sha256sum /app/server.py /app/poller.py /app/run.sh /app/isolation/guest.nft /app/isolation/load.nft /app/isolation/expected-ruleset.json /app/isolation/verify.py /app/isolation/constants.py > "$D/sha256-in-container.txt"
        ( cd "$REPO/sandbox-worker" && sha256sum run.sh isolation/guest.nft isolation/load.nft isolation/expected-ruleset.json isolation/verify.py isolation/constants.py ) > "$D/sha256-repo.txt"
        cat "$D/sha256-in-container.txt"
        check "run.sh/isolation files in image equal working tree" bash -c "diff <(awk 'NR>2{print \$1}' '$D/sha256-in-container.txt') <(awk '{print \$1}' '$D/sha256-repo.txt') >/dev/null"
        E ps -eo pid,ppid,args > "$D/ps.txt"; cat "$D/ps.txt"
        check "no qemu/tshark in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps.txt'"
        check "sentinels (not real server/poller) mounted" E grep -q SENTINEL /app/poller.py /app/server.py
        docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}network={{$k}} ip={{$v.IPAddress}}{{end}}' "$VID" | tee "$D/networks.txt"
        check "eth0 on sandboxnet" grep -q "network=$SANDBOXNET ip=192.168.60." "$D/networks.txt"
        check "tap0 has no master and no bridge exists" bash -c "! grep -q 'master' <(docker exec '$VID' ip -d link show tap0) && [ ! -s '$D/bridges.txt' ]"
        PID=$(docker inspect -f '{{.State.Pid}}' "$VID"); SKEY=$(docker inspect -f '{{.NetworkSettings.SandboxKey}}' "$VID")
        echo "netns: pid=$PID sandboxkey=$SKEY ns=$(readlink /proc/$PID/ns/net) host-ns=$(readlink /proc/1/ns/net)" | tee "$D/netns.txt"
    else
        fail "valid container not running at inspection time"
    fi
    check "no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"

    log "2b. teardown of valid container"
    docker stop -t 10 "$VID" >/dev/null; check "docker stop exit 0" test $? -eq 0
    docker rm "$VID" >/dev/null; check "docker rm exit 0" test $? -eq 0
    check "valid container removed" bash -c "! docker inspect '$VID' >/dev/null 2>&1"
    check "netns sandbox key gone" bash -c "[ -z '${SKEY:-}' ] || [ ! -e '${SKEY:-}' ]"
    check "tap0 not present on host" bash -c "! ip link show tap0 >/dev/null 2>&1"
fi

# ------------------------------------------------------------------ 3. refusal cases
refusal() {  # name allow extra-args...
    local name=$1; shift
    log "3. refusal: $name"
    run_container "$name" "$@" || { fail "$name: could not create"; return; }
    local id=$LAST_ID
    local code; code=$(timeout 60 docker wait "$id"); [ $? -eq 0 ] || code=TIMEOUT
    echo "exit code: $code" | tee "$OUT/$name/exit-code.txt"
    docker logs --timestamps "$id" > "$OUT/$name/docker-logs.txt" 2>&1
    tail -6 "$OUT/$name/docker-logs.txt"
    local restarts; restarts=$(docker inspect -f '{{.RestartCount}}' "$id")
    check "$name: exit code exactly 1" test "$code" = 1
    check "$name: no sentinel marker" bash -c "[ -z \"\$(ls -A '$OUT/$name/sentinel')\" ]"
    check "$name: 0 restarts" test "$restarts" = 0
    check "$name: no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"
    docker rm -f "$id" >/dev/null
    check "$name: container removed" bash -c "! docker inspect '$id' >/dev/null 2>&1"
}
refusal "$ALLOW" true
refusal "$BROKEN" false -v "$H/broken-guest.nft:/app/isolation/guest.nft:ro"

# ------------------------------------------------------------------ 4. host state after
log "4. host state after"
sleep 2
host_state after
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then
        rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else
        echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"
    fi
done
check "host sysctl unchanged" test ! -e "$OUT/host-diff-sysctl.txt.diff"
check "host nft ruleset unchanged" test ! -e "$OUT/host-diff-nft-ruleset-stateless.txt.diff"
check "host IPv4 routes unchanged" test ! -e "$OUT/host-diff-ip-route.txt.diff"
left=0
for id in "${CREATED_IDS[@]:-}"; do [ -n "$id" ] && docker inspect "$id" >/dev/null 2>&1 && left=1; done
check "all containers created by this run are removed" test $left -eq 0
echo "created ids: ${CREATED_IDS[*]:-none}" | tee "$OUT/created-ids.txt"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true

log "result"
if [ ${#FAILS[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
