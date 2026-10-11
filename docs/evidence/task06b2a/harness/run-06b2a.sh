#!/bin/bash
# Nhiệm vụ 06B-2A — real run.sh / V0 startup check, WITHOUT any guest.
#
#   sudo bash /home/dathq/projects/ct01-06b2a/run-06b2a.sh
#
# What it does (and does not do):
#  * Starts throwaway containers named ct01-06b2a-* from sandbox-worker:latest with
#    the worker's real entrypoint (run.sh), on the existing sandboxnet, --privileged
#    like docker-compose.yml, no published ports, no host network, --restart no,
#    no lab-data / docker.sock mounts.
#  * /app/server.py and /app/poller.py are replaced (read-only bind mounts) by
#    sentinels that only record that they were called. run.sh, verify.py,
#    constants and the real ruleset are untouched.
#  * Never starts the compose service sandbox-worker-1, the manager, QEMU, or any sample.
#  * Never changes host network/firewall/sysctl; it only reads them before/after.
#  * Never prints container environment variables.
set -uo pipefail

H=/home/dathq/projects/ct01-06b2a
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
EXPECTED_IMAGE_PREFIX=sha256:a526b0c71752
PREFIX=ct01-06b2a
VALID=$PREFIX-valid
ALLOW=$PREFIX-allow-true
BROKEN=$PREFIX-broken-nft

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
mkdir -p "$OUT"
exec > >(tee "$OUT/run.log") 2>&1

log() { echo; echo "===== $* ($(date -u +%H:%M:%S))"; }
cleanup() {
    for c in "$VALID" "$ALLOW" "$BROKEN"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
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
    for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 \
             net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.core.devconf_inherit_init_net; do
        echo "$k=$(sysctl -n "$k" 2>&1)"
    done > "$d/sysctl.txt"
    ls /proc/sys/net/bridge > "$d/proc-sys-net-bridge.txt" 2>&1 || true
    ss -ltnH | awk '{print $4}' | sort > "$d/listen-tcp.txt"
    docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | sort > "$d/docker-ps.txt"
    docker network ls --format '{{.Name}} {{.Driver}}' | sort > "$d/docker-networks.txt"
    pgrep -a qemu-system > "$d/qemu.txt" 2>&1 || echo "no qemu-system" > "$d/qemu.txt"
}

sentinel_dir() { local d="$OUT/$1/sentinel"; rm -rf "$d"; mkdir -p "$d"; chmod 777 "$d"; echo "$d"; }

run_container() {  # name allow_internet extra-docker-args...
    local name=$1 allow=$2; shift 2
    local sd; sd=$(sentinel_dir "$name")
    docker run -d --name "$name" --restart no --privileged \
        --network "$SANDBOXNET" \
        -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$name" \
        -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
        -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET="$allow" \
        -v "$H/sentinel/server.py:/app/server.py:ro" \
        -v "$H/sentinel/poller.py:/app/poller.py:ro" \
        -v "$sd:/sentinel-out" \
        "$@" "$IMAGE"
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image $IMAGE id=$IMAGE_ID"
case "$IMAGE_ID" in "$EXPECTED_IMAGE_PREFIX"*) echo "image id matches 06B-1R build";;
    *) echo "WARNING: image id differs from 06B-1R build ($EXPECTED_IMAGE_PREFIX…)";; esac
docker ps -a --format '{{.Names}} {{.Status}}'
if docker ps --format '{{.Names}}' | grep -q 'sandbox-worker'; then echo "ABORT: a worker container is running"; exit 3; fi
if pgrep -a qemu-system; then echo "ABORT: qemu running on host"; exit 3; fi
for c in "$VALID" "$ALLOW" "$BROKEN"; do
    docker inspect "$c" >/dev/null 2>&1 && { echo "ABORT: leftover container $c"; exit 3; }
done

SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] || { echo "ABORT: sandboxnet not found"; exit 3; }
docker network inspect -f 'name={{.Name}} id={{.Id}} driver={{.Driver}} internal={{.Internal}} ipv6={{.EnableIPv6}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} containers=[{{range .Containers}}{{.Name}}:{{.IPv4Address}} {{end}}]' "$SANDBOXNET" | tee "$OUT/sandboxnet.txt"
grep -q 'subnet=192.168.60.0/24 gw=192.168.60.1' "$OUT/sandboxnet.txt" || { echo "ABORT: unexpected sandboxnet subnet"; exit 3; }
sha256sum "$H/sentinel/server.py" "$H/sentinel/poller.py" "$H/broken-guest.nft" | tee "$OUT/harness-sha256.txt"
host_state before

# ------------------------------------------------------------------ 2/3. valid start
log "3. valid start: ALLOW_VM_INTERNET=false"
run_container "$VALID" false
sleep 8
ST=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} pid={{.State.Pid}}' "$VALID")
echo "state: $ST"
docker logs --timestamps "$VALID" > "$OUT/$VALID/docker-logs.txt" 2>&1
cat "$OUT/$VALID/docker-logs.txt"
echo "-- ordering (line numbers in docker logs):"
grep -n -E 'ISOLATION (OK|FAIL)|SENTINEL' "$OUT/$VALID/docker-logs.txt"
echo "-- sentinel markers:"; ls -l "$OUT/$VALID/sentinel"; cat "$OUT/$VALID/sentinel/"* 2>/dev/null

if docker inspect -f '{{.State.Running}}' "$VALID" | grep -q true; then
    E() { docker exec "$VALID" "$@"; }
    D="$OUT/$VALID"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-2A recheck"; echo "verify exit=$?"' | tee "$D/verify-recheck.txt"
    E nft --version | tee "$D/nft-version.txt"
    E sh -c 'for k in net/ipv4/ip_forward net/ipv6/conf/all/forwarding net/ipv6/conf/default/disable_ipv6 net/ipv6/conf/tap0/disable_ipv6 net/ipv4/conf/tap0/arp_ignore net/ipv4/conf/tap0/arp_announce net/ipv4/conf/tap0/arp_accept net/ipv4/conf/tap0/rp_filter net/ipv4/conf/all/rp_filter net/ipv4/conf/eth0/rp_filter; do printf "%s=" $k; cat /proc/sys/$k 2>&1; done' | tee "$D/sysctl.txt"
    E ip -d link show > "$D/ip-d-link.txt"
    E ip addr show    > "$D/ip-addr.txt"
    E ip neigh show   > "$D/ip-neigh.txt"
    E ip route show   > "$D/ip-route.txt"
    E ip -6 route show > "$D/ip6-route.txt" 2>&1
    E ip -d link show type bridge > "$D/bridges.txt" 2>&1
    E nft list ruleset > "$D/nft-ruleset.txt"
    E nft -s list ruleset > "$D/nft-ruleset-stateless.txt"
    E nft list tables | tee "$D/nft-tables.txt"
    echo "-- tables outside the three CT-01 tables (for review only):"
    grep -v -E '^table (netdev sandbox_guest_l2|arp sandbox_guest_arp|inet sandbox_guest)$' "$D/nft-tables.txt" | tee "$D/nft-tables-other.txt" || echo "(none)"
    E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
    E sha256sum /app/server.py /app/poller.py /app/run.sh /app/isolation/guest.nft /app/isolation/load.nft /app/isolation/expected-ruleset.json /app/isolation/verify.py /app/isolation/constants.py | tee "$D/sha256-in-container.txt"
    E ps -eo pid,ppid,args | tee "$D/ps.txt"
    echo "-- summary checks:"
    E ip -4 -o addr show dev eth0 | awk '{print "eth0", $4}'
    docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}network={{$k}} ip={{$v.IPAddress}} gw={{$v.Gateway}}{{end}}' "$VALID" | tee "$D/networks.txt"
    E sh -c 'ip -j -d link show tap0' | python3 -c 'import json,sys; l=json.load(sys.stdin)[0]; print("tap0 master:", l.get("master")); print("tap0 kind:", l.get("linkinfo",{}).get("info_kind"), l.get("linkinfo",{}).get("info_data",{}).get("type"))' | tee "$D/tap0.txt"
    grep -c . "$D/bridges.txt" | sed 's/^/bridge lines: /'
    E sh -c 'ps -eo args | grep -E "[q]emu-system|[t]shark" || echo "no qemu/tshark in container"'
    E sh -c 'grep -l "SENTINEL" /app/poller.py /app/server.py'
    pgrep -a qemu-system || echo "no qemu-system on host"
    echo "-- normalized runtime vs expected (repo working tree):"
    if diff <(python3 -m json.tool "$D/normalized-runtime.json") <(python3 -m json.tool "$REPO/sandbox-worker/isolation/expected-ruleset.json") > "$D/normalized-diff.txt"; then
        echo "IDENTICAL"; else echo "DIFFERENT (see normalized-diff.txt)"; fi

    # namespace identity before teardown
    PID=$(docker inspect -f '{{.State.Pid}}' "$VALID")
    SKEY=$(docker inspect -f '{{.NetworkSettings.SandboxKey}}' "$VALID")
    NSID=$(readlink "/proc/$PID/ns/net")
    echo "netns before stop: pid=$PID sandboxkey=$SKEY ns=$NSID host-ns=$(readlink /proc/1/ns/net)" | tee "$D/netns.txt"
    ls -l "$SKEY" >> "$D/netns.txt" 2>&1
else
    echo "VALID CONTAINER IS NOT RUNNING"
fi

log "3b. teardown of valid container"
docker stop -t 10 "$VALID" >/dev/null; echo "stop exit=$?"
docker inspect -f 'after stop: status={{.State.Status}} exit={{.State.ExitCode}} sandboxkey="{{.NetworkSettings.SandboxKey}}"' "$VALID" | tee -a "$OUT/$VALID/netns.txt"
docker rm "$VALID" >/dev/null; echo "rm exit=$?"
{
  echo "after rm:"
  [ -n "${SKEY:-}" ] && { ls -l "$SKEY" 2>&1 || echo "sandbox key file gone"; }
  [ -n "${PID:-}" ] && { ls "/proc/$PID" >/dev/null 2>&1 && echo "pid $PID still exists" || echo "pid $PID gone"; }
  docker inspect "$VALID" >/dev/null 2>&1 && echo "container still exists" || echo "container removed"
  ip link show tap0 2>&1 | head -1
} | tee -a "$OUT/$VALID/netns.txt"

# ------------------------------------------------------------------ 4. refusal cases
refusal() {  # name allow extra-args...
    local name=$1; shift
    log "4. refusal: $name"
    run_container "$name" "$@" >/dev/null
    local code; code=$(timeout 60 docker wait "$name"); local wrc=$?
    if [ $wrc -ne 0 ]; then echo "container did not exit within 60 s"; code=TIMEOUT; fi
    echo "exit code: $code" | tee "$OUT/$name/exit-code.txt"
    docker logs --timestamps "$name" > "$OUT/$name/docker-logs.txt" 2>&1
    tail -5 "$OUT/$name/docker-logs.txt"
    echo "sentinel markers: $(ls "$OUT/$name/sentinel" | tr '\n' ' ')(empty = not called)"
    pgrep -a qemu-system || echo "no qemu-system on host"
    docker inspect -f 'restarts={{.RestartCount}} status={{.State.Status}}' "$name"
    docker rm -f "$name" >/dev/null; echo "removed $name"
}
refusal "$ALLOW" true
refusal "$BROKEN" false -v "$H/broken-guest.nft:/app/isolation/guest.nft:ro"

# ------------------------------------------------------------------ 5. host state after
log "5. host state after"
sleep 2
host_state after
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then
        rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else
        echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"
    fi
done
docker ps -a --format '{{.Names}} {{.Status}}' | grep "$PREFIX" && echo "LEFTOVER test container" || echo "no ct01-06b2a containers left"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true
log "done"
