#!/bin/bash
# Nhiệm vụ 06B-2B — real server.py / HTTP API allowlist test, NO guest.
#
#   sudo bash /home/dathq/projects/ct01-06b2b/run-06b2b.sh
#
#  * One throwaway container (ct01-06b2b-http) from the REVIEWED image (full id pinned below),
#    real entrypoint run.sh, REAL server.py; only /app/poller.py is replaced (read-only) by a
#    sentinel. sandboxnet, --privileged like compose, --restart no, no published ports,
#    no host network, no lab-data / docker.sock mounts.
#  * Guest traffic is simulated by a temporary 10.200.0.2/32 on lo INSIDE the test container
#    (middleware test only; does not exercise tap0/nftables). Removed afterwards, then full verify.
#  * Cleanup removes only container IDs created by this run; every criterion is a hard check;
#    exit != 0 on any failure. No compose service, real poller, QEMU, ELF or sample.
#    No host network/firewall/sysctl writes. No env printing.
set -uo pipefail

EXPECTED_IMAGE_ID=sha256:d0bf9277e7c485823ff5a3b8f5ead6c038ef03c5c9fc72fcd0040799403e6f42
H=/home/dathq/projects/ct01-06b2b
OUT=$H/out
REPO=/home/dathq/projects/CIC-YNU-IoTMal-Sandbox
IMAGE=sandbox-worker:latest
NAME=ct01-06b2b-http
T=06b2b-task-0001
X=06b2b-other-0002

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
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
    ss -ltnH | awk '{print $4}' | sort > "$d/listen-tcp.txt"
    docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | sort > "$d/docker-ps.txt"
    docker network ls --format '{{.Name}} {{.Driver}}' | sort > "$d/docker-networks.txt"
    pgrep -a qemu-system > "$d/qemu.txt" 2>&1 || echo "no qemu-system" > "$d/qemu.txt"
}

# ------------------------------------------------------------------ 1. preparation
log "1. preparation"
echo "host=$(hostname) user=${SUDO_USER:-root}"
git -C "$REPO" -c safe.directory="$REPO" rev-parse --abbrev-ref HEAD
git -C "$REPO" -c safe.directory="$REPO" rev-parse HEAD
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
echo "image $IMAGE id=$IMAGE_ID expected=$EXPECTED_IMAGE_ID"
[ "$IMAGE_ID" = "$EXPECTED_IMAGE_ID" ] || { echo "ABORT: image id is not the reviewed 06B-2AR image"; exit 3; }
pass "image id equals reviewed full id"
docker ps -a --format '{{.Names}} {{.Status}}'
if docker ps --format '{{.Names}}' | grep -q 'sandbox-worker'; then echo "ABORT: a worker container is running"; exit 3; fi
if pgrep -a qemu-system; then echo "ABORT: qemu running on host"; exit 3; fi
if docker inspect "$NAME" >/dev/null 2>&1; then echo "ABORT: pre-existing container named $NAME (left untouched)"; exit 3; fi
SANDBOXNET=$(docker network ls --filter label=com.docker.compose.network=sandboxnet --format '{{.Name}}')
[ -n "$SANDBOXNET" ] || { echo "ABORT: sandboxnet not found"; exit 3; }
docker network inspect -f 'name={{.Name}} id={{.Id}} driver={{.Driver}} subnet={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} containers=[{{range .Containers}}{{.Name}}:{{.IPv4Address}} {{end}}]' "$SANDBOXNET" | tee "$OUT/sandboxnet.txt"
grep -q 'subnet=192.168.60.0/24 gw=192.168.60.1' "$OUT/sandboxnet.txt" || { echo "ABORT: unexpected sandboxnet subnet"; exit 3; }
sha256sum "$0" "$H/sentinel/poller.py" "$H/http_tests.py" | tee "$OUT/harness-sha256.txt"
host_state before

# ------------------------------------------------------------------ 2. startup with real server.py
log "2. startup: real run.sh + real server.py, poller sentinel"
D="$OUT/$NAME"; mkdir -p "$D/sentinel" "$D/http"; chmod 777 "$D/sentinel" "$D/http"
ID=$(docker run -d --name "$NAME" --restart no --privileged --network "$SANDBOXNET" \
    -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$NAME" \
    -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
    -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
    -v "$H/sentinel/poller.py:/app/poller.py:ro" \
    -v "$H/http_tests.py:/harness/http_tests.py:ro" \
    -v "$D/sentinel:/sentinel-out" \
    -v "$D/http:/harness-out" \
    "$IMAGE") || { echo "ABORT: docker run failed"; exit 3; }
CREATED_IDS+=("$ID")
echo "container id: $ID"
E() { docker exec "$ID" "$@"; }

ready=0
for i in $(seq 1 30); do
    if E python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status == 200 else 1)' 2>/dev/null; then ready=1; break; fi
    sleep 1
done
check "server ready: healthcheck 200 from 127.0.0.1 (after ${i}s)" test $ready -eq 1
docker inspect -f 'state: {{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}' "$ID" | tee "$D/state.txt"
check "container running, 0 restarts" grep -q 'state: running exit=0 restarts=0' "$D/state.txt"
docker logs --timestamps "$ID" > "$D/docker-logs-startup.txt" 2>&1
grep -E 'SYSCTL REPORT \(after|ISOLATION|SENTINEL|Started server process|Uvicorn running|Application startup' "$D/docker-logs-startup.txt"
python3 - "$D/docker-logs-startup.txt" "$D/sentinel/poller-called" > "$D/v0-order.txt" <<'PY'
import datetime, sys
def ts(s):
    s = s.rstrip("Z"); a, b = (s.split(".") + ["0"])[:2]; return datetime.datetime.fromisoformat(a + "." + b[:6])
lines = open(sys.argv[1]).read().splitlines()
v0 = [ts(l.split()[0]) for l in lines if "ISOLATION OK (V0 startup)" in l]
srv = [ts(l.split()[0]) for l in lines if "Started server process" in l]
try:
    poll = [ts(l.split()[0]) for l in open(sys.argv[2]) if l.strip()]
except FileNotFoundError:
    poll = []
ok = len(v0) == 1 and len(srv) >= 1 and len(poll) == 1 and srv[0] > v0[0] and poll[0] > v0[0]
print(f"v0={v0} server_started={srv[:1]} poller_sentinel={poll} ok={ok}"); sys.exit(0 if ok else 1)
PY
check "V0 passed before real server started and before poller sentinel" test $? -eq 0
cat "$D/v0-order.txt"
check "server.py started exactly once (no crash loop)" test "$(grep -c 'Started server process' "$D/docker-logs-startup.txt")" -eq 1

E ps -eo pid,ppid,args > "$D/ps.txt"; cat "$D/ps.txt"
check "real server.py process running" grep -q 'python3 server.py' "$D/ps.txt"
check "poller is the sentinel (PID 1)" bash -c "grep -qE '^ +1 +0 python3 poller.py' '$D/ps.txt' && docker exec '$ID' grep -q SENTINEL /app/poller.py"
check "no qemu/tshark in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps.txt'"
check "no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"

FILES="run.sh server.py router/sandbox_router.py router/healthcheck.py util/lifespan_handlers.py config/settings.py service/analysis.py isolation/apifilter.py isolation/current_task.py isolation/constants.py isolation/verify.py isolation/guest.nft isolation/load.nft isolation/expected-ruleset.json"
E sh -c "cd /app && sha256sum $FILES" > "$D/sha256-in-container.txt"
( cd "$REPO/sandbox-worker" && sha256sum $FILES ) > "$D/sha256-repo.txt"
check "server/router/isolation/run.sh code in image equals working tree" diff -q "$D/sha256-in-container.txt" "$D/sha256-repo.txt"
E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-2B before simulation"' > "$D/verify-before.txt" 2>&1
check "verify before simulation exit 0" test $? -eq 0
ETH0_IP=$(E ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
echo "eth0 ip: $ETH0_IP"

# ------------------------------------------------------------------ 3. HTTP/API allowlist via simulated guest source
log "3. HTTP allowlist tests (guest source simulated on lo — middleware only, not tap0)"
E ip addr add 10.200.0.2/32 dev lo
E ip -o addr show > "$D/ip-addr-during-simulation.txt"
check "simulation address 10.200.0.2/32 present on lo" grep -q 'lo .*inet 10.200.0.2/32' "$D/ip-addr-during-simulation.txt"
E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-2B during simulation (informational)"' > "$D/verify-during-simulation.txt" 2>&1
echo "verify during simulation (informational) exit=$?"; cat "$D/verify-during-simulation.txt"
E sh -c "cd /app && python3 /harness/http_tests.py '$T' '$X' '$ETH0_IP' /harness-out" > "$D/http-tests.txt" 2>&1
HTTP_RC=$?
cat "$D/http-tests.txt"
check "all HTTP/API checks passed (http_tests.py exit 0)" test $HTTP_RC -eq 0
docker logs --timestamps "$ID" > "$D/docker-logs-after-http.txt" 2>&1
grep -E 'guest request denied|10\.200\.0\.2:[0-9]+ - |127\.0\.0\.1:[0-9]+ - |'"$ETH0_IP"':[0-9]+ - ' "$D/docker-logs-after-http.txt" > "$D/server-access-and-deny-log.txt" || true
check "server logged guest denials from 10.200.0.2" grep -q "guest request denied: client=('10.200.0.2'" "$D/server-access-and-deny-log.txt"

# ------------------------------------------------------------------ 4. remove simulation, re-verify
log "4. remove simulation address, full verify"
E ip addr del 10.200.0.2/32 dev lo
E ip -o addr show > "$D/ip-addr-after-simulation.txt"
check "no 10.200.0.2 address left on any interface" bash -c "! grep -q 'inet 10.200.0.2/' '$D/ip-addr-after-simulation.txt'"
E sh -c 'test ! -e /run/sandbox/current_task && test -z "$(ls -A /app/data)" && test ! -e /tmp/sandbox_stop_requested'
check "no current_task marker, no fixtures, no stop file left" test $? -eq 0
E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-2B after simulation"' > "$D/verify-after.txt" 2>&1
check "full verify after removing simulation exit 0" test $? -eq 0
cat "$D/verify-after.txt"
E sh -c 'cd /app && python3 -m isolation.verify --dump-normalized' > "$D/normalized-runtime.json"
check "normalized runtime ruleset identical to expected" bash -c "diff <(python3 -m json.tool '$D/normalized-runtime.json') <(python3 -m json.tool '$REPO/sandbox-worker/isolation/expected-ruleset.json') > '$D/normalized-diff.txt'"
E sh -c 'cd /app && python3 -m isolation.verify --sysctl-report "06B-2B end"' > "$D/sysctl-report.txt"; cat "$D/sysctl-report.txt"

# ------------------------------------------------------------------ 5. teardown
log "5. teardown"
docker logs --timestamps "$ID" > "$D/docker-logs-final.txt" 2>&1
docker stop -t 10 "$ID" >/dev/null; check "docker stop exit 0" test $? -eq 0
docker rm "$ID" >/dev/null; check "docker rm exit 0" test $? -eq 0
check "test container removed" bash -c "! docker inspect '$ID' >/dev/null 2>&1"
check "no qemu-system on host" bash -c "! pgrep qemu-system >/dev/null"
sleep 2
host_state after
for f in $(ls "$OUT/host-before"); do
    if diff -u "$OUT/host-before/$f" "$OUT/host-after/$f" > "$OUT/host-diff-$f.diff"; then
        rm "$OUT/host-diff-$f.diff"; echo "unchanged: $f"
    else echo "CHANGED: $f"; cat "$OUT/host-diff-$f.diff"; fi
done
check "host sysctl unchanged" test ! -e "$OUT/host-diff-sysctl.txt.diff"
check "host nft ruleset unchanged" test ! -e "$OUT/host-diff-nft-ruleset-stateless.txt.diff"
check "host IPv4 routes unchanged" test ! -e "$OUT/host-diff-ip-route.txt.diff"
check "host listening ports unchanged" test ! -e "$OUT/host-diff-listen-tcp.txt.diff"
echo "created ids: ${CREATED_IDS[*]}" | tee "$OUT/created-ids.txt"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true

log "result"
if [ ${#FAILS[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "${#FAILS[@]} CHECK(S) FAILED:"; printf ' - %s\n' "${FAILS[@]}"; exit 1
