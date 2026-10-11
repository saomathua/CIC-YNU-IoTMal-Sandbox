#!/bin/bash
# Nhiệm vụ 06B-4I — ARP group (T14-A1, T14-A2, T14-A3, T15-S1) from real guests, ARM then MIPS.
# PREPARED AND TESTED OFFLINE ONLY in 06B-4I/06B-4IR1 (selftest_arp_wiring.py); NOT run. Copy of run-06b4f.sh
# with only these changes (selftest_arp_wiring.py W-tests list them):
#  * H = ct01-06b4ir3 (06B-4IR3); the worker runs probe_matrix.py with CT01_SUITE=arp: ONLY the four reviewed ARP cases of
#    arp_cases.py (06B-4HR2, unchanged) through arp_harness.py; no IPv4 probe, no ICMP case, no case added;
#  * arp_cases.py, arp_harness.py, guest_state.py mounted read-only in /harness (with the ICMP modules that
#    arp_harness reuses: icmp_harness.py, icmp_cases.py, l2frames.py, l2eval.py, signatures.py);
#  * offline self-tests selftest_arp.py and selftest_arp_wiring.py must pass before anything starts (the ICMP
#    ones are kept: arp_harness reuses icmp_harness);
#  * the control container also logs its ARP entry for the worker (ctl_loop.py --arp-worker), checked alive like
#    the other controls; the manager's sandboxnet MAC is passed to the worker (CT01_TARGETS manager_mac): both are
#    inputs of the T14-A1/A2 live controls; 06B-4IR1: ctl's own sandboxnet endpoint MAC is passed too
#    (CT01_TARGETS ctl_mac): it identifies the ctl interface of the ARP entry (no interface name is assumed);
#  * per-architecture outcome from arp_harness.py --outcome, run level from arp_harness.py --run-check.
#  * 06B-4IR3 (PC-1): stop policy between architectures: MIPS is started only if ARM passed every required check
#    (outcome PASS and post-checks); otherwise the loop breaks, the run-level check is skipped (reported), and the
#    teardown/host checks still run; the exit code keeps the cause (FAIL 1 / UNVERIFIED 4).
# Everything else in this script (captures, watcher/heartbeat, leak alerts, scanners, host-state checks, exit
# codes) is run-06b4f.sh unchanged. Inside the worker, probe_matrix.py 06B-4IR1 also guards the boot network
# configuration and the topology gate (startup guard, all suites); 06B-4IR2: the guard is handed over only to a
# guarded branch (the IPv4 branch keeps it for every service link and probe). Guard 20 ms: unmeasured assumption.
#
#   sudo bash /home/dathq/projects/ct01-06b4ir3/run-06b4i.sh   (only when the reviewer allows the run)
#
# ---- HISTORICAL header of run-06b4f.sh (the ICMP script this one was copied from; it does NOT describe what this
# ---- script runs: here the suite is CT01_SUITE=arp and the outcome comes from arp_harness.py):
# Nhiệm vụ 06B-4F — ICMP group (T12-B1, T12-B2, T12-B4, T13-I1, T13-I2) from real guests, ARM then MIPS.
# PREPARED AND TESTED OFFLINE ONLY in 06B-4F (selftest_icmp_wiring.py); NOT run. Copy of run-06b3b.sh
# (06B-4B/4C harness) with only these changes:
#  * the worker runs probe_matrix.py with CT01_SUITE=icmp: ONLY the five reviewed ICMP cases of
#    icmp_cases.py (06B-4ER) through icmp_harness.py; the 20 IPv4 probes are NOT run, no case is added;
#  * icmp_cases.py, icmp_harness.py, l2frames.py, l2eval.py, signatures.py mounted read-only in /harness;
#  * offline self-tests selftest_icmp.py and selftest_icmp_wiring.py must pass before anything starts;
#  * per-architecture outcome from icmp_harness.py --outcome (counter_window.run_outcome on every record +
#    status COMPLETED + each case exactly once + service link before/after HTTP 200 and fixture hash);
#  * run level: icmp_harness.py --run-check (ARM and MIPS each evaluated with the five cases once).
# Boot, topology gate, captures, watcher/heartbeat, leak alerts, scanners, counter reads, session
# measurement, QEMU shutdown, cleanup and host-state checks are those of run-06b3b.sh, unchanged.
# Guard 20 ms: unmeasured assumption. A pass is only "ĐẠT (kiểm quy tắc)".
# 06B-4FR: only H changes in this script; the fixes are in probe_matrix.py (leak alerts also checked
# before every guest command) and icmp_harness.py (required infrastructure confirmations in --outcome).
#
#   sudo bash /home/dathq/projects/ct01-06b4fr/run-06b4f.sh   (06B-4FR: H = ct01-06b4fr)
#
# ---- original header of run-06b3b.sh:
# Nhiệm vụ 06B-3B — IPv4 block matrix from real guests (ARM, then MIPS) with live controls.
# Harness revised in 06B-3C (same 20 probes, no new probe):
#  * signature scan of host pcaps by sigscan.sh (probe URL regex fixed; fixture self-test first);
#  * capture watcher: a capture that dies during the test is FAIL and stops the probes; tcpdump exit
#    codes, kernel drops and pcap read errors are checked;
#  * ip link / addr / route / neigh / rule of the worker netns recorded before and after;
#  * manager restored to its initial state (running stays running and is not restarted).
# Revised in 06B-3DR: timed nft counter reads with boundary zones (counter_window.py); teardown stops
# the controls, drains, then stops captures with a deadline and records a timeline and versions;
# results are PASS (exit 0), FAIL (1), UNVERIFIED (4) or passed-with-open-items (5).
# 06B-3F: a session-wide counter/pcap reconciliation per architecture (session.json) is reported in its
# own section; it does not change the per-probe verdicts or the exit code.
# 06B-4B (harness copy in ct01-06b4b; the 06B-3FR1 copy in ct01-06b3c is unchanged), host side only,
# same 20 probes: ens33 is captured WITHOUT a filter, bounded (snaplen, packet limit: reaching the limit
# ends tcpdump, which the watcher reports as a dead capture); the leak alerts are built from
# signatures.py (alert on `any`: network-layer signatures; alert_eth on the worker veth: + MAC
# signatures, because `ether host` does not compile on LINUX_SLL2); host pcaps are also scanned by
# sigscan_l2.py (guest/spoof MAC, ARP, IPv6, spoofed sources, probe ports/ICMP sizes/qname).
#
#   sudo bash /home/dathq/projects/ct01-06b4b/run-06b3b.sh
#
#  * Worker test container ct01-06b3b-guest: reviewed image (full id pinned), real run.sh (V0),
#    REAL server.py, sentinel poller. sandboxnet, --privileged like compose, --restart no,
#    no published ports, no host network, no lab-data / docker.sock mounts.
#  * The existing sandbox-manager container is used for controls. If it is not running it is started
#    with `docker compose up -d --no-deps --no-build sandbox-manager` and stopped again at the end;
#    if it is already running it is left running and never restarted.
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
H=/home/dathq/projects/ct01-06b4ir3
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
cp "$0" "$H/probe_matrix.py" "$H/ctl_loop.py" "$H/sentinel/poller.py" "$H/harness_lib.sh" "$H/sigscan.sh" \
    "$H/make_fixtures.py" "$H/selftest.sh" "$H/independent_check.sh" "$H/pcapng_stats.py" "$H/mutation_test.sh" \
    "$H/counter_window.py" "$H/signatures.py" "$H/l2frames.py" "$H/guest_state.py" "$H/sigscan_l2.py" \
    "$H/selftest_l2.py" "$H/mutation_l2.py" \
    "$H/icmp_cases.py" "$H/icmp_harness.py" "$H/l2eval.py" "$H/selftest_icmp.py" "$H/selftest_l2eval.py" \
    "$H/selftest_icmp_wiring.py" "$H/run-06b3b.sh" \
    "$H/arp_cases.py" "$H/arp_harness.py" "$H/selftest_arp.py" "$H/selftest_arp_wiring.py" "$H/run-06b4f.sh" \
    "$OUT/harness-copy/"
sha256sum "$OUT"/harness-copy/* | tee "$OUT/harness-sha256.txt"
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
python3 "$H/signatures.py" --check || { echo "ABORT: signature registry invalid"; exit 3; }
eval "$(python3 "$H/signatures.py" --shell)" || { echo "ABORT: signature registry not loadable"; exit 3; }
source "$H/harness_lib.sh"   # alive, start/stop_capture_watch, manager_prepare/restore

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
    stop_captures_deadline "$CAP_DEADLINE_S" "$OUT/hostcap/tcpdump-exit.txt" "$OUT/hostcap/teardown-timeline.txt" "${e[@]}"
    rc=$?
    TCPDUMP_PIDS=(); TCPDUMP_NAMES=()
    return $rc
}
CAPD=""
cleanup() {
    stop_capture_watch
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
    manager_restore >> "$OUT/manager-state.txt" 2>&1 || true   # no-op if teardown already restored it
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
log "2. existing manager for controls (start only if not running: --no-deps --no-build)"
manager_prepare > "$OUT/manager-state.txt" 2>&1; rc=$?
cat "$OUT/manager-state.txt"
[ $rc -eq 0 ] || { echo "ABORT: manager prepare failed (rc=$rc); see manager-state.txt"; exit 3; }
ok=0; for i in $(seq 1 30); do
    python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8011/healthcheck", timeout=2).status==200 else 1)' 2>/dev/null && { ok=1; break; }; sleep 1; done
check "manager healthy (127.0.0.1:8011/healthcheck)" test $ok -eq 1
docker inspect -f 'manager: {{.State.Status}} ip={{(index .NetworkSettings.Networks "'"$SANDBOXNET"'").IPAddress}}' "$MANAGER" | tee -a "$OUT/manager-state.txt"
MANAGER_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").IPAddress}}" "$MANAGER")
# 06B-4B: the manager's real MAC on sandboxnet, so that an ARP claiming 192.168.60.10 with another MAC
# is a signature (sigscan_l2.py arp_spoof_spa_manager)
MANAGER_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").MacAddress}}" "$MANAGER")

# ------------------------------------------------------------------ 3. worker test container
log "3. worker test container"
D="$OUT/container"; mkdir -p "$D/sentinel" "$D/probe"; chmod 777 "$D/sentinel" "$D/probe" "$OUT/ctl" "$OUT/hostcap"
ID=$(docker run -d --name "$NAME" --restart no --privileged --network "$SANDBOXNET" \
    -e PORT=8011 -e APP_BASE_URL=/api/v1/sandbox-worker -e APP_NAME="$NAME" \
    -e SANDBOX_MANAGER_URI=http://sandbox-manager:8011/api/v1/sandbox-manager \
    -e ANALYSIS_DURATION=30 -e POST_ANALYSIS_WAIT=30 -e ALLOW_VM_INTERNET=false \
    -v "$H/sentinel/poller.py:/app/poller.py:ro" -v "$H/probe_matrix.py:/harness/probe_matrix.py:ro" \
    -v "$H/pcapng_stats.py:/harness/pcapng_stats.py:ro" \
    -v "$H/counter_window.py:/harness/counter_window.py:ro" \
    -v "$H/icmp_harness.py:/harness/icmp_harness.py:ro" -v "$H/icmp_cases.py:/harness/icmp_cases.py:ro" \
    -v "$H/l2frames.py:/harness/l2frames.py:ro" -v "$H/l2eval.py:/harness/l2eval.py:ro" \
    -v "$H/signatures.py:/harness/signatures.py:ro" \
    -v "$H/arp_harness.py:/harness/arp_harness.py:ro" -v "$H/arp_cases.py:/harness/arp_cases.py:ro" \
    -v "$H/guest_state.py:/harness/guest_state.py:ro" \
    -v "$D/sentinel:/sentinel-out" -v "$D/probe:/harness-out" \
    -v "$OUT/hostcap:/hostcap:ro" -v "$OUT/ctl:/ctl:ro" \
    "$IMAGE") || { echo "ABORT: docker run failed"; exit 3; }
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
netns_state before
echo "worker netns interfaces: $(cat "$D/netns-before-ifnames.txt")"; cat "$D/netns-before-addr-br.txt" "$D/netns-before-route-main.txt"
check "worker netns has exactly lo, eth0, tap0 (eth0 is the only way out besides tap0)" test "$(cat "$D/netns-before-ifnames.txt")" = "eth0 lo tap0 " \
    || { echo "ABORT: the veth capture would not cover every way out of the worker netns"; exit 3; }

# ------------------------------------------------------------------ 4. control container
log "4. control container (sandboxnet + dbnet)"
CID=$(docker run -d --name "$CTL" --restart no --network "$SANDBOXNET" --entrypoint python3 \
    -v "$H/ctl_loop.py:/ctl_loop.py:ro" -v "$OUT/ctl:/ctl" \
    "$IMAGE" /ctl_loop.py "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" /ctl/ctl.jsonl --arp-worker) || { echo "ABORT: ctl run failed"; exit 3; }
CREATED_IDS+=("$CID")
docker network connect "$DBNET" "$CID"
# 06B-4IR1: ctl's endpoint MAC on sandboxnet, so that the T14-A1 control can bind the ctl ARP entry's interface to
# sandboxnet by MAC (the interface name inside ctl is not assumed)
CTL_MAC=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$SANDBOXNET\").MacAddress}}" "$CID")
echo "ctl sandboxnet endpoint MAC=$CTL_MAC" | tee -a "$OUT/targets-env.txt"
sleep 4
for t in "mongo $MONGO_IP:27017" "worker-eth0 $WORKER_IP:8011" "arp worker-eth0 $WORKER_IP" "manager $MANAGER_IP:8011"; do
    check "control '$t' alive" bash -c "grep -F '\"target\": \"$t\"' '$OUT/ctl/ctl.jsonl' | tail -3 | grep -q '\"ok\": true'"
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
# Watch the four captures for the whole test (1 s). The marker is visible to probe_matrix.py as
# /hostcap/capture-dead.txt; it stops the probes when the marker appears.
DEAD="$OUT/hostcap/capture-dead.txt"
W=(); for i in "${!TCPDUMP_PIDS[@]}"; do W+=("${TCPDUMP_NAMES[$i]}:${TCPDUMP_PIDS[$i]}"); done
HB="$OUT/hostcap/capture-watch.heartbeat"   # /hostcap/capture-watch.heartbeat in the container
start_capture_watch "$DEAD" "$HB" 1 "${W[@]}"
for i in $(seq 1 30); do [ -s "$HB" ] && break; sleep 0.1; done
watch_ok() { alive "$WATCH_PID" && heartbeat_fresh "$HB" 5; }
check "capture watcher running with a fresh heartbeat" watch_ok \
    || { echo "ABORT: capture watcher not running; no guest is booted without it"; exit 3; }
echo "capture watcher pid $WATCH_PID on ${W[*]}"

# ------------------------------------------------------------------ 6. guests, one at a time
TARGETS=$(printf '{"worker_ip":"%s","mongo_ip":"%s","manager_ip":"%s","manager_mac":"%s","ctl_mac":"%s","ssh_ips":["%s","%s","%s"],"lan_dns":"%s"}' \
    "$WORKER_IP" "$MONGO_IP" "$MANAGER_IP" "$MANAGER_MAC" "$CTL_MAC" "$SANDBOX_GW" "$ENS_IP" "$DB_GW" "$LAN_DNS")
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
    check "$ARCH: no QEMU running before start (sequential)" bash -c "! pgrep qemu-system >/dev/null" \
        || { ARCH_STOP="$ARCH: QEMU already running before start: harness not called for $ARCH"; break; }
    check "$ARCH: all host captures alive before start" test ! -s "$DEAD" || break
    check "$ARCH: capture watcher alive with a fresh heartbeat before start" watch_ok || break
    ARCH_CALLED+=("$ARCH")
    timeout 1700 docker exec -e CT01_TARGETS="$TARGETS" -e CT01_SUITE=arp "$ID" sh -c "cd /app && python3 /harness/probe_matrix.py $ARCH /harness-out"
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
    outcome=$(python3 "$H/arp_harness.py" --outcome "$D/probe/$ARCH/result.json" "$D/probe/$ARCH/arp-eval.json" "$ARCH" 2>&1)
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
    E ps -eo pid,args > "$D/ps-after-$ARCH.txt"
    check "$ARCH: no qemu-system/tshark left in container" bash -c "! grep -qE 'qemu-system|tshark' '$D/ps-after-$ARCH.txt'"
    E sh -c 'cd /app && python3 -m isolation.verify --phase "06B-3B after '"$ARCH"'"' > "$D/verify-after-$ARCH.txt" 2>&1
    check "$ARCH: full verify after guest shutdown" test $? -eq 0
    # 06B-4IR3 (PC-1): stop before the NEXT architecture; after the last one (MIPS) there is nothing to stop
    if [ "$ARCH" != MIPS ] && { [ ${#FAILS[@]} -ne "$nf0" ] || [ ${#UNVERIFIED[@]} -ne "$nu0" ]; }; then
        ARCH_STOP="$ARCH did not pass every required check (see FAIL/UNVERIFIED above): the next architecture is not started"
        break
    fi
done
[ -z "$ARCH_STOP" ] && [ ${#ARCH_CALLED[@]} -lt 2 ] && ARCH_STOP="loop left after ${ARCH_CALLED[*]:-no architecture} (stop above)"
if [ -n "$ARCH_STOP" ]; then
    echo "[STOPPED] architecture loop: $ARCH_STOP; harness called for: ${ARCH_CALLED[*]:-none}"
    # never a pass: the loop only stops after a recorded FAIL/UNVERIFIED; this guards the invariant
    [ ${#FAILS[@]} -eq 0 ] && [ ${#UNVERIFIED[@]} -eq 0 ] && fail "architecture loop stopped without a recorded cause: $ARCH_STOP"
    echo "[SKIPPED] ARP run-level check (ARM and MIPS each evaluated): not every architecture was run" | tee "$OUT/arp-run-check.txt"
else
# 06B-4I: both architectures evaluated, each with the four reviewed ARP cases exactly once
python3 "$H/arp_harness.py" --run-check "$D/probe" ARM MIPS > "$OUT/arp-run-check.txt" 2>&1; rc=$?
cat "$OUT/arp-run-check.txt"
check "ARP group evaluated for ARM and MIPS, each case exactly once per architecture" test $rc -eq 0
fi

# ------------------------------------------------------------------ 7. stop captures, analyse host side
netns_state after
check "worker netns interfaces unchanged after the guests" diff -q "$D/netns-before-ifnames.txt" "$D/netns-after-ifnames.txt"
check "worker netns addresses unchanged after the guests" diff -u "$D/netns-before-addr-br.txt" "$D/netns-after-addr-br.txt"
check "worker netns main routes unchanged after the guests" diff -u "$D/netns-before-route-main.txt" "$D/netns-after-route-main.txt"
diff -u "$D/netns-before.txt" "$D/netns-after.txt" > "$D/netns-diff.txt" && echo "worker netns full record: unchanged" \
    || echo "worker netns full record: differences in container/netns-diff.txt (reported, e.g. neighbor states)"

log "7. teardown of controls and captures (drain ${DRAIN_S} s, capture deadline ${CAP_DEADLINE_S} s)"
TL="$OUT/hostcap/teardown-timeline.txt"
timeline "$TL" "guests finished (last probe_matrix returned)"
docker stop -t 5 "$CID" > /dev/null 2>&1; rc=$?
timeline "$TL" "control container stopped (docker stop rc=$rc)"
check "control container stopped after the guests" test $rc -eq 0
sleep "$DRAIN_S"
timeline "$TL" "drain period of ${DRAIN_S} s ended"
check "capture watcher still alive with a fresh heartbeat at the end" watch_ok
stop_capture_watch
timeline "$TL" "capture watcher stopped"
check "no host capture exited during the test (watcher marker empty)" test ! -s "$DEAD"
stop_tcpdumps
check "all host captures exited on SIGINT within ${CAP_DEADLINE_S} s with exit 0" test $? -eq 0
cat "$TL" "$OUT/hostcap/tcpdump-exit.txt"
printf 'capture\tcaptured\treceived_by_filter\tdropped_by_kernel\n' > "$OUT/hostcap/capture-stats.tsv"
for f in veth bridge ens33 alert alert_eth; do
    check "tcpdump $f: exit 0 on stop" grep -qx "$f 0" "$OUT/hostcap/tcpdump-exit.txt"
    st=$(capture_stats "$OUT/hostcap/$f.err")
    check "tcpdump $f: statistics present (captured, received by filter, dropped by kernel)" test -n "$st" || continue
    read -r cap rcv drp <<< "$st"
    printf '%s\t%s\t%s\t%s\n' "$f" "$cap" "$rcv" "$drp" >> "$OUT/hostcap/capture-stats.tsv"
    check "tcpdump $f: 0 packets dropped by kernel" test "$drp" -eq 0
    if [ "$rcv" -ne "$cap" ]; then
        # Reported, not judged: what "received by filter" counts depends on the capture backend and
        # has not been verified for this one; nothing is inferred about which packets these were.
        OPEN_ITEMS+=("tcpdump $f: received by filter ($rcv) - captured ($cap) = $((rcv - cap)), not explained")
        echo "[OPEN] tcpdump $f: received by filter $rcv, captured $cap (difference $((rcv - cap)) not explained)"
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
manager_restore > "$OUT/manager-restore.txt" 2>&1; rc=$?
cat "$OUT/manager-restore.txt"; cat "$OUT/manager-restore.txt" >> "$OUT/manager-state.txt"
check "manager back to its initial state ($MANAGER_STATE_BEFORE; same container; not restarted if it was running)" test $rc -eq 0
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
