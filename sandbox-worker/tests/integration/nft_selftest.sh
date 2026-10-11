#!/bin/bash
# Real-nft self test for CT-01 (Nhiệm vụ 06B-1).
#
# Runs ONLY inside a throwaway container started with --network none and an
# overridden entrypoint (run.sh, server.py, poller.py and QEMU are never run):
#
#   sudo docker run --rm --network none --cap-add NET_ADMIN --device /dev/net/tun \
#     --entrypoint /bin/bash \
#     -v "$PWD/sandbox-worker/tests:/tests:ro" -v "$OUT:/out" \
#     sandbox-worker:latest /tests/integration/nft_selftest.sh
#
# Creates tap0 in the container's own namespace, loads isolation/guest.nft,
# writes the normalised ruleset as a CANDIDATE expected file for human review
# (/out/generated-expected-ruleset.json) and runs mutation and transaction tests.
# Scope: only the three CT-01 tables are compared, not the whole namespace ruleset.
set -euo pipefail
OUT=/out
cd /app
exec > >(tee "$OUT/selftest.log") 2>&1

echo "== environment"
date -u
uname -r
nft --version | tee "$OUT/nft-version.txt"
dpkg-query -W nftables libnftables1 libnftnl11 libjansson4 iproute2 | tee "$OUT/packages.txt"
ip -br link
test "$(ip -br link | awk '{print $1}' | sort | tr '\n' ' ')" = "lo " || { echo "FATAL: expected only lo (--network none)"; exit 1; }

echo "== guest link (container namespace only)"
eval "$(python3 -m isolation.constants --shell)"
ip tuntap add dev "$GUEST_IF" mode tap
ip addr add "${WORKER_GUEST_IP}/${GUEST_PREFIX}" dev "$GUEST_IF"
ip link set "$GUEST_IF" up
ip neigh replace "$GUEST_IP" lladdr "$GUEST_MAC" dev "$GUEST_IF" nud permanent
ip -d link show "$GUEST_IF"; ip addr show "$GUEST_IF"; ip neigh show dev "$GUEST_IF"; ip route

echo "== first load via load.nft (single transaction, CT-01 tables absent)"
nft list tables
nft -f /app/isolation/load.nft
nft list ruleset > "$OUT/ruleset.txt"
nft -j list ruleset > "$OUT/raw-ruleset.json"
python3 -m isolation.verify --dump-normalized > "$OUT/generated-expected-ruleset.json"
sha256sum /app/isolation/guest.nft /app/isolation/load.nft "$OUT/generated-expected-ruleset.json" | tee "$OUT/sha256.txt"

echo "== mutation tests"
python3 /tests/integration/nft_selftest.py \
    --baseline "$OUT/generated-expected-ruleset.json" \
    --repo-expected /app/isolation/expected-ruleset.json
