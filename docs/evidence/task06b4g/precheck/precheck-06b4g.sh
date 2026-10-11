#!/bin/bash
# 06B-4G precheck — READ ONLY. Starts/stops nothing, changes nothing, prints no env/.env/secret.
#   sudo bash /home/dathq/projects/ct01-06b4g-work/precheck-06b4g.sh
set -u
D=/home/dathq/projects/ct01-06b4g-work/precheck
H=/home/dathq/projects/ct01-06b4fr
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ -e "$D" ] && { echo "ABORT: $D exists (keep it)"; exit 2; }
mkdir -p "$D"
{
    echo "== time"; date -u
    echo "== image (full id; expected sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153)"
    docker image inspect -f '{{.Id}}' sandbox-worker:latest
    echo "== containers"; docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'
    echo "== manager"; docker inspect -f '{{.Name}} {{.State.Status}} id={{.Id}} restarts={{.RestartCount}}' cic-ynu-iotmal-sandbox-sandbox-manager-1
    echo "== test containers of the harness (must not exist)"
    for c in ct01-06b3b-guest ct01-06b3b-ctl; do docker inspect "$c" >/dev/null 2>&1 && echo "PRESENT: $c" || echo "absent: $c"; done
    echo "== networks"; docker network ls --format '{{.Name}} {{.Driver}} {{.Labels}}'
    echo "== processes (qemu / capture / harness)"
    pgrep -a qemu-system || echo "no qemu-system"
    pgrep -a 'tcpdump|tshark|dumpcap' || echo "no capture processes"
    pgrep -af 'run-06b|probe_matrix|selftest|mutation_' | grep -v pgrep || echo "no harness processes"
    echo "== output dir (must not exist)"; ls -ld "$H/out" 2>&1
    echo "== /tmp capture dirs of earlier runs"; ls -d /tmp/ct01-06b3b-cap.* 2>&1
    echo "== AppArmor (tool setup, recorded separately from CT-01)"; aa-status 2>&1 | head -5
    aa-status 2>&1 | grep -iE 'tcpdump|bwrap|unpriv' || echo "(no tcpdump/bwrap entry in aa-status)"
} 2>&1 | tee "$D/precheck.txt"
nft -s list ruleset > "$D/nft-ruleset-stateless.txt" 2>&1
aa-status > "$D/aa-status.txt" 2>&1
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$D"
echo "precheck written to $D"
