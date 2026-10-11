#!/bin/bash
# 06B-4IR2 precheck, Docker part — READ ONLY. Prepared, NOT run by Claude (no docker access without sudo).
#   sudo bash /home/dathq/projects/ct01-06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh
# Starts/stops/creates nothing, pulls/builds nothing, changes no network/ruleset, sends nothing to a guest.
# Prints no environment variable, .env or Config.Env: only explicit inspect fields (templates below).
# docker exec is used ONLY for the manager, ONLY if it is already running, ONLY for read-only commands
# (command -v ip; ip -V; ip -j neigh show; cat /proc/net/arp; /sys/class/net/*/address,operstate).
# The worker test container and ctl container do not exist outside a run (the run script creates them), so their
# netns/interfaces/MACs cannot be read here; they are NOT created for this precheck.
set -u
D=/home/dathq/projects/ct01-06b4ir2-precheck/docker-readonly
SANDBOXNET_LABEL=sandboxnet; DBNET_LABEL=dbnet
MANAGER=cic-ynu-iotmal-sandbox-sandbox-manager-1
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ -e "$D" ] && { echo "ABORT: $D exists (keep it)"; exit 2; }
mkdir -p "$D"
SN=$(docker network ls --filter label=com.docker.compose.network=$SANDBOXNET_LABEL --format '{{.Name}}')
DN=$(docker network ls --filter label=com.docker.compose.network=$DBNET_LABEL --format '{{.Name}}')
{
    echo "== time"; date -u +%FT%TZ
    echo "== docker version"; docker version --format 'client={{.Client.Version}} server={{.Server.Version}} api={{.Server.APIVersion}}'
    echo "== docker info (selected fields)"
    docker info --format 'driver={{.Driver}} cgroup={{.CgroupDriver}}/{{.CgroupVersion}} kernel={{.KernelVersion}} os={{.OperatingSystem}} containers={{.Containers}} running={{.ContainersRunning}} images={{.Images}}'
    echo "== image (expected sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153)"
    docker image inspect -f 'id={{.Id}} created={{.Created}} tags={{.RepoTags}} arch={{.Architecture}}' sandbox-worker:latest
    echo "== containers"; docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'
    echo "== harness containers (must not exist)"
    for c in ct01-06b3b-guest ct01-06b3b-ctl; do docker inspect "$c" >/dev/null 2>&1 && echo "PRESENT: $c" || echo "absent: $c"; done
    echo "== networks"; echo "sandboxnet=$SN dbnet=$DN"
    for n in "$SN" "$DN"; do
        [ -n "$n" ] || { echo "network missing"; continue; }
        docker network inspect -f 'name={{.Name}} id={{.Id}} driver={{.Driver}} internal={{.Internal}} subnets={{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}} {{end}}' "$n"
        echo "bridge=br-$(docker network inspect -f '{{.Id}}' "$n" | cut -c1-12)"
        docker network inspect -f '{{range $id, $c := .Containers}}endpoint {{$c.Name}} ip={{$c.IPv4Address}} mac={{$c.MacAddress}}{{"\n"}}{{end}}' "$n"
    done
    echo "== manager"
    docker inspect -f 'state={{.State.Status}} id={{.Id}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$MANAGER"
    docker inspect -f '{{range $n, $s := .NetworkSettings.Networks}}net={{$n}} ip={{$s.IPAddress}} mac={{$s.MacAddress}}{{"\n"}}{{end}}' "$MANAGER"
    echo "== mongo-db"
    docker inspect -f 'state={{.State.Status}} {{range $n, $s := .NetworkSettings.Networks}}net={{$n}} ip={{$s.IPAddress}} mac={{$s.MacAddress}} {{end}}' mongo-db
    echo "== processes"; pgrep -a qemu-system || echo "no qemu-system"; pgrep -a 'tcpdump|tshark|dumpcap' || echo "no capture processes"
} 2>&1 | tee "$D/docker-readonly.txt"
if [ "$(docker inspect -f '{{.State.Status}}' "$MANAGER" 2>/dev/null)" = running ]; then
    {
        echo "== manager (already running): read-only commands"
        docker exec "$MANAGER" sh -c 'command -v ip || echo "no ip"; ip -V 2>&1 || true'
        echo "-- ip -j neigh show"; docker exec "$MANAGER" ip -j neigh show 2>&1; echo "rc=$?"
        echo "-- /proc/net/arp"; docker exec "$MANAGER" cat /proc/net/arp 2>&1
        echo "-- /sys/class/net"; docker exec "$MANAGER" sh -c 'for i in /sys/class/net/*; do echo "$(basename $i) $(cat $i/address) $(cat $i/operstate)"; done' 2>&1
    } > "$D/manager-readonly.txt" 2>&1
else
    echo "manager not running: no docker exec (it is NOT started for this precheck)" > "$D/manager-readonly.txt"
fi
nft -s list ruleset > "$D/nft-ruleset-stateless.txt" 2>&1
aa-status > "$D/aa-status.txt" 2>&1
sha256sum "$D"/* > "$D/SHA256SUMS"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$D"
echo "precheck written to $D"
