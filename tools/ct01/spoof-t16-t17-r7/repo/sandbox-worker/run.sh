#!/bin/bash
# Worker entrypoint. Sets up the isolated guest network (CT-01, PA-2 in
# docs/network-isolation-design.md) inside this container's network namespace,
# verifies it (V0) and only then starts server.py and the poller.
# Fail-closed: any error exits before the poller (and therefore QEMU) starts.
set -euo pipefail
cd /app

if [ "${ALLOW_VM_INTERNET:-false}" != "false" ]; then
    echo "FATAL: ALLOW_VM_INTERNET=${ALLOW_VM_INTERNET} is not supported; guest egress is not designed yet (CT-01)." >&2
    exit 1
fi

eval "$(python3 -m isolation.constants --shell)"

set_sysctl() {  # name value; fails if the key does not exist
    echo "$2" > "/proc/sys/${1//.//}"
}
set_sysctl_if_present() {
    if [ -e "/proc/sys/${1//.//}" ]; then set_sysctl "$1" "$2"; fi
}

# Record configured/effective IPv4 conf values before any change (evidence for eth0 impact).
python3 -m isolation.verify --sysctl-report "before run.sh"

# 1. No forwarding in this namespace; new interfaces start without IPv6.
set_sysctl net.ipv4.ip_forward 0
set_sysctl_if_present net.ipv6.conf.all.forwarding 0
set_sysctl_if_present net.ipv6.conf.default.disable_ipv6 1

# Linux 6.8 uses max(conf.all, conf.<dev>) for rp_filter, arp_ignore, arp_announce
# and arp_accept (isolation/verify.py: KERNEL_COMBINE). conf.all is normalised so
# the per-interface values below are the effective ones on tap0:
#   rp_filter    all=1 -> tap0 strict (1). eth0 keeps max(1, its own value).
#   arp_ignore   all=0 -> tap0 effective = 1.
#   arp_accept   all=0 -> tap0 effective = 0.
#   arp_announce not normalised: max(all, 2) = 2 for every valid all (0..2).
set_sysctl net.ipv4.conf.all.rp_filter 1
set_sysctl net.ipv4.conf.all.arp_ignore 0
set_sysctl net.ipv4.conf.all.arp_accept 0

# 2. Dedicated guest link. eth0 (sandboxnet) is left untouched.
if ip link show "$GUEST_IF" >/dev/null 2>&1; then
    ip link del "$GUEST_IF"
fi
ip tuntap add dev "$GUEST_IF" mode tap
set_sysctl_if_present "net.ipv6.conf.${GUEST_IF}.disable_ipv6" 1
set_sysctl "net.ipv4.conf.${GUEST_IF}.arp_ignore" 1
set_sysctl "net.ipv4.conf.${GUEST_IF}.arp_announce" 2
set_sysctl "net.ipv4.conf.${GUEST_IF}.arp_accept" 0
set_sysctl "net.ipv4.conf.${GUEST_IF}.rp_filter" 1
ip addr add "${WORKER_GUEST_IP}/${GUEST_PREFIX}" dev "$GUEST_IF"
ip link set "$GUEST_IF" up
ip neigh replace "$GUEST_IP" lladdr "$GUEST_MAC" dev "$GUEST_IF" nud permanent

# 3. Firewall: delete-and-load the three CT-01 tables in ONE nft transaction
#    (isolation/load.nft). On error nothing is changed; on first start that
#    means no tables exist, and set -e stops here (fail-closed).
nft -f /app/isolation/load.nft

# 4. V0: compare against the reviewed expected ruleset and check sysctl (configured and
#    effective)/link/neighbor/route.
python3 -m isolation.verify --sysctl-report "after run.sh"
python3 -m isolation.verify --phase "V0 startup"

# 5. Services. The poller clears any stale current_task marker at startup.
(while true; do python3 server.py; echo "server.py exited, restarting..."; sleep 2; done) &
exec python3 poller.py
