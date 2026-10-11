"""Fixed guest-network constants (CT-01, docs/network-isolation-design.md §4.1).

These values are deliberately not configurable through the environment: the
reviewed expected ruleset (expected-ruleset.json) is a static artefact and
must match guest.nft exactly. Changing any value here requires updating
guest.nft and regenerating/re-reviewing expected-ruleset.json.
"""
import ipaddress
import sys

GUEST_IF = "tap0"
GUEST_NET = ipaddress.ip_network("10.200.0.0/30")
GUEST_PREFIX = GUEST_NET.prefixlen
WORKER_GUEST_IP = "10.200.0.1"
GUEST_IP = "10.200.0.2"
GUEST_MAC = "52:54:00:c7:00:02"
SVC_PORT = 8011

# (family, table) loaded from guest.nft and compared against the expected ruleset.
NFT_TABLES = (
    ("netdev", "sandbox_guest_l2"),
    ("arp", "sandbox_guest_arp"),
    ("inet", "sandbox_guest"),
)

# Written by the poller before phase 1 and removed on every exit path.
CURRENT_TASK_FILE = "/run/sandbox/current_task"


def shell_exports() -> str:
    return "\n".join([
        f"GUEST_IF={GUEST_IF}",
        f"GUEST_PREFIX={GUEST_PREFIX}",
        f"WORKER_GUEST_IP={WORKER_GUEST_IP}",
        f"GUEST_IP={GUEST_IP}",
        f"GUEST_MAC={GUEST_MAC}",
        f"SVC_PORT={SVC_PORT}",
    ])


if __name__ == "__main__" and sys.argv[1:] == ["--shell"]:
    print(shell_exports())
