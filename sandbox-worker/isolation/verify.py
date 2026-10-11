"""Guest network isolation checks (CT-01, docs/network-isolation-design.md §6).

V0 runs from run.sh at container startup (CLI); V1/V2 run from
service/analysis.py right before each QEMU spawn (verify_isolation()).
Any failure raises IsolationError so that QEMU is never started.

The loaded nftables ruleset is compared, after normalisation, with the
reviewed file expected-ruleset.json. The expected file is generated only in a
separate test container (tests/integration/nft_selftest.sh) and stored in the
repository for human review (until commit it lives in the working tree);
it is never derived from the runtime ruleset.

Scope: only the three CT-01 tables (constants.NFT_TABLES) are compared. Other
tables in the worker's namespace (e.g. ones Docker creates for its embedded
DNS) are not inspected.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Sequence

from isolation import constants as C

EXPECTED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected-ruleset.json")
ALL_CHECKS = ("ruleset", "sysctl", "link", "neighbor", "route")

# Keys whose values change at runtime without any structural change.
_VOLATILE_KEYS = frozenset({"handle", "packets", "bytes"})

Runner = Callable[[Sequence[str]], str]
SysctlReader = Callable[[str], Optional[str]]


class IsolationError(RuntimeError):
    pass


def _run(cmd: Sequence[str]) -> str:
    return subprocess.run(list(cmd), check=True, capture_output=True, text=True).stdout


def _read_sysctl(name: str) -> Optional[str]:
    path = "/proc/sys/" + name.replace(".", "/")
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


# --------------------------------------------------------------------------- ruleset

def _strip(obj):
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def normalize(nft_json: dict) -> list:
    """Normalise one `nft -j list table ...` document.

    Drops metainfo and volatile keys (handles, counter packets/bytes) while
    keeping every structural element: family, table/chain names, type, hook,
    prio, policy, dev, rule order and all match/verdict expressions.
    """
    return [_strip(item) for item in nft_json.get("nftables", []) if "metainfo" not in item]


def nft_version(run: Runner = _run) -> str:
    return run(["nft", "--version"]).strip()


def dump_normalized(run: Runner = _run) -> Dict[str, list]:
    tables = {}
    for family, table in C.NFT_TABLES:
        tables[f"{family} {table}"] = normalize(json.loads(run(["nft", "-j", "list", "table", family, table])))
    return tables


def load_expected(path: str = EXPECTED_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def compare_ruleset(actual: Dict[str, list], expected: Dict[str, list]) -> List[str]:
    problems = []
    for key in sorted(set(expected) | set(actual)):
        if key not in actual:
            problems.append(f"ruleset: table '{key}' missing")
            continue
        if key not in expected:
            problems.append(f"ruleset: unexpected table '{key}'")
            continue
        a, e = actual[key], expected[key]
        if a == e:
            continue
        for i in range(max(len(a), len(e))):
            ai = a[i] if i < len(a) else None
            ei = e[i] if i < len(e) else None
            if ai != ei:
                problems.append(
                    f"ruleset: table '{key}' differs at item {i}: "
                    f"expected={json.dumps(ei, sort_keys=True)} actual={json.dumps(ai, sort_keys=True)}")
                break
    return problems


# nft 1.0.2 omits the "dev" key of netdev chains in `nft -j` output, so the
# device binding is checked separately from the text listing (found by the
# 06B-1 real-nft mutation test "netdev device tap0 -> lo").
_DEVICE_RE = re.compile(r"hook\s+ingress\s+(?:devices\s*=\s*\{([^}]*)\}|device\s+\"?([\w.:-]+)\"?)")


def netdev_devices(text: str) -> List[List[str]]:
    """Devices bound by each `hook ingress` base chain in an `nft list` text listing."""
    chains = []
    for many, one in _DEVICE_RE.findall(text):
        names = [d.strip().strip('"') for d in many.split(",")] if many else [one]
        chains.append(sorted(n for n in names if n))
    return chains


def check_netdev_device(run: Runner = _run) -> List[str]:
    problems = []
    for family, table in C.NFT_TABLES:
        if family != "netdev":
            continue
        chains = netdev_devices(run(["nft", "list", "table", family, table]))
        if chains != [[C.GUEST_IF]]:
            problems.append(f"ruleset: {family} {table} ingress devices {chains}, expected [['{C.GUEST_IF}']]")
    return problems


def check_ruleset(run: Runner = _run, expected_path: str = EXPECTED_PATH) -> List[str]:
    try:
        expected = load_expected(expected_path)
    except (OSError, ValueError) as e:
        return [f"ruleset: cannot read expected ruleset: {e}"]
    try:
        version = nft_version(run)
        actual = dump_normalized(run)
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        return [f"ruleset: cannot list loaded ruleset: {e}"]
    problems = []
    if version != expected.get("nft_version"):
        problems.append(f"ruleset: nft version '{version}' != expected '{expected.get('nft_version')}'")
    problems += compare_ruleset(actual, expected.get("tables", {}))
    try:
        problems += check_netdev_device(run)
    except (OSError, subprocess.CalledProcessError) as e:
        problems.append(f"ruleset: cannot list netdev table: {e}")
    return problems


# --------------------------------------------------------------------------- sysctl

# How Linux 6.8 combines conf/all/<attr> with conf/<dev>/<attr>
# (include/linux/inetdevice.h at v6.8):
#   IN_DEV_RPFILTER     = IN_DEV_MAXCONF(RP_FILTER)      -> max(all, dev)
#   IN_DEV_ARP_IGNORE   = IN_DEV_MAXCONF(ARP_IGNORE)     -> max(all, dev)
#   IN_DEV_ARP_ANNOUNCE = IN_DEV_MAXCONF(ARP_ANNOUNCE)   -> max(all, dev)
#   IN_DEV_ARP_ACCEPT   = IN_DEV_MAXCONF(ARP_ACCEPT)     -> max(all, dev)  (tri-state since 6.0)
#   IN_DEV_FORWARD      = IN_DEV_CONF_GET(FORWARDING)    -> dev only
# conf/default only seeds interfaces created later; it never enters these formulas.
KERNEL_COMBINE = {
    "rp_filter": "max",
    "arp_ignore": "max",
    "arp_announce": "max",
    "arp_accept": "max",
    "forwarding": "dev",
}

# Required EFFECTIVE values on the guest interface (design §4.2/§4.4).
GUEST_EFFECTIVE = {
    "rp_filter": 1,       # strict
    "arp_ignore": 1,
    "arp_announce": 2,
    "arp_accept": 0,
    "forwarding": 0,
}

# Required CONFIGURED values (what run.sh writes), checked in addition to the effective ones.
REQUIRED_CONFIGURED = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.rp_filter": "1",
    f"net.ipv4.conf.{C.GUEST_IF}.rp_filter": "1",
    f"net.ipv4.conf.{C.GUEST_IF}.arp_ignore": "1",
    f"net.ipv4.conf.{C.GUEST_IF}.arp_announce": "2",
    f"net.ipv4.conf.{C.GUEST_IF}.arp_accept": "0",
    f"net.ipv4.conf.{C.GUEST_IF}.forwarding": "0",
}


def _int_or_none(v: Optional[str]) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def effective(attr: str, dev: str, read: SysctlReader = _read_sysctl) -> Optional[int]:
    """Effective IPv4 conf value of attr on dev, using the kernel 6.8 combination rule."""
    d = _int_or_none(read(f"net.ipv4.conf.{dev}.{attr}"))
    if KERNEL_COMBINE[attr] == "dev":
        return d
    a = _int_or_none(read(f"net.ipv4.conf.all.{attr}"))
    if a is None or d is None:
        return None
    return max(a, d)


def sysctl_report(devs=("all", "default", C.GUEST_IF, "eth0"), read: SysctlReader = _read_sysctl) -> List[str]:
    """Configured values per scope and effective values per real interface."""
    lines = [f"net.ipv4.ip_forward={read('net.ipv4.ip_forward')}"]
    for attr in KERNEL_COMBINE:
        conf = " ".join(f"{d}={read(f'net.ipv4.conf.{d}.{attr}')}" for d in devs)
        eff = " ".join(f"{d}={effective(attr, d, read)}" for d in devs if d not in ("all", "default"))
        lines.append(f"{attr} [{KERNEL_COMBINE[attr]}] configured: {conf} | effective: {eff}")
    return lines


def check_sysctls(read: SysctlReader = _read_sysctl) -> List[str]:
    want = dict(REQUIRED_CONFIGURED)
    ipv6_present = read("net.ipv6.conf.all.forwarding") is not None
    if ipv6_present:
        want["net.ipv6.conf.all.forwarding"] = "0"
        want[f"net.ipv6.conf.{C.GUEST_IF}.disable_ipv6"] = "1"
    problems = []
    for name, value in want.items():
        got = read(name)
        if got != value:
            problems.append(f"sysctl: {name}={got!r}, expected {value!r}")
    for attr, value in GUEST_EFFECTIVE.items():
        eff = effective(attr, C.GUEST_IF, read)
        if eff != value:
            problems.append(
                f"sysctl: effective {attr} on {C.GUEST_IF}={eff!r} ({KERNEL_COMBINE[attr]} of "
                f"all={read(f'net.ipv4.conf.all.{attr}')!r}, {C.GUEST_IF}={read(f'net.ipv4.conf.{C.GUEST_IF}.{attr}')!r}), "
                f"expected {value}")
    return problems


# --------------------------------------------------------------------------- link / addr

def check_links(run: Runner = _run, uplink: str = "eth0") -> List[str]:
    problems = []
    links = json.loads(run(["ip", "-j", "-d", "link", "show"]))
    by_name = {l.get("ifname"): l for l in links}
    for l in links:
        if (l.get("linkinfo") or {}).get("info_kind") == "bridge":
            problems.append(f"link: bridge interface '{l.get('ifname')}' present")
    tap = by_name.get(C.GUEST_IF)
    if tap is None:
        return problems + [f"link: {C.GUEST_IF} missing"]
    info = tap.get("linkinfo") or {}
    if info.get("info_kind") != "tun" or (info.get("info_data") or {}).get("type") != "tap":
        problems.append(f"link: {C.GUEST_IF} is not a tap device ({info})")
    if tap.get("master"):
        problems.append(f"link: {C.GUEST_IF} has master '{tap['master']}'")

    addrs = json.loads(run(["ip", "-j", "addr", "show", "dev", C.GUEST_IF]))
    got = sorted(f"{a['family']} {a['local']}/{a['prefixlen']}"
                 for entry in addrs for a in entry.get("addr_info", []))
    want = [f"inet {C.WORKER_GUEST_IP}/{C.GUEST_PREFIX}"]
    if got != want:
        problems.append(f"link: {C.GUEST_IF} addresses {got}, expected {want}")

    if uplink:
        up = json.loads(run(["ip", "-j", "addr", "show", "dev", uplink]))
        v4 = [a for entry in up for a in entry.get("addr_info", []) if a.get("family") == "inet"]
        if not v4:
            problems.append(f"link: {uplink} has no IPv4 address")
        for a in v4:
            if ipaddress.ip_address(a["local"]) in C.GUEST_NET:
                problems.append(f"link: {uplink} address {a['local']} inside guest network")

    # 06B-2BR: scan IPv4 addresses on EVERY interface of the namespace. The only
    # address allowed to touch the guest network is 10.200.0.1/30 on tap0;
    # any other address inside 10.200.0.0/30, or whose prefix overlaps it, on any
    # interface (lo included) is a failure. No runtime exceptions.
    allowed = (C.GUEST_IF, ipaddress.ip_interface(f"{C.WORKER_GUEST_IP}/{C.GUEST_PREFIX}"))
    for entry in json.loads(run(["ip", "-j", "addr", "show"])):
        ifname = entry.get("ifname")
        for a in entry.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            iface = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
            if (ifname, iface) == allowed:
                continue
            if iface.ip in C.GUEST_NET or iface.network.overlaps(C.GUEST_NET):
                problems.append(f"link: address {iface} on {ifname} is inside/overlaps guest network "
                                f"{C.GUEST_NET} (only {allowed[1]} on {allowed[0]} is allowed)")
    return problems


def check_neighbor(run: Runner = _run) -> List[str]:
    neigh = json.loads(run(["ip", "-j", "neigh", "show", "dev", C.GUEST_IF]))
    for n in neigh:
        if n.get("dst") == C.GUEST_IP:
            if (n.get("lladdr") or "").lower() != C.GUEST_MAC or "PERMANENT" not in (n.get("state") or []):
                return [f"neighbor: {C.GUEST_IP} is {n.get('lladdr')} {n.get('state')}, "
                        f"expected {C.GUEST_MAC} PERMANENT"]
            return []
    return [f"neighbor: no entry for {C.GUEST_IP} on {C.GUEST_IF}"]


def check_routes(run: Runner = _run) -> List[str]:
    problems = []
    v4 = json.loads(run(["ip", "-j", "-4", "route", "show", "dev", C.GUEST_IF]))
    for r in v4:
        if r.get("dst") != str(C.GUEST_NET) or r.get("gateway"):
            problems.append(f"route: unexpected IPv4 route via {C.GUEST_IF}: {r}")
    if not any(r.get("dst") == str(C.GUEST_NET) for r in v4):
        problems.append(f"route: connected route {C.GUEST_NET} on {C.GUEST_IF} missing")
    try:
        v6 = json.loads(run(["ip", "-j", "-6", "route", "show", "dev", C.GUEST_IF]) or "[]")
    except subprocess.CalledProcessError:
        v6 = []
    if v6:
        problems.append(f"route: IPv6 routes on {C.GUEST_IF}: {v6}")
    return problems


# --------------------------------------------------------------------------- entry points

def run_checks(checks: Sequence[str] = ALL_CHECKS, run: Runner = _run,
               read: SysctlReader = _read_sysctl, expected_path: str = EXPECTED_PATH,
               uplink: str = "eth0") -> List[str]:
    problems = []
    for name in checks:
        try:
            if name == "ruleset":
                problems += check_ruleset(run, expected_path)
            elif name == "sysctl":
                problems += check_sysctls(read)
            elif name == "link":
                problems += check_links(run, uplink)
            elif name == "neighbor":
                problems += check_neighbor(run)
            elif name == "route":
                problems += check_routes(run)
            else:
                problems.append(f"unknown check '{name}'")
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as e:
            problems.append(f"{name}: check could not run: {e}")
    return problems


def verify_isolation(phase: str, **kwargs) -> None:
    """Raise IsolationError unless every isolation check passes."""
    problems = run_checks(**kwargs)
    if problems:
        raise IsolationError(f"network isolation check failed ({phase}): " + "; ".join(problems))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--phase", default="startup")
    p.add_argument("--checks", default=",".join(ALL_CHECKS))
    p.add_argument("--expected", default=EXPECTED_PATH)
    p.add_argument("--uplink", default="eth0")
    p.add_argument("--sysctl-report", metavar="LABEL",
                   help="print configured and effective IPv4 conf values (all/default/tap0/eth0) and exit 0")
    p.add_argument("--dump-normalized", action="store_true",
                   help="print the normalised loaded ruleset (test container only; never used as reference at startup)")
    args = p.parse_args(argv)

    if args.sysctl_report:
        for line in sysctl_report():
            print(f"SYSCTL REPORT ({args.sysctl_report}): {line}")
        return 0

    if args.dump_normalized:
        print(json.dumps({"nft_version": nft_version(), "tables": dump_normalized()}, indent=2, sort_keys=True))
        return 0

    checks = [c for c in args.checks.split(",") if c]
    problems = run_checks(checks, expected_path=args.expected, uplink=args.uplink)
    if problems:
        for pr in problems:
            print(f"ISOLATION FAIL ({args.phase}): {pr}", file=sys.stderr)
        return 1
    print(f"ISOLATION OK ({args.phase}): {','.join(checks)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
