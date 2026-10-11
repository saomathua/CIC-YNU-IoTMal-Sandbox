"""Unit tests for isolation/verify.py (normalisation and the non-nft checks).

The real nft behaviour (actual JSON produced by the kernel/nft) is covered by
tests/integration/nft_selftest.py, run in a separate --network none container.
"""
import copy
import json
import os
import re

import pytest

from isolation import constants as C
from isolation import verify as V


def _doc(table_items, packets=0, handle_base=1):
    """A document shaped like `nft -j list table netdev sandbox_guest_l2`."""
    items = [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}]
    h = handle_base
    for it in table_items:
        it = copy.deepcopy(it)
        kind = next(iter(it))
        it[kind]["handle"] = h
        h += 1
        if kind == "counter":
            it[kind]["packets"] = packets
            it[kind]["bytes"] = packets * 60
        if kind == "rule":
            for e in it[kind]["expr"]:
                if isinstance(e.get("counter"), dict):
                    e["counter"] = {"packets": packets, "bytes": packets * 60}
        items.append(it)
    return {"nftables": items}


L2_ITEMS = [
    {"table": {"family": "netdev", "name": "sandbox_guest_l2"}},
    {"counter": {"family": "netdev", "name": "l2_bad_mac", "table": "sandbox_guest_l2"}},
    {"chain": {"family": "netdev", "table": "sandbox_guest_l2", "name": "ingress", "type": "filter",
               "hook": "ingress", "prio": -500, "policy": "accept", "dev": "tap0"}},
    {"rule": {"family": "netdev", "table": "sandbox_guest_l2", "chain": "ingress", "expr": [
        {"match": {"op": "!=", "left": {"payload": {"protocol": "ether", "field": "saddr"}},
                   "right": "52:54:00:c7:00:02"}},
        {"counter": "l2_bad_mac"}, {"drop": None}]}},
    {"rule": {"family": "netdev", "table": "sandbox_guest_l2", "chain": "ingress", "expr": [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "tap0"}},
        {"counter": {}}, {"accept": None}]}},
]
KEY = "netdev sandbox_guest_l2"


def _norm(packets=0, handle_base=1, items=L2_ITEMS):
    return {KEY: V.normalize(_doc(items, packets, handle_base))}


def test_normalize_drops_metainfo_handles_and_counter_values():
    n = V.normalize(_doc(L2_ITEMS, packets=7))
    s = json.dumps(n)
    assert "metainfo" not in s and "handle" not in s and "packets" not in s and "bytes" not in s
    assert {"counter": {"family": "netdev", "name": "l2_bad_mac", "table": "sandbox_guest_l2"}} in n
    assert n[-1]["rule"]["expr"][1] == {"counter": {}}
    assert n[2]["chain"]["dev"] == "tap0" and n[2]["chain"]["prio"] == -500


def test_counter_and_handle_changes_do_not_fail():
    expected = _norm(packets=0, handle_base=1)
    actual = _norm(packets=12345, handle_base=40)
    assert V.compare_ruleset(actual, expected) == []


def _mutated(fn):
    items = copy.deepcopy(L2_ITEMS)
    fn(items)
    return _norm(items=items)


@pytest.mark.parametrize("name,mutation", [
    ("add rule", lambda it: it.append({"rule": {"family": "netdev", "table": "sandbox_guest_l2",
                                                "chain": "ingress", "expr": [{"accept": None}]}})),
    ("delete rule", lambda it: it.pop(3)),
    ("reorder rules", lambda it: it.__setitem__(slice(3, 5), [it[4], it[3]])),
    ("policy", lambda it: it[2]["chain"].__setitem__("policy", "drop")),
    ("hook", lambda it: it[2]["chain"].__setitem__("hook", "egress")),
    ("prio", lambda it: it[2]["chain"].__setitem__("prio", 0)),
    ("device", lambda it: it[2]["chain"].__setitem__("dev", "eth0")),
    ("address", lambda it: it[3]["rule"]["expr"][0]["match"].__setitem__("right", "52:54:00:c7:00:03")),
    ("verdict", lambda it: it[3]["rule"]["expr"].__setitem__(2, {"accept": None})),
    ("named counter removed", lambda it: it.pop(1)),
])
def test_structural_changes_fail(name, mutation):
    problems = V.compare_ruleset(_mutated(mutation), _norm())
    assert problems, name
    assert problems[0].startswith("ruleset: table 'netdev sandbox_guest_l2' differs")


def test_missing_and_extra_tables_fail():
    expected = _norm()
    assert V.compare_ruleset({}, expected) == ["ruleset: table 'netdev sandbox_guest_l2' missing"]
    extra = dict(expected, **{"inet other": []})
    assert V.compare_ruleset(extra, expected) == ["ruleset: unexpected table 'inet other'"]


# Text listing as printed by nftables v1.0.2 in the 06B-1 test container.
NETDEV_TEXT = """table netdev sandbox_guest_l2 {
\tcounter l2_bad_mac {
\t\tpackets 0 bytes 0
\t}

\tchain ingress {
\t\ttype filter hook ingress device "tap0" priority -500; policy accept;
\t\tether saddr != 52:54:00:c7:00:02 counter name "l2_bad_mac" drop
\t}
}
"""


def _fake_nft(doc_by_table, version="nftables v1.0.2 (Lester Gooch)", netdev_text=NETDEV_TEXT):
    def run(cmd):
        if list(cmd) == ["nft", "--version"]:
            return version + "\n"
        if list(cmd) == ["nft", "list", "table", "netdev", "sandbox_guest_l2"]:
            return netdev_text
        assert cmd[:4] == ["nft", "-j", "list", "table"]
        return json.dumps(doc_by_table[f"{cmd[4]} {cmd[5]}"])
    return run


@pytest.fixture
def three_tables(monkeypatch):
    monkeypatch.setattr(C, "NFT_TABLES", (("netdev", "sandbox_guest_l2"),))
    return {KEY: _doc(L2_ITEMS, packets=3)}


def _write_expected(tmp_path, tables, version="nftables v1.0.2 (Lester Gooch)"):
    p = tmp_path / "expected.json"
    p.write_text(json.dumps({"nft_version": version, "tables": tables}))
    return str(p)


def test_check_ruleset_ok_and_version_mismatch(tmp_path, three_tables):
    path = _write_expected(tmp_path, _norm())
    assert V.check_ruleset(_fake_nft(three_tables), path) == []
    problems = V.check_ruleset(_fake_nft(three_tables, version="nftables v1.0.9"), path)
    assert problems and "nft version" in problems[0]


@pytest.mark.parametrize("text,ok", [
    (NETDEV_TEXT, True),
    (NETDEV_TEXT.replace('device "tap0"', 'device "lo"'), False),
    (NETDEV_TEXT.replace('device "tap0"', 'device tap0'), True),
    (NETDEV_TEXT.replace('device "tap0"', 'devices = { tap0, lo }'), False),
    (NETDEV_TEXT.replace('hook ingress device "tap0" ', 'hook ingress '), False),
    (NETDEV_TEXT + NETDEV_TEXT.replace("sandbox_guest_l2", "x"), False),   # two ingress chains
])
def test_netdev_device_binding(tmp_path, three_tables, text, ok):
    """nft 1.0.2 JSON omits the netdev "dev" key: device binding is checked from text."""
    path = _write_expected(tmp_path, _norm())
    problems = V.check_ruleset(_fake_nft(three_tables, netdev_text=text), path)
    assert (problems == []) is ok, problems
    if not ok:
        assert "ingress devices" in problems[-1]


def test_check_ruleset_missing_expected_fails(tmp_path, three_tables):
    problems = V.check_ruleset(_fake_nft(three_tables), str(tmp_path / "nope.json"))
    assert problems and "cannot read expected" in problems[0]


def test_check_ruleset_table_not_loaded_fails(tmp_path, three_tables):
    path = _write_expected(tmp_path, _norm())

    def run(cmd):
        if list(cmd) == ["nft", "--version"]:
            return "nftables v1.0.2 (Lester Gooch)"
        raise V.subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
    problems = V.check_ruleset(run, path)
    assert problems and "cannot list loaded ruleset" in problems[0]


# ---------------------------------------------------------------- sysctl

GOOD_SYSCTL = {
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv6.conf.tap0.disable_ipv6": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.all.arp_ignore": "0",
    "net.ipv4.conf.all.arp_announce": "0",
    "net.ipv4.conf.all.arp_accept": "0",
    "net.ipv4.conf.all.forwarding": "0",
    "net.ipv4.conf.tap0.rp_filter": "1",
    "net.ipv4.conf.tap0.arp_ignore": "1",
    "net.ipv4.conf.tap0.arp_announce": "2",
    "net.ipv4.conf.tap0.arp_accept": "0",
    "net.ipv4.conf.tap0.forwarding": "0",
}


def _with(**changes):
    s = dict(GOOD_SYSCTL)
    for k, v in changes.items():
        s[k.replace("__", ".")] = v
    return s


def test_sysctl_ok():
    assert V.check_sysctls(GOOD_SYSCTL.get) == []


@pytest.mark.parametrize("key,value", [
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.tap0.disable_ipv6", "0"),
    ("net.ipv4.conf.tap0.arp_ignore", "0"),
    ("net.ipv4.conf.tap0.rp_filter", None),
    ("net.ipv6.conf.all.forwarding", "1"),
    ("net.ipv4.conf.tap0.forwarding", "1"),
])
def test_sysctl_bad(key, value):
    s = dict(GOOD_SYSCTL)
    s[key] = value
    problems = V.check_sysctls(s.get)
    assert any(key in p for p in problems)


def test_regression_all_rp_filter_loose_makes_tap0_loose():
    """06B-2A finding: all.rp_filter=2 with tap0.rp_filter=1 is effectively loose."""
    s = _with(**{"net.ipv4.conf.all.rp_filter": "2"})
    problems = V.check_sysctls(s.get)
    assert any("net.ipv4.conf.all.rp_filter='2'" in p for p in problems)
    assert any("effective rp_filter on tap0=2" in p for p in problems)


def test_all_rp_filter_strict_but_tap0_off_fails():
    s = _with(**{"net.ipv4.conf.tap0.rp_filter": "0"})
    problems = V.check_sysctls(s.get)
    assert any("net.ipv4.conf.tap0.rp_filter='0'" in p for p in problems)


@pytest.mark.parametrize("all_key,all_value,attr,eff", [
    ("arp_ignore", "2", "arp_ignore", 2),      # max(2, 1) = 2, design needs 1
    ("arp_ignore", "8", "arp_ignore", 8),
    ("arp_accept", "1", "arp_accept", 1),      # max(1, 0) = 1, design needs 0
    ("arp_accept", "2", "arp_accept", 2),
])
def test_all_value_makes_effective_arp_wrong(all_key, all_value, attr, eff):
    s = _with(**{f"net.ipv4.conf.all.{all_key}": all_value})
    problems = V.check_sysctls(s.get)
    assert problems == [p for p in problems if f"effective {attr} on tap0={eff}" in p] and problems


@pytest.mark.parametrize("all_announce", ["0", "1", "2"])
def test_arp_announce_effective_is_2_for_any_valid_all(all_announce):
    s = _with(**{"net.ipv4.conf.all.arp_announce": all_announce})
    assert V.check_sysctls(s.get) == []


def test_forwarding_is_per_device_not_max():
    # all.forwarding=1 does not change the per-device value the kernel uses (IN_DEV_FORWARD),
    # but ip_forward=0 is still required separately.
    assert V.effective("forwarding", "tap0", _with(**{"net.ipv4.conf.all.forwarding": "1"}).get) == 0


def test_effective_uses_kernel_max_rule():
    s = _with(**{"net.ipv4.conf.all.rp_filter": "1", "net.ipv4.conf.eth0.rp_filter": "2",
                 "net.ipv4.conf.eth0.arp_ignore": "0"})
    assert V.effective("rp_filter", "eth0", s.get) == 2
    assert V.effective("rp_filter", "tap0", s.get) == 1
    assert V.effective("arp_ignore", "eth0", s.get) == 0


def test_sysctl_report_lists_configured_and_effective():
    s = _with(**{"net.ipv4.conf.eth0.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2"})
    lines = V.sysctl_report(read=s.get)
    rp = next(l for l in lines if l.startswith("rp_filter"))
    assert "configured: all=1 default=2 tap0=1 eth0=2" in rp
    assert "effective: tap0=1 eth0=2" in rp


def test_sysctl_ipv6_absent_from_kernel_is_tolerated():
    s = {k: v for k, v in GOOD_SYSCTL.items() if "ipv6" not in k}
    assert V.check_sysctls(s.get) == []


# ---------------------------------------------------------------- link / neighbor / route

LO_ADDR = {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                                         {"family": "inet6", "local": "::1", "prefixlen": 128}]}


def _ip(link=None, tap_addr=None, eth_addr=None, neigh=None, r4=None, r6=None, all_addr=None):
    link = link if link is not None else [
        {"ifname": "lo", "linkinfo": None},
        {"ifname": "eth0", "linkinfo": {"info_kind": "veth"}},
        {"ifname": "tap0", "linkinfo": {"info_kind": "tun", "info_data": {"type": "tap"}}},
    ]
    tap_addr = tap_addr if tap_addr is not None else [
        {"ifname": "tap0", "addr_info": [{"family": "inet", "local": "10.200.0.1", "prefixlen": 30}]}]
    eth_addr = eth_addr if eth_addr is not None else [
        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.60.2", "prefixlen": 24}]}]
    neigh = neigh if neigh is not None else [
        {"dst": "10.200.0.2", "lladdr": "52:54:00:c7:00:02", "state": ["PERMANENT"]}]
    r4 = r4 if r4 is not None else [{"dst": "10.200.0.0/30", "protocol": "kernel", "scope": "link",
                                     "prefsrc": "10.200.0.1", "flags": ["linkdown"]}]
    r6 = r6 if r6 is not None else []
    if all_addr is None:
        all_addr = [LO_ADDR, dict(eth_addr[0], ifname="eth0") if eth_addr else {"ifname": "eth0"},
                    dict(tap_addr[0], ifname="tap0") if tap_addr else {"ifname": "tap0"}]

    def run(cmd):
        cmd = list(cmd)
        table = {
            ("ip", "-j", "-d", "link", "show"): link,
            ("ip", "-j", "addr", "show", "dev", "tap0"): tap_addr,
            ("ip", "-j", "addr", "show", "dev", "eth0"): eth_addr,
            ("ip", "-j", "addr", "show"): all_addr,
            ("ip", "-j", "neigh", "show", "dev", "tap0"): neigh,
            ("ip", "-j", "-4", "route", "show", "dev", "tap0"): r4,
            ("ip", "-j", "-6", "route", "show", "dev", "tap0"): r6,
        }
        return json.dumps(table[tuple(cmd)])
    return run


def test_link_neighbor_route_ok():
    run = _ip()
    assert V.check_links(run) == []
    assert V.check_neighbor(run) == []
    assert V.check_routes(run) == []


@pytest.mark.parametrize("kwargs,needle", [
    (dict(link=[{"ifname": "eth0"}, {"ifname": "br0", "linkinfo": {"info_kind": "bridge"}},
                {"ifname": "tap0", "linkinfo": {"info_kind": "tun", "info_data": {"type": "tap"}}}]), "bridge"),
    (dict(link=[{"ifname": "eth0"}, {"ifname": "tap0", "master": "br0",
                                     "linkinfo": {"info_kind": "tun", "info_data": {"type": "tap"}}}]), "master"),
    (dict(link=[{"ifname": "eth0"}]), "tap0 missing"),
    (dict(link=[{"ifname": "eth0"}, {"ifname": "tap0", "linkinfo": {"info_kind": "veth"}}]), "not a tap"),
    (dict(tap_addr=[{"addr_info": [{"family": "inet", "local": "10.200.0.1", "prefixlen": 24}]}]), "addresses"),
    (dict(tap_addr=[{"addr_info": [{"family": "inet", "local": "10.200.0.1", "prefixlen": 30},
                                   {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}]), "addresses"),
    (dict(eth_addr=[{"addr_info": []}]), "no IPv4"),
    (dict(eth_addr=[{"addr_info": [{"family": "inet", "local": "10.200.0.2", "prefixlen": 30}]}]), "inside guest"),
])
def test_link_bad(kwargs, needle):
    problems = V.check_links(_ip(**kwargs))
    assert any(needle in p for p in problems), problems


# ---- 06B-2BR: guest-network addresses on any interface ----------------------

def _all(lo_extra=(), eth_extra=(), tap_extra=(), other=None):
    lo = {"ifname": "lo", "addr_info": list(LO_ADDR["addr_info"]) + list(lo_extra)}
    eth = {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.60.2", "prefixlen": 24}] + list(eth_extra)}
    tap = {"ifname": "tap0", "addr_info": [{"family": "inet", "local": "10.200.0.1", "prefixlen": 30}] + list(tap_extra)}
    return [lo, eth, tap] + ([other] if other else [])


def v4(ip, plen):
    return {"family": "inet", "local": ip, "prefixlen": plen}


def test_regression_correct_config_passes():
    assert V.check_links(_ip(all_addr=_all())) == []


def test_regression_guest_ip_on_lo_fails():
    """06B-2B finding: 10.200.0.2/32 on lo was not detected."""
    problems = V.check_links(_ip(all_addr=_all(lo_extra=[v4("10.200.0.2", 32)])))
    assert any("10.200.0.2/32 on lo" in p for p in problems), problems


@pytest.mark.parametrize("kw,needle", [
    (dict(eth_extra=[v4("10.200.0.3", 32)]), "10.200.0.3/32 on eth0"),
    (dict(lo_extra=[v4("10.200.0.1", 32)]), "10.200.0.1/32 on lo"),          # worker address copied to lo
    (dict(lo_extra=[v4("10.200.0.0", 32)]), "10.200.0.0/32 on lo"),          # network address
    (dict(other={"ifname": "dummy0", "addr_info": [v4("10.200.0.2", 30)]}), "10.200.0.2/30 on dummy0"),
    (dict(eth_extra=[v4("10.200.1.5", 16)]), "10.200.1.5/16 on eth0"),       # host IP outside, prefix overlaps
    (dict(tap_extra=[v4("10.200.0.2", 30)]), "10.200.0.2/30 on tap0"),       # extra guest address on tap0 itself
])
def test_guest_network_address_on_other_interface_fails(kw, needle):
    problems = V.check_links(_ip(all_addr=_all(**kw)))
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("extra", [
    dict(lo_extra=[v4("192.0.2.10", 32)]),
    dict(eth_extra=[v4("10.200.0.4", 30)]),        # adjacent /30, no overlap
    dict(other={"ifname": "dummy0", "addr_info": [v4("172.31.0.1", 24)]}),
    dict(lo_extra=[{"family": "inet6", "local": "fd00::2", "prefixlen": 128}]),
])
def test_ordinary_addresses_outside_guest_network_pass(extra):
    assert V.check_links(_ip(all_addr=_all(**extra))) == []


@pytest.mark.parametrize("neigh", [
    [],
    [{"dst": "10.200.0.2", "lladdr": "52:54:00:c7:00:02", "state": ["REACHABLE"]}],
    [{"dst": "10.200.0.2", "lladdr": "52:54:00:de:ad:01", "state": ["PERMANENT"]}],
])
def test_neighbor_bad(neigh):
    assert V.check_neighbor(_ip(neigh=neigh))


@pytest.mark.parametrize("r4,r6", [
    ([{"dst": "10.200.0.0/30"}, {"dst": "default", "gateway": "10.200.0.2"}], []),
    ([{"dst": "10.200.0.0/30"}, {"dst": "192.168.177.0/24"}], []),
    ([], []),
    ([{"dst": "10.200.0.0/30"}], [{"dst": "fe80::/64"}]),
])
def test_route_bad(r4, r6):
    assert V.check_routes(_ip(r4=r4, r6=r6))


def test_verify_isolation_raises_with_phase(monkeypatch):
    monkeypatch.setattr(V, "run_checks", lambda **kw: ["sysctl: net.ipv4.ip_forward='1', expected '0'"])
    with pytest.raises(V.IsolationError, match=r"\(V1 before phase 1\).*ip_forward"):
        V.verify_isolation("V1 before phase 1")
    monkeypatch.setattr(V, "run_checks", lambda **kw: [])
    V.verify_isolation("V1 before phase 1")


def test_cli_returns_nonzero_on_failure(monkeypatch, capsys):
    monkeypatch.setattr(V, "run_checks", lambda *a, **kw: ["route: x"])
    assert V.main(["--phase", "V0 startup"]) == 1
    assert "ISOLATION FAIL (V0 startup): route: x" in capsys.readouterr().err


# ---------------------------------------------------------------- consistency of repository artefacts (working tree)

GUEST_NFT = os.path.join(os.path.dirname(V.__file__), "guest.nft")


def test_guest_nft_uses_the_same_constants():
    text = open(GUEST_NFT).read()
    assert f'device "{C.GUEST_IF}"' in text
    assert f"ether saddr != {C.GUEST_MAC}" in text
    assert f"arp saddr ip {C.GUEST_IP} arp daddr ip {C.WORKER_GUEST_IP}" in text
    assert f"ip saddr != {C.GUEST_IP}" in text
    assert f"ip daddr {C.WORKER_GUEST_IP} tcp dport {C.SVC_PORT}" in text
    tables = set(re.findall(r"^table (\w+) (\w+) \{", text, re.M))
    assert tables == set(C.NFT_TABLES)


@pytest.mark.skipif(not os.path.exists(V.EXPECTED_PATH), reason="expected-ruleset.json not generated yet")
def test_expected_ruleset_is_normalised_and_complete():
    exp = V.load_expected()
    assert exp["nft_version"].startswith("nftables v")
    assert set(exp["tables"]) == {f"{f} {t}" for f, t in C.NFT_TABLES}
    s = json.dumps(exp)
    assert '"handle"' not in s and '"packets"' not in s and '"bytes"' not in s
    for addr in (C.GUEST_IP, C.WORKER_GUEST_IP, C.GUEST_MAC):
        assert addr in s
