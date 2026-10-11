"""Mutation tests against the real nft ruleset (see nft_selftest.sh).

Each case reloads the pristine guest.nft, applies one change, and checks that
isolation.verify's ruleset check passes or fails as expected.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, "/app")
from isolation import constants as C          # noqa: E402
from isolation import verify as V             # noqa: E402

GUEST_NFT = "/app/isolation/guest.nft"
LOAD_NFT = "/app/isolation/load.nft"
results = []


def sh(*cmd, check=True):
    return subprocess.run(list(cmd), check=check, capture_output=True, text=True)


def load_via_transaction(guest_text=None, check=True):
    """Load through load.nft (one transaction). guest_text replaces guest.nft."""
    if guest_text is None:
        return sh("nft", "-f", LOAD_NFT, check=check)
    with tempfile.TemporaryDirectory() as d:
        g = os.path.join(d, "guest.nft")
        with open(g, "w") as f:
            f.write(guest_text)
        w = os.path.join(d, "load.nft")
        with open(w, "w") as f:
            f.write(open(LOAD_NFT).read().replace(f'include "{GUEST_NFT}"', f'include "{g}"'))
        return sh("nft", "-f", w, check=check)


def reload(nft_text=None):
    load_via_transaction(nft_text)


def problems(baseline):
    return V.check_ruleset(expected_path=baseline)


def record(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def expect_fail(name, baseline, apply):
    reload()
    try:
        apply()
    except subprocess.CalledProcessError as e:
        record(name, False, f"mutation could not be applied: {e.stderr.strip()}")
        return
    p = problems(baseline)
    record(name, bool(p), p[0][:220] if p else "verify did NOT detect the change")


def counters():
    out = json.loads(sh("nft", "-j", "list", "counters", "table", "inet", "sandbox_guest").stdout)
    return {o["counter"]["name"]: o["counter"]["packets"] for o in out["nftables"] if "counter" in o}


def handle_of(family, table, chain, counter_name):
    out = json.loads(sh("nft", "-a", "-j", "list", "chain", family, table, chain).stdout)
    for o in out["nftables"]:
        r = o.get("rule")
        if r and {"counter": counter_name} in r["expr"]:
            return str(r["handle"])
    raise RuntimeError(f"rule with counter {counter_name} not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--repo-expected")
    a = ap.parse_args()
    base = a.baseline
    src = open(GUEST_NFT).read()

    reload()
    p = problems(base)
    record("pristine ruleset matches baseline", not p, "; ".join(p))

    # Real counter change: traffic from the worker to the guest address is dropped
    # by the output chain (no carrier is needed for the hook to run).
    before = counters()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(3):
        try:
            s.sendto(b"x", (C.GUEST_IP, 9))
        except OSError:
            pass
    after = counters()
    changed = after.get("drop_out", 0) > before.get("drop_out", 0)
    record("counter drop_out increased", changed, f"{before.get('drop_out')} -> {after.get('drop_out')}")
    p = problems(base)
    record("verify still passes after counter change", not p, "; ".join(p))
    sh("nft", "reset", "counters")
    p = problems(base)
    record("verify still passes after counter reset", not p, "; ".join(p))

    expect_fail("add rule (append accept)", base,
                lambda: sh("nft", "add", "rule", "inet", "sandbox_guest", "prerouting", "accept"))
    expect_fail("insert rule at top", base,
                lambda: sh("nft", "insert", "rule", "inet", "sandbox_guest", "prerouting", "iifname", "tap0", "accept"))
    expect_fail("delete rule (drop_public)", base,
                lambda: sh("nft", "delete", "rule", "inet", "sandbox_guest", "prerouting", "handle",
                           handle_of("inet", "sandbox_guest", "prerouting", "drop_public")))
    expect_fail("delete arp rule (arp_in_drop)", base,
                lambda: sh("nft", "delete", "rule", "arp", "sandbox_guest_arp", "input", "handle",
                           handle_of("arp", "sandbox_guest_arp", "input", "arp_in_drop")))
    expect_fail("add rule in arp output", base,
                lambda: sh("nft", "insert", "rule", "arp", "sandbox_guest_arp", "output", "accept"))
    expect_fail("forward policy -> accept", base,
                lambda: sh("nft", "chain", "inet", "sandbox_guest", "forward", "{ policy accept ; }"))
    expect_fail("delete table arp", base,
                lambda: sh("nft", "delete", "table", "arp", "sandbox_guest_arp"))
    expect_fail("delete table netdev", base,
                lambda: sh("nft", "delete", "table", "netdev", "sandbox_guest_l2"))
    expect_fail("extra base chain inside CT-01 table 'inet sandbox_guest'", base,
                lambda: subprocess.run(
                    ["nft", "-f", "-"], text=True, check=True, capture_output=True,
                    input="table inet sandbox_guest { chain extra { type filter hook prerouting priority -400; policy accept; }; }"))

    def edited(old, new, count=1):
        assert src.count(old) >= 1, old
        return lambda: reload(src.replace(old, new, count))

    expect_fail("prio change prerouting -150 -> -100", base, edited("hook prerouting priority -150", "hook prerouting priority -100"))
    expect_fail("hook change inet output -> postrouting", base, edited("hook output priority -10", "hook postrouting priority -10"))
    expect_fail("netdev device tap0 -> lo", base, edited('device "tap0"', 'device "lo"'))
    expect_fail("service port 8011 -> 8012", base, edited("tcp dport 8011 counter", "tcp dport 8012 counter"))
    expect_fail("guest MAC changed", base, edited("ether saddr != 52:54:00:c7:00:02", "ether saddr != 52:54:00:c7:00:03"))
    expect_fail("private range narrowed", base, edited("192.168.0.0/16 }", "192.168.0.0/24 }"))
    expect_fail("drop -> accept on drop_private", base, edited('counter name "drop_private" drop', 'counter name "drop_private" accept'))

    reload()
    p = problems(base)
    record("pristine reload matches baseline again", not p, "; ".join(p))

    # ---- single-transaction replace (load.nft)
    subprocess.run(["nft", "-f", "-"], text=True, check=True, capture_output=True,
                   input="table ip unrelated_test { chain c { type filter hook forward priority 0; policy accept; }; }")
    load_via_transaction()
    present = sh("nft", "list", "tables").stdout
    record("load.nft leaves unrelated table in place (no namespace flush)", "table ip unrelated_test" in present, present.strip().replace("\n", "; "))
    p = problems(base)
    record("load.nft replacing existing CT-01 tables matches baseline", not p, "; ".join(p))

    def snapshot():
        return V.dump_normalized(), counters()

    def bump_counters():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(2):
            try:
                sock.sendto(b"x", (C.GUEST_IP, 9))
            except OSError:
                pass

    for name, broken in [
        # A stray token on its own line is a genuine parser error.
        ("syntax error", src + "\nthis_is_not_nft_syntax {\n"),
        # Parses, but is rejected at evaluation (unknown named counter).
        ("undefined named counter", src.replace('counter name "drop_public" drop', 'counter name "no_such_counter" drop')),
    ]:
        bump_counters()                         # non-zero counters prove the tables were not recreated
        before_tables, before_counters = snapshot()
        r = load_via_transaction(broken, check=False)
        after_tables, after_counters = snapshot()
        intact = (r.returncode != 0 and before_counters.get("drop_out", 0) > 0
                  and after_tables == before_tables and after_counters == before_counters)
        err = r.stderr.strip().splitlines()
        record(f"failed transaction ({name}) leaves previous CT-01 ruleset and counters intact", intact,
               f"nft rc={r.returncode}; drop_out {before_counters.get('drop_out')} -> {after_counters.get('drop_out')}; "
               f"stderr: {' | '.join(l.strip() for l in err if 'Error' in l)[:200]}")
    p = problems(base)
    record("verify still passes after failed transactions", not p, "; ".join(p))
    sh("nft", "delete", "table", "ip", "unrelated_test")

    if a.repo_expected:
        if os.path.exists(a.repo_expected):
            p = problems(a.repo_expected)
            record("loaded ruleset matches expected-ruleset.json in image (working tree, not committed)", not p, "; ".join(p)[:300])
            same = json.load(open(a.repo_expected)) == json.load(open(base))
            record("expected-ruleset.json (working tree) == generated candidate", same)
        else:
            print(f"[INFO] {a.repo_expected} not present in image: candidate must be reviewed and committed")

    print("[INFO] scope: runtime verify compares ONLY the three CT-01 tables "
          f"{[f'{f} {t}' for f, t in C.NFT_TABLES]}; other tables in the namespace are not checked. "
          f"Tables present now: {sh('nft', 'list', 'tables').stdout.strip().splitlines()}")

    # Partial V0 checks available in this container (sysctl needs a writable /proc/sys).
    p = V.run_checks(checks=("link", "neighbor", "route"), uplink="")
    record("link/neighbor/route checks on the test tap0", not p, "; ".join(p))
    p = V.run_checks(checks=("sysctl",))
    print(f"[INFO] sysctl check (not asserted; /proc/sys is read-only without --privileged): {p}")

    failed = [n for n, ok in results if not ok]
    print(f"== {len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
