#!/usr/bin/env python3
"""CT-01 batch B1 — wiring of b1_cases.py into the harness (offline-tested; not run against a guest by the delivery that introduces it).

Used in two places:
  * inside the worker test container by probe_matrix.py when CT01_SUITE=b1: run_suite (-> b1_cases.run_group) and evaluate (-> b1_cases.evaluate_group);
  * on the host by run-ct01-b1.sh:  --outcome <result.json> <b1-eval.json> <ARCH>
                                    --run-check <probe dir> ARM MIPS
                                    --route-check <n4 file> <n5 file> <worker_ip> <sandbox_gw> <sandbox_bridge> <n4 rc file> <n5 rc file>
Reused unchanged from icmp_harness.py: GuardedRunner (every guest command guarded before AND after, first failure stops), the service link
command/parser (HTTP 200 + fixture hash) and malformed_records(). b1_cases.py defines the cases; nothing is added here.
"""
import collections
import json
import os
import re
import sys

import b1_cases as B
import counter_window
import icmp_harness as IH

RECORD_FILE = "b1-group.json"
EVAL_FILE = "b1-eval.json"
LINK_BEFORE_NAME = "allowed service link before the B1 group: GET get-task/T/file HTTP 200 + fixture hash"
LINK_AFTER_NAME = "allowed service link after the B1 group: GET get-task/T/file HTTP 200 + fixture hash"
ALL_CASES_NAME = "all B1 cases recorded exactly once with captures alive"
GROUP_RECORD_NAME = "B1 group record: each case exactly once, service links HTTP 200 + fixture hash"
LINK_ROLE = "guest-worker service link: precondition before/after the group, NOT a live control for the B1 destinations"
REQUIRED_RECORDS = (
    "host leak monitor running and empty before boot",
    "full isolation verify right before QEMU spawn (harness pre-boot, not V1)",
    "tshark capturing on tap0",
    "guest booted and network configured",
    "topology gate: only nic/tap, one tap0 backend, pinned MAC on tap NIC and probe interface",
    "capture liveness traffic from the worker before the B1 group (host captures; not a control for the B1 destinations)",
    LINK_BEFORE_NAME,
    "tap0 MAC unchanged during the B1 group",
    ALL_CASES_NAME,
    "capture liveness traffic from the worker after the B1 group (host captures; not a control for the B1 destinations)",
    LINK_AFTER_NAME,
    "QEMU exit confirmed",
    "tap0 capture stopped cleanly",
    "tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped",
    "fixture, marker and temporary guest disk removed",
    GROUP_RECORD_NAME,
)


class B1GuardedRunner(IH.GuardedRunner):
    """GuardedRunner for B1: (1) `run_banner` sends the banner SCRIPT through guest.run_script (short confirmed console lines), guarded once
    before and once after the whole sequence; (2) a console failure (guest.broken) stops the group at once, so no later command is sent into a
    shell that may sit at a continuation prompt. Unit-tested with a real shell behind a line-limited pty (tests in selftest_b1 / N6 checks)."""

    def _stop_if_broken(self, e):
        """Any exception that reaches here comes from the console path (timeout/EOF/missing marker/refused line): the console is no longer
        trusted, so the group stops and no later command is sent (R13N7: also when the guest object has no `broken` flag, e.g. stubs)."""
        if self.stop is None:
            self.stop = e

    def run(self, cmd, timeout=60):
        if getattr(self.guest, "broken", None) and self.stop is None:
            self.stop = IH.SuiteStopped(f"console not trusted: {self.guest.broken}")
        try:
            return super().run(cmd, timeout=timeout)
        except Exception as e:                                   # noqa: BLE001
            self._stop_if_broken(e)
            raise

    def run_banner(self, script, timeout=60):
        if self.stop is not None:
            raise IH.SuiteStopped(f"not sent: the group was stopped earlier ({type(self.stop).__name__}: {self.stop})")
        label = "banner script upload+run"
        try:
            self.before(label)
        except Exception as e:                                   # noqa: BLE001
            self.stop = e
            raise
        self.sent.append(script)
        try:
            runner = getattr(self.guest, "run_script", None)     # the real Guest always has it; simulated guests of the offline stages only run()
            return (runner or self.guest.run)(script, timeout=timeout)
        except Exception as e:                                   # noqa: BLE001
            self._stop_if_broken(e)
            raise
        finally:
            try:
                self.after(label)
            except Exception as e:                               # noqa: BLE001
                if self.stop is None:
                    self.stop = e
                raise


def case_test_name(case_result):
    """Name of the per-case record in result.json; starts with "probe " so that counter_window.run_outcome() treats a CHUA KIEM CHUNG
    case as undecided and anything else not passed as hard."""
    return f"probe {case_result['id']} (b1, {case_result.get('req', '?')}) -> {case_result['verdict']}"


def run_suite_record_checks(rec, arch, tap_mac):
    return B._validate_record(rec, arch, tap_mac)


def required_problems(results, names):
    p = []
    by_name = collections.defaultdict(list)
    for r in results:
        if isinstance(r, dict) and isinstance(r.get("test"), str):
            by_name[r["test"]].append(r)
    for name in names:
        recs = by_name.get(name, [])
        if not recs:
            p.append(f"required confirmation missing: {name}")
        elif len(recs) > 1:
            p.append(f"required confirmation recorded {len(recs)} times: {name}")
        elif recs[0].get("ok") is not True:
            p.append(f"required confirmation not passed (ok={recs[0].get('ok')!r}): {name}")
    return p


def arch_outcome(result, b1_eval, arch):
    """One architecture -> "PASS" | "UNVERIFIED: ..." | "FAIL: ...". counter_window.run_outcome() on every record plus: well-formed
    records, every REQUIRED record exactly once with ok True, status COMPLETED, an evaluation of this architecture with each case exactly
    once (also in result.json as a 'probe ...' record), no record problem, and group_exit not 1/2. A passed case never hides another failed
    or missing check; a measurement error is never PASS."""
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        return "FAIL: result.json unreadable or without results"
    bad = IH.malformed_records(result["results"])
    if bad:
        return f"FAIL: result record(s) {bad[:5]} not an object with a string 'test' and a boolean 'ok'"
    hard = required_problems(result["results"], REQUIRED_RECORDS)
    if result.get("status") != "COMPLETED":
        hard.append(f"status {result.get('status')!r}")
    if not isinstance(b1_eval, dict):
        hard.append("b1-eval.json missing or unreadable")
    else:
        if b1_eval.get("arch") != arch:
            hard.append(f"b1-eval arch {b1_eval.get('arch')!r} != {arch!r}")
        if b1_eval.get("record_problems"):
            hard.append(f"group record not valid: {b1_eval.get('record_problems')}")
        if b1_eval.get("group_exit") not in (0, 4):
            hard.append(f"b1_cases group exit {b1_eval.get('group_exit')!r}")
        ids = collections.Counter(c.get("id") for c in b1_eval.get("cases") or [] if isinstance(c, dict))
        if sorted(ids.elements()) != sorted(B.ALL_CASE_IDS):
            hard.append(f"b1-eval cases {sorted(ids.elements())} are not each case exactly once")
        names = collections.Counter(r.get("test") for r in result["results"] if isinstance(r, dict))
        for c in b1_eval.get("cases") or []:
            if isinstance(c, dict) and "verdict" in c and names[case_test_name(c)] != 1:
                hard.append(f"{c.get('id')}: not recorded exactly once in result.json")
    try:
        base = counter_window.run_outcome(result["results"])
    except (KeyError, TypeError) as e:
        return f"FAIL: results malformed ({type(e).__name__}: {e})"
    if hard:
        rest = base[len("FAIL: "):] if base.startswith("FAIL: ") else ""
        return "FAIL: " + "; ".join(hard + ([rest] if rest else []))
    return base


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def run_check(probe_dir, archs):
    p = []
    if not archs:
        p.append("no architecture given")
    if len(set(archs)) != len(archs):
        p.append(f"architecture listed twice: {archs}")
    for a in archs:
        ev = _load(os.path.join(probe_dir, a, EVAL_FILE))
        if not isinstance(ev, dict):
            p.append(f"{a}: {EVAL_FILE} missing or unreadable")
            continue
        if ev.get("arch") != a:
            p.append(f"{a}: evaluation is for {ev.get('arch')!r}")
        ids = sorted(str(c.get("id")) for c in ev.get("cases") or [] if isinstance(c, dict))
        if ids != sorted(B.ALL_CASE_IDS):
            p.append(f"{a}: cases {ids} are not each case exactly once")
    return p


def _read_rc(path):
    """Exit status written by the runner next to the evidence: exactly one non-negative integer; anything else -> None (not accepted)."""
    try:
        with open(path) as f:
            text = f.read(65)
            if len(text) > 64:
                return None
            m = re.fullmatch(r"\s*([0-9]{1,3})\s*", text)
    except (OSError, ValueError):
        return None
    return int(m.group(1)) if m else None


def route_check(n4_path, n5_path, worker_ip, sandbox_gw, sandbox_bridge, n4_rc_path, n5_rc_path):
    """-> (text, rc): rc 0 all DAT*, 1 FAIL, 2 measurement error (unreadable file/output, producer rc nonzero or unreadable), 4 not decided.
    The producer's exit status (rc files) is part of the evidence: a nonzero or unreadable rc is never a route that passed."""
    try:
        n4 = open(n4_path).read()
        n5 = open(n5_path).read()
    except OSError as e:
        return f"LOI_PHEP_DO: route evidence unreadable ({e})", 2
    res = B.evaluate_routes(n4, n5, worker_ip, sandbox_gw, sandbox_bridge, n4_rc=_read_rc(n4_rc_path), n5_rc=_read_rc(n5_rc_path))
    cats = {r["category"] for r in res}
    text = "; ".join(f"{r['id']}: {r['verdict']}" for r in res)
    if "FAIL" in cats:
        return "FAIL: " + text, 1
    if "LOI_PHEP_DO" in cats:
        return "LOI_PHEP_DO: " + text, 2
    if cats - set(B.OK_CATEGORIES):
        return "UNVERIFIED: " + text, 4
    return "PASS: " + text, 0


def main(argv):
    if len(argv) == 4 and argv[0] == "--outcome":
        print(arch_outcome(_load(argv[1]), _load(argv[2]), argv[3]))
        return 0
    if len(argv) >= 3 and argv[0] == "--run-check":
        p = run_check(argv[1], argv[2:])
        print("\n".join(p) if p else "B1 groups complete: " + " ".join(argv[2:]))
        return 1 if p else 0
    if len(argv) == 8 and argv[0] == "--route-check":
        text, rc = route_check(*argv[1:])
        print(text)
        return rc
    print("usage: b1_harness.py --outcome RESULT B1_EVAL ARCH | --run-check PROBE_DIR ARCH... | --route-check N4 N5 WORKER_IP GW BRIDGE N4_RC N5_RC", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
