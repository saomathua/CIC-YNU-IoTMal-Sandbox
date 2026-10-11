#!/usr/bin/env python3
"""06B-4F — wiring of the five reviewed ICMP cases (icmp_cases.py, 06B-4ER) into the harness.
Prepared and tested OFFLINE only (selftest_icmp_wiring.py); not run against a guest in 06B-4F.

Used in two places:
  * inside the worker test container by probe_matrix.py when CT01_SUITE=icmp: GuardedRunner,
    link_command / parse_service_link, run_suite (-> icmp_cases.run_group), evaluate (-> evaluate_group);
  * on the host by run-06b4f.sh:  --outcome <result.json> <icmp-eval.json> <ARCH>
                                  --run-check <probe dir> ARM MIPS
No case, probe, address, size, tool or ruleset is added here; the cases come only from
icmp_cases.build_cases() and their sizes only from signatures.py.

The guest-worker service link (GET get-task/T/file) is checked before and after the group with its HTTP
code AND the fixture hash. It is a precondition only: it is NOT a live control for the ICMP destinations
(none exists), so a pass stays "ĐẠT (kiểm quy tắc)" and evidence_kind "rule_check".

06B-4FR: --outcome also requires every infrastructure confirmation of the real ICMP path (REQUIRED_RECORDS)
exactly once with a boolean ok == True; records must be objects with a string test and a boolean ok.
"""
import collections
import json
import os
import re
import sys

import counter_window
import icmp_cases as I

RECORD_FILE = "icmp-group.json"
EVAL_FILE = "icmp-eval.json"
LINK_ROLE = ("guest-worker service link: precondition before/after the group, NOT a live control "
             "for the ICMP destinations")
_HTTP = re.compile(r"HTTP=(\d{3})")
_SHA = re.compile(r"([0-9a-f]{64})\s+\*?/tmp/r\.out")


class SuiteStopped(Exception):
    """A guest command refused because the guard already stopped the group."""


# ------------------------------------------------------------------ guest side
def link_command(url, task):
    """Same request as probe_matrix.service_link(); the old response file is removed first so that a failed
    request can never show the hash of an earlier response."""
    return (f"rm -f /tmp/r.out; curl -s -m 10 -o /tmp/r.out -w 'HTTP=%{{http_code}}\\n' {url}/get-task/{task}/file; "
            "sha256sum /tmp/r.out")


def parse_service_link(rc, out, expected_sha):
    """-> (ok, detail). ok only if exactly one HTTP code line says 200, exactly one hash line for /tmp/r.out
    is present and equals the fixture hash, and the command exited 0."""
    lines = [l.strip() for l in (out or "").replace("\r", "").splitlines()]
    codes = [m.group(1) for l in lines for m in [_HTTP.fullmatch(l)] if m]
    shas = [m.group(1) for l in lines for m in [_SHA.fullmatch(l)] if m]
    http = codes[0] if len(codes) == 1 else None
    sha = shas[0] if len(shas) == 1 else None
    ok = rc == 0 and http == "200" and sha is not None and sha == expected_sha
    return ok, {"rc": rc, "http_code": http, "sha256": sha, "expected_sha256": expected_sha,
                "output_tail": (out or "").strip()[-300:]}


def link_valid(state, expected_sha):
    """Record-level check of one service-link state: ok is exactly True, HTTP code 200, hash == fixture."""
    if not I.link_ok(state):
        return False
    d = state.get("detail")
    return (isinstance(d, dict) and d.get("http_code") == "200" and isinstance(expected_sha, str)
            and d.get("sha256") == expected_sha and d.get("expected_sha256") == expected_sha)


class GuardedRunner:
    """Wraps the guest console for icmp_cases.run_group(), which records every exception as an execution
    error and never raises. `before(cmd)` / `after(cmd)` are the harness checks (captures alive, watcher
    heartbeat, leak alerts). The first exception they raise stops the group: it is kept in `stop`, and every
    later command is refused WITHOUT reaching the guest. The caller re-raises `stop` after run_group()."""

    def __init__(self, guest, before, after):
        self.guest, self.before, self.after = guest, before, after
        self.stop, self.sent = None, []

    def run(self, cmd, timeout=60):
        if self.stop is not None:
            raise SuiteStopped(f"not sent: the group was stopped earlier ({type(self.stop).__name__}: {self.stop})")
        try:
            self.before(cmd)
        except Exception as e:                                   # noqa: BLE001
            self.stop = e
            raise
        self.sent.append(cmd)
        try:
            return self.guest.run(cmd, timeout=timeout)
        finally:
            try:
                self.after(cmd)
            except Exception as e:                               # noqa: BLE001
                if self.stop is None:
                    self.stop = e
                raise


def run_suite(runner, read_counters, service_link, tap_mac, iface, arch, fixture_sha):
    """Runs the five reviewed cases once (icmp_cases.run_group) and returns the group record, annotated
    with what the evaluation checks. Does not raise; the caller re-raises runner.stop if set."""
    cases = I.build_cases(tap_mac)
    rec = I.run_group(runner, read_counters, service_link, cases, iface)
    rec.update(arch=arch, tap_mac=I.L._norm_mac(tap_mac), fixture_sha256=fixture_sha,
               planned_case_ids=[c["id"] for c in cases], evidence_kind="rule_check", service_link_role=LINK_ROLE)
    if runner.stop is not None:
        rec["stopped"] = f"{type(runner.stop).__name__}: {runner.stop}"
    return rec


# ------------------------------------------------------------------ evaluation
def check_record(record, arch, tap_mac, fixture_sha):
    """Problems that forbid concluding the group, as a list of strings (empty = complete and valid):
    every reviewed case exactly once, no unknown case, labels/commands as built from the reviewed cases,
    service link before AND after with HTTP 200 + fixture hash, not stopped, not skipped."""
    if not isinstance(record, dict):
        return [f"group record is {type(record).__name__}, not an object"]
    p = []
    if record.get("arch") != arch:
        p.append(f"record arch {record.get('arch')!r} != {arch!r}")
    cases = record.get("cases")
    if not isinstance(cases, list) or not all(isinstance(c, dict) for c in cases):
        return p + ["'cases' is not a list of objects"]
    if record.get("skipped"):
        p.append(f"group skipped: {record['skipped']}")
    if record.get("stopped"):
        p.append(f"group stopped: {record['stopped']}")
    n = collections.Counter(c.get("id") for c in cases)
    missing = [cid for cid in I.CASE_IDS if n[cid] == 0]
    dup = sorted(str(cid) for cid, k in n.items() if k > 1)
    unknown = sorted(str(cid) for cid in n if cid not in I.CASE_IDS)
    if missing:
        p.append(f"case(s) missing: {missing}")
    if dup:
        p.append(f"case(s) recorded more than once: {dup}")
    if unknown:
        p.append(f"unknown case id(s): {unknown}")
    try:
        defs = {c["id"]: c for c in I.build_cases(tap_mac)}
    except ValueError as e:
        return p + [f"TAP MAC invalid: {e}"]
    for c in cases:
        cid = c.get("id")
        if cid not in defs:
            continue
        if c.get("before") != f"{cid} before" or c.get("after") != f"{cid} after":
            p.append(f"{cid}: counter read labels differ from the reviewed ones")
        try:
            want = I.command(defs[cid], record.get("iface"))
        except ValueError as e:
            want = f"<{e}>"
        if c.get("command") != want:
            p.append(f"{cid}: command {c.get('command')!r} != reviewed {want!r}")
    if record.get("tap_mac") is not None and record.get("tap_mac") != I.L._norm_mac(tap_mac):
        p.append("record TAP MAC differs from the evaluated one")
    if record.get("fixture_sha256") != fixture_sha:
        p.append("record fixture hash differs from the expected one")
    for k in ("service_link_before", "service_link_after"):
        if not link_valid(record.get(k), fixture_sha):
            p.append(f"{k}: not HTTP 200 with the fixture hash")
    return p


def evaluate(pcap, counters_file, tap_mac, record, arch, fixture_sha):
    """evaluate_group() + the completeness/validity checks. Returns the evaluation object written to
    icmp-eval.json. Never raises: an invalid record becomes record_problems + no case result."""
    problems = check_record(record, arch, tap_mac, fixture_sha)
    try:
        res = I.evaluate_group(pcap, counters_file, tap_mac, record)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        res = {"error": f"{type(e).__name__}: {e}", "cases": []}
        problems.append(f"evaluate_group refused the record: {res['error']}")
    ids = collections.Counter(c.get("id") for c in res["cases"])
    if sorted(ids.elements()) != sorted(I.CASE_IDS):
        problems.append(f"evaluated cases {sorted(ids.elements())} are not each of {list(I.CASE_IDS)} exactly once")
    res.update(arch=arch, record_problems=problems, group_complete=not problems, service_link_role=LINK_ROLE)
    return res


def case_test_name(case_result):
    """Name of the per-case record in result.json. It starts with "probe " so that the reviewed
    counter_window.run_outcome() treats a CHƯA KIỂM CHỨNG case as undecided and anything else as hard."""
    return f"probe {case_result['id']} (icmp, rule check) -> {case_result['verdict']}"


# ------------------------------------------------------------------ host side
# 06B-4FR: confirmations that probe_matrix.py records on the real ICMP path (main() + run_icmp() +
# evaluate_icmp()) and that a PASS needs. Each must be present EXACTLY ONCE with "ok" exactly True; a missing,
# duplicated, malformed or failed one is a hard failure. Nothing defaults to success. ("info: ..." records and
# the per-case records are not in this list; the cases are checked separately.)
REQUIRED_RECORDS = (
    "host leak monitor running and empty before boot",
    "full isolation verify right before QEMU spawn (harness pre-boot, not V1)",
    "tshark capturing on tap0",
    "guest booted and network configured",
    "topology gate: only nic/tap, one tap0 backend, pinned MAC on tap NIC and probe interface",
    "capture liveness traffic from the worker before the ICMP group (host captures; not a control for the ICMP "
    "destinations)",
    "allowed service link before the ICMP group: GET get-task/T/file HTTP 200 + fixture hash",
    "allowed service link after the ICMP group: GET get-task/T/file HTTP 200 + fixture hash",
    "tap0 MAC unchanged during the ICMP group",
    "all five ICMP cases executed with captures alive",
    "capture liveness traffic from the worker after the ICMP group (host captures; not a control for the ICMP "
    "destinations)",
    "QEMU exit confirmed",
    "tap0 capture stopped cleanly",
    "tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped",
    "fixture, marker and temporary guest disk removed",
    "ICMP group record: each reviewed case exactly once, service link before/after HTTP 200 + fixture hash",
)


def malformed_records(results):
    """06B-4FR: indexes of records that are not an object with a string "test" and a boolean "ok"."""
    return [i for i, r in enumerate(results)
            if not isinstance(r, dict) or not isinstance(r.get("test"), str) or not isinstance(r.get("ok"), bool)]


def record_problems(results):
    """06B-4FR: every required confirmation must appear exactly once and be ok (exactly True).
    -> list of problems (empty = complete). Malformed records are reported by malformed_records()."""
    p = []
    by_name = collections.defaultdict(list)
    for r in results:
        if isinstance(r, dict) and isinstance(r.get("test"), str):
            by_name[r["test"]].append(r)
    for name in REQUIRED_RECORDS:
        recs = by_name.get(name, [])
        if not recs:
            p.append(f"required confirmation missing: {name}")
        elif len(recs) > 1:
            p.append(f"required confirmation recorded {len(recs)} times: {name}")
        elif recs[0].get("ok") is not True:
            p.append(f"required confirmation not passed (ok={recs[0].get('ok')!r}): {name}")
    return p


def arch_outcome(result, icmp_eval, arch):
    """One architecture -> "PASS" | "UNVERIFIED: ..." | "FAIL: ...". counter_window.run_outcome() on every
    record (infrastructure checks included: captures, heartbeat, QEMU exit, cleanup, drop statistics ...),
    plus: status COMPLETED, an evaluation for this architecture whose five cases each appear exactly once,
    in result.json too, and no record problem. 06B-4FR: every record well-formed (string test, boolean ok) and
    each REQUIRED_RECORDS confirmation present exactly once with ok True. A passed case never hides any other
    failed or missing check, and the case labels are unchanged."""
    hard = []
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        return "FAIL: result.json unreadable or without results"
    bad = malformed_records(result["results"])   # 06B-4FR: run_outcome() must never see these
    if bad:
        return f"FAIL: result record(s) {bad[:5]} not an object with a string 'test' and a boolean 'ok'"
    hard += record_problems(result["results"])   # 06B-4FR: required infrastructure confirmations
    if result.get("status") != "COMPLETED":
        hard.append(f"status {result.get('status')!r}")
    if not isinstance(icmp_eval, dict):
        hard.append("icmp-eval.json missing or unreadable")
    else:
        if icmp_eval.get("arch") != arch:
            hard.append(f"icmp-eval arch {icmp_eval.get('arch')!r} != {arch!r}")
        if icmp_eval.get("record_problems") or icmp_eval.get("group_complete") is not True:
            hard.append(f"group record not complete/valid: {icmp_eval.get('record_problems')}")
        ids = collections.Counter(c.get("id") for c in icmp_eval.get("cases") or [] if isinstance(c, dict))
        if sorted(ids.elements()) != sorted(I.CASE_IDS):
            hard.append(f"icmp-eval cases {sorted(ids.elements())} are not each case exactly once")
        names = collections.Counter(r.get("test") for r in result["results"] if isinstance(r, dict))
        for c in icmp_eval.get("cases") or []:
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
    """Run level: every architecture evaluated exactly once, each with five distinct cases. -> problems."""
    p = []
    if len(set(archs)) != len(archs):
        p.append(f"architecture listed twice: {archs}")
    for a in archs:
        ev = _load(os.path.join(probe_dir, a, EVAL_FILE))
        if not isinstance(ev, dict):
            p.append(f"{a}: {EVAL_FILE} missing or unreadable")
            continue
        if ev.get("arch") != a:
            p.append(f"{a}: evaluation is for {ev.get('arch')!r}")
        ids = sorted(c.get("id") for c in ev.get("cases") or [] if isinstance(c, dict))
        if ids != sorted(I.CASE_IDS):
            p.append(f"{a}: cases {ids} are not each case exactly once")
    return p


def main(argv):
    if len(argv) == 4 and argv[0] == "--outcome":
        print(arch_outcome(_load(argv[1]), _load(argv[2]), argv[3]))
        return 0
    if len(argv) >= 3 and argv[0] == "--run-check":
        p = run_check(argv[1], argv[2:])
        print("\n".join(p) if p else "ICMP groups complete: " + " ".join(argv[2:]))
        return 1 if p else 0
    print("usage: icmp_harness.py --outcome RESULT ICMP_EVAL ARCH | --run-check PROBE_DIR ARCH...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
