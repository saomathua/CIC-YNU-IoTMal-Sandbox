"""06B-3DR — reconcile nft counter deltas with tap0 pcap frames without hiding boundary effects.

Each counter read records when the `nft -j list counters` call started and ended (t_start, t_end).
The snapshot happens somewhere inside that interval, so for a probe with reads A (before) and B
(after) every guest frame falls into one of four zones by its capture timestamp t:

    outside      t <  A.t_start - GUARD   or   t > B.t_end         -> not in the delta
    edge_start   A.t_start - GUARD <= t <= A.t_end                  -> may or may not be in the delta
    certain      A.t_end < t < B.t_start - GUARD                     -> in the delta
    edge_end     B.t_start - GUARD <= t <= B.t_end                  -> may or may not be in the delta

GUARD covers the delay between the capture timestamp of a frame and the moment the same frame
reaches the nft counter (assumed: the timestamp is earlier, by at most GUARD). Its value (20 ms) is
an ASSUMPTION that has NOT been measured. It only widens the ambiguous zones, never the certain zone.
Every PASS below depends on that assumption: a frame whose counter hit lags its capture timestamp by
more than GUARD can be placed in the wrong zone, and the reconciliation can then be wrong in either
direction (including a wrong PASS).

Per counter class:  lo = certain frames,  hi = certain + edge frames,  d = counter delta
    FAIL        d < lo or d > hi           a real mismatch, whatever the edge frames did
    UNVERIFIED  lo <= d <= hi and hi > lo  edge frames make the comparison undecidable
    PASS        d == lo == hi              no ambiguity and the counter equals the pcap
Overall: FAIL if any class fails, else UNVERIFIED if any class is undecidable, else PASS.
Nothing is offset or compensated: within the GUARD assumption, two errors of opposite sign at the two
edges cannot cancel, because any edge frame makes the class UNVERIFIED.

06B-3DR1: the inputs are validated first. Read times must be finite numbers with
A.t_start <= A.t_end <= B.t_start <= B.t_end, GUARD finite and >= 0, every frame time finite, every
counter delta a non-negative integer. Anything else returns verdict "ERROR" (a measurement error,
never a PASS) with the reason; no zone is computed.
"""
import math

GUARD_S = 0.020
ZONES = ("outside", "edge_start", "certain", "edge_end")


def zone(t, read_a, read_b, guard=GUARD_S):
    if t < read_a["t_start"] - guard or t > read_b["t_end"]:
        return "outside"
    if t <= read_a["t_end"]:
        return "edge_start"
    if t < read_b["t_start"] - guard:
        return "certain"
    return "edge_end"


def _finite(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def validate(frames, read_a, read_b, delta, guard):
    """Returns None if the measurement data is usable, else the reason (str)."""
    try:
        ts = [read_a["t_start"], read_a["t_end"], read_b["t_start"], read_b["t_end"]]
    except (KeyError, TypeError) as e:
        return f"read times missing: {e!r}"
    if not all(_finite(x) for x in ts):
        return f"read times not finite numbers: {ts}"
    if not ts[0] <= ts[1] <= ts[2] <= ts[3]:
        return f"read times out of order (need A.start <= A.end <= B.start <= B.end): {ts}"
    if not _finite(guard) or guard < 0:
        return f"guard not a finite non-negative number: {guard!r}"
    for fr in frames:
        if not _finite(fr.get("t")):
            return f"frame time not a finite number: {fr.get('t')!r}"
    for k, d in delta.items():
        if not isinstance(d, int) or isinstance(d, bool) or d < 0:
            return f"counter delta of {k} is not a non-negative integer: {d!r}"
    return None


def reconcile(frames, read_a, read_b, delta, classes, guard=GUARD_S):
    """frames: [{"t": float, "cls": str|None}]; delta: {counter: packets}; classes: counters compared.
    Returns {"verdict", "per_class": {cls: {...}}, "not_compared": {...}, "guard_s", "reads"}; with
    invalid inputs {"verdict": "ERROR", "error": reason, "per_class": {}, ...}."""
    err = validate(frames, read_a, read_b, delta, guard)
    if err:
        return {"verdict": "ERROR", "error": err, "per_class": {}, "guard_s": guard, "not_compared": {},
                "reads": {"before": dict(read_a) if isinstance(read_a, dict) else read_a,
                          "after": dict(read_b) if isinstance(read_b, dict) else read_b}}
    per = {k: {"certain": 0, "edge_start": [], "edge_end": [], "delta": delta.get(k, 0)} for k in classes}
    for fr in frames:
        k = fr.get("cls")
        if k not in per:
            continue
        z = zone(fr["t"], read_a, read_b, guard)
        if z == "certain":
            per[k]["certain"] += 1
        elif z in ("edge_start", "edge_end"):
            per[k][z].append(fr["t"])
    verdicts = []
    for k, v in per.items():
        lo = v["certain"]
        hi = lo + len(v["edge_start"]) + len(v["edge_end"])
        d = v["delta"]
        v["lo"], v["hi"] = lo, hi
        if d < lo or d > hi:
            v["status"] = "FAIL"
        elif hi > lo:
            v["status"] = "UNVERIFIED"
        else:
            v["status"] = "PASS"
        verdicts.append(v["status"])
    overall = "FAIL" if "FAIL" in verdicts else "UNVERIFIED" if "UNVERIFIED" in verdicts else "PASS"
    return {"verdict": overall, "per_class": per, "guard_s": guard,
            "not_compared": {k: d for k, d in delta.items() if k not in per and d},
            "reads": {"before": {x: read_a[x] for x in ("t_start", "t_end")},
                      "after": {x: read_b[x] for x in ("t_start", "t_end")}}}


# Checks whose failure is a determined fact only when the guest really ran the probe (tool present).
GUEST_SIDE_CHECKS = ("guest_connection_failed", "probe_packets_in_tap0_pcap", "probe_packets_hit_expected_counter")
# Checks that only say whether the probe CAN be judged; their failure is never a FAIL by itself.
PRECONDITION_CHECKS = ("control_alive_same_dst_proto_port",)
# Checks computed from the pcap inside the counter-read window: meaningless when the read times are invalid.
WINDOW_DERIVED_CHECKS = ("probe_packets_in_tap0_pcap", "probe_packets_hit_expected_counter")


def determined_failures(checks, recon, expected_class, tool_missing=False):
    """06B-3DR1: failures that are established facts, independent of a missing tool or control."""
    out = []
    exp = recon.get("per_class", {}).get(expected_class, {})
    if recon.get("verdict") == "FAIL" or exp.get("status") == "FAIL":
        out.append("counter_reconciliation")
    for k, v in checks.items():
        if v or k in PRECONDITION_CHECKS:
            continue
        if k in GUEST_SIDE_CHECKS and tool_missing:
            continue   # the guest never sent the probe: this check could not be performed
        if k in WINDOW_DERIVED_CHECKS and recon.get("verdict") == "ERROR":
            continue   # computed from an invalid window: a measurement error, not a determined failure
        out.append(k)
    if not tool_missing and exp.get("status") == "PASS" and exp.get("delta", 0) == 0:
        out.append("expected_counter_not_increased")
    return out


def probe_verdict(checks, recon, expected_class, tool_missing=False, control_alive=True):
    """checks: boolean checks other than the counter reconciliation.
    Returns (verdict text, ok). ok is True only for ĐẠT.
    Order (06B-3DR1): determined failures -> FAIL, always, even with a missing tool or control;
    then a measurement error -> LỖI PHÉP ĐO; then conditions that prevent judging (missing tool,
    no live control, counter-window edges) -> CHƯA KIỂM CHỨNG; only then ĐẠT."""
    if determined_failures(checks, recon, expected_class, tool_missing):
        return "FAIL", False
    if recon.get("verdict") == "ERROR":
        return f"LỖI PHÉP ĐO ({recon.get('error', 'invalid measurement data')})", False
    if tool_missing:
        return "CHƯA KIỂM CHỨNG (guest thiếu công cụ probe)", False
    if not control_alive:
        return "CHƯA KIỂM CHỨNG (không có đối chứng sống)", False
    if recon.get("verdict") == "UNVERIFIED":
        return "CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)", False
    exp = recon["per_class"].get(expected_class, {})
    if recon.get("verdict") != "PASS" or exp.get("status") != "PASS" or exp.get("delta", 0) <= 0:
        return "FAIL", False
    return "ĐẠT", True


def run_outcome(results):
    """One architecture's result.json "results" -> "PASS", "UNVERIFIED: ..." or "FAIL: ...".
    Only probe records whose verdict is CHƯA KIỂM CHỨNG may be undecided; any other failed check
    (or a failed probe) is a FAIL. UNVERIFIED is never a pass."""
    bad = [r for r in results if not r["ok"]]
    if not bad:
        return "PASS"
    hard = [r["test"] for r in bad if not (r["test"].startswith("probe ") and "-> CHƯA KIỂM CHỨNG" in r["test"])]
    if hard:
        return "FAIL: " + "; ".join(hard[:5])
    return "UNVERIFIED: " + "; ".join(r["test"] for r in bad[:10])
