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


# ---------------------------------------------------------------- 06B-3F: session-wide reconciliation
# One window per architecture: read A before QEMU is spawned, final reads after QEMU has exited.
# Reported SEPARATELY (session.json): it never enters the per-probe results, never changes a probe
# verdict and never changes run_outcome() or the exit code of the run.
NOT_COMPARED_REASON = {
    "arp_in_ok": "ARP table (family arp): no pcap mapping in the harness",
    "arp_in_drop": "ARP table (family arp): no pcap mapping in the harness",
    "arp_out_ok": "ARP output towards the guest: not a guest frame",
    "arp_out_drop": "ARP output towards the guest: not a guest frame",
    "drop_input_backstop": "input hook (after prerouting): no pcap mapping in the harness",
    "drop_forward": "forward hook (after prerouting): no pcap mapping in the harness",
    "allow_out_svc": "output towards the guest: not a guest frame",
    "drop_out": "output towards the guest: not a guest frame",
}


def _values_ok(values):
    return isinstance(values, dict) and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0
                                            for v in values.values())


def session_reconcile(frames, read_before, final_reads, classes, qemu, capture, guard=GUARD_S,
                      required_finals=2, final_read_error=None):
    """frames: every frame of the tap0 pcap as {"t", "cls"} (cls None for frames not sent by the guest).
    read_before: counter read before QEMU was spawned; final_reads: every counter read taken after QEMU
    exit was confirmed (all kept; the FIRST one closes the window, the others check stability).
    qemu: {"no_qemu_before": bool, "pids_before": list, "pids_before_error": str | None,
           "exit_confirmed": bool, "exit_confirmed_t": float,
           "pids_after_exit": list | None, "pids_after_exit_error": str | None}
    capture: {"tshark_rc": int|None, "drop_verdict": "PASS"|..., "pcap_readable": bool}
    Verdict: ERROR (invalid measurement / precondition) > FAIL (real mismatch) > UNVERIFIED > PASS.
    06B-3FR: guest frames before the window are checked (all classes, ARP included); QEMU process
    state after exit is part of the verdict; F1 and F2 are both required and a final read error
    blocks PASS; every compared class must be present in A, F1 and F2 (a missing counter is never 0)."""
    out = {"verdict": None, "reasons": [], "guard_s": guard, "classes_compared": list(classes),
           "reads": {"before": read_before, "finals": final_reads, "required_finals": required_finals,
                     "final_read_error": final_read_error},
           "qemu": qemu, "capture": capture}

    def done(verdict, *reasons):
        out["verdict"] = verdict
        out["reasons"] += list(reasons)
        return out

    # --- QEMU process state before boot and after exit (06B-3FR: both are part of the verdict)
    if not qemu.get("no_qemu_before") or qemu.get("pids_before") != [] or qemu.get("pids_before_error"):
        return done("ERROR", f"QEMU process state before boot not clean or not verified: "
                             f"no_qemu_before={qemu.get('no_qemu_before')!r}, pids_before={qemu.get('pids_before')!r}, "
                             f"error={qemu.get('pids_before_error')!r}")
    if not qemu.get("exit_confirmed"):
        return done("ERROR", "QEMU exit was not confirmed before the final reads")
    pa = qemu.get("pids_after_exit")
    if not isinstance(pa, list) or qemu.get("pids_after_exit_error"):
        return done("ERROR", f"QEMU process state after exit could not be verified: pids_after_exit={pa!r}, "
                             f"error={qemu.get('pids_after_exit_error')!r}")
    if pa:
        return done("ERROR", f"QEMU process(es) still present after exit was confirmed: {pa}")

    # --- final reads: F1 and F2 required, no read error
    if final_read_error:
        return done("ERROR", f"a final counter read failed: {final_read_error}")
    if not isinstance(final_reads, list) or len(final_reads) < required_finals:
        n = len(final_reads) if isinstance(final_reads, list) else final_reads
        return done("ERROR", f"{n} final read(s) after QEMU exit, {required_finals} required "
                             "(one snapshot is no evidence of stability)")

    # --- measurement data: values, completeness of compared classes, times
    reads = [("A", read_before)] + [(f"F{i + 1}", r) for i, r in enumerate(final_reads)]
    for name, r in reads:
        if not isinstance(r, dict) or not _values_ok(r.get("values")):
            return done("ERROR", f"counter read {name} without valid values (non-negative integers): {r!r:.200}")
        missing = [k for k in classes if k not in r["values"]]
        if missing:
            return done("ERROR", f"counter read {name} lacks compared counter(s) {missing}; a missing counter is not 0")
        if not (_finite(r.get("t_start")) and _finite(r.get("t_end"))):
            return done("ERROR", f"counter read {name} times not finite: {r.get('t_start')!r}, {r.get('t_end')!r}")
    if not _finite(qemu.get("exit_confirmed_t")):
        return done("ERROR", f"QEMU exit time not finite: {qemu.get('exit_confirmed_t')!r}")
    seq = [read_before["t_start"], read_before["t_end"], qemu["exit_confirmed_t"]]
    for r in final_reads:
        seq += [r["t_start"], r["t_end"]]
    if any(a > b for a, b in zip(seq, seq[1:])):
        return done("ERROR", "times out of order (need read_before <= QEMU exit confirmed <= final reads, "
                             f"each read start <= end, final reads in order): {seq}")
    first = final_reads[0]
    delta = {k: first["values"][k] - read_before["values"][k] for k in classes}
    recon = reconcile(frames, read_before, first, delta, classes, guard)
    out["reconciliation"] = recon
    nc = {}
    for k in sorted((set(first["values"]) | set(read_before["values"])) - set(classes)):
        reason = NOT_COMPARED_REASON.get(k, "no pcap mapping in the harness")
        if k in first["values"] and k in read_before["values"]:
            nc[k] = {"delta": first["values"][k] - read_before["values"][k], "reason": reason}
        else:
            nc[k] = {"delta": None, "reason": reason, "missing_in": "A" if k not in read_before["values"] else "F1"}
    out["not_compared"] = nc
    if recon["verdict"] == "ERROR":
        return done("ERROR", f"measurement data invalid: {recon.get('error')}")

    # --- guest frames outside the window (all classes), capture, stability
    a_start, a_end = read_before["t_start"], read_before["t_end"]
    pre = [{"t": fr["t"], "cls": fr.get("cls"),
            "reason": ("before A.start - guard (outside the window)" if fr["t"] < a_start - guard
                       else "in the start edge [A.start - guard, A.end]")}
           for fr in frames if fr.get("cls") is not None and fr["t"] <= a_end]
    late = [{"t": fr["t"], "cls": fr.get("cls"), "reason": "after QEMU exit was confirmed"}
            for fr in frames if fr.get("cls") is not None and fr["t"] > qemu["exit_confirmed_t"]]
    capture_ok = (capture.get("tshark_rc") == 0 and capture.get("drop_verdict") == "PASS"
                  and capture.get("pcap_readable") is True)
    unstable = {k: [r["values"][k] for r in final_reads] for k in classes
                if len({r["values"][k] for r in final_reads}) > 1}
    out["guest_frames_before_window"] = pre
    out["unstable_after_exit"] = unstable
    out["guest_frames_after_exit"] = late
    low = [k for k, v in recon["per_class"].items() if v["delta"] < v["lo"]]

    if recon["verdict"] == "FAIL" and (capture_ok or low):
        # with an incomplete capture only "counter below the captured frames" is a determined mismatch
        return done("FAIL", "counter delta outside [certain, certain + edges] for: "
                    + ", ".join(k for k, v in recon["per_class"].items() if v["status"] == "FAIL"))
    if pre:
        out["reasons"].append(f"{len(pre)} guest frame(s) at or before the session read before boot "
                              f"(QEMU was not supposed to run yet): {sorted({str(x['cls']) for x in pre})}")
    if not capture_ok:
        out["reasons"].append(f"capture not complete: {capture}")
    if unstable:
        out["reasons"].append(f"compared counters still changed after QEMU exit: {unstable}")
    if late:
        out["reasons"].append(f"{len(late)} guest frame(s) after QEMU exit was confirmed")
    if recon["verdict"] == "UNVERIFIED":
        out["reasons"].append("frames in the edge zones of the session window: " + ", ".join(
            k for k, v in recon["per_class"].items() if v["status"] == "UNVERIFIED"))
    if recon["verdict"] == "FAIL":
        out["reasons"].append("counter/pcap mismatch, but the capture is not complete")
    if out["reasons"]:
        return done("UNVERIFIED")
    return done("PASS")
