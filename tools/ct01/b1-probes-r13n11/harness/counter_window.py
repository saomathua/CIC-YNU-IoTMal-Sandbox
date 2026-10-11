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
This describes reconcile BEFORE the optional R4 closure: every edge frame keeps that initial
comparison UNVERIFIED. Closure may subsequently establish a unique boundary allocation consistent
with H0 and neighbouring snapshots. This is a conditional inference, not a measurement of a frame's
counter-hit time or proof that compensating anomalies did not occur.

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


# ---------------------------------------------------------------- R4: closing the edge ambiguity with the neighbouring snapshots
# A frame whose capture timestamp lies in the read interval of a snapshot may or may not be in that snapshot's
# counter value (the snapshot instant inside [t_start, t_end] is unknown). That is the only source of UNVERIFIED
# handled here. The neighbouring snapshots of the same session often settle it: a frame that was NOT in the counter at
# the after-read MUST appear in the counter at the next read that is clear of it. Nothing is offset or compensated and
# the guard is not changed; the frames are never dropped.
#
# Model (hypothesis H0, with the same GUARD assumption as the rest of the module):
#   every captured frame of a class is counted exactly once, at an instant c in [t, t + GUARD] (t = capture timestamp);
#   snapshot i is taken at an unknown instant s_i in [read_i.t_start, read_i.t_end]; its counter value contains exactly
#   the frames with c <= s_i. Per snapshot a frame is IN (t < t_start - GUARD: surely counted), OUT (t > t_end: surely
#   not counted) or AMB (anything else). a_j = the first snapshot of the chain that counts frame j (m+1: none).
#   Each segment between consecutive snapshots of the chain gives ONE equation: frames first counted there = counter
#   difference. Every segment is checked separately (a total over a large window is never used as a proof).
# A class is RESOLVED only when (1) at least one allocation satisfies every segment equation and (2) all satisfying
# allocations give the same pair (y_start, y_end): how many frames of the start edge were counted after the before-read
# and how many frames of the end edge were counted by the after-read. No allocation -> H0 is contradicted somewhere in the
# chain: the class stays UNVERIFIED (never PASS, and never turned into a FAIL of this case). Several allocations with
# different pairs -> UNVERIFIED. Independent FAILs (delta outside [certain, certain + edges]) are decided before and are
# never touched. Limits that remain: the guard assumption, and two opposite anomalies that cancel inside ONE segment (or in
# adjacent segments with identical counts) are not visible to any counter-based reconciliation.
CLOSURE_DEADLINE_S = 10.0   # PROPOSED operational limit for taking neighbouring snapshots into account; NOT a measured guard
CLOSURE_MAX_FREE_FRAMES = 14
CLOSURE_MAX_SOLUTIONS = 200000


def _read_status(t, read, guard):
    if t > read["t_end"]:
        return "OUT"
    if t < read["t_start"] - guard:
        return "IN"
    return "AMB"


def _solve_allocations(times, chain, values, guard, ia, ib):
    """-> {"state": "inconsistent"|"unique"|"ambiguous"|"too_many"|"decreased", "outcomes": [[y_start, y_end], ...],
    "solutions": int}. chain: reads in time order; values: the class counter at each read; ia/ib: chain indexes of the
    before/after reads of the case."""
    m = len(chain) - 1
    need = [values[i] - values[i - 1] for i in range(1, m + 1)]
    if any(n < 0 for n in need):
        return {"state": "decreased", "outcomes": [], "solutions": 0}
    fixed = [0] * (m + 2)
    free = []
    out_fixed = [0, 0]
    for t in times:
        st = [_read_status(t, r, guard) for r in chain]
        dom = []
        for a in range(m + 2):
            if a <= m and st[a] == "OUT":
                continue
            if a >= 1 and st[a - 1] == "IN":
                continue
            if a == 0 and st[0] != "IN":
                continue        # counted AT the first read: no segment before it corroborates that (the chain's first read is edge-free)
            if a == m + 1 and st[m] != "OUT":
                continue        # "not counted within the chain" is only a fact for a frame after the last read (edge-free last read)
            dom.append(a)
        if not dom:
            return {"state": "inconsistent", "outcomes": [], "solutions": 0}
        amb_a, amb_b = st[ia] == "AMB", st[ib] == "AMB"
        if len(dom) == 1:
            a = dom[0]
            fixed[a] += 1
            if amb_a and a > ia:
                out_fixed[0] += 1
            if amb_b and a <= ib:
                out_fixed[1] += 1
        else:
            free.append((dom, amb_a, amb_b))
    for i in range(1, m + 1):
        if fixed[i] > need[i - 1]:
            return {"state": "inconsistent", "outcomes": [], "solutions": 0}
    if len(free) > CLOSURE_MAX_FREE_FRAMES:
        return {"state": "too_many", "outcomes": [], "solutions": 0}
    outcomes, count = set(), [0]
    counts = list(fixed)

    def rec(k, yA, yB):
        if count[0] > CLOSURE_MAX_SOLUTIONS:
            return
        if k == len(free):
            if all(counts[i] == need[i - 1] for i in range(1, m + 1)):
                outcomes.add((yA, yB))
                count[0] += 1
            return
        rest = len(free) - k - 1
        dom, amb_a, amb_b = free[k]
        for a in dom:
            if 1 <= a <= m:
                counts[a] += 1
                if counts[a] > need[a - 1]:
                    counts[a] -= 1
                    continue
            short = sum(need[i - 1] - counts[i] for i in range(1, m + 1))      # >= 0 here; each remaining frame can fill at most one unit
            if short <= rest:
                rec(k + 1, yA + (1 if amb_a and a > ia else 0), yB + (1 if amb_b and a <= ib else 0))
            if 1 <= a <= m:
                counts[a] -= 1

    rec(0, out_fixed[0], out_fixed[1])
    if count[0] > CLOSURE_MAX_SOLUTIONS:
        return {"state": "too_many", "outcomes": [], "solutions": count[0]}
    outs = sorted([list(o) for o in outcomes])
    state = "inconsistent" if not outs else "unique" if len(outs) == 1 else "ambiguous"
    return {"state": state, "outcomes": outs, "solutions": count[0]}


def _closure_read_errors(reads_seq, labels):
    """Validate snapshot intervals and sequence before using them as closure evidence."""
    errors = []
    for i, read in enumerate(reads_seq):
        label = labels[i]
        if not isinstance(read, dict) or not all(_finite(read.get(k)) for k in ("t_start", "t_end")):
            errors.append(f"counter read {label!r}: timestamps not finite numbers")
        elif read["t_start"] > read["t_end"]:
            errors.append(f"counter read {label!r}: t_start > t_end ({read['t_start']!r} > {read['t_end']!r})")
    for i in range(len(reads_seq) - 1):
        a, b = reads_seq[i], reads_seq[i + 1]
        if isinstance(a, dict) and isinstance(b, dict) and _finite(a.get("t_end")) and _finite(b.get("t_start")) \
                and a["t_end"] > b["t_start"]:
            errors.append(f"counter reads not in time order / overlapping: {labels[i]!r}.t_end > {labels[i + 1]!r}.t_start")
    return errors


def close_edges(recon, frames, reads_seq, labels, ia, ib, guard=GUARD_S, deadline=CLOSURE_DEADLINE_S):
    """Try to resolve the UNVERIFIED classes of `recon` (counter_window.reconcile / l2frames.reconcile_l2 result) with the
    snapshots next to the case. reads_seq: every counter read of the group in time order, as {"t_start","t_end","values"};
    labels: their labels; ia/ib: indexes of the case's before/after read. Mutates and returns recon. Classes that are not
    UNVERIFIED (PASS, FAIL) are never touched; the overall verdict is recomputed (FAIL > UNVERIFIED > PASS); frames without a
    counter mapping (recon["no_counter_frames"]) keep it UNVERIFIED. Invalid read times prevent closure and are returned as
    closure.measurement_errors, including when an independent FAIL already determines the verdict."""
    per = recon.get("per_class") or {}
    info = {"applied": False, "deadline_s": deadline, "guard_s": guard, "model": "H0 per-segment allocation; see module comment", "classes": {}}
    recon["closure"] = info
    read_errors = _closure_read_errors(reads_seq, labels)
    info["measurement_errors"] = read_errors
    if read_errors:
        for k, v in per.items():
            if v.get("status") == "UNVERIFIED":
                info["classes"][k] = {"resolved": False, "state": "invalid_reads", "reason": "; ".join(read_errors)}
        return recon
    if recon.get("verdict") not in ("UNVERIFIED",) or not per:
        return recon
    for k, v in per.items():
        if v.get("status") != "UNVERIFIED":
            continue
        ci = {"resolved": False}
        info["classes"][k] = ci
        ra, rb = reads_seq[ia], reads_seq[ib]

        def val(i):
            x = (reads_seq[i].get("values") or {}).get(k)
            return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else None
        before, after = [], []
        for i in range(ia - 1, -1, -1):
            if ra["t_start"] - reads_seq[i]["t_end"] > deadline or val(i) is None:
                break
            before.append(i)
        for i in range(ib + 1, len(reads_seq)):
            if reads_seq[i]["t_start"] - rb["t_end"] > deadline or val(i) is None:
                break
            after.append(i)
        if any(val(i) is None for i in range(ia, ib + 1)):
            ci["reason"] = "counter value missing in the case window reads"
            continue
        if not before and not after:
            ci["reason"] = f"no neighbouring counter read within {deadline:g} s: edge frames stay undecided"
            continue
        times = [f["t"] for f in frames if f.get("cls") == k and _finite(f.get("t"))]
        nb, na = min(1, len(before)), min(1, len(after))
        last = None
        while True:
            idx = list(reversed(before[:nb])) + list(range(ia, ib + 1)) + after[:na]
            first_amb = any(_read_status(t, reads_seq[idx[0]], guard) == "AMB" for t in times)
            last_amb = any(_read_status(t, reads_seq[idx[-1]], guard) == "AMB" for t in times)
            if first_amb or last_amb:
                moved = False
                if first_amb and nb < len(before):
                    nb += 1
                    moved = True
                if last_amb and na < len(after):
                    na += 1
                    moved = True
                if moved:
                    continue
                last = ({"state": "open_boundary", "outcomes": [], "solutions": 0}, [labels[i] for i in idx])
                break
            sol = _solve_allocations(times, [reads_seq[i] for i in idx], [val(i) for i in idx], guard, idx.index(ia), idx.index(ib))
            last = (sol, [labels[i] for i in idx])
            if sol["state"] != "ambiguous" or (nb >= len(before) and na >= len(after)):
                break
            nb, na = min(nb + 1, len(before)), min(na + 1, len(after))
        sol, used = last
        ci.update(state=sol["state"], reads_used=used, solutions=sol["solutions"], outcomes=sol["outcomes"])
        if sol["state"] == "unique":
            yA, yB = sol["outcomes"][0]
            ci.update(resolved=True, start_edge_frames_counted_after_before_read=yA, end_edge_frames_counted_by_after_read=yB)
            v["status_before_closure"] = "UNVERIFIED"
            v["status"] = "PASS"
            v["closure"] = {k2: ci[k2] for k2 in ("reads_used", "start_edge_frames_counted_after_before_read", "end_edge_frames_counted_by_after_read", "solutions")}
        else:
            ci["reason"] = {"inconsistent": "no allocation of the frames fits every segment: H0 contradicted in the neighbouring segments (not attributed to the case, stays UNVERIFIED)",
                            "decreased": "a counter decreased/reset in the chain",
                            "open_boundary": "the first or last read of the chain has frames of the class in its own edge zone and no further read lies within the deadline (nothing corroborates the edge frames)", "too_many": "too many ambiguous frames to enumerate",
                            "ambiguous": "several allocations with different outcomes remain and no further read within the deadline"}[sol["state"]]
    info["applied"] = True
    verdicts = [v["status"] for v in per.values()]
    recon["verdict"] = "FAIL" if "FAIL" in verdicts else "UNVERIFIED" if ("UNVERIFIED" in verdicts or recon.get("no_counter_frames")) else "PASS"
    return recon


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
