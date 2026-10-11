#!/usr/bin/env python3
"""06B-4D1 — OFFLINE evaluator: one capture file + one counter-snapshot file + one time window -> JSON.

Reads only: a pcap/pcapng file, a counters-raw.jsonl file (format written by probe_matrix.counters_read:
one JSON object per line {"label", "t_start", "t_end", "raw": <nft -j list counters output>}), and the
labels of the two reads that bound the window. It sends nothing, runs no command, controls no guest.
Classification and reconciliation are those of l2frames.py (classify / reconcile_l2); the guard is
counter_window.GUARD_S (20 ms, an UNMEASURED assumption).

    python3 l2eval.py --pcap tap0.pcapng --counters counters-raw.jsonl --tap-mac MAC \
                      --before LABEL --after LABEL [--classes c1,c2,...] [--out result.json]

Exit: 0 PASS, 1 FAIL, 4 UNVERIFIED, 2 ERROR (unreadable capture, invalid or missing measurement data,
bad arguments). The JSON is written in every case (with --out), including ERROR. Nothing missing is
ever replaced by 0: a missing counter, a missing or duplicate label, an unreadable capture or a
malformed snapshot is an ERROR with the reason.
"""
import argparse
import collections
import hashlib
import json
import math
import sys

import counter_window
import l2frames as L

EXIT = {"PASS": 0, "FAIL": 1, "UNVERIFIED": 4, "ERROR": 2}
ASSUMPTION = "guard covers the delay from capture timestamp to nft counter hit; NOT measured"


class InputError(Exception):
    """Invalid or missing measurement data (never a PASS, never 0)."""


def _sha256(path):
    try:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError as e:
        return f"unreadable: {e}"


def _finite(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def load_reads(path):
    """counters-raw.jsonl -> {label: {"t_start", "t_end", "values"}}. Any malformed line, duplicate label,
    non-finite time or non-integer counter is an InputError."""
    try:
        lines = open(path).read().splitlines()
    except OSError as e:
        raise InputError(f"cannot read counter file {path}: {e}") from e
    reads = {}
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        # 06B-4D1R: the type of every level is checked before it is used; anything else is an InputError
        # (never skipped, never replaced by 0).
        try:
            rec = json.loads(line)
        except ValueError as e:
            raise InputError(f"{path}:{n}: line is not JSON ({e})") from e
        if not isinstance(rec, dict):
            raise InputError(f"{path}:{n}: record is {type(rec).__name__}, expected an object")
        for k in ("label", "t_start", "t_end", "raw"):
            if k not in rec:
                raise InputError(f"{path}:{n}: record field {k!r} missing")
        label, t0, t1, raw = rec["label"], rec["t_start"], rec["t_end"], rec["raw"]
        if not isinstance(raw, str):
            raise InputError(f"{path}:{n}: field 'raw' is {type(raw).__name__}, expected the nft JSON text")
        try:
            doc = json.loads(raw)
        except ValueError as e:
            raise InputError(f"{path}:{n}: field 'raw' is not JSON ({e})") from e
        if not isinstance(doc, dict) or "nftables" not in doc:
            raise InputError(f"{path}:{n}: nft output is not an object with 'nftables'")
        objs = doc["nftables"]
        if not isinstance(objs, list):
            raise InputError(f"{path}:{n}: 'nftables' is {type(objs).__name__}, expected a list")
        if not isinstance(label, str) or not label:
            raise InputError(f"{path}:{n}: label missing")
        if label in reads:
            raise InputError(f"{path}:{n}: duplicate label {label!r}")
        if not (_finite(t0) and _finite(t1)):
            raise InputError(f"{path}:{n}: read times not finite numbers ({t0!r}, {t1!r})")
        values = {}
        for i, o in enumerate(objs):
            if not isinstance(o, dict):
                raise InputError(f"{path}:{n}: nftables[{i}] is {type(o).__name__}, expected an object")
            if "counter" not in o:
                continue                                  # metainfo and other non-counter objects
            c = o["counter"]
            if not isinstance(c, dict):
                raise InputError(f"{path}:{n}: nftables[{i}].counter is {type(c).__name__}, expected an object")
            if "name" not in c or "packets" not in c:
                raise InputError(f"{path}:{n}: nftables[{i}].counter lacks 'name' or 'packets'")
            name, pk = c["name"], c["packets"]
            if not isinstance(name, str) or not name:
                raise InputError(f"{path}:{n}: nftables[{i}].counter name is not a non-empty string: {name!r}")
            if not isinstance(pk, int) or isinstance(pk, bool) or pk < 0:
                raise InputError(f"{path}:{n}: counter {name} packets not a non-negative integer: {pk!r}")
            if name in values:
                raise InputError(f"{path}:{n}: counter {name} listed twice")
            values[name] = pk
        if not values:
            raise InputError(f"{path}:{n}: read {label!r} holds no counter")
        reads[label] = {"t_start": t0, "t_end": t1, "values": values}
    if not reads:
        raise InputError(f"{path}: no counter read")
    return reads


def _reasons(rec):
    out = []
    if rec["verdict"] == "ERROR":
        return [rec.get("error", "invalid measurement data")]
    for k, v in rec["per_class"].items():
        if v["status"] == "FAIL":
            out.append(f"{k}: counter delta {v['delta']} outside [{v['lo']}, {v['hi']}] "
                       f"(certain frames {v['certain']}, edge frames {v['hi'] - v['lo']})")
        elif v["status"] == "UNVERIFIED":
            out.append(f"{k}: {v['hi'] - v['lo']} edge frame(s) make [{v['lo']}, {v['hi']}] undecidable "
                       f"(delta {v['delta']})")
    if rec.get("no_counter_frames"):
        kinds = collections.Counter(f["cls"] for f in rec["no_counter_frames"])
        out.append(f"frames without a counter mapping inside the window: {dict(kinds)}")
    if not out:
        out.append("every compared class: counter delta equals the certain frames, no edge frame, "
                   "no frame without a counter inside the window")
    return out


def check_classes(classes):
    """06B-4D1R: None -> every frame-mapped class. Otherwise a NON-EMPTY list of distinct, known,
    frame-mapped class names (a valid subset is allowed). Raises ValueError with the reason."""
    if classes is None:
        return list(L.COUNTER_CLASSES)
    if isinstance(classes, str) or not isinstance(classes, (list, tuple)):
        raise ValueError(f"classes must be a list of class names, got {type(classes).__name__}")
    classes = list(classes)
    if not classes:
        raise ValueError("empty list of classes: nothing would be compared")
    bad = [c for c in classes if not isinstance(c, str) or c not in L.COUNTER_CLASSES]
    if bad:
        raise ValueError(f"unknown or not frame-mapped class name(s): {bad!r}; allowed: {list(L.COUNTER_CLASSES)}")
    dup = sorted({c for c in classes if classes.count(c) > 1})
    if dup:
        raise ValueError(f"duplicate class name(s): {dup}")
    return classes


def evaluate(pcap, counters, tap_mac, before, after, classes=None, guard=counter_window.GUARD_S):
    """Returns the result dict (never raises for bad input: those become verdict ERROR)."""
    try:
        classes = check_classes(classes)
        class_error = None
    except ValueError as e:
        class_error = f"invalid argument: {e}"
        classes = classes if isinstance(classes, (list, tuple)) else repr(classes)
    res = {"input": {"pcap": pcap, "pcap_sha256": _sha256(pcap), "counters": counters,
                     "counters_sha256": _sha256(counters), "tap_mac": tap_mac, "before": before, "after": after,
                     "classes": classes, "guard_s": guard},
           "assumption": ASSUMPTION, "verdict": "ERROR", "reasons": [], "per_class": {},
           "frames_in_window": {}, "frames_outside_window": 0, "no_counter_frames": [], "not_compared": {}}
    if class_error:
        res["error"] = class_error
        res["reasons"] = [class_error]
        return res
    try:
        reads = load_reads(counters)
        for lbl in (before, after):
            if lbl not in reads:
                raise InputError(f"read {lbl!r} not found in {counters}")
        ra, rb = reads[before], reads[after]
        frames = L.classified_frames(pcap, tap_mac)
    except InputError as e:
        res["error"] = f"invalid measurement data: {e}"
    except L.FrameReadError as e:
        res["error"] = f"capture read error: {e}"
    except ValueError as e:                       # e.g. a malformed TAP MAC
        res["error"] = f"invalid argument: {e}"
    if "error" in res:
        res["reasons"] = [res["error"]]
        return res
    res["reads"] = {"before": {k: ra[k] for k in ("t_start", "t_end")},
                    "after": {k: rb[k] for k in ("t_start", "t_end")}}
    rec = L.reconcile_l2(frames, ra, rb, classes, guard)
    res["verdict"] = rec["verdict"]
    if rec["verdict"] == "ERROR":
        res["error"] = rec.get("error", "invalid measurement data")
    res["per_class"] = rec.get("per_class", {})
    res["no_counter_frames"] = rec.get("no_counter_frames", [])
    inside = collections.Counter()
    if rec["verdict"] != "ERROR":
        for f in frames:
            if counter_window.zone(f["t"], ra, rb, guard) == "outside":
                res["frames_outside_window"] += 1
            else:
                inside[f"{f['direction']}/{f['cls']}"] += 1
    res["frames_in_window"] = dict(sorted(inside.items()))
    # Counters present in the snapshots but not compared: listed with their delta and the reason.
    # A counter missing in one read is reported as missing, never as 0.
    names = sorted(set(ra["values"]) | set(rb["values"]))
    for k in names:
        if k in classes:
            continue
        a, b = ra["values"].get(k), rb["values"].get(k)
        why = L.UNOBSERVABLE.get(k, "not in the compared classes")
        if a is None or b is None:
            res["not_compared"][k] = {"delta": None, "missing_in": "before" if a is None else "after", "reason": why}
        else:
            res["not_compared"][k] = {"delta": b - a, "reason": why}
    res["reasons"] = _reasons(rec)
    return res


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--counters", required=True)
    ap.add_argument("--tap-mac", required=True)
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--classes", default=None, help="comma-separated; default: every frame-mapped counter class")
    ap.add_argument("--out", default=None)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return EXIT["ERROR"]
    # 06B-4D1R: no silent filtering: "" -> [] and "a,,b" -> ["a", "", "b"], both rejected by check_classes
    classes = None if a.classes is None else ([] if a.classes == "" else a.classes.split(","))
    res = evaluate(a.pcap, a.counters, a.tap_mac, a.before, a.after, classes)
    text = json.dumps(res, indent=1, sort_keys=True, ensure_ascii=False)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
    print(f"{res['verdict']}: " + "; ".join(res["reasons"]))
    return EXIT[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
