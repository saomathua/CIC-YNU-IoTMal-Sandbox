#!/usr/bin/env python3
"""06B-4D1 — tests of l2eval.py on SYNTHETIC files (generated here) and, optionally, a read-only replay
of the saved 06B-4C captures. Sends nothing, runs no probe, controls no guest.

    python3 selftest_l2eval.py --offline-only
    python3 selftest_l2eval.py --regression <06B-4C run dir> [--json-dir DIR]
Every test has a unique name; exit 0 only if all pass.
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import l2eval as E            # noqa: E402
import l2frames as L          # noqa: E402
import selftest_l2 as B       # noqa: E402  (frame/pcap builders only; its tests are not run)

RESULTS = {}
TAP, GUEST = B.TAP, B.GUEST
A0, A1, B0, B1 = 100.0, 100.01, 110.0, 110.01


def t(name, fn):
    if name in RESULTS:
        raise SystemExit(f"duplicate test name {name}")
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    if not ok and not why:
        why = "returned False"
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""))


# ------------------------------------------------------------------ synthetic inputs
def raw(values):
    objs = [{"metainfo": {"version": "1.0.2"}}] + [
        {"counter": {"family": "inet", "name": k, "table": "t", "handle": i, "packets": v, "bytes": 0}}
        for i, (k, v) in enumerate(values.items())]
    return json.dumps({"nftables": objs})


def write_counters(path, recs):
    with open(path, "w") as f:
        for r in recs:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
    return path


def rec(label, t0, t1, values):
    return {"label": label, "t_start": t0, "t_end": t1, "raw": raw(values)}


BASE = {"arp_in_ok": 5, "arp_in_drop": 0, "arp_out_ok": 4, "allow_svc": 0, "drop_spoof": 0, "drop_non_ipv4": 0,
        "drop_worker_other": 0, "drop_private": 0, "drop_bcast_mcast": 0, "drop_public": 9, "l2_bad_ethertype": 2,
        "l2_bad_mac": 0, "allow_out_svc": 0, "arp_out_drop": 0, "drop_out": 0, "drop_input_backstop": 0,
        "drop_forward": 0}


def after(**inc):
    v = dict(BASE)
    for k, n in inc.items():
        v[k] += n
    return v


def frames_std():
    """In the certain zone: 1 guest ARP request (arp_in_ok), 1 worker reply (arp_out_ok),
    2 guest IPv4 to 1.1.1.1 (drop_public), 1 guest IPv6 (l2_bad_ethertype). Plus 1 frame outside."""
    v6 = B.eth("33:33:00:00:00:01", GUEST, 0x86DD, B.ipv6(B.S.GUEST_LL6, "ff02::1", 58, B.icmp6(8)))
    return [(50.0, B.F_ip()),                                                    # outside the window
            (105.0, B.F_arp_ok()),
            (105.001, B.eth(GUEST, TAP, 0x0806, B.arp(2, TAP, "10.200.0.1", GUEST, "10.200.0.2"))),
            (105.5, B.F_ip()), (106.0, B.F_ip()), (107.0, v6)]


STD_DELTA = dict(arp_in_ok=1, arp_out_ok=1, drop_public=2, l2_bad_ethertype=1)


def pcapng(path, frames):
    data = B.shb() + B.idb(tsresol=9)
    for ts, fr in frames:
        data += B.epb(round(ts * 1e9), fr)
    open(path, "wb").write(data)
    return path


def run(tmp, name, frames, recs, classes=None, tap=TAP):
    p = pcapng(os.path.join(tmp, name + ".pcapng"), frames) if frames is not None else os.path.join(tmp, "missing.pcapng")
    c = write_counters(os.path.join(tmp, name + ".jsonl"), recs)
    return E.evaluate(p, c, tap, "A", "B", classes)


def std_recs(**inc):
    return [rec("A", A0, A1, BASE), rec("B", B0, B1, after(**inc))]


# ------------------------------------------------------------------ S. synthetic cases through evaluate()
def sec_S(tmp):
    r = run(tmp, "pass", frames_std(), std_recs(**STD_DELTA))
    t("S1 PASS: every class equals its certain frames", lambda: r["verdict"] == "PASS")
    t("S2 PASS: per-class certain counts and deltas in the JSON",
      lambda: (r["per_class"]["arp_in_ok"]["certain"], r["per_class"]["arp_in_ok"]["delta"],
               r["per_class"]["drop_public"]["certain"], r["per_class"]["l2_bad_ethertype"]["delta"]) == (1, 1, 2, 1))
    t("S3 frames counted by direction/class inside the window; the outside frame is counted apart",
      lambda: r["frames_in_window"] == {"guest/arp_in_ok": 1, "guest/drop_public": 2, "guest/l2_bad_ethertype": 1,
                                        "worker/arp_out_ok": 1} and r["frames_outside_window"] == 1)
    t("S4 not-compared counters listed with delta and reason (unobservable ones named)",
      lambda: r["not_compared"]["arp_out_drop"]["delta"] == 0 and "capture point" in r["not_compared"]["arp_out_drop"]["reason"]
      and r["not_compared"]["drop_out"]["delta"] == 0)
    t("S5 reasons say why it passed", lambda: "equals the certain frames" in r["reasons"][0])
    t("S6 input hashes and the unmeasured-guard assumption recorded",
      lambda: len(r["input"]["pcap_sha256"]) == 64 and "NOT measured" in r["assumption"] and r["input"]["guard_s"] == 0.02)
    f = run(tmp, "fail", frames_std(), std_recs(arp_in_ok=2, arp_out_ok=1, drop_public=2, l2_bad_ethertype=1))
    t("S7 FAIL: counter delta above the frames (arp_in_ok 2 vs 1 frame)",
      lambda: f["verdict"] == "FAIL" and f["per_class"]["arp_in_ok"]["status"] == "FAIL"
      and any(x.startswith("arp_in_ok: counter delta 2 outside [1, 1]") for x in f["reasons"]))
    f2 = run(tmp, "fail2", frames_std(), std_recs(arp_out_ok=1, drop_public=2, l2_bad_ethertype=1))
    t("S8 FAIL: frame present, counter did not move (arp_in_ok 0 vs 1 frame)",
      lambda: f2["verdict"] == "FAIL" and f2["per_class"]["arp_in_ok"]["status"] == "FAIL")
    edge = frames_std() + [(109.995, B.F_ip())]                     # inside B.t_start - guard
    u = run(tmp, "unv-edge", edge, std_recs(**STD_DELTA))
    t("S9 UNVERIFIED: an edge frame makes drop_public undecidable",
      lambda: u["verdict"] == "UNVERIFIED" and u["per_class"]["drop_public"]["edge_end"] and
      any(x.startswith("drop_public: 1 edge frame") for x in u["reasons"]))
    unk = frames_std() + [(105.2, B.F_ip(smac="02:42:00:00:bb:02"))]
    u2 = run(tmp, "unv-unmapped", unk, std_recs(**STD_DELTA))
    t("S10 UNVERIFIED: a frame without a counter mapping inside the window, listed",
      lambda: u2["verdict"] == "UNVERIFIED" and u2["no_counter_frames"][0]["cls"] == "unmapped"
      and any("without a counter mapping" in x for x in u2["reasons"]))
    nh = frames_std() + [(105.3, B.F_arp_ok(dst="02:42:00:00:bb:02"))]
    u3 = run(tmp, "unv-nothooked", nh, std_recs(**STD_DELTA))
    t("S11 UNVERIFIED: an ARP frame that never reaches the hook (OTHERHOST) is not counted under a counter",
      lambda: u3["verdict"] == "UNVERIFIED" and u3["no_counter_frames"][0]["cls"] == "arp_not_hooked")
    sub = run(tmp, "subset", frames_std(), std_recs(**STD_DELTA), classes=["arp_in_ok", "arp_out_ok"])
    t("S12 class subset: only the chosen classes compared, the others listed as not compared",
      lambda: set(sub["per_class"]) == {"arp_in_ok", "arp_out_ok"} and sub["not_compared"]["drop_public"]["delta"] == 2)


# ------------------------------------------------------------------ X. capture read errors -> ERROR
def sec_X(tmp):
    recs = std_recs(**STD_DELTA)
    m = run(tmp, "x-missing", None, recs)
    t("X1 missing capture -> ERROR (capture read error), not 0 frames",
      lambda: m["verdict"] == "ERROR" and m["error"].startswith("capture read error") and m["per_class"] == {})
    good = pcapng(os.path.join(tmp, "x-good.pcapng"), frames_std())
    cut = os.path.join(tmp, "x-cut.pcapng")
    open(cut, "wb").write(open(good, "rb").read()[:-9])
    c = write_counters(os.path.join(tmp, "x.jsonl"), recs)
    t("X2 file cut inside a block -> ERROR", lambda: E.evaluate(cut, c, TAP, "A", "B")["verdict"] == "ERROR")
    empty = os.path.join(tmp, "x-empty.pcapng")
    open(empty, "wb").close()
    t("X3 empty capture file -> ERROR", lambda: E.evaluate(empty, c, TAP, "A", "B")["verdict"] == "ERROR")
    bad = os.path.join(tmp, "x-capgtorig.pcapng")
    open(bad, "wb").write(B.shb() + B.idb() + B.epb(10**8, B.F_ip(), orig=10))
    t("X4 captured > original length -> ERROR", lambda: E.evaluate(bad, c, TAP, "A", "B")["verdict"] == "ERROR")
    t("X5 malformed TAP MAC -> ERROR (invalid argument)",
      lambda: E.evaluate(good, c, "7a:93", "A", "B")["error"].startswith("invalid argument"))
    snap = os.path.join(tmp, "x-snap.pcapng")
    data = B.shb() + B.idb(tsresol=9)
    for ts, fr in frames_std():
        data += B.epb(round(ts * 1e9), fr[:20], orig=len(fr))
    open(snap, "wb").write(data)
    s = E.evaluate(snap, c, TAP, "A", "B")
    t("X6 frames cut by snaplen are never counted under a counter class -> UNVERIFIED",
      lambda: s["verdict"] in ("UNVERIFIED", "FAIL") and all(f["cls"] == "unmapped" for f in s["no_counter_frames"])
      and s["no_counter_frames"])


# ------------------------------------------------------------------ M. invalid measurement data -> ERROR
def sec_M(tmp):
    fr = frames_std()
    A = rec("A", A0, A1, BASE)
    Bv = rec("B", B0, B1, after(**STD_DELTA))
    cases = [
        ("M1 read label 'B' missing", [A]),
        ("M2 duplicate label", [A, Bv, rec("B", B0, B1, after(**STD_DELTA))]),
        ("M3 malformed JSON line", [A, "{not json"]),
        ("M4 raw nft output not JSON", [A, {"label": "B", "t_start": B0, "t_end": B1, "raw": "nope"}]),
        ("M5 read time not finite", [A, rec("B", B0, float("nan"), after(**STD_DELTA))]),
        ("M6 counter packets is a bool", [A, rec("B", B0, B1, dict(after(**STD_DELTA), arp_in_ok=True))]),
        ("M7 counter packets negative", [A, rec("B", B0, B1, dict(after(**STD_DELTA), drop_public=-1))]),
        ("M8 read without any counter", [A, {"label": "B", "t_start": B0, "t_end": B1, "raw": json.dumps({"nftables": []})}]),
        ("M9 compared counter missing in read B (never 0)",
         [A, rec("B", B0, B1, {k: v for k, v in after(**STD_DELTA).items() if k != "arp_in_ok"})]),
        ("M10 counter decreased", [A, rec("B", B0, B1, dict(after(**STD_DELTA), drop_public=1))]),
        ("M11 reads out of order (B before A)", [A, rec("B", 90.0, 90.01, after(**STD_DELTA))]),
    ]
    # Every case runs INSIDE its test (a crash fails that test), and the error must come from reading the
    # measurement data (prefix "invalid measurement data"), not from a later layer that happens to catch it.
    for name, recs in cases:
        t(f"{name} -> ERROR from the measurement-data check",
          lambda recs=recs, nm=re.sub(r"\W", "", name)[:10]: (lambda r: r["verdict"] == "ERROR" and r["per_class"] == {}
              and r["reasons"] == [r["error"]] and r["error"].startswith("invalid measurement data"))(run(tmp, nm, fr, recs))
          if name[:3] not in ("M9 ", "M10", "M11") else
          (lambda r: r["verdict"] == "ERROR" and r["per_class"] == {} and r["reasons"] == [r["error"]])(run(tmp, nm, fr, recs)))
    t("M15 bool in a NOT compared counter -> ERROR (would otherwise become a numeric delta)",
      lambda: (lambda r: r["verdict"] == "ERROR" and "non-negative integer" in r["error"])(
          run(tmp, "m-boolnc", fr, [A, rec("B", B0, B1, dict(after(**STD_DELTA), drop_out=True))])))
    dup = json.dumps({"nftables": [{"counter": {"name": "arp_in_ok", "packets": 6}},
                                   {"counter": {"name": "arp_in_ok", "packets": 9}}]})
    t("M16 a counter listed twice in one read -> ERROR",
      lambda: (lambda r: r["verdict"] == "ERROR" and "listed twice" in r["error"])(
          run(tmp, "m-dup", fr, [A, {"label": "B", "t_start": B0, "t_end": B1, "raw": dup}])))
    t("M12 comparing an unobservable counter (arp_out_drop) -> ERROR",
      lambda: run(tmp, "m-unobs", fr, std_recs(**STD_DELTA), classes=["arp_in_ok", "arp_out_drop"])["verdict"] == "ERROR")
    t("M13 a NOT compared counter missing in one read is reported missing (delta null), never 0",
      lambda: (lambda r: r["verdict"] == "PASS" and r["not_compared"]["drop_out"] == {
          "delta": None, "missing_in": "after", "reason": L.UNOBSERVABLE["drop_out"]})(
          run(tmp, "m-notcomp", fr, [A, rec("B", B0, B1, {k: v for k, v in after(**STD_DELTA).items() if k != "drop_out"})])))
    t("M14 an unknown class name -> ERROR",
      lambda: run(tmp, "m-unknown-class", fr, std_recs(**STD_DELTA), classes=["arp_in_ok", "no_such_counter"])["verdict"] == "ERROR")


# ------------------------------------------------------------------ C. command line
def sec_C(tmp):
    p = pcapng(os.path.join(tmp, "c.pcapng"), frames_std())

    def cli(recs, *extra):
        c = write_counters(os.path.join(tmp, "c.jsonl"), recs)
        out = os.path.join(tmp, "c-out.json")
        if os.path.exists(out):
            os.remove(out)
        buf, eb = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(eb):
            rc = E.main(["--pcap", p, "--counters", c, "--tap-mac", TAP, "--before", "A", "--after", "B",
                         "--out", out, *extra])
        return rc, (json.load(open(out)) if os.path.exists(out) else None), buf.getvalue()
    rc, j, _ = cli(std_recs(**STD_DELTA))
    t("C1 PASS -> exit 0, JSON written", lambda: rc == 0 and j["verdict"] == "PASS")
    rc, j, _ = cli(std_recs(arp_in_ok=3, arp_out_ok=1, drop_public=2, l2_bad_ethertype=1))
    t("C2 FAIL -> exit 1", lambda: rc == 1 and j["verdict"] == "FAIL")
    rc, j, _ = cli(std_recs(**STD_DELTA), "--classes", "arp_in_ok,no_such")
    t("C3 ERROR -> exit 2, JSON still written with the error", lambda: rc == 2 and j["verdict"] == "ERROR" and j["error"])
    c = write_counters(os.path.join(tmp, "c2.jsonl"), std_recs(**STD_DELTA))
    pe = pcapng(os.path.join(tmp, "c-edge.pcapng"), frames_std() + [(109.995, B.F_ip())])
    with contextlib.redirect_stdout(io.StringIO()):
        rc = E.main(["--pcap", pe, "--counters", c, "--tap-mac", TAP, "--before", "A", "--after", "B"])
    t("C4 UNVERIFIED -> exit 4", lambda: rc == 4)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = E.main(["--pcap", pe])
    t("C5 missing arguments -> exit 2", lambda: rc == 2)
    # 06B-4D1R: --classes is never silently filtered
    rc, j, _ = cli(std_recs(**STD_DELTA), "--classes", "")
    t('C6 --classes "" -> exit 2, JSON written with the reason', lambda: rc == 2 and "empty list" in j["error"])
    rc, j, _ = cli(std_recs(**STD_DELTA), "--classes", "arp_in_ok,,arp_out_ok")
    t('C7 --classes "a,,b" (empty name) -> exit 2, not filtered', lambda: rc == 2 and "unknown" in j["error"])
    rc, j, _ = cli(std_recs(**STD_DELTA), "--classes", "arp_in_ok,arp_in_ok")
    t("C8 --classes with a duplicate -> exit 2", lambda: rc == 2 and "duplicate" in j["error"])
    rc, j, _ = cli(std_recs(**STD_DELTA), "--classes", "arp_in_ok,arp_out_ok")
    t("C9 --classes valid subset -> exit 0, only those classes compared",
      lambda: rc == 0 and set(j["per_class"]) == {"arp_in_ok", "arp_out_ok"})


# ------------------------------------------------------------------ N/J. 06B-4D1R: class list and JSON structure
def sec_N(tmp):
    fr = frames_std()

    def arg_err(classes, needle):
        r = run(tmp, "n", fr, std_recs(**STD_DELTA), classes=classes)
        return (r["verdict"] == "ERROR" and r["per_class"] == {} and r["error"].startswith("invalid argument")
                and needle in r["error"] and r["reasons"] == [r["error"]])
    t("N1 classes=[] -> ERROR (nothing compared is never PASS)", lambda: arg_err([], "empty list"))
    t("N2 duplicate class name -> ERROR", lambda: arg_err(["arp_in_ok", "arp_in_ok"], "duplicate"))
    t("N3 empty class name -> ERROR", lambda: arg_err(["arp_in_ok", ""], "unknown"))
    t("N4 unobservable class (arp_out_drop) -> ERROR before reading anything", lambda: arg_err(["arp_out_drop"], "unknown"))
    t("N5 classes given as a string -> ERROR", lambda: arg_err("arp_in_ok", "must be a list"))
    t("N6 non-string class name -> ERROR", lambda: arg_err([123], "unknown"))
    t("N7 a valid subset (tuple) is still accepted",
      lambda: (lambda r: r["verdict"] == "PASS" and set(r["per_class"]) == {"drop_public", "l2_bad_ethertype"})(
          run(tmp, "n7", fr, std_recs(**STD_DELTA), classes=("drop_public", "l2_bad_ethertype"))))


def sec_J(tmp):
    fr = frames_std()
    A = rec("A", A0, A1, BASE)
    full = json.loads(raw(after(**STD_DELTA)))["nftables"]

    def bline(rawval):
        return {"label": "B", "t_start": B0, "t_end": B1, "raw": rawval if isinstance(rawval, str) else json.dumps(rawval)}
    cases = [
        ("J1 nftables=[{counter: null}]", [A, bline({"nftables": [{"counter": None}]})], "counter is NoneType"),
        ("J2 nftables=null", [A, bline({"nftables": None})], "'nftables' is NoneType"),
        ("J3 nftables=[{counter: []}]", [A, bline({"nftables": [{"counter": []}]})], "counter is list"),
        ("J4 nft output is a list", [A, bline('["nftables"]')], "not an object with 'nftables'"),
        ("J5 nft output without nftables", [A, bline({})], "not an object with 'nftables'"),
        ("J6 a non-object element among valid counters (not skipped)", [A, bline({"nftables": ["x"] + full})],
         "nftables[0] is str"),
        ("J7 counter without packets", [A, bline({"nftables": [{"counter": {"name": "arp_in_ok"}}] + full[1:]})],
         "lacks 'name' or 'packets'"),
        ("J8 counter name not a string", [A, bline({"nftables": [{"counter": {"name": 7, "packets": 1}}]})],
         "name is not a non-empty string"),
        ("J12 counter name empty", [A, bline({"nftables": [{"counter": {"name": "", "packets": 1}}] + full})],
         "name is not a non-empty string"),
        ("J9 record line is a JSON list", [A, '["label", "t_start", "t_end", "raw"]'], "record is list"),
        ("J10 record without raw", [A, {"label": "B", "t_start": B0, "t_end": B1}], "field 'raw' missing"),
        ("J11 raw is an object, not text", [A, {"label": "B", "t_start": B0, "t_end": B1,
                                                "raw": {"nftables": full}}], "expected the nft JSON text"),
    ]
    for name, recs, needle in cases:
        t(f"{name} -> ERROR with reason (evaluate)",
          lambda recs=recs, needle=needle: (lambda r: r["verdict"] == "ERROR" and r["per_class"] == {}
              and r["error"].startswith("invalid measurement data") and needle in r["error"])(run(tmp, "j", fr, recs)))
    # the same malformed snapshots through the real CLI: exit 2 and the JSON written with the error
    p = pcapng(os.path.join(tmp, "j.pcapng"), fr)
    for name, recs, needle in cases[:3]:
        c = write_counters(os.path.join(tmp, "j-cli.jsonl"), recs)
        out = os.path.join(tmp, "j-cli.json")
        if os.path.exists(out):
            os.remove(out)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = E.main(["--pcap", p, "--counters", c, "--tap-mac", TAP, "--before", "A", "--after", "B", "--out", out])
        t(f"{name.split()[0]}-CLI exit 2 and JSON written with the reason",
          lambda rc=rc, out=out, needle=needle: rc == 2 and needle in json.load(open(out))["error"])


# ------------------------------------------------------------------ R. read-only replay of the saved 06B-4C run
def sec_R(run_dir, json_dir):
    txt = open(os.path.join(run_dir, "container", "netns-before.txt")).read()
    tap = re.search(r"\d+: tap0: .*?\n\s+link/ether ([0-9a-f:]{17})", txt).group(1)
    t("R0 TAP_MAC read from the 06B-4C netns record", lambda: tap == "96:c1:56:82:5b:40")
    for arch in ("ARM", "MIPS"):
        p = os.path.join(run_dir, "container", "probe", arch)
        pc, cr = os.path.join(p, "tap0.pcapng"), os.path.join(p, "counters-raw.jsonl")
        sess = json.load(open(os.path.join(p, "session.json")))
        old9 = sess["classes_compared"]
        s9 = E.evaluate(pc, cr, tap, "session before boot", "session final 1", old9)
        t(f"R1 {arch}: session window, 9 legacy classes -> PASS as in session.json, same certain counts",
          lambda s9=s9, sess=sess: s9["verdict"] == sess["verdict"] == "PASS" and all(
              s9["per_class"][k]["certain"] == sess["reconciliation"]["per_class"][k]["certain"] for k in sess["classes_compared"]))
        s13 = E.evaluate(pc, cr, tap, "session before boot", "session final 1")
        t(f"R2 {arch}: session window, 13 frame-mapped classes (ARP added) -> PASS, ARP frames = ARP deltas",
          lambda s13=s13: s13["verdict"] == "PASS" and s13["per_class"]["arp_in_ok"]["certain"] == s13["per_class"]["arp_in_ok"]["delta"] > 0
          and s13["per_class"]["arp_out_ok"]["certain"] == s13["per_class"]["arp_out_ok"]["delta"] > 0)
        same, rows = True, []
        for pr in json.load(open(os.path.join(p, "matrix.json"))):
            e = E.evaluate(pc, cr, tap, pr["probe"] + " before", pr["probe"] + " after", old9)
            same &= e["verdict"] == pr["counter_reconciliation"]["verdict"]
            rows.append({"probe": pr["probe"], "recorded_9class": pr["counter_reconciliation"]["verdict"],
                         "l2eval_9class": e["verdict"],
                         "l2eval_13class": E.evaluate(pc, cr, tap, pr["probe"] + " before", pr["probe"] + " after")["verdict"],
                         "probe_verdict_recorded": pr["verdict"]})
        t(f"R3 {arch}: per probe, 9 legacy classes: reconciliation verdict equals matrix.json", lambda same=same: same)
        if json_dir:
            os.makedirs(json_dir, exist_ok=True)
            for nm, obj in ((f"{arch}-session-9class.json", s9), (f"{arch}-session-13class.json", s13),
                            (f"{arch}-per-probe.json", rows)):
                with open(os.path.join(json_dir, nm), "w") as f:
                    json.dump(obj, f, indent=1, sort_keys=True, ensure_ascii=False)
                    f.write("\n")
        print(f"      {arch} per probe (observation): " + ", ".join(f"{r['probe']}={r['l2eval_13class']}" for r in rows))


def main(argv):
    jdir = None
    if "--json-dir" in argv:
        i = argv.index("--json-dir")
        jdir = argv[i + 1]
        del argv[i:i + 2]
    reg = None
    if argv == ["--offline-only"]:
        pass
    elif len(argv) == 2 and argv[0] == "--regression":
        reg = argv[1]
    else:
        print(__doc__)
        return 64
    with tempfile.TemporaryDirectory(prefix="selftest-l2eval.") as tmp:
        secs = [("S", lambda: sec_S(tmp)), ("X", lambda: sec_X(tmp)), ("M", lambda: sec_M(tmp)), ("C", lambda: sec_C(tmp)),
                ("N", lambda: sec_N(tmp)), ("J", lambda: sec_J(tmp))]
        if reg:
            secs.append(("R", lambda: sec_R(reg, jdir)))
        for name, fn in secs:
            print(f"== section {name}")
            try:
                fn()
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"SELFTEST-L2EVAL: {len(RESULTS) - len(bad)}/{len(RESULTS)} passed" + ("" if not bad else f"; FAILED: {bad}"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
