#!/usr/bin/env python3
"""CT-01 T21b evaluator R2 (offline, reads files only).

    t21b_evaluate.py <server-heartbeat-log> <run_id> <window.json | flow-run-dir> [--max-gap 3.0] [--out verdict.json] [--client-log <file>]

Window: a window.json {"start_epoch","end_epoch","lane","source"} or a flow-lane run directory (window = identity.started .. lane-status.finished; for F5 the
restart interval of f5-restart-time.txt must lie inside the covered beat range).
Server log lines (written by t21b_heartbeat.py inside the SSH session): HEADER <repr dict>, `HB <run> <seq> <iso> <epoch_ns> <mono_ns> <gap>`,
`STOP|ABORT|END <run> seq=<n> epoch_ns=<..> mono_ns=<..> reason=<..>`.
Client log (what the user's terminal received, each line prefixed by the receiver): `RX <utc-iso> <client-mono-ms> <line as received>`.

R2 (independent review 2026-10-11): (H1) STOP/ABORT/END are judged by WHEN they happened: an interruption after the window end does not undo a window that was
measured; one before the window is covered does. An event without epoch cannot be placed and is NOT_MET. (H2) the client log is parsed in full: its HEADER must
equal the server's, every beat of the window must be present with the SAME run/seq/iso/epoch_ns/mono_ns/gap as the server's, in order, no duplicates, no
missing; client receive times (UTC + monotonic) give the gap seen at the client; a bare `HB run N x` or an unprefixed line is not accepted as a client record.
R3 (review H3): the span judged is bracketed by the last beat AT or BEFORE the window start and the first beat AT or AFTER the window end, with every beat
in between; EVERY interval of that span (it all intersects the window, including the ones that cut the start or the end) is checked on the server and on the client.
A missing bracket is NOT_MET; margins are not used to select beats. Exactly one session HEADER per log (a log that several invocations appended to is refused).
Clock skew between client and server is reported, not used (window membership uses the server's epochs; client gaps use the client monotonic)."""
import ast, datetime, json, pathlib, re, sys

HB_RE = re.compile(r"HB (\S+) (\d+) (\S+) (\d+) (\d+) ([0-9.]+)")
EV_RE = re.compile(r"(STOP|ABORT|END) (\S+) seq=(\d+) epoch_ns=(\d+) mono_ns=(\d+) reason=(\S+)")
RX_RE = re.compile(r"RX (\S+) ([0-9]+(?:\.[0-9]+)?) (.*)")


def read_text(path):
    raw = pathlib.Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_lines(lines):
    hdr, hdr_raw, beats, events, other = None, None, [], [], 0
    for line in lines:
        line = line.rstrip("\r\n").strip()
        if not line:
            continue
        if line.startswith("HEADER "):
            hdr_raw = line
            try:
                hdr = ast.literal_eval(line[7:])
            except (ValueError, SyntaxError):
                hdr = {"_unparsable": line[:200]}
            continue
        m = HB_RE.fullmatch(line)
        if m:
            beats.append({"run": m.group(1), "seq": int(m.group(2)), "iso": m.group(3), "epoch_ns": int(m.group(4)), "mono_ns": int(m.group(5)), "gap": m.group(6),
                          "epoch": int(m.group(4)) / 1e9, "raw": line})
            continue
        m = EV_RE.fullmatch(line)
        if m:
            events.append({"kind": m.group(1), "run": m.group(2), "seq": int(m.group(3)), "epoch": int(m.group(4)) / 1e9, "reason": m.group(6), "raw": line})
            continue
        if re.match(r"(STOP|ABORT|END) ", line):
            events.append({"kind": line.split()[0], "run": None, "seq": None, "epoch": None, "reason": "no-epoch", "raw": line})
            continue
        other += 1
    return hdr, hdr_raw, beats, events, other


def parse_client(text):
    rx, bad = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        m = RX_RE.fullmatch(line.rstrip("\r\n"))
        if not m:
            bad += 1
            continue
        try:
            utc = datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp()
        except ValueError:
            bad += 1
            continue
        rx.append({"utc": utc, "mono_ms": float(m.group(2)), "line": m.group(3).strip()})
    return rx, bad


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    log, run_id, wp = argv[0], argv[1], pathlib.Path(argv[2])
    max_gap = float(argv[argv.index("--max-gap") + 1]) if "--max-gap" in argv else 3.0
    if wp.is_dir():
        iso = lambda x: datetime.datetime.fromisoformat(x).timestamp()                           # noqa: E731
        ident = json.loads((wp / "identity.json").read_text())
        stat = json.loads((wp / "lane-status.json").read_text())
        win = {"start_epoch": iso(ident["started"]), "end_epoch": iso(stat["finished"]), "lane": ident.get("label"), "source": f"{wp.name} identity.started/lane-status.finished"}
        rt = wp / "f5-restart-time.txt"
        if rt.exists():
            a, b = (float(x) for x in rt.read_text().split()[:2])
            win["restart_epoch"] = [a, b]
    else:
        win = json.loads(wp.read_text())
    s, e = float(win["start_epoch"]), float(win["end_epoch"])
    checks = []

    def add(n, ok, d=""):
        checks.append({"name": n, "ok": bool(ok), "detail": str(d)[:400]})
    add("window is ordered (start < end)", s < e, f"{s} .. {e}")
    srv_lines = read_text(log).splitlines()
    headers = [l for l in srv_lines if l.strip().startswith("HEADER ")]
    hdr, hdr_raw, beats, events, _ = parse_lines(srv_lines)
    add("header present, sshd ancestor and SSH_CONNECTION recorded, run id equal", isinstance(hdr, dict) and hdr.get("sshd_ancestor") is True and bool(hdr.get("SSH_CONNECTION"))
        and hdr.get("run_id") == run_id, hdr and {k: hdr.get(k) for k in ("run_id", "sshd_ancestor", "SSH_CONNECTION", "tty0")})
    add("exactly one HEADER (one invocation/session appended to this log)", len(headers) == 1, f"{len(headers)} HEADER lines")
    add("run id on every beat", bool(beats) and all(b["run"] == run_id for b in beats))
    add("sequence 1..N without holes or duplicates", bool(beats) and [b["seq"] for b in beats] == list(range(1, len(beats) + 1)), len(beats))
    # H3: bracket the window with the nearest beats at/before start and at/after end; judge every interval of that span
    pre = [b for b in beats if b["epoch"] <= s]
    post = [b for b in beats if b["epoch"] >= e]
    b0, b1 = (pre[-1] if pre else None), (post[0] if post else None)
    first, last = (beats[0]["epoch"], beats[-1]["epoch"]) if beats else (None, None)
    add("coverage: a beat at or before the window start AND a beat at or after the window end exist (bracket)", b0 is not None and b1 is not None and b0["seq"] <= b1["seq"],
        f"before-start bracket={'none' if b0 is None else round(b0['epoch'] - s, 2)}s, after-end bracket={'none' if b1 is None else round(b1['epoch'] - e, 2)}s")
    if win.get("restart_epoch"):
        a_, b_ = win["restart_epoch"]
        add("the restart interval lies inside the bracketed span", b0 is not None and b1 is not None and b0["epoch"] <= a_ and b1["epoch"] >= b_, win["restart_epoch"])
    inw = [b for b in beats if b0 is not None and b1 is not None and b0["seq"] <= b["seq"] <= b1["seq"]]
    gaps = [round(b2["epoch"] - b1_["epoch"], 3) for b1_, b2 in zip(inw, inw[1:])]
    add(f"every interval of the bracketed span <= {max_gap}s on the server (intervals cutting the window start/end included)", bool(gaps) and max(gaps) <= max_gap,
        f"max interval {max(gaps) if gaps else None}s over {len(inw)} beats")
    # H1: an event is judged by when it happened
    early = [ev["raw"][:120] for ev in events if ev["epoch"] is None or ev["epoch"] < e]
    after = [ev["kind"] for ev in events if ev["epoch"] is not None and ev["epoch"] >= e]
    add("no STOP/ABORT/END before the window end (events after the window end are recorded, not held against it)", not early, early[:2] or f"events after the window: {after}")
    client = None
    if "--client-log" in argv:
        rx, bad = parse_client(read_text(argv[argv.index("--client-log") + 1]))
        c_hdr, c_hdr_raw, c_beats, c_events, c_other = parse_lines([r["line"] for r in rx])
        n_c_hdr = sum(1 for r in rx if r["line"].startswith("HEADER "))
        # pair every client beat with its receive record (same order as parse_lines kept them)
        rx_of = [r for r in rx if HB_RE.fullmatch(r["line"])]
        by_seq, dups = {}, []
        for b, r in zip(c_beats, rx_of):
            if b["seq"] in by_seq:
                dups.append(b["seq"])
            by_seq[b["seq"]] = (b, r)
        want = [b for b in inw]
        srv = {b["seq"]: b for b in beats}
        missing = [b["seq"] for b in want if b["seq"] not in by_seq]
        wrong = [b["seq"] for b in want if b["seq"] in by_seq and (by_seq[b["seq"]][0]["raw"] != srv[b["seq"]]["raw"])]
        order_ok = [b["seq"] for b in c_beats] == sorted(b["seq"] for b in c_beats) and not dups
        mono_ok = all(r2["mono_ms"] >= r1["mono_ms"] for r1, r2 in zip(rx, rx[1:]))
        wseq = [b["seq"] for b in want if b["seq"] in by_seq]
        cgaps = []
        for q1, q2 in zip(wseq, wseq[1:]):
            if q2 == q1 + 1:
                cgaps.append((by_seq[q2][1]["mono_ms"] - by_seq[q1][1]["mono_ms"]) / 1000.0)
        skew = [by_seq[q][1]["utc"] - srv[q]["epoch"] for q in wseq] or [None]
        client = {"rx_records": len(rx), "unprefixed_or_bad_lines": bad, "beats": len(c_beats), "missing": missing[:10], "mismatch": wrong[:10], "duplicates": dups[:10],
                  "max_client_gap_s": round(max(cgaps), 3) if cgaps else None, "rx_minus_server_s": [round(min(skew), 3) if skew[0] is not None else None,
                                                                                                    round(max(skew), 3) if skew[0] is not None else None]}
        add("client log: every line carries the receiver prefix `RX <utc> <mono_ms>` (no bare lines)", bad == 0 and bool(rx), client)
        add("client log: exactly one session HEADER, equal to the server's HEADER byte for byte", n_c_hdr == 1 and c_hdr_raw is not None and c_hdr_raw == hdr_raw)
        add("client log: every beat of the window present with the server's run/seq/time fields (same content), none missing", bool(want) and not missing and not wrong, client)
        add("client log: increasing sequence, no duplicate, receive monotonic never goes back", order_ok and mono_ok, f"dups={dups[:5]} mono_ok={mono_ok}")
        add(f"client log: receive gap <= {max_gap}s between consecutive beats of the window (SSH channel)", bool(cgaps) and max(cgaps) <= max_gap,
            f"max client gap {client['max_client_gap_s']}s over {len(cgaps)} intervals")
        c_early = [ev["raw"][:120] for ev in c_events if ev["epoch"] is None or ev["epoch"] < e]
        add("client log: no STOP/ABORT/END before the window end", not c_early, c_early[:2])
    ok_server = all(c["ok"] for c in checks if not c["name"].startswith("client log"))
    ok_client = client is not None and all(c["ok"] for c in checks if c["name"].startswith("client log"))
    out = {"schema": "ct01-t21b-verdict/2", "run_id": run_id, "window": win, "checks": checks, "client": client,
           "verdict": ("T21B_TWO_SIDED_HELD" if ok_server and ok_client else "SERVER_SIDE_ONLY" if ok_server and client is None else "NOT_MET"),
           "all_ok": bool(ok_server and ok_client),
           "statement": "the session-bound heartbeat covered the lane window at both ends of the SSH channel; not a statement about other sessions or CT-01 as a whole"}
    if "--out" in argv:
        pathlib.Path(argv[argv.index("--out") + 1]).write_text(json.dumps(out, indent=1))
    for c in checks:
        print(("PASS " if c["ok"] else "FAIL ") + c["name"] + ("" if c["ok"] else f"  -> {c['detail']}"))
    print("T21B:", out["verdict"])
    return 0 if out["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
