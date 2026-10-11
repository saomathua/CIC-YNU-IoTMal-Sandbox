#!/usr/bin/env python3
"""Export of a flow-lane run directory from the root-owned stage to the user's evidence directory, with an honest receipt. Stdlib only.

    export_run.py <stage_run> <out> --uid U --gid G --lane-rc N --eval-rc N [--signal N] [--stage <stage_dir>]

Steps (each one is attempted, recorded and never hides a later one): manifest of <stage_run> -> copy (symlinks kept, never followed) -> chown (lchown) ->
verify the copy (same file set, same sha256, same symlink targets) -> receipt. A step that fails makes the export NOT VERIFIED; the stage always stays.
Exit code of THIS helper: 0 = export verified, 4 = not verified. The entry maps it to the final exit with the priority
    signal (128+n) > lane rc != 0 > evaluator rc != 0 > export not verified (4) > 0
(the same rule is written into the receipt as `final_rc`). Receipt: <stage>/export-receipt.json and, when <out> exists, <out>.export-receipt.json beside it
(never inside <out>: <out> is covered by MANIFEST-SHA256 and must stay equal to the stage copy).

R4 (independent review 2026-10-11, X1/X2): `verify` recomputes the sha256 of EVERY manifest line against the real file in the stage AND in the copy (each read is
bracketed by stat: a file that changes while it is read does not verify), requires the manifest to be well-formed (no blank/duplicate/absolute/'..' path, the
exact file set of both trees, MANIFEST-SYMLINKS equal to the real link targets of both trees). Writing the receipts is part of the export: a receipt that cannot
be written (stage) or written/chowned (sidecar) makes the export NOT verified (rc 4), is said on stderr, and never prints EXPORT VERIFIED."""
import hashlib, json, os, pathlib, re, shutil, sys

MAN = "MANIFEST-SHA256"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def inventory(root):
    """{relative path: ('f', sha256) | ('l', target)} for every file/symlink under root (directories are implied); MANIFEST itself excluded."""
    root = pathlib.Path(root)
    inv = {}
    for dp, dn, fn in os.walk(root, followlinks=False):
        for n in dn:
            q = pathlib.Path(dp) / n
            if q.is_symlink():
                inv[q.relative_to(root).as_posix()] = ("l", os.readlink(q))
        for n in fn:
            q = pathlib.Path(dp) / n
            rel = q.relative_to(root).as_posix()
            if rel == MAN:
                continue
            inv[rel] = ("l", os.readlink(q)) if q.is_symlink() else ("f", sha(q))
    return inv


def hashed(path):
    """sha256 of a regular file, bracketed by stat; raises if the file changed while being read."""
    a = os.lstat(path)
    h = sha(path)
    b = os.lstat(path)
    if (a.st_size, a.st_mtime_ns, a.st_ino) != (b.st_size, b.st_mtime_ns, b.st_ino):
        raise ValueError(f"{path} changed while it was being hashed")
    return h


def parse_manifest(root):
    """-> {path: sha256} from root/MANIFEST-SHA256; any malformed/duplicate/unsafe line raises."""
    out = {}
    raw = (pathlib.Path(root) / MAN).read_text()
    for n, l in enumerate(raw.splitlines(), 1):
        parts = l.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not parts[1]:
            raise ValueError(f"{root}/{MAN} line {n} malformed")
        pth = pathlib.PurePosixPath(parts[1])
        if pth.is_absolute() or ".." in pth.parts or parts[1] in out or parts[1] == MAN:
            raise ValueError(f"{root}/{MAN} line {n}: unsafe or duplicate path {parts[1]!r}")
        out[parts[1]] = parts[0]
    return out


def parse_links(root):
    out = {}
    for n, l in enumerate((pathlib.Path(root) / "MANIFEST-SYMLINKS").read_text().splitlines(), 1):
        if " -> " not in l:
            raise ValueError(f"MANIFEST-SYMLINKS line {n} malformed")
        k, t_ = l.split(" -> ", 1)
        if k in out:
            raise ValueError(f"MANIFEST-SYMLINKS duplicate {k!r}")
        out[k] = t_
    return out


def check_tree(root):
    """The tree really holds what its own manifest says: file set, every sha256 (bracketed reads), every symlink target."""
    root = pathlib.Path(root)
    man, links = parse_manifest(root), parse_links(root)
    inv = inventory(root)
    files = {k for k, v in inv.items() if v[0] == "f"}
    real_links = {k: v[1] for k, v in inv.items() if v[0] == "l"}
    if set(man) != files:
        raise ValueError(f"{root}: manifest lists {len(man)} files, the tree holds {len(files)}: {sorted(set(man) ^ files)[:5]}")
    for k, h in man.items():
        got = hashed(root / k)
        if got != h:
            raise ValueError(f"{root}: {k} has sha256 {got[:12]}..., the manifest says {h[:12]}...")
    if links != real_links:
        raise ValueError(f"{root}: MANIFEST-SYMLINKS differs from the real links: {sorted(set(links.items()) ^ set(real_links.items()))[:3]}")
    return len(man), len(links)


def _fault(name):
    """Test seam (only with CT01_EXPORT_TESTING=1): CT01_EXPORT_FAULT=<name>:<relpath>, applied by the step it names."""
    if os.environ.get("CT01_EXPORT_TESTING") != "1":
        return None
    f = os.environ.get("CT01_EXPORT_FAULT", "")
    n, _, rel = f.partition(":")
    return rel if n == name else None


def final_rc(lane_rc, eval_rc, signal, export_ok):
    if signal:
        return 128 + int(signal), "signal"
    if lane_rc:
        return int(lane_rc), "lane"
    if eval_rc:
        return int(eval_rc), "evaluator"
    if not export_ok:
        return 4, "export"
    return 0, "none"


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    run, out = pathlib.Path(argv[0]), pathlib.Path(argv[1])
    opt = {}
    k = 2
    while k < len(argv):
        opt[argv[k].lstrip("-")] = argv[k + 1] if k + 1 < len(argv) else None
        k += 2
    uid, gid = int(opt.get("uid", os.getuid())), int(opt.get("gid", os.getgid()))
    lane_rc, eval_rc = int(opt.get("lane-rc", 0)), int(opt.get("eval-rc", 0))
    signal = int(opt["signal"]) if opt.get("signal") not in (None, "", "0") else None
    stage = pathlib.Path(opt["stage"]) if opt.get("stage") else run.parent
    steps = {}

    def step(name, fn):
        try:
            r = fn()
            steps[name] = {"ok": True, "detail": r}
            return True
        except Exception as e:                                   # noqa: BLE001
            steps[name] = {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}
            return False

    def manifest():
        links = {k: v[1] for k, v in inventory(run).items() if v[0] == "l"}
        (run / "MANIFEST-SYMLINKS").write_text("".join(f"{k} -> {t}\n" for k, t in sorted(links.items())))     # written first: it is itself a listed file
        inv = inventory(run)
        lines = [f"{v[1]}  {k}\n" for k, v in sorted(inv.items()) if v[0] == "f"]
        (run / MAN).write_text("".join(lines))
        rel = _fault("mutate-after-manifest")
        if rel:
            (run / rel).write_bytes((run / rel).read_bytes() + b"X")
        return {"files": len(lines), "symlinks": len(links)}

    def copy():
        shutil.copytree(run, out, symlinks=True, dirs_exist_ok=False)
        rel = _fault("mutate-after-copy")
        if rel:
            (out / rel).write_bytes((out / rel).read_bytes() + b"X")
        return "copied"

    def chown():
        n = 0
        for dp, dn, fn in os.walk(out, followlinks=False):
            for nme in dn + fn:
                os.lchown(os.path.join(dp, nme), uid, gid)
                n += 1
        os.lchown(out, uid, gid)
        return {"entries": n + 1}

    def verify():
        ns, nl = check_tree(run)          # the stage itself must still equal its manifest (input unchanged between manifest and copy)
        nc, ncl = check_tree(out)         # and so must the copy; one manifest for both
        if (run / MAN).read_bytes() != (out / MAN).read_bytes() or (run / "MANIFEST-SYMLINKS").read_bytes() != (out / "MANIFEST-SYMLINKS").read_bytes():
            raise ValueError("manifest files differ between stage and copy")
        if inventory(run) != inventory(out):
            raise ValueError("stage and copy inventories differ")
        return {"files": ns, "symlinks": nl, "manifest_sha256": hashlib.sha256((out / MAN).read_bytes()).hexdigest()}

    ok_m = step("manifest", manifest)
    ok_c = ok_m and step("copy", copy)
    ok_o = ok_c and step("chown", chown)
    ok_v = ok_o and step("verify", verify)
    for name, ok in (("copy", ok_c), ("chown", ok_o), ("verify", ok_v)):
        if name not in steps:
            steps[name] = {"ok": False, "detail": "not attempted (an earlier step failed)"}
    export_ok = bool(ok_m and ok_c and ok_o and ok_v)
    side = out.parent / (out.name + ".export-receipt.json")

    def receipt():
        frc, why = final_rc(lane_rc, eval_rc, signal, export_ok)
        return json.dumps({"schema": "ct01-flow-export-receipt/1", "export_status": "verified" if export_ok else "not_verified", "steps": steps,
                           "lane_rc": lane_rc, "evaluator_rc": eval_rc, "signal": signal, "final_rc": frc, "final_rc_reason": why,
                           "stage_run": str(run), "out": str(out), "stage_kept": True,
                           "manifest_sha256": (steps.get("verify", {}).get("detail") or {}).get("manifest_sha256") if export_ok else None}, indent=1) + "\n"

    def write_stage():
        (stage / "export-receipt.json").write_text(receipt())
        return "written"

    def write_side():
        if not out.exists():
            raise FileNotFoundError(f"{out} does not exist: no copy to put a receipt beside")
        side.write_text(receipt())
        os.lchown(side, uid, gid)
        return "written+chowned"
    # the receipts are part of the export: a receipt that cannot be written makes it NOT verified (and is said on stderr)
    ok_rs = step("receipt_stage", write_stage)
    ok_rc = step("receipt_sidecar", write_side) if (ok_c or out.exists()) else False
    if not ok_c and not out.exists():
        steps["receipt_sidecar"] = {"ok": False, "detail": "no copy exists: the receipt stays in the stage only"}
        ok_rc = True        # nothing to put it beside; the export is already not verified through its own steps
    if not (ok_rs and ok_rc):
        export_ok = False
        for k in ("receipt_stage", "receipt_sidecar"):
            if not steps[k]["ok"]:
                print(f"RECEIPT WRITE FAILED ({k}): {steps[k]['detail']}", file=sys.stderr)
        for fn in (write_stage, write_side):          # best effort: say the truth in whichever receipt is writable
            try:
                fn()
            except Exception:                                    # noqa: BLE001
                pass
    print(("EXPORT VERIFIED: " if export_ok else "EXPORT NOT VERIFIED: ") + str(out), json.dumps({k: v["ok"] for k, v in steps.items()}))
    return 0 if export_ok else 4


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
