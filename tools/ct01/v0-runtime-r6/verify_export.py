#!/usr/bin/env python3
"""Offline check AFTER the run (D4): the frozen run directory verifies in the stage AND in the export, the two are identical, and the receipt / exit status
are consistent with them (D2/D3).

    python3 -I -B verify_export.py --stage <STAGE_DIR> --export <EXPORT_DIR>        (the stage part needs root: the stage is root-owned 0700)
    python3 -I -B verify_export.py --run <RUN_DIR_OR_EXPORT_DIR>                    (one directory only: manifest, file set, symlinks)

Exit 0 only when every check holds; 1 otherwise. Prints one line per check. Reads files only."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

SIGNALS = {"INT": 2, "TERM": 15, "HUP": 1}
EXTRA_IN_EXPORT = {"EXPORT-RECEIPT.json", "EXIT-STATUS.json"}


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def listing(d, skip=()):
    d = pathlib.Path(d)
    out = []
    for p in sorted(d.rglob("*")):
        if p.is_symlink() or p.is_file():
            rel = p.relative_to(d).as_posix()
            if rel not in skip:
                out.append(rel)
    return out


def check_dir(d, label):
    """-> list of (ok, text). Manifest hash check, exact file set (files + symlinks), symlink targets."""
    d = pathlib.Path(d)
    rows = []
    man, sym = d / "EVIDENCE-SHA256SUMS", d / "EVIDENCE-SYMLINKS"
    if not man.is_file() or not sym.is_file():
        return [(False, f"{label}: EVIDENCE-SHA256SUMS / EVIDENCE-SYMLINKS missing")]
    r = subprocess.run(["sha256sum", "--strict", "--check", "--quiet", "EVIDENCE-SHA256SUMS"], cwd=d, capture_output=True, text=True)
    rows.append((r.returncode == 0, f"{label}: every file equals its manifest hash" + ("" if r.returncode == 0 else f" -> {r.stdout.strip()[:200]}{r.stderr.strip()[:100]}")))
    listed = sorted(l.split("  ", 1)[1].strip().removeprefix("./") for l in man.read_text().splitlines() if l.strip())
    regular = sorted(rel for rel in listing(d, skip={"EVIDENCE-SHA256SUMS", "EXPORT-RECEIPT.json", "EXIT-STATUS.json"}) if not (d / rel).is_symlink())
    links = sorted(rel for rel in listing(d) if (d / rel).is_symlink())
    rows.append((listed == regular, f"{label}: the manifest lists exactly the regular files present ({len(listed)} vs {len(regular)})"
                 + ("" if listed == regular else f" extra={sorted(set(regular) - set(listed))[:3]} missing={sorted(set(listed) - set(regular))[:3]}")))
    want, malformed = [], []
    for line in sym.read_text().splitlines():
        if not line.strip():
            continue
        path, sep, target = line.partition(" -> ")
        if not sep or not path or not target:
            malformed.append(line)
        else:
            want.append((path.removeprefix("./"), target))
    actual = sorted((rel, os.readlink(d / rel)) for rel in links)
    rows.append((not malformed and actual == sorted(want),
                 f"{label}: symlink names AND targets match the listing ({len(links)})"))
    return rows


def final_exit_rule(signal, abort, erc, xstatus):
    if signal:
        return 128 + SIGNALS[signal]
    if abort:
        return 3
    if erc != 0:
        return erc
    return 0 if xstatus == "verified" else 4


def main(argv):
    ck = []
    if "--run" in argv and "--stage" not in argv:
        ck += check_dir(argv[argv.index("--run") + 1], "run")
    elif "--stage" in argv and "--export" in argv:
        S = pathlib.Path(argv[argv.index("--stage") + 1])
        E = pathlib.Path(argv[argv.index("--export") + 1])
        run = S / "run"
        ck += check_dir(run, "stage run")
        ck += check_dir(E, "export")
        if (run / "EVIDENCE-SHA256SUMS").is_file() and (E / "EVIDENCE-SHA256SUMS").is_file():
            ck.append((sha(run / "EVIDENCE-SHA256SUMS") == sha(E / "EVIDENCE-SHA256SUMS"), "the stage and export manifests are byte-identical"))
            ck.append((sha(run / "EVIDENCE-SYMLINKS") == sha(E / "EVIDENCE-SYMLINKS"), "the stage and export symlink listings are byte-identical"))
        extra = sorted(set(listing(E)) - set(listing(run)))
        ck.append((set(extra) <= EXTRA_IN_EXPORT, f"the export holds nothing beyond the run directory except {sorted(EXTRA_IN_EXPORT)}: extra={extra}"))
        missing = sorted(set(listing(run)) - set(listing(E)))
        ck.append((not missing, f"the export lacks no file of the run directory: missing={missing[:3]}"))
        try:
            rc = json.loads((S / "export-receipt.json").read_text())
            es = json.loads((S / "exit-status.json").read_text())
        except (OSError, ValueError) as e:
            ck.append((False, f"export-receipt.json / exit-status.json unreadable: {e}"))
            rc = es = None
        if rc is not None:
            ck.append((rc.get("status") == "verified" and es.get("export_status") == "verified", f"receipt status {rc.get('status')!r}, exit-status export_status {es.get('export_status')!r}"))
            ck.append((rc.get("evidence_manifest_sha256") == sha(run / "EVIDENCE-SHA256SUMS"), "the receipt binds the evidence manifest hash"))
            ck.append((rc.get("symlinks_sha256") == sha(run / "EVIDENCE-SYMLINKS"), "the receipt binds the symlink listing hash"))
            ck.append((rc.get("tree_manifest_sha256") == sha(S / "tree/SHA256SUMS") and rc.get("runner_sha256") == sha(S / "tree/run-v0-runtime.sh")
                       and rc.get("evaluator_sha256") == sha(S / "tree/evaluate_v0_runtime.py") and rc.get("pins_sha256") == sha(S / "tree/pins.json"),
                       "the receipt binds the staged tree manifest, runner, evaluator and pins"))
            ck.append((rc.get("verdicts_sha256") == sha(run / "verdicts.json") and rc.get("identity_sha256") == sha(run / "run-identity.json"),
                       "the receipt binds verdicts.json and run-identity.json"))
            lab = (run / "run-label.txt").read_text().strip()
            ck.append((rc.get("label") == lab == es.get("label"), "label of receipt, exit status and run-label.txt agree"))
            ck.append(((E / "EXPORT-RECEIPT.json").is_file() and sha(E / "EXPORT-RECEIPT.json") == sha(S / "export-receipt.json"), "the exported receipt equals the stage receipt"))
            ck.append(((E / "EXIT-STATUS.json").is_file() and sha(E / "EXIT-STATUS.json") == sha(S / "exit-status.json"), "the exported exit status equals the stage exit status"))
            fs = json.loads((run / "final-status.json").read_text())
            ck.append((es.get("signal") == fs.get("signal") and es.get("abort_reason") == fs.get("abort_reason"), "exit-status signal/abort_reason equal final-status"))
            want = final_exit_rule(es.get("signal"), es.get("abort_reason"), es.get("evaluator_rc"), es.get("export_status"))
            ck.append((es.get("final_exit") == want, f"final_exit {es.get('final_exit')!r} follows the rule signal > abort > evaluator > export (expected {want})"))
            v = json.loads((run / "verdicts.json").read_text())
            ck.append(((es.get("evaluator_rc") == 0) == (v.get("all_ok") is True), "evaluator rc 0 exactly when verdicts.json says all_ok"))
    else:
        print(__doc__)
        return 2
    for ok, text in ck:
        print(("PASS " if ok else "FAIL ") + text)
    good = all(ok for ok, _ in ck)
    print("VERIFY-EXPORT:", "ALL HELD" if good else "NOT VERIFIED")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
