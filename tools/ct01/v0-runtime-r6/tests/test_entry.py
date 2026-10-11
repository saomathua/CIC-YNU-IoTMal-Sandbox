"""R2 entry test: the pasted root command (root-command.txt) executed in a user-owned sandbox base, with ONLY these asserted substitutions: the root/owner checks
(no root here), BASE under a temp dir, and the final runner call replaced by `echo` (the runner has its own test). Shows what the entry stages and refuses.
usage: python3 -I -B tests/test_entry.py"""
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, traceback

P = pathlib.Path(__file__).resolve().parent.parent
RES = {}


def t(name, fn):
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    RES[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""), flush=True)


def tree_copy(tmp, mutate=None):
    d = tmp / "tree"
    shutil.copytree(P, d, ignore=shutil.ignore_patterns("run", "__pycache__", "root-command.txt", "*.log"))
    inputs = os.environ.get("CT01_V0RT_INPUTS")          # packaged copy of the repo inputs: point the copy's pins at it (the manifest/entry of the copy are regenerated)
    if inputs:
        pj = json.loads((d / "pins.json").read_text())
        for rel, m in pj["sources"].items():
            m["src"] = str(pathlib.Path(inputs) / rel)
        (d / "pins.json").write_text(json.dumps(pj, indent=2) + "\n")
    if mutate:
        mutate(d)
    files = sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (d / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((d / f).read_bytes()).hexdigest()}  {f}\n" for f in files if not f.startswith("../")))
    return d


def entry_text(d, manifest_lines=None):
    if manifest_lines is not None:
        (d / "SHA256SUMS").write_text(manifest_lines)
    subprocess.run([sys.executable, "-I", "-B", str(d / "make_entry.py")], check=True, capture_output=True)
    txt = (d / "root-command.txt").read_text()
    body = txt.split("<<'CT01_V0RT_ENTRY'\n", 1)[1].rsplit("\nCT01_V0RT_ENTRY\n", 1)[0]
    return body


def run_entry(tmp, body):
    base = tmp / "base"
    base.mkdir(mode=0o755)
    subs = [
        ('[ "$(id -u)" = 0 ] || { echo "run through sudo"; exit 2; }\n', ""),
        ("BASE=/var/lib/ct01-v0rt\n", f"BASE={base}\n"),
        ('[ "$(stat -c \'%u %a\' "$BASE")" = "0 755" ]', '[ "$(stat -c \'%a\' "$BASE")" = "755" ]'),
        ('install -d -m 755 -o root -g root "$BASE"', 'install -d -m 755 "$BASE"'),
        ('install -m 600 -o root -g root "$TREE/SHA256SUMS"', 'install -m 600 "$TREE/SHA256SUMS"'),
        ('install -D -m 600 -o root -g root "$TREE/$f"', 'install -D -m 600 "$TREE/$f"'),
        ('CT01_V0RT_STAGE="$STAGE" CT01_V0RT_EXPORT_TO="$OUT" /bin/bash "$STAGE/tree/run-v0-runtime.sh" "$IMG"', 'echo "RUNNER-WOULD-START stage=$STAGE img=$IMG"'),
    ]
    for a, b in subs:
        assert body.count(a) == 1, a
        body = body.replace(a, b)
    r = subprocess.run(["/bin/bash", "-c", body], capture_output=True, text=True, timeout=120)
    return r, base


def main():
    with tempfile.TemporaryDirectory(prefix="v0r2e.") as tmp:
        tmp = pathlib.Path(tmp)
        d = tree_copy(tmp / "a") if (tmp / "a").mkdir() is None else None
        body = entry_text(d)
        t("N0 the real root-command.txt of the delivered tree is well formed and carries the manifest hash literal",
          lambda: ('MAN=' + hashlib.sha256((P / "SHA256SUMS").read_bytes()).hexdigest()) in (P / "root-command.txt").read_text() and "set -euo pipefail" in (P / "root-command.txt").read_text())
        r, base = run_entry(tmp / "a", body)
        stage = next(iter(base.iterdir()), None)
        t("N1 clean tree: stage built (0700), tree files equal the manifest, repo inputs staged and equal their pins, runner would start from the stage",
          lambda: r.returncode == 0 and "RUNNER-WOULD-START" in r.stdout and (oct(stage.stat().st_mode & 0o777) == "0o700")
          and "inputs staged and verified: 7" in r.stdout and "PINS OK" in r.stdout and (stage / "tree/run-v0-runtime.sh").exists())
        # tampered file in the user tree BEFORE the entry (manifest literal stays the reviewed one): refused
        (tmp / "b").mkdir()
        d2 = tree_copy(tmp / "b")
        body2 = entry_text(d2)                              # literal of the clean tree
        (d2 / "files/sentinel/poller.py").write_text((d2 / "files/sentinel/poller.py").read_text() + "# harmless\n")
        # manifest file untouched: sha256sum -c of the staged tree must fail
        r2, base2 = run_entry(tmp / "b", body2)
        t("N2 a file of the user tree changed after the manifest was fixed: entry refuses (staged tree differs from its manifest), runner not started",
          lambda: r2.returncode == 3 and "RUNNER-WOULD-START" not in r2.stdout and "differs from its manifest" in r2.stdout)
        # manifest changed (the attacker also updates SHA256SUMS): the literal hash catches it
        (tmp / "c").mkdir()
        d3 = tree_copy(tmp / "c")
        body3 = entry_text(d3)
        (d3 / "SHA256SUMS").write_text((d3 / "SHA256SUMS").read_text() + "\n")
        r3, _ = run_entry(tmp / "c", body3)
        t("N3 manifest itself changed: refused by the literal manifest hash", lambda: r3.returncode == 3 and "manifest hash differs" in r3.stdout and "RUNNER-WOULD-START" not in r3.stdout)
        # repo input tampered (pins src points to a changed file)
        (tmp / "d").mkdir()
        def mut(d):
            fake = d / "tampered-run.sh"
            fake.write_text("echo tampered\n")
            pins = json.loads((d / "pins.json").read_text())
            pins["sources"]["run.sh"]["src"] = str(fake)
            (d / "pins.json").write_text(json.dumps(pins, indent=2) + "\n")
        d4 = tree_copy(tmp / "d", mut)
        r4, _ = run_entry(tmp / "d", entry_text(d4))
        t("N4 a repo input that differs from its literal pin: refused while staging, runner not started", lambda: r4.returncode != 0 and "differs from its pin" in (r4.stdout + r4.stderr) and "RUNNER-WOULD-START" not in r4.stdout)
        # path traversal in the manifest
        (tmp / "e").mkdir()
        d5 = tree_copy(tmp / "e")
        lines = (d5 / "SHA256SUMS").read_text() + f"{'0' * 64}  ../escape\n"
        r5, _ = run_entry(tmp / "e", entry_text(d5, lines))
        t("N5 a manifest path with `..`: refused before copying", lambda: r5.returncode == 3 and "bad manifest path" in r5.stdout)
        # missing file listed in the manifest
        (tmp / "f").mkdir()
        d6 = tree_copy(tmp / "f")
        lines = (d6 / "SHA256SUMS").read_text() + f"{'0' * 64}  nonexistent-file.txt\n"
        r6, _ = run_entry(tmp / "f", entry_text(d6, lines))
        t("N6 a manifest file that does not exist: the entry stops (set -e), runner not started", lambda: r6.returncode != 0 and "RUNNER-WOULD-START" not in r6.stdout)
    n = sum(RES.values())
    print(f"TEST-V0RT-ENTRY: {n}/{len(RES)} passed")
    return 0 if n == len(RES) else 1


if __name__ == "__main__":
    sys.exit(main())
