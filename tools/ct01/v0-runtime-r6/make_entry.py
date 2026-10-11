#!/usr/bin/env python3
"""Writes root-command.txt: the ONE command the user pastes (reviewed text, with the manifest hash as a literal). Run after SHA256SUMS is final.
It is not part of the tree manifest (it contains the manifest hash). Offline, no root."""
import argparse, hashlib, json, pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("--tree-path", type=pathlib.Path, default=HERE,
                help="Destination tree for the printed root command; does not execute it")
a = ap.parse_args()
TARGET = a.tree_path.resolve()
if any(c in str(TARGET) for c in "\n\r\t ") or not str(TARGET).startswith("/"):
    ap.error("tree path must be an absolute path without whitespace")
MAN = hashlib.sha256((HERE / "SHA256SUMS").read_bytes()).hexdigest()
IMG = json.loads((HERE / "pins.json").read_text())["image_id"]
TEMPLATE = r'''# CT-01 V0 runtime R6 — ONE root command (sudo). Prepared text; requires a separate operational decision. Not executed.
sudo bash -c "$(cat <<'CT01_V0RT_ENTRY'
set -euo pipefail
TREE=@TREE@
MAN=@MAN@
IMG=@IMG@
BASE=/var/lib/ct01-v0rt
OUT=@OUTBASE@-$(date -u +%Y%m%dT%H%M%SZ)
[ "$(id -u)" = 0 ] || { echo "run through sudo"; exit 2; }
[ -d "$BASE" ] || install -d -m 755 -o root -g root "$BASE"
[ "$(stat -c '%u %a' "$BASE")" = "0 755" ] || { echo "ABORT: $BASE is not root:root 0755"; exit 2; }
STAGE="$BASE/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 700 "$STAGE" "$STAGE/tree" "$STAGE/inputs"
# 1. the manifest is read ONCE, copied into the stage and its hash compared with the literal MAN above; every file is then copied
#    from the user tree and VERIFIED IN THE STAGE (never executed from the user tree)
install -m 600 -o root -g root "$TREE/SHA256SUMS" "$STAGE/tree/SHA256SUMS"
[ "$(sha256sum "$STAGE/tree/SHA256SUMS" | cut -d' ' -f1)" = "$MAN" ] || { echo "ABORT: manifest hash differs from the reviewed literal"; exit 3; }
while read -r h f; do
    case "$f" in ''|/*|*..*) echo "ABORT: bad manifest path $f"; exit 3;; esac
    install -D -m 600 -o root -g root "$TREE/$f" "$STAGE/tree/$f"
done < "$STAGE/tree/SHA256SUMS"
( cd "$STAGE/tree" && sha256sum --strict --check --quiet SHA256SUMS ) || { echo "ABORT: staged tree differs from its manifest"; exit 3; }
# 2. repo inputs named by the staged pins: copied into the stage and compared with the literal hashes of pins.json (itself covered by the manifest)
/usr/bin/python3 -I -B - "$STAGE" <<'CT01_V0RT_INPUTS'
import hashlib, json, pathlib, shutil, sys
S = pathlib.Path(sys.argv[1])
pins = json.loads((S / "tree/pins.json").read_text())
for rel, m in pins["sources"].items():
    d = S / m["path"]
    assert str(d.resolve()).startswith(str(S.resolve()) + "/"), m["path"]
    d.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(m["src"], d)
    d.chmod(0o600)
    h = hashlib.sha256(d.read_bytes()).hexdigest()
    if h != m["sha256"]:
        sys.exit(f"ABORT: input {rel} differs from its pin: {h}")
print("inputs staged and verified:", len(pins["sources"]))
CT01_V0RT_INPUTS
/usr/bin/python3 -I -B "$STAGE/tree/verify_pins.py" "$STAGE" || { echo "ABORT: pins/files differ in the stage"; exit 3; }
echo "stage: $STAGE   evidence copy will be: $OUT"
set +e
CT01_V0RT_STAGE="$STAGE" CT01_V0RT_EXPORT_TO="$OUT" /bin/bash "$STAGE/tree/run-v0-runtime.sh" "$IMG"
rc=$?
echo "v0-runtime rc=$rc   (0 = every criterion held; this is NOT CT-01 PASS)"
exit "$rc"
CT01_V0RT_ENTRY
)"
'''
txt = (TEMPLATE.replace("@TREE@", str(TARGET)).replace("@MAN@", MAN).replace("@IMG@", IMG)
       .replace("@OUTBASE@", str(TARGET.parent / "ct01-v0-runtime-r6-run")))
(HERE / "root-command.txt").write_text(txt)
print("root-command.txt written; manifest", MAN)
