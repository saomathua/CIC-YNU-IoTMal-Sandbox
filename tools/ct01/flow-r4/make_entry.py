#!/usr/bin/env python3
"""Writes root-command-<mode>.txt (ONE sudo command per lane mode, manifest hash literal). Not part of the tree manifest. Offline.
The command only stages the tree (manifest literal, per-file check) and hands over to lane_entry.sh FROM THE STAGE (so that the tail is pinned by the
manifest, testable and not reviewed twice): lane, evaluator, ONE export with receipt, final exit with the priority documented in lane_entry.sh."""
import hashlib, json, pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
MAN = hashlib.sha256((HERE / "SHA256SUMS").read_bytes()).hexdigest()
IMG = json.loads((HERE / "pins.json").read_text())["image_id"]
T = r'''# CT-01 flow lane R2 @MODE@ — ONE root command (sudo). Reviewed text with the manifest hash as a literal.
sudo bash -c "$(cat <<'CT01_FLOW_ENTRY'
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
TREE=@TREE@
MAN=@MAN@
IMG=@IMG@
MODE=@MODE@
BASE=/var/lib/ct01-flow
OUT=@OUTBASE@-$(date -u +%Y%m%dT%H%M%SZ)
[ "$(id -u)" = 0 ] || { echo "run through sudo"; exit 2; }
[ -d "$BASE" ] || install -d -m 755 -o root -g root "$BASE"
[ "$(stat -c '%u %a' "$BASE")" = "0 755" ] || { echo "ABORT: $BASE is not root:root 0755"; exit 2; }
STAGE="$BASE/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 700 "$STAGE" "$STAGE/tree"
install -m 600 -o root -g root "$TREE/SHA256SUMS" "$STAGE/tree/SHA256SUMS"
[ "$(sha256sum "$STAGE/tree/SHA256SUMS" | cut -d' ' -f1)" = "$MAN" ] || { echo "ABORT: manifest hash differs from the reviewed literal"; exit 3; }
while read -r h f; do
    case "$f" in ''|/*|*..*) echo "ABORT: bad manifest path $f"; exit 3;; esac
    install -D -m 600 -o root -g root "$TREE/$f" "$STAGE/tree/$f"
done < "$STAGE/tree/SHA256SUMS"
( cd "$STAGE/tree" && sha256sum --strict --check --quiet SHA256SUMS ) || { echo "ABORT: staged tree differs from its manifest"; exit 3; }
exec /bin/bash "$STAGE/tree/lane_entry.sh" "$MODE" "$STAGE" "$OUT" "$IMG" "$MAN"
CT01_FLOW_ENTRY
)"
'''
MODES = ("success", "f3", "f4", "f5")
if __name__ == "__main__":
    for mode in MODES:
        s = (T.replace("@MODE@", mode).replace("@TREE@", str(HERE)).replace("@MAN@", MAN).replace("@IMG@", IMG)
             .replace("@OUTBASE@", str(HERE.parent / f"{HERE.name}-{mode}-run")))
        (HERE / f"root-command-{mode}.txt").write_text(s)
    print("manifest", MAN)
