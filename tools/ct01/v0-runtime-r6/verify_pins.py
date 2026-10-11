#!/usr/bin/env python3
"""Verifies the STAGE copy: python3 -I -B verify_pins.py <STAGE_DIR>. Every file named in pins.json (inputs/…, tree/…) must equal its literal pin and
the tree manifest must verify. Exit 0 or 1; prints each mismatch. Reads only <STAGE_DIR>."""
import hashlib, json, pathlib, subprocess, sys
S = pathlib.Path(sys.argv[1]).resolve()
T = S / "tree"
pins = json.loads((T / "pins.json").read_text())
sha = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()    # noqa: E731
bad = []
for rel, m in pins["sources"].items():
    if sha(S / m["path"]) != m["sha256"]:
        bad.append(("source", rel))
if sha(S / pins["expected_ruleset"]) != pins["sources"]["isolation/expected-ruleset.json"]["sha256"]:
    bad.append(("expected_ruleset", ""))
for rel, h in pins["sentinels"].items():
    if sha(T / rel) != h:
        bad.append(("sentinel", rel))
if sha(S / pins["guest_f6_path"]) != pins["guest_f6_sha256"]:
    bad.append(("guest-f6", pins["guest_f6_path"]))
if sha(T / "files/guest-f6.nft.diff") != pins["guest_f6_diff_sha256"]:
    bad.append(("guest-f6.diff", ""))
a = (S / pins["sources"]["isolation/guest.nft"]["path"]).read_text().splitlines()
b = (S / pins["guest_f6_path"]).read_text().splitlines()
extra = [l for l in b if l not in a]
if len(b) != len(a) + 1 or len(extra) != 1 or "203.0.113.250 accept" not in extra[0]:
    bad.append(("guest-f6 is not the pinned guest.nft plus one rule", ""))
r = subprocess.run(["sha256sum", "--strict", "--check", "--quiet", "SHA256SUMS"], cwd=T, capture_output=True, text=True)
if r.returncode != 0:
    bad.append(("tree manifest SHA256SUMS", r.stdout.strip()[:200] + r.stderr.strip()[:200]))
for x in bad:
    print("MISMATCH", *x)
print("PINS OK" if not bad else "PINS NOT OK")
sys.exit(1 if bad else 0)
