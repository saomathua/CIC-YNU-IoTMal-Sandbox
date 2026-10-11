#!/usr/bin/env python3
"""Non-root, offline. Builds files/guest-f6.nft from the PINNED guest.nft by ONE asserted insertion: a harmless accept rule for TEST-NET-3
(203.0.113.250) as the last rule of `chain input` of `table inet sandbox_guest` (after the `drop_input_backstop` drop, so it is unreachable).
The pinned image, load.nft and expected-ruleset.json are not touched: at run time this file is bind-mounted READ-ONLY over /app/isolation/guest.nft
of a throwaway container (the way 06B-2A mounted broken-guest.nft). Writes files/guest-f6.nft and files/guest-f6.nft.diff; prints both hashes."""
import difflib
import hashlib
import pathlib
import sys

SRC = pathlib.Path("/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/sandbox-worker/isolation/guest.nft")
PIN = "5892d2d74f97c446ffa0f72f3de06764148a79ff3b4e7b80f4d791662b7fdce4"
HERE = pathlib.Path(__file__).resolve().parent
raw = SRC.read_bytes()
if hashlib.sha256(raw).hexdigest() != PIN:
    sys.exit("STOP: guest.nft differs from the pinned bytes")
text = raw.decode()
anchor = '    counter name "drop_input_backstop" drop\n  }\n'
if text.count(anchor) != 1:
    sys.exit("STOP: anchor not unique")
new = text.replace(anchor, '    counter name "drop_input_backstop" drop\n    ip saddr 203.0.113.250 accept   # CT01 V0-RUNTIME F6 FIXTURE: structural difference only\n  }\n')
(HERE / "files/guest-f6.nft").write_text(new)
(HERE / "files/guest-f6.nft.diff").write_text("".join(difflib.unified_diff(text.splitlines(True), new.splitlines(True), "guest.nft (pinned 5892d2d7)", "guest-f6.nft")))
print("guest-f6.nft", hashlib.sha256(new.encode()).hexdigest())
print("diff", hashlib.sha256((HERE / "files/guest-f6.nft.diff").read_bytes()).hexdigest())
