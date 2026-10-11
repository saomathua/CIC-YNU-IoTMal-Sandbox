#!/usr/bin/env python3
"""Non-root, offline: writes pins.json from files that already exist. The expected hashes are LITERALS taken from earlier evidence (not recomputed from
whatever is on disk), so a changed file is a mismatch, not a new pin. Refuses to write if any literal differs from the file."""
import hashlib, json, pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path("/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/sandbox-worker")
sha = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()    # noqa: E731
SOURCES = {   # image-resident bytes: docs/evidence/task06b3a/run2/container/sha256-in-container.txt (image 1ab784c7…) and the offline V0 review provenance
    "run.sh": "d0a22a19f9fe20b31ff627f30b55a851da0ca73462b2b8cb622ced0035ba23f9",
    "isolation/verify.py": "692dcae87e013e188214a448d0604f7b53d6f4351be2af45b504ca57ed4c5ebf",
    "isolation/constants.py": "9a8eb13892e2bb68d3b521ed436cb896d1398a98d8d6c1de7a9b98d12cfe434e",
    "isolation/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "isolation/expected-ruleset.json": "9fb32d7f7ec0e83d0440f7a9bce2e18021da6f9ee4557cfe26ac38eae8572b16",
    "isolation/load.nft": "0991fbdf89498c45853f076a3095acd2e8e6e33bdb8ecb43f6a23797156b54c8",
    "isolation/guest.nft": "5892d2d74f97c446ffa0f72f3de06764148a79ff3b4e7b80f4d791662b7fdce4",
}
FILES = {"files/sentinel/server.py": "517be1541e1c0b812f014fa84d93406d54aef7e56e3d1a1979de331faf0eeb20",
         "files/sentinel/poller.py": "7e49a99bac3a1b5f277d0700b4250043a13fce15bbb6f5c58dd7d24d44a8ab26"}
bad = []
for rel, h in SOURCES.items():
    if sha(REPO / rel) != h:
        bad.append(rel)
for rel, h in FILES.items():
    if sha(HERE / rel) != h:
        bad.append(rel)
if bad:
    sys.exit(f"STOP: differs from the literal pin: {bad}")
P = pathlib.Path("/home/dathq/projects")
pins = {
    "schema": "ct01-v0-runtime-pins/2",
    "image_id": "sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153",
    "image_id_source": "ct01-b1probes-r13/harness/run-ct01-b1.sh:17 (EXPECTED_IMAGE_ID); image holds the seven pinned files per docs/evidence/task06b3a/run2/container/sha256-in-container.txt",
    "sources": {rel: {"path": f"inputs/sandbox-worker/{rel}", "src": str(REPO / rel), "sha256": h} for rel, h in SOURCES.items()},
    "expected_ruleset": "inputs/sandbox-worker/isolation/expected-ruleset.json",
    "sentinels": {rel: h for rel, h in FILES.items()},
    "sentinel_source": "docs/evidence/task06b2ar/harness/sentinel (hashes equal the in-container hashes logged by 06B-2AR)",
    "guest_f6_path": "tree/files/guest-f6.nft",
    "guest_f6_sha256": sha(HERE / "files/guest-f6.nft"),
    "guest_f6_diff_sha256": sha(HERE / "files/guest-f6.nft.diff"),
    "review_inputs": {"ct01-v0-negative-review/REVIEW.md": "32a2c687d2775dfd160ada4a24997a7e65bbfe197f50ae7368c7db79a5e029a8",
                      "ct01-v0-negative-review/MATRIX-V0-UPDATED.md": "21cdefb97ed80908a70be52e7f2acc978c34ac1366079bfd2fa475fe20bbb09b",
                      "ct01-v0-negative-work/SHA256SUMS": "defa332ee31f280cb9d8a15fc5b276200b608adfc9b96b6f876d4626579bdf2d",
                      "ct01-v0-runtime-independent-review/REVIEW.md": "a229417c6404bf40bebd2d5bc39de48df70ac3399cfe229616d750177d1da063"},   # informational names only: not read at run time
    "sandboxnet_expect": {"subnet": "192.168.60.0/24", "gateway": "192.168.60.1", "label": "com.docker.compose.network=sandboxnet"},
}
(HERE / "pins.json").write_text(json.dumps(pins, indent=2) + "\n")
print("pins.json", sha(HERE / "pins.json"))
