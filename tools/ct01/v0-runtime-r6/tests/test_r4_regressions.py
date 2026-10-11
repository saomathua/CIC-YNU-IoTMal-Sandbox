"""R4 regressions with real runner/verifier CLIs and fake Docker/host tools only.
Usage: CT01_V0RT_INPUTS=<packaged inputs> python3 -I -B tests/test_r4_regressions.py --out <directory>
--tree selects a private source copy for before/after or code-mutation checks.
No real Docker, sudo, container, guest or network is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--select", choices=("all", "logger", "verifier"), default="all")
    a = ap.parse_args()
    tree = a.tree.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("r4_fixture", tree / "tests/test_orchestration.py")
    T = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(T)
    results = {}
    observations = []

    def check(name, condition):
        results[name] = bool(condition)
        print(("PASS " if condition else "FAIL ") + name, flush=True)

    def verify(*args):
        return subprocess.run(["/usr/bin/python3", "-I", "-B", str(tree / "verify_export.py"), *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    if a.select in ("all", "verifier"):
        r, argv, S, E, containers, tmp = T.run()
        receipt = json.loads((S / "export-receipt.json").read_text())
        v = verify("--stage", S, "--export", E)
        check("clean runner and post-exit verifier", r.returncode == 0 and T.verdict(S)["all_ok"] is True
              and receipt["status"] == "verified" and v.returncode == 0 and not containers)
        (out / "clean-verifier.log").write_text(v.stdout + v.stderr)
        link = E / "ct01-path/ip"
        target = os.readlink(link)
        link.unlink()
        link.symlink_to("/changed-target-for-r4-test")
        v = verify("--stage", S, "--export", E)
        check("changed symlink target refused", v.returncode == 1 and "FAIL export: symlink" in v.stdout)
        (out / "changed-target.log").write_text(v.stdout + v.stderr)
        link.unlink()
        link.symlink_to(target)
        check("restored symlink control", verify("--stage", S, "--export", E).returncode == 0)
        modified = dict(receipt, symlinks_sha256="0" * 64)
        for p in (S / "export-receipt.json", E / "EXPORT-RECEIPT.json"):
            p.write_text(json.dumps(modified))
        v = verify("--stage", S, "--export", E)
        check("receipt symlink-list hash refused independently", v.returncode == 1 and "FAIL the receipt binds the symlink listing hash" in v.stdout)
        (out / "changed-receipt.log").write_text(v.stdout + v.stderr)
        # Isolate listing validation: each regular-file manifest is regenerated,
        # so a hash mismatch cannot mask a bad symlink listing.
        for name, listing, expected in (
            ("correct", "./link -> /original-target\n", 0),
            ("wrong-target", "./link -> /wrong-target\n", 1),
            ("missing-delimiter", "./link\n", 1),
            ("duplicate", "./link -> /original-target\n" * 2, 1),
            ("empty-target", "./link -> \n", 1),
        ):
            d = pathlib.Path(tempfile.mkdtemp(prefix="v0r4-links."))
            (d / "link").symlink_to("/original-target")
            (d / "EVIDENCE-SYMLINKS").write_text(listing)
            h = hashlib.sha256((d / "EVIDENCE-SYMLINKS").read_bytes()).hexdigest()
            (d / "EVIDENCE-SHA256SUMS").write_text(h + "  ./EVIDENCE-SYMLINKS\n")
            check("standalone listing " + name, verify("--run", d).returncode == expected)

    if a.select in ("all", "logger"):
        original_bins = T.bins

        def bins(tmp, *args, **kw):
            b = original_bins(tmp, *args, **kw)
            (b / "tee").write_text("#!/usr/bin/python3\nimport json, os, pathlib, sys\n"
                "args=sys.argv[1:]\n"
                "if len(args)!=1 or pathlib.Path(args[0]).name!='run.log':\n"
                " os.execv('/usr/bin/tee',['tee',*args])\n"
                "data=sys.stdin.buffer.read()\n"
                "pathlib.Path(args[0]).write_bytes(data[:80])\n"
                "pathlib.Path(os.environ['LOGGER_TEST_STATUS']).write_text(json.dumps({'pid':os.getpid(),'received':len(data),'saved':80,'exit':17}))\n"
                "sys.exit(17)\n")
            (b / "tee").chmod(0o755)
            return b

        T.bins = bins
        for name, mode, extra, expected in (
            ("clean", "ok", {}, 4),
            ("evaluator-failure", "ok", {"FAKE_NFT_AFTER_RC": "17"}, 1),
            ("abort", "nft_check_fails", {}, 3),
        ):
            status = out / (name + "-logger.json")
            count = out / (name + "-nft-count.txt")
            env = dict(extra, LOGGER_TEST_STATUS=str(status), FAKE_NFT_COUNT=str(count))
            r, argv, S, E, containers, tmp = T.run(mode, env_extra=env)
            rcpt = json.loads((S / "export-receipt.json").read_text())
            es = json.loads((S / "exit-status.json").read_text())
            logger = json.loads(status.read_text())
            check(name + ": logger received more than retained prefix", logger["received"] > logger["saved"] and logger["exit"] == 17)
            check(name + ": logger failure blocks verified export", rcpt["status"] == "freeze_failed" and not E.exists())
            check(name + ": exit priority and fixture cleanup", r.returncode == expected and es["final_exit"] == expected and not containers)
            try:
                os.kill(logger["pid"], 0)
                exited = False
            except ProcessLookupError:
                exited = True
            check(name + ": logger awaited", exited)
            (out / (name + "-receipt.json")).write_text(json.dumps(rcpt, indent=2))
            (out / (name + "-exit-status.json")).write_text(json.dumps(es, indent=2))
            (out / (name + "-finalize.log")).write_bytes((S / "finalize.log").read_bytes())
            observations.append({"case": name, "runner_rc": r.returncode, "export_status": rcpt["status"],
                                 "evaluator_all_ok": T.verdict(S)["all_ok"], "stage": str(S), "export": str(E)})
    summary = {"tree": str(tree), "select": a.select, "passed": sum(results.values()), "total": len(results),
               "checks": results, "observations": observations, "scope": "offline stubs only"}
    (out / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"R4-REGRESSION: {summary['passed']}/{summary['total']}")
    return 0 if results and all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
