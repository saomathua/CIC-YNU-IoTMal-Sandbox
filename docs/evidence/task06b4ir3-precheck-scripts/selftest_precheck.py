#!/usr/bin/env python3
"""06B-4IR3 — offline tests of the precheck collector/evaluator (PC-2) and of the output/launch path (PC-4).
No root, no Docker, no system target: every docker/pgrep/nft/aa-status call goes through a fake runner; the output
tests run in a toy tree owned by the current user; the root snippet runs with BASE in the toy tree and a stub PY.

    python3 -I -B selftest_precheck.py [--json FILE]
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collector as C          # noqa: E402
import evaluate_precheck as EV  # noqa: E402
sys.path.insert(0, "/home/dathq/projects/ct01-06b4ir3")
import arp_cases as A          # noqa: E402
import arp_harness as AH       # noqa: E402

RESULTS = {}
REF = "table inet fixture {\n}\n"
SB_INSPECT = ('n1\tcic-ynu-iotmal-sandbox_sandboxnet\tbridge\tfalse\t[{"Subnet":"192.168.60.0/24","Gateway":"192.168.60.1"}]'
              '\t{}\n')
DB_INSPECT = 'n2\tcic-ynu-iotmal-sandbox_dbnet\tbridge\tfalse\t[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]\t{}\n'


def t(name, fn):
    if name in RESULTS:
        raise SystemExit(f"duplicate test name {name}")
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=3).strip().splitlines()[-1]
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why or 'returned False'})" if not ok else ""))


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


def fake_runner(spec):
    """spec: overrides keyed by read name prefix -> (rc, stdout, stderr, error). Default = clean environment with the
    manager exited and mongo running."""
    calls = []

    def answer(argv):
        calls.append(argv)
        j = " ".join(argv)
        def pick(key, default):
            return spec.get(key, default)
        if argv[0] == C.BINS["docker"]:
            if spec.get("docker_all"):
                return spec["docker_all"]
            if argv[1] == "version":
                return pick("version", (0, b"client=29.8.2 server=29.8.2 api=1.51\n", b"", None))
            if argv[1] == "info":
                return pick("info", (0, b"driver=overlay2 cgroup=systemd/2 kernel=6.8.0 os=Ubuntu running=1\n", b"", None))
            if argv[1:3] == ["image", "inspect"]:
                return pick("image", (0, (C.EXPECTED_IMAGE_ID + "\n").encode(), b"", None))
            if argv[1:3] == ["ps", "-a"]:
                return pick("ps", (0, b"cic-ynu-iotmal-sandbox-sandbox-manager-1\texited\tx\tid1\nmongo-db\trunning\tmongo\tid2\n",
                                   b"", None))
            if argv[1:3] == ["network", "ls"]:
                net = "sandboxnet" if "sandboxnet" in j else "dbnet"
                return pick(f"ls-{net}", (0, f"n{1 if net == 'sandboxnet' else 2}\tcic-ynu-iotmal-sandbox_{net}\n".encode(),
                                          b"", None))
            if argv[1:3] == ["network", "inspect"]:
                return pick("inspect-sb" if argv[-1] == "n1" else "inspect-db",
                            (0, (SB_INSPECT if argv[-1] == "n1" else DB_INSPECT).encode(), b"", None))
            if argv[1] == "inspect":
                if argv[-1] == C.MANAGER:
                    return pick("manager", (0, b'exited\tid1\t0\t2026-10-08T08:42:17Z\t{"cic-ynu-iotmal-sandbox_sandboxnet":'
                                           b'{"IPAddress":"","MacAddress":""}}\n', b"", None))
                return pick("mongo", (0, b'running\tid2\t0\tx\t{"cic-ynu-iotmal-sandbox_dbnet":{"IPAddress":"172.18.0.2",'
                                         b'"MacAddress":"92:95:79:0b:84:90"}}\n', b"", None))
            if argv[1] == "exec":
                return pick("exec", (0, b'[{"dst":"192.168.60.2","dev":"eth0","lladdr":"92:95:79:0b:84:91","state":["STALE"]}]\n',
                                     b"", None))
        if argv[0] == C.BINS["pgrep"]:
            return pick("pgrep", (1, b"", b"", None))
        if argv[0] == C.BINS["nft"]:
            return pick("nft", (0, REF.encode(), b"", None))
        if argv[0] == C.BINS["aa-status"]:
            return pick("aa", (0, b"apparmor module is loaded.\n   tcpdump\n", b"", None))
        return None, b"", b"", f"EXEC_ERROR: unexpected {argv}"
    answer.calls = calls
    return answer


def run(tmp, name, spec, ref=REF):
    d = os.path.join(tmp, name)
    os.mkdir(d, 0o700)
    fd = C.prepare_outdir(d, owner_uid=os.geteuid())
    runner = fake_runner(spec)
    rc = C.collect(fd, runner)
    os.close(fd)
    doc = json.load(open(os.path.join(d, "reads.json")))
    res = EV.evaluate(doc, ref, AH.endpoint_mac_problem, A.parse_neigh_full)
    st = {i["item"]: i for i in res["items"]}
    return {"rc": rc, "doc": doc, "res": res, "items": st, "calls": runner.calls, "dir": d,
            "reads": {r["name"]: r for r in doc["reads"]}}


def find(x, prefix):
    return next(v for k, v in x["items"].items() if k.startswith(prefix))


PERM = (1, b"", b"permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n", None)
DAEMON = (1, b"", b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n", None)


def sec_C(tmp):
    x = run(tmp, "clean", {})
    t("C1 clean environment (manager exited, mongo running): collector exit 0, evaluator PASS",
      lambda: x["rc"] == 0 and x["res"]["verdict"] == "PASS")
    t("C2 every read keeps argv, rc, status and stdout/stderr files", lambda: all(
        r["status"] == "SKIPPED" or (r["argv"] and "rc" in r and os.path.exists(os.path.join(x["dir"], r["stdout_file"]))
                                     and os.path.exists(os.path.join(x["dir"], r["stderr_file"]))) for r in x["doc"]["reads"]))
    t("C3 no docker verb other than version/info/image inspect/ps/network ls+inspect/inspect/exec; no Config.Env",
      lambda: all(c[1] in ("version", "info", "image", "ps", "network", "inspect", "exec") for c in x["calls"]
                  if c[0] == C.BINS["docker"]) and not any("Env" in " ".join(c) for c in x["calls"]))
    t("C4 manager exited -> no docker exec at all (SKIPPED with the reason)",
      lambda: not any(c[1] == "exec" for c in x["calls"] if c[0] == C.BINS["docker"])
      and x["reads"]["manager-ip-j-neigh"]["status"] == "SKIPPED"
      and "not running according to a successful inspect" in x["reads"]["manager-ip-j-neigh"]["error"])
    for n, spec in (("permission-denied", {"docker_all": PERM}), ("daemon-down", {"docker_all": DAEMON})):
        x = run(tmp, n, spec)
        t(f"C5 {n}: harness containers UNKNOWN (never 'absent'), manager UNKNOWN (never 'not running'), exec skipped as "
          "'state unknown', collector exit 3, evaluator UNKNOWN (2), no FAIL invented",
          lambda x=x: all(find(x, f"harness container {c}")["status"] == "UNKNOWN" for c in C.HARNESS_CONTAINERS)
          and find(x, "manager:")["status"] == "UNKNOWN" and "state unknown" in x["reads"]["manager-ip-j-neigh"]["error"]
          and x["rc"] == 3 and x["res"]["verdict"] == "UNKNOWN"
          and x["reads"]["ps-all"]["status"] == "NONZERO" and b"denied" in open(os.path.join(
              x["dir"], x["reads"]["ps-all"]["stderr_file"]), "rb").read() + b"denied" * (n == "daemon-down"))
    x = run(tmp, "image-mismatch", {"image": (0, b"sha256:" + b"0" * 64 + b"\n", b"", None)})
    t("C6 image id differs from the reviewed one -> FAIL (compared automatically), evaluator exit 1 path",
      lambda: find(x, "image sandbox-worker")["status"] == "FAIL" and x["res"]["verdict"] == "FAIL")
    x = run(tmp, "harness-present", {"ps": (0, b"ct01-06b3b-ctl\texited\tx\ti\ncic-ynu-iotmal-sandbox-sandbox-manager-1\texited\tx\t"
                                             b"i1\nmongo-db\trunning\tm\ti2\n", b"", None)})
    t("C7 a harness container left over -> FAIL (PRESENT from the successful listing)",
      lambda: find(x, "harness container ct01-06b3b-ctl")["status"] == "FAIL"
      and find(x, "harness container ct01-06b3b-guest")["status"] == "PASS")
    for n, out in (("network-missing", b""), ("network-ambiguous", b"n1\ta_sandboxnet\nn3\tb_sandboxnet\n")):
        x = run(tmp, n, {"ls-sandboxnet": (0, out, b"", None)})
        t(f"C8 {n}: network not inspected (SKIPPED, reason kept), collector exit 3, evaluator UNKNOWN",
          lambda x=x: x["reads"]["network-inspect-sandboxnet"]["status"] == "SKIPPED" and x["rc"] == 3
          and find(x, "network sandboxnet")["status"] == "UNKNOWN" and x["res"]["verdict"] == "UNKNOWN")
    x = run(tmp, "subnet-other", {"inspect-sb": (0, SB_INSPECT.replace("192.168.60.", "192.168.61.").encode(), b"", None)})
    t("C9 sandboxnet with another subnet -> FAIL", lambda: find(x, "network sandboxnet")["status"] == "FAIL")
    run_ok = (0, b'running\tid1\t0\tx\t{"cic-ynu-iotmal-sandbox_sandboxnet":{"IPAddress":"192.168.60.10",'
                 b'"MacAddress":"8a:d3:09:b5:72:af"}}\n', b"", None)
    x = run(tmp, "manager-running", {"manager": run_ok})
    t("C10 manager running: read-only exec commands only (ip -V, ip -j neigh, /proc/net/arp, /sys/class/net), MAC "
      "usable -> PASS; neighbour JSON parsed (informational)",
      lambda: [c[3:] for c in x["calls"] if c[0] == C.BINS["docker"] and c[1] == "exec"]
      == [["sh", "-c", "command -v ip && ip -V"], ["ip", "-j", "neigh", "show"], ["cat", "/proc/net/arp"],
          ["sh", "-c", 'for i in /sys/class/net/*; do echo "$(basename $i) $(cat $i/address) $(cat $i/operstate)"; done']]
      and find(x, "manager (running)")["status"] == "PASS" and x["res"]["verdict"] == "PASS")
    x = run(tmp, "manager-zero-mac", {"manager": (0, run_ok[1].replace(b"8a:d3:09:b5:72:af", b"00:00:00:00:00:00"), b"", None)})
    t("C11 manager running with an all-zero MAC -> FAIL (endpoint MAC unusable)",
      lambda: find(x, "manager (running)")["status"] == "FAIL")
    x = run(tmp, "manager-absent", {"manager": (1, b"", b"Error: No such object: cic-ynu-iotmal-sandbox-sandbox-manager-1\n", None),
                                     "ps": (0, b"mongo-db\trunning\tm\ti2\n", b"", None)})
    t("C12 manager inspect fails AND the successful listing has no manager -> FAIL 'ABSENT'",
      lambda: find(x, "manager:")["status"] == "FAIL" and find(x, "manager:")["ps_all_presence"] == "ABSENT")
    x = run(tmp, "manager-inspect-error", {"manager": PERM})
    t("C13 manager inspect fails but the listing shows it -> UNKNOWN (not 'not running')",
      lambda: find(x, "manager:")["status"] == "UNKNOWN" and find(x, "manager:")["ps_all_presence"] == "PRESENT")
    for n, sp, want in (("pgrep-found", (0, b"123 qemu-system-arm\n", b"", None), "FAIL"),
                        ("pgrep-error", (2, b"", b"pgrep: bad\n", None), "UNKNOWN")):
        x = run(tmp, n, {"pgrep": sp})
        t(f"C14 {n}: pgrep rc 1 = none, rc 0 = present (FAIL), other rc = read error (UNKNOWN), never 'none'",
          lambda x=x, want=want: find(x, "no qemu-system")["status"] == want)
    x = run(tmp, "nft-error", {"nft": (1, b"", b"Operation not permitted (you must be root)\n", None)})
    t("C15 nft read error -> UNKNOWN + collector exit 3", lambda: find(x, "nft ruleset")["status"] == "UNKNOWN" and x["rc"] == 3)
    x = run(tmp, "nft-differs", {"nft": (0, b"table inet other {\n}\n", b"", None)})
    t("C16 nft ruleset differs from the 06B-4G reference -> FAIL", lambda: find(x, "nft ruleset")["status"] == "FAIL")
    x = run(tmp, "exec-error", {"aa": (None, b"", b"", "EXEC_ERROR: FileNotFoundError: x")})
    t("C17 an executable that cannot run -> status EXEC_ERROR kept, UNKNOWN", lambda: x["reads"]["aa-status"]["status"] == "EXEC_ERROR"
      and find(x, "AppArmor")["status"] == "UNKNOWN")
    x = run(tmp, "timeout", {"version": (None, b"", b"", "TIMEOUT")})
    t("C18 a read that times out -> status TIMEOUT kept, UNKNOWN", lambda: x["reads"]["docker-version"]["status"] == "TIMEOUT"
      and find(x, "docker server")["status"] == "UNKNOWN")
    t("C19 collector never states a verdict: its meta says 'NOT a precheck verdict' and the code has no PASS output",
      lambda: "NOT a precheck verdict" in x["doc"]["meta"]["note"] and "PASS" not in open(os.path.join(HERE, "collector.py")).read()
      .split("def main", 1)[1])


def sec_E(tmp):
    def cli(src):
        dst = os.path.join(tmp, "res-%d.json" % len(os.listdir(tmp)))
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "evaluate_precheck.py"), src, dst,
                            "--ruleset-ref", os.path.join(tmp, "ref.txt")], capture_output=True, text=True)
        return p.returncode, json.load(open(dst))
    open(os.path.join(tmp, "ref.txt"), "w").write(REF)
    t("E1 evaluator CLI exit 0 only for a complete PASS", lambda: cli(os.path.join(tmp, "clean"))[0] == 0)
    t("E2 evaluator CLI exit 1 on a FAIL", lambda: cli(os.path.join(tmp, "image-mismatch"))[0] == 1)
    t("E3 evaluator CLI exit 2 on missing/failed reads", lambda: cli(os.path.join(tmp, "permission-denied"))[0] == 2)
    os.mkdir(os.path.join(tmp, "empty"))
    t("E4 collector output without reads.json -> UNUSABLE, exit 3", lambda: cli(os.path.join(tmp, "empty")) == (3, cli(os.path.join(tmp, "empty"))[1])
      and cli(os.path.join(tmp, "empty"))[1]["verdict"] == "UNUSABLE")


def sec_O(tmp):
    base = os.path.join(tmp, "toy")
    os.mkdir(base)
    me = os.geteuid()
    d = os.path.join(base, "out-link")
    victim = os.path.join(base, "victim")
    os.mkdir(victim, 0o700)
    open(os.path.join(victim, "reads.json"), "w").write("victim-original\n")
    os.symlink(victim, d)
    t("O1 output path that is a symlink -> refused (O_NOFOLLOW), nothing written to the target",
      lambda: raises(C.Refused, lambda: C.prepare_outdir(d, me)) and open(os.path.join(victim, "reads.json")).read()
      == "victim-original\n")
    ev = os.path.join(base, "empty-victim")
    os.mkdir(ev, 0o700)
    d2 = os.path.join(base, "out-link-empty")
    os.symlink(ev, d2)
    t("O1b symlink to an EMPTY directory with the right owner/mode -> still refused (only O_NOFOLLOW stops it)",
      lambda: raises(C.Refused, lambda: C.prepare_outdir(d2, me)) and os.listdir(ev) == [])
    for n, mode, owner, content in (("mode-0755", 0o755, me, False), ("not-empty", 0o700, me, True),
                                    ("other-owner", 0o700, me + 1, False)):
        p = os.path.join(base, n)
        os.mkdir(p, mode)
        os.chmod(p, mode)
        if content:
            open(os.path.join(p, "x"), "w").close()
        t(f"O2 output directory {n} -> refused", lambda p=p, owner=owner: raises(C.Refused, lambda: C.prepare_outdir(p, owner)))
    # race of the 06B-4IR2 review: the path is replaced by a symlink AFTER the check; writes follow the fd, not the path
    p = os.path.join(base, "race")
    os.mkdir(p, 0o700)
    fd = C.prepare_outdir(p, me)
    os.rename(p, p + ".orig")
    os.symlink(victim, p)
    C.collect(fd, fake_runner({}))
    os.close(fd)
    t("O3 output path swapped for a symlink after the check: every file lands in the checked directory, the symlink "
      "target is untouched",
      lambda: os.path.exists(os.path.join(p + ".orig", "reads.json"))
      and open(os.path.join(victim, "reads.json")).read() == "victim-original\n" and len(os.listdir(victim)) == 1)
    q = os.path.join(base, "planted")
    os.mkdir(q, 0o700)
    fd = C.prepare_outdir(q, me)
    os.symlink(os.path.join(victim, "reads.json"), os.path.join(q, "reads.json"))
    t("O4 a symlink planted under an output name -> creation fails (O_EXCL|O_NOFOLLOW), target untouched",
      lambda: raises(OSError, lambda: C.write_new(fd, "reads.json", "x")) and open(os.path.join(victim, "reads.json")).read()
      == "victim-original\n")
    os.close(fd)
    b = os.path.join(base, "bin")
    os.mkdir(b, 0o755)
    good, gw = os.path.join(b, "good"), os.path.join(b, "groupw")
    for f, m in ((good, 0o755), (gw, 0o775)):
        open(f, "w").write("#!/bin/sh\n")
        os.chmod(f, m)
    t("O5 trusted_bins: owner/mode checked for the file and its directory; group-writable or foreign-owned refused; "
      "relative path refused",
      lambda: C.trusted_bins({"g": good}, me) == [] and C.trusted_bins({"w": gw}, me) and C.trusted_bins({"g": good}, me + 1)
      and C.trusted_bins({"r": "docker"}, me))
    t("O6 the real pinned executables on this host pass trusted_bins (root-owned, not group/other-writable)",
      lambda: C.trusted_bins() == [])
    os.environ["CT01_SECRET_LIKE"] = "should-not-leak"
    rc, out, err, e = C.subprocess_runner(["/usr/bin/env"])     # prints exactly the environment it receives
    t("O7 subprocess environment is exactly the fixed minimal one (nothing inherited)",
      lambda: rc == 0 and sorted(l.split("=")[0] for l in out.decode().splitlines() if "=" in l) == sorted(C.ENV)
      and b"should-not-leak" not in out)
    p = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "collector.py"), os.path.join(base, "clean-x")],
                       capture_output=True, text=True)
    t("O8 collector main as a normal user -> REFUSED, exit 2 (needs root), nothing collected",
      lambda: p.returncode == 2 and "REFUSED" in p.stderr and not os.path.exists(os.path.join(base, "clean-x")))


def sec_L(tmp):
    """The root snippet of RUN-PROCEDURE.md, run as the current user with BASE in the toy tree and a stub PY."""
    doc = open(os.path.join(HERE, "RUN-PROCEDURE.md")).read()
    snip = doc.split("# --- BEGIN ROOT SNIPPET ---", 1)[1].split("# --- END ROOT SNIPPET ---", 1)[0]
    base = os.path.join(tmp, "launch")
    os.mkdir(base)
    stub = os.path.join(base, "py-stub")
    open(stub, "w").write('#!/bin/sh\necho "STUB-RAN $*" >> "$(dirname "$0")/ran.log"\nexit 0\n')
    os.chmod(stub, 0o755)
    good = C.sha256_file(os.path.join(HERE, "collector.py")) if hasattr(C, "sha256_file") else \
        subprocess.run(["sha256sum", os.path.join(HERE, "collector.py")], capture_output=True, text=True).stdout.split()[0]

    def go(h):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "BASE": base, "PY": stub, "HASH": h,
               "SRC": os.path.join(HERE, "collector.py")}
        return subprocess.run(["/bin/sh", "-c", snip], env=env, capture_output=True, text=True)
    p = go(good)
    tdirs = [x for x in os.listdir(base) if x.startswith("ct01-precheck.")]
    t("L1 snippet with the right hash: fresh mktemp dir (0700), copy checked, `out` 0700, the COPY is run",
      lambda: p.returncode == 0 and len(tdirs) == 1 and "STUB-RAN" in open(os.path.join(base, "ran.log")).read()
      and os.path.join(base, tdirs[0], "collector.py") in open(os.path.join(base, "ran.log")).read()
      and stat.S_IMODE(os.stat(os.path.join(base, tdirs[0])).st_mode) == 0o700
      and stat.S_IMODE(os.stat(os.path.join(base, tdirs[0], "out")).st_mode) == 0o700)
    if os.path.exists(os.path.join(base, "ran.log")):
        os.remove(os.path.join(base, "ran.log"))
    before = set(os.listdir(base))
    p = go("0" * 64)
    new = [x for x in os.listdir(base) if x.startswith("ct01-precheck.") and x not in before]
    t("L2 snippet with a wrong hash (file swapped/changed): nothing run, the copy removed, exit 1",
      lambda: p.returncode == 1 and "HASH MISMATCH" in p.stdout and not os.path.exists(os.path.join(base, "ran.log"))
      and len(new) == 1 and os.listdir(os.path.join(base, new[0])) == [])
    unquoted = re.sub(r'"[^"]*"', '""', snip)                 # command words only, not text inside strings
    words = re.findall(r"(?:^|[|;]|\$\(|\bif !|\|\|)\s*([^\s;|()]+)", unquoted, re.M)
    t("L3 snippet: absolute executables only, no source, no tee, no chown, no redirection into the user tree",
      lambda: not re.search(r"\b(source|tee|chown)\b|(^|\s)\.\s", snip) and ">" not in snip.replace("<HASH>", "")
      and all(w.startswith(("/", "$", "#")) or "=" in w or w in ("set", "umask", "if", "echo", "then", "fi", "exit", "!")
              for w in words))


def main(argv):
    jf = argv[argv.index("--json") + 1] if "--json" in argv else None
    with tempfile.TemporaryDirectory(prefix="selftest-precheck.") as tmp:
        for name, fn in (("C", sec_C), ("E", sec_E), ("O", sec_O), ("L", sec_L)):
            print(f"== section {name}")
            try:
                fn(tmp)
            except Exception:
                t(f"{name}-INFRA section crashed", lambda: False)
                traceback.print_exc()
    n = sum(RESULTS.values())
    if jf:
        json.dump(RESULTS, open(jf, "w"), indent=1)
    print(f"SELFTEST-PRECHECK: {n}/{len(RESULTS)} passed")
    return 0 if n == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
