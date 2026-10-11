"""Offline tests of evaluate_v0_runtime.py on SYNTHETIC run directories. Nothing here is runtime evidence: it shows that the criteria discriminate
(the clean synthetic run passes; every single defect below makes it fail), and that no constant item number is required.
usage: python3 -I -B tests/test_evaluator.py"""
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import traceback

P = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(P))
import evaluate_v0_runtime as EV  # noqa: E402

PINS = json.loads((P / "pins.json").read_text())
EXP = json.loads(pathlib.Path(PINS["expected_ruleset"]).read_text())
IMG = PINS["image_id"]
NET = "cic-ynu-iotmal-sandbox_sandboxnet"
LABEL = "20261010T050000Z-4242"
ID = {"control": "a" * 64, "f1b": "b" * 64, "f6": "c" * 64}
RESULTS = {}
TS = "2026-10-10T05:00:00.%09dZ"
RULE = {"rule": {"chain": "input", "expr": [{"match": {"left": {"payload": {"field": "saddr", "protocol": "ip"}}, "op": "==", "right": "203.0.113.250"}}, {"accept": None}],
                 "family": "inet", "table": "sandbox_guest"}}


def t(name, fn):
    try:
        ok, why = bool(fn()), ""
    except Exception:
        ok, why = False, traceback.format_exc(limit=2).strip().splitlines()[-1]
    RESULTS[name] = ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({why})" if why else ""))


def lines(*texts, start=1):
    return "".join((TS % (start + i)) + " " + x + "\n" for i, x in enumerate(texts))


def inspect_obj(case, env_extra=(), binds_extra=(), exit_code=0, status="exited", image=IMG, net=NET, binds_override=None, ports=None, restarts=0, label=LABEL):
    binds = ["/p/files/sentinel/server.py:/app/server.py:ro", "/p/files/sentinel/poller.py:/app/poller.py:ro", f"/p/run/{case}/sentinel:/sentinel-out"] + list(binds_extra)
    if binds_override is not None:
        binds = binds_override
    return [{"Id": ID[case], "Image": image, "RestartCount": restarts,
             "HostConfig": {"NetworkMode": net, "PortBindings": ports or {}, "RestartPolicy": {"Name": "no"}, "Binds": binds, "Privileged": True},
             "Config": {"Env": ["ALLOW_VM_INTERNET=false", "PORT=8011"] + list(env_extra), "Labels": {"ct01-v0rt": label}},
             "State": {"Status": status, "ExitCode": exit_code, "OOMKilled": False}}]


def build(dst):
    """A run directory in which every criterion holds."""
    w = lambda p, s: (dst / p).parent.mkdir(parents=True, exist_ok=True) or (dst / p).write_text(s if isinstance(s, str) else json.dumps(s))   # noqa: E731
    w("network-name.txt", NET + "\n")
    w("run-label.txt", LABEL + "\n")
    w("f6-guest-path.txt", PINS["guest_f6_path"] + "\n")
    w("preflight/resolve-default-path.txt", "nft=/usr/sbin/nft\nip=/usr/sbin/ip\npython3=/usr/bin/python3\n")
    w("preflight/resolve-nonft-path.txt", "nft=NONE\nip=/ct01-path/ip\npython3=/ct01-path/python3\n")
    w("preflight/sha256-in-image.txt", "".join(f"{m['sha256']}  {rel}\n" for rel, m in PINS["sources"].items() if rel != "isolation/__init__.py"))
    w("preflight/f6-nft-check.rc", "0\n")
    w("preflight/f6-nft-check.txt", "RC=0\n")
    # control
    w("control/inspect.json", inspect_obj("control"))
    w("control/state-before-stop.json", {"Status": "running", "ExitCode": 0, "RestartCount": 0})
    w("control/docker-logs.txt", lines("SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=1", "SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0",
                                       "ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route", "SENTINEL poller.py called (no real poller started)",
                                       "SENTINEL server.py called (no real server started)"))
    (dst / "control/sentinel").mkdir()
    (dst / "control/sentinel/poller-called").write_text("x\n")
    (dst / "control/sentinel/server-called").write_text("x\n")
    w("control/exec/verify-recheck.rc", "0\n")
    w("control/exec/ps.txt", "  PID  PPID COMMAND\n    1     0 python3 poller.py\n")
    w("control/exec/sentinel-grep.rc", "0\n")
    w("control/exec/sha256-in-container.txt", "".join(f"{m['sha256']}  {rel}\n" for rel, m in PINS["sources"].items() if rel != "isolation/__init__.py"))
    w("control/exec/normalized-runtime.json", EXP)
    w("control/container-id.txt", ID["control"] + "\n")
    # f1b
    w("f1b/inspect.json", inspect_obj("f1b", env_extra=["PATH=/ct01-path"], binds_extra=["/p/run/ct01-path:/ct01-path:ro"], exit_code=127))
    w("f1b/docker-logs.txt", lines("SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=1", "run.sh: line 59: nft: command not found"))
    (dst / "f1b/sentinel").mkdir()
    w("f1b/container-id.txt", ID["f1b"] + "\n")
    # f6: expected item = the item after the last `input` rule in the pinned expected ruleset (information), actual = the added rule
    n = EV.derived_item_index(EXP["tables"])
    fail = f"ISOLATION FAIL (V0 startup): ruleset: table 'inet sandbox_guest' differs at item {n}: expected={json.dumps(EXP['tables']['inet sandbox_guest'][n], sort_keys=True)} actual={json.dumps(RULE, sort_keys=True)}"
    w("f6/inspect.json", inspect_obj("f6", binds_extra=[PINS["guest_f6_path"] + ":/app/isolation/guest.nft:ro"], exit_code=1))
    w("f6/docker-logs.txt", lines("SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=1", "SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0", fail))
    (dst / "f6/sentinel").mkdir()
    w("f6/container-id.txt", ID["f6"] + "\n")
    # global
    ev = []
    for c, code in (("control", "0"), ("f1b", "127"), ("f6", "1")):
        for st in ("create", "start", "kill", "die", "destroy"):
            e = {"Type": "container", "status": st, "id": ID[c], "Actor": {"ID": ID[c], "Attributes": {"name": f"ct01-v0rt-{c}"}}}
            if st == "die":
                e["Actor"]["Attributes"]["exitCode"] = code
            ev.append(e)
    w("events.jsonl", "".join(json.dumps(e) + "\n" for e in ev))
    cmds = ["image inspect -f {{.Id}} " + IMG, "ps --format {{.Names}}", "network ls", "network inspect x", "events --since 1"]
    cmds += [f"run -d --name ct01-v0rt-{c} --label ct01-v0rt={LABEL} --restart no --privileged --network {NET} {IMG}" for c in ID]
    cmds += [f"inspect {ID[c]}" for c in ID] + [f"wait {ID['f1b']}", f"wait {ID['f6']}", f"logs --timestamps {ID['control']}", f"exec {ID['control']} ps -eo pid",
                                               f"stop -t 10 {ID['control']}"] + [f"rm {ID[c]}" for c in ID]
    w("docker-commands.log", "\n".join(cmds) + "\n")
    for ph in ("host-before", "host-after"):
        for f, s in (("nft-ruleset-stateless.txt", "table inet filter\n"), ("sysctl.txt", "a=1\n"), ("ip-route.txt", "default via 1.1.1.1\n"), ("ip6-route.txt", "\n"),
                     ("qemu.txt", "no qemu-system\n"), ("listen-tcp.txt", "0.0.0.0:22\n"), ("docker-others.txt", "/mongo-db abc running 2026 0\n"),
                     ("image-id.txt", IMG + "\n"), ("iptables-save.txt", "*filter\n"), ("host-tap0.txt", 'Device "tap0" does not exist.\n')):
            w(f"{ph}/{f}", s)
    w("leftover-containers.txt", "")


def run_eval(mutator=None):
    d = pathlib.Path(tempfile.mkdtemp(prefix="v0rt-test."))
    try:
        build(d)
        if mutator:
            mutator(d)
        ck, info = EV.evaluate(d, PINS)
        return ck, info
    finally:
        shutil.rmtree(d, ignore_errors=True)


def failed(ck):
    return [f"[{r['case']}] {r['check']}" for r in ck.rows if not r["ok"]]


def mut(fn):
    return lambda d: fn(d)


def sub(path, a, b):
    def f(d):
        p = d / path
        s = p.read_text()
        assert a in s, (path, a)
        p.write_text(s.replace(a, b))
    return f


def setjson(path, fn):
    def f(d):
        o = json.loads((d / path).read_text())
        fn(o)
        (d / path).write_text(json.dumps(o))
    return f


def chain(*fs):
    return lambda d: [f(d) for f in fs]


def main():
    ck, info = run_eval()
    t("T0 the clean synthetic run satisfies every criterion", lambda: ck.all_ok() and not failed(ck))
    t("T0b the derived item index is information (25 for the pinned expected ruleset), never a pass condition", lambda: info["derived_item_index_for_a_rule_appended_to_input"] == 25)

    def item_variant(n):
        def f(d):
            p = d / "f6/docker-logs.txt"
            s = p.read_text()
            import re
            p.write_text(re.sub(r"at item \d+:", f"at item {n}:", s))
        return f
    for n in (31, 7, 0):
        t(f"T1 F6 with item {n} still passes: the number is parsed, never compared with a constant", lambda n=n: run_eval(item_variant(n))[0].all_ok())

    cases = {
        # F1b
        "F1b exit code 1 instead of 127": setjson("f1b/inspect.json", lambda o: o[0]["State"].update(ExitCode=1)),
        "F1b the container is still running": setjson("f1b/inspect.json", lambda o: o[0]["State"].update(Status="running")),
        "F1b run.sh got past nft (after-run.sh report)": sub("f1b/docker-logs.txt", "run.sh: line 59", "SYSCTL REPORT (after run.sh): x\n" + TS % 9 + " run.sh: line 59"),
        "F1b nft message names another line (another script ran)": sub("f1b/docker-logs.txt", "line 59", "line 58"),
        "F1b a V0 line is present": sub("f1b/docker-logs.txt", "run.sh: line 59", "ISOLATION OK (V0 startup): x\n" + TS % 9 + " run.sh: line 59"),
        "F1b a sentinel marker exists (a server/poller was started)": mut(lambda d: (d / "f1b/sentinel/server-called").write_text("x")),
        "F1b without the PATH override": setjson("f1b/inspect.json", lambda o: o[0]["Config"].update(Env=["ALLOW_VM_INTERNET=false"])),
        "F1b restricted PATH still resolves nft": sub("preflight/resolve-nonft-path.txt", "nft=NONE", "nft=/usr/sbin/nft"),
        "F1b the default PATH lacks nft too (not a controlled difference)": sub("preflight/resolve-default-path.txt", "nft=/usr/sbin/nft", "nft=NONE"),
        # F6
        "F6 exit code 0": setjson("f6/inspect.json", lambda o: o[0]["State"].update(ExitCode=0)),
        "F6 no ISOLATION FAIL line": sub("f6/docker-logs.txt", "ISOLATION FAIL (V0 startup)", "SOMETHING ELSE"),
        "F6 a second ISOLATION FAIL line": mut(lambda d: (d / "f6/docker-logs.txt").write_text((d / "f6/docker-logs.txt").read_text() + TS % 99 + " ISOLATION FAIL (V0 startup): sysctl: x\n")),
        "F6 the diff is about another table": sub("f6/docker-logs.txt", "table 'inet sandbox_guest'", "table 'arp sandbox_guest_arp'"),
        "F6 the actual JSON is another rule": sub("f6/docker-logs.txt", "203.0.113.250", "198.51.100.1"),
        "F6 nft itself rejected the file (Error:)": sub("f6/docker-logs.txt", "SYSCTL REPORT (after run.sh)", "Error: syntax error\n" + TS % 8 + " SYSCTL REPORT (after run.sh)"),
        "F6 V0 not reached (no after-run.sh report)": sub("f6/docker-logs.txt", "SYSCTL REPORT (after run.sh)", "SYSCTL REPORT (before run.sh)"),
        "F6 a sentinel marker exists": mut(lambda d: (d / "f6/sentinel/poller-called").write_text("x")),
        "F6 guest-f6.nft not mounted read-only": setjson("f6/inspect.json", lambda o: o[0]["HostConfig"].update(Binds=[b.replace("guest.nft:ro", "guest.nft") for b in o[0]["HostConfig"]["Binds"]])),
        "F6 nft -c check failed": mut(lambda d: (d / "preflight/f6-nft-check.rc").write_text("1\n")),
        "F6 the fixture file differs from the pin": mut(lambda d: (d / "f6-guest-path.txt").write_text(str(P / "files/guest-f6.nft.diff") + "\n")),
        # control
        "control without sentinel markers": mut(lambda d: [x.unlink() for x in (d / "control/sentinel").iterdir()]),
        "control sentinel logged BEFORE the V0 OK line": setjson("control/inspect.json", lambda o: None) if False else mut(lambda d: (d / "control/docker-logs.txt").write_text(
            lines("SENTINEL poller.py called", "SENTINEL server.py called", "ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route"))),
        "control real kernel ruleset differs from expected": setjson("control/exec/normalized-runtime.json", lambda o: o["tables"]["inet sandbox_guest"].append(RULE)),
        "control shows a qemu process": sub("control/exec/ps.txt", "python3 poller.py", "qemu-system-arm -M virt"),
        "control container holds other bytes of run.sh": sub("control/exec/sha256-in-container.txt", PINS["sources"]["run.sh"]["sha256"][:16], "0" * 16),
        "control sentinels not mounted (real poller path)": setjson("control/inspect.json", lambda o: o[0]["HostConfig"].update(Binds=[b for b in o[0]["HostConfig"]["Binds"] if "poller.py" not in b])),
        # common/global
        "wrong image id": setjson("f6/inspect.json", lambda o: o[0].update(Image="sha256:" + "0" * 64)),
        "host network mode": setjson("f6/inspect.json", lambda o: o[0]["HostConfig"].update(NetworkMode="host")),
        "published port": setjson("f1b/inspect.json", lambda o: o[0]["HostConfig"].update(PortBindings={"8011/tcp": [{"HostPort": "8011"}]})),
        "restart policy always": setjson("f1b/inspect.json", lambda o: o[0]["HostConfig"].update(RestartPolicy={"Name": "always"})),
        "ALLOW_VM_INTERNET not false": setjson("f1b/inspect.json", lambda o: o[0]["Config"].update(Env=["ALLOW_VM_INTERNET=true", "PATH=/ct01-path"])),
        "host nft ruleset changed": mut(lambda d: (d / "host-after/nft-ruleset-stateless.txt").write_text("table inet filter\ntable inet sandbox_guest\n")),
        "host sysctl changed": mut(lambda d: (d / "host-after/sysctl.txt").write_text("a=0\n")),
        "another container changed state": mut(lambda d: (d / "host-after/docker-others.txt").write_text("/mongo-db abc exited 2026 0\n")),
        "image id changed": mut(lambda d: (d / "host-after/image-id.txt").write_text("sha256:" + "f" * 64 + "\n")),
        "qemu on the host after": mut(lambda d: (d / "host-after/qemu.txt").write_text("1234 qemu-system-arm\n")),
        "leftover container": mut(lambda d: (d / "leftover-containers.txt").write_text(ID["f6"] + "\n")),
        "docker build in the command log": mut(lambda d: (d / "docker-commands.log").write_text((d / "docker-commands.log").read_text() + "build -t x .\n")),
        "docker run --network host in the command log": mut(lambda d: (d / "docker-commands.log").write_text((d / "docker-commands.log").read_text() + "run -d --network host x\n")),
        "docker rm of a container this run did not create": mut(lambda d: (d / "docker-commands.log").write_text((d / "docker-commands.log").read_text() + "rm " + "d" * 64 + "\n")),
        "docker exec into mongo-db": mut(lambda d: (d / "docker-commands.log").write_text((d / "docker-commands.log").read_text() + "exec mongo-db mongosh\n")),
        "no die event for the f1b container": mut(lambda d: (d / "events.jsonl").write_text("".join(l + "\n" for l in (d / "events.jsonl").read_text().splitlines()
                                                                                              if not (ID["f1b"] in l and '"die"' in l)))),
        "die event exit code differs from the expected one": sub("events.jsonl", '"exitCode": "127"', '"exitCode": "1"'),
        "a restart event": mut(lambda d: (d / "events.jsonl").write_text((d / "events.jsonl").read_text() + json.dumps({"Type": "container", "status": "restart", "id": ID["f6"]}) + "\n")),
    }
    for name, m in cases.items():
        t(f"D {name} -> criteria NOT met", lambda m=m: not run_eval(m)[0].all_ok())

    def incomplete():
        d = pathlib.Path(tempfile.mkdtemp(prefix="v0rt-test."))
        try:
            build(d)
            (d / "f6/docker-logs.txt").unlink()
            r = subprocess.run([sys.executable, "-I", "-B", str(P / "evaluate_v0_runtime.py"), str(d), str(P / "pins.json")], capture_output=True, text=True)
            return r.returncode == 2 and "INCOMPLETE" in r.stdout
        finally:
            shutil.rmtree(d, ignore_errors=True)
    t("D a missing artefact -> exit 2 (incomplete, not a result)", incomplete)

    def cli_clean():
        d = pathlib.Path(tempfile.mkdtemp(prefix="v0rt-test."))
        try:
            build(d)
            r = subprocess.run([sys.executable, "-I", "-B", str(P / "evaluate_v0_runtime.py"), str(d), str(P / "pins.json"), "--out", str(d / "v.json")], capture_output=True, text=True)
            v = json.loads((d / "v.json").read_text())
            return r.returncode == 0 and v["all_ok"] and (d / "f6-v0-diff.json").exists() and "Not CT-01 PASS" in v["statement"]
        finally:
            shutil.rmtree(d, ignore_errors=True)
    t("T2 CLI exit 0 on the clean synthetic run; the F6 diff JSON is written next to the log; the statement denies a CT-01 PASS", cli_clean)
    n = sum(RESULTS.values())
    print(f"TEST-V0-RUNTIME-EVALUATOR: {n}/{len(RESULTS)} passed")
    return 0 if n == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
