#!/usr/bin/env python3
"""A FAKE `docker` for tests/test_orchestration.py: no daemon, no container, no network. Logs every argv, keeps a tiny state, prints canned output.
FAKE_DOCKER_STATE=<dir> FAKE_MODE=<mode> FAKE_PINS=<pins.json>. Not evidence of anything about a real daemon."""
import hashlib, json, os, pathlib, sys, time

S = pathlib.Path(os.environ["FAKE_DOCKER_STATE"])
MODE = os.environ.get("FAKE_MODE", "ok")
PINS = json.loads(pathlib.Path(os.environ["FAKE_PINS"]).read_text())
IMG = PINS["image_id"]
STAGE = pathlib.Path(os.environ["FAKE_PINS"]).resolve().parent.parent
EXPECTED = STAGE / PINS["expected_ruleset"]
NET = "cic-ynu-iotmal-sandbox_sandboxnet"
A = sys.argv[1:]
S.mkdir(parents=True, exist_ok=True)
with (S / "argv.log").open("a") as f:
    f.write(json.dumps(A) + "\n")
cf = S / "containers.json"
C = json.loads(cf.read_text()) if cf.exists() else {}
OTHER = {"m" * 64: {"name": "mongo-db", "running": True}}


def save():
    cf.write_text(json.dumps(C))


def ev(cid, status, **attrs):
    with (S / "events.log").open("a") as f:
        f.write(json.dumps({"Type": "container", "status": status, "id": cid, "Actor": {"ID": cid, "Attributes": dict({"name": C.get(cid, {}).get("name", "")}, **attrs)}}) + "\n")


def val(flag, default=None, multi=False):
    out = []
    for i, a in enumerate(A):
        if a == flag and i + 1 < len(A):
            out.append(A[i + 1])
    return out if multi else (out[0] if out else default)


def has_f(fmt):
    return "-f" in A and fmt in A[A.index("-f") + 1]


def ident(x):
    if x in C:
        return x
    for k, v in C.items():
        if v["name"] == x:
            return k
    return None


cmd = A[0] if A else ""
if cmd == "image" and A[1] == "inspect":
    if MODE == "image_mismatch":
        print("sha256:" + "9" * 64)
    else:
        print(IMG)
elif cmd == "image" and A[1] == "ls":
    print(IMG)
elif cmd == "network" and A[1] == "ls":
    if MODE != "no_network":
        print(NET)
elif cmd == "network" and A[1] == "inspect":
    print(f"name={NET} id=1d86 driver=bridge internal=false subnet=192.168.60.0/24 gw=192.168.60.1 containers=[]")
elif cmd == "ps":
    if "--format" in A:
        print("mongo-db")
        if MODE == "worker_running":
            print("ct01-sandbox-worker-1")
    elif "--filter" in A:
        want = A[A.index("--filter") + 1].split("=", 2)[-1]
        for k, v in C.items():
            if v["labels"].get("ct01-v0rt") == want:
                print(k)
    else:
        if MODE == "ps_fail":
            sys.exit(19)
        for k in list(OTHER) + list(C):
            print(k)
elif cmd == "inspect":
    tgt = A[-1]
    if tgt in OTHER or tgt == "mongo-db":
        print("/mongo-db " + "m" * 64 + " running 2026-10-06T13:00:00Z 0")
        sys.exit(0)
    cid = ident(tgt)
    if cid is None:
        if MODE == "name_exists" and tgt == "ct01-v0rt-f6":
            print("[{}]")
            sys.exit(0)
        sys.exit(1)
    c = C[cid]
    state = {"Status": "running" if c["running"] else "exited", "Running": c["running"], "ExitCode": c["exit"], "OOMKilled": False}
    if has_f("index .Config.Labels"):
        print(c["labels"].get("ct01-v0rt", ""))
    elif has_f(".State.Running"):
        print("true" if c["running"] else "false")
    elif has_f("json .State"):
        print(json.dumps(state))
    else:
        print(json.dumps([{"Id": cid, "Name": "/" + c["name"], "Image": IMG, "RestartCount": 0, "State": state,
                           "HostConfig": {"NetworkMode": NET, "PortBindings": {}, "RestartPolicy": {"Name": "no"}, "Binds": c["binds"], "Privileged": True},
                           "Config": {"Env": c["env"], "Labels": c["labels"]}}]))
elif cmd == "run":
    rm = "--rm" in A
    envs, binds = val("-e", multi=True), val("-v", multi=True)
    c_arg = val("-c")
    if rm:
        if c_arg and "command -v" in c_arg:
            nft = "NONE" if "PATH=/ct01-path" in envs else "/usr/sbin/nft"
            ipp = "/ct01-path/ip" if "PATH=/ct01-path" in envs else "/usr/sbin/ip"
            py = "/ct01-path/python3" if "PATH=/ct01-path" in envs else "/usr/bin/python3"
            if MODE == "nft_resolvable":
                nft = "/usr/sbin/nft"
            print(f"nft={nft}\nip={ipp}\npython3={py}")
        elif c_arg and "sha256sum" in c_arg:
            for rel, m in PINS["sources"].items():
                if rel != "isolation/__init__.py":
                    print(f"{'0' * 64 if (MODE == 'image_bytes' and rel == 'run.sh') else m['sha256']}  {rel}")
        elif c_arg and "nft -c" in c_arg:
            # real behaviour (R4 run 20261010T161816Z + r5 probe): the netdev chain is bound to tap0; without a tap0 in the container netns nft -c fails
            if MODE == "tap0_create_fails" and "ip link add tap0" in c_arg:
                print("TAP0-CREATE-FAILED\nRC=97")
            elif MODE == "nft_check_fails" or "ip link add tap0" not in c_arg:
                print("RC=1")
            else:
                print("ip link show tap0 (fake)\nRC=0")
        ev("pre" + "0" * 61, "start")
        sys.exit(0)
    name = val("--name")
    cid = hashlib.sha256(name.encode()).hexdigest()
    case = name.rsplit("-", 1)[-1]
    exit_code = {"control": 0, "f1b": 127, "f6": 1}[case]
    if MODE == "f1b_exit_1" and case == "f1b":
        exit_code = 1
    C[cid] = {"name": name, "case": case, "running": case == "control", "exit": 0 if case == "control" else exit_code, "env": envs,
              "binds": binds, "labels": {"ct01-v0rt": val("--label").split("=", 1)[1]}}
    save()
    ev(cid, "create"), ev(cid, "start")
    if MODE == "create_gap":                          # the daemon has created the container; the CLI has not yet printed the id
        (S / "created").write_text(cid)
        time.sleep(float(os.environ.get("FAKE_GAP", "4")))
    sd = [b.split(":")[0] for b in binds if b.endswith(":/sentinel-out")][0]
    if case == "control":
        for m in ("poller-called", "server-called"):
            pathlib.Path(sd, m).write_text("x\n")
    elif MODE == "f6_marker" and case == "f6":
        pathlib.Path(sd, "poller-called").write_text("x\n")
    else:
        ev(cid, "die", exitCode=str(exit_code))
    print(cid)
elif cmd == "wait":
    if MODE == "wait_timeout":
        sys.exit(124)
    print(C[ident(A[-1])]["exit"])
elif cmd == "logs":
    c = C.get(ident(A[-1]))
    if c is None:
        sys.exit(1)
    n = 59
    # R6: the shape of the real R5 run (20261010T164552Z): the F1b bash message and the F6 ISOLATION FAIL line are on STDERR; the sentinel markers are one
    # line without newline followed by an empty line. FAKE_MODE=logs_stdout_only keeps every line on stdout (the R4 fixture shape) for the regression test.
    L = [("SYSCTL REPORT (before run.sh): net.ipv4.ip_forward=1", "out")]
    if c["case"] == "control":
        L += [("SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0", "out"), ("ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route", "out"),
              ("SENTINEL poller.py called (no real poller started)SENTINEL server.py called (no real server started)", "out"), ("", "out")]
    elif c["case"] == "f1b":
        L += [(f"run.sh: line {n}: nft: command not found", "err")]
    else:
        exp = json.loads(EXPECTED.read_text())["tables"]["inet sandbox_guest"]
        last = max(i for i, x in enumerate(exp) if x.get("rule", {}).get("chain") == "input")
        rule = {"rule": {"chain": "input", "expr": [{"match": {"left": {"payload": {"field": "saddr", "protocol": "ip"}}, "op": "==", "right": "203.0.113.250"}}, {"accept": None}],
                         "family": "inet", "table": "sandbox_guest"}}
        L += [("SYSCTL REPORT (after run.sh): net.ipv4.ip_forward=0", "out"),
              (f"ISOLATION FAIL (V0 startup): ruleset: table 'inet sandbox_guest' differs at item {last + 1}: expected={json.dumps(exp[last + 1], sort_keys=True)} actual={json.dumps(rule, sort_keys=True)}", "err")]
    for i, (l, stream) in enumerate(L):
        out = sys.stdout if (stream == "out" or MODE == "logs_stdout_only") else sys.stderr
        print(f"2026-10-10T05:00:00.{i + 1:09d}Z {l}", file=out)
elif cmd == "exec":
    text = " ".join(A[2:])
    if "isolation.verify --phase" in text:
        print("ISOLATION OK (ct01 v0rt control recheck): ruleset,sysctl,link,neighbor,route")
    elif text.startswith("ps"):
        print("  PID  PPID COMMAND\n    1     0 python3 poller.py")
    elif "grep -q SENTINEL" in text:
        pass
    elif "sha256sum" in text:
        for rel, m in PINS["sources"].items():
            if rel != "isolation/__init__.py":
                print(f"{m['sha256']}  {rel}")
    elif "--dump-normalized" in text:
        print(EXPECTED.read_text())
    elif "nft --version" in text:
        print("nftables v1.0.2 (Lester Gooch)")
elif cmd == "stop":
    cid = ident(A[-1]); C[cid]["running"] = False; save(); ev(cid, "kill"); ev(cid, "die", exitCode="0")
elif cmd == "rm":
    cid = ident(A[-1])
    if cid:
        ev(cid, "destroy")
        C.pop(cid)
        save()
elif cmd == "events":
    seen = 0
    end = time.time() + 60
    while time.time() < end:
        p = S / "events.log"
        if p.exists():
            ls = p.read_text().splitlines()
            for l in ls[seen:]:
                print(l, flush=True)
            seen = len(ls)
        time.sleep(0.05)
else:
    print("fake docker: unhandled", A, file=sys.stderr)
    sys.exit(97)
