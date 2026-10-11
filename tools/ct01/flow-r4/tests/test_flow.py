#!/usr/bin/env python3
"""Offline tests R2: flow_lane.py / evaluate_flow.py / export_run.py / lane_entry.sh (real code) against a fake manager/worker/docker/compose (fakes.py), the
evaluator on the produced run directories and on mutations of them, the review counterexamples (F1 failed measurements, F2 export failure), F5 and the entry
tail. No docker, no root, no network, no QEMU. usage: python3 -I -B tests/test_flow.py <tree>"""
import copy, hashlib, json, os, pathlib, re, shutil, signal, subprocess, sys, tempfile, threading, time
TREE = pathlib.Path(sys.argv[1]).resolve()
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fakes

RES = {}
def t(n, ok, detail=""):
    RES[n] = bool(ok); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"  -> {detail}"))

PINS = json.loads((TREE / "pins.json").read_text())
LITERAL = hashlib.sha256((TREE / "SHA256SUMS").read_bytes()).hexdigest()
FIX = TREE / "fixtures"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="flowtest."))
BIN = TMP / "bin"; BIN.mkdir()
for n, body in (("nft", "echo 'table inet filter'\n"), ("ip", "case \"$*\" in *addr*) echo '2: ens33    inet 192.168.177.128/24 brd 192.168.177.255 scope global dynamic ens33 valid_lft 1000sec preferred_lft 1000sec';; *) echo 'default via 192.168.177.2 dev ens33';; esac\n"), ("pgrep", "exit 1\n"), ("sysctl", "echo 1\n")):
    (BIN / n).write_text("#!/bin/bash\n" + body); (BIN / n).chmod(0o755)
(BIN / "docker").write_text(fakes.FAKE_DOCKER); (BIN / "docker").chmod(0o755)


def run_lane(mode, name, opts=None, extra_env=None, kill_after=None):
    sim = fakes.Sim(FIX, opts)
    srv = fakes.make_server(sim)
    th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
    env = dict(os.environ, PATH=f"{BIN}:/usr/bin:/bin", CT01_FAKE_PORT=str(srv.server_address[1]), CT01_FLOW_DOCKER=str(BIN / "docker"),
               CT01_FLOW_MANAGER_URL=f"http://127.0.0.1:{srv.server_address[1]}{fakes.BASE}", CT01_FLOW_V0_WAIT_S="10", CT01_FLOW_TASK_WAIT_S="40", CT01_FLOW_FAULT_WAIT_S="20")
    env.update(extra_env or {})
    run = TMP / name
    env["CT01_FLOW_PROC_ROOT"] = str(TMP / (name + "-proc"))
    sim.proc_root = TMP / (name + "-proc")
    p = subprocess.Popen([sys.executable, "-I", "-B", str(TREE / "flow_lane.py"), mode, str(run), name, PINS["image_id"], str(FIX), LITERAL], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if kill_after:
        time.sleep(kill_after); p.send_signal(signal.SIGTERM)
    out, _ = p.communicate(timeout=240)
    srv.shutdown()
    return p.returncode, run, sim, out


def ev(run, out=None, tree=None):
    tree = tree or TREE
    p = subprocess.run([sys.executable, "-I", "-B", str(tree / "evaluate_flow.py"), str(run), str(tree / "pins.json"), "--out", str(out or run / "verdicts.json")],
                       capture_output=True, text=True)
    v = json.loads(pathlib.Path(out or run / "verdicts.json").read_text())
    return p.returncode, v, p.stdout


def failing(v):
    return [c["name"] for c in v.get("checks", []) if not c["ok"]]


def mutate(run, name, fn):
    d = TMP / (run.name + "-mut-" + name)
    shutil.copytree(run, d)
    fn(d)
    return ev(d)


# ------------------------------------------------------------------ success
rc, run, sim, out = run_lane("success", "ok")
erc, v, so = ev(run)
t("S1 success lane rc 0 and every criterion held (both archs), identity pinned, every measurement valid", rc == 0 and erc == 0 and v["all_ok"] and len(v["checks"]) >= 60, f"rc={rc} erc={erc} fail={failing(v)}")
t("S2 the worker was removed by label and nothing is left", sim.worker is None and json.loads((run / "cleanup.json").read_text())["labelled_after"] == [])
t("S3 evidence files: identity, per-arch submit/poll/final/result, verify samples, manager before/after, host before/after",
  all((run / f).exists() for f in ("identity.json", "lane-status.json", "submit-ARM.json", "poll-MIPS.jsonl", "result-ARM.zip", "verify-MIPS-p2-uploading.txt",
                                    "manager-after-status.json", "host-before/nft.txt", "t19-manager-to-worker-health.txt", "verify-ARM-p1-running.json", "verify-MIPS-p2-uploading.json")))

def m_zip(d):
    import zipfile, io
    tid = json.loads((d / "submit-ARM.json").read_text())["task_id"]
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zz:
        for n, b in {tid: b"x", "strace.log": b"execve ./exec", "sar.out": b"s", "network.pcap": b"p", "qemu.log": b"q"}.items():
            zz.writestr(n, b)
    (d / "result-ARM.zip").write_bytes(z.getvalue())
MUT = {
    "result-binary-not-the-fixture": (m_zip, "result: the task binary is the submitted fixture (sha256)"),
    "no-execve-in-strace": (lambda d: [(d / "result-MIPS.zip").write_bytes(__import__("re").sub(b"", b"", (d / "result-MIPS.zip").read_bytes()))] and None, None),
    "worker-log-phase2-missing": (lambda d: [(d / n).write_text("\n".join(l for l in (d / n).read_text().splitlines() if "Uploading strace" not in l)) for n in ("worker-logs-final.txt", "worker-logs-final.err")],
                                  "T01/T02 runtime order in the worker log"),
    "t19-nonzero": (lambda d: (d / "t19-manager-to-worker-health.rc").write_text("1\n"), "manager container -> worker healthcheck"),
    "status-failed-seen": (lambda d: (d / "poll-ARM.jsonl").open("a").write(json.dumps({"t": 1, "http": 200, "task": {"task_id": "x", "status": "FAILED", "worker_id": "ct01-flow-worker"}}) + "\n"), "T18: the real poller"),
    "verify-p1-failed": (lambda d: (d / "verify-ARM-p1-running.rc").write_text("1\n"), "isolation verifier run IN the worker while p1-running"),
    "host-nft-changed": (lambda d: (d / "host-after/nft.txt").write_text("changed\n"), "nft unchanged"),
    "cleanup-leftover": (lambda d: (d / "cleanup.json").write_text(json.dumps({"labelled_before": ["a"], "ps_rc": 0, "labelled_after": ["a"], "ps_after_rc": 0})), "cleanup by label"),
    "manager-completed-not-incremented": (lambda d: (d / "manager-after-status.json").write_text(json.dumps({"http": 200, "body": json.dumps({"queued": 0, "processing": 0, "completed": 0, "failed": 0, "cancelled": 0, "in_memory_queue": 0})})),
                                          "/status: completed"),
    "v0-twice": (lambda d: (d / "worker-logs-final.txt").open("a").write("2026-10-11T00:00:00Z ISOLATION OK (V0 startup): ruleset\n"), "V0 OK exactly once"),
    "qemu-left": (lambda d: (d / "host-after/qemu.txt").write_text("123 qemu-system-arm\n"), "no qemu-system after"),
    "lane-aborted": (lambda d: (d / "lane-status.json").write_text(json.dumps({"schema": "ct01-flow-lane-status/1", "mode": "success", "label": "ok", "completed": False, "abort_reason": "x", "signal": None})), "the lane completed"),
    "image-id-differs": (lambda d: (d / "env-image-id.txt").write_text("sha256:deadbeef\n"), "worker image id equals"),
}
for name, (fn, want) in MUT.items():
    if name == "no-execve-in-strace":
        def fn(d):                                                # noqa: F811
            import zipfile, io
            tid = json.loads((d / "submit-MIPS.json").read_text())["task_id"]
            src = zipfile.ZipFile(d / "result-MIPS.zip"); z = io.BytesIO()
            with zipfile.ZipFile(z, "w") as zz:
                for n in src.namelist():
                    zz.writestr(n, b"nothing" if n == "strace.log" else src.read(n))
            (d / "result-MIPS.zip").write_bytes(z.getvalue())
        want = "strace.log non-empty and shows the guest executing"
    erc, vv, _ = mutate(run, name, fn)
    t(f"M-{name}: the evaluator refuses ({want[:50]})", erc == 1 and not vv["all_ok"] and any(want in f for f in failing(vv)), failing(vv)[:3])
# ------------------------------------------------------------------ f3 / f4
rc, run3, sim3, _ = run_lane("f3", "f3")
erc, v3, _ = ev(run3)
t("F3-1 fault while idle: task FAILED with the V1 reason, no QEMU, lane rc 0, evaluator holds", rc == 0 and erc == 0 and v3["all_ok"], failing(v3))
rc, run4, sim4, _ = run_lane("f4", "f4", {"phase1_s": 9.0})
erc, v4, _ = ev(run4)
t("F4-1 fault during phase 1: FAILED at V2, phase 1 confirmed down, phase 2 never started, evaluator holds", rc == 0 and erc == 0 and v4["all_ok"], failing(v4))
rc, runx, _, _ = run_lane("f3", "f3-fault-cmd-fails", {"fault_cmd_fails": True})
erc, vx, _ = ev(runx)
t("F3-2 the fault command failed: not a pass (the task completes without a fault)", erc == 1 and not vx["all_ok"], failing(vx))
rc, runy, _, _ = run_lane("f3", "f3-no-effect", {"ignore_fault": True})
erc, vy, _ = ev(runy)
t("F3-3 the fault had no effect (task COMPLETED): the F3 criteria fail", erc == 1 and not vy["all_ok"] and any("F3: FAILED" in f for f in failing(vy)), failing(vy))
rc, runz, _, _ = run_lane("success", "t19-fails", {"t19_fails": True})
erc, vz, _ = ev(runz)
t("T19-1 the manager->worker health check failed: the lane finishes, the evaluator refuses", erc == 1 and any("manager container -> worker healthcheck" in f for f in failing(vz)), failing(vz))
# ------------------------------------------------------------------ lane error paths
rc, runw, simw, _ = run_lane("success", "wrong-image", {"image_id": "sha256:other"})
erc, vw, _ = ev(runw)
t("E1 image id differs from the pin: lane aborts (rc 3) before any container, evaluator: not ok, nothing left", rc == 3 and erc != 0 and simw.worker is None and not vw["all_ok"])
rc, runk, simk, _ = run_lane("success", "sigterm", {"phase1_s": 5.0}, kill_after=4.0)
erc, vk, _ = ev(runk)
t("E2 SIGTERM during the task: cleanup ran (worker removed), lane rc 128+15, lane-status records the signal, evaluator refuses",
  rc == 143 and simk.worker is None and json.loads((runk / "lane-status.json").read_text())["signal"] == 15 and erc != 0 and not vk["all_ok"], f"rc={rc}")
rc, runq, simq, _ = run_lane("success", "queue-not-empty", {"preload_queued": 1})
erc, vq, _ = ev(runq)
t("E3 a foreign queued task exists: the lane aborts (rc 3) before the worker is started; nothing submitted; evaluator not ok",
  rc == 3 and simq.worker is None and not (runq / "submit-ARM.json").exists() and erc != 0 and not vq["all_ok"], f"rc={rc}")
# ------------------------------------------------------------------ R2: review counterexamples and new criteria
def setf(d, rel, text):
    pathlib.Path(d / rel).write_text(text)

rc, runok, _, _ = run_lane("success", "ok2")
def both_nft_fail(d):
    for side in ("before", "after"):
        setf(d, f"host-{side}/nft.rc", "1\n"); setf(d, f"host-{side}/nft.txt", ""); setf(d, f"host-{side}/nft.err", "Permission denied\n")
erc, vv, _ = mutate(runok, "F1-nft-both-failed", both_nft_fail)
t("F1 review counterexample: both host nft reads rc 1 with empty stdout are NOT 'unchanged': the evaluator refuses and names the measurement",
  erc == 1 and not vv["all_ok"] and any("host-before/nft: rc/schema" in f for f in failing(vv)) and any("nft unchanged before/after" in f for f in failing(vv)), failing(vv))
for name, fn, want in (
    ("ip-route-rc2-both", lambda d: [setf(d, f"host-{x}/ip-route.rc", "2\n") for x in ("before", "after")], "host-before/ip-route: rc/schema"),
    ("sysctl-garbage-both", lambda d: [setf(d, f"host-{x}/sysctl-forward.txt", "error\n") for x in ("before", "after")], "host-before/sysctl-forward: rc/schema"),
    ("docker-ps-empty-both", lambda d: [setf(d, f"host-{x}/docker-ps.txt", "") for x in ("before", "after")], "host-before/docker-ps: rc/schema"),
    ("rc-file-missing", lambda d: (d / "host-after/ip-addr.rc").unlink(), "host-after/ip-addr: rc/schema"),
    ("pgrep-rc2", lambda d: setf(d, "host-after/qemu.rc", "2\n"), "host-after/qemu: rc/schema"),
    ("pgrep-rc1-with-stderr", lambda d: setf(d, "host-after/capture.err", "pgrep: error\n"), "host-after/capture: rc/schema"),
    ("image-id-rc1", lambda d: setf(d, "env-image-id.rc", "1\n"), "env-image-id: rc 0"),
    ("env-qemu-rc127", lambda d: setf(d, "env-qemu.rc", "127\n"), "env-qemu: pgrep rc 0"),
    ("worker-logs-rc1", lambda d: setf(d, "worker-logs-final.rc", "1\n"), "worker-logs-final: docker logs rc 0"),
    ("t19-garbage", lambda d: setf(d, "t19-manager-to-worker-health.txt", "hello\n"), "manager container -> worker healthcheck"),
):
    erc, vv, _ = mutate(runok, "M2-" + name, fn)
    t(f"M2-{name}: refused ({want})", erc == 1 and not vv["all_ok"] and any(want in f for f in failing(vv)), failing(vv)[:4])
ok_abs = (runok / "host-after/qemu.rc").read_text().strip() == "1"
t("M2-pgrep-absent: the accepted run really carries pgrep rc 1 (absent) for qemu after the lane", ok_abs)
# identity pins
def legacy(d):
    j = json.loads((d / "identity.json").read_text()); j["schema"] = "ct01-flow-identity/1"; j.pop("tree", None); setf(d, "identity.json", json.dumps(j))
def tamper(key):
    def f(d):
        j = json.loads((d / "identity.json").read_text()); j["tree"][key] = "0" * 64; setf(d, "identity.json", json.dumps(j))
    return f
def noliteral(d):
    j = json.loads((d / "identity.json").read_text()); j["tree"]["manifest_literal"] = None; setf(d, "identity.json", json.dumps(j))
for name, fn in (("legacy-schema", legacy), ("runner-hash", tamper("runner_sha256")), ("evaluator-hash", tamper("evaluator_sha256")), ("pins-hash", tamper("pins_sha256")),
                 ("manifest-hash", tamper("manifest_sha256")), ("export-hash", tamper("export_sha256")), ("no-literal", noliteral)):
    erc, vv, _ = mutate(runok, "ID-" + name, fn)
    t(f"ID-{name}: the evaluator refuses a run whose identity does not pin the evaluating tree", erc == 1 and any("identity pins the staged tree" in f for f in failing(vv)), failing(vv)[:3])
# verifier binding
def vjson(d, tag, fn):
    p_ = d / f"verify-ARM-{tag}.json"; j = json.loads(p_.read_text()); fn(j); p_.write_text(json.dumps(j))
for name, fn in (("task-completed", lambda j: j["after"].update(task_status="COMPLETED")),
                 ("no-qemu-before", lambda j: j["before"].update(qemu_rc=1, qemu="")),
                 ("pid-set-changed", lambda j: j["after"].update(qemu="9999 qemu-system-arm")),
                 ("other-task", lambda j: j.update(task_id="someone-else")),
                 ("times-inverted", lambda j: j.update(t_start=j["t_end"] + 1)),
                 ("trigger-line-wrong", lambda j: j["trigger"].update(line="something else"))):
    erc, vv, _ = mutate(runok, "BIND-" + name, lambda d, fn=fn: vjson(d, "p1-running", fn))
    t(f"BIND-{name}: the verifier sample is not accepted as bound to the task/QEMU", erc == 1 and any("verifier sample p1-running bound" in f for f in failing(vv)), failing(vv)[:3])
t("BIND-ok: the samples carry the trigger line, start/end, task status PROCESSING and the same QEMU pid at both ends",
  all("verifier sample" not in f for f in failing(v)) and json.loads((runok / "verify-MIPS-p2-uploading.json").read_text())["before"]["task_status"] == "PROCESSING")

# ------------------------------------------------------------------ F5
rc5, run5, sim5, o5 = run_lane("f5", "f5")
erc5, v5, _ = ev(run5)
t("F5-1 compose worker created, restarted, verified, removed by exact id: lane rc 0 and every F5 criterion held", rc5 == 0 and erc5 == 0 and v5["all_ok"] and len(v5["checks"]) >= 35,
  f"rc={rc5} erc={erc5} {failing(v5)} {o5[-300:]}")
t("F5-2 the compose container is gone, manager/mongo records equal before/after, no flow worker was created", sim5.cw is None and sim5.worker is None
  and json.loads((run5 / "f5-others-before.json").read_text()) == json.loads((run5 / "f5-others-after.json").read_text()))
t("F5-3 the cleanup record names the exact id and labels were read back", json.loads((run5 / "cleanup.json").read_text()).get("labels_ok") is True
  and json.loads((run5 / "cleanup.json").read_text()).get("id") == fakes.CID)
for name, opts, want in (("same-netns", {"restart_same_ns": True}, "A14: Docker built a NEW network sandbox"),
                         ("no-second-v0", {"restart_no_v0": True}, "V0 OK once before and twice after"),
                         ("table-missing-after", {"f5_table_missing_after_restart": True}, "after set-up (after the restart)"),
                         ("manager-touched", {"restart_touches_manager": True}, "manager and MongoDB untouched"),
                         ("wrong-service-label", {"label_service": "sandbox-manager"}, "restart target is exactly the Compose service container")):
    rcx, runx5, simx5, _ = run_lane("f5", "f5-" + name, opts)
    erc, vx, _ = ev(runx5)
    t(f"F5-{name}: the evaluator refuses ({want[:45]})", erc == 1 and not vx["all_ok"] and any(want in f for f in failing(vx)), f"rc={rcx} {failing(vx)[:4]}")
rcx, runu, simu, _ = run_lane("f5", "f5-up-fails", {"up_fails": True})
erc, vu, _ = ev(runu)
t("F5-up-fails: lane aborts (rc 3), nothing created, evaluator refuses", rcx == 3 and simu.cw is None and erc != 0 and not vu["all_ok"], f"rc={rcx}")
rcx, runr, simr, _ = run_lane("f5", "f5-restart-fails", {"restart_fails": True})
erc, vr, _ = ev(runr)
t("F5-restart-fails: lane aborts (rc 3), the compose container is removed by id, evaluator refuses", rcx == 3 and simr.cw is None and erc != 0 and not vr["all_ok"], f"rc={rcx}")
rcx, runl, siml, _ = run_lane("f5", "f5-wrong-label", {"label_service": "sandbox-manager"})
t("F5-wrong-label-cleanup: a container whose service label is not the pinned one is NOT removed by the lane (labels read back first); cleanup.json says so",
  siml.cw is not None and json.loads((runl / "cleanup.json").read_text()).get("labels_ok") is False and json.loads((runl / "cleanup.json").read_text()).get("rm_rc") is None)

# the R2 real finding: the netns inode string is reused after a restart; with a new sandbox identity and a pristine second start the F5 criteria hold
def inode_reused(d):
    for tag in ("before", "after"):
        j = json.loads((d / f"f5-{tag}.json").read_text()); j["netns"] = "net:[4026532810]"; (d / f"f5-{tag}.json").write_text(json.dumps(j))
erc, vi, _ = mutate(run5, "F5-inode-reused", inode_reused)
t("F5-inode-reused: identical netns inode strings before/after (as observed on the real host) do NOT fail F5 when Docker's sandbox identity changed and the second start was pristine",
  erc == 0 and vi["all_ok"], failing(vi))
def second_start_inherited(d):
    p2 = d / "worker-logs-final.txt"; lines = p2.read_text().splitlines(); n = 0
    for i, l in enumerate(lines):
        if "(before run.sh): net.ipv4.ip_forward=1" in l:
            n += 1
            if n == 2:
                lines[i] = l.replace("ip_forward=1", "ip_forward=0")
    p2.write_text("\n".join(lines) + "\n")
erc, vs, _ = mutate(run5, "F5-second-start-not-pristine", second_start_inherited)
t("F5-second-start-not-pristine: the second start's pre-run.sh report shows inherited state: refused", erc == 1 and any("both starts saw a pristine namespace" in f for f in failing(vs)), failing(vs))

# ------------------------------------------------------------------ F2: export + entry tail
XR = TREE / "export_run.py"
def export(run_, out_, uid=None, gid=None, lane=0, ev_=0, sig=0, stage=None):
    cmd = [sys.executable, "-I", "-B", str(XR), str(run_), str(out_), "--uid", str(os.getuid() if uid is None else uid), "--gid", str(os.getgid() if gid is None else gid),
           "--lane-rc", str(lane), "--eval-rc", str(ev_), "--signal", str(sig)]
    if stage:
        cmd += ["--stage", str(stage)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout
st1 = TMP / "stage1"; shutil.copytree(runok, st1 / "run", symlinks=True)
os.symlink("host-before/nft.txt", st1 / "run" / "a-link")
xrc, xo = export(st1 / "run", TMP / "out1", stage=st1)
rcpt = json.loads((st1 / "export-receipt.json").read_text())
t("X1 clean export: rc 0, receipt verified, symlink preserved as a link, receipt beside (not inside) the copy",
  xrc == 0 and rcpt["export_status"] == "verified" and rcpt["final_rc"] == 0 and os.path.islink(TMP / "out1" / "a-link")
  and not (TMP / "out1" / "export-receipt.json").exists() and (TMP / "out1.export-receipt.json").exists(), xo)
st2 = TMP / "stage2"; shutil.copytree(runok, st2 / "run")
(TMP / "out2").mkdir()
xrc, xo = export(st2 / "run", TMP / "out2", stage=st2)
rcpt = json.loads((st2 / "export-receipt.json").read_text())
t("X2 copy fails (destination exists): rc 4, EXPORT NOT VERIFIED, receipt not_verified with the failing step, the stage run is kept", xrc == 4 and "NOT VERIFIED" in xo
  and rcpt["export_status"] == "not_verified" and rcpt["steps"]["copy"]["ok"] is False and (st2 / "run" / "identity.json").exists() and rcpt["final_rc"] == 4)
st3 = TMP / "stage3"; shutil.copytree(runok, st3 / "run")
xrc, xo = export(st3 / "run", TMP / "out3", uid=0 if os.getuid() else 1, gid=0, stage=st3)
rcpt = json.loads((st3 / "export-receipt.json").read_text())
t("X3 chown fails (a uid this user cannot give away to): rc 4, not_verified, chown step failed, verify not attempted", xrc == 4 and rcpt["steps"]["chown"]["ok"] is False
  and rcpt["steps"]["verify"]["detail"].startswith("not attempted") and rcpt["export_status"] == "not_verified")
st4 = TMP / "stage4"; shutil.copytree(runok, st4 / "run")
xrc0, _ = export(st4 / "run", TMP / "out4", stage=st4)
(TMP / "out4" / "identity.json").write_text("tampered")           # a copy that differs from the stage must not verify (checked by re-running verify on a tampered copy)
sys.path.insert(0, str(TREE))
import importlib.util
spec = importlib.util.spec_from_file_location("export_run_mod", XR); XM = importlib.util.module_from_spec(spec); spec.loader.exec_module(XM)
t("X4 inventory/verify: a tampered copy differs from the stage inventory", XM.inventory(st4 / "run") != XM.inventory(TMP / "out4"))
t("X5 final-exit priority: signal > lane > evaluator > export > 0",
  XM.final_rc(0, 0, 15, False)[0] == 143 and XM.final_rc(3, 1, None, False)[0] == 3 and XM.final_rc(0, 1, None, False)[0] == 1
  and XM.final_rc(0, 0, None, False)[0] == 4 and XM.final_rc(0, 0, None, True)[0] == 0 and XM.final_rc(130, 0, 2, True)[0] == 130)

def entry(mode, name, opts=None, pre=None, signal_after=None, image=None):
    """lane_entry.sh through the real bash with the stage layout the root command builds (tree copy, no manifest check: that is the root command's job)."""
    sim = fakes.Sim(FIX, opts)
    srv = fakes.make_server(sim)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stage = TMP / ("stage-" + name); (stage / "tree").mkdir(parents=True)
    for f in ("SHA256SUMS", "flow_lane.py", "evaluate_flow.py", "pins.json", "export_run.py", "lane_entry.sh"):
        shutil.copy(TREE / f, stage / "tree" / f)
    shutil.copytree(FIX, stage / "tree" / "fixtures")
    out = TMP / ("out-" + name)
    sim.proc_root = TMP / ("proc-" + name)
    env = dict(os.environ, PATH=f"{BIN}:/usr/bin:/bin", CT01_FAKE_PORT=str(srv.server_address[1]), CT01_FLOW_DOCKER=str(BIN / "docker"), CT01_FLOW_PY=sys.executable,
               CT01_FLOW_MANAGER_URL=f"http://127.0.0.1:{srv.server_address[1]}{fakes.BASE}", CT01_FLOW_V0_WAIT_S="10", CT01_FLOW_TASK_WAIT_S="40", CT01_FLOW_FAULT_WAIT_S="20",
               CT01_FLOW_PROC_ROOT=str(sim.proc_root), SUDO_UID=str(os.getuid()), SUDO_GID=str(os.getgid()))
    if pre:
        pre(stage, out)
    p = subprocess.Popen(["/bin/bash", str(stage / "tree" / "lane_entry.sh"), mode, str(stage), str(out), image or PINS["image_id"], LITERAL], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if signal_after:
        time.sleep(signal_after); p.send_signal(signal.SIGTERM)
    o, _ = p.communicate(timeout=300)
    srv.shutdown()
    rc_ = json.loads((stage / "export-receipt.json").read_text()) if (stage / "export-receipt.json").exists() else None
    return p.returncode, stage, out, o, rc_, sim
rc, stg, outd, o, rcp, _ = entry("f3", "e-ok")
t("EN1 entry tail, clean f3: exit 0, evaluator held, export verified, receipt final_rc 0, copy has MANIFEST and the evaluator verdict",
  rc == 0 and rcp and rcp["export_status"] == "verified" and (outd / "MANIFEST-SHA256").exists() and json.loads((outd / "verdicts.json").read_text())["all_ok"], f"rc={rc} {o[-300:]}")
rc, stg, outd, o, rcp, _ = entry("f3", "e-export-fails", pre=lambda s, out: out.mkdir())
t("EN2 review counterexample F2: lane rc 0 + evaluator rc 0 + export fails: EXPORT NOT VERIFIED and the exit is NONZERO (4), stage kept, receipt says not_verified",
  rc == 4 and "EXPORT NOT VERIFIED" in o and rcp and rcp["export_status"] == "not_verified" and (stg / "run" / "identity.json").exists(), f"rc={rc} {o[-300:]}")
rc, stg, outd, o, rcp, _ = entry("f3", "e-lane-abort", image="sha256:other")
t("EN3 lane aborts (image differs): exit 3 (the lane rc), export still done and verified, evaluator refused", rc == 3 and rcp and rcp["final_rc"] == 3 and rcp["export_status"] == "verified", f"rc={rc} {o[-200:]}")
rc, stg, outd, o, rcp, _ = entry("f3", "e-lane-abort-export-fails", image="sha256:other", pre=lambda s, out: out.mkdir())
t("EN4 lane aborts AND export fails: the lane rc (3) keeps priority over the export status (4)", rc == 3 and rcp and rcp["final_rc"] == 3 and rcp["export_status"] == "not_verified", f"rc={rc}")
rc, stg, outd, o, rcp, _ = entry("f3", "e-eval-fails-export-fails", {"ignore_fault": True}, pre=lambda s, out: out.mkdir())
t("EN5 the task completes despite the fault (evaluator rc 1) AND export fails: exit 1", rc == 1 and rcp and rcp["final_rc"] == 1 and rcp["export_status"] == "not_verified", f"rc={rc}")
rc, stg, outd, o, rcp, _ = entry("f4", "e-sigterm", {"phase1_s": 12.0}, signal_after=3.0)
t("EN6 SIGTERM to the entry: it finalises ONCE (one receipt, stage kept) and exits 128+15", rc == 143 and rcp and rcp["signal"] == 15 and rcp["final_rc"] == 143, f"rc={rc} {o[-200:]}")
n = sum(RES.values())
print(f"TEST-FLOW: {n}/{len(RES)} passed")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0 if n == len(RES) else 1)
