"""analysis.py: guest network parameters and V1/V2 gating of QEMU spawns."""
import os

import pytest

from conftest import BASE
from isolation import constants as C
from isolation.verify import IsolationError
from service import analysis as A


class FakeProc:
    def __init__(self, cmd, **kw):
        self.cmd = cmd
        self.sent = []
        self.killed = False
        self.logfile = None
        self.before = ""

    def expect(self, patterns):
        return 1          # index 1 == the success pattern in every expect() call

    def sendline(self, line=""):
        self.sent.append(line)

    pid = 424242
    exitstatus = None
    signalstatus = None

    def kill(self, sig):
        self.killed = True

    def isalive(self):
        return not self.killed

    def close(self, force=True):
        pass


@pytest.fixture
def spawns(monkeypatch):
    calls = []

    def spawn(cmd, **kw):
        p = FakeProc(cmd, **kw)
        calls.append(p)
        return p
    monkeypatch.setattr(A.pexpect, "spawn", spawn)
    if os.path.exists(A._STOP_FILE):
        os.remove(A._STOP_FILE)
    return calls


def _analysis(tmp_path):
    return A.Analysis("task", str(tmp_path), C.GUEST_IP, C.WORKER_GUEST_IP,
                      "/k", "/r", {"worker_ip": "192.168.60.2"})


@pytest.mark.parametrize("arch", sorted(A.ARCH_CONFIGS))
def test_qemu_command_pins_guest_mac_on_tap_nic(arch):
    cmd = A.ARCH_CONFIGS[arch].qemu_cmd_template.format(kernel="/k", rootfs="/r", mac=C.GUEST_MAC)
    assert "ifname=tap0" in cmd
    assert cmd.count(f"mac={C.GUEST_MAC}") == 1
    netdev_id = "net1" if arch == "ARM" else "net0"
    assert f"netdev={netdev_id},mac={C.GUEST_MAC}" in cmd
    assert "-netdev user" not in cmd and "-nic" not in cmd


def test_guest_url_uses_isolated_link(tmp_path):
    assert _analysis(tmp_path).worker_base_url == f"http://10.200.0.1:8011{BASE}"


def test_guest_network_configuration_commands(tmp_path, spawns):
    a = _analysis(tmp_path)
    proc = FakeProc("qemu")
    a._configure_network(proc, A.ARCH_CONFIGS["MIPS"])
    assert proc.sent[0] == "ip addr add 10.200.0.2/30 brd + dev br-lan"
    assert proc.sent[1] == "route add default gw 10.200.0.1 dev br-lan"


def test_v1_failure_prevents_any_qemu_spawn(tmp_path, spawns, monkeypatch):
    def fail(phase):
        raise IsolationError(f"network isolation check failed ({phase}): sysctl")
    monkeypatch.setattr(A, "verify_isolation", fail)
    with pytest.raises(IsolationError, match="V1 before phase 1"):
        _analysis(tmp_path).behaviour_analysis(A.ARCH_CONFIGS["ARM"])
    assert spawns == []


def test_v2_failure_prevents_phase2_spawn(tmp_path, spawns, monkeypatch):
    phases = []

    def verify(phase):
        phases.append(phase)
        if phase.startswith("V2"):
            raise IsolationError(f"network isolation check failed ({phase}): ruleset")
    monkeypatch.setattr(A, "verify_isolation", verify)
    monkeypatch.setattr(A.Analysis, "_run_analysis", lambda self, proc, arch: None)
    with pytest.raises(IsolationError, match="V2 before phase 2"):
        _analysis(tmp_path).behaviour_analysis(A.ARCH_CONFIGS["MIPS"])
    assert phases == ["V1 before phase 1", "V2 before phase 2"]
    assert len(spawns) == 1 and spawns[0].cmd.startswith("qemu-system-mips ")
    assert spawns[0].killed            # phase-1 VM was shut down before V2


def test_both_checks_pass_two_spawns(tmp_path, spawns, monkeypatch):
    monkeypatch.setattr(A, "verify_isolation", lambda phase: None)
    monkeypatch.setattr(A.Analysis, "_run_analysis", lambda self, proc, arch: None)
    monkeypatch.setattr(A.Analysis, "_exfiltrate", lambda self, proc, arch: None)
    _analysis(tmp_path).behaviour_analysis(A.ARCH_CONFIGS["ARM"])
    assert len(spawns) == 2


def test_run_locked_uses_guest_constants(tmp_path, monkeypatch):
    captured = {}

    class Z:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def extractall(self, path): captured["extracted"] = True

    monkeypatch.setattr(A, "detect_arch", lambda p: "ARM")
    monkeypatch.setattr(A, "ZipFile", Z)
    monkeypatch.setattr(A.Analysis, "behaviour_analysis",
                        lambda self, arch: captured.update(ip=self.qemu_ip, gw=self.qemu_gw))
    A._run_analysis_locked("t", str(tmp_path), {"worker_ip": "192.168.60.2"})
    assert captured == {"extracted": True, "ip": "10.200.0.2", "gw": "10.200.0.1"}


def test_port_mismatch_refuses_before_extraction(tmp_path, monkeypatch):
    monkeypatch.setattr(A.app_settings, "port", 9999)
    monkeypatch.setattr(A, "detect_arch", lambda p: "ARM")
    monkeypatch.setattr(A, "ZipFile", lambda *a: pytest.fail("must not extract"))
    with pytest.raises(RuntimeError, match="guest service port"):
        A._run_analysis_locked("t", str(tmp_path), {"worker_ip": "192.168.60.2"})


# ---------------------------------------------------------------- QEMU lifecycle with real child processes

import dataclasses
import logging
import sys
import time

FAKE_QEMU = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_qemu.py")


def _alive(pid):
    """True while the pid exists and is not a zombie."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


def _arch(tmp_path, *flags, timeout=5):
    pidfile = tmp_path / f"qemu-{time.monotonic_ns()}.pid"
    cmd = f"{sys.executable} {FAKE_QEMU} --pidfile {pidfile} " + " ".join(flags)
    return dataclasses.replace(A.ARCH_CONFIGS["MIPS"], qemu_cmd_template=cmd,
                               qemu_timeout=timeout, extra_boot_prompt_phase2=False), pidfile


@pytest.fixture
def short_grace(monkeypatch):
    """Short grace periods, and keep a strong reference to every spawned child.

    pexpect.spawn.__del__ kills its child when the object is garbage collected,
    which would hide a missing cleanup path; holding the objects here means a
    child only dies if analysis.py actually stops it.
    """
    monkeypatch.setattr(A, "QEMU_SIGINT_GRACE", 1.0)
    monkeypatch.setattr(A, "QEMU_SIGKILL_GRACE", 2.0)
    if os.path.exists(A._STOP_FILE):
        os.remove(A._STOP_FILE)
    kept = []
    real_spawn = A.pexpect.spawn

    def spawn(*args, **kw):
        kept.append(real_spawn(*args, **kw))
        return kept[-1]
    monkeypatch.setattr(A.pexpect, "spawn", spawn)
    yield kept
    for p in kept:                     # do not leak children from failing runs
        if p.isalive():
            p.kill(9)


def _pid(pidfile):
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            return int(pidfile.read_text())
        time.sleep(0.02)
    raise AssertionError("fake qemu did not write its pid")


@pytest.mark.parametrize("flags,expect_sigkill", [
    ((), False),                          # exits on SIGINT
    (("--exit-delay", "0.5"), False),     # exits 0.5 s after SIGINT, within the 1 s grace
    (("--ignore-sigint",), True),         # ignores SIGINT: needs SIGKILL
])
def test_shutdown_confirms_exit(tmp_path, short_grace, caplog, flags, expect_sigkill):
    arch, pidfile = _arch(tmp_path, *flags)
    a = _analysis(tmp_path)
    proc = a._start_qemu(arch)
    pid = _pid(pidfile)
    assert _alive(pid)
    with caplog.at_level(logging.INFO, logger=A.logger.name):
        A.shutdown_qemu(proc, "phase 1")
    assert not _alive(pid)
    msgs = [r.getMessage() for r in caplog.records]
    assert any("SIGKILL" in m for m in msgs) is expect_sigkill
    assert msgs[-1].startswith("QEMU shutdown complete (phase 1")


def test_v2_runs_only_after_phase1_qemu_exited(tmp_path, short_grace, monkeypatch):
    arch, pidfile = _arch(tmp_path, "--ignore-sigint")
    seen = []

    def verify(phase):
        if phase.startswith("V2"):
            seen.append(_alive(_pid(pidfile)))
            raise IsolationError("stop here")
    monkeypatch.setattr(A, "verify_isolation", verify)
    monkeypatch.setattr(A.Analysis, "_run_analysis", lambda self, proc, arch: None)
    with pytest.raises(IsolationError):
        _analysis(tmp_path).behaviour_analysis(arch)
    assert seen == [False]                # phase-1 QEMU already gone when V2 ran


class Unkillable(FakeProc):
    def isalive(self):
        return True


def test_unconfirmed_exit_blocks_v2_and_phase2(tmp_path, short_grace, monkeypatch, caplog):
    monkeypatch.setattr(A, "QEMU_SIGINT_GRACE", 0.1)
    monkeypatch.setattr(A, "QEMU_SIGKILL_GRACE", 0.1)
    spawned, phases = [], []
    monkeypatch.setattr(A.pexpect, "spawn", lambda cmd, **kw: spawned.append(Unkillable(cmd)) or spawned[-1])
    monkeypatch.setattr(A, "verify_isolation", lambda phase: phases.append(phase))
    monkeypatch.setattr(A.Analysis, "_run_analysis", lambda self, proc, arch: None)
    with caplog.at_level(logging.INFO, logger=A.logger.name):
        with pytest.raises(A.QemuShutdownError, match="did not exit after SIGKILL"):
            _analysis(tmp_path).behaviour_analysis(A.ARCH_CONFIGS["ARM"])
    assert phases == ["V1 before phase 1"] and len(spawned) == 1
    assert not any("shutdown complete" in r.getMessage() for r in caplog.records)


def test_boot_timeout_does_not_leave_qemu(tmp_path, short_grace):
    arch, pidfile = _arch(tmp_path, "--no-boot-prompt", "--ignore-sigint", timeout=1)
    with pytest.raises(RuntimeError, match="timed out waiting for boot prompt"):
        _analysis(tmp_path)._start_qemu(arch)
    assert not _alive(_pid(pidfile))


@pytest.mark.parametrize("failing", ["_configure_network", "_run_analysis"])
def test_phase1_error_does_not_leave_qemu(tmp_path, short_grace, monkeypatch, failing):
    arch, pidfile = _arch(tmp_path, "--ignore-sigint")
    phases = []
    monkeypatch.setattr(A, "verify_isolation", lambda phase: phases.append(phase))

    def boom(self, proc, arch):
        raise RuntimeError(f"{failing} failed")
    monkeypatch.setattr(A.Analysis, failing, boom)
    if failing == "_run_analysis":
        monkeypatch.setattr(A.Analysis, "_configure_network", lambda self, proc, arch: None)
    with pytest.raises(RuntimeError, match=f"{failing} failed"):
        _analysis(tmp_path).behaviour_analysis(arch)
    assert not _alive(_pid(pidfile))
    assert phases == ["V1 before phase 1"]


def test_cancel_during_analysis_does_not_leave_qemu(tmp_path, short_grace, monkeypatch):
    arch, pidfile = _arch(tmp_path, "--ignore-sigint")
    monkeypatch.setattr(A, "verify_isolation", lambda phase: None)
    monkeypatch.setattr(A.Analysis, "_configure_network", lambda self, proc, arch: None)

    def cancel(self, proc, arch):
        proc.kill(A.signal.SIGINT)        # what _run_analysis does on a stop request
        raise A.AnalysisCancelled("Stop requested by user")
    monkeypatch.setattr(A.Analysis, "_run_analysis", cancel)
    with pytest.raises(A.AnalysisCancelled):
        _analysis(tmp_path).behaviour_analysis(arch)
    assert not _alive(_pid(pidfile))


def test_phase2_error_does_not_leave_qemu(tmp_path, short_grace, monkeypatch):
    arch, pidfile = _arch(tmp_path, "--ignore-sigint")
    monkeypatch.setattr(A, "verify_isolation", lambda phase: None)
    monkeypatch.setattr(A.Analysis, "_run_analysis", lambda self, proc, arch: None)

    def boom(self, proc, arch):
        raise RuntimeError("exfiltrate failed")
    monkeypatch.setattr(A.Analysis, "_exfiltrate", boom)
    with pytest.raises(RuntimeError, match="exfiltrate failed"):
        _analysis(tmp_path).behaviour_analysis(arch)
    assert not _alive(_pid(pidfile))
