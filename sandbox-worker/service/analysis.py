import fcntl
import hashlib
import logging
import os
import signal
import subprocess
import time
import pexpect
from dataclasses import dataclass
from zipfile import ZipFile

from config.settings import app_settings
from isolation import constants as guestnet
from isolation.verify import verify_isolation
from service import execution_class as xc

logger = logging.getLogger(__name__)

# QEMU shutdown (CT-01): phase 2 and V2 only run once the phase-1 QEMU process
# is confirmed to have exited. Module-level so tests can shorten them.
QEMU_SIGINT_GRACE = 10.0
QEMU_SIGKILL_GRACE = 5.0
CAPTURE_SIGINT_GRACE = 5.0
CAPTURE_SIGKILL_GRACE = 3.0
TRACE_START_PROBE_DELAY = 0.5   # CT-04: seconds between starting the trace and the start probe


class UnsafeWorkerState(RuntimeError):
    """A child process (QEMU, capture) could not be confirmed to have exited and been reaped/closed: the worker must not take another task
    (the poller exits with status 3; whether the container then restarts depends on the restart policy in force).
    `errors` lists EVERY top-level fault that led here (analysis error first, then each unsafe finalizer error, this one included);
    `details` holds the low-level signal/liveness faults the finalizer recorded while trying."""

    def __init__(self, message="", errors=(), details=()):
        super().__init__(message)
        self.errors = list(errors) or [self]
        self.details = list(details)


class QemuShutdownError(UnsafeWorkerState):
    """The QEMU process could not be confirmed to have exited (or its pty could not be closed)."""


class CaptureShutdownError(UnsafeWorkerState):
    """The network capture (tshark) could not be confirmed to have exited and been reaped/closed."""


class ShutdownFaults(UnsafeWorkerState):
    """Several unsafe cleanup faults (e.g. capture AND QEMU) in one task: nothing is hidden behind the last one."""


def with_primary(primary, unsafe):
    """The exception to raise when a finalizer failed (`unsafe`, an UnsafeWorkerState) while `primary` (any exception or None) was already propagating.
    The result is always an UnsafeWorkerState that lists every fault; the primary is its __cause__ (never lost, never replaces the unsafe classification)."""
    if primary is None:
        return unsafe
    faults, seen = [], set()
    for e in (primary, unsafe):
        for f in (getattr(e, "errors", None) or [e]):
            key = (type(f).__name__, str(f))
            if key not in seen:                                       # the same fault reported by two finalizer passes is listed once
                seen.add(key)
                faults.append(f)
    text = "; ".join(f"{type(e).__name__}: {e}" for e in faults)
    details = [d for e in (primary, unsafe) for d in getattr(e, "details", [])]
    if isinstance(primary, UnsafeWorkerState):
        out = ShutdownFaults(text, faults, details)
    else:
        out = type(unsafe)(text, faults, details)
    out.__cause__ = primary
    return out


def finalize_child(proc, label, what, error_cls, sigint_grace, sigkill_grace):
    """The ONLY owner of a child's end of life (idempotent): wait 0 -> SIGINT -> bounded monotonic wait -> SIGKILL -> bounded wait, then reap (isalive) and
    close. Any signal / liveness error is recorded and never ends the escalation. An exit that cannot be confirmed (or a close error) raises `error_cls`
    carrying every recorded fault; when exit AND close ARE confirmed (e.g. SIGINT denied, SIGKILL delivered) the call returns normally and the recorded faults are
    only logged (bounded) — a signal error alone is not "unsafe". ProcessLookupError (already gone) is not a fault: the next liveness check decides."""
    errors = []                                                       # low-level faults (text), de-duplicated with a count

    def note(text):
        errors.append(text)

    def alive():
        try:
            return proc.isalive()
        except Exception as e:                                        # noqa: BLE001
            t = f"isalive: {e!r}"
            if t not in errors:                                       # a persistently failing check is listed once
                note(t)
            return True                                               # cannot confirm => treat as alive

    def send(sig):
        try:
            proc.kill(sig)
        except ProcessLookupError:
            pass
        except Exception as e:                                        # noqa: BLE001
            note(f"signal {int(sig)}: {e!r}")

    def waited(grace):
        deadline = time.monotonic() + grace
        while alive():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    pid = getattr(proc, "pid", "?")
    if not waited(0):
        send(signal.SIGINT)
        if not waited(sigint_grace):
            logger.warning(f"{what} pid {pid} still running {sigint_grace}s after SIGINT ({label}); sending SIGKILL")
            send(signal.SIGKILL)
            if not waited(sigkill_grace):
                raise error_cls(f"{what} pid {pid} did not exit after SIGKILL ({label}): exit not confirmed; faults: {errors}", details=errors)
    try:
        proc.close()
    except Exception as e:                                            # noqa: BLE001
        raise error_cls(f"{what} pid {pid} exited but close failed ({label}): {e!r}", details=errors + [repr(e)]) from e
    if errors:
        # exit/reap/close were CONFIRMED, so the worker is safe; the transient signal/liveness faults seen on the way are kept as a bounded diagnostic
        logger.warning(f"{what} pid {pid} ({label}) ended and was reaped/closed after {len(errors)} recoverable fault(s): {errors[:5]}")


def stop_capture(proc, label: str) -> None:
    """Idempotent end of the tshark child. Raises CaptureShutdownError when exit/close cannot be confirmed (never silent)."""
    if proc is None:
        return
    finalize_child(proc, label, "capture", CaptureShutdownError, CAPTURE_SIGINT_GRACE, CAPTURE_SIGKILL_GRACE)


RAW_CONSOLE_FILE = "/console.raw"          # in the task dir; appended by every QEMU phase: the bytes os.read() returned, BEFORE any decoding or newline handling
RAW_CONSOLE_MAX = 4 * 1024 * 1024


class RawConsoleLog:
    """Byte sink for the received console stream (evidence only). It is fed by RawTeeDecoder with exactly what pexpect read from the pty, before the
    UTF-8 decoder runs: CR/LF, invalid UTF-8 and multi-byte characters split between reads are kept as they came. It never raises into the analysis
    (a write error disables the sink and is logged once), it is capped, and it keeps a running sha256 of what it wrote."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "ab")
        self.start_offset = self.f.tell()
        self.written = 0
        self.dropped = 0
        self.failed = False
        self.closed = False
        self.sha = hashlib.sha256()

    def write_bytes(self, b):
        if self.failed or self.closed:
            return
        try:
            b = bytes(b)
            room = max(RAW_CONSOLE_MAX - self.start_offset - self.written, 0)
            if len(b) > room:
                self.dropped += len(b) - room
                b = b[:room]
            if b:
                self.f.write(b)
                self.f.flush()
                self.written += len(b)
                self.sha.update(b)
        except Exception:                                             # noqa: BLE001
            self.failed = True
            logger.exception("raw console log write failed (evidence only; analysis continues)")

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.f.close()
        except Exception:                                             # noqa: BLE001
            logger.exception("closing the raw console log failed")
        logger.info(f"raw console log {self.path}: phase started at offset {self.start_offset}, {self.written} bytes, {self.dropped} dropped"
                    f"{', WRITE FAILED' if self.failed else ''}, phase sha256 {self.sha.hexdigest()}")


class RawTeeDecoder:
    """Stands in for pexpect's incremental decoder (`proc._decoder`): records the input bytes, then delegates unchanged. The delegate's result AND its
    exceptions (e.g. UnicodeDecodeError on invalid UTF-8) are returned/raised exactly as before; recording happens first, so the bytes that triggered the
    error are in the evidence."""

    def __init__(self, inner, sink):
        self._inner = inner
        self._sink = sink

    def decode(self, data, final=False):
        try:
            if data:
                self._sink.write_bytes(data)
        except Exception:                                             # noqa: BLE001
            pass
        return self._inner.decode(data, final)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def attach_raw_console(proc, path):
    """Install the raw byte tap on a spawned pexpect child. Returns the sink, or None when it cannot be installed (evidence only: logged, never raised).
    Depends on pexpect's private `_decoder` (pinned pexpect 4.9.0 in the image); the guard below refuses anything that is not a text-mode child
    with a decode() method."""
    try:
        dec = getattr(proc, "_decoder", None)
        if getattr(proc, "encoding", None) is None or dec is None or not callable(getattr(dec, "decode", None)):
            logger.warning("raw console log not installed: this pexpect child has no incremental decoder to tap")
            return None
        sink = RawConsoleLog(path)
        proc._decoder = RawTeeDecoder(dec, sink)
        proc.ct04_raw_console = sink
        return sink
    except Exception:                                                 # noqa: BLE001
        logger.exception("raw console log not installed (evidence only; analysis continues)")
        return None


def shutdown_qemu(proc, phase: str) -> None:
    """Stop a QEMU child and confirm it exited and was reaped/closed (same finalizer as the capture). Raises QemuShutdownError otherwise, so
    phase 2 / V2 / the next task never run on an unconfirmed QEMU. A failing log-file close is logged only (it says nothing about the process)."""
    logger.info(f"Shutting down QEMU ({phase}, pid {proc.pid})...")
    finalize_child(proc, phase, "QEMU", QemuShutdownError, QEMU_SIGINT_GRACE, QEMU_SIGKILL_GRACE)
    if getattr(proc, "logfile", None) is not None:
        try:
            proc.logfile.close()
        except Exception:                                             # noqa: BLE001
            logger.exception("closing QEMU log failed")
    if getattr(proc, "ct04_raw_console", None) is not None:
        try:
            proc.ct04_raw_console.close()
        except Exception:                                             # noqa: BLE001
            logger.exception("closing the raw console log failed")
    logger.info(f"QEMU shutdown complete ({phase}, pid {proc.pid}, "
                f"exitstatus={getattr(proc, 'exitstatus', None)}, signalstatus={getattr(proc, 'signalstatus', None)})")


def shutdown_qemu_after(proc, phase: str, primary) -> None:
    """Finalizer used inside `finally`/`except`: shutdown_qemu, but an unsafe result keeps `primary` as its cause and in `errors`."""
    try:
        shutdown_qemu(proc, phase)
    except UnsafeWorkerState as q:
        if primary is None:
            raise
        raise with_primary(primary, q) from primary


@dataclass
class ArchConfig:
    qemu_cmd_template: str
    net_iface: str
    boot_ready_prompt: str
    qemu_timeout: int
    image_zip_path: str
    image_kernel_path: str
    image_rootfs_path: str
    cd_before_analysis: bool = True
    # MIPS/MIPSEL need an extra terminal poke after DNS setup in both phases
    extra_prompt_after_dns: bool = False
    # MIPS/MIPSEL need an extra terminal poke in the phase 2 boot before the network-ready prompt
    extra_boot_prompt_phase2: bool = False
    # Set True when the network-ready prompt may not appear (e.g. x86) — timeout is tolerated
    network_ready_prompt_optional: bool = False
    # Seconds to wait after network is up in phase 2 before exfiltrating.
    # Allows time for the filesystem from phase 1 to be fully accessible after reboot.
    exfiltrate_wait: int = 0


ARCH_CONFIGS = {
    "ARM": ArchConfig(
        qemu_cmd_template=(
            'qemu-system-arm -M virt-2.9 -kernel {kernel} -no-reboot -nographic'
            ' -device virtio-net-pci -netdev tap,id=net1,ifname=tap0,script=no,downscript=no'
            ' -device virtio-net-pci,netdev=net1,mac={mac} -drive file={rootfs},if=virtio,format=raw'
            ' -append "root=/dev/vda"'
        ),
        net_iface="eth1",
        boot_ready_prompt="br-lan: link becomes ready",
        qemu_timeout=100,
        image_zip_path="./ARM/image.zip",
        image_kernel_path="/image/zImage",
        image_rootfs_path="/image/root.ext4",
        cd_before_analysis=False,
        extra_prompt_after_dns=False,
        extra_boot_prompt_phase2=False,
        exfiltrate_wait=0,
    ),
    "MIPS": ArchConfig(
        qemu_cmd_template=(
            'qemu-system-mips -M malta -kernel {kernel} -hda {rootfs}'
            ' -append "root=/dev/sda" -nographic -no-reboot'
            ' -device pcnet,netdev=net0,mac={mac} -netdev tap,id=net0,ifname=tap0,script=no,downscript=no'
        ),
        net_iface="br-lan",
        boot_ready_prompt="entered forwarding state",
        qemu_timeout=30,
        image_zip_path="./MIPS/image.zip",
        image_kernel_path="/image/vmlinux",
        image_rootfs_path="/image/root.ext4",
        cd_before_analysis=True,
        extra_prompt_after_dns=True,
        extra_boot_prompt_phase2=True,
        exfiltrate_wait=10,
    ),
    "MIPSEL": ArchConfig(
        qemu_cmd_template=(
            'qemu-system-mipsel -m 512 -kernel {kernel} -hda {rootfs}'
            ' -append "root=/dev/sda" -nographic -no-reboot'
            ' -device pcnet,netdev=net0,mac={mac} -netdev tap,id=net0,ifname=tap0,script=no,downscript=no'
        ),
        net_iface="br-lan",
        boot_ready_prompt="entered forwarding state",
        qemu_timeout=30,
        image_zip_path="./MIPSEL/image.zip",
        image_kernel_path="/image/vmlinux",
        image_rootfs_path="/image/root.ext4",
        cd_before_analysis=True,
        extra_prompt_after_dns=True,
        extra_boot_prompt_phase2=True,
        exfiltrate_wait=10,
    ),
    "x86": ArchConfig(
        qemu_cmd_template=(
            'qemu-system-i386 -m 512 -kernel {kernel} -hda {rootfs}'
            ' -append "root=/dev/sda" -nographic -no-reboot'
            ' -device pcnet,netdev=net0,mac={mac} -netdev tap,id=net0,ifname=tap0,script=no,downscript=no'
        ),
        net_iface="br-lan",
        boot_ready_prompt="entered forwarding state",
        qemu_timeout=20,
        image_zip_path="./x86/image.zip",
        image_kernel_path="/image/vmlinux",
        image_rootfs_path="/image/root.ext4",
        cd_before_analysis=True,
        extra_prompt_after_dns=False,
        extra_boot_prompt_phase2=False,
        exfiltrate_wait=10,
        network_ready_prompt_optional=True,
    ),
}


def detect_arch(binary_path: str) -> str:
    """Detect the CPU architecture of an ELF binary using the file command.
    Reads ELF magic bytes, so works on stripped and statically linked binaries."""
    result = subprocess.run(['file', binary_path], capture_output=True, text=True)
    output = result.stdout
    logger.info(f"Binary type: {output.strip()}")

    # MIPS must be checked before ARM since MIPS output never contains "ARM"
    # Endianness distinguishes MIPS (MSB, big-endian) from MIPSEL (LSB, little-endian)
    if 'MIPS' in output and 'MSB' in output:
        return 'MIPS'
    if 'MIPS' in output and 'LSB' in output:
        return 'MIPSEL'
    if 'ARM' in output:
        return 'ARM'
    if '80386' in output:
        return 'x86'

    raise ValueError(f"Unsupported or unrecognized architecture: {output.strip()}")


class Analysis:
    def __init__(self, task_id, task_dir, qemu_ip, qemu_gw, kernel_path, rootfs_path, worker):
        self.task_id = task_id
        self.task_dir = task_dir
        self.qemu_ip = qemu_ip
        self.qemu_gw = qemu_gw
        self.kernel_path = kernel_path
        self.rootfs_path = rootfs_path
        self.worker = worker
        # URL used by the guest: the worker's address on the isolated guest link,
        # not its sandboxnet address (CT-01).
        self.worker_base_url = (
            f"http://{guestnet.WORKER_GUEST_IP}:{guestnet.SVC_PORT}{app_settings.app_base_url}"
        )

    def _start_qemu(self, arch: ArchConfig) -> pexpect.spawn:
        qemu_cmd = arch.qemu_cmd_template.format(kernel=self.kernel_path, rootfs=self.rootfs_path,
                                                 mac=guestnet.GUEST_MAC)
        logger.info("Starting QEMU...")
        proc = pexpect.spawn(qemu_cmd, encoding='utf-8', timeout=arch.qemu_timeout)
        try:
            proc.logfile = open(self.task_dir + app_settings.qemu_log_path, 'w', encoding='utf-8')
            attach_raw_console(proc, self.task_dir + RAW_CONSOLE_FILE)
            idx = proc.expect([pexpect.TIMEOUT, 'Please press Enter to activate this console.', pexpect.EOF])
            if idx == 0:
                raise RuntimeError("QEMU timed out waiting for boot prompt")
            proc.sendline("")
            idx = proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
            if idx == 0:
                raise RuntimeError("QEMU timed out waiting for shell prompt after boot")
        except BaseException as e:
            # Never leave a spawned QEMU behind when boot fails.
            shutdown_qemu_after(proc, "boot failure", e)
            raise
        logger.info("Started QEMU")
        return proc

    def _start_qemu_phase2(self, arch: ArchConfig) -> pexpect.spawn:
        """Boot QEMU for the exfiltration phase.
        MIPS/MIPSEL require an extra terminal poke after the initial prompt
        before the network-ready prompt appears."""
        proc = self._start_qemu(arch)
        if arch.extra_boot_prompt_phase2:
            try:
                proc.sendline("")
                proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
            except BaseException as e:
                shutdown_qemu_after(proc, "phase 2 boot failure", e)
                raise
        return proc

    def _configure_network(self, proc: pexpect.spawn, arch: ArchConfig):
        idx = proc.expect([pexpect.TIMEOUT, arch.boot_ready_prompt, pexpect.EOF])
        if idx == 0 and not arch.network_ready_prompt_optional:
            raise RuntimeError("QEMU timed out waiting for network-ready prompt")
        proc.sendline(f'ip addr add {self.qemu_ip}/{guestnet.GUEST_PREFIX} brd + dev {arch.net_iface}')
        idx = proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        if idx == 0:
            raise RuntimeError("QEMU timed out after IP assignment")
        proc.sendline(f'route add default gw {self.qemu_gw} dev {arch.net_iface}')
        idx = proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        if idx == 0:
            raise RuntimeError("QEMU timed out after gateway setup")
        logger.info("Set IP in QEMU")
        proc.sendline('echo "nameserver 8.8.8.8" > /etc/resolv.conf')
        proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        logger.info("Set DNS in QEMU")
        # MIPS/MIPSEL need an extra poke after DNS before the terminal is stable
        if arch.extra_prompt_after_dns:
            proc.sendline("")
            proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])

    def _run_analysis(self, proc: pexpect.spawn, arch: ArchConfig):
        if arch.cd_before_analysis:
            proc.sendline("cd /")
            proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])

        # Keep a backup of curl in case the malware overwrites or kills it
        proc.sendline("cp /usr/bin/curl /tmp/c")
        proc.sendline("ifconfig")
        proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])

        # Download the malware executable into the VM
        proc.sendline(
            f"/tmp/c --location '{self.worker_base_url}/get-task/{self.task_id}/file' -o exec"
        )
        idx = proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        if idx == 0:
            raise RuntimeError("QEMU timed out waiting for binary download")
        logger.debug(proc.before)
        proc.sendline("chmod +x ./exec")
        idx = proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        if idx == 0:
            raise RuntimeError("QEMU timed out after chmod")
        logger.debug(proc.before)
        logger.info("Got the executable inside QEMU")

        # Start network capture on the host
        net_proc = pexpect.spawn(
            f"tshark -i tap0 -w {self.task_dir}/network.pcap", encoding='utf-8', timeout=100
        )
        logger.info("Started network capture")
        primary = None
        rec = xc.TraceRecorder(self.task_id, app_settings.analysis_duration)
        stop_reason = "error"
        try:

            # Start system resource monitor inside the VM
            self._send(proc, "sar -o sar.out 1 >/dev/null 2>&1 & echo $! > sar_pid", "the sar start")
            self._expect_prompt(proc, 'root@OpenWrt:/# ', "the prompt after the sar start")
            logger.info(f"Started sar (PID: {proc.before.strip()})")

            # Start syscall trace and execute the malware
            self._send(proc, "strace -f -tt -T -y -yy -s 2048 -o /strace.log ./exec & echo $! > strace_pid", "the strace start")
            self._expect_prompt(proc, 'root@OpenWrt:/# ', "the prompt after the strace start")
            logger.info(f"Started strace (PID: {proc.before.strip()})")
            rec.started()
            time.sleep(TRACE_START_PROBE_DELAY)
            self._probe(proc, rec, "start")

            # Let the malware run for the configured duration, checking for stop requests
            deadline = time.time() + app_settings.analysis_duration
            while time.time() < deadline:
                time.sleep(1)
                if os.path.exists(_STOP_FILE):
                    proc.kill(signal.SIGINT)
                    raise AnalysisCancelled("Stop requested by user")

            self._send(proc, "", "the first prompt refresh")
            self._send(proc, "", "the second prompt refresh")
            self._expect_prompt(proc, '# ', "the prompt after the window")
            self._send(proc, "ls", "ls")
            self._expect_prompt(proc, '# ', "the prompt after ls")
            logger.debug(proc.before)

            stop_capture(net_proc, "after the analysis window")
            logger.info("Stopped network capture")

            self._probe(proc, rec, "final")
            rec.stopping()
            self._send(proc, "kill -9 $(cat strace_pid)", "the strace kill")
            self._expect_prompt(proc, 'root@OpenWrt:/# ', "the prompt after the strace kill")
            logger.debug(proc.before)
            self._confirm_trace_stopped(proc, rec)
            logger.info("Killed strace (stop confirmed)")
            stop_reason = "window_elapsed"         # only now: the trace-stop path is confirmed

            self._send(proc, "kill -9 $(cat sar_pid)", "the sar kill")
            self._expect_prompt(proc, 'root@OpenWrt:/# ', "the prompt after the sar kill")
            logger.debug(proc.before)
            logger.info("Killed sar")

            # Wait for the VM filesystem to flush captured files before shutdown
            time.sleep(app_settings.post_analysis_wait)
        except AnalysisCancelled as e:
            primary = e
            stop_reason = "cancelled"
            raise
        except BaseException as e:                                    # noqa: BLE001
            primary = e
            raise
        finally:
            # the metadata is evidence about THIS trace: written on every exit path, never allowed to change the outcome of the analysis
            err = xc.write_meta(self.task_dir, rec.meta(stop_reason))
            if err:
                logger.warning(f"trace metadata not written: {err}")
            try:
                stop_capture(net_proc, "finalizer")
            except UnsafeWorkerState as ce:
                if primary is not None:
                    # keep BOTH: the analysis error and the cleanup failure
                    raise with_primary(primary, ce) from primary
                raise

    def _send(self, proc, line, what):
        """Send one console line. A pty-level error (OSError) propagates UNCHANGED: it is the original error and the reviewed host cleanup handles it."""
        proc.sendline(line)

    def _expect_prompt(self, proc, prompt, what, timeout=None):
        """Wait for `prompt`. TIMEOUT and EOF are NOT 'continue': the console is no longer synchronised with the commands, so nothing more is sent on it.
        Errors raised by pexpect itself propagate unchanged."""
        kw = {} if timeout is None else {"timeout": timeout}
        idx = proc.expect([pexpect.TIMEOUT, prompt, pexpect.EOF], **kw)
        if idx != 1:
            raise ConsoleLost(f"guest console lost while waiting for {what}: {'timeout' if idx == 0 else 'EOF'}")

    def _probe(self, proc, rec, which):
        """One state probe of the traced sample through the guest console.
        Two different outcomes are kept apart:
          * the console answered (end marker and prompt arrived) but no sample could be identified -> a probe error is recorded and the analysis goes on;
          * the console did not answer in sync (timeout, EOF, missing end marker or prompt) -> ConsoleLost, nothing more is sent, the cleanup path runs."""
        self._send(proc, rec.probe_command(), f"the {which} probe")
        idx = proc.expect([pexpect.TIMEOUT, xc.probe_end_pattern(rec.trace_id), pexpect.EOF], timeout=xc.PROBE_WAIT_S)
        if idx != 1:
            raise ConsoleLost(f"guest console lost during the {which} probe: {'timeout' if idx == 0 else 'EOF'} before the end marker")
        rec.add_probe(which, (proc.before or "") + (proc.after if isinstance(proc.after, str) else ""))      # never raises
        self._expect_prompt(proc, '# ', f"the prompt after the {which} probe", timeout=2)

    def _confirm_trace_stopped(self, proc, rec):
        """After `kill -9 strace`: ask the guest, with the exit status of every read, whether the strace process is gone (see xc.stop_check_command).
        The whole answer (raw text, rc of each read, target pid, verdict) is stored in the metadata. The trace counts as stopped only when the verdict is `gone`
        (positive evidence of absence) or `zombie` (the same pid AND start time as the strace baseline, state Z). Silence, read errors, tool errors, a wrong/missing pid
        file, a truncated answer and a live process all leave the stop UNCONFIRMED: stop_reason must not become window_elapsed."""
        self._send(proc, xc.stop_check_command(rec.trace_id), "the trace-stop check")
        idx = proc.expect([pexpect.TIMEOUT, xc.stop_check_end_pattern(rec.trace_id), pexpect.EOF], timeout=xc.PROBE_WAIT_S)
        if idx != 1:
            rec.stop_check = xc.judge_stop_check("", rec.trace_id, rec.strace_pid, rec.strace_starttime, rec.clock())
            rec.stop_check["reason"] = "no answer: " + ("timeout" if idx == 0 else "EOF")
            raise ConsoleLost(f"guest console lost during the trace-stop check: {'timeout' if idx == 0 else 'EOF'}")
        text = (proc.before or "") + (proc.after if isinstance(proc.after, str) else "")
        rec.stop_check = xc.judge_stop_check(text, rec.trace_id, rec.strace_pid, rec.strace_starttime, rec.clock())
        self._expect_prompt(proc, '# ', "the prompt after the trace-stop check", timeout=2)
        if rec.stop_check["verdict"] not in xc.STOPPED_VERDICTS:
            raise TraceStopNotConfirmed(f"trace stop not confirmed: {rec.stop_check['verdict']} ({rec.stop_check['reason']})")

    def _exfiltrate(self, proc: pexpect.spawn, arch: ArchConfig):
        # Wait for the rebooted filesystem to fully settle before reading captured files
        if arch.exfiltrate_wait > 0:
            time.sleep(arch.exfiltrate_wait)
            proc.sendline("cd /")
            proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
            proc.sendline("ls")
            proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
            logger.debug(proc.before)

        logger.info("Uploading strace...")
        proc.sendline(
            f"curl --location '{self.worker_base_url}/update-task/{self.task_id}/strace'"
            f" --form 'file=@/strace.log'"
        )
        proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        logger.debug(proc.before)

        logger.info("Uploading sar...")
        proc.sendline(
            f"curl --location '{self.worker_base_url}/update-task/{self.task_id}/sar'"
            f" --form 'file=@/sar.out'"
        )
        proc.expect([pexpect.TIMEOUT, '# ', pexpect.EOF])
        logger.debug(proc.before)

    def behaviour_analysis(self, arch: ArchConfig):
        # Phase 1: Boot VM, execute malware, capture strace/sar/network data
        _check_stop()
        verify_isolation("V1 before phase 1")
        proc = self._start_qemu(arch)
        primary = None
        try:
            self._configure_network(proc, arch)
            self._run_analysis(proc, arch)
        except BaseException as e:                                    # noqa: BLE001
            primary = e
            raise
        finally:
            # Raises an UnsafeWorkerState (QEMU, or capture + QEMU) if exit cannot be confirmed: V2/phase 2 never run then, and the
            # analysis/capture error stays attached (a generic cleanup error can no longer replace the unsafe classification).
            shutdown_qemu_after(proc, "phase 1", primary)

        # Phase 2: Reboot VM to exfiltrate captured log files.
        # Files are read from the same virtual disk written in phase 1.
        _check_stop()
        verify_isolation("V2 before phase 2")
        proc = self._start_qemu_phase2(arch)
        primary = None
        try:
            self._configure_network(proc, arch)
            self._exfiltrate(proc, arch)
        except BaseException as e:                                    # noqa: BLE001
            primary = e
            raise
        finally:
            shutdown_qemu_after(proc, "phase 2", primary)


_LOCK_FILE = "/tmp/sandbox_worker.lock"
_STOP_FILE = "/tmp/sandbox_stop_requested"


class ConsoleLost(RuntimeError):
    """The guest console is not usable any more (timeout, EOF, a prompt or marker that never arrived). No further command is sent on it; the host cleanup runs."""


class TraceStopNotConfirmed(RuntimeError):
    """`kill -9 strace` was sent but the strace process was not observed gone; the trace metadata must not claim window_elapsed."""


class AnalysisCancelled(RuntimeError):
    """Raised when a stop is requested via the /stop endpoint."""
    pass


def request_stop():
    """Create the stop-signal file. Called by the server process."""
    open(_STOP_FILE, 'w').close()


def clear_stop():
    """Remove the stop-signal file. Called by the poller before each task."""
    try:
        os.remove(_STOP_FILE)
    except FileNotFoundError:
        pass


def _check_stop():
    if os.path.exists(_STOP_FILE):
        raise AnalysisCancelled("Stop requested by user")


def dynamic_analysis(task_id, task_dir="", worker={}):
    with open(_LOCK_FILE, 'w') as _lock:
        try:
            fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another analysis is already running on this worker")
        _run_analysis_locked(task_id, task_dir, worker)


def _run_analysis_locked(task_id, task_dir="", worker={}):
    logger.info(f"Starting task: {task_id}")

    binary_path = task_dir + "/" + task_id
    arch_name = detect_arch(binary_path)
    logger.info(f"Detected architecture: {arch_name}")

    arch_config = ARCH_CONFIGS[arch_name]

    if app_settings.port != guestnet.SVC_PORT:
        raise RuntimeError(f"worker PORT {app_settings.port} != guest service port {guestnet.SVC_PORT}")
    qemu_ip = guestnet.GUEST_IP
    qemu_gw = guestnet.WORKER_GUEST_IP

    with ZipFile(arch_config.image_zip_path, 'r') as z:
        z.extractall(path=task_dir)

    kernel_path = task_dir + arch_config.image_kernel_path
    rootfs_path = task_dir + arch_config.image_rootfs_path

    analysis = Analysis(task_id, task_dir, qemu_ip, qemu_gw, kernel_path, rootfs_path, worker)
    analysis.behaviour_analysis(arch_config)
