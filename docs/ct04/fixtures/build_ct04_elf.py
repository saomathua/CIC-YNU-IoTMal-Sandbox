#!/usr/bin/env python3
"""CT-04 benign fixture generator (R2, OFFLINE: nothing here is built into an image or executed on a kernel).
Static, tiny, harmless ELF files for the lane that will exercise execution classification later. Same container layout, e_flags and honesty limits as the
CT-02 marker generator (no toolchain/qemu-user/readelf on the lab host: machine code is assembled from a listing; a mini-emulator written for exactly these
instructions checks encodings; verify_elf.py checks the container independently).

  exit0   : exit(0)                         -> expected class EXITED_0
  exit7   : exit(7)                         -> expected class EXITED_NONZERO
  sleep   : nanosleep(3600 s) then exit(0)  -> runs to the end of the analysis window -> SAMPLE_TIMEOUT only with trace metadata + probe
  noisy   : loop { write(1, "CT04-NOISE!\\n", 12); nanosleep(10 ms) }  -> writes to the console ~100 lines/s until stopped (console-sync measurement, lane A6)
  fork    : fork(); both processes nanosleep(3600 s) then exit(0)       -> parent + one child alive for the whole window (ppid/selection measurement, lane A7)
  a64stub : ELF64 AArch64 header-only stub  -> `file` says "ARM aarch64", detect_arch() accepts it as 'ARM' (substring match), a 32-bit ARM guest kernel is
            expected to refuse it at execve => EXEC_FORMAT_ERROR. EXPECTATION ONLY: never executed; the real errno is to be observed, not assumed.
NOT prepared (needs a dynamic loader + DT_NEEDED in the guest and cannot be validated offline): MISSING_LIBRARY; and a log-capture-failure fixture is a
worker-side fault injection, not a sample.
usage: build_ct04_elf.py <out_dir>   (deterministic; rebuilding gives identical bytes)"""
import hashlib
import json
import pathlib
import struct
import sys

BASE = 0x10000
ARM_FLAGS, MIPS_FLAGS = 0x05000000, 0x70001001


def elf32(le, machine, flags, words, data):
    e = "<" if le else ">"
    code = b"".join(struct.pack(e + "I", w) for w in words)
    total = 84 + len(code) + len(data)
    ident = b"\x7fELF" + bytes([1, 1 if le else 2, 1, 0, 0]) + b"\0" * 7
    eh = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, BASE + 84, 52, 0, flags, 52, 32, 1, 40, 0, 0)
    ph = struct.pack(e + "IIIIIIII", 1, 0, BASE, BASE, total, total, 5, 0x1000)
    return eh + ph + code + data


def arm(kind, n=0):
    if kind == "exit":
        words = [0xE3A00000 | n, 0xE3A07001, 0xEF000000]
        return elf32(True, 40, ARM_FLAGS, words, b"")
    # sleep: ldr r0,[pc,#20]; mov r1,#0; mov r7,#162; svc; mov r0,#0; mov r7,#1; svc; .word &ts ; ts = {3600, 0}
    ts_addr = BASE + 84 + 8 * 4
    words = [0xE59F0014, 0xE3A01000, 0xE3A070A2, 0xEF000000, 0xE3A00000, 0xE3A07001, 0xEF000000, ts_addr]
    return elf32(True, 40, ARM_FLAGS, words, struct.pack("<II", 3600, 0))


def arm_noisy():
    # 0 ldr r1,[pc,#msg] ; 1 mov r0,#1 ; 2 mov r2,#12 ; 3 mov r7,#4 ; 4 svc ; 5 ldr r0,[pc,#ts] ; 6 mov r1,#0 ; 7 mov r7,#162 ; 8 svc ; 9 b 0 ; 10 .word msg ; 11 .word ts
    msg = BASE + 84 + 12 * 4
    ts = msg + 12
    ldr = lambda rd, idx, pool: 0xE59F0000 | (rd << 12) | ((10 + pool) * 4 - (idx * 4 + 8))          # noqa: E731
    words = [ldr(1, 0, 0), 0xE3A00001, 0xE3A0200C, 0xE3A07004, 0xEF000000, ldr(0, 5, 1), 0xE3A01000, 0xE3A070A2, 0xEF000000,
             0xEA000000 | ((0 - (9 + 2)) & 0xFFFFFF), msg, ts]
    return elf32(True, 40, ARM_FLAGS, words, b"CT04-NOISE!\n" + struct.pack("<II", 0, 10_000_000))


def arm_fork():
    # 0 mov r7,#2 ; 1 svc ; 2 ldr r0,[pc,#ts] ; 3 mov r1,#0 ; 4 mov r7,#162 ; 5 svc ; 6 mov r0,#0 ; 7 mov r7,#1 ; 8 svc ; 9 .word ts
    ts = BASE + 84 + 10 * 4
    words = [0xE3A07002, 0xEF000000, 0xE59F0000 | (9 * 4 - (2 * 4 + 8)), 0xE3A01000, 0xE3A070A2, 0xEF000000, 0xE3A00000, 0xE3A07001, 0xEF000000, ts]
    return elf32(True, 40, ARM_FLAGS, words, struct.pack("<II", 3600, 0))


def mips_noisy():
    ori = lambda rt, rs, imm: (0x0D << 26) | (rs << 21) | (rt << 16) | imm          # noqa: E731
    lui = lambda rt, imm: (0x0F << 26) | (rt << 16) | imm                           # noqa: E731
    beq = lambda rs, rt, off: (0x04 << 26) | (rs << 21) | (rt << 16) | (off & 0xFFFF)  # noqa: E731
    SYS = 0x0C
    n = 13                                                       # instruction words below
    msg = BASE + 84 + n * 4
    ts = msg + 12
    words = [lui(5, msg >> 16), ori(5, 5, msg & 0xFFFF), ori(4, 0, 1), ori(6, 0, 12), ori(2, 0, 4004), SYS,
             lui(4, ts >> 16), ori(4, 4, ts & 0xFFFF), ori(5, 0, 0), ori(2, 0, 4166), SYS,
             beq(0, 0, 0 - (11 + 1)), 0]                         # branch back to word 0 (offset relative to the delay slot), nop in the delay slot
    assert len(words) == n
    return elf32(False, 8, MIPS_FLAGS, words, b"CT04-NOISE!\n" + struct.pack(">II", 0, 10_000_000))


def mips_fork():
    ori = lambda rt, rs, imm: (0x0D << 26) | (rs << 21) | (rt << 16) | imm          # noqa: E731
    lui = lambda rt, imm: (0x0F << 26) | (rt << 16) | imm                           # noqa: E731
    SYS = 0x0C
    n = 10
    ts = BASE + 84 + n * 4
    words = [ori(2, 0, 4002), SYS, lui(4, ts >> 16), ori(4, 4, ts & 0xFFFF), ori(5, 0, 0), ori(2, 0, 4166), SYS, ori(4, 0, 0), ori(2, 0, 4001), SYS]
    assert len(words) == n
    return elf32(False, 8, MIPS_FLAGS, words, struct.pack(">II", 3600, 0))


def mips(kind, n=0):
    ori = lambda rt, rs, imm: (0x0D << 26) | (rs << 21) | (rt << 16) | imm          # noqa: E731
    lui = lambda rt, imm: (0x0F << 26) | (rt << 16) | imm                           # noqa: E731
    SYS = 0x0C
    if kind == "exit":
        words = [ori(4, 0, n), ori(2, 0, 4001), SYS]
        return elf32(False, 8, MIPS_FLAGS, words, b"")
    words = [0, 0, ori(5, 0, 0), ori(2, 0, 4166), SYS, ori(4, 0, 0), ori(2, 0, 4001), SYS]      # words 0,1 (lui/ori a0 = &ts) fixed below
    ts_addr = BASE + 84 + len(words) * 4
    words[0], words[1] = lui(4, ts_addr >> 16), ori(4, 4, ts_addr & 0xFFFF)
    return elf32(False, 8, MIPS_FLAGS, words, struct.pack(">II", 3600, 0))


def a64stub():
    code = struct.pack("<III", 0xD2800000, 0xD2800BA8, 0xD4000001)          # mov x0,#0 ; mov x8,#93 ; svc #0
    total = 64 + 56 + len(code)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
    eh = ident + struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0x400000 + 120, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, total, total, 0x1000)
    return eh + ph + code


# ---- encoding self-check: mini emulators for exactly these instructions; returns the list of (syscall, args) ----
def emu_arm(img, limit=0):
    e = "<"
    pc = struct.unpack_from(e + "I", img, 24)[0] - BASE
    r = [0] * 16
    tr = []
    for _ in range(400):
        w = struct.unpack_from(e + "I", img, pc)[0]
        if (w & 0xFFFF0000) == 0xE59F0000:
            r[(w >> 12) & 0xF] = struct.unpack_from(e + "I", img, pc + 8 + (w & 0xFFF))[0]
        elif (w & 0xFFF00000) == 0xE3A00000:
            rot, imm = (w >> 8) & 0xF, w & 0xFF
            assert rot == 0, "rotated immediate not used by these listings"
            r[(w >> 12) & 0xF] = imm
        elif (w & 0xFF000000) == 0xEA000000:                                  # B (unconditional)
            off = w & 0xFFFFFF
            off = off - (1 << 24) if off & 0x800000 else off
            pc = pc + 8 + off * 4
            continue
        elif w == 0xEF000000:
            if r[7] == 1:
                tr.append(("exit", r[0]))
                return tr
            if r[7] == 162:
                a = r[0] - BASE
                tr.append(("nanosleep", struct.unpack_from(e + "II", img, a)))
                r[0] = 0
            elif r[7] == 4:
                a = r[1] - BASE
                tr.append(("write", r[0], bytes(img[a:a + r[2]])))
                r[0] = r[2]
            elif r[7] == 2:
                tr.append(("fork",))
                r[0] = 2                                                         # the parent path; the child runs the same words with r0 = 0
            else:
                raise AssertionError("unexpected syscall %d" % r[7])
            if limit and len(tr) >= limit:
                return tr
        else:
            raise AssertionError("unknown instruction %08x" % w)
        pc += 4
    raise AssertionError("no exit")


def emu_mips(img, limit=0):
    e = ">"
    pc = struct.unpack_from(e + "I", img, 24)[0] - BASE
    r = [0] * 32
    tr = []
    delay_target = None
    for _ in range(600):
        w = struct.unpack_from(e + "I", img, pc)[0]
        op, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        nxt = pc + 4
        was_delay = delay_target is not None
        if op == 0x0F:
            r[rt] = imm << 16
        elif op == 0x0D:
            r[rt] = r[rs] | imm
        elif op == 0x04:                                                          # beq rs, rt, off (the delay slot executes first)
            if r[rs] == r[rt]:
                off = imm - 0x10000 if imm & 0x8000 else imm
                delay_target = pc + 4 + off * 4
        elif w == 0:
            pass
        elif w == 0x0C:
            if r[2] == 4001:
                tr.append(("exit", r[4]))
                return tr
            if r[2] == 4166:
                tr.append(("nanosleep", struct.unpack_from(e + "II", img, r[4] - BASE)))
                r[2] = 0
            elif r[2] == 4004:
                a = r[5] - BASE
                tr.append(("write", r[4], bytes(img[a:a + r[6]])))
                r[2] = r[6]
            elif r[2] == 4002:
                tr.append(("fork",))
                r[2] = 2
            else:
                raise AssertionError("unexpected syscall %d" % r[2])
            r[7] = 0
            if limit and len(tr) >= limit:
                return tr
        else:
            raise AssertionError("unknown instruction %08x" % w)
        r[0] = 0
        if was_delay:
            pc, delay_target = delay_target, None
        else:
            pc = nxt
    raise AssertionError("no exit")


def main(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for a, build, emu in (("ARM", arm, emu_arm), ("MIPS", mips, emu_mips)):
        for name, kind, n, want in (("exit0", "exit", 0, [("exit", 0)]), ("exit7", "exit", 7, [("exit", 7)]),
                                    ("sleep", "sleep", 0, [("nanosleep", (3600, 0)), ("exit", 0)])):
            img = build(kind, n)
            assert emu(img) == want, (a, name, emu(img))
            files["ct04-%s-%s" % (name, a)] = img
    noisy_want = [("write", 1, b"CT04-NOISE!\n"), ("nanosleep", (0, 10_000_000))] * 3
    fork_want = [("fork",), ("nanosleep", (3600, 0)), ("exit", 0)]
    for a, nb, fb, emu in (("ARM", arm_noisy, arm_fork, emu_arm), ("MIPS", mips_noisy, mips_fork, emu_mips)):
        ni, fi = nb(), fb()
        assert emu(ni, limit=6) == noisy_want, (a, "noisy", emu(ni, limit=6))
        assert emu(fi) == fork_want, (a, "fork", emu(fi))
        files["ct04-noisy-%s" % a], files["ct04-fork-%s" % a] = ni, fi
    files["ct04-a64stub-ARM64"] = a64stub()
    for k, v in files.items():
        (out / k).write_bytes(v)
    prov = {"schema": "ct04-fixture-provenance/1", "generator": "build_ct04_elf.py",
            "generator_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            "files": {k: {"sha256": hashlib.sha256(v).hexdigest(), "bytes": len(v)} for k, v in sorted(files.items())},
            "expected_class": {"exit0": "EXITED_0", "exit7": "EXITED_NONZERO", "sleep": "SAMPLE_TIMEOUT (needs trace metadata + live probe)",
                               "noisy": "measurement only (console stays in sync?); SAMPLE_TIMEOUT only with a proven probe", "fork": "SAMPLE_TIMEOUT for the main pid (CHILDREN_SEEN)",
                               "a64stub": "EXEC_FORMAT_ERROR (expectation only)"},
            "not_done": "never executed on a real kernel; encodings checked by a mini-emulator only; not built into any image; no runtime"}
    (out / "PROVENANCE.json").write_text(json.dumps(prov, indent=1, sort_keys=True))
    print(json.dumps({k: v["sha256"][:16] for k, v in prov["files"].items()}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
