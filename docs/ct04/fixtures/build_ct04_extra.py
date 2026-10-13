#!/usr/bin/env python3
"""CT-04 EXTRA benign fixtures (OFFLINE; prepared, NOT executed, NOT built into any image, no lane). They cover classes that the 13 measured lanes did not:
  segv      : store to address 0                         -> SIGSEGV (kernel-generated si_code)    -> expected CRASHED
  selfkill  : kill(getpid(), SIGTERM)                    -> killed by SIGTERM, source = itself    -> expected KILLED_BY_SIGNAL (+SELF_SENT)
  noloader  : ET_EXEC with PT_INTERP "/lib/ld-ct04-missing.so" (loader absent in the guest)  -> execve ENOENT -> expected EXEC_NOT_FOUND
  missinglib: ET_EXEC with PT_INTERP = the guest's musl loader (ARM /lib/ld-musl-armhf.so.1, MIPS /lib/ld-musl-mips-sf.so.1, read from the images' root.ext4 with debugfs)
            and DT_NEEDED "libct04missing.so" (absent). STRUCTURE verified by an own parser only; musl's behaviour (expected: "Error loading shared library ...",
            exit 127) is NOT verified; only a lane can show it. The classifier reports it as EXITED_NONZERO + LOADER_ERROR_REPORTED (+ LIB_LOOKUP_FAILED_SAME_NAME):
            MISSING_LIBRARY stays RESERVED because loader provenance of the message cannot be certified (see the loader plan).
NOT prepared, and why: a true MISSING_LIBRARY verdict needs provenance of the loader message (not available);  STOPPED_BY_SANDBOX needs the manager cancel path (a task, not a sample). EXEC_PERMISSION_DENIED cannot occur because the
worker chmods the file. A log-capture failure is a worker fault injection, not a sample.
Encodings are checked by a mini-emulator written for exactly these instructions; the container is checked structurally. Honest limit: no kernel ever executed them.
usage: build_ct04_extra.py <out_dir> <path to ct04-offline-r6/fixtures/elf/build_ct04_elf.py>"""
import hashlib, importlib.util, json, pathlib, struct, sys

spec = importlib.util.spec_from_file_location("b", sys.argv[2]); B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
BASE = B.BASE


def arm_prog(kind):
    if kind == "segv":      # mov r0,#0 ; str r0,[r0] ; mov r7,#1 ; svc
        words = [0xE3A00000, 0xE5800000, 0xE3A07001, 0xEF000000]
    else:                   # selfkill: mov r7,#20 ; svc ; mov r1,#15 ; mov r7,#37 ; svc ; mov r0,#0 ; mov r7,#1 ; svc
        words = [0xE3A07014, 0xEF000000, 0xE3A0100F, 0xE3A07025, 0xEF000000, 0xE3A00000, 0xE3A07001, 0xEF000000]
    return B.elf32(True, 40, B.ARM_FLAGS, words, b"")


def mips_prog(kind):
    ori = lambda rt, rs, imm: (0x0D << 26) | (rs << 21) | (rt << 16) | imm          # noqa: E731
    SYS = 0x0C
    if kind == "segv":      # sw $zero,0($zero) ; a0=0 ; v0=4001 ; syscall
        words = [0xAC000000, ori(4, 0, 0), ori(2, 0, 4001), SYS]
    else:                   # v0=4020 getpid ; syscall ; a0=v0 ; a1=15 ; v0=4037 kill ; syscall ; a0=0 ; v0=4001 ; syscall
        words = [ori(2, 0, 4020), SYS, 0x00402025, ori(5, 0, 15), ori(2, 0, 4037), SYS, ori(4, 0, 0), ori(2, 0, 4001), SYS]
    return B.elf32(False, 8, B.MIPS_FLAGS, words, b"")


def noloader(le, machine, flags, words):
    e = "<" if le else ">"
    interp = b"/lib/ld-ct04-missing.so\0"
    code = b"".join(struct.pack(e + "I", w) for w in words)
    hdr = 52 + 2 * 32
    ioff = hdr + len(code)
    total = ioff + len(interp)
    ident = b"\x7fELF" + bytes([1, 1 if le else 2, 1, 0, 0]) + b"\0" * 7
    eh = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, BASE + hdr, 52, 0, flags, 52, 32, 2, 40, 0, 0)
    ph_interp = struct.pack(e + "IIIIIIII", 3, ioff, BASE + ioff, BASE + ioff, len(interp), len(interp), 4, 1)
    ph_load = struct.pack(e + "IIIIIIII", 1, 0, BASE, BASE, total, total, 5, 0x1000)
    return eh + ph_interp + ph_load + code + interp


def missinglib(le, machine, flags, words, interp_path):
    e = "<" if le else ">"
    interp = interp_path.encode() + b"\0"
    strtab = b"\0libct04missing.so\0"
    code = b"".join(struct.pack(e + "I", w) for w in words)
    nph = 3
    hdr = 52 + nph * 32
    off_code = hdr
    off_interp = off_code + len(code)
    off_str = off_interp + len(interp)
    off_sym = (off_str + len(strtab) + 3) & ~3
    sym = b"\0" * 16
    off_hash = off_sym + 16
    hash_ = struct.pack(e + "IIII", 1, 1, 0, 0)
    off_dyn = off_hash + len(hash_)
    v = lambda o: BASE + o                                                           # noqa: E731
    dyn = b"".join(struct.pack(e + "II", t, x) for t, x in ((1, 1), (4, v(off_hash)), (5, v(off_str)), (6, v(off_sym)), (10, len(strtab)), (11, 16), (0, 0)))
    total = off_dyn + len(dyn)
    ident = b"\x7fELF" + bytes([1, 1 if le else 2, 1, 0, 0]) + b"\0" * 7
    eh = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, BASE + off_code, 52, 0, flags, 52, 32, nph, 40, 0, 0)
    ph = (struct.pack(e + "IIIIIIII", 3, off_interp, v(off_interp), v(off_interp), len(interp), len(interp), 4, 1)
          + struct.pack(e + "IIIIIIII", 1, 0, BASE, BASE, total, total, 7, 0x1000)
          + struct.pack(e + "IIIIIIII", 2, off_dyn, v(off_dyn), v(off_dyn), len(dyn), len(dyn), 6, 4))
    img = eh + ph + code + interp + strtab
    img += b"\0" * (off_sym - len(img)) + sym + hash_ + dyn
    assert len(img) == total
    return img


def parse_missinglib(img, le):
    """independent structural check: PT_INTERP string, DT_NEEDED name resolved through DT_STRTAB, DT_STRTAB/SYMTAB/HASH inside the file, entry inside the PT_LOAD"""
    e = "<" if le else ">"
    ph = struct.unpack_from(e + "H", img, 44)[0]
    segs = [struct.unpack_from(e + "IIIIIIII", img, 52 + 32 * i) for i in range(ph)]
    byt = {s[0]: s for s in segs}
    assert set(byt) == {1, 2, 3}, byt.keys()
    interp = img[byt[3][1]:byt[3][1] + byt[3][4]].rstrip(b"\0").decode()
    d = {}
    off = byt[2][1]
    while True:
        t, x = struct.unpack_from(e + "II", img, off)
        off += 8
        if t == 0:
            break
        d.setdefault(t, []).append(x)
    strtab = d[5][0] - BASE
    name = img[strtab + d[1][0]: img.index(b"\0", strtab + d[1][0])].decode()
    entry = struct.unpack_from(e + "I", img, 24)[0]
    assert BASE <= entry < BASE + len(img) and all(BASE <= d[k][0] < BASE + len(img) for k in (4, 5, 6)), d
    assert byt[1][1] == 0 and byt[1][4] == len(img)
    return interp, name


# ---- mini emulators (only the instructions above) ----
def emu_arm(img):
    pc = struct.unpack_from("<I", img, 24)[0] - BASE
    r = [0] * 16
    out = []
    for _ in range(40):
        w = struct.unpack_from("<I", img, pc)[0]
        if (w & 0xFFFFF000) == 0xE3A00000 | (0 << 12) and False:
            pass
        if (w >> 20) == 0xE3A:                       # mov rd,#imm8
            r[(w >> 12) & 15] = w & 0xFF
        elif w == 0xEF000000:
            out.append(("svc", r[7], r[0], r[1]))
            if r[7] == 1:
                return out
            if r[7] == 20:
                r[0] = 4242
        elif w == 0xE5800000:                        # str r0,[r0]
            if r[0] < BASE:
                out.append(("SIGSEGV", r[0]))
                return out
        else:
            raise AssertionError("unknown arm word %08x" % w)
        pc += 4
    raise AssertionError("no exit")


def emu_mips(img):
    pc = struct.unpack_from(">I", img, 24)[0] - BASE
    r = [0] * 32
    out = []
    for _ in range(40):
        w = struct.unpack_from(">I", img, pc)[0]
        op = w >> 26
        if op == 0x0D:                               # ori
            r[(w >> 16) & 31] = r[(w >> 21) & 31] | (w & 0xFFFF)
        elif w == 0x0000000C:
            out.append(("syscall", r[2], r[4], r[5]))
            if r[2] == 4001:
                return out
            if r[2] == 4020:
                r[2] = 4242
        elif w == 0xAC000000:                        # sw $zero,0($zero)
            out.append(("SIGSEGV", 0))
            return out
        elif w == 0x00402025:                        # or $a0,$v0,$zero
            r[4] = r[2]
        else:
            raise AssertionError("unknown mips word %08x" % w)
        pc += 4
    raise AssertionError("no exit")


def main(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    a_segv, a_kill, m_segv, m_kill = arm_prog("segv"), arm_prog("selfkill"), mips_prog("segv"), mips_prog("selfkill")
    assert emu_arm(a_segv) == [("SIGSEGV", 0)], emu_arm(a_segv)
    assert emu_mips(m_segv) == [("SIGSEGV", 0)], emu_mips(m_segv)
    ea = emu_arm(a_kill); em = emu_mips(m_kill)
    assert ea[0] == ("svc", 20, 0, 0) and ea[1] == ("svc", 37, 4242, 15) and ea[2][1] == 1, ea
    assert em[0] == ("syscall", 4020, 0, 0) and em[1] == ("syscall", 4037, 4242, 15) and em[2][1] == 4001, em
    files.update({"ct04-segv-ARM": a_segv, "ct04-selfkill-ARM": a_kill, "ct04-segv-MIPS": m_segv, "ct04-selfkill-MIPS": m_kill})
    files["ct04-noloader-ARM"] = noloader(True, 40, B.ARM_FLAGS, [0xE3A00000, 0xE3A07001, 0xEF000000])
    files["ct04-noloader-MIPS"] = noloader(False, 8, B.MIPS_FLAGS, [0x34040000, 0x34020FA1, 0x0000000C])
    ma = missinglib(True, 40, B.ARM_FLAGS, [0xE3A00000, 0xE3A07001, 0xEF000000], "/lib/ld-musl-armhf.so.1")
    mm = missinglib(False, 8, B.MIPS_FLAGS, [0x34040000, 0x34020FA1, 0x0000000C], "/lib/ld-musl-mips-sf.so.1")
    assert parse_missinglib(ma, True) == ("/lib/ld-musl-armhf.so.1", "libct04missing.so"), parse_missinglib(ma, True)
    assert parse_missinglib(mm, False) == ("/lib/ld-musl-mips-sf.so.1", "libct04missing.so"), parse_missinglib(mm, False)
    files["ct04-missinglib-ARM"], files["ct04-missinglib-MIPS"] = ma, mm
    for k, v in files.items():
        (out / k).write_bytes(v)
    prov = {"schema": "ct04-fixture-provenance-extra/1", "generator": "build_ct04_extra.py", "generator_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            "base_generator_sha256": hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
            "files": {k: {"sha256": hashlib.sha256(v).hexdigest(), "bytes": len(v)} for k, v in sorted(files.items())},
            "expected_class": {"segv": "CRASHED (kernel si_code)", "selfkill": "KILLED_BY_SIGNAL (SELF_SENT)", "noloader": "EXEC_NOT_FOUND (execve ENOENT: missing interpreter)",
                               "missinglib": "EXITED_NONZERO + LOADER_ERROR_REPORTED (+ LIB_LOOKUP_FAILED_SAME_NAME); NOT MISSING_LIBRARY (reserved)"},
            "not_prepared": ["MISSING_LIBRARY verdict (reserved: loader message provenance cannot be certified)", "STOPPED_BY_SANDBOX (needs the manager cancel path)", "EXEC_PERMISSION_DENIED (worker chmods)", "log capture failure (fault injection)"],
            "not_done": "never executed; encodings checked by a mini-emulator only; not built into an image; no lane exists for them; a lane definition + bundle + approval would be needed"}
    (out / "PROVENANCE.json").write_text(json.dumps(prov, indent=1, sort_keys=True))
    print(json.dumps({k: v["sha256"][:16] for k, v in prov["files"].items()}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
