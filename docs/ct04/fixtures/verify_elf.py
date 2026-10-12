#!/usr/bin/env python3
"""Independent structural check of the CT-02 fixture ELF files (a parser separate from the generator; NOT an execution).
usage: verify_elf.py <file> ARM|MIPS     exit 0 = all structural checks hold, 1 = a check failed (printed), 2 = unreadable"""
import struct, subprocess, sys

EXPECT = {"ARM": dict(data=1, machine=40, flags=0x05000000, endian="<", file_words=("ARM", "EABI5", "LSB", "statically linked")),
          "MIPS": dict(data=2, machine=8, flags=0x70001001, endian=">", file_words=("MIPS", "MSB", "statically linked"))}


def check(path, arch):
    e = EXPECT[arch]
    d = open(path, "rb").read()
    why = []
    if len(d) < 84 or d[:4] != b"\x7fELF":
        return ["not an ELF"]
    if d[4] != 1: why.append("not ELFCLASS32")
    if d[5] != e["data"]: why.append("wrong byte order")
    en = e["endian"]
    etype, machine, ver, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(en + "HHIIIIIHHHHHH", d, 16)
    if etype != 2: why.append("not ET_EXEC")
    if machine != e["machine"]: why.append(f"machine {machine}")
    if flags != e["flags"]: why.append(f"e_flags {flags:#x} != {e['flags']:#x}")
    if arch == "MIPS" and flags & 0x04000000: why.append("EF_MIPS_ARCH_ASE_M16 set (the code is 32-bit MIPS)")
    if shoff or shnum: why.append("section headers present (expected none)")
    if phnum != 1 or phentsize != 32 or phoff != 52: why.append(f"program headers: n={phnum} size={phentsize} off={phoff}")
    else:
        ptype, off, vaddr, paddr, filesz, memsz, pflags, align = struct.unpack_from(en + "IIIIIIII", d, phoff)
        if ptype != 1: why.append("segment is not PT_LOAD (no PT_INTERP/PT_DYNAMIC allowed)")
        if filesz != len(d) or memsz != filesz or off != 0: why.append("segment does not cover exactly the file")
        if not (vaddr + 84 <= entry < vaddr + filesz) or entry % 4: why.append("entry outside the segment or unaligned")
        if pflags != 5: why.append(f"p_flags {pflags} (expected R+X = 5)")
        if (len(d) - 84) % 4 and False: pass
    try:
        out = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=10).stdout
        for w in e["file_words"]:
            if w not in out:
                why.append(f"file(1) output lacks {w!r}: {out.strip()}")
    except (OSError, subprocess.TimeoutExpired):
        pass                                             # file(1) optional
    return why


if __name__ == "__main__":
    try:
        w = check(sys.argv[1], sys.argv[2])
    except OSError as ex:
        print(f"UNREADABLE: {ex}")
        sys.exit(2)
    print("ELF-OK" if not w else "ELF-FAIL: " + "; ".join(w))
    sys.exit(0 if not w else 1)
