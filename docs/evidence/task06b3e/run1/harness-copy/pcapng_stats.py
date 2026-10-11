"""06B-3CR — drop statistics of a tshark/dumpcap pcapng capture, read from the file itself.

tshark (the version in the worker image) prints only "N packets captured" on stderr and prints
no drop line at all when nothing was dropped, so a missing stderr line cannot mean "0 dropped".
dumpcap writes an Interface Statistics Block (ISB) at the end of a clean capture; in 06B-3B run 5:
    ISB if 0 {comment: "Counters provided by dumpcap", isb_ifrecv: 97, isb_ifdrop: 0}
This module reads those counters. Pure Python, no dependencies; imported by probe_matrix.py.

    read_stats(path)  -> {"interfaces": n_idb, "epb": {if: n}, "isb": {if: {...}}}  (last ISB per if)
                         raises PcapngError on anything malformed or truncated
    drop_verdict(st)  -> ("PASS" | "FAIL" | "UNVERIFIED", reason)
        PASS        every interface has an ISB with isb_ifdrop == 0 (isb_osdrop == 0 if present)
                    and isb_ifrecv, if present, equals the packets stored for that interface
        FAIL        a drop counter > 0, or ifrecv != stored packets
        UNVERIFIED  no ISB, or an ISB without isb_ifdrop: the drop count is unknown
"""
import struct

SHB, IDB, EPB, SPB, ISB = 0x0A0D0D0A, 0x00000001, 0x00000006, 0x00000003, 0x00000005
OPT = {1: "comment", 4: "isb_ifrecv", 5: "isb_ifdrop", 6: "isb_filteraccept", 7: "isb_osdrop",
       8: "isb_usrdeliv"}


class PcapngError(Exception):
    pass


def _options(body, off, end, E):
    opts = {}
    while off + 4 <= end:
        code, ln = struct.unpack_from(E + "HH", body, off)
        off += 4
        if code == 0:
            return opts
        if off + ln > end:
            raise PcapngError("option runs past the end of its block")
        val = body[off:off + ln]
        name = OPT.get(code)
        if name == "comment":
            opts[name] = val.decode("utf-8", "replace")
        elif name:
            if ln != 8:
                raise PcapngError(f"{name} has length {ln}, expected 8")
            opts[name] = struct.unpack(E + "Q", val)[0]
        off += (ln + 3) & ~3
    return opts


def read_stats(path):
    """Raises PcapngError (never struct.error etc.) on anything that cannot be decoded."""
    data = open(path, "rb").read()
    try:
        return _read(data)
    except PcapngError:
        raise
    except (struct.error, IndexError, ValueError) as e:
        raise PcapngError(f"cannot decode pcapng: {type(e).__name__}: {e}")


def _read(data):
    E = "<"
    if len(data) < 28:
        raise PcapngError(f"file too short ({len(data)} bytes)")
    if struct.unpack_from("<I", data, 0)[0] != SHB:
        raise PcapngError("not a pcapng file (no section header block)")
    st = {"interfaces": 0, "epb": {}, "isb": {}}
    off = 0
    while off < len(data):
        if off + 12 > len(data):
            raise PcapngError(f"truncated block header at offset {off}")
        btype = struct.unpack_from("<I", data, off)[0]
        if btype == SHB:
            magic = data[off + 8:off + 12]
            E = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(magic)
            if E is None:
                raise PcapngError("bad byte-order magic")
        blen = struct.unpack_from(E + "I", data, off + 4)[0]
        if blen < 12 or blen % 4 or off + blen > len(data):
            raise PcapngError(f"truncated or invalid block (type {btype:#x}, length {blen}) at offset {off}")
        if struct.unpack_from(E + "I", data, off + blen - 4)[0] != blen:
            raise PcapngError(f"block length trailer mismatch at offset {off}")
        btype = struct.unpack_from(E + "I", data, off)[0]
        body_end = off + blen - 4
        if btype == IDB:
            st["interfaces"] += 1
        elif btype == EPB:
            iface = struct.unpack_from(E + "I", data, off + 8)[0]
            st["epb"][iface] = st["epb"].get(iface, 0) + 1
        elif btype == SPB:
            st["epb"][0] = st["epb"].get(0, 0) + 1
        elif btype == ISB:
            iface = struct.unpack_from(E + "I", data, off + 8)[0]
            st["isb"][iface] = _options(data, off + 20, body_end, E)   # after if id + 64-bit timestamp
        off += blen
    if st["interfaces"] == 0:
        raise PcapngError("no interface description block")
    return st


def drop_verdict(st):
    if not st["isb"]:
        return "UNVERIFIED", "no interface statistics block: drop count unknown"
    for iface in range(st["interfaces"]):
        isb = st["isb"].get(iface)
        if isb is None:
            return "UNVERIFIED", f"interface {iface}: no interface statistics block"
        if "isb_ifdrop" not in isb:
            return "UNVERIFIED", f"interface {iface}: statistics block without isb_ifdrop"
        if isb["isb_ifdrop"] > 0:
            return "FAIL", f"interface {iface}: isb_ifdrop={isb['isb_ifdrop']}"
        if isb.get("isb_osdrop", 0) > 0:
            return "FAIL", f"interface {iface}: isb_osdrop={isb['isb_osdrop']}"
        stored = st["epb"].get(iface, 0)
        if "isb_ifrecv" in isb and isb["isb_ifrecv"] != stored:
            return "FAIL", f"interface {iface}: isb_ifrecv={isb['isb_ifrecv']} but {stored} packets stored"
    return "PASS", "isb_ifdrop=0 on every interface; isb_ifrecv equals stored packets"
