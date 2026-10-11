"""06B-4B — save / restore the guest network state around a probe that changes it (D2). Offline module.

No probe uses it yet. It talks to the guest only through a `runner` with the interface of
probe_matrix.Guest.run(cmd, timeout) -> (rc, text), so the offline tests drive it with a simulated
guest. Only busybox tools that the static inventory found in both images are used (`cat`, `ip`,
`arp`); that inventory is static evidence, the tools must still be confirmed in the running guest.

State of one probe interface IF (ARM eth1, MIPS br-lan):
    mac, operstate       /sys/class/net/IF/{address,operstate}   (operstate = operational observation, e.g. carrier)
    admin_up             UP flag of the `ip link show dev IF` header (06B-4IR3: administrative configuration, kept
                         apart from operstate; a bridge can be admin UP with operstate down / NO-CARRIER)
    addrs                IPv4 "a.b.c.d/p" on IF                 (ip -4 addr show dev IF)
    routes               every IPv4 route, whitespace-normalised (ip -4 route show)
    neigh_static         {(ip, dev): mac} with ATF_PERM          (/proc/net/arp, flags & 0x4)
    neigh_dynamic        {(ip, dev): (mac, flags)} the rest      (reported, not restored)
    arp_notify           /proc/sys/net/ipv4/conf/IF/arp_notify
    nat_postrouting      (R5, only when asked: `nat=True`) `iptables -t nat -S POSTROUTING` lines (ARM, fw3/iptables), IN THE ORDER the guest printed
                         them (R6: policy line first, then the rules by position; order and multiplicity are part of the state). Restore deletes
                         only extra rules BY POSITION, only when the recorded rules are still present in the same order (a subsequence) and only
                         those the case owns; a missing/reordered/duplicated-away rule is never re-created here and keeps `restored` False.
                         Read with ONE extra command (the spoof suite's console line cap is 480 characters; the main snapshot is already 448).

Restore = return to the state recorded BEFORE the probe, in rounds (each step re-reads the state):
link (MAC, admin up/down as recorded) -> addresses -> routes -> static neighbours -> arp_notify. Static neighbours follow
the before-state exactly: an entry the probe added is deleted, an entry that existed before and was
lost (e.g. flushed by a link down [Kernel]) is re-created with its old MAC. Dynamic entries are
kernel-managed: they are reported, never forced, and do not make the restore fail.
The result says `restored` only if the re-read state equals the before-state on every restored item.
"""
import re

SECTIONS = ("mac", "operstate", "link", "addr", "route", "arp", "arp_notify")
_LINK_HDR = re.compile(r"\d+:\s+([^\s:@]+)(?:@\S+)?:\s+<([A-Z0-9_,-]*)>(?:\s.*)?")


class StateReadError(Exception):
    """The guest state could not be read completely: never treated as an empty state."""


NAT_CMD = "echo '@@S nat'; iptables -t nat -S POSTROUTING; echo \"@@RC $?\""


def snapshot_cmd(iface):
    _check_iface(iface)
    parts = []
    for name, cmd in (("mac", f"cat /sys/class/net/{iface}/address"),
                      ("operstate", f"cat /sys/class/net/{iface}/operstate"),
                      ("link", f"ip link show dev {iface}"),
                      ("addr", f"ip -4 addr show dev {iface}"),
                      ("route", "ip -4 route show"),
                      ("arp", "cat /proc/net/arp"),
                      ("arp_notify", f"cat /proc/sys/net/ipv4/conf/{iface}/arp_notify")):
        parts.append(f"echo '@@S {name}'; {cmd}; echo \"@@RC $?\"")
    return "; ".join(parts)


def _check_iface(iface):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface or ""):
        raise ValueError(f"bad interface name {iface!r}")


def parse_snapshot(text, iface=None):
    sec, cur, rcs = {}, None, {}
    for line in text.replace("\r", "").split("\n"):
        m = re.fullmatch(r"@@S (\w+)", line.strip())
        if m:
            cur = m.group(1)
            sec[cur] = []
            continue
        m = re.fullmatch(r"@@RC (\d+)", line.strip())
        if m and cur is not None:
            rcs[cur] = int(m.group(1))
            cur = None
            continue
        if cur is not None:
            sec[cur].append(line)
    for name in SECTIONS:
        if name not in sec or name not in rcs:
            raise StateReadError(f"section {name} missing in the guest output")
        if rcs[name] != 0:
            raise StateReadError(f"reading {name} failed in the guest (rc {rcs[name]})")
    mac = "".join(sec["mac"]).strip().lower()
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise StateReadError(f"bad MAC {mac!r}")
    oper = "".join(sec["operstate"]).strip()
    if not oper:
        raise StateReadError("empty operstate")
    # 06B-4IR3: administrative state from the link header (never inferred from operstate)
    hdrs = [l.strip() for l in sec["link"] if re.match(r"\s*\d+:\s", l)]
    if len(hdrs) != 1:
        raise StateReadError(f"link section: {len(hdrs)} interface header line(s), expected exactly 1")
    m = _LINK_HDR.fullmatch(hdrs[0])
    if not m:
        raise StateReadError(f"link header not understood: {hdrs[0][:120]!r}")
    if iface is not None and m.group(1) != iface:
        raise StateReadError(f"link header is for {m.group(1)!r}, not {iface!r}")
    flags = [f for f in m.group(2).split(",") if f]
    admin_up = "UP" in flags
    addrs = sorted(m.group(1) for l in sec["addr"] for m in [re.search(r"\binet (\d+\.\d+\.\d+\.\d+/\d+)", l)] if m)
    routes = sorted(" ".join(l.split()) for l in sec["route"] if l.strip())
    static, dynamic = {}, {}
    rows = [l for l in sec["arp"] if l.strip()]
    if not rows or not rows[0].startswith("IP address"):
        raise StateReadError("/proc/net/arp header missing")
    for l in rows[1:]:
        f = l.split()
        if len(f) != 6:
            raise StateReadError(f"unexpected /proc/net/arp row {l!r}")
        ip, flags, hw, dev = f[0], int(f[2], 16), f[3].lower(), f[5]
        if flags & 0x4:
            static[(ip, dev)] = hw
        else:
            dynamic[(ip, dev)] = (hw, flags)
    notify = "".join(sec["arp_notify"]).strip()
    if not notify.isdigit():
        raise StateReadError(f"bad arp_notify {notify!r}")
    return {"mac": mac, "operstate": oper, "admin_up": admin_up, "addrs": addrs, "routes": routes, "neigh_static": static,
            "neigh_dynamic": dynamic, "arp_notify": int(notify)}


def parse_nat(text):
    """-> list of `iptables -t nat -S POSTROUTING` lines IN GUEST ORDER (R6: never sorted; order and duplicates are state). The first line must be the
    one `-P POSTROUTING <policy>` line, every other line an `-A POSTROUTING ...` rule; anything else is a read error, never an empty rule set."""
    sec, rc = [], None
    inside = False
    for line in text.replace("\r", "").split("\n"):
        s = line.strip()
        if s == "@@S nat":
            inside = True
            continue
        m = re.fullmatch(r"@@RC (\d+)", s)
        if m and inside:
            rc = int(m.group(1))
            inside = False
            continue
        if inside and s:
            sec.append(" ".join(s.split()))
    if rc is None:
        raise StateReadError("nat section missing in the guest output")
    if rc != 0:
        raise StateReadError(f"reading nat failed in the guest (rc {rc})")
    if not sec or not sec[0].startswith("-P POSTROUTING ") or any(not l.startswith("-A POSTROUTING ") for l in sec[1:]):
        raise StateReadError(f"nat section not understood: {sec[:3]!r}")
    return sec


def read_state(runner, iface, timeout=30, nat=False):
    rc, out = runner.run(snapshot_cmd(iface), timeout=timeout)
    if rc != 0:
        raise StateReadError(f"snapshot command rc {rc}")
    st = parse_snapshot(out, iface)
    if nat:
        rc, out = runner.run(NAT_CMD, timeout=timeout)
        if rc != 0:
            raise StateReadError(f"nat snapshot command rc {rc}")
        st["nat_postrouting"] = parse_nat(out)
    return st


def diff(before, after):
    """Differences that a restore must remove. Dynamic neighbours are not part of it."""
    d = []
    for k in ("mac", "operstate", "arp_notify"):
        if before[k] != after[k]:
            d.append(f"{k}: {before[k]!r} -> {after[k]!r}")
    if before["admin_up"] is not after["admin_up"]:          # 06B-4IR3: administrative state, separate field
        d.append(f"admin_up: {before['admin_up']!r} -> {after['admin_up']!r}")
    for k in ("addrs", "routes"):
        b, a = set(before[k]), set(after[k])
        d += [f"{k}: missing {x!r}" for x in sorted(b - a)] + [f"{k}: extra {x!r}" for x in sorted(a - b)]
    b, a = before["neigh_static"], after["neigh_static"]
    for key in sorted(set(b) | set(a)):
        if b.get(key) != a.get(key):
            d.append(f"neigh_static {key[0]} dev {key[1]}: {b.get(key)!r} -> {a.get(key)!r}")
    if "nat_postrouting" in before or "nat_postrouting" in after:      # R5: both sides must carry it; one-sided is a difference
        bn, an = before.get("nat_postrouting"), after.get("nat_postrouting")
        if bn is None or an is None:
            d.append("nat_postrouting: missing on one side")
        else:
            d += nat_diff(bn, an)
    return d


def nat_diff(bn, an):
    """R6: ordered comparison with multiplicity. Equal sequences -> []. Otherwise one line per rule missing/extra (multiset), and, when the multisets
    are equal, an explicit order line."""
    if list(bn) == list(an):
        return []
    from collections import Counter
    cb, ca = Counter(bn), Counter(an)
    d = [f"nat_postrouting: missing {x!r} (x{cb[x] - ca[x]})" for x in sorted(cb) if cb[x] > ca[x]]
    d += [f"nat_postrouting: extra {x!r} (x{ca[x] - cb[x]})" for x in sorted(ca) if ca[x] > cb[x]]
    if not d:
        d.append(f"nat_postrouting: same rules, different order: {list(bn)!r} -> {list(an)!r}")
    return d


def dynamic_changes(before, after):
    b, a = before["neigh_dynamic"], after["neigh_dynamic"]
    return [f"neigh_dynamic {k[0]} dev {k[1]}: {b.get(k)!r} -> {a.get(k)!r}"
            for k in sorted(set(b) | set(a)) if b.get(k) != a.get(k)]


def _link_cmds(iface, before, now):
    if now["mac"] != before["mac"]:
        return ([f"ip link set dev {iface} down", f"ip link set dev {iface} address {before['mac']}"]
                + ([f"ip link set dev {iface} up"] if before["admin_up"] else []))   # 06B-4IR3: back to admin state
    if now["admin_up"] is not before["admin_up"]:          # 06B-4IR3: restore the recorded administrative state
        return [f"ip link set dev {iface} {'up' if before['admin_up'] else 'down'}"]
    if now["operstate"] != before["operstate"] and before["operstate"] in ("up", "unknown"):
        return [f"ip link set dev {iface} up"]
    return []


def _addr_cmds(iface, before, now):
    b, a = set(before["addrs"]), set(now["addrs"])
    return ([f"ip addr del {x} dev {iface}" for x in sorted(a - b)]
            + [f"ip addr add {x} brd + dev {iface}" for x in sorted(b - a)])


def _route_cmds(iface, before, now):
    b, a = set(before["routes"]), set(now["routes"])
    return [f"ip route del {x}" for x in sorted(a - b)] + [f"ip route add {x}" for x in sorted(b - a)]


def _neigh_cmds(iface, before, now):
    b, a = before["neigh_static"], now["neigh_static"]
    out = []
    for (ip, dev) in sorted(set(a) - set(b)):
        out.append(f"arp -i {dev} -d {ip}")
    for (ip, dev), mac in sorted(b.items()):
        if a.get((ip, dev)) != mac:
            if (ip, dev) in a:
                out.append(f"arp -i {dev} -d {ip}")
            out.append(f"arp -i {dev} -s {ip} {mac}")
    return out


def _sysctl_cmds(iface, before, now):
    if now["arp_notify"] != before["arp_notify"]:
        return [f"echo {before['arp_notify']} > /proc/sys/net/ipv4/conf/{iface}/arp_notify"]
    return []


def nat_extra_positions(before, now):
    """R6: positions (1-based rule numbers, ascending) of the rules in `now` that are not part of `before`, or None when `before` is not an ordered
    subsequence of `now` (a rule was removed/reordered/the policy changed: nothing may be 'restored' by deleting)."""
    if not before or not now or before[0] != now[0]:
        return None
    rb, rn = before[1:], now[1:]
    extra, i = [], 0
    for pos, rule in enumerate(rn, 1):
        if i < len(rb) and rule == rb[i]:
            i += 1
        else:
            extra.append(pos)
    return extra if i == len(rb) else None


def _nat_cmds(iface, before, now, owned=None):
    """R6: delete (by rule number, highest first) only the rules that were ADDED: `before` must be an ordered subsequence of `now`. `owned` (list of
    `-A POSTROUTING ...` texts the case inserted, as a multiset) limits what may be deleted: an extra rule that the case does not own is never
    touched (no command at all: diff() keeps it and `restored` stays False). owned=None: no ownership filter (unit tests)."""
    if "nat_postrouting" not in before or "nat_postrouting" not in now:
        return []
    b, n = before["nat_postrouting"], now["nat_postrouting"]
    pos = nat_extra_positions(b, n)
    if not pos:
        return []
    if owned is not None:
        rest = list(owned)
        for p in pos:
            r = n[p]                      # n[0] is the policy line: rule number p is n[p]
            if r not in rest:
                return []
            rest.remove(r)
    return [f"iptables -t nat -D POSTROUTING {p}" for p in sorted(pos, reverse=True)]


STEPS = (("link", _link_cmds), ("addrs", _addr_cmds), ("routes", _route_cmds),
         ("neigh_static", _neigh_cmds), ("arp_notify", _sysctl_cmds), ("nat", _nat_cmds))


def restore(runner, iface, before, timeout=30, owned_nat=None):
    """Bring IF back to `before`. Never raises for a failed command: every command and its rc is
    recorded, and only the final re-read decides `restored`. A state read error -> restored False."""
    _check_iface(iface)
    log = {"commands": [], "restored": False, "diffs": [], "dynamic_changes": [], "error": None}
    nat = "nat_postrouting" in before
    try:
        for name, fn in STEPS:
            now = read_state(runner, iface, timeout, nat=nat)
            for cmd in (_nat_cmds(iface, before, now, owned_nat) if name == "nat" else fn(iface, before, now)):
                rc, out = runner.run(cmd, timeout=timeout)
                log["commands"].append({"step": name, "cmd": cmd, "rc": rc, "out": out.strip()[-300:]})
        after = read_state(runner, iface, timeout, nat=nat)
    except StateReadError as e:
        log["error"] = f"state read failed: {e}"
        return log
    log["after"] = after
    log["diffs"] = diff(before, after)
    log["dynamic_changes"] = dynamic_changes(before, after)
    log["restored"] = not log["diffs"]
    return log


class GuestChange:
    """with GuestChange(runner, iface) as rec:  ...probe that changes the guest...
    Records the before-state on entry and always restores on exit (also after an exception).
    rec["restore"]["restored"] False means: the caller must not run further probes on this guest."""

    def __init__(self, runner, iface, timeout=30, nat=False, owned_nat=None):
        self.runner, self.iface, self.timeout, self.nat, self.owned_nat = runner, iface, timeout, nat, owned_nat
        self.rec = {"iface": iface, "before": None, "restore": None}

    def __enter__(self):
        self.rec["before"] = read_state(self.runner, self.iface, self.timeout, nat=self.nat)
        return self.rec

    def __exit__(self, *exc):
        self.rec["restore"] = restore(self.runner, self.iface, self.rec["before"], self.timeout, owned_nat=self.owned_nat)
        return False
