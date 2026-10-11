#!/usr/bin/python3
"""06B-4IR3 precheck COLLECTOR (PC-2, PC-4) — read only. Prepared and tested offline; NOT run by Claude.

It collects; it never concludes. evaluate_precheck.py (run later as a normal user, offline) turns the collected data
into PASS / FAIL / UNKNOWN items. "Collector finished" or "output written" is NOT a passed precheck.

Run only through the trusted procedure in RUN-PROCEDURE.md: root copies THIS file into a fresh root-owned mkdtemp
directory, checks its SHA-256 there, and runs that copy with a fixed minimal environment:
    /usr/bin/python3 -I -B <root-owned copy>/collector.py <root-owned, empty, mode 0700 output directory>

What it does (nothing else):
  * docker: version, info (selected fields), image id of sandbox-worker:latest, `ps -a` (one listing used for every
    presence decision), compose networks sandboxnet/dbnet resolved by label (exactly one each, else not inspected),
    inspect of those networks, of the manager and of mongo-db (selected fields; never Config.Env), and — only if the
    manager is ALREADY running according to a successful inspect — `docker exec` of read-only commands in it;
  * host: pgrep for qemu/capture processes, `nft -s list ruleset`, `aa-status`.
  * It starts/stops/creates nothing, pulls/builds nothing, changes no network or ruleset, sends nothing to a guest.

Every read keeps argv, rc, stdout and stderr (files) and a status: OK | NONZERO (rc not accepted for that read) |
EXEC_ERROR | TIMEOUT | SKIPPED (with the reason). A failed read is never turned into "absent" / "not running".
Exit code: 0 = every REQUIRED read has status OK (data complete; still not a verdict); 3 = at least one required read
did not succeed (data incomplete); 2 = refused before collecting (not root, output directory unsafe, executable
untrusted).
"""
import json
import os
import stat
import subprocess
import sys
import time

EXPECTED_IMAGE_ID = "sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153"
IMAGE = "sandbox-worker:latest"
MANAGER = "cic-ynu-iotmal-sandbox-sandbox-manager-1"
MONGO = "mongo-db"
HARNESS_CONTAINERS = ("ct01-06b3b-guest", "ct01-06b3b-ctl")
NETWORK_LABELS = {"sandboxnet": "com.docker.compose.network=sandboxnet", "dbnet": "com.docker.compose.network=dbnet"}
BINS = {"docker": "/usr/bin/docker", "pgrep": "/usr/bin/pgrep", "nft": "/usr/sbin/nft", "aa-status": "/usr/sbin/aa-status"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}   # nothing inherited
TIMEOUT_S = 60
SCHEMA = "ct01-precheck-collector/1"


class Refused(Exception):
    """Collection refused before any read (exit 2)."""


# ------------------------------------------------------------------ output directory (PC-4)
def prepare_outdir(path, owner_uid=0):
    """Open the output directory WITHOUT following a symlink and check it is a real, empty directory owned by
    owner_uid with no group/other permission. Returns its fd; every file is then created relative to that fd."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise Refused(f"output directory {path!r} not openable as a real directory (symlink?): {e}")
    st = os.fstat(fd)
    problems = []
    if st.st_uid != owner_uid:
        problems.append(f"owned by uid {st.st_uid}, expected {owner_uid}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        problems.append(f"mode {stat.S_IMODE(st.st_mode):o} gives group/other access (expected 0700)")
    if os.listdir(fd):
        problems.append("not empty")
    if problems:
        os.close(fd)
        raise Refused(f"output directory {path!r} unsafe: {'; '.join(problems)}")
    return fd


def write_new(dfd, name, data):
    """Create a NEW file in the output directory (O_EXCL | O_NOFOLLOW, mode 0600): an existing name or a planted
    symlink makes it fail instead of writing elsewhere."""
    if "/" in name or name in (".", ".."):
        raise ValueError(f"bad output name {name!r}")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def trusted_bins(bins=BINS, owner_uid=0):
    """Every executable used: an absolute path to a regular file owned by owner_uid, not group/other-writable, in a
    directory with the same properties. -> list of problems (empty = trusted)."""
    p = []
    for name, path in bins.items():
        if not os.path.isabs(path):
            p.append(f"{name}: {path!r} is not absolute")
            continue
        for target in (path, os.path.dirname(path)):
            try:
                st = os.stat(target)          # the binary itself may be a root-owned symlink (e.g. /usr/sbin/nft)
            except OSError as e:
                p.append(f"{name}: {target}: {e}")
                break
            if st.st_uid != owner_uid or st.st_mode & 0o022:
                p.append(f"{name}: {target} owned by uid {st.st_uid} with mode {stat.S_IMODE(st.st_mode):o}")
        else:
            if not stat.S_ISREG(os.stat(path).st_mode):
                p.append(f"{name}: {path} is not a regular file")
    return p


# ------------------------------------------------------------------ reads
def subprocess_runner(argv):
    """-> (rc, stdout bytes, stderr bytes, error) with the fixed environment; never a shell."""
    try:
        r = subprocess.run(argv, env=dict(ENV), stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_S)
        return r.returncode, r.stdout, r.stderr, None
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or b"", e.stderr or b"", "TIMEOUT"
    except OSError as e:
        return None, b"", b"", f"EXEC_ERROR: {type(e).__name__}: {e}"


class Collector:
    def __init__(self, dfd, runner, bins=BINS):
        self.dfd, self.runner, self.bins, self.reads, self.n = dfd, runner, bins, [], 0

    def read(self, name, argv, required=True, ok_rcs=(0,)):
        self.n += 1
        rc, out, err, error = self.runner(argv)
        status = "OK" if error is None and rc in ok_rcs else (error.split(":")[0] if error else "NONZERO")
        base = f"{self.n:02d}-{name}"
        write_new(self.dfd, base + ".stdout", out)
        write_new(self.dfd, base + ".stderr", err)
        r = {"name": name, "argv": argv, "required": required, "rc": rc, "status": status, "error": error,
             "ok_rcs": list(ok_rcs), "stdout_file": base + ".stdout", "stderr_file": base + ".stderr",
             "stdout": out.decode(errors="replace")}
        self.reads.append(r)
        return r

    def skip(self, name, reason, required=True):
        r = {"name": name, "argv": None, "required": required, "rc": None, "status": "SKIPPED", "error": reason,
             "stdout": ""}
        self.reads.append(r)
        return r


def collect(dfd, runner, bins=BINS, clock=time.time):
    c = Collector(dfd, runner, bins)
    d = bins["docker"]
    t0 = clock()
    c.read("docker-version", [d, "version", "--format", "client={{.Client.Version}} server={{.Server.Version}} api={{.Server.APIVersion}}"])
    c.read("docker-info", [d, "info", "--format", "driver={{.Driver}} cgroup={{.CgroupDriver}}/{{.CgroupVersion}} "
                           "kernel={{.KernelVersion}} os={{.OperatingSystem}} running={{.ContainersRunning}}"])
    c.read("image-id", [d, "image", "inspect", "--format", "{{.Id}}", IMAGE])
    ps = c.read("ps-all", [d, "ps", "-a", "--no-trunc", "--format", "{{.Names}}\t{{.State}}\t{{.Image}}\t{{.ID}}"])
    nets = {}
    for net, label in NETWORK_LABELS.items():
        r = c.read(f"network-ls-{net}", [d, "network", "ls", "--no-trunc", "--filter", f"label={label}",
                                          "--format", "{{.ID}}\t{{.Name}}"])
        names = [l.split("\t") for l in r["stdout"].splitlines() if l.strip()]
        if r["status"] != "OK":
            c.skip(f"network-inspect-{net}", f"network list for {net} not read ({r['status']})")
        elif len(names) != 1:
            c.skip(f"network-inspect-{net}", f"{len(names)} networks carry {label}: exactly one required")
        else:
            nets[net] = names[0][-1]
            c.read(f"network-inspect-{net}", [d, "network", "inspect", "--format",
                                               "{{.Id}}\t{{.Name}}\t{{.Driver}}\t{{.Internal}}\t{{json .IPAM.Config}}\t"
                                               "{{json .Containers}}", names[0][0]])
    for who, name in (("manager", MANAGER), ("mongo", MONGO)):
        c.read(f"inspect-{who}", [d, "inspect", "--type", "container", "--format",
                                  "{{.State.Status}}\t{{.Id}}\t{{.RestartCount}}\t{{.State.StartedAt}}\t"
                                  "{{json .NetworkSettings.Networks}}", name])
    m = next(r for r in c.reads if r["name"] == "inspect-manager")
    running = m["status"] == "OK" and m["stdout"].split("\t", 1)[0].strip() == "running"
    exec_cmds = (("manager-ip-version", ["sh", "-c", "command -v ip && ip -V"]),
                 ("manager-ip-j-neigh", ["ip", "-j", "neigh", "show"]),
                 ("manager-proc-net-arp", ["cat", "/proc/net/arp"]),
                 ("manager-sys-class-net", ["sh", "-c", 'for i in /sys/class/net/*; do echo "$(basename $i) '
                                                         '$(cat $i/address) $(cat $i/operstate)"; done']))
    for name, cmd in exec_cmds:
        if running:
            c.read(name, [d, "exec", MANAGER] + cmd, required=False)
        else:
            c.skip(name, "manager not running according to a successful inspect" if m["status"] == "OK"
                   else f"manager state unknown (inspect {m['status']}): no exec", required=False)
    c.read("pgrep-qemu", [bins["pgrep"], "-a", "qemu-system"], ok_rcs=(0, 1))       # 1 = no process
    c.read("pgrep-capture", [bins["pgrep"], "-a", "tcpdump|tshark|dumpcap"], ok_rcs=(0, 1))
    c.read("nft-ruleset", [bins["nft"], "-s", "list", "ruleset"])
    c.read("aa-status", [bins["aa-status"]])
    complete = all(r["status"] == "OK" for r in c.reads if r["required"])
    meta = {"schema": SCHEMA, "t_start": t0, "t_end": clock(), "expected_image_id": EXPECTED_IMAGE_ID,
            "image": IMAGE, "manager": MANAGER, "mongo": MONGO, "harness_containers": list(HARNESS_CONTAINERS),
            "networks_resolved": nets, "bins": bins, "env": ENV, "data_complete": complete,
            "note": "collector output, NOT a precheck verdict: run evaluate_precheck.py"}
    write_new(dfd, "reads.json", json.dumps({"meta": meta, "reads": c.reads}, indent=1, ensure_ascii=False))
    return 0 if complete else 3


def main(argv):
    if len(argv) != 1:
        print("usage: collector.py <root-owned empty 0700 output directory>", file=sys.stderr)
        return 2
    try:
        if os.geteuid() != 0:
            raise Refused("must run as root (Docker daemon, nft, aa-status)")
        bad = trusted_bins()
        if bad:
            raise Refused("untrusted executable(s): " + "; ".join(bad))
        dfd = prepare_outdir(argv[0])
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    rc = collect(dfd, subprocess_runner)
    # readable by the user afterwards (no secret is collected); changed through the fd, never through a path
    for name in os.listdir(dfd):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        os.fchmod(fd, 0o644)
        os.close(fd)
    os.fchmod(dfd, 0o755)
    print(f"collector finished, exit {rc} ({'data complete' if rc == 0 else 'DATA INCOMPLETE'}); this is NOT a "
          "precheck verdict: run evaluate_precheck.py on the copied output")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
