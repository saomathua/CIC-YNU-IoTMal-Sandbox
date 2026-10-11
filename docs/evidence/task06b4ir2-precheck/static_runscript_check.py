#!/usr/bin/env python3
"""06B-4IR2 precheck (read only): what run-06b4i.sh needs, checked statically against the working copy and the host
PATH. Executes nothing from the run script."""
import os, re, shutil, sys
H = "/home/dathq/projects/ct01-06b4ir2"
s = open(os.path.join(H, "run-06b4i.sh")).read()
code = "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))
out = []
def item(name, ok, detail=""):
    out.append(f"[{'OK ' if ok else 'BAD'}] {name}" + (f" — {detail}" if detail else ""))
m = re.search(r"^H=(\S+)$", s, re.M); item("H points to the 06B-4IR2 working copy", m and m.group(1) == H, m and m.group(1))
m = re.search(r"^EXPECTED_IMAGE_ID=(\S+)$", s, re.M); item("expected image id pinned", bool(m), m and m.group(1))
m = re.search(r"^IMAGE=(\S+)$", s, re.M); item("image name", bool(m), m and m.group(1))
for var in ("NAME", "CTL", "MANAGER", "GUEST_MAC", "LAN_DNS", "REPO"):
    m = re.search(rf"^{var}=(\S+)$", s, re.M); item(f"{var} set", bool(m), m and m.group(1))
copy = sorted(set(re.findall(r'"\$H/([\w./-]+)"', s.split('"$OUT/harness-copy/"')[0])))
miss = [f for f in copy if not os.path.isfile(os.path.join(H, f))]
item(f"harness-copy list: {len(copy)} files exist in H", not miss, f"missing {miss}" if miss else "")
mounts = sorted(set(re.findall(r'-v "\$H/([\w./-]+):(/[\w./-]+):ro"', s)))
miss = [f for f, _ in mounts if not os.path.isfile(os.path.join(H, f))]
item(f"read-only mounts: {len(mounts)} sources exist in H", not miss, ", ".join(f"{a}->{b}" for a, b in mounts))
selftests = re.findall(r'python3 "\$H/(selftest[\w]*\.py)"', code) + re.findall(r'bash "\$H/(selftest\.sh)"', code)
item("self-tests run before docker exist", all(os.path.isfile(os.path.join(H, f)) for f in selftests), " ".join(selftests))
calls = [l.strip() for l in code.splitlines() if "probe_matrix.py $ARCH" in l]
item("exactly one probe_matrix call, CT01_SUITE=arp", len(calls) == 1 and "CT01_SUITE=arp" in calls[0])
item("ctl started with --arp-worker", "/ctl/ctl.jsonl --arp-worker)" in code)
item("CTL_MAC from docker inspect on sandboxnet; manager_mac and ctl_mac in CT01_TARGETS",
     'CTL_MAC=$(docker inspect' in code and '"manager_mac":"%s","ctl_mac":"%s"' in code)
item("outcome/run-check through arp_harness.py", 'arp_harness.py" --outcome' in code and 'arp_harness.py" --run-check' in code)
for d in ("sentinel/poller.py",):
    item(f"{d} exists", os.path.isfile(os.path.join(H, d)))
tools = ["docker", "python3", "tcpdump", "nft", "sysctl", "ip", "ss", "pgrep", "lsmod", "journalctl", "timeout", "git",
         "sha256sum", "diff", "awk", "mktemp", "tee"]
for t in tools:
    p = shutil.which(t) or (shutil.which(t, path="/usr/sbin:/sbin") if t in ("nft", "sysctl", "lsmod") else None)
    item(f"host executable {t}", bool(p), p or "not found on PATH (root PATH may differ)")
item("output dir absent (run script aborts if it exists)", not os.path.exists(os.path.join(H, "out")))
item("repo docker-compose.yml present", os.path.isfile("/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/docker-compose.yml"))
files = "run.sh server.py service/analysis.py isolation/apifilter.py isolation/verify.py isolation/guest.nft isolation/expected-ruleset.json ARM/image.zip MIPS/image.zip".split()
miss = [f for f in files if not os.path.isfile(os.path.join("/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/sandbox-worker", f))]
item("worker files hashed by the run script exist in the working tree", not miss, f"missing {miss}" if miss else "")
print("\n".join(out))
sys.exit(0 if all(l.startswith("[OK") for l in out) else 1)
