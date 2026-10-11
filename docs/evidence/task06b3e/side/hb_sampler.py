"""06B-3D — read-only side sampler (runs as the normal user, NOT part of the harness).

Every second, while run-06b3b.sh runs, records into <outfile> (TSV):
  wall time, current harness step (last "=====" line of out/run.log), heartbeat value and age,
  capture-dead marker size, and the capture / QEMU processes visible on the host.
It only reads files under ct01-06b3c/out and /proc; it never writes there and never signals anything.
Stops when run.log shows "===== result", when out/ disappears after having existed, or after 60 min.

  python3 hb_sampler.py /home/dathq/projects/ct01-06b3c/out <outfile>
"""
import os
import re
import sys
import time

OUT, DEST = sys.argv[1], sys.argv[2]
HB = os.path.join(OUT, "hostcap", "capture-watch.heartbeat")
DEAD = os.path.join(OUT, "hostcap", "capture-dead.txt")
LOG = os.path.join(OUT, "run.log")


def procs():
    names = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            comm = open(f"/proc/{pid}/comm").read().strip()
            state = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if comm in ("tcpdump", "tshark", "dumpcap") or comm.startswith("qemu-system"):
            names[comm] = names.get(comm, 0) + 1
            if state == "Z":
                names[comm + "(Z)"] = names.get(comm + "(Z)", 0) + 1
    return ",".join(f"{k}={v}" for k, v in sorted(names.items())) or "-"


def step():
    try:
        lines = [l for l in open(LOG, errors="replace") if l.startswith("=====")]
        return re.sub(r"\s+", " ", lines[-1].strip()) if lines else "-"
    except OSError:
        return "-"


start = time.time()
seen_out = False
with open(DEST, "a", buffering=1) as f:
    f.write("wall_utc\tstep\theartbeat\tage_s\tdead_marker_bytes\tprocs\n")
    while time.time() - start < 3600:
        now = time.time()
        try:
            hb = open(HB).read().strip()
            age = f"{now - float(hb):.2f}"
        except (OSError, ValueError) as e:
            hb, age = "-", type(e).__name__
        try:
            dead = str(os.path.getsize(DEAD))
        except OSError:
            dead = "-"
        st = step()
        seen_out = seen_out or os.path.isdir(OUT)
        f.write(f"{time.strftime('%H:%M:%S', time.gmtime(now))}\t{st}\t{hb}\t{age}\t{dead}\t{procs()}\n")
        if st.startswith("===== result") or (seen_out and not os.path.isdir(OUT)):
            break
        time.sleep(1)
