"""06B-2A SENTINEL replacing /app/poller.py. Records that it was called and keeps
the container alive for inspection; imports and runs no analysis code."""
import datetime, os, signal, sys, time
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
with open(os.path.join("/sentinel-out", "poller-called"), "a") as f:
    f.write(f"{datetime.datetime.utcnow().isoformat()}Z pid={os.getpid()}\n")
print("SENTINEL poller.py called (no real poller started)", flush=True)
while True:
    time.sleep(3600)
