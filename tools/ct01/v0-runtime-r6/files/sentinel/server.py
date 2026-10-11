"""06B-2A SENTINEL replacing /app/server.py. Records that it was called; starts no server."""
import datetime, os, signal, sys, time
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
with open(os.path.join("/sentinel-out", "server-called"), "a") as f:
    f.write(f"{datetime.datetime.utcnow().isoformat()}Z pid={os.getpid()}\n")
print("SENTINEL server.py called (no real server started)", flush=True)
while True:
    time.sleep(3600)
