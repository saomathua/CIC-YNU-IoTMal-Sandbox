import signal, sys, time
mode = sys.argv[1]   # ok: exit 0 shortly after SIGINT | rc3: exit 3 on SIGINT | ignore: ignore SIGINT
def on_int(*a):
    if mode == "ignore":
        return
    time.sleep(0.3)
    sys.exit(3 if mode == "rc3" else 0)
signal.signal(signal.SIGINT, on_int)
while True:
    time.sleep(0.05)
