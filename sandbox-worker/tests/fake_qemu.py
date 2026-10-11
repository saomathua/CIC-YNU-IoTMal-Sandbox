"""Stand-in for qemu-system-* used by tests (never boots anything).

Prints the console prompts analysis.py waits for and answers each input line
with a shell prompt. Behaviour on SIGINT is controlled by flags:
  --ignore-sigint       keep running after SIGINT (only SIGKILL stops it)
  --exit-delay SECONDS  exit this long after SIGINT
  --no-boot-prompt      never print the boot prompt (boot timeout path)
  --pidfile PATH        write own pid (lets tests check the process is gone)
"""
import argparse
import signal
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("--ignore-sigint", action="store_true")
p.add_argument("--exit-delay", type=float, default=0.0)
p.add_argument("--no-boot-prompt", action="store_true")
p.add_argument("--pidfile")
a, _ = p.parse_known_args()

if a.pidfile:
    with open(a.pidfile, "w") as f:
        f.write(str(__import__("os").getpid()))


def on_sigint(signum, frame):
    if a.ignore_sigint:
        return
    time.sleep(a.exit_delay)
    sys.exit(0)


signal.signal(signal.SIGINT, on_sigint)

if a.no_boot_prompt:
    while True:
        time.sleep(1)

print("Please press Enter to activate this console.", flush=True)
first = True
for line in sys.stdin:
    print("root@OpenWrt:/# ", end="", flush=True)
    if first:   # like the real guest: network-ready kernel message after the first prompt
        time.sleep(0.1)
        print("\nbr-lan: port 1(eth0) entered forwarding state", flush=True)
        first = False
