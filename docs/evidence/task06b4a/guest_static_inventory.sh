#!/bin/bash
# 06B-4A: STATIC, read-only inventory of the stock guest images (no QEMU, no mount, no root).
# Unzips sandbox-worker/<ARCH>/image.zip into a scratch dir and reads the ext4 rootfs with debugfs.
#   bash guest_static_inventory.sh <repo> <scratch-dir>
set -uo pipefail
REPO=${1:?repo}; S=${2:?scratch}
for a in ARM MIPS; do
    Z=$REPO/sandbox-worker/$a/image.zip
    echo "===== $a  $(sha256sum "$Z" | cut -d' ' -f1)  image.zip"
    rm -rf "$S/$a"; mkdir -p "$S/$a"; unzip -q -o "$Z" -d "$S/$a" || { echo "UNZIP ERROR"; exit 2; }
    R=$S/$a/image/root.ext4
    echo "-- /etc/openwrt_release"; debugfs -R 'cat /etc/openwrt_release' "$R" 2>/dev/null | grep -E 'DISTRIB_(RELEASE|REVISION|TARGET|ARCH)'
    for d in /bin /sbin /usr/bin /usr/sbin; do
        echo "-- ls $d"; debugfs -R "ls -p $d" "$R" 2>/dev/null | awk -F/ 'NF>5 && $6!="." && $6!=".."{print $6}' | tr '\n' ' '; echo
    done
    echo "-- link targets"
    for f in /sbin/ip /bin/ping /bin/ping6 /usr/bin/nc /sbin/ifconfig /sbin/route /sbin/sysctl /sbin/udhcpc /usr/bin/curl /usr/sbin/dropbear; do
        t=$(debugfs -R "stat $f" "$R" 2>/dev/null | grep -oE 'Type: [a-z]+|Fast link dest: "[^"]*"' | tr '\n' ' ')
        echo "$f: ${t:-absent}"
    done
    debugfs -R 'dump /bin/busybox '"$S/$a/busybox" "$R" 2>/dev/null
    echo "-- busybox applet names (heuristic: NUL-delimited strings in /bin/busybox; confirm with 'busybox --list' at runtime)"
    python3 - "$S/$a/busybox" <<'PY'
import re, sys
d = open(sys.argv[1], "rb").read()
v = re.search(rb"BusyBox v[0-9.]+[^\x00]*", d)
print("version:", v.group(0).decode(errors="replace")[:60] if v else None)
names = set(x.decode() for x in re.findall(rb"(?<=\x00)([a-z0-9_.\[-]{1,20})(?=\x00)", d))
for n in ["arping", "arp", "ether-wake", "ping", "ping6", "nc", "ip", "ifconfig", "route", "udhcpc", "brctl", "nslookup", "traceroute6", "vconfig"]:
    print(f"  {n}: {'present' if n in names else 'not found'}")
PY
    echo "-- /etc/rc.d"; debugfs -R 'ls -p /etc/rc.d' "$R" 2>/dev/null | awk -F/ 'NF>5 && $6!="." && $6!=".."{print $6}' | tr '\n' ' '; echo
    for c in network dropbear uhttpd; do
        echo "-- /etc/config/$c"; debugfs -R "cat /etc/config/$c" "$R" 2>/dev/null | grep -vE '^\s*(#|$)' || echo "(absent)"
    done
    echo "-- /etc/config/firewall (defaults and zones)"
    debugfs -R 'cat /etc/config/firewall' "$R" 2>/dev/null | awk '/^config (defaults|zone)/{p=1} /^config (rule|forwarding|include|redirect)/{p=0} p' | grep -vE '^\s*(#|$)'
    rm -rf "$S/$a"
done
