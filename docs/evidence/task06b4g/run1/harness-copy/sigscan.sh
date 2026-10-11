#!/bin/bash
# 06B-3C — leak-signature scanner for one pcap/pcapng file. Read-only, needs no root.
#
#   bash sigscan.sh <pcap>        prints key=value lines, exit 0
#                                 exit 2 on any read problem (tcpdump error, truncated/empty file)
#
# Counts are PACKETS (not output lines):
#   frames         all frames
#   guest_l2l3     guest MAC, 10.200.0.0/30, or ARP for 10.200.0.2           (BPF)
#   probe_sport    TCP/UDP port 41000-41020 (probe source ports)              (BPF)
#   probe_qname    DNS name ct01-06b3b-probe-<arch>-<n>                       (payload)
#   probe_url      URL path /ct01-06b3b-<probe name> of probe_matrix.py      (payload)
#   control_qname  DNS name ct01-06b3b-ctl-<arch> (controls; expected > 0 on ens33, proves the
#                  payload scan sees real traffic)
# 06B-3B used /ct01-06b3b-[0-9], which never matched: probe names are words such as internet-tcp.
set -uo pipefail
F=${1:?pcap}
GUEST_MAC=52:54:00:c7:00:02
# Probe names exactly as in probe_matrix.py's plan; ssh-host-<IPv4> carries dots.
NAMES='internet-tcp|lan-dns-udp|lan-dns-tcp|ssh-host-[0-9]{1,3}(\.[0-9]{1,3}){3}|manager|mongodb|worker-eth0|tap0-other-port-listener'
URL_RE="/ct01-06b3b-($NAMES)([^A-Za-z0-9.-]|\$)"
QNAME_RE='ct01-06b3b-probe-(arm|mips)-[0-9]+'
CTL_RE='ct01-06b3b-ctl-(arm|mips)'

ERR=$(mktemp); trap 'rm -f "$ERR"' EXIT
rd() {  # filter -> tcpdump output; exit 2 on error or any stderr other than the banner
    local out rc
    out=$(tcpdump -n -tt "$@" -r "$F" 2>"$ERR"); rc=$?
    if [ $rc -ne 0 ] || grep -qv '^reading from file ' "$ERR"; then
        echo "READ ERROR rc=$rc file=$F: $(tr '\n' ' ' < "$ERR")" >&2; exit 2
    fi
    printf '%s' "$out"
}
pkts() { local o; o=$(rd "$@") || exit 2; [ -z "$o" ] && echo 0 || printf '%s\n' "$o" | grep -c .; }
# -A output: a packet starts with an epoch timestamp line. Join each packet onto one line
# (tab-separated) so that grep -c counts packets, not lines.
per_packet() { awk '/^[0-9]+\.[0-9][0-9][0-9][0-9][0-9][0-9] / { if (p != "") print p; p = $0; next } { p = p "\t" $0 } END { if (p != "") print p }'; }

[ -s "$F" ] || { echo "READ ERROR: $F is empty or missing" >&2; exit 2; }
v=$(pkts) || exit 2; echo "frames=$v"
v=$(pkts "ether host $GUEST_MAC or net 10.200.0.0/30 or arp host 10.200.0.2") || exit 2; echo "guest_l2l3=$v"
v=$(pkts "tcp portrange 41000-41020 or udp portrange 41000-41020") || exit 2; echo "probe_sport=$v"
A=$(rd -A) || exit 2
P=$(printf '%s\n' "$A" | per_packet)
echo "probe_qname=$(printf '%s\n' "$P" | grep -cE "$QNAME_RE")"
echo "probe_url=$(printf '%s\n' "$P" | grep -cE "$URL_RE")"
echo "control_qname=$(printf '%s\n' "$P" | grep -cE "$CTL_RE")"
