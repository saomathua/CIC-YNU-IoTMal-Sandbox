#!/bin/bash
# 06B-3B — independent re-check of a finished run, using only the host's tcpdump and python3
# (not the harness's tshark/classifier). Read-only; needs no root.
#
#   bash independent_check.sh <run-dir>     e.g. out-run5
#
# 1. tap0 pcap (per arch): guest->destination packets per probe, keyed by the probe's fixed source
#    port 41000+n; replies to the guest; the guest DNS probe qname.
# 2. host pcaps (veth, bridge, ens33): guest MAC / 10.200.0.0/30 / ARP for 10.200.0.2, probe source
#    ports 41000-41020, the guest probe qname and the probe URL path. All must be 0.
# 3. ctl.jsonl: failures and longest gap between successful controls per target.
# Every tcpdump read is exit-code checked; a read error aborts instead of counting as 0.
set -uo pipefail
R=${1:?run dir}
rd() {  # file filter... -> packet lines; abort on tcpdump error
    local f=$1; shift; local out
    out=$(tcpdump -n "$@" -r "$f" 2>/dev/null) || { echo "READ ERROR: $f $*" >&2; exit 2; }
    printf '%s' "$out"
}
cnt() { local o; o=$(rd "$@") || exit 2; [ -z "$o" ] && echo 0 || printf '%s\n' "$o" | grep -c .; }

echo "== 1. tap0 pcaps"
for A in ARM MIPS; do
    P=$R/container/probe/$A/tap0.pcapng
    echo "-- $A ($(cnt "$P" "") frames)"
    n=0
    for spec in "internet-tcp 1.1.1.1 443" "lan-dns-udp 192.168.177.2 53" "lan-dns-tcp 192.168.177.2 53" \
                "ssh-host-192.168.60.1 192.168.60.1 22" "ssh-host-192.168.177.128 192.168.177.128 22" \
                "ssh-host-172.18.0.1 172.18.0.1 22" "manager 192.168.60.10 8011" "mongodb 172.18.0.2 27017" \
                "worker-eth0 192.168.60.2 8011" "tap0-other-port-listener 10.200.0.1 18080"; do
        set -- $spec; lp=$((41000 + n)); n=$((n + 1))
        if [ "$1" = lan-dns-udp ]; then
            out=$(cnt "$P" "src host 10.200.0.2 and dst host $2 and udp dst port $3")
            back=$(cnt "$P" "dst host 10.200.0.2 and src host $2 and udp src port $3")
            echo "$1: guest->$2:$3/udp=$out replies-to-guest=$back"
        else
            out=$(cnt "$P" "src host 10.200.0.2 and src port $lp and dst host $2 and tcp dst port $3")
            other=$(cnt "$P" "src host 10.200.0.2 and not src port $lp and dst host $2 and tcp dst port $3")
            back=$(cnt "$P" "dst host 10.200.0.2 and src host $2 and tcp src port $3")
            echo "$1: guest:$lp->$2:$3/tcp=$out (other src ports=$other) replies-to-guest=$back"
        fi
    done
    echo "IPv4 to guest from anything but 10.200.0.1: $(cnt "$P" "ip and dst host 10.200.0.2 and not src host 10.200.0.1")"
    o=$(rd "$P" -A "") || exit 2
    echo "guest probe qname lines: $(printf '%s\n' "$o" | grep -c "ct01-06b3b-probe-")"
done

echo "== 2. host pcaps"
for f in veth bridge ens33; do
    P=$R/hostcap/$f.pcap
    o=$(rd "$P" -A "") || exit 2
    echo "$f: frames=$(cnt "$P" "")" \
         "mac/net/arp=$(cnt "$P" "ether host 52:54:00:c7:00:02 or net 10.200.0.0/30 or arp host 10.200.0.2")" \
         "probe-src-ports=$(cnt "$P" "tcp portrange 41000-41020 or udp portrange 41000-41020")" \
         "probe-qname=$(printf '%s\n' "$o" | grep -c 'ct01-06b3b-probe-')" \
         "probe-url=$(printf '%s\n' "$o" | grep -cE '/ct01-06b3b-[0-9]')" \
         "control-qname=$(printf '%s\n' "$o" | grep -c 'ct01-06b3b-ctl-')"
done

echo "== 3. control log"
python3 - "$R/ctl/ctl.jsonl" <<'EOF'
import collections, json, sys, time
rows = [json.loads(l) for l in open(sys.argv[1])]
by = collections.defaultdict(list)
for r in rows:
    by[r["target"]].append(r)
hm = lambda t: time.strftime("%H:%M:%S", time.gmtime(t))
for t, rs in by.items():
    oks = [r["ts"] for r in rs if r["ok"]]
    bad = [hm(r["ts"]) + " " + r["detail"] for r in rs if not r["ok"]]
    gap = max(b - a for a, b in zip(oks, oks[1:]))
    print(f"{t}: n={len(rs)} ok={len(oks)} fail={len(bad)} {bad} "
          f"span={hm(rs[0]['ts'])}-{hm(rs[-1]['ts'])} max_gap_between_ok={gap:.2f}s")
EOF
