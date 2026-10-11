"""06B-4BR repro (offline): the reviewer's case. One IPv4 ICMP echo with a 1705-byte payload, after NAT
(MAC/IP no longer the guest's), written twice: full, and cut to 512 bytes by snaplen with the original
length kept. Runs sigscan_l2.scan() of the harness directory given as argv[1]."""
import os, struct, sys, tempfile, ipaddress
sys.path.insert(0, sys.argv[1])
import sigscan_l2 as SL

def csum(b):
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\xab" * 1705
h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 63, 1, 0,
                ipaddress.IPv4Address("192.168.177.128").packed, ipaddress.IPv4Address("1.1.1.1").packed)
h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
frame = bytes.fromhex("005056e00001000c2942ad4c0800") + h + icmp   # NATed: host MAC/IP on ens33
def pcap(path, data, orig):
    open(path, "wb").write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 512, 1)
                           + struct.pack("<IIII", 100, 0, len(data), orig) + data)
d = tempfile.mkdtemp()
pcap(os.path.join(d, "full.pcap"), frame, len(frame))
pcap(os.path.join(d, "cut512.pcap"), frame[:512], len(frame))
for n in ("full", "cut512"):
    c = SL.scan(os.path.join(d, n + ".pcap"), None)
    print(f"{os.path.basename(sys.argv[1].rstrip('/'))}: {n:7s} frame {len(frame)} B -> " +
          " ".join(f"{k}={v}" for k, v in c.items() if k != "arp_spoof_spa_manager"))
