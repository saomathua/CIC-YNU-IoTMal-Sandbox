"""06B-4ER repro (offline): the reviewer's two cases against the harness directory in argv[1]."""
import os, sys, tempfile, ipaddress, struct
sys.path.insert(0, sys.argv[1]); sys.path.insert(1, "/home/dathq/projects/ct01-06b4e")
import icmp_cases as I, selftest_icmp as T, selftest_l2 as B, signatures as S
tmp = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
# 1. link before failed, no 'skipped' marker, but cases + a perfect capture/counters
pc, cf, rec = T.scenario(tmp, "lb", [("T12-B1", T.spaced(T.probe_frames("T12-B1")), {"drop_bcast_mcast": 3}, T.OK_EXEC)])
rec["service_link_before"] = {"ok": False, "detail": "HTTP 000"}
print("case 1 link_before.ok=False, cases present, no skipped ->", I.evaluate_group(pc, cf, T.TAP, rec)["cases"][0]["verdict"])
# 2. the 06B-4E NS fixture: icmp6(16, typ=135) -> target bytes cdcd...; sent to the right solicited-node group
c = T.CASES["T13-I2"]
grp = c["ns_group"]
mac = "33:33:" + ":".join(f"{b:02x}" for b in ipaddress.IPv6Address(grp).packed[12:])
bad = B.eth(mac, B.GUEST, 0x86DD, B.ipv6(S.GUEST_LL6, grp, 58, B.icmp6(16, typ=135)))
tgt = ipaddress.IPv6Address(B.ipv6(S.GUEST_LL6, grp, 58, B.icmp6(16, typ=135))[40 + 8:40 + 24])
pc, cf, rec = T.scenario(tmp, "ns", [("T13-I2", T.spaced([bad] * 3), {"l2_bad_ethertype": 3}, T.OK_EXEC)])
r = I.evaluate_group(pc, cf, T.TAP, rec)["cases"][0]
print(f"case 2 NS with target {tgt} (case target {c['dst']}) -> probe_frames={r.get('probe_frames')} verdict={r['verdict']}")
