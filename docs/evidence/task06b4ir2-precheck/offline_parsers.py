#!/usr/bin/env python3
"""06B-4IR2 precheck: run the EXISTING parsers (copy of ct01-06b4ir2) offline on raw data read in this precheck and on
real evidence saved by 06B-4G. Reads files only."""
import ast, json, os, re, sys
P = "/home/dathq/projects/ct01-06b4ir2-precheck"
sys.path.insert(0, os.path.join(P, "harness-copy"))
import arp_cases as A, arp_harness as AH, guest_state as GS
EV = "/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/docs/evidence/task06b4g/run1"
out = {}
# 1. host `ip -j neigh show` (host iproute2-6.1.0; NOT the worker image's iproute2)
txt = open(f"{P}/raw/host-neigh/ip-j-neigh-show.json").read()
rows, probs, unknown = A.parse_neigh_full(txt)
out["host_ip_j_neigh"] = {"source": "host netns, iproute2-6.1.0 (not the worker image)", "rows": len(rows),
                          "problems": probs, "unknown": unknown,
                          "states": sorted({s for r in rows for s in r["states"]}),
                          "keys_per_row": sorted({tuple(sorted(r)) for r in json.loads(txt)}),
                          "bindings": sum(r["binding"] for r in rows)}
# neigh_check of the host table against itself: no tap0 entry -> the mandatory tap0 rule fires (expected off-worker)
out["host_neigh_check_self"] = A.neigh_check(txt, txt, [])
# 2. real worker-netns neighbour text saved by 06B-4G (ip neigh show, TEXT): the JSON parser must refuse it
for name in ("netns-before.txt", "netns-after.txt"):
    t = open(f"{EV}/container/{name}").read()
    sec = t.split("## ip neigh show")[1].split("## ")[0].strip()
    try:
        A.parse_neigh_full(sec)
        r = "parsed (unexpected)"
    except A.NeighReadError as e:
        r = f"NeighReadError: {e}"
    out[f"06b4g_{name}_ip_neigh_text"] = {"text": sec.splitlines(), "json_parser": r}
# 3. ctl_loop.arp_entry (ast-extracted, as in selftest) on the host /proc/net/arp copy + host /sys copy
src = open(os.path.join(P, "harness-copy", "ctl_loop.py")).read()
fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "arp_entry")
ns = {"PROC_ARP": "/nonexistent", "SYS_NET": "/nonexistent"}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "ctl_loop.py", "exec"), ns)
arp = {}
for ip in ("172.18.0.2", "192.168.177.2", "192.168.60.2"):
    try:
        arp[ip] = ns["arp_entry"](ip, f"{P}/raw/host-neigh/proc-net-arp.txt", f"{P}/raw/host-neigh/sys-net-copy")
    except Exception as e:                                  # noqa: BLE001
        arp[ip] = f"{type(e).__name__}: {e}"
out["ctl_loop_arp_entry_on_host_proc_net_arp"] = arp
# 4. endpoint MAC validator on the MACs Docker assigned on this host (bridges, container endpoints seen from host)
macs = {}
for line in open(f"{P}/raw/host-neigh/sys-class-net-address-operstate.txt"):
    d, mac, st = line.split()
    macs[d] = {"mac": mac, "operstate": st, "endpoint_mac_problem": AH.endpoint_mac_problem(mac)}
for r in rows:
    macs[f"neigh {r['dst']}"] = {"mac": r["lladdr"], "endpoint_mac_problem": AH.endpoint_mac_problem(r["lladdr"])}
out["endpoint_mac_problem_on_observed_macs"] = macs
# 5. guest interfaces from the real 06B-4G topology (ip addr TEXT, not sysfs operstate)
for arch in ("ARM", "MIPS"):
    t = json.load(open(f"{EV}/container/probe/{arch}/topology.json"))
    states = re.findall(r"^\d+: (\S+?):.*? state (\S+)", t["ip_addr"], re.M)
    out[f"06b4g_guest_{arch}"] = {"ip_addr_link_states": states, "ifaces_mac": t["ifaces_mac"].split("\n"),
                                  "guest_state_OPERSTATES": sorted(A.OPERSTATES),
                                  "note": "ip addr prints the link state in upper case; guest_state reads "
                                          "/sys/class/net/IF/operstate (lower case): no sysfs value saved"}
json.dump(out, open(f"{P}/parsed/offline-parsers.json", "w"), indent=1, ensure_ascii=False, default=str)
print(json.dumps(out, indent=1, ensure_ascii=False, default=str)[:6000])
