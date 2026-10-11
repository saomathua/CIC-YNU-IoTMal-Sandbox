#!/usr/bin/env python3
"""06B-4IR3 precheck EVALUATOR (PC-2) — offline, as a normal user, on a COPY of the collector output.

    python3 -I -B evaluate_precheck.py <collector output dir> <result.json> [--harness DIR] [--ruleset-ref FILE]

Each item is PASS, FAIL or UNKNOWN (data missing, read error, ambiguous) with its reasons and the raw values it used.
A read that failed is UNKNOWN, never "absent" / "not running" / "ok". Exit code: 0 = every required item PASS;
1 = at least one required item FAIL; 2 = no FAIL but at least one required item UNKNOWN (incomplete precheck);
3 = the collector output itself is unusable (missing/malformed reads.json or wrong schema).
"""
import ipaddress
import json
import os
import re
import sys

SCHEMA = "ct01-precheck-collector/1"
EXPECTED_IMAGE_ID = "sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153"
SANDBOXNET = ("192.168.60.0/24", "192.168.60.1")      # 06B-4G targets-env + host ip addr (br-1d86fe3e8bbe)
MANAGER_IP = "192.168.60.10"                          # address the ARP cases use for T14-A2
HARNESS_CONTAINERS = ("ct01-06b3b-guest", "ct01-06b3b-ctl")
DEFAULT_HARNESS = "/home/dathq/projects/ct01-06b4ir3"
DEFAULT_RULESET_REF = ("/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/docs/evidence/task06b4g/run1/host-after/"
                       "nft-ruleset-stateless.txt")


def item(items, title, status, required=True, **detail):
    assert status in ("PASS", "FAIL", "UNKNOWN", "INFO")
    items.append({"item": title, "status": status, "required": required, **detail})


def evaluate(reads_doc, ruleset_ref_text, endpoint_mac_problem, parse_neigh_full):
    items = []
    meta, reads = reads_doc.get("meta", {}), {r["name"]: r for r in reads_doc.get("reads", [])}

    def get(name):
        r = reads.get(name)
        if r is None:
            return None, f"read {name!r} missing in the collector output"
        if r.get("status") != "OK":
            return None, f"read {name!r} status {r.get('status')} (rc {r.get('rc')}, {r.get('error')})"
        return r.get("stdout", ""), None

    item(items, "collector: every required read OK (data complete)",
         "PASS" if meta.get("data_complete") is True else "UNKNOWN",
         failed=[{"name": r["name"], "status": r.get("status"), "rc": r.get("rc"), "error": r.get("error")}
                 for r in reads.values() if r.get("required") and r.get("status") != "OK"])
    out, err = get("docker-version")
    m = re.search(r"server=(\S+)", out or "")
    item(items, "docker server readable", "PASS" if m and m.group(1) else "UNKNOWN", raw=out, reason=err)
    out, err = get("image-id")
    item(items, "image sandbox-worker:latest has the reviewed id",
         "UNKNOWN" if err else ("PASS" if out.strip() == EXPECTED_IMAGE_ID else "FAIL"),
         observed=None if err else out.strip(), expected=EXPECTED_IMAGE_ID, reason=err)
    out, err = get("ps-all")
    rows = [l.split("\t") for l in (out or "").splitlines() if l.strip()]
    names = {r[0]: r for r in rows if r}
    if err:
        for c in HARNESS_CONTAINERS:
            item(items, f"harness container {c} absent", "UNKNOWN", reason=err)
    else:
        for c in HARNESS_CONTAINERS:
            item(items, f"harness container {c} absent", "FAIL" if c in names else "PASS",
                 observed="PRESENT" if c in names else "ABSENT")
    # networks: exactly one each (collector skips the inspect otherwise)
    for net in ("sandboxnet", "dbnet"):
        out, err = get(f"network-inspect-{net}")
        if err:
            item(items, f"network {net}: exactly one, inspected", "UNKNOWN", reason=err)
            continue
        f = out.rstrip("\n").split("\t")
        try:
            ipam = json.loads(f[4]) or []
            ctrs = json.loads(f[5]) or {}
        except (IndexError, ValueError) as e:
            item(items, f"network {net}: exactly one, inspected", "UNKNOWN", reason=f"inspect output not parsed: {e}")
            continue
        detail = {"network": f[1], "driver": f[2], "internal": f[3], "ipam": ipam,
                  "endpoints": {v.get("Name"): {"ip": v.get("IPv4Address"), "mac": v.get("MacAddress")}
                                for v in ctrs.values()}}
        if net == "sandboxnet":
            ok = any(c.get("Subnet") == SANDBOXNET[0] and c.get("Gateway") == SANDBOXNET[1] for c in ipam)
            item(items, "network sandboxnet: exactly one, subnet 192.168.60.0/24 gateway 192.168.60.1",
                 "PASS" if ok else "FAIL", **detail)
        else:
            item(items, "network dbnet: exactly one, inspected", "PASS", **detail)
    # manager / mongo
    for who, label in (("manager", "manager"), ("mongo", "mongo-db")):
        out, err = get(f"inspect-{who}")
        if err:
            present = None if get("ps-all")[1] else (("cic-ynu-iotmal-sandbox-sandbox-manager-1" if who == "manager"
                                                    else "mongo-db") in names)
            st = "FAIL" if present is False else "UNKNOWN"
            item(items, f"{label}: present, state readable", st, reason=err,
                 ps_all_presence={None: "UNKNOWN", True: "PRESENT", False: "ABSENT"}[present])
            continue
        f = out.rstrip("\n").split("\t")
        state = f[0].strip()
        try:
            nets = json.loads(f[4]) if len(f) > 4 else {}
        except ValueError:
            nets = None
        if who == "manager":
            if state not in ("running", "exited"):
                item(items, "manager: state running or exited (the run script handles both)", "FAIL", state=state)
                continue
            item(items, "manager: state running or exited (the run script handles both)", "PASS", state=state,
                 restarts=f[2] if len(f) > 2 else None)
            sb = None
            for n, s in (nets or {}).items():
                if n.endswith("_sandboxnet"):
                    sb = s
            if state == "running":
                mac = (sb or {}).get("MacAddress")
                p = endpoint_mac_problem((mac or "").lower()) if sb else "no sandboxnet endpoint"
                item(items, "manager (running): sandboxnet IP 192.168.60.10 and a usable endpoint MAC",
                     "PASS" if sb and sb.get("IPAddress") == MANAGER_IP and not p else "FAIL",
                     ip=(sb or {}).get("IPAddress"), mac=mac, mac_problem=p)
            else:
                item(items, "manager (exited): sandboxnet MAC/IP not available while stopped; read by the run script "
                     "after it starts the manager", "INFO", required=False, networks=nets)
        else:
            db = next((s for n, s in (nets or {}).items() if n.endswith("_dbnet")), None)
            item(items, "mongo-db: running with an address on dbnet",
                 "PASS" if state == "running" and db and db.get("IPAddress") else "FAIL",
                 state=state, ip=(db or {}).get("IPAddress"))
    for name, label in (("pgrep-qemu", "no qemu-system process on the host"),
                        ("pgrep-capture", "no tcpdump/tshark/dumpcap process on the host")):
        r = reads.get(name)
        if r is None or r.get("status") != "OK":
            item(items, label, "UNKNOWN", reason=f"read {name} {None if r is None else r.get('status')}")
        else:
            item(items, label, "PASS" if r.get("rc") == 1 else "FAIL", rc=r.get("rc"), raw=r.get("stdout"))
    out, err = get("nft-ruleset")
    if err or ruleset_ref_text is None:
        item(items, "nft ruleset identical to 06B-4G host-after", "UNKNOWN",
             reason=err or "reference ruleset not readable")
    else:
        item(items, "nft ruleset identical to 06B-4G host-after", "PASS" if out == ruleset_ref_text else "FAIL",
             lines=len(out.splitlines()), ref_lines=len(ruleset_ref_text.splitlines()))
    out, err = get("aa-status")
    item(items, "AppArmor status readable (tool setup, recorded apart from CT-01)", "UNKNOWN" if err else "PASS",
         tcpdump_listed=None if err else ("tcpdump" in out), reason=err)
    # informational: manager reads with the harness parsers (manager is NOT the worker/ctl: no worker conclusion)
    out, err = get("manager-ip-j-neigh")
    if out is not None:
        try:
            rows_, probs, unknown = parse_neigh_full(out)
            item(items, "manager ip -j neigh parsed by arp_cases.parse_neigh_full (informational; manager image, "
                 "not the worker image)", "INFO", required=False, rows=len(rows_), problems=probs,
                 states=sorted({s for r in rows_ for s in r["states"]}))
        except Exception as e:                                   # noqa: BLE001
            item(items, "manager ip -j neigh parsed", "INFO", required=False, error=f"{type(e).__name__}: {e}")
    req = [i for i in items if i["required"]]
    verdict = "FAIL" if any(i["status"] == "FAIL" for i in req) else \
        "UNKNOWN" if any(i["status"] == "UNKNOWN" for i in req) else "PASS"
    return {"verdict": verdict, "items": items,
            "note": "precheck of the host/Docker state only; worker/ctl netns, image iproute2, guest operstate are "
                    "read only during an approved run"}


def main(argv):
    harness = argv[argv.index("--harness") + 1] if "--harness" in argv else DEFAULT_HARNESS
    ref = argv[argv.index("--ruleset-ref") + 1] if "--ruleset-ref" in argv else DEFAULT_RULESET_REF
    pos = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or not argv[i - 1].startswith("--"))]
    if len(pos) != 2:
        print(__doc__, file=sys.stderr)
        return 3
    src, dst = pos
    try:
        doc = json.load(open(os.path.join(src, "reads.json")))
        if doc.get("meta", {}).get("schema") != SCHEMA or not isinstance(doc.get("reads"), list):
            raise ValueError(f"schema {doc.get('meta', {}).get('schema')!r} != {SCHEMA!r}")
    except (OSError, ValueError, AttributeError) as e:
        json.dump({"verdict": "UNUSABLE", "error": f"{type(e).__name__}: {e}"}, open(dst, "w"), indent=1)
        print(f"UNUSABLE collector output: {e}")
        return 3
    sys.path.insert(0, harness)
    import arp_cases
    import arp_harness
    try:
        ref_text = open(ref).read()
    except OSError:
        ref_text = None
    res = evaluate(doc, ref_text, arp_harness.endpoint_mac_problem, arp_cases.parse_neigh_full)
    res.update(collector_output=os.path.abspath(src), harness=harness, ruleset_ref=ref)
    with open(dst, "w") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    for i in res["items"]:
        print(f"[{i['status']}] {i['item']}" + ("" if i["required"] else " (not required)"))
    print(f"PRECHECK VERDICT: {res['verdict']}")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
