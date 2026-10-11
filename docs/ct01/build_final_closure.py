#!/usr/bin/env python3
"""CT-01 final closure index. Reads files only. For EVERY one of the 38 MATRIX-CORRECTED rows: class, label, scope, and a list of evidence files with path +
full sha256 (hashed here, from the files that exist). Writes CLOSURE-FINAL.md/.json and EVIDENCE-INDEX-FINAL.json. Nothing is generated to add evidence."""
import hashlib, json, pathlib
P = pathlib.Path("/home/dathq/projects")
UP = pathlib.Path("/home/dathq/.claude/uploads/local_7deed7fc-e514-4498-ad85-35d2850fb846")
rows = json.load(open(P / "ct01-acceptance-matrix-corrected/MATRIX-CORRECTED.json"))["rows"]
by = {r["id"]: r for r in rows}
D = "CIC-YNU-IoTMal-Sandbox/docs/evidence/"
R10 = "ct01-arp-b1b2r10-run-prep/run/ct01-arp-evidence-export.yhwff6_v/stage/harness/out/container/probe/"
B1 = "ct01-b1probes-r13n11-ops-run-prep2/run/ct01-arp-evidence-export.kyjjou3b/stage/harness/out/container/probe/"
R7 = "ct01-t1617-r7-run-prep/run/ct01-arp-evidence-export.wnpsy472/stage/harness/out/"
V0 = "ct01-v0-runtime-r6-run-20261010T165222Z/"
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
REV = {   # review key -> file (hashed); reviewer packages as received, or the extracted REVIEW/REPORT
 "REV-matrix": "ct01-acceptance-matrix-independent-review/outputs/REPORT.md",
 "REV-R10": "ct01-arp-yhwff6_v-independent-review/outputs/REPORT.md",
 "REV-V0-R6": str(UP / "ct01-v0-r6-independent-review.zip"),
 "REV-B1-R13N11+T1617R4": str(UP / "ct01-b1-r13n11-t1617r4-independent-review.zip"),
 "REV-FLOW-T17R5": str(UP / "ct01-flow-t17r5-independent-review.zip"),
 "REV-FLOW-R6": str(UP / "ct01-flow-r6-independent-review.zip"),
 "REV-T17R7": str(UP / "ct01-t17r7-independent-review__1_.zip"),
 "REV-FINAL": str(UP / "ct01-r7-t21b-final-independent-review__1_.zip"),
 "SCOPE-DECISION": "ct01-final-review/ct01-r7-t21b-final-independent-review/SCOPE-DECISION.json",
 "MATRIX-CONFIRMED": "ct01-acceptance-matrix-independent-review/outputs/MATRIX-CONFIRMED.json",
 "MATRIX-CORRECTED": "ct01-acceptance-matrix-corrected/MATRIX-CORRECTED.json",
 "DESIGN": "CIC-YNU-IoTMal-Sandbox/docs/network-isolation-design.md",
 "PLAN": "CIC-YNU-IoTMal-Sandbox/docs/ct01-remaining-tests-plan.md",
}
def g3(a): return [(f"{D}task06b3g/run1/container/probe/{a}/matrix.json", a), (f"{D}task06b3g/run1/container/probe/{a}/tap0.pcapng", a)]
E = {}
def ev(row, items, cls, label, scope, reviews):
    E[row] = dict(cls=cls, label=label, scope=scope, reviews=reviews, evidence=[dict(path=p, arch=a, what=w) for p, a, w in items])
m3 = [(f"{D}task06b3g-summary.md", "ARM+MIPS", "06B-3G summary"), (f"{D}task06b3g/run1/container/probe/ARM/matrix.json", "ARM", "3G matrix"),
      (f"{D}task06b3g/run1/container/probe/MIPS/matrix.json", "MIPS", "3G matrix"), (f"{D}task06b3b-summary.md", "ARM+MIPS", "06B-3B summary")]
ev("T05a", m3, "mandatory", "ĐẠT về mạng (3G internet-tcp ARM+MIPS); FAIL 06B-3D giữ lịch sử", "tcp 1.1.1.1:443, đối chứng cùng IP/giao thức/cổng sống; TCP443 là phép thử của T05a, không phải T05b", ["REV-matrix", "MATRIX-CORRECTED"])
b1 = lambda a: (f"{B1}{a}/b1-eval.json", a, "B1 R13N11 evaluator verdicts")
ev("T05b", [b1("ARM"), b1("MIPS"), ("ct01-b1-r13n11-t1617r4-results.zip", "ARM+MIPS", "B1 R13N11 results package")], "mandatory",
   "ĐẠT ARM+MIPS (ca T05-DNS-8888: UDP DNS 8.8.8.8:53 + đối chứng sống cùng IP/giao thức/cổng; pcap B1: UDP, ARM 8 / MIPS 48 khung)", "UDP DNS 8.8.8.8:53. Không phải TCP443 (đó là T05a). Guard 20 ms không đo", ["REV-B1-R13N11+T1617R4"])
ev("T05c", [], "coverage", "CHƯA KIỂM — bổ sung, không là gate", "ICMP công cộng không có trong ma trận thiết kế", ["MATRIX-CORRECTED"])
ev("T06a", m3, "mandatory", "ĐẠT TCP53 (UDP53 phủ bổ sung) ARM+MIPS", "192.168.177.2:53 tcp/udp; đối chứng TCP connect/DNS từ W cùng IP/giao thức/cổng", ["REV-matrix"])
ev("T06b", [b1("ARM"), b1("MIPS")], "mandatory", "ĐẠT ARM+MIPS (T06-ICMP-LANDNS + đối chứng ICMP cùng IP)", "ICMP 192.168.177.2", ["REV-B1-R13N11+T1617R4"])
ev("T06c", [b1("ARM"), b1("MIPS")], "mandatory", "ĐẠT kiểm quy tắc (D6) ARM+MIPS (T06-TCP-LAN2)", "TCP LAN2; không listener sống/đối chứng sống", ["REV-B1-R13N11+T1617R4"])
dec = lambda l: l
ev("T07", m3, "mandatory (phạm vi mạng đã chốt)", "ĐẠT về mạng: ARM 3/3 + MIPS 2/3 trực tiếp + ssh-host-192.168.60.1 MIPS dẫn xuất H0 (3G UNVERIFIED giữ lịch sử); log ssh bổ sung KHÔNG đo",
   "tcp 192.168.60.1:22 / 192.168.177.128:22 / 172.18.0.1:22; đối chứng tương ứng. Phạm vi mạng do người dùng chấp nhận 13:32:02+07 (\"chấp nhận phạm vi\")", ["REV-matrix", "SCOPE-DECISION", "REV-FINAL"])
ev("T08", m3, "mandatory (phạm vi mạng đã chốt)", "ĐẠT về mạng ARM+MIPS; log manager bổ sung KHÔNG đo", "tcp 192.168.60.10:8011; đối chứng worker health/ctl", ["REV-matrix", "SCOPE-DECISION", "REV-FINAL"])
ev("T09", m3, "mandatory (phạm vi mạng đã chốt)", "ĐẠT cách ly TCP27017 ARM+MIPS với control TCP connect từ dbnet; KHÔNG claim M /status hay mongosh ping", "tcp 172.18.0.2:27017", ["REV-matrix", "SCOPE-DECISION", "REV-FINAL"])
ev("T10", m3 + [("ct01-flow-r1-success-run-20261011T031502Z/MANIFEST-SHA256", "ARM+MIPS", "T19 manager→worker 200 (nguồn M)")], "mandatory (phạm vi mạng đã chốt)",
   "ĐẠT tổng hợp: network proof 3G (ARM+MIPS) + T19 chứng minh nguồn M→worker 200 ở lượt riêng; T19 KHÔNG là control đồng thời của probe guest cũ", "tcp 192.168.60.2:8011", ["REV-matrix", "SCOPE-DECISION", "REV-FINAL", "REV-FLOW-T17R5"])
ev("T11a", m3, "extra probe (không thay T11b/c)", "ĐẠT listener 10.200.0.1:18080 ARM+MIPS", "tcp 10.200.0.1:18080 listener tạm đối chứng", ["REV-matrix"])
ev("T11b", [b1("ARM"), b1("MIPS")], "mandatory", "ĐẠT kiểm quy tắc (D6) ARM+MIPS (TCP22, TCP80)", "tcp 10.200.0.1:22/80; không đối chứng sống", ["REV-B1-R13N11+T1617R4"])
ev("T11c", [b1("ARM"), b1("MIPS")], "mandatory", "ĐẠT kiểm quy tắc (D6) ARM+MIPS (ICMP→10.200.0.1)", "ICMP 10.200.0.1", ["REV-B1-R13N11+T1617R4"])
g4 = lambda a: (f"{D}task06b4g/run1/container/probe/{a}/icmp-eval.json", a, "06B-4G ICMP evaluator")
ev("T12", [g4("ARM"), g4("MIPS"), (f"{D}task06b4g-summary.md", "ARM+MIPS", "06B-4G summary")], "mandatory", "ĐẠT kiểm quy tắc B1/B2/B4 ARM+MIPS; host capture OPEN (received−captured=8) vẫn mở, không là bằng chứng host hoàn chỉnh",
   "ICMP echo tới 255.255.255.255 / 224.0.0.1 / 10.200.0.3; delta = số khung pcap", ["REV-matrix"])
ev("T12-B3", [], "coverage", "CHƯA KIỂM — bổ sung, không là gate", "UDP53 → 224.0.0.251", ["MATRIX-CORRECTED"])
ev("T13", [g4("ARM"), g4("MIPS")], "mandatory", "Giữ nhãn gốc 4G: I2 ĐẠT cả hai; I1 MIPS ĐẠT; I1 ARM UNVERIFIED (lịch sử), đối chiếu dẫn xuất H0 PASS ghi riêng", "ICMPv6 NS/echo tới fe80; host capture OPEN giữ", ["REV-matrix"])
ev("T13-I3", [], "coverage", "CHƯA KIỂM — bổ sung, không là gate", "curl6/NS EUI-64", ["MATRIX-CORRECTED"])
ra = lambda a: (f"{R10}{a}/arp-eval.json", a, "R10 ARP evaluator")
ev("T14", [ra("ARM"), ra("MIPS"), ("ct01-arp-yhwff6_v-independent-review/outputs/ANALYSIS.json", "ARM+MIPS", "reviewer analysis")], "mandatory", "ĐẠT A1/A2/A3 ARM+MIPS (A1/A2 đối chứng sống; A3 kiểm quy tắc)", "ARP request kernel guest", ["REV-R10"])
ev("T15-1", [ra("ARM"), ra("MIPS")], "mandatory", "ĐẠT S1 (kiểm quy tắc) ARM+MIPS", "gratuitous ARP request; neighbor trước/sau", ["REV-R10"])
ev("T15-2", [], "postponed", "HOÃN ĐÃ DUYỆT (D1)", "reply giả/htype/hlen/plen tùy ý", ["MATRIX-CORRECTED"])
s7 = lambda a: (f"{R7}container/probe/{a}/spoof-eval.json", a, "R7 spoof evaluator")
ev("T16", [s7("ARM"), s7("MIPS"), (f"{R7}container/probe/ARM/tap0.pcapng", "ARM", "R7 tap0 pcap"), (f"{R7}container/probe/MIPS/tap0.pcapng", "MIPS", "R7 tap0 pcap"),
           ("ct01-t1617-r7-run-prep/APPROVAL-RECORD.json", "ARM+MIPS", "R7 approval (verbatim user quote)"), ("ct01-t1617-r7-run-prep/run/ct01-arp-evidence-export.wnpsy472/stage/launch-receipt.json", "ARM+MIPS", "R7 launch receipt")], "mandatory",
   "ĐẠT T16-M1 ARM (6 khung) + MIPS (3 khung); restore True (R7, reviewer chấp nhận)", "MAC giả 52:54:00:de:ad:01, service link tới 10.200.0.1:8011; TAP_MAC giả hoãn (D5)", ["REV-T17R7", "REV-FINAL"])
ev("T17", [s7("ARM"), s7("MIPS"), (f"{R7}hostcap/drain-result.json", "ARM+MIPS", "R7 drain PASS"), ("ct01-t1617-r6-run-prep/run/ct01-arp-evidence-export.1hqd8d7n/stage/harness/out/container/probe/ARM/spoof-eval.json", "ARM", "R6 (P1/P4 KHONG_TAO_DUOC_GOI, lịch sử)")],
   "mandatory", "ĐẠT P1 (mandatory) + P2/P4/P5 (coverage) ARM+MIPS với nguồn giả trên dây (R7); `.5/32` là biến thể của `.3`; R6 ARM P1/P4 KHONG_TAO_DUOC_GOI và R4 FAILED giữ lịch sử",
   "P1 10.200.0.5→10.200.0.1:8011; P2 192.168.60.10→10.200.0.1:8011; P4 10.200.0.5→1.1.1.1:443; P5 ICMP 192.168.60.10→192.168.60.1; P3 hoãn; không chứng nhận `.3`", ["REV-T17R7", "REV-FINAL"])
fl = lambda k: f"ct01-flow-r1-{k}/MANIFEST-SHA256"
ev("T18", [(fl("success-run-20261011T031502Z"), "ARM+MIPS", "flow success #3 run manifest"), ("ct01-flow-and-t17r5-package.zip", "ARM+MIPS", "flow package")], "mandatory", "ĐẠT ARM+MIPS: poller thật nhận tác vụ, PROCESSING→COMPLETED", "fixture busybox vô hại, worker ct01-flow-worker", ["REV-FLOW-T17R5"])
ev("T19", [(fl("success-run-20261011T031502Z"), "ARM+MIPS", "flow success #3 run manifest")], "mandatory", "ĐẠT: container manager → worker 192.168.60.2:8011/healthcheck 200 (worker rảnh)", "không nói về worker bận", ["REV-FLOW-T17R5"])
ev("T20", [b1("ARM"), b1("MIPS")], "mandatory", "core N4/N5 ĐẠT lookup; N1–N3 coverage ĐẠT (N2-TCP22 banner sống; còn lại kiểm quy tắc)", "N4/N5 chỉ tra route; N6 không chạy", ["REV-B1-R13N11+T1617R4"])
ev("T21a", [(f"ct01-arp-b1b2r10-run-prep/run/ct01-arp-evidence-export.yhwff6_v/export-result.json", "ARM+MIPS", "R10 export"), ("ct01-arp-yhwff6_v-independent-review/outputs/REPORT.md", "ARM+MIPS", "R10 review"),
                ("ct01-flow-r3-f5-run-20261011T041311Z/MANIFEST-SHA256", "worker Compose", "F5 R3 (Compose service thật; lượt riêng)")], "mandatory",
   "ĐẠT invariant bắt buộc trong lượt R10 đã review (không là toàn host bất biến; lsmod đổi không là gate). Compose thật đã chạy ở F5/T21b R3 (lượt riêng, scope riêng); câu 'Compose chưa từng chạy' là lịch sử R10", "host trước/sau; harness R10 dùng container privileged riêng", ["REV-R10", "REV-FLOW-R6"])
ev("T21b", [("ct01-t21b-r3-final.zip", "n/a (phiên SSH)", "T21b R3 final package"), ("t21b-client-t21b-r3-20261011a.log", "n/a", "client log gốc"),
            ("ct01-t21b-run-t21b-r3-20261011a/heartbeat-t21b-r3-20261011a.log", "n/a", "server heartbeat log"), ("ct01-flow-r4-f5-run-20261011T060519Z/MANIFEST-SHA256", "worker Compose", "lane F5 R4")], "mandatory",
   "ĐẠT T21B_TWO_SIDED_HELD (15/15) trong cửa sổ startup/restart worker rảnh của lượt F5 R4; R2 NOT_MET giữ lịch sử", "một phiên SSH, ngưỡng 3 s; không mọi phiên, không T21a. Thu hồi sudo là thông tin operator", ["REV-FINAL"])
ev("F1a", [(f"{D}task06b2ar-summary.md", "worker image", "06B-2AR summary"), (f"{D}task06b2ar/run.log", "worker image", "06B-2AR run.log")], "mandatory", "ĐẠT nhánh syntax ở V0 (guest.nft lỗi → exit 1)", "không mở thành mọi nhánh V0", ["MATRIX-CORRECTED"])
ev("F1b", [(V0 + "verdicts.json", "worker image", "V0 R6 verdicts"), (V0 + "EXPORT-RECEIPT.json", "worker image", "V0 R6 receipt"), ("ct01-v0-runtime-final-evidence.zip", "worker image", "V0 final evidence")], "mandatory",
   "ĐẠT theo PATH-resolution (nft không resolve qua PATH hạn chế; exit 127)", "không chứng minh image thiếu binary; manager /status không đo", ["REV-V0-R6"])
ev("F2", [(f"{D}task06b2ar-summary.md", "worker image", "06B-2AR summary"), (f"{D}task06b2ar/run.log", "worker image", "06B-2AR run.log")], "mandatory", "ĐẠT ở V0 (ALLOW_VM_INTERNET=true → exit 1)", "raw FATAL + exit 1", ["MATRIX-CORRECTED"])
ev("F3", [(fl("f3-run-20261011T031907Z"), "ARM", "flow F3 run manifest")], "mandatory", "ĐẠT ARM (xóa bảng khi worker rảnh → FAILED lý do V1, không QEMU)", "một loại fault; MIPS/biến thể chưa đo", ["REV-FLOW-T17R5"])
ev("F4", [(fl("f4-run-20261011T031923Z"), "ARM", "flow F4 run manifest")], "mandatory", "ĐẠT ARM (xóa khi phase 1 → V2, phase 2 không bắt đầu)", "như F3", ["REV-FLOW-T17R5"])
ev("F5", [("ct01-flow-r3-f5-run-20261011T041311Z/MANIFEST-SHA256", "worker Compose", "F5 R3 run manifest"), ("ct01-flow-r3-f5-run-20261011T041311Z.export-receipt.json", "worker Compose", "F5 R3 receipt"),
          ("ct01-flow-r2-f5-run-20261011T040725Z/MANIFEST-SHA256", "worker Compose", "F5 R2 (53/54, lịch sử)")], "mandatory", "ĐẠT startup/restart worker Compose rảnh (A14: sandbox mới, V0×2); R2 53/54 giữ lịch sử", "không chứng minh tác vụ đang chạy sống qua restart", ["REV-FLOW-R6"])
ev("F6", [(V0 + "f6-v0-diff.json", "worker image", "V0 R6 F6 diff"), (V0 + "verdicts.json", "worker image", "V0 R6 verdicts")], "mandatory", "ĐẠT runtime (V0 từ chối khác biệt cấu trúc, exit 1, không sentinel)", "V0, không V1", ["REV-V0-R6"])
ev("T01/T02-harness", [(f"{D}task06b3a-summary.md", "ARM+MIPS", "06B-3A summary")], "mandatory", "ĐẠT riêng download/upload qua guest ARM/MIPS (3A, 37/37)", "không đồng nghĩa đã qua poller/phase1/phase2 thật", ["MATRIX-CORRECTED"])
ev("T03/T04", [(f"{D}task06b3a-summary.md", "ARM+MIPS", "06B-3A summary"), (f"{D}task06b2b-summary.md", "worker", "06B-2B summary"), (f"{D}task06b2br-summary.md", "worker", "06B-2BR summary")], "mandatory (scope tổng hợp đã chấp nhận)",
   "Giữ scope tổng hợp hai cấp evidence (peer TCP mô phỏng nguồn 2B + route từ guest 3A)", "T04 là ba route allowlist khi không current_task; không từng route từ cả hai guest", ["MATRIX-CORRECTED"])
ev("T01/T02-runtime; A7/A11/A15", [(fl("success-run-20261011T031502Z"), "ARM+MIPS", "flow success #3 run manifest"), ("ct01-flow-and-t17r5-package.zip", "ARM+MIPS", "flow package")], "mandatory",
   "T01/T02-runtime ĐẠT ARM+MIPS; A7/A11/A15 chỉ checkpoint verifier rc 0 trong worker (không claim timing guard 20 ms)", "không hash strace/sar riêng trong guest trước upload; fixture vô hại", ["REV-FLOW-T17R5"])
ev("D1/D3/D4/D5 + ngoài06B", [], "postponed", "HOÃN — không mở scope (P3, TAP_MAC giả, N6, v.v.)", "giữ đúng quyết định", ["MATRIX-CORRECTED"])
# ---- hash everything
cache, missing = {}, []
def h(path):
    p = pathlib.Path(path) if path.startswith("/") else P / path
    if path not in cache:
        cache[path] = dict(path=path, exists=p.is_file(), sha256=sha(p) if p.is_file() else None, bytes=p.stat().st_size if p.is_file() else None)
        if not p.is_file():
            missing.append(path)
    return cache[path]
out = []
for r in rows:
    i = r["id"]
    e = E[i]
    for x in e["evidence"]:
        x.update(h(x["path"]))
    e["review_files"] = {k: h(REV[k]) for k in e["reviews"] if k in REV}
    e["id"] = i
    out.append(e)
mand_without = [e["id"] for e in out if e["cls"].startswith("mandatory") and not [x for x in e["evidence"] if x["exists"]]]
for k in REV: h(REV[k])
idx = dict(files=cache, rows=len(out), files_checked=len(cache), missing=missing, mandatory_rows_without_existing_evidence=mand_without,
           classes={c: sum(1 for e in out if e["cls"].split(" ")[0] == c) for c in ("mandatory", "coverage", "postponed", "extra")})
json.dump(dict(rows=out, index=idx), open("CLOSURE-FINAL.json", "w"), ensure_ascii=False, indent=1)
json.dump(idx, open("EVIDENCE-INDEX-FINAL.json", "w"), ensure_ascii=False, indent=1)
esc = lambda s: str(s).replace("|", "/").replace("\n", " ")
md = ["# CT-01 — bảng closure cuối (38 hàng; 2026-10-11)", "",
      f"Index: {idx['files_checked']} tệp được băm trực tiếp, thiếu {len(missing)}, hàng mandatory không có evidence tồn tại: {mand_without or 'không'}. Lớp: {idx['classes']}. "
      "Phạm vi T07–T10 theo `SCOPE-DECISION.json` (người dùng: \"chấp nhận phạm vi\", 13:32:02 +07). Không phải tuyên bố PASS toàn thiết kế: mọi giới hạn/lịch sử giữ nguyên.", "",
      "| Hàng | Lớp | Nhãn | Phạm vi / giao thức / control | Evidence (path · arch · sha256 đầy đủ) | Review |", "|---|---|---|---|---|---|"]
for e in out:
    evs = "<br>".join(f"`{x['path']}` · {x['arch']} · `{x['sha256'] or 'MISSING'}`" for x in e["evidence"]) or "—"
    rv = "<br>".join(f"{k}: `{v['sha256'][:16] if v['sha256'] else 'MISSING'}…`" for k, v in e["review_files"].items())
    md.append(f"| {esc(e['id'])} | {esc(e['cls'])} | {esc(e['label'])} | {esc(e['scope'])} | {evs} | {rv} |")
pathlib.Path("CLOSURE-FINAL.md").write_text("\n".join(md) + "\n")
print("rows", len(out), "files", len(cache), "missing", missing, "mandatory_without", mand_without)

# Post-review (2026-10-11): status/acceptance fields were added to CLOSURE-FINAL.md/.json by the finalisation step (see ACCEPTANCE-RECORD.md); the evidence rows are unchanged.
