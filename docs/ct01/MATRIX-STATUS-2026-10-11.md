# CT-01 — trạng thái hàng sau B1 R13N11, V0 R6 và T16/T17 R4 (2026-10-11)

Không thay `MATRIX-CORRECTED.md`. Chỉ các hàng có evidence + kết luận reviewer; mọi hàng khác giữ nhãn đã đối chiếu. Không phải PASS CT-01.

| Hàng | Nhãn mới | Evidence (ghim) | Giới hạn |
|---|---|---|---|
| T05b | **ĐẠT, ARM+MIPS** (đối chứng sống cùng IP/giao thức/cổng) | B1 R13N11 `476b0d69…ea667`, launch `02f021d6…`, ca T05-DNS-8888 | Đối chứng sống; guard 20 ms không đo |
| T06b | **ĐẠT, ARM+MIPS** (ICMP LAN DNS, đối chứng ICMP cùng IP) | ca T06-ICMP-LANDNS | như trên |
| T06c | **ĐẠT kiểm quy tắc (D6), ARM+MIPS** | ca T06-TCP-LAN2 | không có listener sống; không đối chứng sống |
| T11b | **ĐẠT kiểm quy tắc (D6), ARM+MIPS** (TCP22, TCP80, hai cửa sổ) | ca T11-TCP22, T11-TCP80 | như trên |
| T11c | **ĐẠT kiểm quy tắc (D6), ARM+MIPS** (ICMP→10.200.0.1, đếm khung) | ca T11-ICMP | như trên |
| T20 | **core N4/N5: ĐẠT lookup (không qua worker)**; N1–N3 coverage: ĐẠT (N2-TCP22 banner alive; N1/N2-TCP80/N3 kiểm quy tắc) | route-check + ca T20-* | N4/N5 chỉ tra route, không policy routing/reachability; N6 không chạy; không tuyên bố T20 hoàn tất ngoài phạm vi giao kèo |
| F1b | **ĐẠT theo PATH-resolution** (nft không resolve qua PATH hạn chế; exit 127 `run.sh: line 59`) | V0 R6 `4d2e8873…2b1c`, evaluator 157 | không chứng minh image thiếu binary; `/status` chưa đo |
| F6 | **ĐẠT runtime** (V0 nhận file, từ chối khác biệt cấu trúc item 25, exit 1, không sentinel) | V0 R6 | một container thử, V0 (không V1) |
| T16 | **một phần**: M1 ARM ĐẠT (6 khung, restore True); MIPS **chưa chạy** | T16/T17 R4 `c2d64577…582f58a`, launch `b745b9be…` | FAILED lịch sử (T17-P1) |
| T17 | **FAILED lịch sử, CHƯA KẾT LUẬN spoof**: P1/P2 HTTP 200 từ **IP thật** `10.200.0.2`; P4/P5 CHƯA KIỂM CHỨNG | pcap R4 (reviewer index 89–94, 130–135, 157–180) | cần probe có IP giả thật trên dây; không nâng PASS, không kết luận lỗ hổng |
| T01/T02-runtime, T18, T19, T21b, F3, F4, F5, V1/V2 | CHƯA KIỂM (không đổi) | — | đang chuẩn bị gói luồng thật |
| Giữ nguyên | T05a, T06a, T07–T15-1, T21a, F1a, F2, T01/T02-harness, T03/T04 | như MATRIX-CORRECTED | không chạy lại |

Lịch sử không sửa: V0 R4 (rc 3), V0 R5 (rc 1), B1 R13N10 (FAILED SyntaxError 3.10), B1 R13N11 lần 1 (FAILED: bridge mất IPv4), T16/T17 R4 FAILED. Drain: ens33 plateau cumulative-anchor PASS; lsmod-raw đổi; không nâng thành "host bất biến".


---
## Phần 2 (cùng ngày, sau review `ct01-flow-t17r5-independent-review`): luồng tác vụ thật, F5, T21b, T16/T17 R6

Chỉ các hàng có evidence + (nếu ghi) kết luận reviewer. Không phải PASS CT-01.

| Hàng | Nhãn | Evidence | Giới hạn |
|---|---|---|---|
| T18 | **ĐẠT, ARM+MIPS** (reviewer chấp nhận) | flow success #3 `20261011T031502Z-72529` 39/39, task ARM `77cb4735…`, MIPS `db517a1d…` | fixture busybox; một worker |
| T19 | **ĐẠT** (worker rảnh; từ container manager) | cùng lượt, `t19-manager-to-worker-health` 200 | không nói về T19 khi worker bận |
| T01/T02-runtime | **ĐẠT, ARM+MIPS** (đường thực thi/vận chuyển với fixture vô hại) | cùng lượt; zip manager: hash binary, strace execve, sar, pcap, qemu.log | không hash strace/sar riêng trong guest; không đánh giá phân tích malware |
| A7/A11/A15 | **checkpoint**: verifier rc 0 trong worker ở phase 1 và phase 2 upload | 4 hồ sơ verifier rc 0 | **không** claim timing guard 20 ms/đồng thời chính xác (R2 sampler ghi start/end + task + PID QEMU cho lượt sau) |
| F3 | **ĐẠT ARM** (một loại fault) | `20261011T031907Z-75366` 21/21 | MIPS và biến thể rule/sysctl/neighbor chưa đo |
| F4 | **ĐẠT ARM** | `20261011T031923Z-75814` 21/21 | như trên |
| F5 | **evidence thật, CHỜ review**: `compose restart` worker Compose; V0 OK lần 2; sandbox Docker mới; manager/Mongo không đổi | `ct01-flow-r3-f5-run-20261011T041311Z` 55/55 (manifest flow `97a18cfd…`); lượt R2 53/54 giữ làm lịch sử (tiêu chí inode sai) | F5 không là "task qua restart"; tiêu chí A14 viết sau khi thấy R2 |
| T21b | **CHƯA KIỂM** (gói sẵn, chờ phiên SSH của người dùng) | `ct01-t21b-r1` | cần nhịp trong chính phiên + file terminal phía client |
| T16 / T17 | **không đổi**: T17 FAILED lịch sử chưa kết luận spoof; R6 sẵn sàng offline, **chưa chạy** | `ct01-t1617-r6` `555a1eba…5398` | chờ review + câu duyệt nguyên văn chứa manifest; tác động mới: rule NAT tạm trong guest ARM |
| V1/V2 | gián tiếp qua F3/F4 (từ chối V1/V2 đúng lý do) | như F3/F4 | chưa có đối chứng "V1/V2 đạt" ghi trong log worker (worker không log thành công) |


---
## Phần 3: T16/T17 R7 (launch `e4980062…`) — evidence thật, chờ review
| Hàng | Nhãn | Evidence | Giới hạn |
|---|---|---|---|
| T16 | M1 **ĐẠT** ARM (6 khung) và MIPS (3 khung), restore True — chờ review | `ct01-t1617-r7-run-prep/run/ct01-arp-evidence-export.wnpsy472` (spoof-eval ARM `2fc5216c…`, MIPS `98c712b8…`) | D5 (TAP_MAC giả) hoãn |
| T17 | M1 + P1/P2/P4/P5 = **5 ca ĐẠT mỗi kiến trúc (ARM+MIPS)**: nguồn giả `10.200.0.5/32` và `192.168.60.10` trên dây, chặn, restore True, drain PASS — chờ review | cùng export; receipt `9b6da47a…`; drain `598187fb…` | `.5` là biến thể của `.3` (thiết kế); P3 hoãn; cơ chế R6 `.3` chưa xác minh |
Ghi chú: câu "broadcast /30 ⇒ IP thật ra dây" ở phần trước **bị bỏ**: chỉ hai quan sát xác minh — `.3` là broadcast của `10.200.0.0/30`; capture R6 ghi IP thật `10.200.0.2`, không ghi khung nguồn `.3`.

---
## Phần 4: T21b R3 — evidence thật, chờ review
| Hàng | Nhãn | Evidence | Giới hạn |
|---|---|---|---|
| T21b | **T21B_TWO_SIDED_HELD** (15/15): heartbeat trong phiên SSH thật, 300 nhịp, khớp server/client từng trường, mọi khoảng ≤ 3 s, bao phủ cửa sổ F5 R4 `20261011T060519Z` (restart 06:05:24–06:05:34Z) — chờ review | `ct01-t21b-r3-final.zip` (client log sha256 `aa0cdedd…134fdf`, verdict, server log, lane run, receipt) | một phiên, một lượt F5; ngưỡng 3 s; không nói về phiên khác/T21a |

---
## Phần 5: trạng thái CT-01 (reviewer chốt 2026-10-11)
**ĐẠT — hoàn tất theo phạm vi nghiệm thu đã duyệt; reviewer chốt 2026-10-11.** Tham chiếu: biên bản reviewer `ct01-final-acceptance/REVIEW.md` (sha256 `6da3f67bb3bb94649ce67429369bd21cc65ca69de663f5f7623ca914dd47914d`, trong gói `ct01-final-acceptance.zip` sha256 `7a9ee8d7ef219faccf57dab4b8ffd69027ebf862034a2d50942beeebc85e6b6f`), phạm vi theo `SCOPE-DECISION.json` (sha256 `9e537e4a32e02cbea35ad8f7585996bca1cb4d94dfd93b08c0b660fa80a9e13d`; câu người dùng nguyên văn "chấp nhận phạm vi" 2026-10-11T13:32:02+07:00; mapping là diễn giải của reviewer, không phải câu duyệt nguyên văn). Các hàng Phần 1–4 giữ nguyên nhãn/giới hạn lịch sử; T07–T10 theo phạm vi mạng đã chốt; coverage/hoãn không thành gate.
