# Minh chứng Nhiệm vụ 06B-4E: chuẩn bị offline kiểm tra T12–T13 bằng ping/ping6 (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4ER):** reviewer tái hiện 2 lỗi: `evaluate_group()` cho ĐẠT khi liên kết trước nhóm thất bại nếu không có marker `skipped`; fixture NS của T13-I2 có target sai (`cdcd…`) vẫn được tính là probe. Phần sửa ở [`task06b4er-summary.md`](task06b4er-summary.md). Nội dung dưới đây giữ nguyên như lúc bàn giao.

> **Loại bằng chứng: kiểm thử offline.**
>
> - Chỉ viết và kiểm offline: không Docker, QEMU, gửi gói, sudo, malware; không thay đổi mạng host hay source cô lập.
> - Các ca **chưa chạy trên guest nào**. Bàn giao để review trước khi thực thi.
> - **T12–T13 chưa được kiểm chứng. CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

**Phạm vi:** kiểm tra firewall với ICMP broadcast/multicast IPv4 (T12) và ICMPv6 (T13), chỉ dùng `ping`/`ping6` của BusyBox có sẵn trong guest, theo [`../ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md).

**Không làm:**

- ARP giả mạo, đổi MAC/IP nguồn, gói thô;
- thêm công cụ vào guest;
- thay đổi cấu hình guest;
- T14–T17, T20; thay đối chứng TCP/53.

## 1. Bản làm việc

- Bản mới `/home/dathq/projects/ct01-06b4e/` **chỉ thêm** 3 file: `icmp_cases.py`, `selftest_icmp.py`, `mutation_icmp.py`.
- 21 file còn lại giống hệt bản 06B-4D1R (hash khớp).
- Các bản đã bàn giao không đổi: `ct01-06b4d1` (06B-4D1R), `ct01-06b4b` (06B-4BR), `ct01-06b3c` (06B-3FR1).
- Run script và `probe_matrix.py` không sửa: các ca **chưa được nối vào run script** (để bước sau, sau review).
- Diff: [`task06b4e/ct01-06b4e-harness-vs-06b4d1r.diff`](task06b4e/ct01-06b4e-harness-vs-06b4d1r.diff). Hash: [`task06b4e/harness-sha256.txt`](task06b4e/harness-sha256.txt).

## 2. Các ca đã chuẩn bị

Danh sách đầy đủ, kèm lệnh ví dụ: [`task06b4e/prepared-cases.txt`](task06b4e/prepared-cases.txt).

| Ca | Lệnh trong guest (BusyBox) | Lớp mong đợi |
|---|---|---|
| T12-B1 | `ping -c 3 -s 1201 -w 5 255.255.255.255` | `drop_bcast_mcast` |
| T12-B2 | `ping -c 3 -s 1202 -w 5 224.0.0.1` | `drop_bcast_mcast` |
| T12-B4 | `ping -c 3 -s 1204 -w 5 10.200.0.3` (broadcast subnet) | `drop_private` |
| T13-I1 | `ping6 -c 3 -s 1301 -w 5 -I IF ff02::1` | `l2_bad_ethertype` |
| T13-I2 | `ping6 -c 3 -s 1302 -w 5 -I IF <link-local EUI-64 của TAP_MAC>` | `l2_bad_ethertype` (chỉ mong có NS tới nhóm solicited-node, vì `tap0` không có IPv6) |

- Kích thước chỉ lấy từ `signatures.py`; test D3 kiểm rằng đổi registry thì đổi lệnh.
- `IF` được kiểm tên. Địa chỉ đích được kiểm bằng `ipaddress`.

**Thực thi** (`run_group`, đã viết nhưng **chưa gọi** trên guest; offline chỉ dùng guest giả):

1. Kiểm liên kết dịch vụ guest–worker trước nhóm. Không đạt → **không chạy ca nào**.
2. Mỗi ca: đọc bộ đếm A → `ping` → đọc bộ đếm B.
3. Kiểm liên kết dịch vụ sau nhóm.

- Lỗi console, rc 127 hay "not found", lỗi đọc bộ đếm, lỗi kiểm liên kết đều **được ghi lại**, không ném ra ngoài.
- Một ca lỗi thì các ca sau vẫn chạy.

## 3. Đánh giá (nối vào bộ phân tích đã review)

`evaluate_group(pcap, counters-raw.jsonl, TAP_MAC, record)` dùng:

- `l2frames.classified_frames` để đọc capture;
- `l2eval.load_reads` để đọc snapshot bộ đếm;
- `l2eval.check_classes(None)`: đối chiếu đủ 13 lớp có ánh xạ khung;
- `l2frames.reconcile_l2` với guard 20 ms (giả định chưa đo, ghi trong kết quả);
- `l2frames.probe_verdict_l2(..., "rule_check")`.

**Phân loại kết quả, tách bạch:**

| Loại | Khi nào |
|---|---|
| `FAIL` | delta lệch số khung; gói probe không vào lớp mong đợi (ví dụ OTHERHOST); **có gói ICMP/ICMPv6 đi tới guest** trong cửa sổ. Ưu tiên cao nhất, kể cả khi thực thi cũng lỗi |
| `LOI_PHEP_DO` | capture không đọc được; file bộ đếm thiếu hoặc hỏng; lần đọc A/B thiếu; bộ đếm thiếu hoặc giảm; lỗi đọc bộ đếm khi chạy |
| `LOI_THUC_THI` | lệnh không chạy được trong guest (lỗi console, thiếu công cụ, không có bản ghi thực thi) |
| `KHONG_TAO_DUOC_GOI` | lệnh đã chạy nhưng **không có gói probe nào trên `tap0`** |
| `CHUA_KIEM_CHUNG` | gói ở biên; khung không có bộ đếm trong cửa sổ; liên kết dịch vụ sau nhóm không đạt; liên kết trước nhóm không đạt (không ca nào được chạy) |
| `DAT_KIEM_QUY_TAC` | "ĐẠT (kiểm quy tắc)" |

**Gói probe** được nhận diện theo nguồn guest, đích của ca và kích thước trên dây (IPv4: tổng độ dài = kích thước + 28; ICMPv6: payload = kích thước + 8; T13-I2: NS tới đúng nhóm solicited-node). Gói ICMP nền cùng đích nhưng khác kích thước **không** được tính là gói probe (test K4).

**Theo yêu cầu:**

- **Timeout hay không có gói không phải bằng chứng chặn.** Ping thất bại (rc 1, "0 received", "permission denied") mà không có gói probe → `KHONG_TAO_DUOC_GOI`, không bao giờ ĐẠT. Lưu lượng nền không thay cho probe (test K3).
- **"ĐẠT (kiểm quy tắc)" không bị nâng thành bằng chứng có đối chứng sống:**
  - các đích này không có đối chứng sống, nên `evidence_kind` luôn là `rule_check`;
  - không kết quả nào là "ĐẠT" trơn (test L2);
  - liên kết dịch vụ chỉ là điều kiện để đánh giá, không phải đối chứng của đích.
- Mã thoát nhóm (CLI): 0 khi cả nhóm ĐẠT (kiểm quy tắc); 1 khi có FAIL; 2 khi có lỗi đo hoặc đầu vào hỏng; 4 khi chưa đánh giá được. FAIL thắng LỖI PHÉP ĐO.

## 4. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_icmp.py` | **55/55**, ổn định 3 lần (JSON giống hệt) | [`logs/selftest-icmp.log`](task06b4e/logs/selftest-icmp.log) |
| `mutation_icmp.py` | baseline 55/55; **19/19** đột biến hành vi bị bắt đúng test; 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-icmp.txt`](task06b4e/logs/mutation-icmp.txt) |
| `selftest_l2eval.py --regression <06B-4C>` (không đổi) | 72/72 | [`logs/selftest-l2eval.log`](task06b4e/logs/selftest-l2eval.log) |
| `selftest_l2.py --offline-only` (không đổi) | 175/175 | [`logs/selftest-l2.log`](task06b4e/logs/selftest-l2.log) |

**Các test đều đi qua `evaluate_group()` thật**, trên capture pcapng và `counters-raw.jsonl` tổng hợp:

- **PASS:** 5 ca, mỗi ca 3 gói probe = delta 3; thêm DHCP nền.
- **FAIL:** delta 2 cho 3 gói; gói ICMP đi tới guest; gói probe OTHERHOST; FAIL kèm lỗi thực thi.
- **UNVERIFIED:** gói ở biên; khung không có bộ đếm; liên kết sau nhóm hỏng; liên kết trước nhóm hỏng.
- **Không tạo được gói:** broadcast bị từ chối; timeout; chỉ có lưu lượng nền; ICMP khác kích thước.
- **Lỗi thực thi:** lỗi console; rc 127; không có bản ghi thực thi.
- **Lỗi đo:** capture thiếu; file bộ đếm thiếu; lần đọc B thiếu; bộ đếm thiếu; file bộ đếm hỏng; lỗi đọc khi chạy; `TAP_MAC` sai.
- Ngoài ra:
  - `run_group` với guest giả: thứ tự gọi, bỏ qua khi liên kết trước hỏng, lỗi console, lỗi đọc bộ đếm, rc 127, lỗi khi kiểm liên kết; một ca đầu-cuối (guest giả → file bộ đếm → `evaluate_group`);
  - CLI.
- Mọi kịch bản được dựng **bên trong** test của nó, nên crash chỉ làm fail đúng test đó.

**Đột biến** (C1–C19):

| Mã | Đột biến |
|---|---|
| C1 | không có gói vẫn đánh giá |
| C2 | bỏ lỗi thực thi |
| C3 | bỏ kiểm liên kết sau |
| C4 | bỏ kiểm gói tới guest |
| C5 | bỏ kiểm lớp của gói probe |
| C6 | nâng nhãn thành "ĐẠT" |
| C7 | bỏ ưu tiên FAIL |
| C8 | kích thước gán cứng |
| C9 | bỏ lỗi đọc bộ đếm |
| C10 | bỏ kiểm nhãn đọc |
| C11 | chạy khi liên kết trước hỏng |
| C12 | bỏ phát hiện thiếu công cụ |
| C13 | bỏ nhận diện NS |
| C14 | bỏ kiểm kích thước |
| C15 | bỏ trạng thái nhóm bị bỏ qua |
| C16 | nuốt lỗi đọc capture |
| C17 | bỏ lỗi đọc B |
| C18 | đổi thứ tự ưu tiên mã thoát |
| C19 | nhận tên interface sai |

Lần chạy đầu có C14 và C16 lọt. Lý do:

- C14: chưa có ca ICMP khác kích thước.
- C16: đột biến bị một lớp khác che mất.

Đã thêm test K4 và sửa đột biến C16, đồng thời biến C18 (trước đó dự kiến lọt) thành đột biến phải bị bắt, với test L6 mới. Log là lần chạy cuối.

## 5. Hạn chế

- **Chưa chạy trên guest.** Hành vi của BusyBox `ping` với broadcast (`SO_BROADCAST`, giả định G1), multicast (G2) và `ping6 -I` mới chỉ là giả định; nếu không có gói thì kết quả sẽ là `KHONG_TAO_DUOC_GOI`, không phải ĐẠT.
- Chưa nối vào run script hay `probe_matrix.py`. Kiểm liên kết dịch vụ và đọc bộ đếm khi chạy thật sẽ do bước tích hợp cung cấp, qua đúng giao diện đã kiểm bằng guest giả.
- Kiểm chữ ký phía host (`sigscan_l2`, cảnh báo) đã có sẵn trong run script 06B-4BR; ở đây chưa nối với từng ca.
- Giả định [Kernel] trong `l2frames.py` chưa kiểm thực tế. Guard 20 ms chưa đo.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 6. Hash

Mọi file trong `task06b4e/`: [`task06b4e/SHA256SUMS`](task06b4e/SHA256SUMS) (`b18f5eb8832d821d1c21cc3ab5b22eed00948537fb533e8f03b876ef0fd7bf42`).
