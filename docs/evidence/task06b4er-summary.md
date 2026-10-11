# Minh chứng Nhiệm vụ 06B-4ER: sửa hai lỗi đánh giá của 06B-4E (08/10/2026)

> **Loại bằng chứng: kiểm thử offline.**
>
> - Không Docker, QEMU, gửi gói, sudo; không thay đổi mạng host hay source cô lập.
> - Các ca T12–T13 **vẫn chưa chạy trên guest**. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

**Lỗi reviewer tái hiện trên 06B-4E:**

1. `evaluate_group()` vẫn cho **ĐẠT** khi `record.service_link_before.ok = False`, nếu record có `cases` và không có marker `skipped`. Điều kiện liên kết trước nhóm chỉ được suy ra từ marker do `run_group` sinh ra.
2. Fixture `probe_frames("T13-I2")` dùng `icmp6(16, typ=135)`: target thật là `cdcd:cdcd:…`, nhưng vẫn được tính là probe. Lý do: NS chỉ được nhận diện theo nhóm solicited-node, mà nhiều địa chỉ dùng chung một nhóm.

## 1. Tái hiện trước/sau

Log: [`logs/repro-before-after.txt`](task06b4er/logs/repro-before-after.txt); script: [`repro.py`](task06b4er/repro.py).

| Ca | 06B-4E | 06B-4ER |
|---|---|---|
| `service_link_before.ok = False`, có `cases`, không `skipped`, capture và bộ đếm hoàn hảo | **ĐẠT (kiểm quy tắc)** | CHƯA KIỂM CHỨNG (liên kết dịch vụ trước nhóm thử thiếu, không đạt hoặc không hợp lệ) |
| 3 NS tới đúng nhóm solicited-node, nhưng target `cdcd:…` (fixture cũ) | `probe_frames=3`, **ĐẠT (kiểm quy tắc)** | `probe_frames=0`, CHƯA KIỂM CHỨNG (không tạo được gói probe) |

Test mới chạy trên `icmp_cases.py` và `l2frames.py` của 06B-4E: 17 test fail. Trên 06B-4ER: 79/79.

## 2. Bản sửa

Bản làm việc vẫn là `ct01-06b4e`; bản 06B-4E được giữ trong `ct01-06b4e/base-06b4e/`. Diff: [`ct01-06b4er-harness-vs-06b4e.diff`](task06b4er/ct01-06b4er-harness-vs-06b4e.diff). Chỉ 4 file đổi: `icmp_cases.py`, `selftest_icmp.py`, `mutation_icmp.py` và **module dùng chung `l2frames.py`**.

**Liên kết trước nhóm (`icmp_cases.py`):**

- `link_ok(state)` chỉ đúng khi `state` là object và `ok` **đúng bằng `True`**. Thiếu, `False`, `None`, `"true"`, `1`, list, hay thiếu khóa `ok` đều là "không đạt".
- `evaluate_group` tự đánh giá cả liên kết trước và sau **từ dữ liệu trong record**, không dựa riêng vào `skipped` (marker vẫn được xử lý như trước).
- Trong `evaluate_case`, điều kiện liên kết đứng **sau** các lỗi đã xác định: capture/bộ đếm chứng minh FAIL thì vẫn báo FAIL. Còn ĐẠT thì chỉ có khi cả hai liên kết đạt.
- Record có `cases` không phải list các object → `ValueError` (CLI exit 2).

**Nhận diện NS của T13-I2:**

- **`l2frames.decode` (module dùng chung, thay đổi chỉ bổ sung):** với ICMPv6 loại 135, thêm trường `ns_target`, là 16 byte target sau 8 byte đầu header NS.
  - Trường là `None` nếu target không có đủ trong capture **hoặc** nằm ngoài `payload length` của IPv6 (ví dụ có byte đệm Ethernet ở cuối).
  - **Phân lớp không đổi.** Đã chạy lại `selftest_l2` (gồm hồi quy 06B-3G), `mutation_l2`, `selftest_l2eval` (gồm phát lại 06B-4C) và `mutation_l2eval`; tất cả đạt, và JSON phát lại 06B-4C giống hệt bản 06B-4D1.
- **`is_probe_frame` (T13-I2):** NS chỉ được tính khi `ns_target` giải mã được, **bằng đúng địa chỉ link-local của `TAP_MAC`**, **và** đích là nhóm solicited-node của địa chỉ đó. Chỉ khớp nhóm là không đủ.
- **Fixture NS mới đúng cấu trúc RFC 4861:**
  - type 135, code 0, checksum, 4 byte reserved;
  - target là link-local của `TAP_MAC`;
  - option địa chỉ link-layer nguồn;
  - gửi tới nhóm solicited-node đúng.

## 3. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_icmp.py` | **79/79** (24 test mới), ổn định 3 lần | [`logs/selftest-icmp.log`](task06b4er/logs/selftest-icmp.log) |
| `mutation_icmp.py` | baseline 79/79; **28/28** đột biến hành vi bị bắt đúng test (19 cũ + 9 mới C20–C28, có 2 đột biến trong `l2frames.py`); 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-icmp.txt`](task06b4er/logs/mutation-icmp.txt) |
| `selftest_l2.py --regression <06B-3G>` (do sửa module dùng chung) | 195/195 | [`logs/selftest-l2.log`](task06b4er/logs/selftest-l2.log) |
| `mutation_l2.py` | 69/69 + 2 đối chứng | [`logs/mutation-l2.txt`](task06b4er/logs/mutation-l2.txt) |
| `selftest_l2eval.py --regression <06B-4C>` | 72/72; JSON phát lại giống hệt [`task06b4d1/replay-06b4c/`](task06b4d1/replay-06b4c/) | [`logs/selftest-l2eval.log`](task06b4er/logs/selftest-l2eval.log) |
| `mutation_l2eval.py` | 26/26 + 2 đối chứng | [`logs/mutation-l2eval.txt`](task06b4er/logs/mutation-l2eval.txt) |

**Test mới:**

- **N0–N10 (NS):**
  - bộ giải mã đọc đúng target; target thiếu → `None`; payload IPv6 kết thúc trước target dù khung có byte đệm → `None`;
  - NS đúng target → ĐẠT (kiểm quy tắc);
  - các ca **không** được thay probe, kết quả "không tạo được gói": NS **cùng nhóm nhưng target khác**; NS thiếu target; fixture cũ `cdcd…`; chỉ có MLD nền; NS đúng target nhưng gửi sai nhóm;
  - hỗn hợp 3 NS thật + NS khác target + MLD → chỉ 3 được tính.
- **B1–B13 (liên kết trước nhóm, gọi `evaluate_group()` trực tiếp và CLI):**
  - `ok = False`, trạng thái thiếu, `null`, `"true"`, `1`, list, thiếu khóa `ok` → CHƯA KIỂM CHỨNG, không bao giờ ĐẠT;
  - `ok = True` → vẫn có thể ĐẠT;
  - liên kết trước hỏng nhưng bộ đếm lệch, hoặc có gói tới guest → **FAIL** vẫn được báo;
  - CLI: exit 4; `cases` sai kiểu → `ValueError`.

**Đột biến mới:**

| Mã | Đột biến |
|---|---|
| C20 | bỏ kiểm liên kết trước |
| C21 | `ok` chỉ cần là truthy |
| C22 | bỏ kiểm object |
| C23 | bỏ kiểm target |
| C24 | bỏ kiểm nhóm |
| C25 | bỏ kiểm kiểu `cases` |
| C26 | quay lại dựa vào `skipped` |
| C27 | đọc sai vị trí target (`l2frames.py`) |
| C28 | bỏ kiểm `payload length` (`l2frames.py`) |

Đột biến cũ C13 được chuyển sang dòng mã mới.

## 4. Hash

- [`harness-sha256.txt`](task06b4er/harness-sha256.txt): 24 file của bản làm việc.
- Mọi file trong `task06b4er/`: [`SHA256SUMS`](task06b4er/SHA256SUMS) (`1ffc25f42900cfbcc3913a74575fc5647f661364eb052b711bca41e6bcffd40d`).

## 5. Hạn chế

- Không đổi so với [`task06b4e-summary.md`](task06b4e-summary.md) §5:
  - chưa chạy trên guest; chưa nối vào run script;
  - hành vi `ping`/`ping6` của BusyBox với broadcast/multicast là giả định;
  - guard 20 ms chưa đo.
- Checksum ICMPv6 của NS không được kiểm, giống mọi checksum L4 khác trong bộ giải mã.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
