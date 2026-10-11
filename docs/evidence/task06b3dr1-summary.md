# Minh chứng Nhiệm vụ 06B-3DR1: sửa hai lỗ hổng kết luận của harness, kiểm thử OFFLINE (07/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Harness đã sửa **chưa chạy tích hợp lần nào**.

**Bối cảnh:**

- Reviewer tái hiện được hai lỗ hổng trong kết luận của harness 06B-3DR.
- Chỉ sửa mã kiểm thử (ngoài repo, `/home/dathq/projects/ct01-06b3c/`) và tài liệu. Không sửa source cô lập.
- Bản 06B-3DR được giữ trong `ct01-06b3c/base-06b3dr/` và khớp đúng hash đã bàn giao.

## 1. Tái hiện trên bản 06B-3DR, so với bản đã sửa

Log: [`logs/repro-before-after.txt`](task06b3dr1/logs/repro-before-after.txt).

| Trường hợp | 06B-3DR (trước) | 06B-3DR1 (sau) |
|---|---|---|
| đối chiếu FAIL + thiếu đối chứng | CHƯA KIỂM CHỨNG | **FAIL** |
| đối chiếu FAIL + thiếu công cụ | CHƯA KIỂM CHỨNG | **FAIL** |
| `no_host_alert=False` + thiếu đối chứng | CHƯA KIỂM CHỨNG | **FAIL** |
| `no_host_alert=False` + thiếu công cụ | CHƯA KIỂM CHỨNG | **FAIL** |
| thời gian kết thúc đọc B = Infinity | **PASS** | ERROR |
| hai lần đọc đảo ngược | **PASS** | ERROR |
| hai lần đọc chồng nhau | CHƯA KIỂM CHỨNG | ERROR |
| guard âm | **PASS** | ERROR |
| guard NaN | CHƯA KIỂM CHỨNG | ERROR |

## 2. `probe_verdict()`: lỗi đã xác định được giữ trước

Hàm mới `determined_failures()` liệt kê các lỗi đã xác định độc lập:

- đối chiếu bộ đếm FAIL (tổng thể, hoặc riêng lớp dự kiến);
- mọi check bị False, trừ ba loại sau:
  - check chỉ là điều kiện để kiểm (đối chứng sống);
  - check phía guest khi guest **thiếu công cụ**, vì probe không được gửi nên check không thực hiện được;
  - check được tính **từ cửa sổ** (có gói probe trong pcap, gói probe chạm đúng bộ đếm) khi dữ liệu đo không hợp lệ;
- delta của lớp dự kiến bằng 0 khi guest có công cụ.

Thứ tự kết luận của một probe:

1. có lỗi đã xác định → **FAIL**. Luôn luôn, kể cả khi thiếu công cụ hay thiếu đối chứng;
2. dữ liệu đo không hợp lệ → **LỖI PHÉP ĐO** (cả lần chạy bị tính là FAIL);
3. thiếu công cụ / thiếu đối chứng / gói ở biên cửa sổ → **CHƯA KIỂM CHỨNG**;
4. còn lại, đối chiếu chính xác và lớp dự kiến tăng → **ĐẠT**.

`probe_matrix.py` ghi thêm `determined_failures` và `measurement_error` cho mỗi probe.

**Phát hiện trong khi sửa:** phép thử phát lại `evaluate()` thật cho thấy, khi thời gian đọc đảo ngược, cửa sổ tìm gói probe rỗng, nên phiên bản đầu của bản sửa đã báo FAIL thay vì LỖI PHÉP ĐO. Lỗi này được sửa bằng quy tắc "check tính từ cửa sổ" ở trên.

## 3. `counter_window.reconcile()`: kiểm dữ liệu đo

Dữ liệu được kiểm trước khi tính vùng:

- thời gian đọc là số hữu hạn, đúng thứ tự `A.start ≤ A.end ≤ B.start ≤ B.end`;
- guard hữu hạn và không âm;
- thời gian của mọi gói là số hữu hạn;
- mọi delta bộ đếm là số nguyên không âm.

Vi phạm nào cũng trả `verdict = "ERROR"` kèm lý do; không có vùng nào được tính, và kết quả không bao giờ là PASS.

Fixture mới (12 ca):

- 11 ca **phải trả ERROR**: đọc A đảo ngược; hai lần đọc đảo ngược; hai lần đọc chồng nhau; NaN và Infinity ở thời gian đọc; thiếu `t_end`; NaN ở thời gian gói; guard âm, NaN, Infinity; delta âm;
- 1 ca biên hợp lệ phải được chấp nhận: hai lần đọc chạm nhau (`A.end = B.start`), guard 0.

## 4. Tài liệu

- Bỏ câu "không bao giờ báo PASS nhầm".
- Thay bằng: kết quả đối chiếu **phụ thuộc giả định** rằng độ trễ giữa timestamp capture và lúc gói chạm bộ đếm nằm trong guard 20 ms. **Giả định này chưa được đo.** Nếu độ trễ vượt guard, gói có thể bị xếp sai vùng, và kết quả có thể sai theo cả hai chiều, kể cả PASS nhầm.
- Nội dung này nằm trong docstring của `counter_window.py` và trong các summary.
- Đính chính trong [`task06b3dr-summary.md`](task06b3dr-summary.md):
  - câu "một check thật bị FAIL luôn thắng trạng thái CHƯA KIỂM CHỨNG" **không đúng** với mã 06B-3DR;
  - câu "không bao giờ báo PASS nhầm" là khẳng định quá mức.

## 5. Kết quả offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` | **143/143 PASS**, ổn định qua 3 lần chạy | [`logs/selftest.log`](task06b3dr1/logs/selftest.log) (`aac3b9f7…fff4`) |
| `mutation_test.sh` | Baseline đạt; **48/48** đột biến hành vi bị bắt đúng check được nhắm; 2 đột biến đối chứng đúng loại. Chạy trên bản mã cuối; harness không đổi trong lúc chạy | [`logs/mutation-test.txt`](task06b3dr1/logs/mutation-test.txt) (`1eb9ad14…c953`) |

**11 đột biến mới**, đều bị bắt ngay lần đầu:

- **Thứ tự kết luận (6):** quay lại thứ tự cũ; coi cảnh báo host là điều kiện tiên quyết; bỏ qua check phía guest cả khi có công cụ; để thiếu công cụ che FAIL đối chiếu; tính check từ cửa sổ khi dữ liệu không hợp lệ; bỏ kết luận LỖI PHÉP ĐO.
- **Kiểm dữ liệu (5):** bỏ kiểm thứ tự; bỏ kiểm hữu hạn (khi đó Infinity cho ra PASS); cho guard âm; cho delta âm; bỏ kiểm thời gian gói.

Đột biến V2 của 06B-3DR được chuyển sang dòng mã tương đương, vì đoạn mã cũ đã được viết lại.

## 6. Hash và diff

- [`harness-sha256.txt`](task06b3dr1/harness-sha256.txt) (`10353429…0b48`).
- Diff so với 06B-3DR: [`ct01-06b3dr1-harness-vs-06b3dr.diff`](task06b3dr1/ct01-06b3dr1-harness-vs-06b3dr.diff) (`c5294615…43b8`).

| File | sha256 | So với 06B-3DR |
|---|---|---|
| `counter_window.py` | `f1d42562aac5f8b20a83cf535481acf3d700c4198fa0205af26cdbccf438b5a7` | +83 −12 |
| `probe_matrix.py` | `7fefd40ca0dbd4de1cfe2d59e408f926cef19f2c70e60cafa98e53fc8c6a318f` | +4 −1 |
| `selftest.sh` | `e07c93a67807e5a85bad793dcd8384fbbbec0066dc9eae7cc990ec8412b3e2e8` | +49 −4 |
| `mutation_test.sh` | `32e6653f2d2f93d9c16bfd013eea5dd8cde59e0fee58f192863e38cf77eea3bf` | +40 −1 |
| `make_fixtures.py` | `afb4d0157f982a43c46edb4f5990d60b81f7659a50d50ca1e4deec33ca6b29cf` | +30 −2 |
| `run-06b3b.sh`, `harness_lib.sh`, `pcapng_stats.py`, `sigscan.sh`, `independent_check.sh`, `ctl_loop.py`, `poller.py` | không đổi | — |

## 7. Hạn chế

- Chưa chạy tích hợp với harness mới.
- Guard 20 ms vẫn là giả định chưa đo; mọi kết quả PASS của phép đối chiếu phụ thuộc vào nó.
- Việc phân loại check thành "lỗi đã xác định / không thực hiện được / tính từ cửa sổ" là lựa chọn thiết kế, cần reviewer xem.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
