# Minh chứng Nhiệm vụ 06B-3DR: sửa phép đo của harness, kiểm thử OFFLINE (07/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Harness đã sửa **chưa chạy tích hợp lần nào**. Bằng chứng tích hợp gần nhất (06B-3D) dùng harness 06B-3CR: [`task06b3d-summary.md`](task06b3d-summary.md).

**Bối cảnh:**

- Sửa theo review 06B-3D.
- Chỉ sửa mã kiểm thử (ngoài repo, `/home/dathq/projects/ct01-06b3c/`) và tài liệu. Không sửa source cô lập. Delta của repo so với tree bàn giao 06B-3D (`3481541b…`) chỉ gồm tài liệu và minh chứng (xem file diff bàn giao).
- Bản 06B-3CR được giữ trong `ct01-06b3c/base-06b3cr/` và khớp đúng hash đã được chấp nhận.

## 1. Cửa sổ bộ đếm

Module mới: `counter_window.py`. `probe_matrix.py` dùng nó.

- **Mỗi lần đọc nft** ghi `t_start`/`t_end` của lệnh `nft -j list counters`. JSON thô được giữ trong `counters-raw.jsonl`, mỗi lần đọc một dòng.
- **Mỗi gói guest trên `tap0`** được xếp vào một trong 4 vùng, theo timestamp `t` so với lần đọc trước (A) và lần đọc sau (B):

| Vùng | Điều kiện | Ý nghĩa |
|---|---|---|
| ngoài | `t < A.t_start − guard` hoặc `t > B.t_end` | không thuộc delta |
| biên đầu | `A.t_start − guard ≤ t ≤ A.t_end` | **mơ hồ** |
| chắc chắn | `A.t_end < t < B.t_start − guard` | thuộc delta |
| biên cuối | `B.t_start − guard ≤ t ≤ B.t_end` | **mơ hồ** |

- `guard` = 20 ms là **giả định, chưa đo**: độ trễ giữa timestamp capture và lúc gói chạm bộ đếm. Nó chỉ mở rộng vùng mơ hồ, không bao giờ mở rộng vùng chắc chắn.
- **Kết luận cho mỗi lớp bộ đếm**, với `lo` = số gói chắc chắn, `hi` = `lo` + số gói biên, `d` = delta bộ đếm:
  - `d < lo` hoặc `d > hi` → **FAIL** (lệch thật);
  - có gói biên → **CHƯA KIỂM CHỨNG**;
  - chỉ khi `d = lo = hi` → **PASS**.
  - Không nới cửa sổ, không bù trừ. Gói biên được liệt kê theo lớp, kèm timestamp.
- **Kết luận cho mỗi probe:** CHƯA KIỂM CHỨNG không được tính là đạt. *(Đính chính 06B-3DR1: bản 06B-3DR từng ghi "một check thật bị FAIL luôn thắng trạng thái CHƯA KIỂM CHỨNG". Câu đó **không đúng** với mã 06B-3DR: khi thiếu công cụ hoặc thiếu đối chứng, một FAIL đã xác định có thể bị chuyển thành CHƯA KIỂM CHỨNG. Lỗi này đã được sửa ở [06B-3DR1](task06b3dr1-summary.md).)*
- **Kết luận cho cả lần chạy** (`run-06b3b.sh`): FAIL → exit 1; chỉ có CHƯA KIỂM CHỨNG → exit 4 ("NOT PASSED"); chỉ đạt khi exit 0.
- **Lớp không được đối chiếu:** các bộ đếm ARP nằm trong bảng `arp` riêng và **không** được đối chiếu với pcap. Delta của chúng được liệt kê trong `not_compared`.

## 2. Kết thúc capture

- **Ghi lại:**
  - phiên bản tcpdump/libpcap (`hostcap/versions.txt`);
  - mọi mốc của teardown (`hostcap/teardown-timeline.txt`);
  - thống kê capture (`hostcap/capture-stats.tsv`).
- **Trình tự sau khi guest cuối kết thúc:**
  1. dừng container đối chứng;
  2. chờ 3 giây để capture xử lý phần lưu lượng còn lại;
  3. kiểm bộ giám sát và heartbeat, rồi dừng bộ giám sát;
  4. gửi SIGINT tới mọi capture. Thời hạn là **10 giây**; capture nào còn chạy sẽ bị SIGKILL, ghi `KILLED_AT_DEADLINE` và tính là FAIL.
- **Giữ nguyên:**
  - kiểm mã thoát, lỗi đọc pcap, `dropped by kernel = 0`;
  - kiểm capture còn sống (có gói đối chứng);
  - kiểm chữ ký.
  - Thiếu bất kỳ dòng thống kê nào là FAIL, không bao giờ tính là 0.
- **Chênh lệch "received by filter − captured"** được báo là **mục mở**, không phải quy tắc PASS/FAIL, vì ý nghĩa của thống kê này với backend đang dùng chưa được xác minh. Lần chạy có mục mở kết thúc với exit 5 ("CHECKS PASSED, INCONCLUSIVE"), không phải exit 0. Harness không suy ra gì về các gói thiếu.

## 3. Kết quả offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` | **116/116 PASS**, ổn định qua 3 lần chạy | [`logs/selftest.log`](task06b3dr/logs/selftest.log) (`bae3f9ed…6a5e`) |
| `mutation_test.sh` | Baseline đạt; **37/37** đột biến hành vi bị bắt đúng check được nhắm; 2 đột biến đối chứng đúng loại (`INVALID`, `ERROR`). Chạy trên bản mã cuối; harness không đổi trong lúc chạy | [`logs/mutation-test.txt`](task06b3dr/logs/mutation-test.txt) (`5c3e152c…a5e`) |

**Self-test mới (D–H):**

- **D. Cửa sổ bộ đếm, 11 trường hợp:**
  - sạch → PASS;
  - biên đầu (gói được tính / không được tính) → CHƯA KIỂM CHỨNG;
  - biên cuối → CHƯA KIỂM CHỨNG;
  - vùng guard → CHƯA KIỂM CHỨNG;
  - lệch thật → FAIL; lệch thật kể cả khi có gói biên → FAIL;
  - **hai sai lệch triệt tiêu nhau** → CHƯA KIỂM CHỨNG. Với cùng dữ liệu, cách đo cũ của 06B-3B/3D báo **PASS nhầm**; self-test kiểm cả điều này;
  - gói ngoài cửa sổ → PASS;
  - lớp không đối chiếu → PASS;
  - bộ đếm tăng mà không có gói → FAIL.
- **E. Kết luận probe và lần chạy:** CHƯA KIỂM CHỨNG không bao giờ được tính là đạt; FAIL thật thắng CHƯA KIỂM CHỨNG.
- **F. Dừng capture có thời hạn**, với 3 tiến trình giả bằng Python: thoát 0, thoát 3, và bỏ qua SIGINT (bị kill đúng hạn). Thời gian chạy < 3,5 s với hạn 2 s.
- **G. Thống kê tcpdump:** thiếu dòng là lỗi, không bao giờ tính là 0.
- **H. Phát lại `evaluate()` thật** của `probe_matrix.py`, với các module worker được thay bằng stub:
  - probe sạch → ĐẠT;
  - **dạng 06B-3D**, gói IPv6 nằm trong lúc đọc A → CHƯA KIỂM CHỨNG, gói biên được liệt kê kèm timestamp;
  - lệch thật → FAIL.

**Đột biến mới (12):**

- bỏ qua gói biên; bỏ `guard`; coi gói biên là chắc chắn;
- để vùng mơ hồ che lệch thật;
- tính CHƯA KIỂM CHỨNG là đạt; để CHƯA KIỂM CHỨNG che check FAIL; để kết luận lần chạy làm nhẹ FAIL;
- không kill khi quá hạn; không giữ mã thoát; coi thống kê thiếu là 0;
- `evaluate()` quay lại cửa sổ cũ; ghi probe CHƯA KIỂM CHỨNG thành ok.

Cả 12 đều bị bắt đúng check được nhắm ngay ở lần chạy đầu.

## 4. Hash của harness 06B-3DR

[`harness-sha256.txt`](task06b3dr/harness-sha256.txt) (`5dfafa96…2211`). Diff so với 06B-3CR: [`ct01-06b3dr-harness-vs-06b3cr.diff`](task06b3dr/ct01-06b3dr-harness-vs-06b3cr.diff) (`55f71e5d…12f5e`).

| File | sha256 | So với 06B-3CR |
|---|---|---|
| `run-06b3b.sh` | `5227632f9293d631295216f8c5d50f937bd2c6fc619455805a62a72604f2f210` | +58 −16 |
| `probe_matrix.py` | `9f911ef033dfeb320ea0e12c1fbadcee2cfd6b9a84fa3289c9a1e0818c96bd54` | +45 −30 |
| `counter_window.py` | `86d4f9f019e6ea2b7ae220f17f9e5a8ad4d3402ca3392bf49e83dca28b57f869` | mới, 100 dòng |
| `harness_lib.sh` | `e148be6492d6a2a0f9117661f5efd1ec66c85665d66277366ca70763e850e071` | +47 |
| `selftest.sh` | `93b3120237b80e581b60b1ff3b15d6f7de2f6a9f18172ee96afd35149332f646` | +216 |
| `mutation_test.sh` | `8ccc5126d2d38410ce4ed504f60d351067078b221911dcd1df24b9be2a86ee97` | +37 −1 |
| `make_fixtures.py` | `8d5a5fca2608b8ddbfac81ad5660370809ed213756657266fdcf031cc835b162` | +26 |
| `pcapng_stats.py`, `sigscan.sh`, `independent_check.sh`, `ctl_loop.py`, `sentinel/poller.py` | không đổi | — |

## 5. Hồ sơ đã sửa diễn đạt

Không có pcap hay log nào bị sửa.

- [`task06b3d-summary.md`](task06b3d-summary.md):
  - nguyên nhân của FAIL nay được ghi là **giả thuyết**;
  - kết luận phía host giới hạn ở "không thấy chữ ký probe trong các pcap đã lưu";
  - chênh lệch "received − captured" là **chưa giải thích**; suy luận cũ về thời điểm các gói thiếu **đã bị rút lại**;
  - `vnet_hdr off → on` là **quan sát**, chưa kết luận là lỗi.
- [`task06b3b-summary.md`](task06b3b-summary.md): thêm ghi chú phạm vi cho câu "không có gói probe nào thoát ra".

## 6. Hạn chế

- Chưa chạy tích hợp với harness mới.
- `guard` = 20 ms là giả định. Với lưu lượng nền khoảng 1–2 gói/s, một số probe có thể ra CHƯA KIỂM CHỨNG; khi đó lần chạy không đạt. Đây là đánh đổi có chủ đích, để giảm nguy cơ PASS nhầm. *(Đính chính 06B-3DR1: bản trước ghi "không bao giờ báo PASS nhầm". Đó là khẳng định quá mức: kết quả đối chiếu chỉ đúng **nếu** độ trễ giữa timestamp capture và lúc gói chạm bộ đếm nằm trong guard 20 ms, mà giả định này chưa được đo.)*
- Bộ đếm ARP không được đối chiếu với pcap.
- Thời gian chờ 3 s và hạn 10 s là lựa chọn thiết kế, chưa được đo trên hệ thống thật.
- Ý nghĩa thống kê của backend capture (TPACKET) chưa được xác minh.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
