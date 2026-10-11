# Minh chứng Nhiệm vụ 06B-3F: đối chiếu bộ đếm toàn phiên guest, kiểm thử OFFLINE (07/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Phép đo toàn phiên **chưa chạy tích hợp lần nào**.

> **Trạng thái review (cập nhật ở 06B-3FR, 07/10/2026):** reviewer đã đọc patch 06B-3F, xác nhận hash, và tái hiện được **4 trường hợp báo PASS sai**. 06B-3F **còn lỗi** và **chưa được chấp nhận để chạy tích hợp**. Bốn nhóm lỗi gồm: gói guest trước cửa sổ bị bỏ qua; trạng thái QEMU sau khi thoát không vào kết luận; thiếu F2 hoặc có lỗi đọc cuối vẫn PASS; bộ đếm bị thiếu được thay bằng 0. Phần sửa ở [`task06b3fr-summary.md`](task06b3fr-summary.md). Nội dung bên dưới giữ nguyên như lúc bàn giao 06B-3F.

**Bối cảnh:**

- Reviewer chấp nhận báo cáo 06B-3E đúng phạm vi exit 4; kết quả và evidence của 06B-3E giữ nguyên.
- Chỉ sửa mã kiểm thử (ngoài repo, `/home/dathq/projects/ct01-06b3c/`) và tài liệu. Không sửa source cô lập.
- Bản 06B-3DR1 được giữ trong `ct01-06b3c/base-06b3dr1/` và khớp đúng hash đã được chấp nhận.
- Guard giữ 20 ms. Không tắt DHCP/IPv6/DNS của guest. Không thêm probe mạng.

## 1. Tiêu chí mới: đối chiếu toàn phiên (mỗi kiến trúc một lần)

### Trình tự đo trong `probe_matrix.py`

1. **Trước boot:**
   - tshark trên `tap0` đang chạy;
   - capture phía host và heartbeat còn sống (`captures_alive`);
   - quét `/proc` trong container để **xác nhận chưa có QEMU**;
   - đọc bộ đếm nền A (`session before boot`), có `t_start`/`t_end`; JSON thô vào `counters-raw.jsonl`.
2. **Trong suốt** boot, liên kết dịch vụ và 10 probe, tshark capture **liên tục**, không dừng.
3. **Sau `shutdown_qemu`:**
   - ghi `exit_confirmed` và thời điểm xác nhận QEMU đã thoát;
   - nếu đã xác nhận: chờ 0,5 s → đọc F1, chờ 0,5 s → đọc F2. Tổng thời gian chờ có giới hạn: 1 s.
   - **Mọi lần đọc đều được lưu.** F1 đóng cửa sổ phiên; F2 chỉ dùng để kiểm bộ đếm đã ổn định. Không lần đọc nào bị bỏ để có kết quả đẹp.
   - Các lần đọc cuối diễn ra **trước** khi dừng tshark.
4. **Sau khi dừng tshark:** `evaluate_session()` đọc toàn bộ pcap, phân loại mọi gói guest như ở đối chiếu từng probe, rồi gọi `counter_window.session_reconcile()`. Kết quả ghi vào `session.json`.

Thứ tự trên được kiểm trên mã nguồn bằng `ast` (`main()` cần QEMU nên không chạy offline được): đọc nền < spawn QEMU < shutdown < đọc cuối < dừng tshark < đánh giá.

### Kết luận toàn phiên (`session_reconcile`)

Xét theo thứ tự:

| Kết luận | Điều kiện |
|---|---|
| **ERROR** | QEMU đã chạy trước lần đọc nền; QEMU thoát chưa được xác nhận; không có lần đọc cuối; thời gian không hữu hạn hoặc sai thứ tự (`A.start ≤ A.end ≤ xác nhận QEMU thoát ≤ F1.start ≤ F1.end ≤ F2.start ≤ …`); bộ đếm giảm hoặc dữ liệu đọc không hợp lệ |
| **FAIL** | delta F1 − A của một lớp nằm ngoài `[chắc chắn, chắc chắn + biên]` **và** capture đầy đủ. Nếu capture không đầy đủ, chỉ trường hợp "bộ đếm **nhỏ hơn** số gói đã ghi" mới là FAIL, vì capture thiếu không thể sinh thêm gói |
| **CHƯA KIỂM CHỨNG** | capture không đầy đủ (tshark exit ≠ 0, thống kê ISB không ĐẠT, hoặc pcap không đọc được); bộ đếm đang so còn thay đổi giữa F1 và F2; có gói guest sau thời điểm xác nhận QEMU thoát; có gói ở biên đầu hoặc biên cuối của cửa sổ phiên |
| **PASS** | không có điều kiện nào ở trên, và mọi lớp khớp chính xác |

- **Kỳ vọng thiết kế (chưa phải kết luận):** lần đọc A nằm trước khi spawn QEMU, và lần đọc F1 nằm sau khi QEMU đã thoát, nên hai biên của cửa sổ phiên **được kỳ vọng** không có gói guest. *(Đính chính: bản nháp trước viết như thể "QEMU chưa chạy nên không có gói guest ở biên đầu". Đó là suy luận từ thứ tự lệnh, không phải điều đã kiểm. Điều này phải được kiểm bằng trạng thái tiến trình **và** pcap.)*
- **Mã hiện tại kiểm đến đâu:**

| Thời điểm | Trạng thái tiến trình | Pcap |
|---|---|---|
| Trước lần đọc A | **có kiểm:** quét `/proc`; có QEMU thì ERROR | gói ở `[A.start − guard, A.end]` làm kết quả CHƯA KIỂM CHỨNG. **Chỗ hở:** gói guest có timestamp trước `A.start − guard` bị xếp vào vùng "ngoài cửa sổ" và **bị bỏ qua, không làm mất PASS** |
| Sau khi xác nhận QEMU thoát | `exit_confirmed` theo `proc.isalive()`. **Chỗ hở:** `qemu_pids_after_exit` chỉ được ghi vào `session.json`, **không** dùng trong kết luận | **có kiểm:** gói guest sau thời điểm xác nhận thoát → CHƯA KIỂM CHỨNG |

  Hai chỗ hở trên chưa được sửa trong 06B-3F, cần reviewer quyết định. Điều kiện "không có gói guest ở biên" **chưa được kiểm chứng tích hợp**.
- **Lớp được đối chiếu:** đúng các lớp như ở từng probe: `allow_svc`, `drop_spoof`, `drop_non_ipv4`, `drop_worker_other`, `drop_private`, `drop_bcast_mcast`, `drop_public`, `l2_bad_ethertype`, `l2_bad_mac`.
- **Lớp chưa đối chiếu** được ghi rõ trong `not_compared`, kèm delta và lý do:

| Bộ đếm | Lý do |
|---|---|
| `arp_in_ok`, `arp_in_drop` | bảng `arp`; harness chưa có ánh xạ từ pcap |
| `arp_out_ok`, `arp_out_drop`, `allow_out_svc`, `drop_out` | chiều từ worker tới guest, không phải gói guest |
| `drop_input_backstop`, `drop_forward` | hook input/forward (sau prerouting); chưa có ánh xạ từ pcap |

- **Giả định:** mọi kết quả PASS phụ thuộc giả định rằng độ trễ giữa timestamp capture và lúc gói chạm bộ đếm nằm trong guard 20 ms. Giả định này **chưa được đo**, và được ghi trong mỗi `session.json`.

### Tách bạch khỏi kết luận hiện có

- Kết quả toàn phiên **không** được ghi bằng `record()`, nên không vào `result.json["results"]`.
- Vì vậy nó **không** đổi kết luận của từng probe, không đổi `run_outcome()` và **không đổi mã thoát** (0/1/4/5 như cũ).
- `run-06b3b.sh` in mỗi kiến trúc một dòng `[SESSION]`, và một mục riêng "SESSION-WIDE reconciliation (reported separately; does not change the exit code)" ở phần kết quả. Kết quả toàn phiên không vào FAILS hay UNVERIFIED.
- **Toàn phiên PASS không che** FAIL của probe, lỗi capture hay probe CHƯA KIỂM CHỨNG. Phép phát lại `evaluate()` và `evaluate_session()` thật kiểm điều này (§2).
- Quy tắc nghiệm thu chưa đổi. Có dùng kết quả toàn phiên trong nghiệm thu hay không là việc reviewer quyết định sau.

## 2. Kết quả offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` | **171/171 PASS**, ổn định qua 3 lần chạy | [`logs/selftest.log`](task06b3f/logs/selftest.log) |
| `mutation_test.sh` | Baseline đạt; **60/60** đột biến hành vi bị bắt đúng check được nhắm (12 đột biến toàn phiên mới đều bị bắt ngay lần đầu); 2 đột biến đối chứng đúng loại. Chạy trên bản mã cuối; harness không đổi trong lúc chạy | [`logs/mutation-test.txt`](task06b3f/logs/mutation-test.txt) |

**Self-test mới:**

- **I. Toàn phiên, 17 ca:**
  - phiên sạch → PASS, và các lớp chưa đối chiếu được liệt kê kèm delta và lý do;
  - gói ở biên đầu; gói ở biên cuối → CHƯA KIỂM CHỨNG;
  - lệch thật → FAIL;
  - thiếu capture: bộ đếm lớn hơn pcap → CHƯA KIỂM CHỨNG; bộ đếm nhỏ hơn pcap → FAIL; pcap không đọc được → CHƯA KIỂM CHỨNG; tshark thoát ≠ 0 → CHƯA KIỂM CHỨNG;
  - thời gian sai: QEMU thoát sau lần đọc cuối; lần đọc cuối trước lần đọc nền; NaN → ERROR;
  - QEMU chạy từ trước; QEMU thoát chưa được xác nhận; không có lần đọc cuối; bộ đếm giảm → ERROR;
  - bộ đếm còn thay đổi sau khi QEMU thoát; có gói guest sau khi QEMU thoát → CHƯA KIỂM CHỨNG.
- **Thứ tự trong `main()`:** kiểm bằng `ast`. Thiếu một bước bắt buộc là FAIL, không phải lỗi của phép thử.
- **H. Phát lại `evaluate()` / `evaluate_session()` thật** (module worker thay bằng stub):
  - toàn phiên khớp → PASS, có `session.json`;
  - kết quả toàn phiên không thêm bản ghi nào vào `results`;
  - **toàn phiên PASS nhưng một probe FAIL:** probe vẫn FAIL, kết luận lần chạy vẫn FAIL;
  - toàn phiên FAIL (thừa một gói được đếm) được báo riêng; kết luận lần chạy của các probe không đổi;
  - `session.json` ghi giả định guard chưa được đo.

**Đột biến mới (12):** bỏ qua gói biên toàn phiên; bỏ kiểm capture đầy đủ; bỏ kiểm gói sau khi QEMU thoát; bỏ kiểm ổn định; bỏ kiểm "chưa có QEMU"; bỏ kiểm thứ tự thời gian; để capture thiếu che trường hợp bộ đếm nhỏ hơn pcap; ẩn `not_compared`; đưa kết quả toàn phiên vào `results`; chuyển việc đọc cuối ra sau khi dừng tshark; chuyển việc đọc nền ra sau khi spawn QEMU; xóa việc đọc nền.

## 3. Hash và diff

- Diff so với 06B-3DR1: [`ct01-06b3f-harness-vs-06b3dr1.diff`](task06b3f/ct01-06b3f-harness-vs-06b3dr1.diff) (`bd32dfda16736f776a39614ee4e107733499d1c80419811fe4643ba24f6bad45`).
- [`harness-sha256.txt`](task06b3f/harness-sha256.txt) (`5ec05b1fca0b062b1b91ee7beb5f6b7e7b1678d00e489fda24fe1022825ec17b`).
- Log: [`logs/selftest.log`](task06b3f/logs/selftest.log) (`cd1f380610d65b6dfd503b2f46e5595a387ca95b978628ca9fe63385cb61d2ba`); [`logs/mutation-test.txt`](task06b3f/logs/mutation-test.txt) (`67c36d39449438a488b1d123a1e4d6abec852e64b452f3f9bd40db96cdc34a64`).

| File | sha256 | So với 06B-3DR1 |
|---|---|---|
| `counter_window.py` | `d1f8c2084ed1c3eb73ec3c789dccf199b8f432f2e1e4bed29879da39c0a27b2c` | +97 |
| `probe_matrix.py` | `3fa565ed8192e22270438c924f8773fb5be7ed32e8a9626e2db48c92d822caca` | +65 |
| `run-06b3b.sh` | `8b193e93d0d255285c30a5f9141fdfc769a008847d916fe6171d91c9da715458` | +11 −1 |
| `selftest.sh` | `3d2c0a7ae0fb032ed79d28cd50e8e1869cad31bf2034b6469fd64cb564a12f72` | +84 |
| `mutation_test.sh` | `21f404c8165a2c0b15f5330a239f38c9ea21f01ab8c38ec6dedaf49ea9f0f531` | +43 |
| `make_fixtures.py` | `5b971ea607c68042c9cd64fcecc5bc0f2b98c23794562dcad1b58f38e5614b10` | +54 |
| `harness_lib.sh`, `pcapng_stats.py`, `sigscan.sh`, `independent_check.sh`, `ctl_loop.py`, `poller.py` | không đổi | — |

## 4. Hạn chế

- Phép đo toàn phiên mới chỉ được kiểm offline. Thứ tự trong `main()` chỉ được kiểm trên mã nguồn, chưa chạy thật.
- Hai chỗ hở ở §1: gói guest trước biên đầu bị bỏ qua; `qemu_pids_after_exit` không được dùng trong kết luận.
- Guard 20 ms là giả định chưa đo.
- Thời gian chờ 0,5 s trước mỗi lần đọc cuối (tổng 1 s) là lựa chọn thiết kế, chưa được đo trên hệ thống thật.
- Bộ đếm ARP, input/forward và chiều ra chưa được đối chiếu; chúng được liệt kê trong `not_compared`.
- Toàn phiên PASS không chứng minh từng probe; kết luận của từng probe vẫn như cũ.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
