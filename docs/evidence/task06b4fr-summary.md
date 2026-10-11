# Minh chứng Nhiệm vụ 06B-4FR: sửa hai phát hiện của review độc lập 06B-4F (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4G):** Codex review độc lập, **chấp nhận ở mức offline** (P1/P2 đã sửa; không có lỗi chức năng mới chặn tích hợp). Cập nhật diễn đạt: "lần chạy sạch/thật" ở bản bàn giao nghĩa là **thực thi `main()` thật với stub offline** (container, guest, nft, tshark giả), không phải lần chạy tích hợp.

> **Loại bằng chứng: kiểm thử offline.**
>
> - **Harness chưa chạy tích hợp.** Không Docker, QEMU, sudo, probe mạng; không thay đổi host, source cô lập, ruleset, địa chỉ hay guard.
> - T12–T13 **vẫn chưa chạy trên guest nào**. Guard 20 ms vẫn là giả định chưa đo.
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".** Đây là kiểm chứng riêng của CT-01; đánh giá tổng thể CT-14 chưa bắt đầu.

**Mốc:** bản 06B-4F (records tree `c3f26ce900bde9942e7ea38501a78c423379ac56`). Trạng thái 06B-4F: đã review độc lập, **còn 2 lỗi, chưa chấp nhận tích hợp** (ghi chú đã thêm ở đầu [`task06b4f-summary.md`](task06b4f-summary.md)).

**Phát hiện của review:**

- **P1:** trong `run_icmp`, cảnh báo rò rỉ chỉ được kiểm **sau** mỗi lệnh guest. Nếu cảnh báo xuất hiện sau lần kiểm cuối của ca trước (ví dụ lúc đọc bộ đếm A của ca kế tiếp), ping của ca kế tiếp vẫn được gửi.
- **P2:** `arch_outcome` chỉ đòi các bản ghi có mặt đều đạt; nó **không** đòi các xác nhận hạ tầng bắt buộc có mặt. Thiếu "QEMU exit confirmed", cleanup, thống kê drop… vẫn có thể PASS. Bản ghi trùng hoặc `ok` sai kiểu (`"true"`, `1`) cũng PASS.

## 1. Bản làm việc

- Bản mới `/home/dathq/projects/ct01-06b4fr/`, chép từ `ct01-06b4f` **sau khi xác minh** 28 file khớp [`task06b4f/harness-sha256.txt`](task06b4f/harness-sha256.txt) (không thiếu, không thừa).
- `ct01-06b4f` và evidence `task06b4f/` không đổi (kiểm lại hash sau khi sửa).
- Diff: [`task06b4fr/ct01-06b4fr-harness-vs-06b4f.diff`](task06b4fr/ct01-06b4fr-harness-vs-06b4f.diff). Hash 28 file: [`task06b4fr/harness-sha256.txt`](task06b4fr/harness-sha256.txt).

| File | Thay đổi |
|---|---|
| `probe_matrix.py` | P1, chỉ trong `run_icmp` (nhánh ICMP) và docstring; nhánh IPv4 không đổi |
| `icmp_harness.py` | P2: `REQUIRED_RECORDS`, `malformed_records`, `record_problems`; `arch_outcome` dùng chúng |
| `run-06b4f.sh` | chỉ `H=/home/dathq/projects/ct01-06b4fr` và 2 dòng chú thích |
| `selftest_icmp_wiring.py` | thêm kịch bản P1, mục R (P2), sửa fixture unit theo danh sách bắt buộc |
| `mutation_icmp_wiring.py` | sửa mẫu W17 theo dòng mới; thêm W28–W34 |

## 2. Bản sửa

**P1 — kiểm cảnh báo trước lệnh (`probe_matrix.run_icmp`):**

- Hàm `check_alerts(cmd, when)` đọc file cảnh báo bằng `alert_lines()` (không đổi). Có dòng nào thì ghi bản ghi "NO probe packet seen on host interfaces (leak monitor)" (thêm trường `when`) và ném `LeakDetected`.
- Kiểm tra **trước** mỗi lệnh gửi vào guest: `check_alerts` rồi `captures_alive`. **Sau** lệnh giữ như cũ: `check_alerts` rồi `captures_alive`.
- **Lỗi đọc** file cảnh báo (thiếu file, không đọc được) ném lỗi từ `alert_lines()`, và `GuardedRunner` dừng nhóm. Lỗi này **không bao giờ** được coi là "không có cảnh báo": lần chạy kết thúc với status ERROR (exit 1).
- Dừng theo mã lỗi hiện có: rò rỉ → exit 99; mất capture → 98; lỗi khác → 1.
- **Không** thêm cơ chế ngắt tức thì lệnh đang chạy: một cảnh báo xuất hiện **trong lúc** ping đang chạy vẫn chỉ được phát hiện ở lần kiểm sau lệnh.

**P2 — xác nhận hạ tầng bắt buộc (`icmp_harness.arch_outcome`, lệnh `--outcome` mà run script gọi):**

- `REQUIRED_RECORDS`: 16 xác nhận mà đường chạy ICMP thật (`main` + `run_icmp` + `evaluate_icmp`) ghi lại và mà một PASS cần:
  - trước boot: cảnh báo trống, verify trước spawn, tshark trên `tap0`;
  - boot và cổng topology;
  - lưu lượng kiểm capture trước và sau nhóm;
  - liên kết dịch vụ trước và sau nhóm;
  - MAC `tap0` không đổi; đủ 5 ca đã chạy;
  - QEMU thoát; tshark dừng sạch; thống kê drop; cleanup fixture/marker/đĩa tạm;
  - bản ghi nhóm ICMP hợp lệ.
- Mỗi xác nhận phải có **đúng một lần**, với `ok` **đúng bằng `True`**. Thiếu, trùng hoặc không đạt đều FAIL, kèm tên xác nhận.
- Mọi bản ghi trong `result.json` phải là object có `test` kiểu chuỗi và `ok` kiểu boolean; sai thì FAIL ngay, **trước** khi `counter_window.run_outcome` đọc. Không có giá trị mặc định thành công.
- Bản ghi `info: …` và bản ghi ca không nằm trong danh sách; các ca vẫn được kiểm riêng như 06B-4F.
- **Đồng bộ với đường mã thật:** test R1 kiểm rằng lần thực thi `main()` thật với stub offline (kịch bản sạch) ghi mỗi xác nhận đúng một lần. Test R2 kiểm rằng đường mã đó không ghi thêm kiểm tra nào (ngoài `info:` và ca) nằm ngoài danh sách. Đổi tên hay thêm một kiểm tra hạ tầng mà không cập nhật danh sách thì test hỏng.
- Không đổi: nhãn "ĐẠT (kiểm quy tắc)", thứ tự ưu tiên, cách xử lý ca CHƯA KIỂM CHỨNG (UNVERIFIED). ĐẠT của ca không che lỗi hay thiếu hạ tầng.

## 3. Tái hiện trước/sau

Script: [`task06b4fr/repro.py`](task06b4fr/repro.py). Log: [`logs/repro-before-after.txt`](task06b4fr/logs/repro-before-after.txt).

- Mỗi phiên bản chạy bằng `probe_matrix.py`, `icmp_harness.py`, `run-06b4f.sh` **của chính nó**.
- Chỉ bộ dựng kịch bản (container/guest giả) lấy từ 06B-4FR, vì hai kịch bản P1 chỉ có ở đó.
- P2 dùng biến thể của `result.json` **từ lần thực thi `main()` thật với stub offline (kịch bản sạch)** của từng phiên bản. Kết luận lấy từ `icmp_harness.py --outcome`, đúng lệnh mà run script gọi.

**P1** (cảnh báo xuất hiện trong lần đọc bộ đếm "T12-B2 before"):

| Kịch bản | 06B-4F | 06B-4FR |
|---|---|---|
| Dòng cảnh báo được ghi | **ping T12-B2 vẫn được gửi** (2 ping); exit 99, "LEAK: after 'ping … 224.0.0.1'" | ping T12-B2 **không** được gửi (1 ping); exit 99, "LEAK: before 'ping … 224.0.0.1'" |
| File cảnh báo không đọc được (thay bằng thư mục) | **ping T12-B2 vẫn được gửi**; dừng ở lần kiểm sau lệnh | ping T12-B2 **không** được gửi; exit 1, status ERROR (IsADirectoryError) |

**P2** (26 biến thể): 06B-4F kết luận sai **21**, 06B-4FR sai **0**.

| Biến thể | 06B-4F | 06B-4FR |
|---|---|---|
| Fixture sạch (thực thi `main()` thật với stub offline) | PASS | PASS |
| Thiếu từng xác nhận (16 biến thể) | **PASS** cả 16 | FAIL "required confirmation missing: …" |
| Thiếu tất cả xác nhận | **PASS** | FAIL, liệt kê đủ 16 |
| Trùng (cả hai `ok`): "QEMU exit confirmed", "tap0 capture stopped cleanly" | **PASS** | FAIL "recorded 2 times" |
| `ok="true"`, `ok=1` | **PASS** | FAIL (không phải boolean) |
| `ok=None`; thiếu khóa `ok` | FAIL | FAIL (không phải boolean) |
| `ok=False` (QEMU exit, cleanup) | FAIL | FAIL "not passed (ok=False)" |

## 4. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_icmp_wiring.py` | **129/129**; ổn định 6 lần liên tiếp | [`logs/selftest-icmp-wiring.log`](task06b4fr/logs/selftest-icmp-wiring.log), [`logs/selftest-icmp-wiring-stability.txt`](task06b4fr/logs/selftest-icmp-wiring-stability.txt) |
| `mutation_icmp_wiring.py` | **33/33** đột biến hành vi bị bắt đúng test (26 cũ + 7 mới) + 2 đối chứng đúng loại; hash harness không đổi | [`logs/mutation-icmp-wiring.txt`](task06b4fr/logs/mutation-icmp-wiring.txt) |
| `selftest.sh` (do sửa `probe_matrix.py`; mục H import nó ở chế độ IPv4 mặc định) | 205 PASS, "ALL PASSED" | [`logs/selftest-sh.log`](task06b4fr/logs/selftest-sh.log) |
| `selftest_icmp.py` (run script chạy trước khi bắt đầu) | 79/79 | [`logs/selftest-icmp.log`](task06b4fr/logs/selftest-icmp.log) |

**Test mới, đều đi qua đường mã thật:**

| Test | Nội dung |
|---|---|
| S35, S36 | `probe_matrix.main()` thật: cảnh báo ghi khi đọc "T12-B2 before" → 1 ping, exit 99, bản ghi `when=before`; QEMU vẫn tắt, cleanup vẫn chạy |
| S37 | File cảnh báo không đọc được khi đọc A → 1 ping, exit 1 (ERROR), không đánh giá, kết luận FAIL |
| R1, R2 | Danh sách bắt buộc đồng bộ với lần thực thi `main()` thật với stub offline |
| R3 | Fixture sạch PASS (hàm và CLI); nhãn ca không đổi |
| R4.1–R4.16 | Thiếu từng xác nhận → FAIL |
| R5, R6 | Thiếu tất cả xác nhận; không có bản ghi nào → FAIL |
| R7 | Trùng 3 xác nhận khác nhau → FAIL |
| R8–R11 | `ok` là `"true"`, `1`, `None`, list, object; thiếu khóa `ok`; `test` không phải chuỗi; bản ghi không phải object → FAIL |
| R12 | Từng xác nhận `ok=False` → FAIL |
| R13 | 5 ca ĐẠT không che thống kê drop thất bại |

Các kiểm tra R chạy cả `arch_outcome()` và CLI `icmp_harness.py --outcome` mà `run-06b4f.sh` gọi.

**Đột biến mới:**

| Mã | Đột biến | Bị bắt ở |
|---|---|---|
| W28 | bỏ kiểm cảnh báo trước lệnh | S35 |
| W29 | nuốt lỗi đọc cảnh báo thành "không có cảnh báo" | S37 |
| W30 | bỏ kiểm thiếu | R5 |
| W31 | bỏ kiểm trùng | R7 |
| W32 | bỏ kiểm kiểu `ok` | R8 |
| W33 | xóa "QEMU exit confirmed" khỏi danh sách | R2 |
| W34 | bỏ hẳn kiểm xác nhận | R4.15 |

W17 (bỏ kiểm cảnh báo) chuyển sang dòng mới, vẫn bị bắt ở S16.

**Không chạy lại** (không liên quan tới file đổi):

- `mutation_test.sh` (~13 phút): các đột biến `probe_matrix.py` của nó nhắm vào `captures_alive`, `evaluate`, đo toàn phiên, quét QEMU. Diff 06B-4F → 06B-4FR của `probe_matrix.py` chỉ nằm ở docstring đầu file và `run_icmp`. Lần chạy 78/78 ở 06B-4F vẫn áp dụng cho các dòng đó.
- `selftest_l2`, `selftest_l2eval` và mutation tương ứng: `l2frames.py`, `l2eval.py`, `signatures.py`, `icmp_cases.py` không đổi.

## 5. Tài liệu đã cập nhật

Không tìm thấy báo cáo Codex trong repo hay trên máy. Các đoạn dưới đây là đoạn lỗi thời **tự rà** theo yêu cầu của nhiệm vụ; reviewer cần đối chiếu với báo cáo Codex.

- [`../network-isolation-design.md`](../network-isolation-design.md):
  - dòng trạng thái ("chưa chạy worker/guest; chưa có kiểm thử T01–T21") được thay bằng trạng thái hiện tại;
  - đầu §7 có thêm bảng tình trạng thực hiện T01–T21/F1–F6;
  - tiêu đề §7 và §11 bỏ "chưa thực hiện"/"chưa chạy guest".
- [`../ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md):
  - dòng trạng thái ("chưa chạy phép thử nào; chưa viết probe mới"): nay ghi 5 ca T12–T13 đã viết và nối offline; B3, I3, T20 chưa viết; T14–T17 chưa có probe;
  - §6 bước 2 thêm ghi chú tiến độ.
- [`../../KQCaiTien.md`](../../KQCaiTien.md):
  - 06B-4F: đã review, còn lỗi, chưa chấp nhận tích hợp; thêm mục 06B-4FR;
  - mục "Chưa kiểm chứng" không còn ghi T12/T13 "chỉ có kế hoạch". Mục "Còn thiếu" bỏ việc "review harness 06B-4B" (đã xong ở 06B-4BR);
  - bỏ cách gọi "IPv6 có đối chứng (T13)": T13 là kiểm quy tắc, không có đối chứng sống;
  - **CT-14:** tách rõ "đánh giá tổng thể chưa bắt đầu" với các kiểm chứng từng phần của CT-01 (và CT-05), không tính vào CT-14.

Log, pcap và evidence cũ không sửa. Chỉ thêm ghi chú review ở đầu `task06b4f-summary.md`, như đã làm với 06B-4E.

## 6. Hạn chế còn lại

- **Chưa chạy tích hợp;** toàn bộ bằng chứng là offline với container, guest, nft và tshark giả.
- **Cảnh báo trong lúc lệnh đang chạy:** chỉ được phát hiện sau khi lệnh kết thúc (ping tối đa `-w 5`; lệnh liên kết `curl -m 10`). Theo yêu cầu, không có ngắt tức thì.
- **Danh sách bắt buộc là danh sách tên:** đổi tên bản ghi trong `probe_matrix.py` phải sửa cả `REQUIRED_RECORDS`; test R1/R2 bắt sự lệch này.
- **Phạm vi P2:** chỉ áp dụng cho kết luận theo kiến trúc. Các kiểm tra phía host vẫn do run script ghi vào `FAILS` như trước: cảnh báo, bộ quét, trạng thái host, netns, ruleset chuẩn hóa, xóa container, khôi phục manager.
- **`run-06b4f.sh` chưa chạy**, kể cả với docker giả: chỉ kiểm cú pháp, kiểm tĩnh và khối ánh xạ kết luận.
- **Giả định chưa kiểm:** guest giả không mô phỏng MLD/DAD thật; hành vi BusyBox với broadcast vẫn là giả định; guard 20 ms chưa đo.
- **Tài liệu:** cập nhật theo rà soát của tôi, chưa đối chiếu với báo cáo Codex (không có trên máy).
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"; CT-14 chưa bắt đầu.**

## 7. Hash

- [`harness-sha256.txt`](task06b4fr/harness-sha256.txt): 28 file của bản làm việc.
- Mọi file trong `task06b4fr/`: [`SHA256SUMS`](task06b4fr/SHA256SUMS) (`f3abe320b5c8388b83338f7e5169f896e30540d8c214c36a81965fd5801b32a7`).
