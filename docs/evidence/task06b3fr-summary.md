# Minh chứng Nhiệm vụ 06B-3FR: sửa tính đầy đủ của phép đo toàn phiên, kiểm thử OFFLINE (07/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Phép đo toàn phiên **chưa chạy tích hợp lần nào**.

> **Trạng thái review (cập nhật ở 06B-3FR1):** reviewer xác nhận phần đối chiếu của 06B-3FR, nhưng tái hiện được một lỗi còn lại: `qemu_pids()` gặp `PermissionError` khi đọc `/proc/<pid>/comm` thì trả `[]`, dẫn đến toàn phiên PASS sai. Vì vậy mục (2) "không xác minh được thì ERROR" ở dưới **không đúng** với mã 06B-3FR khi lỗi xảy ra **bên trong** `qemu_pids()`: lỗi bị nuốt trước khi tới bên gọi. Phần sửa ở [`task06b3fr1-summary.md`](task06b3fr1-summary.md). Nội dung bên dưới giữ nguyên như lúc bàn giao.

**Bối cảnh:**

- Reviewer đọc patch 06B-3F, xác nhận hash, và tái hiện được 4 trường hợp báo PASS sai. 06B-3F còn lỗi, **chưa được chấp nhận để chạy tích hợp**.
- Chỉ sửa harness (ngoài repo, `/home/dathq/projects/ct01-06b3c/`) và tài liệu. Không sửa source cô lập hay mạng host.
- Bản 06B-3F được giữ trong `ct01-06b3c/base-06b3f/` và khớp đúng hash đã bàn giao.
- Guard giữ 20 ms. Giả định "độ trễ từ timestamp capture tới lúc gói chạm bộ đếm nằm trong guard" **chưa được đo**, và được ghi trong mỗi `session.json`.
- Kết quả toàn phiên vẫn **báo riêng**: không đổi kết luận probe, `run_outcome()` hay mã thoát.

## 1. Tái hiện trên bản 06B-3F, so với bản đã sửa

Log: [`logs/repro-before-after.txt`](task06b3fr/logs/repro-before-after.txt).

| Ca hồi quy | Mong đợi | 06B-3F (trước) | 06B-3FR (sau) |
|---|---|---|---|
| gói guest (`drop_public`) trước cửa sổ | CHƯA KIỂM CHỨNG | **PASS** | CHƯA KIỂM CHỨNG |
| gói guest ARP trước cửa sổ | CHƯA KIỂM CHỨNG | **PASS** | CHƯA KIỂM CHỨNG |
| gói guest ARP ở biên đầu | CHƯA KIỂM CHỨNG | **PASS** | CHƯA KIỂM CHỨNG |
| còn QEMU sau khi thoát | ERROR | **PASS** | ERROR |
| trạng thái QEMU sau khi thoát không xác minh được (`None`) | ERROR | **PASS** | ERROR |
| quét tiến trình QEMU bị lỗi | ERROR | **PASS** | ERROR |
| thiếu F2 | ERROR | **PASS** | ERROR |
| có `final_read_error` | ERROR | **PASS** | ERROR |
| thiếu bộ đếm được đối chiếu ở A / F1 / F2 | ERROR | **PASS** (cả 3) | ERROR (cả 3) |

## 2. Tiêu chí đã sửa (`counter_window.session_reconcile`, `probe_matrix.evaluate_session`)

1. **Gói guest trước cửa sổ:**
   - Kiểm **toàn bộ** pcap. Mọi gói guest (`cls` khác `None`, **kể cả ARP và lớp chưa đối chiếu**) có timestamp ≤ `A.end` đều được ghi vào `session.json` → `guest_frames_before_window`, mỗi gói kèm `t`, `cls` và `reason` ("before A.start − guard (outside the window)" hoặc "in the start edge [A.start − guard, A.end]").
   - Có gói như vậy thì kết quả toàn phiên **không PASS** (CHƯA KIỂM CHỨNG).
   - Gói không phải của guest trước cửa sổ không ảnh hưởng.
2. **Trạng thái QEMU sau khi thoát:**
   - `qemu_pids_after_exit` được truyền vào `session_reconcile` qua `evaluate_session()` thật, và là một phần của kết luận.
   - Còn pid QEMU → **ERROR**. Không xác minh được (không phải danh sách, `None`, chưa được ghi, hoặc có lỗi khi quét) → **ERROR**.
   - Việc quét sau khi thoát được bọc try; lỗi được ghi vào `qemu_pids_after_exit_error`, khối `finally` không bị hỏng.
   - Trước boot cũng kiểm nhất quán: `no_qemu_before` phải đúng **và** `pids_before` phải là danh sách rỗng.
3. **Đủ các lần đọc cuối:**
   - Bắt buộc F1 và F2 (`required_finals = SESSION_FINAL_READS = 2`). Thiếu thì **ERROR**: một snapshot không phải bằng chứng ổn định.
   - `final_read_error` có giá trị → **ERROR**. Lỗi được giữ trong `session.json` → `reads.final_read_error`.
   - Mọi lần đọc đều được giữ.
4. **Đủ bộ đếm:**
   - A, F1, F2 đều phải có đủ mọi lớp được đối chiếu. Thiếu → **ERROR** "a missing counter is not 0". Đã bỏ `get(k, 0)` ở delta và ở phép kiểm ổn định.
   - Giá trị phải là số nguyên không âm (bool bị từ chối). Thứ tự thời gian vẫn được kiểm.
   - Bộ đếm chưa đối chiếu chỉ có ở một phía được ghi `delta: null` kèm `missing_in`, không thay bằng 0.

## 3. Kết quả offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` | **195/195 PASS**, ổn định qua 3 lần chạy | [`logs/selftest.log`](task06b3fr/logs/selftest.log) (`d0f0da65380f510bc795b5e8a60098a4b6480a2dfc145e6fff69c6735889442a`) |
| `mutation_test.sh` (lần 2, bản cuối) | Baseline đạt; **71/71** đột biến hành vi bị bắt đúng check được nhắm; 2 đột biến đối chứng đúng loại; harness không đổi trong lúc chạy | [`logs/mutation-test.txt`](task06b3fr/logs/mutation-test.txt) (`a2ea1532bea7ce751241d0087d5b1403ed1bf6e3c2f563f7baa9ef5647393cdc`) |
| `mutation_test.sh` (lần 1) | 70/71 đúng như dự kiến. Đột biến cũ **SE1** (bỏ qua gói biên của cửa sổ phiên) bị bắt, nhưng ở ca `edge-end` thay vì ca được nhắm `edge-start` (DETECTED-ELSEWHERE) | [`logs/mutation-test-run1-SE1-retargeted.txt`](task06b3fr/logs/mutation-test-run1-SE1-retargeted.txt) (`6b5a762db147f0b1a975f4a2083935eba018dff5e66d394b3cb4860a0121e36e`) |

**Về SE1:** gói trong ca `edge-start` có `t ≤ A.end`, nên nay cũng bị quy tắc mới về gói trước cửa sổ bắt, và ca này không còn cô lập riêng phần xử lý biên. SE1 được đổi mục tiêu sang `edge-end`, ca duy nhất còn cô lập phần đó; lý do được ghi ngay trong `mutation_test.sh`. Đây là việc chọn lại ca mục tiêu: đột biến bị bắt ở cả hai lần chạy, phép thử không bị nới.

**Test hồi quy mới:**

- **Phần I, 14 ca cho 4 nhóm:**
  - gói `drop_public` trước cửa sổ; gói ARP trước cửa sổ (kiểm cả bản ghi timestamp/lớp/lý do); gói ARP ở biên đầu; gói không phải của guest trước cửa sổ (vẫn PASS);
  - còn QEMU; trạng thái `None`; lỗi khi quét; `pids_before` có pid;
  - thiếu F2; `final_read_error`;
  - thiếu lớp ở A, F1, F2; giá trị là bool.
  - Mỗi ca bị lỗi Python được báo FAIL theo tên ca, không bao giờ tính là đạt.
- **Hai fixture cũ được sửa** (`final-before-read-before`, `final-time-nan`): nay có đủ F1 và F2, để vẫn kiểm đúng điều kiện thứ tự thời gian và NaN của chúng. Nếu không sửa, chúng sẽ dừng sớm ở check "thiếu F2".
- **Phần H, 9 ca phát lại qua `evaluate_session()` thật:**
  - baseline đầy đủ → PASS;
  - ARP của guest trước cửa sổ → không PASS, có trong `session.json`;
  - còn QEMU, trạng thái chưa ghi, lỗi khi quét → ERROR;
  - chỉ có F1, có lỗi đọc → ERROR, lỗi được giữ;
  - thiếu lớp ở A → ERROR;
  - kết quả toàn phiên vẫn không vào `results`.

**Đột biến mới (11), mỗi cái bỏ một điều kiện mới:**

- bỏ kiểm gói trước cửa sổ; chỉ kiểm lớp được đối chiếu; bỏ chi tiết timestamp/lớp/lý do;
- bỏ qua pid sau khi thoát; chấp nhận trạng thái không xác minh được; `evaluate_session()` không truyền pid; bỏ kiểm `pids_before`;
- không bắt buộc F2; bỏ qua lỗi đọc cuối; `evaluate_session()` không truyền lỗi đọc;
- quay lại `get(k, 0)` cho bộ đếm bị thiếu.

Hai đột biến 06B-3F (SE5, SE8) được chuyển sang dòng mã mới tương ứng.

## 4. Hash và diff

- Diff so với 06B-3F: [`ct01-06b3fr-harness-vs-06b3f.diff`](task06b3fr/ct01-06b3fr-harness-vs-06b3f.diff) (`27151c7e9b84e7a711d78e96e740ac6e46bb35e3b68e8183943a4f8cc154843a`).
- [`harness-sha256.txt`](task06b3fr/harness-sha256.txt) (`06163c5bc0e7ee464e5c32764a718a662644995ee111ad43f954c32038edfdfe`).
- [`logs/repro-before-after.txt`](task06b3fr/logs/repro-before-after.txt) (`2a08868641af10a1e698a43039a611a4f8a0845b2083e472ed0b13b60191c420`).

| File | sha256 | So với 06B-3F |
|---|---|---|
| `counter_window.py` | `4c4ea6b8a2725b9749a921d972c64b529833f84f0b5e0026411db57cc5ae3f15` | +62 −22 |
| `probe_matrix.py` | `b231e956190a8827ad2684c81bd11301ba83b435e033b753f33cef784fff376d` | +11 −6 |
| `selftest.sh` | `965e1fe33dc55ee4aee483b4f0b0be4b82ddb4e165969768f69adc03b6a2b56e` | +49 −3 |
| `mutation_test.sh` | `00555d37645af6c0dc90f95ee6696dd93b186fd2b49dd10ef13b6960566dcdc2` | +37 −3 |
| `make_fixtures.py` | `2825156fc1e1c7cdcb07b8857d0377f4e6ff36491fbc2a396fa862a70607712e` | +38 −9 |
| `run-06b3b.sh`, `harness_lib.sh`, `pcapng_stats.py`, `sigscan.sh`, `independent_check.sh`, `ctl_loop.py`, `poller.py` | không đổi | — |

## 5. Hạn chế

- Chưa chạy tích hợp; 06B-3F/3FR chưa được chấp nhận để chạy tích hợp.
- Guard 20 ms là giả định chưa đo.
- Thứ tự các bước trong `main()` chỉ được kiểm trên mã nguồn.
- Đối chiếu từng probe (không thuộc phạm vi 06B-3FR) vẫn tính delta probe bằng `get(k, 0)` trên các khóa của lần đọc sau. Điều này chưa được rà theo tiêu chí "thiếu bộ đếm không phải 0".
- Bộ đếm ARP, input/forward và chiều ra vẫn chưa được đối chiếu với pcap. Gói ARP của guest nay được kiểm ở **ngoài** cửa sổ phiên, nhưng chưa được đối chiếu số lượng.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
