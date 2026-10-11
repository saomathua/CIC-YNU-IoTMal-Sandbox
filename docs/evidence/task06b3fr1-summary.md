# Minh chứng Nhiệm vụ 06B-3FR1: không nuốt lỗi khi quét tiến trình QEMU, kiểm thử OFFLINE (07/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Phép đo toàn phiên **chưa chạy tích hợp lần nào**.

**Bối cảnh:**

- Reviewer xác nhận phần đối chiếu của 06B-3FR, và tái hiện được một lỗi: `qemu_pids()` gặp `PermissionError` khi đọc `/proc/<pid>/comm` nhưng vẫn trả `[]`, dẫn đến toàn phiên PASS sai.
- Chỉ sửa harness (ngoài repo, `/home/dathq/projects/ct01-06b3c/`) và hồ sơ. Không sửa source cô lập hay mạng host.
- Bản 06B-3FR được giữ trong `ct01-06b3c/base-06b3fr/` và khớp đúng hash đã bàn giao.
- Guard giữ 20 ms (giả định chưa đo). Kết quả toàn phiên vẫn báo riêng; kết luận probe, `run_outcome()` và mã thoát không đổi.

## 1. Tái hiện trên bản 06B-3FR, so với bản đã sửa

Log: [`logs/repro-before-after.txt`](task06b3fr1/logs/repro-before-after.txt). Cách làm: liệt kê `/proc` thật (chỉ đọc), mô phỏng `PermissionError` khi đọc mọi `/proc/<pid>/comm`.

| | 06B-3FR | 06B-3FR1 |
|---|---|---|
| `qemu_pids()` | `[]`: lỗi bị nuốt, trông như "không có QEMU" | ném `ProcessScanError: cannot read /proc/1/comm: PermissionError …` |
| Dữ liệu ghi vào phiên | `pids_after_exit = []` | `pids_after_exit = None`, `pids_after_exit_error` = nội dung lỗi |
| Kết luận toàn phiên (phần còn lại sạch) | **PASS** | **ERROR** |

## 2. Bản sửa

- **`qemu_pids()`** không còn bắt mọi `OSError`:
  - **PID đã biến mất trong lúc quét:** đọc `comm` gặp `FileNotFoundError`/`ProcessLookupError` **và** thư mục `/proc/<pid>` không còn → bỏ qua PID đó (tiến trình đã thoát).
  - **Không xác minh được** → ném `ProcessScanError`. Gồm: `comm` thiếu trong khi thư mục PID vẫn còn; `PermissionError`; mọi `OSError` khác như lỗi I/O; không liệt kê được `/proc`.
  - Thư mục gốc là biến module `PROC_ROOT` (mặc định `/proc`), để test gọi chính hàm này trên một cây `/proc` giả.
- **`record_qemu_scan(when)`** mới, được `main()` dùng cho cả lần quét **trước boot** lẫn **sau khi QEMU thoát**:
  - gọi `qemu_pids()`; lỗi được ghi vào `session["qemu_pids_<when>_error"]`, danh sách là `None`;
  - không ném tiếp, nên khối `finally` vẫn dọn dẹp bình thường.
  - `no_qemu_before` chỉ True khi danh sách **đúng bằng** `[]`. Bản cũ dùng `not before_pids`, nên với `None` sẽ ra True.
- **`evaluate_session()`** truyền thêm `pids_before_error`. **`session_reconcile()`** trả ERROR khi có lỗi quét trước boot, cũng như khi có lỗi quét sau khi thoát (đã có từ 06B-3FR).
- **Phép kiểm thứ tự trong `main()`** nay tìm `record_qemu_scan("before")`. Thứ tự vẫn là: quét QEMU + đọc nền < spawn < shutdown < đọc cuối < dừng tshark < đánh giá.

## 3. Test mới

Phần H, phát lại với module worker được thay bằng stub. Mỗi ca gọi **chính** `qemu_pids()`/`record_qemu_scan()` trên một cây `/proc` giả, rồi đi qua `evaluate_session()` thật. **Không có ca nào đưa sẵn trường lỗi vào `session`.**

| # | Tình huống | Kết quả quét | Kết luận toàn phiên |
|---|---|---|---|
| 1 | quét thành công, không có QEMU (có cả mục `self` không phải số) | `[]`, không lỗi | PASS |
| 2 | có `qemu-system-mips`, quét sau khi thoát | `[3]` | ERROR |
| 2 | có QEMU, quét trước boot | `[3]`, `no_qemu_before` False | ERROR |
| 3 | PID được liệt kê rồi biến mất (không còn `/proc/300`) | bỏ qua, `[]` | PASS |
| 3b | `comm` thiếu trong khi `/proc/4` vẫn còn | lỗi "pid directory exists" | ERROR |
| 4 | `PermissionError` khi đọc `/proc/2/comm`, sau khi thoát | `None` + lỗi | ERROR |
| 4 | `PermissionError`, trước boot | `None` + lỗi, `no_qemu_before` False | ERROR |
| 4 | lỗi đọc khác (`EIO`) | `None` + lỗi | ERROR |
| 4 | không liệt kê được `/proc` | `None` + lỗi "cannot list" | ERROR |
| — | quay lại cây sạch | `[]` | PASS (không rò trạng thái giữa các ca) |

## 4. Kiểm thử đã chạy trên bản mới

> **Lần chạy bị mất (ghi rõ):** lần self-test và mutation test đầu tiên của 06B-3FR1 chạy trong `/tmp` (scratchpad). Hệ thống đã báo lệnh mutation **kết thúc với mã 0**, nhưng output **chưa được đọc** trước khi người dùng dừng phiên và tắt máy. Máy khởi động lại lúc 15:08 và `/tmp` bị xóa, nên log self-test, log mutation, file hash của bản đã kiểm thử và log tái hiện của lần đó đều **mất**, không còn gì để giữ. Lần đó **không được dùng làm bằng chứng**.
>
> Kết quả dưới đây là của **lần chạy lại** trên đúng mã hiện tại. Mã không đổi kể từ lần chạy trước (file sửa lần cuối lúc 10:30:22, trước khi lần mutation đó bắt đầu). Hash được ghi trước khi chạy và kiểm lại sau mutation test. Log lần này nằm trong `/home` (`ct01-06b3fr1-work/`) và được chép vào evidence.

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` (chạy lại) | **205/205 PASS**, ổn định qua 3 lần chạy | [`logs/selftest.log`](task06b3fr1/logs/selftest.log) (`90ca466fcd8a57776283a5aae4e5e8c3f4c0bff583386905d4a3a6b8a0035173`) |
| Tái hiện trước/sau (chạy lại) | 06B-3FR: `[]` → **PASS**; 06B-3FR1: `ProcessScanError` → **ERROR** | [`logs/repro-before-after.txt`](task06b3fr1/logs/repro-before-after.txt) (`7ff71d7b20cdc2c2db71ff696a2871e99e8e4aae0d9f9edf176bc1797bad99f6`) |
| `mutation_test.sh` (chạy lại), **toàn bộ** bộ đột biến trên bản 06B-3FR1 | Baseline đạt; **76/76** đột biến hành vi bị bắt đúng check được nhắm; 2 đột biến đối chứng đúng loại; hash khớp trước và sau khi chạy | [`logs/mutation-test.txt`](task06b3fr1/logs/mutation-test.txt) (`5011088f4465184f7d9da972f49ca3b6dfa3376f355d0e9a8bd9c9460a51a285`); [`logs/mutation-test.status.txt`](task06b3fr1/logs/mutation-test.status.txt) (`aa313544db5d593bd361bce6234564df1a68fdaa09ac42c295ae0a795c5415ed`) |

Nhiệm vụ cho phép chỉ chạy các đột biến liên quan. Tuy vậy, `probe_matrix.py`, `counter_window.py` và `selftest.sh` đều đã đổi, nên **toàn bộ** bộ đột biến được chạy lại trên bản mới. Trong đó:

- **5 đột biến mới cho bản sửa:**
  - Q1: bắt lại mọi `OSError` khi đọc `comm`;
  - Q2: coi PID đã biến mất là lỗi;
  - Q3: bỏ kiểm "thư mục PID vẫn còn";
  - Q4: `record_qemu_scan()` nuốt lỗi thành `[]`;
  - Q5: nuốt lỗi khi liệt kê `/proc`.
- **4 đột biến cũ được chuyển sang dòng mã mới**, vì đoạn mã chúng nhắm đã đổi: SE5 và QP4 (điều kiện "chưa có QEMU" nay có thêm lỗi quét), SE11 và SE12 (đọc nền nay dùng `record_qemu_scan`).
- **Đột biến tương đương, không đưa vào bộ:**
  - đổi `no_qemu_before = (pids == [])` thành `not pids`;
  - bỏ kiểm `pids_before_error` trong `session_reconcile`.
  - Với lỗi quét, `pids_before` là `None`, nên check `pids_before != []` vẫn trả ERROR. Hai lớp kiểm này là phòng thủ chồng lên nhau, không phải điểm mà test có thể phân biệt.

## 5. Hash và diff

- Diff so với 06B-3FR: [`ct01-06b3fr1-harness-vs-06b3fr.diff`](task06b3fr1/ct01-06b3fr1-harness-vs-06b3fr.diff) (`68f64ec2d4c07b288fad9dcbb64bf000d1159d73a4db17138c8abf7a5693c571`).
- [`harness-sha256.txt`](task06b3fr1/harness-sha256.txt) (`06b1fa73a574643ccad3435fd8ddc135324895e9033ea1a08af9a12acecf0e7c`): đúng bản đã được kiểm thử ở lần chạy lại.

| File | sha256 | So với 06B-3FR |
|---|---|---|
| `probe_matrix.py` | `99fb741fd6b327a229ce6a6217809141a9a6329f9e3d2746ca133a88ac3b7380` | +50 −16 |
| `counter_window.py` | `09613fedb5a38eb7dca6ba915d3632d7332a6f8a7563797fbd9b3097bd6088f7` | +5 −3 |
| `selftest.sh` | `2247db1ef8846818b164300fc65210560b78b0a140cb9077dd9c24d2620c7ff4` | +61 −1 |
| `mutation_test.sh` | `5b27dd2b3bb5ff71355df377f292a533b6476705bf08b1511f2dd2347d77a411` | +24 −9 |
| `run-06b3b.sh`, `harness_lib.sh`, `make_fixtures.py`, `pcapng_stats.py`, `sigscan.sh`, `independent_check.sh`, `ctl_loop.py`, `poller.py` | không đổi | — |

## 6. Hạn chế

- Chưa chạy tích hợp.
- Quy tắc "PID biến mất = `FileNotFoundError`/`ProcessLookupError` và thư mục PID không còn" dựa trên hành vi của procfs, chưa kiểm trong container thật.
- Lỗi được mô phỏng bằng cách thay `open`/`os.listdir` của module, và trên một cây `/proc` giả. `PermissionError` thật trên procfs chưa được tạo ra.
- Guard 20 ms là giả định chưa đo.
- Còn mở từ 06B-3FR: delta của đối chiếu từng probe vẫn dùng `get(k, 0)`.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
