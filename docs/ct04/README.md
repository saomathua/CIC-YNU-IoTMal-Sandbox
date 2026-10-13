# CT-04 — Xác minh thực thi và log

**Trạng thái (theo `KQCaiTien.md`):** **CT-04 ĐẠT theo phạm vi nghiệm thu** do reviewer kết luận ngày 2026-10-13 ([ACCEPTANCE.md](ACCEPTANCE.md); phạm vi, loại trừ và ánh xạ evidence → image/kiến trúc trong [CLOSURE.md](CLOSURE.md), [EVIDENCE-INDEX.md](EVIDENCE-INDEX.md)). Đây **không** phải nghiệm thu triển khai thường trực và không chuyển kết luận sang image mới; malware thật chưa đo; `MISSING_LIBRARY` không phát; `STOPPED_BY_SANDBOX` chỉ offline; `SAMPLE_TIMEOUT` có điều kiện. PR `saomathua/CIC-YNU-IoTMal-Sandbox#3`.

## Thiết kế (tóm tắt)
- **Worker phân loại, manager lưu.** `sandbox-worker/service/execution_class.py` (mới) đọc `strace.log` + metadata `trace-meta.json` (`ct04-trace-meta/2`) và sinh `execution-class.json` (`ct04-execution-class/1`). `execution_class` **tách khỏi** `COMPLETED`.
- **Lớp:** `EXITED_0`, `EXITED_NONZERO`, `CRASHED`, `KILLED_BY_SIGNAL`, `STOPPED_BY_SANDBOX`, `SAMPLE_TIMEOUT`, `EXEC_FORMAT_ERROR`, `EXEC_NOT_FOUND`, `EXEC_PERMISSION_DENIED`, `EXEC_FAILED`, `LOG_MISSING`, `LOG_INVALID`, `UNKNOWN_INCOMPLETE`, `INCONSISTENT_EVIDENCE`, `INFRA_TIMEOUT`, `INFRA_FAILURE`. `MISSING_LIBRARY` **dự phòng, không bao giờ được phát** (không có nguồn chứng thực loader).
- **`SAMPLE_TIMEOUT` là kết luận có điều kiện:** cần cửa sổ phân tích trôi hết, probe đầu và cuối cùng pid/starttime, ppid thô = pid strace, xác nhận dừng trace (stop-check) và thứ tự thời gian. Đuôi `strace.log` cụt chỉ "tương thích với syscall đang mở"; không phải bằng chứng chắc chắn.
- **Console fail-closed:** mất đồng bộ (`ConsoleLost`) hoặc không xác nhận được việc dừng trace làm task thất bại có lý do, không âm thầm tiếp tục.
- **Console thô:** `console.raw` (byte trước giải mã UTF-8) trong ZIP; khi lỗi, khối base64 + độ dài + sha256 trong worker log.
- **Manager (P4):** `POST /submit-result/{task_id}` nhận trường form `execution_class` (JSON). Vắng ⇒ `NOT_CLASSIFIED` + `NO_WORKER_REPORT`. Có mà sai (schema, task id, kiểu, kích thước, lớp ngoài danh sách) ⇒ **422 trước khi ghi ZIP hoặc DB**. `/tasks` chưa phơi trường này.

## Kiểm thử (offline, trong image đã ghim)
| Bộ | Lệnh | Kết quả đã ghi |
|---|---|---|
| Classifier | `python3 -I -B sandbox-worker/tests/ct04/classifier/tests/check_classify.py` | 215/0 FAIL |
| Mutant classifier | `python3 -I -B sandbox-worker/tests/ct04/classifier/tests/run_mutants.py` | 70 mutant, 0 sống sót |
| Worker (P0–P3) | `python3 -I -B sandbox-worker/tests/ct04/check_worker_p0_p3.py sandbox-worker sandbox-worker` | 85/0 FAIL |
| Console CR CR LF | `python3 -I -B sandbox-worker/tests/ct04/check_console_crlf.py sandbox-worker/service/execution_class.py` | 8/8 |
| Console thô | `python3 -I -B sandbox-worker/tests/ct04/check_raw_console.py sandbox-worker sandbox-worker` | 18/18 |
| Manager (P4) | `python3 -I -B sandbox-manager/tests/ct04/check_manager_p4.py sandbox-manager sandbox-manager` | 57/0 FAIL |
Các `check_*.py` là script thuần (không pytest; đặt tên `check_*` để pytest của repo không thu thập). Bộ pytest sẵn có của repo (`sandbox-worker/tests`, trừ `integration/`): **142 passed trước và sau thay đổi** (chạy trong image worker đã ghim, pytest 8.3.4 gắn từ ngoài, không đổi image).

## Evidence trên guest thật (fixture lành tính, không mã độc)
| Lane | Fixture | Image | Kết quả |
|---|---|---|---|
| A1, A2 (ARM, MIPS) | exit 0, exit 7 | worker `62199ff7…` | HELD (EXITED_0, EXITED_NONZERO) |
| A3, A4 (cửa sổ 3 s), A6, A7 (ARM, MIPS) | sleep, noisy, fork | worker `68f7150f…` | HELD (SAMPLE_TIMEOUT, có điều kiện) |
| A5 (ARM) | stub AArch64 | worker `68f7150f…` | HELD (EXEC_FORMAT_ERROR) |
| A8 (ARM, MIPS) | SIGSEGV tự gây | worker `68f7150f…` | evaluator HELD; lớp thực tế CRASHED (`SEGV_MAPERR`, `killed by SIGSEGV`) — bằng chứng lớp ĐẠT |
| A9 (ARM, MIPS) | `kill(getpid(), SIGTERM)` | worker `68f7150f…` | evaluator HELD; KILLED_BY_SIGNAL + `SELF_SENT` (`si_code=SI_USER`, `si_pid` = pid chính) — bằng chứng lớp ĐẠT |
| A10 (ARM, MIPS) | PT_INTERP thiếu | worker `68f7150f…` | evaluator HELD; EXEC_NOT_FOUND (`execve = -1 ENOENT` có trong log) — bằng chứng lớp ĐẠT; chỉ nói ENOENT, không phân biệt interpreter hay tệp |
| A11 (ARM, MIPS) | thiếu thư viện qua loader musl | worker `68f7150f…` (lịch sử), `8418cf66…` (bản sửa) | `68f7150f`: evaluator HELD, lớp EXITED_NONZERO, bằng chứng loader **chưa đạt** (classifier không ghép `writev`); giữ nguyên. `8418cf66` (2026-10-12): evaluator HELD, lớp EXITED_NONZERO, `LOADER_ERROR_REPORTED` + `LIB_LOOKUP_FAILED_SAME_NAME` — bằng chứng lớp ĐẠT: 3 `open` ENOENT cùng tên thư viện, 3 `writev` thành công (85+7+1 = 93 byte, return = tổng `iov_len`), thông điệp `Error loading shared library libct04missing.so: No such file or directory (needed by ./exec)\n`, `exit_group(127)`. **Là claim của tiến trình, không phải MISSING_LIBRARY.** |
| A12 (ARM, MIPS) | PT_INTERP trỏ tới tệp thường không thực thi (`/etc/passwd`, mode 0644) | worker `8418cf66…` (2026-10-12, mỗi kiến trúc một lượt, không retry) | evaluator HELD (25 kiểm, không kiểm nào hỏng); lớp thực tế EXEC_PERMISSION_DENIED; raw `execve("./exec", …) = -1 EACCES (Permission denied)` (ARM main_pid 971, MIPS 1850); không cờ; export verified; **reviewer đã chấp nhận theo phạm vi đã đo** — một fixture mỗi kiến trúc, EACCES do interpreter không thực thi, không phải mọi nguyên nhân quyền |
Lưu ý đọc: với lane `observe`, evaluator HELD KHÔNG có nghĩa lớp kỳ vọng đã đo; báo cáo luôn tách verdict của evaluator và bằng chứng lớp.
Lịch sử giữ nguyên: lượt A1-ARM trên image `2b310137…` thất bại (console CR CR LF); A3-ARM trên `62199ff7…` NOT-HELD (đuôi cụt chặn SAMPLE_TIMEOUT). Evidence nằm ở các gói bàn giao của nhóm, không đưa vào repo.

## Manager: tương thích và rollback
Image ứng viên `sandbox-manager:ct04-e317797a9f97` (`sha256:c93fba47…`) đã build (có DRIFT dpkg `libpcre2-8-0`). Hai lượt stack cô lập (Mongo riêng, manager cũ → ứng viên → cũ trên cùng dữ liệu; không chạm production):
- Lượt 1 (runner r2): 28/39 đạt; 11 không đạt do **lỗi kịch bản runner** (manager khởi động đưa lại QUEUED/PROCESSING vào hàng đợi — K3 — nên runner cấp phát nhầm task). Giữ nguyên là kết quả FAIL.
- Lượt 2 (runner r3, đã sửa): **72/72 đạt**, cleanup sạch, export verified. Đạt trên hệ thật: K1 (manager cũ bỏ qua trường lạ), lưu class/evidence/flags trong Mongo, `NOT_CLASSIFIED` khi vắng trường, 8 báo cáo sai bị 422 **không ghi ZIP/DB và task không đổi**, ZIP tải đồng nhất, rollback về manager cũ (trường mới còn trong Mongo, báo cáo mới vẫn được nhận), K3 đo được cả hai chiều.
**Reviewer đã chấp nhận evidence này theo phạm vi đã đo** (stack cô lập, ZIP fixture giả, không có worker/guest). Không suy thành triển khai production: manager mới chưa được đưa vào Compose, chưa đo trên hàng đợi production thật.

## Quyết định kỹ thuật đã chốt (reviewer, 2026-10-12)
- **`STOPPED_BY_SANDBOX` chỉ offline.** Không sửa luồng huỷ CT-03 để tạo lớp này; worker không gửi tín hiệu tới mẫu. Lớp được định nghĩa và kiểm bằng metadata dựng tay, không được báo là đã đo.
- **`MISSING_LIBRARY` vẫn dự phòng, không phát.** Thiếu thư viện chỉ được báo qua cờ claim `LOADER_ERROR_REPORTED` (+ `LIB_LOOKUP_FAILED_SAME_NAME`); không thêm cờ mới.
- **Đã đo (A12):** `EXEC_PERMISSION_DENIED` cho ARM và MIPS trên fixture `permdenied`; reviewer chấp nhận theo phạm vi đã đo.
- **Đã đo (Compose trial r3):** một lượt thử Compose r3 đã chạy (2026-10-12 16:14:48Z–16:18:45Z, wrapper `0dc1afb6…`, mặc định 1800 s/reserve 480 s, không retry): rc 0, 2 task fixture lành tính EXITED_0, ZIP/Mongo/binding đạt, 422 đạt, rollback verified (worker vắng, manager về `13f02b81…`, Mongo không restart, host khớp). Giới hạn: hai task cùng một fixture ARM lành tính, manager production bị recreate rồi khôi phục; không phải triển khai thường trực.
- **Chưa chứng minh:** triển khai thường trực Compose (manager/worker mới là mặc định) và nghiệm thu toàn CT-04.

## Phần CÒN THIẾU (không tính là hoàn thành)
- `STOPPED_BY_SANDBOX`: chỉ offline (worker không gửi tín hiệu tới mẫu; không sửa luồng huỷ CT-03). `MISSING_LIBRARY`: dự phòng, không phát (nguồn gốc thông điệp loader không chứng thực được từ log; chỉ có cờ claim `LOADER_ERROR_REPORTED`).
- `SAMPLE_TIMEOUT` là kết luận **có điều kiện** (đuôi log "tương thích với syscall đang mở"): **Diễn đạt chính xác:** nó nghĩa là, tại thời điểm dừng trace, tiến trình chính vẫn còn (cùng pid/starttime ở hai probe) và log không có dòng kết thúc, đuôi log tương thích với một syscall còn mở. Nó **không** chứng minh mẫu bị treo, không chứng minh mẫu sống liên tục suốt cửa sổ, và không phải bằng chứng đã chứng minh; phạm vi nghiệm thu không đổi.
- Triển khai thường trực Compose, `/tasks` phơi `execution_class`, K3 trên hàng đợi thật, mã độc thật, nghiệm thu toàn CT-04 của reviewer.
- Đã đo (không còn trong danh sách thiếu): `CRASHED`, `KILLED_BY_SIGNAL`, `EXEC_NOT_FOUND` (A8–A10), `EXEC_PERMISSION_DENIED` (A12), một lượt Compose r3 có rollback.

## Fixture (generator, không commit ELF)
`docs/ct04/fixtures/build_ct04_elf.py` (A1–A7), `build_ct04_extra.py` (segv, selfkill, noloader, missinglib, permdenied), `verify_elf.py`. Đầu ra là tệp ELF lành tính tất định; không commit kết quả (AGENTS.md).
