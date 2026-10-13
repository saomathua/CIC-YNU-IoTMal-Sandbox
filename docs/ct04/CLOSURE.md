# CT-04 — hồ sơ closure (reviewer kết luận ĐẠT theo phạm vi, 2026-10-13)

Ngày soạn: 2026-10-12; kết luận reviewer: 2026-10-13 (ĐẠT theo phạm vi nghiệm thu, xem [ACCEPTANCE.md](ACCEPTANCE.md); không phải nghiệm thu triển khai thường trực). Nhánh `feat/ct04-execution-classification`; PR `saomathua/CIC-YNU-IoTMal-Sandbox#3`. Yêu cầu (`docs/requirements.md`): xác minh thực thi và log. Đường dẫn/hash evidence: [EVIDENCE-INDEX.md](EVIDENCE-INDEX.md).

## 1. Ánh xạ nhóm evidence → image, kiến trúc, phạm vi
| Nhóm | Evidence | Image | Kiến trúc | Phạm vi đã đo | Giới hạn |
|---|---|---|---|---|---|
| Thoát 0 / ≠ 0 | A1, A2 | worker `62199ff7…` | ARM, MIPS | `EXITED_0`, `EXITED_NONZERO` (exit 7) | một fixture/kiến trúc; chưa chạy lại ở image sau |
| Hết thời gian | A3, A4 (cửa sổ 3 s), A6 (console ồn), A7 (fork) | worker `68f7150f…` | ARM, MIPS | `SAMPLE_TIMEOUT` **có điều kiện** (probe đầu/cuối cùng pid/starttime, ppid = strace, trace dừng, thứ tự thời gian) | đuôi log "tương thích với syscall đang mở" (`TAIL_OPEN_SYSCALL`); **không** chứng minh mẫu bị treo hay sống liên tục suốt cửa sổ, chỉ rằng khi dừng trace tiến trình chính còn tồn tại và log chưa kết thúc |
| Sai kiến trúc | A5 | `68f7150f…` | ARM (stub AArch64) | `EXEC_FORMAT_ERROR` | một ca; MIPS bị launcher từ chối theo thiết kế |
| Crash / signal / thiếu interpreter | A8, A9, A10 | `68f7150f…` | ARM, MIPS | `CRASHED` (`SEGV_*`), `KILLED_BY_SIGNAL`+`SELF_SENT`, `EXEC_NOT_FOUND` (`execve = -1 ENOENT`) | một fixture/kiến trúc; ENOENT không phân biệt interpreter hay tệp |
| Thiếu thư viện (loader musl) | A11 | `68f7150f…` (lịch sử: bằng chứng loader chưa đạt), `8418cf66…` (bản sửa) | ARM, MIPS | `EXITED_NONZERO` + `LOADER_ERROR_REPORTED` + `LIB_LOOKUP_FAILED_SAME_NAME` (3 open ENOENT cùng tên, 3 `writev` thành công, exit 127) | **claim của tiến trình**, không chứng minh `MISSING_LIBRARY` (không bao giờ phát) |
| Quyền thực thi | A12 | `8418cf66…` | ARM, MIPS | `EXEC_PERMISSION_DENIED` (`execve = -1 EACCES`, PT_INTERP trỏ tới tệp thường không thực thi) | một fixture/kiến trúc; không phải mọi nguyên nhân quyền |
| Mất console/log (fail-closed) | A1-ARM lượt đầu (`2b310137…`) + test offline | `2b310137…` | ARM | `ConsoleLost` → task `FAILED` đúng thiết kế | các nhánh `LOG_MISSING`/`LOG_INVALID`/`INFRA_*`: chỉ offline |
| `STOPPED_BY_SANDBOX` | test offline (metadata dựng tay) | — | — | — | **chỉ offline**; không sửa luồng huỷ CT-03; không báo là đã đo |
| Manager (P4, NOT_CLASSIFIED, K1/K3, rollback) | compat run r3 | manager `c93fba47…` vs `13f02b81…` | — | 72/72 trên stack cô lập | ZIP fixture giả; không worker/guest |
| Compose | Compose trial r3 | manager `c93fba47…`, worker `8418cf66…` | ARM (fixture exit0) | rc 0; 2 task EXITED_0; ZIP/Mongo chấm lại 34/34 mỗi task; 422 và không ZIP; rollback 19/19; ZIP sau rollback giống từng byte; 46 task cũ không đổi, thêm đúng 2 | hai task cùng fixture ARM lành tính; manager recreate; không phải triển khai thường trực |

## 2. Trạng thái từng tiêu chí
| Tiêu chí con | Trạng thái |
|---|---|
| Phân loại thực thi trên guest thật (ARM+MIPS) | Đã đo theo bảng §1; reviewer chấp nhận theo phạm vi đã đo |
| `COMPLETED` tách `execution_class`; manager lưu class/evidence/flags; từ chối báo cáo sai | Đã đo (compat 72/72 + Compose r3) |
| Không dựa vào mất log: fail-closed | Một lần đo thật + offline |
| Thử Compose có rollback | **Đã thử một lượt** (rc 0, rollback verified); **chưa triển khai thường trực** |
| Malware thật | **Chưa đo** (ngoài phạm vi; chỉ fixture lành tính) |
| `/tasks` phơi `execution_class` | Chưa làm (đọc qua ZIP/Mongo) |
| K3 trên hàng đợi production thật | Chưa đo |
| Nghiệm thu CT-04 theo phạm vi | **ĐẠT theo phạm vi** (reviewer, 2026-10-13); loại trừ giữ nguyên; không phải triển khai thường trực |

## 3. Giữ nguyên lịch sử
A1-ARM `2b310137…` thất bại (console `\r\r\n`), A3-ARM `62199ff7…` NOT-HELD (đuôi cụt), A11 `68f7150f…` bằng chứng loader chưa đạt, compat runner r2 28/39 — tất cả còn nguyên trong evidence và index. Không dọn stage `/var/lib/ct04-rt`, tag `ct04-*`, task fixture trong Mongo.

## 4. Sau kết luận
CT-04 ĐẠT theo phạm vi §1–§2 và [ACCEPTANCE.md](ACCEPTANCE.md). Còn ngoài phạm vi (quyết định và đo riêng, chưa duyệt): triển khai thường trực (đổi `docker-compose.yml`/tag `latest`, có kế hoạch rollback đã chứng minh ở Compose r3); `/tasks` phơi `execution_class`; malware thật (cần cách ly đã chứng minh ở CT-01). Kết luận không chuyển sang image mới (CT-06/CT-09 dùng image khác ⇒ đo lại).
