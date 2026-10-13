# CT-04 — biên bản kết luận của reviewer (ngày 2026-10-13)

**Kết luận của reviewer: CT-04 ĐẠT theo phạm vi nghiệm thu dưới đây.** Đây **không** phải nghiệm thu triển khai thường trực, và không chuyển mọi kết luận sang một image mới. Văn bản này ghi lại kết luận reviewer đã thông báo; **không có chữ ký của người dùng** và không dựng chữ ký nào. Các loại trừ và giới hạn được giữ nguyên.

**Đối tượng:** CT-04 Xác minh thực thi và log — nhánh `feat/ct04-execution-classification` (PR `saomathua/CIC-YNU-IoTMal-Sandbox#3`). **Ngày kết luận:** 2026-10-13. **Nguồn:** thông báo của reviewer; hồ sơ: [CLOSURE.md](CLOSURE.md), [EVIDENCE-INDEX.md](EVIDENCE-INDEX.md).

## 1. Phạm vi được chấp nhận (ĐẠT)
1. Phân loại thực thi trên guest thật, fixture lành tính, từng evidence gắn với **đúng image và kiến trúc** ghi trong `CLOSURE.md` §1 và `EVIDENCE-INDEX.md` §1: `EXITED_0`, `EXITED_NONZERO` (A1–A2, image worker `62199ff7…`); `SAMPLE_TIMEOUT` có điều kiện (A3, A4, A6, A7, image `68f7150f…`); `EXEC_FORMAT_ERROR` (A5, ARM, `68f7150f…`); `CRASHED`, `KILLED_BY_SIGNAL` + `SELF_SENT`, `EXEC_NOT_FOUND` (A8–A10, `68f7150f…`); cờ loader `LOADER_ERROR_REPORTED` như claim của tiến trình (A11, `8418cf66…`); `EXEC_PERMISSION_DENIED` (A12, `8418cf66…`) — ARM và MIPS (A5 chỉ ARM).
2. Manager (image ứng viên `c93fba47…`): lưu `execution_class` tách khỏi `COMPLETED`; báo cáo sai bị 422 không ghi ZIP/DB; rollback giữ dữ liệu — stack cô lập 72/72 (runner r3; lượt r2 28/39 giữ làm lịch sử).
3. Một lượt Compose r3 có rollback (manager `c93fba47…` + worker `8418cf66…`, hai task ARM EXITED_0; ZIP/Mongo chấm lại 34/34 mỗi task; 422 và không ZIP; rollback 19/19; ZIP sau rollback giống từng byte).

## 2. Loại trừ và giới hạn (giữ nguyên)
- `MISSING_LIBRARY`: dự phòng, không bao giờ phát; thông điệp loader chỉ là claim của tiến trình, không chứng minh thư viện thiếu.
- `STOPPED_BY_SANDBOX`: chỉ offline; không sửa luồng huỷ CT-03; không báo là đã đo.
- `SAMPLE_TIMEOUT`: kết luận có điều kiện (đuôi log "tương thích với syscall đang mở"), không phải bằng chứng đã chứng minh.
- Malware thật: chưa đo. Mỗi lớp chỉ có một fixture mỗi kiến trúc.
- **Không** là nghiệm thu triển khai thường trực: manager/worker mới chưa là mặc định; một lượt Compose có rollback, hai task cùng fixture ARM; K3 trên hàng đợi thật chưa đo; `/tasks` chưa phơi `execution_class`.
- Kết luận gắn với các image/kiến trúc đã đo; **không** chuyển sang image mới (ví dụ các image của CT-06/CT-09) mà không đo lại.
- Lane A5 dựa vào việc `detect_arch` nhận nhầm AArch64 là ARM; nếu CT-06 sửa lỗi đó, A5 không còn tái hiện (evidence lịch sử giữ nguyên).

## 3. Điều kiện còn lại
Triển khai thường trực (đổi `docker-compose.yml`/`latest`), `/tasks` phơi `execution_class`, malware thật: quyết định và đo riêng; **chưa làm, chưa được duyệt**.

## 4. Ghi nhận
Kết luận: reviewer, 2026-10-13. Ghi bởi: Claude (soạn tài liệu theo thông báo của reviewer). Chữ ký người dùng: **không có**.
