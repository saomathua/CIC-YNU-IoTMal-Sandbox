# CT-04 — biên bản nghiệm thu (DỰ THẢO, chưa ký, chưa có hiệu lực)

Dự thảo để reviewer chỉnh/ký. Không ghi CT-04 ĐẠT toàn bộ.

**Đối tượng:** CT-04 Xác minh thực thi và log — nhánh `feat/ct04-execution-classification` (PR `saomathua/CIC-YNU-IoTMal-Sandbox#3`). **Ngày:** ____. **Reviewer:** ____.

## 1. Nội dung được đề nghị chấp nhận (theo phạm vi đã đo)
1. Phân loại thực thi trên guest thật, fixture lành tính, ARM và MIPS: EXITED_0, EXITED_NONZERO, SAMPLE_TIMEOUT (có điều kiện), CRASHED, KILLED_BY_SIGNAL (+SELF_SENT), EXEC_NOT_FOUND, EXEC_PERMISSION_DENIED; EXEC_FORMAT_ERROR (ARM); cờ loader `LOADER_ERROR_REPORTED` như **claim** của tiến trình.
2. Manager: lưu `execution_class` tách khỏi `COMPLETED`; báo cáo sai bị từ chối 422 không ghi ZIP/DB; rollback giữ dữ liệu — stack cô lập 72/72 và Compose r3 (rc 0, rollback 19/19).
3. Một lượt Compose r3 có rollback (2 task ARM EXITED_0, ZIP/Mongo chấm lại 34/34).

## 2. Loại trừ (không nằm trong chấp nhận)
`MISSING_LIBRARY` (dự phòng, không phát); `STOPPED_BY_SANDBOX` (chỉ offline); SAMPLE_TIMEOUT như bằng chứng đã chứng minh; malware thật; triển khai thường trực; `/tasks` phơi `execution_class`; K3 trên hàng đợi thật.

## 3. Bằng chứng
Index: `docs/ct04/EVIDENCE-INDEX.md` (path + hash); ánh xạ: `docs/ct04/CLOSURE.md`.

## 4. Điều kiện còn lại
____ (reviewer điền). | Quyết định: [ ] chấp nhận theo phạm vi  [ ] yêu cầu bổ sung ____ | Chữ ký/ngày: ____
