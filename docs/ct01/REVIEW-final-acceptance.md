# CT-01 — chấp nhận đóng theo phạm vi nghiệm thu đã duyệt

Ngày review: 2026-10-11. Reviewer: Codex.

**Kết luận: CT-01 hoàn tất theo phạm vi nghiệm thu đã chốt. Không còn blocker closure.** Kết luận này dựa trên các review evidence trước, kiểm nhất quán hồ sơ cuối và quyết định phạm vi của người dùng; không phải chứng nhận mọi phép thử trong thiết kế ban đầu hoặc mọi image về sau.

## Đầu vào và kiểm tra

- Gói cuối: `ct01-final-package.zip`, 66.117 byte, SHA-256 `ef4da8a137ef1504fd158f8616a4a581d1a0f16be95d667a8dae889e8edfdd06`.
- ZIP đọc được; 16/16 hash trong SHA256SUMS khớp.
- Closure có 38 ID duy nhất, khớp MATRIX-CORRECTED: 32 mandatory, 3 coverage, 2 postponed, 1 extra. Không có yêu cầu thiết kế bị âm thầm hạ thành coverage.
- Index nhúng trong closure giống bản index riêng; mỗi hàng liên kết path/hash/size phù hợp. Index ghi 55 tệp và không hàng mandatory nào thiếu evidence.
- Đối chiếu trực tiếp được 44/55 hash với các bản hiện có và gói đã review: tất cả khớp. 11 tệp không có bản tương ứng tại workspace reviewer hiện tại, gồm report ma trận gốc, evidence ICMP 4G/ARP R10 và hai tài liệu thiết kế đầy đủ mới cập nhật. Các kết luận lịch sử liên quan được kế thừa review trước; không tuyên bố đã băm lại 11 tệp này trong lượt cuối, và không coi việc thiếu bản cục bộ là mất evidence tại máy tác giả.
- REVIEW.md, CLAUDE-NEXT.md và SCOPE-DECISION.json trong gói giống nguyên byte bản reviewer đã bàn giao.
- Closure, KQCaiTien trích, phân loại đối chứng/giao thức/kiến trúc và các giới hạn không có mâu thuẫn chặn nghiệm thu.

## Phạm vi được chấp nhận

Quyết định người dùng: nguyên văn **“chấp nhận phạm vi”**, 2026-10-11T13:32:02+07:00. Mapping dưới đây là diễn giải reviewer của đề xuất đã được chấp nhận, không phải câu duyệt nguyên văn mới:

| Hàng | Phạm vi |
|---|---|
| T07/T08 | ĐẠT về mạng; log SSH/manager bổ sung không đo |
| T09 | Cách ly TCP27017, control TCP từ dbnet; không claim M /status hay mongosh ping |
| T10 | Tổng hợp network proof và T19 nguồn manager; T19 không là control đồng thời của probe cũ |

Các review runtime được giữ: B1 R13N11 ARM/MIPS; V0 R6 với F1b chỉ PATH-resolution; luồng tác vụ success ARM/MIPS và F3/F4 ARM; F5 startup/restart worker rảnh; T16/T17 R7 ARM/MIPS; T21b R3 hai phía. T05b là UDP DNS 8.8.8.8:53, không phải TCP443. T16-M1/T17-P1 mandatory; P2/P4/P5 coverage. T17 `.5/32` là biến thể ghi nhận của `.3`, không chứng nhận `.3`.

## Giới hạn giữ nguyên

FAIL/OPEN/UNVERIFIED lịch sử không bị thay verdict. H0 và T12/T13 host capture OPEN vẫn được ghi rõ. Guard 20 ms không được đo; A7/A11/A15 chỉ là checkpoint; N4/N5 là route lookup, không chứng minh policy routing/reachability. T21b chỉ một phiên SSH và một cửa sổ startup/restart với ngưỡng gap 3 s. P3, TAP_MAC và các mục hoãn/coverage không được tính thành phép thử đã hoàn thành. Kết luận gắn với image/cấu hình/evidence đã ghim; thay image cần xác định và thực hiện hồi quy phù hợp với phần đổi.

Thông tin thu hồi sudo là báo cáo vận hành của operator, không phải audit root độc lập. Không có runtime/root hay thu mới trong lượt review cuối này.

## Hoàn thiện văn bản, không chặn closure

1. Đổi trạng thái hiện tại “chờ reviewer chốt” thành “ĐẠT — hoàn tất theo phạm vi nghiệm thu đã duyệt; reviewer chốt 2026-10-11”, tham chiếu biên bản này. Giữ mọi nhãn chờ/FAIL của các lượt lịch sử.
2. Trong NEXT-IMPROVEMENTS.md, bỏ câu cũ “V1/V2 ‘đạt’ không có log thành công từ worker”. Thay bằng: “Có evidence verifier ISOLATION OK tại các checkpoint đã review và evidence fault F3/F4 ARM; không chứng minh kiểm liên tục hoặc timing guard 20 ms.”

Hai cập nhật diễn đạt này không yêu cầu sửa mã, đổi image, chạy suite hoặc runtime. CT-01 có thể chuyển sang các mục cải tiến tiếp theo; kế hoạch tiếp theo chưa là quyền triển khai runtime mới.
