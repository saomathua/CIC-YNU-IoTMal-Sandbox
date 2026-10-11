# Kế hoạch sau CT-01 (chỉ lập kế hoạch; không đổi image/pin, không mở runtime mới)

Nguồn: `KQCaiTien.md` Phần B (CT-02…CT-14, "Còn thiếu"/"Nghi vấn") và các vấn đề ghi nhận khi làm CT-01. Mọi bước dưới đây là **đề xuất** cho review; chưa có quyết định hay approval.

## 0. Ràng buộc đến từ CT-01
- Ảnh worker `sha256:1ab784c7…9153` và cây V0/B1/flow/T16-T17 được **ghim** theo image đó. Mọi sửa `sandbox-worker/**` (kể cả log) tạo image mới ⇒ pin của V0/B1/flow mất hiệu lực; muốn giữ kết luận CT-01 phải có một **hồi quy hẹp có ghi nhận** (V0 control + một lane flow success) chứ không suy kết luận cũ sang image mới.
- Dữ liệu manager còn lại từ CT-01: Mongo 4 COMPLETED + 2 FAILED, 4 zip trong `data/manager/output` (fixture busybox vô hại). Không xóa tự ý; CT-05 có thể dùng làm đầu vào "tác vụ thật" với quyết định riêng.
- Tài sản tái dùng: lane flow R4 (`ct01-flow-r4`: worker thật + fixture + evaluator có kiểm rc/schema + export có receipt), run-prep/writer ghim cho suite spoof/B1, heartbeat T21b.

## 1. Thứ tự đề xuất
| # | Mục | Vì sao trước | Bước đầu có thể đo | Phụ thuộc / rủi ro |
|---|---|---|---|---|
| 1 | **Lỗi nhãn PID trong log** (`sandbox-worker/service/analysis.py:288,293`: `proc.before` là echo lệnh, không phải PID; `sar_pid`/`strace_pid` chỉ ghi vào tệp trong guest) — **tách khỏi CT-01** | nhỏ, tự chứa, ảnh hưởng chẩn đoán CT-04/CT-12 | đọc `sar_pid`/`strace_pid` qua console guest rồi log; kiểm bằng một lượt flow success (log có PID số) | đổi image ⇒ xem §0; không đụng cách ly |
| 2 | **CT-03 Cleanup** | "Nghi vấn [Mã]": không có `finally` dừng QEMU; tshark không dừng khi lỗi sau khi khởi động (`analysis.py:171-263`, `:218`) | lane flow với fault giữa phase (đã có cơ chế F3/F4) + kiểm `pgrep qemu/tshark` sau FAILED/CANCELLED/timeout | cần mở rộng lane (CANCEL, timeout) — runtime mới cần quyết định |
| 3 | **CT-02 Môi trường sạch** | rẻ trên lane hiện có | marker giữa hai tác vụ liên tiếp; hash `*/image.zip` trước/sau (đã có hai tác vụ liên tiếp trong lane success) | cần fixture có marker ghi vào guest |
| 4 | **CT-04 Xác minh thực thi/log** | `COMPLETED` đặt ngay khi nhận ZIP (`sandbox_router.py:120-136`) | phân loại chạy được / thiếu thư viện / sai kiến trúc / lỗi thu log / hết giờ từ `strace.log` + exit | quy tắc phân loại là quyết định thiết kế |
| 5 | **CT-05 Lưu dữ liệu bền vững** (3 tiêu chí con chưa kiểm) | có sẵn tác vụ thật trong Mongo/`output` | tạo lại container mongo/manager (quyết định riêng: đụng manager/Mongo, ngoài ủy quyền CT-01) rồi so hàng Mongo ↔ tệp | **đụng dịch vụ đang chạy** |
| 6 | **CT-12 Giai đoạn/worker** | PROCESSING→QUEUED khi manager khởi động lại; không heartbeat/timeout | thiết kế trạng thái giai đoạn; dùng log worker hiện chỉ ghi V-failure | cần thay đổi manager + worker |
| 7 | CT-06 Kiểm tra đầu vào, CT-13 Thông tin tái lập | độc lập, rủi ro thấp | hash/kích thước tại `submit-file`; đưa phiên bản đã ghi vào báo cáo tác vụ | CT-13 cần CT-09 để có chỗ ghi |
| 8 | CT-07 strace, CT-08 PCAP → CT-09 báo cáo JSON → CT-11 PDF | chuỗi phụ thuộc | parser trên `strace.log`/`network.pcap` của fixture busybox (đã có trong 4 zip) | không dùng mẫu mã độc thật cho tới khi quyết định riêng (AGENTS.md mục 5) |
| 9 | CT-10 Dashboard | sau CT-09/CT-12 | tiến trình/lỗi/báo cáo | — |
| 10 | **CT-14 Kiểm thử và đánh giá tổng hợp** | cuối cùng; CT-01 từng phần không tính | bộ kiểm ARM/MIPS qua luồng thật, cô lập, khôi phục, lỗi/hủy, báo cáo, xuất | cần các mục trên |

## 2. Việc CT-01 cố ý để ngoài (không phải nợ kỹ thuật bị quên)
Hoãn theo quyết định: T15-2, T17-P3, TAP_MAC giả (D5), N6, D1/D3/D4/D5; coverage T05c/T12-B3/T13-I3; guard 20 ms không đo; T12/T13 host capture OPEN (received−captured=8); MIPSEL/x86; log manager/ssh bổ sung của T07/T08 và M /status/mongosh của T09 (đã chấp nhận phạm vi mạng); Có evidence verifier ISOLATION OK tại các checkpoint đã review và evidence fault F3/F4 ARM; không chứng minh kiểm liên tục hoặc timing guard 20 ms. Chỉ mở khi có quyết định mới; không tính vào CT-14 như đã đạt.
