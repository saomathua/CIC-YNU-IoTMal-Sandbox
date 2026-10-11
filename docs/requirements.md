# Yêu cầu và roadmap cải tiến

**Đề tài:** Nghiên cứu và triển khai Sandbox ứng dụng trong phân tích mã độc IoT.
**Nền tảng kế thừa:** [CIC-YNU-IoTMal-Sandbox](https://github.com/UNBCIC/CIC-YNU-IoTMal-Sandbox) (commit nền `0ce8796622a8f9587a0fda205764cfa44dfb5711`).
**Hạn hoàn thành:** 08/11/2026 (tài liệu lập ở tuần 7, 06/10/2026).

> Đây là **roadmap**, không phải lệnh thực hiện tất cả cùng lúc. Mỗi cải tiến được
> triển khai qua nhiệm vụ riêng có phạm vi và tiêu chí nghiệm thu (xem `AGENTS.md`).
> Trạng thái thực tế và bằng chứng được ghi tại [`KQCaiTien.md`](../KQCaiTien.md).

## Danh sách cải tiến đã chốt

| Mã | Cải tiến | Tiêu chí nghiệm thu |
|---|---|---|
| CT-01 | Cô lập mạng QEMU | Chặn Internet, LAN và dịch vụ quản lý; chỉ cho luồng cần thiết. Có kiểm thử đích được phép/bị chặn, không chỉ kiểm tra biến cấu hình. |
| CT-02 | Môi trường sạch giữa các mẫu | Tệp đánh dấu của tác vụ trước không xuất hiện ở tác vụ sau; image gốc không đổi. |
| CT-03 | Cleanup | Thành công, lỗi, timeout hoặc hủy đều dọn QEMU/tshark của tác vụ; tác vụ tiếp theo chạy được. |
| CT-04 | Xác minh thực thi và log | Phân biệt chạy được, thiếu thư viện, sai kiến trúc, lỗi thu log và hết thời gian. COMPLETED không chỉ dựa vào nhận ZIP. |
| CT-05 | Lưu dữ liệu bền vững | Tạo lại container vẫn giữ mẫu upload, log/kết quả, dữ liệu MongoDB và liên kết tác vụ. |
| CT-06 | Kiểm tra đầu vào | Từ chối non-ELF, vượt dung lượng, kiến trúc không hỗ trợ; lưu SHA-256. |
| CT-07 | Phân tích strace | Danh sách/tần suất syscall, tiến trình, thao tác tệp, kết nối mạng và lỗi. |
| CT-08 | Phân tích PCAP | IP/port, giao thức, DNS, kết nối và lưu lượng; phân biệt thử kết nối với kết nối thành công. |
| CT-09 | Báo cáo JSON | Chuẩn hóa thông tin mẫu, môi trường, thời gian, thực thi, hành vi và hạn chế. |
| CT-10 | Dashboard | Kế thừa `/ui` hiện có; bổ sung tiến trình, lỗi và báo cáo phân tích chi tiết. |
| CT-11 | Xuất PDF | Dùng cùng dữ liệu báo cáo JSON, có task ID và hash mẫu. |
| CT-12 | Theo dõi giai đoạn và worker | Biết đang boot/chạy/lấy log/phân tích; xử lý worker mất kết nối, tránh tác vụ treo vô hạn. |
| CT-13 | Thông tin tái lập | Giữ log lỗi, cấu hình thí nghiệm và phiên bản; không lưu bí mật vào báo cáo. |
| CT-14 | Kiểm thử và đánh giá | Minh chứng ARM/MIPS, cô lập, khôi phục, lỗi/hủy, báo cáo và xuất kết quả. |

## Thứ tự ưu tiên

1. **Nền tảng: CT-01 → CT-06**, kiểm thử bằng ELF **lành tính** ARM/MIPS.
   CT-01 phải đạt trước khi chạy bất kỳ mẫu mã độc thật nào.
2. **Phân tích và báo cáo: CT-07 → CT-11.**
3. **CT-12 → CT-14** được tích hợp dần vào các nhiệm vụ liên quan, không làm thành giai đoạn riêng ở cuối.

## Ngoài phạm vi hiện tại

- Chưa ưu tiên: học máy (ML), kiến trúc PPC/ARM64, nhiều worker.
- Trích xuất bộ nhớ động: **cần làm rõ với giảng viên** trước khi đưa vào roadmap.

## Nguyên tắc đánh giá

- Phân biệt rõ ba loại: **chức năng CIC đã có**, **phần nhóm sửa/bổ sung**, **phần chưa kiểm chứng**.
- Build thành công không đồng nghĩa vận hành thành công; cấu hình đúng không đồng nghĩa cơ chế hoạt động.
- Không kết luận mẫu là mã độc hay lành tính chỉ từ vài syscall hoặc vài kết nối mạng; báo cáo phải nêu hạn chế.
- Mỗi bàn giao gồm: thay đổi, kết quả kiểm tra, bằng chứng (lệnh, output, SHA) và hạn chế.
