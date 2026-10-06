# Quy tắc làm việc cho agent và thành viên

Áp dụng cho mọi người và mọi AI agent làm việc trên repository này
(khóa luận: Sandbox ứng dụng trong phân tích mã độc IoT).

## Quy tắc bắt buộc

1. **Làm trên nhánh riêng.** Không commit trực tiếp vào `main`. Đặt tên
   nhánh theo loại việc, ví dụ `chore/...`, `feat/...`, `fix/...`, `docs/...`.
2. **Không commit bí mật hoặc mẫu mã độc.** Không đưa `.env`, mật khẩu, token,
   khóa riêng, hay bất kỳ mẫu ELF/mã độc nào vào Git hoặc Docker build context.
   Chỉ commit `*.env.example` với giá trị placeholder. Không in bí mật ra log
   hoặc báo cáo, và không yêu cầu gửi chúng qua chat.
3. **Mỗi nhiệm vụ có phạm vi và tiêu chí nghiệm thu.** Ghi rõ việc được làm,
   việc không được làm, và cách xác nhận hoàn thành trước khi bắt đầu. Không
   mở rộng phạm vi khi chưa được đồng ý.
4. **Báo cáo bằng chứng, SHA và hạn chế.** Mỗi bàn giao nêu nhánh, SHA commit,
   lệnh đã chạy và kết quả thực tế, và các hạn chế. Phân biệt rõ điều *đã kiểm
   chứng* với điều *chỉ đọc từ tài liệu/mã nguồn*.
5. **Chưa chạy mẫu trước khi kiểm chứng cô lập.** Không chạy mẫu mã độc thật
   cho đến khi cô lập mạng của VM đã được kiểm chứng bằng binary vô hại và có
   bằng chứng (xem `docs/deployment.md`, mục 7).
6. **Không merge khi chưa có review.** Mọi thay đổi vào `main` đi qua Pull
   Request và được ít nhất một thành viên review.

## Tham khảo

- Triển khai và vận hành: `docs/deployment.md`.
- Chỉ thay đổi cấu hình mạng, firewall, SSH hoặc phân vùng của host khi
  nhiệm vụ cho phép rõ ràng.
