# Minh chứng

Lưu bằng chứng cho [`KQCaiTien.md`](../../KQCaiTien.md). Quy tắc:

- Không lưu bí mật (mật khẩu, token, `.env`), không lưu mẫu mã độc.
- Output lệnh được rút gọn khi cần; phần che ghi rõ `[đã che]`.
- Đặt tên `taskNN-<nội-dung>.<ext>`; ghi sha256 của tệp nhị phân/log trong bảng dưới.

| Tệp | Nhiệm vụ | Nội dung | sha256 |
|---|---|---|---|
| [`task01-03-baseline-docker-config.md`](task01-03-baseline-docker-config.md) | 01–03 | Khảo sát môi trường, cài Docker, kiểm tra cấu hình tĩnh | — |
| [`task04-build.md`](task04-build.md) | 04 | Tóm tắt kết quả build image | — |
| [`task04-build.log`](task04-build.log) | 04 | Log build đầy đủ (`--progress=plain`) | `3615edb2a21a032048c491dfb84f57b30dcbae5ef64f1d94f938da9621321b10` |
| [`task05-manager-mongo.md`](task05-manager-mongo.md) | 05 | MongoDB + manager, endpoint, cổng, mount, marker lưu trữ | — |
| [`task05-ui-ssh-tunnel.webp`](task05-ui-ssh-tunnel.webp) | 05 | Ảnh `/ui` mở qua SSH tunnel từ Windows (người dùng chụp) | `81778685001998771838c58cb054713db750c397123e60598e52e19322ce64e8` |
