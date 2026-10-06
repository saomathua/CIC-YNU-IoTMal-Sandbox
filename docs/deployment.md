# Triển khai sandbox (bản fork của nhóm)

Tài liệu này mô tả cách cấu hình, build và vận hành sandbox bằng `sudo docker compose` trên Ubuntu 24.04.

> **Trạng thái kiểm chứng (cập nhật 06/10/2026):** cấu hình dưới đây mới được kiểm tra tĩnh (`docker compose config`, đối chiếu mã nguồn). **Chưa build image, chưa chạy stack, chưa kiểm chứng cô lập mạng.** Mục [Chưa kiểm thử](#chưa-kiểm-thử) liệt kê cụ thể.

## 1. Yêu cầu

- Docker Engine + Compose plugin (đã cài: Engine 29.8.2, Compose v5.6.0).
- Dùng `sudo docker …`; tài khoản chưa nằm trong nhóm `docker`.
- Kernel hỗ trợ TUN/TAP (`/dev/net/tun`). Worker chạy `privileged`.
- Không cần KVM: QEMU chạy giả lập TCG (chậm hơn).

## 2. Cách ứng dụng nạp cấu hình

Cả manager và worker dùng `pydantic-settings` (`BaseSettings`, `env_file=".env"`):

- `sandbox-manager/config/settings.py` — bắt buộc: `PORT`, `APP_BASE_URL`, `MONGO_USERNAME`, `MONGO_PASSWORD`, `MALWARE_DIRECTORY`.
- `sandbox-worker/config/settings.py` — bắt buộc: `PORT`, `APP_BASE_URL`.

Biến môi trường của tiến trình được ưu tiên hơn file `.env`, và nếu `.env` không tồn tại thì bị bỏ qua (pydantic-settings 2.7.0, `sources.py`: `if env_path.is_file()`). Vì vậy:

- Dockerfile **không còn** `COPY .env`; image không chứa bí mật.
- Mọi giá trị được cấp lúc chạy qua khối `environment:` trong `docker-compose.yml`.
- File `.env` ở thư mục gốc chỉ dùng cho Compose thay biến (`${...}`). Nó không nằm trong build context (`./sandbox-manager`, `./sandbox-worker`), và hai thư mục này có `.dockerignore` loại `.env`, `.env.*`.

Riêng `ALLOW_VM_INTERNET` không thuộc `Settings`; nó được `sandbox-worker/run.sh` đọc trực tiếp từ môi trường.

## 3. Cấu hình

```bash
cd /home/dathq/projects/CIC-YNU-IoTMal-Sandbox
cp .env.example .env
chmod 600 .env
```

Sửa `.env`:

| Biến | Mặc định mẫu | Ghi chú |
|---|---|---|
| `MONGO_USERNAME`, `MONGO_PASSWORD` | placeholder | **Bắt buộc**, tự đặt giá trị. Compose dừng nếu để trống. Chỉ áp dụng khi `./data/mongo` khởi tạo lần đầu. |
| `MANAGER_BIND_ADDR` | `127.0.0.1` | Địa chỉ host publish API manager. API không có xác thực — giữ loopback. |
| `MANAGER_PORT` | `8011` | Cổng trên host. |
| `MALWARE_DIR` | `./malware` | Thư mục mẫu trên host, mount read-only vào `/malware`. |
| `ANALYSIS_DURATION`, `POST_ANALYSIS_WAIT` | `30` | Giây. |
| `ALLOW_VM_INTERNET` | `false` | Xem mục 7. |

Không commit `.env` và mẫu mã độc (`.gitignore` đã loại `.env`, `.env.*`, `data/`, `malware/`).

## 4. Build và vận hành

```bash
sudo docker compose config --quiet      # kiểm tra cú pháp + biến
sudo docker compose build
sudo docker compose up -d
sudo docker compose ps
sudo docker compose logs -f sandbox-manager sandbox-worker-1
sudo docker compose down                # dừng; dữ liệu trong ./data được giữ
```

Thư mục `./data/...` sẽ do Docker tạo với chủ sở hữu `root` nếu chưa có.

## 5. Vị trí dữ liệu

| Dữ liệu | Trong container | Trên host | Nguồn trong mã |
|---|---|---|---|
| MongoDB | `/data/db` | `./data/mongo` | image `mongo` |
| Kết quả (zip) | `/app/output` (`OUTPUT_DIR=./output/`, WORKDIR `/app`) | `./data/manager/output` | `sandbox-manager/router/sandbox_router.py` (`submit_result`, `get_result`) |
| File upload | `/app/uploads` (`UPLOAD_DIR=./uploads/`) | `./data/manager/uploads` | `sandbox_router.py` (`submit_file`); đường dẫn `./uploads/<task_id>` lưu trong MongoDB |
| Mẫu (read-only) | `/malware` | `${MALWARE_DIR}` | `sandbox_router.py` (`init_queue`) |
| Dữ liệu tạm worker | `/app/data` | (không lưu) | `sandbox-worker/poller.py`; xóa sau mỗi task |

Giữ nguyên `OUTPUT_DIR`/`UPLOAD_DIR` dạng tương đối: các task cũ trong MongoDB lưu đường dẫn tương đối, đổi giá trị sẽ làm chúng trỏ sai.

## 6. Truy cập manager qua SSH tunnel

Từ máy cá nhân:

```bash
ssh -N -L 8011:127.0.0.1:8011 dathq@<địa-chỉ-máy-hq>
```

Sau đó trên máy cá nhân:

- `http://127.0.0.1:8011/api/v1/sandbox-manager/status`
- `http://127.0.0.1:8011/ui` (giao diện web, `router/ui_router.py`)
- `http://127.0.0.1:8011/healthcheck`

## 7. Mạng và cô lập — CHƯA KIỂM CHỨNG

`ALLOW_VM_INTERNET=false` chỉ là **cấu hình yêu cầu**. Chưa có bằng chứng VM bị chặn Internet. Những điểm cần kiểm tra trước khi chạy bất kỳ mẫu thật nào:

- `sandbox-worker/run.sh` chèn 2 luật bằng `iptables -I`, khiến luật `DROP` đứng trên luật `ACCEPT`.
- Lưu lượng từ `tap0` đi qua bridge `br0` trong container; iptables `FORWARD` chỉ thấy lưu lượng bridge khi có `br_netfilter`, và khi đó `-i` có thể khớp `br0` thay vì `tap0`.
- VM dùng gateway `192.168.60.1` (bridge Docker) → NAT của host ra Internet nếu không bị chặn.

Kiểm thử cô lập (nhiệm vụ sau) phải dùng binary vô hại và có bằng chứng (pcap, iptables counters) trước khi chạy mẫu.

## 8. Một worker

Compose chỉ cấu hình `sandbox-worker-1` (`192.168.60.2`). VM lấy IP = IP worker + 1 (`sandbox-worker/service/analysis.py`), tức `192.168.60.3`, nên không thể gán `.3` cho worker thứ hai. Cần xem lại cách cấp IP trước khi mở rộng.

## 9. MongoDB: lựa chọn phiên bản

Ghim `mongo:8.0.32` kèm digest `sha256:d0d926f9…a9c` (Docker Hub, cập nhật 2026-10-02).

- Manager dùng `pymongo==4.11` (`sandbox-manager/requirements.txt`).
- PyMongo 4.11 hỗ trợ wire version 7–25 (`pymongo/common.py`: `MIN_SUPPORTED_WIRE_VERSION = 7`, `MAX_SUPPORTED_WIRE_VERSION = 25`), tức MongoDB 4.0 đến 8.0; changelog PyMongo 4.9 ghi "Added support for MongoDB 8.0".
  Nguồn: <https://github.com/mongodb/mongo-python-driver/blob/4.11/pymongo/common.py>, <https://github.com/mongodb/mongo-python-driver/blob/4.11/doc/changelog.rst>.
- MongoDB 8.3 (tag `latest` hiện tại) mới hơn phạm vi driver này đã công bố hỗ trợ, nên không dùng.
- MongoDB ≥ 5.0 cần CPU có AVX; máy `hq` có `avx`/`avx2` trong `/proc/cpuinfo`.

**Chưa coi là tương thích** cho đến khi chạy thử: kết nối, `init-queue`, `submit-file`, `status`.

## Chưa kiểm thử

- [ ] `docker compose build` cho manager và worker (sau khi bỏ `COPY .env`).
- [ ] Manager khởi động và kết nối MongoDB 8.0.32.
- [ ] Bind mount `./data/manager/{output,uploads}` ghi được, dữ liệu còn sau `down`/`up`.
- [ ] Cổng manager chỉ lắng nghe trên `127.0.0.1` của host (`ss -ltnp`).
- [ ] SSH tunnel.
- [ ] Worker khởi tạo `tap0`/`br0`, kết nối manager.
- [ ] Cô lập mạng VM với `ALLOW_VM_INTERNET=false`.
- [ ] Phân tích end-to-end với binary vô hại cho từng kiến trúc.
