# Kết quả cải tiến (KQCaiTien)

Ghi tiến độ khóa luận **"Nghiên cứu và triển khai Sandbox ứng dụng trong phân tích mã độc IoT"**, dựa trên bằng chứng.
Roadmap và tiêu chí nghiệm thu: [`docs/requirements.md`](docs/requirements.md). Minh chứng: [`docs/evidence/`](docs/evidence/).

Cập nhật lần cuối: 06/10/2026 (tuần 7, sau Nhiệm vụ 05C). Hạn hoàn thành: 08/11/2026.

`docs/requirements.md`: **reviewer đã đọc và chấp nhận**.

## Quy ước

| Trạng thái | Ý nghĩa |
|---|---|
| **Chưa bắt đầu** | Nhóm chưa sửa gì cho tiêu chí này. |
| **Đã cấu hình – chưa kiểm chứng** | Có thay đổi cấu hình/mã nhưng chưa có kiểm thử chứng minh hoạt động. |
| **Kiểm chứng một phần** | Một số tiêu chí con có bằng chứng; phần còn lại chưa. |
| **Đạt** | Mọi tiêu chí nghiệm thu có bằng chứng và đã được review. |

Nguồn: **[KC]** đã kiểm chứng bằng lệnh/kết quả thực tế; **[Mã]** chỉ đọc mã nguồn, chưa chạy.
Phân biệt: **CIC đã có** (mã gốc), **Nhóm đã làm**, **Chưa kiểm chứng**.

## Trạng thái commit / PR

| Hạng mục | Giá trị |
|---|---|
| Commit nền CIC (`main`) | `0ce8796622a8f9587a0fda205764cfa44dfb5711` |
| Nhánh làm việc | `chore/deployment-prep` (tách từ `chore/baseline-audit`) |
| Commit mốc triển khai | `chore: prepare deployment and record baseline verification` trên `chore/deployment-prep` (SHA xem `git log`; một commit không thể tự chứa SHA của chính nó) |
| Push / PR | **Chưa** — chưa push, chưa mở PR, chưa merge |
| Diff đã review (NV03) | sha256 `04113607e9a01a6f3b2d5581ea9c40ffbd7ebce9697a4961864e78515ff35045` |

---

# Phần A — Chuẩn bị môi trường

Không thuộc CT-01–14; là nền để triển khai và kiểm thử.

### NV01 — Khảo sát nền

- **Mục tiêu:** chuẩn bị repo, khảo sát kiến trúc và điểm cần kiểm chứng.
- **Thay đổi:** clone repo; thêm remote `upstream`; tạo nhánh `chore/baseline-audit`. Không sửa source.
- **Kiểm thử / Kết quả [KC]:** Ubuntu 24.04, 4 vCPU, 7.7 GiB RAM, `/` 73G; không có `/dev/kvm` (QEMU chạy TCG); Git 2.43.0.
- **Hạn chế:** `sudo vgs/lvs` chưa chạy (cần mật khẩu).
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Commit/PR:** không có.
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md).

### NV02 — Cài Docker

- **Mục tiêu:** cài Docker Engine từ kho APT chính thức.
- **Thay đổi (hệ thống):** khóa APT Docker (fingerprint `9DC8…CD88` khớp), cài `docker-ce 29.8.2`, `containerd.io 2.3.6`, `buildx 0.37.1`, `compose-plugin 5.6.0`, `unzip`. Chưa thêm user vào nhóm `docker`.
- **Kiểm thử / Kết quả [KC]:** `hello-world` in "Hello from Docker!"; `docker`, `containerd` active + enabled.
- **Hạn chế:** Docker tự thêm chain iptables và bridge `docker0` (hành vi mặc định).
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Commit/PR:** không áp dụng.
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md).

### NV03 — Cấu hình build và lưu trữ

- **Mục tiêu:** bỏ `.env` khỏi image, lưu trữ bền vững, ghim MongoDB, bind loopback, mặc định chặn Internet cho VM, tài liệu.
- **Thay đổi:** `Dockerfile` (bỏ `COPY .env`) ×2; `.dockerignore` ×2; `.gitignore`; `.env.example` ×2; `docker-compose.yml`; `README.md`; `docs/deployment.md`; `AGENTS.md`; `CLAUDE.md`.
- **Kiểm thử / Kết quả [KC]:** `git diff --check` OK; `compose config --quiet` OK; thiếu biến Mongo → Compose báo lỗi; script so `Settings`↔`environment` thiếu 0 biến; nguồn `COPY` không bị `.dockerignore` loại; `.env`, `malware/`, `data/` bị Git bỏ qua.
- **Hạn chế:** kiểm tra tĩnh.
- **Review:** reviewer đã đối chiếu trực tiếp patch với source và chấp nhận bước build. **Commit/PR:** chưa (xem trên).
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md); patch đầy đủ chưa được lưu trong `docs/evidence/` (**thiếu**, hiện chỉ có tại `/home/dathq/projects/chore-deployment-prep.patch` ngoài repo).

### NV04 — Build image

- **Mục tiêu:** build `sandbox-manager`, `sandbox-worker`; chưa chạy.
- **Kiểm thử / Kết quả [KC]:** `exit=0`, `real 1m18.6s`; manager `13f02b814da6` (240 MB), worker `003a465550aa` (862 MB); build context của manager 30 kB, của worker 40 MB → `.env` không nằm trong context.
- **Hạn chế:** build thành công ≠ ứng dụng chạy được.
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Minh chứng:** [`task04-build.md`](docs/evidence/task04-build.md), [`task04-build.log`](docs/evidence/task04-build.log).

### NV05 — Kiểm chứng MongoDB và manager

- **Mục tiêu:** chạy riêng MongoDB và manager, kiểm tra endpoint, cổng, mount, lưu trữ; chưa chạy worker.
- **Thay đổi (hệ thống):** tạo `.env` (600, giá trị do người dùng đặt); tạo `malware/`, `data/mongo`, `data/manager/{output,uploads}`; pull `mongo:8.0.32`; chạy 2 container.
- **Kiểm thử / Kết quả [KC]:**
  - `mongo-db` ping `1`; manager restarts=0; log `Connected to MongoDB — recovered 0 task(s)`.
  - `/healthcheck`, `/status`, `/ui` đều 200; `/status` toàn 0; `/tasks` `[]`.
  - Cổng chỉ `127.0.0.1:8011`; không truy cập được qua IP LAN; Mongo không publish cổng.
  - Mount `output`/`uploads` rw, `malware` ro; marker còn nguyên hash sau `--force-recreate` manager; đã xóa marker.
  - UI mở được qua SSH tunnel từ Windows.
  - Không có worker/QEMU.
- **Hạn chế:**
  - Mật khẩu MongoDB ngắn (3 ký tự). **Người dùng quyết định giữ** để thuận tiện trong lab; không đổi mật khẩu hay cấu hình xác thực. Việc MongoDB không publish cổng ra host chỉ hạn chế truy cập trực tiếp từ ngoài VM; **chưa đủ để kết luận cô lập**, vì manager vẫn kết nối được database (manager nằm trên cả `dbnet` và `sandboxnet`) và mạng QEMU chưa được kiểm chứng (CT-01). Cần đánh giá lại trước khi chạy mẫu thật hoặc dùng ngoài lab.
  - `SyntaxWarning` ở `ui_router.py:462` (mã gốc).
- **Review:** reviewer chấp nhận báo cáo kiểm thử và ảnh UI qua SSH tunnel. **Minh chứng:** [`task05-manager-mongo.md`](docs/evidence/task05-manager-mongo.md), [`task05-ui-ssh-tunnel.webp`](docs/evidence/task05-ui-ssh-tunnel.webp).

---

# Phần B — Cải tiến CT-01 → CT-14

| Mã | Cải tiến | Trạng thái | Review | Commit/PR |
|---|---|---|---|---|
| CT-01 | Cô lập mạng QEMU | Đã cấu hình – chưa kiểm chứng | chưa | chưa |
| CT-02 | Môi trường sạch giữa các mẫu | Chưa bắt đầu | — | — |
| CT-03 | Cleanup | Chưa bắt đầu | — | — |
| CT-04 | Xác minh thực thi và log | Chưa bắt đầu | — | — |
| CT-05 | Lưu dữ liệu bền vững | Kiểm chứng một phần | chưa | chưa |
| CT-06 | Kiểm tra đầu vào | Chưa bắt đầu | — | — |
| CT-07 | Phân tích strace | Chưa bắt đầu | — | — |
| CT-08 | Phân tích PCAP | Chưa bắt đầu | — | — |
| CT-09 | Báo cáo JSON | Chưa bắt đầu | — | — |
| CT-10 | Dashboard | Chưa bắt đầu (`/ui` gốc chạy được [KC]) | — | — |
| CT-11 | Xuất PDF | Chưa bắt đầu | — | — |
| CT-12 | Theo dõi giai đoạn và worker | Chưa bắt đầu | — | — |
| CT-13 | Thông tin tái lập | Chưa bắt đầu (phiên bản đã ghi trong tài liệu) | — | — |
| CT-14 | Kiểm thử và đánh giá | Chưa bắt đầu | — | — |

### CT-01 — Cô lập mạng QEMU · Đã cấu hình – chưa kiểm chứng

- **Mục tiêu:** chặn Internet, LAN và dịch vụ quản lý; chỉ cho luồng cần thiết; có kiểm thử đích được phép/bị chặn.
- **CIC đã có [Mã]:** `ALLOW_VM_INTERNET=false` → 2 luật iptables FORWARD (`sandbox-worker/run.sh:27-31`); mặc định gốc `true`.
- **Nhóm đã làm:** mặc định `false` trong `docker-compose.yml`, `.env.example`, `.env`; manager bind `127.0.0.1`.
- **Kiểm thử / Kết quả:** chỉ xác nhận giá trị biến [KC] (NV03, NV05). **Chưa có kiểm thử cô lập.**
- **Hạn chế / nghi vấn [Mã]:** `DROP` đứng trên `ACCEPT` do cùng dùng `-I`; lưu lượng `tap0` qua bridge `br0` có thể không đi qua FORWARD; worker dùng `iptables-nft`.
- **Còn thiếu:** kiểm thử bằng ELF lành tính tới đích được phép (worker) và bị chặn (Internet, LAN `192.168.177.0/24`, manager, MongoDB, host), kèm pcap và bộ đếm luật.

### CT-02 — Môi trường sạch giữa các mẫu · Chưa bắt đầu

- **CIC đã có [Mã]:** mỗi tác vụ giải nén `image.zip` vào thư mục riêng (`sandbox-worker/service/analysis.py:360-361`) và xóa sau khi xong (`poller.py:68-81`). Thiết kế có thể đáp ứng, **chưa kiểm chứng**.
- **Còn thiếu:** kiểm thử marker giữa 2 tác vụ liên tiếp; so hash `*/image.zip` trước/sau.

### CT-03 — Cleanup · Chưa bắt đầu

- **CIC đã có [Mã]:** xóa thư mục tác vụ khi lỗi/hủy (`poller.py:49-63`); dừng QEMU/tshark khi hủy (`analysis.py:237-240`).
- **Nghi vấn [Mã]:** khi lỗi/timeout (`analysis.py:171-263`) không có `finally` dừng QEMU; tshark (`analysis.py:218`) không bị dừng nếu lỗi xảy ra sau khi khởi động.
- **Còn thiếu:** dọn bảo đảm cho thành công/lỗi/timeout/hủy và kiểm thử tác vụ kế tiếp.

### CT-04 — Xác minh thực thi và log · Chưa bắt đầu

- **CIC đã có [Mã]:** `COMPLETED` đặt ngay khi nhận ZIP (`sandbox-manager/router/sandbox_router.py:120-136`); kiến trúc không hỗ trợ → `FAILED` (`analysis.py:130`).
- **Còn thiếu:** phân loại chạy được / thiếu thư viện / sai kiến trúc / lỗi thu log / hết giờ.

### CT-05 — Lưu dữ liệu bền vững · Kiểm chứng một phần

- **Mục tiêu:** tạo lại container vẫn giữ mẫu upload, log/kết quả, dữ liệu MongoDB và liên kết tác vụ.
- **CIC đã có [Mã]:** chỉ MongoDB có bind mount `./data/mongo`.
- **Nhóm đã làm:** bind mount `./data/manager/output:/app/output`, `./data/manager/uploads:/app/uploads`; ghim `mongo:8.0.32`.

| Tiêu chí con | Trạng thái | Bằng chứng |
|---|---|---|
| Tệp `output`/`uploads` còn sau khi tạo lại container manager | Đạt [KC] | NV05 marker: hash giống nhau ở container cũ/mới/host |
| Mount đúng đường dẫn, ghi được | Đạt [KC] | NV05 `docker inspect` |
| Dữ liệu MongoDB còn sau khi tạo lại container mongo | Chưa kiểm chứng | — |
| Mẫu upload và kết quả thật còn sau khi tạo lại | Chưa kiểm chứng | chưa có tác vụ |
| Liên kết tác vụ (MongoDB ↔ tệp) | Chưa kiểm chứng | chưa có tác vụ |

- **Hạn chế:** marker chỉ chứng minh lưu trữ tệp qua việc tạo lại container manager.

### CT-06 — Kiểm tra đầu vào · Chưa bắt đầu

- **CIC đã có [Mã]:** `submit-file` nhận mọi tệp, không kiểm tra loại/dung lượng, không tính hash (`sandbox_router.py:85-101`); kiến trúc chỉ xác định ở worker (`analysis.py:112-130`).

### CT-07 — Phân tích strace · Chưa bắt đầu

- **CIC đã có [Mã]:** chỉ thu `strace.log` thô vào ZIP.

### CT-08 — Phân tích PCAP · Chưa bắt đầu

- **CIC đã có [Mã]:** chỉ thu `network.pcap` thô (tshark trên `tap0`).

### CT-09 — Báo cáo JSON · Chưa bắt đầu

- **CIC đã có [Mã]:** ZIP gồm `strace.log`, `sar.out`, `network.pcap`, `qemu.log`; không có báo cáo cấu trúc.

### CT-10 — Dashboard · Chưa bắt đầu

- **CIC đã có [KC]:** `/ui` trả 200 và hiển thị qua SSH tunnel (NV05).
- **Còn thiếu:** tiến trình, lỗi, báo cáo chi tiết.

### CT-11 — Xuất PDF · Chưa bắt đầu

- Phụ thuộc CT-09.

### CT-12 — Theo dõi giai đoạn và worker · Chưa bắt đầu

- **CIC đã có [Mã]:** 5 trạng thái; khi manager khởi động lại, PROCESSING → QUEUED (`sandbox-manager/util/lifespan_handlers.py:34-44`). Không có giai đoạn, heartbeat hay timeout cho worker.

### CT-13 — Thông tin tái lập · Chưa bắt đầu

- **Đã ghi ở mức tài liệu [KC]:** phiên bản Docker/Compose, `mongo:8.0.32` + digest, digest base image, QEMU `1:6.2+dfsg-2ubuntu6.31`, tshark 3.6.2; `.env` không vào image.
- **Còn thiếu:** đưa vào từng báo cáo tác vụ; giữ log lỗi theo tác vụ.

### CT-14 — Kiểm thử và đánh giá · Chưa bắt đầu

- Chưa có kiểm thử ARM/MIPS, cô lập, khôi phục, lỗi/hủy, báo cáo, xuất kết quả.
