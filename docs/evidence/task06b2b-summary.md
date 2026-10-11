# Minh chứng Nhiệm vụ 06B-2B: HTTP/API thật, chưa boot guest (06/10/2026)

**Bối cảnh:**

- Reviewer đã chấp nhận 06B-2AR ở mức startup/V0.
- Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), chưa commit. Working tree trước khi làm khớp tree `20a245ddff5a1a5ba7f0e77db27b0ef8d089a667` (bàn giao 06B-2AR).
- **Không** chạy service worker bằng Compose, poller thật, QEMU, ELF hay mẫu nào. Không bật manager. Không sửa cấu hình host. Không gọi `submit-task` từ peer có quyền quản trị.

## Harness

Bản lưu trong repo: [`task06b2b/harness/`](task06b2b/harness/).

| File | sha256 |
|---|---|
| `run-06b2b.sh` | `418097ffcf5b0ba2634463759fdf3ea0cd02caac082298e45f1241312f601f67` |
| `http_tests.py` | `c34cf278d244ab4a75ccd9f62aa812efc350cb8b868018943623e985d2f3ea32` |
| `sentinel/poller.py` | `7e49a99bac3a1b5f277d0700b4250043a13fce15bbb6f5c58dd7d24d44a8ab26` |

**Lệnh** (người dùng chạy): `sudo bash /home/dathq/projects/ct01-06b2b/run-06b2b.sh`. Kết quả **ALL CHECKS PASSED**, `exit=0`. Log: [`task06b2b/run.log`](task06b2b/run.log) (`cd3f1db8…d5a7`).

**Cấu hình container `ct01-06b2b-http`** (id `e0c582a54bdc…`):

- Image `sha256:d0bf9277e7c485823ff5a3b8f5ead6c038ef03c5c9fc72fcd0040799403e6f42`, kiểm khớp ID đầy đủ.
- `sandboxnet`, `--privileged`, `--restart no`, không publish cổng, không dùng host network, không mount dữ liệu lab hay `docker.sock`.
- Chỉ `/app/poller.py` được thay bằng sentinel (chỉ đọc); **`server.py` là bản thật**.
- sha256 của `run.sh`, `server.py`, router, `lifespan_handlers.py`, `settings.py`, `analysis.py` và các file `isolation/*` trong image **khớp working tree**.

## 1. Startup và server thật: ĐẠT

| Kiểm tra | Kết quả |
|---|---|
| V0 | `ISOLATION OK (V0 startup)` lúc `14:02:24.369097`, **trước** poller sentinel (`.384194`) và trước uvicorn `Started server process` (`.750179`) |
| Server sẵn sàng | `/healthcheck` từ `127.0.0.1` trả 200 sau 2 giây; server chỉ khởi động 1 lần; container 0 lần restart |
| Tiến trình | PID 1 `python3 poller.py` (sentinel), `bash run.sh`, **`python3 server.py` (thật)**. Không có QEMU hay tshark trong container; không có `qemu-system` trên host ([`ps.txt`](task06b2b/ct01-06b2b-http/ps.txt)) |
| Verify trước khi mô phỏng | `ISOLATION OK` |

## 2. API allowlist qua HTTP thật: 42/42 ĐẠT

**Phạm vi:** IP nguồn của guest được **mô phỏng** bằng cách thêm tạm `10.200.0.2/32` vào `lo` của container test. Client `http.client` bind nguồn `10.200.0.2` và gọi `10.200.0.1:8011`. Server thấy peer TCP thật là `10.200.0.2`.

Lưu lượng này đi qua `lo`, nằm ngoài mọi luật CT-01 (luật chỉ lọc `tap0`). Vì vậy phép thử **chứng minh middleware HTTP, KHÔNG chứng minh việc lọc trên `tap0`**.

Fixture:

- Task `06b2b-task-0001`: file văn bản vô hại (`b9ee18e4…5c5f`, 4 byte đầu `3036422d` = "06B-", không phải ELF).
- Task `06b2b-other-0002`: file văn bản thứ hai, dùng để chứng minh 403 là do bộ lọc chứ không phải 404.
- Marker `current_task` được ghi bằng helper thật `isolation.current_task.set_current()`.

| Nhóm | Kết quả |
|---|---|
| Không có `current_task`: GET `get-task/T/file`, POST `update-task/T/strace`, POST `update-task/T/sar` | **403** cả ba; không có file nào được ghi |
| GET `get-task/T/file` (có marker) | **200**; sha256 nội dung = fixture (`b9ee18e4…5c5f`) |
| POST `update-task/T/strace`, `/sar` | **200**; `strace.log` (`22e6b9e6…f382`) và `sar.out` (`357ca3ee…261e`) khớp sha256 đã gửi |
| Task khác (GET file, POST strace); sai phương thức (POST/HEAD file, GET/PUT update); `/healthcheck`; POST `/stop`; POST `/submit-task/X` và `/submit-task/new-06b2b-task`; `/docs`; `/openapi.json`; path có `/` ở cuối | **403** cả 13 |
| Header giả `X-Forwarded-For` (IP `eth0`, `127.0.0.1`), `Forwarded: for=…`, `X-Real-IP` từ nguồn guest | `/healthcheck` và task khác **vẫn 403** (8 phép thử) |
| Tác dụng phụ của route bị cấm | Không có file `/tmp/sandbox_stop_requested`; `data/` chỉ có hai fixture; task khác không bị ghi |
| Peer ngoài mạng guest | `127.0.0.1` → `/healthcheck` **200**; IP `eth0` `192.168.60.2` → **200**; `127.0.0.1` kèm `X-Forwarded-For: 10.200.0.2` → **vẫn 200** (không bị coi là guest) |
| Xóa marker | Xóa được; GET `get-task/T/file` lại **403** |
| Dọn fixture | `data/` rỗng; không còn marker |

Log server ([`server-access-and-deny-log.txt`](task06b2b/ct01-06b2b-http/server-access-and-deny-log.txt)):

- access log của uvicorn ghi đúng peer `10.200.0.2:<port>` cho từng request, kèm mã kết quả;
- có **25** dòng `guest request denied: client=('10.200.0.2', …)`, khớp với 25 phản hồi 403 gửi về nguồn guest.

Kết quả chi tiết: [`http-tests.txt`](task06b2b/ct01-06b2b-http/http-tests.txt), [`http-results.json`](task06b2b/ct01-06b2b-http/http/http-results.json).

## 3. Sau khi xóa địa chỉ mô phỏng: ĐẠT

- `ip addr del 10.200.0.2/32 dev lo`. Không còn địa chỉ `10.200.0.2` trên interface nào ([`ip-addr-after-simulation.txt`](task06b2b/ct01-06b2b-http/ip-addr-after-simulation.txt)).
- Không còn marker, fixture hay file stop.
- **Verify đầy đủ:** `ISOLATION OK (06B-2B after simulation)`. Ruleset tại runtime giống hệt expected.
- Teardown: stop và rm exit 0, container đã xóa. Container duy nhất do lần chạy tạo là `e0c582a5…` ([`created-ids.txt`](task06b2b/created-ids.txt)).
- **Host không đổi:** sysctl, ruleset nft, route IPv4/IPv6, địa chỉ, cổng đang nghe, module, container, network.

## 4. Phát hiện cần reviewer quyết định

**Verify không phát hiện địa chỉ thuộc mạng guest nằm trên interface khác `tap0`.**

- Khi `10.200.0.2/32` đang nằm trên `lo`, verify vẫn báo `ISOLATION OK (… during simulation (informational))` ([`verify-during-simulation.txt`](task06b2b/ct01-06b2b-http/verify-during-simulation.txt)).
- Nguyên nhân: `check_links` chỉ kiểm địa chỉ của `tap0` và `eth0`; `check_routes` chỉ xem route của `tap0`.
- Hệ quả, chỉ là **suy luận**: worker sẽ coi `10.200.0.2` là địa chỉ của chính nó, nên giao tiếp với guest bị sai. Đây là lệch cấu hình không bị phát hiện, không phải đường thoát cho guest.
- Đề xuất, **chưa sửa**: verify báo lỗi nếu bất kỳ interface nào ngoài `tap0` có địa chỉ trong `10.200.0.0/30`, hoặc nếu bảng `local` có route cho `GUEST_NET` ngoài `10.200.0.1`.

## 5. Kết luận và giới hạn

- **ĐẠT theo đúng phạm vi phép thử:** với server thật và peer TCP thật, middleware chỉ cho nguồn `10.200.0.0/30` gọi đúng ba route của task hiện tại; mọi route và phương thức khác bị 403; header proxy giả bị bỏ qua; peer ngoài mạng guest không bị ảnh hưởng.
- **Chưa chứng minh:**
  - lọc trên `tap0` (nft prerouting, ARP, L2), vì lưu lượng mô phỏng đi qua `lo`;
  - giao tiếp với guest thật;
  - V1/V2 trong luồng thật;
  - ma trận T01–T21 và F1–F6.
- **CT-01 vẫn chưa đạt.**
