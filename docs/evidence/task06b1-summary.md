# Minh chứng Nhiệm vụ 06B-1: triển khai CT-01, kiểm tra trước khi chạy guest (06/10/2026)

Nhánh `feat/ct01-network-isolation`, tách từ `3c54d55`. Thay đổi **chưa commit** tại thời điểm ghi.

**Không** khởi chạy `sandbox-worker-1`, không boot QEMU, không chạy ELF, không đổi mạng/firewall/sysctl của host.

## 1. Unit test (không cần nft)

Chạy trên host `hq` trong venv tạm (Python 3.12, cùng phiên bản thư viện với `sandbox-worker/requirements.txt`, thêm `pytest 8.3.4`):

```
cd sandbox-worker && python -m pytest -v tests
107 passed
```

Output đầy đủ: [`task06b1/unit-tests.txt`](task06b1/unit-tests.txt).

| Nhóm | File test | Nội dung |
|---|---|---|
| Verify | `tests/test_verify.py` | Đổi counter/handle không làm fail. Thêm, xóa hoặc đổi thứ tự rule, đổi policy, hook, prio, device, địa chỉ, verdict, xóa counter, thiếu hoặc thừa bảng, sai phiên bản nft đều làm fail. Có kiểm sysctl, link, neighbor, route, và kiểm device netdev từ output văn bản |
| API allowlist | `tests/test_apifilter.py` | Chạy qua app FastAPI thật. Thiếu `current_task`, task khác, sai phương thức, biến thể path, route quản trị (`/healthcheck`, `/stop`, `/submit-task`, `/docs`, `/openapi.json`) đều trả 403. `X-Forwarded-For`/`Forwarded`/`X-Real-IP` không vượt được allowlist. Peer IPv4-mapped hoặc không xác định bị coi là guest. `proxy_headers=False` |
| current_task | `tests/test_current_task.py` | Ghi nguyên tử. Ghi lỗi thì giữ giá trị cũ, không để lại file tạm. Task id không hợp lệ bị từ chối. Marker bị xóa khi thành công, lỗi, hủy, và cả `KeyboardInterrupt`. Startup xóa marker cũ |
| QEMU gating | `tests/test_analysis_isolation.py` | Lỗi V1 thì không spawn QEMU nào. Lỗi V2 thì chỉ có 1 spawn (phase 1) và VM phase 1 đã bị kill. Có MAC trên NIC gắn tap của cả 4 kiến trúc, URL `10.200.0.1:8011`, `/30`, gateway `10.200.0.1`, từ chối khi `PORT != 8011` |

**Kiểm tra đối chứng cho bộ test:** cố ý phá mã trên một bản sao, mỗi lần một chỗ, rồi chạy lại test. Cả 14 lần đều có test thất bại, nghĩa là test bắt được lỗi:

| Chỗ bị phá | Số test thất bại |
|---|---|
| middleware cho qua mọi request | 25 |
| tin `X-Forwarded-For` | 2 |
| cho thêm `/healthcheck` vào allowlist | 4 |
| bỏ `finally` xóa marker | 4 |
| bỏ V1 | 2 |
| bỏ V2 | 1 |
| normalize giữ `handle` | 2 |
| normalize bỏ `prio` | 2 |
| không kiểm `ip_forward` | 1 |
| bỏ kiểm state `PERMANENT` | 1 |
| `proxy_headers=True` | 1 |
| bỏ `mac=` khỏi lệnh QEMU | 1 |
| prefix `/24` | 1 |
| bỏ kiểm device netdev | 4 |

## 2. Build image worker

| Lần | Lệnh | Kết quả | Manifest list |
|---|---|---|---|
| 1 | `sudo docker compose --progress plain build sandbox-worker-1` | `exit=0` | `sha256:ac9bf7cfd4a2…` ([log](task06b1/build-run1.log)) |
| 2 (sau khi thêm `expected-ruleset.json` và kiểm device) | như trên | `exit=0` | `sha256:6a15d4ed6ad6…` ([log](task06b1/build-run2.log)) |

Gói mới: `nftables 1.0.2-1ubuntu3.1`, `libnftables1 1.0.2-1ubuntu3.1` ([packages.txt](task06b1/packages.txt)). `nft --version` = `nftables v1.0.2 (Lester Gooch)`.

Sau build: `docker ps -a` chỉ có `mongo-db` (Up) và `sandbox-manager` (Exited). **Không có container worker.**

## 3. Kiểm thử nft thật trong container riêng

```
sudo docker run --rm --network none --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint /bin/bash -v …/sandbox-worker/tests:/tests:ro -v …/out:/out \
  sandbox-worker:latest /tests/integration/nft_selftest.sh
```

- Không `--privileged`. Entrypoint bị thay, nên `run.sh`, `server.py`, poller và QEMU không chạy.
- Script tự dừng nếu container có interface khác ngoài `lo`.
- `tap0`, địa chỉ, neighbor và ruleset chỉ được tạo trong netns của container kiểm thử.

| Lần | Kết quả | Log |
|---|---|---|
| 1 | **20/22**, `exit=1` | [nft-selftest-run1.log](task06b1/nft-selftest-run1.log) |
| 2 | **24/24**, `exit=0` | [nft-selftest-run2.log](task06b1/nft-selftest-run2.log) |

Hai lỗi của lần 1:

1. `extra base chain in inet table`: lỗi cú pháp trong chính script kiểm thử (thiếu `;` giữa hai `}`). Đã sửa script.
2. `netdev device tap0 -> lo` **không bị phát hiện**. Đây là **phát hiện thật**: `nft 1.0.2` **bỏ khóa `dev`** của chain netdev trong output `nft -j`. Bằng chứng là chain trong `raw-ruleset.json` không có `dev`, trong khi `ruleset.txt` có `device "tap0"`.
   - Khắc phục: thêm `check_netdev_device()`, đọc `nft list table netdev …` dạng văn bản và yêu cầu đúng `[['tap0']]`, kèm unit test.
   - Lần 2 báo: `ingress devices [['lo']], expected [['tap0']]`.

Các phép thử của lần 2:

- Ruleset vừa nạp khớp baseline.
- Bộ đếm `drop_out` tăng 0 → 3 (gửi UDP thật tới `10.200.0.2`), mà verify vẫn đạt; `nft reset counters` cũng không làm fail.
- **17 đột biến đều bị phát hiện**, mỗi đột biến chạy riêng trên ruleset vừa nạp lại:
  - thêm rule cuối; chèn rule đầu;
  - xóa rule `drop_public`; xóa rule `arp_in_drop`; chèn rule vào ARP output;
  - policy forward thành `accept`;
  - xóa bảng arp; xóa bảng netdev;
  - thêm base chain;
  - prio `-150` thành `-100`;
  - hook `output` thành `postrouting`;
  - device `tap0` thành `lo`;
  - cổng `8011` thành `8012`;
  - đổi MAC; thu hẹp dải private;
  - `drop` thành `accept` ở rule `drop_private`.
- Ruleset nạp khớp `expected-ruleset.json` **trong working tree** (đã được copy vào image khi build): PASS. Expected trong working tree giống hệt ứng viên vừa sinh: PASS.
- Log thô lần 2 ghi hai phép thử này bằng tên cũ `… committed expected-ruleset.json` và `committed expected == generated candidate`. Log được giữ nguyên làm bằng chứng lịch sử, nhưng tên cũ **không đúng**: lúc đó file chưa được commit. Từ 06B-1R, tên phép thử đã được sửa.
- Kiểm link, neighbor và route trên `tap0` thử: PASS.

**`expected-ruleset.json`:**

- sha256 `9fb32d7f7ec0e83d0440f7a9bce2e18021da6f9ee4557cfe26ac38eae8572b16`, sinh trong container kiểm thử lần 1. Lần 2 sinh lại cho kết quả giống hệt.
- Sinh từ `guest.nft` có sha256 `5892d2d7…fdce4`.
- Số rule: inet 15, arp 6, netdev 2; khớp `guest.nft`.
- **Chờ reviewer đọc nội dung.**

Ruleset đã nạp, dạng văn bản: [ruleset-loaded.txt](task06b1/ruleset-loaded.txt).

## 4. Quan sát phụ (không assert)

Trong container kiểm thử (`--network none`, không privileged, chưa chạy `run.sh`), giá trị mặc định là:

| sysctl | Giá trị |
|---|---|
| `net.ipv4.ip_forward` | `1` |
| `net.ipv4.conf.tap0.arp_ignore` | `0` |
| `net.ipv4.conf.tap0.arp_announce` | `0` |
| `net.ipv4.conf.tap0.rp_filter` | `2` |
| `net.ipv6.conf.tap0.disable_ipv6` | `0` |

Điều này **ủng hộ giả định A1**: netns của container kế thừa `ip_forward=1` từ host, nên `run.sh` bắt buộc phải tự đặt về 0. Việc `run.sh` đặt được các giá trị này **chưa được kiểm chứng**, vì `/proc/sys` chỉ đọc khi không có `--privileged`; sẽ kiểm ở 06B-2 (V0 trong worker thật).

## 5. Hạn chế

- Chưa chạy `run.sh` thật. V0 đầy đủ (sysctl và `eth0`) chưa chạy trong worker.
- Chưa boot guest. T01–T21 và F1–F6 chưa thực hiện. **CT-01 chưa đạt.**
- Unit test chạy trên Python 3.12 của host, trong khi image dùng Python 3.10.
- Kiểm thử nft có thể khiến kernel host tự nạp module `nft_*`. Việc này không được đo.
