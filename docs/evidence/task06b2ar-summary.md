# Minh chứng Nhiệm vụ 06B-2AR: sysctl hiệu lực trước khi thử guest (06/10/2026)

**Bối cảnh:**

- Reviewer quyết định giữ `rp_filter` **strict** trên `tap0` theo thiết kế.
- Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), chưa commit.
- Mốc trước đợt sửa: tree `4864457ddb17f0001b31a65da4915cee6b25a63f` (trạng thái sau 06B-2A).
- Evidence thô của 06B-2A giữ nguyên.

**Không** chạy server/poller thật, QEMU hay mẫu nào. Không đổi sysctl, firewall hay mạng của host. Sysctl chỉ được đổi trong netns của container kiểm thử.

## 1. Cách kernel kết hợp giá trị

Nguồn: `include/linux/inetdevice.h` của Linux **v6.8** (GitHub `torvalds/linux`, tag `v6.8`, sha256 file `a0ea83025eb317a1260eba2fe40a3ab7bf9d36938a3b47f03db6371d351e757e`).

| Biến | Macro (dòng) | Giá trị hiệu lực |
|---|---|---|
| `rp_filter` | `IN_DEV_MAXCONF(RP_FILTER)` (101) | `max(all, dev)` |
| `arp_accept` | `IN_DEV_MAXCONF(ARP_ACCEPT)` (134) | `max(all, dev)` |
| `arp_announce` | `IN_DEV_MAXCONF(ARP_ANNOUNCE)` (135) | `max(all, dev)` |
| `arp_ignore` | `IN_DEV_MAXCONF(ARP_IGNORE)` (136) | `max(all, dev)` |
| `forwarding` | `IN_DEV_FORWARD = IN_DEV_CONF_GET(FORWARDING)` | chỉ giá trị của dev |
| `default` | — | chỉ là giá trị khởi tạo cho interface mới |

Đây là mã upstream; bản vá riêng của Ubuntu `6.8.0-146` chưa được đối chiếu. Giá trị thực tế quan sát được trong container (mục 3) nhất quán với công thức trên.

## 2. Thay đổi

| File | Thay đổi |
|---|---|
| `sandbox-worker/isolation/verify.py` | `KERNEL_COMBINE`, `effective()`, `sysctl_report()`, CLI `--sysctl-report`. Kiểm giá trị cấu hình (`ip_forward=0`, `all.rp_filter=1`, `tap0.{rp_filter=1, arp_ignore=1, arp_announce=2, arp_accept=0, forwarding=0}`) **và** giá trị hiệu lực trên `tap0` (`rp_filter=1`, `arp_ignore=1`, `arp_announce=2`, `arp_accept=0`, `forwarding=0`) |
| `sandbox-worker/run.sh` | Báo cáo sysctl trước khi đổi. Sau `ip_forward=0`: `all.rp_filter=1`, `all.arp_ignore=0`, `all.arp_accept=0`. Báo cáo sysctl sau khi đổi, rồi V0 |
| `sandbox-worker/tests/test_verify.py` | Test hồi quy `all.rp_filter=2` + `tap0=1` → fail. `tap0.rp_filter=0` → fail. `all.arp_ignore` 2 hoặc 8 → fail. `all.arp_accept` 1 hoặc 2 → fail. `arp_announce` hiệu lực = 2 với mọi `all` ∈ {0,1,2}. `forwarding` lấy theo dev. Báo cáo có cả giá trị cấu hình và hiệu lực |
| `docs/network-isolation-design.md` | Thêm mục §4.2a; sửa bảng kiểm sysctl ở §6.1 |
| Harness `ct01-06b2ar/run-06b2ar.sh` (bản lưu ở [`task06b2ar/harness/`](task06b2ar/harness/)) | Sửa ba điểm review (mục 5) |

Bản cũ `tap0.rp_filter=1` vẫn giữ. Bảng nft `arp` và neighbor `PERMANENT` giữ nguyên. **`arp_accept=0` không được coi là đủ** để chống thay đổi neighbor.

## 3. Kết quả

**Do người dùng chạy (sudo):**

| Bước | Lệnh | Kết quả |
|---|---|---|
| Build | `sudo docker compose --progress plain build sandbox-worker-1` | `exit=0`; image `sha256:d0bf9277e7c485823ff5a3b8f5ead6c038ef03c5c9fc72fcd0040799403e6f42` ([build.log](task06b2ar/build.log)) |
| Unit test trong image | `docker run --rm --network none … /run-unit-py310.sh` | **130 passed**, Python 3.10.12 ([log](task06b2ar/unit-tests-py310.txt)) |
| Harness | `sudo bash run-06b2ar.sh <ID đầy đủ lấy từ build.log>` | **ALL CHECKS PASSED**, `exit=0` ([run.log](task06b2ar/run.log)) |

**Do Claude chạy:**

- Unit test trên host, Python 3.12: **130 passed** ([log](task06b2ar/unit-tests-py312.txt)).
- Kiểm tra đối chứng: phá mã 5 kiểu, lần nào cũng có test thất bại:

| Đột biến | Test thất bại |
|---|---|
| Hiệu lực = giá trị `tap0` (hành vi của 06B-2A) | 5 |
| Bỏ kiểm giá trị hiệu lực | 5 |
| Không yêu cầu `all.rp_filter=1` | 1 |
| Coi `arp_accept` là theo dev | 2 |
| Chấp nhận `rp_filter` loose | 10 |

- Test harness bằng `docker` giả: image ID sai hoặc có sẵn container trùng tên đều dẫn tới exit 3, **0** lệnh `docker run`/`rm`. Tham số image ID sai định dạng dẫn tới exit 2.

**sysctl trong netns worker** (log startup, báo cáo "before run.sh" và "after run.sh"):

| Biến | Trước (cấu hình all/default/eth0) | Sau (cấu hình all/default/tap0/eth0) | Hiệu lực sau: `tap0` / `eth0` |
|---|---|---|---|
| `ip_forward` | 1 | 0 | — |
| `rp_filter` | 2 / 2 / 2 | **1** / 2 / 1 / 2 | **1** / 2 |
| `arp_ignore` | 0 / 0 / 0 | 0 / 0 / 1 / 0 | **1** / 0 |
| `arp_announce` | 0 / 0 / 0 | 0 / 0 / 2 / 0 | **2** / 0 |
| `arp_accept` | 0 / 0 / 0 | 0 / 0 / 0 / 0 | **0** / 0 |
| `forwarding` | 1 / 1 / 1 | 0 / 0 / 0 / 0 | **0** / 0 |

**Tác động lên `eth0`** (đối chiếu trước/sau, cùng một netns):

- `rp_filter` hiệu lực của `eth0` **không đổi** (2 → 2), vì `max(1, 2) = 2`.
- Các biến `arp_*` không đổi.
- `forwarding` của `eth0` **đổi 1 → 0**. Nguyên nhân là `ip_forward=0` (đã có từ 06B-1), không phải đợt sửa này.
- Ở lần chạy này `conf.all.arp_ignore` và `conf.all.arp_accept` vốn đã bằng 0, nên bước chuẩn hóa không làm thay đổi gì.

**Các kiểm tra bắt buộc khác (đều PASS):**

- V0 đạt (`13:40:00.556017Z`) **trước** cả hai sentinel (`.572791Z`, `.572915Z`); không có `ISOLATION FAIL`.
- Verify chạy lại trong container đang sống: `exit 0`.
- Ruleset tại runtime giống hệt expected trong working tree.
- sha256 của `run.sh` và các file isolation trong image khớp working tree (`run.sh` `d0a22a19…23f9`, `verify.py` `8c900ae5…5f1a`; `guest.nft`, `load.nft`, `expected-ruleset.json`, `constants.py` không đổi).
- Không có QEMU hay tshark; sentinel được mount thay server/poller.
- `eth0` trên `sandboxnet` (`192.168.60.2`, IPAM cấp); `tap0` không có master; không có bridge.
- Teardown: stop và rm exit 0; container đã xóa; SandboxKey không còn; trên host không có `tap0`.
- `ALLOW_VM_INTERNET=true` và `guest.nft` lỗi cú pháp: exit **đúng 1**, không có marker sentinel, 0 lần restart, không có QEMU, container đã xóa.
- Mọi container do lần chạy này tạo đều đã bị xóa (3 ID trong [`created-ids.txt`](task06b2ar/created-ids.txt)); `mongo-db` và manager có sẵn từ trước không bị đụng.

**Host trước/sau: không đổi gì** (sysctl `all`/`default`/`ens33` cho cả 5 biến và `ip_forward`; ruleset nft; route IPv4/IPv6; địa chỉ; module; cổng; danh sách container; network). Module `nft_ct` và địa chỉ IPv6 link-local trên bridge `sandboxnet` đã có từ 06B-2A.

**Bảng ngoài CT-01** trong netns: vẫn chỉ có `table ip nat` của Docker (DNS nhúng).

## 4. Hạn chế

- Công thức kết hợp lấy từ mã upstream v6.8. Hành vi định tuyến thật với `rp_filter` strict (gói giả mạo bị kernel loại) **chưa được thử**, vì chưa có guest.
- Giá trị hiệu lực do `verify` tính dựa trên công thức trên. Một thay đổi trong cách kernel kết hợp sẽ không bị phát hiện tự động.
- **CT-01 vẫn chưa đạt:** chưa có guest, HTTP thật, V1/V2 trong luồng thật, hay T01–T21/F1–F6.

## 5. Harness: sửa theo review

| Điểm | 06B-2A | 06B-2AR |
|---|---|---|
| Cleanup | Xóa theo **tên**; trap được cài trước kiểm tra trùng tên, nên có thể xóa container có sẵn | Chỉ xóa các **ID do chính lần chạy tạo** (`CREATED_IDS`, không qua subshell); thu `docker logs` trước khi xóa; container trùng tên có sẵn → ABORT và giữ nguyên |
| Image | Chỉ so prefix; khác thì in WARNING rồi chạy tiếp | Bắt buộc ID đầy đủ làm tham số (lấy từ `exporting manifest list` của build 06B-2AR); khác → ABORT exit 3 |
| Kết quả | Luôn `exit 0` | Mọi tiêu chí là kiểm tra bắt buộc; còn bất kỳ FAIL nào → `exit 1` |
