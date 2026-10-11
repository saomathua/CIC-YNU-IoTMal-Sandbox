# Minh chứng Nhiệm vụ 06B-3A: boot guest ARM/MIPS và kiểm tra liên kết dịch vụ (06/10/2026)

**Bối cảnh:**

- Người dùng đã tạo snapshot và bật lại VM (host khởi động lúc 14:28 UTC).
- Reviewer đã chấp nhận 06B-2BR ở mức trước guest.
- Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), chưa commit. Working tree trước khi chạy khớp tree `7b838dad666fa14a5025786b1f8fb8fc2aec3521` (bàn giao 06B-2BR).
- **Không sửa source** trong nhiệm vụ này.

**Phạm vi:** boot guest thật (ARM rồi MIPS, tuần tự), chỉ kiểm liên kết từ guest tới dịch vụ worker `10.200.0.1:8011`.

- `server.py` thật; poller là sentinel.
- Không có `dynamic_analysis`, ELF hay mẫu, không có netprobe.
- **Chưa** thử Internet, LAN, SSH hay MongoDB.
- Không bật manager, không đổi host.

## Harness

Bản lưu trong repo là phiên bản lần chạy 2: [`task06b3a/harness/`](task06b3a/harness/).

| File | Lần 1 | Lần 2 |
|---|---|---|
| `run-06b3a.sh` | `c8f7f0d6…f575` | `58bfb13d585b2f625707af054256e708b7f954f6ea2a900197c01433bf66da42` |
| `guest_probe.py` | `9f035d9f…603f` | `02e6bf68aedfe4a686b99953b30bf4747548d5e5c8977842fe89cd70e2c409d6` |
| `sentinel/poller.py` | `7e49a99b…ab26` | không đổi |

Harness lần 1 bị sửa tại chỗ nên không còn bản sao riêng. Hash của nó được ghi trong `run1/harness-sha256.txt`, và các thay đổi được mô tả ở mục 1.

**Cách hoạt động:**

- **Container:** image `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153` (kiểm khớp đầy đủ); `sandboxnet`; privileged như Compose; `--restart no`; không publish cổng; không dùng host network; không mount dữ liệu lab hay `docker.sock`.
- **Kiểm tra trong container:** sha256 của mã và `ARM/image.zip`, `MIPS/image.zip` khớp working tree; cleanup chỉ xóa ID do lần chạy tạo; mọi tiêu chí là kiểm tra bắt buộc.
- **`guest_probe.py`** dùng đúng đường mã thật: `ARCH_CONFIGS`, `Analysis._start_qemu` (MAC đã ghim, `tap0`), `Analysis._configure_network`, `shutdown_qemu`.
- Mỗi kiến trúc được giải nén `image.zip` gốc vào `/tmp/g-<ARCH>` riêng, và đĩa tạm bị xóa sau khi xong.
- **Verify đầy đủ chạy ngay trước khi spawn QEMU. Đây là kiểm tra trước boot của harness, KHÔNG phải V1/V2 của luồng phân tích thật.**
- Deadline mỗi kiến trúc 900 giây. Trong `finally`: `shutdown_qemu` (xác nhận đã thoát), dừng tshark, xóa đĩa tạm, fixture và marker.
- Fixture là file văn bản vô hại. File upload do guest tự tạo bằng `printf`. Request từ guest dùng `curl` có sẵn trong image OS.

## 1. Lần chạy 1: `exit=1` (3 tiêu chí FAIL), giữ làm bằng chứng

Log: [`run1/run.log`](task06b3a/run1/run.log) (`180c7c55…fda2`).

| Tiêu chí FAIL | Nguyên nhân (có bằng chứng) | Loại |
|---|---|---|
| ARM, MIPS: hash file tải về | Console nối tiếp kết thúc dòng bằng `\r\r\n` (`cat -A`: `^M^M$`). Parser tìm `@@B13\r\n` nên trả về cả dòng lệnh echo (`"guest": "echo"`). Console cho thấy guest **đã in đúng** hash: ARM `d9d5786a…656e`, MIPS `4108f5ea…3e38`, bằng sha256 của fixture. Check lần này **vẫn tính FAIL**, vì hash chỉ được đối chiếu sau khi chạy | Lỗi parser của harness |
| MIPS: 3 POST trả `status 0` | `curl -F file=@/etc/hostname` → `HTTP=000`, `rc=26`: image MIPS không có `/etc/hostname`, **request không được gửi**. Bộ đếm khớp: `allow_svc` của nhóm 1 MIPS = 7, tức chỉ có một GET | Lỗi harness |
| `ip-addr` của host đổi | Bridge `sandboxnet` có thêm IPv6 link-local sau khi host khởi động lại, đúng như hiện tượng đã ghi ở 06B-2A | Thay đổi do Docker/kernel; harness lúc đó coi mọi thay đổi là FAIL |

**Sửa harness, không sửa source:**

1. Bỏ `\r` trước khi tìm marker; không thấy marker thì ném lỗi.
2. Guest tạo `/tmp/up_dummy` bằng `printf` để upload. Thêm kiểm tra bắt buộc: curl phải `exit 0` và có mã HTTP.
3. `ip-addr` của host chỉ chấp nhận đúng việc thêm IPv6 link-local trên `br-<sandboxnet>`; mọi khác biệt khác vẫn FAIL.

Lần 1 không có thất bại nào liên quan tới cô lập: các tiêu chí topology, 403, upload và khớp bộ đếm/pcap đều PASS.

## 2. Lần chạy 2: ALL CHECKS PASSED, `exit=0`

Log: [`run2/run.log`](task06b3a/run2/run.log) (`748bba98…df61`).

**Startup:**

- V0 đạt lúc `14:39:39.441`, trước poller sentinel (`.457`) và trước khi uvicorn khởi động (`.791`).
- `/healthcheck` trả 200.
- Mã và guest image trong container khớp working tree.

### Topology (mục 3 của nhiệm vụ)

| | ARM | MIPS |
|---|---|---|
| Lệnh QEMU ([ARM](task06b3a/run2/container/probe/ARM/qemu-command.txt), [MIPS](task06b3a/run2/container/probe/MIPS/qemu-command.txt)) | `qemu-system-arm -M virt-2.9 … -device virtio-net-pci -netdev tap,id=net1,ifname=tap0,… -device virtio-net-pci,netdev=net1,mac=52:54:00:c7:00:02 …` | `qemu-system-mips -M malta … -device pcnet,netdev=net0,mac=52:54:00:c7:00:02 -netdev tap,id=net0,ifname=tap0,…` |
| Boot tới shell | 6,0 s | 11,8 s |
| `info network` | `virtio-net-pci.0` (MAC `52:54:00:12:34:56`, **không có backend**); `virtio-net-pci.1` (MAC `52:54:00:c7:00:02`) → `net1: type=tap,ifname=tap0` | `pcnet.0` (MAC `52:54:00:c7:00:02`) → `net0: type=tap,ifname=tap0` |
| Backend | chỉ `nic` và `tap`; **không có user/slirp/socket** | chỉ `nic` và `tap`; **không có user/slirp/socket** |
| Interface trong guest mang `10.200.0.2/30` | `eth1` (MAC đã ghim) | `br-lan` (cùng MAC với `eth0`, MAC đã ghim) |
| Default route | `via 10.200.0.1 dev eth1` | `via 10.200.0.1 dev br-lan` |

**Quan sát, không phải backend ngoài thiết kế:**

- ARM có NIC thứ nhất `virtio-net-pci.0` **không gắn backend** (theo `ARCH_CONFIGS` gốc của CIC); trong guest, NIC này là `eth0`/`br-lan`.
- MIPS có interface `hwsim0` (mac80211_hwsim của OpenWrt), không có backend QEMU.
- Không thấy đường mạng phụ nào ngoài `tap0`, nên harness tiếp tục gửi probe.

### Liên kết dịch vụ từ guest thật

ARM và MIPS đều **37/37** check đạt.

| Nhóm | Kết quả (ARM / MIPS) |
|---|---|
| 1. Không có `current_task`: GET file, POST strace, POST sar | 403 / 403 cả ba; không có gì được ghi |
| 2. GET `get-task/T/file` | 200 / 200. Hash **tính trong guest** = fixture: ARM `d9d5786a…656e`, MIPS `4108f5ea…3e38` |
| 3. POST `update-task/T/strace`, `/sar` | 200 / 200. File nhận được: ARM `e4d8c2c7…c611`, `91a0d0c7…2401`; MIPS `02603db7…031c`, `5e5db3cd…0b57`; đều khớp payload |
| 4. `/healthcheck`, `POST /stop`, GET file task khác, POST strace task khác | 403 / 403 cả bốn; không có file stop; không có task mới; task khác không bị ghi |
| 5. Sau khi xóa `current_task`: GET file | 403 / 403 |

### Bằng chứng lưu lượng thực sự đi qua `tap0`

| Nhóm | `allow_svc` = gói guest→`10.200.0.1:8011` trong pcap (ARM / MIPS) |
|---|---|
| 1 | 22 = 22 / 21 = 21 |
| 2 | 7 = 7 / 7 = 7 |
| 3 | 16 = 16 / 14 = 14 |
| 4 | 28 = 28 / 28 = 28 |
| 5 | 7 = 7 / 7 = 7 |
| **Toàn bộ capture** | **80 / 77**, khớp tổng bộ đếm |

Không có gói IPv4 nào gửi tới guest với nguồn khác `10.200.0.1`. Chi tiết: [`run2/pcap-guest-background.txt`](task06b3a/run2/pcap-guest-background.txt); pcap: [ARM](task06b3a/run2/container/probe/ARM/tap0.pcap) (`bf14c6d6…a723`), [MIPS](task06b3a/run2/container/probe/MIPS/tap0.pcap) (`4dcd677b…5a78`).

**Lưu lượng nền guest tự phát sinh** (chỉ là quan sát, **chưa** phải phép thử chặn có đối chứng):

| Loại | ARM | MIPS | Bộ đếm drop tăng tương ứng |
|---|---|---|---|
| DHCP `0.0.0.0 → 255.255.255.255:67` | 3 | 2 | `drop_spoof` |
| DNS `10.200.0.2 → 8.8.8.8:53` (resolv do `_configure_network` đặt) | 4 | 6 | `drop_public` |
| IPv6 (`0x86dd`) | 9 | 7 | `l2_bad_ethertype` |
| ARP who-has `10.200.0.1` | 1 | 1 | `arp_in_ok`; worker trả lời (`arp_out_ok`) |

### Kết thúc

- Sau mỗi kiến trúc: QEMU được xác nhận đã thoát (`exitstatus=0`); tshark dừng; không còn `qemu-system` hay tshark trong container hay trên host; verify đầy đủ đạt.
- Hai kiến trúc chạy **tuần tự**: trước khi bắt đầu MIPS đã kiểm không có QEMU.
- Cuối cùng: không còn marker, fixture, file stop hay đĩa tạm. Ruleset tại runtime giống hệt expected. Container `06da2be2…` đã bị xóa.
- **Host:** sysctl, ruleset nft, route, cổng, QEMU, tshark, module và `ip-addr` đều không đổi. IPv6 link-local trên bridge đã có từ lần 1 nên không còn khác biệt.

## 3. Hạn chế

- Kiểm tra verify trước boot là của **harness**; **V1/V2 trong luồng phân tích thật chưa chạy**.
- Chỉ kiểm liên kết tới `10.200.0.1:8011`. **Chưa** có ma trận chặn (Internet, LAN, SSH, MongoDB, manager, IP `eth0`, ARP spoof, đổi MAC, IPv6) **có đối chứng**.
- Lưu lượng nền bị drop mới chỉ là quan sát.
- Chưa chạy netprobe hay ELF nào.
- **CT-01 vẫn chưa đạt.**
