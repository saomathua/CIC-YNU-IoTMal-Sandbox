# Minh chứng Nhiệm vụ 06B-3B: ma trận chặn IPv4 có đối chứng, ARM rồi MIPS (06/10/2026)

**Bối cảnh:**

- Reviewer đã chấp nhận 06B-3A.
- Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), chưa commit. Working tree trước và sau nhiệm vụ đều khớp tree `7232d94b72f2f575a36d002e0b6222d00960b601` (bàn giao 06B-3A).
- **Không sửa source.** Không sửa firewall, sysctl, mạng hay AppArmor của host.

**Phạm vi:** từ guest thật (ARM rồi MIPS, tuần tự), gửi probe IPv4 tới các đích cố định bị cấm. Mỗi probe có một đối chứng **cùng IP/giao thức/cổng**, chạy cùng lúc từ một vị trí được phép tới đích đó.

- `server.py` thật; poller là sentinel.
- Chỉ dùng công cụ có sẵn trong image OS của guest (`curl`, `nslookup`). Không có ELF, mẫu hay netprobe.
- Manager có sẵn chỉ được bật để làm đối chứng, bằng `docker compose up -d --no-deps --no-build sandbox-manager`, và bị dừng lại khi xong. **Không bật service worker của Compose.**

## Harness

Bản lưu: [`task06b3b/harness/`](task06b3b/harness/). Mỗi lần chạy còn có bản sao harness riêng tại `runN/harness-copy/` và hash tại `runN/harness-sha256.txt`.

| File | Lần 5 (bản cuối) | Ghi chú |
|---|---|---|
| `run-06b3b.sh` | `f43ec3c4340a36ce8553a2982236bc5ab672db0a5999d1b85f19e00964f41e49` | lần 1 `478298ca…`, lần 2 `347ef90c…`, lần 3 `80d23230…`, lần 4 `d25995ed…` |
| `probe_matrix.py` | `4d7391d8e2e305652485693b5416f7738dbd8a638fc1ba97228b4abac13de457` | lần 1 `3d7b9d8d…`, lần 2–5 không đổi |
| `ctl_loop.py` | `4392b3974ca644abd4b229a40638cb32dd5d31159effb234ab06536dc7385340` | không đổi |
| `sentinel/poller.py` | `7e49a99bac3a1b5f277d0700b4250043a13fce15bbb6f5c58dd7d24d44a8ab26` | không đổi |
| `independent_check.sh` | `1f7eb4bf0f5cea05e2547ce87a2854185cacc30a588001f111e886ff5f45406e` | viết sau lần 5 để kiểm lại độc lập (§4) |

**Các thành phần:**

- **Container worker** `ct01-06b3b-guest`:
  - image `sha256:1ab784c7…9153`, kiểm khớp ID đầy đủ;
  - `run.sh` thật (V0), `server.py` thật, poller sentinel;
  - privileged như Compose; chạy trên `sandboxnet`; không publish cổng; không dùng host network;
  - sha256 của mã và image guest trong container khớp working tree.
- **Container đối chứng** `ct01-06b3b-ctl`, nối cả `sandboxnet` và `dbnet`:
  - cứ 0,5 giây kiểm `mongo 172.18.0.2:27017` (TCP connect), `worker-eth0 192.168.60.2:8011` và `manager 192.168.60.10:8011` (`GET /healthcheck` = 200);
  - ghi kết quả vào `ctl/ctl.jsonl`.
- **`probe_matrix.py`**, chạy trong container worker, dùng đúng đường mã thật: `ARCH_CONFIGS`, `Analysis._start_qemu`, `_configure_network`, `shutdown_qemu`.
- **Cổng topology**, phải đạt thì mới gửi probe:
  - `info network` được phân tích đầy đủ: bỏ mã ANSI và dòng echo; tên backend có thể chứa `-`;
  - chỉ có `nic` và `tap`, đúng một backend `tap` với `ifname=tap0`, đúng một NIC gắn tap mang MAC đã ghim;
  - interface probe trong guest phải mang MAC đã ghim (đọc từ `/sys/class/net`).
- **Capture phía host** (chỉ đọc), trên:
  - veth của worker, bridge `sandboxnet` và `ens33`;
  - một cảnh báo rò rỉ: `tcpdump -i any 'net 10.200.0.0/30'`. Có gói nào thì dừng toàn bộ (`exit 99`).
- **Không boot guest nếu capture phía host chưa chạy.** Mọi lệnh đọc pcap đều kiểm exit code, nên lỗi công cụ không bao giờ bị tính thành "0 gói".

### Tiêu chí cho mỗi probe

Cả 7 điều kiện phải đúng thì probe mới **ĐẠT**:

1. Guest thất bại: `curl` rc 7/28 và `HTTP=000`; với `nslookup` UDP thì rc ≠ 0.
2. Đối chứng cùng đích, giao thức và cổng thành công cả trước và sau probe. Với đối chứng từ xa: có lần OK trước `t0`, có lần OK sau `t1`, và không có lần lỗi nào trong cửa sổ.
3. Có gói probe trong pcap `tap0`.
4. Gói probe rơi vào đúng bộ đếm drop dự kiến.
5. Mức tăng của bộ đếm dự kiến bằng số gói pcap thuộc cùng lớp, và lớn hơn 0.
6. **Mọi** bộ đếm thay đổi trong cửa sổ đều bằng số gói pcap được phân loại theo `guest.nft`. Điều kiện này tính cả retransmission và lưu lượng nền.
7. Không có cảnh báo rò rỉ trên host.

Probe TCP dùng cổng nguồn cố định `41000+n`, để nhận ra trong pcap.

## 1. Lần 1–4: không đạt, giữ làm bằng chứng

| Lần | Kết quả | Nguyên nhân | Sửa (chỉ harness) |
|---|---|---|---|
| 1 ([log](task06b3b/run1/run.log)) | `exit=1`, 15 FAIL. Guest đã boot và probe đã gửi | (a) Ba lệnh `tcpdump -Z root -w` phía host segfault nên **không có capture phía host**; pcap rỗng, đọc lỗi (`truncated dump file`), check FAIL đúng. (b) Cảnh báo rò rỉ đếm dòng trống mà tcpdump in khi dừng (`alert.err`: `0 packets captured`). (c) Đối chứng từ xa được đọc tại `t1`, khi log chưa có bản ghi sau `t1`, nên manager/MongoDB/`eth0` bị ghi "CHƯA KIỂM CHỨNG". (d) `busybox --list` không có trên các image này, nên LAN UDP không chạy. (e) Hàm `check` luôn trả 0, nên điều kiện dừng `\|\| cap_ok=0` không bao giờ kích hoạt | (b) chỉ đếm dòng có nội dung, kèm kiểm `0 packets captured`; (c) đánh giá sau cùng, sau khi chờ 4 giây; (d) dò công cụ bằng `command -v`, thêm probe LAN TCP; (e) `check` trả 1 khi thất bại; dừng trước khi boot guest nếu capture không chạy |
| 2 ([log](task06b3b/run2/run.log)) | `exit=3`, dừng trước khi boot guest | Ghi vào `/tmp` vẫn segfault, và **không có** AppArmor DENIED. Kết luận sau lần 1 rằng AppArmor gây crash (lần 1 có một lời từ chối `dac_read_search` cùng lúc) là **sai** | tcpdump ghi ra stdout (`-w -`); thêm chẩn đoán tự động trên `lo` |
| 3 ([log](task06b3b/run3/run.log), [chẩn đoán](task06b3b/run3/hostcap/tcpdump-diag.txt)) | `exit=3`, dừng trước khi boot guest | Chẩn đoán: `-w file` và `-w -` chạy được; `-Z root -w file` và `-Z root -w -` **segfault** (rc 139); `-Z root -l` chạy được. Lỗi nằm ở tổ hợp `-Z root` + `-w` của tcpdump 4.99.4 / libpcap 1.10.4 trên host này | Bỏ `-Z root` ở ba capture pcap |
| 4 ([log](task06b3b/run4/run.log)) | `exit=3`, dừng trước khi boot guest | Capture đã chạy (veth 260 gói, bridge 522 gói), nhưng check "listening" dùng regex `^listening on`, trong khi ở chế độ `-w` tcpdump in `tcpdump: listening on`. Lỗi của harness | Regex `^(tcpdump: )?listening on `; đã thử trên file `.err` thật của lần 4 |

**Kết quả từ lần 1, không thay thế lần 5:** các probe có tap0 pcap và bộ đếm khớp đều cho kết quả drop giống lần 5. **Không có bằng chứng phía host**, nên lần 1 không được tính.

Sau mỗi lần dừng sớm, trap cleanup đã: xóa container do lần chạy tạo, dừng manager về `exited`, dừng mọi tcpdump và xóa thư mục tạm. Không có lần nào boot guest khi chưa có capture phía host.

## 2. Lần 5: ALL CHECKS PASSED, `exit=0`

Log: [`run5/run.log`](task06b3b/run5/run.log) (`c3caded6…ef45`).

**Chuẩn bị:**

- Image khớp ID đầy đủ. Manager `exited` → `running` (`192.168.60.10`), healthy.
- Container worker `0fb4035c…`: V0 đạt; `server.py` sẵn sàng; worker `eth0` = `192.168.60.2`, veth trên host là `vethce5323c`.
- Ba đối chứng từ xa đều sống trước khi bắt đầu.
- Bốn tcpdump trên host đều chạy và báo `listening`; pcap veth và bridge đã có dữ liệu.

### Topology (ARM / MIPS)

| | ARM | MIPS |
|---|---|---|
| Lệnh QEMU | `qemu-system-arm -M virt-2.9 … -device virtio-net-pci -netdev tap,id=net1,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=net1,mac=52:54:00:c7:00:02 …` | `qemu-system-mips -M malta … -device pcnet,netdev=net0,mac=52:54:00:c7:00:02 -netdev tap,id=net0,ifname=tap0,script=no,downscript=no` |
| `info network` | `virtio-net-pci.0`: `nic`, không có backend; `virtio-net-pci.1`: `nic` → `tap` | `pcnet.0`: `nic` → `tap` |
| Cổng topology | đạt, `problems: []` | đạt, `problems: []` |
| Interface probe / MAC | `eth1` / `52:54:00:c7:00:02` | `br-lan` / `52:54:00:c7:00:02` |
| Công cụ trong guest | `nslookup`, `nc`, `wget`, `ping`; không có `arping` | như ARM |
| Liên kết dịch vụ **trước** và **sau** probe | `GET get-task/T/file` 200, hash khớp (`602ec43c…`) | 200, hash khớp (`b13ee440…`) |

### Ma trận chặn

Cột "gói" là số gói probe guest gửi (ARM / MIPS). Vì đích không trả lời, đây là SYN cùng các lần retransmission, hoặc các truy vấn DNS lặp lại.

| Probe | Đích | Đối chứng (cùng IP/giao thức/cổng) | Bộ đếm dự kiến | Gói ARM / MIPS | Bộ đếm = pcap | Kết quả |
|---|---|---|---|---|---|---|
| Internet | `1.1.1.1:443/tcp` | TCP connect từ worker | `drop_public` | 3 / 4 | 7=7 / 8=8 (gồm DNS nền tới `8.8.8.8`) | **ĐẠT / ĐẠT** |
| LAN DNS UDP | `192.168.177.2:53/udp` | truy vấn DNS UDP từ worker (`ct01-06b3b-ctl-<arch>.example` → NXDOMAIN) | `drop_private` | 4 / 4 | 4=4 / 4=4 | **ĐẠT / ĐẠT** |
| LAN DNS TCP | `192.168.177.2:53/tcp` | TCP connect từ worker | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| SSH host | `192.168.60.1:22` | banner `SSH-` từ worker | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| SSH host | `192.168.177.128:22` | banner `SSH-` từ worker | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| SSH host | `172.18.0.1:22` | banner `SSH-` từ worker | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| Manager | `192.168.60.10:8011` | `GET /healthcheck` 200 từ worker **và** từ container đối chứng | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| MongoDB | `172.18.0.2:27017` | TCP connect từ container đối chứng (trên `dbnet`) | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| IP `eth0` của worker | `192.168.60.2:8011` | `GET /healthcheck` 200 từ container đối chứng | `drop_private` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |
| `10.200.0.1`, cổng khác | `10.200.0.1:18080` (listener tạm) | listener trả lời cục bộ trong worker | `drop_worker_other` | 3 / 4 | 3=3 / 4=4 | **ĐẠT / ĐẠT** |

- **20/20 probe ĐẠT; mỗi kiến trúc 24/24 check.** Ma trận đầy đủ: [ARM](task06b3b/run5/container/probe/ARM/matrix.md), [MIPS](task06b3b/run5/container/probe/MIPS/matrix.md); dạng JSON có thêm mọi delta bộ đếm và phân loại pcap.
- Ở mọi probe, mọi bộ đếm thay đổi trong cửa sổ đều bằng số gói pcap được phân loại. Lưu lượng nền gồm DHCP (`drop_spoof`), IPv6 (`l2_bad_ethertype`), DNS tới `8.8.8.8` (`drop_public`) và ARP tới `10.200.0.1` (`arp_in_ok`/`arp_out_ok`). Không có `mismatch` nào.
- Sau từng kiến trúc:
  - QEMU được xác nhận đã thoát (`exitstatus=0`);
  - tshark dừng sạch, listener tạm dừng;
  - fixture, marker và đĩa tạm đã bị xóa;
  - verify đầy đủ đạt.
- Ruleset tại runtime giống hệt expected.

### Phía host: không có gói probe nào thoát ra

> **Ghi chú phạm vi (06B-3DR, 07/10/2026):** câu trên cần đọc là "không thấy gói probe nào trong các pcap đã lưu phía host, và cảnh báo `-i any` bắt 0 gói". Ở lần 5 này, thống kê tcpdump có "captured" bằng "received by filter" trên cả ba capture; ý nghĩa của các thống kê đó với backend đang dùng chưa được xác minh (xem [`task06b3d-summary.md`](task06b3d-summary.md) §4).

| Capture | Tổng gói | Gói mang dấu hiệu guest (MAC `52:54:00:c7:00:02`, `10.200.0.0/30`) | Gói đối chứng (chứng minh capture đang sống) |
|---|---|---|---|
| Cảnh báo `-i any 'net 10.200.0.0/30'` | **0** (`0 packets captured`) | 0 | — |
| veth worker `vethce5323c` | 3813 | **0** | 122 gói đối chứng từ worker |
| bridge `br-1d86fe3e8bbe` | 7342 | **0** | 1604 gói từ worker |
| `ens33` (có bộ lọc) | 90 | **0** | 90 gói đối chứng đã NAT tới `1.1.1.1` / `192.168.177.2` |

**Vì sao veth là đủ:** container worker chỉ được gắn **một** mạng Docker (`docker run --network sandboxnet`, không có `network connect`). Vì vậy mọi gói rời netns của worker ra phía host, kể cả gói tới MongoDB trên `dbnet`, đều phải đi qua veth này. **Hạn chế:** lần 5 không ghi lại danh sách interface trong netns của worker. Điều này được suy ra từ lệnh chạy container, không phải từ một bản ghi `ip link`.

### Đối chứng từ xa

Nguồn: [`ctl/ctl.jsonl`](task06b3b/run5/ctl/ctl.jsonl).

- Mỗi đích có 325 lần kiểm, khoảng cách lớn nhất giữa hai lần OK là 0,51 giây.
- Chỉ có **1** lần lỗi: `mongo` lúc 15:24:32, là lần kiểm đầu tiên, trước `docker network connect dbnet`. Lần này cách probe đầu tiên hơn 2 phút.
- Không có lỗi nào trong cửa sổ của bất kỳ probe nào.

### Kết thúc và trạng thái host

- Đã xóa hai container do lần chạy tạo (`0fb4035c…`, `ad863809…`).
- **Manager:** trước `exited` → bật lúc 15:24:28 → dừng lúc 15:27:22 → `exited`, đúng trạng thái trước. `mongo-db` không bị động tới.
- Không còn QEMU hay tiến trình capture trên host; thư mục capture tạm đã bị xóa.
- **Mọi khác biệt của host đều được báo cáo**, không loại trừ IPv6 link-local:
  - không đổi: `ip-addr`, `ip-link`, `ip-route`, `ip6-route`, `listen-tcp`, `lsmod-net`, `nft-ruleset-stateless`, `sysctl`, `qemu`, `capture-procs`, `host-tap0`;
  - đổi: chỉ `docker-ps`, gồm chuỗi thời gian ("Exited (0) About a minute ago" → "2 seconds ago"; uptime của mongo). Đây là hệ quả của việc bật/dừng manager.

## 3. Hạn chế của harness lần 5

- Capture pcap phía host chạy với quyền root, không hạ quyền, do lỗi `-Z root` + `-w` của tcpdump trên host. Lệnh cảnh báo vẫn hạ quyền (`-Z root -l`).
- `ens33` chỉ được capture với bộ lọc (MAC guest, `10.200.0.0/30`, `1.1.1.1`, LAN DNS). Bridge `dbnet` không được capture riêng; lý do veth là đủ đã nêu ở trên.
- Danh sách interface trong netns của worker không được ghi lại.
- Phân loại pcap theo `guest.nft` là của harness (`classify()`). Kiểm tra độc lập ở §4 xác nhận số gói theo từng probe, không kiểm lại toàn bộ phép phân loại.
- Bảng ở §2 ghi "ĐẠT" theo tiêu chí của 06B-3B. Mức phủ so với ma trận thiết kế ghi ở §5.

## 4. Kiểm tra độc lập sau lần 5

Script [`harness/independent_check.sh`](task06b3b/harness/independent_check.sh) chỉ dùng tcpdump của host, không dùng tshark hay bộ phân loại của harness, và không cần root. Output: [`run5/independent-check.txt`](task06b3b/run5/independent-check.txt) (`03e9064b…3266`).

- **`tap0`:**
  - mỗi probe TCP có đúng 3 (ARM) / 4 (MIPS) gói từ đúng cổng nguồn `41000+n`, và 0 gói từ cổng khác tới cùng đích;
  - probe UDP có 4 gói;
  - **0 gói trả về guest** từ mọi đích;
  - 0 gói IPv4 tới guest từ nguồn khác `10.200.0.1`;
  - tên DNS probe `ct01-06b3b-probe-<arch>-1` **có** trong pcap.
- **Host (veth, bridge, `ens33`):** 0 gói theo mọi dấu hiệu sau: MAC guest, `10.200.0.0/30`, ARP cho `10.200.0.2`, cổng nguồn probe `41000–41020`, tên DNS probe và đường dẫn URL probe `/ct01-06b3b-<pid>`.
  - Có 12 dòng khớp `ct01-06b3b-ctl-<arch>.example`. Đây là truy vấn DNS **đối chứng** từ worker, có nguồn NAT `192.168.177.128`; không phải gói của guest.
- **Log đối chứng:** khớp với §2.

## 5. Đối chiếu với ma trận thiết kế ([`network-isolation-design.md`](../network-isolation-design.md))

| Mã | Nội dung thiết kế | 06B-3B đã phủ | Còn thiếu |
|---|---|---|---|
| T05 | `1.1.1.1:443` TCP; `8.8.8.8:53` UDP | `1.1.1.1:443` TCP có đối chứng | `8.8.8.8:53` UDP mới chỉ là lưu lượng nền, chưa có probe kèm đối chứng |
| T06 | `192.168.177.2` (ICMP, TCP 53), một IP LAN khác | TCP 53 và UDP 53 có đối chứng | ICMP; IP LAN thứ hai |
| T07 | SSH host trên 3 IP | cả 3 IP, đối chứng là banner `SSH-` | chưa đối chiếu `journalctl -u ssh` |
| T08 | Manager `:8011` | có đối chứng từ worker và từ container đối chứng | chưa đối chiếu log manager |
| T09 | MongoDB `:27017` | có đối chứng TCP connect từ `dbnet` | đối chứng là TCP connect, không phải `mongosh ping` |
| T10 | IP `eth0` của worker `:8011` | có đối chứng | — |
| T11 | `10.200.0.1` cổng 22, 80; ICMP | cổng 18080 với listener tạm, theo phạm vi 06B-3B | cổng 22, 80; ICMP |
| T12–T17, T20 | broadcast/multicast, IPv6, ARP, ARP spoof, đổi MAC, giả IP nguồn, inbound | — | toàn bộ |

## 6. Chưa kiểm chứng (ngoài phạm vi 06B-3B)

- ARP spoof, đổi MAC trong guest, IPv6 có đối chứng (mới chỉ quan sát IPv6 nền bị `l2_bad_ethertype` drop).
- Kết nối vào guest (inbound) từ worker, manager, host hay LAN.
- Fail-closed khi chạy: mất luật trong lúc guest chạy, V1/V2 trong luồng phân tích thật.
- ICMP: chưa probe, dù guest có `ping`.
- Mỗi lớp mới thử một đích: Internet = `1.1.1.1:443`; LAN = DNS của VMware NAT `192.168.177.2:53`.
- Worker vẫn privileged. Bảng nft ngoài ba bảng CT-01 không được kiểm.
- **CT-01 vẫn chưa đạt.**
