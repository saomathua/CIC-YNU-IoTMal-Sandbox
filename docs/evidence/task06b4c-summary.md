# Minh chứng Nhiệm vụ 06B-4C: kiểm tích hợp harness 06B-4BR trên môi trường thật (08/10/2026)

> **Loại bằng chứng: tích hợp thật.** Dùng Docker thật, worker và manager thật, guest ARM/MIPS thật, capture thật trên `tap0` và phía host. Mục tiêu là kiểm **phần capture và bộ quét mới** (06B-4B/4BR) với **đúng 20 probe IPv4 hiện có**. Chưa thêm probe L2/ARP/IPv6 nào. Bằng chứng offline của harness: [`task06b4b-summary.md`](task06b4b-summary.md), [`task06b4br-summary.md`](task06b4br-summary.md).

**Phạm vi:**

- Chạy **một lần**, ARM rồi MIPS tuần tự.
- Giữ nguyên 20 probe, guard 20 ms (giả định chưa đo), luật kết luận và mã thoát.
- Không sửa harness, không chạy lại, không chạy mẫu, không thêm công cụ hay probe vào guest.
- Không sửa source cô lập, firewall, sysctl hay mạng host.

**Kết quả: `exit=4` (NOT PASSED: chưa kiểm chứng).**

- **Probe: 17/20 ĐẠT, 3/20 CHƯA KIỂM CHỨNG, 0 FAIL, 0 LỖI PHÉP ĐO.**
- **Toàn phiên (báo riêng): ARM PASS, MIPS PASS.**
- **Capture và bộ quét mới hoạt động như thiết kế:**
  - 5 capture phía host, gồm `ens33` không lọc và cảnh báo Ethernet trên veth;
  - bộ quét cũ và mới đều chạy; `truncated_frames`/`unscannable_*` được báo cáo.
- Không thấy chữ ký nào trên các pcap đã lưu phía host.
- **Không phát hiện lỗi harness.**

## 1. Trước khi chạy

| Kiểm tra | Kết quả |
|---|---|
| Repo | tree `0700d55e1005cf0c977ea1588cfbf689d7e6f12f` (bàn giao 06B-4BR), HEAD `3c54d55` |
| Harness `ct01-06b4b` | 18/18 hash khớp [`task06b4br/harness-sha256.txt`](task06b4br/harness-sha256.txt). Bản sao trong lần chạy ([`run1/harness-sha256.txt`](task06b4c/run1/harness-sha256.txt)) cũng khớp từng file. Kiểm lại sau lần chạy: vẫn khớp |
| Image | `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153`: kiểm bằng sudo ([`side/precheck.txt`](task06b4c/side/precheck.txt)) và harness kiểm lại |
| Tồn đọng | không có QEMU, capture, harness hay container `ct01-06b3b-*`; `mongo-db` đang chạy |
| Manager ban đầu | `exited`, ID `494ae3d2e2eb…`, `StartedAt` `2026-10-07T16:12:39.645814307Z` |
| Output | chưa có `ct01-06b4b/out`. Lần chạy được đổi tên thành `ct01-06b4b/out-06b4c-run1` (trong `/home`); bản sao giống hệt ở [`task06b4c/run1/`](task06b4c/run1/). Console lưu ở [`side/console.txt`](task06b4c/side/console.txt) (giống hệt `run.log`) |
| Self-test trong harness (root, trước mọi thao tác container) | `SELFTEST: ALL PASSED` (205); **`SELFTEST-L2: 175/175`** ([`run1/selftest-l2.txt`](task06b4c/run1/selftest-l2.txt)) |

**Rủi ro ghi trước khi chạy** (đọc run script, không sửa):

- Vì `ens33` không còn bộ lọc (D7), khóa cũ `probe_sport` của `sigscan.sh` (dải 41000–41020, nằm trong dải cổng tạm) có thể khớp nhầm kết nối của chính host. Ở lần này nó bằng 0.
- `ens33.pcap` không lọc chứa lưu lượng khác của host, mỗi gói tối đa 512 byte:
  - TLS 443 của host;
  - SSH từ `192.168.177.1`;
  - DNS và ICMPv6 của host;
  - các đối chứng NAT.
- Không có khóa hay mật khẩu nào được in ra. pcap được giữ trong evidence như mọi lần chạy.

Lệnh (người dùng chạy): `sudo bash /home/dathq/projects/ct01-06b4b/run-06b3b.sh`, bước chuẩn bị bắt đầu 04:31:13, kết quả lúc 04:34:31 UTC.

## 2. Kết luận từng probe

Log: [`run1/run.log`](task06b4c/run1/run.log). Ma trận: [ARM](task06b4c/run1/container/probe/ARM/matrix.md), [MIPS](task06b4c/run1/container/probe/MIPS/matrix.md).

| | ARM | MIPS |
|---|---|---|
| Cổng topology, liên kết dịch vụ trước và sau | đạt | đạt |
| ĐẠT | **9/10** | **8/10** |
| CHƯA KIỂM CHỨNG | `lan-dns-tcp` (không có đối chứng sống) | `lan-dns-tcp` (không có đối chứng sống); `lan-dns-udp` (gói ở biên) |
| FAIL / LỖI PHÉP ĐO | 0 / 0 | 0 / 0 |
| Check của `probe_matrix` | 26/27 | 25/27 |
| Thời gian một lần đọc nft | 4,9 – 20,1 ms, trung vị 9,5 | 4,3 – 16,8 ms, trung vị 8,4 |

### `lan-dns-tcp` (cả hai kiến trúc): đối chứng không sống

- **Đối chứng:** `192.168.177.2:53/tcp` từ worker → `ConnectionRefusedError(111)`, trước và sau probe, ở cả ARM và MIPS.
- **[KC] trên `ens33.pcap`:** kết nối đối chứng (đã NAT thành `192.168.177.128`) gửi SYN tới `192.168.177.2:53`, và gateway LAN trả **RST** sau 2–3 lần gửi lại. Có 13 khung, trong đó 4 RST và 0 SYN-ACK từ `192.168.177.2`.
  - Ở 06B-3B/3E/3G, đối chứng này sống.
  - Đây là thay đổi của **môi trường** (dịch vụ DNS TCP của gateway VMware NAT), không phải của harness.
- **Phía guest:** probe vẫn thất bại; đối chiếu bộ đếm của probe đạt (`drop_private` 3/4 khung, delta khớp).
- Theo quy tắc, không có đối chứng sống thì **không được** ghi ĐẠT. Harness ghi CHƯA KIỂM CHỨNG là đúng.

### MIPS `lan-dns-udp`: gói biên

- Lớp: `drop_public`. Delta 5 / chắc chắn 4 / tính cả biên 6.
- Hai gói DNS nền của guest (`A?` và `AAAA? 2.openwrt.pool.ntp.org` → `8.8.8.8:53`) nằm **bên trong** lần đọc B (`B = […010.774798, …010.789582]`; gói lúc `…010.787233` và `…010.788103`).
- Lớp dự kiến `drop_private` khớp chính xác.
- Chi tiết: [`side/edge-and-zone-check.txt`](task06b4c/side/edge-and-zone-check.txt). Lưu ý: dòng "−12,4 ms before B.start" trong file đó nghĩa là gói nằm **sau** `B.start`, tức bên trong lần đọc B.

**Gói của chính probe** nằm trong vùng chắc chắn ở cả 20 probe (cùng file).

## 3. Toàn phiên (báo riêng)

`session.json`: [ARM](task06b4c/run1/container/probe/ARM/session.json), [MIPS](task06b4c/run1/container/probe/MIPS/session.json).

| | ARM | MIPS |
|---|---|---|
| Kết luận | **PASS**, `reasons` rỗng | **PASS**, `reasons` rỗng |
| Quét QEMU trước boot / sau khi thoát | `[]` / `[]`, không lỗi | `[]` / `[]`, không lỗi |
| F1 / F2 | đủ, giống nhau, không lỗi đọc | đủ, giống nhau, không lỗi đọc |
| Gói guest trước cửa sổ / sau khi thoát | 0 / 0 | 0 / 0 |
| ISB `tap0` | 100/0 | 133/0 |

- Kiểm chéo độc lập: JSON nft thô khớp `session.json` ([`side/raw-reads-check.txt`](task06b4c/side/raw-reads-check.txt)).
- Tổng khung guest theo tcpdump: ARM 87 = 84 + 3 ARP; MIPS 120 = 118 + 2 ARP; khung tới guest 13 = `allow_out_svc` + `arp_out` ([`side/session-crosscheck.txt`](task06b4c/side/session-crosscheck.txt)).

## 4. Capture, heartbeat, teardown

| Capture | Cấu hình đã áp dụng [KC] | captured / received / dropped | Thoát |
|---|---|---|---|
| veth (`veth5073d55`) | không lọc | 4072 / 4072 / 0 | rc 0 |
| bridge `br-1d86fe3e8bbe` | không lọc | 7960 / 7960 / 0 | rc 0 |
| **`ens33`** | **không lọc**, `snapshot length 512 bytes` (`ens33.err`); giới hạn 200 000 gói (registry trong bản sao harness của lần chạy) | 589 / 589 / 0 | rc 0 |
| cảnh báo `any` (LINUX_SLL2) | bộ lọc từ registry ([`alert-filter-any.txt`](task06b4c/run1/hostcap/alert-filter-any.txt)) | 0 / 0 / 0 | rc 0 |
| **cảnh báo Ethernet trên veth** (`alert_eth`) | bộ lọc từ registry ([`alert-filter-eth.txt`](task06b4c/run1/hostcap/alert-filter-eth.txt)), `listening on veth5073d55, link-type EN10MB` | 0 / 0 / 0 | rc 0 |

- **`ens33`:**
  - header pcap: snaplen 512, link type Ethernet;
  - 589 khung, khung lưu dài nhất 512 byte;
  - **7 khung bị cắt** (độ dài gốc lớn nhất 14 654 byte, là khung đã gộp offload);
  - check "did not reach its packet limit (200000)" đạt.
  - Chi tiết: [`side/alert-and-ens33-check.txt`](task06b4c/side/alert-and-ens33-check.txt).
- **Cảnh báo không mù:** áp offline đúng hai bộ lọc của lần chạy lên `tap0` đã lưu:
  - `alert_any` khớp 77/100 (ARM), 110/133 (MIPS);
  - `alert_eth` khớp 100/100 và 133/133;
  - trên veth, bridge, `ens33`: 0.
  - Tức là bộ lọc khớp lưu lượng guest thật, và không có lưu lượng guest nào ở phía host.
- **Heartbeat:** đạt ở 4 mốc kiểm của harness. Giá trị cuối `1791434065.844` (04:34:25.844), 0,63 s trước khi watcher dừng. Không có `CaptureLost`; marker rỗng.
- **Teardown** ([`teardown-timeline.txt`](task06b4c/run1/hostcap/teardown-timeline.txt)):
  - guest xong 04:34:22.754 → dừng ctl 23.443 (rc 0);
  - hết thời gian chờ 3 s lúc 26.450 → dừng watcher 26.477;
  - SIGINT tới **5** capture 26.480–26.490 → cả 5 thoát rc 0 lúc 26.510–26.586, trước hạn 10 s.

## 5. Bộ quét cũ và mới

| pcap host | `sigscan.sh` (cũ) | `sigscan_l2.py` (mới) |
|---|---|---|
| veth | `guest_l2l3=0 probe_sport=0 probe_qname=0 probe_url=0`, `control_qname=8` | mọi khóa chữ ký = 0; `truncated_frames=0`, `unscannable_truncated=0`, `unscannable_undecoded=0` |
| bridge | như trên, `control_qname=8` | như trên, `truncated_frames=0` |
| `ens33` | như trên, `control_qname=8` | mọi khóa chữ ký = 0; **`truncated_frames=7`**, `unscannable_truncated=0`, `unscannable_undecoded=0` |

- Cả hai bộ quét exit 0. Mọi check "= 0" trong run script đều đạt.
- `truncated_frames=7` là thông tin: 7 khung lớn bị cắt nhưng header vẫn đủ để quét, nên `unscannable_truncated=0`.
- `arp_spoof_spa_manager` dùng MAC thật của manager trong lần chạy. Manager khởi động lại thì nhận MAC mới (`0a:b9:d9:5c:c4:51`, khác 06B-3G), nên phải đọc MAC lúc chạy như harness đang làm.
- Kiểm tra độc lập ([`side/independent-check.txt`](task06b4c/side/independent-check.txt)): `tap0` có đủ gói probe (ARM 3, MIPS 4 mỗi probe TCP; UDP 4), 0 gói trả về guest.
- Đối chứng: mongo 358/359 (1 lỗi lúc 04:31:18, trước khi ctl nối `dbnet`, giống các lần trước); worker `eth0` và manager 359/359.

## 6. ARP/L2 bằng module mới — **quan sát lưu lượng hiện có, chưa phải ma trận probe mới**

[`side/l2-observation.txt`](task06b4c/side/l2-observation.txt), script [`side/l2_observation.py`](task06b4c/side/l2_observation.py). `TAP_MAC` lần này là `96:c1:56:82:5b:40`.

- **Toàn phiên, 13 lớp có bộ đếm** (9 lớp cũ, thêm `arp_in_ok`, `arp_in_drop`, `arp_out_ok`, `allow_out_svc`): **PASS** ở cả hai kiến trúc.
  - ARM: ARP guest 3 khung = delta `arp_in_ok` 3; `arp_out_ok` 3 = 3; `allow_out_svc` 10 = 10.
  - MIPS: 2 = 2; 2 = 2; 11 = 11.
  - `arp_in_drop` 0; `l2_bad_mac` 0; không có khung không bộ đếm (`arp_not_hooked`, `ip_not_hooked`, `unmapped`, `worker_unexpected`).
- 9 lớp cũ: số khung chắc chắn bằng `session.json`.
- **Từng probe, 13 lớp:** kết luận bằng kết luận 9 lớp đã ghi. Các lần ARP làm mới neighbor rơi vào các probe ARM `ssh-host-192.168.177.128`, ARM `tap0-other-port-listener`, MIPS `mongodb`; khung khớp delta (1 = 1).
- **Phạm vi:**
  - lưu lượng ARP ở đây chỉ là ARP hợp lệ của guest (hỏi `10.200.0.1`) và trả lời của worker;
  - không có ARP sai đích, ARP giả, MAC giả, IPv6 có chủ đích hay broadcast/multicast nào được gửi;
  - T12–T17 và T20 **chưa được kiểm**.

## 7. Netns, manager, dọn dẹp, host

- **Netns worker:**
  - `eth0 lo tap0`; địa chỉ và route không đổi;
  - `ISOLATION OK` sau ARM và sau MIPS;
  - ruleset tại runtime giống hệt expected.
  - Khác biệt được báo cáo, giống các lần trước: `tap0` `vnet_hdr off→on`; 3 neighbor `REACHABLE` trên `eth0` do đối chứng.
- **Manager** ([`manager-state.txt`](task06b4c/run1/manager-state.txt)): trước `exited` `494ae3d2e2eb` → harness bật → sau `exited`, **cùng ID**. `StartedAt` đổi vì lần chạy đã bật manager. Check "manager back to its initial state" đạt.
- **Dọn dẹp:**
  - xóa đúng 2 container do lần chạy tạo (`b6208752…`, `71dc247b…`);
  - không còn QEMU, capture, thư mục capture tạm.
  - **Còn lại một sản phẩm phụ:** `ct01-06b4b/__pycache__/` thuộc root, do Python chạy dưới root khi import module harness. Không phải file harness, không ảnh hưởng hash. Chưa xóa (cần sudo); ghi lại để xử lý theo quyết định.
- **Host:** các check hard (sysctl, nft, route, cổng, QEMU, capture, `tap0` host) không đổi. Khác biệt được báo cáo, giống 06B-3E/3G:
  - `docker-ps`: chuỗi thời gian;
  - IPv6 link-local và route `fe80::/64 … linkdown` trên bridge `sandboxnet`;
  - `nft_ct`.

## 8. Kết luận theo phạm vi

- **Harness 06B-4BR chạy đúng trên môi trường thật** ở phần được giao kiểm:
  - `ens33` không lọc, snaplen 512, có giới hạn;
  - cảnh báo Ethernet trên veth;
  - 5 capture có thống kê đầy đủ và teardown đúng hạn;
  - bộ quét cũ và mới cùng chạy;
  - khung bị cắt được báo `truncated_frames`, không có khung không quét được.
- **Không phát hiện lỗi harness.**
- **Ma trận 20 probe chưa được kiểm chứng trọn vẹn:** 3 CHƯA KIỂM CHỨNG (2 do đối chứng TCP/53 của gateway LAN không sống, 1 do gói biên). Exit 4.
- Không có lệch thật giữa bộ đếm và pcap. Không có FAIL. Không thấy chữ ký nào phía host.
- Đối chứng `192.168.177.2:53/tcp` đã thay đổi theo môi trường. Có dùng tiếp đối chứng này, hay chọn đích LAN khác cho probe TCP, cần reviewer quyết định.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 9. Hạn chế

- Một lần chạy. Guard 20 ms là giả định chưa đo.
- Phần ARP/L2 chỉ là quan sát lưu lượng hợp lệ có sẵn; các lớp `arp_in_drop`, `l2_bad_mac`, `arp_not_hooked` chưa có khung thật nào.
- Giả định [Kernel] trong `l2frames.py` vẫn chưa kiểm thực tế.
- Giới hạn 200 000 gói của `ens33` chưa từng bị chạm. Hành vi khi chạm (tcpdump thoát → watcher báo capture chết) mới chỉ được thiết kế, chưa kiểm thật.
- `ens33.pcap` không lọc chứa lưu lượng khác của host (đã mô tả ở §1).

## 10. Hash

| File | sha256 |
|---|---|
| [`run1/run.log`](task06b4c/run1/run.log) | `9e8bca0d01d483a47487f0cb859046202d82a1a427684baf0481805754cad7cd` |
| [`run1/harness-sha256.txt`](task06b4c/run1/harness-sha256.txt) | `5c363de6a1cafa943b69b02f63fd3af64ceb5ff8ff0ba5bae9ae90440c02fb69` |
| [`ARM/session.json`](task06b4c/run1/container/probe/ARM/session.json), [`MIPS/session.json`](task06b4c/run1/container/probe/MIPS/session.json) | `f4f9a02d2bd09fceda4668c489ccf151288b1f60a0a4d8cf1ead2b156fe2cd1f`, `06553310f7f30e55e15eca7a96cbdf2759ff63b8510b2189f74106f3fbbae0b3` |
| [`ARM/matrix.json`](task06b4c/run1/container/probe/ARM/matrix.json), [`MIPS/matrix.json`](task06b4c/run1/container/probe/MIPS/matrix.json) | `eca77c214deeb8daacbc7443fe2d9b5601c074409423de1adf9739615dc843a3`, `c12e37c23b37f09f74e3d15500a6a6f9df7d126088247f07f01b42d37730191e` |
| [`ARM/tap0.pcapng`](task06b4c/run1/container/probe/ARM/tap0.pcapng), [`MIPS/tap0.pcapng`](task06b4c/run1/container/probe/MIPS/tap0.pcapng) | `1e43b866d737f4c95c6d600aa674706116691d57d143026ef9b88a47a3b083cc`, `bb87e7c70deff97fdf7c8410234ad659b221de62dd3eb8f47bba7451acddf20a` |
| [`hostcap/veth.pcap`](task06b4c/run1/hostcap/veth.pcap), [`bridge.pcap`](task06b4c/run1/hostcap/bridge.pcap), [`ens33.pcap`](task06b4c/run1/hostcap/ens33.pcap) | `372823006faa916841c504379002a4e6421d4f896a44c4c0d1006a4b59755960`, `f7cfae9da3dba658b01ce46b760c79e12c837a21ab60f73bfb40fe16ef3b7c53`, `3c1e67645ebff9284f815a8ccd4de791cce903a2efb4af5c859304ab24a907dc` |
| [`hostcap/capture-stats.tsv`](task06b4c/run1/hostcap/capture-stats.tsv) | `5cbc4ae6d37cee42a93cdd6fc5af19989cdb5cb595508ede5e17bc62c735d8f2` |
| [`side/l2-observation.txt`](task06b4c/side/l2-observation.txt) | `9ed80d14ae98ba78936e7800c57f6d5ce7cf7927bdf41cc72b5197ad3609bee3` |
| [`side/alert-and-ens33-check.txt`](task06b4c/side/alert-and-ens33-check.txt) | `4fdc342a03d8107602ab81c3a02955fc0a6f8d5dde0966bd95defa4e135e782d` |
| [`side/precheck.txt`](task06b4c/side/precheck.txt) | `0619216be59cc480d850108a6ef21c29b0e8429da0a56cb868dbdd6347dfe82f` |

Mọi file trong `task06b4c/` (trừ `.pyc` của stub self-test, bị `.gitignore` loại): [`task06b4c/SHA256SUMS`](task06b4c/SHA256SUMS) (`41868db911208951f19cfbea8285cbfbff21bf4c90317b04e98990b41940cbd9`).
