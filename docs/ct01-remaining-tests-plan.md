# Kế hoạch kiểm thử các phần CT-01 còn thiếu (Nhiệm vụ 06B-4A, sửa ở 06B-4B)

**Trạng thái (cập nhật 06B-4IR3):** chỉ 5 ca T12–T13 đã chạy trên guest (06B-4G, một lần); T14–T17/T20 chưa chạy. Không sửa source cô lập.

- T12–T13: 5 ca kiểm quy tắc (B1, B2, B4, I1, I2) đã viết (06B-4E, sửa ở 06B-4ER) và nối vào harness ở mức offline (06B-4F, sửa ở 06B-4FR; bản `ct01-06b4fr`). Chạy tích hợp một lần ở 06B-4G: exit 4, 9/10 ĐẠT (kiểm quy tắc), ARM T13-I1 CHƯA KIỂM CHỨNG (gói ở biên), 0 FAIL ([`evidence/task06b4g-summary.md`](evidence/task06b4g-summary.md)). B3 (`nslookup` tới `224.0.0.251`) và I3 (`curl -6`) chưa viết.
- T14 (A1, A2, A3) và T15 mức 1 (S1, gratuitous do kernel guest): đã viết và kiểm **offline** ở 06B-4H, sửa lỗi review ở 06B-4HR, 06B-4HR1, 06B-4HR2 (`arp_cases.py`; hành vi guest mới chỉ mô phỏng); nối vào harness và run script `run-06b4i.sh` ở mức offline ở 06B-4I, sửa review ở 06B-4IR1 và 06B-4IR2 (bản `ct01-06b4ir2`, chốt offline); precheck review ra PC-1–PC-4, sửa ở 06B-4IR3 (bản `ct01-06b4ir3`: dừng giữa kiến trúc, admin link state, collector/evaluator precheck mới); **chưa chạy** ([`evidence/task06b4ir3-summary.md`](evidence/task06b4ir3-summary.md)). T15 mức 2 chưa phủ (D1).
- T16, T17, T20: chưa viết probe. Harness L2/ARP/IPv6 (06B-4B/4BR) và bộ đánh giá L2/ARP offline (06B-4D1R) đã có; 06B-4C chỉ kiểm tích hợp harness đó với 20 probe IPv4 cũ, không có probe mới.
- Đây là kiểm chứng riêng của CT-01; đánh giá tổng thể CT-14 chưa bắt đầu.

Phần dưới giữ nguyên như lúc chấp nhận kế hoạch (06B-4B), trừ các ghi chú "cập nhật 06B-4FR".

**06B-4B:** reviewer chấp nhận hướng kế hoạch, kèm các quyết định D1–D7 (§5.2). Kế hoạch đã sửa theo review:

- T17-P3 hoãn (§2, T17);
- thống nhất danh sách cổng và chữ ký (§2.0); các cổng mới chuyển xuống dưới dải cổng tạm;
- neighbor khôi phục theo trạng thái trước phép thử (§1.3);
- T20 tách lần gọi gửi, `errno` và bằng chứng bộ đếm;
- script inventory dùng scratch `mktemp` mới;
- danh mục BusyBox chỉ là bằng chứng tĩnh.

Harness đo L2/ARP/IPv6 đã được chuẩn bị offline ở bản harness mới `ct01-06b4b` (§3.3); bản 06B-3FR1 giữ nguyên. Chi tiết: [`evidence/task06b4b-summary.md`](evidence/task06b4b-summary.md).

**Điểm xuất phát:**

- 06B-3G đã được reviewer chấp nhận đúng phạm vi: ma trận IPv4 20 probe có 19 ĐẠT, 1 CHƯA KIỂM CHỨNG (MIPS `ssh-host-192.168.60.1`, do gói biên). Toàn phiên ARM và MIPS đều PASS (báo riêng).
- Không chạy lại ma trận IPv4 để tìm exit 0.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

**Đối chiếu với:**

- [`docs/network-isolation-design.md`](network-isolation-design.md): ruleset §4.3, ARP §4.4, nguyên tắc bằng chứng §7.1, ma trận §7.2, giả định §8;
- `sandbox-worker/isolation/guest.nft`: ruleset thật, có thêm bộ đếm `allow_out_svc` so với §4.3;
- harness 06B-3FR1/3G ngoài repo (`/home/dathq/projects/ct01-06b3c/`);
- danh mục tĩnh của ảnh guest: [`evidence/task06b4a/guest-static-inventory.txt`](evidence/task06b4a/guest-static-inventory.txt). Script đã sửa ở 06B-4B (scratch do `mktemp` tạo, không xóa đường dẫn nhận từ tham số), cho cùng nội dung: [`evidence/task06b4b/guest-static-inventory.txt`](evidence/task06b4b/guest-static-inventory.txt).

Ký hiệu nguồn:

| Ký hiệu | Ý nghĩa |
|---|---|
| **[Mã]** | đọc từ mã repo hoặc harness |
| **[KC]** | quan sát trong một lần chạy đã có evidence |
| **[Tĩnh]** | đọc tĩnh từ file ảnh guest bằng `debugfs`, không boot. Danh sách applet BusyBox lấy từ chuỗi trong binary (kiểu `strings`): chỉ là **bằng chứng tĩnh**, **không thay thế** việc xác nhận công cụ khi guest chạy (`busybox --list`, `command -v`, thử gửi và thấy khung trong pcap) |
| **[Kernel]** | đọc từ mã Linux upstream v6.8; chưa kiểm trên kernel `6.8.0-146` của host |
| **[GĐ]** | giả định, phải kiểm trước khi dùng làm tiêu chí |

---

## 1. Điều kiện chung

### 1.1 Thứ tự điểm chặn của ruleset hiện hành [Mã]

Một khung đi từ guest vào `tap0` được xét theo thứ tự sau:

1. **`netdev sandbox_guest_l2` ingress (prio −500):**
   - MAC nguồn khác `52:54:00:c7:00:02` → `l2_bad_mac`;
   - ethertype khác IPv4/ARP → `l2_bad_ethertype`. IPv6, VLAN, LLDP… đều dừng ở đây.
2. **ARP** → `arp_rcv` của kernel, rồi **`arp sandbox_guest_arp` input:**
   - chỉ request/reply có `sha = GUEST_MAC`, `spa = 10.200.0.2`, `tpa = 10.200.0.1`, htype 1, ptype IPv4, hlen 6, plen 4 → `arp_in_ok`;
   - mọi ARP khác → `arp_in_drop`. Xem §3.2 về các khung ARP không bao giờ tới hook.
3. **IPv4** → **`inet sandbox_guest` prerouting (prio −150)**, theo đúng thứ tự:
   - `drop_non_ipv4`;
   - `drop_spoof`: nguồn ≠ `10.200.0.2`;
   - `allow_svc`: `10.200.0.1:8011/tcp`;
   - `drop_worker_other`: mọi đích khác trên `10.200.0.1`;
   - `drop_private`: các dải riêng/đặc biệt, **gồm cả `10.200.0.3`**;
   - `drop_bcast_mcast`: `224.0.0.0/4`, `255.255.255.255`;
   - `drop_public`: còn lại.
4. **Chiều worker → guest:**
   - `arp output`: chỉ ARP giữa `.1` và `.2` → `arp_out_ok`, còn lại → `arp_out_drop`;
   - `inet output`: chỉ TCP từ cổng 8011, `ct state established` → `allow_out_svc`, còn lại → `drop_out`.

Hệ quả, quan trọng cho kỳ vọng của các phép thử:

- Gói giả IP nguồn luôn vào `drop_spoof` **trước** mọi luật theo đích, kể cả khi đích là dịch vụ được phép.
- IPv6 không bao giờ tới bảng `inet`, nên `drop_non_ipv4` phải đứng yên ở 0.
- Broadcast có nguồn `0.0.0.0` (DHCP) vào `drop_spoof`, không vào `drop_bcast_mcast` [KC 06B-3A/3E].
- Broadcast theo subnet `10.200.0.3` vào `drop_private`, không vào `drop_bcast_mcast`.

### 1.2 Guest thực tế [Tĩnh, một phần KC]

| | ARM | MIPS |
|---|---|---|
| Hệ điều hành | OpenWrt 18.06.1 (`armvirt/32`) | OpenWrt SNAPSHOT r30207 (`malta/be`) |
| BusyBox | v1.28.3 | v1.37.0 |
| Interface probe | `eth1` (NIC thứ hai, gắn `tap0`) [KC] | `br-lan` (bridge, cổng `eth0` gắn `tap0`) [KC] |
| Cấu hình netifd của interface probe | `wan` = `proto dhcp`, `wan6` = `dhcpv6` | `lan` = `proto dhcp` |
| Firewall guest (fw3/fw4) | vùng `wan`: input REJECT | vùng `lan`: input ACCEPT |
| Dịch vụ lắng nghe theo cấu hình | dropbear `:22`, uhttpd `:80`/`:443` | dropbear `:22` |
| Công cụ có sẵn | `curl` 7.60.0 [KC], busybox `ip`, `ping`, `ping6`, `nc`, `ifconfig`, `route`, `sysctl`, `udhcpc`, `arp` (heuristic); `iptables` | `curl` 8.12.1 [KC], busybox như ARM; `nft` |
| **Không có** | `arping` [KC: `command -v`; Tĩnh: không có applet], `python`, `tcpdump`, `ether-wake` | như ARM |

Lưu lượng nền đã quan sát và bộ đếm tương ứng:

| Lưu lượng nền | Bộ đếm | Nguồn |
|---|---|---|
| DHCP `0.0.0.0 → 255.255.255.255` | `drop_spoof` | [KC] |
| DNS tới `8.8.8.8:53` | `drop_public` | [KC] |
| IPv6 (MLD, RS, DHCPv6) | `l2_bad_ethertype` | [KC] |
| ARP hỏi `10.200.0.1` | `arp_in_ok` | [KC tổng, 06B-3G: 2 khung ARP của guest = delta `arp_in_ok` 2 ở mỗi kiến trúc] |

**Hệ quả của bảng công cụ:**

- Thiếu `arping`, nên T14/T15 phải tạo ARP bằng chính kernel guest. **D1: chưa nạp công cụ mới**, nên ARP reply giả tùy ý chưa phủ.
- `ping`/`ping6` là nguồn chính cho ICMP, với kích thước payload riêng làm chữ ký.
- `nslookup` tạo UDP mang tên DNS đánh dấu (đã dùng ở 06B-3B).
- `nc -u` của busybox chưa chắc được bật [GĐ G4].

### 1.3 Quy tắc chung kế thừa từ harness 06B-3G

**Thực hiện:**

- Chạy tuần tự ARM rồi MIPS. Mỗi phép thử là một probe với cửa sổ bộ đếm riêng:
  - đọc A có mốc thời gian → probe → đọc B;
  - phân vùng gói `outside`/`edge_start`/`certain`/`edge_end`; guard giữ **20 ms (giả định chưa đo)**.
- Đối chiếu từng lớp với pcap `tap0`, tính cả retransmission và lưu lượng nền.
- Thứ tự ưu tiên kết luận giữ nguyên: **FAIL > LỖI PHÉP ĐO > CHƯA KIỂM CHỨNG > ĐẠT**.
- Kết quả toàn phiên (`session.json`) vẫn báo riêng, không đổi kết luận probe hay mã thoát.

**Liên kết dịch vụ:**

- Kiểm liên kết dịch vụ (GET `get-task/T/file` 200 + hash) trước nhóm probe và sau mỗi phép thử có đổi cấu hình guest.
- **Khôi phục theo trạng thái trước phép thử (D2, `guest_state.py`):**
  - trước khi đổi, ghi MAC, trạng thái link, địa chỉ IPv4, route, neighbor (`/proc/net/arp`) và `arp_notify` của `IF`;
  - sau phép thử, đưa về **đúng** bản ghi đó theo thứ tự link → địa chỉ → route → neighbor tĩnh → `arp_notify`, đọc lại trạng thái ở mỗi bước;
  - neighbor tĩnh (cờ `ATF_PERM`) theo đúng trạng thái trước: entry do phép thử thêm thì xóa; entry có từ trước mà bị mất (ví dụ bị xóa khi link down [Kernel]) hoặc bị đổi MAC thì đặt lại MAC cũ;
  - neighbor động do kernel quản lý chỉ được ghi lại, không ép, và không làm khôi phục thất bại;
  - chỉ ghi "đã khôi phục" khi trạng thái đọc lại bằng bản ghi trước ở mọi mục được khôi phục.
- Nếu khôi phục cấu hình guest không đạt, các probe còn lại của kiến trúc đó **không chạy** và được ghi CHƯA KIỂM CHỨNG ("cấu hình guest chưa khôi phục"), không được ghi ĐẠT.

**Capture và an toàn:**

- Capture host trên veth, bridge `sandboxnet`, `ens33`; cảnh báo rò rỉ; heartbeat. Thấy gói bị cấm trên host → dừng ngay.
- Không chạy mẫu, ELF hay công cụ ngoài ảnh guest (D1: chưa nạp công cụ mới). Không đổi mạng, firewall hay sysctl của host.

**Kiểm quy tắc:**

- Phép thử không có **đối chứng sống cùng IP/giao thức/cổng** thì kết luận tốt nhất là **"ĐẠT (kiểm quy tắc)"**.
- Nghĩa là luật khớp và drop đúng chỗ, **không** chứng minh dịch vụ đích không truy cập được (thiết kế §7.1).
- Cách ghi nhãn này cần reviewer duyệt (D6).

### 1.4 Điểm lệch so với ma trận thiết kế §7.2

| # | Thiết kế ghi | Thực tế / sửa trong kế hoạch | Nguồn |
|---|---|---|---|
| L1 | T14/T15 dùng `arping` (kèm `-U`, `-s`) | Guest **không có** `arping`. Dùng ARP do kernel guest sinh ra (route on-link, `arp_notify`). Riêng ARP reply giả tùy ý cần quyết định D1 | [KC], [Tĩnh] |
| L2 | T14: `arping 10.200.0.3` | `10.200.0.3` là **địa chỉ broadcast** của `10.200.0.0/30`; kernel guest không gửi ARP cho địa chỉ này. Thay bằng đích ngoài subnet qua route on-link | [Mã] hằng số |
| L3 | T12: broadcast/multicast → `drop_bcast_mcast` | Chỉ đúng khi nguồn là `10.200.0.2` và đích `255.255.255.255` hoặc `224.0.0.0/4`. `10.200.0.3` → `drop_private`; DHCP (nguồn `0.0.0.0`) → `drop_spoof` | [Mã] thứ tự luật |
| L4 | T13 → `l2_bad_ethertype` | Đúng. Thêm tiêu chí `drop_non_ipv4 = 0`, vì IPv6 dừng ở L2 trước bảng `inet` | [Mã] |
| L5 | Bằng chứng §7.1 yêu cầu delta = số khung pcap | Harness hiện **không phân lớp được `l2_bad_mac`** (`classify()` coi mọi khung có MAC nguồn khác guest là khung đi tới guest) và **không ánh xạ ARP**. pcapng `tap0` **không có cờ hướng** (EPB flags): 0/97 và 0/125 khung ở 06B-3G | [Mã] `probe_matrix.classify`; [KC] pcap 06B-3G |
| L6 | Bộ lọc host tổng quát `net 10.200.0.0/30 or ether host GUEST_MAC` | Capture `ens33` của harness **có bộ lọc** (`ether host GUEST_MAC or net 10.200.0.0/30 or host 1.1.1.1 or host LAN_DNS`), cảnh báo chỉ lọc `net 10.200.0.0/30`. Chữ ký giả (MAC/IP giả, IPv6, multicast) sẽ **không được ghi** trên `ens33` và không kích hoạt cảnh báo nếu không mở rộng | [Mã] `run-06b3b.sh` |
| L7 | T20: M, H gửi tới `10.200.0.2` | Gói từ M/H đi theo default route của host ra `ens33` (LAN), và cảnh báo `net 10.200.0.0/30` sẽ kích hoạt. Kế hoạch dùng tra route (chỉ đọc); gửi gói chỉ khi reviewer chọn D3 | [Mã], [GĐ] |
| L8 | T17: thêm `10.200.0.3/30` | Thêm `/30` trùng subnet sẽ đổi định tuyến của guest. Dùng địa chỉ phụ `/32` cho từng nguồn giả | [Mã] |

> L8 **[Điều chỉnh R7, 2026-10-11 — giữ trace]:** nguồn giả của P1/P4 chuyển `10.200.0.3` → `10.200.0.5/32` vì `10.200.0.3` là địa chỉ broadcast của `10.200.0.0/30`; ở R6 ARM probe `.3` không tạo được khung nguồn `.3` (capture chỉ có IP thật `10.200.0.2`; cơ chế liên hệ chưa xác minh). `.5` là biến thể có ghi nhận của phép thử, không chứng nhận `.3` hay mọi nguồn giả. Bảng §2.x và hằng số `signatures.SPOOF_SRC_IPS` của R7: `10.200.0.5` (P1/P4), `192.168.60.10` (P2/P5).

---

## 2. Từng phép thử

Quy ước chung cho các bảng dưới đây:

- `TAP_MAC` là MAC ngẫu nhiên của `tap0` trong mỗi lần chạy (06B-3G: `7a:93:2a:f1:47:47`), đọc từ bản ghi netns.
- `IF` là interface probe (ARM `eth1`, MIPS `br-lan`).
- Cổng, kích thước ICMP, MAC/IP giả: chỉ lấy từ bảng §2.0 (nguồn duy nhất: `signatures.py` của harness 06B-4B).
- Mọi đếm "khung" là đếm trên pcap `tap0`.

### 2.0 Danh sách cổng và chữ ký (thống nhất ở 06B-4B)

**Sửa so với 06B-4A:**

- 06B-4A ghi dải dành riêng 42000–42099 nhưng dùng cổng 42171–42174, ngoài dải đó.
- Dải 42xxx nằm trong dải cổng tạm của Linux (`ip_local_port_range` của host = `32768 60999` [KC]; container mặc định cùng dải).
- **[KC] pcap bridge của 06B-3G** có một kết nối đối chứng hợp lệ `192.168.60.3:42172 → 192.168.60.10:8011` (12 khung), tức chữ ký chỉ dựa trên cổng 42172 sẽ báo động giả.
- Các cổng mới vì vậy chuyển xuống **31000–31299**, dưới dải cổng tạm: 0 khung trên dải này ở veth, bridge và `ens33` của 06B-3G, và host không có dịch vụ nào nghe ở đó [KC].
- Ánh xạ: 42013 → 31013, 42016 → 31016, 42020 → 31020, **42171–42174 → 31171–31174**; cổng nguồn cố định mới cho T20-N2: 31201/31202.

| Mã | Cổng / giá trị | Ghi chú |
|---|---|---|
| T13-I3 | `31013` (nguồn TCP) | `curl -6` tới địa chỉ EUI-64 của `TAP_MAC`; trên dây chỉ có NS |
| T16-M1 | `31016` (nguồn TCP) | liên kết dịch vụ khi MAC giả |
| T17-P1 | `31171` | nguồn `10.200.0.3` → `10.200.0.1:8011` |
| T17-P2 | `31172` | nguồn `192.168.60.10` → `10.200.0.1:8011` |
| T17-P3 | `31173` (giữ chỗ) | **hoãn**, xem T17 |
| T17-P4 | `31174` | nguồn `10.200.0.3` → `1.1.1.1:443` |
| T20-N2 | `31201`, `31202` (nguồn TCP phía W) | W → guest `:22`, `:80` |
| T20-N3 | `31020` (UDP) | W → guest |
| ICMPv4 (`ping -s`) | T12-B1 1201, B2 1202, B4 1204; T14-A1/A2/A3 1401/1402/1403; T17-P5 1705 | trên dây: tổng độ dài IP = kích thước + 28 |
| ICMPv6 (`ping6 -s`) | T13-I1 1301, I2 1302 | trên dây: độ dài payload IPv6 = kích thước + 8 |
| MAC giả | `52:54:00:de:ad:01` | chỉ MAC **đã chọn** này được nhận là "guest giả MAC"; giả `TAP_MAC` không phủ (D5) |
| IP nguồn giả | `10.200.0.3` (P1, P4), `192.168.60.10` (P2, P5), `10.200.0.1` (P3, hoãn) | `192.168.60.10` là máy thật trên `sandboxnet`: chỉ là chữ ký khi đi kèm **cổng nguồn** probe hoặc kích thước ICMP probe |
| Tên DNS | tiền tố `ct01-06b4-` | `nslookup` của probe mới |
| Cũ (06B-3B) | `41000–41020` | giữ nguyên trong `sigscan.sh`. Cũng nằm trong dải cổng tạm: đến nay luôn 0 ở phía host, nhưng về nguyên tắc có thể va chạm (ghi nhận, không đổi) |

**Chữ ký phía host** (sinh từ bảng trên):

- **cảnh báo trên `-i any`:** chỉ chữ ký tầng mạng, vì `ether host` **không biên dịch được** trên kiểu link `LINUX_SLL2` ([KC] biên dịch thử offline);
- **cảnh báo Ethernet trên veth của worker:** thêm chữ ký MAC. Veth là đường ra duy nhất của netns worker (harness kiểm);
- **`sigscan_l2.py`** quét veth/bridge/`ens33` sau khi chạy theo các khóa:
  - MAC guest, MAC giả;
  - IP trong `10.200.0.0/30`;
  - ARP có `sha` là MAC guest hoặc MAC giả, ARP có `spa`/`tpa` thuộc `10.200.0.0/30`, ARP khai `192.168.60.10` với MAC khác MAC thật của manager;
  - IPv6 của guest;
  - IP nguồn giả;
  - cổng probe, kích thước ICMP, tên DNS.
- **`ens33` bắt không lọc, có giới hạn** (D7): snaplen 512, tối đa 200 000 gói. Chạm giới hạn thì tcpdump thoát, watcher báo capture chết và probe dừng; không bao giờ cắt cụt âm thầm.

### T12 — Broadcast/multicast IPv4 (kiểm quy tắc)

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Không đổi cấu hình guest. Công cụ: busybox `ping` (ICMP), `nslookup` (UDP 53 mang tên đánh dấu). Kiểm khi chạy: `ping` có bật `SO_BROADCAST` không [GĐ G1]; nếu `ping 255.255.255.255` lỗi cục bộ ("permission denied") và không có khung nào → probe đó **CHƯA KIỂM CHỨNG (TOOL)** |
| **2. Gói, đích, mong đợi, điểm chặn** | **B1:** `ping -c 3 -s 1201 255.255.255.255` → `drop_bcast_mcast` +3. **B2:** `ping -c 3 -s 1202 224.0.0.1` (all-hosts; theo default route) → `drop_bcast_mcast` +3. **B3:** `nslookup ct01-06b4-t12-<arch>-3 224.0.0.251` (UDP 53 tới mDNS group) → `drop_bcast_mcast` + số lần thử lại. **B4 (ranh giới):** `ping -c 3 -s 1204 10.200.0.3` (broadcast subnet) → **`drop_private`** +3, không phải `drop_bcast_mcast`. Mong đợi chung: không có trả lời nào tới guest; `drop_forward`, `drop_input_backstop` đứng yên |
| **3. Đối chứng** | Không có dịch vụ sống trên các đích này → **kiểm quy tắc**. Không kết luận "không chạm được dịch vụ multicast/broadcast trên `sandboxnet`" |
| **4. Chữ ký** | `tap0`: ICMP echo có độ dài IP = 28 + kích thước (`ip[2:2] = 1229…1232`); tên DNS `ct01-06b4-t12-*`. Host (veth, bridge, `ens33`, cảnh báo): `ether src 52:54:00:c7:00:02`; `ip src 10.200.0.2`; `icmp and ip[2:2] >= 1229 and ip[2:2] <= 1232`; `ether dst ff:ff:ff:ff:ff:ff and ether src 52:54:00:c7:00:02`; `ether dst 01:00:5e:00:00:01 and ether src 52:54:00:c7:00:02`; payload `ct01-06b4-t12-`. `ens33` bắt không lọc từ 06B-4B (D7) |
| **5. Khôi phục, liên kết dịch vụ** | Không có gì để khôi phục. Kiểm liên kết dịch vụ sau nhóm T12 |
| **6. Kết luận** | **ĐẠT (kiểm quy tắc):** mọi khung probe nằm trong vùng chắc chắn; delta `drop_bcast_mcast` (B1–B3) và `drop_private` (B4) bằng số khung pcap; các lớp khác chỉ tăng đúng bằng nền đã phân lớp; không có trả lời; không có chữ ký trên host. **FAIL:** delta lệch ngoài khoảng cho phép; khung probe vào lớp khác; có trả lời tới guest từ đích khác `10.200.0.1`; chữ ký trên host. **CHƯA KIỂM CHỨNG:** công cụ không gửi được (không có khung probe); gói biên; capture không đầy đủ. **Chưa phủ:** broadcast/multicast L2 không phải IP; IGMP join (cần ứng dụng join group); multicast có TTL > 1 ra ngoài (không có định tuyến multicast, `ip_forward = 0`) |

### T13 — IPv6 (kiểm quy tắc)

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Ghi trước: `ip -6 addr`, `ip -6 route` trong guest; `ip -6 addr show dev tap0` (mong đợi rỗng) và `sysctl net.ipv6.conf.tap0.disable_ipv6` (=1) trong worker. Công cụ: busybox `ping6`, `curl -6`. Không đổi cấu hình guest |
| **2. Gói, đích, mong đợi, điểm chặn** | **I1:** `ping6 -c 3 -s 1301 -I IF ff02::1` → `l2_bad_ethertype` +3. **I2:** `ping6 -c 3 -s 1302 -I IF fe80::<EUI-64 của TAP_MAC>`. `tap0` không có IPv6, nên guest chỉ gửi Neighbor Solicitation tới `ff02::1:ffXX:XXXX` → `l2_bad_ethertype` += số NS (thường 3, [GĐ G5]); không có echo nào. **I3:** `curl -6 -g --local-port 31013 'http://[fe80::<EUI-64>%25IF]:8011/'` → chỉ có NS → `l2_bad_ethertype`. **I4:** `ping6 -c 1 2001:db8::1` (không có route) → lỗi cục bộ, **không có khung**; chỉ ghi lại để xác nhận guest không có IPv6 toàn cục. Mong đợi chung: **`drop_non_ipv4` = 0**; không có khung IPv6 nào tới guest |
| **3. Đối chứng** | Không có đường hợp lệ nào tới cùng địa chỉ IPv6/cổng → **kiểm quy tắc**. Ghi thêm `ss -ltn` của host (`[::]:22` đang nghe) làm bối cảnh, không coi là đối chứng |
| **4. Chữ ký** | `tap0`: `ether src 52:54:00:c7:00:02 and ip6`; `icmp6 and ip6[4:2] = 1309/1310` (độ dài payload IPv6 = 8 + kích thước); NS có `ip6 dst ff02::1:ff00:0/104`. Host: `ip6 and ether src 52:54:00:c7:00:02`; mọi khung có nguồn là link-local EUI-64 của MAC guest (`fe80::5054:ff:fec7:2`); các kích thước trên. Cảnh báo đã có chữ ký IPv6 của guest; `ens33` bắt không lọc (06B-4B, D7) |
| **5. Khôi phục, liên kết dịch vụ** | Không có gì để khôi phục. Kiểm liên kết dịch vụ sau nhóm T13 |
| **6. Kết luận** | **ĐẠT (kiểm quy tắc):** delta `l2_bad_ethertype` = số khung IPv6 của guest trong pcap (probe + nền: MLD/RS/DHCPv6); `drop_non_ipv4` = 0; `tap0` không có IPv6 trước và sau; không có chữ ký trên host. **FAIL:** có khung IPv6 tới guest; `drop_non_ipv4` > 0 (IPv6 vượt được L2); delta lệch; chữ ký trên host. **CHƯA KIỂM CHỨNG:** công cụ thiếu/không gửi; gói biên (nền IPv6 khoảng 1 gói mỗi vài giây làm tăng khả năng này [KC 06B-3E]). **Chưa phủ:** ethertype khác (VLAN 802.1Q, LLDP, PPPoE) vì guest không có công cụ tạo khung thô (busybox không có `vconfig`; module `8021q` chưa kiểm [GĐ]); IPv6 trong IPv4 (proto 41) — **có thể làm được** bằng `ip tunnel` nếu busybox hỗ trợ, gói này là IPv4 nên phải vào `drop_public`/`drop_private` [GĐ G6] |

### T14 — ARP request hỏi sai đích

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Guest có `arping` → không. Tạo ARP request bằng kernel guest: thêm **route on-link** rồi gửi một gói IP để kernel phải phân giải. Ghi trước: `ip route`, `ip neigh`/`arp -a` của guest; `ip neigh show dev tap0` và `ip neigh show dev eth0` của worker. Công cụ: busybox `ip route`, `ping` |
| **2. Gói, đích, mong đợi, điểm chặn** | **A1 (IP `eth0` của chính worker):** `ip route add 192.168.60.2/32 dev IF; ping -c 1 -W 2 -s 1401 192.168.60.2` → kernel guest gửi `who-has 192.168.60.2 tell 10.200.0.2` (broadcast; số lần theo `mcast_solicit`, mặc định 3 [GĐ G7]) → **`arp_in_drop`** += số request. Lớp thứ hai: `arp_ignore=1` trên `tap0`. **A2 (manager):** như A1 với `192.168.60.10`. **A3 (IP không tồn tại):** như A1 với `10.200.0.6`. Mong đợi chung: **không có ARP reply** nào ra `tap0` cho các `tpa` này (`arp_out_*` đứng yên); không có khung IP probe (ARP không phân giải được, nên ICMP không bao giờ được gửi); neighbor `tap0`/`eth0` của worker không đổi |
| **3. Đối chứng** | A1: W có địa chỉ `192.168.60.2` trên `eth0`; M hoặc ctl phân giải được `192.168.60.2` qua ARP trên `sandboxnet` (`/proc/net/arp` của ctl sau một kết nối tới worker) → cùng IP/giao thức (ARP). A2: W phân giải được `192.168.60.10` trên `eth0` (`ip neigh show dev eth0` sau khi ctl/W gọi manager). A3: không có máy → **kiểm quy tắc** |
| **4. Chữ ký** | `tap0`: `arp and ether src 52:54:00:c7:00:02 and arp[24:4] = <tpa>` (A1 `0xc0a83c02`, A2 `0xc0a83c0a`, A3 `0x0ac80006`). Host: `arp and arp[8:4] = 0x525400c7 and arp[12:2] = 0x0002` (sha = MAC guest), `arp and arp[14:4] = 0x0ac80002` (spa = `10.200.0.2`), và `ether src 52:54:00:c7:00:02`. Trên `sandboxnet` hợp lệ có ARP hỏi `192.168.60.2`/`.10`, nhưng với spa/sha của container khác, nên chữ ký phải dựa trên **spa/sha của guest**, không dựa trên `tpa` |
| **5. Khôi phục, liên kết dịch vụ** | Khôi phục theo bản ghi trước (§1.3): xóa các route on-link đã thêm; so `ip route` với bản ghi trước. Neighbor tĩnh theo trạng thái trước. Entry động `INCOMPLETE/FAILED` do phép thử tạo ra tự hết hạn: chỉ ghi lại, không ép. Kiểm liên kết dịch vụ |
| **6. Kết luận** | **ĐẠT:** delta `arp_in_drop` = số khung ARP của guest có `tpa` đích trong pcap (theo ánh xạ §3.2); `arp_in_ok` chỉ tăng bằng ARP hợp lệ của nền; `arp_out_ok`/`arp_out_drop` không tăng vì probe; không có ARP reply tới guest; neighbor worker không đổi; không có chữ ký trên host; đối chứng sống (A1, A2). A3 ghi "ĐẠT (kiểm quy tắc)". **FAIL:** có ARP reply cho `tpa` ≠ `10.200.0.1`; neighbor worker đổi; delta lệch; chữ ký trên host. **CHƯA KIỂM CHỨNG:** ánh xạ ARP chưa được kiểm (§3.2); gói biên; đối chứng không sống; route on-link không tạo được. **Chưa phủ:** ARP với `spa` khác `10.200.0.2` (thuộc T15/T17); ARP unicast tới MAC khác `TAP_MAC` (không tới hook, xem §3.2) |

### T15 — ARP giả mạo (gratuitous / reply khai IP khác)

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Hai mức. **Mức 1 (không cần công cụ mới):** gratuitous ARP do kernel guest gửi khi `arp_notify=1` và interface lên lại (`NETDEV_UP`) hoặc đổi MAC (`NETDEV_CHANGEADDR`). Kernel gửi một gratuitous request cho **mỗi** địa chỉ IPv4 trên interface [Kernel `inetdev_send_gratuitous_arp`]. Thêm địa chỉ phụ `/32` mang IP muốn giả: `10.200.0.1`, `192.168.60.10`, `192.168.60.1`. Ghi trước giá trị `net.ipv4.conf.IF.arp_notify`. **Mức 2 (ARP reply tùy ý, `-A`/`-U`/`-s`):** cần công cụ tạo khung ARP, ví dụ gói `iputils-arping` chính thức của OpenWrt cho đúng kiến trúc, nạp qua đường dịch vụ được phép, có hash. **Chờ quyết định D1; không làm khi chưa được duyệt** |
| **2. Gói, đích, mong đợi, điểm chặn** | **S1 (mức 1):** `sysctl -w net.ipv4.conf.IF.arp_notify=1; ip addr add 10.200.0.1/32 dev IF; ip addr add 192.168.60.10/32 dev IF; ip link set IF down; ip link set IF up` → các gratuitous request (`spa = tpa`, `sha = GUEST_MAC`, broadcast) cho `10.200.0.2`, `10.200.0.1`, `192.168.60.10` → mọi khung vào **`arp_in_drop`**. Gratuitous khai đúng `10.200.0.2` cũng bị drop vì `tpa ≠ 10.200.0.1` (thiết kế §4.4). Cùng lúc, guest có thể gửi DHCP/IPv6/RS do link lên lại → các lớp nền tương ứng. **S2 (mức 2, nếu D1 duyệt):** reply `10.200.0.1 is-at GUEST_MAC` và `192.168.60.10 is-at GUEST_MAC`, gửi tới **`TAP_MAC` hoặc broadcast** (gửi tới MAC khác thì không tới hook, §3.2) → `arp_in_drop`. Mong đợi chung: neighbor `10.200.0.2` trên `tap0` vẫn `PERMANENT` đúng MAC; worker **không** có entry mới trên `tap0`; neighbor `eth0` của worker không đổi; không có ARP nào của guest ra host |
| **3. Đối chứng** | Không có "dịch vụ" để đối chứng. Bằng chứng tác động là bảng neighbor worker trước/sau, cùng `sysctl arp_accept=0`. Ghi là **kiểm quy tắc + kiểm trạng thái neighbor** |
| **4. Chữ ký (gồm chữ ký giả)** | `tap0`: `arp and ether src 52:54:00:c7:00:02 and arp[14:4] = arp[24:4]` (gratuitous); `arp[14:4] = 0x0ac80001` (spa giả `10.200.0.1`); `arp[14:4] = 0xc0a83c0a` (spa giả manager). Host: **mọi** ARP có `sha = 52:54:00:c7:00:02`; mọi ARP có `spa = 10.200.0.1`; ARP có `spa = 192.168.60.10` **mà `sha` khác MAC thật của manager** (đọc MAC manager trước khi chạy); `ether src 52:54:00:c7:00:02` |
| **5. Khôi phục, liên kết dịch vụ** | Khôi phục theo bản ghi trước (§1.3): xóa các `/32` phụ; trả `arp_notify` về giá trị đã ghi; nếu `IF` mất địa chỉ hoặc route sau khi down/up (netifd có thể chạy lại DHCP [GĐ G8]; link down xóa route qua `IF` [Kernel]), đặt lại đúng các địa chỉ/route trong bản ghi. Neighbor tĩnh có từ trước bị xóa khi link down [Kernel] thì đặt lại MAC cũ; neighbor tĩnh không có từ trước thì xóa. Kiểm liên kết dịch vụ. Không đạt → dừng các probe còn lại (§1.3). Lưu ý: trong lúc S1, `10.200.0.1/32` là địa chỉ cục bộ của guest, nên route tới gateway của guest không dùng được; liên kết dịch vụ chỉ được kiểm sau khi khôi phục |
| **6. Kết luận** | **ĐẠT (kiểm quy tắc):** mọi khung ARP giả đều vào `arp_in_drop` theo ánh xạ §3.2; neighbor worker trên `tap0` và `eth0` giống hệt trước/sau; không có chữ ký trên host; khôi phục và liên kết dịch vụ đạt. **FAIL:** neighbor worker đổi; worker trả lời/ghi nhận IP giả; chữ ký giả trên host; delta lệch. **CHƯA KIỂM CHỨNG:** kernel guest không gửi gratuitous (không có khung); gói biên; ánh xạ ARP chưa kiểm. **Chưa phủ (nếu không có D1):** ARP reply giả, gratuitous dạng reply, ARP sai `htype`/`hlen`/`plen` |

### T16 — Thay MAC trong guest

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Ghi trước: `ip link` của guest (MAC mọi interface; topology đã ghi `ifaces_mac`), `ip addr`, `ip route`. MAC giả: `52:54:00:de:ad:01` (như thiết kế). **ARM:** đổi MAC của `eth1` (`ip link set eth1 down; ip link set eth1 address 52:54:00:de:ad:01; ip link set eth1 up`). **MIPS:** khung gửi từ `br-lan` dùng MAC của chính bridge, nên đổi MAC `br-lan` (`ip link set br-lan address …`); cổng `eth0` giữ MAC cũ. Cách làm trên MIPS cần xác nhận bằng pcap [GĐ G9]. Công cụ: busybox `ip`, `curl` |
| **2. Gói, đích, mong đợi, điểm chặn** | **M1:** sau khi đổi MAC, chạy liên kết dịch vụ T01 (`curl … get-task/T/file`, `--local-port 31016`) → **thất bại** (timeout). Mọi khung có MAC nguồn `de:ad:01` (ARP hỏi `10.200.0.1`, SYN nếu ARP còn trong cache, DHCP/IPv6/RS do link lên lại) → **`l2_bad_mac`**. Lưu ý: luật MAC đứng **trước** luật ethertype, nên IPv6 có MAC giả cũng vào `l2_bad_mac`, không vào `l2_bad_ethertype`. Mong đợi: `allow_svc` không tăng vì probe; worker không trả lời tới MAC giả; neighbor `10.200.0.2` vẫn `PERMANENT` với MAC guest gốc |
| **3. Đối chứng** | T01 đạt **ngay trước** khi đổi MAC (cùng IP/giao thức/cổng `10.200.0.1:8011/tcp`), và đạt lại sau khi khôi phục |
| **4. Chữ ký (gồm chữ ký giả)** | `tap0`: `ether src 52:54:00:de:ad:01`; `arp[8:4]`/`arp[12:2]` = MAC giả (sha). Host: `ether host 52:54:00:de:ad:01`; `arp` có sha = MAC giả; cổng `31016`; cộng chữ ký guest thông thường (`ether host 52:54:00:c7:00:02`, `net 10.200.0.0/30`). Cảnh báo Ethernet trên veth có `ether host 52:54:00:de:ad:01`; `ens33` bắt không lọc (06B-4B, D7) |
| **5. Khôi phục, liên kết dịch vụ** | Khôi phục theo bản ghi trước (§1.3): đặt lại MAC gốc (ARM: down/addr/up `eth1`; MIPS: `br-lan`); đặt lại địa chỉ/route bị mất khi down/up (như T15); neighbor tĩnh theo trạng thái trước; so với bản ghi; kiểm liên kết dịch vụ (200 + hash). Không đạt → dừng các probe còn lại |
| **6. Kết luận** | **ĐẠT:** delta `l2_bad_mac` = số khung có MAC nguồn khác `GUEST_MAC` và khác `TAP_MAC` trong pcap (§3.1); `allow_svc` không tăng; T01 thất bại khi đổi MAC và đạt trước/sau; không có chữ ký trên host. **FAIL:** T01 thành công với MAC giả; có khung từ worker tới MAC giả; delta lệch; chữ ký trên host. **CHƯA KIỂM CHỨNG:** guest không đổi được MAC (không thấy khung MAC giả); gói biên; khôi phục lỗi. **Chưa phủ:** MAC giả **bằng `TAP_MAC`** hoặc MAC multicast làm nguồn: pcap không có cờ hướng nên không tách được khung guest giả `TAP_MAC` với khung worker gửi đi (L5); cần capture riêng chiều vào (D5) |

### T17 — Giả IP nguồn

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Thêm địa chỉ phụ `/32` lên `IF` cho từng nguồn giả. Đặt neighbor tĩnh `arp -s 10.200.0.1 TAP_MAC` trong guest, để kernel guest không phát ARP với `spa` giả (ARP đó sẽ vào `arp_in_drop` và chặn luôn gói IP) [GĐ G10: busybox `arp -s` hoạt động]. Công cụ: `curl --interface <ip> --local-port <p>`, `ping -I <ip>` |
| **2. Gói, đích, mong đợi, điểm chặn** | **P1 (giả nguồn tới dịch vụ được phép):** nguồn `10.200.0.3`, `curl --interface 10.200.0.3 --local-port 31171 http://10.200.0.1:8011/…/get-task/T/file` → **`drop_spoof`**, **không** `allow_svc`. **P2 (giả manager tới dịch vụ được phép):** nguồn `192.168.60.10`, cổng `31172` → `drop_spoof`. Ý nghĩa: middleware API coi nguồn không thuộc `10.200.0.0/30` là "không phải guest" (06B-2B), nên nếu gói giả này tới được `server.py`, guest có thể giả manager gọi `/stop`. **P3 (giả IP của worker) — HOÃN, chưa thực hiện:**

- Cách cũ: thêm `10.200.0.1/32` vào guest rồi gọi `10.200.0.1:8011`. Cách này sai: địa chỉ đó trở thành **địa chỉ cục bộ** của guest, nên kernel guest định tuyến gói qua `lo`, gói **không** đi qua `tap0`, và không có gì để đo.
- Đồng thời gateway `10.200.0.1` của guest cũng thành địa chỉ cục bộ.
- Đề xuất thay thế (chưa làm):
  - (a) gói thô nguồn `10.200.0.1` tạo bằng công cụ, cần D1;
  - (b) nguồn `10.200.0.1` tới một đích **khác** `10.200.0.1` (ví dụ `1.1.1.1:443`), nhưng vì gateway của guest cũng là `10.200.0.1`, hành vi định tuyến của guest khi đó phải kiểm trước [GĐ].
- Cổng `31173` được giữ chỗ.

**P4 (giả nguồn tới đích ngoài):** nguồn `10.200.0.3` tới `1.1.1.1:443`, cổng `31174` → `drop_spoof` (đứng trước `drop_public`). **P5:** `ping -c 3 -s 1705 -I 192.168.60.10 192.168.60.1` → `drop_spoof` +3. Mong đợi chung: không có SYN-ACK/echo reply nào tới guest; log `server.py` không có request từ các nguồn này; không có file `/tmp/sandbox_stop_requested`. `rp_filter=1` trên `tap0` là lớp thứ hai và không có bộ đếm riêng |
| **3. Đối chứng** | P1, P2: T01 từ `10.200.0.2` đạt ngay trước (cùng đích/giao thức/cổng). P4: đối chứng `1.1.1.1:443` sống từ ctl (như 06B-3B). P5: đối chứng `192.168.60.1` ICMP từ ctl/W [GĐ: ICMP echo được trả lời] |
| **4. Chữ ký (gồm chữ ký giả)** | `tap0`: `ether src 52:54:00:c7:00:02 and not src host 10.200.0.2` cộng cổng `31171`–`31174`. Host: `src host 10.200.0.3`; `src host 10.200.0.1`; **`src host 192.168.60.10 and ((tcp src port 31172) or (icmp and ip[2:2] = 1733))`** (`and`/`or` của pcap-filter cùng mức ưu tiên, nên phải đóng ngoặc), vì trên `sandboxnet` có lưu lượng hợp lệ thật từ `192.168.60.10`, nên chữ ký giả phải kèm cổng/kích thước riêng. Gói thoát qua NAT ra `ens33` sẽ mang nguồn `192.168.177.128`, nên trên `ens33` tìm theo cổng `31171`–`31174`, kích thước ICMP và MAC guest. `ens33` bắt không lọc (D7) |
| **5. Khôi phục, liên kết dịch vụ** | Khôi phục theo bản ghi trước (§1.3): xóa từng `/32`. Neighbor `10.200.0.1` **theo trạng thái trước phép thử**: nếu trước đó không có entry tĩnh thì xóa entry `arp -s` đã thêm; nếu trước đó đã có entry tĩnh thì đặt lại đúng MAC cũ (không xóa). So `ip addr`, `ip route`, neighbor tĩnh với bản ghi trước; kiểm liên kết dịch vụ |
| **6. Kết luận** | **ĐẠT:** mỗi probe, delta `drop_spoof` = số khung có nguồn giả trong pcap; `allow_svc` không tăng vì probe; không có phản hồi tới guest; không có request trong log server; đối chứng sống; không có chữ ký trên host. **FAIL:** `allow_svc` tăng bởi gói nguồn giả; có SYN-ACK/phản hồi; server ghi nhận request; chữ ký giả trên host. **CHƯA KIỂM CHỨNG:** guest không gửi được (curl không bind được, ARP với `spa` giả chặn trước); gói biên; đối chứng không sống. **Chưa phủ:** giả nguồn bằng gói thô có MAC hợp lệ nhưng không đi qua stack guest; IP options, phân mảnh |

### T20 — Kết nối từ ngoài vào guest

| Mục | Nội dung |
|---|---|
| **1. Chuẩn bị, công cụ** | Ghi trong guest: `netstat -ltn` (dropbear `:22`; ARM thêm uhttpd `:80`), firewall guest (`iptables -S` ARM / `nft list ruleset` MIPS). W: `python3` của harness; ghi **từng lần gọi** `sendto`/`connect` kèm thời điểm và `errno`. M/ctl: `ip route get` hoặc `/proc/net/route`. H: `ip route get 10.200.0.2` (chỉ đọc). **D3: chỉ tra route trên host/manager, không gửi gói.** D4: container `NET_ADMIN` riêng cho N6 được thiết kế, **chưa chạy** |
| **2. Gói, đích, mong đợi, điểm chặn** | Ba loại dữ liệu được ghi **riêng** và không suy ra nhau:

- (i) số lần **gọi** gửi của công cụ;
- (ii) `errno` của từng lần gọi;
- (iii) delta bộ đếm `drop_out`, là bằng chứng duy nhất cho việc **gói** đã tới hook và bị drop.

**Không** mặc định mỗi lần gọi tạo đúng một gói: một lần gọi có thể không tạo gói (lỗi định tuyến hay neighbor trước hook), hoặc tạo nhiều gói (TCP gửi lại SYN). `EPERM` [GĐ G11] chỉ là dấu hiệu, không thay bộ đếm.

- **N1 (W → guest, ICMP):** W gọi gửi 3 echo tới `10.200.0.2`. Mong đợi `drop_out` > 0. Quan hệ "delta = số lần gọi" chỉ là quan sát, không phải tiêu chí.
- **N2 (W → guest, TCP 22 và 80, cổng nguồn `31201`/`31202`):** `connect()` với thời gian chờ cố định. Kernel coi lỗi từ hook output là lỗi tạm và vẫn gửi lại SYN [Kernel `tcp_connect`], nên số gói không cố định; tiêu chí là delta > 0.
- **N3 (W → guest, UDP, cổng nguồn `31020`):** 3 lần gọi, tiêu chí delta > 0. **N4 (M/ctl):** `ip route get 10.200.0.2` → qua `192.168.60.1` (host), **không** qua `192.168.60.2`. **N5 (H):** `ip route get 10.200.0.2` → qua default route `ens33`, không qua bridge `sandboxnet`. Mong đợi chung: không có khung nào từ worker tới guest ngoài ARP `.1↔.2` và TCP từ cổng 8011 đã thiết lập; guest không nhận kết nối nào |
| **3. Đối chứng** | Dịch vụ guest **sống**: từ chính guest, `nc 10.200.0.2 22` nhận banner `SSH-2.0-dropbear` (cùng IP/giao thức/cổng; điểm duy nhất được phép chạm cổng này). Nếu dropbear không chạy → N2 chỉ là kiểm quy tắc. Tra route N4/N5 là bằng chứng cấu hình, **không** phải đối chứng sống |
| **4. Chữ ký** | `tap0`: mọi khung `ether src TAP_MAC and ether dst 52:54:00:c7:00:02` **không** phải ARP `.1↔.2` hay TCP sport 8011; `dst host 10.200.0.2 and (icmp or tcp dst port 22 or tcp dst port 80 or udp port 31020)`. Host: `dst net 10.200.0.0/30` trên mọi capture (D3: M/H không gửi gói, nên mọi khung như vậy là bất thường); cổng `31020`, `31201`, `31202` |
| **5. Khôi phục, liên kết dịch vụ** | Không đổi cấu hình guest. Kiểm liên kết dịch vụ sau nhóm T20 (xác nhận `drop_out` không ảnh hưởng `allow_out_svc` của phiên đã thiết lập) |
| **6. Kết luận** | **ĐẠT:** delta `drop_out` > 0 trong cửa sổ của probe (bằng chứng bộ đếm); mọi lần gọi đều thất bại và có `errno` được ghi (chỉ là dấu hiệu); không có khung tương ứng trên `tap0`; guest không ghi nhận kết nối; N4/N5 đúng route; đối chứng guest sống. **CHƯA KIỂM CHỨNG (không phải ĐẠT):** delta `drop_out` = 0, vì khi đó không chứng minh được gói đã được tạo ra và tới hook. **FAIL:** thấy khung W→guest ngoài allowlist trên `tap0`; guest nhận được kết nối hoặc trả lời; `allow_out_svc` tăng không có request từ guest. **CHƯA KIỂM CHỨNG:** công cụ phía W không gửi được; dịch vụ guest không sống (với N2); gói biên. **Giới hạn đo:** gói bị `drop_out` bị hủy **trước** điểm bắt của `tap0` [Kernel: tap AF_PACKET nằm trong `dev_queue_xmit`, sau hook output], nên `drop_out` **không đối chiếu được với pcap**. Bằng chứng là bộ đếm cộng với số lần gửi của công cụ, và pcap chỉ dùng để chứng minh *không có* khung đi ra. **Chưa phủ:** N6 (route độc hại `10.200.0.0/30 via 192.168.60.2` từ một container thử có `NET_ADMIN` trong netns riêng): gói tới `eth0` của W, `ip_forward=0` nên bị bỏ ở định tuyến, không qua bộ đếm nào của ta; bằng chứng sẽ là `IpInAddrErrors` của W và việc không có khung trên `tap0` [Kernel `ip_route_input_slow`/`ip_error`]. D4: được thiết kế, chưa chạy. M/H gửi gói thật tới `10.200.0.2`: không làm (D3) |

---

## 3. Harness: tái sử dụng và bổ sung

### 3.1 Tái sử dụng nguyên trạng [Mã]

| Thành phần | Dùng cho |
|---|---|
| `run-06b3b.sh`: container worker thử (image ghim ID), container ctl, manager có khôi phục, capture veth/bridge/`ens33`, cảnh báo rò rỉ, watcher + heartbeat, teardown có hạn, trạng thái host trước/sau, dọn dẹp chỉ những gì lần chạy tạo ra | Mọi phép thử |
| `probe_matrix.Guest.run()` (console có marker, `rc`), `monitor()`, cổng topology, liên kết dịch vụ trước/sau | Mọi phép thử phía guest |
| `counters_read()` có mốc thời gian (đọc đủ 17 bộ đếm, gồm 4 bộ đếm ARP), `counters-raw.jsonl` | Mọi phép thử |
| `counter_window.reconcile/validate`, `determined_failures`, `probe_verdict`, `run_outcome` | Mọi phép thử, sau khi mở rộng lớp |
| Phép đo toàn phiên (`session_reconcile`, quét QEMU, F1/F2) | Giữ nguyên, báo riêng |
| `sigscan.sh`, `independent_check.sh`, `pcapng_stats.py`, `selftest.sh` + `mutation_test.sh` (khung baseline/phân loại) | Mở rộng chữ ký và ca thử |

### 3.2 Ánh xạ bộ đếm ARP (cần bổ sung trước T14/T15)

*(Cập nhật 06B-4IR1; phân biệt ba mức:)*

- **Baseline lịch sử (06B-4A):** harness ghi các bộ đếm ARP là "no pcap mapping" (`NOT_COMPARED_REASON`), và `probe_matrix.classify()` trả `"arp"` cho mọi ARP. Hai chỗ này vẫn còn trong `counter_window.py`/`probe_matrix.py` và chỉ dùng cho đo toàn phiên.
- **Mapping offline (06B-4B, `l2frames.py`):** ánh xạ dưới đây đã viết và kiểm bằng fixture/đột biến. Bộ đánh giá ARP (`arp_cases.py`) và phần nối 06B-4I/4IR1 dùng mapping này.
- **Mapping trên kernel/nft thật:** **chưa kiểm**. Mọi giả định [Kernel] bên dưới chưa được xác nhận bằng lần chạy guest nào.

**Ánh xạ đề xuất** cho một khung ARP trên `tap0` có MAC nguồn bằng `GUEST_MAC` (khung có MAC nguồn khác đã dừng ở `l2_bad_mac`):

1. **Không tới hook ARP, không có bộ đếm** [Kernel `arp_rcv`: kiểm `IFF_NOARP`, `PACKET_OTHERHOST`/`PACKET_LOOPBACK`, độ dài header, `ar_hln == dev->addr_len`, `ar_pln == 4` **trước** `NF_HOOK(NFPROTO_ARP, NF_ARP_IN)`]:
   - MAC đích không phải `TAP_MAC`, broadcast hay multicast (`PACKET_OTHERHOST`);
   - `hlen ≠ 6` hoặc `plen ≠ 4`, hoặc khung ngắn hơn header ARP đầy đủ.
   - Các khung này được ghi lớp riêng **`arp_not_hooked`**, không gộp vào `arp_in_drop`.
2. **`arp_in_ok`:** htype 1, ptype `0x0800`, `sha = GUEST_MAC`, `spa = 10.200.0.2`, `tpa = 10.200.0.1`, opcode 1 hoặc 2.
3. **`arp_in_drop`:** mọi ARP còn lại đã tới hook, gồm `sha` khác MAC nguồn Ethernet, gratuitous, `tpa`/`spa` khác, opcode khác.

**Chiều worker → guest:**

- `arp_out_ok` = khung ARP trên `tap0` có `src = TAP_MAC`, `spa = 10.200.0.1`, `tpa = 10.200.0.2`, opcode 1 hoặc 2.
- `arp_out_drop`: **không quan sát được** trên `tap0`, vì khung bị drop ở `NF_ARP_OUT` trước `dev_queue_xmit` [Kernel `arp_xmit`]. Chỉ là bằng chứng bộ đếm, mong đợi 0.

**Trường tshark cần thêm** vào `guest_frames()`:

- `eth.dst`;
- `arp.opcode`, `arp.hw.type`, `arp.proto.type`, `arp.hw.size`, `arp.proto.size`;
- `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4`;
- độ dài khung.

**Kiểm ánh xạ:**

- **Offline:** fixture cho từng nhánh (ok, drop theo từng trường, gratuitous, not-hooked do MAC đích, do `hlen`), cùng các đột biến tương ứng (đảo `tpa`, bỏ kiểm `sha`, gộp `not_hooked` vào `drop`…).
- **Tích hợp:**
  - đưa `arp_in_ok`/`arp_in_drop` vào `classes_compared` của phép đo toàn phiên **sau khi** fixture đạt;
  - số liệu 06B-3G (2 khung ARP guest = delta `arp_in_ok` 2 mỗi kiến trúc) chỉ là ủng hộ yếu ở mức tổng.
- Lớp `arp_not_hooked` > 0 ở T14/T15 là dấu hiệu probe gửi sai địa chỉ, nên probe được ghi **CHƯA KIỂM CHỨNG**, không ghi ĐẠT.

**06B-4B:** ánh xạ trên đã được viết trong `l2frames.py` (bản harness mới) cùng fixture và đột biến. Phát lại trên pcap 06B-3G: 2 khung `arp_in_ok` = delta 2, 2 khung `arp_out_ok` = delta 2, 0 `arp_in_drop` ở mỗi kiến trúc. Giả định [Kernel] vẫn **chưa kiểm thực tế**.

### 3.3 Các bổ sung khác (trạng thái sau 06B-4B)

| # | Bổ sung | Lý do |
|---|---|---|
| — | **Trạng thái 06B-4B:** H1, H3, H6, H7, H9 và khung lưu/khôi phục của H4 **đã chuẩn bị offline** (`l2frames.py`, `signatures.py`, `sigscan_l2.py`, `guest_state.py`, run script). H7 làm thành `sigscan_l2.py` riêng; `sigscan.sh` giữ nguyên. H2 hoãn (D5). H5, H8, H10 chưa làm vì gắn với probe | — |
| H1 | `classify()`: khung có MAC nguồn khác `GUEST_MAC` **và** khác `TAP_MAC` → `l2_bad_mac`; khung có nguồn `TAP_MAC` → chiều ra. `TAP_MAC` đọc từ netns của lần chạy | L5; T16 |
| H2 | Tùy chọn (D5): thêm một tshark/dumpcap **chỉ chiều vào** trên `tap0` (`-f inbound`, nếu libpcap trong container hỗ trợ [GĐ G12]) để tách khung guest giả `TAP_MAC` | T16 biến thể |
| H3 | Lớp IPv6: tách khung IPv6 (`eth.type 0x86dd`) với `icmpv6.type`, `ipv6.dst`, `ipv6.plen` để nhận diện probe so với nền MLD/RS/DHCPv6 | T13 |
| H4 | Bước **thay đổi trạng thái guest** có cấu trúc: ghi trước → áp dụng → probe → khôi phục → so sánh với bản ghi → liên kết dịch vụ; lỗi khôi phục → dừng các probe còn lại, ghi CHƯA KIỂM CHỨNG | T14–T17 |
| H5 | Probe phía worker (T20) chạy trong container worker thử bằng Python: đếm số lần gửi, ghi `errno`; đối chiếu `drop_out` với số lần gửi, không với pcap | T20 |
| H6 | Mở rộng bộ lọc capture `ens33` và cảnh báo: `ether host 52:54:00:de:ad:01`, `ip6 and ether src 52:54:00:c7:00:02`, `arp and ether src 52:54:00:c7:00:02`, `src host 10.200.0.3`, cổng probe (§2.0), ICMP theo kích thước riêng. D7: `ens33` bắt không lọc, có giới hạn | L6 |
| H7 | `sigscan.sh`: thêm các chữ ký ở §2 (gồm chữ ký giả), có fixture dương cho từng chữ ký như 06B-3C | Mọi phép thử |
| H8 | Kiểm công cụ lúc chạy: `busybox --list`, `ping` broadcast, `nc -u`, `arp -s`, `ip route add … dev`, `ip link set address`; thiếu → probe CHƯA KIỂM CHỨNG (TOOL), không ĐẠT | G1–G10 |
| H9 | Nhãn kết luận "ĐẠT (kiểm quy tắc)" cho probe không có đối chứng sống; không làm đổi thứ tự ưu tiên | §1.3, D6 |
| H10 | Đọc thêm trạng thái neighbor của worker (`ip -j neigh show dev tap0/eth0`) trước/sau mỗi probe ARP/MAC/IP giả | T14–T17 |

---

## 4. Các mục còn thiếu khác (chỉ liệt kê, chưa triển khai)

### 4.1 IPv4

| Mục | Hiện trạng | Còn thiếu |
|---|---|---|
| Probe chưa quyết định ở 06B-3G | MIPS `ssh-host-192.168.60.1` CHƯA KIỂM CHỨNG (gói biên) | Reviewer quyết định cách xử lý gói biên (đo độ trễ capture → bộ đếm, giảm lưu lượng nền…). Không chạy lại chỉ để tìm exit 0 |
| T05 | `1.1.1.1:443/tcp` ĐẠT | `8.8.8.8:53` UDP có đối chứng; ICMP tới IP công cộng |
| T06 | `192.168.177.2:53` UDP/TCP ĐẠT | ICMP tới `192.168.177.2`; một IP LAN thứ hai (không có máy → kiểm quy tắc) |
| T11 | `10.200.0.1:18080` ĐẠT (có listener tạm) | `10.200.0.1:22`, `:80`, ICMP echo |
| T01/T02 trong luồng thật | Đạt qua harness ở 06B-3A (poller sentinel, verify của harness) | Chạy trong luồng phân tích thật (poller thật, phase 1/phase 2) |
| T18 | Chưa (poller là sentinel) | Poller thật → manager `get-file` |
| T19 | Container ctl gọi `192.168.60.2:8011` sống | Gọi từ chính container manager |
| T21 | Trạng thái host trước/sau mỗi lần chạy: các check hard không đổi | Phiên SSH được giữ liên tục khi khởi động worker thật bằng Compose |
| Ngoài ma trận thiết kế (đề xuất, cần duyệt) | — | UDP tới `10.200.0.1:8011` (mong đợi `drop_worker_other`); IPv4 phân mảnh tới dịch vụ được phép; IP options; TTL = 1 |

### 4.2 Fail-closed và verify

| Mục | Hiện trạng | Còn thiếu |
|---|---|---|
| F1 | `guest.nft` lỗi cú pháp → exit 1 [KC 06B-2A] | Thiếu binary `nft` |
| F2 | `ALLOW_VM_INTERNET=true` → exit 1 [KC 06B-2A] | — |
| F3 | Chưa | V1 trong luồng thật: xóa/sửa rule, `ip_forward=1`, xóa neighbor permanent khi worker rảnh → task FAILED, không có QEMU |
| F4 | Chưa | V2: hỏng cấu hình giữa phase 1 và 2 (hook kiểm thử) |
| F5 | Netns bị hủy sau `stop`/`rm` [KC 06B-2A] | Restart container: netns mới, V0 đạt lại (A14) |
| F6 | Đột biến cấu trúc bị phát hiện trong selftest nft [KC 06B-1] | Ruleset "đúng nhưng khác expected" tại V0/V1 trong worker thật |
| A7, A15 | Hai guest tuần tự trong một lần chạy, verify sau mỗi guest OK [KC 06B-3G] | Nhiều tác vụ liên tiếp trong luồng thật |
| §6.1a | Chỉ đối chiếu ba bảng CT-01 | Phát hiện base chain lạ ngoài bảng CT-01 (đề xuất, cần duyệt) |
| Mất luật khi guest đang chạy | Ngoài phạm vi 06B (thiết kế §6.2, §10) | Watchdog (đề xuất) |

---

## 5. Giả định cần kiểm và quyết định cần reviewer

### 5.1 Giả định mới

| ID | Giả định | Cách kiểm |
|---|---|---|
| G1 | `ping` của busybox bật `SO_BROADCAST` (gửi được tới `255.255.255.255`, `10.200.0.3`) | Lúc chạy: có khung trong pcap hay lỗi cục bộ |
| G2 | Gửi tới `224.0.0.1` đi theo default route qua `IF` | pcap |
| G3 | `nslookup` gửi được tới server multicast | pcap |
| G4 | `nc -u` có trong busybox của hai ảnh | `nc --help` / `busybox --list` |
| G5 | Số NS cho một đích không phân giải được (thường 3) | pcap; chỉ dùng làm quan sát, tiêu chí là delta = số khung |
| G6 | `ip tunnel` (sit) có trong busybox/kernel guest | Lúc chạy |
| G7 | Số ARP request cho một đích on-link không trả lời (`mcast_solicit`) | pcap; tiêu chí vẫn là delta = số khung |
| G8 | netifd phản ứng với down/up `IF` (chạy lại DHCP, có thể đổi địa chỉ/route) | So `ip addr`/`ip route` sau khôi phục |
| G9 | Trên MIPS, đổi MAC `br-lan` làm khung ra `tap0` mang MAC mới | pcap |
| G10 | Busybox `arp -s` tạo được neighbor tĩnh | `arp -a` |
| G11 | Drop ở hook output trả `EPERM` cho `sendto`/`connect` trong W | `errno` do Python ghi |
| G12 | libpcap trong container worker hỗ trợ bộ lọc hướng `inbound` trên `tap0` | Thử trên lưu lượng đã biết, trước khi dùng |

### 5.2 Quyết định của reviewer (06B-4B)

| ID | Quyết định |
|---|---|
| D1 | **Chưa nạp công cụ mới.** ARP reply giả, gratuitous dạng reply, T17-P3 kiểu gói thô: chưa phủ |
| D2 | **Cho phép** thay đổi guest tạm thời, có khôi phục theo bản ghi trước (§1.3, `guest_state.py`) |
| D3 | **Chỉ tra route** trên host/manager; không gửi gói tới `10.200.0.2` |
| D4 | Được **thiết kế** container `NET_ADMIN` riêng cho N6, **chưa chạy** |
| D5 | **Hoãn** trường hợp giả MAC bằng `TAP_MAC`; không tuyên bố phủ |
| D6 | Dùng nhãn **"ĐẠT (kiểm quy tắc)"** |
| D7 | `ens33` **bắt không lọc, có giới hạn** |

Câu hỏi gốc ở 06B-4A:

| ID | Câu hỏi |
|---|---|
| D1 | Có cho phép nạp một công cụ tạo ARP (ví dụ `iputils-arping` chính thức của OpenWrt, ghi hash) vào guest qua đường dịch vụ được phép không? Nếu không, ARP reply giả và gratuitous dạng reply ghi là **chưa phủ** |
| D2 | Có cho phép harness đổi cấu hình guest (MAC, địa chỉ phụ, route, `arp_notify`, neighbor tĩnh) với quy tắc khôi phục ở §1.3/H4 không? |
| D3 | T20 từ M/H: chỉ tra route (mặc định), hay gửi một gói đánh dấu với TTL = 1 (dừng ở host; cảnh báo phải có ngoại lệ theo chữ ký)? |
| D4 | T20 N6: có cho phép một container thử có `NET_ADMIN` trên `sandboxnet` (chỉ đổi route trong netns của nó) không? |
| D5 | Có thêm capture chiều vào trên `tap0` để phủ MAC giả bằng `TAP_MAC` không? |
| D6 | Nhãn "ĐẠT (kiểm quy tắc)" cho probe không có đối chứng sống |
| D7 | Mở rộng bộ lọc `ens33` theo chữ ký (H6), hay bắt `ens33` không lọc (lớn hơn, có lưu lượng LAN khác)? |

---

## 6. Trình tự đề xuất cho các nhiệm vụ sau

1. **Offline:** H1, H3, ánh xạ ARP §3.2 cùng fixture và đột biến; H6, H7 cùng fixture chữ ký; H4, H9 — **đã làm ở 06B-4B**. H8, H10 làm cùng với probe.
2. **Tích hợp, một lần:** T12, T13, T20 (không đổi cấu hình guest), ARM rồi MIPS. *Cập nhật 06B-4G:* 5 ca T12–T13 đã chạy một lần (06B-4G, exit 4); T20, B3, I3 chưa viết.
3. **Sau review bước 2:** T14, T17 (đổi route/địa chỉ, có khôi phục).
4. **Sau review bước 3:** T15 mức 1, T16; T15 mức 2 chỉ khi có D1.
5. Các mục §4 theo quyết định của reviewer.

Mỗi bước dừng sau một lần chạy, giữ guard 20 ms, bàn giao trước khi sang bước sau.

## 7. Hạn chế của kế hoạch

- Danh mục công cụ guest là **đọc tĩnh** từ file ảnh. Danh sách applet BusyBox dựa trên chuỗi trong binary: là bằng chứng tĩnh, **không thay thế** việc xác nhận công cụ khi guest chạy (`busybox --list`, `command -v`, và thấy khung probe trong pcap).
- Các khẳng định [Kernel] đọc từ mã upstream v6.8, chưa kiểm trên kernel `6.8.0-146` của host: thứ tự kiểm trong `arp_rcv`, vị trí điểm bắt so với hook output, gửi lại SYN, `IpInAddrErrors`, gratuitous ARP cho mọi địa chỉ.
- Số khung mong đợi (3 echo, 3 ARP, 3 NS…) chỉ để định hướng. Tiêu chí luôn là **delta = số khung thực tế trong pcap**, hoặc số lần gửi do công cụ ghi lại khi pcap không quan sát được (T20).
- Guard 20 ms vẫn là giả định chưa đo. Lưu lượng nền và phép thử đổi trạng thái link (T15, T16) làm tăng khả năng gói biên, tức tăng khả năng CHƯA KIỂM CHỨNG.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
