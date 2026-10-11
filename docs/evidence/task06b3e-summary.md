# Minh chứng Nhiệm vụ 06B-3E: kiểm chứng TÍCH HỢP harness 06B-3DR1 (07/10/2026)

> **Loại bằng chứng: tích hợp thật.** Dùng Docker thật, worker và manager thật, guest ARM/MIPS thật, capture thật trên `tap0` và phía host. Bằng chứng offline của harness này: [`task06b3dr1-summary.md`](task06b3dr1-summary.md).

**Phạm vi:**

- Chạy **một lần** đúng ma trận 20 probe IPv4 của 06B-3B, ARM rồi MIPS, bằng harness 06B-3DR1.
- Guard giữ nguyên 20 ms. Không thêm probe, ELF hay mẫu malware.
- Không build image, không sửa source cô lập, firewall hay sysctl.
- **Không chạy lại.**

**Kết quả: `exit=4` (NOT PASSED: chưa kiểm chứng).**

- **16/20 probe ĐẠT; 4/20 CHƯA KIỂM CHỨNG** vì có gói ở biên cửa sổ bộ đếm.
- **Không có check nào FAIL. Không có mục capture chưa giải thích.**
- Không thấy chữ ký probe nào trong các pcap đã lưu phía host, và cảnh báo `-i any` bắt 0 gói.
- Theo quy tắc của harness, lần chạy **không đạt**.

## 1. Trước khi chạy

| Kiểm tra | Kết quả |
|---|---|
| Working tree | tree `ecf2ae7d…` (bàn giao 06B-3DR1), HEAD `3c54d55` |
| Harness | 12/12 hash khớp bàn giao 06B-3DR1; bản sao trong lần chạy cũng khớp ([`run1/harness-sha256.txt`](task06b3e/run1/harness-sha256.txt)) |
| Image ID | `sha256:1ab784c7…9153`, đúng ID đầy đủ (harness kiểm) |
| `out` cũ | không có; các thư mục cũ giữ nguyên. Lần chạy này được đổi tên thành `ct01-06b3c/out-06b3e-run1`, bản sao ở [`task06b3e/run1/`](task06b3e/run1/) |
| Self-test | user thường: 143/143 ([log](task06b3e/side/selftest-pre-run-user.log)). Trong harness, dưới root, trước khi tác động container: `SELFTEST: ALL PASSED` ([log](task06b3e/run1/selftest.txt)) |

## 2. Ma trận và đối chiếu bộ đếm

Log: [`run1/run.log`](task06b3e/run1/run.log) (`07747626…2488`).

Ma trận: [ARM](task06b3e/run1/container/probe/ARM/matrix.md), [MIPS](task06b3e/run1/container/probe/MIPS/matrix.md); JSON có đầy đủ vùng, delta, gói chắc chắn và gói biên theo lớp. Dữ liệu thô các lần đọc nft: [ARM](task06b3e/run1/container/probe/ARM/counters-raw.jsonl), [MIPS](task06b3e/run1/container/probe/MIPS/counters-raw.jsonl).

| | ARM | MIPS |
|---|---|---|
| Cổng topology, liên kết dịch vụ trước và sau | đạt | đạt |
| ĐẠT | 8/10 | 8/10 |
| CHƯA KIỂM CHỨNG (gói biên) | `ssh-host-172.18.0.1`, `manager` | `internet-tcp`, `lan-dns-tcp` |
| FAIL / LỖI PHÉP ĐO | 0 / 0 | 0 / 0 |
| `determined_failures` | rỗng ở mọi probe | rỗng ở mọi probe |
| Thời gian một lần đọc nft (20 lần mỗi kiến trúc) | 4,8 – 14,0 ms, trung vị 10,2 | 5,0 – 18,4 ms, trung vị 10,4 |

Ở mọi probe, gói của chính probe đều nằm trong vùng chắc chắn: ARM 3 SYN mỗi probe, MIPS 4 SYN mỗi probe, UDP 4 gói. Kết quả này được xác minh sau lần chạy bằng tcpdump: [`side/probe-frames-zone-check.txt`](task06b3e/side/probe-frames-zone-check.txt). Ở cả 4 probe CHƯA KIỂM CHỨNG, **lớp dự kiến** của probe đối chiếu khớp chính xác; gói biên chỉ nằm ở lớp nền khác. Đây là quan sát, không làm thay đổi kết luận CHƯA KIỂM CHỨNG.

### Bốn probe CHƯA KIỂM CHỨNG: gói biên

Chi tiết: [`side/edge-analysis.txt`](task06b3e/side/edge-analysis.txt).

| Probe | Lớp | Delta / chắc chắn / tính cả biên | Gói biên | Vị trí |
|---|---|---|---|---|
| ARM `ssh-host-172.18.0.1` | `drop_spoof` | 2 / 1 / 2 | DHCP `0.0.0.0:68 → 255.255.255.255:67` lúc `…264.966677` | **bên trong** lần đọc B |
| ARM `manager` (probe kế tiếp) | `drop_spoof` | 1 / 1 / 2 | **cùng gói DHCP đó** | trong guard, 15,8 ms trước lần đọc A |
| MIPS `internet-tcp` | `l2_bad_ethertype` | 2 / 2 / 3 | IPv6 MLD `→ ff02::16` lúc `…316.841918` | trong guard, 4,6 ms trước lần đọc A |
| MIPS `lan-dns-tcp` | `drop_public` | 6 / 5 / 6 | DNS nền của guest `→ 8.8.8.8:53` (`AAAA? 3.openwrt.pool.ntp.org`) lúc `…333.374486` | trong guard, 19,4 ms trước lần đọc B |

- Cả 4 gói biên đều là **lưu lượng nền của guest**, và đều thuộc lớp bị drop.
- Ở cả 4 probe, delta nằm **trong** khoảng `[chắc chắn, chắc chắn + biên]`, nên không có lệch thật.
- **Quan sát:** gói DHCP của ARM rơi vào biên của hai probe liền nhau. Delta của probe trước ứng với trường hợp gói được tính, delta của probe sau ứng với trường hợp không được tính, tức gói được tính đúng một lần. Harness **không** dùng suy luận chéo giữa các probe này để chuyển kết quả thành PASS, và tài liệu này cũng không dùng nó làm kết luận.

**Giả định còn nguyên:** mọi kết quả ĐẠT của phép đối chiếu phụ thuộc giả định rằng độ trễ giữa timestamp capture và lúc gói chạm bộ đếm nằm trong guard 20 ms. Giả định này **chưa được đo**. Lần chạy chỉ đo được thời gian của lệnh nft (4,8–18,4 ms), không đo được độ trễ đó.

## 3. Capture, heartbeat, đối chứng

- **Phiên bản:** tcpdump 4.99.4, libpcap 1.10.4 (TPACKET_V3) ([`versions.txt`](task06b3e/run1/hostcap/versions.txt)); tshark 3.6.2 trong container.
- **Thống kê tcpdump** ([`capture-stats.tsv`](task06b3e/run1/hostcap/capture-stats.tsv)): captured = received by filter ở cả 4 capture (veth 3822, bridge 7444, `ens33` 93, cảnh báo 0); dropped by kernel = 0. **Không có mục mở.**
- **Teardown** ([`teardown-timeline.txt`](task06b3e/run1/hostcap/teardown-timeline.txt)):
  - guest xong lúc 05:36:14.716 → dừng container đối chứng lúc 14.999 (rc 0);
  - hết thời gian chờ 3 s lúc 18.010 → dừng bộ giám sát lúc 18.037;
  - SIGINT gửi lúc 18.040–18.046 → 4 capture thoát với rc 0 lúc 18.064–18.115, đều trước hạn 10 s.
- **ISB `tap0`:** ARM 83/0, MIPS 125/0, ĐẠT.
- **Heartbeat** (bộ ghi mẫu chỉ đọc, không thuộc harness, [`heartbeat-samples.tsv`](task06b3e/side/heartbeat-samples.tsv)):
  - ARM 75 mẫu, tuổi tối đa 1,05 s; MIPS 83 mẫu, tối đa 1,06 s;
  - khoảng cách lớn nhất giữa hai giá trị liên tiếp 1,06 s;
  - không có marker, không có zombie.
  - Trong harness: bộ giám sát còn sống và heartbeat còn mới ở mọi mốc kiểm; không có `CaptureLost`.
- **Chữ ký** ([`side/independent-check.txt`](task06b3e/side/independent-check.txt)):
  - veth, bridge và `ens33` có 0 ở mọi chữ ký (MAC/IP guest, cổng probe, tên DNS probe, URL probe), trong khi bộ tìm vẫn thấy DNS đối chứng (8 gói);
  - trên `tap0`: tên DNS probe có 4 gói mỗi kiến trúc; 0 gói trả về guest.
  - Phạm vi: chỉ các gói đã được ghi (ở lần này captured = received by filter).
- **Đối chứng:** mỗi đích 326 lần kiểm. Chỉ có 1 lần lỗi: `mongo` lúc 05:33:27, khi container đối chứng vừa khởi động, trước khi nối `dbnet`.

## 4. Netns, manager, dọn dẹp, host

- **Netns của worker:**
  - `eth0 lo tap0` cả trước và sau; địa chỉ và route bảng main không đổi.
  - Khác biệt được báo cáo, giống 06B-3D:
    - `tap0` `vnet_hdr off → on` (quan sát, chưa kết luận);
    - 3 neighbor `REACHABLE` trên `eth0`, do đối chứng tạo ra.
- **Manager:**
  - trước: `exited`, ID `494ae3d2e2eb`;
  - bật bằng `compose up --no-recreate`, xác nhận cùng container;
  - sau: `exited`, **cùng ID** ([`manager-restore.txt`](task06b3e/run1/manager-restore.txt)).
  - `StartedAt` đổi là đúng, vì lần chạy này đã bật manager. Nhánh "ban đầu đang chạy" chưa được kiểm tích hợp.
- **Dọn dẹp:**
  - đã xóa đúng 2 container do lần chạy tạo (`c34c3d7c…`, `3e084b8f…`);
  - không còn QEMU hay tiến trình capture; thư mục capture tạm đã bị xóa;
  - ruleset tại runtime giống hệt expected.
- **Host:** các check hard (sysctl, nft, route, cổng, QEMU, capture, `tap0` của host) đều không đổi. Ba khác biệt được báo cáo, không phải check hard:
  - `docker-ps`: chuỗi thời gian của manager;
  - `ip-addr` và `ip6-route`: bridge `sandboxnet` (`br-1d86fe3e8bbe`) có thêm IPv6 link-local `fe80::74f6:e0ff:feb4:bf8c/64` và route `fe80::/64 … linkdown`. Host đã khởi động lại khoảng 2 giờ trước lần chạy (mongo "Up 2 hours"), và trước lần chạy bridge không có địa chỉ IPv6. Hiện tượng giống 06B-2A và 06B-3A lần 1. Harness không cấu hình IPv6 trên host;
  - `lsmod-net`: thêm `nft_ct`, giống 06B-2A. Đây là module của kernel host, được nạp khi ruleset trong netns worker cần.
  - Cả ba khác biệt đều được ghi lại, không coi là bình thường mặc nhiên.

## 5. Kết luận theo phạm vi

- Tích hợp harness 06B-3DR1 **chạy đúng thiết kế**:
  - đọc bộ đếm có mốc thời gian;
  - phân vùng gói;
  - CHƯA KIỂM CHỨNG khi có gói biên, kèm danh sách gói;
  - teardown có thời hạn;
  - thống kê đầy đủ.
- **Ma trận 20 probe chưa được kiểm chứng trọn vẹn** trong lần chạy này: 4 probe không quyết định được. Lần chạy không đạt (exit 4).
- **Không có lệch thật nào** giữa bộ đếm và pcap. Không có FAIL đã xác định. Không thấy chữ ký probe trong các pcap đã lưu phía host.
- **Với nền khoảng 1–2 gói/s:** tỷ lệ gói biên quan sát được là 4/20 probe. Cách giảm tỷ lệ này (chẳng hạn giảm lưu lượng nền, hoặc đo độ trễ để có cơ sở chọn guard) cần reviewer quyết định. **Không** được tự tăng guard hay chạy lại để tìm PASS.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
