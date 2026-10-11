# Minh chứng Nhiệm vụ 06B-3D: kiểm chứng TÍCH HỢP harness 06B-3CR (06/10/2026)

> **Loại bằng chứng: tích hợp thật.** Dùng Docker thật, worker và manager thật, guest ARM/MIPS thật, capture thật trên `tap0` và phía host. Bằng chứng offline của chính harness này nằm ở [`task06b3c-summary.md`](task06b3c-summary.md).

**Phạm vi:**

- Chạy lại **đúng 20 probe IPv4 của 06B-3B** bằng harness 06B-3CR (`/home/dathq/projects/ct01-06b3c/`).
- Không có probe mới, ELF hay mẫu malware.
- Không sửa source, firewall hay sysctl; không build lại image.

**Kết quả: `exit=1`, 1 check FAIL.** 19/20 probe ĐẠT. Probe Internet của MIPS FAIL; giả thuyết là lỗi biên cửa sổ thời gian của harness (§3). **Không thấy chữ ký probe nào trong các pcap đã lưu phía host**, và cảnh báo `-i any` bắt 0 gói (§2).

> **Ghi chú 06B-3DR (07/10/2026):** sau review, phần diễn đạt của summary này được sửa cho đúng phạm vi bằng chứng (§3, §4, netns, câu kết luận về host). Pcap, log và các file phân tích gốc giữ nguyên. Harness đã sửa phép đo theo [`task06b3dr-summary.md`](task06b3dr-summary.md); lần chạy này **không** được chạy lại.

## 1. Trước khi chạy

| Kiểm tra | Kết quả |
|---|---|
| Working tree | tree `e347ac05…` (HEAD `3c54d55`), không đổi |
| Harness | đủ 11 file khớp `harness-sha256.txt` của 06B-3CR; bản sao trong [`run1/harness-copy/`](task06b3d/run1/harness-copy/) |
| Image ID | kiểm trong harness: `sha256:1ab784c7…9153`, đúng ID đầy đủ |
| Thư mục `out` | chưa có trước khi chạy. Sau khi chạy được đổi tên thành `ct01-06b3c/out-06b3d-run1` (không xóa); bản sao ở [`task06b3d/run1/`](task06b3d/run1/) |
| Self-test | user thường: 68/68 ([log](task06b3d/side/selftest-pre-run-user.log)). Trong harness, dưới root, **trước khi tác động container**: `SELFTEST: ALL PASSED` ([log](task06b3d/run1/selftest.txt)) |
| Dọn trước khi chạy | file lạc `ct01-06b3c/0.2` là heartbeat do lần chạy self-test cũ ở 06B-3CR để lại. Đã chuyển ra ngoài, không xóa; file này không nằm trong danh sách hash |

## 2. Bằng chứng thu được

Log đầy đủ: [`run1/run.log`](task06b3d/run1/run.log) (`aa6d4712…d9f`).

### Heartbeat và capture

- **Bộ ghi mẫu bên ngoài** ([`side/hb_sampler.py`](task06b3d/side/hb_sampler.py), `30c422b9…275c`):
  - chỉ đọc, chạy dưới user thường; **không thuộc harness**;
  - mỗi giây ghi một mẫu vào [`heartbeat-samples.tsv`](task06b3d/side/heartbeat-samples.tsv) (`b12d498f…590e`).

| Giai đoạn | Số mẫu | Tuổi heartbeat lớn nhất | Marker | Tiến trình |
|---|---|---|---|---|
| ARM (16:42:16–16:43:32) | 75 | **1,03 s** | không có | luôn đủ 4 tcpdump; tshark, dumpcap, `qemu-system-arm`; không có zombie |
| MIPS (16:43:33–16:44:55) | 82 | **1,05 s** | không có | luôn đủ 4 tcpdump; tshark, dumpcap, `qemu-system-mips`; không có zombie |
| Sau khi bộ giám sát dừng (bước 7–8) | 5 | tăng lên 5,14 s | — | đúng thiết kế: heartbeat ngừng được cập nhật |

- Có 153 giá trị heartbeat khác nhau; khoảng cách lớn nhất giữa hai giá trị liên tiếp là 1,08 s.
- Trong harness: bộ giám sát còn sống và heartbeat còn mới ở các mốc trước boot, trước ARM, trước MIPS và cuối run. `probe_matrix.py` kiểm trước và sau mỗi probe; mỗi kiến trúc đều ghi `all planned probes executed with captures alive` (10/10), không có `CaptureLost`.
- **tcpdump phía host:**
  - cả 4 tiến trình thoát với mã 0 ([`tcpdump-exit.txt`](task06b3d/run1/hostcap/tcpdump-exit.txt)), đều in thống kê, đều `0 packets dropped by kernel`;
  - không tiến trình nào chết giữa chừng; marker rỗng.
- **Phát hiện mới (§4):** veth và bridge có "received by filter" lớn hơn "captured"; chênh lệch **chưa được giải thích**.

### `pcapng_stats.py` trong container thật

- tshark trong image: `TShark (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)`.
- **ARM:** ISB `isb_ifrecv=99`, `isb_ifdrop=0`, 99 gói đã lưu → ĐẠT.
- **MIPS:** ISB 125/0, 125 gói đã lưu → ĐẠT.
- Mỗi kiến trúc đã ghi check `tap0 capture drop statistics (pcapng ISB from dumpcap): present and 0 dropped`.

### Ma trận 20 probe

| | ARM | MIPS |
|---|---|---|
| Cổng topology | đạt (`eth1`, MAC đã ghim) | đạt (`br-lan`, MAC đã ghim) |
| Liên kết dịch vụ trước và sau | 200, hash khớp | 200, hash khớp |
| Probe ĐẠT | **10/10** | **9/10**: `internet-tcp` FAIL (§3) |
| Check của `probe_matrix` | 27/27 | 26/27 |

Ma trận: [ARM](task06b3d/run1/container/probe/ARM/matrix.md), [MIPS](task06b3d/run1/container/probe/MIPS/matrix.md). Số gói của từng probe giống 06B-3B: ARM 3 gói, MIPS 4 gói, UDP 4 gói.

### Chữ ký trên `tap0` và phía host

Kiểm tra độc lập: [`side/independent-check.txt`](task06b3d/side/independent-check.txt).

| Capture | Tổng gói | MAC/IP guest | Cổng probe | Tên DNS probe | URL probe | DNS đối chứng |
|---|---|---|---|---|---|---|
| `tap0` ARM | 99 | 99 | 27 | 4 | 0* | 0 |
| `tap0` MIPS | 125 | 125 | 36 | 4 | 0* | 0 |
| veth của worker | 3837 | **0** | **0** | **0** | **0** | 8 |
| bridge `sandboxnet` | 7438 | **0** | **0** | **0** | **0** | 8 |
| `ens33` | 94 | **0** | **0** | **0** | **0** | 8 |

\* Kết nối TCP không bao giờ được thiết lập, nên request HTTP không được gửi.

- Cảnh báo `-i any 'net 10.200.0.0/30'`: 0 gói.
- **Phạm vi:** các số 0 phía host chỉ nói về những gói **đã được ghi** vào pcap. Các gói mà tcpdump báo "received by filter" nhưng không ghi (§4) thì không xem được.
- Trên `tap0`: mọi probe đi từ đúng cổng nguồn; 0 gói trả về guest; 0 gói IPv4 tới guest từ nguồn khác `10.200.0.1`.
- Log đối chứng: mỗi đích có 327 lần kiểm. Chỉ có 1 lần lỗi: `mongo` lúc 16:42:09, khi container đối chứng vừa khởi động, trước khi nối `dbnet`.

### Netns của worker

Bản ghi: [trước](task06b3d/run1/container/netns-before.txt), [sau](task06b3d/run1/container/netns-after.txt), [diff](task06b3d/run1/container/netns-diff.txt).

- Interface là `eth0 lo tap0` cả trước và sau. Địa chỉ và route bảng main không đổi (check hard đạt).
- **Khác biệt** (đã báo cáo, không phải check hard):
  - `tap0`: `vnet_hdr off` → `on`. **Đây là quan sát**, chưa kết luận là lỗi. Giả thuyết (chưa kiểm): QEMU bật cờ khi mở tap và cờ còn lại sau khi QEMU thoát. Verify hiện không kiểm cờ này.
  - Thêm 3 neighbor `REACHABLE` trên `eth0` (`192.168.60.1`, `.3`, `.10`), do các đối chứng của worker tạo ra.
  - Neighbor permanent của guest không đổi.

### Manager và dọn dẹp

- **Manager:**
  - trước khi chạy: `exited`, ID `494ae3d2e2eb`;
  - harness bật bằng `compose up --no-recreate`; xác nhận cùng container;
  - sau khi chạy: `exited`, **cùng ID `494ae3d2e2eb`** ([`manager-state.txt`](task06b3d/run1/manager-state.txt)).
  - `StartedAt` đổi (16:42:05) là đúng, vì ban đầu manager dừng và lần chạy này đã bật nó.
  - **Nhánh "ban đầu đang chạy" (StartedAt phải giữ nguyên) không được kiểm trong lần tích hợp này**; nó mới chỉ được kiểm offline.
- **Dọn dẹp:**
  - đã xóa đúng 2 container do lần chạy tạo (`8020bd2e…`, `35bb3f9d…`);
  - không còn QEMU, tcpdump hay tshark nào; thư mục capture tạm đã bị xóa;
  - ruleset tại runtime giống hệt expected.
- **Host:** chỉ `docker-ps` đổi (chuỗi thời gian của manager). sysctl, nft, route, `ip-addr`, cổng, module và `tap0` của host đều không đổi.

## 3. FAIL: MIPS `internet-tcp`; giả thuyết: lỗi biên cửa sổ thời gian của harness

Phân tích: [`side/mips-internet-tcp-window-analysis.txt`](task06b3d/side/mips-internet-tcp-window-analysis.txt). File được giữ nguyên như lúc bàn giao; câu kết luận trong file ("the extra counted frame is …") cần đọc là **giả thuyết**, như diễn giải dưới đây.

- `all_counter_deltas_eq_pcap_classification` sai ở bộ đếm `l2_bad_ethertype`: delta 3, pcap trong cửa sổ 2. Các check còn lại của probe đều đạt: 4 SYN từ cổng 41000, `drop_public` 8 = 8, đối chứng sống, không có cảnh báo host.
- **Sự kiện quan sát được:**
  - `probe_matrix.py` (06B-3CR) đọc bộ đếm trước rồi mới lấy thời điểm: `c0, t0 = counters(), time.time()`, và tương tự ở cuối: `t1, c1 = time.time(), counters()`. Thời gian chạy của lệnh nft **không được ghi**.
  - Ngay trước `t0` có hai gói IPv6 nền (MLD tới `ff02::16`): lúc `…038.136532` (0,8 ms trước `t0`) và `…038.108195` (29 ms trước `t0`).
- **Giả thuyết (chưa được chứng minh):** một trong hai gói đó đến sau lúc nft chụp bộ đếm nhưng trước `t0`, nên được tính vào delta mà nằm ngoài cửa sổ pcap. Vì không có thời gian của lần đọc nft, giả thuyết này **không kiểm được** bằng dữ liệu của lần chạy này. Gói lệch thuộc lớp IPv6 nền (`l2_bad_ethertype`); dữ liệu hiện có không cho thấy chặn bị lọt, nhưng cũng không đủ để loại trừ mọi khả năng khác.
- Theo quy tắc của harness, **probe này là FAIL** và lần chạy không đạt.
- Lỗi đo cùng kiểu có thể đã tồn tại từ 06B-3B. Nó còn có thể gây báo nhầm ĐẠT nếu hai sai lệch ngược chiều triệt tiêu nhau. Fixture `two-errors-cancel` của 06B-3DR minh họa trường hợp này.
- **Đã sửa ở 06B-3DR (offline, chưa chạy tích hợp):** mỗi lần đọc nft ghi `t_start`/`t_end` và JSON thô; gói ở biên làm phép đối chiếu thành CHƯA KIỂM CHỨNG; không nới cửa sổ, không bù trừ.

## 4. Phát hiện mới: tcpdump "received by filter" > "captured"

| Capture | Captured | Received by filter | Dropped by kernel |
|---|---|---|---|
| veth | 3837 | 3859 | 0 |
| bridge | 7438 | 7484 | 0 |
| `ens33` | 94 | 94 | 0 |

- Có 22 gói trên veth và 46 gói trên bridge đã qua bộ lọc nhưng không được ghi vào pcap. Ở lần 5 của 06B-3B, hai số này bằng nhau.
- **Chênh lệch này chưa được giải thích.** Ý nghĩa chính xác của "received by filter" với backend capture đang dùng chưa được xác minh. Không thể biết các gói không được ghi đến vào lúc nào hay là gói gì.
  - Bản summary trước đã suy ra thời điểm của chúng từ timestamp của gói cuối được ghi. **Suy luận đó đã bị rút lại**, vì không có dữ liệu chứng minh.
- Harness 06B-3CR chỉ kiểm `dropped by kernel = 0`, nên không phát hiện được hiện tượng này.
- 06B-3DR (offline): teardown dừng đối chứng, chờ capture xử lý phần còn lại, rồi dừng capture có thời hạn; ghi phiên bản tcpdump/libpcap và các mốc thời gian. Mọi chênh lệch "received − captured" được báo là mục mở, **không** dùng làm quy tắc PASS/FAIL.

## 5. Chưa được kiểm chứng bằng tích hợp thật

- Các nhánh lỗi chỉ được kiểm offline: `CaptureLost` khi mất capture hoặc heartbeat, manager ban đầu `running` hoặc `created`, Compose lỗi.
- Chưa có lần chạy tích hợp nào đạt trọn vẹn.
- Ngoài ra, các mục chưa kiểm của CT-01 vẫn giữ như cũ: ARP/MAC spoof, IPv6 có đối chứng, inbound, fail-closed khi chạy, V1/V2.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
