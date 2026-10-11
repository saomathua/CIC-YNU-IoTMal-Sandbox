# Minh chứng Nhiệm vụ 06B-4B: chuẩn bị harness đo L2/ARP/IPv6, kiểm thử OFFLINE (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4BR):** reviewer tái hiện được một lỗi. Gói lớn sau NAT bị capture cắt bởi snaplen (ví dụ `ens33` với `-s 512`) có chữ ký bị `sigscan_l2` báo bằng 0, vì `decode()` coi IPv4 có `total_length` lớn hơn phần đã lưu là không hợp lệ, và bộ quét bỏ qua cả gói. Phần sửa ở [`task06b4br-summary.md`](task06b4br-summary.md). Nội dung dưới đây giữ nguyên như lúc bàn giao.

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Chưa viết probe mới. Phát lại (chỉ đọc) pcap và bộ đếm của 06B-3G.

**Bối cảnh:**

- Reviewer chấp nhận hướng kế hoạch 06B-4A, với các quyết định D1–D7 ([`../ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md) §5.2):

  | ID | Quyết định |
  |---|---|
  | D1 | chưa nạp công cụ mới |
  | D2 | cho phép thay đổi guest tạm, có khôi phục |
  | D3 | chỉ tra route trên host/manager |
  | D4 | thiết kế container `NET_ADMIN` riêng, chưa chạy |
  | D5 | hoãn giả MAC bằng `TAP_MAC` |
  | D6 | dùng nhãn "ĐẠT (kiểm quy tắc)" |
  | D7 | `ens33` bắt không lọc, có giới hạn |

- **Harness mới** ở `/home/dathq/projects/ct01-06b4b/` (ngoài repo), là bản sao của 06B-3FR1 cộng phần bổ sung. Bản 06B-3FR1 ở `ct01-06b3c/` **giữ nguyên**: 12/12 hash vẫn khớp bàn giao 06B-3FR1 (kiểm trước và sau).
- Không sửa source cô lập, mạng host hay evidence cũ. Guard giữ 20 ms (giả định chưa đo). Kết quả toàn phiên vẫn báo riêng.

## 1. Sửa kế hoạch

Kế hoạch: [`docs/ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md).

| Yêu cầu review | Đã sửa |
|---|---|
| T17-P3 | **Hoãn.** Thêm `10.200.0.1/32` vào guest làm địa chỉ đó thành địa chỉ cục bộ: gói đi qua `lo`, không qua `tap0`, và gateway của guest cũng thành cục bộ. Hai cách thay thế được nêu, chưa làm: gói thô (cần D1), hoặc nguồn `10.200.0.1` tới đích khác (định tuyến của guest phải kiểm trước). Cổng `31173` giữ chỗ |
| Danh sách cổng và chữ ký | Bảng thống nhất §2.0, nguồn duy nhất là `signatures.py`. **Cổng mới chuyển 42xxx → 31xxx** (42171–42174 → 31171–31174), xem mục 2 |
| Khôi phục neighbor | Theo **trạng thái trước phép thử** (§1.3; T14, T15, T16, T17): entry tĩnh do phép thử thêm thì xóa; entry tĩnh có từ trước mà bị mất hoặc đổi MAC thì đặt lại MAC cũ; entry động chỉ ghi lại, không ép |
| T20 | Tách (i) số lần gọi gửi, (ii) `errno`, (iii) delta `drop_out`. Không mặc định một lần gọi = một gói. Tiêu chí là delta > 0; delta = 0 → CHƯA KIỂM CHỨNG. D3: chỉ tra route. D4: chỉ thiết kế |
| Script inventory | Bản sửa dùng scratch mới do `mktemp -d` tạo, chỉ xóa đúng đường dẫn đó, không xóa đường dẫn nhận từ tham số ([`task06b4b/guest_static_inventory.sh`](task06b4b/guest_static_inventory.sh)). Chạy lại cho cùng nội dung với 06B-4A ([`task06b4b/guest-static-inventory.txt`](task06b4b/guest-static-inventory.txt)), không còn thư mục scratch sau khi chạy. Evidence 06B-4A giữ nguyên |
| Danh mục BusyBox | Ghi rõ là bằng chứng tĩnh (đọc chuỗi trong binary), **không thay thế** xác nhận công cụ khi guest chạy |

## 2. Phát hiện khi chuẩn bị (offline, trên dữ liệu đã có)

1. **Cổng 42xxx va chạm cổng tạm [KC]:**
   - `ip_local_port_range` của host là `32768 60999`.
   - pcap bridge của 06B-3G có kết nối đối chứng hợp lệ `192.168.60.3:42172 → 192.168.60.10:8011` (12 khung). Chữ ký chỉ dựa trên cổng 42172 vì vậy báo động giả: bản quét mới lần đầu cho `probe_port=12`, `spoof_src_ip=5` trên pcap đó.
   - Cổng mới đặt trong **31000–31299**: 0 khung ở veth, bridge và `ens33` của 06B-3G, host không có dịch vụ nào nghe ở đó.
   - Dải cũ 41000–41020 của `sigscan.sh` cũng nằm trong dải cổng tạm. Ghi nhận, không đổi.
2. **`ether host` không biên dịch được trên `-i any` (LINUX_SLL2)** [KC, biên dịch thử bằng tcpdump trên file rỗng]. Vì vậy cảnh báo chia hai: cảnh báo `any` chỉ dùng chữ ký tầng mạng; cảnh báo Ethernet thứ hai trên veth của worker thêm chữ ký MAC.
3. **pcap-filter:** `and`/`or` cùng mức ưu tiên, nên mọi nhóm trong bộ lọc sinh ra đều được đóng ngoặc.
4. **Timestamp:** pcapng `tap0` lưu nano giây. Đổi `units × 1e-9` thẳng sang float lệch khoảng 0,2 µs ở mốc 1,79e9, nên bộ đọc mới tách phần nguyên trước. tcpdump in micro giây bị **cắt** (không làm tròn); phép so sánh có tính điều này.

## 3. Phần harness mới

Diff so với 06B-3FR1: [`task06b4b/ct01-06b4b-harness-vs-06b3fr1.diff`](task06b4b/ct01-06b4b-harness-vs-06b3fr1.diff). Mọi file cũ khác **không đổi** (`probe_matrix.py`, `counter_window.py`, `sigscan.sh`, `selftest.sh`, `mutation_test.sh`, …).

| File | Nội dung |
|---|---|
| `signatures.py` (mới) | Registry duy nhất: MAC guest/MAC giả đã chọn, IP nguồn giả, cổng probe, kích thước ICMP, tên DNS; `check()` (trùng, ngoài dải, trong dải cổng tạm, EUI-64); sinh bộ lọc cảnh báo `any` và Ethernet; giới hạn `ens33` |
| `l2frames.py` (mới) | Bộ đọc pcap/pcapng chỉ dùng thư viện chuẩn: mọi lỗi đọc là `FrameReadError`, không bao giờ "0 khung"; giải mã Ethernet/ARP/IPv4/IPv6; phân lớp; đối chiếu chặt; nhãn D6 |
| `guest_state.py` (mới) | Lưu và khôi phục trạng thái mạng guest theo bản ghi trước (D2). Chưa probe nào dùng |
| `sigscan_l2.py` (mới) | Quét chữ ký L2/ARP/IPv6/giả trên pcap host; lỗi đọc → exit 2 |
| `run-06b3b.sh` (sửa) | Đường dẫn `ct01-06b4b`; chạy `selftest_l2.py --offline-only` trước mọi thao tác với container; `ens33` không lọc, có giới hạn; hai cảnh báo từ registry; MAC thật của manager; quét `sigscan_l2.py` trên veth/bridge/`ens33` với mọi khóa phải bằng 0; chạm giới hạn `ens33` là check FAIL. **Cùng 20 probe**, không thêm probe |
| `selftest_l2.py`, `mutation_l2.py` (mới) | Kiểm thử offline và mutation cho phần mới |

**Phân biệt chiều khung** trên `tap0` (không có cờ hướng):

- MAC guest → khung của guest;
- **MAC giả đã chọn** → `l2_bad_mac`;
- `TAP_MAC` → chiều worker;
- MAC khác → `unmapped` (không bao giờ tính là `l2_bad_mac`).
- **Không tuyên bố phủ** trường hợp guest giả `TAP_MAC` (D5): khung như vậy sẽ bị coi là chiều worker.

**Lớp của khung:**

- **ARP:**
  - `arp_in_ok` theo đúng luật;
  - `arp_in_drop`;
  - **`arp_not_hooked`**: MAC đích không phải `TAP_MAC`/broadcast/multicast, header < 28 byte, `hlen ≠ 6` hoặc `plen ≠ 4`;
  - chiều worker: `arp_out_ok`; khung worker ngoài luật → `worker_unexpected`.
- **IPv6** → `l2_bad_ethertype`, kèm chi tiết nhận diện (`plen`, next header, kiểu ICMPv6, địa chỉ).
- **VLAN** → `unmapped`, vì nft `ether type` khi VLAN đã được bóc tag chưa được kiểm.
- **IPv4:** giữ đúng thứ tự cũ, thêm **`ip_not_hooked`** (OTHERHOST, header sai, checksum sai).
- `arp_out_drop`, `drop_out`: không quan sát được trên `tap0`; đưa chúng vào đối chiếu sẽ bị từ chối.
- Các thứ tự kiểm của kernel (`arp_rcv`, `ip_rcv`, điểm bắt sau hook output) đọc từ Linux upstream v6.8, **chưa kiểm thực tế** trên kernel host.

**Đối chiếu chặt (`reconcile_l2`):**

- Bộ đếm thiếu ở A hoặc B, giá trị không phải số nguyên không âm (kể cả bool), hoặc bộ đếm giảm → **ERROR** ("a missing counter is not 0"). Không dùng `get(k, 0)`.
- Khung thuộc lớp không có bộ đếm (`arp_not_hooked`, `ip_not_hooked`, `unmapped`, `worker_unexpected`) nằm trong cửa sổ → kết quả tốt nhất là CHƯA KIỂM CHỨNG, với từng khung được liệt kê.
- Lỗi đọc file → `FrameReadError`.
- Đối chiếu từng probe của ma trận IPv4 (`probe_matrix.py`, không đổi) vẫn dùng `get(k, 0)`. Chỉ phép đo mới là đối chiếu chặt.

**Nhãn kết luận (D6):**

- `probe_verdict_l2(..., control_kind)`:
  - `live`: phải có `control_alive` True/False;
  - `rule_check`: không được truyền đối chứng; ĐẠT được ghi **"ĐẠT (kiểm quy tắc)"**.
- Thứ tự FAIL > LỖI PHÉP ĐO > CHƯA KIỂM CHỨNG > ĐẠT không đổi.
- CHƯA KIỂM CHỨNG do khung không có bộ đếm được ghi đúng lý do, không gọi là "gói ở biên".
- `run_outcome` coi "ĐẠT (kiểm quy tắc)" là đạt.

**Lưu/khôi phục guest:**

- Chỉ đi qua `runner.run(cmd)`, như `probe_matrix.Guest`, và chỉ dùng `cat`, `ip`, `arp` của BusyBox (bằng chứng tĩnh).
- Đọc lỗi hoặc thiếu section → `StateReadError`.
- `GuestChange` luôn khôi phục, kể cả khi probe ném lỗi.
- `restored` chỉ True khi trạng thái đọc lại bằng bản ghi trước.

## 4. Kiểm thử offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_l2.py --regression <06B-3G>` | **167/167 PASS** (147 offline + 20 hồi quy R), ổn định 3 lần (JSON kết quả giống hệt) | [`logs/selftest-l2.log`](task06b4b/logs/selftest-l2.log) |
| `mutation_l2.py` (phần mới) | baseline 147/147; **56/56** đột biến hành vi bị bắt đúng test được nhắm; 2 đối chứng đúng loại (X1 INVALID, X2 ERROR); hash harness không đổi | [`logs/mutation-l2.txt`](task06b4b/logs/mutation-l2.txt) |
| `selftest.sh` cũ trên bản mới | **205/205**, `SELFTEST: ALL PASSED` | [`logs/selftest-legacy.log`](task06b4b/logs/selftest-legacy.log) |
| `mutation_test.sh` cũ trên bản mới | baseline đạt; **76/76** đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại (78 dòng OK, như 06B-3FR1) | [`logs/mutation-legacy.txt`](task06b4b/logs/mutation-legacy.txt) |

**Fixture của self-test L2:**

- **A, registry và bộ lọc:**
  - bộ lọc biên dịch trên Ethernet và SLL2; bộ lọc Ethernet bị từ chối trên SLL2;
  - tcpdump áp bộ lọc lên fixture dương (mỗi mệnh đề một khung, gồm khung chỉ có chữ ký MAC) và fixture âm (gồm đúng kết nối `42172` của 06B-3G, lưu lượng thật của manager, ARP thật của manager).
- **B, bộ đọc:** pcap LE/BE/ns, pcapng µs/ns/BE/nhiều section; lỗi đọc: rỗng, magic lạ, cắt cụt, trailer sai, EPB không có IDB, SPB, link type khác Ethernet, file không tồn tại.
- **D, phân lớp:** chiều khung; ethertype (IPv6, LLDP, 802.3, VLAN); 15 ca ARP (ok, drop theo từng trường, gratuitous, OTHERHOST, multicast, `hlen`/`plen`, ngắn); 13 ca IPv4 (thứ tự luật, phân mảnh, broadcast subnet, DHCP, OTHERHOST, checksum, độ dài); chiều worker.
- **E, đối chiếu chặt:** 15 ca: PASS, thiếu bộ đếm A/B, bool, giảm, FAIL, biên, khung không bộ đếm trong/ngoài cửa sổ, bộ đếm không quan sát được, thời gian sai.
- **F, nhãn D6:** 9 ca.
- **G, lưu/khôi phục:** dùng văn bản BusyBox thật của 06B-3G và một guest mô phỏng, 17 ca:
  - đổi MAC qua down/up: mất default route, neighbor bị xóa;
  - `/32` và route on-link thừa;
  - neighbor tĩnh thêm mới, mất, đổi MAC;
  - `arp_notify`;
  - netifd thêm địa chỉ;
  - lệnh khôi phục lỗi;
  - không đọc được trạng thái;
  - ngoại lệ trong probe.
  - Hành vi kernel trong mô phỏng là **[Kernel], chưa kiểm**.
- **H, `sigscan_l2.py`:** đếm chính xác từng khóa trên fixture dương; 0 trên fixture âm; nguồn giả dùng chung chỉ khớp theo cổng **nguồn**; lỗi đọc → exit 2; `skipped` khi không có MAC manager.
- **I, run script:** các dòng 06B-4B ở dạng tĩnh.

**Hồi quy trên 06B-3G (R, chỉ đọc, evidence không đổi):**

| Kiểm | Kết quả |
|---|---|
| Đọc và giải mã | 97 và 125 khung; thời gian (trong 1 µs) và MAC nguồn từng khung khớp tcpdump |
| Cửa sổ phiên, 9 lớp cũ | số khung chắc chắn từng lớp **bằng** `session.json` (ARM và MIPS) |
| Cửa sổ phiên, 13 lớp (thêm ARP, `allow_out_svc`) | **PASS**; `arp_in_ok` 2 = delta 2, `arp_out_ok` 2 = delta 2, `arp_in_drop` 0; không có khung không bộ đếm |
| Từng probe, 9 lớp cũ | khung chắc chắn và khung biên của mọi lớp ở cả 20 probe bằng `matrix.json`; kết luận bằng kết luận cũ (MIPS `ssh-host-192.168.60.1` vẫn UNVERIFIED) |
| Từng probe, 13 lớp (quan sát) | như trên. Kết luận cũ không đổi |
| `sigscan_l2.py` trên pcap host 06B-3G | mọi khóa = 0 ở veth, bridge, `ens33` |
| `sigscan_l2.py` trên `tap0` | dương: thấy MAC guest, ARP guest, IPv6 guest |

## 5. Hash

Hash từng file harness: [`task06b4b/harness-sha256.txt`](task06b4b/harness-sha256.txt). Mọi file trong `task06b4b/`: [`task06b4b/SHA256SUMS`](task06b4b/SHA256SUMS).

## 6. Hạn chế

- **Chưa chạy tích hợp.**
  - Run script đã sửa (`ens33` không lọc, hai cảnh báo, `sigscan_l2`) mới chỉ được kiểm tĩnh và bằng biên dịch/áp bộ lọc trên fixture.
  - Hiệu năng và kích thước của `ens33` không lọc chưa đo.
  - Cảnh báo Ethernet trên veth chưa chạy thật.
- **Chưa có probe mới.** `guest_state.py` chỉ được kiểm trên guest mô phỏng. Lệnh BusyBox (`ip link set … address`, `arp -s/-d`, ghi `arp_notify`) chưa được xác nhận trong guest đang chạy.
- **Giả định [Kernel] chưa kiểm thực tế:**
  - điểm drop trong `arp_rcv` và `ip_rcv`;
  - điểm bắt nằm sau hook output;
  - link down xóa route và mọi neighbor (kể cả permanent) của interface;
  - VLAN và `ether type`.
- **Mỗi khung chỉ thuộc một lớp:** khung guest giả `TAP_MAC` không phân biệt được (D5).
- Bộ đọc mới và tshark (`probe_matrix.guest_frames`) là hai bộ giải mã khác nhau. Chúng khớp nhau trên dữ liệu 06B-3G, nhưng chưa được đối chiếu trên ARP/IPv6 dị dạng thật.
- Đối chiếu từng probe cũ vẫn `get(k, 0)` (chưa đổi, như đã ghi từ 06B-3FR).
- Guard 20 ms là giả định chưa đo.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
