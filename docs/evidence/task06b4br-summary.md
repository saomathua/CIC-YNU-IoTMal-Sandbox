# Minh chứng Nhiệm vụ 06B-4BR: chữ ký trên capture bị cắt bởi snaplen, kiểm thử OFFLINE (08/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Không sửa source cô lập hay mạng host.

**Lỗi reviewer tái hiện trên 06B-4B:**

- Một gói IPv4 ICMP payload 1705 byte, sau NAT (MAC/IP không còn của guest), được `sigscan_l2` nhận ra `icmp_size=1` khi lưu đầy đủ.
- Khi pcap chỉ lưu 512 byte (độ dài gốc vẫn đầy đủ), mọi chữ ký bằng 0.
- **Nguyên nhân:**
  - `l2frames.decode()` đánh dấu IPv4 không hợp lệ khi `total_length` lớn hơn phần đã capture;
  - `sigscan_l2` bỏ qua toàn bộ IPv4 không hợp lệ;
  - bộ đọc bỏ độ dài gốc, nên không phân biệt được gói bị cắt bởi snaplen với file hỏng hay gói dị dạng.
- Với `ens33` bắt không lọc, snaplen 512 (D7), lỗi này làm chữ ký của gói lớn đã qua NAT **âm thầm thành 0**.

## 1. Tái hiện trước/sau

Log: [`logs/repro-before-after.txt`](task06b4br/logs/repro-before-after.txt); script: [`repro_snaplen.py`](task06b4br/repro_snaplen.py).

| | 06B-4B | 06B-4BR |
|---|---|---|
| ICMP 1705 B sau NAT, lưu đầy đủ | `icmp_size=1` | `icmp_size=1` |
| Cùng gói, lưu 512 B, độ dài gốc 1747 | **`icmp_size=0`** (mọi khóa 0) | `icmp_size=1`, `truncated_frames=1`, `unscannable_truncated=0` |

Section K mới chạy trên module 06B-4B: 22 test K FAIL và section crash. Trên 06B-4BR: 25/25 test K đạt.

## 2. Bản sửa (harness `ct01-06b4b`; bản 06B-4B giữ trong `ct01-06b4b/base-06b4b/`)

Diff so với 06B-4B: [`ct01-06b4br-harness-vs-06b4b.diff`](task06b4br/ct01-06b4br-harness-vs-06b4b.diff).

**Phân biệt ba trường hợp:**

| Trường hợp | Nhận biết | Xử lý |
|---|---|---|
| Gói bị cắt bởi snaplen | captured < original length | header nào đã lưu đủ thì vẫn đọc (`hdr_ok`); gói đánh dấu `truncated` |
| File capture hỏng | captured > original length (pcap hoặc EPB), bản ghi/block vượt cuối file, … | `FrameReadError` → `sigscan_l2` exit 2; không bao giờ là 0 |
| Gói dị dạng trên dây | capture đầy đủ nhưng header không khớp (`total_length` > khung trên dây, checksum sai, IHL sai) | header có đủ byte thì vẫn đọc; không bị coi là "cắt" |

**`l2frames`:**

- `read_records()` trả thêm độ dài gốc; `read_frames()` giữ API cũ.
- `decode(t, raw, orig_len)` đọc trường header IPv4/IPv6/ARP khi **byte header có đủ**, tách khỏi `valid`. `valid` vẫn chặt: đủ trên dây **và** trong capture, checksum/độ dài đúng.
- **Bộ phân lớp `tap0` vẫn chặt:**
  - khung guest hoặc worker bị cắt bởi snaplen → `unmapped`, nên đối chiếu ra CHƯA KIỂM CHỨNG; không bao giờ được xếp vào lớp có bộ đếm;
  - quyết định chỉ cần L2 (MAC giả → `l2_bad_mac`, ethertype) không đổi.

**`sigscan_l2` (phía host):**

- Đọc chữ ký từ mọi header đã lưu đủ, kể cả khi payload bị cắt hoặc gói dị dạng: kích thước ICMP lấy từ `total_length` IPv4 hoặc `payload_length` IPv6, cổng lấy từ 4 byte đầu TCP/UDP.
- Dữ liệu thiếu **không** được coi là không có chữ ký. Các khóa mới:
  - `truncated_frames`: thông tin;
  - `unscannable_truncated`: header mang chữ ký (Ethernet, ARP, IPv4/IPv6, cổng TCP/UDP, hoặc payload DNS) bị snaplen cắt mất;
  - `unscannable_undecoded`: header đó thiếu hoặc hỏng trên dây, hoặc là đóng gói không giải (VLAN).
- `run-06b3b.sh` yêu cầu `unscannable_truncated = 0` và `unscannable_undecoded = 0` trên veth/bridge/`ens33`, nên chữ ký không quét được là check FAIL. `truncated_frames` chỉ được báo cáo.
- **Phạm vi chữ ký DNS:** tên DNS chỉ được coi là "có thể nằm sau snaplen" với gói cổng 53 có payload bị cắt (tên probe luôn đi qua DNS). Payload khác bị cắt không được quét tên ngoài phần đã lưu (ghi ở hạn chế).

## 3. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_l2.py --regression <06B-3G>` | **195/195** (175 offline + 20 hồi quy), ổn định 3 lần (JSON giống hệt) | [`logs/selftest-l2.log`](task06b4br/logs/selftest-l2.log) |
| `mutation_l2.py` | baseline 175/175; **69/69** đột biến hành vi bị bắt đúng test (gồm 13 đột biến mới TR1–TR13); 2 đối chứng đúng loại; hash harness không đổi | [`logs/mutation-l2.txt`](task06b4br/logs/mutation-l2.txt) |
| `selftest.sh` cũ | 205/205 | [`logs/selftest-legacy.log`](task06b4br/logs/selftest-legacy.log) |
| `mutation_test.sh` cũ (chạy lại vì `run-06b3b.sh` đổi) | baseline đạt; **76/76** đột biến hành vi + 2 đối chứng đúng loại (78 OK, không đổi so với 06B-4B) | [`logs/mutation-legacy.txt`](task06b4br/logs/mutation-legacy.txt) |
| `sigscan_l2.py` trên pcap host 06B-3G | mọi khóa = 0, `truncated_frames` = 0 (06B-3G bắt đầy đủ) | trong log self-test (R8) |

**Fixture mới (section K, 25 test):**

- **ICMP 1705 sau NAT:** đầy đủ; cắt 512 (pcap và pcapng).
- **TCP và UDP sau NAT:** cổng probe, đầy đủ và cắt 512.
- **DNS:** đầy đủ, và cắt trước tên DNS → `unscannable_truncated`.
- **Header thiếu do snaplen** → `unscannable_truncated`, không tuyên bố chữ ký: Ethernet, IPv4, cổng TCP, ARP < 28 B, IPv6.
- **ICMPv6 1301 bị cắt** → vẫn nhận ra.
- **Gói dị dạng trên dây:**
  - `total_length` lớn: header vẫn đọc, không tính là bị cắt;
  - header < 20 B trên dây → `unscannable_undecoded`;
  - VLAN → `unscannable_undecoded`.
- **File hỏng** → lỗi đọc: captured > original ở pcap; EPB captured > original; file cắt giữa bản ghi.
- **`tap0` chặt:**
  - khung guest IPv4/ARP và khung worker bị cắt → `unmapped`;
  - MAC giả bị cắt vẫn `l2_bad_mac`;
  - khung bị cắt trong cửa sổ → UNVERIFIED;
  - `decode` giữ header nhưng `valid` False.

**Đột biến mới:**

| Mã | Đột biến |
|---|---|
| TR1 | dùng `valid` thay cho `hdr_ok` |
| TR2 | không đếm header IPv4 bị cắt |
| TR3 | không đếm DNS bị cắt |
| TR4 | `tap0` bỏ qua khung guest bị cắt |
| TR5 | bộ đọc pcap chấp nhận captured > original |
| TR6 | bộ đọc pcapng chấp nhận captured > original |
| TR7 | bỏ độ dài gốc của EPB |
| TR8 | không đếm cổng bị cắt |
| TR9 | gói dị dạng bị coi là bị cắt |
| TR10 | run script bỏ hai khóa unscannable |
| TR11 | `tap0` bỏ qua khung worker bị cắt |
| TR12 | gói dị dạng được báo là bị cắt bởi snaplen |
| TR13 | không đếm Ethernet bị cắt |

Đột biến cũ LI1 được chuyển sang dòng mã mới (kiểm checksum).

## 4. Hash

[`harness-sha256.txt`](task06b4br/harness-sha256.txt); mọi file trong `task06b4br/`: [`SHA256SUMS`](task06b4br/SHA256SUMS).

## 5. Hạn chế

- Chưa chạy tích hợp: hành vi của tcpdump `-s 512` trên `ens33` thật chỉ được mô phỏng bằng fixture (captured < original).
- Tên DNS trong payload không phải DNS mà nằm sau snaplen sẽ không thấy; chỉ gói DNS bị cắt mới được báo `unscannable_truncated`. Snaplen 512 đủ cho truy vấn DNS của probe, nhưng đó là giả định về kích thước truy vấn.
- Gói dị dạng trên dây vẫn được đọc header nếu đủ byte. Đây là chủ ý cho bộ quét phía host; bộ phân lớp `tap0` không dùng trường của gói không hợp lệ.
- Guard 20 ms vẫn là giả định chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
