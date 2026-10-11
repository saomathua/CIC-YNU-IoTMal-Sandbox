# Minh chứng Nhiệm vụ 06B-3G: kiểm thử TÍCH HỢP phép đo toàn phiên (harness 06B-3FR1) (07/10/2026)

> **Loại bằng chứng: tích hợp thật.** Dùng Docker thật, worker và manager thật, guest ARM/MIPS thật, capture thật trên `tap0` và phía host. Bằng chứng offline của harness này: [`task06b3fr1-summary.md`](task06b3fr1-summary.md). Đây là **lần đầu** phép đo toàn phiên (06B-3F → 3FR → 3FR1) chạy tích hợp.

**Phạm vi:**

- Reviewer chấp nhận 06B-3FR1 ở mức offline. Chạy **một lần** bằng harness đã review, ARM rồi MIPS tuần tự, đúng 20 probe IPv4 hiện có.
- Guard giữ 20 ms. Lưu lượng nền của guest giữ nguyên. Mọi check và quy tắc mã thoát giữ nguyên. Không thêm probe; không chạy mẫu malware hay ELF.
- Không build image, không sửa mã harness, source cô lập, firewall hay sysctl.
- **Không chạy lại, không chỉnh guard.**

**Kết quả: `exit=4` (NOT PASSED: chưa kiểm chứng).**

- **Probe: 19/20 ĐẠT; 1/20 CHƯA KIỂM CHỨNG** (MIPS `ssh-host-192.168.60.1`, do một gói nền của guest ở biên cửa sổ bộ đếm). **0 FAIL, 0 LỖI PHÉP ĐO.**
- **Toàn phiên (báo riêng): ARM PASS, MIPS PASS.** Kết quả này **không** đổi probe CHƯA KIỂM CHỨNG thành ĐẠT và không đổi mã thoát.
- Không thấy chữ ký probe nào trong các pcap đã lưu phía host, và cảnh báo `-i any` bắt 0 gói.
- Theo quy tắc của harness, lần chạy **không đạt**.

## 1. Trước khi chạy

| Kiểm tra | Kết quả |
|---|---|
| Working tree | tree `77ac4c371addfb9fb22aba44d9eaaa3011feb623` (đúng tree bàn giao 06B-3FR1), HEAD `3c54d55`, nhánh `feat/ct01-network-isolation` |
| Harness | 12/12 hash khớp [`harness-sha256.txt` của 06B-3FR1](task06b3fr1/harness-sha256.txt) (bản sao: [`side/harness-sha256-06b3fr1.txt`](task06b3g/side/harness-sha256-06b3fr1.txt)). Bản sao harness trong lần chạy ([`run1/harness-sha256.txt`](task06b3g/run1/harness-sha256.txt)) cũng khớp từng file. Kiểm lại sau lần chạy: vẫn khớp |
| Image ID | `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153`: người dùng kiểm bằng sudo trước khi chạy ([`side/precheck.txt`](task06b3g/side/precheck.txt)); harness kiểm lại ID đầy đủ |
| Tiến trình | không có QEMU, tcpdump/tshark/dumpcap, self-test, mutation test hay harness đang chạy (user thường và root); không có container `ct01-06b3b-*` hay worker |
| `out` cũ | không có, nên không phải đổi tên; `out-06b3d-run1`, `out-06b3e-run1` giữ nguyên. Lần chạy này được đổi tên thành `ct01-06b3c/out-06b3g-run1`; bản sao giống hệt (`diff -r`) ở [`task06b3g/run1/`](task06b3g/run1/) |
| Self-test trong harness | dưới root, trước khi tác động container: **205/205**, `SELFTEST: ALL PASSED` ([`run1/selftest.txt`](task06b3g/run1/selftest.txt)) |
| Manager / mongo | manager `exited` (ID `494ae3d2e2eb`); `mongo-db` đang chạy |

Lệnh chạy (người dùng chạy): `sudo bash /home/dathq/projects/ct01-06b3c/run-06b3b.sh`. Thời gian: 16:12:38 → 16:15:39 UTC.

## 2. Kết luận từng probe

Log: [`run1/run.log`](task06b3g/run1/run.log) (`e02c76f23dc947900fd2ceab5386a0c7baa28ac81a59196df258942982d202a8`). Ma trận: [ARM](task06b3g/run1/container/probe/ARM/matrix.md), [MIPS](task06b3g/run1/container/probe/MIPS/matrix.md); JSON: [ARM](task06b3g/run1/container/probe/ARM/matrix.json), [MIPS](task06b3g/run1/container/probe/MIPS/matrix.json).

| | ARM | MIPS |
|---|---|---|
| Cổng topology, liên kết dịch vụ trước và sau | đạt | đạt |
| ĐẠT | **10/10** | **9/10** |
| CHƯA KIỂM CHỨNG (gói biên) | — | `ssh-host-192.168.60.1` |
| FAIL / LỖI PHÉP ĐO | 0 / 0 | 0 / 0 |
| `determined_failures` | rỗng ở mọi probe | rỗng ở mọi probe |
| Check của `probe_matrix` | 27/27 | 26/27 |
| Thời gian một lần đọc nft (23 lần mỗi kiến trúc) | 4,3 – 16,7 ms, trung vị 8,8 | 4,4 – 12,9 ms, trung vị 7,5 |

- Dòng của probe CHƯA KIỂM CHỨNG mang nhãn `[FAIL]` trong log của `probe_matrix` vì check đó không đạt. Ở mức lần chạy, nó được phân loại là **UNVERIFIED**, không phải FAIL ("no check failed, but some results are UNVERIFIED").
- **Gói của chính probe** nằm trong vùng chắc chắn ở cả 20 probe (sau `A.end` ít nhất 74 ms, trước `B.start − guard` ít nhất 1,87 s). Kiểm sau lần chạy bằng tcpdump: [`side/edge-and-zone-check.txt`](task06b3g/side/edge-and-zone-check.txt).

### Probe CHƯA KIỂM CHỨNG: gói biên

| Probe | Lớp | Delta / chắc chắn / tính cả biên | Gói biên | Vị trí |
|---|---|---|---|---|
| MIPS `ssh-host-192.168.60.1` | `drop_public` | 4 / 3 / 4 | DNS nền của guest `10.200.0.2:52319 → 8.8.8.8:53` (`A? 3.openwrt.pool.ntp.org`) lúc `…689.3230836` | **bên trong** lần đọc A `[…689.318886, …689.323299]`, 0,22 ms trước `A.end` |

- Lớp dự kiến (`drop_private`) của probe này đối chiếu khớp chính xác (4 = 4); gói biên nằm ở lớp nền khác. Delta nằm trong khoảng `[chắc chắn, chắc chắn + biên]`, nên không có lệch thật.
- Gói `AAAA?` kế tiếp (`…689.323328`) rơi ngay sau `A.end`, nên thuộc vùng chắc chắn.
- **Quan sát:** lần đọc B của probe trước (`lan-dns-tcp`) kết thúc lúc `…689.304616`, trước gói này, nên gói không thuộc cửa sổ của probe trước. Delta 4 cho thấy bộ đếm `drop_public` tăng sau khi lần đọc A lấy giá trị lớp này. Harness **không** dùng suy luận này để chuyển kết quả thành ĐẠT, và tài liệu này cũng không dùng nó làm kết luận.

## 3. Phép đo toàn phiên (báo riêng)

`session.json`: [ARM](task06b3g/run1/container/probe/ARM/session.json) (`f48ca3aca70ac3149b255dba45ecfee8b554386a181fc722b26d75ea5b598cbc`), [MIPS](task06b3g/run1/container/probe/MIPS/session.json) (`031a0f38b8f61511a2c18025d4fa3e8cd0a1519c4a640c77c1509f90f72d6ff6`). JSON bộ đếm thô (mọi lần đọc nft, kèm `t_start`/`t_end`): [ARM](task06b3g/run1/container/probe/ARM/counters-raw.jsonl) (`07b845397a4e050c06b87f230033788d543eee1f0696e7be497497f660b468ba`), [MIPS](task06b3g/run1/container/probe/MIPS/counters-raw.jsonl) (`68101f2d4c3a52ddaac07066a6d27042e92fe7396aaafdea811b33cce25c9a74`).

| | ARM | MIPS |
|---|---|---|
| **Kết luận toàn phiên** | **PASS**, `reasons` rỗng | **PASS**, `reasons` rỗng |
| Quét QEMU trước boot | `pids_before = []`, `pids_before_error = null`, `no_qemu_before = true` | như ARM |
| QEMU thoát | `exit_confirmed = true` lúc `…641.522` | `exit_confirmed = true` lúc `…725.533` |
| Quét QEMU sau khi thoát | `pids_after_exit = []`, `pids_after_exit_error = null` | như ARM |
| A (trước boot) | `…573.0381 – …573.0548` | `…648.1208 – …648.1256` |
| F1 / F2 (sau khi thoát) | `…642.0240 – …642.0351` / `…642.5360 – …642.5476`, cách nhau 0,501 s | `…726.0347 – …726.0475` / `…726.5484 – …726.5603`, cách nhau 0,501 s |
| `required_finals` / `final_read_error` | 2 / `null` | 2 / `null` |
| F1 = F2 trên mọi bộ đếm | có (`unstable_after_exit` rỗng) | có |
| Gói guest trước cửa sổ / sau khi thoát | `[]` / `[]` | `[]` / `[]` |
| Capture `tap0` | tshark rc 0; ISB 97/0 (ĐẠT); pcap đọc được | tshark rc 0; ISB 125/0 (ĐẠT); pcap đọc được |
| 9 lớp đối chiếu (delta A→F1 = chắc chắn, không gói biên) | `allow_svc` 14, `drop_spoof` 19, `drop_worker_other` 3, `drop_private` 25, `drop_public` 7, `l2_bad_ethertype` 15; còn lại 0 | `allow_svc` 14, `drop_spoof` 18, `drop_worker_other` 4, `drop_private` 32, `drop_public` 36, `l2_bad_ethertype` 7; còn lại 0 |
| Chưa đối chiếu (ghi delta + lý do) | `allow_out_svc` 10, `arp_in_ok` 2, `arp_out_ok` 2; còn lại 0 | như ARM |

- **Bộ đếm cộng dồn giữa hai kiến trúc** (cùng ruleset trong netns worker). Vì vậy A của MIPS bằng F2 của ARM. Mọi kết luận dùng delta.
- **Biên của cửa sổ phiên:** gói guest đầu tiên cách `A.end` 12,6 s (ARM) / 23,5 s (MIPS); gói guest cuối cùng trước `F1.start` 0,67 s / 0,66 s, và trước thời điểm xác nhận QEMU thoát. Ở lần chạy này không có gói nào ở hai biên. Đây là **quan sát** của một lần chạy, đã được kiểm bằng pcap và trạng thái tiến trình, không phải đảm bảo chung.
- **Nhánh lỗi của quét QEMU** (06B-3FR1: `PermissionError`, lỗi đọc, …) **không xảy ra** trong lần chạy này: cả 4 lần quét thành công với `[]`. Nhánh đó chỉ được kiểm ở mức offline.

### Kiểm chéo độc lập (sau lần chạy, chỉ đọc, không thuộc harness)

| Kiểm | Kết quả | File |
|---|---|---|
| Phân tích lại JSON nft thô của A/F1/F2 so với giá trị và thời gian trong `session.json` | khớp ở cả 6 lần đọc | [`side/raw-reads-check.txt`](task06b3g/side/raw-reads-check.txt), script [`raw_reads_check.py`](task06b3g/side/raw_reads_check.py) |
| tcpdump: số khung có MAC nguồn của guest = tổng delta 9 lớp đối chiếu + `arp_in` | ARM 85 = 83 + 2; MIPS 113 = 111 + 2 | [`side/session-crosscheck.txt`](task06b3g/side/session-crosscheck.txt), script [`session_crosscheck.py`](task06b3g/side/session_crosscheck.py) |
| tcpdump: số khung tới guest = `allow_out_svc` + `arp_out` | ARM 12 = 10 + 2; MIPS 12 = 10 + 2; tổng khớp số khung `tap0` (97, 125) | như trên |
| tcpdump: khung trước `A.end` / từ `F1.start` trở đi | 0 / 0 ở cả hai kiến trúc | như trên |

- Phép kiểm chéo này chỉ so **tổng** số khung, không phân lớp lại như harness.
- Việc ghép ARP của guest với `arp_in_ok` và khung tới guest với chiều ra là **giả định của phép kiểm chéo**. Harness không đối chiếu các lớp này.

## 4. Capture, heartbeat, đối chứng

- **Phiên bản:** tcpdump 4.99.4, libpcap 1.10.4 (TPACKET_V3) ([`versions.txt`](task06b3g/run1/hostcap/versions.txt)); tshark 3.6.2 trong container.
- **Thống kê tcpdump** ([`capture-stats.tsv`](task06b3g/run1/hostcap/capture-stats.tsv)): captured = received by filter ở cả 4 capture (veth 3943, bridge 7665, `ens33` 101, cảnh báo 0); dropped by kernel = 0. **Không có mục mở.**
- **ISB `tap0`:** ARM 97/0, MIPS 125/0, ĐẠT.
- **Teardown** ([`teardown-timeline.txt`](task06b3g/run1/hostcap/teardown-timeline.txt)):
  - guest xong lúc 16:15:31.937 → dừng container đối chứng lúc 32.299 (rc 0);
  - hết thời gian chờ 3 s lúc 35.309 → dừng bộ giám sát lúc 35.330;
  - SIGINT gửi lúc 35.335–35.340 → 4 capture thoát với rc 0 lúc 35.358–35.408, đều trước hạn 10 s.
- **Heartbeat:**
  - harness kiểm "bộ giám sát còn sống, heartbeat còn mới (≤ 5 s)" ở 4 mốc: sau khi bật capture, trước ARM, trước MIPS, cuối lần chạy. Cả 4 đều đạt;
  - không có `CaptureLost`; marker của bộ giám sát rỗng;
  - giá trị heartbeat cuối: `1791389734.806` (16:15:34.806), 0,52 s trước khi bộ giám sát bị dừng ([`capture-watch.heartbeat`](task06b3g/run1/hostcap/capture-watch.heartbeat)).
  - Lần này **không** chạy bộ ghi mẫu heartbeat ngoài harness như 06B-3E. Vì vậy không có chuỗi mẫu liên tục, chỉ có 4 mốc kiểm và giá trị cuối.
- **Chữ ký** ([`side/independent-check.txt`](task06b3g/side/independent-check.txt)):
  - veth, bridge và `ens33` có 0 ở mọi chữ ký (MAC/IP guest, cổng probe, tên DNS probe, URL probe), trong khi bộ tìm vẫn thấy DNS đối chứng (8 gói);
  - trên `tap0`: đủ gói probe ở mọi probe (ARM 3, MIPS 4 SYN; UDP 4), 0 gói trả về guest, 0 gói IPv4 tới guest từ địa chỉ khác `10.200.0.1`.
  - Phạm vi: chỉ các gói đã được ghi (ở lần này captured = received by filter).
- **Đối chứng:** mỗi đích (mongo, worker `eth0`, manager) 332 lần kiểm, **0 lỗi**; khoảng cách lớn nhất giữa hai lần thành công 0,53 s.

## 5. Netns, manager, dọn dẹp, host

- **Netns của worker** ([`netns-diff.txt`](task06b3g/run1/container/netns-diff.txt)):
  - `eth0 lo tap0` cả trước và sau; địa chỉ và route bảng main không đổi; `ISOLATION OK` sau ARM và sau MIPS.
  - Khác biệt được báo cáo, giống 06B-3D/3E:
    - `tap0` `vnet_hdr off → on` (quan sát, chưa kết luận);
    - 3 neighbor mới trên `eth0` (`192.168.60.1`, `.10`, `.3`), do đối chứng tạo ra.
- **Manager** ([`manager-state.txt`](task06b3g/run1/manager-state.txt)):
  - trước: `exited`, ID `494ae3d2e2eb`;
  - bật bằng `compose up --no-deps --no-build`, xác nhận cùng container, healthcheck đạt;
  - sau: `exited`, **cùng ID**. `StartedAt` đổi là đúng, vì lần chạy này đã bật manager. Nhánh "ban đầu đang chạy" chưa được kiểm tích hợp.
- **Dọn dẹp:**
  - đã xóa đúng 2 container do lần chạy tạo (`9404afd3…`, `5fc1c400…`);
  - trong container không còn `qemu-system`/`tshark` sau mỗi kiến trúc; không còn marker, fixture hay đĩa guest tạm;
  - trên host không còn QEMU hay tiến trình capture; thư mục capture tạm đã bị xóa;
  - ruleset tại runtime giống hệt expected.
- **Host:** các check hard (sysctl, nft, route, cổng, QEMU, capture, `tap0` của host) đều không đổi. Ba khác biệt được báo cáo, không phải check hard:
  - `docker-ps`: chuỗi thời gian của manager;
  - `ip-addr` và `ip6-route`: bridge `sandboxnet` (`br-1d86fe3e8bbe`) có thêm IPv6 link-local `fe80::4c50:83ff:fe98:a72e/64` và route `fe80::/64 … linkdown`. Host đã khởi động lại lúc 15:08, khoảng 1 giờ trước lần chạy, và trước lần chạy bridge không có địa chỉ IPv6. Hiện tượng giống 06B-2A, 06B-3A lần 1 và 06B-3E. Harness không cấu hình IPv6 trên host;
  - `lsmod-net`: thêm `nft_ct`, giống 06B-2A và 06B-3E. Đây là module của kernel host, được nạp khi ruleset trong netns worker cần.
  - Cả ba khác biệt đều được ghi lại, không coi là bình thường mặc nhiên.

## 6. Kết luận theo phạm vi

- **Phép đo toàn phiên đã chạy tích hợp một lần trên mỗi kiến trúc, và cho PASS ở cả ARM và MIPS:**
  - quét QEMU trước boot và sau khi thoát đều thành công, rỗng, không lỗi;
  - đủ F1 và F2, hai lần giống nhau;
  - không có gói guest trước cửa sổ hay sau khi thoát;
  - capture đầy đủ;
  - 9 lớp đối chiếu khớp chính xác với pcap.
  - Hai phép kiểm chéo độc lập (JSON nft thô; tổng khung bằng tcpdump) nhất quán với `session.json`.
- **Kết quả toàn phiên được báo riêng:** probe MIPS `ssh-host-192.168.60.1` **vẫn CHƯA KIỂM CHỨNG**, và mã thoát vẫn 4. Toàn phiên PASS cho thấy tổng bộ đếm khớp pcap trên cả phiên; nó **không** quy được gói biên về đúng một probe, nên không dùng để đổi kết luận probe.
- **Ma trận 20 probe chưa được kiểm chứng trọn vẹn** trong lần chạy này: còn 1 probe không quyết định được (06B-3E: 4). Lần chạy không đạt (exit 4).
- **Không có lệch thật nào** giữa bộ đếm và pcap. Không có FAIL đã xác định. Không thấy chữ ký probe trong các pcap đã lưu phía host.
- Việc dùng kết quả toàn phiên trong nghiệm thu (nếu có) cần reviewer quyết định. **Không** tự tăng guard hay chạy lại để tìm PASS.

## 7. Hạn chế

- **Một lần chạy.** Không lặp lại, nên không có số liệu về độ ổn định giữa các lần.
- **Guard 20 ms là giả định chưa đo.** Lần chạy chỉ đo được thời gian của lệnh nft (4,3–16,7 ms), không đo được độ trễ từ timestamp capture tới lúc gói chạm bộ đếm. Mọi kết quả ĐẠT/PASS của phép đối chiếu phụ thuộc giả định này.
- Nhánh lỗi của quét QEMU chưa xảy ra ở môi trường thật; chỉ được kiểm offline.
- Heartbeat chỉ có 4 mốc kiểm của harness và giá trị cuối, không có chuỗi mẫu liên tục.
- ARP, input/forward và chiều ra vẫn chưa được harness đối chiếu với pcap. Phép kiểm chéo tổng khung chỉ là quan sát.
- Còn mở từ 06B-3FR: delta của đối chiếu từng probe vẫn dùng `get(k, 0)`. Ở lần chạy này, mọi lần đọc nft có đủ 17 bộ đếm.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 8. Hash

| File | sha256 |
|---|---|
| [`run1/run.log`](task06b3g/run1/run.log) | `e02c76f23dc947900fd2ceab5386a0c7baa28ac81a59196df258942982d202a8` |
| [`run1/harness-sha256.txt`](task06b3g/run1/harness-sha256.txt) | `c7e9445579cc60ad168ab46a4e7aa9c27c4e23aa0b0b212392535259a9202f8f` |
| [`run1/selftest.txt`](task06b3g/run1/selftest.txt) | `37657ff23e06baf9ea36fa6cafcc289e6da674f040b07260c691f2af137599be` |
| [`ARM/session.json`](task06b3g/run1/container/probe/ARM/session.json), [`MIPS/session.json`](task06b3g/run1/container/probe/MIPS/session.json) | `f48ca3aca70ac3149b255dba45ecfee8b554386a181fc722b26d75ea5b598cbc`, `031a0f38b8f61511a2c18025d4fa3e8cd0a1519c4a640c77c1509f90f72d6ff6` |
| [`ARM/counters-raw.jsonl`](task06b3g/run1/container/probe/ARM/counters-raw.jsonl), [`MIPS/counters-raw.jsonl`](task06b3g/run1/container/probe/MIPS/counters-raw.jsonl) | `07b845397a4e050c06b87f230033788d543eee1f0696e7be497497f660b468ba`, `68101f2d4c3a52ddaac07066a6d27042e92fe7396aaafdea811b33cce25c9a74` |
| [`ARM/matrix.json`](task06b3g/run1/container/probe/ARM/matrix.json), [`MIPS/matrix.json`](task06b3g/run1/container/probe/MIPS/matrix.json) | `26f030a666bd1ddf723462e93482cd5a7eda256f2edc51413713a89e46871b54`, `2e21b88d1e8acae8f374f1a744602d75dbec175a2cc9061ce341cc229ce0757b` |
| [`ARM/result.json`](task06b3g/run1/container/probe/ARM/result.json), [`MIPS/result.json`](task06b3g/run1/container/probe/MIPS/result.json) | `5f9a7d6e40047e780a26cd87b7151361f939b8b52aba321a3d8d070ca21fd522`, `1693db5dc780a4eaa6c9f147dcdd8db32636c62eca71fcf81100e03dab003f19` |
| [`ARM/tap0.pcapng`](task06b3g/run1/container/probe/ARM/tap0.pcapng), [`MIPS/tap0.pcapng`](task06b3g/run1/container/probe/MIPS/tap0.pcapng) | `50516af3f12718025d04877c6b042b32d5780cca8b15364f635d96fc5c1a69a2`, `603daafa862e2a4dcde331403e5414f4a62b40a80f4445fb41c7d2d70d12fb71` |
| [`hostcap/veth.pcap`](task06b3g/run1/hostcap/veth.pcap), [`bridge.pcap`](task06b3g/run1/hostcap/bridge.pcap), [`ens33.pcap`](task06b3g/run1/hostcap/ens33.pcap) | `4941ef030e5eafc0a88f6d72bbca3b026fecaf2a657efbeef7fa53d3c39c99c5`, `4df9633fa8019b7b7e0bfe409014d55f6b6090ccd9054d5e7385099efcc69ba4`, `d22194e9f59db578a10c71e0ba63c08d15ab75319b35354eb1752341a5edb50c` |
| [`hostcap/teardown-timeline.txt`](task06b3g/run1/hostcap/teardown-timeline.txt), [`capture-stats.tsv`](task06b3g/run1/hostcap/capture-stats.tsv), [`capture-watch.heartbeat`](task06b3g/run1/hostcap/capture-watch.heartbeat) | `487e0beadb987fb9b74f82c4d503e34ea9968da05db7f889fc5b65b28a1668e8`, `9667841874da717e89bcc8febc6b3cdf9a596f3ac4d3f508ae90c509d2e942bb`, `036d1ab2a8af41c8a2df57b0dc6f7d1e3e5a71216a6d9b06487afa171c5f8db9` |
| [`run1/manager-state.txt`](task06b3g/run1/manager-state.txt) | `9bd3f87733779ee04df0f0638174b36da80f6af64779650d4822281ccc0fb6a8` |
| [`side/precheck.txt`](task06b3g/side/precheck.txt) | `b12ccc67950de11f0fae4f0db07632c14d6462e71a275ba6c12dc5d50c6d169c` |
| [`side/independent-check.txt`](task06b3g/side/independent-check.txt) | `baedd05a1f6dc49968519bf487f98cf2c82cd66b1bf8b71a6b52dd6077bf50d1` |
| [`side/session-crosscheck.txt`](task06b3g/side/session-crosscheck.txt) / [`session_crosscheck.py`](task06b3g/side/session_crosscheck.py) | `ebc354a33f51030e8881b830f8de0271c4604e9d7e53d6297b88edfe18cfe336` / `8f058ccacc0b970f627e45c7879b37623d730649d9985772f96d28398427cdf6` |
| [`side/raw-reads-check.txt`](task06b3g/side/raw-reads-check.txt) / [`raw_reads_check.py`](task06b3g/side/raw_reads_check.py) | `697d150391c37189ce7d8dfa1dcaaa942cc5b26ff95d5689cabf472032dd3da1` / `fc4888b684f0d37fbf9fa70d1a05e0147870a5932204b40403767aec70a80fa8` |
| [`side/edge-and-zone-check.txt`](task06b3g/side/edge-and-zone-check.txt) / [`edge_and_zone_check.py`](task06b3g/side/edge_and_zone_check.py) | `9542727343090bbbf35162612236156c94060ec6aa29ca9dc728e5e94b9e33d9` / `6aa71ef4161f9b705c30b097c74dbd8df9d2bcf2ea10550e3100470112fd1b88` |

Mọi file trong `task06b3g/` có hash trong [`task06b3g/SHA256SUMS`](task06b3g/SHA256SUMS) (`f92445bdeabf207f126199272dace3dd2a2724ecf807f4bb8893506938801680`), trừ 6 file `.pyc` trong `run1/selftest/stubs.*/__pycache__/`. Đây là bytecode do stub của self-test sinh ra; chúng bị `.gitignore` loại khỏi patch, giống 06B-3E, và vẫn còn trong `ct01-06b3c/out-06b3g-run1/`.
