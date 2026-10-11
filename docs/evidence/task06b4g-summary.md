# Minh chứng Nhiệm vụ 06B-4G: chạy tích hợp 5 ca ICMP (T12–T13) bằng harness 06B-4FR, một lần (08/10/2026)

> **Trạng thái review và đính chính (cập nhật ở 06B-4H):** reviewer **chấp nhận đúng phạm vi**: 9/10 ca kiểm quy tắc đạt, ARM T13-I1 UNVERIFIED, exit 4, ba mục OPEN còn nguyên. Các câu được đính chính ở 06B-4H đánh dấu *(đính chính 06B-4H)*; log, pcap và evidence gốc trong `task06b4g/` không sửa.

> **Loại bằng chứng: tích hợp thật [KC]**, chạy **đúng một lần**.
>
> - Guest ARM rồi MIPS, tuần tự, chỉ 5 ca đã review.
> - Không malware, không thêm probe, không chạy lại 20 probe IPv4.
> - Không sửa harness, ruleset, source cô lập, địa chỉ hay guard.
>
> **Kết quả: exit 4** (không có check nào FAIL; có kết quả CHƯA KIỂM CHỨNG):
>
> - **9/10 ca "ĐẠT (kiểm quy tắc)"**; **ARM T13-I1 CHƯA KIỂM CHỨNG** do một gói ở biên cửa sổ bộ đếm.
> - Có 3 mục mở chưa giải thích (tcpdump "received by filter" − "captured" = 8).
> - Toàn phiên ARM/MIPS PASS, báo riêng; **không** dùng để nâng ca CHƯA KIỂM CHỨNG.
>
> **Giới hạn của kết luận:**
>
> - Guard 20 ms vẫn là **giả định chưa đo**.
> - "Kiểm quy tắc": luật khớp và drop đúng chỗ. Không có đối chứng sống cho các đích này, nên **không** kết luận "không chạm được dịch vụ".
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

**Mốc:** harness `/home/dathq/projects/ct01-06b4fr/` (06B-4FR, Codex chấp nhận offline), script `run-06b4f.sh`. Records tree trước nhiệm vụ: `91a89cd3b4c9eaab8866b95c3b9b0b004891d0e1`.

## 1. Trước khi chạy

**Hướng dẫn repo:** đã đọc `AGENTS.md` và `docs/deployment.md` §7. Không chạy mẫu; chỉ dùng binary vô hại có sẵn trong guest (`ping`/`ping6` của BusyBox).

**Harness:**

- 28/28 file khớp manifest [`task06b4fr/harness-sha256.txt`](task06b4fr/harness-sha256.txt) (không thiếu, không thừa).
- Bản copy mà run script tạo trong `run1/harness-copy/` (25 file) cũng khớp manifest.
- Sau lần chạy, harness vẫn khớp manifest. Lần chạy để lại `__pycache__/` do root tạo khi self-test import module; thư mục này không thuộc harness.

**Precheck:** [`precheck/precheck.txt`](task06b4g/precheck/precheck.txt), script chỉ đọc [`precheck/precheck-06b4g.sh`](task06b4g/precheck/precheck-06b4g.sh); người dùng chạy bằng sudo.

- Image ID đầy đủ `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153` = bản đã review.
- Manager `exited`, ID `494ae3d2e2eb`; `mongo-db` đang chạy.
- Không có container thử `ct01-06b3b-guest`/`-ctl`.
- Không có QEMU, tcpdump, tshark, dumpcap hay tiến trình harness nào.
- Thư mục output chưa tồn tại; không còn thư mục capture tạm cũ.

**Baseline host mới:**

- Không sudo: [`precheck/baseline-nosudo/`](task06b4g/precheck/baseline-nosudo/). Có sudo: ruleset nft và `aa-status` trong `precheck/`. Run script cũng tự lấy `host-before/`.
- So với `host-after` của 06B-4C:
  - ruleset nft, route, cổng nghe và module mạng **giống hệt**;
  - `sysctl.txt` chỉ khác vì baseline không-sudo của tôi không ghi khóa `net.core.devconf_inherit_init_net`.

### 1a. Thay đổi thiết lập công cụ (ghi riêng, **không phải kết quả CT-01**)

Để kết nối Codex desktop, trên host đã có thêm các thay đổi sau, theo `/var/log/dpkg.log` ([`precheck/baseline-nosudo/tool-install-dpkg.txt`](task06b4g/precheck/baseline-nosudo/tool-install-dpkg.txt)):

- **Gói cài lúc 2026-10-08 07:23:56 UTC:**
  - `bubblewrap 0.9.0-1ubuntu0.3`;
  - `apparmor-profiles` và `apparmor-utils` `4.0.1really4.0.1-0ubuntu0.24.04.8`;
  - phụ thuộc `python3-apparmor`, `python3-libapparmor`.
- **Profile AppArmor:** `/etc/apparmor.d/bwrap-userns-restrict` mới; `aa-status` có `bwrap`, `unpriv_bwrap`, `unprivileged_userns` ở enforce.
- **tcpdump:** profile `/etc/apparmor.d/usr.bin.tcpdump` không đổi (file ngày 2025-08-05), `tcpdump` ở enforce như mặc định.

Các capture của host chạy bình thường trong lần này (§3).

## 2. Lần chạy

Người dùng chạy một lần: `sudo bash /home/dathq/projects/ct01-06b4fr/run-06b4f.sh`, 08:41–08:44:48 UTC.

- Toàn bộ output lưu nguyên ở [`task06b4g/run1/`](task06b4g/run1/) (bản sao giống hệt `ct01-06b4fr/out/`, kiểm bằng `diff -r`).
- Không chạy lại.
- Self-test trước khi chạy:

  | Self-test | Kết quả |
  |---|---|
  | `selftest.sh` | ALL PASSED |
  | L2 | 175/175 |
  | ICMP | 79/79 |
  | ICMP wiring | 129/129 |
  | Registry | OK |

- Log: [`run1/run.log`](task06b4g/run1/run.log); mỗi kiến trúc `run1/container/probe/<ARCH>/`, gồm:
  - `result.json`, `icmp-group.json`, `icmp-eval.json`;
  - `counters-raw.jsonl` (JSON nft thô), `tap0.pcapng`;
  - `session.json`, `console.log`.

## 3. Kết quả từng ca

Lệnh guest: `ping -c 3 -s <size> -w 5 <dst>` / `ping6 -c 3 -s <size> -w 5 -I <if> <dst>`; giao diện ARM `eth1`, MIPS `br-lan`. TAP_MAC `26:b3:9f:a4:8c:01`, nên đích T13-I2 là `fe80::24b3:9fff:fea4:8c01`, nhóm `ff02::1:ffa4:8c01`.

| Ca | Lớp mong đợi | ARM: khung probe (chắc/biên), delta | ARM | MIPS: khung probe, delta | MIPS |
|---|---|---|---|---|---|
| T12-B1 `255.255.255.255` | `drop_bcast_mcast` | 5 (5/0), Δ=5 | ĐẠT (kiểm quy tắc) | 3 (3/0), Δ=3 | ĐẠT (kiểm quy tắc) |
| T12-B2 `224.0.0.1` | `drop_bcast_mcast` | 5 (5/0), Δ=5 | ĐẠT (kiểm quy tắc) | 3 (3/0), Δ=3 | ĐẠT (kiểm quy tắc) |
| T12-B4 `10.200.0.3` | `drop_private` | 5 (5/0), Δ=5 | ĐẠT (kiểm quy tắc) | 3 (3/0), Δ=3 | ĐẠT (kiểm quy tắc) |
| T13-I1 `ff02::1` | `l2_bad_ethertype` | 3 (**2/1**), Δ=3 | **CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm)** | 3 (3/0), Δ=3 | ĐẠT (kiểm quy tắc) |
| T13-I2 link-local TAP (chỉ NS) | `l2_bad_ethertype` | 4 NS (4/0), Δ=4 | ĐẠT (kiểm quy tắc) | 3 NS (3/0), Δ=3 | ĐẠT (kiểm quy tắc) |

**Mọi ca:**

- Đối chiếu bộ đếm/pcap của harness trên **mọi lớp** có bộ đếm là PASS. Ngoại lệ: ARM T13-I1 là UNVERIFIED do khung ở biên.
- 0 khung **ICMP/ICMPv6** tới guest trong cửa sổ các ca *(đính chính 06B-4H: chỉ áp dụng cho ICMP/ICMPv6 của probe; TCP của liên kết dịch vụ và ARP của worker tới guest vẫn có trong capture)*.
- Không ca nào là LỖI THỰC THI, KHÔNG TẠO ĐƯỢC GÓI hay LỖI PHÉP ĐO.

**Phân loại (yêu cầu phân biệt):**

| Loại | Kết quả lần này |
|---|---|
| Kiểm quy tắc đạt | 9 ca |
| Không tạo được gói | 0. Cả broadcast `255.255.255.255` và `10.200.0.3` đều ra `tap0`, nên giả định G1 (BusyBox từ chối broadcast) **không** xảy ra trên hai image này |
| Lỗi phép đo | 0 |
| Lỗi thực thi | 0 |
| Lỗi hạ tầng | 0 (mọi check hạ tầng đạt, §4) |
| Chưa kiểm chứng | 1: ARM T13-I1 |

**ARM T13-I1 — vì sao CHƯA KIỂM CHỨNG:**

- Echo thứ 3 có `t=1791448983.574760`, tức 15,75 ms trước khi lần đọc B bắt đầu (`1791448983.590512`), nằm trong guard 20 ms → vùng biên.
- Delta `l2_bad_ethertype` = 3 bằng đúng 3 khung IPv6 của guest trong cửa sổ. Dù vậy, theo quy tắc đã review, một khung ở biên thì **không** kết luận ĐẠT.
- Kết quả toàn phiên PASS **không** nâng ca này.

**Quan sát [KC]** (không đổi kết luận):

- **ARM `ping6 ff02::1` báo "3 packets received" (rc 0).** Cả ba phản hồi đến **từ chính địa chỉ của guest** `fe80::5054:ff:fec7:2` ([`run1/container/probe/ARM/console.log`](task06b4g/run1/container/probe/ARM/console.log), dòng 293–299). *(Đính chính 06B-4H:)* điều này **chỉ phù hợp** với phản hồi nội bộ guest (ví dụ loopback multicast); **chưa có capture trong guest** xác nhận cơ chế.
  - `tap0.pcapng` ARM có **0** echo reply ICMPv6.
  - 12 khung tới MAC guest đều nằm ngoài cửa sổ T13-I1: 11 là TCP từ `10.200.0.1:8011` của liên kết dịch vụ, 1 là ARP của worker.
  - MIPS không có hiện tượng này.
- **BusyBox ARM với `-c 3 -w 5`** gửi 5 echo khi không có phản hồi và 3 khi báo có phản hồi (T13-I1); điều này phù hợp với việc gửi tới khi nhận đủ 3 phản hồi hoặc hết 5 s, nhưng chưa được xác nhận riêng. MIPS gửi 3 ở mọi ca. Tiêu chí luôn là delta = số khung thực tế, nên không ảnh hưởng.
- **T13-I2:** ARM gửi 4 NS, MIPS 3 NS (giả định G5 "thường 3"). Mọi NS có target đúng link-local của TAP_MAC.

## 4. Liên kết dịch vụ, hạ tầng và host

**Liên kết guest–worker** (tiền đề, không phải đối chứng sống cho đích ICMP):

- Trước và sau nhóm, cả ARM lẫn MIPS: HTTP 200, hash bằng hash fixture.
  - ARM `602ec43c…3d78f`;
  - MIPS `b13ee440…8f5e5a`.

**Lưu lượng kiểm capture từ worker,** trước và sau nhóm:

- DNS tới `192.168.177.2` có phản hồi (rcode 3); HTTP tới manager 200;
- `control_qname = 8` trên cả veth, bridge và `ens33`.

**Capture `tap0`:**

| Kiến trúc | tshark rc | ISB `ifdrop` | `ifrecv` = khung lưu |
|---|---|---|---|
| ARM | 0 | 0 | 78 = 78 |
| MIPS | 0 | 0 | 115 = 115 |

**QEMU và cleanup:**

- Thoát được xác nhận (exitstatus 0) cả hai kiến trúc; không còn `qemu-system`/tshark trong container.
- Verify đầy đủ sau khi tắt guest đạt.
- Fixture, marker và đĩa tạm đã xóa. Ruleset chuẩn hóa lúc chạy giống expected.
- Hai container của lần chạy đã xóa; thư mục capture tạm đã xóa.

**Host capture** (veth, bridge, `ens33`):

- Watcher sống suốt lần chạy, marker trống.
- tcpdump dừng bằng SIGINT, exit 0, 0 gói bị kernel drop.
- `ens33` chưa chạm giới hạn 200000 gói.
- **Cảnh báo rò rỉ:**
  - `alert.txt` không có dòng nào;
  - alert (`any`) và alert_eth (veth) đều bắt 0 gói.
- **Chữ ký:**
  - `sigscan.sh`: `guest_l2l3`, `probe_sport`, `probe_qname`, `probe_url` = 0 trên cả ba pcap;
  - `sigscan_l2.py`: mọi chữ ký = 0 (MAC guest/giả, IP guest, ARP, IPv6 guest, IP nguồn giả, cổng probe, **kích thước ICMP**, qname), kể cả `unscannable_*` = 0.
  - `ens33` có 441 khung bị cắt bởi snaplen 512, nhưng không khung nào mất phần header cần quét.
- **Kiểm tra dương:** veth thấy 35 gói đối chứng từ worker; `ens33` thấy 54 gói đối chứng qua NAT; bridge thấy 1230 gói từ worker.

**Manager:** `exited` → bật cho lần chạy → `exited`, cùng container `494ae3d2e2eb`.

**Host trước/sau:**

- Chỉ `docker-ps` đổi (chuỗi thời gian "Exited … ago" của manager).
- sysctl, ruleset nft, route, `ip-addr`, `ip-link`, cổng nghe, module, QEMU, tiến trình capture và `host-tap0` không đổi.

**Netns worker:**

- Interface, địa chỉ và route chính không đổi.
- Bản ghi đầy đủ khác ở hai chỗ, giống hệt dạng của 06B-4C: `tap0` có `vnet_hdr on` sau khi QEMU mở; có thêm neighbor trên `eth0` (ctl, manager, gateway).
- Neighbor `10.200.0.2` trên `tap0` vẫn `PERMANENT`.

**Mục mở (không giải thích):** trên veth (2995/2987), bridge (5910/5902) và `ens33` (1283/1275), "received by filter" − "captured" = **8**, cả ba bằng nhau. 06B-4C không có mục này. Run script báo là mục mở. *(Đính chính 06B-4H:)* tcpdump báo kernel dropped=0; received−captured=8 vẫn chưa được giải thích; chưa suy thời điểm/nội dung gói.

**Toàn phiên (báo riêng, không đổi kết luận ca):** ARM PASS, MIPS PASS.

**Đối chứng của container ctl** *(bổ sung 06B-4H)*: [`run1/ctl/ctl.jsonl`](task06b4g/run1/ctl/ctl.jsonl) có 810 bản ghi, 1 lỗi. Lần kiểm MongoDB `172.18.0.2:27017` đầu tiên (08:42:21.454 UTC, ngay khi container ctl khởi động, trước khi bật capture và boot guest) báo `TimeoutError('timed out')`. Lần kế tiếp (08:42:23.967) kết nối được, và 269/270 lần kiểm MongoDB đều đạt. Check "control 'mongo …' alive" của run script đạt. Không suy nguyên nhân của lần timeout.

## 5. Kiểm chéo độc lập trên file đã lưu

Script [`crosscheck.py`](task06b4g/crosscheck.py), kết quả [`crosscheck.txt`](task06b4g/crosscheck.txt). Script **không** import module harness:

- giá trị bộ đếm đọc từ JSON nft thô trong `counters-raw.jsonl`;
- khung đếm bằng `tcpdump -r` với bộ lọc BPF viết riêng (kích thước ICMP, đích, type ICMPv6; NS lọc theo nhóm và **cả 16 byte target**);
- vùng tính từ thời điểm đọc đã ghi.

**Kết quả kiểm chéo:**

- **10/10 ca:** số khung probe, số khung chắc chắn và số khung ICMP/ICMPv6 tới guest khớp `icmp-eval.json`.
- **Delta lớp mong đợi:** bằng số khung probe ở mọi ca.
- **Khung IPv6 của guest:** số khung trong cửa sổ khớp delta `l2_bad_ethertype` ở mọi ca, kể cả khung nền.
- **Pcap host, lọc riêng:**
  - các bộ lọc: MAC guest, `10.200.0.0/30`, ICMP độ dài IP 1229–1232, ICMPv6 payload 1309/1310, link-local guest, NS tới nhóm của TAP;
  - kết quả: **0** trên veth, bridge và `ens33`.
- **Kết luận:** chạy lại `icmp_harness.py --outcome` trên file đã lưu cho ARM UNVERIFIED (T13-I1), MIPS PASS. `--run-check`: "ICMP groups complete: ARM MIPS".

*(Đính chính 06B-4H:)* hàm `zone()` của `crosscheck.py` khác định nghĩa đã review `counter_window.zone()`: nó kéo vùng `edge_start` tới `A.t_end + guard`, trong khi bản đã review chỉ tính `[A.t_start − guard, A.t_end]`. Chạy lại bằng bản sửa [`task06b4h/crosscheck-06b4g-v2.py`](task06b4h/crosscheck-06b4g-v2.py) trên cùng output: mọi số đếm **giống hệt**, và không khung nào nằm trong khoảng `(A.t_end, A.t_end + 20 ms]` của bất kỳ ca nào ([`task06b4h/crosscheck-06b4g-v2.txt`](task06b4h/crosscheck-06b4g-v2.txt)). Kết luận kiểm chéo không đổi; file gốc trong `task06b4g/` giữ nguyên.

**Không kiểm chéo độc lập:** đối chiếu từng lớp nền (`drop_spoof`, `drop_public`, ARP) với pcap. Các lớp này chỉ có kết quả đối chiếu của harness (PASS).

## 6. Hạn chế

- **Một lần chạy:** kết quả không chạy lại. Ca ARM T13-I1 vẫn CHƯA KIỂM CHỨNG.
- **Guard 20 ms chưa đo.** ARM T13-I1 cho thấy khung probe có thể rơi vào guard ngay trước lần đọc B.
- **Phạm vi phép thử:**
  - "Kiểm quy tắc" không có đối chứng sống;
  - T12-B3 (`nslookup` tới `224.0.0.251`), T13-I3 (`curl -6`), T14–T17, T20 chưa viết hay chạy;
  - F3–F6, V1/V2 trong luồng thật chưa làm.
- **F1:** mới kiểm lỗi cú pháp ruleset; thiếu binary `nft` chưa kiểm. **F2:** đã kiểm `ALLOW_VM_INTERNET=true` (06B-2A).
- 3 mục mở của tcpdump chưa được giải thích.
- **Phụ thuộc phiên bản:** phản hồi nội bộ của ping6 trong guest ARM (cơ chế chưa xác nhận) và cách BusyBox đếm `-c`/`-w` là quan sát của lần này, phụ thuộc phiên bản image.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"; CT-14 chưa bắt đầu.**

## 7. Hash

Mọi file trong `task06b4g/`: [`SHA256SUMS`](task06b4g/SHA256SUMS) (`4bec69a1474d8ea8b4190f5411b51de493b24891ce02603c41496f2a20d2cbf3`).
