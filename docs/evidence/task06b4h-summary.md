# Minh chứng Nhiệm vụ 06B-4H: đính chính hồ sơ 06B-4G và chuẩn bị offline T14/T15 (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4HR):** Codex review độc lập: **còn lỗi, chưa chấp nhận nối tích hợp**. Ba lỗi P1 có thể báo ĐẠT sai (F1 S1 nhận opcode 2/99; F2 neighbor thiếu/sai vẫn coi là không đổi; F3 hồ sơ lệnh thiếu vẫn exit 0) và hai lỗi P2 (F4 ping rc 2 bị nuốt; F5 lỗi đo che FAIL đã xác định). Phần sửa và tái hiện trước/sau ở [`task06b4hr-summary.md`](task06b4hr-summary.md). Các câu bị phản ví dụ bác bỏ được đánh dấu *(đính chính 06B-4HR)* ngay tại chỗ; phần đính chính hồ sơ 06B-4G ở §1 được chấp nhận. Mọi hành vi guest/kernel trong tài liệu này là **mô phỏng** trong kiểm thử offline, chưa phải hành vi guest thật.

> **Loại bằng chứng:**
>
> - Phần 1 là **đính chính hồ sơ**.
> - Phần 2 là **kiểm thử offline**: fixture, guest mô phỏng, stub.
> - Không Docker, QEMU, sudo, probe mạng; không đổi host, source cô lập, ruleset, địa chỉ hay guard.
> - **T14/T15 chưa chạy trên guest, chưa nối vào run script tích hợp.**
> - Guard 20 ms vẫn là giả định chưa đo.
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đính chính hồ sơ 06B-4G

Chỉ sửa [`task06b4g-summary.md`](task06b4g-summary.md) và [`../../KQCaiTien.md`](../../KQCaiTien.md); log, pcap và evidence trong `task06b4g/` **không** sửa (`SHA256SUMS` vẫn khớp).

**Trạng thái:** chấp nhận **đúng phạm vi**: 9/10 ca kiểm quy tắc đạt, ARM T13-I1 UNVERIFIED, exit 4, ba mục OPEN còn nguyên.

**Câu đã sửa:**

| Chỗ sửa | Thành |
|---|---|
| Mục mở tcpdump | "tcpdump báo kernel dropped=0; received−captured=8 vẫn chưa được giải thích; chưa suy thời điểm/nội dung gói." (thay câu "đây không phải gói bị drop") |
| "không có phản hồi về guest" | chỉ áp dụng cho **ICMP/ICMPv6 của probe**; TCP của liên kết dịch vụ và ARP của worker tới guest vẫn có |
| Phản hồi ping6 từ địa chỉ guest | chỉ **phù hợp với** phản hồi nội bộ guest; chưa có capture trong guest xác nhận cơ chế |
| Hành vi `-c`/`-w` của BusyBox | ghi là phù hợp với, chưa xác nhận riêng |

**Bổ sung:**

- **Timeout MongoDB.** Trong [`task06b4g/run1/ctl/ctl.jsonl`](task06b4g/run1/ctl/ctl.jsonl) (810 bản ghi, 1 lỗi):
  - lần kiểm MongoDB `172.18.0.2:27017` **đầu tiên**, lúc 08:42:21.454 UTC (container ctl vừa khởi động, trước khi bật capture và boot guest), báo `TimeoutError('timed out')`;
  - lần kế tiếp (08:42:23.967) kết nối được; 269/270 lần kiểm MongoDB đạt.
  - Không suy nguyên nhân.
- **Phát hiện thêm khi làm 06B-4H — cross-check 06B-4G.** Hàm `zone()` trong `task06b4g/crosscheck.py` kéo vùng `edge_start` tới `A.t_end + guard`. Định nghĩa đã review (`counter_window.zone`) chỉ tính `[A.t_start − guard, A.t_end]`.
  - Bản sửa [`crosscheck-06b4g-v2.py`](task06b4h/crosscheck-06b4g-v2.py) chạy trên cùng output cho số đếm **giống hệt** ([`crosscheck-06b4g-v2.txt`](task06b4h/crosscheck-06b4g-v2.txt)).
  - Không khung nào của 06B-4G rơi vào khoảng `(A.t_end, A.t_end + 20 ms]`.
  - Kết luận kiểm chéo không đổi; đã ghi đính chính trong summary 06B-4G.

## 2. Chuẩn bị offline T14/T15

**Đã đọc lại trước khi viết** [`../ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md):

- §1.3 (quy tắc chung, khôi phục), §1.4 (L1, L2), T14, T15, §3.2 (ánh xạ ARP), §5.1 (G7, G8);
- §5.2 (quyết định): **D1** chưa nạp công cụ mới; **D2** cho phép đổi guest tạm thời có khôi phục; **D6** nhãn kiểm quy tắc.

**Bản làm việc:**

- Bản mới `/home/dathq/projects/ct01-06b4h/`, chép từ `ct01-06b4fr` (06B-4FR, đã review) **sau khi xác minh** 28 hash; bản cũ giữ nguyên.
- **Chỉ thêm 3 file:** `arp_cases.py`, `selftest_arp.py`, `mutation_arp.py`. 28 file cũ giống hệt.
- **Không file nào đã review bị sửa:** `guest_state.py`, `l2frames.py`, `l2eval.py`, `counter_window.py`, `signatures.py`, `probe_matrix.py`, run script.
- Diff: [`task06b4h/ct01-06b4h-harness-vs-06b4fr.diff`](task06b4h/ct01-06b4h-harness-vs-06b4fr.diff). Hash 31 file: [`task06b4h/harness-sha256.txt`](task06b4h/harness-sha256.txt).

### 2.1 Các ca (đúng phạm vi kế hoạch)

Lệnh đầy đủ cho ARM `eth1` và MIPS `br-lan`: [`task06b4h/prepared-cases.txt`](task06b4h/prepared-cases.txt).

| Ca | Cách tạo khung (kernel guest, công cụ có sẵn) | Mong đợi | Đối chứng |
|---|---|---|---|
| T14-A1 | `ip route add 192.168.60.2/32 dev IF`; `ping -c 1 -W 2 -s 1401 192.168.60.2`; `sleep 3` | ARP request `tpa=192.168.60.2` → `arp_in_drop` | sống: ARP trên `sandboxnet` (do harness tích hợp cung cấp) |
| T14-A2 | như trên với `192.168.60.10`, size 1402 | `arp_in_drop` | sống: như A1 |
| T14-A3 | như trên với `10.200.0.6`, size 1403 | `arp_in_drop` | kiểm quy tắc |
| T15-S1 | `echo 1 > …/IF/arp_notify`; `ip addr add {10.200.0.1, 192.168.60.10, 192.168.60.1}/32 dev IF`; `ip link set dev IF down`; `… up`; `sleep 3` | gratuitous ARP (`spa = tpa`) cho mọi địa chỉ → `arp_in_drop` | kiểm quy tắc + kiểm neighbor worker |

- Kích thước chỉ lấy từ `signatures.py` (T14-A1..A3).
- `sleep 3` để các lần ARP gửi lại của kernel (`mcast_solicit` 3 × 1 s, giả định G7) kết thúc trước lần đọc B. Nếu không kết thúc kịp, khung ở biên → CHƯA KIỂM CHỨNG, không bao giờ ĐẠT.
- **Không làm (D1):**
  - ARP reply giả (T15 mức 2), gratuitous dạng reply, sai `htype`/`hlen`/`plen`;
  - không `arping`, không công cụ gói thô, không công cụ mới.

### 2.2 Thực thi (`run_group`, chuẩn bị, **chưa gọi thật**)

Mọi phụ thuộc đều tiêm được: console guest, đọc bộ đếm, liên kết dịch vụ, neighbor worker, đối chứng.

- **Trước nhóm:** kiểm liên kết dịch vụ; không đạt thì bỏ cả nhóm.
- **Mỗi ca, theo thứ tự:**
  1. neighbor worker (trước);
  2. `guest_state.GuestChange` lưu trạng thái `IF`: MAC, link, địa chỉ, route, neighbor tĩnh, `arp_notify`;
  3. đọc A → setup → trigger → settle → đọc B;
  4. **khôi phục, kể cả khi có lỗi;**
  5. neighbor worker (sau);
  6. đối chứng sống (A1/A2);
  7. liên kết dịch vụ sau ca (chỉ khi đã khôi phục).
- **Lỗi bước:**
  - setup/settle lỗi, `ip link` lỗi hoặc thiếu công cụ thì dừng ca đó; ghi lỗi thực thi; vẫn đọc B và vẫn khôi phục;
  - ping không có phản hồi (rc 1) là kết quả **mong đợi**.
- **Khôi phục thất bại:** dừng nhóm; các ca sau **không chạy**, ghi CHƯA KIỂM CHỨNG.
- Trạng thái guest không đọc được trước ca: không gửi lệnh nào, không có gì để khôi phục.

### 2.3 Đánh giá (`evaluate_case` / `evaluate_group`)

Dùng các hàm đã review: `l2frames.classified_frames`, `reconcile_l2` (mọi lớp có bộ đếm), `probe_verdict_l2`, `strict_delta`, và `l2eval.load_reads`/`check_classes`.

- **Khung probe** nhận diện bằng trường ARP, không bằng lớp bộ đếm:
  - T14: guest, ARP, `op = 1`, `sha = MAC guest`, `spa = 10.200.0.2`, `tpa = đích`;
  - T15: guest, ARP, `sha = MAC guest`, `spa = tpa` ∈ {10.200.0.2, 3 IP giả}. *(Đính chính 06B-4HR: bản 4H **không** kiểm opcode, nên khung opcode 2/99 cũng được tính là probe và S1 vẫn ĐẠT. 06B-4HR chỉ nhận gratuitous ARP **request**: `op = 1`, htype 1, ptype IPv4, hlen 6, plen 4, đích broadcast.)*
- **Thứ tự** FAIL > LỖI PHÉP ĐO > CHƯA KIỂM CHỨNG > ĐẠT. *(Đính chính 06B-4HR: bản 4H **không** giữ thứ tự này khi có lỗi đọc: `read_error`, thiếu lần đọc, lỗi đối chiếu hay lỗi capture/bộ đếm trả LỖI PHÉP ĐO **trước** khi tìm bằng chứng FAIL, nên FAIL đã xác định bị che và mất chi tiết. 06B-4HR thu bằng chứng FAIL trước và giữ cả hai trong JSON.)*

| Kết quả | Điều kiện |
|---|---|
| **FAIL** | đối chiếu bộ đếm FAIL; khung probe vào lớp có bộ đếm khác `arp_in_drop`; worker gửi ARP cho IP đích (T14) hoặc về IP giả (T15); có gói ICMP probe (tức ARP đã phân giải); neighbor worker đổi (tap0 khác trước/sau, entry ngoài tap0 mang MAC guest, IP được theo dõi đổi MAC) |
| **LỖI PHÉP ĐO** | lần đọc lỗi/thiếu; bộ đếm giảm hoặc thiếu (kể cả `arp_out_drop`); capture không đọc được; bảng neighbor worker không đọc được |
| **LỖI THỰC THI** | bước setup/trigger lỗi, thiếu công cụ, timeout console, trạng thái guest không đọc được |
| **KHÔNG TẠO ĐƯỢC GÓI** | không có khung probe; T15 thiếu gratuitous cho một IP giả. **Không phải bằng chứng chặn.** |
| **CHƯA KIỂM CHỨNG** | khung ở biên; khung không có bộ đếm (vd. `arp_not_hooked`); đối chứng sống không đạt (A1/A2); `arp_out_drop` tăng; khôi phục không thành công; liên kết trước nhóm hoặc sau ca không đạt (`ok` phải đúng bằng `True`); ca không chạy |
| **ĐẠT** (A1/A2) / **ĐẠT (kiểm quy tắc)** (A3/S1) | đúng khung probe, đúng bộ đếm, liên kết trước/sau đạt, khôi phục thành công, neighbor worker không đổi. *(Đính chính 06B-4HR: bộ so sánh neighbor của 4H **không đủ** để kết luận "không đổi": entry bị xóa, chuyển interface, MAC sai kiểu/`null`, thiếu `state` hay hàng trùng che MAC guest đều vẫn ĐẠT.)* |

- **Bản ghi nhóm:** mỗi ca đúng một lần (trừ nhóm bị bỏ qua), nhãn đọc bộ đếm và lệnh guest đúng như bản đã review. Thiếu, trùng, lạ hay sai lệnh thì `record_problems`, và CLI không bao giờ trả 0 (exit 2). *(Đính chính 06B-4HR: câu này **sai**. Bản 4H chấp nhận mọi tiền tố lệnh, kể cả rỗng hay chỉ setup; không kiểm phase/rc hay baseline/restore. Nhóm như vậy vẫn có bốn ca ĐẠT và exit 0. Ngoài ra ping rc 2 không được ghi là lỗi thực thi.)*

## 3. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp.py` | **90/90**; ổn định 5 lần | [`logs/selftest-arp.log`](task06b4h/logs/selftest-arp.log), [`logs/selftest-arp-stability.txt`](task06b4h/logs/selftest-arp-stability.txt) |
| `mutation_arp.py` | **29/29** đột biến hành vi bị bắt đúng test + 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-arp.txt`](task06b4h/logs/mutation-arp.txt) |
| `selftest_l2.py --offline-only` (module `guest_state`/`l2frames` mà ca mới dùng; không sửa) | 175/175 | [`logs/selftest-l2.log`](task06b4h/logs/selftest-l2.log) |
| `selftest_l2eval.py --offline-only` (`l2eval`; không sửa) | 65/65 | [`logs/selftest-l2eval.log`](task06b4h/logs/selftest-l2eval.log) |

Không chạy lại các suite IPv4/ICMP/wiring: không file nào của chúng đổi.

**Fixture và stub theo yêu cầu:**

| Yêu cầu | Test |
|---|---|
| Ca sạch | P1 (4 ca), P2 (có nền DHCP/MLD), E1/E2 (đầu-cuối trên guest mô phỏng) |
| Sai trường ARP | P3 (sender MAC, target IP, opcode reply, `hlen` 8), P4 (MAC đích OTHERHOST → `arp_not_hooked`), P36 (spa giả nhưng không gratuitous) |
| Không tạo gói | P5, P6 (T15 thiếu IP), P7, E3 |
| Lỗi đo | P8 (đọc lỗi), P9 (thiếu đọc B), P10 (bộ đếm giảm), P11 (thiếu `arp_out_drop`), P12 (capture không đọc được), P13 (neighbor không đọc được), X13 |
| Gói biên | P14 (biên đọc A), P15 (biên đọc B) |
| Lỗi thực thi | P16, P17, P18; X7 (timeout console giữa ca → vẫn đọc B, vẫn khôi phục), X8 (setup lỗi → không gửi trigger), X9 (trạng thái không đọc được), X18 (`link down` lỗi) |
| Lỗi khôi phục | P19, P20, P21; X6 và E4 (khôi phục lỗi → ca sau không chạy, không ĐẠT) |
| Liên kết / đối chứng | P22–P26, P37, X4, X10, X19 |
| FAIL đã xác định | P28–P35, E5 (neighbor manager mang MAC guest trong lúc A2) |
| Bản ghi | X5, X14–X17, C1–C5 |
| Neighbor | N1–N9 |
| Định nghĩa | D1–D9 (kích thước từ registry, chỉ `ip`/`ping`/`sleep`/`echo`, không `arping`/gói thô) |

**Guest mô phỏng:** `SimGuest` mở rộng `selftest_l2.FakeGuest` đã review.

- Đích on-link không phân giải → 3 ARP request.
- `link up` với `arp_notify=1` → 1 gratuitous cho mỗi địa chỉ.
- Bộ đếm theo `l2frames.classify`.

Đây là hành vi kernel/ruleset **mô phỏng, chưa kiểm**.

## 4. Phạm vi phủ và phần chưa phủ

**Phủ (offline):** T14-A1, A2, A3; T15-S1 (mức 1). Gồm:

- tạo khung bằng kernel guest; lưu và khôi phục trạng thái *(đính chính 06B-4HR: đây là **luồng lệnh và fixture mô phỏng** đã kiểm offline; hành vi kernel/guest thật chưa được kiểm)*;
- đối chiếu bộ đếm/pcap trên mọi lớp; kiểm neighbor worker;
- liên kết trước/sau; đối chứng sống A1/A2 (dưới dạng đầu vào).

**Chưa phủ:**

- **T15 mức 2 (D1):** ARP reply giả, gratuitous dạng reply, ARP sai `htype`/`hlen`/`plen`.
- **ARP có `spa` khác `10.200.0.2` ngoài gratuitous:** thuộc T17.
- **ARP unicast tới MAC khác `TAP_MAC`:** chỉ có fixture `arp_not_hooked`.
- **Thiết kế đối chứng sống A1/A2 chưa cụ thể:** đọc `/proc/net/arp` của ctl, hoặc `ip neigh` của worker trên `eth0` sau một kết nối. Việc nối vào harness tích hợp, đọc `ip -j neigh` trong worker và đường lệnh qua `GuardedRunner` **chưa làm**; run script chưa đổi.
- **Giả định chưa kiểm:**
  - [Kernel] thứ tự kiểm trong `arp_rcv`; gratuitous khi `arp_notify` và `NETDEV_UP`; link down xóa route và neighbor;
  - G7 (số ARP gửi lại), G8 (netifd sau down/up, đặc biệt `br-lan` trên MIPS);
  - BusyBox `ip`/`ping -W` trên hai image; `echo > /proc/...` được phép trong guest.
- **Guard 20 ms chưa đo.** Link down/up ở T15 dễ sinh gói biên và lưu lượng nền (DHCP, IPv6), nên dễ CHƯA KIỂM CHỨNG.

## 5. Hash

Mọi file trong `task06b4h/`: [`SHA256SUMS`](task06b4h/SHA256SUMS) (`77b83defc543c09389cc5f3547bb5338e73a7242bd2b96602d628a7b3baafd4b`).
