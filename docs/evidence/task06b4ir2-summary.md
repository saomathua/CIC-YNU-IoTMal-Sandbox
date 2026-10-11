# Minh chứng Nhiệm vụ 06B-4IR2: sửa IR1-R1 (handoff IPv4) và IR1-R2 (MAC endpoint toàn 0), chỉ offline (08/10/2026)

> **Trạng thái review (cập nhật ở precheck 06B-4IR2):** Codex review hẹp độc lập: IR1-R1 và IR1-R2 **đã khắc phục**; không còn lỗi chặn bước precheck. Người điều phối **chốt 4IR2 ở mức offline**. Đây **không** phải chấp thuận chạy guest. Precheck chỉ đọc: [`task06b4ir2-precheck-summary.md`](task06b4ir2-precheck-summary.md).

> **Loại bằng chứng: kiểm thử offline.** Chưa chạy precheck thật, guest hay run script.
>
> - Không Docker, QEMU, sudo, probe mạng; không đổi host, ruleset, source cô lập hay guard; không đọc bí mật hay malware.
> - **Guest, console, `nft`, `ip -j neigh`, tshark, log ctl, listener và lời gọi TCP/HTTP/DNS trong test đều là giả.**
> - Không fixture nào xác nhận raw `ip -j neigh` JSON, operstate, kernel/netifd, netns thật, `docker inspect` thật, đối chứng sống thật hay guard 20 ms.
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào và trạng thái

| File | SHA-256 |
|---|---|
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir1-independent-review.md` | `93b57d93594b53d141c323b7d32eff89047da89ae423f40bbbfe38f775411f1a` |
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir1-offline-reproductions.zip` | `dd71269b7f05a564aa8d4a8ee08dda7d12532c90893190ddb8935f72368d2044` |

- Bundle giải nén vào `/home/dathq/projects/ct01-06b4ir2-codex-bundle/`. `bundle-SHA256SUMS` khớp; `harness/` trong bundle giống hệt manifest 4IR1.
- Đã đọc `targeted.py` trước khi chạy. Script chỉ sửa helper test **trong bộ nhớ** (listener giả, nhánh phân lớp IPv4 giả) và gọi `main()` thật; không mở mạng.

**Kết luận review 4IR1:**

- **I1:** tái hiện khởi động/topology cũ đã sửa; còn **IR1-R1 (P1)**.
- **I2:** các trường hợp cũ đã sửa; còn **IR1-R2 (P2)**.
- **I3:** đã sửa trong phạm vi kiểm.
- Codex rút lại việc coi PASS của bốn fixture I2/I3 cũ là bằng chứng (lỗi `sys.argv` của fixture), và tự chứng minh lại lỗi 4I bằng biến thể áp đúng. **Đính chính fixture 4I giữ nguyên** trong [`task06b4ir1-summary.md`](task06b4ir1-summary.md) §4.

**Hai lỗi cần sửa:**

- **IR1-R1:** `startup.armed = False` ngay sau topology. Nhánh IPv4 gửi `service_link('before probes')` bằng `g.run` trực tiếp, nên khi capture mất đúng lúc đó, lệnh `curl …get-task…` vẫn tới guest.
- **IR1-R2:** `ctl_mac` và `device_mac` chỉ được kiểm định dạng và so bằng; `00:00:00:00:00:00` ở cả hai nguồn → A1 ĐẠT, PASS.

## 2. Bản làm việc

- `/home/dathq/projects/ct01-06b4ir2/`, chép từ `ct01-06b4ir1` **sau khi xác minh** 35 file khớp [`task06b4ir1/harness-sha256.txt`](task06b4ir1/harness-sha256.txt).
- 4IR1, evidence cũ và bundle review không sửa.
- Diff: [`task06b4ir2/ct01-06b4ir2-harness-vs-06b4ir1.diff`](task06b4ir2/ct01-06b4ir2-harness-vs-06b4ir1.diff). Hash 35 file: [`task06b4ir2/harness-sha256.txt`](task06b4ir2/harness-sha256.txt).

| File | Thay đổi |
|---|---|
| `probe_matrix.py` | IR1-R1: handoff guard (§3); `StartupGuard.run` nhận `timeout`; thuộc tính `phase` |
| `arp_harness.py` | IR1-R2: `endpoint_mac_problem`; dùng cho `ctl_mac` (cấu hình) và `device_mac` (payload) |
| `run-06b4i.sh` | chỉ `H` = `ct01-06b4ir2` và chú thích (giữ tên file như 4FR) |
| `selftest_arp_wiring.py`, `mutation_arp_wiring.py` | test và đột biến mới |

**Không sửa:** `ctl_loop.py`, `arp_cases.py` (validator R1), `guest_state.py`, `service/analysis.py`, `icmp_*`, `l2*`, `counter_window.py`, `signatures.py`, run script cũ.

## 3. Bản sửa

### IR1-R1 — handoff guard sang nhánh nhận

- **Không tắt guard sau topology nữa.** Guard chỉ được chuyển giao ở chỗ nhánh nhận đã có guard riêng:
  - **ARP/ICMP:** `startup.armed = False` ngay trước `run_arp`/`run_icmp`. Giữa hai điểm này không có lệnh guest nào: chỉ đọc MAC, ghi record và lưu lượng kiểm capture **phía worker**. `GuardedRunner` của nhánh kiểm trước và sau **mọi** lệnh guest, kể cả lệnh đầu tiên.
  - **IPv4:** guard **giữ nguyên** cho cả nhánh (`phase = "ipv4 group"`). `service_link('before probes')`, `service_link('after probes')` và từng probe (`curl --local-port …`, `nslookup …`) đi qua `startup.run(g, cmd, timeout)`: kiểm cảnh báo rò rỉ rồi capture/heartbeat **trước và sau mỗi lệnh**. Với `Guest` thật, `GuardedConsole` còn kiểm trước mỗi lần gửi và sau mỗi lần chờ.
- Trong `main()` không còn lời gọi `g.run`/`g.monitor` trực tiếp nào.
- **Chốt dừng (latch), tắt QEMU bằng console gốc và cleanup trong `finally`** không đổi. Mã thoát: rò rỉ → 99; mất capture → 98; lỗi khác (vd. file cảnh báo không đọc được) → 1.
- **Hành vi sạch:** không thêm bản ghi nào trên đường sạch (danh sách xác nhận bắt buộc của ICMP/ARP không đổi).
  - IPv4 sạch (offline) vẫn gửi đủ liên kết → 7 probe → liên kết theo thứ tự, status COMPLETED.
  - Các kiểm tra sẵn có của vòng IPv4 (captures trước probe, cảnh báo và captures sau probe) giữ nguyên. Guard chỉ thêm kiểm trước/sau lệnh.
- **Thay đổi trên đường lỗi IPv4:** cảnh báo xuất hiện **trong** một probe IPv4 nay được guard bắt ngay sau lệnh. Bản ghi rò rỉ có `phase="ipv4 group"` và tên lệnh, trước khi vòng cũ kịp ghi bản ghi probe đó. Kết quả vẫn exit 99, FAIL.

### IR1-R2 — MAC endpoint phải dùng được để nhận diện

`endpoint_mac_problem(mac)` theo giao kèo Ethernet:

- **từ chối:** 6 octet sai định dạng; toàn 0 (không có địa chỉ); MAC nhóm (bit I/G 0x01 của octet đầu, gồm multicast và broadcast `ff:…`);
- **vẫn nhận:** MAC unicast locally administered (bit U/L 0x02, như Docker cấp, vd. `02:42:…`, `0a:…`).

Áp cho **cả hai nguồn**:

- `ctl_mac` của cấu hình: không dùng được → "ctl interface cannot be identified" kèm lý do;
- `device_mac` của payload: không dùng được → "device_mac unusable to identify the ctl interface".

Hai giá trị không dùng được **bằng nhau vẫn bị từ chối**. Hồ sơ giữ nguyên giá trị gốc (không tự thay MAC): A1 CHƯA KIỂM CHỨNG, kiến trúc UNVERIFIED, không PASS. Endpoint đúng dưới tên `eth7` vẫn PASS.

**Giữ nguyên:** I3 (schema/payload/trùng), validator R1, restore lỗi chặn ca sau, phân biệt FAIL hạ tầng với bằng chứng vi phạm ARP.

## 4. Tái hiện trước/sau

`targeted.py` của Codex **nguyên byte** (`cmp`), chạy `python3 -I -B` trên bản sao bundle với `harness/` = 4IR1 (trước) hoặc 4IR2 (sau): [`logs/codex-targeted-before-4IR1.txt`](task06b4ir2/logs/codex-targeted-before-4IR1.txt), [`logs/codex-targeted-after-4IR2.txt`](task06b4ir2/logs/codex-targeted-after-4IR2.txt).

| Biến thể | 4IR1 | 4IR2 |
|---|---|---|
| `ipv4-handoff` (mất capture ngay sau cổng topology) | **1 lệnh `curl …get-task…` gửi tới guest**, rồi exit 98 ở "before probe internet-tcp" | **0 lệnh** sau handoff; exit 98 "CAPTURE LOST: ipv4 group: before 'curl …'" |
| `icmp-handoff` | 0 lệnh, exit 98 | 0 lệnh, exit 98 |
| `arp-handoff` | 0 lệnh, exit 98 | 0 lệnh, exit 98 |
| `cfg-zero-mac` (`ctl_mac` = `device_mac` = `00:…:00`) | **A1 ĐẠT, PASS** (hàm, CLI, Bash) | A1 CHƯA KIỂM CHỨNG, UNVERIFIED |
| `device-eth7` | PASS | PASS |
| `clean` | PASS | PASS |

## 5. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp_wiring.py` | **182/182** (159 cũ + 23 mới); ổn định 3 lần liên tiếp (~74 s mỗi lần) | [`logs/selftest-arp-wiring.log`](task06b4ir2/logs/selftest-arp-wiring.log), [`logs/selftest-arp-wiring-stability.txt`](task06b4ir2/logs/selftest-arp-wiring-stability.txt) |
| Cùng suite trên mã **4IR1** | 168/182: 14 hỏng (R1.2 ×4, R1.5, R2.1 ×5, U42, U43, S42, W2) | [`logs/selftest-arp-wiring-new-tests-on-06b4ir1-code.log`](task06b4ir2/logs/selftest-arp-wiring-new-tests-on-06b4ir1-code.log) |
| `mutation_arp_wiring.py` | **67/67** đột biến hành vi (60 cũ, trong đó V45/V46/V50 đã sửa mẫu, + 7 mới V62–V68) bị bắt đúng test + 2 đối chứng đúng loại, ngay lượt đầu; hash harness không đổi. ERROR/timeout không tính là bắt | [`logs/mutation-arp-wiring.txt`](task06b4ir2/logs/mutation-arp-wiring.txt) |
| `selftest.sh` (do sửa `main()` dùng chung) | ALL PASSED | [`logs/selftest-sh.log`](task06b4ir2/logs/selftest-sh.log) |
| `selftest_icmp_wiring.py` (`main()` ICMP thật) | 129/129 | [`logs/selftest-icmp-wiring.log`](task06b4ir2/logs/selftest-icmp-wiring.log) |
| Mẫu đột biến cũ còn khớp đúng một chỗ | `mutation_test.sh` 78/78; `mutation_icmp_wiring.py` 34/34 (+ X1 đối chứng) | [`logs/mutation-patterns-still-unique.txt`](task06b4ir2/logs/mutation-patterns-still-unique.txt) |

**Không chạy lại:** `selftest_arp.py` (`arp_cases.py` không đổi; lần chạy 224/224 ở 06B-4IR1 vẫn áp dụng) và `mutation_test.sh`/`mutation_icmp_wiring.py` (nhắm phần không đổi; mẫu vẫn khớp đúng một chỗ; hai suite chúng dùng đều đạt).

**Test mới** (qua `probe_matrix.main()` thật → record → evaluator → `result.json` → `arch_outcome` → CLI → khối `case` Bash; IPv4 dùng listener và lời gọi TCP giả, không mở socket):

| Test | Nội dung |
|---|---|
| R1.1 | IPv4 sạch: liên kết, 6 probe TCP + 1 `nslookup`, liên kết, đúng thứ tự; status COMPLETED |
| R1.2, R1.3 | Ngay sau cổng topology: mất capture, rò rỉ, file cảnh báo không đọc được (lỗi kiểm), heartbeat cũ → **không lệnh guest nào** sau handoff; exit 98/99/1/98; QEMU tắt, cleanup chạy; FAIL |
| R1.4 | Mất capture trong lúc liên kết 'before probes' → lệnh đó là lệnh cuối, không probe nào |
| R1.5 | Cảnh báo trong probe IPv4 đầu tiên → probe đó là lệnh cuối; bản ghi rò rỉ `phase="ipv4 group"`; exit 99 |
| R1.6 | ICMP, ARP: mất capture hoặc rò rỉ ngay sau topology → 0 lệnh guest; exit 98/99 |
| R2.1 | MAC toàn 0 chỉ ở cấu hình, chỉ ở payload, ở cả hai; broadcast cả hai; multicast cả hai (payload sạch, chỉ đổi điều kiện đang kiểm) → A1 CHƯA KIỂM CHỨNG, A2 ĐẠT, UNVERIFIED (hàm = CLI, Bash) |
| R2.2 | Giá trị gốc `00:…:00` giữ trong record, không bị thay |
| R2.3 | MAC unicast locally administered khác (`0a:…`) ở cả hai nguồn → PASS |
| U42, U43 | `endpoint_mac_problem`; `control_a1` với zero/nhóm bằng nhau và payload zero với cấu hình hợp lệ |

R1.4 cũng đạt trên 4IR1, vì vòng probe cũ đã kiểm capture trước probe đầu. Đây là kiểm hồi quy, không phải kiểm phân biệt.

**Đột biến mới V62–V68:**

- IPv4 `service_link` gọi `g.run` trực tiếp;
- probe TCP gọi `g.run` trực tiếp;
- tắt guard ngay sau topology như 4IR1;
- bỏ kiểm MAC toàn 0;
- bỏ kiểm bit I/G;
- bỏ kiểm `device_mac` dùng được;
- `ctl_mac` chỉ kiểm định dạng.

V45, V46, V50 được sửa mẫu theo dòng mới (`phase=self.phase`, `endpoint_mac_problem`). Không thêm đột biến tắt guard ở ARP/ICMP: với guest giả, việc giữ hay tắt guard console ở các nhánh đó không quan sát được.

## 6. Giới hạn và đề xuất riêng (không mở rộng trong lượt này)

- **Enter kích hoạt console** trong `_start_qemu`: chỉ có kiểm trước boot và sau khi hàm trả, không bọc từng phím (review: không phải lỗi chặn trong giao kèo boot hiện có). Đổi tiêu chí thì cần người điều phối chốt phạm vi boot.
- **Chốt lỗi transport native:** ngoại lệ từ `proc.sendline/expect` khi guard còn khỏe không tự chốt `stop` trong adapter; `main()` vẫn xử lý và teardown. Đề xuất riêng.
- **Đánh giá hậu kỳ cho status ERROR** sau khi group đã lưu (`fail-and-outer-error`): chưa làm; run vẫn FAIL, `arp-group.json` giữ bằng chứng thô. Đề xuất riêng.
- Đối chứng A1/A2 là binding hiện có + HTTP theo T14 §3, không chứng minh trao đổi ARP mới trong cửa sổ.
- **Chưa xác nhận:**
  - raw `ip -j neigh` JSON, operstate, kernel/netifd;
  - mapping nft/kernel thật;
  - netns thật;
  - `docker inspect` thật (`MacAddress` của ctl/manager);
  - đối chứng sống thật;
  - guard 20 ms.

**Điều kiện trước khi chạy guest:**

1. Reviewer chấp nhận 06B-4IR2.
2. Precheck chỉ đọc được duyệt (image/collector, interface và MAC ctl, schema dữ liệu, trạng thái nền).
3. Người điều phối cho phép chạy.

Review này không cấp phép precheck hay guest. Không mở rộng ARP reply giả (D1). CT-01 **không** được nâng.

## 7. Hash

- Bản làm việc: [`harness-sha256.txt`](task06b4ir2/harness-sha256.txt) (35 file).
- Kiểm lại: `ct01-06b4ir1` khớp manifest; mọi `SHA256SUMS` của evidence cũ khớp; `ctl_loop.py`, `arp_cases.py`, `guest_state.py`, `icmp_harness.py`, run script cũ giống hệt 4IR1.
- Mọi file trong `task06b4ir2/`: [`SHA256SUMS`](task06b4ir2/SHA256SUMS) (`f25802d57fd7ad7daed7e5c2bfa519498dc0a42a2459aeb023d2d8a66c555bfd`).
