# Minh chứng Nhiệm vụ 06B-4IR1: sửa I1–I3 của review độc lập 06B-4I, chỉ kiểm offline (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4IR2):** Codex review độc lập: **chưa chốt chạy guest**.
>
> - **I1:** các tái hiện khởi động/topology cũ đã sửa, nhưng còn khoảng hở ở **handoff IPv4 dùng chung** (IR1-R1, P1). Guard bị tắt ngay sau cổng topology, nên lệnh `service_link('before probes')` của IPv4 vẫn được gửi khi capture đã mất.
> - **I2:** các trường hợp cũ đã sửa, nhưng còn nhận **MAC endpoint toàn số 0** khi cấu hình và payload bằng nhau (IR1-R2, P2).
> - **I3:** đã sửa trong phạm vi kiểm.
> - Codex cũng **rút lại** việc coi PASS của bốn fixture I2/I3 cũ là bằng chứng (lỗi `sys.argv` của fixture), và đã tự chứng minh lại lỗi 4I bằng biến thể áp đúng.
>
> Sửa ở [`task06b4ir2-summary.md`](task06b4ir2-summary.md). Câu sai được đánh dấu *(đính chính 06B-4IR2)* tại chỗ; log và evidence trong `task06b4ir1/` không sửa.

> **Loại bằng chứng: kiểm thử offline.** Chưa chạy guest; run script **chưa chạy**.
>
> - Không Docker, QEMU, sudo, probe mạng; không đổi host, ruleset, source cô lập, địa chỉ hay guard; không đọc bí mật hay malware.
> - **Guest, console, `nft`, `ip -j neigh`, tshark, log ctl và file capture trong test đều là giả.** Không fixture nào xác nhận raw `ip -j neigh` JSON, operstate, kernel/netifd, netns thật, đối chứng sống thật hay guard 20 ms.
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào

Ba file Codex, đọc toàn bộ:

| File | SHA-256 |
|---|---|
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4i-independent-review.md` | `50b1c87b7e2adb1b5087784c0f56608c8da4f7efd3125cc553c80753f718a1a5` |
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4i-independent-evidence.json` | `a1272737f39e5061d254c2919182a3fccca570481ba22b259c03c9171e582cb6` |
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4i-offline-reproductions.zip` | `6da9f107510c634da4a04eb96d4d6ea7342496fc86e316debb0ae112c18144d0` |

- Bundle giải nén vào thư mục riêng `/home/dathq/projects/ct01-06b4ir1-codex-bundle/`. `bundle-SHA256SUMS` khớp; `harness/` trong bundle giống hệt manifest 4I (35 file).
- Đã đọc `reproduce.py` và `configure-network-extracted.py` trước khi chạy. Chúng chỉ dựng fixture, gọi `probe_matrix.main()` với stub của self-test, và không mở mạng.
- Mọi lần chạy dùng `python3 -I -B` trên **bản sao** của bundle.

**Phát hiện:**

- **I1 (P1):** khởi động và topology gửi lệnh guest ngoài guard. `_configure_network` được gọi trực tiếp; 5 lệnh topology và `monitor info network` đi thẳng tới console. Guard **chưa được tạo** ở đoạn này: đây không phải trường hợp "runner đã dừng mà vẫn gửi".
- **I2 (P1):** A1 với `device` sai hoặc thiếu vẫn ĐẠT/PASS.
- **I3 (P2):** dòng log ctl trùng, hoặc HTTP thiếu `detail`, vẫn là đối chứng đạt.

## 2. Bản làm việc

- `/home/dathq/projects/ct01-06b4ir1/`, chép từ `ct01-06b4i` **sau khi xác minh** 35 file khớp [`task06b4i/harness-sha256.txt`](task06b4i/harness-sha256.txt).
- 4I, evidence `task06b4i/` và log/bundle review không sửa.
- Diff: [`task06b4ir1/ct01-06b4ir1-harness-vs-06b4i.diff`](task06b4ir1/ct01-06b4ir1-harness-vs-06b4i.diff). Hash 35 file: [`task06b4ir1/harness-sha256.txt`](task06b4ir1/harness-sha256.txt).

| File | Thay đổi |
|---|---|
| `probe_matrix.py` | I1: `StartupGuard`, `GuardedConsole`; khối khởi động/topology trong `main()`; docstring đính chính |
| `arp_harness.py` | I2: `_arp_detail_check`, `control_a1` (tham số `ctl_mac`), `make_control`. I3: `ctl_records` (schema), `http_detail_check`, `ctl_window` (trùng/thứ tự, detail của bản ghi lỗi); A2 dùng kiểm HTTP |
| `ctl_loop.py` | payload ARP thêm `ip` và `device_mac` (MAC của device, đọc `/sys/class/net/<dev>/address`) |
| `run-06b4i.sh` | `H` = `ct01-06b4ir1`; lấy `CTL_MAC` bằng `docker inspect` (endpoint của ctl trên `sandboxnet`) và thêm `ctl_mac` vào `CT01_TARGETS`; header kế thừa ghi rõ là lịch sử |
| `selftest_arp_wiring.py`, `mutation_arp_wiring.py` | test và đột biến mới |

**Không sửa:**

- `arp_cases.py` (validator R1, giao kèo ARP), `guest_state.py`;
- `service/analysis.py` của repo, `icmp_*`, `l2*`, `counter_window.py`, `signatures.py`;
- `run-06b4f.sh`, `run-06b3b.sh`.

## 3. Bản sửa

### I1 — guard khởi động/topology (`probe_matrix.py`, mọi suite)

- **`StartupGuard.check(when, what)`:** kiểm cảnh báo rò rỉ (`alert_lines()`, lỗi đọc file → dừng, không bao giờ coi là "không cảnh báo"), rồi `captures_alive`.
  - Lỗi đầu tiên được **chốt** (`stop`): mọi lần kiểm sau ném lại lỗi đó.
  - Rò rỉ ghi bản ghi "NO probe packet seen on host interfaces (leak monitor)" với `phase="startup"` và tên thao tác.
- **`GuardedConsole`:** adapter cục bộ quanh console pexpect.
  - Kiểm **trước mỗi** `send`/`sendline` và **sau mỗi** `expect`; mọi thuộc tính khác chuyển nguyên.
  - Vì vậy sự kiện xảy ra **giữa hai lệnh trong cùng một hàm** cũng chặn được lệnh kế tiếp: giữa `ip addr add` và `route add` trong `_configure_network`, hay giữa các phím của `Guest.monitor`.
  - Không sửa `service/analysis.py`.
- **Trong `main()`:**
  1. Sau `_start_qemu`: kiểm một lần (sau thao tác kích hoạt console; trước đó đã có kiểm "before boot").
  2. `an._configure_network(console, cfg)`; nếu hàm nuốt lỗi thì `startup.stop` vẫn được ném lại ngay sau đó.
  3. `Guest(console)`.
  4. 5 lệnh topology và `monitor info network` qua `startup.run`/`startup.monitor` (kiểm trước/sau mỗi lệnh).
  5. Sau cổng topology: `startup.armed = False`. Các pha nhóm giữ guard riêng: vòng IPv4 và `GuardedRunner` ICMP/ARP. *(Đính chính 06B-4IR2: đúng cho ICMP/ARP; **sai cho IPv4**. Nhánh IPv4 gửi `service_link('before probes')` trực tiếp, trước lần kiểm đầu tiên của vòng probe, nên lệnh đó không được bảo vệ (review: IR1-R1). 06B-4IR2 giữ guard cho tới khi nhánh nhận đã có guard.)*
- **Sau khi dừng:**
  - không gửi thêm thao tác guest nào;
  - đường tắt QEMU dùng **console gốc** `proc` (`A.shutdown_qemu`), cleanup trong `finally` không đổi;
  - lỗi đi theo mã cũ: rò rỉ → 99; mất capture → 98; lỗi khác (vd. file cảnh báo không đọc được) → 1.
- **Không thêm bản ghi** trên đường sạch, nên danh sách xác nhận bắt buộc của ICMP/ARP không đổi.
- **Giới hạn:** phím Enter kích hoạt console bên trong `_start_qemu` (trước khi có console bọc) không được kiểm riêng. Ngay trước spawn có kiểm "before boot", ngay sau `_start_qemu` có kiểm mới.

**Ảnh hưởng tới IPv4/ICMP:** đoạn khởi động/topology dùng chung, nên guard này áp cho cả ba suite.

- Trên đường sạch: không đổi bản ghi, không đổi kết luận. `selftest.sh` ALL PASSED, `selftest_icmp_wiring.py` 129/129.
- Khi có sự kiện ở khởi động/topology: IPv4/ICMP nay dừng sớm hơn (trước đây dừng ở lần kiểm đầu tiên của nhóm).
- Vòng probe IPv4 và nhóm ICMP không đổi. *(Đính chính 06B-4IR2: chính vì vòng IPv4 không đổi nên lệnh liên kết dịch vụ đầu nhánh IPv4 không có guard sau khi guard khởi động bị tắt.)*
- Kịch bản I1.8 (suite ICMP) xác nhận cùng hành vi.

### I2 — interface của entry ARP ctl (A1)

- **Producer (`ctl_loop.py --arp-worker`):** `{ip, hw, flags, device, device_mac}`. `device_mac` đọc từ `/sys/class/net/<device>/address` của ctl; tên device lạ (`/`, `.`, `..`) hoặc không đọc được → bản ghi lỗi.
- **Căn cứ cho interface kỳ vọng:**
  - run script lấy **MAC endpoint của ctl trên `sandboxnet`** bằng `docker inspect … .NetworkSettings.Networks[$SANDBOXNET].MacAddress`, sau khi ctl được tạo, và truyền qua `CT01_TARGETS.ctl_mac`;
  - interface được xác định bằng MAC đó, **không** suy tên (`eth0`) từ worker;
  - ctl sau đó còn được nối `dbnet`, nên entry trên interface dbnet có MAC khác và bị từ chối.
- **Consumer (`control_a1`):** đối chứng không đạt nếu thiếu, sai hoặc không xác định được, kèm lý do:
  - payload phải có **đúng** 5 khóa, `ip` = địa chỉ worker, cờ complete, `hw` = MAC `eth0` worker;
  - `device` là tên interface hợp lệ, `device_mac` = `ctl_mac`;
  - trong cửa sổ chỉ một device;
  - `ctl_mac` thiếu hoặc sai dạng → "ctl interface cannot be identified". *(Đính chính 06B-4IR2: chưa đủ. MAC đúng dạng nhưng không xác định endpoint, như `00:00:00:00:00:00`, ở cả cấu hình và payload vẫn ĐẠT/PASS (IR1-R2). Bổ sung ở 06B-4IR2.)*
- **Hồ sơ:** giữ dữ liệu gốc (`ctl_arp` với vấn đề, `ctl_devices`, `ctl_sandboxnet_mac`) trong `arp-group.json`. Ca thành CHƯA KIỂM CHỨNG; kiến trúc UNVERIFIED, **không PASS**.
- Cùng endpoint dưới **tên khác** (`eth7`) vẫn được nhận (I2.2), vì tên không bị giả định.

### I3 — chất lượng log ctl

- **`ctl_records`:** mỗi dòng phải là object có **đúng** 4 khóa của producer (`ts`, `target`, `ok`, `detail`), `ts` là số hữu hạn, `target` là chuỗi, `ok` là boolean. Sai → `ValueError` → log không đọc được → đối chứng không đạt.
- **Payload theo loại target:**
  - HTTP (`worker-eth0`, `manager`) với `ok=true` phải có `detail == "HTTP 200"`, đúng giá trị `ctl_loop.http_health()` trả về;
  - ARP như I2;
  - bản ghi lỗi phải có `detail` chuỗi (producer ghi `repr(e)`).
- **Trùng:** trong khoảng `[t0 − slack, t1 + slack]` của một target, theo thứ tự file, hai bản ghi cùng `ts` (định danh target + ts) → "duplicate record"; `ts` không tăng → "ts not after the previous record". Không tự bỏ trùng; đối chứng không đạt.
- **Giữ nguyên:** các lần đọc hợp lệ độc lập (ts khác nhau) được chấp nhận (U38); kiểm thời gian trước/sau/trong cửa sổ không đổi (U40: bản ghi cũ 60 s không bao giờ thành "sau B").
- Không tuyên bố lỗi trùng chứng minh được replay vượt kiểm thời gian.

**Giữ nguyên:**

- validator R1 và giao kèo ARP;
- restore lỗi chặn ca sau, FAIL hạ tầng có nguyên nhân;
- FAIL độc lập cùng lỗi đo;
- đối chứng = binding hiện hữu + HTTP theo T14 §3: không flush neighbor, không thêm yêu cầu trao đổi ARP mới.

## 4. Tái hiện trước/sau

Bản sao bundle, `python3 -I -B`. Script của Codex **giữ nguyên byte** (`cmp`): [`codex-repro-before-4I.txt`](task06b4ir1/logs/codex-repro-before-4I.txt), [`codex-repro-after-4IR1.txt`](task06b4ir1/logs/codex-repro-after-4IR1.txt).

| Biến thể (script Codex nguyên trạng) | 4I | 4IR1 |
|---|---|---|
| `topology-leak` | exit 99, **4 lệnh topology + monitor sau sự kiện**; dừng ở liên kết đầu nhóm ARP | exit 99 "LEAK: startup: after 'ip addr'"; **0 lệnh sau sự kiện**, không monitor |
| `topology-capture` | exit 98, 4 lệnh + monitor sau sự kiện | exit 98, 0 lệnh sau sự kiện |
| `boot-leak-v2` (thân `_configure_network` thật) | 3 lệnh khởi động đều gửi, rồi 5 lệnh topology + monitor; exit 99 | chỉ `ip addr add`; không `route add`/DNS, không topology; exit 99 |
| `boot-capture-v2` | như trên, exit 98 | như trên, exit 98 |
| `clean` | PASS | PASS |

**Phát hiện về fixture I2/I3 của Codex.** Luồng ctl giả trong `reproduce.py` đọc biến thể bằng `sys.argv[1]` **bên trong luồng**, nhưng `scenario_main()` đã ghi đè `sys.argv` thành `["probe_matrix.py", "ARM", …]` trước khi luồng chạy. Vì vậy với `a1-wrong-interface`, `a1-missing-interface`, `duplicate-control`, `http-missing-detail`, log ctl **giống log sạch**:

- device `eth0`, không dòng trùng, có `detail`;
- kiểm lại trên `ctl.jsonl` trong bundle của Codex: 177 dòng, 0 trùng, 0 thiếu detail.

Kết quả PASS của bốn biến thể đó trong bundle **không chứng minh** lỗi. Lỗi vẫn có thật theo mã 4I, và đã được xác nhận bằng biến thể áp đúng:

- [`codex-fixed/reproduce_variant_fixed.py`](task06b4ir1/codex-fixed/reproduce_variant_fixed.py), kèm [diff](task06b4ir1/codex-fixed/reproduce_variant_fixed.diff): chỉ đọc biến thể lúc import, và thêm đối chứng `codex-thread-unmodified`;
- kết quả: [`codex-repro-variant-fixed-before-after.txt`](task06b4ir1/logs/codex-repro-variant-fixed-before-after.txt).

| Biến thể (áp đúng; log ctl xác nhận: device `eth9` / không có device / 174 định danh trùng / 118 dòng thiếu detail) | 4I | 4IR1 |
|---|---|---|
| `a1-wrong-interface` | **A1 ĐẠT, PASS** | A1 CHƯA KIỂM CHỨNG, UNVERIFIED |
| `a1-missing-interface` | **A1 ĐẠT, PASS** | A1 CHƯA KIỂM CHỨNG, UNVERIFIED |
| `duplicate-control` | **A1/A2 ĐẠT, PASS** | A1, A2 CHƯA KIỂM CHỨNG, UNVERIFIED |
| `http-missing-detail` | **A1/A2 ĐẠT, PASS** | A1, A2 CHƯA KIỂM CHỨNG, UNVERIFIED |
| `codex-thread-unmodified` (đối chứng: luồng Codex không đổi gì) | PASS | A1 CHƯA KIỂM CHỨNG |

**Lưu ý:**

- Luồng ctl của Codex ghi payload ARP **dạng 4I** (không có `ip`, `device_mac`). Trên 4IR1, A1 của **mọi** biến thể Codex, kể cả đối chứng, đều không đạt vì schema.
- Việc tách I2 khỏi lỗi schema nằm ở test của tôi với payload dạng mới: I2.1 (sai/thiếu interface, hai device, IP khác, thiếu `ctl_mac` → không đạt) và I2.2 (cùng endpoint, tên khác → đạt).
- Với I3, A2 (chỉ phụ thuộc HTTP) là phần phân biệt: 4I ĐẠT → 4IR1 CHƯA KIỂM CHỨNG.

## 5. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp_wiring.py` | **159/159** (116 cũ, đã cập nhật theo schema mới, + 43 mới: U31–U41, I1.1–I1.12, I2.1–I2.2, I3.1, W12–W13); ổn định 3 lần liên tiếp (~65 s mỗi lần) | [`logs/selftest-arp-wiring.log`](task06b4ir1/logs/selftest-arp-wiring.log), [`logs/selftest-arp-wiring-stability.txt`](task06b4ir1/logs/selftest-arp-wiring-stability.txt) |
| Cùng suite trên mã **4I** | 109/159: 50 hỏng, gồm mọi test I1/I2/I3 và W mới. Một số unit hỏng vì chữ ký hàm mới (`TypeError`); các test hành vi qua `main()` hỏng vì 4I PASS/tiếp tục gửi lệnh | [`logs/selftest-arp-wiring-new-tests-on-06b4i-code.log`](task06b4ir1/logs/selftest-arp-wiring-new-tests-on-06b4i-code.log) |
| `mutation_arp_wiring.py` | **60/60** đột biến hành vi (37 cũ V1–V37 + 23 mới V38–V61, bỏ V47) bị bắt đúng test + 2 đối chứng đúng loại; hash harness không đổi. Hai lượt trước giữ nguyên ([`run1`](task06b4ir1/logs/mutation-arp-wiring-run1-before-test-fixes.txt): 56/62; [`run2`](task06b4ir1/logs/mutation-arp-wiring-run2-before-U4-fix.txt): 61/62). Các mục lệch đều do **test**: kiểm mới che mất V1 trong U4; V39/V40/V42 bị bắt ở test khác nên sửa mục tiêu; V43/V44 cần thêm kiểm (không có bản ghi "guest booted"; xóa cảnh báo để thấy tác dụng của chốt). Mã harness không đổi giữa các lượt | [`logs/mutation-arp-wiring.txt`](task06b4ir1/logs/mutation-arp-wiring.txt) |
| `selftest.sh` (do sửa `main()` dùng chung) | ALL PASSED | [`logs/selftest-sh.log`](task06b4ir1/logs/selftest-sh.log) |
| `selftest_icmp_wiring.py` (`main()` ICMP thật) | 129/129 | [`logs/selftest-icmp-wiring.log`](task06b4ir1/logs/selftest-icmp-wiring.log) |
| `selftest_arp.py` (run script gọi; `arp_cases.py` không đổi) | 224/224 | [`logs/selftest-arp.log`](task06b4ir1/logs/selftest-arp.log) |
| Mẫu đột biến cũ còn khớp đúng một chỗ | `mutation_test.sh` 78/78; `mutation_icmp_wiring.py` 34/34 (+ X1 đối chứng) | [`logs/mutation-patterns-still-unique.txt`](task06b4ir1/logs/mutation-patterns-still-unique.txt) |

**Không chạy lại** `mutation_test.sh` (~13 phút) và `mutation_icmp_wiring.py`:

- các đột biến của chúng nhắm vào phần `probe_matrix.py` không đổi (`captures_alive`, `evaluate`, phiên, quét QEMU, nhánh ICMP);
- mọi mẫu vẫn khớp đúng một chỗ;
- `selftest.sh` và `selftest_icmp_wiring.py`, hai suite chúng dùng, vẫn đạt đủ;
- `l2*`, `icmp_cases`, `arp_cases` không đổi.

**Test mới đi qua phần nối thật** (`probe_matrix.main()` → record → evaluator → `result.json` → `arch_outcome` → CLI → khối `case` Bash):

| Test | Nội dung |
|---|---|
| I1.1, I1.2 | Thân `Analysis._configure_network` **thật** (trích bằng ast từ `sandbox-worker/service/analysis.py`, hash ghi trong `scenario.json`) trên console pexpect giả. Sự kiện lúc gửi `ip addr add` → không gửi `route add`, DNS, topology hay monitor; exit 99/98; QEMU tắt, cleanup chạy; FAIL ở hàm, CLI và Bash. Cả khi hàm nuốt mọi ngoại lệ (`boot-leak-swallowed`) |
| I1.3–I1.5 | Sự kiện sau `ip addr` / `ip route` của topology → lệnh đó là thao tác cuối; không record nhóm, không đánh giá; bản ghi rò rỉ có `phase=startup` và tên thao tác |
| I1.6, I1.7 | Sự kiện trong `monitor info network` → dừng trước nhóm ARP. File cảnh báo không đọc được → ERROR exit 1, monitor không gửi |
| I1.8 | Suite ICMP: cùng guard dừng sau `ip addr` |
| I1.9–I1.11 | `probe_matrix.Guest` **thật** trên `GuardedConsole` + pexpect giả: sự kiện sau phím thoát đầu tiên của `monitor` → `info network` không được gõ; sau khi dừng mọi lần gửi bị chặn (chốt); console sạch chạy bình thường; tắt guard thì không kiểm |
| I1.12 | Ca sạch vẫn PASS; A1 có `ctl_devices=["eth0"]` được ràng buộc bằng MAC endpoint |
| I2.1, I2.2 | Device trên endpoint khác, thiếu device, hai device, entry IP khác, thiếu `ctl_mac` → A1 CHƯA KIỂM CHỨNG, lý do và dữ liệu gốc giữ, UNVERIFIED. Cùng endpoint tên `eth7` → PASS |
| I3.1 | Dòng trùng, HTTP thiếu detail, `"HTTP 500"` với `ok=true`, khóa thừa → A1 và A2 CHƯA KIỂM CHỨNG, A3/S1 không đổi |
| U31–U41 | đơn vị cho I2/I3, gồm đọc hợp lệ độc lập được nhận và bản ghi cũ 60 s bị chặn |
| W12, W13 | `CTL_MAC` lấy từ `docker inspect` của ctl trên `sandboxnet`, sau khi ctl được tạo, trước `TARGETS`; header kế thừa ghi là lịch sử |

**Đột biến mới V38–V61** (bỏ V47 vì tắt guard sau topology không quan sát được với guest giả):

| Phạm vi | Đột biến |
|---|---|
| I1 | truyền console gốc cho `_configure_network`; bỏ kiểm trước `sendline`; bỏ kiểm sau `expect`; topology hoặc monitor không qua guard; bỏ ném lại lỗi bị nuốt; bỏ chốt; bỏ kiểm cảnh báo; bỏ `captures_alive` |
| I2 | bỏ kiểm `device_mac`; bỏ kiểm tập khóa; bỏ kiểm `ctl_mac`; bỏ kiểm một device; bỏ kiểm IP; dùng MAC sai làm `ctl_mac`; producer bỏ `device_mac`; run script lấy MAC trên `dbnet` |
| I3 | cho thiếu `detail`; bỏ kiểm payload HTTP; trùng `ts` không bị bắt; A2 bỏ kiểm HTTP; cho `ts` không hữu hạn; bỏ kiểm detail của bản ghi lỗi |

Mutant chỉ tính là bị bắt khi **đúng test mục tiêu** hỏng. ERROR hay timeout không tính là bị bắt.

## 6. Đã kiểm bằng stub và phần cần chạy thật

| Điểm | Offline (stub/fixture) | Chưa xác nhận |
|---|---|---|
| Guard khởi động/topology | thứ tự kiểm/gửi qua console giả; thân `_configure_network` thật; `Guest` thật | pexpect và console QEMU thật; thời điểm thực của sự kiện so với lệnh |
| Interface ctl | so khớp MAC endpoint với `device_mac` | `docker inspect` có trả `MacAddress` cho ctl trên `sandboxnet`; `/proc/net/arp` và `/sys/class/net` trong container ctl thật |
| Log ctl | schema, payload, trùng | nhịp ghi thật; đồng hồ (`ts` lùi do chỉnh giờ sẽ làm đối chứng không đạt: thận trọng, có thể thành CHƯA KIỂM CHỨNG) |
| Collector, trạng thái guest | như 4I | raw `ip -j neigh` JSON, operstate, kernel/netifd, netns thật |
| Mapping ARP | offline (`l2frames.py`) | mapping trên kernel/nft thật; guard 20 ms chưa đo |

## 7. Lỗi còn lại, giới hạn và điều kiện trước khi chạy guest

**Còn lại:**

- **Enter kích hoạt console** trong `_start_qemu` không được kiểm riêng (§3).
- **Nhánh `fail-and-outer-error`** (review ghi nhận, không chặn): một lỗi ngoài nhóm sau khi có vi phạm làm status ERROR, nên `arp-eval.json` không được sinh. Run vẫn FAIL và `arp-group.json` giữ nguyên bằng chứng thô. Chưa thêm đánh giá hậu kỳ; khi review nhánh này cần đọc/replay group.
- **Phạm vi đối chứng A1/A2:** binding hiện hữu cộng HTTP, đúng phạm vi T14 §3. Không chứng minh một trao đổi ARP mới trong cửa sổ.

**Điều kiện trước khi chạy guest:**

1. Reviewer chấp nhận 06B-4IR1 và cho phép chạy.
2. Precheck được duyệt, chỉ đọc:
   - image worker có `ip -j neigh show` và JSON đọc được bằng `arp_cases.parse_neigh_full`;
   - ctl đọc được `/proc/net/arp` và `/sys/class/net/*/address`;
   - `docker inspect` trả MAC manager và MAC ctl trên `sandboxnet`;
   - trạng thái nền như 06B-4G.
3. Chấp nhận trước rằng T15 dễ sinh khung biên (CHƯA KIỂM CHỨNG); guard 20 ms chưa đo.

**Không làm:** chạy guest, script tích hợp, Docker, QEMU, sudo, probe mạng, đổi host/ruleset, đọc bí mật/malware, commit/push/merge, ảnh/snapshot, xóa evidence cũ. Không mở rộng ARP reply giả (D1). CT-01 **không** được nâng.

## 8. Hash

- Bản làm việc: [`harness-sha256.txt`](task06b4ir1/harness-sha256.txt) (35 file).
- Kiểm lại: `ct01-06b4i` khớp manifest 35 file; mọi `SHA256SUMS` của evidence cũ khớp; `arp_cases.py`, `guest_state.py`, `icmp_harness.py`, `run-06b4f.sh`, `run-06b3b.sh` giống hệt 4I.
- Mọi file trong `task06b4ir1/`: [`SHA256SUMS`](task06b4ir1/SHA256SUMS) (`5197b2e90052d3f3f914db346dd8841ee29d06256b72faa7016e718f35c2acd1`).
