# Minh chứng Nhiệm vụ 06B-4I: nối ARP 06B-4HR2 vào harness, chỉ kiểm offline (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4IR1):** Codex review độc lập: **chưa chấp nhận để chạy guest**. Còn hai lỗi chặn và một lỗi kiểm hồ sơ:
>
> - **I1 (P1):** khởi động và topology gửi lệnh guest **ngoài guard**. Guard **chưa được tạo** ở đoạn đó; đây không phải trường hợp "runner đã dừng mà vẫn gửi".
> - **I2 (P1):** đối chứng A1 với interface sai hoặc thiếu vẫn ĐẠT.
> - **I3 (P2):** log đối chứng trùng, hoặc HTTP thiếu payload, vẫn được nhận.
>
> Sửa ở [`task06b4ir1-summary.md`](task06b4ir1-summary.md). Các câu sai được đánh dấu *(đính chính 06B-4IR1)* ngay tại chỗ. Log, fixture và evidence trong `task06b4i/` không sửa.

> **Loại bằng chứng: kiểm thử offline của phần nối.** Chưa chạy guest; run script mới **chưa chạy**.
>
> - Không Docker, QEMU, sudo, probe mạng; không đổi host, ruleset, source cô lập, địa chỉ hay guard; không đọc bí mật hay malware.
> - **Mọi hành vi guest/kernel/netifd, bảng neighbor, log đối chứng và capture trong test đều là mô phỏng/stub.** Không fixture nào xác nhận raw `ip -j neigh` JSON, operstate thật, hành vi kernel/netifd, đối chứng sống thật hay guard 20 ms.
> - Guard 20 ms vẫn là giả định chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào

- Bản `/home/dathq/projects/ct01-06b4hr2/` (06B-4HR2).
- Review Codex `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4hr2-independent-review.md`, SHA-256 `313e332bdc52f9de3f0e12266bf906240c4cc7a7e8383e853408e02afc306c3b`. Đọc toàn bộ.
  - Kết luận: **R1 đã khắc phục; chấp nhận bản sửa ở mức offline.** Review không xác nhận collector hay luồng tích hợp, và không tự cho phép chạy tích hợp.
- Evidence Codex `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4hr2-independent-evidence.json`, SHA-256 `51fab7d1d81635ae5eb493aa145e148f793730cd7ccc006ff26621b0c5adda4a`. Chỉ đọc cấu trúc và kết quả (29 biến thể R1, `selftest_arp` 224/224); không chạy gì từ đó.
- Đã đọc `AGENTS.md`, summary 06B-4F/4FR/4G/4H và giao kèo hiện có: `probe_matrix.py` (nhánh ICMP, `GuardedRunner`, `captures_alive`, cleanup trong `finally`), `icmp_harness.py`, `run-06b4f.sh`, `arp_cases.py`, `guest_state.py`, `ctl_loop.py`, kế hoạch T14/T15 §3.2.
- Ghi chú review đã thêm vào đầu [`task06b4hr2-summary.md`](task06b4hr2-summary.md); evidence `task06b4hr2/` không sửa.

## 2. Bản làm việc

- Bản mới `/home/dathq/projects/ct01-06b4i/`, chép từ `ct01-06b4hr2` **sau khi xác minh** 31 file khớp [`task06b4hr2/harness-sha256.txt`](task06b4hr2/harness-sha256.txt) (không thiếu, không thừa, không lệch).
- `ct01-06b4hr2` và evidence cũ không đổi (kiểm lại hash ở §8).
- Diff: [`task06b4i/ct01-06b4i-harness-vs-06b4hr2.diff`](task06b4i/ct01-06b4i-harness-vs-06b4hr2.diff). Hash 35 file: [`task06b4i/harness-sha256.txt`](task06b4i/harness-sha256.txt).

| File | Thay đổi |
|---|---|
| `arp_harness.py` | **mới:** lớp nối ARP (chạy nhóm, collector, đối chứng sống A1/A2, kiểm record, đánh giá, kết luận kiến trúc và lần chạy) |
| `probe_matrix.py` | thêm nhánh `CT01_SUITE=arp` (`run_arp`, `evaluate_arp`, `read_iface_mac`); `capture_liveness` thêm tham số tên bộ thử (mặc định "ICMP", tên bản ghi ICMP không đổi). Nhánh IPv4/ICMP không đổi hành vi |
| `ctl_loop.py` | thêm tùy chọn `--arp-worker` (đọc `/proc/net/arp` của container ctl). Không có tùy chọn thì không đổi gì |
| `run-06b4i.sh` | **mới:** chép từ `run-06b4f.sh`, chỉ đổi các điểm nối ARP (§4) |
| `selftest_arp_wiring.py` | **mới:** kiểm offline phần nối |
| `mutation_arp_wiring.py` | **mới:** mutation của phần nối |

**Không sửa:** `arp_cases.py` (evaluator đã review), `guest_state.py`, `icmp_harness.py`, `icmp_cases.py`, `l2frames.py`, `l2eval.py`, `counter_window.py`, `signatures.py`, `run-06b4f.sh`, `run-06b3b.sh`. Không cần đổi evaluator: mọi kiểm tra thêm nằm ở lớp nối.

## 3. Luồng trong worker (`probe_matrix.py`, `CT01_SUITE=arp`)

**Dùng lại nguyên các bước đã review** (như nhánh ICMP): giải nén image, fixture, `verify_isolation` trước boot; tshark trên `tap0`; `captures_alive`; đo toàn phiên; boot QEMU; cổng topology; `counters_read`; tắt QEMU, thống kê drop, cleanup trong `finally`. Không mở listener, không chạy probe IPv4 hay ca ICMP.

**Nhóm ARP (`run_arp`):**

1. Đọc MAC `tap0` và `eth0` của worker từ `/sys/class/net` (chỉ đọc).
2. Lưu lượng kiểm capture từ worker trước và sau nhóm (như ICMP; tên bản ghi "…not a control for the ARP destinations").
3. `arp_harness.run_suite` gọi `arp_cases.run_group` với 4 ca từ `build_cases()`, giao diện `cfg.net_iface`.
4. **Mọi lệnh guest** đi qua `GuardedRunner` đã review: liên kết dịch vụ, snapshot/restore của `guest_state`, setup/trigger/settle. *(Đính chính 06B-4IR1: chỉ đúng cho **lệnh guest của nhóm ARP**. Cấu hình mạng lúc khởi động (`Analysis._configure_network`) và cổng topology (5 lệnh + `monitor info network`) đi thẳng tới console, chưa có guard; review I1.)*
   - **Trước** lệnh: kiểm cảnh báo rò rỉ rồi `captures_alive`. **Sau** lệnh: như trên.
   - Lỗi đầu tiên dừng nhóm: lệnh sau **không tới guest**, kể cả lệnh restore. Guest sau đó bị tắt và đĩa tạm bị xóa như cũ.
   - Lỗi được ném lại sau `run_group`: rò rỉ → exit 99; mất capture → 98; lỗi khác (vd. file cảnh báo không đọc được) → 1.
   - Lần dừng của guard ghi ở `guard_stopped`, tách khỏi `stopped` của `arp_cases` (restore lỗi).
5. **Collector neighbor:** `ip -j neigh show` chạy bằng `run_checked` ngay trong container worker, tức netns của `tap0`/`eth0`. Lấy cả bảng: nếu lọc `dev X`, iproute2 bỏ trường `dev`. rc ≠ 0 hoặc ngoại lệ → `run_group` ghi `neigh_*_error`.
6. **Liên kết dịch vụ:** trước nhóm và sau mỗi ca đã khôi phục (giao kèo `arp_cases`). Lệnh và cách đọc dùng lại `icmp_harness.link_command`/`parse_service_link` (HTTP 200 + hash fixture). Tên bản ghi theo ca.
7. **Đối chứng sống** (`arp_harness.make_control`, gọi sau ca, sau `neigh_after`):
   - Cửa sổ ca = `[t_start` của lần đọc A, `t_end` của lần đọc B`]`, lấy từ lần đọc bộ đếm. Callback chờ tới `t1 + 3 s + 0,6 s` (tối đa 10 s) để log ctl có bản ghi sau cửa sổ.
   - **T14-A1 (192.168.60.2):** container ctl trên `sandboxnet` (chạy `ctl_loop.py --arp-worker`) ghi mỗi vòng kiểm HTTP `worker-eth0` và ngay sau đó entry ARP của chính nó cho worker trong `/proc/net/arp`.
     - Cần: HTTP và entry ARP đều OK trước lần đọc A và sau lần đọc B (trong 3 s); không có bản ghi lỗi trong khoảng; mọi entry có cờ complete (0x2) và MAC = MAC `eth0` của worker.
     - Cần thêm: đích của ca bằng địa chỉ `eth0` của worker (`CT01_TARGETS.worker_ip`).
   - **T14-A2 (192.168.60.10):**
     - Ctl kiểm HTTP manager OK trước/sau cửa sổ, không lỗi.
     - Sau đó worker gọi manager (HTTP 200), rồi bảng neighbor của worker phải có đúng một hàng hợp lệ `192.168.60.10 dev eth0`, một trạng thái REACHABLE/STALE/DELAY/PROBE/PERMANENT, MAC = MAC thật của manager.
     - MAC manager do run script lấy bằng `docker inspect` và truyền qua `CT01_TARGETS.manager_mac`. Hàng không đọc được có thể là entry đó → không đạt.
   - Thiếu, không đọc được hay khác → `(False, chi tiết)` → ca **CHƯA KIỂM CHỨNG (không có đối chứng sống)** theo `arp_cases`; không bao giờ ĐẠT. *(Đính chính 06B-4IR1: chỉ đúng cho các điều kiện đã liệt kê. Bản 4I **không** kiểm `device` của entry ARP ctl, không phát hiện dòng trùng và không kiểm payload HTTP, nên các log như vậy vẫn ĐẠT; review I2/I3.)*
8. Ghi `arp-group.json`; ghi các xác nhận:
   - restore của mỗi ca có baseline;
   - collector đọc được trước/sau mọi ca đã chạy;
   - MAC `tap0` không đổi;
   - đủ 4 ca, mỗi ca một lần.

**Đánh giá (`evaluate_arp` → `arp_harness.evaluate`):**

- Gọi `arp_cases.evaluate_group` **không sửa** trên `tap0.pcapng`, `counters-raw.jsonl`, TAP MAC đã đọc và record. Ghi `arp-eval.json`, kèm đường dẫn/tham số đã dùng (`inputs`).
- Kiểm thêm ở lớp nối (`check_record`), có vấn đề thì không bao giờ kết luận nhóm đạt:
  - kiến trúc, giao diện, TAP MAC, hash fixture, danh sách ca dự kiến, lệnh collector;
  - không bị guard dừng;
  - liên kết trước nhóm và sau mỗi ca đã khôi phục: HTTP 200 + hash fixture.
- `record_problems` của `arp_cases` được giữ (tiền tố `arp_cases:`). `group_exit` của `arp_cases` ghi vào JSON.
- Mỗi ca thành bản ghi `probe <id> (arp, live control|rule check) -> <verdict>` để `counter_window.run_outcome` (đã review) coi CHƯA KIỂM CHỨNG là chưa quyết định, còn FAIL/LỖI PHÉP ĐO là lỗi cứng.

## 4. Kết luận kiến trúc, lần chạy và run script

**`arp_harness.arch_outcome`** (lệnh `--outcome` mà run script gọi) chỉ PASS khi **tất cả** đúng:

- mọi bản ghi đúng dạng (`test` chuỗi, `ok` boolean); `run_outcome` PASS;
- 16 xác nhận hạ tầng/nhóm bắt buộc, **mỗi cái đúng một lần, `ok` đúng `True`** (quy tắc 06B-4FR);
- các xác nhận theo ca lấy từ record (`case_requirements`): restore của mỗi ca có baseline; liên kết sau mỗi ca đã khôi phục;
- `status` COMPLETED; `arp-eval.json` đúng kiến trúc, đủ 4 ca mỗi ca một lần (cả trong `result.json`), không có vấn đề record;
- `group_exit` của `arp_cases` là 0 hoặc 4.

Chỉ có ca CHƯA KIỂM CHỨNG thì UNVERIFIED. ĐẠT của ca không che lỗi hạ tầng.

**Quyết định ở lớp nối:** restore lỗi là **FAIL ở mức kiến trúc**.

- Giao kèo ca của `arp_cases` giữ nguyên: ca lỗi restore và các ca sau là CHƯA KIỂM CHỨNG, các ca sau không chạy.
- Lý do: D2 chỉ cho phép đổi guest tạm thời **có khôi phục**. Restore không đạt là một kiểm tra hạ tầng thất bại (như cleanup), không phải kết quả chưa quyết định.
- Ca **chưa bắt đầu** (không đọc được trạng thái guest, không gửi lệnh nào) không có yêu cầu restore/liên kết sau. Ca đó là LỖI THỰC THI, kết luận UNVERIFIED.

**`run-06b4i.sh` (chưa chạy)**, so với `run-06b4f.sh`. Test W9 kiểm rằng chỉ các dòng dưới đây bị thay; mọi phần khác chỉ được thêm vào:

| Thay đổi | Nội dung |
|---|---|
| `H` | `/home/dathq/projects/ct01-06b4i` |
| Bản sao harness | thêm `arp_cases.py`, `arp_harness.py`, `selftest_arp.py`, `selftest_arp_wiring.py`, `run-06b4f.sh` |
| Self-test | `selftest_arp.py` và `selftest_arp_wiring.py` phải đạt trước mọi lệnh docker; lỗi → exit 3. Giữ self-test ICMP (vì `arp_harness` dùng lại `icmp_harness`) |
| Mount chỉ đọc | thêm `arp_harness.py`, `arp_cases.py`, `guest_state.py` vào `/harness` |
| Container ctl | `ctl_loop.py … --arp-worker`; kiểm "control 'arp worker-eth0 $WORKER_IP' alive" như ba đối chứng cũ |
| `CT01_TARGETS` | thêm `manager_mac` (MAC `sandboxnet` của manager, đã lấy cho `sigscan_l2`) |
| Lời gọi worker | `docker exec … -e CT01_SUITE=arp …` (lời gọi `probe_matrix.py` duy nhất) |
| Kết luận | `arp_harness.py --outcome … arp-eval.json` mỗi kiến trúc; `arp_harness.py --run-check …/probe ARM MIPS` |

Giữ nguyên: capture veth/bridge/ens33, watcher và heartbeat, hai cảnh báo rò rỉ, `sigscan.sh`/`sigscan_l2.py` (đã có chữ ký ARP của guest), kiểm tra dương, dừng capture có hạn chót, netns trước/sau, ruleset chuẩn hóa, xóa container, khôi phục manager, trạng thái host, mã thoát 0/1/4/5.

Lệnh dự kiến **khi reviewer cho phép** (chưa chạy; người dùng tự chạy):

```
sudo bash /home/dathq/projects/ct01-06b4i/run-06b4i.sh
```

## 5. Kiểm thử offline

`selftest_arp_wiring.py` chạy **`probe_matrix.main()` thật** ở chế độ ARP, mỗi kịch bản trong một tiến trình riêng:

- worker là module giả (`isolation`, `service.analysis`);
- `nft`, `ip -j neigh show`, tshark, log ctl, file capture/cảnh báo/heartbeat là giả;
- tiến trình **chỉ import được các file mà `run-06b4i.sh` mount** (S13, W5);
- guest là `selftest_arp.SimGuest` (06B-4H…4HR2): lệnh `guest_state`, ping/sleep, khung và bộ đếm **mô phỏng** theo `l2frames.classify`.

Không gói thật, không mạng, không guest.

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp_wiring.py` | **116/116**; ổn định 3 lần liên tiếp (mỗi lần ~50 s) | [`logs/selftest-arp-wiring.log`](task06b4i/logs/selftest-arp-wiring.log), [`logs/selftest-arp-wiring-stability.txt`](task06b4i/logs/selftest-arp-wiring-stability.txt) |
| `mutation_arp_wiring.py` | **37/37** đột biến hành vi bị bắt đúng test + 2 đối chứng đúng loại; hash harness không đổi. Lần chạy đầu ([`logs/mutation-arp-wiring-run1-before-test-fixes.txt`](task06b4i/logs/mutation-arp-wiring-run1-before-test-fixes.txt)): 34/39. Năm mục lệch đều do **test** thiếu, mã nối không đổi: U8 chưa tách riêng kiểm địa chỉ; S15 chưa kiểm bản ghi nhóm trong `result.json`; U29 thiếu hàng cờ 0x0 có MAC khác 0; kịch bản sạch hỏng làm cả suite dừng thay vì báo hỏng (V21, V29). Đã bổ sung test và chạy lại toàn bộ | [`logs/mutation-arp-wiring.txt`](task06b4i/logs/mutation-arp-wiring.txt) |
| `selftest_icmp_wiring.py` (do sửa `probe_matrix.py`; chạy `main()` thật ở chế độ ICMP) | 129/129 | [`logs/selftest-icmp-wiring.log`](task06b4i/logs/selftest-icmp-wiring.log) |
| `selftest.sh` (do sửa `probe_matrix.py`; mục H, B2, thứ tự phiên ở chế độ IPv4) | 205 PASS, "ALL PASSED" | [`logs/selftest-sh.log`](task06b4i/logs/selftest-sh.log) |
| `selftest_arp.py` (run script chạy trước khi bắt đầu; `arp_cases.py` không đổi) | 224/224 | [`logs/selftest-arp.log`](task06b4i/logs/selftest-arp.log) |
| *Ghi chú:* `selftest_icmp_wiring`, `selftest.sh`, `selftest_arp` chạy trước khi bổ sung test ở dòng mutation; sau đó chỉ `selftest_arp_wiring.py`/`mutation_arp_wiring.py` đổi, mã harness giống hệt | | |
| Mẫu đột biến cũ còn khớp đúng một chỗ trên file mới | `mutation_test.sh` 78/78; `mutation_icmp_wiring.py` 34/34 (+ X1 đối chứng không khớp) | [`logs/mutation-patterns-still-unique.txt`](task06b4i/logs/mutation-patterns-still-unique.txt) |

**Không chạy lại** (lý do):

- `mutation_test.sh` (~13 phút) và `mutation_icmp_wiring.py`: các đột biến của chúng nhắm vào phần `probe_matrix.py` không đổi (`captures_alive`, `evaluate`, đo toàn phiên, quét QEMU, nhánh ICMP). Mọi mẫu vẫn khớp đúng một chỗ trên file mới (log trên). `selftest.sh` và `selftest_icmp_wiring.py`, hai suite mà chúng dùng, vẫn đạt đủ.
- `selftest_l2`, `selftest_l2eval`, `selftest_icmp` và mutation tương ứng, `mutation_arp`: module không đổi.

**Kịch bản qua `probe_matrix.main()`** (41 kịch bản). Mỗi kịch bản cũng đi qua `arp_harness.arch_outcome`, CLI `arp_harness.py --outcome` (gọi như run script) và khối `case "$rc:$outcome"` thật của `run-06b4i.sh` chạy bằng bash.

| Yêu cầu | Kịch bản → kết quả |
|---|---|
| Ca sạch đi hết luồng | exit 0, COMPLETED, PASS (hàm, CLI, run script). A1/A2 ĐẠT (`live_control`), A3/S1 ĐẠT (kiểm quy tắc). Mọi bước giao kèo đúng thứ tự. 5 lần liên kết; collector đúng `ip -j neigh show` 9 lần (2/ca + 1 cho đối chứng A2) (S1–S14) |
| Collector/capture/counter/control lỗi không ĐẠT | collector rc ≠ 0, không phải JSON, ngoại lệ lạ → ca LỖI PHÉP ĐO, FAIL (S18–S20). Lỗi đọc bộ đếm → LỖI PHÉP ĐO, FAIL (S27). Capture không đọc được → mọi ca LỖI PHÉP ĐO (S39). Đối chứng A1/A2 không sống (ARP ctl sai MAC, không có ARP, lỗi trong cửa sổ, địa chỉ khác, MAC `eth0` thiếu; neighbor manager thiếu/sai MAC; worker không gọi được manager; thiếu MAC manager; log ctl thiếu/hỏng) → ca đó CHƯA KIỂM CHỨNG, UNVERIFIED, không bao giờ PASS (S36, S37) |
| Lỗi trước khi bắt đầu | không đọc được trạng thái guest trước A3 → không lệnh A3 nào được gửi; `not_started` giữ; LỖI THỰC THI; S1 vẫn chạy; UNVERIFIED (S22). Liên kết trước nhóm hỏng → không ca nào chạy, FAIL (S16) |
| FAIL độc lập + lỗi đo đồng thời | MAC guest trên neighbor `eth0` sau A3 **và** lỗi đọc bộ đếm A3 → FAIL, `measurement_errors` giữ bên cạnh `failure_evidence` (S21). Chưa bắt đầu + neighbor mang MAC guest → FAIL, `not_started` và bằng chứng giữ (S23) |
| Restore lỗi chặn ca sau | `ip route del` lỗi khi khôi phục A2 → A3/S1 không chạy, không lệnh nào của chúng tới guest; A2 CHƯA KIỂM CHỨNG (khôi phục); không có liên kết sau A2; xác nhận restore FAIL → FAIL (S28, S29) |
| Guard | capture chết sau ping A2; heartbeat cũ sau setup A1; tshark thoát sau `link down` S1; rò rỉ sau ping A3 → lệnh gây dừng là **lệnh cuối cùng** gửi guest (không restore, không liên kết); exit 98/99; FAIL; không đánh giá; QEMU tắt, cleanup chạy; record giữ `guard_stopped` (S30–S32). Cảnh báo/mất capture xuất hiện lúc đọc A → setup của ca **không** được gửi (S33, S35). File cảnh báo không đọc được → không coi là "không cảnh báo", ERROR exit 1 (S34) |
| Lỗi thực thi | setup lỗi → trigger không gửi, restore vẫn chạy, LỖI THỰC THI, UNVERIFIED (S24). Timeout console → LỖI THỰC THI, các ca sau vẫn chạy (S25). Kernel mô phỏng không gửi khung → KHÔNG TẠO ĐƯỢC GÓI, UNVERIFIED (S26) |
| Hạ tầng | drop trên `tap0`, QEMU không thoát, marker còn sau cleanup, lưu lượng kiểm capture lỗi → 4 ca ĐẠT nhưng FAIL (S38) |
| Cleanup khi lỗi | callback lỗi (log ctl là thư mục, worker gọi manager bị từ chối, collector KeyError) → mọi lỗi được ghi, QEMU tắt, cleanup chạy, FAIL (S41). Lỗi ngoài nhóm (địa chỉ `tap0` mất) → ERROR exit 1, record giữ, QEMU/cleanup chạy (S40) |
| Tổng | không kịch bản nào ngoài kịch bản sạch PASS (S42); hàm và CLI cho cùng kết luận ở mọi kịch bản (S43). *(Đính chính 06B-4IR1: chỉ trong **tập kịch bản đã chọn**, không phải bảo đảm tổng quát.)* |

**R — xác nhận bắt buộc và R1 qua phần nối:**

- R1, R2: đường mã thật ghi mỗi xác nhận (tĩnh + theo ca) đúng một lần, không ghi kiểm tra nào ngoài danh sách.
- R3–R6: thiếu, trùng, `ok="true"`; thiếu xác nhận theo ca; thiếu `case_requirements`; `group_exit` 2; sai kiến trúc → FAIL.
- **R7 (R1 của 06B-4HR2 qua phần nối):** lấy record của lần chạy sạch, đổi thành mâu thuẫn, đánh giá lại bằng `arp_harness.evaluate` trên cùng capture/bộ đếm, rồi `--outcome` và khối run script. Ba biến thể:
  1. flags 6 trong `neigh_dynamic` của baseline, entry mất sau restore;
  2. cùng khóa ở hai nhóm;
  3. `after` mang flags 4 trong nhóm động.

  Cả ba: `record_problems` nêu lỗi, `group_exit` 2, CLI FAIL, run script FAIL, record không bị sửa.
- R8 (đối chứng): neighbor động hợp lệ đổi trong `after` → vẫn PASS.

**Unit U1–U30:** cửa sổ log ctl; A1/A2 với mọi điều kiện ở §3; `make_control` (chờ, cửa sổ không biết, log hỏng, ca không có đối chứng); `check_record`; `evaluate`; `case_requirements`; `run_check`; CLI; `ctl_loop.arp_entry` (tách bằng ast, chạy trên file `/proc/net/arp` mẫu: entry đủ, 0x0, MAC 0, không có, hai hàng, header/hàng sai). Vòng lặp ctl thật không chạy trong test vì nó kết nối mạng.

**Run script W1–W11:** `bash -n`; `H`; một lời gọi `CT01_SUITE=arp`; self-test trước docker; đủ mount; `--outcome`/`--run-check` qua `arp_harness`; `--arp-worker` và kiểm alive; `manager_mac`; chỉ các dòng liệt kê bị thay so với `run-06b4f.sh`; `run-06b4f.sh`/`run-06b3b.sh` giữ hash manifest 4HR2; bản sao harness có file ARP.

**Fixture phần nối:** [`task06b4i/fixtures/`](task06b4i/fixtures/), xuất bằng [`task06b4i/export_fixtures.py`](task06b4i/export_fixtures.py) (dùng chính `selftest_arp_wiring.run_scenario`), bảng tóm tắt [`fixtures/fixtures-summary.json`](task06b4i/fixtures/fixtures-summary.json).

- 10 kịch bản: sạch, restore lỗi A2, capture chết sau ping A2, cảnh báo trước S1, FAIL + lỗi đo A3, chưa bắt đầu + neighbor FAIL, A1 không có ARP ctl, A2 MAC manager sai, collector lỗi sau A2, lỗi ngoài nhóm.
- Mỗi kịch bản: `scenario.json` (exit, lệnh guest/worker, module), `result.json`, `arp-group.json`, `arp-eval.json`, `counters-raw.jsonl`, `tap0.pcapng`, `session.json`.
- **Toàn bộ là dữ liệu mô phỏng.** Đường dẫn tuyệt đối trong JSON trỏ tới `/home/dathq/projects/ct01-06b4i-work/fixtures-run/`.

**Đột biến (V1–V37 + 2 đối chứng):**

| Phạm vi | Đột biến |
|---|---|
| Cửa sổ ctl | bỏ đếm lỗi; bỏ yêu cầu "sau" |
| A1 | bỏ kiểm MAC ARP; bỏ kiểm địa chỉ đích |
| A2 | bỏ kiểm MAC neighbor; bỏ kiểm hàng không đọc được |
| `make_control` | không chờ |
| Record | ghi đè `stopped` thay vì `guard_stopped`; bỏ kiểm liên kết sau ca; bỏ `record_problems` của `arp_cases` |
| Kết luận | bỏ xác nhận theo ca; bỏ kiểm `group_exit`; bỏ xác nhận collector khỏi danh sách; bỏ yêu cầu liên kết sau ca; tên bản ghi ca không bắt đầu bằng "probe " |
| Collector | lệnh `ip -j neigh show dev tap0` (cả ở `arp_harness` và `probe_matrix`) |
| `probe_matrix.py` | không ném lại lỗi guard; bỏ kiểm cảnh báo trước lệnh; bỏ `captures_alive` trước lệnh; nuốt lỗi đọc cảnh báo; gọi `evaluate_icmp`; xác nhận restore luôn đạt; xác nhận collector luôn đạt; mọi liên kết cùng tên; TAP MAC sai cho evaluator; không ghi cửa sổ ca; bản ghi nhóm luôn đạt; import sai module |
| `ctl_loop.py` | bỏ kiểm cờ complete; nhận nhiều hàng |
| Run script | bỏ `CT01_SUITE=arp`; bỏ mount `guest_state.py`; ánh xạ UNVERIFIED thành PASS; bỏ self-test wiring; bỏ `--arp-worker`; bỏ `manager_mac` |

## 6. Phần đã kiểm bằng stub và phần cần chạy thật

| Điểm | Offline đã kiểm (stub/fixture) | Cần chạy thật, **chưa xác nhận** |
|---|---|---|
| Collector neighbor | lệnh, lỗi rc/JSON/ngoại lệ, truyền vào evaluator; nơi chạy (tiến trình worker) chỉ **suy từ cấu hình** `docker exec`, kiểm tĩnh *(đính chính 06B-4IR1: chưa thực thi trong worker/netns thật)* | `ip -j neigh show` có trong image worker và hỗ trợ `-j`; **dạng JSON thật** (trường `state`, `lladdr`, hàng IPv6, cờ `router`…); trạng thái của entry `10.200.0.2` trên `tap0` |
| Trạng thái guest | lệnh `guest_state` qua `GuardedRunner`, restore/khôi phục mô phỏng | **operstate thật** trên `eth1` (ARM) / `br-lan` (MIPS); BusyBox `ip`/`arp`/`echo > /proc`; định dạng `/proc/net/arp` của hai image |
| Kernel/netifd | không (mô phỏng) | ARP do route on-link + ping; số lần gửi lại (G7); gratuitous khi `arp_notify` + link up; link down xóa route/neighbor; netifd sau down/up (G8, `br-lan` MIPS) |
| Đối chứng A1/A2 | logic cửa sổ, MAC, địa chỉ, lỗi log | `/proc/net/arp` của ctl thật có entry complete cho worker; `docker inspect` cho MAC manager; neighbor `eth0` của worker sau khi gọi manager; nhịp log ctl đủ dày quanh cửa sổ |
| Capture/counter | stub tshark/nft theo `l2frames.classify` | ánh xạ ARP của ruleset thật (§3.2 kế hoạch), khung biên |
| Guard 20 ms | không | **chưa đo** |

## 7. Lỗi còn lại, giới hạn và điều kiện trước khi chạy guest

**Giới hạn đã biết của phần nối:**

- Đối chứng A1/A2 đọc **entry ARP đang có** (ctl/worker), được xác nhận bởi lưu lượng TCP/HTTP đang chạy. Không ép một lần ARP mới, vì không có công cụ hay quyền trong ctl. Đây là bằng chứng "cùng IP được phân giải bằng ARP trên `sandboxnet` và trả lời quanh cửa sổ", không phải một trao đổi ARP mới trong cửa sổ.
- Đối chứng gọi sau ca, chờ khoảng 3,6 s mỗi ca A1/A2; trong lúc chờ không có lệnh guest. Cảnh báo/capture lỗi lúc đó được bắt ở lệnh guest kế tiếp (như ICMP); sau lệnh guest cuối, run script vẫn kiểm `alert.txt`.
- Restore lỗi → FAIL ở mức kiến trúc (quyết định ở §4, cần reviewer xác nhận).
- Sau khi guard dừng, restore không được gửi tới guest. Guest bị tắt và đĩa tạm bị xóa; record ghi restore lỗi.

**Điều kiện cần trước khi chạy guest:**

1. Reviewer chấp nhận phần nối 06B-4I và cho phép chạy (tối đa một lần như 06B-4G).
2. Xác nhận chỉ đọc trong image worker đã review: có `ip` hỗ trợ `-j neigh show`, và JSON thật đọc được bằng `arp_cases.parse_neigh_full` (nếu không, mọi ca sẽ LỖI PHÉP ĐO → FAIL, không ĐẠT sai).
3. Xác nhận `/proc/net/arp` đọc được trong container ctl, và `docker inspect` trả MAC manager trên `sandboxnet`.
4. Precheck host như 06B-4G: image ID, manager, không còn container/QEMU/capture, thư mục `out/` chưa tồn tại.
5. Chấp nhận trước rằng T15 (link down/up, địa chỉ phụ) dễ sinh khung biên và lưu lượng nền, nên kết quả có thể là CHƯA KIỂM CHỨNG; guard 20 ms vẫn chưa đo.

**Không làm:** chạy script tích hợp, Docker, QEMU, sudo, probe mạng, đổi host/ruleset/source cô lập, đọc bí mật/malware, commit/push/merge, ảnh/snapshot. CT-01 **không** được nâng.

## 8. Hash

- Bản làm việc: [`harness-sha256.txt`](task06b4i/harness-sha256.txt) (35 file).
- Kiểm lại: `ct01-06b4hr2` vẫn khớp manifest 31 file; mọi `SHA256SUMS` của evidence cũ khớp; `arp_cases.py`, `guest_state.py` giống hệt 4HR2.
- Mọi file trong `task06b4i/`: [`SHA256SUMS`](task06b4i/SHA256SUMS) (`229df5759d56dbacc81540371dbc8ce2f4f812e3e50c501e72e4bfaa9b0a7746`).
