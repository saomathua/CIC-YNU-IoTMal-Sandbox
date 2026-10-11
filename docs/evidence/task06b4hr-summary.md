# Minh chứng Nhiệm vụ 06B-4HR: sửa năm phát hiện của Codex trong 06B-4H (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4HR1):** Codex review độc lập: các tái hiện F1–F5 của 4H cho kết quả đúng trên 4HR, nhưng **còn lỗi, chưa chấp nhận nối tích hợp**. Còn 2 P1 báo ĐẠT sai và 3 P2:
> - HR1: baseline/restore chỉ kiểm kiểu vỏ;
> - HR2: binding guest bắt buộc chấp nhận tổ hợp state mâu thuẫn;
> - HR3: nhánh chưa bắt đầu trả về sớm, bỏ bằng chứng độc lập;
> - HR4: hàng neighbor không đọc được bị suy thành mất/đổi binding;
> - HR5: callback đối chứng sai cấu trúc làm ném ngoại lệ.
>
> Phần sửa ở [`task06b4hr1-summary.md`](task06b4hr1-summary.md). Các câu bị bác bỏ được đánh dấu *(đính chính 06B-4HR1)* tại chỗ; evidence `task06b4hr/` không sửa.

> **Loại bằng chứng: kiểm thử offline.**
>
> - Chưa nối tích hợp: run script không đổi.
> - Không Docker, QEMU, sudo, probe mạng, công cụ mới; không đổi host, source cô lập, ruleset, địa chỉ hay guard.
> - **Mọi hành vi guest/kernel nêu dưới đây là mô phỏng** (guest giả, fixture, stub), chưa phải hành vi guest thật.
> - Bộ phân lớp `l2frames.classify` được dùng để tạo bộ đếm trong fixture; nó **không** là bằng chứng độc lập về kernel hay nft thật.
> - Guard 20 ms vẫn là giả định chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào

**Báo cáo Codex:** `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4h-independent-review.md`, SHA-256 `aabe3b3497dd30d906c2a547ac78a3b270354bc05fe054416ce706ad2287b9a1`. Đã đọc toàn bộ.

**Bundle tái hiện:** `…/06b4h-offline-reproductions.zip`, SHA-256 `efd880cbaaccc10b7494a59565f0236dad2a00b5f992b0bcddf0677d46778abe`.

- Giải nén vào thư mục riêng; đọc `reproduce.py` và `extra_stubs.py` trước khi chạy.
- Hai script chỉ dựng fixture, gọi hàm offline và ghi JSON; không chạy run script, không gửi gói.
- Bản harness trong bundle giống hệt 4H.

**Trạng thái 06B-4H:** đã review, **còn lỗi, chưa chấp nhận nối tích hợp**. Ghi chú review và các câu bị phản ví dụ bác bỏ đã được đánh dấu *(đính chính 06B-4HR)* trong [`task06b4h-summary.md`](task06b4h-summary.md). Evidence `task06b4h/` không sửa (`SHA256SUMS` vẫn khớp).

## 2. Bản làm việc

- `/home/dathq/projects/ct01-06b4hr/`, chép từ `ct01-06b4h` **sau khi xác minh** manifest 31 file. Bản 4H giữ nguyên.
- **Chỉ đổi 3 file:** `arp_cases.py`, `selftest_arp.py`, `mutation_arp.py`. 28 file còn lại giống hệt (`guest_state`, `l2frames`, `l2eval`, `counter_window`, `signatures`, `probe_matrix`, run script…).
- Diff: [`task06b4hr/ct01-06b4hr-harness-vs-06b4h.diff`](task06b4hr/ct01-06b4hr-harness-vs-06b4h.diff). Hash 31 file: [`task06b4hr/harness-sha256.txt`](task06b4hr/harness-sha256.txt).

## 3. Bản sửa (`arp_cases.py`)

### F1 — S1 chỉ nhận gratuitous ARP request đã duyệt

`is_probe_frame` yêu cầu mọi khung probe có:

- `htype 1`, `ptype 0x0800`, `hlen 6`, `plen 4`, **`op = 1`**;
- `sha` = MAC guest, hướng guest.

**T15** thêm: `spa = tpa` ∈ {10.200.0.2, 3 IP giả} và đích **broadcast**.

Khung opcode 2/99, đích unicast, hay htype/ptype khác không thay được probe. Không mở rộng sang ARP reply giả (D1).

### F2 — Neighbor worker

**`parse_neigh` kiểm từng hàng:**

- `dst` là IP; `dev` hợp lệ;
- `state` là danh sách **không rỗng** các trạng thái NUD đã biết;
- `lladdr`, nếu có, phải là MAC; thiếu `lladdr` chỉ hợp lệ với `INCOMPLETE`/`FAILED`/`NONE`.

Hàng sai được báo, không bao giờ chuyển thành `None`. Mọi hàng được **giữ riêng**; khóa `(dst, dev)` trùng là lỗi dữ liệu, không ghi đè.

**`neigh_check` trả ba loại:**

| Loại | Điều kiện | Kết quả ca |
|---|---|---|
| `fail` | MAC guest trên interface khác `tap0`, xét trên **mọi hàng hợp lệ**, kể cả khi bảng có hàng trùng/sai; `tap0` khác trước/sau; `10.200.0.2` không còn PERMANENT đúng MAC *(đính chính 06B-4HR1: 4HR chỉ kiểm có chữ "PERMANENT" và đúng MAC, nên chấp nhận cả tổ hợp mâu thuẫn như PERMANENT+FAILED; và vì suy từ danh sách đã lọc bỏ hàng hỏng, một hàng guest không đọc được bị coi là "mất/đổi" → FAIL vượt dữ liệu)*; IP theo dõi có binding **mới** (đổi MAC, hoặc chuyển interface dù cùng MAC) | FAIL |
| `invalid` | không đọc được, hàng sai, trùng | LỖI PHÉP ĐO, trừ khi có FAIL |
| `inconclusive` | IP theo dõi có binding trước nhưng **mất** sau, hoặc chỉ còn trạng thái không có binding (`FAILED`/`INCOMPLETE`) | CHƯA KIỂM CHỨNG |

Biến động trạng thái của một binding giữ nguyên interface và MAC (REACHABLE ↔ STALE ↔ DELAY ↔ PROBE) là bình thường: **không** báo, không ép thành FAIL.

### F3 — Giao kèo hồ sơ thực thi (`execution_problems`, dùng trong cả `record_problems` và `evaluate_case`)

| Loại ca | Hồ sơ phải có |
|---|---|
| **Hoàn tất** (không `exec_error`) | `steps` đúng **đủ** các bước của giao kèo, đúng thứ tự, đúng phase và lệnh; rc trong giao kèo; baseline guest hợp lệ (đủ trường của `guest_state`, MAC hợp lệ); bằng chứng restore (`restored` boolean, danh sách `commands`/`diffs`; `restored=True` thì không còn `diffs`). *(Đính chính 06B-4HR1: chưa đủ. 4HR chỉ kiểm kiểu vỏ của baseline và tin cờ `restored`/`diffs`: `restore.after` mâu thuẫn với baseline hoặc bị xóa, `addrs=[42]`, `commands=[42]`, `restored=True` kèm `error` đều vẫn exit 0.)* |
| **Dừng vì lỗi** (`exec_error`) | `steps` là tiền tố của giao kèo; mọi bước trừ bước cuối nằm trong giao kèo; có baseline và restore nếu baseline đã được lấy |
| **Chưa bắt đầu** | baseline không đọc được: không bước, không baseline, không restore |

- Hồ sơ sai: ca là CHƯA KIỂM CHỨNG ("hồ sơ thực thi không đầy đủ/không hợp lệ"), có `record_problems`, và nhóm **không bao giờ exit 0**.
- Prefix rỗng, chỉ setup, thiếu settle, sai phase, sai rc, mất baseline hay mất restore đều không ĐẠT.
- Ca dừng hợp lệ là LỖI THỰC THI, **không** đánh đồng với ca hoàn tất.
- `run_group` ghi `iface` vào từng ca. Khi restore ném ngoại lệ, ghi bằng chứng `restored: False` kèm lỗi (trước đây là `None`).

### F4 — Giao kèo rc

- Chỉ **ping rc 0/1** hợp lệ. Setup, settle và `ip link` phải rc 0.
- Rc khác, rc 127/"not found" hay ngoại lệ console thì ghi lỗi thực thi và dừng các bước còn lại của ca.
- **Vẫn đọc B và vẫn restore.**

### F5 — FAIL thắng lỗi đo

`evaluate_case` **thu bằng chứng trước**:

1. neighbor từ các hàng hợp lệ;
2. khung, **chỉ khi cửa sổ hợp lệ**: hai lần đọc tồn tại, thời gian hữu hạn và A kết thúc trước B;
3. đối chiếu bộ đếm, chỉ khi bộ đếm hợp lệ và không có `read_error`.

Sau đó mới xét: FAIL → LỖI PHÉP ĐO → lỗi thực thi / hồ sơ → không tạo gói → các điều kiện chỉ ngăn kết luận.

- `evaluate_group` không còn trả sớm khi capture hay file bộ đếm lỗi: mọi ca vẫn được đánh giá với phần dữ liệu hợp lệ.
- JSON mỗi ca luôn có `failure_evidence`, `measurement_errors`, `execution_problems`, `neighbour_inconclusive`. Khi FAIL đi cùng lỗi đo, **cả hai** đều được ghi. *(Đính chính 06B-4HR1: **sai** với nhánh `not_run` và nhánh chưa bắt đầu. Nhánh chưa bắt đầu còn trả về trước khi thu bằng chứng neighbor/lỗi capture.)*
- Docstring `group_exit` sửa đúng mã: FAIL (1) thắng mọi thứ; rồi LỖI PHÉP ĐO / không có ca / vấn đề bản ghi (2); rồi chưa kết luận (4); rồi 0.

## 4. Tái hiện trước/sau: chạy lại chính các ca của Codex

**Cách chạy:**

- `reproduce.py` và `extra_stubs.py` của Codex, **không sửa** (đã so `cmp`), mỗi phiên bản một thư mục riêng.
- Helper fixture lấy từ `selftest_arp.py` 4HR (giữ nguyên tên và giao diện helper của 4H). Fixture sạch dùng baseline guest đầy đủ thay cho `{"mac": …}`.
- Module đánh giá là `arp_cases.py` của **phiên bản được kiểm**.

**Kiểm chứng tính tương đương:** lần chạy trên 4H cho log **giống hệt** `reproduce.log` và `extra-stubs.log` trong bundle của Codex.

Bảng đầy đủ: [`task06b4hr/codex-reproductions-before-after.txt`](task06b4hr/codex-reproductions-before-after.txt); JSON và log: [`task06b4hr/codex-rerun/`](task06b4hr/codex-rerun/).

| Ca Codex | 06B-4H | 06B-4HR |
|---|---|---|
| `s1_wrong_opcode_2`, `_99` | **ĐẠT (kiểm quy tắc)** | KHÔNG TẠO ĐƯỢC GÓI |
| `manager_removed` | **ĐẠT** | CHƯA KIỂM CHỨNG |
| `manager_moved_interface_changed_mac` | **ĐẠT** | FAIL |
| `manager_bad_lladdr_*` (None, int, bool, list, dict) | **ĐẠT** | LỖI PHÉP ĐO |
| `manager_missing_state`, `manager_bad_state_items` | **ĐẠT** | LỖI PHÉP ĐO |
| `manager_failed_state` | **ĐẠT** | CHƯA KIỂM CHỨNG |
| `duplicate_hides_abnormal_guest_mac` | **ĐẠT** | FAIL |
| `known_violation_and_read_error`, `known_neighbor_violation_and_read_error` | LỖI PHÉP ĐO (mất bằng chứng) | FAIL, JSON giữ cả bằng chứng FAIL và lỗi đo |
| `group_empty_steps`, `_setup_only`, `_wrong_rc`, `_wrong_phase`, `_missing_guest_baseline` | **exit 0**, 4 ca ĐẠT | exit 2, không ca nào ĐẠT |
| `ping_rc2_actual_run_group` (`run_group` thật → `evaluate_group`) | **exit 0** | exit 4; T14 LỖI THỰC THI "rc 2 outside the contract"; read B có; restore đạt |
| Ca sạch: `clean_s1`, `clean_a3`, `clean_group`, `control_True`, `run_group_control_True` | ĐẠT đúng nhãn | **giữ nguyên nhãn** (DAT / DAT_KIEM_QUY_TAC; nhóm exit 0) |
| Ca đã đúng ở 4H (`a2_wrong_*`, `abnormal_guest_mac_detected`, `manager_changed_mac_detected`, `neighbor_read_error`, `known_violation_clean_reads`, `control_*` sai kiểu, `s1_all_edge`, `edge_s1`, restore lỗi chặn ping tiếp theo) | đúng | **không đổi** |
| Ma trận restore 40 tình huống, baseline có cấu hình sẵn (`eth1`/`br-lan`, timeout trước/sau từng bước, đổi MAC) | 0 diff | **0 diff** |

## 5. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp.py` | **146/146** (90 cũ đã cập nhật fixture + 56 mới); ổn định 5 lần | [`logs/selftest-arp.log`](task06b4hr/logs/selftest-arp.log), [`logs/selftest-arp-stability.txt`](task06b4hr/logs/selftest-arp-stability.txt) |
| Test mới chạy trên `arp_cases.py` **4H** | 89/138; 47 test F hỏng; mục N và F6 crash (4H không có `neigh_check`/giao kèo). 9 test F vẫn đạt trên 4H vì đó là ca **đối chứng** mà 4H đã xử lý đúng: S1 sạch, REACHABLE→STALE/DELAY, hàng MAC guest + hàng sai, nhóm sạch, ca dừng hợp lệ, ping rc 0/1, thứ tự `group_exit` | [`logs/selftest-arp-new-tests-on-06b4h-code.log`](task06b4hr/logs/selftest-arp-new-tests-on-06b4h-code.log) |
| `mutation_arp.py` | **48/48** đột biến hành vi bị bắt đúng test + 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-arp.txt`](task06b4hr/logs/mutation-arp.txt) |
| `selftest_l2.py --offline-only` (`guest_state`/`l2frames`, không đổi) | 175/175 | [`logs/selftest-l2.log`](task06b4hr/logs/selftest-l2.log) |
| `selftest_l2eval.py --offline-only` (không đổi) | 65/65 | [`logs/selftest-l2eval.log`](task06b4hr/logs/selftest-l2eval.log) |

Không chạy các suite IPv4/ICMP/wiring: không file nào của chúng đổi.

**Test mới (mục F trong `selftest_arp.py`):**

| Mục | Nội dung |
|---|---|
| F1.1–F1.5 | S1 sạch vẫn ĐẠT; opcode 2/99; request unicast; htype 6 / ptype IPv6; hỗn hợp 2 request + 1 reply |
| F2 (22 ca) | xóa entry; chuyển `eth9` (khác hoặc cùng MAC); `FAILED`; `INCOMPLETE` không MAC; REACHABLE→STALE/DELAY vẫn ĐẠT; `lladdr` None/1/True/[]/{}; thiếu/rỗng/sai `state`; `dst` sai; trùng hàng che MAC guest; trùng hàng bình thường; hàng MAC guest + hàng sai; bảng *trước* sai; A2 mất entry đích |
| F3 (15 ca) | nhóm sạch exit 0 đúng nhãn; prefix rỗng; chỉ setup; thiếu settle; sai phase; rc 2; rc không phải số; đảo thứ tự; mất baseline; baseline thiếu; mất restore; `restored` không boolean; restored kèm diff; ca dừng hợp lệ là LỖI THỰC THI không có vấn đề bản ghi; ca dừng có bước sai trước bước cuối |
| F4 | `run_group` thật với ping rc 2/3 (lỗi; vẫn đọc B; restore; không chạy settle) và rc 0/1 (hợp lệ); rồi `evaluate_group` → LỖI THỰC THI, exit 4 |
| F5.1–F5.7 | vi phạm khung với đọc sạch/có `read_error`; vi phạm neighbor + `read_error`; cửa sổ không hợp lệ thì không suy FAIL từ vị trí khung; vi phạm neighbor khi capture không đọc được / file bộ đếm sai; `group_exit` FAIL thắng LỖI PHÉP ĐO |
| F6 | ma trận restore 40 tình huống (`eth1`/`br-lan` × A2/S1 × lỗi trước/sau từng bước, đổi MAC), baseline có `arp_notify=1`, địa chỉ phụ, route thêm, neighbor tĩnh: trạng thái khôi phục đúng, có lỗi thực thi, hồ sơ trong giao kèo |

**Đột biến mới/đổi:**

| Nhóm | Đột biến |
|---|---|
| F1 | A3 opcode, A4b broadcast, A4c htype/ptype |
| F2 | A20 binding mới, A20b inconclusive, A20c binding của `FAILED`, A21b MAC, A21c state, A21d trùng, A21e bỏ bằng chứng khi bảng có lỗi |
| F3 | A28 đủ bước, A28b rc, A28c baseline, A28d restore, A28e bước giữa |
| F4 | A23 thêm rc 2 vào giao kèo, A23b bỏ kiểm rc, A24 trigger |
| F5 | B1 lỗi đo trước FAIL, B2 bỏ kiểm cửa sổ, B3 bỏ khung khi `read_error`, B4 trả sớm khi lỗi đầu vào, B5 thứ tự `group_exit`, B6 bỏ neighbor khi `read_error` |

## 6. Giới hạn còn lại

- **Chưa nối tích hợp:** collector `ip -j neigh` trong worker netns, đối chứng sống A1/A2, `GuardedRunner`/capture/heartbeat, mount/copy-list/run script cho ARP. Mọi bằng chứng là offline với guest/kernel mô phỏng.
- **Phân loại neighbor:**
  - "mất entry" và "không còn binding" được ghi CHƯA KIỂM CHỨNG chứ không phải FAIL, vì kernel có thể dọn entry động. Ngưỡng này cần reviewer xác nhận.
  - Trạng thái `NOARP` và các cờ khác của `ip -j neigh` chưa được kiểm trên dữ liệu thật.
- **Giao kèo rc:** dựa trên giả định về BusyBox `ping` (0 có phản hồi, 1 không phản hồi). Hành vi thật trên hai image chưa kiểm.
- **Giả định kernel/guest chưa kiểm:**
  - gratuitous request khi `arp_notify` + `NETDEV_UP`; số ARP gửi lại (G7); netifd sau down/up (G8);
  - đích broadcast của gratuitous request.
- **Guard 20 ms chưa đo.**
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"; CT-14 chưa bắt đầu.**

## 7. Hash

Mọi file trong `task06b4hr/`: [`SHA256SUMS`](task06b4hr/SHA256SUMS) (`063873ec108dfd4003626215f4e478d3b8b7bc8c8850c730ac3435773714163d`).
