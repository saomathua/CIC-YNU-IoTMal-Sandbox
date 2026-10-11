# Minh chứng Nhiệm vụ 06B-4HR1: sửa HR1–HR5 trong review Codex 06B-4HR (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4HR2):** Codex review độc lập: các tái hiện HR1–HR5 đã được khắc phục, nhưng **còn một lỗi P1 (R1), chưa chấp nhận nối tích hợp**. Validator baseline nhận entry mang cờ PERMANENT (0x4) trong `neigh_dynamic`, nên khi entry đó mất sau restore, evaluator vẫn ĐẠT (CLI exit 0). Vì vậy nhận định "đã khắc phục HR1" dưới đây chỉ đúng **cho các biến thể đã tái hiện**, không có nghĩa mọi nội dung baseline đều được kiểm. R1 được sửa ở [`task06b4hr2-summary.md`](task06b4hr2-summary.md). Evidence `task06b4hr1/` không sửa.

> **Loại bằng chứng: kiểm thử offline. Chưa nối tích hợp; run script không đổi.**
>
> - Không Docker, QEMU, sudo, probe mạng, công cụ mới; không đổi host, source cô lập, ruleset, địa chỉ hay guard.
> - **Mọi hành vi guest/kernel là mô phỏng.** Bộ phân lớp chỉ tạo bộ đếm cho fixture, không là bằng chứng về kernel/nft thật.
> - Guard 20 ms chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào

**Báo cáo Codex:** `…/outputs/06b4hr-independent-review.md`, SHA-256 `9246598cc5a6759812094ee9be9d53973b5dbcb0ee11f7b98236d69253a42725`. Đọc toàn bộ.

**Bundle:** `…/06b4hr-offline-reproductions.zip`, SHA-256 `4476a3cef13f71a6f4c02fc2511376e015ee172ce39d2233fd66d787c14d3449`.

- Giải nén vào thư mục riêng; đọc bốn script trước khi chạy: `reproduce.py`, `extra_stubs.py`, `extended_review.py`, `verify_extended_paths.py`.
- Các script chỉ dựng fixture, gọi hàm offline/CLI của `arp_cases.py` và ghi JSON.
- Bản harness trong bundle giống hệt 4HR.

**Trạng thái 06B-4HR:** đã review, **còn lỗi, chưa chấp nhận nối tích hợp**. Ghi chú review và đính chính tại chỗ đã thêm vào [`task06b4hr-summary.md`](task06b4hr-summary.md); evidence `task06b4hr/` không sửa.

**Quyết định phân loại neighbor của reviewer** (được áp dụng):

- entry **động** của IP theo dõi mất hoặc không còn binding → CHƯA KIỂM CHỨNG;
- REACHABLE→STALE/DELAY/PROBE giữ MAC/interface là bình thường;
- guest `10.200.0.2` trên tap0 **bắt buộc** PERMANENT đúng MAC và dùng được;
- bảng hợp lệ cho thấy mất/đổi → FAIL;
- dữ liệu hỏng → LỖI PHÉP ĐO, giữ FAIL độc lập.

## 2. Bản làm việc

- `/home/dathq/projects/ct01-06b4hr1/`, chép từ `ct01-06b4hr` **sau khi xác minh** manifest 31 file. Bản 4HR giữ nguyên.
- **Sửa cục bộ** trong `arp_cases.py`, không viết lại module; cập nhật `selftest_arp.py`, `mutation_arp.py`. 28 file khác giống hệt.
- Diff: [`task06b4hr1/ct01-06b4hr1-harness-vs-06b4hr.diff`](task06b4hr1/ct01-06b4hr1-harness-vs-06b4hr.diff). Hash 31 file: [`task06b4hr1/harness-sha256.txt`](task06b4hr1/harness-sha256.txt).

## 3. Bản sửa

### HR1 — Baseline và restore

**`baseline_problem` kiểm nội dung, không chỉ kiểu:**

- MAC hợp lệ;
- `operstate` thuộc tập operstate của kernel (`up`, `down`, `unknown`, …);
- mỗi `addrs` là địa chỉ IPv4/prefix; mỗi `routes` là dòng route không rỗng;
- `neigh_static`: khóa `"ip dev"` hợp lệ và MAC hợp lệ;
- `neigh_dynamic`: khóa hợp lệ, `[MAC, flags ≥ 0]`;
- `arp_notify ≥ 0`.

**`restore_problem(restore, before)` kiểm bằng chứng:**

- `commands` là danh sách bản ghi `{step, cmd, rc int|None}`; `diffs` là danh sách chuỗi; `error` là chuỗi hoặc `None`.
- Khi **`restored=True`**, cần đủ:
  - không có `error`, không có `diffs`;
  - có trạng thái đọc lại **`after` hợp lệ** (cùng kiểm nội dung như baseline);
  - **`guest_state.diff(baseline, after)` tính lại tại đây phải rỗng**. Không tin cờ `restored`/`diffs` đã lưu.

Neighbor động không bị ép giống baseline (quy tắc của `guest_state`). *(Đính chính 06B-4HR2: validator này **chưa** kiểm tính nhất quán giữa hai nhóm: `neigh_dynamic` có cờ PERMANENT, hay cùng khóa ở cả hai nhóm, vẫn được nhận. Đây là R1, sửa ở 06B-4HR2.)*

### HR2 — Binding guest bắt buộc

- Một entry neighbor có **đúng một** trạng thái NUD. Tổ hợp như PERMANENT+FAILED, PERMANENT+INCOMPLETE, PERMANENT+REACHABLE là hàng **không hợp lệ** → LỖI PHÉP ĐO, không bao giờ ĐẠT. Quy tắc này là [Kernel], chưa kiểm trên dữ liệu thật.
- Hàng bắt buộc `10.200.0.2` dev `tap0` phải có trạng thái **đúng** `PERMANENT`, MAC guest **và** binding dùng được.
- Hàng hợp lệ mà REACHABLE, FAILED (có hoặc không MAC), hay MAC khác → FAIL. Kể cả khi trước cũng sai như vậy, tức không có thay đổi tap0.

### HR3 — Nhánh chưa bắt đầu

`evaluate_case` không còn trả về sớm. Ca chưa bắt đầu (`exec_error`, không baseline, không bước) vẫn được thu bằng chứng như mọi ca:

- neighbor từ hàng hợp lệ;
- lỗi capture/bộ đếm của đầu vào;
- `read_error` nếu có.

**Không** coi thiếu lần đọc A/B là lỗi đo: ca chưa chạy thì không có lần đọc. Không suy FAIL từ vị trí khung khi không có cửa sổ.

**Thứ tự:** FAIL (vd. binding bắt buộc đổi) → LỖI PHÉP ĐO → LỖI THỰC THI. JSON giữ `not_started: true` cùng mọi bằng chứng.

### HR4 — Hàng neighbor hỏng là "chưa biết", không phải "mất"

- `parse_neigh_full` trả thêm `unknown`: định danh `(dst, dev)` đọc được của mỗi hàng hỏng; `None` nếu không đọc được.
- **Hàng bắt buộc:**
  - có hàng hợp lệ sai → FAIL;
  - không có hàng hợp lệ nhưng có hàng hỏng có thể là nó → LỖI PHÉP ĐO ("không đọc được, chưa biết");
  - bảng hợp lệ thực sự không có nó → FAIL.
- **So sánh tap0 trước/sau** và **so sánh IP theo dõi**: bỏ qua, ghi lỗi đo, khi một bên có hàng hỏng có thể liên quan. Không suy "mất", "đổi" hay "không còn binding" từ danh sách đã lọc.
- **FAIL độc lập vẫn giữ:** hàng hợp lệ mang MAC guest ngoài tap0, hàng bắt buộc hợp lệ mà sai.

### HR5 — Callback đối chứng

- Chỉ nhận payload là tuple/list **đúng hai phần tử**; `ok` phải **đúng bằng `True`**.
- Bare `True`/`1`, dict, list thiếu/thừa phần tử, `None` đều thành bản ghi đối chứng thất bại có mô tả, không ném ngoại lệ, không mất hồ sơ ca.
- `ok=1` hay `"true"` không được nhận.

### Trường JSON chung

`_result` bảo đảm **mọi nhánh** có cùng các trường, rỗng khi không áp dụng: `failure_evidence`, `measurement_errors`, `execution_problems`, `neighbour_inconclusive`, `not_started`, `not_run`, `probe_frames`, `probe_frames_certain`.

Các nhánh: ca thường, FAIL, `not_run`, chưa bắt đầu, id lạ, nhóm bị bỏ qua, lỗi đầu vào.

## 4. Tái hiện trước/sau: chạy lại nguyên bốn script của Codex

**Cách chạy:**

- Bốn script **không sửa** (đã so `cmp`), mỗi phiên bản một thư mục.
- Helper fixture lấy từ `selftest_arp.py` 4HR1. Fixture "restored" nay có thêm trạng thái `after` (= baseline); 4HR không đọc trường này.
- Module là `arp_cases.py` của phiên bản được kiểm.

**Kiểm chứng tính tương đương:** lần chạy trên 4HR cho **bốn log giống hệt** log trong bundle của Codex.

Bảng: [`task06b4hr1/codex-reproductions-before-after.txt`](task06b4hr1/codex-reproductions-before-after.txt); JSON/log: [`task06b4hr1/codex-rerun/`](task06b4hr1/codex-rerun/).

| Ca Codex | 06B-4HR | 06B-4HR1 |
|---|---|---|
| `actual_restore_after_mismatch` (record thật của `run_group`, MAC `after` khác) | **exit 0**, CLI exit 0 | exit 2; CLI exit 2, nêu đúng khác biệt MAC |
| `actual_restore_after_missing` | **exit 0** | exit 2 |
| `group_baseline_*` (addrs, routes, neigh_static, operstate rỗng, arp_notify −1) | **exit 0** | exit 2 |
| `group_restore_error_with_true`, `group_restore_commands_invalid_contents` | **exit 0** | exit 2 |
| `mandatory_contradictory_states` (PERMANENT+FAILED) | **ĐẠT (kiểm quy tắc)** | LỖI PHÉP ĐO |
| `mandatory_mac_invalid_type`, `_state_missing`, `_state_invalid_type`, `mandatory_before_invalid_type` | FAIL (vượt dữ liệu) | LỖI PHÉP ĐO |
| `unstarted_case_known_neighbor_violation` | LỖI THỰC THI (mất bằng chứng) | FAIL |
| `unstarted_actual_plus_capture_error` (`run_group` thật) | LỖI THỰC THI, không có bằng chứng | FAIL; giữ `not_started`, bằng chứng neighbor **và** lỗi capture |
| `callback_control_True`, `_1`, `_{'ok': True}`, `_[True]` | **TypeError / KeyError / IndexError** (mất hồ sơ) | có hồ sơ, đối chứng không đạt |
| Ca hợp lệ/đúng sẵn: `mandatory_removed`, `_mac_changed`, `_not_permanent`, `_failed_no_mac` (FAIL); `dynamic_*`; mọi tái hiện F1–F5 cũ; `group_clean` exit 0; liên kết/đối chứng sai kiểu; ma trận restore 40 tình huống (0 diff) | đúng | **không đổi** |

**Lưu ý đọc log:** dòng "Required neighbour parsed binding: True" của 4HR1 không có nghĩa hàng mâu thuẫn được nhận. Hàng PERMANENT+FAILED nay là hàng không hợp lệ (vào `unknown`), nên `parse_neigh()[0][0]` mà script in ra là hàng khác. Test H2.2 kiểm điều này.

## 5. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp.py` | **212/212** (146 cũ + 66 mới ở mục H); ổn định 5 lần | [`logs/selftest-arp.log`](task06b4hr1/logs/selftest-arp.log), [`logs/selftest-arp-stability.txt`](task06b4hr1/logs/selftest-arp-stability.txt) |
| Test mới chạy trên `arp_cases.py` **4HR** | 161/212: **51/66 test H hỏng**. 15 test H đạt là ca đối chứng mà 4HR đã đúng (bản ghi sạch, neighbor động không ép, binding sai do hàng hợp lệ, callback tuple đúng dạng) | [`logs/selftest-arp-new-tests-on-06b4hr-code.log`](task06b4hr1/logs/selftest-arp-new-tests-on-06b4hr-code.log) |
| `mutation_arp.py` | **71/71** đột biến hành vi bị bắt đúng test (48 cũ + 23 mới C1–C23) + 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-arp.txt`](task06b4hr1/logs/mutation-arp.txt) |
| `selftest_l2 --offline-only`, `selftest_l2eval --offline-only` (module dùng chung, không đổi) | 175/175; 65/65 | [`logs/`](task06b4hr1/logs/) |

**Test mới (mục H):**

| Mục | Nội dung |
|---|---|
| H1 (25) | record thật của `run_group`: `after` khác MAC/route/arp_notify, mất `after`, `after` có địa chỉ sai; `restored=True` kèm `error`; `commands` sai; baseline sai từng trường; cùng nội dung sai ở **cả** baseline và `after` (để `diff()` không thấy); `after` có neighbor động sai; neighbor động khác nhau **không** bị ép; CLI exit 2 |
| H2 (10) | 4 tổ hợp state với PERMANENT; hàng mâu thuẫn không nằm trong hàng hợp lệ; hàng bắt buộc hợp lệ REACHABLE / FAILED có-không MAC / MAC khác → FAIL; REACHABLE cả trước lẫn sau vẫn FAIL |
| H3 (5) | `run_group` thật với baseline không đọc được: thay đổi neighbor bắt buộc → FAIL (không lệnh nào tới guest); + capture mất → FAIL giữ lỗi capture; capture mất, neighbor sạch → LỖI PHÉP ĐO; đầu vào đọc được → LỖI THỰC THI đủ trường; không suy FAIL từ khung khi không có cửa sổ |
| H4 (9) | hàng bắt buộc hỏng (lladdr 1, thiếu state, state chuỗi) → LỖI PHÉP ĐO, không FAIL; hàng bắt buộc hỏng ở *trước*; bảng hợp lệ thực sự thiếu → FAIL; hàng hỏng + MAC guest trên eth0 → FAIL; hàng không định danh được; IP theo dõi hỏng ở trước hoặc sau không bị suy là mất/đổi |
| H5 (10) | callback trả `True`, `1`, `"true"`, `{'ok': True}`, `[True]`, list 3 phần tử, `(1, x)`, `("true", x)`, `None` → có hồ sơ, không ĐẠT; `(True, detail)` → đạt |
| H6 (7) | mọi nhánh JSON có đủ trường bằng chứng/lỗi đúng kiểu |

## 6. Giới hạn còn lại

- **Chưa nối tích hợp:** collector `ip -j neigh` trong worker netns, đối chứng sống A1/A2, `GuardedRunner`/capture/heartbeat, mount/run script cho ARP.
- **Giả định chưa kiểm trên dữ liệu thật:**
  - quy tắc "một trạng thái NUD mỗi entry" và cách `ip -j neigh` biểu diễn trạng thái;
  - tập operstate; định dạng `/proc/net/arp` (đã có từ 4B).
- **Mọi hành vi guest/kernel là mô phỏng:** gratuitous request, số ARP gửi lại, netifd, phản ứng của console.
- **Ca chưa bắt đầu với file bộ đếm rỗng** được ghi lỗi đo "no counter read". Thực tế file luôn có các lần đọc toàn phiên.
- **Guard 20 ms chưa đo. CT-01 vẫn "Kiểm chứng một phần — chưa đạt"; CT-14 chưa bắt đầu.**

## 7. Hash

Mọi file trong `task06b4hr1/`: [`SHA256SUMS`](task06b4hr1/SHA256SUMS) (`f80873525975f049ffef83aa20803f3023f6fbdea872f02e599e2c160c520176`).
