# Minh chứng Nhiệm vụ 06B-4HR2: sửa R1 (nhất quán static/dynamic của neighbor guest) (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4I):** Codex review hẹp độc lập: **R1 đã khắc phục; chấp nhận bản sửa ở mức offline.** Review không xác nhận collector hay luồng tích hợp thật và không tự cho phép chạy tích hợp. Câu `AssertionError` (rc 1) của `static_flag_review.py` cũ là kỳ vọng lỗi cũ đã hết hiệu lực, không phải lỗi sản phẩm và không dùng làm bằng chứng test đạt. Các số mutation 75/75, ổn định 3 lần, `selftest_l2` 175/175 trong tài liệu này reviewer chỉ đọc, không tự chạy lại. Phần nối ở [`task06b4i-summary.md`](task06b4i-summary.md).

> **Loại bằng chứng: kiểm thử offline. Chưa nối tích hợp; run script không đổi.**
>
> - Không Docker, QEMU, sudo, probe mạng; không đổi host, source cô lập, ruleset hay guard.
> - **Mọi hành vi guest/kernel là mô phỏng.** Guard 20 ms chưa đo.
> - **CT-01 vẫn "Kiểm chứng một phần — chưa đạt"**; CT-14 chưa bắt đầu.

## 1. Đầu vào

- Báo cáo Codex `…/outputs/06b4hr1-independent-review.md`, SHA-256 `05ccfad6af518047f9706648a15920aa58a515e6f13472fd7ce953aa062f2aec`. Đọc toàn bộ.
- Bundle `…/06b4hr1-offline-reproductions.zip`, SHA-256 `377d133215a5aec0ac52d67f71f3b307c2215e44ed9999f6a10f9582de0b41f2`.
  - Giải nén vào thư mục riêng; đọc `static_flag_review.py` và `additional_review.py` trước khi chạy.
  - Hai script chỉ dựng fixture, gọi hàm offline/CLI của `arp_cases.py`, và đọc vài snapshot đã lưu.
  - Bản harness trong bundle giống hệt 4HR1.
- **Trạng thái 06B-4HR1:** đã review; các tái hiện HR1–HR5 đã khắc phục; **còn R1, chưa chấp nhận nối tích hợp**.
  - Ghi chú review đã thêm vào [`task06b4hr1-summary.md`](task06b4hr1-summary.md).
  - Nhận định "đã khắc phục HR1" được giới hạn cho các biến thể đã tái hiện.
  - Evidence `task06b4hr1/` không sửa.

**R1 (P1):**

- Baseline có `neigh_dynamic['10.200.0.9 eth1'] = [MAC, 6]` (flags 6 chứa ATF_PERM 0x4) và entry đó **mất** sau restore → A1 ĐẠT, nhóm exit 0, CLI exit 0.
- Lý do: `guest_state.diff` không so neighbor động, mà validator lại nhận entry mang cờ PERMANENT trong nhóm động.
- Theo giao kèo `guest_state.parse_snapshot`, mọi hàng có `flags & 0x4` thuộc `neigh_static`. Hồ sơ như trên tự mâu thuẫn với giao kèo đó.

## 2. Bản làm việc

- `/home/dathq/projects/ct01-06b4hr2/`, chép từ `ct01-06b4hr1` **sau khi xác minh** manifest 31 file. Bản 4HR1 giữ nguyên.
- **Sửa cục bộ** trong `baseline_problem` của `arp_cases.py` (cộng hằng số `GS_ATF_PERM = 0x4`); cập nhật `selftest_arp.py`, `mutation_arp.py`.
- **Không sửa `guest_state.py`** hay file nào khác (28 file giống hệt).
- Diff: [`task06b4hr2/ct01-06b4hr2-harness-vs-06b4hr1.diff`](task06b4hr2/ct01-06b4hr2-harness-vs-06b4hr1.diff). Hash 31 file: [`task06b4hr2/harness-sha256.txt`](task06b4hr2/harness-sha256.txt).

## 3. Bản sửa

`baseline_problem` được dùng cho **cả baseline lẫn `restore.after`**. Hàm này nay từ chối thêm hai trường hợp:

1. **Entry `neigh_dynamic` có bit PERMANENT (0x4)**, ví dụ flags 4, 6, 0xc. Lỗi nêu rõ "belongs to neigh_static".
2. **Cùng khóa neighbor xuất hiện ở cả `neigh_static` và `neigh_dynamic`.**

**Cách xử lý:**

- Hồ sơ mâu thuẫn chỉ được **báo lỗi**: ca không ĐẠT, có `record_problems`, nhóm và CLI exit 2.
- Evaluator **không** tự chuyển entry sang nhóm khác để PASS, và không sửa input (test R1.8).
- Neighbor động hợp lệ (không có bit 0x4) thay đổi hay mất sau restore vẫn **không** bị ép giống baseline, đúng quy tắc `guest_state` (R1.7: exit 0).
- Entry static đúng nhóm mà mất sau restore vẫn bị chặn (R1.6).

## 4. Tái hiện trước/sau

Chạy **nguyên sáu script của Codex, không sửa** (`cmp`): `reproduce.py`, `extra_stubs.py`, `extended_review.py`, `verify_extended_paths.py`, `additional_review.py`, `static_flag_review.py`.

- Mỗi phiên bản một thư mục; helper fixture lấy từ `selftest_arp.py` 4HR2; module là `arp_cases.py` của phiên bản được kiểm.
- **Đối chiếu với log của Codex:** lần chạy trên 4HR1 cho log giống hệt bundle, trừ đường dẫn tuyệt đối của fixture trong một thông báo của `verify_extended_paths`.

Bảng: [`task06b4hr2/codex-reproductions-before-after.txt`](task06b4hr2/codex-reproductions-before-after.txt); log/JSON: [`task06b4hr2/codex-rerun/`](task06b4hr2/codex-rerun/).

| `static_flag_review.py` | 06B-4HR1 | 06B-4HR2 |
|---|---|---|
| flags 6 trong `neigh_dynamic`, mất sau restore | **nhóm exit 0, CLI exit 0, A1 ĐẠT** | nhóm exit 2, CLI exit 2, A1 CHƯA KIỂM CHỨNG; `record_problems` nêu "has the PERMANENT flag (0x6): belongs to neigh_static" |
| Đối chứng: cùng entry đúng nhóm static, mất sau restore | exit 2 | exit 2 |

- Trên 4HR2, script kết thúc với `AssertionError` (rc 1) ở câu `assert` cuối, vốn kỳ vọng lỗi vẫn còn. JSON được ghi trước câu đó.
- **Không hồi quy:** bốn script còn lại cho log **giống hệt** giữa 4HR1 và 4HR2, gồm:
  - F1–F5; HR1–HR5; nhóm sạch exit 0;
  - ma trận restore 40 tình huống 0 diff;
  - đổi neighbor động hợp lệ trong `after` của record thật vẫn exit 0.

## 5. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_arp.py` | **224/224** (212 cũ + 12 mới ở mục R1); ổn định 3 lần | [`logs/selftest-arp.log`](task06b4hr2/logs/selftest-arp.log), [`logs/selftest-arp-stability.txt`](task06b4hr2/logs/selftest-arp-stability.txt) |
| Test mới chạy trên `arp_cases.py` **4HR1** | 216/224: **8 test R1 hỏng** (R1.1 ×3, R1.2, R1.3, R1.4, R1.5, R1.8). 4 test đạt là ca đối chứng: static mất bị chặn, neighbor động thay đổi, giao kèo `guest_state`, đầu-cuối | [`logs/selftest-arp-new-tests-on-06b4hr1-code.log`](task06b4hr2/logs/selftest-arp-new-tests-on-06b4hr1-code.log) |
| `mutation_arp.py` | **75/75** đột biến hành vi bị bắt đúng test (71 cũ + D1–D4) + 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-arp.txt`](task06b4hr2/logs/mutation-arp.txt) |
| `selftest_l2.py --offline-only` (`guest_state`/`l2frames`, không đổi) | 175/175 | [`logs/selftest-l2.log`](task06b4hr2/logs/selftest-l2.log) |

`selftest_l2eval` và các suite IPv4/ICMP/wiring không chạy lại: file của chúng không đổi và `arp_cases` không đổi phần dùng `l2eval`.

**Test mới (mục R1, qua `evaluate_group` trên record thật của `run_group` và qua CLI):**

| Test | Nội dung |
|---|---|
| R1.1 | baseline `neigh_dynamic` có flags 6 / 4 / 0xc, entry mất sau restore → bị chặn |
| R1.2 | cùng record qua CLI → exit 2 |
| R1.3 | cùng khóa ở hai nhóm → bị chặn (cả hai đường) |
| R1.4 | `after` mâu thuẫn (dynamic có cờ PERMANENT), baseline sạch → bị chặn |
| R1.5 | `after` có khóa ở hai nhóm → bị chặn |
| R1.6 | entry static đúng nhóm mất sau restore → bị chặn |
| R1.7 | neighbor động hợp lệ thay đổi/mất → vẫn exit 0 |
| R1.8 | hồ sơ mâu thuẫn chỉ bị báo, không bị sửa hay chuyển nhóm |
| R1.9 | `GS.read_state` thật trên `/proc/net/arp` mô phỏng: flags 6 → `neigh_static`; validator nhận trạng thái đó |
| R1.10 | guest mô phỏng có neighbor static flags 6, chạy `run_group` + `evaluate_group` → exit 0, nhãn không đổi |

**Đột biến mới:**

| Mã | Đột biến |
|---|---|
| D1 | bỏ kiểm bit PERMANENT |
| D2 | bỏ kiểm trùng khóa |
| D3 | sai giá trị bit (0x8) |
| D4 | bỏ kiểm `after` bằng `baseline_problem` |

Một fixture H1 cũ dùng khóa `10.200.0.1 eth1`, khóa này cũng có trong `neigh_dynamic` của baseline mô phỏng, nên đột biến C7 bị kiểm tra trùng khóa che mất. Fixture đã đổi sang khóa chỉ có ở nhóm static (`10.200.0.77 eth1`) để C7 lại bị bắt đúng test.

## 6. Giới hạn còn lại

- **Chưa nối tích hợp:** collector `ip -j neigh` trong worker netns, đối chứng sống A1/A2, `GuardedRunner`/capture/heartbeat, run script.
- **Định dạng thật chưa kiểm:** chưa kiểm `ip -j neigh` JSON thật và operstate sysfs thật. Như Codex ghi nhận, các snapshot đã lưu (06B-3G/4C/4G) chỉ có text `ip neigh`/`ip addr`, không phải raw JSON. Do đó tập operstate, cách mã hóa state và quy tắc "một trạng thái NUD mỗi entry" vẫn cần xác nhận ở mốc tích hợp.
- **Quy tắc static/dynamic** dựa trên giao kèo `guest_state.parse_snapshot` (`flags & 0x4`). Định dạng `/proc/net/arp` thật trên hai image chưa kiểm ngoài parser đã có.
- **Mọi hành vi guest/kernel là mô phỏng. Guard 20 ms chưa đo. CT-01 vẫn chưa đạt; CT-14 chưa bắt đầu.**

## 7. Hash

Mọi file trong `task06b4hr2/`: [`SHA256SUMS`](task06b4hr2/SHA256SUMS) (`73951341777a119b7332b3b3fad6ebbd6417ca95f40670b794a1dfd4d081d13a`).
