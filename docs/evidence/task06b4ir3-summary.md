# Minh chứng Nhiệm vụ 06B-4IR3: sửa PC-1–PC-4 của review precheck, chỉ offline (09/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Chưa chạy root precheck, guest hay run script.
>
> - Không sudo, Docker thật, QEMU, probe mạng; không đổi host hay ruleset; không đọc bí mật hay malware.
> - Guest, console, Docker, `nft`, tshark… trong test đều là giả. Các lệnh Bash cô lập dùng hàm giả cho Docker/timeout/CLI.
> - Guard 20 ms và hành vi ARM/MIPS chưa xác nhận. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 1. Đầu vào

| File | SHA-256 |
|---|---|
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir2-precheck-independent-review.md` | `5d4bd8476f1b46e3c06e42b890425476aa27aefe12fd8af445e7b3ac5ee9b977` |
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir2-precheck-offline-reproductions.zip` | `a3c7e4ad3ea49a8b86cf9bfa977dd2042a34a97f395809d59f6ae9a61df1bec1` |

- Bundle giải nén vào `/home/dathq/projects/ct01-06b4ir3-codex-bundle/`. `bundle-SHA256SUMS` khớp; `harness/` trong bundle giống hệt manifest 4IR2.
- Đã đọc `mips-fixtures.py`, `mips-extra.py`, `control-fragments.py` trước khi chạy. Ba script chỉ gọi hàm thật với guest/console giả; các đoạn Bash dùng hàm giả; không chạy precheck hay Docker.

**Kết luận review:**

- Hồ sơ precheck được chấp nhận ở phạm vi snapshot host không-sudo và parser offline.
- **Chưa** chấp nhận script để chạy root, chưa đủ căn cứ cho lần chạy guest.
- Bốn phát hiện PC-1…PC-4. Ghi chú và đính chính đã thêm vào [`task06b4ir2-precheck-summary.md`](task06b4ir2-precheck-summary.md).

## 2. Bản làm việc

| Phần | Đường dẫn | Manifest | Diff |
|---|---|---|---|
| Harness | `/home/dathq/projects/ct01-06b4ir3/`, chép từ `ct01-06b4ir2` sau khi xác minh 35 file | [`task06b4ir3/harness-sha256.txt`](task06b4ir3/harness-sha256.txt) (35 file) | [`task06b4ir3/ct01-06b4ir3-harness-vs-06b4ir2.diff`](task06b4ir3/ct01-06b4ir3-harness-vs-06b4ir2.diff) |
| Script precheck (bản **mới riêng**) | `/home/dathq/projects/ct01-06b4ir3-precheck/` | [`task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt`](task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt) | [`task06b4ir3-precheck-scripts/precheck-scripts-vs-06b4ir2.diff`](task06b4ir3-precheck-scripts/precheck-scripts-vs-06b4ir2.diff) |

- `ct01-06b4ir2`, script precheck cũ (`7c86f9ae…`) và evidence cũ không đổi.
- **File harness đổi:**
  - `guest_state.py`, `arp_cases.py` (PC-3);
  - `run-06b4i.sh` (PC-1, `H`);
  - test/mutation: `selftest_l2.py`, `selftest_arp.py`, `selftest_arp_wiring.py`, `mutation_l2.py`, `mutation_arp.py`, `mutation_arp_wiring.py`.
- **Không đổi:** `probe_matrix.py`, `arp_harness.py`, `ctl_loop.py`, ICMP/IPv4, `l2frames.py`, `l2eval.py`, `counter_window.py`, run script cũ.

## 3. PC-1 — dừng giữa kiến trúc (`run-06b4i.sh`)

**Chính sách lần chạy đầu:** harness MIPS **chỉ** được gọi khi ARM đạt **mọi** điều kiện bắt buộc của lượt đó: outcome `PASS`, không còn QEMU/tshark trong container, verify sau khi tắt guest đạt.

- **Dừng vòng (`break`) nếu:** có bất kỳ FAIL (kết luận, restore, hậu kiểm sau ARM, ERROR), UNVERIFIED, hoặc kiểm "không có QEMU trước kiến trúc" lỗi.
- **Ghi lại:**
  - `ARCH_STOP` ghi lý do, `ARCH_CALLED` ghi các kiến trúc **đã gọi harness**;
  - "harness không được gọi" được tách khỏi "guest không boot" (việc boot do `probe_matrix.py` quyết định);
  - run-level check bị **bỏ qua có báo cáo** (`[SKIPPED]`), không thêm một FAIL mới che nguyên nhân.
- **Không exit sớm:** teardown capture, netns, ruleset, xóa container, khôi phục manager và host-state sau vòng lặp vẫn chạy.
- **Exit code giữ nguyên nhân:** FAIL → 1, chỉ UNVERIFIED → 4. Bất biến bảo vệ: dừng mà không có nguyên nhân ghi lại thì `fail`.
- Sau kiến trúc cuối (MIPS) không có gì để dừng: run-level check vẫn chạy.

**Kiểm** (PC1.1–PC1.7, trong `selftest_arp_wiring.py`): Bash thật chạy **nguyên** vòng kiến trúc, khối sau vòng tới §7 và khối kết quả của `run-06b4i.sh`; docker/timeout/CLI/`E`/`bash` là hàm giả.

| Biến thể | Harness được gọi | Exit |
|---|---|---|
| Cả hai đạt | ARM, MIPS; run-check chạy | 0 |
| ARM FAIL / restore FAIL / ERROR / verify sau ARM FAIL / QEMU còn sót / leak 99 / capture 98 | chỉ ARM; `[STOPPED]`, run-check `[SKIPPED]`, vẫn tới sau vòng | 1 |
| ARM UNVERIFIED | chỉ ARM | 4 |
| QEMU chạy sẵn trước ARM | **không** kiến trúc nào ("harness not called for ARM") | 1 |
| QEMU chạy sẵn trước MIPS | chỉ ARM | 1 |
| MIPS FAIL | cả hai; run-check chạy | 1 |

**Script `control-fragments.py` của reviewer** (nguyên byte, trên 4IR3): ba trace FAIL nay **chỉ gọi ARM**, nên assert cũ (kỳ vọng ARM rồi MIPS) hỏng. Đọc trace thực tế: [`logs/codex-bash-loop-after-4IR3.txt`](task06b4ir3/logs/codex-bash-loop-after-4IR3.txt); trên 4IR2 là `ARM MIPS` ([`logs/codex-control-fragments.py-before-4IR2.log`](task06b4ir3/logs/codex-control-fragments.py-before-4IR2.log)).

## 4. PC-2 — collector/evaluator (`/home/dathq/projects/ct01-06b4ir3-precheck/`)

Script cũ được thay bằng hai phần:

- **`collector.py`** (root, chỉ đọc). Mỗi lần đọc ghi argv, rc, stdout/stderr (file) và trạng thái `OK | NONZERO | EXEC_ERROR | TIMEOUT | SKIPPED` kèm lý do.
  - **Hiện diện container** chỉ quyết định từ **một** `docker ps -a` thành công: `PRESENT`/`ABSENT`. Listing lỗi → `UNKNOWN`. Permission denied hay daemon lỗi **không bao giờ** thành "absent".
  - **Trạng thái manager** lấy từ inspect thành công. Inspect lỗi → `UNKNOWN`; listing có mà inspect lỗi → `UNKNOWN`; listing thành công không có → `ABSENT`. `docker exec` chỉ khi inspect **thành công** báo `running`.
  - **Network** phân giải theo label, đúng **một** kết quả. Không có hoặc nhiều hơn một → không inspect (`SKIPPED`, lý do giữ).
  - `pgrep` rc 1 = không có tiến trình; rc khác 0/1 = lỗi đọc.
  - **Exit:** 0 = mọi lần đọc bắt buộc OK (dữ liệu đủ, **chưa phải kết luận**); 3 = dữ liệu thiếu; 2 = từ chối trước khi đọc. Không có dòng "PASS".
- **`evaluate_precheck.py`** (user, offline, trên bản sao output). Từng mục `PASS/FAIL/UNKNOWN`, kèm raw và lý do:
  - image ID **so tự động** với ID đã review;
  - container thử vắng; `sandboxnet` đúng một, subnet 192.168.60.0/24, gateway .1; `dbnet` đúng một;
  - manager `running|exited`: nếu running thì phải có IP 192.168.60.10 và MAC endpoint dùng được (`endpoint_mac_problem`); nếu exited thì MAC/IP để run script đọc sau;
  - mongo chạy; không QEMU/capture;
  - ruleset bằng `host-after` 06B-4G; AppArmor đọc được.
  - **Exit:** 0 = mọi mục bắt buộc PASS; 1 = có FAIL; 2 = có UNKNOWN; 3 = output collector không dùng được.

**Schema mới:** `reads.json` (`ct01-precheck-collector/1`: `meta` + `reads[]`) và `precheck-result.json` (`verdict` + `items[]`).

## 5. PC-3 — admin link state (`guest_state.py`, `arp_cases.py`)

- **Snapshot** thêm section `link` = `ip link show dev IF`. Trường mới `admin_up` lấy từ cờ `UP` của header, **tách khỏi** `operstate` (sysfs).
  - Header được kiểm: đúng **một** dòng; đúng tên interface; cờ dạng `<A,B,…>`. Thiếu hoặc lạ → `StateReadError`.
  - Snapshot dạng cũ (thiếu `link`) → lỗi đọc, không bao giờ "không đổi".
- **`diff`** thêm `admin_up`. **`restore`** khôi phục admin theo baseline (`ip link set up` **hoặc** `down`).
  - Khi đổi MAC, chỉ `up` lại nếu baseline admin UP.
  - Quy tắc operstate cũ giữ nguyên (không nới); operstate `down` **không** bị diễn dịch thành admin down.
  - `restored=true` chỉ khi lần đọc lại không còn diff, kể cả `admin_up`.
- **Validator ARP:** `BASELINE_KEYS` bắt buộc `admin_up: bool` cho baseline **và** `restore.after`. Hồ sơ thiếu hay sai kiểu → vấn đề record, không phải restore đã xác nhận.
- **`FakeGuest`** (`selftest_l2`) tách admin (`ip link set`) khỏi carrier/operstate, thêm section `link`.

**Kiểm:**

- **GA1–GA11** (`selftest_l2`): header ARM thật (06B-3G) và MIPS thật (06B-4G: `NO-CARRIER … state DOWN` mà admin UP); header lạ/thiếu/hai dòng/sai interface; chỉ cờ admin khác → diff; baseline admin UP + operstate down → mất UP → restore `up`; lệnh `up` lỗi → `restored=false`; baseline admin DOWN giữ đúng hướng ngược; không diễn dịch operstate; MAC + admin DOWN; quy tắc operstate không nới.
- **PC3.1–PC3.6** (`selftest_arp`, **thứ tự sản xuất**, S1 cuối):
  - record thiếu/sai/mâu thuẫn `admin_up` → exit 2;
  - `up` lỗi ở trigger **và** restore → `restored=false`, **không có service link sau S1**;
  - `up` lỗi một lần → restore thành công, link sau S1 được gửi, S1 LỖI THỰC THI;
  - guest **mô phỏng** kiểu MIPS (admin UP, không carrier) → mọi restore xác nhận, exit 0.

**Script reviewer (nguyên byte):**

- `mips-fixtures.py`: khoảng mù nay `diff=["admin_up: True -> False"]`, nên trường `ok` cũ (kỳ vọng lỗi) thành false. Ma trận operstate 12 ca và 3 nhóm giữ nguyên như 4IR2 (thận trọng, không nới).
- `mips-extra.py` (thứ tự S1→A1 **tự dựng**, không phải thứ tự sản xuất): assert cũ hỏng. Bộ quan sát riêng [`reproductions/mips-extra-observe.py`](task06b4ir3/reproductions/mips-extra-observe.py) cho thấy:
  - 4IR2: `restored=true`, ca thứ hai chạy, link sau S1 với admin DOWN;
  - 4IR3: `restored=false` (`ip link set up` rc 2), ca sau không chạy, không link sau S1.
  - Log: [`logs/mips-extra-observe-before-after.txt`](task06b4ir3/logs/mips-extra-observe-before-after.txt).

**Phân loại:** PC-3 là **lỗi xác nhận restore**. Evaluator 4IR2 vẫn giữ S1 là LỖI THỰC THI, nên **chưa có bằng chứng false PASS của ca**.

## 6. PC-4 — chuẩn bị chạy root ([`RUN-PROCEDURE.md`](task06b4ir3-precheck-scripts/RUN-PROCEDURE.md))

**Đề xuất để reviewer xét, chưa thực hiện:**

- Root sao chép `collector.py` **một lần** vào thư mục `mktemp -d` mới trong `/var/tmp` (0700), rồi kiểm SHA-256 **trên bản sao**. Sai hash → xóa bản sao, không chạy gì.
- Chạy bản sao bằng `/usr/bin/python3 -I -B`, với `sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin`.
- **Collector:**
  - mở output bằng `O_NOFOLLOW|O_DIRECTORY`, kiểm chủ root, mode 0700, thư mục rỗng;
  - tạo file bằng `O_CREAT|O_EXCL|O_NOFOLLOW` qua fd thư mục;
  - không redirection/`tee`/`chown -R`;
  - executable có đường dẫn tuyệt đối, được kiểm thuộc root và không nhóm/người khác ghi được (kể cả thư mục chứa);
  - env của tiến trình con chỉ có `PATH`, `LANG`, `LC_ALL`.
- Output được sao ra bằng `sudo tar -c` (root chỉ đọc) và giải nén với quyền user.

**Kiểm offline trong cây toy** (không root, không đích hệ thống):

- symlink/không rỗng/mode/chủ sở hữu → từ chối;
- **race của review:** thay đường dẫn bằng symlink **sau** kiểm tra → file vẫn vào thư mục đã kiểm (theo fd), đích symlink không đổi;
- symlink cài sẵn dưới tên output → tạo file lỗi;
- executable đúng/sai; env tối thiểu;
- `main` khi không root → exit 2;
- đoạn root: hash đúng chạy **bản sao**; hash sai → không chạy, xóa bản sao; không `source`/`tee`/`chown`, không chuyển hướng ra ngoài.

## 7. Tái hiện, kiểm thử, mutation

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_l2.py --offline-only` | **187/187** (+12 GA) | [`logs/selftest-l2.log`](task06b4ir3/logs/selftest-l2.log) |
| `selftest_arp.py` | **233/233** (+9 PC3) | [`logs/selftest-arp.log`](task06b4ir3/logs/selftest-arp.log) |
| `selftest_arp_wiring.py` | **196/196** (+14: PC1.x, W2/W9 cập nhật); ổn định 2 lần (~74 s) | [`logs/selftest-arp-wiring.log`](task06b4ir3/logs/selftest-arp-wiring.log) |
| Bộ test mới trên mã **4IR2** | `selftest_l2` 175/177, `selftest_arp` 225/233, wiring 184/196 | `logs/*-new-tests-on-06b4ir2-code.log` |
| `selftest_precheck.py` | **40/40** | [`logs/selftest-precheck.log`](task06b4ir3/logs/selftest-precheck.log) |
| `mutation_l2.py` (đủ, vì `guest_state` đổi) | **78/78** (gồm GS12–GS18 mới) | [`logs/mutation-l2.txt`](task06b4ir3/logs/mutation-l2.txt) |
| `mutation_arp.py --only D5,X1,X2` | D5 bắt đúng PC3.2 + 2 đối chứng | [`logs/mutation-arp-targeted.txt`](task06b4ir3/logs/mutation-arp-targeted.txt) |
| `mutation_arp_wiring.py --only V69–V74,X1,X2` | 6/6 + 2 đối chứng | [`logs/mutation-arp-wiring-targeted.txt`](task06b4ir3/logs/mutation-arp-wiring-targeted.txt) |
| `mutation_precheck.py` | **12/12** + 2 đối chứng | [`logs/mutation-precheck.txt`](task06b4ir3/logs/mutation-precheck.txt) |

- **Lượt mutation đầu**, giữ log `…-run1-…`:
  - D5 bị crash trong section, không tính là bắt; test được sửa để lỗi rơi vào đúng PC3.2.
  - V74 bị bắt ở PC1.1 (đúng hành vi), nên đổi mục tiêu.
  - Trong `mutation_precheck`, P3 bị che bởi kiểm "không rỗng" (thêm O1b), và đoạn root cần `SRC` của bản sao.
- `--only` được thêm vào hai script mutation để chạy có mục tiêu. Không chạy lại toàn bộ mutation ARP/wiring cũ: mẫu cũ vẫn khớp đúng một chỗ (LS1 có hai cặp thay thế, mỗi cặp một chỗ).
- **Không chạy lại** ICMP wiring, `selftest.sh`, `selftest_l2eval`, IPv4/ICMP mutation: `probe_matrix.py`, ICMP, `l2eval` không đổi và không dùng `guest_state`.

## 8. Ảnh hưởng tương thích

- **Bản ghi 06B-4I…4IR2 cũ** (baseline/`restore.after` không có `admin_up`) đánh giá bằng 4IR3 → vấn đề record, exit 2; không bao giờ được coi là restore đã xác nhận. Không có lần chạy guest ARP thật nào bị ảnh hưởng.
- **Snapshot guest** thêm một lệnh đọc `ip link show dev IF` (BusyBox). Dạng header khớp evidence `ip addr` thật của hai image, nhưng **`ip link show` của BusyBox thật chưa được thu**.
- **ICMP/IPv4:** không dùng `guest_state`; run script ICMP và `probe_matrix.py` không đổi.
- **Precheck:** script cũ không còn được đề xuất. Output mới là `reads.json`/`precheck-result.json`, không dùng chung định dạng với script cũ.

## 9. Giới hạn và điều kiện còn lại

- Host samples (`ip -j neigh`, `/proc/net/arp`) **không thay** dữ liệu worker/ctl.
- Precheck 4IR2 **đã đọc trạng thái mạng host**, chưa có probe mạng.
- Carrier/operstate đổi giữa baseline và lần đọc lại là **điều kiện cần quan sát thật**.
- Chính sách dừng nay **khớp** run script 4IR3 (§3).
- **Chưa xác nhận:**
  - raw `ip -j neigh` worker;
  - operstate và admin flags thật của guest, BusyBox `ip link show`;
  - interface/MAC thật của ctl;
  - đối chứng sống; guard 20 ms.

**Trước khi chạy guest:**

1. Reviewer chấp nhận 06B-4IR3.
2. Chốt hash collector; người dùng chạy theo `RUN-PROCEDURE.md`; evaluator cho exit 0.
3. Người điều phối cho phép chạy.

## 10. Hash

- Harness: [`task06b4ir3/harness-sha256.txt`](task06b4ir3/harness-sha256.txt). Script precheck: [`task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt`](task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt) (`collector.py` `6604fbda18cb26f56e6b531c55d0e2bd64209ae1540a989ccc47363d663f1a2d`).
- `SHA256SUMS`: [`task06b4ir3/SHA256SUMS`](task06b4ir3/SHA256SUMS) (`9643b220bc7a842df83f5b6237abdfefb425bfc07952c06703cbadafdbd9d9ef`), [`task06b4ir3-precheck-scripts/SHA256SUMS`](task06b4ir3-precheck-scripts/SHA256SUMS) (`b245774aca8071e997e12988da446d2b899c3f382cac9507ecec6af923513f9c`).
