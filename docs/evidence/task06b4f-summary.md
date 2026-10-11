# Minh chứng Nhiệm vụ 06B-4F: nối 5 ca ICMP đã review vào harness, chỉ kiểm offline (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4FR):** đã review độc lập, **còn 2 lỗi, chưa chấp nhận tích hợp**. P1: cảnh báo rò rỉ chỉ được kiểm sau lệnh guest, nên cảnh báo xuất hiện lúc đọc bộ đếm A của ca kế tiếp không chặn được ping của ca đó. P2: `arch_outcome` không yêu cầu các xác nhận hạ tầng bắt buộc có mặt (thiếu "QEMU exit confirmed", cleanup… vẫn PASS). Phần sửa ở [`task06b4fr-summary.md`](task06b4fr-summary.md). Nội dung dưới đây giữ nguyên như lúc bàn giao.

> **Loại bằng chứng: kiểm thử offline.**
>
> - **Harness mới chưa chạy tích hợp.** Không Docker, QEMU, gửi gói, sudo, malware; không thay đổi mạng host, source cô lập, địa chỉ, ruleset hay guard.
> - T12–T13 **vẫn chưa chạy trên guest nào**. Bàn giao để review trước lần chạy thật.
> - Guard 20 ms vẫn là giả định chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

**Mốc:** records tree `9aaa8cadfd039d7e16b9df6b3cddb7f1241e1bd5` (06B-4ER, reviewer chấp nhận offline).

**Phạm vi:** nối `run_group`/`evaluate_group` của `icmp_cases.py` (06B-4ER, không sửa) vào luồng harness cho đúng 5 ca: T12-B1, T12-B2, T12-B4, T13-I1, T13-I2; ARM rồi MIPS, tuần tự.

**Không làm:**

- thêm ca;
- chạy lại 20 probe IPv4 cũ;
- sửa `icmp_cases.py`, `l2frames.py`, `l2eval.py`, `counter_window.py`, `signatures.py`;
- sửa `run-06b3b.sh` (vẫn là harness IPv4 06B-4B/4C).

## 1. Bản làm việc

- Bản mới `/home/dathq/projects/ct01-06b4f/`, chép từ `ct01-06b4e` (06B-4ER).
- Các bản đã bàn giao không đổi: `ct01-06b4e` (06B-4ER), `ct01-06b4d1`, `ct01-06b4b`, `ct01-06b3c`.
- Diff: [`task06b4f/ct01-06b4f-harness-vs-06b4e.diff`](task06b4f/ct01-06b4f-harness-vs-06b4e.diff). Hash 28 file: [`task06b4f/harness-sha256.txt`](task06b4f/harness-sha256.txt).

| File | Thay đổi |
|---|---|
| `icmp_harness.py` | **mới:** lớp nối (chạy nhóm, kiểm đủ ca, đánh giá, kết luận theo kiến trúc và cả lần chạy) |
| `probe_matrix.py` | thêm nhánh `CT01_SUITE=icmp`; mặc định (`ipv4`) giữ nguyên hành vi |
| `run-06b4f.sh` | **mới:** chép từ `run-06b3b.sh`, chỉ đổi phần nối ICMP (§3) |
| `selftest_icmp_wiring.py` | **mới:** kiểm offline phần nối bằng container và guest giả |
| `mutation_icmp_wiring.py` | **mới:** mutation cho phần nối |

## 2. Luồng trong worker (`probe_matrix.py`, `CT01_SUITE=icmp`)

**Dùng lại nguyên các bước đã review:**

- giải nén image, fixture, `verify_isolation` trước boot;
- tshark trên `tap0`, `captures_alive` (marker, heartbeat), đo toàn phiên (`session.json`);
- boot QEMU qua `Analysis._start_qemu`, cổng topology;
- `counters_read` (ghi `counters-raw.jsonl`);
- tắt QEMU, thống kê drop pcapng, cleanup fixture/marker/đĩa tạm.

**Khác nhánh IPv4:**

- không mở listener 18080 (chỉ là đích của ma trận IPv4);
- không chạy 20 probe IPv4.

**Nhóm ICMP (`run_icmp`):**

1. Đọc MAC `tap0` từ `/sys/class/net/tap0/address` (chỉ đọc). Dùng để dựng T13-I2 và phân lớp khung.
2. **Lưu lượng kiểm capture từ worker** (DNS tới LAN gateway, HTTP tới manager), trước và sau nhóm:
   - cùng các lời gọi mà ma trận IPv4 dùng làm đối chứng cục bộ;
   - cần để các kiểm tra dương của host (veth, ens33, `control_qname`) không mù;
   - **không** phải đối chứng cho các đích ICMP.
3. `icmp_harness.run_suite` gọi `icmp_cases.run_group` với 5 ca từ `build_cases(TAP_MAC)`: liên kết trước → mỗi ca đọc A / ping / đọc B → liên kết sau.
4. **Mọi lệnh guest** (cả hai liên kết và 5 ping) đi qua `GuardedRunner`:
   - **trước** lệnh: `captures_alive`;
   - **sau** lệnh: file cảnh báo rò rỉ, rồi `captures_alive`.
   - Lỗi đầu tiên dừng nhóm: các lệnh sau **không tới guest**. Lỗi được ném lại sau `run_group`, nên `LeakDetected` (exit 99) và `CaptureLost` (exit 98) xử lý như cũ.
   - Cần lớp này vì `run_group` ghi mọi ngoại lệ thành lỗi thực thi và không bao giờ ném.
5. Ghi `icmp-group.json`; kiểm MAC `tap0` không đổi; kiểm đã chạy đủ 5 ca.

**Liên kết guest–worker (yêu cầu 4):**

- Lệnh: `rm -f /tmp/r.out; curl … -w 'HTTP=%{http_code}' …/get-task/T/file; sha256sum /tmp/r.out`.
  - Thêm `rm -f` so với bản IPv4: nếu curl lỗi, file phản hồi cũ không thể cho hash đúng.
- Chỉ đạt khi có đúng một dòng `HTTP=200`, đúng một hash của `/tmp/r.out`, hash bằng hash fixture, và rc 0.
- Mã HTTP và hash được ghi vào record.
- Vai trò ghi trong record: điều kiện tiền đề, **không phải đối chứng sống** cho đích ICMP. Kết quả vẫn chỉ là "ĐẠT (kiểm quy tắc)", `evidence_kind` = `rule_check`.

**Đánh giá (`evaluate_icmp`):**

- `icmp_harness.evaluate` gọi `icmp_cases.evaluate_group` (06B-4ER) trên `tap0.pcapng` và `counters-raw.jsonl`, ghi `icmp-eval.json`.
- Thêm `check_record`, có vấn đề thì **không bao giờ kết luận nhóm đạt**:
  - mỗi ca trong 5 ca **đúng một lần**; không thiếu, trùng hay lạ;
  - nhãn đọc bộ đếm và lệnh đúng như bản đã review;
  - kiến trúc, TAP MAC và hash fixture khớp;
  - liên kết trước **và** sau: HTTP 200 + hash fixture;
  - nhóm không bị dừng hay bỏ qua.
- Mỗi ca thành một bản ghi `probe <id> (icmp, rule check) -> <kết quả>`. Như vậy `counter_window.run_outcome` (đã review) xử lý đúng:
  - CHƯA KIỂM CHỨNG (gồm lỗi thực thi, không tạo được gói) là chưa quyết định;
  - FAIL hoặc LỖI PHÉP ĐO là lỗi cứng.

## 3. Run script `run-06b4f.sh` (chưa chạy)

So với `run-06b3b.sh`, test W7 kiểm rằng chỉ 4 chỗ bị thay; mọi phần khác chỉ được thêm vào:

| Thay đổi | Nội dung |
|---|---|
| `H` | `/home/dathq/projects/ct01-06b4f` |
| Bản sao harness | thêm các file ICMP vào `harness-copy` |
| Self-test | `selftest_icmp.py` và `selftest_icmp_wiring.py` phải đạt trước mọi lệnh docker; lỗi thì exit 3 |
| Mount chỉ đọc | `icmp_harness.py`, `icmp_cases.py`, `l2frames.py`, `l2eval.py`, `signatures.py` vào `/harness` |
| Lời gọi worker | `docker exec … -e CT01_SUITE=icmp …` (lời gọi `probe_matrix.py` duy nhất) |
| Kết luận mỗi kiến trúc | `icmp_harness.py --outcome` (§4) |
| Kết luận cả lần chạy | `icmp_harness.py --run-check …/probe ARM MIPS`: cả hai kiến trúc có đánh giá, mỗi ca đúng một lần |

Giữ nguyên:

- capture veth/bridge/ens33, watcher và heartbeat, hai cảnh báo rò rỉ;
- `sigscan.sh`, `sigscan_l2.py` (đã có chữ ký kích thước ICMP T12/T13), kiểm tra dương;
- dừng capture có hạn chót, thống kê tcpdump;
- netns trước/sau, ruleset chuẩn hóa, xóa container, khôi phục manager, không còn QEMU/capture, trạng thái host trước/sau;
- mã thoát 0/1/4/5.

Lệnh dự kiến khi reviewer cho phép (**chưa chạy**, người dùng tự chạy):

```
sudo bash /home/dathq/projects/ct01-06b4f/run-06b4f.sh
```

## 4. Kết luận (yêu cầu 5–7)

**Một kiến trúc** (`arch_outcome`) chỉ PASS khi **tất cả** điều sau đúng:

- `counter_window.run_outcome` trên **mọi** bản ghi là PASS. Bản ghi gồm cả hạ tầng: capture/heartbeat, QEMU thoát, thống kê drop `tap0`, cleanup, liên kết, lưu lượng kiểm capture, MAC `tap0`;
- `status` là `COMPLETED`;
- `icmp-eval.json` đúng kiến trúc, đủ 5 ca mỗi ca đúng một lần, không có vấn đề record;
- mỗi ca xuất hiện đúng một lần trong `result.json`.

Thiếu một điều thì FAIL. Chỉ có ca CHƯA KIỂM CHỨNG thì UNVERIFIED.

**Cả lần chạy:** cộng thêm các kiểm tra của run script (cảnh báo rò rỉ, bộ quét host, trạng thái host…) và `--run-check`. **ĐẠT của một ca không che lỗi hạ tầng:** test S26 và S34 có cả 5 ca ĐẠT nhưng kết luận vẫn FAIL.

**Phân loại không đổi:**

- nhãn "ĐẠT (kiểm quy tắc)";
- timeout hay không tạo được gói → CHƯA KIỂM CHỨNG, **không phải bằng chứng chặn**;
- LỖI PHÉP ĐO → lỗi cứng (giống 06B-3DR).

## 5. Kiểm thử offline

`selftest_icmp_wiring.py` chạy **`probe_matrix.main()` thật** ở chế độ ICMP, mỗi kịch bản trong một tiến trình riêng:

- worker được thay bằng module giả: `isolation`, `service.analysis`;
- guest console, `nft`, tshark và file capture/cảnh báo/heartbeat của host đều là giả;
- tiến trình **chỉ import được các file mà `run-06b4f.sh` mount** (thiếu mount thì hỏng: S9, W5);
- guest giả phát khung đúng như `selftest_icmp` và tăng bộ đếm theo `l2frames.classify`. Không có gói thật nào.

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_icmp_wiring.py` | **92/92**; ổn định 6 lần liên tiếp + 24 lần chạy song song kịch bản sạch | [`logs/selftest-icmp-wiring.log`](task06b4f/logs/selftest-icmp-wiring.log), [`logs/selftest-icmp-wiring-stability.txt`](task06b4f/logs/selftest-icmp-wiring-stability.txt) |
| `mutation_icmp_wiring.py` | **26/26** đột biến hành vi bị bắt đúng test + 2 đối chứng đúng loại; hash harness không đổi | [`logs/mutation-icmp-wiring.txt`](task06b4f/logs/mutation-icmp-wiring.txt) |
| `selftest.sh` (do sửa `probe_matrix.py`; mục H import `probe_matrix` ở chế độ IPv4 mặc định) | 205 PASS, "ALL PASSED" (bằng 06B-3FR1) | [`logs/selftest-sh.log`](task06b4f/logs/selftest-sh.log) |
| `mutation_test.sh` (đột biến cũ trên `probe_matrix.py` và helper) | 78/78 đột biến đúng loại, "every mutation got its expected class" (bằng 06B-3FR1) | [`logs/mutation-test-sh.log`](task06b4f/logs/mutation-test-sh.log) |
| `selftest_icmp.py` (run script chạy trước khi bắt đầu; `icmp_cases.py` không đổi) | 79/79 | [`logs/selftest-icmp.log`](task06b4f/logs/selftest-icmp.log) |

Không chạy lại `selftest_l2`/`selftest_l2eval` và các mutation tương ứng: `l2frames.py`, `l2eval.py`, `signatures.py` không đổi.

**Kịch bản qua `probe_matrix.main()`** (mỗi kịch bản cũng qua `icmp_harness --outcome` và khối `case` thật của run script):

| Nhóm | Kịch bản → kết quả |
|---|---|
| Đủ ca | sạch → exit 0, PASS; đúng thứ tự lệnh (liên kết, 5 ping, liên kết); không có probe IPv4 hay listener (S1–S9) |
| Thiếu/trùng ca | danh sách ca bị thiếu 1 hoặc trùng 1 → FAIL kèm vấn đề record, dù các ca chạy đều ĐẠT (S10, S11) |
| Lỗi capture | marker sau T12-B4; heartbeat cũ sau T12-B1; tshark thoát sau T13-I1; capture chết **giữa hai ca** (bị bắt trước ping kế tiếp) → exit 98, không lệnh nào tới guest sau đó, không đánh giá, QEMU vẫn tắt và cleanup vẫn chạy (S12–S15, S33) |
| Rò rỉ | cảnh báo sau T12-B2 → exit 99, dừng ngay (S16) |
| Lỗi thực thi | `ping6` không có (rc 127) → T13 LỖI THỰC THI, T12 vẫn ĐẠT, kết luận UNVERIFIED; timeout console → LỖI THỰC THI, các ca sau vẫn chạy; không tạo được gói → KHÔNG TẠO ĐƯỢC GÓI (S17–S20) |
| Phép đo | lỗi đọc bộ đếm → LỖI PHÉP ĐO → FAIL; bộ đếm không tăng → FAIL; khung tới guest → FAIL; capture không đọc được → mọi ca LỖI PHÉP ĐO (S21–S23, S27) |
| Liên kết | trước HTTP 000 → không ping nào, FAIL; sau sai hash hoặc HTTP 000 dù hash đúng (file cũ) → không ca nào ĐẠT, FAIL (S24, S25) |
| Hạ tầng / cleanup | drop trên `tap0`; QEMU không thoát; marker còn sau cleanup; lưu lượng kiểm capture lỗi → 5 ca ĐẠT nhưng FAIL (S26, S28, S34) |
| Mức lần chạy | thiếu MIPS → `--run-check` exit 1; sai kiến trúc → FAIL (S29–S32) |

**Unit (U1–U38):**

- phân tích liên kết (HTTP 000 với hash đúng, hash sai, thiếu hash, hai dòng HTTP, rc ≠ 0, `HTTP=2000`, CRLF);
- `GuardedRunner`;
- `check_record`: thiếu, trùng, lạ, sai lệnh, sai nhãn, sai hash liên kết, kiểu sai, bị dừng;
- `arch_outcome`: mọi điều kiện ở §4;
- `run_check` và CLI.

**Run script (W1–W8):**

- `bash -n`;
- `H`;
- một lời gọi duy nhất có `CT01_SUITE=icmp`;
- self-test chạy trước docker và lỗi thì dừng;
- đủ mount;
- `--outcome` và `--run-check`;
- chỉ 4 chỗ thay so với `run-06b3b.sh`;
- `run-06b3b.sh` giữ nguyên hash.

**Đột biến (W1–W27, bỏ số W15):**

| Phạm vi | Đột biến |
|---|---|
| Liên kết | bỏ kiểm HTTP; bỏ kiểm hash; bỏ `rm -f` |
| Lớp chặn lệnh | không chặn lệnh sau khi dừng; không giữ lỗi kiểm-sau |
| Kiểm record | bỏ kiểm thiếu; bỏ kiểm trùng; bỏ kiểm liên kết |
| Kết luận | bỏ kiểm status; bỏ kiểm số bản ghi ca; bỏ lỗi cứng; bỏ kiểm kiến trúc |
| `run_check` | bỏ kiểm file thiếu |
| Tên bản ghi | không bắt đầu bằng "probe " |
| `probe_matrix.py` | không ném lại lỗi dừng; bỏ kiểm cảnh báo; bỏ kiểm trước lệnh; gọi `evaluate()` IPv4; bỏ kiểm lưu lượng capture; mở listener; sai TAP MAC; bỏ bản ghi vấn đề record |
| Run script | bỏ `CT01_SUITE`; bỏ mount `l2eval.py`; ánh xạ UNVERIFIED thành PASS; bỏ self-test wiring |

## 6. Hạn chế

- **Chưa chạy tích hợp;** chưa có guest, gói hay bộ đếm thật. Toàn bộ bằng chứng là offline với thành phần giả.
- Guest giả không mô phỏng lưu lượng nền thật khi ping6 (MLD, DAD). Bộ đánh giá 06B-4ER đã kiểm các khung này ở mức offline.
- Hành vi `ping`/`ping6` của BusyBox với broadcast/multicast vẫn là giả định (có thể "không tạo được gói").
- Guard 20 ms chưa đo.
- `run-06b4f.sh` không được chạy trong test, kể cả với docker giả. Chỉ kiểm cú pháp, kiểm tĩnh, khối ánh xạ kết luận (chạy bằng bash), so khác biệt với `run-06b3b.sh`, và các lệnh Python mà nó gọi.
- Lưu lượng kiểm capture (DNS tới `192.168.177.2`, HTTP tới manager) là lưu lượng của worker, như các đối chứng cục bộ của ma trận IPv4. Nếu nó lỗi thì lần chạy FAIL.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 7. Hash

- [`harness-sha256.txt`](task06b4f/harness-sha256.txt): 28 file của bản làm việc.
- Mọi file trong `task06b4f/`: [`SHA256SUMS`](task06b4f/SHA256SUMS) (`52dbe9d6dab27b06e906adf6a7dcc53767c9991cb00dff2cfb3252702370219e`).
