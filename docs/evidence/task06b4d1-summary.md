# Minh chứng Nhiệm vụ 06B-4D1: bộ đánh giá L2/ARP offline từ file capture (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4D1R):** reviewer tái hiện 2 lỗi đầu vào: `classes=[]` trả PASS với `per_class` rỗng; JSON bộ đếm sai cấu trúc gây crash thay vì ERROR. Phần sửa ở [`task06b4d1r-summary.md`](task06b4d1r-summary.md). Nội dung dưới đây giữ nguyên như lúc bàn giao.

> **Loại bằng chứng: kiểm thử offline.** Phạm vi chỉ gồm đọc pcap/pcapng, đọc JSON bộ đếm, và kiểm bằng dữ liệu tổng hợp hoặc capture đã lưu.
>
> Không tạo hay sửa lệnh probe, không điều khiển guest, không có mã gửi gói. Không Docker, QEMU, sudo hay thay đổi mạng host. Không sửa run script, `probe_matrix.py`, mã cấu hình mạng hay luồng điều khiển guest.
>
> **Đây chỉ là hoàn thiện bộ phân tích offline. T12–T15 chưa được triển khai hay kiểm chứng. CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 1. Bản làm việc

- Bản mới `/home/dathq/projects/ct01-06b4d1/` (ngoài repo) **chỉ thêm** 3 file: `l2eval.py`, `selftest_l2eval.py`, `mutation_l2eval.py`.
- 18 file còn lại giống hệt bản 06B-4BR, đã so từng byte.
- Bản 06B-4BR ở `ct01-06b4b/` không đổi (18/18 hash khớp bàn giao).
- Evidence 06B-4C và output đã lưu `ct01-06b4b/out-06b4c-run1` không đổi (`SHA256SUMS` đạt, `diff -r` giống hệt).
- Diff: [`task06b4d1/ct01-06b4d1-harness-vs-06b4br.diff`](task06b4d1/ct01-06b4d1-harness-vs-06b4br.diff). Hash: [`task06b4d1/harness-sha256.txt`](task06b4d1/harness-sha256.txt).

## 2. `l2eval.py`

```
python3 l2eval.py --pcap tap0.pcapng --counters counters-raw.jsonl --tap-mac MAC \
                  --before LABEL --after LABEL [--classes c1,c2,...] [--out result.json]
```

**Đầu vào:**

- file capture;
- file snapshot bộ đếm, đúng định dạng `counters-raw.jsonl` mà harness ghi: mỗi dòng có `label`, `t_start`, `t_end` và output thô của `nft -j list counters`;
- nhãn hai lần đọc làm biên cửa sổ thời gian;
- `TAP_MAC`;
- tập lớp đối chiếu (mặc định 13 lớp có ánh xạ khung).

**Xử lý:** dùng `l2frames.classified_frames` và `l2frames.reconcile_l2`. Guard là `counter_window.GUARD_S` = 20 ms, **giả định chưa đo** (được ghi trong JSON).

**JSON đầu ra:**

- `input`: đường dẫn, SHA-256 của capture và file bộ đếm, nhãn, lớp, guard;
- `verdict` (PASS, FAIL, UNVERIFIED, ERROR) và `reasons` (lý do kết luận bằng lời);
- `per_class`: số khung chắc chắn, khung biên đầu/cuối, delta, `lo`/`hi`, trạng thái;
- `frames_in_window` (theo chiều/lớp) và `frames_outside_window`;
- `no_counter_frames`: khung không có bộ đếm trong cửa sổ (`arp_not_hooked`, `ip_not_hooked`, `unmapped`, `worker_unexpected`);
- `not_compared`: bộ đếm có trong snapshot nhưng không đối chiếu, kèm delta và lý do (ví dụ `arp_out_drop`, `drop_out` không quan sát được trên `tap0`). Bộ đếm thiếu ở một lần đọc được ghi `delta: null` kèm `missing_in`, **không** thành 0.

**Lỗi không bao giờ thành 0 hay PASS:**

- capture không đọc được (thiếu, rỗng, cắt giữa block, captured > original) → ERROR "capture read error";
- dữ liệu đo không hợp lệ → ERROR "invalid measurement data":
  - nhãn thiếu hoặc trùng;
  - dòng JSON hỏng, output nft không phải JSON;
  - thời gian không hữu hạn;
  - bộ đếm là bool, âm, trùng tên;
  - lần đọc không có bộ đếm nào;
  - bộ đếm thiếu, giảm, thứ tự đọc sai (qua `reconcile_l2`);
- lớp không quan sát được hoặc tên lớp lạ → ERROR.

**Mã thoát:** 0 PASS, 1 FAIL, 4 UNVERIFIED, 2 ERROR. Khi có `--out`, JSON luôn được ghi, kể cả khi ERROR.

## 3. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_l2eval.py --regression <06B-4C>` | **46/46** (39 tổng hợp + 7 phát lại 06B-4C), ổn định 3 lần (JSON phát lại giống hệt) | [`logs/selftest-l2eval.log`](task06b4d1/logs/selftest-l2eval.log) |
| `mutation_l2eval.py` | baseline 39/39; **13/13** đột biến hành vi bị bắt đúng test; 2 đối chứng đúng loại (X1 INVALID, X2 ERROR); hash không đổi | [`logs/mutation-l2eval.txt`](task06b4d1/logs/mutation-l2eval.txt) |
| `selftest_l2.py` (module dùng chung, không đổi) | 195/195 | [`logs/selftest-l2.log`](task06b4d1/logs/selftest-l2.log) |

**Fixture tổng hợp** (tạo trong thư mục tạm, đi qua `evaluate()` thật):

- **PASS:** ARP guest → `arp_in_ok`, ARP worker → `arp_out_ok`, IPv4 → `drop_public`, IPv6 → `l2_bad_ethertype`, một khung ngoài cửa sổ.
- **FAIL:** delta lớn hơn số khung; khung có mà bộ đếm đứng yên.
- **UNVERIFIED:** khung ở biên; khung không có bộ đếm (`unmapped`, `arp_not_hooked`); khung bị cắt bởi snaplen.
- **Lỗi đọc capture:** thiếu, rỗng, cắt giữa block, captured > original, `TAP_MAC` sai.
- **Dữ liệu đo không hợp lệ:** 16 ca. Mỗi ca chạy **bên trong** test của nó, và test kiểm lỗi đến từ chính bước kiểm dữ liệu đo. Lý do: một số lỗi cũng bị lớp sau (`strict_delta`, `validate`) bắt, nên chỉ thấy ERROR là chưa đủ để chứng minh bước đọc snapshot bắt được. Có hai ca chỉ bước đọc snapshot bắt được: bool ở bộ đếm **không** đối chiếu, và bộ đếm trùng tên.
- **CLI:** mã thoát và JSON trong mọi trường hợp.

**Đột biến:**

| Mã | Đột biến |
|---|---|
| V1 | nhận nhãn trùng |
| V2 | bỏ kiểm nhãn thiếu |
| V3 | nhận bool |
| V4 | bỏ kiểm thời gian hữu hạn |
| V5 | nhận lần đọc rỗng |
| V6 | bộ đếm thiếu không đối chiếu thành 0 |
| V7 | nuốt lỗi đọc capture |
| V8 | UNVERIFIED thoát 0 |
| V9 | đếm cả khung ngoài cửa sổ |
| V10 | bỏ lý do khung không bộ đếm |
| V11 | không ghi JSON khi ERROR |
| V12 | lỗi tham số bị gọi là lỗi capture |
| V13 | nhận bộ đếm trùng tên |

Lần chạy mutation đầu tiên có 4 đột biến chưa bắt đúng chỗ (V2–V5). Nguyên nhân nằm ở test chứ không phải mã đánh giá: test chạy ngoài phạm vi từng ca, và chỉ kiểm "ERROR" chung chung. Đã sửa test như mô tả ở trên. Lần chạy cuối là lần trong log.

## 4. Phát lại 06B-4C (chỉ đọc; kết luận đã bàn giao không đổi)

JSON: [`task06b4d1/replay-06b4c/`](task06b4d1/replay-06b4c/).

| | ARM | MIPS |
|---|---|---|
| Cửa sổ phiên, 9 lớp cũ | **PASS**, số khung chắc chắn từng lớp bằng `session.json` | **PASS**, bằng `session.json` |
| Cửa sổ phiên, 13 lớp | **PASS**; `arp_in_ok` 3 = 3, `arp_out_ok` 3 = 3, `allow_out_svc` 10 = 10; `arp_in_drop` 0 | **PASS**; 2 = 2, 2 = 2, 11 = 11 |
| Từng probe, 9 lớp | kết luận đối chiếu bằng `matrix.json` ở cả 10 probe | bằng `matrix.json` (`lan-dns-udp` vẫn UNVERIFIED) |

**Ghi chú:**

- Bảng trên là kết luận **đối chiếu bộ đếm**, không phải kết luận probe.
- Hai probe `lan-dns-tcp` có đối chiếu PASS, nhưng kết luận probe đã bàn giao vẫn là **CHƯA KIỂM CHỨNG (không có đối chứng sống)**. Công cụ này không đổi và không thay kết luận đó.
- ARP ở đây là lưu lượng hợp lệ có sẵn, **không** phải probe ARP chủ động.

## 5. Hạn chế

- **Chưa triển khai T12–T15.** Không có probe chủ động nào; các lớp `arp_in_drop`, `l2_bad_mac`, `arp_not_hooked` mới chỉ có khung tổng hợp, chưa có khung thật.
- Giả định [Kernel] trong `l2frames.py` (`arp_rcv`, `ip_rcv`, điểm bắt) vẫn chưa kiểm thực tế.
- `l2eval.py` chưa được nối vào run script hay `probe_matrix.py` (ngoài phạm vi). Đối chiếu từng probe cũ vẫn dùng `get(k, 0)`.
- Guard 20 ms là giả định chưa đo. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 6. Hash

[`task06b4d1/SHA256SUMS`](task06b4d1/SHA256SUMS) (`b5709988e5c85109906da0f3e3409c0c090bd042d2f3706e134ec8a978ad0f4c`) liệt kê mọi file trong `task06b4d1/`.
