# CT-02 / CT-03 — bản ghi nghiệm thu và đóng (2026-10-11)

Tài liệu này ghi **điều reviewer đã chấp nhận** và **phạm vi đã đo**. Dữ liệu thô nằm trong gói bàn giao
(`ct01-r6-run2-package.zip`), không đưa vào Git; chỉ mục băm: [`RUN-EVIDENCE-INDEX.json`](RUN-EVIDENCE-INDEX.json).

## 1. Quyết định của reviewer
Nguồn: văn bản reviewer do người dùng chuyển lại (chưa có biên bản reviewer riêng được băm):

> Reviewer đã kiểm gói ct01-r6-run2-package.zip (SHA-256 `36dfb0e3…c0701`). 834/834 hash khớp, stage/export giống nhau,
> replay cả năm evaluator rc 0. Chấp nhận CT-02 ARM/MIPS và CT-03 ĐẠT theo phạm vi runtime đã đo. Giữ đầy đủ giới hạn;
> không claim sạch toàn rootfs, unsafe restart đã đo, hoặc toàn bộ CT-01 được chuyển sang image mới.

## 2. Định danh bị ràng buộc
| Mục | Giá trị |
|---|---|
| Image đã đo | `sandbox-worker:ct0203-r4-96db2b433725` = `sha256:24569c9f1a1d058101997864c6cb4897cdb71d4357d89f4ab050e97ca61ef943` |
| Image CT-01 / `latest` | `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153` — **không đổi**; image mới **chưa** được triển khai vào Compose |
| Build context | manifest `96db2b433725397a1ea30ab8c6115319440050aaed482e883fb62e3dfbc0c094` (38 tệp); khác `main` đúng hai tệp sản phẩm |
| Hai tệp sản phẩm | `sandbox-worker/poller.py` sha256 `56b06cea…ee4`; `sandbox-worker/service/analysis.py` sha256 `0bf85625…0000` (đầy đủ trong index) |
| Base | `ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401`; build `--pull=false` sau một lần pull; NO-DRIFT chỉ đúng cho image đã build |
| Manifest flow (hồi quy) | `67429cef77e2717509d10feb53811683de806a730885380a718dc368c19ab65e` |
| Manifest runtime CT-02/CT-03 | `28b2990f44c76329f692be73331ebce3e99611961036ddcf390abd96394e53ea` |
| Câu duyệt chạy | `APPROVAL-2-VERBATIM.txt` sha256 `83f74633…52a2` (nguyên văn người dùng) |

## 3. Kết quả từng lượt (mỗi lượt đúng một lần, không retry)
| # | Lượt | Run ID | Evaluator | lane/eval/signal | Export manifest sha256 |
|---|---|---|---|---|---|
| 1 | flow success ARM+MIPS (hồi quy) | `20261011T134429Z` | ALL CRITERIA HELD, 63 PASS / 0 FAIL | 0/0/0 | `1dbd7d2b…c77e6c` |
| 2 | flow f4 (hồi quy) | `20261011T134834Z` | ALL CRITERIA HELD, 41 PASS / 0 FAIL | 0/0/0 | `1f6ee491…1353d6` |
| 3 | **CT-03** | `20261011T135015Z` | **HELD**, 26 hàng | 0/0/0 | `22d89f7f…dd11a4` |
| 4 | **CT-02 ARM** | `20261011T135717Z` | **CLEAN**, 21 hàng | 0/0/0 | `e7452f00…fa8c51` |
| 5 | **CT-02 MIPS** | `20261011T140045Z` | **CLEAN**, 21 hàng | 0/0/0 | `6ef3710a…988b65` |

Mọi lượt: precheck riêng, bản ghi quyết định riêng, cleanup xác nhận theo ID, export kiểm hash. Host cuối: chỉ manager + mongo,
không QEMU, queue rỗng.

## 4. Điều được chứng minh (trong phạm vi đo)
- **CT-02 (ARM, MIPS):** ELF fixture lành tính chạy trên guest thật; tác vụ A tạo marker 12 byte; tác vụ B **không thấy** marker;
  hash `*/image.zip` trước = sau = pin; `data_dir` `/app/data/` không còn thư mục A/B.
- **CT-03:** tác vụ bị hủy (cancel) sau khi phase 1 được quan sát trong worker (qemu-system + tshark + `current_task`):
  trạng thái CANCELLED, log `was cancelled`, worker không thoát, không còn tiến trình QEMU/tshark của tác vụ, tác vụ kế tiếp
  chạy được (COMPLETED).
- **Hồi quy flow (image mới):** success ARM+MIPS và f4 đạt; checkpoint phase 2 chứng minh QEMU phase 2 **đang chạy**.

## 5. Giới hạn giữ nguyên (không claim)
- CT-02 chỉ đo marker, hash `image.zip` và `data_dir`; **không** claim sạch toàn rootfs guest, `/tmp`, exec/strace/sar trên đĩa guest.
  Mỗi lượt một kiến trúc, một fixture.
- CT-03: các nhánh không an toàn (capture/QEMU không chết, PermissionError, manager 5xx) chỉ có bằng chứng offline;
  **restart policy thực của Compose chưa đo** (lane chạy `--restart no`).
- Chưa chuyển acceptance CT-01 sang image mới; kết luận CT-01 vẫn gắn với image `1ab784c7…8153`. Hồi quy flow ở đây là
  bằng chứng riêng của image mới, không phải acceptance CT-01 lại.
- Flow checkpoint không phải bằng chứng timing hay "trong lúc upload"; ELF là busybox, không phải mã độc; guard 20 ms không đo.
- Lượt flow success đầu tiên trên image này (R5, `20261011T125521Z`) **chưa đạt** do evaluator (không phải rò mạng); giữ làm lịch sử,
  sửa ở flow R6 rồi chạy lại bằng approval mới.

## 6. Việc chưa làm
Triển khai image mới vào Compose / đổi `latest`; CT-04 trở đi.
