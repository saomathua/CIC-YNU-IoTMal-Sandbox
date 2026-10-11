# Minh chứng Nhiệm vụ 06B-4D1R: sửa hai lỗi đầu vào của bộ đánh giá L2/ARP offline (08/10/2026)

> **Loại bằng chứng: kiểm thử offline.**
>
> - Chỉ sửa bộ phân tích offline `l2eval.py` và kiểm thử của nó.
> - 18 file harness cũ (gồm run script, `probe_matrix.py`) và evidence cũ giữ nguyên.
> - Không Docker, QEMU, probe mạng, sudo hay điều khiển guest.
>
> **Chưa triển khai T12–T15. CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

**Lỗi reviewer tái hiện trên 06B-4D1:**

1. `evaluate(..., classes=[])` trả **PASS** với `per_class` rỗng, tức không có gì được đối chiếu mà vẫn đạt.
2. JSON bộ đếm sai cấu trúc làm chương trình crash thay vì trả ERROR:
   - `{"nftables":[{"counter":null}]}` → `AttributeError`;
   - `{"nftables":null}` → `TypeError`;
   - `{"nftables":[{"counter":[]}]}` → `AttributeError`.

## 1. Tái hiện trước/sau

Log: [`logs/repro-before-after.txt`](task06b4d1r/logs/repro-before-after.txt); script: [`repro.py`](task06b4d1r/repro.py).

| Đầu vào | 06B-4D1 | 06B-4D1R |
|---|---|---|
| `classes=[]` | **PASS**, `per_class` rỗng | ERROR "invalid argument: empty list of classes: nothing would be compared" |
| `{"nftables":[{"counter":null}]}` | **AttributeError** | ERROR "invalid measurement data: …:2: nftables[0].counter is NoneType, expected an object" |
| `{"nftables":null}` | **TypeError** | ERROR "…: 'nftables' is NoneType, expected a list" |
| `{"nftables":[{"counter":[]}]}` | **AttributeError** | ERROR "…: nftables[0].counter is list, expected an object" |

Các test mới chạy trên bộ phân tích 06B-4D1: 21 test fail và section J crash. Trên 06B-4D1R: 65/65 đạt.

## 2. Bản sửa

Bản làm việc: `/home/dathq/projects/ct01-06b4d1/` (bản 06B-4D1 giữ trong `ct01-06b4d1/base-06b4d1/`). Diff: [`ct01-06b4d1r-analyzer-vs-06b4d1.diff`](task06b4d1r/ct01-06b4d1r-analyzer-vs-06b4d1.diff).

**Danh sách lớp (`check_classes`):**

- `None` nghĩa là dùng mọi lớp có ánh xạ khung.
- Ngoài ra, danh sách phải **khác rỗng**, gồm tên **không trùng**, là **chuỗi** và thuộc các lớp có ánh xạ khung. Tập con hợp lệ vẫn được chấp nhận.
- Vi phạm → ERROR "invalid argument: …" **trước khi đọc bất kỳ file nào**; JSON vẫn được ghi.
- **CLI không còn lọc âm thầm:** `--classes ""` thành `[]`, `"a,,b"` thành `["a", "", "b"]`; cả hai bị từ chối, exit 2.

**Cấu trúc JSON (`load_reads`)** kiểm kiểu ở từng cấp trước khi dùng:

1. dòng là JSON object;
2. đủ các trường `label`, `t_start`, `t_end`, `raw`;
3. `raw` là chuỗi, và là JSON hợp lệ;
4. output nft là object có khóa `nftables`;
5. `nftables` là list;
6. mỗi phần tử là object;
7. `counter` là object có `name` (chuỗi khác rỗng) và `packets`, như trước.

- Sai ở bất kỳ cấp nào → `InputError` → ERROR "invalid measurement data: <file>:<dòng>: <lý do>".
- Phần tử không phải counter (ví dụ `metainfo`) vẫn được bỏ qua như trước. Phần tử **sai kiểu** thì **không** bị bỏ qua.
- Dữ liệu thiếu không bao giờ thay bằng 0.

## 3. Kiểm thử

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest_l2eval.py --regression <06B-4C>` | **72/72** (65 offline + 7 phát lại), ổn định 3 lần | [`logs/selftest-l2eval.log`](task06b4d1r/logs/selftest-l2eval.log) |
| JSON phát lại 06B-4C | giống hệt bản 06B-4D1 ([`task06b4d1/replay-06b4c/`](task06b4d1/replay-06b4c/)): kết luận đối chiếu không đổi | — |
| `mutation_l2eval.py` | baseline 65/65; **26/26** đột biến hành vi bị bắt đúng test (13 cũ + 13 mới W1–W13); 2 đối chứng đúng loại; hash không đổi | [`logs/mutation-l2eval.txt`](task06b4d1r/logs/mutation-l2eval.txt) |
| `selftest_l2.py --offline-only` (module dùng chung, không đổi) | 175/175 | [`logs/selftest-l2.log`](task06b4d1r/logs/selftest-l2.log) |

**Test mới, gọi `evaluate()` và CLI thật:**

- **N1–N7 (danh sách lớp):** rỗng; trùng; tên rỗng; lớp không quan sát được; chuỗi thay cho list; tên không phải chuỗi; tập con hợp lệ (tuple) vẫn PASS.
- **C6–C9 (CLI):** `--classes ""`, `"a,,b"`, trùng → exit 2 kèm JSON có lý do; tập con hợp lệ → exit 0.
- **J1–J12 (cấu trúc JSON):**
  - ba ca của reviewer;
  - output nft là list; thiếu `nftables`;
  - phần tử không phải object nằm **giữa các counter hợp lệ** (không được bỏ qua);
  - counter thiếu `packets`; tên không phải chuỗi; tên rỗng;
  - dòng là list; thiếu `raw`; `raw` là object.
  - Ba ca của reviewer chạy thêm qua CLI: exit 2, JSON có lý do.

**Đột biến mới:**

| Mã | Đột biến |
|---|---|
| W1 | cho phép danh sách rỗng |
| W2 | cho phép trùng |
| W3 | bỏ kiểm tên lớp |
| W4 | nhận chuỗi |
| W5 | CLI lọc âm thầm |
| W6 | bỏ kiểm counter là object |
| W7 | bỏ kiểm `nftables` là list |
| W8 | bỏ qua phần tử sai kiểu |
| W9 | bỏ kiểm thiếu `packets` |
| W10 | bỏ kiểm `raw` là chuỗi |
| W11 | bỏ kiểm output nft là object |
| W12 | bỏ kiểm dòng là object |
| W13 | nhận tên rỗng |

## 4. Hash

- [`harness-sha256.txt`](task06b4d1r/harness-sha256.txt): 18 file cũ không đổi so với 06B-4BR; 3 file phân tích đã sửa.
- Mọi file trong `task06b4d1r/`: [`SHA256SUMS`](task06b4d1r/SHA256SUMS) (`e3056cda53d5b02c059d1b7e0ce70003132e92049486aaadb2494bb27a63b696`).

## 5. Hạn chế

- Không đổi so với [`task06b4d1-summary.md`](task06b4d1-summary.md) §5: chưa triển khai T12–T15; `l2eval.py` chưa nối vào run script; giả định [Kernel] chưa kiểm thực tế; guard 20 ms chưa đo.
- **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**
