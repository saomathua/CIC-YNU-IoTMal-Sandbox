# CT-01 flow lane R4 — T01/T02-runtime, T18, T19 (success), F3/F4 (fault) và F5 (restart Compose)

**R4 = R3 + sửa export (review 2026-10-11, X1/X2).** `export_run.py` kiểm từng hash của MANIFEST-SHA256 với tệp thật ở stage **và** bản copy (đọc có bao stat), manifest hợp lệ (không dòng trống/trùng/tuyệt đối/`..`, đúng tập tệp, MANIFEST-SYMLINKS khớp link thật); ghi receipt (stage + sidecar + chown) là một phần của export: lỗi ⇒ `RECEIPT WRITE FAILED` trên stderr, không bao giờ in `EXPORT VERIFIED`, rc 4; thứ tự ưu tiên exit giữ nguyên. Kiểm hẹp: `tests/test_export_r4.py` 13/13 (+ `tests/test_flow.py` chạy lại cho phần export). Tiêu chí F5/A14 như R3: danh tính sandbox Docker + trạng thái nguyên sơ của lần start thứ hai; **inode `/proc/<pid>/ns/net` chỉ để tham khảo, bằng nhau không chứng minh cùng namespace** (số inode được tái sử dụng). Không đánh giá lại evidence R3/R2 bằng cây này.

R2 sửa các lỗi review độc lập 2026-10-11 (F1/F2 + identity/sampler); R1 giữ nguyên, bằng chứng R1 không đánh giá lại bằng evaluator này (identity /1 ⇒ hàng "identity pins" FAIL, đúng thiết kế). Success #3, F3 và F4 đã được reviewer chấp nhận: **không chạy lại**; R2 chỉ dùng cho F5 (và T21b) trừ khi có quyết định mới.

## Thay đổi so với R1
| Mục | R1 | R2 |
|---|---|---|
| F1 phép đo | so stdout trước/sau, bỏ qua rc: hai lần đọc nft rc 1 vẫn 39/39 | mọi phép đo bắt buộc có rc cho phép + schema tối thiểu (`judge`): nft có `table`, route có `dev`, addr có `inet`, sysctl 0/1, docker ps ≥3 trường, image id sha256. `pgrep` rc 1 + stdout/stderr rỗng là **"absent" hợp lệ duy nhất** (chỉ pgrep). Thiếu `.rc` ⇒ FAIL, không PASS. So sánh before/after chỉ tính khi cả hai đọc hợp lệ |
| F2 export | `make_entry.py` `set +e`, lỗi copy/chown/verify vẫn exit 0 | `export_run.py`: manifest → copy (giữ symlink) → chown (lchown) → verify (tập tệp, hash, đích symlink) → receipt (`export-receipt.json` trong stage và cạnh bản copy). Exit cuối (`lane_entry.sh`): **tín hiệu (128+n) > lane rc > evaluator rc > export không verified (4) > 0**; finalize đúng một lần; stage luôn giữ |
| Identity | image/mode/label | thêm hash manifest/runner/evaluator/pins/export/entry của stage + literal manifest của lệnh root; evaluator kiểm chúng bằng đúng các tệp đang đánh giá và các dòng manifest |
| Sampler verifier | rc + chữ "ISOLATION OK" | mỗi mẫu `verify-<arch>-<tag>.json`: dòng log kích hoạt, t_start/t_end, trạng thái task (manager) và `pgrep -a qemu-system` TRONG worker ngay trước và sau; evaluator đòi PROCESSING cả hai đầu, cùng tập PID QEMU, task id đúng. Vẫn là "checkpoint", **không** chứng minh guard 20 ms/đồng thời chính xác |

## Mode f5 (design F5/A14: `docker compose restart sandbox-worker-1`)
Lane tạo worker bằng **Compose thật** `up -d --no-deps --no-build --pull never sandbox-worker-1` (project `cic-ynu-iotmal-sandbox`, file compose của repo; container `cic-ynu-iotmal-sandbox-sandbox-worker-1-1`, IP 192.168.60.2; dry-run xác nhận chỉ tạo container này, manager/Mongo không được nhắc tới). Không restart bằng nhãn kế thừa của `ct01-flow-worker`: ID thật lấy từ truy vấn nhãn project+service (đúng 1 container) và dùng cho mọi lệnh sau.
Trước: gate như R1 (+ không container project/service nào tồn tại); manager/Mongo inspect (id, StartedAt, running). V0 OK; trạng thái "before": StartedAt, PID, **netns** (`/proc/<pid>/ns/net`), bảng `inet sandbox_guest`, `tap0`, verifier, healthcheck manager→worker. `compose restart -t 10`. Sau: V0 OK lần 2 (log cộng dồn), cùng container id, StartedAt muộn hơn, PID khác, **netns inode khác (A14)**, bảng + tap0 + verifier + health. Manager/Mongo: cùng id/StartedAt/running. Dọn: đọc lại nhãn của đúng ID rồi `docker rm -f <ID>` (không `compose down`, không theo mẫu tên); truy vấn nhãn sau đó rỗng.
Không submit tác vụ; `/status` không đổi. Dữ liệu manager không tăng.

## Lệnh
`root-command-f5.txt` (và `-success|-f3|-f4`, không dùng nếu không có quyết định mới): một lệnh `sudo`, hash manifest literal, giao cho `lane_entry.sh` từ stage; dòng cuối `lane_rc=… evaluator_rc=… signal=… export_rc=… final=…`.

## Giới hạn
Offline: manager/worker/docker/compose GIẢ (`tests/test_flow.py`, 74 kiểm R3 + `tests/test_export_r4.py` 13 kiểm); hành vi Docker/Compose/QEMU thật chỉ quan sát qua lượt thật. F5 không phải test tác vụ qua restart. T21b là gói riêng (`ct01-t21b-r2`).
