# CT-01 V0 runtime âm F1b / F6 — bản R4 (đóng logger/symlink và giữ D1–D4, VR1–VR5), CHỈ CHUẨN BỊ, chưa sudo/Docker, chưa chạy

Cây: `/home/dathq/projects/ct01-v0-runtime-r6/` (dẫn xuất từ `ct01-v0-runtime-prep`, giữ nguyên bản cũ). Nền: `ct01-v0-runtime-independent-review/REVIEW.md` (VR1–VR5).

## 1. Phương pháp (không đổi): một control + hai nhánh âm tuần tự, mỗi nhánh một container riêng cùng image ID đã ghim
| Nhánh | Khác control đúng một điều | Kỳ vọng |
|---|---|---|
| control | — (image + sentinel) | `ISOLATION OK (V0 startup)`, hai sentinel gọi sau dòng V0, ruleset kernel thật = expected đã ghim |
| F1b | `PATH=/ct01-path` (chỉ `ip`, `python3`) | `run.sh` dừng ở `nft -f`: exit 127 `nft: command not found`, không V0, không sentinel |
| F6 | `guest-f6.nft` (= guest.nft ghim + đúng một dòng `ip saddr 203.0.113.250 accept`) mount read-only | `nft -f` được nhận; V0 từ chối khác biệt cấu trúc: exit 1, không sentinel |

**Phạm vi F1b (đính chính):** kiểm chứng "executable `nft` **không resolve được** qua PATH hạn chế và `run.sh` dừng fail-closed ở dòng `nft -f`". `/usr/sbin/nft` **vẫn nằm trong image** (preflight ghi lại resolve ở PATH mặc định). Đây **không** là bằng chứng "image không chứa nft". Hàng ma trận F1b ghi "container/image không có nft, pgrep… manager `/status` không đổi" chưa được đáp ứng bởi phương pháp này nếu giữ nguyên chữ; quyết định thuộc người điều phối (§5). **Trạng thái container/exit code không thay bằng chứng `/status` của manager.**

## 2. Sửa so với bản prep (mỗi mục ↔ phát hiện)
| ID | Sửa | Kiểm |
|---|---|---|
| VR1 | Entry `root-command.txt` (một lệnh sudo, nội dung đã review, **hash manifest là literal trong lệnh**): copy cây vào `/var/lib/ct01-v0rt/<stamp>` (root:root, 0700), copy đầu vào repo theo `pins.json` vào `inputs/`, kiểm hash **trên bản trong stage**, rồi mới chạy runner/verifier/evaluator/fixture từ stage. Runner từ chối nếu không được khởi từ stage. Cây người dùng không còn được đọc sau khi copy. | V1–V4 |
| VR2 | Mọi phép đo ghi exit code (`measure-rc.tsv`) và stderr riêng; baseline chỉ được dùng khi nft/ip route/sysctl lõi/ss/docker ps/image/inspect từng container đều rc 0 (pgrep: 0/1); lỗi ⇒ abort trước khi tạo container; sau: rc ≠ 0 ⇒ tiêu chí fail, không bao giờ "unchanged". Guard đọc ps/pgrep/inspect giữ rc. | M1–M4, E6–E7 |
| VR3 | Container luôn mang label của lượt; finalizer (EXIT/INT/TERM/HUP) dọn **theo label** (kể cả khi CLI chưa trả ID) và theo tên nhưng chỉ khi label khớp; `rm` lỗi được ghi (`cleanup.log`) và làm hỏng verdict; `docker wait` chạy nền để tín hiệu được xử lý ngay; logger bỏ qua tín hiệu nhóm. | S1–S4, E10–E11 |
| VR4 | Mọi đường (abort, tín hiệu, lỗi) đi qua finalizer: host-after (nếu đã có before), leftover, `final-status.json` (completed/stage/signal/abort_reason), evaluator, bản sao evidence; exit 130/143/129 hoặc 3. | S2–S4, A1, E8 |
| VR5 | F6: đối chiếu **toàn bộ** rule (chain/family/table, field `saddr`, protocol `ip`, op `==`, right, thứ tự biểu thức, verdict) và `expected` bằng item đã ghim tại index báo cáo; `exit-code.txt` = `TIMEOUT` hoặc khác exit đã inspect ⇒ fail. | E1–E5 |

| Export | Bản sao forensic: manifest `EVIDENCE-SHA256SUMS` (+ `EVIDENCE-SYMLINKS`, symlink không bị theo) tạo **từ bản stage** trước khi copy; sau copy kiểm hash VÀ tập tệp; `export-receipt.json` (status `verified`/`mismatch`/`copy_failed`/`refused`, hash manifest evidence, manifest cây, runner, evaluator, pins, verdicts) ghi ngoài thư mục run và chép cạnh evidence. Không `verified` ⇒ exit 4, evidence ở lại stage. | O2b–O2d |

## 2b. Sửa R3 (review D1–D4 gốc đã được đối chiếu trực tiếp ở review R3; phản ví dụ cũ đều đã chặn)
| ID | Sửa | Kiểm |
|---|---|---|
| D1 | `measure-rc.tsv` 5 cột (name, rc, file, **label của lượt**, **seq 1..n**); evaluator bắt buộc: mỗi phép đo đúng một dòng, không tên lạ, đúng tệp của phép đo, đúng label/seq, **đủ** phép đo host trước và sau (nft, ip route, ip -6 route, tap0, iptables, 19 sysctl, ss, pgrep, image inspect/ls, ps-all và từng inspect của container liệt kê), mọi phép đo khác của lượt hoàn tất, tập inspect khớp `docker ps`, không mâu thuẫn rc ↔ nội dung/stderr (rc 0 mà sysctl rỗng, image id lạ, pgrep 1 mà có dòng qemu…). Trùng tên ⇒ rc coi như không xác định. | D1.1–D1.16 |
| D2 | `run-identity.json` (label, stage, hash manifest cây, image, runner); `final-status` phải nhất quán: completed ⇒ stage `evaluating`, không signal/abort, exit 0; signal ⇒ exit 128+n; abort ⇒ exit 3; không completed ⇒ có lý do; kiểu dữ liệu chặt; label = `run-label.txt` = identity; identity khớp manifest/ảnh/stage đã stage. | D2.1–D2.17 |
| D3 | Mọi bước xuất đều kiểm rc: manifest, copy, chown, verify (hash + tập tệp + symlink), ghi receipt, copy/chown/cmp receipt, ghi/copy `exit-status.json`. Lỗi ⇒ trạng thái riêng (`manifest_failed`, `copy_failed`, `chown_failed`, `mismatch`, `receipt_failed`, `receipt_copy_failed`, `exit_status_failed`, `exit_status_copy_failed`, `freeze_failed`), exit ≠ 0, rút lại mọi tuyên bố "verified" đã chép cạnh evidence. Ưu tiên giữ: signal (128+n) > abort (3) > evaluator ≠ 0 > export (4). | D3.1–D3.9 |
| D4 | Logger là tiến trình con đọc FIFO ngoài thư mục run; finalizer kill+wait writer `docker events`, đóng FIFO và **chờ logger thoát** trước khi tạo manifest (không thoát ⇒ `freeze_failed`, không copy). Log export/finalize ở `$STAGE/export.log`, `finalize.log` (ngoài run). Sau exit: `verify_export.py --stage S --export E` kiểm manifest ở cả stage và export, tập tệp chính xác, symlink, receipt/exit-status/verdicts/identity. | D4.1–D4.8 |

`tests/before_after.py`: cùng phản ví dụ chạy trên R2 (chấp nhận / exit 0 / manifest stage hỏng sau exit) và R3 (từ chối) — kết quả trong `before-after.json` của gói.

## 3. Lệnh (chưa chạy)
Không root, offline:
```bash
source /home/dathq/projects/ct01-v0-runtime-r6/STEP0-verify.sh; ct01_v0rt_step0
python3 -I -B /home/dathq/projects/ct01-v0-runtime-r6/tests/test_orchestration.py   # runner+evaluator, docker/host giả
python3 -I -B /home/dathq/projects/ct01-v0-runtime-r6/tests/test_entry.py           # entry: stage, hash, từ chối sai
# sau một lượt thật (root cho phần stage): python3 -I -B verify_export.py --stage /var/lib/ct01-v0rt/<stamp> --export <bản sao evidence>
```
Sau quyết định riêng (root, MỘT lần, không retry; không chạy cùng B1/collection/launch): dán nội dung `root-command.txt`. Evidence: bản stage `/var/lib/ct01-v0rt/<stamp>/run` (root) và bản sao `ct01-v0-runtime-r6-run-<stamp>` (đã chown cho người dùng); không tự xóa/dùng lại.

## 4. Tác động
Docker: tạo/xóa 3 container `ct01-v0rt-{control,f1b,f6}` + 4 container `--rm --network none` (không tạo image/volume/network); ba case `--privileged` trên `sandboxnet` sẵn có (precedent 06B-2A/2AR), sentinel không phát traffic ứng dụng (ARP/IPv6/Docker nền không được loại trừ). Host: ghi `/var/lib/ct01-v0rt/` và thư mục evidence; không đổi ruleset/sysctl/route; đọc nft/ip/sysctl/ss/pgrep/docker (read-only).

## 5. Quyết định vận hành còn thiếu (không tự thay)
1. Phương pháp PATH có đáp ứng F1b của ma trận không, hay cần bằng chứng "không có binary" (build/ảnh riêng — chưa được duyệt)?
2. `/status` của manager: giữ yêu cầu đo `/status` hay chấp nhận bằng chứng thay thế có ghi phạm vi (container state không thay thế được)?
3. Duyệt `--privileged` + `sandboxnet` như compose/06B-2AR, một lượt không retry.
4. Lịch độc quyền: không B1/collection/launch khác trong cả thử và hậu kiểm (guard theo tên chỉ phủ `sandbox-worker`, `ct01-06b3b-*`, qemu; không phải khóa).
5. Cách lấy evidence root-owned (bản sao tự động đã có; xác nhận chấp nhận).

## 6. Giới hạn
Chỉ kiểm bằng docker/host giả: không chứng minh hành vi Docker/kernel/nft/image thật, cú pháp/vị trí rule thật, hay signal Docker thật. Ctrl-C/SIGHUP được xử lý như SIGTERM trong mô phỏng (nhóm tiến trình); timeout bên ngoài/SIGKILL không có finalizer. Không nâng kết quả stub thành PASS CT-01; V1, restart, luồng tác vụ không thuộc phạm vi.

## 7. R4: hai sửa evidence, không đổi tiêu chí V0
- Logger phải được await và exit 0; thoát lỗi hoặc còn writer giữ `freeze_failed`, không copy và không `verified`. Exit ưu tiên signal > abort > evaluator > export vẫn giữ.
- Verifier kiểm đủ tên và target symlink, đồng thời kiểm hash listing với receipt. Listing sai hoặc target đổi không PASS.
- D4.2 không còn `or True`; D4.4 chỉ tuyên bố byte log bằng nhau. Lỗi logger và symlink có regression riêng `tests/test_r4_regressions.py` với control sạch và phản ví dụ.
- `make_entry.py --tree-path /home/dathq/projects/ct01-v0-runtime-r6` sinh root command đúng đường cài đặt; chỉ tạo text, không chạy sudo.
- Pin và root-command trong gói R4 không kế thừa quyền launch. Chưa có approval hoặc evidence runtime. Mọi quyết định §5 vẫn mở.

## 8. R5 → R6 (lượt R5 `20261010T164552Z-16780`: hành vi thật khớp, evaluator bị lỗi cách đọc)
- R4 (`…161816Z-3873`): abort ở preflight vì `nft -c` trong container `--network none` không có `tap0` (probe `ct01-v0-runtime-r5-probe-20261010T162921Z`: bản guest.nft gốc cũng lỗi; có `tap0` dummy thì rc 0 cả gốc và F6). R5 tạo `tap0` dummy chỉ trong netns của container preflight.
- R5 chạy hết (rc 1, CRITERIA NOT MET) với 10 FAIL do evaluator, không do hành vi: (a) `docker logs` đưa stderr sang `docker-logs.txt.err` — F1b `run.sh: line 59: nft: command not found` và F6 `ISOLATION FAIL … item 25` chỉ nằm ở đó; (b) hai marker sentinel in trong MỘT dòng, không xuống dòng; (c) `iptables-save` có bộ đếm gói của chain (`[pkts:bytes]`) khác nhau giữa hai lần đọc; (d) `nft -s list ruleset` in cảnh báo `table … is managed by iptables-nft` trên stderr, rc 0.
- R6 sửa đúng bốn điểm trong `evaluate_v0_runtime.py`: hợp nhất stdout+stderr của `docker logs` theo timestamp (tiêu chí F1b/F6/control đọc cả hai luồng, nghiêm hơn: ISOLATION FAIL ở stderr control cũng bị bắt); sentinel đếm theo marker (mỗi marker đúng một lần, không SENTINEL nào khác, sau dòng OK); bộ đếm `[n:m]` được chuẩn hóa trong so sánh iptables-save (quy tắc thay đổi vẫn bị bắt); chỉ đúng dòng cảnh báo iptables-nft được bỏ qua trên stderr của nft. Runner chỉ đổi ở preflight (R5). Kiểm: `tests/test_orchestration.py` 101/101 gồm R6.1–R6.4 (fixture có dạng log thật; 8 bằng chứng bị đột biến đều bị từ chối).
