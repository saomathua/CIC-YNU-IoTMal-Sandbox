# Minh chứng Nhiệm vụ 06B-1R: sửa theo review trước khi chạy worker (06/10/2026)

Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), thay đổi **chưa commit**. Mốc working tree trước đợt sửa: Git tree `eaf3d69f71a0e6cce518f028268a92400f634e61`. Đây là tree object tạo bằng index tạm, không phải commit và không có ref.

**Không** khởi chạy `sandbox-worker-1`, poller hay QEMU thật; không chạy ELF; không đổi mạng/firewall/sysctl của host.

## Phần đã tự chạy và phần do người dùng chạy

| Việc | Ai chạy | Kết quả |
|---|---|---|
| Unit test Python 3.12 (venv tạm trên host) | Claude | **117 passed** ([log](task06b1r/unit-tests-py312.txt)) |
| Kiểm tra đối chứng (phá mã vòng đời QEMU trên bản sao) | Claude | 6/6 đột biến bị bắt (bảng dưới) |
| Build image worker có ghim gói | Người dùng (sudo) | `exit=0`; manifest `sha256:a526b0c71752…` ([log](task06b1r/build.log)) |
| Selftest nft trong container `--network none` | Người dùng (sudo) | Lần 1: 27/29 ([log](task06b1r/nft-selftest-run1.log)); lần 2: **29/29**, `exit=0` ([log](task06b1r/nft-selftest-run2.log)) |
| Unit test Python 3.10 trong image (`--network none`, mã mount chỉ đọc, pytest cài offline) | Người dùng (sudo) | **117 passed**, Python 3.10.12 ([log](task06b1r/unit-tests-py310.txt)) |

## 1. Xác nhận QEMU đã thoát trước V2

- `shutdown_qemu()` trong `service/analysis.py`: gửi SIGINT, chờ tối đa 10 s; nếu chưa thoát thì SIGKILL, chờ tối đa 5 s.
- Việc thoát được xác nhận bằng `isalive()`, hàm này gọi `waitpid` để thu hồi tiến trình. Không xác nhận được thì ném `QemuShutdownError`.
- Phase 1 dùng `try/finally`, nên V2 và phase 2 chỉ chạy **sau** khi đã xác nhận.
- "QEMU shutdown complete" chỉ được ghi sau khi xác nhận.
- Lỗi sau khi spawn trong `_start_qemu` và trong lần nhắc thêm của phase 2 đều dừng QEMU trước khi ném lỗi tiếp.

**Test với tiến trình thật** (`tests/fake_qemu.py`, script Python giả lập console, không phải QEMU):

| Test | Kết quả |
|---|---|
| Thoát ngay khi nhận SIGINT; thoát trễ 0,5 s; bỏ qua SIGINT | Cả ba được xác nhận đã chết; chỉ trường hợp bỏ qua SIGINT mới dùng SIGKILL; dòng log cuối là "shutdown complete" |
| `test_v2_runs_only_after_phase1_qemu_exited` | Tại thời điểm V2 chạy, PID của QEMU phase 1 không còn tồn tại |
| `test_unconfirmed_exit_blocks_v2_and_phase2` | `isalive()` luôn trả True → `QemuShutdownError`; V2 không chạy; chỉ có 1 lần spawn; không có log "shutdown complete" |
| Boot timeout; lỗi `_configure_network`, `_run_analysis`, `_exfiltrate`; hủy | Tiến trình QEMU giả bị dừng |

**Phát hiện khi kiểm tra đối chứng:** ở phiên bản đầu của bộ test, các đột biến "bỏ dọn khi boot lỗi" và "bỏ `finally` phase 2" **không** bị bắt. Nguyên nhân: `pexpect.spawn.__del__` tự kill tiến trình con khi đối tượng bị garbage-collect. Fixture đã được sửa để giữ tham chiếu mạnh tới mọi tiến trình đã spawn. Sau khi sửa:

| Đột biến | Test thất bại |
|---|---|
| Phase 1 quay lại kiểu "gửi SIGINT rồi đi tiếp" | 5 |
| Không leo thang SIGKILL | 7 |
| Không chờ sau SIGINT | 2 |
| Bỏ dọn khi boot lỗi | 1 |
| Bỏ `finally` phase 2 | 1 |
| Ghi "complete" trước khi xác nhận | 1 |

**Giới hạn:** chỉ xử lý vòng đời QEMU cần cho CT-01. tshark và thư mục tác vụ khi lỗi thuộc CT-03, **chưa làm**. Trường hợp kernel không thể kill tiến trình (trạng thái D) chỉ được mô phỏng bằng đối tượng giả.

## 2. Transaction nft

`isolation/load.nft` (sha256 `0991fbdf…54c8`) gồm cặp `table X` / `delete table X` cho từng bảng CT-01, rồi `include "/app/isolation/guest.nft"`, tất cả trong một lệnh `nft -f`. `run.sh` gọi `nft -f /app/isolation/load.nft`.

Kết quả selftest lần 2:

| Phép thử | Kết quả |
|---|---|
| Lần nạp đầu khi chưa có bảng CT-01 | Thành công (lệnh trong `nft_selftest.sh`) |
| `load.nft leaves unrelated table in place (no namespace flush)` | PASS: `table ip unrelated_test` vẫn còn |
| `load.nft replacing existing CT-01 tables matches baseline` | PASS |
| `failed transaction (syntax error)` | PASS: `nft rc=1`; `drop_out 2 -> 2`; `Error: syntax error, unexpected '{'` |
| `failed transaction (undefined named counter)` | PASS: `nft rc=1`; `drop_out 4 -> 4`; `Error: Could not process rule: No such file or directory` (lỗi khi commit trong kernel) |
| `verify still passes after failed transactions` | PASS |

Bộ đếm khác 0 và giữ nguyên chứng minh bảng cũ **không bị tạo lại**: nạp thành công sẽ reset bộ đếm về 0.

**Lần 1 (27/29) có hai lỗi, đều do script kiểm thử:**

1. Nội dung "lỗi cú pháp" thực ra vẫn hợp lệ: bỏ `;` ở cuối dòng thì xuống dòng vẫn kết thúc câu lệnh. Kết quả `rc=0`, nạp thành công, bộ đếm reset.
2. Snapshot "trước" chỉ chụp một lần cho cả vòng lặp, nên so sai mốc.

Đã sửa: dùng token lạ làm lỗi cú pháp thật, chụp snapshot riêng cho từng trường hợp, và yêu cầu `rc != 0` cùng bộ đếm khác 0.

## 3. Ghim gói

`Dockerfile` (ARG) ghim: `nftables=1.0.2-1ubuntu3.1`, `libnftables1=1.0.2-1ubuntu3.1`, `libnftnl11=1.2.1-1build1`, `libjansson4=2.13.1-1.1build3`.

Phiên bản thực tế trong image ([packages.txt](task06b1r/packages.txt)):

```
iproute2            5.15.0-1ubuntu2.2
libjansson4:amd64   2.13.1-1.1build3
libnftables1:amd64  1.0.2-1ubuntu3.1
libnftnl11:amd64    1.2.1-1build1
nftables            1.0.2-1ubuntu3.1
```

`nft --version` = `nftables v1.0.2 (Lester Gooch)`. Ứng viên sinh lại giống hệt `expected-ruleset.json` trong working tree (sha256 `9fb32d7f…2b16`). **Không** sửa expected.

## 4. Phạm vi bằng chứng

- Runtime **chỉ** đối chiếu ba bảng CT-01 (thiết kế §6.1a; docstring `verify.py`; selftest in ra `[INFO] scope …`). Đề xuất mở rộng (allowlist bảng Docker lấy thực nghiệm ở 06B-2) để reviewer duyệt riêng.
- Đổi tên phép thử:
  - "extra base chain" → `extra base chain inside CT-01 table 'inet sandbox_guest'`;
  - "committed expected" → `expected-ruleset.json in image (working tree, not committed)` và `expected-ruleset.json (working tree) == generated candidate`.
- Log thô 06B-1 vẫn giữ tên cũ; [`task06b1-summary.md`](task06b1-summary.md) giải thích.

## 5. Chưa kiểm chứng

- `run.sh` thật, gồm V0 với sysctl và `eth0`, chưa chạy trong worker.
- Chưa boot QEMU thật; T01–T21 và F1–F6 chưa làm. **CT-01 chưa đạt.**
- Mất luật khi guest đang chạy chỉ được phát hiện ở V2 hoặc tác vụ sau.
- Bảng nft ngoài ba bảng CT-01 không được kiểm.
- Wheel pytest dùng cho test Python 3.10 tải từ PyPI; sha256 ghi ở [`pytest-wheels.sha256`](task06b1r/pytest-wheels.sha256). pytest chỉ được cài vào `/tmp` của container test, không có trong image.
