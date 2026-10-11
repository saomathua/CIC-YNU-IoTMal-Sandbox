# Minh chứng Nhiệm vụ 06B-3C và 06B-3CR: sửa harness, kiểm thử OFFLINE (06/10/2026)

> **Loại bằng chứng: kiểm thử offline.** Không có Docker, QEMU, guest hay probe mạng. Toàn bộ chạy dưới user thường. Phép thử tích hợp thật nằm ở [`task06b3d-summary.md`](task06b3d-summary.md).

**Bối cảnh:**

- Reviewer chấp nhận 06B-3B trong phạm vi 20 probe IPv4.
- 06B-3C sửa harness theo review. 06B-3CR sửa các lỗi reviewer phát hiện trong 06B-3C.
- **Reviewer đã chấp nhận mã và bằng chứng offline của 06B-3CR.**
- Không sửa source; working tree của repo vẫn là tree `e347ac05f455f3a279682a18983ce6e5b592fb57`.
- Harness nằm ngoài repo, tại `/home/dathq/projects/ct01-06b3c/`. Bản gốc 06B-3B được giữ trong `base/`.

## 06B-3C: bốn điểm sửa

Bàn giao gốc: [`task06b3c/offline-06b3c/`](task06b3c/offline-06b3c/).

| Điểm | Sửa |
|---|---|
| Regex URL | `/ct01-06b3b-[0-9]` của 06B-3B **không bao giờ khớp** tên probe thật (như `internet-tcp`). Bộ tìm chữ ký mới là `sigscan.sh`: đếm theo gói; lỗi đọc trả exit 2; có fixture có và không có chữ ký. |
| Giám sát capture | Bộ giám sát nền theo dõi 4 tcpdump phía host. Mỗi probe kiểm tshark trên `tap0`; mất capture thì dừng với exit 98. |
| Netns worker | Ghi `ip link/addr/route/neigh/rule` trước và sau. Nếu có interface khác `lo`, `eth0`, `tap0` thì dừng trước khi boot guest. |
| Manager | Khôi phục đúng trạng thái ban đầu. Bản 06B-3B luôn chạy `compose stop`. |

## 06B-3CR: sửa theo review 06B-3C

Bàn giao: [`task06b3c/offline-06b3cr/`](task06b3c/offline-06b3cr/).

1. **Heartbeat.**
   - Mỗi giây, bộ giám sát ghi thời gian hiện tại (ghi file tạm rồi đổi tên).
   - `probe_matrix.py` ném `CaptureLost` khi gặp một trong các trường hợp: heartbeat thiếu, sai định dạng, cũ hơn 5 s hoặc ở tương lai; marker có nội dung hoặc không đọc được; tshark đã thoát.
2. **Manager.**
   - Giữ mã lỗi của `compose up` (thêm `--no-recreate`). Chỉ đánh dấu "đã khởi động" sau khi xác nhận đúng container cũ đang chạy.
   - Từ chối `created` và mọi trạng thái khác `running`/`exited` trước khi thay đổi gì.
   - Dừng bằng `docker stop <ID>`, sau khi đã kiểm ID; không bao giờ dừng container thay thế.
3. **Thống kê drop.**
   - tshark 3.6 **không in dòng drop nào khi drop = 0**, nên stderr không chứng minh được "0 drop".
   - Nay số liệu đọc từ khối ISB trong pcapng do dumpcap ghi, qua `pcapng_stats.py`.
   - Chỉ **ĐẠT** khi có `isb_ifdrop=0` và `ifrecv` bằng số gói đã lưu. Thiếu thống kê là **CHƯA KIỂM CHỨNG**; lỗi đọc là **FAIL**.

## Kết quả offline

| Phép thử | Kết quả | Log |
|---|---|---|
| `selftest.sh` | **68/68 PASS**, ổn định qua 3 lần | [`selftest.log`](task06b3c/offline-06b3cr/logs/selftest.log) (`c29b8a89…c15d`) |
| `mutation_test.sh` | Baseline đạt; **26/26** đột biến hành vi bị bắt đúng check được nhắm; 2 đột biến đối chứng được phân loại đúng (cú pháp → `INVALID`, thiếu phụ thuộc → `ERROR`) | [`mutation-run3-final.txt`](task06b3c/offline-06b3cr/logs/mutation-run3-final.txt) (`fcd8f298…7f49`) |

**Mutation test tìm ra lỗi ở chính các phép thử**, đã sửa trong 06B-3CR. Log lần chạy đầu: [`mutation-run1-before-fixes.txt`](task06b3c/offline-06b3cr/logs/mutation-run1-before-fixes.txt).

- **Ca zombie chưa từng được kiểm.** Bàn giao 06B-3C ghi ca này như đã kiểm, nhưng điều đó **sai**: bash tự thu dọn tiến trình con, nên test chưa từng tạo ra zombie. Giờ test tạo zombie thật.
- **`pcapng_stats.py` ném `struct.error` với file bị cắt cụt.** Lỗi này sẽ làm hỏng khối `finally` của `probe_matrix.py`.
- **Fixture drop>0 không cô lập được quy tắc drop.**
- **Một check mong đợi bị chọn sai** (C6 → C7).

## Hash của harness (bản 06B-3CR, cũng là bản chạy ở 06B-3D)

| File | sha256 |
|---|---|
| `run-06b3b.sh` | `f1569baa706ba44e53c72864e1618b0064d78bd8da65229eb9a0bd0145b8e300` |
| `probe_matrix.py` | `255b395186a9b9b6136b312ef35462b7027aefc7b3aa54b0c5678c38ba2c61f0` |
| `harness_lib.sh` | `de079deb45da1fefb05c24219dd19a460962ad636faef9e962c6b10f300c5a86` |
| `pcapng_stats.py` | `c3d18072bc8b3b394c3c90de95b282b20cd0b97e391882da59caad486c3fcffd` |
| `sigscan.sh` | `f85f52115d4b4cfb4d491d27ad2ba0f81b0dd13a1bd758d28983f664ed78a74b` |
| `selftest.sh` | `ffbed6bb475ce8d1459eca0f900ee7ab731c01c120ad56d329421ff360d0d944` |
| `mutation_test.sh` | `376b7b45dbc9b8ebe5675e4e5f9d0e24e877f7307a57450d29f2debedc3c166d` |
| `make_fixtures.py` | `b0620ad3808914538e22ad2f2a32e6396712fbf6d8121d066b22ee60626e3a1d` |
| `independent_check.sh` | `06852ac23d5e7b5526530afea8358b68b9e280411c1f7d9882a52a1ffe4b9f56` |
| `ctl_loop.py`, `sentinel/poller.py` | không đổi từ 06B-3B |

Diff: [06B-3B → 06B-3C](task06b3c/offline-06b3c/ct01-06b3c-harness.diff); [06B-3C → 06B-3CR](task06b3c/offline-06b3cr/ct01-06b3cr-delta-vs-06b3c.diff); [06B-3B → 06B-3CR](task06b3c/offline-06b3cr/ct01-06b3cr-full-vs-06b3b.diff).

## Hạn chế của bằng chứng offline

- Docker, Compose và tcpdump/tshark khi đang capture thật đều được **giả lập** (`docker` giả, tiến trình `sleep`). Riêng `run-06b3b.sh` chỉ được kiểm cú pháp.
- Bộ đọc ISB mới được kiểm trên fixture và trên hai pcapng thật của 06B-3B.
- Những điểm này được kiểm bằng tích hợp thật ở 06B-3D.
