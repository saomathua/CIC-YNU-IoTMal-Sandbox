# Minh chứng Nhiệm vụ 04 — Build image (06/10/2026)

Lệnh (người dùng chạy, `.env.example` chỉ dùng để thay biến):

```
$ sudo docker compose --env-file .env.example config --quiet && echo CONFIG_OK
CONFIG_OK
$ time sudo docker compose --env-file .env.example build --progress=plain sandbox-manager sandbox-worker-1
...
 Image sandbox-worker Built
 Image sandbox-manager Built
real    1m18.645s
exit=0
```

Bắt đầu 05:04:10 UTC, kết thúc 05:05:28 UTC. Log đầy đủ: [`task04-build.log`](task04-build.log); trong log có 0 dòng chứa "error" hoặc "failed".

| | sandbox-manager | sandbox-worker |
|---|---|---|
| ID | `13f02b814da6` | `003a465550aa` |
| Config digest | `sha256:d65ee3ba3f48…` | `sha256:1f185db29db8…` |
| Kích thước (đĩa / nội dung) | 240 MB / 58.1 MB | 862 MB / 220 MB |
| Base | `python:3.12-slim@sha256:02108f5d…` | `ubuntu:22.04@sha256:5ec03bb3…` |
| Build context | 30.15 kB | 40.03 MB (≈ 4 `image.zip`) |

Gói chính trong worker: QEMU `1:6.2+dfsg-2ubuntu6.31`, tshark `3.6.2-2`, sysstat `12.5.2`, iptables `1.8.7` (alternative mặc định: `iptables-nft`).

Đĩa `/`: 61G còn trống trước build → 60G sau build.

**Hạn chế:** build thành công chỉ chứng minh Dockerfile hợp lệ, gói cài được và file cần `COPY` có trong build context; không chứng minh ứng dụng chạy được.
