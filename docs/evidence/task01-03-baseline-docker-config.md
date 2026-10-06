# Minh chứng Nhiệm vụ 01–03 (06/10/2026)

## NV01 — Môi trường và repository

```
$ hostname; whoami
hq
dathq
$ nproc; free -h | head -2
4
Mem:  7.7Gi ...
$ df -h /
/dev/mapper/ubuntu--vg-ubuntu--lv   73G  7.1G   62G  11% /
$ ls /dev/kvm
ls: cannot access '/dev/kvm': No such file or directory      # QEMU chạy TCG
$ git remote -v
origin    https://github.com/saomathua/CIC-YNU-IoTMal-Sandbox.git
upstream  https://github.com/UNBCIC/CIC-YNU-IoTMal-Sandbox.git
$ git rev-parse HEAD        # main
0ce8796622a8f9587a0fda205764cfa44dfb5711
```

VM image (đọc danh sách zip, không giải nén): `ARM/image.zip` (zImage + root.ext4 256 MB),
`MIPS`, `MIPSEL`, `x86` (vmlinux + root.ext4 104 MB).

## NV02 — Docker Engine

```
$ gpg --show-keys /etc/apt/keyrings/docker.asc
      9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88
uid   Docker Release (CE deb) <docker@docker.com>
$ dpkg-query -W docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin unzip
docker-ce              5:29.8.2-1~ubuntu.24.04~noble
docker-ce-cli          5:29.8.2-1~ubuntu.24.04~noble
containerd.io          2.3.6-1~ubuntu.24.04~noble
docker-buildx-plugin   0.37.1-1~ubuntu.24.04~noble
docker-compose-plugin  5.6.0-1~ubuntu.24.04~noble
unzip                  6.0-28ubuntu4.1
$ sudo docker run --rm hello-world
Hello from Docker!   (digest sha256:5e23090353324d887c48ad5e5c56d294eab81588df9605b07d1afe895f9cc8f8)
$ systemctl is-active docker containerd   → active active
```

## NV03 — Kiểm tra cấu hình tĩnh (không cần daemon)

```
$ git diff --check                                         → OK
$ docker compose --env-file .env.example config --quiet    → OK
$ docker compose --env-file /dev/null config --quiet
error ... required variable MONGO_PASSWORD is missing a value: set MONGO_PASSWORD in .env
```

Kiểm tra bằng script:
- Biến bắt buộc của `Settings` so với `environment:` của Compose: manager thiếu 0, worker thiếu 0.
- Nguồn `COPY` trong Dockerfile so với `.dockerignore`: không nguồn nào bị loại.
- `git check-ignore`: `.env` (3 cấp), `.env.local`, `malware/*`, `data/*` bị ignore; `*.env.example` không bị ignore.
- PyMongo 4.11 `MAX_SUPPORTED_WIRE_VERSION = 25` (MongoDB ≤ 8.0) → chọn `mongo:8.0.32`.
