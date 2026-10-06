# Minh chứng Nhiệm vụ 05 — MongoDB và manager (06/10/2026)

Giá trị bí mật **đã che**; chỉ ghi độ dài.

## Cấu hình

```
$ ls -l .env
-rw------- 1 dathq dathq 1588 Oct  6 05:30 .env
$ awk ... .env      # in tên biến, độ dài, không in giá trị
MONGO_USERNAME len=7 ok
MONGO_PASSWORD len=3 ok          # [đã che] — quá ngắn, xem Hạn chế
MANAGER_BIND_ADDR=127.0.0.1
ALLOW_VM_INTERNET=false
$ sudo docker compose config --quiet && echo CONFIG_OK
CONFIG_OK
```

## Khởi chạy từng service

```
$ sudo docker compose pull mongo-db
 ✔ Image mongo:8.0.32@sha256:d0d926f94df099bff534b7ee5b59864... Pulled
$ sudo docker compose up -d --no-deps mongo-db
$ sudo docker compose exec mongo-db mongosh --quiet --eval 'db.adminCommand({ping:1}).ok'
1
$ sudo docker compose up -d --no-deps --no-build sandbox-manager
$ sudo docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
cic-ynu-iotmal-sandbox-sandbox-manager-1   sandbox-manager   Up 21 seconds   127.0.0.1:8011->8011/tcp
mongo-db                                   mongo:8.0.32      Up 39 seconds   27017/tcp
/mongo-db status=running restarts=0
/cic-ynu-iotmal-sandbox-sandbox-manager-1 status=running restarts=0
$ sudo docker compose logs --tail 30 sandbox-manager
/app/router/ui_router.py:462: SyntaxWarning: invalid escape sequence '\.'
INFO:     Started server process [1]
[INFO] util.lifespan_handlers: Connected to MongoDB — recovered 0 task(s) into queue
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8011
```

## Endpoint và cổng (chạy trên host)

```
/healthcheck                    HTTP 200  {"message":"Hello World","startup_completed":"STARTED"}
/api/v1/sandbox-manager/status  HTTP 200  {"queued":0,"processing":0,"completed":0,"failed":0,"cancelled":0,"in_memory_queue":0}
/ui                             HTTP 200  text/html, 17066 B, <title>CIC-YNU-IoTMal-Sandbox</title>
/api/v1/sandbox-manager/tasks   HTTP 200  {"tasks":[]}
/api/v1/sandbox-manager/results HTTP 200  {"results":[]}

$ ss -ltn | grep -E ':8011|:27017'
LISTEN 0 4096 127.0.0.1:8011 0.0.0.0:*          # không có 27017 trên host
curl http://192.168.177.128:8011/healthcheck → 000 (không kết nối được từ IP LAN)
$ pgrep -a qemu → (không có); không có container worker
```

`/status` chạy `aggregate` trên MongoDB và lúc khởi động manager chạy `find()`, nên xác thực MongoDB thành công.

## Mount

```
$ sudo docker inspect -f '{{range .Mounts}}...{{end}}' <manager>
/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/malware -> /malware rw=false
/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/data/manager/output -> /app/output rw=true
/home/dathq/projects/CIC-YNU-IoTMal-Sandbox/data/manager/uploads -> /app/uploads rw=true
```

## Marker lưu trữ qua tạo lại container

```
# container cũ 6d03a6767f01…, marker ghi TỪ TRONG container
4e3a737da3e6a005c55230792df1dc0b0d9e5c8cbfb36d16b36353304cc9f7fc  /app/output/task05-persistence-marker.txt
83228e2d82e7e4613c2c0944dae351fc10041ece4fd21bce031b7ad22a10ed18  /app/uploads/task05-persistence-marker.txt
$ sudo docker compose up -d --no-deps --no-build --force-recreate sandbox-manager
# container mới 494ae3d2e2eb…, status=running restarts=0
4e3a737da3e6a005c55230792df1dc0b0d9e5c8cbfb36d16b36353304cc9f7fc  /app/output/task05-persistence-marker.txt
83228e2d82e7e4613c2c0944dae351fc10041ece4fd21bce031b7ad22a10ed18  /app/uploads/task05-persistence-marker.txt
# trên host (owner uid 0): cùng hai hash
$ rm -v data/manager/{output,uploads}/task05-persistence-marker.txt   # chỉ xóa 2 marker
$ find data/manager malware -type f | wc -l → 0
```

## UI qua SSH tunnel

`ssh -N -L 8011:127.0.0.1:8011 dathq@192.168.177.128` từ Windows; ảnh: [`task05-ui-ssh-tunnel.webp`](task05-ui-ssh-tunnel.webp) — bộ đếm đều 0, "No tasks.". Sau khi mở UI, `/status` vẫn 0 và `/tasks` `[]`.

## Hạn chế

- Marker chỉ chứng minh tệp trong `output/uploads` còn sau khi tạo lại container manager; chưa chứng minh quy trình tác vụ, độ bền dữ liệu MongoDB hay liên kết tác vụ.
- Mật khẩu MongoDB dài 3 ký tự: người dùng quyết định giữ cho lab (NV05C), không đổi. Mongo không publish cổng chỉ hạn chế truy cập trực tiếp từ ngoài VM; chưa đủ kết luận cô lập vì manager kết nối được database và mạng QEMU chưa kiểm chứng (CT-01).
- Chưa chạy worker/QEMU/ELF; chưa gọi `init-queue`/`submit-file`.
