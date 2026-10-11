# Kết quả cải tiến (KQCaiTien)

Ghi tiến độ khóa luận **"Nghiên cứu và triển khai Sandbox ứng dụng trong phân tích mã độc IoT"**, dựa trên bằng chứng.
Roadmap và tiêu chí nghiệm thu: [`docs/requirements.md`](docs/requirements.md). Minh chứng: [`docs/evidence/`](docs/evidence/).

Cập nhật lần cuối: 11/10/2026 (CT-01 chốt theo phạm vi nghiệm thu đã duyệt; CT-02/CT-03 đang chuẩn bị offline, chưa là kết quả). Hạn hoàn thành: 08/11/2026.

`docs/requirements.md`: **reviewer đã đọc và chấp nhận**.

## Quy ước

| Trạng thái | Ý nghĩa |
|---|---|
| **Chưa bắt đầu** | Nhóm chưa sửa gì cho tiêu chí này. |
| **Đã cấu hình – chưa kiểm chứng** | Có thay đổi cấu hình/mã nhưng chưa có kiểm thử chứng minh hoạt động. |
| **Kiểm chứng một phần** | Một số tiêu chí con có bằng chứng; phần còn lại chưa. |
| **Đạt** | Mọi tiêu chí nghiệm thu có bằng chứng và đã được review. |

Nguồn: **[KC]** đã kiểm chứng bằng lệnh/kết quả thực tế; **[Mã]** chỉ đọc mã nguồn, chưa chạy; **[Offline]** kiểm thử offline (fixture, giả lập; không Docker/QEMU/mạng), chưa phải tích hợp thật.
Phân biệt: **CIC đã có** (mã gốc), **Nhóm đã làm**, **Chưa kiểm chứng**.

## Trạng thái commit / PR

| Hạng mục | Giá trị |
|---|---|
| Commit nền CIC (`main`) | `0ce8796622a8f9587a0fda205764cfa44dfb5711` |
| Nhánh làm việc | `chore/deployment-prep` (tách từ `chore/baseline-audit`) |
| Commit mốc triển khai | `3c54d55925b7471687b9be5b3cebcbb5b2e4bd43` — `chore: prepare deployment and record baseline verification` (nhánh `chore/deployment-prep`); reviewer đã kiểm tra qua patch |
| Nhánh CT-01 | `feat/ct01-network-isolation`, tách từ `3c54d55` |
| Push / PR | **Chưa** — chưa push, chưa mở PR, chưa merge |
| Diff đã review (NV03) | sha256 `04113607e9a01a6f3b2d5581ea9c40ffbd7ebce9697a4961864e78515ff35045` |

---

# Phần A — Chuẩn bị môi trường

Không thuộc CT-01–14; là nền để triển khai và kiểm thử.

### NV01 — Khảo sát nền

- **Mục tiêu:** chuẩn bị repo, khảo sát kiến trúc và điểm cần kiểm chứng.
- **Thay đổi:** clone repo; thêm remote `upstream`; tạo nhánh `chore/baseline-audit`. Không sửa source.
- **Kiểm thử / Kết quả [KC]:** Ubuntu 24.04, 4 vCPU, 7.7 GiB RAM, `/` 73G; không có `/dev/kvm` (QEMU chạy TCG); Git 2.43.0.
- **Hạn chế:** `sudo vgs/lvs` chưa chạy (cần mật khẩu).
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Commit/PR:** không có.
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md).

### NV02 — Cài Docker

- **Mục tiêu:** cài Docker Engine từ kho APT chính thức.
- **Thay đổi (hệ thống):** khóa APT Docker (fingerprint `9DC8…CD88` khớp), cài `docker-ce 29.8.2`, `containerd.io 2.3.6`, `buildx 0.37.1`, `compose-plugin 5.6.0`, `unzip`. Chưa thêm user vào nhóm `docker`.
- **Kiểm thử / Kết quả [KC]:** `hello-world` in "Hello from Docker!"; `docker`, `containerd` active + enabled.
- **Hạn chế:** Docker tự thêm chain iptables và bridge `docker0` (hành vi mặc định).
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Commit/PR:** không áp dụng.
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md).

### NV03 — Cấu hình build và lưu trữ

- **Mục tiêu:** bỏ `.env` khỏi image, lưu trữ bền vững, ghim MongoDB, bind loopback, mặc định chặn Internet cho VM, tài liệu.
- **Thay đổi:** `Dockerfile` (bỏ `COPY .env`) ×2; `.dockerignore` ×2; `.gitignore`; `.env.example` ×2; `docker-compose.yml`; `README.md`; `docs/deployment.md`; `AGENTS.md`; `CLAUDE.md`.
- **Kiểm thử / Kết quả [KC]:** `git diff --check` OK; `compose config --quiet` OK; thiếu biến Mongo → Compose báo lỗi; script so `Settings`↔`environment` thiếu 0 biến; nguồn `COPY` không bị `.dockerignore` loại; `.env`, `malware/`, `data/` bị Git bỏ qua.
- **Hạn chế:** kiểm tra tĩnh.
- **Review:** reviewer đã đối chiếu trực tiếp patch với source và chấp nhận bước build. **Commit/PR:** chưa (xem trên).
- **Minh chứng:** [`task01-03-baseline-docker-config.md`](docs/evidence/task01-03-baseline-docker-config.md); patch đầy đủ chưa được lưu trong `docs/evidence/` (**thiếu**, hiện chỉ có tại `/home/dathq/projects/chore-deployment-prep.patch` ngoài repo).

### NV04 — Build image

- **Mục tiêu:** build `sandbox-manager`, `sandbox-worker`; chưa chạy.
- **Kiểm thử / Kết quả [KC]:** `exit=0`, `real 1m18.6s`; manager `13f02b814da6` (240 MB), worker `003a465550aa` (862 MB); build context của manager 30 kB, của worker 40 MB → `.env` không nằm trong context.
- **Hạn chế:** build thành công ≠ ứng dụng chạy được.
- **Review:** reviewer chấp nhận báo cáo bàn giao. **Minh chứng:** [`task04-build.md`](docs/evidence/task04-build.md), [`task04-build.log`](docs/evidence/task04-build.log).

### NV05 — Kiểm chứng MongoDB và manager

- **Mục tiêu:** chạy riêng MongoDB và manager, kiểm tra endpoint, cổng, mount, lưu trữ; chưa chạy worker.
- **Thay đổi (hệ thống):** tạo `.env` (600, giá trị do người dùng đặt); tạo `malware/`, `data/mongo`, `data/manager/{output,uploads}`; pull `mongo:8.0.32`; chạy 2 container.
- **Kiểm thử / Kết quả [KC]:**
  - `mongo-db` ping `1`; manager restarts=0; log `Connected to MongoDB — recovered 0 task(s)`.
  - `/healthcheck`, `/status`, `/ui` đều 200; `/status` toàn 0; `/tasks` `[]`.
  - Cổng chỉ `127.0.0.1:8011`; không truy cập được qua IP LAN; Mongo không publish cổng.
  - Mount `output`/`uploads` rw, `malware` ro; marker còn nguyên hash sau `--force-recreate` manager; đã xóa marker.
  - UI mở được qua SSH tunnel từ Windows.
  - Không có worker/QEMU.
- **Hạn chế:**
  - Mật khẩu MongoDB ngắn (3 ký tự). **Người dùng quyết định giữ** để thuận tiện trong lab; không đổi mật khẩu hay cấu hình xác thực. Việc MongoDB không publish cổng ra host chỉ hạn chế truy cập trực tiếp từ ngoài VM; **chưa đủ để kết luận cô lập**, vì manager vẫn kết nối được database (manager nằm trên cả `dbnet` và `sandboxnet`) và mạng QEMU chưa được kiểm chứng (CT-01). Cần đánh giá lại trước khi chạy mẫu thật hoặc dùng ngoài lab.
  - `SyntaxWarning` ở `ui_router.py:462` (mã gốc).
- **Review:** reviewer chấp nhận báo cáo kiểm thử và ảnh UI qua SSH tunnel. **Minh chứng:** [`task05-manager-mongo.md`](docs/evidence/task05-manager-mongo.md), [`task05-ui-ssh-tunnel.webp`](docs/evidence/task05-ui-ssh-tunnel.webp).

---

# Phần B — Cải tiến CT-01 → CT-14

| Mã | Cải tiến | Trạng thái | Review | Commit/PR |
|---|---|---|---|---|
| CT-01 | Cô lập mạng QEMU | **ĐẠT — hoàn tất theo phạm vi nghiệm thu đã duyệt; reviewer chốt 2026-10-11** (xem 'Closure CT-01' trong mục CT-01; không phải chứng nhận mọi phép thử của thiết kế gốc hay mọi image về sau; giới hạn/lịch sử giữ nguyên). Lịch sử các lượt trước: kiểm chứng một phần (guest ARM/MIPS thật: liên kết dịch vụ qua `tap0` đạt; ma trận chặn IPv4 có đối chứng 20/20 probe đạt ở 06B-3B; tích hợp harness sửa đổi 06B-3D: 19/20, 1 FAIL, giả thuyết là lỗi biên cửa sổ của harness; phép đo đã sửa ở 06B-3DR/3DR1 [Offline]; tích hợp 06B-3E: exit 4, 16/20 ĐẠT, 4 CHƯA KIỂM CHỨNG do gói biên, 0 FAIL; đối chiếu toàn phiên chuẩn bị ở 06B-3F, sửa ở 06B-3FR và 06B-3FR1 [Offline]; tích hợp 06B-3G: exit 4, 19/20 ĐẠT, 1 CHƯA KIỂM CHỨNG do gói biên, 0 FAIL, toàn phiên ARM/MIPS PASS (báo riêng); T12/T13 5 ca kiểm quy tắc, tích hợp 06B-4G: exit 4, 9/10 ĐẠT (kiểm quy tắc), ARM T13-I1 CHƯA KIỂM CHỨNG do gói biên, 0 FAIL; **chưa**: ARP/MAC spoof, giả IP nguồn, IPv6/broadcast có đối chứng sống, inbound, fail-closed khi chạy) | thiết kế: đã duyệt hướng; 06B-1R + expected: chấp nhận trước guest; 06B-2AR: chấp nhận startup/V0; 06B-2BR: chấp nhận trước guest; 06B-3A: chấp nhận; 06B-3B: **chấp nhận** (phạm vi 20 probe); 06B-3CR: **chấp nhận** mã + bằng chứng offline; 06B-3D: đã review, yêu cầu sửa phép đo và diễn đạt (06B-3DR); 06B-3DR: đã review, reviewer tái hiện 2 lỗ hổng kết luận (sửa ở 06B-3DR1); 06B-3DR1: **chấp nhận** mã + bằng chứng offline; 06B-3E: **chấp nhận** (đúng phạm vi exit 4); 06B-3F: đã review, **còn lỗi** (4 trường hợp PASS sai), chưa chấp nhận chạy tích hợp; 06B-3FR: đã review, phần đối chiếu được xác nhận, còn lỗi nuốt lỗi quét QEMU (sửa ở 06B-3FR1); 06B-3FR1: **chấp nhận** ở mức offline; 06B-3G: **chấp nhận** (đúng phạm vi exit 4); 06B-4A (kế hoạch): **chấp nhận hướng**, quyết định D1–D7; 06B-4B (harness L2/ARP/IPv6, offline): đã review, **còn lỗi** chữ ký trên capture bị cắt bởi snaplen (sửa ở 06B-4BR); 06B-4BR: **chấp nhận** ở mức offline; 06B-4C (tích hợp harness 06B-4BR): **chấp nhận** (phạm vi kiểm tích hợp harness); 06B-4D1 (bộ đánh giá L2/ARP offline): đã review, **còn 2 lỗi đầu vào** (sửa ở 06B-4D1R); 06B-4D1R: **chấp nhận**; 06B-4E (chuẩn bị T12–T13, offline): đã review, **còn 2 lỗi đánh giá** (sửa ở 06B-4ER); 06B-4ER: **chấp nhận** ở mức offline; 06B-4F (nối 5 ca ICMP vào harness, offline, chưa chạy tích hợp): đã review độc lập, **còn 2 lỗi** (P1 guard cảnh báo trước lệnh, P2 tính đầy đủ hồ sơ hạ tầng), **chưa chấp nhận tích hợp** (sửa ở 06B-4FR); 06B-4FR: **chấp nhận** ở mức offline (Codex review độc lập); 06B-4G (chạy tích hợp 5 ca ICMP, exit 4): **chấp nhận đúng phạm vi** (9/10 kiểm quy tắc đạt, ARM T13-I1 UNVERIFIED, 3 mục OPEN còn nguyên); 06B-4H (đính chính hồ sơ 06B-4G + chuẩn bị T14/T15 offline): đã review (Codex), đính chính 4G được chấp nhận; phần T14/T15 **còn 5 lỗi** (3 P1 có thể báo ĐẠT sai, 2 P2), **chưa chấp nhận nối tích hợp** (sửa ở 06B-4HR); 06B-4HR: đã review (Codex), F1–F5 cũ đúng nhưng **còn 5 lỗi mới** (HR1–HR5: 2 P1 báo ĐẠT sai, 3 P2), **chưa chấp nhận nối tích hợp** (sửa ở 06B-4HR1); 06B-4HR1: đã review (Codex), HR1–HR5 đã khắc phục cho các biến thể tái hiện, **còn R1** (P1: `neigh_dynamic` mang cờ PERMANENT làm mất neighbor static vẫn ĐẠT), **chưa chấp nhận nối tích hợp** (sửa ở 06B-4HR2); 06B-4HR2: **chấp nhận** ở mức offline (Codex review hẹp: R1 đã khắc phục; không xác nhận collector/tích hợp); 06B-4I (nối ARP vào harness, offline, chưa chạy guest): đã review (Codex), **còn I1/I2 (P1) và I3 (P2)**, **chưa chấp nhận chạy guest** (sửa ở 06B-4IR1); 06B-4IR1: đã review (Codex), I1 tái hiện cũ và I2 trường hợp cũ đã sửa, I3 đã sửa; **còn IR1-R1** (P1: handoff IPv4 gửi service link không có guard) **và IR1-R2** (P2: MAC endpoint toàn 0 vẫn PASS), **chưa chốt chạy guest** (sửa ở 06B-4IR2); 06B-4IR2: **chấp nhận** ở mức offline (Codex review hẹp; không phải chấp thuận chạy guest); precheck chỉ đọc 06B-4IR2: chấp nhận ở phạm vi snapshot host + parser offline; script root **chưa** chấp nhận (PC-1…PC-4, sửa ở 06B-4IR3); 06B-4IR3: chưa review | chưa commit |
| CT-02 | Môi trường sạch giữa các mẫu | Chưa bắt đầu | — | — |
| CT-03 | Cleanup | Chưa bắt đầu | — | — |
| CT-04 | Xác minh thực thi và log | Chưa bắt đầu | — | — |
| CT-05 | Lưu dữ liệu bền vững | Kiểm chứng một phần | chưa | chưa |
| CT-06 | Kiểm tra đầu vào | Chưa bắt đầu | — | — |
| CT-07 | Phân tích strace | Chưa bắt đầu | — | — |
| CT-08 | Phân tích PCAP | Chưa bắt đầu | — | — |
| CT-09 | Báo cáo JSON | Chưa bắt đầu | — | — |
| CT-10 | Dashboard | Chưa bắt đầu (`/ui` gốc chạy được [KC]) | — | — |
| CT-11 | Xuất PDF | Chưa bắt đầu | — | — |
| CT-12 | Theo dõi giai đoạn và worker | Chưa bắt đầu | — | — |
| CT-13 | Thông tin tái lập | Chưa bắt đầu (phiên bản đã ghi trong tài liệu) | — | — |
| CT-14 | Kiểm thử và đánh giá | Chưa bắt đầu (đánh giá tổng thể; các kiểm chứng từng phần của CT-01 không tính là CT-14) | — | — |

### CT-01 — Cô lập mạng QEMU · ĐẠT — hoàn tất theo phạm vi nghiệm thu đã duyệt; reviewer chốt 2026-10-11

- **Mục tiêu:** chặn Internet, LAN và dịch vụ quản lý; chỉ cho luồng cần thiết; có kiểm thử đích được phép và bị chặn.
- **CIC đã có [Mã]:** `ALLOW_VM_INTERNET=false` → 2 luật iptables FORWARD trong `run.sh` gốc; guest được bắc cầu vào `sandboxnet`.
- **Thiết kế:** [`docs/network-isolation-design.md`](docs/network-isolation-design.md). Reviewer đã chấp nhận hướng PA-2 (06A) và bản 2; bản 3 bổ sung các quy tắc bằng chứng trước 06B-1.
- **Nhóm đã làm (06B-1, nhánh `feat/ct01-network-isolation`, chưa commit):**
  - `tap0` riêng `10.200.0.0/30`, không bridge `eth0`; MAC guest cố định `52:54:00:c7:00:02`; neighbor permanent; `ip_forward=0`.
  - nftables 3 bảng (`netdev`/`arp`/`inet`, chặn ở prerouting). Verify V0 (startup), V1 (trước phase 1), V2 (trước phase 2) đối chiếu `expected-ruleset.json` đã chuẩn hóa, cộng kiểm device netdev, sysctl, link, neighbor, route. Fail-closed.
  - API allowlist bắt buộc theo `current_task`; `proxy_headers=False`.
  - Poller ghi `current_task` nguyên tử và xóa trong `finally`. `run.sh` từ chối `ALLOW_VM_INTERNET != false`.
- **Kiểm thử / Kết quả [KC]** ([`task06b1-summary.md`](docs/evidence/task06b1-summary.md)):
  - Unit test **107 passed**. Kiểm tra đối chứng: phá mã ở 14 chỗ, lần nào cũng có test thất bại.
  - Build image worker `exit=0` hai lần; thêm `nftables 1.0.2-1ubuntu3.1`.
  - Kiểm thử nft thật trong container `--network none` (không privileged, không chạy entrypoint/QEMU):
    - lần 1: 20/22. Phát hiện `nft 1.0.2` bỏ khóa `dev` của chain netdev trong JSON → thêm kiểm device dạng văn bản;
    - lần 2: **24/24**. Đổi bộ đếm không làm fail; 17 đột biến (rule, policy, hook, prio, device, địa chỉ, cổng, MAC, verdict, bảng) đều bị phát hiện; ruleset nạp khớp `expected-ruleset.json` trong working tree (chưa commit).
- **06B-1R (sửa theo review)** ([`task06b1r-summary.md`](docs/evidence/task06b1r-summary.md)):
  - **Vòng đời QEMU:** dừng có xác nhận (SIGINT → chờ có hạn → SIGKILL → chờ có hạn); không xác nhận được thì không chạy V2 hay phase 2. Lỗi khi boot, cấu hình, phân tích, exfiltrate hoặc hủy đều dừng QEMU. Test bằng tiến trình giả thật (trì hoãn, bỏ qua SIGINT); 6 đột biến bị bắt, sau khi sửa lỗ hổng test do `pexpect.__del__`. **CT-03 chưa làm.**
  - **Transaction nft:** `load.nft` xóa và nạp ba bảng CT-01 trong một transaction, không flush namespace. Selftest **29/29**: lỗi cú pháp và lỗi commit trong kernel đều để lại bảng và bộ đếm cũ nguyên vẹn; bảng không liên quan vẫn còn.
  - **Ghim gói:** `nftables`/`libnftables1` `1.0.2-1ubuntu3.1`, `libnftnl11` `1.2.1-1build1`, `libjansson4` `2.13.1-1.1build3`; đã xác nhận trong image. Expected không đổi.
  - **Unit test:** 117 passed trên Python 3.12 (host) và **117 passed trên Python 3.10.12 trong image**.
  - **Phạm vi:** runtime chỉ đối chiếu ba bảng CT-01. Đề xuất mở rộng (allowlist bảng Docker lấy thực nghiệm) để duyệt riêng.
- **`expected-ruleset.json`:** sha256 `9fb32d7f…2b16`, sinh trong container kiểm thử từ `guest.nft` (`5892d2d7…fdce4`); nằm trong **working tree, chưa commit**; 06B-1R sinh lại cho kết quả giống hệt. **Reviewer đã đọc và chấp nhận nội dung ở mức trước guest**, cùng với bản sửa 06B-1R.
- **06B-2A: startup và V0 thật, chưa có guest** ([`task06b2a-summary.md`](docs/evidence/task06b2a-summary.md)):
  - `run.sh` thật chạy trong container test trên `sandboxnet` thật (privileged như Compose); server/poller được thay bằng sentinel; không chạy service worker, QEMU hay mẫu.
  - **V0 đạt [KC]:** `ISOLATION OK (V0 startup)` lúc `13:25:19.1107Z`, trước khi sentinel được gọi (`.1271Z`). Verify chạy lại trong container cũng đạt. Ruleset tại runtime giống hệt expected. sysctl, `tap0` (không master, không bridge), neighbor permanent và route đều đúng; `eth0` = `192.168.60.2` trên `sandboxnet`.
  - **Fail-closed [KC]:** `ALLOW_VM_INTERNET=true` → exit 1; `guest.nft` lỗi cú pháp → exit 1. Cả hai không gọi sentinel và không có QEMU.
  - Netns bị hủy sau `stop`/`rm` (SandboxKey và pid không còn).
  - Trạng thái host: route, firewall và sysctl không đổi. Các khác biệt đã giải thích: `nft_ct` được nạp do ruleset; bridge `sandboxnet` có thêm IPv6 link-local (Docker/kernel); chuỗi thời gian chạy.
  - Bảng ngoài CT-01 trong netns: `table ip nat` của Docker cho DNS nhúng `127.0.0.11`. Chưa làm allowlist.
  - **Hạn chế đã biết:** V0 của 06B-2A chỉ kiểm giá trị **cấu hình** của `tap0`, chưa kiểm giá trị hiệu lực. `rp_filter` hiệu lực khi đó là **2 (loose)** vì `conf.all.rp_filter=2`. Harness 06B-2A có ba hạn chế (cleanup theo tên, image chỉ WARNING, luôn exit 0). IPAM cấp `192.168.60.2` cho container test. Tất cả đã ghi trong [`task06b2a-summary.md`](docs/evidence/task06b2a-summary.md) §5a.
- **06B-2AR: sysctl hiệu lực** ([`task06b2ar-summary.md`](docs/evidence/task06b2ar-summary.md)):
  - Reviewer quyết định giữ `rp_filter` strict.
  - Theo kernel 6.8 (`inetdevice.h`): `rp_filter`/`arp_ignore`/`arp_announce`/`arp_accept` dùng `max(all, dev)`; `forwarding` chỉ lấy theo dev.
  - `run.sh`: `all.rp_filter=1`, `all.arp_ignore=0`, `all.arp_accept=0`; ghi báo cáo sysctl trước/sau. `verify` kiểm cả giá trị cấu hình và hiệu lực.
  - **[KC]** Trong worker thật, hiệu lực trên `tap0`: `rp_filter=1`, `arp_ignore=1`, `arp_announce=2`, `arp_accept=0`, `forwarding=0`. Trên `eth0`: `rp_filter` hiệu lực không đổi (2); `forwarding` 1 → 0 do `ip_forward=0`; `arp_*` không đổi.
  - Unit test **130 passed** (Python 3.12 và 3.10.12 trong image); 5 đột biến bị bắt. Harness đã sửa theo review: **ALL CHECKS PASSED**, `exit=0`; host không đổi.
  - **Reviewer chấp nhận 06B-2AR ở mức startup/V0.**
- **06B-2B: HTTP/API thật, chưa boot guest** ([`task06b2b-summary.md`](docs/evidence/task06b2b-summary.md)):
  - `server.py` thật, chỉ poller là sentinel; image đã review `d0bf9277…6f42`. V0 đạt trước khi uvicorn khởi động; `/healthcheck` 200; không có QEMU.
  - **ĐẠT theo phạm vi phép thử [KC]:** nguồn guest được **mô phỏng** bằng `10.200.0.2/32` trên `lo`, tức kiểm middleware HTTP, **không** kiểm lọc trên `tap0`. Kết quả 42/42:
    - ba route của task hiện tại trả 200, nội dung và upload khớp sha256;
    - thiếu `current_task`, task khác, sai phương thức, `/healthcheck`, `/stop`, `/submit-task`, `/docs`, `/openapi.json` đều trả 403;
    - header proxy giả bị bỏ qua;
    - không tạo task hay file stop;
    - peer `127.0.0.1` và `eth0` vẫn được 200.
  - Server ghi 25 dòng `guest request denied`, khớp với 25 phản hồi 403. Sau khi xóa địa chỉ mô phỏng: verify đầy đủ đạt, host không đổi.
  - **Phát hiện:** verify **không** phát hiện địa chỉ thuộc `10.200.0.0/30` nằm trên interface khác `tap0` (khi `10.200.0.2/32` ở trên `lo`, verify vẫn OK). Đã sửa ở 06B-2BR.
- **06B-2BR: địa chỉ guest nằm sai interface** ([`task06b2br-summary.md`](docs/evidence/task06b2br-summary.md)):
  - **Verify trước đợt này chưa kiểm điều kiện này**, nên mọi V0/verify từ 06B-1 đến 06B-2B đều không bao gồm nó. Evidence 06B-2B giữ nguyên. Phép thử HTTP qua `lo` vẫn chỉ chứng minh middleware.
  - `check_links` quét IPv4 trên mọi interface, kể cả `lo`. Chỉ cho phép `10.200.0.1/30` trên `tap0`; mọi địa chỉ khác nằm trong hoặc có dải trùng với `10.200.0.0/30` đều làm verify fail. Không có ngoại lệ runtime.
  - Unit test **142 passed** (Python 3.12 và 3.10.12 trong image); 4 đột biến bị bắt.
  - **[KC]** Container sentinel trên image `1ab784c7…9153`:
    - cấu hình đúng → OK;
    - `10.200.0.2/32` trên `lo`, `10.200.0.3/32` trên `eth0`, `10.200.1.5/16` trên `lo` → verify exit 1, thông báo nêu đúng địa chỉ;
    - `192.0.2.10/32` → OK;
    - địa chỉ sai có sẵn **trước** `run.sh` → V0 fail, exit 1, không gọi sentinel.
  - Harness: **ALL CHECKS PASSED**; host không đổi.
  - **Reviewer chấp nhận 06B-2BR ở mức trước guest.**
- **06B-3A: boot guest ARM/MIPS, liên kết dịch vụ** ([`task06b3a-summary.md`](docs/evidence/task06b3a-summary.md)):
  - Guest thật boot bằng đường mã thật (`ARCH_CONFIGS`, `_start_qemu`, `_configure_network`, `shutdown_qemu`), image OS gốc, đĩa tạm riêng, chạy tuần tự. `server.py` thật, poller sentinel. Không có `dynamic_analysis`, ELF hay mẫu. Verify trước boot là của harness, **không phải V1/V2**.
  - **Lần 1: exit 1** (giữ làm bằng chứng). Hai lỗi harness: parser `\r\r\n`; `/etc/hostname` không có trên MIPS. Thêm `ip-addr` của host đổi do IPv6 link-local trên bridge sau reboot. Không lỗi nào liên quan tới cô lập.
  - **Lần 2 [KC]: ALL CHECKS PASSED, ARM 37/37, MIPS 37/37:**
    - `info network` chỉ có backend `tap` `ifname=tap0` (không user/slirp); NIC gắn tap có MAC `52:54:00:c7:00:02`; guest `10.200.0.2/30`, gateway `10.200.0.1`;
    - từ guest: tải file 200 (hash tính trong guest khớp), upload strace/sar 200 (hash khớp); thiếu marker, `/healthcheck`, `/stop`, task khác đều 403; không có tác dụng phụ;
    - `allow_svc` = số gói guest→`10.200.0.1:8011` trong pcap `tap0` ở mọi nhóm (ARM 80, MIPS 77).
  - Quan sát (chưa có đối chứng): lưu lượng nền của guest — DHCP, DNS `8.8.8.8`, IPv6 — bị drop đúng bộ đếm `drop_spoof`/`drop_public`/`l2_bad_ethertype`; không có gói IPv4 nào tới guest từ nguồn khác `10.200.0.1`.
  - Host không đổi; không còn QEMU, tshark hay container test.
  - **Reviewer chấp nhận 06B-3A.**
- **06B-3B: ma trận chặn IPv4 có đối chứng, ARM rồi MIPS** ([`task06b3b-summary.md`](docs/evidence/task06b3b-summary.md)):
  - Guest thật như 06B-3A; `server.py` thật, poller sentinel; không có ELF hay mẫu; chỉ dùng `curl`/`nslookup` có sẵn trong guest. Không sửa source; working tree vẫn là tree `7232d94b…`.
  - Manager có sẵn chỉ được bật để làm đối chứng (`--no-deps --no-build`), rồi dừng về `exited`. Không bật service worker của Compose.
  - Cổng topology đạt trước khi gửi probe: `info network` chỉ có `nic`/`tap`, đúng một `tap0`, MAC đã ghim trên NIC gắn tap và trên interface probe (ARM `eth1`, MIPS `br-lan`).
  - **Lần 1–4 không đạt, giữ làm bằng chứng:** lỗi harness, và `tcpdump -Z root -w` segfault trên host. Lần 2–4 dừng **trước khi boot guest** vì capture phía host chưa chạy. Kết luận ban đầu rằng AppArmor gây crash là sai; chẩn đoán lần 3 cho thấy chỉ tổ hợp `-Z root` + `-w` crash.
  - **Lần 5 [KC]: ALL CHECKS PASSED, 20/20 probe ĐẠT (ARM 24/24, MIPS 24/24 check).** Mỗi probe đạt đủ 7 tiêu chí: guest thất bại; đối chứng cùng IP/giao thức/cổng sống trước và sau; gói probe có trong pcap `tap0`; đúng bộ đếm drop; delta bộ đếm = số gói pcap (> 0); **mọi** delta bộ đếm = phân loại pcap (tính cả retransmission và lưu lượng nền); không có cảnh báo trên host.
    - `drop_public`: `1.1.1.1:443/tcp`.
    - `drop_private`: `192.168.177.2:53` UDP và TCP; SSH `192.168.60.1`, `192.168.177.128`, `172.18.0.1`; manager `192.168.60.10:8011`; MongoDB `172.18.0.2:27017`; IP `eth0` của worker `192.168.60.2:8011`.
    - `drop_worker_other`: `10.200.0.1:18080`, với listener tạm đang sống.
    - Liên kết dịch vụ `10.200.0.1:8011` đạt cả trước và sau probe.
  - **Không thấy gói probe nào trong các pcap đã lưu phía host [KC]** (phạm vi diễn đạt sửa ở 06B-3DR): cảnh báo `-i any 'net 10.200.0.0/30'` bắt 0 gói. Pcap veth (3813 gói), bridge (7342) và `ens33` (90) đều có 0 gói mang MAC guest hoặc `10.200.0.0/30`, trong khi vẫn thấy gói đối chứng. Kiểm tra độc lập bằng tcpdump của host còn tìm thêm cổng nguồn probe, tên DNS probe và URL probe: cũng 0.
  - Host: chỉ `docker-ps` đổi (chuỗi thời gian do bật/dừng manager); mọi mục khác không đổi, kể cả `ip-addr`.
  - **Mức phủ so với thiết kế:** T07, T08, T09, T10 đạt về mạng. T05, T06, T11 mới phủ **một phần**: thiếu `8.8.8.8:53` UDP, ICMP, IP LAN thứ hai, và `10.200.0.1` cổng 22/80. Chi tiết: §5 của summary.
  - **Reviewer chấp nhận 06B-3B trong phạm vi 20 probe IPv4 đã thử.**
  - Phát hiện sau đó (06B-3C): regex URL của bước kiểm tra độc lập 06B-3B (`/ct01-06b3b-[0-9]`) không bao giờ khớp. Quét lại evidence lần 5 bằng `sigscan.sh` đã sửa: phía host vẫn 0 ở mọi chữ ký.
- **06B-3C / 06B-3CR: sửa harness — [Offline]** ([`task06b3c-summary.md`](docs/evidence/task06b3c-summary.md)):
  - Harness nằm ngoài repo. Không sửa source.
  - Các điểm sửa:
    - bộ tìm chữ ký `sigscan.sh` (regex URL đúng; đếm theo gói; lỗi đọc pcap là lỗi, không bao giờ là 0 gói);
    - bộ giám sát capture có heartbeat; mất capture, mất heartbeat hoặc có marker thì `CaptureLost`, exit 98;
    - ghi netns của worker trước/sau;
    - manager: giữ mã lỗi của Compose, `--no-recreate`, từ chối `created`, dừng bằng `docker stop <ID>` sau khi kiểm ID;
    - thống kê drop của tshark lấy từ khối ISB của pcapng (`pcapng_stats.py`); thiếu thống kê là CHƯA KIỂM CHỨNG, không phải "0 drop".
  - **[Offline]** self-test 68/68 (ổn định 3 lần). Mutation test: baseline đạt; 26/26 đột biến hành vi bị bắt đúng check; 2 đột biến đối chứng (cú pháp, thiếu phụ thuộc) được phân loại đúng.
  - Mutation test tìm ra lỗi trong chính các phép thử, đã sửa:
    - ca zombie mà bàn giao 06B-3C ghi là đã kiểm thực ra chưa từng được kiểm;
    - `pcapng_stats.py` ném `struct.error` với file bị cắt cụt.
  - **Reviewer chấp nhận mã và bằng chứng offline của 06B-3CR.**
- **06B-3D: tích hợp thật harness 06B-3CR, đúng 20 probe IPv4 của 06B-3B** ([`task06b3d-summary.md`](docs/evidence/task06b3d-summary.md)):
  - **[KC] Kết quả:** `exit=1`. ARM 10/10 probe ĐẠT; MIPS 9/10. Probe `internet-tcp` của MIPS **FAIL**: bộ đếm `l2_bad_ethertype` tăng 3, nhưng pcap trong cửa sổ chỉ có 2.
    - các gói của chính probe khớp (4 SYN, `drop_public` 8 = 8);
    - **giả thuyết (chưa chứng minh):** lỗi biên cửa sổ. Harness đọc bộ đếm trước rồi mới lấy `t0`, và ngay trước `t0` có hai gói IPv6 nền (0,8 ms và 29 ms). Lần chạy không ghi thời gian của lệnh nft, nên giả thuyết không kiểm được bằng dữ liệu này;
    - theo quy tắc của harness, probe này là FAIL.
  - **[KC] Phần tích hợp hoạt động đúng:**
    - self-test chạy dưới root trước khi tác động container;
    - heartbeat cập nhật suốt ARM/MIPS: tuổi tối đa 1,03 / 1,05 s qua 157 mẫu của bộ ghi mẫu chỉ đọc bên ngoài harness;
    - 4 tcpdump thoát với mã 0, `0 dropped by kernel`;
    - `pcapng_stats.py` trong container thật: ISB ARM 99/0, MIPS 125/0, ĐẠT; tshark 3.6.2;
    - netns trước/sau: chỉ `lo`, `eth0`, `tap0`; địa chỉ và route không đổi;
    - manager `exited` → `exited`, cùng ID `494ae3d2e2eb`;
    - dọn đúng 2 container do lần chạy tạo; không còn tiến trình nào.
  - **[KC] Không thấy chữ ký probe nào trong các pcap đã lưu phía host:**
    - cảnh báo `-i any` bắt 0 gói;
    - veth, bridge và `ens33` có 0 ở mọi chữ ký (MAC/IP guest, cổng probe, tên DNS probe, URL probe), trong khi bộ tìm vẫn thấy DNS đối chứng (8 gói);
    - phạm vi: chỉ các gói đã được ghi; các gói "received by filter" nhưng không được ghi thì không xem được.
  - **Phát hiện, đã báo cáo:**
    - tcpdump trên veth/bridge có "received by filter" lớn hơn "captured" (lệch 22 và 46 gói). **Chênh lệch chưa được giải thích**; suy luận trước đó về thời điểm của các gói thiếu đã bị rút lại.
    - `tap0`: `vnet_hdr off` → `on` sau khi chạy guest. Đây là **quan sát**, chưa kết luận là lỗi; verify không kiểm cờ này.
  - Chỉ được kiểm **[Offline]**, chưa tích hợp thật: các nhánh lỗi (`CaptureLost`, manager ban đầu `running`/`created`, Compose lỗi).
  - Reviewer đã review 06B-3D và yêu cầu sửa phép đo cùng cách diễn đạt (06B-3DR).
- **06B-3DR: sửa phép đo của harness — [Offline]** ([`task06b3dr-summary.md`](docs/evidence/task06b3dr-summary.md)):
  - **Cửa sổ bộ đếm** (`counter_window.py`):
    - mỗi lần đọc nft ghi `t_start`/`t_end` và JSON thô;
    - pcap được chia thành vùng chắc chắn và hai vùng biên mơ hồ (guard 20 ms, **giả định chưa đo**; mọi PASS của phép đối chiếu phụ thuộc vào giả định này);
    - có gói biên → CHƯA KIỂM CHỨNG và lần chạy không đạt (exit 4);
    - delta nằm ngoài khoảng cho phép → FAIL;
    - chỉ khớp chính xác, không mơ hồ mới PASS; không nới cửa sổ, không bù trừ.
  - **Teardown capture:**
    - ghi phiên bản tcpdump/libpcap và các mốc thời gian;
    - guest xong thì dừng đối chứng, chờ capture 3 s, rồi SIGINT với hạn 10 s (quá hạn thì kill và tính là FAIL);
    - giữ các check về mã thoát, lỗi đọc, drop và capture còn sống;
    - "received − captured" được báo là **mục mở** (exit 5), không dùng làm quy tắc PASS/FAIL.
  - **[Offline]** self-test 116/116 (ổn định 3 lần). Mutation test: baseline đạt; 37/37 đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại.
    - fixture "hai sai lệch triệt tiêu nhau" cho thấy cách đo cũ báo PASS nhầm, còn cách đo mới báo CHƯA KIỂM CHỨNG;
    - phát lại `evaluate()` thật với dạng dữ liệu của 06B-3D → CHƯA KIỂM CHỨNG.
  - Hồ sơ 06B-3D/3B được sửa diễn đạt cho đúng phạm vi; pcap và log giữ nguyên.
  - **Chưa chạy tích hợp với harness 06B-3DR.**
  - Reviewer tái hiện 2 lỗ hổng: (1) thiếu công cụ/đối chứng che mất FAIL đã xác định; (2) dữ liệu thời gian hoặc guard không hợp lệ vẫn có thể ra PASS. Summary 06B-3DR được đính chính hai khẳng định quá mức.
- **06B-3DR1: sửa hai lỗ hổng kết luận — [Offline]** ([`task06b3dr1-summary.md`](docs/evidence/task06b3dr1-summary.md)):
  - **Tái hiện trên bản 06B-3DR:** đối chiếu FAIL hoặc cảnh báo host, kèm thiếu công cụ hoặc thiếu đối chứng, đều thành CHƯA KIỂM CHỨNG. Thời gian Infinity, hai lần đọc đảo ngược, guard âm đều ra **PASS**. Bản sửa cho ra FAIL ở các ca đầu và ERROR ở các ca sau.
  - **`probe_verdict()`:** lỗi đã xác định (`determined_failures`) luôn thành FAIL trước. Sau đó đến dữ liệu đo không hợp lệ → LỖI PHÉP ĐO (lần chạy FAIL). Rồi đến thiếu công cụ / thiếu đối chứng / gói biên → CHƯA KIỂM CHỨNG. Check phía guest không tính là lỗi khi guest thiếu công cụ; check tính từ cửa sổ không tính là lỗi khi dữ liệu đo không hợp lệ.
  - **`reconcile()`:** kiểm thời gian hữu hạn và đúng thứ tự `A.start ≤ A.end ≤ B.start ≤ B.end`, guard hữu hạn và không âm, thời gian gói hữu hạn, delta là số nguyên không âm. Sai thì ERROR, không bao giờ PASS.
  - **[Offline]** self-test 143/143 (ổn định 3 lần). Mutation test: baseline đạt; 48/48 đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại. Phép thử phát lại `evaluate()` thật đã bắt thêm một lỗi trong chính bản sửa (cửa sổ đảo ngược báo FAIL thay vì LỖI PHÉP ĐO); lỗi này đã được sửa.
  - **Reviewer chấp nhận mã và bằng chứng offline của 06B-3DR1.**
- **06B-3E: tích hợp thật harness 06B-3DR1, một lần, đúng 20 probe IPv4** ([`task06b3e-summary.md`](docs/evidence/task06b3e-summary.md)):
  - Trước khi chạy: tree `ecf2ae7d…`; 12/12 hash harness khớp; image ID khớp; self-test 143/143 (user thường) và đạt dưới root trước khi tác động container. Guard giữ 20 ms. **Không chạy lại.**
  - **[KC] Kết quả: `exit=4` (NOT PASSED, chưa kiểm chứng).** 16/20 probe ĐẠT; 4 CHƯA KIỂM CHỨNG do có gói ở biên cửa sổ bộ đếm (ARM `ssh-host-172.18.0.1`, `manager`; MIPS `internet-tcp`, `lan-dns-tcp`). **0 FAIL, 0 LỖI PHÉP ĐO**; `determined_failures` rỗng ở mọi probe.
    - Cả 4 gói biên đều là lưu lượng nền của guest thuộc lớp bị drop: DHCP (cùng một gói, nằm ở biên của hai probe ARM liền nhau), IPv6 MLD, và DNS tới `8.8.8.8`. Delta nằm trong khoảng cho phép, nên không có lệch thật.
    - Gói của chính probe nằm trong vùng chắc chắn ở cả 20 probe (kiểm sau lần chạy). Lớp dự kiến của 4 probe CHƯA KIỂM CHỨNG đối chiếu khớp chính xác. Đây là quan sát, không đổi kết luận.
    - Thời gian một lần đọc nft: 4,8–18,4 ms. Độ trễ capture → bộ đếm (giả định guard 20 ms) **vẫn chưa đo**.
  - **[KC] Capture và teardown:**
    - tcpdump 4.99.4 / libpcap 1.10.4 (TPACKET_V3); captured = received by filter ở cả 4 capture, drop 0, **không có mục mở**;
    - teardown đúng trình tự, 4 capture thoát với rc 0 trước hạn;
    - ISB `tap0` ARM 83/0, MIPS 125/0;
    - heartbeat tuổi tối đa 1,05/1,06 s (bộ ghi mẫu ngoài harness); không có `CaptureLost`.
  - **[KC] Không thấy chữ ký probe nào trong các pcap đã lưu phía host:** cảnh báo bắt 0 gói; veth, bridge và `ens33` có 0 ở mọi chữ ký, trong khi vẫn thấy DNS đối chứng.
  - **Manager:** `exited` → `exited`, cùng ID `494ae3d2e2eb`. Đã dọn đúng 2 container; ruleset tại runtime giống hệt expected.
  - **Host:** các check hard không đổi. Báo cáo thêm:
    - IPv6 link-local và route `fe80::/64` mới trên bridge `sandboxnet` (host đã khởi động lại khoảng 2 giờ trước; giống 06B-2A và 06B-3A lần 1);
    - module `nft_ct` được nạp (giống 06B-2A);
    - netns worker: `vnet_hdr off→on` (quan sát).
  - Cách xử lý tỷ lệ gói biên (4/20) cần reviewer quyết định; không tự tăng guard hay chạy lại.
  - **Reviewer chấp nhận báo cáo 06B-3E đúng phạm vi exit 4.**
- **06B-3F: đối chiếu bộ đếm toàn phiên guest — [Offline]** ([`task06b3f-summary.md`](docs/evidence/task06b3f-summary.md)):
  - **Trình tự đo, mỗi kiến trúc một lần:**
    - đọc bộ đếm nền (có mốc thời gian) **trước khi spawn QEMU**, sau khi xác nhận capture/heartbeat còn sống và chưa có QEMU;
    - tshark capture liên tục qua boot, liên kết dịch vụ và các probe;
    - **sau khi xác nhận QEMU đã thoát:** đọc 2 snapshot cuối (mỗi lần chờ 0,5 s), lưu cả hai, trước khi dừng tshark;
    - đối chiếu toàn bộ gói guest trong pcap với delta từng lớp ingress. Các lớp chưa đối chiếu (ARP, input/forward, chiều ra) được liệt kê kèm delta và lý do.
  - **Kết luận toàn phiên** (`session.json`):
    - ERROR: điều kiện tiên quyết hoặc dữ liệu thời gian sai;
    - FAIL: lệch thật;
    - CHƯA KIỂM CHỨNG: gói ở biên đầu/cuối, capture không đầy đủ, bộ đếm còn đổi sau khi QEMU thoát, hoặc gói guest sau khi QEMU thoát;
    - PASS chỉ khi không có điều kiện nào ở trên.
  - **Báo cáo riêng:** không vào kết luận từng probe, không đổi `run_outcome()` hay mã thoát. Toàn phiên PASS không che FAIL, lỗi capture hay probe CHƯA KIỂM CHỨNG.
  - Guard 20 ms giữ nguyên; giả định chưa được đo, ghi trong `session.json`. Không tắt DHCP/IPv6/DNS của guest, không thêm probe.
  - **[Offline]** self-test 171/171 (ổn định 3 lần). Mutation test: baseline đạt; 60/60 đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại.
  - **Đính chính:** việc hai biên của cửa sổ phiên không có gói guest chỉ là **kỳ vọng thiết kế**, chưa phải điều đã kiểm. Nó phải được kiểm bằng trạng thái tiến trình và pcap. Hai chỗ hở của mã hiện tại:
    - gói guest trước biên đầu bị bỏ qua (vùng "ngoài cửa sổ");
    - `qemu_pids_after_exit` chỉ được ghi lại, không dùng trong kết luận.
    - Chưa sửa; cần reviewer quyết định.
  - **Chưa chạy tích hợp phép đo toàn phiên** (không chạy Docker/QEMU).
  - **Review:** reviewer đọc patch, xác nhận hash và tái hiện 4 trường hợp báo PASS sai. 06B-3F **còn lỗi, chưa được chấp nhận để chạy tích hợp**.
- **06B-3FR: sửa tính đầy đủ của phép đo toàn phiên — [Offline]** ([`task06b3fr-summary.md`](docs/evidence/task06b3fr-summary.md)):
  - **Tái hiện trên bản 06B-3F:** cả 11 ca hồi quy đều báo **PASS** sai. Bản 06B-3FR cho đúng kết quả mong đợi ở cả 11 ca.
  - **(1) Gói guest trước cửa sổ:** kiểm toàn bộ pcap, kể cả ARP và lớp chưa đối chiếu. Mọi gói guest có timestamp ≤ `A.end` được ghi vào `session.json` kèm timestamp, lớp và lý do; có gói như vậy thì không PASS.
  - **(2) QEMU sau khi thoát:** `qemu_pids_after_exit` đi qua `evaluate_session()` thật và vào kết luận. Còn QEMU hoặc không xác minh được → ERROR. `pids_before` phải là danh sách rỗng.
  - **(3) Lần đọc cuối:** bắt buộc đủ F1 và F2; `final_read_error` → ERROR. Mọi lần đọc và lỗi được giữ.
  - **(4) Bộ đếm:** A, F1, F2 phải có đủ lớp được đối chiếu; thiếu → ERROR (bỏ `get(k, 0)`). Vẫn kiểm số nguyên không âm và thứ tự thời gian.
  - **[Offline]** self-test 195/195 (ổn định 3 lần). Mutation test: baseline đạt; 71/71 đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại. Ở lần 1, đột biến SE1 bị bắt ở ca khác ca được nhắm (vì quy tắc mới cũng bao biên đầu); đã đổi mục tiêu sang `edge-end` và chạy lại toàn bộ.
  - Guard 20 ms giữ nguyên; giả định chưa đo. Kết quả toàn phiên vẫn báo riêng: không đổi kết luận probe, `run_outcome()` hay mã thoát.
  - Còn mở: delta của đối chiếu từng probe vẫn dùng `get(k, 0)`, chưa rà theo tiêu chí mới.
  - **Chưa chạy tích hợp.**
  - **Review:** reviewer xác nhận phần đối chiếu, nhưng tái hiện được: `qemu_pids()` gặp `PermissionError` khi đọc `/proc/<pid>/comm` thì trả `[]`, nên toàn phiên PASS sai. Lỗi bị nuốt **bên trong** hàm quét, trước khi tới bên gọi.
- **06B-3FR1: không nuốt lỗi khi quét tiến trình QEMU — [Offline]** ([`task06b3fr1-summary.md`](docs/evidence/task06b3fr1-summary.md)):
  - **Tái hiện trên bản 06B-3FR:** `PermissionError` mô phỏng trên `/proc` thật → `qemu_pids()` trả `[]` → toàn phiên **PASS**. Bản 06B-3FR1: `ProcessScanError`, lỗi được ghi lại → **ERROR**.
  - **`qemu_pids()`:**
    - chỉ bỏ qua PID đã biến mất (`FileNotFoundError`/`ProcessLookupError` **và** thư mục `/proc/<pid>` không còn);
    - `PermissionError`, lỗi đọc khác, `comm` thiếu trong khi thư mục PID còn, hoặc không liệt kê được `/proc` → ném `ProcessScanError` lên bên gọi.
  - **`record_qemu_scan()`** (dùng cho cả lần quét trước boot và sau khi thoát) ghi pid hoặc lỗi vào phiên, không ném tiếp, nên khối `finally` vẫn dọn dẹp. `no_qemu_before` chỉ True khi danh sách đúng bằng `[]`. Có lỗi quét → toàn phiên ERROR.
  - **[Offline]** self-test 205/205 (ổn định 3 lần). Các ca mới gọi chính `qemu_pids()`/`record_qemu_scan()` trên `/proc` giả: quét sạch, có QEMU, PID biến mất, `comm` thiếu, `PermissionError` (trước boot và sau khi thoát), lỗi `EIO`, `/proc` không liệt kê được. Mỗi ca đi qua `evaluate_session()` thật; không ca nào đưa sẵn trường lỗi vào phiên.
  - Mutation test (toàn bộ bộ đột biến trên bản mới): baseline đạt; 76/76 đột biến hành vi bị bắt đúng check; 2 đối chứng đúng loại; hash khớp trước và sau.
  - **Lần chạy bị mất:** lần self-test/mutation đầu tiên chạy trong `/tmp`. Lệnh mutation báo kết thúc mã 0 nhưng output chưa được đọc trước khi máy tắt; khởi động lại đã xóa `/tmp`, nên mọi log của lần đó mất và lần đó không được dùng làm bằng chứng. Self-test, tái hiện và mutation đã được chạy lại một lần trên đúng mã hiện tại, log nằm trong `/home`.
  - Guard 20 ms giữ nguyên; kết quả toàn phiên vẫn báo riêng; mã thoát không đổi. **Chưa chạy tích hợp.**
  - **Reviewer chấp nhận 06B-3FR1 ở mức offline.**
- **06B-3G: tích hợp thật phép đo toàn phiên (harness 06B-3FR1), một lần, đúng 20 probe IPv4** ([`task06b3g-summary.md`](docs/evidence/task06b3g-summary.md)):
  - Trước khi chạy: tree `77ac4c37…` (bàn giao 06B-3FR1); 12/12 hash harness khớp; image ID đầy đủ khớp; không có QEMU/capture/harness đang chạy; không có `out` cũ. Self-test 205/205 dưới root trước khi tác động container. Guard giữ 20 ms, lưu lượng nền guest giữ nguyên. **Không chạy lại.**
  - **[KC] Kết quả: `exit=4` (NOT PASSED, chưa kiểm chứng).** ARM 10/10 ĐẠT; MIPS 9/10 ĐẠT, 1 CHƯA KIỂM CHỨNG (`ssh-host-192.168.60.1`). **0 FAIL, 0 LỖI PHÉP ĐO**; `determined_failures` rỗng ở mọi probe.
    - Gói biên: DNS nền của guest tới `8.8.8.8:53` (lớp `drop_public`), nằm **bên trong** lần đọc A. Lớp dự kiến của probe khớp chính xác; delta nằm trong khoảng cho phép, nên không có lệch thật.
    - Gói của chính probe nằm trong vùng chắc chắn ở cả 20 probe (kiểm sau lần chạy).
    - Thời gian một lần đọc nft: 4,3–16,7 ms. Độ trễ capture → bộ đếm (giả định guard 20 ms) **vẫn chưa đo**.
  - **[KC] Toàn phiên (báo riêng, không đổi kết luận probe hay mã thoát): ARM PASS, MIPS PASS.**
    - Quét QEMU trước boot và sau khi thoát đều thành công: `[]`, không lỗi. QEMU thoát được xác nhận. Đủ F1 và F2, hai lần giống nhau.
    - Không có gói guest trước cửa sổ hay sau khi thoát; ISB `tap0` 97/0 và 125/0. 9 lớp đối chiếu khớp chính xác với pcap, không có gói biên.
    - Kiểm chéo độc lập sau lần chạy: JSON nft thô của A/F1/F2 khớp `session.json`; tổng khung guest theo tcpdump bằng tổng delta (ARM 85, MIPS 113).
    - Toàn phiên PASS **không** đổi probe CHƯA KIỂM CHỨNG thành ĐẠT: nó không quy được gói biên về đúng một probe.
    - Nhánh lỗi của quét QEMU không xảy ra trong lần chạy này; nhánh đó chỉ được kiểm offline.
  - **[KC] Capture và teardown:** captured = received by filter ở cả 4 capture, drop 0, **không có mục mở**; teardown đúng trình tự, 4 capture thoát với rc 0 trước hạn. Heartbeat: đạt ở 4 mốc kiểm của harness; lần này không chạy bộ ghi mẫu ngoài harness.
  - **[KC] Không thấy chữ ký probe nào trong các pcap đã lưu phía host:** cảnh báo bắt 0 gói; veth, bridge và `ens33` có 0 ở mọi chữ ký, trong khi vẫn thấy DNS đối chứng. Đối chứng: 3 × 332 lần kiểm, 0 lỗi.
  - **Manager:** `exited` → `exited`, cùng ID `494ae3d2e2eb`. Đã dọn đúng 2 container; ruleset tại runtime giống hệt expected.
  - **Host:** các check hard không đổi. Báo cáo thêm, giống 06B-3E: IPv6 link-local và route `fe80::/64` mới trên bridge `sandboxnet` (host khởi động lại lúc 15:08); module `nft_ct`; netns worker `vnet_hdr off→on` (quan sát).
  - Cách dùng kết quả toàn phiên trong nghiệm thu, và cách xử lý gói biên, cần reviewer quyết định; không tự tăng guard hay chạy lại.
  - **Reviewer đã kiểm tra và chấp nhận 06B-3G đúng phạm vi.** Không chạy lại ma trận IPv4 để tìm exit 0; giữ nguyên 19/20 ĐẠT, 1 CHƯA KIỂM CHỨNG, toàn phiên ARM/MIPS PASS.
- **06B-4A: kế hoạch kiểm thử phần CT-01 còn thiếu — chỉ đọc mã, chưa chạy** ([`docs/ct01-remaining-tests-plan.md`](docs/ct01-remaining-tests-plan.md)):
  - Đối chiếu với thiết kế §4.3/§4.4/§7. Với T12 (broadcast/multicast), T13 (IPv6), T14–T15 (ARP sai đích, ARP giả), T16 (đổi MAC), T17 (giả IP nguồn), T20 (vào guest), kế hoạch ghi: chuẩn bị và công cụ; gói, đích, điểm chặn, bộ đếm; đối chứng hoặc "kiểm quy tắc"; chữ ký trên `tap0` và host (gồm chữ ký giả MAC/IP); khôi phục guest và liên kết dịch vụ; điều kiện ĐẠT/FAIL/CHƯA KIỂM CHỨNG và phần chưa phủ.
  - **[Tĩnh]** Danh mục ảnh guest (debugfs, không boot; [`task06b4a/guest-static-inventory.txt`](docs/evidence/task06b4a/guest-static-inventory.txt)): ARM OpenWrt 18.06.1 / BusyBox 1.28.3, MIPS OpenWrt SNAPSHOT / BusyBox 1.37.0. Cả hai có `ping`, `ping6`, `ip`, `nc`, `curl`; **không có `arping`**, Python hay tcpdump. Vì vậy ARP giả kiểu reply cần quyết định của reviewer về công cụ; ARP request sai đích và gratuitous ARP tạo được bằng kernel guest.
  - **Điểm lệch so với thiết kế được ghi rõ:**
    - `10.200.0.3` là broadcast của `/30`, nên không dùng làm đích ARP;
    - broadcast subnet vào `drop_private`, DHCP vào `drop_spoof`;
    - harness chưa phân lớp `l2_bad_mac` và chưa ánh xạ bộ đếm ARP; pcapng `tap0` không có cờ hướng ([KC] 06B-3G);
    - capture `ens33` và cảnh báo của harness chưa bao chữ ký giả;
    - gói `drop_out` không quan sát được trên `tap0`.
  - **Ánh xạ bộ đếm ARP đề xuất:** `arp_in_ok`/`arp_in_drop` theo đúng các trường của luật; lớp riêng cho ARP không tới hook (MAC đích khác, `hlen`/`plen` sai) theo mã `arp_rcv` upstream (chưa kiểm trên kernel host); `arp_out_drop` chỉ có bằng chứng bộ đếm.
  - Liệt kê riêng các mục IPv4 (phần còn lại của T05/T06/T11, T01/T02 trong luồng thật, T18, T19, đề xuất ngoài ma trận) và fail-closed (F3–F6, A7/A15, §6.1a), **chưa triển khai**. Có 12 giả định mới và 7 câu hỏi cho reviewer (D1–D7).
  - Không chạy Docker/QEMU, không sửa harness hay source, không viết probe mới.
  - **Reviewer chấp nhận hướng kế hoạch**, với các quyết định:

    | ID | Quyết định |
    |---|---|
    | D1 | chưa nạp công cụ mới |
    | D2 | cho thay đổi guest tạm, có khôi phục |
    | D3 | chỉ tra route trên host/manager |
    | D4 | thiết kế container `NET_ADMIN` riêng, chưa chạy |
    | D5 | hoãn giả MAC bằng `TAP_MAC` |
    | D6 | nhãn "ĐẠT (kiểm quy tắc)" |
    | D7 | `ens33` bắt không lọc, có hạn |
- **06B-4B: chuẩn bị harness đo L2/ARP/IPv6 — [Offline]** ([`task06b4b-summary.md`](docs/evidence/task06b4b-summary.md)):
  - **Sửa kế hoạch:**
    - T17-P3 hoãn: `10.200.0.1/32` trên guest tạo route cục bộ, gói không qua `tap0`;
    - bảng cổng và chữ ký thống nhất;
    - neighbor khôi phục theo trạng thái trước phép thử;
    - T20 tách lần gọi gửi, `errno` và bằng chứng bộ đếm;
    - script inventory dùng scratch `mktemp` mới;
    - danh mục BusyBox ghi rõ là bằng chứng tĩnh.
  - **[KC] Phát hiện trên pcap 06B-3G:**
    - Kết nối đối chứng hợp lệ dùng cổng tạm `42172`, trùng cổng probe dự kiến. Cổng probe mới chuyển xuống **31000–31299**, ngoài dải cổng tạm `32768–60999`.
    - `ether host` không biên dịch được trên `-i any` (LINUX_SLL2), nên cảnh báo theo MAC chạy trên veth.
  - **Harness mới `ct01-06b4b`** (bản 06B-3FR1 giữ nguyên, hash khớp):
    - `signatures.py`: registry chữ ký;
    - `l2frames.py`:
      - bộ đọc pcap/pcapng, lỗi đọc không bao giờ thành 0;
      - phân biệt khung guest / MAC giả đã chọn / chiều worker (không tuyên bố phủ guest giả `TAP_MAC`);
      - ánh xạ ARP (`arp_in_ok`, `arp_in_drop`, lớp riêng `arp_not_hooked`), `ip_not_hooked`, `unmapped`, nhận diện IPv6;
      - đối chiếu chặt, không mặc định bộ đếm thiếu bằng 0;
      - nhãn "ĐẠT (kiểm quy tắc)";
    - `guest_state.py`: lưu/khôi phục trạng thái guest;
    - `sigscan_l2.py`: chữ ký MAC/IP giả, ARP, IPv6, cổng probe;
    - run script: `ens33` không lọc có giới hạn, hai cảnh báo từ registry, quét `sigscan_l2`. Cùng 20 probe, không thêm probe.
  - **[Offline] Kiểm thử:**
    - self-test L2 **167/167** (147 fixture dương/âm/lỗi + 20 hồi quy trên pcap 06B-3G), ổn định 3 lần;
    - mutation L2: **56/56** đột biến bị bắt đúng test, 2 đối chứng đúng loại;
    - self-test cũ 205/205 trên bản mới; mutation cũ trên bản mới: 76/76 + 2 đối chứng đúng loại.
  - **Hồi quy 06B-3G:**
    - phân lớp mới tái hiện đúng số khung của `session.json` và `matrix.json`, kết luận cũ không đổi;
    - thêm ARP vào phép đo toàn phiên vẫn PASS (2 khung = delta 2);
    - mọi chữ ký mới = 0 trên pcap host.
  - Giả định [Kernel] (`arp_rcv`, `ip_rcv`, điểm bắt, link down xóa neighbor) **chưa kiểm thực tế**. Chưa chạy Docker/QEMU, chưa viết probe mới.
  - **Review:** reviewer tái hiện được: ICMP 1705 byte sau NAT, lưu đủ thì `icmp_size=1`, nhưng pcap lưu 512 byte (độ dài gốc đủ) thì mọi chữ ký = 0. `decode()` coi IPv4 bị cắt là không hợp lệ và bộ quét bỏ qua cả gói.
- **06B-4BR: chữ ký trên capture bị cắt bởi snaplen — [Offline]** ([`task06b4br-summary.md`](docs/evidence/task06b4br-summary.md)):
  - **Tái hiện:** bản 06B-4B cho `icmp_size=0` ở bản cắt 512 byte; bản sửa cho `icmp_size=1`, `truncated_frames=1`.
  - **Phân biệt ba trường hợp:**
    - gói bị cắt bởi snaplen (captured < original): đọc mọi header đã lưu đủ;
    - file hỏng (captured > original, bản ghi vượt cuối file): lỗi đọc, exit 2;
    - gói dị dạng trên dây: header đủ byte vẫn đọc, không coi là bị cắt.
  - **`sigscan_l2`:** thêm `truncated_frames` (thông tin), `unscannable_truncated` và `unscannable_undecoded`. Hai khóa unscannable phải bằng 0 trong run script, nên dữ liệu thiếu không âm thầm thành "không có chữ ký".
  - **Bộ phân lớp `tap0` vẫn chặt:** khung bị cắt → `unmapped` → CHƯA KIỂM CHỨNG.
  - **[Offline]:**
    - self-test L2 **195/195** (25 test mới: ICMP/TCP/UDP/DNS sau NAT đầy đủ và bị cắt, header thiếu, gói dị dạng, file hỏng, `tap0`), ổn định 3 lần;
    - mutation L2 **69/69** + 2 đối chứng (13 đột biến mới);
    - self-test cũ 205/205; mutation cũ: 76/76 + 2 đối chứng (chạy lại vì run script đổi).
  - **Reviewer chấp nhận 06B-4BR ở phạm vi offline.**
- **06B-4C: tích hợp thật harness 06B-4BR, một lần, đúng 20 probe IPv4** ([`task06b4c-summary.md`](docs/evidence/task06b4c-summary.md)):
  - Trước khi chạy: tree `0700d55e…`, HEAD `3c54d55`; 18/18 hash harness khớp; image ID đầy đủ khớp; không có gì tồn đọng; manager ban đầu `exited` `494ae3d2e2eb`. Self-test trong harness 205/205 và L2 175/175. **Không chạy lại.**
  - **[KC] Kết quả: `exit=4`.** 17/20 ĐẠT; 3 CHƯA KIỂM CHỨNG; **0 FAIL, 0 LỖI PHÉP ĐO**.
    - `lan-dns-tcp` ở ARM và MIPS: đối chứng `192.168.177.2:53/tcp` không sống. Trên `ens33` thấy gateway LAN trả RST: môi trường thay đổi so với 06B-3G, không phải lỗi harness.
    - MIPS `lan-dns-udp`: 2 gói DNS nền của guest nằm trong lần đọc B.
  - **[KC] Toàn phiên (báo riêng): ARM PASS, MIPS PASS.**
  - **[KC] Capture và bộ quét mới hoạt động trên môi trường thật:**
    - 5 capture (veth, bridge, `ens33`, cảnh báo `any`, cảnh báo Ethernet trên veth) đều captured = received, drop 0, thoát rc 0 trước hạn;
    - `ens33` không lọc, snaplen 512 (589 khung, 7 khung bị cắt), chưa chạm giới hạn 200 000;
    - áp offline hai bộ lọc cảnh báo lên `tap0` cho thấy chúng khớp lưu lượng guest thật (không mù), và cho 0 trên mọi pcap host;
    - `sigscan.sh` và `sigscan_l2.py` đều 0 ở mọi chữ ký; `ens33` có `truncated_frames=7`, `unscannable_truncated=0`, `unscannable_undecoded=0`.
  - **Quan sát ARP/L2 bằng module mới** (lưu lượng có sẵn, **chưa phải ma trận probe mới**): toàn phiên 13 lớp PASS; ARP guest 3/2 khung = delta `arp_in_ok`; `arp_out_ok` khớp; không có khung không bộ đếm.
  - Manager về `exited`, cùng ID; đã dọn đúng 2 container; host: các check hard không đổi. Còn lại `ct01-06b4b/__pycache__/` thuộc root (sản phẩm phụ của Python chạy dưới root), ghi lại.
  - Không phát hiện lỗi harness. Cách xử lý đối chứng TCP/53 của gateway LAN cần reviewer quyết định.
  - **Reviewer chấp nhận 06B-4C trong phạm vi kiểm tích hợp harness.**
- **06B-4D1: bộ đánh giá L2/ARP offline từ file capture — [Offline]** ([`task06b4d1-summary.md`](docs/evidence/task06b4d1-summary.md)):
  - **Chỉ hoàn thiện bộ phân tích offline. Chưa triển khai hay kiểm chứng T12–T15.** Không có lệnh probe, không điều khiển guest, không gửi gói. Không sửa run script hay `probe_matrix.py`.
  - Bản làm việc `ct01-06b4d1`: thêm `l2eval.py` cùng test và mutation; 18 file còn lại giống hệt 06B-4BR; bản 06B-4BR và evidence 06B-4C không đổi.
  - **`l2eval.py`:**
    - đầu vào: capture, `counters-raw.jsonl`, nhãn hai lần đọc, `TAP_MAC`;
    - đầu ra JSON: số khung theo lớp, delta, gói biên, khung không bộ đếm, bộ đếm không đối chiếu (thiếu thì `delta: null`, không thành 0), lý do kết luận;
    - capture không đọc được hoặc dữ liệu đo không hợp lệ → ERROR (exit 2), JSON vẫn được ghi.
  - **[Offline]:**
    - self-test 46/46 (PASS, FAIL, UNVERIFIED, lỗi đọc capture, 16 ca dữ liệu đo không hợp lệ, CLI; phát lại 06B-4C), ổn định 3 lần;
    - mutation 13/13 + 2 đối chứng;
    - `selftest_l2` 195/195.
  - **Phát lại 06B-4C (chỉ đọc):** đối chiếu phiên và từng probe bằng kết quả đã ghi; thêm ARP vẫn PASS. Kết luận probe đã bàn giao không đổi.
  - **Review:** reviewer tái hiện 2 lỗi đầu vào: `classes=[]` trả PASS với `per_class` rỗng; JSON bộ đếm sai cấu trúc (`counter: null`, `nftables: null`, `counter: []`) gây crash thay vì ERROR.
- **06B-4D1R: sửa hai lỗi đầu vào của bộ đánh giá offline — [Offline]** ([`task06b4d1r-summary.md`](docs/evidence/task06b4d1r-summary.md)):
  - **Tái hiện:** bản 06B-4D1 cho PASS và 3 exception. Bản sửa trả ERROR có lý do cho cả 4 ca.
  - **Danh sách lớp:** phải khác rỗng, không trùng, là tên lớp hợp lệ; tập con hợp lệ vẫn được. CLI không còn lọc âm thầm (`--classes ""` → exit 2).
  - **JSON bộ đếm:** kiểm kiểu ở từng cấp (dòng, `raw`, output nft, `nftables`, phần tử, `counter`, `name`/`packets`). Sai → `InputError` → ERROR, exit 2, JSON vẫn ghi. Phần tử sai kiểu không bị bỏ qua; dữ liệu thiếu không thành 0.
  - **[Offline]:**
    - self-test 72/72 (24 test mới gọi `evaluate()` và CLI thật), ổn định 3 lần;
    - mutation 26/26 + 2 đối chứng (13 đột biến mới);
    - JSON phát lại 06B-4C giống hệt bản trước.
  - 18 file harness cũ, run script, `probe_matrix.py` và evidence cũ không đổi. **Chưa triển khai T12–T15.**
  - **Reviewer chấp nhận bộ phân tích 06B-4D1R.**
- **06B-4E: chuẩn bị offline kiểm tra T12–T13 bằng `ping`/`ping6` có sẵn trong guest — [Offline]** ([`task06b4e-summary.md`](docs/evidence/task06b4e-summary.md)):
  - **Chỉ chuẩn bị và kiểm offline; chưa chạy trên guest. T12–T13 chưa được kiểm chứng.** Không ARP giả mạo, không đổi MAC/IP, không gói thô, không thêm công cụ.
  - Bản làm việc `ct01-06b4e`: thêm `icmp_cases.py` cùng test và mutation; 21 file còn lại giống hệt 06B-4D1R. Chưa nối vào run script hay `probe_matrix.py`.
  - **5 ca**, kích thước lấy từ `signatures.py`:
    - T12-B1 `255.255.255.255`, T12-B2 `224.0.0.1` → `drop_bcast_mcast`;
    - T12-B4 `10.200.0.3` → `drop_private`;
    - T13-I1 `ff02::1`, T13-I2 link-local của `TAP_MAC` (chỉ có NS) → `l2_bad_ethertype`.
  - **Thực thi** (đã viết, chưa gọi): kiểm liên kết dịch vụ trước nhóm (không đạt thì không chạy) → mỗi ca đọc A / ping / đọc B → kiểm liên kết sau nhóm.
  - **Đánh giá:** dùng `l2frames`/`l2eval`/`reconcile_l2`/`probe_verdict_l2` đã review, đối chiếu đủ 13 lớp. Kết quả tách bạch: FAIL, LỖI PHÉP ĐO, LỖI THỰC THI, KHÔNG TẠO ĐƯỢC GÓI, CHƯA KIỂM CHỨNG, ĐẠT (kiểm quy tắc).
    - Timeout hay không có gói **không** phải bằng chứng chặn;
    - lưu lượng nền không thay cho probe;
    - kết quả luôn là `rule_check`, không bao giờ "ĐẠT" trơn.
  - **[Offline]:** self-test 55/55 (đi qua hàm đánh giá thật), ổn định 3 lần; mutation 19/19 + 2 đối chứng; `selftest_l2eval` 72/72; `selftest_l2` 175/175.
  - **Review:** reviewer tái hiện 2 lỗi:
    - `evaluate_group()` vẫn cho ĐẠT khi `service_link_before.ok=False` nếu record có `cases` và không có `skipped`;
    - fixture NS của T13-I2 có target `cdcd…` mà vẫn được tính là probe, vì chỉ khớp nhóm solicited-node.
- **06B-4ER: sửa hai lỗi đánh giá của 06B-4E — [Offline]** ([`task06b4er-summary.md`](docs/evidence/task06b4er-summary.md)):
  - **Tái hiện:** bản 06B-4E cho ĐẠT ở cả 2 ca. Bản sửa: CHƯA KIỂM CHỨNG (liên kết trước nhóm) và "không tạo được gói" (`probe_frames=0`).
  - **Liên kết trước nhóm:** đánh giá từ record, chỉ đạt khi `ok` đúng bằng `True`; không dựa riêng vào `skipped`. FAIL đã xác định vẫn được báo.
  - **NS:** `l2frames.decode` (module dùng chung, chỉ bổ sung trường `ns_target`, phân lớp không đổi) giải mã target. NS chỉ là probe khi target đúng là link-local của `TAP_MAC` và gửi đúng nhóm. Fixture NS mới đúng RFC 4861. NS cùng nhóm khác target, NS thiếu target, MLD nền đều không thay probe.
  - **[Offline]:** ICMP 79/79, ổn định 3 lần; mutation ICMP 28/28 + 2 đối chứng. Do sửa module dùng chung, chạy lại: `selftest_l2` 195/195 (hồi quy 06B-3G), mutation L2 69/69, `selftest_l2eval` 72/72 (phát lại 06B-4C giống hệt), mutation `l2eval` 26/26.
  - **Chưa chạy trên guest; T12–T13 chưa được kiểm chứng.**
  - **Review:** reviewer chấp nhận ở mức offline (mốc records tree `9aaa8cad…`).
- **06B-4F: nối 5 ca ICMP đã review vào harness — [Offline], chưa chạy tích hợp** ([`task06b4f-summary.md`](docs/evidence/task06b4f-summary.md)):
  - Bản làm việc `ct01-06b4f`.
    - `probe_matrix.py` thêm nhánh `CT01_SUITE=icmp`: chỉ 5 ca T12-B1/B2/B4, T13-I1/I2, không chạy 20 probe IPv4. Boot, capture, heartbeat, bộ đếm, toàn phiên, tắt QEMU, cleanup dùng lại.
    - `icmp_harness.py` mới: lớp chặn lệnh guest dừng nhóm khi mất capture hoặc có cảnh báo; kiểm mỗi ca đúng một lần; liên kết trước/sau phải có HTTP 200 và hash fixture (tiền đề, không phải đối chứng sống); kết luận theo kiến trúc và cả lần chạy.
    - `run-06b4f.sh` mới: chép `run-06b3b.sh`, chỉ đổi phần nối.
  - ĐẠT của ca không che lỗi hạ tầng; nhãn "ĐẠT (kiểm quy tắc)"; timeout hay không tạo được gói không phải bằng chứng chặn.
  - **[Offline]:** chạy `probe_matrix.main()` thật với container/guest giả. Kết quả:
    - wiring 92/92, ổn định; mutation wiring 26/26 + 2 đối chứng;
    - `selftest.sh` 205 PASS; `mutation_test.sh` 78/78;
    - `selftest_icmp` 79/79.
  - **Chưa chạy Docker/QEMU; T12–T13 chưa được kiểm chứng.**
  - **Review độc lập:** còn 2 lỗi, **chưa chấp nhận tích hợp**:
    - P1: cảnh báo rò rỉ chỉ được kiểm **sau** lệnh guest; cảnh báo xuất hiện lúc đọc bộ đếm A của ca kế tiếp không chặn được ping của ca đó;
    - P2: `arch_outcome` không yêu cầu các xác nhận hạ tầng bắt buộc có mặt; thiếu "QEMU exit confirmed", cleanup… vẫn có thể PASS.
- **06B-4FR: sửa hai lỗi của 06B-4F — [Offline], chưa chạy tích hợp** ([`task06b4fr-summary.md`](docs/evidence/task06b4fr-summary.md)):
  - Bản làm việc `ct01-06b4fr`, chép từ 06B-4F sau khi xác minh hash 28 file.
  - **P1:** trong `run_icmp`, cảnh báo rò rỉ được kiểm **trước và sau** mỗi lệnh guest, cùng capture/heartbeat. Lỗi đọc file cảnh báo dừng nhóm (ERROR), không bao giờ coi là "không có cảnh báo". Không ngắt tức thì lệnh đang chạy.
  - **P2:** `arch_outcome` yêu cầu 16 xác nhận hạ tầng bắt buộc của đường chạy ICMP thật, mỗi cái đúng một lần với `ok` đúng bằng `True`; bản ghi phải là object với `test` chuỗi và `ok` boolean. Thiếu, trùng, sai kiểu hay không đạt đều FAIL. Nhãn ca không đổi.
  - **Tái hiện:** cảnh báo khi đọc "T12-B2 before": 06B-4F vẫn gửi ping T12-B2, 06B-4FR không gửi. 26 biến thể hồ sơ hạ tầng từ lần thực thi `main()` thật với stub offline (kịch bản sạch): 06B-4F kết luận sai 21, 06B-4FR 0; fixture sạch vẫn PASS.
  - **[Offline]:** wiring 129/129, ổn định 6 lần; mutation wiring 33/33 + 2 đối chứng; `selftest.sh` 205 PASS; `selftest_icmp` 79/79.
  - **Chưa chạy Docker/QEMU; T12–T13 chưa được kiểm chứng.**
  - **Review:** Codex review độc lập, **chấp nhận ở mức offline**; không có lỗi chức năng mới chặn tích hợp.
- **06B-4G: chạy tích hợp 5 ca ICMP (T12-B1/B2/B4, T13-I1/I2) một lần, ARM rồi MIPS — [KC]** ([`task06b4g-summary.md`](docs/evidence/task06b4g-summary.md)):
  - Harness 06B-4FR (28 hash khớp), image `1ab784c7…9153`, không sửa gì. Chạy đúng một lần, **exit 4**; không chạy lại.
  - **9/10 ca "ĐẠT (kiểm quy tắc)":**
    - T12-B1/B2 → `drop_bcast_mcast`; T12-B4 → `drop_private`; T13 → `l2_bad_ethertype`;
    - delta = số khung probe thực tế (ARM 5, MIPS 3 echo; T13-I2 chỉ có NS đúng target: ARM 4, MIPS 3);
    - 0 khung ICMP/ICMPv6 tới guest (TCP của liên kết dịch vụ và ARP của worker tới guest vẫn có).
  - **ARM T13-I1: CHƯA KIỂM CHỨNG** — echo thứ 3 nằm 15,75 ms trước lần đọc B, trong guard 20 ms. Toàn phiên PASS không nâng ca này.
  - **Không có** ca KHÔNG TẠO ĐƯỢC GÓI, LỖI THỰC THI hay LỖI PHÉP ĐO: broadcast `255.255.255.255`/`10.200.0.3` đều ra `tap0`.
  - **Hạ tầng đạt:**
    - liên kết trước/sau HTTP 200 + hash fixture;
    - capture `tap0` 0 drop; QEMU thoát; cleanup;
    - cảnh báo rò rỉ 0; mọi chữ ký host (gồm kích thước ICMP, IPv6 guest) = 0 trên veth/bridge/`ens33`;
    - manager trả về `exited`; host chỉ đổi `docker-ps`.
  - **3 mục mở chưa giải thích:** tcpdump báo kernel dropped=0; "received by filter" − "captured" = 8 trên veth/bridge/`ens33` vẫn chưa được giải thích; chưa suy thời điểm/nội dung gói.
  - Container ctl: lần kiểm MongoDB đầu tiên (trước boot) timeout, lần sau thành công trở lại (269/270 đạt); không suy nguyên nhân.
  - **Kiểm chéo độc lập** (tcpdump + JSON nft thô, không dùng module harness): 10/10 ca khớp.
  - **Quan sát:** ARM `ping6 ff02::1` báo 3 phản hồi, nguồn là địa chỉ của chính guest; `tap0` không có echo reply nào. Chỉ phù hợp với phản hồi nội bộ guest; chưa có capture trong guest xác nhận cơ chế.
  - Guard 20 ms vẫn là giả định chưa đo.
  - **Review:** chấp nhận đúng phạm vi (exit 4; 9/10; ARM T13-I1 UNVERIFIED; 3 mục OPEN còn nguyên).
  - Thay đổi thiết lập công cụ cho Codex desktop (bubblewrap, `apparmor-profiles`/`apparmor-utils`, profile `bwrap-userns-restrict`) được ghi riêng ở §1a của summary, **không phải kết quả CT-01**.
- **06B-4H: đính chính hồ sơ 06B-4G + chuẩn bị offline T14/T15 — [Offline]** ([`task06b4h-summary.md`](docs/evidence/task06b4h-summary.md)):
  - **Đính chính 06B-4G** (log/pcap/evidence gốc không sửa):
    - mục mở tcpdump ghi "kernel dropped=0; received−captured=8 chưa giải thích; chưa suy thời điểm/nội dung gói";
    - "không có phản hồi về guest" chỉ cho ICMP/ICMPv6 của probe;
    - phản hồi ping6 chỉ phù hợp với phản hồi nội bộ guest, cơ chế chưa xác nhận;
    - ghi timeout MongoDB đầu tiên của ctl (trước boot) và thành công trở lại, không suy nguyên nhân;
    - hàm `zone()` của cross-check 06B-4G lệch định nghĩa đã review; chạy lại bản sửa cho số đếm giống hệt.
  - **T14/T15** (bản `ct01-06b4h`, chỉ thêm `arp_cases.py`, `selftest_arp.py`, `mutation_arp.py`):
    - T14 A1/A2/A3: ARP request do kernel guest sinh bằng route on-link `/32` + một ping;
    - T15 S1: gratuitous ARP do kernel guest sinh, bằng `arp_notify=1` + 3 địa chỉ `/32` giả + link down/up;
    - trạng thái guest lưu/khôi phục bằng `guest_state` (kể cả khi lỗi); đánh giá bằng `l2frames`/`l2eval` đã review;
    - ĐẠT chỉ khi đúng khung probe, đúng bộ đếm, liên kết trước/sau đạt, khôi phục thành công, neighbor worker không đổi (A1/A2 thêm đối chứng sống). Không tạo được khung → CHƯA KIỂM CHỨNG.
  - **[Offline]:** `selftest_arp` 90/90, ổn định 5 lần; mutation 29/29 + 2 đối chứng; `selftest_l2` 175/175; `selftest_l2eval` 65/65.
  - **Chưa nối run script, chưa chạy guest.** ARP reply giả (T15 mức 2) chưa phủ (D1).
  - **Review (Codex):** phần đính chính 06B-4G được chấp nhận. Phần T14/T15 còn lỗi, chưa chấp nhận nối tích hợp:
    - F1: S1 nhận gratuitous opcode 2/99;
    - F2: neighbor thiếu/sai/trùng vẫn coi là không đổi;
    - F3: hồ sơ lệnh thiếu vẫn exit 0;
    - F4: ping rc 2 bị nuốt;
    - F5: lỗi đo che FAIL đã xác định.
- **06B-4HR: sửa năm phát hiện của Codex trong 06B-4H — [Offline]** ([`task06b4hr-summary.md`](docs/evidence/task06b4hr-summary.md)):
  - Bản `ct01-06b4hr`; chỉ đổi `arp_cases.py`, `selftest_arp.py`, `mutation_arp.py`.
  - **F1:** chỉ nhận gratuitous ARP **request** (op 1, Ethernet/IPv4, broadcast).
  - **F2:** kiểm từng hàng neighbor, không ghi đè hàng trùng. Đổi MAC/interface của IP theo dõi → FAIL; mất entry/không còn binding → CHƯA KIỂM CHỨNG; dữ liệu sai → LỖI PHÉP ĐO; REACHABLE↔STALE bình thường.
  - **F3:** giao kèo hồ sơ thực thi: đủ bước/phase/rc, baseline, restore. Ca dừng vì lỗi tách khỏi ca hoàn tất.
  - **F4:** ping chỉ rc 0/1; rc khác là lỗi thực thi, vẫn đọc B và restore.
  - **F5:** thu bằng chứng FAIL trước; FAIL thắng lỗi đo; JSON giữ cả hai; không suy FAIL từ khung khi cửa sổ không hợp lệ.
  - **Tái hiện:** chạy lại nguyên script Codex trên 4H (log giống hệt bản Codex) và 4HR. Mọi ca sai đổi đúng; ca sạch giữ nhãn; ma trận restore 40 tình huống 0 diff.
  - **[Offline]:** `selftest_arp` 146/146, ổn định 5 lần; mutation 48/48 + 2 đối chứng; `selftest_l2` 175/175; `selftest_l2eval` 65/65.
  - **Mọi hành vi guest/kernel là mô phỏng.** Chưa nối run script, chưa chạy guest.
  - **Review (Codex):** tái hiện F1–F5 cũ cho kết quả đúng, nhưng còn lỗi, chưa chấp nhận nối tích hợp:
    - HR1: baseline/restore chỉ kiểm kiểu, tin cờ `restored`;
    - HR2: binding guest bắt buộc chấp nhận PERMANENT+FAILED;
    - HR3: nhánh chưa bắt đầu trả về sớm, mất bằng chứng;
    - HR4: hàng neighbor hỏng bị suy thành mất/đổi → FAIL vượt dữ liệu;
    - HR5: callback đối chứng sai cấu trúc ném ngoại lệ.
- **06B-4HR1: sửa HR1–HR5 — [Offline]** ([`task06b4hr1-summary.md`](docs/evidence/task06b4hr1-summary.md)):
  - Bản `ct01-06b4hr1`; sửa cục bộ `arp_cases.py`, cập nhật test/mutation.
  - **HR1:** kiểm nội dung baseline. `restored=True` phải có `after` hợp lệ và `guest_state.diff(baseline, after)` tính lại rỗng; không có lỗi/diffs; `commands` đúng dạng. Neighbor động không ép.
  - **HR2:** mỗi entry đúng một trạng thái NUD (tổ hợp → lỗi đo). Hàng bắt buộc phải đúng PERMANENT, MAC guest, binding dùng được; hàng hợp lệ sai → FAIL.
  - **HR3:** ca chưa bắt đầu vẫn thu bằng chứng; FAIL thắng; JSON giữ `not_started`.
  - **HR4:** hàng hỏng là "chưa biết": không suy mất/đổi từ danh sách đã lọc (→ lỗi đo). Bảng hợp lệ thực sự thiếu hàng bắt buộc → FAIL; giữ FAIL độc lập.
  - **HR5:** kiểm cấu trúc payload callback; payload sai thành bản ghi lỗi.
  - **JSON:** mọi nhánh có cùng trường bằng chứng/lỗi.
  - **Tái hiện:** nguyên 4 script Codex: 4HR khớp log Codex; 4HR1 sửa mọi ca HR; ca sạch giữ nhãn; ma trận restore 40 tình huống 0 diff.
  - **[Offline]:** `selftest_arp` 212/212, ổn định 5 lần; 51/66 test mới hỏng trên mã 4HR; mutation 71/71 + 2 đối chứng; `selftest_l2` 175/175; `selftest_l2eval` 65/65.
  - **Mọi hành vi guest/kernel là mô phỏng.** Chưa nối run script.
  - **Review (Codex):** HR1–HR5 đã khắc phục cho các biến thể tái hiện; còn **R1**. Baseline nhận entry `neigh_dynamic` có cờ PERMANENT (0x4), nên entry đó mất sau restore mà vẫn ĐẠT (CLI exit 0). Chưa chấp nhận nối tích hợp.
- **06B-4HR2: sửa R1 — [Offline]** ([`task06b4hr2-summary.md`](docs/evidence/task06b4hr2-summary.md)):
  - Bản `ct01-06b4hr2`; sửa cục bộ `baseline_problem`; không sửa `guest_state`.
  - Baseline và `restore.after` từ chối `neigh_dynamic` có bit PERMANENT, và cùng khóa ở cả hai nhóm. Hồ sơ mâu thuẫn chỉ bị báo lỗi, không tự chuyển nhóm.
  - Neighbor động hợp lệ thay đổi vẫn không bị ép; static mất vẫn bị chặn.
  - **Tái hiện:** `static_flag_review.py` của Codex: 4HR1 exit 0 / CLI 0 → 4HR2 exit 2 / CLI 2. Năm script khác cho log giống hệt giữa 4HR1 và 4HR2 (không hồi quy; ma trận restore 40 tình huống 0 diff).
  - **[Offline]:** `selftest_arp` 224/224, ổn định 3 lần; 8/12 test mới hỏng trên mã 4HR1; mutation 75/75 + 2 đối chứng; `selftest_l2` 175/175.
  - **Còn giới hạn:** raw `ip -j neigh` JSON và operstate thật chưa kiểm. Mọi hành vi guest/kernel là mô phỏng. Chưa nối run script.
  - **Review (Codex):** R1 đã khắc phục; **chấp nhận ở mức offline**. Không xác nhận collector hay luồng tích hợp; không tự cho phép chạy.
- **06B-4I: nối ARP vào harness — [Offline]** ([`task06b4i-summary.md`](docs/evidence/task06b4i-summary.md)):
  - Bản `ct01-06b4i`. Mới: `arp_harness.py`, `run-06b4i.sh`, `selftest_arp_wiring.py`, `mutation_arp_wiring.py`. Sửa: nhánh `CT01_SUITE=arp` trong `probe_matrix.py`, tùy chọn `--arp-worker` của `ctl_loop.py`. **Không sửa** `arp_cases.py`, `guest_state.py`.
  - Mọi lệnh guest (cả snapshot/restore) qua `GuardedRunner`. Collector `ip -j neigh show` chạy trong netns worker. Đối chứng sống A1 (ARP của ctl cho `eth0` worker) và A2 (neighbor manager trên `eth0` worker). Kết luận qua `arp_harness --outcome`.
  - Restore lỗi → các ca sau không chạy (giao kèo ca); ở mức kiến trúc là FAIL (quyết định lớp nối, chờ reviewer).
  - **[Offline]:** `probe_matrix.main()` thật với stub và guest mô phỏng; số liệu ở summary. Suite liên quan: `selftest_icmp_wiring` 129/129, `selftest.sh` ALL PASSED, `selftest_arp` 224/224.
  - **Chưa xác nhận:** raw `ip -j neigh` JSON, operstate, kernel/netifd, đối chứng sống thật, guard 20 ms. `run-06b4i.sh` chưa chạy.
  - **Review (Codex):** chưa chấp nhận chạy guest:
    - **I1:** khởi động/topology gửi lệnh ngoài guard; guard chưa được tạo ở đoạn đó;
    - **I2:** A1 sai/thiếu interface vẫn ĐẠT;
    - **I3:** log ctl trùng hoặc HTTP thiếu payload vẫn được nhận.
- **06B-4IR1: sửa I1–I3 — [Offline]** ([`task06b4ir1-summary.md`](docs/evidence/task06b4ir1-summary.md)):
  - Bản `ct01-06b4ir1`. Không sửa `arp_cases.py`, `guest_state.py`, `service/analysis.py`.
  - **I1:** guard khởi động/topology cho mọi suite (adapter console cục bộ: kiểm trước mỗi lần gửi, sau mỗi lần chờ; chốt dừng). Tắt QEMU và cleanup không đổi.
  - **I2:** interface của entry ARP ctl được xác định bằng MAC endpoint `sandboxnet` của ctl (`docker inspect`), không suy tên.
  - **I3:** schema log ctl, payload HTTP `"HTTP 200"`, phát hiện dòng trùng (không tự bỏ).
  - **Tái hiện:** topology/boot của Codex: 4I gửi tiếp lệnh sau sự kiện → 4IR1 dừng ngay. Fixture I2/I3 gốc của Codex **không áp biến thể** (`sys.argv` bị ghi đè trước luồng ctl). Bản áp đúng xác nhận 4I PASS sai, 4IR1 UNVERIFIED.
  - **[Offline]:** số liệu ở summary. Suite chung: `selftest.sh` ALL PASSED, ICMP wiring 129/129, ARP 224/224.
  - **Review (Codex):** I1 tái hiện cũ đã sửa nhưng còn **IR1-R1** (handoff IPv4: `service_link('before probes')` gửi khi capture đã mất); I2 trường hợp cũ đã sửa nhưng còn **IR1-R2** (MAC toàn 0 ở cả cấu hình và payload → PASS); I3 đã sửa. Codex rút lại bằng chứng fixture I2/I3 cũ (lỗi `sys.argv`) và tự chứng minh lại lỗi 4I.
- **06B-4IR2: sửa IR1-R1, IR1-R2 — [Offline]** ([`task06b4ir2-summary.md`](docs/evidence/task06b4ir2-summary.md)):
  - Bản `ct01-06b4ir2`.
  - **IR1-R1:** guard khởi động chỉ chuyển giao cho nhánh đã có guard (ARP/ICMP: ngay trước `GuardedRunner`). IPv4 giữ guard cho mọi liên kết và probe.
  - **IR1-R2:** MAC endpoint phải là unicast dùng được (không toàn 0, không nhóm), ở cả cấu hình và payload; locally administered vẫn hợp lệ.
  - **Tái hiện Codex:** `ipv4-handoff`: 1 lệnh guest sau sự cố → 0; `cfg-zero-mac`: PASS → UNVERIFIED; `eth7` và clean vẫn PASS.
  - **Còn giới hạn:** Enter boot, chốt lỗi transport, đánh giá hậu kỳ ERROR (đề xuất riêng); dữ liệu thật và guard 20 ms chưa xác nhận.
  - **Review (Codex):** IR1-R1, IR1-R2 đã khắc phục; **chốt ở mức offline**. Không phải chấp thuận chạy guest.
- **Precheck chỉ đọc 06B-4IR2** ([`task06b4ir2-precheck-summary.md`](docs/evidence/task06b4ir2-precheck-summary.md)):
  - **Đạt:**
    - manifest harness và evidence;
    - kiểm tĩnh run script (37/37);
    - host link/addr/route/cổng/module/sysctl giống 06B-4G;
    - không QEMU/capture/thư mục cũ.
  - **Chưa kiểm** (user không có quyền Docker, không dùng sudo): image ID, network/container inspect, MAC endpoint, `docker exec`, ruleset nft, AppArmor. Đã soạn script chỉ đọc cho người dùng chạy.
  - **Parser offline** (mẫu host): `ip -j neigh` JSON trên iproute2 6.1.0 của host khớp parser; JSON của image worker và `/proc/net/arp` của ctl chưa có.
  - **Rủi ro R-MIPS** từ evidence 06B-4G: `br-lan` MIPS `NO-CARRIER/DOWN` sau boot. Operstate so chặt trong restore có thể làm restore MIPS FAIL; cần quyết định trước khi chạy.
  - **Review (Codex):** chấp nhận ở phạm vi snapshot host không-sudo + parser offline. **Chưa** chấp nhận script root. Bốn phát hiện:
    - **PC-1:** ARM FAIL vẫn gọi MIPS;
    - **PC-2:** lỗi đọc bị ghi thành "absent"/"not running";
    - **PC-3:** `guest_state` bỏ sót admin UP (lỗi xác nhận restore, chưa chứng minh false PASS ca);
    - **PC-4:** đường output root có thể bị đổi đích.
- **06B-4IR3: sửa PC-1–PC-4 — [Offline]** ([`task06b4ir3-summary.md`](docs/evidence/task06b4ir3-summary.md)):
  - **PC-1:** run script dừng giữa kiến trúc (ARM không đạt mọi điều kiện → không gọi MIPS); teardown vẫn chạy; exit giữ nguyên nhân.
  - **PC-2:** precheck mới gồm collector (rc/stdout/stderr từng lần đọc; `ABSENT` tách khỏi `UNKNOWN`) và evaluator offline (`PASS/FAIL/UNKNOWN`, exit rõ).
  - **PC-3:** `guest_state` ghi, so và khôi phục `admin_up` (header `ip link`) tách khỏi operstate; validator ARP bắt buộc `admin_up`.
  - **PC-4:** quy trình root dùng bản sao đã kiểm hash, output `mktemp`, fd/`O_NOFOLLOW`/`O_EXCL`, executable tuyệt đối, `env -i`; **chưa thực hiện**.
  - **[Offline]:** `selftest_l2` 187/187, `selftest_arp` 233/233, wiring 196/196, precheck 40/40; mutation `l2` 78/78, có mục tiêu: ARP 1/1, wiring 6/6, precheck 12/12.
- **Runtime thật 2026-10-10/11 (tuần tự, reviewer độc lập đã chấp nhận phạm vi nêu; không là PASS CT-01):**
  - **V0 R6 (control/F1b/F6)** — cây `ct01-v0-runtime-r6` manifest `4d2e88738e5c60b32f6f276a95b375d6aaae209ba1c17c6e8828ec81b8d02b1c`, stage `20261010T165222Z`, evaluator rc 0 (157 kiểm), hậu kiểm stage+export ALL HELD ([`ct01-v0-runtime-final-evidence.zip`] sha256 `556b7a08…e511`). Control `ISOLATION OK`; **F1b chỉ là "nft không resolve qua PATH hạn chế"** (`/usr/sbin/nft` vẫn có trong image; không chứng minh image thiếu binary); F6 `nft -f` nhận và V0 từ chối khác biệt cấu trúc (exit 1). R4 abort rc 3 (preflight thiếu `tap0`) và R5 rc 1 (evaluator) giữ nguyên là lịch sử. `/status` manager **chưa đo**; container state không thay `/status`.
  - **B1 R13N11 (launch `02f021d60a9644ab965b3d869082e81f`)** — manifest `476b0d69d559766809c49ec9a5e9208433fcf0741509414f3d188ca0e74ea667`, collection `66c6e7d3` (historical PASS MGR3), FINISHED ENTRY/SETUP/ARM/MIPS, `ct01-b1-r13n11-t1617r4-results.zip` sha256 `c423d9fd…2863`. ARM và MIPS **10/10 ca ĐẠT mỗi kiến trúc**: 3 ca có đối chứng sống (T05-DNS-8888, T06-ICMP-LANDNS, T20-N2-TCP22 banner alive) + 7 kiểm quy tắc; T20 N4/N5 chỉ tra route (không policy routing/reachability). Drain veth/bridge/ens33 PASS theo cumulative-anchor/1 (ens33 R lệch C trước mốc rồi bằng; N=C=R 3892/7690/949); cleanup sạch; nft/route/sysctl/qemu/docker ps giống byte, **`lsmod-raw` có thay đổi** (không tuyên bố host bất biến). Không chứng minh timing guard 20 ms. Các lượt B1 R13N10 (SyntaxError Python 3.10) và R13N11 lần 1 (bridge mất IPv4) giữ FAILED lịch sử.
  - **T16/T17 R4 (launch `b745b9be35df447d9f381d0b265dc1ea`)** — FAILED lịch sử, **chỉ ARM** (MIPS chưa chạy): T16-M1 ĐẠT (6 khung, restore True); T17-P1/P2 FAIL do HTTP 200, **nhưng pcap cho thấy probe ra dây bằng IP thật `10.200.0.2`, không phải IP giả** nên chưa chứng minh lỗ hổng; P4/P5 CHƯA KIỂM CHỨNG. Chưa có bằng chứng spoof thật; ảnh ARM có WAN/masq (chưa kết luận). Session-wide `l2_bad_mac` ARM cần phân tích riêng. M1 chưa có MIPS.
  - **Luồng tác vụ thật (lane `ct01-flow-r1`, reviewer độc lập đã chấp nhận đúng phạm vi; không là PASS CT-01):** worker thật (entrypoint `run.sh` → V0 → server + poller) trên `sandboxnet` 192.168.60.2, fixture busybox vô hại (sha256 ARM `6a534541…f6a5`, MIPS `3b06c11b…8488`) gửi qua `/submit-file` của manager thật. **success #3** (label `20261011T031502Z-72529`, 39/39): **T18** poller thật nhận tác vụ ARM và MIPS (PROCESSING bởi `ct01-flow-worker` rồi COMPLETED), **T19** manager→worker `/healthcheck` 200 (worker rảnh), **T01/T02-runtime** tải trong guest → capture → shutdown phase 1 → boot phase 2 → upload strace/sar → shutdown phase 2 → upload 200; zip manager có binary đúng hash, strace `execve ./exec`, sar, pcap, qemu.log. **F3** ARM (label `20261011T031907Z-75366`, 21/21): xóa bảng `inet sandbox_guest` trong netns worker khi rảnh → FAILED lý do V1, không QEMU. **F4** ARM (`20261011T031923Z-75814`, 21/21): xóa khi phase 1 đang chạy → FAILED lý do V2, phase 1 shutdown xác nhận, phase 2 không bắt đầu. Verifier cách ly rc 0 trong worker tại checkpoint phase 1/phase 2 (A7/A11/A15 ở mức **checkpoint**, không claim timing guard 20 ms). Giới hạn: F3/F4 chỉ ARM và một loại fault; không hash strace/sar riêng trong guest trước upload; fixture không phản ánh chất lượng phân tích malware. Success #1/#2 giữ là abort/criteria-not-met lịch sử. Dữ liệu để lại: 4 hàng COMPLETED + 2 FAILED trong Mongo, 4 zip trong `data/manager/output`.
  - **F5 (lane `ct01-flow-r3`, evidence thật; reviewer đã chấp nhận phạm vi startup/restart worker Compose rảnh):** `docker compose restart sandbox-worker-1` trên worker Compose do lane tạo (`up --no-deps --no-build --pull never`; project `cic-ynu-iotmal-sandbox`; manager/Mongo chỉ đọc, id/StartedAt không đổi). Lượt R2 `20261011T040725Z`: 53/54, **kiểm A14 sai do giả định của tôi** (inode netns bằng nhau vì số inode được tái sử dụng; Docker đã dựng sandbox mới: SandboxID/SandboxKey/EndpointID/MAC đổi, log lần start 2 `tap0=None`, `ip_forward=1`). Giữ nguyên; R3 đổi tiêu chí sang danh tính sandbox + trạng thái nguyên sơ; lượt R3 `20261011T041311Z`: **55/55**, V0 OK hai lần, bảng/tap0/verifier/health trước và sau, container dọn theo ID. Tiêu chí R3 viết sau khi thấy dữ liệu R2.
  - **T16/T17 R6 runtime (launch `43ef2bc63410486d904b1416fc7304ad`, collection `6662edaf…`, approval record `c7f18906…`; quyết định nguyên văn của người dùng 2026-10-11T04:51Z):** `FAILED`/UNVERIFIED, **chỉ ARM** (MIPS không chạy: cổng ARM không đạt). T16-M1 ĐẠT (6 khung, restore True); T17-P2 và T17-P5 **ĐẠT** (nguồn giả `192.168.60.10` thật sự trên dây, 3 khung mỗi ca; rule NAT bypass chèn ở số 1 và xóa theo số, mọi restore True, NAT baseline có thứ tự khôi phục đúng); **T17-P1 (bắt buộc) và T17-P4 KHONG_TAO_DUOC_GOI**: hai quan sát đã xác minh (cơ chế liên hệ **chưa xác minh**): `10.200.0.3` là địa chỉ broadcast của `/30` của guest, và capture ghi IP thật `10.200.0.2` (P1 HTTP 200, P4 3 SYN thật), không có khung nguồn `.3`. Không phải FAIL cách ly, cũng không phải bằng chứng chặn. Drain PASS (veth/bridge/ens33), cleanup không lỗi, export forensic `ct01-arp-evidence-export.1hqd8d7n`. R7 (`ct01-t1617-r7`, manifest `5383df39…fc35`) đổi nguồn P1/P4 sang `10.200.0.5` (ngoài /30); đã chạy, xem dòng R7 bên dưới. Chưa review runtime R6 mới.
  - **T16/T17 R7 runtime (reviewer chấp nhận ARM+MIPS trong phạm vi ca đã chạy; launch `e49800623806498ca1f47bfebb3b4c58`, manifest `5383df39…fc35`, collection `2b030512…` (mới của lượt này), approval record `190993c1…`; câu duyệt nguyên văn của người dùng 2026-10-11T05:44Z; FINISHED, rc 0):** **ARM 5/5 ĐẠT** (T16-M1 6 khung; P1 nguồn `10.200.0.5/32`, P2 `192.168.60.10`, P4 `10.200.0.5`→`1.1.1.1:443`, P5 ICMP `192.168.60.10`, mỗi ca 3 khung nguồn giả trên dây, 0 reply tới danh tính giả, 0 khung IP thật, restore True, NAT bypass chèn số 1/xóa theo số rc 0) và **MIPS 5/5 ĐẠT** (T16-M1 3 khung; P1/P2/P4 4 khung, P5 3). Đối chứng sống/service link hợp lệ; drain PASS (veth 3324, bridge 6566, ens33 6142, N=C=R); cleanup `attempts_completed`, không lỗi; mọi `not_measured` giữ nguyên (server.py request log, /tmp/sandbox_stop_requested). **Giới hạn:** `.5/32` là biến thể có ghi nhận của phép thử `.3` trong thiết kế (đã cập nhật mapping trong `docs/`); không chứng nhận `.3` hay mọi nguồn giả; nguyên nhân R6 `.3` chưa xác minh; P3 và TAP_MAC giả hoãn. R6 (P1/P4 KHONG_TAO_DUOC_GOI) giữ làm lịch sử.
  - **T21b R3 (run id `t21b-r3-20261011a`; evidence thật, reviewer chấp nhận hai phía):** heartbeat chạy trong phiên SSH thật của người dùng (192.168.177.1 → 192.168.177.128:22), 300 nhịp, evaluator R3 ghim trên file client gốc (sha256 `aa0cdedd…134fdf`): **T21B_TWO_SIDED_HELD 15/15**, bao phủ lượt F5 flow R4 `20261011T060519Z` (rc 0, 55/55; restart 06:05:24–06:05:34Z). Một phiên, một lượt, ngưỡng gap 3 s; không nói về phiên khác/T21a. R2 (`t21b-r2-20261011a`) NOT_MET giữ làm lịch sử.
  - **Flow R4 / T21b R2:** export flow kiểm từng hash manifest và coi lỗi receipt là lỗi export (review X1/X2); T21b R2 sửa H1/H2 (STOP theo thời điểm; client log đầy đủ có timestamp nhận). Chạy thật T21b chờ phiên SSH của người dùng. Vấn đề sản phẩm ghi nhận, **không sửa** (ngoài phạm vi CT-01/ảnh worker ghim): `service/analysis.py:288,293` log `Started sar/strace (PID: …)` in `proc.before` (echo lệnh), không phải PID thật (`sar_pid`/`strace_pid` được ghi vào tệp trong guest, không đọc lại).
  - **Trạng thái CT-01 hiện tại: ĐẠT — hoàn tất theo phạm vi nghiệm thu đã duyệt; reviewer chốt 2026-10-11.** Tham chiếu: biên bản reviewer `ct01-final-acceptance/REVIEW.md` (sha256 `6da3f67bb3bb94649ce67429369bd21cc65ca69de663f5f7623ca914dd47914d`, trong gói `ct01-final-acceptance.zip` sha256 `7a9ee8d7ef219faccf57dab4b8ffd69027ebf862034a2d50942beeebc85e6b6f`), phạm vi theo `SCOPE-DECISION.json` (sha256 `9e537e4a32e02cbea35ad8f7585996bca1cb4d94dfd93b08c0b660fa80a9e13d`; câu người dùng nguyên văn "chấp nhận phạm vi" 2026-10-11T13:32:02+07:00; mapping là diễn giải của reviewer, không phải câu duyệt nguyên văn). Kết luận gắn với image/cấu hình/evidence đã ghim; thay image cần xác định và thực hiện hồi quy phù hợp với phần đổi.
- **Closure CT-01 (2026-10-11; reviewer + người dùng chốt phạm vi; hồ sơ trước review):** bảng 38 hàng và index evidence (`ct01-final-closure/CLOSURE-FINAL.md/.json`, `EVIDENCE-INDEX-FINAL.json`: 55 tệp băm trực tiếp, 0 thiếu, 0 hàng mandatory thiếu evidence) nằm trong gói final. Phạm vi T07–T10 theo quyết định người dùng 13:32:02 +07 ("chấp nhận phạm vi"): T07/T08 ĐẠT về mạng (log ssh/manager bổ sung **không đo**); T09 ĐẠT cách ly TCP27017 với control TCP từ dbnet (**không** claim M /status hay mongosh ping); T10 ĐẠT tổng hợp network proof + T19 nguồn M (T19 **không** là control đồng thời của probe cũ). Sửa báo cáo theo review: T05b là **UDP DNS 8.8.8.8:53** (TCP443 là T05a); T16/T17 là 5 ca/kiến trúc (M1 mandatory + P1 mandatory + P2/P4/P5 coverage); T21a "Compose chưa từng chạy" là lịch sử R10, Compose thật chạy ở F5/T21b R3 (scope riêng). Giữ nguyên: FAIL 06B-3D, MIPS ssh-host-192.168.60.1 UNVERIFIED 3G (dẫn xuất H0), T12/T13 host capture OPEN (received−captured=8), H0, T13-I1 ARM UNVERIFIED lịch sử, R4/R6 T17, `.5/32` là biến thể của `.3`, guard 20 ms không đo, A7/A11/A15 chỉ checkpoint, PID log là vấn đề sản phẩm ngoài CT-01. Coverage (T05c, T12-B3, T13-I3) và hoãn (T15-2, D1/D3/D4/D5, P3, TAP_MAC) không thành gate. Sudo của phiên đã thu hồi (thông tin operator).
- **Chưa kiểm chứng / hạn chế (trạng thái LỊCH SỬ tới 2026-10-09; các mục T16/T17/T20/F3–F6/V1–V2 đã được đo ở các dòng 'Runtime thật' và 'Closure CT-01' phía trên, xem đó trước khi dùng danh sách này):**
  - V1 và V2 trong luồng phân tích thật chưa chạy.
  - T12/T13 mới phủ 5 ca kiểm quy tắc, chạy tích hợp một lần ở 06B-4G (ARM T13-I1 CHƯA KIỂM CHỨNG); không có đối chứng sống.
  - Chưa chạy trên guest: ARP (T14, T15), đổi MAC (T16), giả IP nguồn (T17, gồm hành vi `rp_filter` strict với guest), inbound vào guest (T20). Kế hoạch: 06B-4A/4B.
    - T12-B3, T13-I3 trong kế hoạch chưa viết.
    - T14 A1/A2/A3 và T15 S1 (mức 1): chuẩn bị **offline** ở 06B-4H, sửa theo review ở 06B-4HR, 06B-4HR1, 06B-4HR2; nối vào harness và run script `run-06b4i.sh` ở mức offline (06B-4I); chưa chạy. T15 mức 2 chưa phủ (D1).
    - T16, T17, T20: chưa viết probe. Harness và bộ đánh giá L2/ARP offline đã có (06B-4B/4BR, 06B-4D1R); 06B-4C chỉ kiểm tích hợp harness đó với 20 probe IPv4 cũ.
  - Fail-closed khi chạy (F3–F6) chưa làm. Ở mức V0 (06B-2A): F1 mới kiểm **lỗi cú pháp ruleset** (`guest.nft` lỗi → exit 1); **thiếu binary `nft` chưa kiểm**. F2 đã kiểm `ALLOW_VM_INTERNET=true` → exit 1.
  - Mất luật khi guest đang chạy chỉ bị phát hiện ở V2 hoặc tác vụ sau.
  - Worker vẫn privileged.
  - Bảng nft ngoài ba bảng CT-01 không được kiểm.
- **Hiện trạng gốc (chỉ suy ra từ mã/cấu hình, chưa thử nghiệm):** guest cùng L2 với `sandboxnet`, nên **có thể** tới Internet, LAN, SSH host và manager. Quan sát thực tế [KC]: host không nạp `br_netfilter`; netns mới mặc định `ip_forward=1`.
- **Còn thiếu để CT-01 đạt:** các phép thử ở mục "Chưa kiểm chứng" (ARP/MAC spoof, giả IP nguồn, IPv6, broadcast/multicast, inbound, phần còn lại của T05/T06/T11, fail-closed khi chạy F3–F6, V1/V2 trong luồng thật), một lần chạy tích hợp quyết định được toàn bộ 20 probe (06B-3E còn 4, 06B-3G còn 1 CHƯA KIỂM CHỨNG); quyết định của reviewer về ARM T13-I1 (06B-4G) và mục mở tcpdump; viết và chạy các probe còn lại theo kế hoạch ([`docs/ct01-remaining-tests-plan.md`](docs/ct01-remaining-tests-plan.md)); đo độ trễ capture → bộ đếm (guard 20 ms vẫn là giả định); reviewer quyết định cách dùng kết quả toàn phiên trong nghiệm thu. **CT-01 vẫn chưa đạt.**

### CT-02 — Môi trường sạch giữa các mẫu · Chưa bắt đầu

- **CIC đã có [Mã]:** mỗi tác vụ giải nén `image.zip` vào thư mục riêng (`sandbox-worker/service/analysis.py:360-361`) và xóa sau khi xong (`poller.py:68-81`). Thiết kế có thể đáp ứng, **chưa kiểm chứng**.
- **Còn thiếu:** kiểm thử marker giữa 2 tác vụ liên tiếp; so hash `*/image.zip` trước/sau.

### CT-03 — Cleanup · Chưa bắt đầu

- **CIC đã có [Mã]:** xóa thư mục tác vụ khi lỗi/hủy (`poller.py:49-63`); dừng QEMU/tshark khi hủy (`analysis.py:237-240`).
- **Nghi vấn [Mã]:** khi lỗi/timeout (`analysis.py:171-263`) không có `finally` dừng QEMU; tshark (`analysis.py:218`) không bị dừng nếu lỗi xảy ra sau khi khởi động.
- **Còn thiếu:** dọn bảo đảm cho thành công/lỗi/timeout/hủy và kiểm thử tác vụ kế tiếp.

### CT-04 — Xác minh thực thi và log · Chưa bắt đầu

- **CIC đã có [Mã]:** `COMPLETED` đặt ngay khi nhận ZIP (`sandbox-manager/router/sandbox_router.py:120-136`); kiến trúc không hỗ trợ → `FAILED` (`analysis.py:130`).
- **Còn thiếu:** phân loại chạy được / thiếu thư viện / sai kiến trúc / lỗi thu log / hết giờ.

### CT-05 — Lưu dữ liệu bền vững · Kiểm chứng một phần

- **Mục tiêu:** tạo lại container vẫn giữ mẫu upload, log/kết quả, dữ liệu MongoDB và liên kết tác vụ.
- **CIC đã có [Mã]:** chỉ MongoDB có bind mount `./data/mongo`.
- **Nhóm đã làm:** bind mount `./data/manager/output:/app/output`, `./data/manager/uploads:/app/uploads`; ghim `mongo:8.0.32`.

| Tiêu chí con | Trạng thái | Bằng chứng |
|---|---|---|
| Tệp `output`/`uploads` còn sau khi tạo lại container manager | Đạt [KC] | NV05 marker: hash giống nhau ở container cũ/mới/host |
| Mount đúng đường dẫn, ghi được | Đạt [KC] | NV05 `docker inspect` |
| Dữ liệu MongoDB còn sau khi tạo lại container mongo | Chưa kiểm chứng | — |
| Mẫu upload và kết quả thật còn sau khi tạo lại | Chưa kiểm chứng | chưa có tác vụ |
| Liên kết tác vụ (MongoDB ↔ tệp) | Chưa kiểm chứng | chưa có tác vụ |

- **Hạn chế:** marker chỉ chứng minh lưu trữ tệp qua việc tạo lại container manager.

### CT-06 — Kiểm tra đầu vào · Chưa bắt đầu

- **CIC đã có [Mã]:** `submit-file` nhận mọi tệp, không kiểm tra loại/dung lượng, không tính hash (`sandbox_router.py:85-101`); kiến trúc chỉ xác định ở worker (`analysis.py:112-130`).

### CT-07 — Phân tích strace · Chưa bắt đầu

- **CIC đã có [Mã]:** chỉ thu `strace.log` thô vào ZIP.

### CT-08 — Phân tích PCAP · Chưa bắt đầu

- **CIC đã có [Mã]:** chỉ thu `network.pcap` thô (tshark trên `tap0`).

### CT-09 — Báo cáo JSON · Chưa bắt đầu

- **CIC đã có [Mã]:** ZIP gồm `strace.log`, `sar.out`, `network.pcap`, `qemu.log`; không có báo cáo cấu trúc.

### CT-10 — Dashboard · Chưa bắt đầu

- **CIC đã có [KC]:** `/ui` trả 200 và hiển thị qua SSH tunnel (NV05).
- **Còn thiếu:** tiến trình, lỗi, báo cáo chi tiết.

### CT-11 — Xuất PDF · Chưa bắt đầu

- Phụ thuộc CT-09.

### CT-12 — Theo dõi giai đoạn và worker · Chưa bắt đầu

- **CIC đã có [Mã]:** 5 trạng thái; khi manager khởi động lại, PROCESSING → QUEUED (`sandbox-manager/util/lifespan_handlers.py:34-44`). Không có giai đoạn, heartbeat hay timeout cho worker.

### CT-13 — Thông tin tái lập · Chưa bắt đầu

- **Đã ghi ở mức tài liệu [KC]:** phiên bản Docker/Compose, `mongo:8.0.32` + digest, digest base image, QEMU `1:6.2+dfsg-2ubuntu6.31`, tshark 3.6.2; `.env` không vào image.
- **Còn thiếu:** đưa vào từng báo cáo tác vụ; giữ log lỗi theo tác vụ.

### CT-14 — Kiểm thử và đánh giá · Chưa bắt đầu

- **Đánh giá tổng thể CT-14 chưa bắt đầu:** chưa có bộ kiểm thử/đánh giá tổng hợp theo tiêu chí CT-14 (ARM/MIPS trong luồng phân tích thật, cô lập, khôi phục, lỗi/hủy, báo cáo, xuất kết quả).
- **Không tính vào CT-14:** các phép thử đã có là kiểm chứng **riêng từng phần của CT-01** (cô lập mạng: guest ARM/MIPS thật boot bằng image OS gốc, liên kết dịch vụ, ma trận IPv4 20 probe, harness L2/ICMP offline) và của CT-05 (một phần). Chúng không chạy mẫu, không đi qua luồng phân tích thật (`dynamic_analysis`, V1/V2), và chưa được tổng hợp hay nghiệm thu theo tiêu chí CT-14.
