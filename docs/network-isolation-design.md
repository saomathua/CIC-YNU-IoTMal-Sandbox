# Thiết kế cô lập mạng QEMU (CT-01)

**Trạng thái:** thiết kế bản 3 (bổ sung theo review trước 06B-1). Mã triển khai: 06B-1 (mục 11). **Cập nhật 06B-4FR/06B-4G/06B-4H/06B-4HR/06B-4HR1/06B-4HR2/06B-4I/06B-4IR1/06B-4IR2:** worker thật và guest ARM/MIPS thật đã chạy từ 06B-2A/06B-3A; một phần ma trận §7.2 đã thực hiện (tình trạng ở đầu mục 7; chi tiết và bằng chứng trong [`../KQCaiTien.md`](../KQCaiTien.md), CT-01). Nội dung thiết kế bên dưới giữ nguyên. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".** Các phép thử này là kiểm chứng riêng của CT-01, không phải đánh giá tổng thể CT-14 (chưa bắt đầu).
Nhánh: `feat/ct01-network-isolation`, tách từ mốc `3c54d55925b7471687b9be5b3cebcbb5b2e4bd43`.
Reviewer đã chấp nhận hướng PA-2 (mục 3).

Ký hiệu nguồn:

- **[Mã]** suy ra từ mã nguồn hoặc cấu hình. Nói về *đường đi tiềm năng*, **chưa thử nghiệm**.
- **[KC]** quan sát thực tế trên host `hq` bằng lệnh chỉ đọc.
- **[GĐ]** giả định cần kiểm chứng (mục 8).

---

## 1. Hiện trạng: luồng và đường đi gói

### 1.1 Thành phần và địa chỉ

| Thành phần | Mạng | Địa chỉ / cổng | Nguồn |
|---|---|---|---|
| Host Ubuntu `hq` | LAN | `192.168.177.128/24` (ens33), gateway LAN `192.168.177.2` | [KC] |
| Host trên `sandboxnet` | bridge Docker | `192.168.60.1` | [KC] `ip addr`; compose |
| Host trên `dbnet` | bridge Docker | `172.18.0.1/16` | [KC] |
| Dịch vụ host | | `sshd` nghe `0.0.0.0:22` và `[::]:22`; resolver `127.0.0.53` | [KC] `ss -ltn` |
| sandbox-manager | `sandboxnet` + `dbnet` | `192.168.60.10:8011` (không xác thực); publish `127.0.0.1:8011` | [Mã] compose |
| mongo-db | chỉ `dbnet` | `172.18.0.x:27017`, không publish | [Mã] compose |
| sandbox-worker-1 | chỉ `sandboxnet` | `192.168.60.2`; `server.py` nghe `0.0.0.0:8011` | [Mã] compose, `server.py:17` |
| QEMU guest (hiện tại) | bắc cầu vào `sandboxnet` | `192.168.60.3` (= IP worker + 1), gateway `192.168.60.1`, DNS `8.8.8.8` | [Mã] `analysis.py:175-185, 357-358` |

Kernel host `6.8.0-146`. Trên host [KC]: `net.ipv4.ip_forward=1`, `net.core.devconf_inherit_init_net=0`, IPv6 bật, module `br_netfilter` **không** được nạp (`lsmod`), không có `/proc/sys/net/bridge`.

### 1.2 Cấu hình mạng worker hiện tại — `sandbox-worker/run.sh:4-21` [Mã]

1. Tạo `tap0`, tạo bridge `br0`, đưa `tap0` vào `br0`.
2. Gỡ IP khỏi `eth0`, đưa `eth0` vào `br0`, gán IP cũ cho `br0`, đặt default route qua `br0`.

QEMU nối guest vào `tap0` (`-netdev tap,ifname=tap0,script=no`) [Mã] `analysis.py:38-109`:

| Kiến trúc | NIC | Interface trong guest |
|---|---|---|
| ARM | 2 × `virtio-net-pci`; NIC thứ nhất không có netdev | `eth1` |
| MIPS, MIPSEL, x86 | `pcnet` | `br-lan` |

Chưa NIC nào được đặt MAC tường minh.

### 1.3 Luồng cần thiết [Mã]

| # | Luồng | Endpoint | Khởi tạo | Nguồn |
|---|---|---|---|---|
| L1 | Lấy tác vụ | `GET http://sandbox-manager:8011/api/v1/sandbox-manager/get-file/{APP_NAME}?worker_uri=…` | poller | `poller.py:32-35` |
| L2 | Gửi kết quả / báo lỗi | `POST …/submit-result/{id}`, `POST …/submit-failure/{id}` | poller | `poller.py:62-88` |
| L3 | Manager yêu cầu dừng | `POST {worker_uri}/stop`, `worker_uri=http://192.168.60.2:8011/api/v1/sandbox-worker` | manager | `sandbox_router.py` (manager) `:167-170` |
| L4 | **Guest tải mẫu** | `GET …/api/v1/sandbox-worker/get-task/{id}/file` | guest (curl) | `analysis.py:142-144, 203-205` |
| L5 | **Guest gửi log** | `POST …/update-task/{id}/strace`, `…/update-task/{id}/sar` | guest (phase 2) | `analysis.py:276-288` |
| L6 | Bắt gói | `tshark -i tap0` | worker | `analysis.py:218-220` |
| L7 | Worker tự xác định IP | `socket.connect(("8.8.8.8",80))` dạng UDP, không gửi gói | poller, lifespan | `poller.py:23-26`, `lifespan_handlers.py:17-19` |

Guest chỉ cần **L4 và L5**.

### 1.4 Đường đi tiềm năng của guest hiện tại — [Mã], CHƯA KIỂM CHỨNG

Suy ra từ `run.sh` và cấu hình Compose. **Chưa có phép thử nào xác nhận các đường này.**

```
guest ─ tap0 ─ br0 (netns worker) ─┬─ tới 192.168.60.2 → giao nội bộ cho worker            [L4/L5]
                                   └─ eth0 → veth → bridge Docker trên host (br-1d86…)
                                          ├─ manager 192.168.60.10:8011         (cùng L2)
                                          ├─ host 192.168.60.1:22 (sshd)        (cùng L2)
                                          └─ host định tuyến + NAT → ens33 → LAN, Internet
```

Theo cấu hình, guest **có thể**:

- tới Internet, LAN, SSH của host và manager;
- giả mạo ARP/IP trên `sandboxnet`;
- chạm `[::]:22` của host qua IPv6 link-local, nếu khung IPv6 được bắc cầu.

**Luật `ALLOW_VM_INTERNET=false` hiện tại** (`run.sh:27-31`):

- Thứ tự sai [Mã]: hai luật cùng dùng `-I`, nên `DROP` đứng trên `ACCEPT`.
- Suy luận, chưa kiểm chứng: lưu lượng `tap0→eth0` là bắc cầu L2, nên iptables `FORWARD` chỉ thấy khi có `br_netfilter`, mà host hiện không nạp module này [KC]. Nếu có `br_netfilter` thì `-i` khớp `br0`, không khớp `tap0`.
- Không có lọc ARP hay IPv6, và không có cơ chế fail-closed.

MongoDB chỉ nằm trên `dbnet`. Đường qua host phụ thuộc vào luật cô lập liên mạng của Docker [GĐ]. Manager thì kết nối được MongoDB.

---

## 2. Yêu cầu cô lập

| Mã | Yêu cầu |
|---|---|
| R1 | Guest chỉ tới được **ba route API** của worker cho tác vụ hiện tại (mục 5), qua TCP 8011 trên IP phía guest của worker. |
| R2 | Chặn guest tới Internet, LAN, host (mọi IP), manager, MongoDB và IP `eth0` của worker. |
| R3 | Worker vẫn giao tiếp với manager (L1–L3). |
| R4 | Xét đủ: L2 (MAC, ethertype), ARP (request, reply, gratuitous, spoof), IPv4 (vào worker và đi qua), IPv6. |
| R5 | Fail-closed: kiểm tra cô lập thất bại thì không khởi chạy QEMU. |
| R6 | Không thay đổi network namespace của host, để không làm mất SSH hay kết nối Claude. |
| R7 | Vẫn quan sát được ý định kết nối của guest (pcap trên `tap0`) cho CT-08. |

---

## 3. Phương án (reviewer đã chấp nhận PA-2)

| Tiêu chí | PA-1 giữ bridge, lọc tầng bridge | **PA-2 tách mạng guest (chọn)** |
|---|---|---|
| Guest cùng L2 với `sandboxnet` | Có. Một luật sai là guest ra thẳng mạng Docker | Không. Guest chỉ có link `tap0` tới worker |
| Phụ thuộc | nft bridge hoặc `br_netfilter` (module toàn cục) | nft `netdev`/`inet`/`arp` và sysctl trong netns |
| Lớp phòng thủ | Một lớp lọc bridge | Không chung L2; `ip_forward=0`; nft mặc định drop; API allowlist |
| `eth0` của worker | Vẫn bị flush và chuyển vào `br0` | Không bị đụng |
| Nhiều worker | Guest chiếm IP trên `sandboxnet` | Guest dùng subnet riêng trong netns của mỗi worker |
| Chế độ cho Internet về sau | Dễ | Cần thiết kế egress riêng |
| Sửa source | Ít | `run.sh`, `analysis.py`, `settings.py`, router worker, Dockerfile, file mới |

---

## 4. Thiết kế mạng PA-2

### 4.1 Hằng số

Các giá trị cố định trong mã và ruleset, **không cấu hình qua env**. Lý do: tập luật chuẩn (mục 6) phải là một artefact tĩnh đã được review.

| Hằng số | Giá trị |
|---|---|
| `GUEST_IF` | `tap0` |
| `GUEST_NET` | `10.200.0.0/30` (không trùng `172.17/16`, `172.18/16`, `192.168.60/24`, `192.168.177/24` [KC]) |
| `WORKER_GUEST_IP` | `10.200.0.1` |
| `GUEST_IP` | `10.200.0.2` |
| `GUEST_MAC` | `52:54:00:c7:00:02` (đặt tường minh: `-device …,netdev=…,mac=52:54:00:c7:00:02`) |
| `SVC_PORT` | `8011` |

Guest có default route qua `10.200.0.1` (R7). DNS `8.8.8.8` giữ nguyên trong guest: truy vấn sẽ bị drop nhưng vẫn được ghi lại.

### 4.2 Trình tự `run.sh` (fail-closed)

```
set -euo pipefail
0. Nếu ALLOW_VM_INTERNET != "false" → log lỗi, exit 1
1. sysctl (netns worker): net.ipv4.ip_forward=0, net.ipv6.conf.all.forwarding=0,
                          net.ipv6.conf.default.disable_ipv6=1
2. ip tuntap add dev tap0 mode tap; ip addr add 10.200.0.1/30 dev tap0; ip link set tap0 up
   sysctl tap0: disable_ipv6=1, arp_ignore=1, arp_announce=2, arp_accept=0, rp_filter=1
   ip neigh replace 10.200.0.2 lladdr 52:54:00:c7:00:02 dev tap0 nud permanent
3. nft -f /app/isolation/guest.nft             (nạp nguyên tử; lỗi → exit)
4. /app/isolation/verify --phase startup       (mục 6; lỗi → exit)
5. Khởi động server.py, rồi poller.py
```

Bỏ toàn bộ khối bridge (`run.sh:4-21`) và hai luật iptables cũ (`run.sh:27-31`). Không đụng `eth0`.

### 4.2a Giá trị sysctl hiệu lực (06B-2AR)

Theo `include/linux/inetdevice.h` của Linux **v6.8** (đối chiếu mã upstream; chưa đối chiếu bản vá riêng của Ubuntu `6.8.0-146`):

| Biến | Macro | Giá trị hiệu lực |
|---|---|---|
| `rp_filter` | `IN_DEV_MAXCONF(RP_FILTER)` | `max(all, dev)` |
| `arp_ignore` | `IN_DEV_MAXCONF(ARP_IGNORE)` | `max(all, dev)` |
| `arp_announce` | `IN_DEV_MAXCONF(ARP_ANNOUNCE)` | `max(all, dev)` |
| `arp_accept` | `IN_DEV_MAXCONF(ARP_ACCEPT)` (ba giá trị từ 6.0) | `max(all, dev)` |
| `forwarding` (theo interface) | `IN_DEV_CONF_GET(FORWARDING)` | **chỉ giá trị của dev** |
| `default` | — | chỉ là giá trị khởi tạo cho interface tạo sau đó |

`run.sh` chuẩn hóa `conf.all` trong netns worker:

- `rp_filter=1`: theo quyết định của reviewer, giữ strict trên `tap0`. `eth0` hiệu lực = `max(1, eth0)`; tác động thực tế được ghi bằng báo cáo trước/sau trong log startup.
- `arp_ignore=0` và `arp_accept=0`: để giá trị riêng của `tap0` chính là giá trị hiệu lực.
- `arp_announce` không cần chuẩn hóa, vì `max(all, 2) = 2`.

`verify` kiểm **cả** giá trị cấu hình **và** giá trị hiệu lực. Ghi chú: `arp_accept=0` không đủ để chống mọi thay đổi neighbor. Bảo vệ chính vẫn là bảng nft `arp` và neighbor `PERMANENT` (§4.4).

V0 ở 06B-2A chỉ kiểm giá trị riêng của `tap0`, **chưa** kiểm giá trị hiệu lực. Lần đó, `rp_filter` hiệu lực thực tế là 2 (loose).

### 4.3 Ruleset `guest.nft`

Ruleset gồm ba bảng. Các bộ đếm có tên được dùng làm bằng chứng điểm chặn.

```nft
# --- L2: chặn sớm nhất, ngay khi khung vào tap0 ---
table netdev sandbox_guest_l2 {
  counter l2_bad_mac {}
  counter l2_bad_ethertype {}
  chain ingress {
    type filter hook ingress device "tap0" priority -500; policy accept;
    ether saddr != 52:54:00:c7:00:02 counter name "l2_bad_mac" drop
    ether type != { ip, arp } counter name "l2_bad_ethertype" drop     # IPv6, LLDP, VLAN, …
  }
}

# --- ARP: mục 4.4 ---
table arp sandbox_guest_arp {
  counter arp_in_ok {}
  counter arp_in_drop {}
  counter arp_out_ok {}
  counter arp_out_drop {}
  chain input {
    type filter hook input priority 0; policy accept;
    iifname != "tap0" accept
    arp htype 1 arp ptype ip arp hlen 6 arp plen 4 \
      arp saddr ether 52:54:00:c7:00:02 arp saddr ip 10.200.0.2 arp daddr ip 10.200.0.1 \
      arp operation { request, reply } counter name "arp_in_ok" accept
    counter name "arp_in_drop" drop
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oifname != "tap0" accept
    arp saddr ip 10.200.0.1 arp daddr ip 10.200.0.2 \
      arp operation { request, reply } counter name "arp_out_ok" accept
    counter name "arp_out_drop" drop
  }
}

# --- IPv4/IPv6 ---
table inet sandbox_guest {
  counter allow_svc {}
  counter drop_spoof {}
  counter drop_non_ipv4 {}
  counter drop_worker_other {}
  counter drop_private {}
  counter drop_bcast_mcast {}
  counter drop_public {}
  counter drop_input_backstop {}
  counter drop_forward {}
  counter drop_out {}

  chain prerouting {            # trước quyết định định tuyến: thấy MỌI gói guest gửi đi
    type filter hook prerouting priority -150; policy accept;
    iifname != "tap0" accept
    meta nfproto != ipv4 counter name "drop_non_ipv4" drop
    ip saddr != 10.200.0.2 counter name "drop_spoof" drop
    ip daddr 10.200.0.1 tcp dport 8011 counter name "allow_svc" accept
    ip daddr 10.200.0.1 counter name "drop_worker_other" drop
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
               172.16.0.0/12, 192.168.0.0/16 } counter name "drop_private" drop
    ip daddr { 224.0.0.0/4, 255.255.255.255 } counter name "drop_bcast_mcast" drop
    counter name "drop_public" drop
  }
  chain input {                 # lớp dự phòng; mong đợi drop_input_backstop = 0
    type filter hook input priority -10; policy accept;
    iifname != "tap0" accept
    ip saddr 10.200.0.2 ip daddr 10.200.0.1 tcp dport 8011 accept
    counter name "drop_input_backstop" drop
  }
  chain forward {               # lớp dự phòng; với ip_forward=0 thường không có gói tới đây
    type filter hook forward priority -10; policy drop;
    counter name "drop_forward" drop
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname != "tap0" accept
    ip saddr 10.200.0.1 ip daddr 10.200.0.2 tcp sport 8011 ct state established counter accept
    counter name "drop_out" drop
  }
}
```

Ghi chú về các lớp chặn:

- Gói tới đích không thuộc worker bị drop ở **prerouting**, trước định tuyến. Với `ip_forward=0`, nếu không có prerouting thì kernel bỏ gói ở bước định tuyến mà **không qua chain `input` hay `forward`**, và có thể gửi lại ICMP unreachable. Vì vậy:
  - bằng chứng chặn là các bộ đếm `drop_private`, `drop_public`, …;
  - **không** dùng `drop_forward`; bộ đếm này có thể đứng yên ở 0.
- Chain `input`, `forward` và lớp `ip_forward=0` là các lớp dự phòng. `drop_input_backstop` và `drop_forward` khác 0 là dấu hiệu bất thường cần điều tra.
- `drop` ở bất kỳ base chain nào cũng là quyết định cuối, nên bảng khác (ví dụ luật DNS nhúng của Docker) không mở lại được lưu lượng đã bị chặn.
- `ip saddr`, `ip daddr` và cổng trong `guest.nft` phải khớp đúng hằng số ở mục 4.1.

### 4.4 Chính sách ARP và chống giả mạo

| Hướng | Cho phép | Chặn | Lớp chặn |
|---|---|---|---|
| Guest → worker, request | `who-has 10.200.0.1 tell 10.200.0.2`, `sha=GUEST_MAC` | request hỏi IP khác (dò `192.168.60.10`, `.1`…) | `arp_in_drop` |
| Guest → worker, reply | `10.200.0.2 is-at GUEST_MAC`, gửi tới `10.200.0.1` | reply tự nhận IP khác (giả `10.200.0.1`, `192.168.60.10`) | `arp_in_drop` |
| Gratuitous ARP từ guest | — | mọi gratuitous ARP. Gói này có `tpa = spa`, nên không khớp `arp daddr ip 10.200.0.1`, kể cả khi guest khai đúng `10.200.0.2`. Neighbor `permanent` là lớp thứ hai | `arp_in_drop`; neighbor permanent |
| MAC nguồn khác `GUEST_MAC` | — | mọi khung (ARP và IP) | `l2_bad_mac` |
| Worker → guest | request/reply giữa `10.200.0.1` và `10.200.0.2` | mọi ARP khác ra `tap0` | `arp_out_drop` |

Các biện pháp bổ trợ:

- `ip neigh … nud permanent` cho `10.200.0.2`: ARP giả không cập nhật được entry permanent.
- `arp_ignore=1` và `arp_announce=2`: worker không trả lời ARP cho IP của `eth0` qua `tap0`.
- `arp_accept=0`: không tạo neighbor từ gratuitous ARP.
- `rp_filter=1` và luật `drop_spoof`: chặn gói IP có nguồn khác `10.200.0.2`.

Phạm vi tác động: `tap0` là link điểm-điểm chỉ có worker và guest. Giả mạo, dù lọt, cũng không chạm được `sandboxnet`. Các luật trên chủ yếu bảo đảm tính đúng của bằng chứng và phòng thủ nhiều lớp.

---

## 5. Allowlist API phía guest (bắt buộc)

Lọc API là **bắt buộc**, không phải tùy chọn. Lý do: `server.py` nghe `0.0.0.0:8011` nên mạng chỉ khống chế được cổng, còn route thì phải lọc ở tầng ứng dụng.

**Cơ chế:**

- Middleware trong `sandbox-worker/server.py`, hoặc dependency chung cho `router/sandbox_router.py` và `router/healthcheck.py`.
- Nếu `request.client.host` thuộc `10.200.0.0/30`, chỉ cho phép đúng các route dưới đây. Mọi request khác từ guest bị trả **403** và ghi log.
- `{T}` là task hiện tại, đọc từ `/run/sandbox/current_task`:
  - poller ghi file này **trước** lần boot QEMU phase 1;
  - poller xóa file trong `finally` sau phase 2, hoặc khi lỗi/hủy;
  - không có file nghĩa là guest bị từ chối mọi route.

| Phương thức | Route (tiền tố `/api/v1/sandbox-worker`) | Guest được phép |
|---|---|---|
| GET | `/get-task/{T}/file` | Có |
| POST | `/update-task/{T}/strace` | Có |
| POST | `/update-task/{T}/sar` | Có |
| GET | `/healthcheck` (không tiền tố) | **Không** (403) |
| POST | `/submit-task/{any}` | **Không** |
| POST | `/stop` | **Không** |
| GET/POST | `/get-task/{khác T}/…`, `/update-task/{khác T}/…` | **Không** |
| * | mọi route/phương thức khác, `/docs`, `/openapi.json` | **Không** |

Request **không** đến từ guest (manager gọi `/stop` theo L3, healthcheck nội bộ) đi qua bình thường.

---

## 6. Kiểm tra cô lập (verify)

### 6.1 Ruleset chuẩn và chuẩn hóa

**Chuẩn mong đợi** là file `sandbox-worker/isolation/expected-ruleset.json`:

- được lưu trong repository và được reviewer duyệt cùng `guest.nft`. Hiện tại file nằm trong **working tree, chưa commit**;
- **không** được sinh lúc runtime từ ruleset đang nạp; hash của ruleset hiện tại không bao giờ được dùng làm chuẩn.

**Chuẩn hóa** (`normalize`), áp dụng cho output `nft -j list table …` của từng bảng `netdev sandbox_guest_l2`, `arp sandbox_guest_arp`, `inet sandbox_guest`:

1. Bỏ khóa `handle` ở mọi phần tử, và bỏ phần tử `metainfo`.
2. Bộ đếm ẩn trong rule (`{"counter": {"packets": n, "bytes": m}}`): thay bằng `{"counter": {}}`.
3. Đối tượng counter có tên: giữ `family`, `table`, `name`; bỏ `packets`, `bytes`.
4. Giữ nguyên mọi thứ thuộc cấu trúc:
   - family, tên bảng và chain, `type`, `hook`, `prio`, `policy`, `dev`;
   - thứ tự rule và toàn bộ biểu thức match/verdict, kể cả `ct state`.
5. Xuất JSON với `sort_keys=True`, giữ nguyên thứ tự danh sách rule.

**Chuẩn có hai lớp đối chiếu:**

- *Khi phát triển (06B):* nạp `guest.nft` trong một netns tạm, có tạo `tap0` giả để bảng `netdev` gắn được, rồi chạy `normalize`. Kết quả phải **bằng** `expected-ruleset.json`; nếu khác, kiểm thử thất bại. Lần đầu tạo expected, reviewer phải **đọc lại nội dung JSON**, không chỉ hash.
- *Lúc chạy:* `normalize(ruleset đang nạp) == expected-ruleset.json`.

Định dạng JSON có thể khác giữa các phiên bản `nft`. Vì vậy phải ghim gói `nftables` của Ubuntu 22.04 và ghi phiên bản vào evidence. Khi đổi phiên bản phải sinh lại và review lại expected.

**Ngoài ruleset, `verify` còn kiểm:**

| Nhóm | Điều kiện |
|---|---|
| sysctl (06B-2AR) | **Cấu hình:** `net.ipv4.ip_forward=0`, `conf.all.rp_filter=1`; trên `tap0`: `rp_filter=1`, `arp_ignore=1`, `arp_announce=2`, `arp_accept=0`, `forwarding=0`; IPv6 `all.forwarding=0`, `tap0.disable_ipv6=1`. **Hiệu lực trên `tap0`** (theo §4.2a): `rp_filter=1`, `arp_ignore=1`, `arp_announce=2`, `arp_accept=0`, `forwarding=0` |
| Link | `tap0` tồn tại, chỉ có `10.200.0.1/30`, không có master; trong netns không có interface kiểu bridge; `eth0` vẫn có IP trong `192.168.60.0/24`. **06B-2BR:** quét mọi interface (kể cả `lo`); mọi địa chỉ IPv4 nằm trong hoặc có dải trùng với `10.200.0.0/30` ngoài `10.200.0.1/30` trên `tap0` đều làm verify thất bại |
| Neighbor | `10.200.0.2 lladdr 52:54:00:c7:00:02 PERMANENT` trên `tap0` |
| Route | không có route nào ngoài `10.200.0.0/30` trỏ qua `tap0` |

### 6.1a Phạm vi đối chiếu (06B-1R)

**Runtime hiện chỉ đối chiếu ba bảng CT-01:** `netdev sandbox_guest_l2`, `arp sandbox_guest_arp`, `inet sandbox_guest`. Các bảng khác trong network namespace của worker **không** được kiểm. Ví dụ: Docker tạo bảng `ip nat` (qua iptables-nft) cho DNS nhúng `127.0.0.11` trong user-defined network [GĐ].

Phép thử "extra base chain" chỉ chứng minh rằng thêm chain **bên trong** một bảng CT-01 thì bị phát hiện. Nó **không** chứng minh việc phát hiện bảng lạ ở nơi khác.

**Rủi ro còn lại:**

- `drop` của ta là quyết định cuối, nên một bảng khác không thể `accept` để mở lại lưu lượng đã bị chặn.
- Tuy nhiên, một bảng khác có thể tác động **trước** điểm chặn của ta. Ví dụ: chain `netdev ingress` trên `tap0` với priority < -500 dùng `fwd to eth0` sẽ chuyển khung đi thẳng, vượt qua mọi luật.
- Điều này cần quyền root trong worker, cùng mức rủi ro đã ghi ở §10.

**Đề xuất mở rộng** (chưa làm, cần reviewer duyệt riêng):

1. Lúc V0/V1/V2, liệt kê `nft -j list ruleset`, rồi:
   - báo lỗi với **mọi** base chain `netdev` gắn `tap0` không thuộc `sandbox_guest_l2`;
   - báo lỗi với mọi bảng `bridge`;
   - báo lỗi với mọi base chain ở family `ip`/`inet`/`arp`/`netdev` không nằm trong allowlist.
2. Allowlist các bảng Docker phải lấy **thực nghiệm** từ worker đang chạy ở 06B-2 (tên bảng, chain, hook, priority), được review, rồi chuẩn hóa theo cùng cách. Không đoán trước.
3. Cần tính khả năng Docker hoặc phiên bản Docker khác tạo bảng khác. Khi đó V0 sẽ fail-closed, và allowlist phải được review lại.

### 6.2 Thời điểm kiểm tra

| Mã | Thời điểm | Thất bại thì |
|---|---|---|
| V0 | Khởi động container: `run.sh` bước 4 | `run.sh` exit ≠ 0; `server.py` và poller không chạy; không có QEMU |
| V1 | Ngay trước khi spawn QEMU **phase 1** (`behaviour_analysis`, `analysis.py:291-296`) | `RuntimeError("network isolation check failed: <mục>")` → poller gửi `FAILED` (`poller.py:53-63`); không spawn |
| V2 | Ngay trước khi spawn QEMU **phase 2** (`analysis.py:303-305`) | Như V1; phase 1 đã kết thúc nên không có guest nào đang chạy |

**Khi mất luật:**

- Mất luật giữa hai tác vụ, hoặc giữa phase 1 và phase 2: bị V1/V2 phát hiện trước lần boot kế tiếp.
- Mất luật **trong lúc guest đang chạy**: thiết kế hiện tại **không** phát hiện cho tới V2 hoặc tác vụ sau. Xem giới hạn ở mục 10.
- Có thể làm sau: một watchdog kiểm tra định kỳ trong `_run_analysis`, phát hiện lỗi thì kill QEMU và tshark. Watchdog chỉ thu hẹp cửa sổ rủi ro, không loại bỏ nó.

---

## 7. Ma trận kiểm thử (thiết kế; đã thực hiện một phần)

**Tình trạng thực hiện (cập nhật 06B-4FR; nguồn: [`../KQCaiTien.md`](../KQCaiTien.md), CT-01):**

| Phép thử | Tình trạng |
|---|---|
| T01–T04 | Middleware với nguồn mô phỏng (06B-2B); từ guest ARM/MIPS thật (06B-3A), trong phạm vi ghi ở [`evidence/task06b3a-summary.md`](evidence/task06b3a-summary.md) |
| T05–T11 | Ma trận IPv4 20 probe có đối chứng (06B-3B, chấp nhận): T07–T10 đạt về mạng; T05, T06, T11 **một phần** (thiếu `8.8.8.8:53` UDP, ICMP, IP LAN thứ hai, `10.200.0.1` cổng 22/80). Các lần tích hợp harness sau (06B-3E, 06B-3G) có kết quả CHƯA KIỂM CHỨNG do gói biên |
| T12, T13 | 5 ca kiểm quy tắc (B1, B2, B4, I1, I2) chạy tích hợp một lần ở 06B-4G: 9/10 ĐẠT (kiểm quy tắc), ARM T13-I1 CHƯA KIỂM CHỨNG (gói ở biên); không có đối chứng sống. B3, I3 chưa viết |
| T14, T15 | T14 A1/A2/A3 và T15 S1 (gratuitous do kernel guest, mức 1) **chuẩn bị offline** ở 06B-4H, sửa theo review ở 06B-4HR/06B-4HR1/06B-4HR2 (`arp_cases.py`; hành vi guest mới chỉ mô phỏng); nối vào harness/run script `run-06b4i.sh` ở mức offline (06B-4I, sửa review ở 06B-4IR1/06B-4IR2), **chưa chạy**. T15 mức 2 (ARP reply giả) chưa phủ (D1) |
| T16, T17, T20 | Kế hoạch [`ct01-remaining-tests-plan.md`](ct01-remaining-tests-plan.md); harness và bộ đánh giá L2/ARP offline; **chưa viết probe, chưa chạy** |
| T18, T19, T21 | Chưa có kết luận riêng. Các harness có so trạng thái host trước/sau, nhưng chưa được nghiệm thu như T21 |
| F1 | Ở mức V0 (06B-2A): chỉ **lỗi cú pháp `guest.nft`** → exit 1; **thiếu binary `nft` chưa kiểm** |
| F2 | Ở mức V0 (06B-2A): `ALLOW_VM_INTERNET=true` → exit 1 |
| F3–F6 | Chưa làm |

### 7.1 Nguyên tắc bằng chứng

- Mỗi phép thử chạy **riêng lẻ, tuần tự**. Chụp các bộ đếm có tên ngay trước và ngay sau (`nft -j list counters`), lấy chênh lệch.
- **Đích bị chặn** cần đủ bốn thứ:
  1. phép thử từ guest thất bại;
  2. **đối chứng** cùng thời điểm từ một điểm được phép, cho thấy dịch vụ đích đang hoạt động;
  3. **bộ đếm đúng điểm chặn** (cột "Điểm chặn") khớp với **capture thực tế** trên `tap0`, xem quy tắc đối chiếu bên dưới;
  4. **không có gói nào của probe rời khỏi worker**, xem quy tắc capture phía host bên dưới.
- **Đối chiếu bộ đếm với capture:**
  - Chênh lệch bộ đếm phải bằng số khung/gói **thực tế** khớp bộ lọc của probe trong pcap `tap0` cùng khoảng thời gian, **kể cả retransmission** (TCP SYN gửi lại, truy vấn DNS lặp lại, ARP request lặp lại).
  - Không so với "số lần probe" mà người thử dự định. Gói nền của guest (ví dụ ARP, IGMP, DHCP tự phát) có thể làm bộ đếm tăng. Gói nền phải được đếm và trừ riêng bằng bộ lọc pcap, hoặc phải tạm dừng trước khi thử.
  - Các bộ đếm không liên quan chỉ được tăng đúng bằng số gói nền đã nhận diện.
- **Capture phía host:**
  - Bắt trên **veth phía host của worker**. Tìm veth bằng `cat /sys/class/net/eth0/iflink` trong worker để lấy ifindex, rồi `ip -o link | grep "^<ifindex>:"` trên host.
  - Bắt bổ sung trên bridge `sandboxnet` (`br-…`) và `ens33`.
  - Mỗi probe dùng **dấu hiệu riêng** để bộ lọc không lẫn với lưu lượng hợp lệ của worker:
    - cổng nguồn cố định (`curl --local-port`, `nc -p`);
    - cổng đích riêng;
    - payload đánh dấu (`echo PROBE-T05 | nc …`) khi có thể.
  - Probe giả mạo dùng chính dấu hiệu giả: lọc `src host 10.200.0.3` (T17), lọc `ether src 52:54:00:de:ad:01` (T16), lọc `arp and ether src 52:54:00:c7:00:02` (T14/T15).
  - Bộ lọc tổng quát `net 10.200.0.0/30 or ether host 52:54:00:c7:00:02` vẫn chạy song song, để phát hiện mọi gói của guest lọt ra.
- **Đối chứng đúng đích:**
  - Đối chứng phải dùng **cùng IP đích, giao thức và cổng** với probe. Ví dụ: T07 đối chứng bằng `192.168.60.1:22/tcp` cho probe `192.168.60.1:22/tcp`; không lấy SSH ở IP khác làm đối chứng.
  - Đích **không có dịch vụ sống** thì ghi phép thử là **"kiểm thử quy tắc"**: chứng minh luật khớp và drop đúng chỗ, **không** kết luận đã kiểm chứng việc chặn kết nối tới một dịch vụ. Gồm: IP LAN không có máy, `10.200.0.1:22/80`, broadcast/multicast, `ff02::1`, ARP tới IP không tồn tại.
- **Không** yêu cầu "không có gói trả lời" như một tiêu chí chung. Một số phép thử có thể nhận phản hồi cục bộ hợp lệ (ví dụ 403 từ API filter). Riêng đích ngoài worker, nếu thấy trên `tap0` một gói trả lời đến từ đích bên ngoài thì đó là **thất bại**.
- **Không** dùng `drop_forward` làm bằng chứng. Mong đợi nó bằng 0, kèm `ip_forward=0` theo verify.
- Timeout đơn lẻ không được tính là bằng chứng.
- **Đích được phép** cần mã HTTP và hash nội dung.

### 7.2 Ma trận

Ký hiệu: **G** guest; **W** container worker; **M** container manager; **H** host. `T` là task thử hiện tại; `X` là một task id khác. IP Mongo lấy bằng `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mongo-db`.

| ID | Nguồn | Đích / thao tác | Mong đợi | Điểm chặn / điểm cho phép | Đối chứng | Bằng chứng bổ sung |
|---|---|---|---|---|---|---|
| T01 | G | `GET 10.200.0.1:8011/…/get-task/T/file` | **200**; sha256 = tệp thử | `allow_svc` tăng; API cho phép | — | sha256 trong guest và trên W |
| T02 | G | `POST …/update-task/T/strace`, `…/sar` | **200**; tệp tới W | `allow_svc`; API cho phép | — | sha256 tệp trong thư mục tác vụ |
| T03 | G | `/healthcheck`, `POST /submit-task/X`, `POST /stop`, `GET /get-task/X/file`, `POST /update-task/X/strace`, `/docs` | **403** từng route; không tạo tác vụ, không có file stop | `allow_svc` (mạng cho qua), **API filter** chặn | W hoặc M gọi `/healthcheck` → 200 | log 403 của worker; `/tmp/sandbox_stop_requested` không tồn tại; không có thư mục `data/X` |
| T04 | G | Mọi route khi **không có** `current_task` | **403** | API filter | — | log |
| T05 | G | `1.1.1.1:443` TCP; `8.8.8.8:53` UDP (truy vấn DNS) | Chặn | `drop_public` | W kết nối được `1.1.1.1:443` (qua NAT Docker) | pcap `tap0`; tcpdump host không có gói |
| T06 | G | `192.168.177.2` (ICMP, TCP 53), một IP LAN khác | Chặn | `drop_private` | H `ping -c1 192.168.177.2` thành công | như trên |
| T07 | G | SSH host: `192.168.177.128:22`, `192.168.60.1:22`, `172.18.0.1:22` | Chặn | `drop_private` | W đọc banner `SSH-2.0` từ `192.168.60.1:22` | như trên; `journalctl -u ssh` trên host không có kết nối liên quan |
| T08 | G | Manager `192.168.60.10:8011` | Chặn | `drop_private` | W `GET /healthcheck` → 200 | log manager không có request từ guest |
| T09 | G | MongoDB `<mongo IP>:27017` | Chặn | `drop_private` | M `/status` 200, hoặc `mongosh ping` = 1 | như trên |
| T10 | G | IP `eth0` của worker `192.168.60.2:8011` | Chặn | `drop_private` | M gọi `http://192.168.60.2:8011/healthcheck` → 200 | như trên |
| T11 | G | `10.200.0.1` cổng 22 và 80; ICMP echo | Chặn | `drop_worker_other` | — (dùng để kiểm điểm chặn cục bộ) | pcap |
| T12 | G | Broadcast/multicast: `255.255.255.255`, `224.0.0.1` | Chặn | `drop_bcast_mcast` | — | tcpdump host không có gói |
| T13 | G | IPv6: `ping6 ff02::1%if`, gửi tới `fe80::…%if` | Chặn | `l2_bad_ethertype` | H `ss -ltn` thấy `[::]:22` đang nghe | `tap0` không có IPv6 (`ip -6 addr`); tcpdump host |
| T14 | G | ARP request hỏi IP khác: `arping 192.168.60.10`, `arping 10.200.0.3` | Không có reply | `arp_in_drop` | W `ip neigh` có MAC của manager trên `eth0` | pcap `tap0` chỉ có request |
| T15 | G | ARP giả mạo: gratuitous hoặc reply khai `10.200.0.1` hoặc `192.168.60.10`; `arping -U` | Bị drop; neighbor của W không đổi | `arp_in_drop` | — | `ip neigh show dev tap0` trước/sau (`PERMANENT`, đúng MAC) |
| T16 | G | Đổi MAC trong guest (`ip link set … address 52:54:00:de:ad:01`), rồi thử T01 | Thất bại | `l2_bad_mac` | T01 thành công trước khi đổi MAC | — |
| T17 | G | Giả IP nguồn: thêm `10.200.0.3/30`, gọi `curl --interface 10.200.0.3 …` | Chặn | `drop_spoof` | T01 thành công từ `10.200.0.2` | — |

> T17 **[Điều chỉnh R7, 2026-10-11 — giữ trace]:** nguồn giả của P1/P4 chuyển `10.200.0.3` → `10.200.0.5/32` vì `10.200.0.3` là địa chỉ broadcast của `10.200.0.0/30`; ở R6 ARM probe `.3` không tạo được khung nguồn `.3` (capture chỉ có IP thật `10.200.0.2`; cơ chế liên hệ chưa xác minh). `.5` là biến thể có ghi nhận của phép thử, không chứng nhận `.3` hay mọi nguồn giả.
| T18 | W | Poller → manager `get-file` | **Cho phép** (404 "No tasks" vẫn chứng minh tới được) | — | — | log poller và manager |
| T19 | M | `http://192.168.60.2:8011/healthcheck` (đường của `/stop`) | **200** | — | — | output python urllib trong M |
| T20 | M, H | Gửi tới `10.200.0.2` | Không định tuyến được | — | — | `ip route get 10.200.0.2` trên M/H không đi qua worker; không có gói vào `tap0` |
| T21 | H | SSH và phiên Claude | Không gián đoạn | — | — | phiên SSH giữ nguyên; `ip route`, `ip -br addr`, `sudo nft list ruleset` và sysctl `net.*` của host chụp trước/sau khi khởi động worker (chỉ khác phần Docker tự quản) |
| F1 | W | Ruleset hỏng (sửa `guest.nft` trong bản build thử) hoặc thiếu `nft` | Container exit ≠ 0; không có QEMU; poller không chạy | V0 | — | log; `pgrep -a qemu` rỗng; `/status` của manager không đổi |
| F2 | W | `ALLOW_VM_INTERNET=true` | Từ chối khởi động | V0 bước 0 | — | log; exit code |
| F3 | W | **Lúc worker rảnh**: xóa hoặc sửa một rule (`nft delete rule …`), đặt `ip_forward=1`, hoặc xóa neighbor permanent; rồi đưa tác vụ thử | Tác vụ `FAILED` với lý do nêu đúng mục sai; không có QEMU | V1 | — | log; `failure_reason` trong MongoDB; `pgrep qemu` |
| F4 | W | Làm hỏng cấu hình giữa phase 1 và phase 2 (hook kiểm thử) | `FAILED` trước khi boot phase 2 | V2 | — | log |
| F5 | W | Restart container (`docker compose restart sandbox-worker-1`) | Thiết lập lại thành công; V0 đạt | V0 | — | log |
| F6 | W | Ruleset đúng nhưng khác expected (thêm một rule accept vô hại) | V0 hoặc V1 thất bại do diff cấu trúc | V0/V1 | — | diff JSON in trong log |

Bộ thử chạy cho **ARM** (`eth1`) và **MIPS** (`br-lan`).

**Không kiểm thử trong 06B:** mất luật **khi guest đang chạy** (mục 6.2, mục 10).

---

## 8. Giả định cần kiểm chứng

| ID | Giả định | Cách kiểm |
|---|---|---|
| A1 | Netns container kế thừa `ip_forward=1` từ host (`devconf_inherit_init_net=0`) nên phải tự đặt 0 | Đọc sysctl trong W trước và sau thiết lập |
| A2 | Ghi sysctl `net.*` trong netns container không đổi giá trị của host | So sysctl host trước/sau (T21) |
| A3 | QEMU không tạo netdev `user`/slirp mặc định; NIC thứ nhất của ARM (không netdev) không có đường ra | `info network` trong monitor QEMU; `ip link` trong guest |
| A4 | Guest có `ip`, `route`, `curl`, `nc`, `ping`, `ping6`, `arping` (kèm `-U`, `-s`) | Liệt kê bằng harness |
| A5 | Trạng thái IPv6 mặc định trong container worker | sysctl trong W |
| A6 | `nftables` của Ubuntu 22.04 chạy được bảng `netdev` (ingress gắn `tap0`), `arp`, `inet` và `-j list` trong container privileged, kernel 6.8 | Build và nạp thử |
| A7 | Chain `netdev ingress` vẫn gắn với `tap0` qua nhiều lần QEMU mở/đóng tap persistent | Kiểm tra V1/V2 giữa các tác vụ |
| A8 | tshark trên `tap0` vẫn bắt đủ lưu lượng guest | pcap T01–T17 |
| A9 | Bảng của nhóm không ảnh hưởng luật DNS nhúng của Docker; tên `sandbox-manager` vẫn phân giải | T18 |
| A10 | Docker chặn liên mạng `sandboxnet↔dbnet` (lớp thứ hai cho T09) | Không bắt buộc với PA-2; ghi nhận nếu quan sát được |
| A11 | Phase 2 dùng lại cấu hình mạng như phase 1 | T01/T02 ở phase 2 |
| A12 | `request.client.host` trong FastAPI/uvicorn là IP nguồn thật (không có proxy) | T03, T19 |
| A13 | Đặt `mac=` trên `-device` được cả 4 kiến trúc chấp nhận, và guest dùng đúng MAC đó | pcap; `ip link` trong guest |
| A14 | `docker stop/start` tạo netns mới (không giữ `tap0` và luật cũ); `run.sh` vẫn chạy được nếu `tap0` hoặc bảng đã tồn tại | So inode netns; F5 |
| A15 | Neighbor `permanent` của `10.200.0.2` không bị xóa khi `tap0` mất hoặc có lại carrier (QEMU mở/đóng tap) | V1/V2 kiểm `PERMANENT` giữa các tác vụ |

---

## 9. Tác động tới source (Nhiệm vụ 06B)

| File | Thay đổi dự kiến |
|---|---|
| `sandbox-worker/run.sh` | Viết lại phần mạng theo mục 4.2; fail-closed |
| `sandbox-worker/isolation/guest.nft` (mới) | Ruleset mục 4.3 |
| `sandbox-worker/isolation/expected-ruleset.json` (mới) | Chuẩn đã review (mục 6.1) |
| `sandbox-worker/isolation/verify.py` (mới) | `normalize`, kiểm sysctl/link/neighbor/route; CLI dùng cho V0; hàm dùng cho V1/V2 |
| `sandbox-worker/Dockerfile` | Thêm gói `nftables` (ghi phiên bản); `COPY isolation/`; có thể bỏ `uml-utilities` |
| `sandbox-worker/config/settings.py` | Hằng số mục 4.1, hoặc import từ module isolation |
| `sandbox-worker/service/analysis.py` | `qemu_ip`/`qemu_gw` (357-358) theo hằng số; URL guest dùng (142-144) là `http://10.200.0.1:8011…`; prefix `/24` cứng (175) đổi thành `/30`; thêm `mac=` vào template QEMU (38-109); gọi V1/V2 |
| `sandbox-worker/poller.py` | Ghi/xóa `/run/sandbox/current_task` (mục 5), xóa trong `finally` |
| `sandbox-worker/server.py`, `router/*.py` | Middleware allowlist (mục 5) |
| `docker-compose.yml` | Bỏ chú thích "VM = IP worker + 1"; giữ `ALLOW_VM_INTERNET=false` |
| Không đổi | Manager, MongoDB, L1–L3 |

Đề xuất sau 06B: thay `privileged: true` bằng `cap_add: [NET_ADMIN]` + `devices: [/dev/net/tun]`. Cần kiểm thử QEMU và tshark trước khi áp dụng.

---

## 10. Phạm vi tác động, rollback và giới hạn còn lại

**Phạm vi tác động (theo thiết kế, chưa kiểm chứng — xem T21):**

- Các luật và sysctl nêu trên chỉ được ghi trong network namespace của container worker.
- Thiết kế không chủ đích thay đổi route, firewall hay sysctl của host.
- Tuy nhiên, container chạy `privileged`, nên về nguyên tắc vẫn có thể tác động host. Ví dụ: nạp `nftables` có thể khiến kernel host tự nạp thêm module `nf_tables`/`nft_*`, và các module này **vẫn nằm lại** sau khi container dừng.

**Rollback (chưa kiểm chứng):**

Phân biệt các thao tác:

| Thao tác | Container | Network namespace | Image / mã |
|---|---|---|---|
| `docker compose stop sandbox-worker-1` | Còn (trạng thái exited), cùng ID | Docker hủy sandbox mạng khi container dừng; lần `start` sau tạo **netns mới**, nên `run.sh` thiết lập lại từ đầu [GĐ A14] | Không đổi |
| `docker compose rm` hoặc `up --force-recreate` | Xóa / tạo container **mới** (ID mới) | netns mới | Không đổi; vẫn chạy image hiện tại |
| Rollback mã | — | — | `git checkout 3c54d55 -- sandbox-worker docker-compose.yml`, rebuild image worker, rồi tạo lại container |

Xác minh namespace (thuộc T21/F5):

- Ghi `docker inspect -f '{{.Id}} {{.State.Pid}} {{.NetworkSettings.SandboxKey}}'` và inode `readlink /proc/<pid>/ns/net` **trước và sau** mỗi thao tác.
- Sau `stop`: `SandboxKey` không còn tồn tại trên host.
- Sau `start` hoặc tạo lại: inode netns khác giá trị cũ, và V0 chạy lại thành công.
- `ip link show tap0` **trên host** phải luôn báo không tồn tại, vì `tap0` chỉ nằm trong netns của worker.

Các thao tác trên **không** gỡ module kernel đã được nạp lên host.

**Giới hạn còn lại:**

- Mất luật **khi guest đang chạy** không được phát hiện cho tới V2 hoặc tác vụ kế tiếp. Lớp `ip_forward=0` và việc không có bridge vẫn còn, trừ khi chúng cũng bị thay đổi.
- Guest vẫn chạm được `server.py` (TCP 8011). API filter giới hạn route, nhưng không giảm bề mặt tấn công của chính uvicorn/FastAPI.
- Không có Internet nên pcap chỉ có ý định kết nối; mã độc cần C2 sẽ không biểu hiện đầy đủ. Egress có kiểm soát (sinkhole, INetSim) là thiết kế riêng.
- Container worker vẫn `privileged`. Thoát khỏi QEMU (guest → tiến trình QEMU) nằm ngoài lọc mạng.
- Một tiến trình root bị chiếm quyền trong worker có thể gỡ luật nft.
- Manager vẫn không có xác thực và vẫn kết nối được MongoDB.
- Sau khi VM Ubuntu khởi động lại, manager không tự chạy lại (`restart: on-failure`) [KC 06A]. Điều này ảnh hưởng quy trình kiểm thử.

---

## 11. Triển khai 06B-1 (mã viết ở 06B-1; worker/guest thật chạy từ 06B-2A/06B-3A)

| Thành phần | File | Ghi chú so với thiết kế |
|---|---|---|
| Hằng số | `sandbox-worker/isolation/constants.py` | Nguồn duy nhất; `run.sh` lấy qua `python3 -m isolation.constants --shell` |
| Ruleset | `sandbox-worker/isolation/guest.nft` | Như §4.3. Rule `accept` ở output được gán bộ đếm có tên `allow_out_svc` |
| Verify | `sandbox-worker/isolation/verify.py` | Chuẩn hóa như §6.1. Expected chứa thêm `nft_version`, và runtime đối chiếu cả phiên bản. Kiểm `eth0` chỉ yêu cầu có IPv4 nằm ngoài `10.200.0.0/30`, không cố định subnet Docker. Nếu kernel không có IPv6 (`/proc/sys/net/ipv6` không tồn tại) thì bỏ qua các sysctl IPv6 |
| Fail-closed | `sandbox-worker/run.sh` | `set -euo pipefail`; từ chối `ALLOW_VM_INTERNET != false`; không đụng `eth0`; xóa và nạp lại bảng nft; V0 |
| V1/V2 | `sandbox-worker/service/analysis.py` | `verify_isolation()` trước mỗi lần spawn QEMU; thêm `mac=` trên NIC gắn tap; guest URL `http://10.200.0.1:8011…`; prefix `/30`; từ chối nếu `PORT != 8011` |
| current_task | `sandbox-worker/isolation/current_task.py`, `poller.py` | Ghi nguyên tử (tmp + `fsync` + `os.replace`); xóa trong `finally`; xóa file cũ khi poller khởi động; task id phải khớp `^[A-Za-z0-9._-]{1,128}$` |
| API allowlist | `sandbox-worker/isolation/apifilter.py`, `server.py` | Middleware ASGI. Peer lấy từ `scope["client"]`; uvicorn chạy `proxy_headers=False`. Peer không xác định hoặc IPv4-mapped của guest được coi là guest; websocket từ guest bị đóng |
| Kiểm thử | `sandbox-worker/tests/` | Unit test (không cần nft) và `tests/integration/nft_selftest.{sh,py}` (nft thật trong container `--network none`) |

**Phát hiện khi chạy nft thật (06B-1):**

- `nftables v1.0.2` (Ubuntu 22.04, gói `1.0.2-1ubuntu3.1`) **không xuất khóa `dev`** cho chain netdev trong `nft -j`. Vì vậy chuẩn hóa JSON không thấy device.
- Đã bổ sung `check_netdev_device()`: đọc `nft list table netdev sandbox_guest_l2` dạng văn bản và yêu cầu chain ingress gắn đúng `tap0`. Đột biến `tap0 → lo` được phát hiện ở lần kiểm thử 2.
- Trong container `--network none` chưa chạy `run.sh`, `net.ipv4.ip_forward` mặc định là `1`. Điều này ủng hộ giả định A1.

**06B-1R (sửa theo review):**

| Hạng mục | Thay đổi |
|---|---|
| Vòng đời QEMU | `shutdown_qemu()` gửi SIGINT, chờ tối đa `QEMU_SIGINT_GRACE` (10 s); nếu chưa thoát thì SIGKILL và chờ tối đa `QEMU_SIGKILL_GRACE` (5 s). "Thoát" được xác nhận bằng `isalive()` (có `waitpid`). Không xác nhận được thì ném `QemuShutdownError` và **không chạy V2 hay phase 2**. Chỉ ghi "QEMU shutdown complete" sau khi đã xác nhận. Lỗi trong `_start_qemu` (sau khi spawn), trong `_configure_network`, `_run_analysis`, `_exfiltrate`, hoặc khi hủy, đều dừng QEMU trong `except`/`finally`. **Đây chỉ là phần vòng đời QEMU cần cho CT-01; CT-03 (tshark, thư mục tác vụ, các tình huống khác) chưa làm** |
| Transaction nft | `isolation/load.nft`: cặp `table X` / `delete table X` cho từng bảng CT-01, rồi `include "guest.nft"`, tất cả trong **một** `nft -f`. Không flush ruleset của cả namespace. Lỗi cú pháp hoặc lỗi đánh giá thì toàn bộ transaction bị bỏ, bảng cũ còn nguyên. Lần khởi động đầu mà lỗi thì không có bảng nào, và `set -e` dừng `run.sh` (fail-closed) |
| Ghim gói | `nftables=1.0.2-1ubuntu3.1`, `libnftables1=1.0.2-1ubuntu3.1`, `libnftnl11=1.2.1-1build1`, `libjansson4=2.13.1-1.1build3`. `libmnl0` và `libxtables12` do `iptables` kéo vào, không ghim riêng |
| Phạm vi | §6.1a |

`isolation/expected-ruleset.json` chỉ được tạo từ output của container kiểm thử (`generated-expected-ruleset.json`), rồi được reviewer đọc trước khi commit. `run.sh` và `verify.py` **không** sinh chuẩn lúc runtime.
