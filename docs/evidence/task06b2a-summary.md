# Minh chứng Nhiệm vụ 06B-2A: startup và V0 thật, chưa có guest (06/10/2026)

**Bối cảnh:**

- Người dùng đã tạo snapshot và bật lại VM (host khởi động lúc 13:20 UTC).
- Reviewer đã chấp nhận bản sửa 06B-1R và nội dung `expected-ruleset.json` (sha256 `9fb32d7f…2b16`) **ở mức trước guest**.
- Nhánh `feat/ct01-network-isolation`, HEAD `3c54d55`, thay đổi chưa commit. Working tree trước khi làm khớp tree đã bàn giao ở 06B-1R: `f97351b7946b6c2ce4aad44b0f4887a02151253d`.

**Không** chạy service `sandbox-worker-1`, server/poller thật, QEMU hay mẫu nào. Không sửa mạng, firewall hay sysctl của host. Không bật lại manager.

## Harness

Bản lưu trong repo: [`task06b2a/harness/`](task06b2a/harness/). Bản dùng khi chạy nằm ngoài repo, tại `/home/dathq/projects/ct01-06b2a/`.

| File | sha256 |
|---|---|
| `run-06b2a.sh` | `0765d4fa3bb5a66779337e29b24eba7fd5baa0e4a86c5374db52bbac665341c3` |
| `sentinel/server.py` | `517be1541e1c0b812f014fa84d93406d54aef7e56e3d1a1979de331faf0eeb20` |
| `sentinel/poller.py` | `7e49a99bac3a1b5f277d0700b4250043a13fce15bbb6f5c58dd7d24d44a8ab26` |
| `broken-guest.nft` | `5a967a476726c09832b31c02be7c428fe042880e03ac9e9cd921533f784f483b` |

Lệnh do người dùng chạy: `sudo bash /home/dathq/projects/ct01-06b2a/run-06b2a.sh`. Output đầy đủ: [`task06b2a/run.log`](task06b2a/run.log), sha256 `62f432c5…f55b`.

Cấu hình container test:

- Image `sandbox-worker:latest`, id `sha256:a526b0c7175258ce089ba0e15885d4dbf19c02ede35cde1eb0f9abcaf7c2d71e`, đúng bản build 06B-1R.
- Network `cic-ynu-iotmal-sandbox_sandboxnet` (id `1d86fe3e8bbe…`, bridge, subnet `192.168.60.0/24`, gateway `.1`; lúc bắt đầu không có container nào gắn vào).
- `--privileged` như Compose; `--restart no`; không publish cổng; không dùng host network; không mount dữ liệu lab hay `docker.sock`.
- `/app/server.py` và `/app/poller.py` được thay bằng sentinel qua bind mount chỉ đọc. `run.sh`, `verify.py`, `constants.py`, ruleset và expected đều là bản thật trong image; sha256 trong container khớp repo.

## 1. Trường hợp hợp lệ (`ALLOW_VM_INTERNET=false`): ĐẠT

| Kiểm tra | Kết quả | File |
|---|---|---|
| V0 của `run.sh` thật | `ISOLATION OK (V0 startup): ruleset,sysctl,link,neighbor,route` lúc `13:25:19.110703Z` | [`docker-logs.txt`](task06b2a/ct01-06b2a-valid/docker-logs.txt) |
| V0 xảy ra trước sentinel | Sentinel được gọi lúc `13:25:19.127120Z` (server, pid 26) và `.127224Z` (poller, pid 1), **sau** dòng V0 | `sentinel/*-called` |
| Chạy lại verify đầy đủ trong container đang sống | `ISOLATION OK (06B-2A recheck)`, `verify exit=0` | [`verify-recheck.txt`](task06b2a/ct01-06b2a-valid/verify-recheck.txt) |
| Ruleset đã chuẩn hóa tại runtime so với expected trong working tree | **IDENTICAL** (diff 0 byte) | `normalized-runtime.json`, `normalized-diff.txt` |
| `nft --version` | `nftables v1.0.2 (Lester Gooch)` | `nft-version.txt` |
| sysctl (trong netns container) | `ip_forward=0`, `ipv6 all.forwarding=0`, `default.disable_ipv6=1`, `tap0.disable_ipv6=1`, `tap0.arp_ignore=1`, `tap0.arp_announce=2`, `tap0.arp_accept=0`, `tap0.rp_filter=1` | [`sysctl.txt`](task06b2a/ct01-06b2a-valid/sysctl.txt) |
| `eth0` | `192.168.60.2/24`, thuộc `cic-ynu-iotmal-sandbox_sandboxnet`, gateway `.1`; không có IPv6 | `ip-addr.txt`, `networks.txt` |
| `tap0` | `tun`/`tap`, **master: None**, chỉ có `10.200.0.1/30`, NO-CARRIER (chưa có guest) | `tap0.txt`, `ip-d-link.txt` |
| Bridge trong netns | 0 | `bridges.txt` |
| Neighbor | `10.200.0.2 lladdr 52:54:00:c7:00:02 PERMANENT` | `ip-neigh.txt` |
| Route | `default via 192.168.60.1 dev eth0`; `10.200.0.0/30 dev tap0`; `192.168.60.0/24 dev eth0`; IPv6: không có | `ip-route.txt`, `ip6-route.txt` |
| Tiến trình | PID 1 `python3 poller.py` (sentinel), `bash run.sh`, `python3 server.py` (sentinel). Không có QEMU hay tshark trong container; không có `qemu-system` trên host | [`ps.txt`](task06b2a/ct01-06b2a-valid/ps.txt) |

**Bảng nft ngoài ba bảng CT-01** (chỉ để review, chưa triển khai allowlist): **`table ip nat`** do Docker tạo cho DNS nhúng.

- Chain `OUTPUT` (`nat` hook output priority -100) và `POSTROUTING` (srcnat) chỉ khớp `ip daddr 127.0.0.11` hoặc `ip saddr 127.0.0.11`, rồi `dnat`/`snat` sang cổng DNS nội bộ (cổng ngẫu nhiên mỗi lần chạy).
- Bảng này không có chain ở hook prerouting, forward hay ingress, và không khớp `tap0`.
- Nội dung: [`nft-ruleset-stateless.txt`](task06b2a/ct01-06b2a-valid/nft-ruleset-stateless.txt).

## 2. Hủy container và namespace

| Bước | Kết quả |
|---|---|
| Trước khi stop | pid `2574`, SandboxKey `/var/run/docker/netns/37350c981a8a`, netns `net:[4026532740]` (khác netns host `net:[4026531840]`) |
| `docker stop -t 10` | exit 0; `status=exited exit=0 sandboxkey=""` |
| `docker rm` | exit 0 |
| Sau rm | File SandboxKey không còn; pid 2574 không còn; container đã xóa; trên host `Device "tap0" does not exist` |

File: [`netns.txt`](task06b2a/ct01-06b2a-valid/netns.txt).

## 3. Các trường hợp phải từ chối khởi động: ĐẠT

| Trường hợp | Exit code | Log | Sentinel bị gọi | QEMU | Restarts |
|---|---|---|---|---|---|
| `ALLOW_VM_INTERNET=true` | **1** | `FATAL: ALLOW_VM_INTERNET=true is not supported; guest egress is not designed yet (CT-01).` | Không | Không | 0 |
| `guest.nft` lỗi cú pháp (mount chỉ trong container test) | **1** | `In file included from /app/isolation/load.nft:17` … `guest.nft:91:24-24: Error: syntax error, unexpected '{'` | Không | Không | 0 |

File: [`ct01-06b2a-allow-true/`](task06b2a/ct01-06b2a-allow-true/), [`ct01-06b2a-broken-nft/`](task06b2a/ct01-06b2a-broken-nft/).

## 4. Trạng thái host trước và sau

**Không đổi:** `ip -br link`, `ip route` (IPv4), `nft -s list ruleset` của host (gồm cả luật Docker), sysctl (`ip_forward`, `rp_filter`, IPv6), cổng TCP đang nghe, danh sách network Docker, `/proc/sys/net/bridge` (không tồn tại), `tap0` trên host (không tồn tại), QEMU (không có).

**Có thay đổi, kèm giải thích** (không có thao tác thủ công nào trên host):

| Khác biệt | Nguyên nhân | Loại |
|---|---|---|
| `docker ps`: "Up 4 minutes" → "Up 5 minutes" của `mongo-db` | Chuỗi hiển thị thời gian chạy | Hiển thị |
| `br-1d86fe3e8bbe` (bridge `sandboxnet`) có thêm `fe80::c80:d8ff:fe19:b37a/64` và route `fe80::/64 … linkdown` | **Suy luận, chưa kiểm chứng riêng:** khi Docker gắn veth của container test vào bridge, bridge có carrier lần đầu kể từ khi host khởi động lại, nên kernel host tự cấu hình địa chỉ IPv6 link-local (host bật IPv6: `all.disable_ipv6=0`). Địa chỉ vẫn còn sau khi container bị xóa | Do Docker/kernel tự làm |
| Module `nft_ct` được nạp trên host | Ruleset CT-01 dùng `ct state established`; khi nạp ruleset trong netns container, kernel dùng chung nên tự nạp module. Module vẫn còn sau khi container bị xóa (đúng như giới hạn đã ghi ở thiết kế §10) | Do ruleset CT-01 (tự động) |

Không có khác biệt nào chưa giải thích được. Các file `host-diff-*.diff` lưu chi tiết.

## 5. Phát hiện cần reviewer quyết định

1. **`rp_filter` hiệu lực trên `tap0` là loose (2), không phải strict.**
   - Kernel áp dụng `max(conf.all.rp_filter, conf.tap0.rp_filter)`. Trong netns container, `net.ipv4.conf.all.rp_filter=2`, cùng giá trị với host (`host-before/sysctl.txt`: `all.rp_filter=2`), khớp với cơ chế kế thừa `devconf_inherit_init_net=0`, nên dù `tap0.rp_filter=1`, giá trị hiệu lực vẫn là 2.
   - `verify` hiện chỉ kiểm giá trị riêng của `tap0`, nên **không phát hiện** điều này.
   - Chống giả IP nguồn vẫn có lớp chính là rule nft `drop_spoof` (`ip saddr != 10.200.0.2`, đã nằm trong expected). `rp_filter` chỉ là lớp bổ trợ.
   - Lựa chọn: (a) đặt `net.ipv4.conf.all.rp_filter=1` trong netns worker (ảnh hưởng cả `eth0`) và kiểm giá trị hiệu lực; hoặc (b) chấp nhận loose, sửa thiết kế và verify để kiểm giá trị hiệu lực, ghi rõ đó chỉ là lớp bổ trợ. **Chưa sửa mã.**
2. Tương tự, `arp_ignore`/`arp_announce` hiệu lực = `max(all, tap0)`, và `arp_accept` phụ thuộc cả `all`. Lần chạy này **không thu** `net.ipv4.conf.all.arp_*`, nên giá trị hiệu lực của ARP **chưa được xác nhận**. Đề xuất `verify` kiểm giá trị hiệu lực.
3. IPAM cấp cho container test địa chỉ `192.168.60.2`, tức chính IP Compose dành cho worker. Mô tả trước khi chạy ("không chiếm `.2`") là sai; không có xung đột vì worker không chạy.
4. Hai sentinel ghi ra stdout gần như cùng lúc, nên `docker logs` gộp thành một dòng. Đây chỉ là vấn đề hiển thị; thứ tự được chứng minh bằng timestamp.

## 5a. Ghi chú bổ sung (06B-2AR)

- **V0 ở lần chạy này chỉ kiểm giá trị cấu hình của `tap0`, chưa kiểm giá trị hiệu lực.** Vì vậy kết quả "V0 đạt" của 06B-2A **không** bao gồm `rp_filter`/`arp_*` hiệu lực. 06B-2AR bổ sung phần này.
- **Hạn chế của harness 06B-2A** (đã sửa ở harness 06B-2AR):
  - `trap cleanup` được cài **trước** kiểm tra container trùng tên, nên khi ABORT vì trùng tên, nó vẫn `docker rm -f` container có sẵn đó. Lần chạy thực tế không gặp trường hợp này.
  - Image ID khác chỉ in WARNING rồi chạy tiếp, và chỉ so prefix.
  - Script luôn kết thúc `exit 0`; các tiêu chí chỉ được in ra, không được kiểm bắt buộc.
- **IPAM:** container test thực tế được cấp `192.168.60.2`, chính IP Compose dành cho worker. Mô tả trước khi chạy ("không chiếm `.2`") là sai; không xung đột vì worker không chạy.
- Log thô 06B-2A giữ nguyên.

## 6. Kết luận và giới hạn

- **V0 thật đạt** trong worker có cấu hình mạng thật (`sandboxnet`, privileged), và fail-closed đúng ở hai trường hợp từ chối.
- **CT-01 vẫn chưa đạt:**
  - chưa chạy `server.py` thật, nên HTTP và API allowlist qua mạng thật chưa được kiểm chứng;
  - chưa có guest, nên T01–T21 và F1–F6 chưa làm;
  - V1 và V2 trong luồng thật chưa chạy.

**Sửa báo cáo 06B-1R:** hash `06B1R-full.diff` đã báo là `1018e4e8…09ac6`, **sai phần đuôi**. Hash đầy đủ đúng là `1018e4e89ed32e6beafba656e25134e2afebee56f5667e12d9b037bd4fd5b3cc`. Hash `06B1R-delta.diff` đã đúng: `4bbfd820e6dbb9889be89fbef9786c2f8b385d148a270e5f3a6bc66192109ac6`.
