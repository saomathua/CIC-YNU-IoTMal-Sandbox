# Minh chứng Nhiệm vụ: precheck chỉ đọc cho bản 06B-4IR2 (08/10/2026)

> **Trạng thái review (cập nhật ở 06B-4IR3):** Codex chấp nhận hồ sơ đã lưu **ở phạm vi snapshot host không-sudo và parser offline**. **Chưa** chấp nhận script precheck để chạy root; chưa đủ căn cứ chốt lần chạy guest đề xuất. Bốn phát hiện, sửa ở [`task06b4ir3-summary.md`](task06b4ir3-summary.md):
>
> - **PC-1:** run script không dừng giữa kiến trúc; ARM FAIL vẫn gọi harness MIPS.
> - **PC-2:** collector ghi lỗi đọc thành "absent"/"not running", và exit 0 không chứng minh precheck đạt.
> - **PC-3:** `guest_state` bỏ sót admin UP. Đây là **lỗi xác nhận restore, chưa chứng minh false PASS của ca**.
> - **PC-4:** đường ghi output root có thể bị đổi đích qua cây user-writable.
>
> Các câu sai được đánh dấu *(đính chính 06B-4IR3)* tại chỗ; raw và evidence trong `task06b4ir2-precheck/` không sửa. Precheck này **đã đọc trạng thái mạng host** (`ip link/addr/route/neigh`, `sysctl`, `ss`, thử đọc nft, `/proc/net/arp`, sysfs); **chưa có probe mạng**.

> **Loại bằng chứng:** đọc trạng thái host (không sudo), kiểm tĩnh và chạy parser offline. **Không** khởi động guest, chạy run script, tạo/start container, gửi lệnh console, bật capture/listener/ctl, sudo, probe mạng hay sửa host/ruleset.
>
> - **Thiếu quyền Docker:** user `dathq` không thuộc nhóm `docker`; socket `root:docker` mode 660. Mọi mục Docker inspect/exec là **chưa kiểm** (không đủ điều kiện kiểm), **không phải lỗi sản phẩm**. Không dùng sudo, không tìm cách vượt quyền.
> - Guard 20 ms và hành vi ARM/MIPS chưa xác nhận. **CT-01 vẫn "Kiểm chứng một phần — chưa đạt".**

## 1. Đầu vào và trạng thái 4IR2

| Đầu vào | SHA-256 |
|---|---|
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir2-independent-review.md` | `133a0149afd8b9d11bf94131059bc1b113941c563080a22bc0646fa17338cb4f` |
| `/home/dathq/Documents/Codex/2026-10-08/l-m-vi-c-tr-n/outputs/06b4ir2-independent-evidence.json` | `430e6b124050fb049cdd47ad82aa09a1dff61419ea4936389d0a284470a847b8` |

- **Review 4IR2:** IR1-R1 và IR1-R2 đã khắc phục trong phạm vi offline; không còn lỗi chặn bước precheck. 4IR2 được **chốt ở mức offline**. Đây **không** phải chấp thuận chạy guest.
- Ghi chú đã thêm vào đầu [`task06b4ir2-summary.md`](task06b4ir2-summary.md).
- Đã đọc `AGENTS.md`, `CLAUDE.md`, `docs/deployment.md` §7, và precheck 06B-4G ([`task06b4g/precheck/precheck-06b4g.sh`](task06b4g/precheck/precheck-06b4g.sh), `baseline-nosudo/`, `run1/host-after/`).
- Thư mục làm việc: `/home/dathq/projects/ct01-06b4ir2-precheck/`. Evidence: [`task06b4ir2-precheck/`](task06b4ir2-precheck/).

## 2. Kết quả từng mục

| # | Mục | Kết quả | Bằng chứng |
|---|---|---|---|
| 1a | Manifest harness 4IR2 (35 file), không file lạ, không `__pycache__` | **Đạt** | [`raw/01-manifest.txt`](task06b4ir2-precheck/raw/01-manifest.txt) |
| 1b | `SHA256SUMS` của mọi evidence cũ (24 bộ); hash 2 file review | **Đạt** | như trên |
| 1c | Run script: `H`, image ID ghim, tên container/manager, copy-list 29 file, 13 mount chỉ đọc, 6 self-test, một lời gọi `CT01_SUITE=arp`, ctl `--arp-worker`, `CTL_MAC`/`ctl_mac`/`manager_mac`, `--outcome`/`--run-check` qua `arp_harness.py`, file worker được hash có trong working tree, `out/` chưa tồn tại | **Đạt** (37/37; kiểm tĩnh, không thực thi) | [`raw/04-runscript-static.txt`](task06b4ir2-precheck/raw/04-runscript-static.txt), [`static_runscript_check.py`](task06b4ir2-precheck/static_runscript_check.py) |
| 1d | Executable trên host: `docker`, `python3`, `tcpdump`, `nft`, `sysctl`, `ip`, `ss`, `pgrep`, `lsmod`, `journalctl`, `timeout`, `git`, `sha256sum`… | **Đạt** (theo PATH của user; PATH của root chưa kiểm) | như trên |
| 1e | Image `sandbox-worker:latest` có đúng ID đã review | **Chưa kiểm** (cần Docker) | [`raw/02-docker-access.txt`](task06b4ir2-precheck/raw/02-docker-access.txt) |
| 2 | Docker version/info, image/container/network inspect, trạng thái container | **Chưa kiểm** (permission denied, không sudo). Client Docker 29.8.2; server không đọc được | như trên |
| 3 | Đối chiếu sandboxnet/dbnet, IP, MAC endpoint, interface thực của worker/ctl/manager | **Chưa kiểm** qua Docker. Chỉ có quan sát gián tiếp ở host (§3) | [`raw/host-nosudo/`](task06b4ir2-precheck/raw/host-nosudo/) |
| 4 | `docker exec` chỉ đọc (`ip -V`, `ip -j neigh show`, `/proc/net/arp`, MAC/interface) | **Chưa kiểm**: không có quyền Docker. Container worker/ctl chỉ tồn tại trong lần chạy (run script tạo); không tạo chúng cho precheck | — |
| 5 | Raw output + parser hiện có chạy offline trên bản sao | **Đạt một phần** (§4): mẫu **host**, không phải worker/ctl | [`parsed/offline-parsers.json`](task06b4ir2-precheck/parsed/offline-parsers.json) |
| 6a | Không QEMU, không capture, không tiến trình harness; không thư mục capture cũ trong `/tmp`; `out/` chưa có | **Đạt** | [`raw/host-nosudo/processes.txt`](task06b4ir2-precheck/raw/host-nosudo/processes.txt), [`leftovers.txt`](task06b4ir2-precheck/raw/host-nosudo/leftovers.txt) |
| 6b | Host: link/addr/route/route6, cổng nghe, module mạng | **Đạt**: giống hệt baseline không-sudo 06B-4G và `host-after` 06B-4G | [`raw/03-host-vs-06b4g.txt`](task06b4ir2-precheck/raw/03-host-vs-06b4g.txt) |
| 6c | sysctl liên quan (`ip_forward`, `rp_filter`, `arp_*`…) | **Đạt**: giống `host-after` 06B-4G. Khác baseline không-sudo 4G đúng một khóa (`devconf_inherit_init_net=0`) mà baseline đó không ghi (đã biết ở 4G) | như trên |
| 6d | Ruleset nft, AppArmor | **Chưa kiểm** (cần root: "Operation not permitted") | [`raw/host-nosudo/nft-nosudo-attempt.txt`](task06b4ir2-precheck/raw/host-nosudo/nft-nosudo-attempt.txt) |
| 6e | Manager `exited`, không container thử, `mongo-db` chạy | **Chưa kiểm** qua Docker. Gián tiếp: bridge `sandboxnet` không có endpoint (DOWN), `dbnet` có một veth | §3 |

## 3. Quan sát gián tiếp ở host (không phải inspect Docker)

- `br-1d86fe3e8bbe` = `192.168.60.1/24`: bridge `sandboxnet` theo `targets-env.txt` của 06B-4G. Trạng thái `DOWN`/`NO-CARRIER`, không có veth gắn vào. Điều này **phù hợp với** manager đang `exited` và không có worker/ctl, nhưng chưa xác nhận bằng Docker.
- `br-09fed07bbb6b` = `172.18.0.1/16` (`dbnet`) có một veth `UP`. Neighbor host: `172.18.0.2` (MongoDB của 4G) và `172.18.0.3`. Chưa xác định container nào.
- MAC endpoint Docker quan sát từ host (`92:95:79:…`, `aa:ca:ff:…`) là **unicast locally administered ngẫu nhiên**, không theo dạng `02:42:…`. Validator 4IR2 nhận chúng (§4). Fixture offline dùng `02:42:…` chỉ là giá trị giả.

## 4. Parser hiện có chạy offline

Chạy trên bản sao `/home/dathq/projects/ct01-06b4ir2-precheck/harness-copy/`; kết quả: [`parsed/offline-parsers.json`](task06b4ir2-precheck/parsed/offline-parsers.json).

| Dữ liệu | Nguồn, thời điểm | Kết quả parser | Ý nghĩa |
|---|---|---|---|
| `ip -j neigh show` | **host** netns, iproute2 6.1.0, 08/10/2026 16:27 UTC | `arp_cases.parse_neigh_full`: 5 hàng hợp lệ, 0 vấn đề. Khóa `dst/dev/lladdr/state`; `state` là **list một phần tử** (`REACHABLE`, `STALE`) | Dạng JSON khớp giả định của parser **trên iproute2 của host**. iproute2 trong image worker (`ubuntu:22.04`, không ghim; có thể 5.15) **chưa kiểm**. `PERMANENT` (entry `tap0`), `DELAY`, hàng IPv6 hay cờ `router` dạng JSON **chưa quan sát** |
| `neigh_check` trên bảng host | như trên | FAIL "tap0 neighbour 10.200.0.2 missing" | Đúng như thiết kế: bảng ngoài worker không có entry bắt buộc. Không phải kết quả ca |
| `ip neigh show` **text** của netns worker thật | 06B-4G `run1/container/netns-before/after.txt` (08:41–08:45 UTC) | `parse_neigh_full`: `NeighReadError` (không phải JSON) | Có state thật dạng text: `PERMANENT` (`10.200.0.2 dev tap0`, MAC guest), `REACHABLE` (ctl `192.168.60.3`), `DELAY` (manager, gateway). **Chưa có JSON thật từ worker** |
| `/proc/net/arp` | **host**, cùng thời điểm (container dùng chung kernel) | `ctl_loop.arp_entry` (tách bằng ast): entry `172.18.0.2` → `{ip, hw, flags 0x2, device br-09fed07bbb6b, device_mac}`; IP không có trong bảng → lỗi rõ | Định dạng `/proc/net/arp` của kernel này đọc được. `/proc/net/arp` và `/sys/class/net` **trong container ctl** chưa kiểm |
| MAC quan sát | host `/sys/class/net`, neighbor | `endpoint_mac_problem`: mọi MAC bridge/veth/neighbor hợp lệ; `lo` (`00:…:00`) bị từ chối đúng | Validator không từ chối MAC Docker thật đã thấy |
| Trạng thái link của guest | 06B-4G `probe/{ARM,MIPS}/topology.json` (`ip addr` **text**, ngay sau boot) | ARM: `eth1` **UP**. MIPS: `br-lan` (giao diện probe) **`NO-CARRIER … state DOWN`**, `eth0` (cổng bridge) `UNKNOWN` | **Không có operstate sysfs thật đã lưu.** Xem rủi ro R-MIPS bên dưới |

**Rủi ro R-MIPS (từ evidence thật, chưa kiểm trên guest):**

- `guest_state.diff()` so operstate **chặt**. `_link_cmds()` chỉ tự `ip link set up` khi baseline là `up`/`unknown`.
- Nếu operstate của `br-lan` trên MIPS là `down` lúc lấy baseline rồi tự đổi (carrier của bridge), hoặc đổi sau T15 link down/up, restore sẽ báo lỗi. Khi đó ca sau không chạy và kiến trúc FAIL (xác nhận restore).
- Đây là **rủi ro của luồng đã review**, không phải phát hiện lỗi đã chứng minh. Cần người điều phối quyết định trước khi chạy (§6).
- *(Đính chính 06B-4IR3:)*
  - Topology MIPS thật cùng ghi **admin UP** (cờ `UP` trong header `br-lan`) với `NO-CARRIER`/`state DOWN`. Admin state và operstate là **hai dữ liệu khác nhau**, và lúc đó `guest_state` không ghi admin state (PC-3, đã sửa ở 06B-4IR3).
  - Carrier/operstate đổi giữa baseline và lần đọc lại là **điều kiện cần quan sát trên guest thật**, chưa phải lỗi logic. Quy tắc so operstate chặt được giữ, không nới.

## 5. Script precheck Docker chỉ đọc (soạn sẵn, **chưa chạy**)

*(Đính chính 06B-4IR3: "chỉ đọc" mô tả các lệnh Docker, **không** có nghĩa chạy root an toàn. Script này phân loại lỗi đọc thành "absent"/"not running" (PC-2), kết thúc exit 0 cả khi lệnh đọc lỗi, và ghi output qua đường có thể bị đổi đích (PC-4). **Không chạy bản này.** Bản thay thế: collector/evaluator 06B-4IR3.)*

[`precheck-06b4ir2-docker-readonly.sh`](task06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh) (bản làm việc: `/home/dathq/projects/ct01-06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh`).

- Đã kiểm `bash -n`; không có lệnh Docker làm thay đổi trạng thái (`run/start/restart/create/pull/build/compose/stop/rm/network connect`); không in env hay `Config.Env`.
- **Nội dung:**
  - Docker version/info (trường chọn lọc), image ID;
  - `ps -a`, kiểm container thử không tồn tại;
  - inspect `sandboxnet`/`dbnet` (subnet, gateway, endpoint IP/MAC), manager và `mongo-db` (state, IP/MAC theo mạng);
  - `nft -s list ruleset`, `aa-status`;
  - `docker exec` vào manager **chỉ khi manager đang chạy sẵn**, chỉ các lệnh đọc (`ip -V`, `ip -j neigh show`, `/proc/net/arp`, `/sys/class/net/*/{address,operstate}`).
- Nếu người dùng chọn chạy: `sudo bash /home/dathq/projects/ct01-06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh`. Output được so với 06B-4G và chạy parser offline như §4.
- **Giới hạn:** script không đọc được netns/interface/MAC của worker và ctl, cũng như iproute2 trong image, vì các container đó chỉ có trong lần chạy. Những điểm này chỉ xác nhận được ở lần chạy thật, qua `arp-group.json` (raw `neigh_*`) và `ctl.jsonl`.

## 6. Điều kiện còn thiếu trước khi chạy guest

1. **Precheck Docker chỉ đọc** (§5) do người dùng chạy bằng sudo và được review:
   - image ID;
   - manager `exited`/`running`, container thử vắng;
   - `sandboxnet`/`dbnet` và subnet `192.168.60.0/24`;
   - MAC manager khác 0, không phải multicast;
   - ruleset host giống `host-after` 06B-4G;
   - AppArmor không đổi.
2. **Quyết định về R-MIPS:**
   - (a) chấp nhận rủi ro restore MIPS FAIL; hoặc
   - (b) giao một nhiệm vụ offline riêng để xử lý operstate của bridge MIPS trong `guest_state` (cần review). Không tự sửa trong precheck.
3. Người điều phối **cho phép chạy** (precheck này không cấp phép).
4. Chấp nhận các điểm chỉ xác nhận được trong lần chạy:
   - iproute2/JSON của image worker;
   - interface và MAC của ctl trên `sandboxnet`;
   - `/proc/net/arp` của ctl;
   - operstate sysfs thật của guest;
   - hành vi kernel/netifd ARM/MIPS;
   - guard 20 ms (chưa đo).

## 7. Đề xuất cho lần chạy thật đầu tiên (chỉ đề xuất, chưa thực hiện)

- **Phạm vi:** đúng **một** lần `sudo bash /home/dathq/projects/ct01-06b4ir2/run-06b4i.sh`. Chạy ARM rồi MIPS, tuần tự, chỉ 4 ca T14-A1/A2/A3, T15-S1 như run script; không thêm probe, không chạy lại IPv4/ICMP, không malware. Có thể cân nhắc chạy sau khi đã quyết định R-MIPS.
- **Điều kiện dừng** (đã có trong harness, không chạy lại khi chưa review). *(Đính chính 06B-4IR3: câu "bất kỳ FAIL… → dừng" **không khớp** run script 06B-4IR2: ARM FAIL/UNVERIFIED vẫn gọi harness MIPS (PC-1). Chính sách dừng giữa kiến trúc được hiện thực ở 06B-4IR3.)*
  - cảnh báo rò rỉ → exit 99;
  - mất capture/heartbeat → 98;
  - lỗi guard hoặc lỗi khác → 1;
  - restore lỗi → các ca sau không chạy, kiến trúc FAIL;
  - bất kỳ FAIL, chữ ký trên host, lệch ruleset/host-state → dừng, báo cáo, **không chạy lại**;
  - self-test lỗi → exit 3 trước mọi lệnh Docker.
- **Bằng chứng cần thu** (toàn bộ `out/` giữ nguyên, kiểm `diff -r` như 06B-4G):
  - `run.log`, `targets-env.txt` (gồm `CTL_MAC`, `MANAGER_MAC`);
  - `ctl/ctl.jsonl`;
  - mỗi kiến trúc: `arp-group.json` (raw `ip -j neigh show` trước/sau mỗi ca, baseline/restore `guest_state` với operstate thật, lệnh và rc), `arp-eval.json`, `result.json`, `counters-raw.jsonl`, `tap0.pcapng`, `session.json`, `console.log`, `topology.json`;
  - capture veth/bridge/`ens33`, `sigscan*`, `alert.txt`, `capture-stats.tsv`;
  - netns trước/sau, ruleset chuẩn hóa, host trước/sau.
  - Kiểm chéo độc lập trên file đã lưu (như `crosscheck.py` 06B-4G), không import harness.
- **Cách đọc kết quả:**
  - A1/A2 "ĐẠT" chỉ trong phạm vi binding hiện có + HTTP (T14 §3), **không** phải trao đổi ARP mới trong cửa sổ;
  - A3/S1 là "ĐẠT (kiểm quy tắc)";
  - CHƯA KIỂM CHỨNG không được nâng nhờ PASS toàn phiên.

## 8. Hash

Mọi file trong `task06b4ir2-precheck/`: [`SHA256SUMS`](task06b4ir2-precheck/SHA256SUMS) (`54a5cd85e1b13ec6a617ce5c88a556071d3640f5cda3ef67c07afb21977df19d`).
