# Minh chứng Nhiệm vụ 06B-2BR: phát hiện địa chỉ guest nằm sai interface (06/10/2026)

**Bối cảnh:**

- Sửa phát hiện của 06B-2B: khi `10.200.0.2/32` nằm trên `lo`, verify cũ vẫn báo `ISOLATION OK`.
- Nhánh `feat/ct01-network-isolation` (HEAD `3c54d55`), chưa commit. Mốc trước đợt sửa: tree `08796afaa5d6b213f77807731ea554ce4d0c5d77` (bàn giao 06B-2B).
- **Evidence 06B-2B giữ nguyên vẹn** (thư mục `task06b2b/` và `task06b2b-summary.md` không bị sửa).
- **Verify trước đợt này chưa kiểm điều kiện này.** Mọi lần chạy V0/verify từ 06B-1 đến 06B-2B đều không phát hiện được địa chỉ thuộc mạng guest trên interface khác `tap0`.
- Phép thử HTTP qua `lo` ở 06B-2B **vẫn chỉ chứng minh middleware**.

Không chạy QEMU, guest hay mẫu nào; không đổi host.

## 1. Thay đổi

| File | Thay đổi |
|---|---|
| `sandbox-worker/isolation/verify.py` | `check_links` quét địa chỉ IPv4 trên **mọi** interface của netns (`ip -j addr show`). Chỉ cho phép đúng `10.200.0.1/30` trên `tap0`. Mọi địa chỉ khác **nằm trong** `10.200.0.0/30`, hoặc có **dải trùng** với mạng này, trên bất kỳ interface nào (kể cả `lo`, kể cả địa chỉ thứ hai trên `tap0`) đều làm verify thất bại. Không có ngoại lệ runtime |
| `sandbox-worker/tests/test_verify.py` | Test hồi quy (mục 2) |
| `docs/network-isolation-design.md` | Bảng kiểm "Link" ở §6.1 |

## 2. Test

**Unit test:**

- **142 passed** trên Python 3.12 (host, [log](task06b2br/unit-tests-py312.txt)).
- **142 passed** trên Python **3.10.12** trong image ([log](task06b2br/unit-tests-py310.txt)).

| # | Trường hợp | Kết quả mong đợi |
|---|---|---|
| 1 | Cấu hình đúng | đạt |
| 2 | `10.200.0.2/32` trên `lo` | **fail** |
| 3 | `10.200.0.3/32` trên `eth0`; `10.200.0.1/32` trên `lo`; `10.200.0.0/32` trên `lo`; `10.200.0.2/30` trên `dummy0`; `10.200.1.5/16` trên `eth0` (dải trùng); `10.200.0.2/30` thêm trên `tap0` | **fail** |
| 4 | `192.0.2.10/32` trên `lo`; `10.200.0.4/30` trên `eth0` (liền kề, không trùng); `172.31.0.1/24` trên `dummy0`; IPv6 `fd00::2` | đạt |

**Kiểm tra đối chứng:** phá mã 4 kiểu, lần nào cũng có test thất bại:

| Đột biến | Test thất bại |
|---|---|
| Bỏ quét (hành vi 06B-2B) | 7 |
| Bỏ qua `lo` | 3 |
| Bỏ kiểm trùng dải | 1 |
| Cho phép mọi địa chỉ trên `tap0` | 1 |

## 3. Build và kiểm thử bằng container sentinel (người dùng chạy)

**Build:** `exit=0`, image `sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153` ([build.log](task06b2br/build.log)).

**Harness:** `sudo bash run-06b2br.sh <ID đầy đủ lấy từ build.log>` (sha256 `d47b1fa1…0e05`), kết quả **ALL CHECKS PASSED**, `exit=0` ([run.log](task06b2br/run.log), `639e9812…195b`).

Cấu hình container giống các harness trước: `sandboxnet`, `--privileged`, `--restart no`, không publish cổng, sentinel thay server và poller. Mọi lệnh `ip addr add/del` chạy **bên trong** container.

**A. Khởi động hợp lệ rồi thêm từng địa chỉ** (container `b23aab41…`):

- V0 đạt; cả hai sentinel được gọi; `verify.py` trong image khớp working tree.

| Bước | Thao tác trong netns container | verify | Thông báo |
|---|---|---|---|
| 1 | Cấu hình đúng | exit 0 | `ISOLATION OK` |
| 2 | `10.200.0.2/32` trên `lo` | **exit 1** | `address 10.200.0.2/32 on lo is inside/overlaps guest network 10.200.0.0/30` |
| 3 | `10.200.0.3/32` trên `eth0` | **exit 1** | hai lỗi: kiểm `eth0` cũ và quét mới (`10.200.0.3/32 on eth0`) |
| 3b | `10.200.1.5/16` trên `lo` (dải trùng) | **exit 1** | `10.200.1.5/16 on lo …` |
| 4 | `192.0.2.10/32` trên `lo` | exit 0 | `ISOLATION OK` |
| 5 | Sau khi xóa hết | exit 0 | Chỉ còn `10.200.0.1/30` trên `tap0` |

Sau mỗi bước, địa chỉ thêm vào đều được xác nhận đã xóa. Không có QEMU hay tshark.

**B. Fail-closed lúc khởi động** (container `82e3f729…`):

- `10.200.0.2/32` được đặt lên `lo` **trước** khi `run.sh` (không sửa) chạy, bằng entrypoint bọc.
- V0 báo `ISOLATION FAIL (V0 startup): link: address 10.200.0.2/32 on lo …`.
- Exit code **đúng 1**, sentinel không được gọi, 0 lần restart.

**Host:** không đổi (sysctl, ruleset nft, route, địa chỉ, cổng, module, container). Cả 2 container do lần chạy tạo đều đã bị xóa ([created-ids.txt](task06b2br/created-ids.txt)).

## 4. Hạn chế

- Chỉ kiểm IPv4. IPv6 trên `tap0` đã được chặn bằng `disable_ipv6` và nft `l2_bad_ethertype`; địa chỉ IPv6 trên interface khác không liên quan đến `10.200.0.0/30`.
- Không kiểm route trong bảng `local` hay route policy; địa chỉ là nguồn chính tạo ra route local.
- **CT-01 vẫn chưa đạt:** chưa có guest, chưa lọc thật trên `tap0`, chưa có V1/V2 trong luồng thật, chưa làm T01–T21/F1–F6.
