# Quy trình chạy precheck root 06B-4IR3 (PC-4) — để reviewer xét, **chưa thực hiện**

Chỉ chạy khi reviewer và người điều phối đã chốt **hash** của `collector.py` dưới đây. Không chạy trực tiếp script nằm trong thư mục user.

## 1. Người dùng (không root): kiểm hash bản được review

```
sha256sum /home/dathq/projects/ct01-06b4ir3-precheck/collector.py
```

Giá trị phải đúng `HASH` được chốt; hash của bản bàn giao nằm trong `SHA256SUMS` của evidence.

## 2. Root: sao chép vào thư mục root, kiểm hash trên **bản sao**, chạy bản sao

Đoạn giữa hai dấu `BEGIN`/`END` dưới đây là đoạn mà người dùng gõ (hoặc dán) vào `sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh -c '…'`. Thay `<HASH>` bằng hash đã chốt. `env -i` xóa mọi biến môi trường, nên `BASE`/`SRC`/`HASH`/`PY` chỉ có giá trị mặc định ghi trong đoạn. Các biến này chỉ dùng cho test offline trong cây toy.

```sh
# --- BEGIN ROOT SNIPPET ---
set -eu
umask 077
BASE=${BASE:-/var/tmp}
SRC=${SRC:-/home/dathq/projects/ct01-06b4ir3-precheck/collector.py}
HASH=${HASH:-<HASH>}
T=$(/usr/bin/mktemp -d "$BASE/ct01-precheck.XXXXXXXX")
/bin/cp -- "$SRC" "$T/collector.py"
if ! echo "$HASH  $T/collector.py" | /usr/bin/sha256sum -c --quiet - ; then /bin/rm -f -- "$T/collector.py"; echo "HASH MISMATCH: nothing was run"; exit 1; fi
/bin/mkdir -m 0700 -- "$T/out"
rc=0; ${PY:-/usr/bin/python3} -I -B "$T/collector.py" "$T/out" || rc=$?
echo "collector exit $rc; output in $T/out (root-owned; collector exit 0 = data complete, NOT a verdict)"
# --- END ROOT SNIPPET ---
```

**Vì sao an toàn hơn bản 06B-4IR2:**

- **Thư mục output** do root tạo nguyên tử: `mktemp -d` trong `/var/tmp` (sticky), mode 0700, không có kiểm-rồi-tạo, không đi qua cây user.
- **Collector:**
  - mở thư mục bằng `O_NOFOLLOW|O_DIRECTORY`;
  - kiểm chủ sở hữu root, mode 0700, thư mục rỗng;
  - tạo mọi file bằng `O_CREAT|O_EXCL|O_NOFOLLOW` qua fd thư mục (`dir_fd`);
  - không redirection, không `tee`, không `chown -R`.
- **Script user chỉ được đọc đúng một lần** (`cp`). Bản sao root được kiểm hash **trước khi** chạy. Nếu file user bị thay giữa chừng, kể cả bằng symlink, hash sẽ lệch: bản sao bị xóa, không có gì được chạy.
- **Executable và PATH:**
  - mọi executable được gọi bằng đường dẫn tuyệt đối: `/usr/bin/docker`, `/usr/bin/pgrep`, `/usr/sbin/nft`, `/usr/sbin/aa-status`, `/usr/bin/python3`;
  - collector kiểm chúng thuộc root và không nhóm/người khác ghi được, kể cả thư mục chứa; không đạt thì từ chối (exit 2);
  - môi trường con chỉ có `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`, `LC_ALL=C`;
  - lệnh `sudo` dùng `env -i`.
- Không file nào được `source`.

## 3. Người dùng: sao output ra và đánh giá offline

```
sudo /usr/bin/tar -C <T> -cf - out | tar -xf - -C /home/dathq/projects/ct01-06b4ir3-precheck/run1/
python3 -I -B /home/dathq/projects/ct01-06b4ir3-precheck/evaluate_precheck.py /home/dathq/projects/ct01-06b4ir3-precheck/run1/out /home/dathq/projects/ct01-06b4ir3-precheck/run1/precheck-result.json
```

`tar` phía root chỉ **đọc** thư mục root và ghi ra stdout; việc giải nén chạy với quyền user. Root không ghi vào cây user.

**Exit code của evaluator:**

| Exit | Ý nghĩa |
|---|---|
| 0 | Mọi mục bắt buộc PASS |
| 1 | Có mục FAIL |
| 2 | Không FAIL nhưng có mục UNKNOWN (precheck chưa đủ) |
| 3 | Output collector không dùng được |

Chỉ exit 0 mới là precheck đạt. Kết quả đó vẫn **không** cấp phép chạy guest.

## 4. Không làm trong quy trình này

Không start/stop/create container; không pull/build image; không đổi mạng/ruleset; không QEMU/guest; không probe mạng; không in env/`Config.Env`; không đọc bí mật.

Collector chỉ `docker exec` vào manager khi một inspect **thành công** cho biết manager **đang chạy sẵn**, và chỉ chạy các lệnh đọc: `ip -V`, `ip -j neigh show`, `/proc/net/arp`, `/sys/class/net`.
