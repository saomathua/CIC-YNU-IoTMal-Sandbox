# RUN-PROCEDURE 06B-4IR3R2 — đề xuất cho review độc lập, CHƯA chạy root

Harness 4IR3 đã chốt offline, giữ nguyên 35 file. Cổng precheck này **chờ Claude review độc lập và người điều phối chốt**. Chưa có cửa sổ độ mới được duyệt, chưa sẵn sàng chạy hiện tại/guest. CT-01 chưa đạt.

## Giao kèo và quyền

Collector v2 là **một file standalone**: root copy → hash bản sao → chạy bản sao bằng Python stdlib, không import/source code ở cây user. Đầu ra mới gồm reads.json + raw stdout/stderr; run UUID, root source, host/uid, t_start/t_end và SHA collector được ghi. Exit collector 0 chỉ dữ liệu đọc hợp lệ/đủ; 3 thiếu/hỏng; 2 từ chối. Không phải precheck PASS.

Đọc Docker version/info chọn trường, image ID, ps-a, network list/inspect, manager/mongo inspect; exec **chỉ manager đang chạy sẵn và inspect payload hợp lệ**, chỉ ip version/neigh, /proc/net/arp, sysfs. Host: pgrep/nft/AppArmor. Không đọc Config.Env/env/credential, không start/create/stop container, không thay network/ruleset, không probe hay guest. Manager/host samples không chứng minh worker/ctl hoặc BusyBox guest.

## 1. Người điều phối: chốt nguồn và trust trước mọi root execution

Hash collector bàn giao: `8300562e055e9f900c1cd0e3cc46ae774e914fd132529ccdf75c318a1c6ab85e`.

Kiểm hash collector, evaluator/exporter/audit và toàn manifest đã review, không tin riêng hash trong metadata. Dùng audit_paths.py **không root** để đọc owner/mode/symlink của toàn ancestry lexical **và resolved**, gồm tools launcher/collector/export; cần errors rỗng. /var/tmp phải real root-owned 1777 sticky. Xác minh installed content/trust của executable theo chính sách host; metadata audit không chứng minh nội dung binary. Loại trừ writer có quyền root/thay mount/path trong khoảng thao tác. Nếu audit/trust không đủ, dừng; không chuyển staging sang cây user.

```
/usr/bin/python3 -I -B /home/dathq/projects/ct01-06b4ir3r2-precheck/audit_paths.py
/usr/bin/sha256sum /home/dathq/projects/ct01-06b4ir3r2-precheck/collector.py
```

Đây chỉ là lệnh được đề xuất sau review, không đã thực thi root. trusted_bins kiểm ancestry lexical/final resolved của collector binaries; symlink nhiều hop cần kiểm trust thủ công các thư mục trung gian (H1 là hardening tùy chọn, chưa mở rộng code lượt này), nhưng **không thay trust bootstrap launcher hoặc attestation binary**. O_NOFOLLOW bảo vệ file cuối; FD bảo vệ những ghi sau open. Không suy chúng bảo vệ cả chuỗi thư mục trước open.

## 2. Root staging cố định: người dùng chỉ chạy sau review/chốt

Dán đoạn đã chốt trực tiếp vào wrapper `/usr/bin/sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/sh`. Không source hoặc chạy file shell ở cây user. Các BASE/SRC/HASH/PY dưới đây chỉ override khi selftest offline; wrapper env-i không nhận giá trị ambient. Production luôn /var/tmp, /usr/bin/python3, HASH literal được review. Không thay HASH bằng hash tự lấy từ nguồn chưa review. Không root precheck trong nhiệm vụ này.

```sh
# --- BEGIN ROOT SNIPPET ---
set -eu
umask 077
BASE=${BASE:-/var/tmp}
SRC=${SRC:-/home/dathq/projects/ct01-06b4ir3r2-precheck/collector.py}
HASH=${HASH:-8300562e055e9f900c1cd0e3cc46ae774e914fd132529ccdf75c318a1c6ab85e}
T=$(/usr/bin/mktemp -d "$BASE/ct01-precheck.XXXXXXXX")
/bin/cp -- "$SRC" "$T/collector.py"
if ! echo "$HASH  $T/collector.py" | /usr/bin/sha256sum -c --quiet - ; then /bin/rm -f -- "$T/collector.py"; echo "HASH MISMATCH: nothing was run"; exit 1; fi
/bin/mkdir -m 0700 -- "$T/out"
rc=0; ${PY:-/usr/bin/python3} -I -B "$T/collector.py" "$T/out" || rc=$?
echo "collector exit $rc; source $T/out; keep stage for audit; this is NOT a verdict"
exit "$rc"
# --- END ROOT SNIPPET ---
```

Root T 0700 và owner root giữ sau thu, dù collector cho files 0644/out 0755 để export. Không chmod/chown root T cho user. Hash copy vẫn an toàn nếu SRC đổi sau copy; chỉ bytes bản sao đã chốt được chạy. Hash mismatch xóa riêng copy vừa tạo, để lại T rỗng; không recursive cleanup, không xóa evidence cũ. Lỗi thu giữ raw evidence, không coi return wrapper thành đạt.

## 3. Export mới: quyền user, không pipeline

Exporter tạo **mkdtemp mới mỗi lần** dưới dest-parent đã chuẩn bị với quyền user. Không dùng run1/out; không merge/extract lên output cũ. Producer là `/usr/bin/sudo /usr/bin/tar -C <root-T> -cf - out`, chỉ đọc root stage. Archive riêng được lưu; kiểm producer rc trước extractor. Sau kiểm member regular/dir, không link/device/traversal, extractor user tar vào thư mục mới. Kiểm extractor rc trước evaluate; mọi lỗi giữ export-result.json và không gọi evaluator. Không dùng pipeline hoặc chỉ rc lệnh cuối.

Quy trình duy nhất: sau collector hoàn tất, đọc **metadata chọn lọc của chính root stage đã thu** bằng lệnh dưới đây; lấy run_id/root_source/hash từ kết quả đó, rồi tạo export mới với identity ấy. Không cần export để lấy run_id, không suy UUID từ tên thư mục hoặc lần trước. Lệnh root đọc metadata này nằm trong phạm vi cần reviewer xét và người điều phối cho phép cùng quy trình; **chưa được chạy**. Chỉ đọc reads.json ở T root-owned đã xác minh, không env/credential; kiểm rc và đầy đủ sáu trường, đối chiếu root_source với chính T/out và hash với collector được review trước khi export. Đọc metadata không phê duyệt context hay cửa sổ độ mới.

```
/usr/bin/sudo /usr/bin/python3 -I -B -c 'import json,sys; d=json.load(open(sys.argv[1]))["meta"]; print(json.dumps({k:d[k] for k in ("run_id","root_source","collector_sha256","host","t_start","t_end")}, ensure_ascii=True, allow_nan=False))' <root-T>/out/reads.json
```

Lệnh lịch sử dưới đây cần thay các placeholder bằng nguồn/run/hash đã chốt; dest-parent phải tồn tại, thuộc cây user phù hợp. Không gọi nó như xác nhận hiện tại:

```
/usr/bin/python3 -I -B /home/dathq/projects/ct01-06b4ir3r2-precheck/export_precheck.py --root-source <root-T>/out --run-id <UUID-32-hex> --collector-sha256 8300562e055e9f900c1cd0e3cc46ae774e914fd132529ccdf75c318a1c6ab85e --dest-parent <user-export-parent> --mode historical
```

Historical PASS chỉ snapshot. Export-result.json ghi destination mới, producer/extractor argv+rc, input digest, evaluator_called và verdict. precheck-result.json mới có evaluation_id/time, raw input, issues, collection binding; **current_ready=false** ở lịch sử. Exit exporter 4 là lỗi export/binding, 5 output lỗi; 0/1/2/3 từ evaluator khi có kết quả bound đúng input. Luôn kiểm exit và status, không chỉ nhìn một result.json cũ.

## 4. Chế độ hiện tại: không có window mặc định

Người điều phối chốt context ngoài output, cung cấp file JSON `ct01-precheck-context/1` gồm:

- approved_by, approval_ref (tham chiếu phê duyệt thực, không fixture);
- run_id, root_source, collector_sha256, host, t_start, t_end đúng metadata;
- reads_sha256 của **bytes reads.json** export thành công;
- not_before (mốc sớm nhất được chốt), max_age_s dương hữu hạn **do người điều phối phê duyệt**.

Context là đầu vào tin cậy được người điều phối quản lý, không chứng thư chữ ký và không tự chứng minh ai đã phê duyệt. Không tự lấy context từ metadata rồi coi đó là phê duyệt. Không đưa cửa sổ fixture vào vận hành. Timestamp phải hữu hạn/t_start≤t_end; hiện tại yêu cầu source root cố định/uid0, kết thúc không ở tương lai, bắt đầu không trước not_before và age tính từ **t_start** không vượt window. Context/hash/binding thiếu hoặc sai → UNKNOWN, không current_ready.

Sau review/context được chốt, dùng `--mode current --context <approved-context.json>` thay lịch sử trên exporter; mỗi export vẫn mới. Hoặc evaluate bản export mới thành công trực tiếp:

```
/usr/bin/python3 -I -B /home/dathq/projects/ct01-06b4ir3r2-precheck/evaluate_precheck.py <fresh-export>/out <fresh-export>/current-result.json --mode current --context <approved-context.json>
```

Evaluator kiểm raw files khớp inline reads, tên/order/schema/status/rc/argv/source và payload, không sửa input. FAIL/UNKNOWN/UNUSABLE đều không đạt cổng. Exit 0 PASS; 1 FAIL; 2 UNKNOWN; 3 UNUSABLE; 5 OUTPUT_ERROR. Khi bắt đầu, result regular cũ ở dst được invalidated; input lỗi vẫn ghi JSON kết luận mới nếu ghi được. Nếu không invalidated/ghi được, exit 5 và structured stdout/stderr nêu rõ **old_result_may_remain**; không dùng result path cũ. Result phải nằm **ngoài cây source evidence**. Output trùng/alias input, ref, context hoặc bất kỳ file evidence trong source (kể cả raw stdout/stderr và hardlink đặt ngoài cây) bị từ chối **trước invalidation/unlink**. Symlink/directory output cũng bị từ chối. Không thay đổi cây input trong lúc evaluator chạy; kiểm alias không bảo đảm chống writer đồng thời. Non-finite/surrogate, gồm giá trị lồng sâu và JSON nhúng trong payload, bị từ chối trước kết luận; không chuyển thành PASS bằng cách sửa input. JSON kết luận/diagnostic dùng ASCII escaping để encode an toàn; nếu output lỗi, structured stdout OUTPUT_ERROR/exit 5 thay cho traceback; không coi raw diagnostic là kết luận PASS.

**Giới hạn:** snapshot không chứng minh host giữ nguyên sau thu. Dù current_ready=true về gating dữ liệu/thời gian, vẫn cần người điều phối quyết định bước tiếp; không là phép chạy guest. Không giả mạo worker/ctl/operstate/đối chứng/guard đã kiểm thật. Root T/output mới giữ để audit; không tự xóa evidence hay host state. Cửa sổ chưa chốt hiện tại → chưa sẵn sàng.


## 5. Candidate nft reference-set/1 — chờ review trước vận hành

Policy `ct01-nft-exact-channels/1`, reference-set `ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4`: so exact bytes stdout và stderr với đúng bốn snapshot đã ghim (4G, 3G, MGR, MGR2, MGR3 — MGR3 là một reference exact-byte do người dùng duyệt bổ sung từ hai luồng đã lưu của collection REJECTED caf80efb, chỉ khác MGR hai dòng địa chỉ manager 172.18.0.2↔.3; MGR2 là một reference exact-byte do người dùng duyệt bổ sung từ collection 6215094f, chỉ khác MGR ở thứ tự luật theo bridge; 4G, 3G, MGR manager-running) đã ghim trong nft_policy.py; không sort hoặc semantic comparator. Không tự lấy collection mới làm reference; MGR là baseline saved collection 6685285a được chỉ thị riêng phê duyệt bổ sung để review. Collection này và historical replay không dùng để launch. `references/provenance.json` ghi nguồn/manifest/hash và phép tách đúng ba warning cho 3G/4G; MGR copy nguyên byte hai kênh từ raw_input kết quả lưu, hash khớp trace; chưa đối chiếu raw root files riêng. Hash/provenance tự khai trong reads/context không bổ sung reference hoặc chứng minh approval. Mọi sửa policy/reference artifacts phải review và chốt manifest mới. Bản này CHƯA vận hành, root/guest/current window vẫn chưa được cấp phép.

`--ruleset-ref` chỉ là đầu vào diagnostic legacy 4G: bắt buộc bytes đúng hash 4G source, không đổi reference-set. Default `references/4G.source.txt` trong bản precheck. Result schema3 ghi evaluator argv/logical invocation và process argv (exporter gọi in-process), policy version/set/module hash, paths raw/resolved/hash/size reference, matched reference, observed stdout/stderr hash, diagnostic verdict/reason và diff. `strict_4g_channels` và `legacy_4g_merged_text` là hai diagnostic riêng; không được dùng chúng làm verdict theo set hoặc sửa FAIL cũ.

Exporter schema2 lưu evaluator argv, result digest, policy/provenance và kiểm binding schema/version, exit/verdict, mode/readiness, observed-channel hashes và matched pinned reference. Snapshot mới historical có thể PASS theo set/1 trong replay offline, luôn current_ready=false; đó không phải PASS của phiên policy cũ hay phép tiến bước.

Trước bất kỳ vận hành sau review: đối chiếu toàn manifest recursive gồm references và nft_policy.py; collector vẫn cùng hash, copy/hash root snippet vẫn bắt buộc. Khi export tạo output mới, dùng đúng exporter/evaluator/module/artifacts đã review, không mix phiên bản. Đánh giá historical trước; context/window/current chỉ chốt sau xem dữ liệu thật. Không tạo context tự động từ metadata. Không chỉnh ruleset host/reference lịch sử để đạt cổng.
