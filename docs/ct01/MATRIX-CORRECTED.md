# Ma trận nghiệm thu CT-01 — bản đính chính (dẫn xuất từ MATRIX-CONFIRMED.md và REPORT.md của review độc lập)

Nguồn: `/home/dathq/projects/ct01-acceptance-matrix-independent-review/outputs/MATRIX-CONFIRMED.md` sha256 `eb8a2091b4c9ca49d16fe2763838a5e79591ab0727496a722f89761aa13d55bc`, `REPORT.md` sha256 `fed1c94b2d4132c2161eb683feba18a41f5f38fd7ee0fddb2699b7ccc44b59f3`. Thay thế các điểm tương ứng của `ct01-acceptance-matrix/MATRIX.md` (không sửa tệp đó). Giữ tám ca ARP R10; CT-01 vẫn **kiểm chứng một phần — chưa đạt**; chưa có hàng nào được dùng để kết luận nghiệm thu toàn bộ.

## 0. Đính chính so với MATRIX.md đầu vào

1. **Thiếu evidence = chưa biết.** Nhãn CHƯA KIỂM không có nghĩa "không có lỗi"; bỏ cột "Loại = OK/EV/FN" và câu "không có hàng FN". Không có hàng FAIL **hiện tại** không chứng minh chức năng không lỗi.
2. **FAIL 06B-3D giữ nguyên** (xem §2). Bỏ cụm "FAIL = giả thuyết gói biên": kết quả là FAIL theo giao kèo harness; nguyên nhân chưa được chứng minh.
3. **T08–T10 tách hai lớp:** kết luận mạng (ĐẠT trong scope đã chấp nhận) và nguồn/log/dạng đối chứng còn thiếu (§3). Không ghi "không thiếu".
4. **T21:** thiếu *chứng cứ phiên liên tục* (SSH/phiên Claude); không tự yêu cầu Compose cho T21 (thiết kế §7.2 nói "khởi động worker"; invariant host bắt buộc của R10 đã được review đạt). Compose chỉ liên quan F5 (restart).
5. **Phần hoãn tách khỏi bắt buộc:** D1 (ARP reply/P3 raw), D3 (không probe M/H), D4 (N6), D5 (TAP_MAC giả) và các mục ngoài 06B là HOÃN; số thiếu bắt buộc, coverage kế hoạch và HOÃN được đếm riêng (§1).
6. **Phân biệt thiết kế và kế hoạch:** T05c, T12-B3, T13-I3, T12-B4, T17-P2/P4/P5, T20 N1–N3 là chi tiết kế hoạch được chấp nhận hướng (D1–D7); giữ coverage đã cam kết nhưng không tự biến thành cổng nghiệm thu mới.
7. **Thứ tự/phụ thuộc:** kế hoạch §6 đặt T20 trước nhóm đổi cấu hình và **T17 trước T16** (đợt D cũ ghi ngược). Không có phụ thuộc "sửa closure → viết probe"; T20 không phải đợi spoof.
8. **Giới hạn launcher:** `run-arp-b1b2.sh` hardcode `CT01_SUITE=arp` (dòng 444) và mount `probe_matrix_launch.py`; không thể chỉ gán `CT01_SUITE` ngoài để chạy suite khác qua entrypoint đã review. Probe mới cần runner/pin riêng được review.
9. **OPEN host capture của 06B-4G (received−captured = 8 ở veth/bridge/ens33) độc lập với closure.** Closure ARM T13-I1 chỉ xử lý ambiguity bộ đếm, không làm bằng chứng "không probe rời worker" đầy đủ hơn; drain R10 không đóng OPEN 4G.
10. **Hai closure không đóng cả bốn hàng UNVERIFIED cũ:** chỉ T07 (MIPS) và T13 (ARM I1) được đối chiếu dẫn xuất; T19 và T21 cần phép đo đúng nguồn/phiên.

## 1. Đếm riêng (một hàng có thể phủ nhiều ca/kiến trúc; không dùng số hàng để kết luận nghiệm thu)

| Loại | Số hàng |
|---|---|
| THIẾU BẮT BUỘC theo thiết kế (CHƯA KIỂM/UNVERIFIED trên yêu cầu §7.2) | 17 |
| ĐẠT về mạng nhưng thiếu nguồn/log/dạng đối chứng (T08–T10) | 3 |
| Coverage kế hoạch chưa chạy (không tự là cổng) | 3 |
| HOÃN/GIỚI HẠN đã duyệt (tách khỏi bắt buộc) | 2 |
| Đã đạt trong scope ghi ở bảng | 13 |

## 2. Sổ lịch sử: FAIL 06B-3D (không xóa, không giải thích bằng lượt sau)

- Probe `internet-tcp` (MIPS) `tcp 1.1.1.1:443`; harness kết luận **FAIL** (exit 1 của lượt): `l2_bad_ethertype` delta 3 so với 2 khung pcap trong cửa sổ; các lớp khác khớp (drop_public 8=8); đối chứng sống trước/sau; `guest_failed` đúng.
- **Nguyên nhân chưa được chứng minh**: giả thuyết gói IPv6 nền ngay trước `t0` không kiểm được vì lượt đó không ghi thời gian lệnh nft; không thể tái tạo closure hợp lệ cho 3D.
- **Phân loại:** *mismatch nghiệm thu, nguyên nhân chưa xác định; chưa có bằng chứng leak.* Không khẳng định lỗi mạng, cũng không khẳng định lỗi đo đã được giải thích.
- 06B-3G ĐẠT internet-tcp (ARM/MIPS) chỉ chứng minh lượt 3G; không xóa hay giải thích FAIL 3D. 06B-3B dùng phép đo cũ cùng hạn chế timestamp: giữ scope chấp nhận lịch sử, ưu tiên raw 3G cho kết luận hiện tại.

## 3. T08–T10: kết luận mạng và phần nguồn/log còn thiếu

| Hàng | Kết luận mạng (đã chấp nhận trong scope) | Nguồn/log/dạng đối chứng còn thiếu | Cách đóng tối thiểu |
|---|---|---|---|
| T08 manager `:8011` | ĐẠT về mạng (`drop_private`; đối chứng W/ctl `healthcheck` 200) | Chưa đối chiếu log manager (không có request từ guest). Log của lượt sau không chứng minh nội dung lượt trước | Đọc log manager đúng cửa sổ của một lượt đã duyệt, hoặc ghi chấp nhận thay bằng bằng chứng mạng |
| T09 MongoDB `:27017` | ĐẠT về mạng (`drop_private`; đối chứng TCP connect từ dbnet) | Đối chứng là TCP connect, không phải `M /status` 200 hoặc `mongosh ping` | Lưu căn cứ chấp nhận dạng thay thế, hoặc bổ sung đúng dạng khi có môi trường |
| T10 `192.168.60.2:8011` | ĐẠT về mạng (`drop_private`; đối chứng ctl `healthcheck` 200) | Nguồn đối chứng là ctl, không phải container M | Đóng cùng phép xác nhận nguồn M của T19; không cần lặp probe guest |
| T07 (liên quan) | 5/6 ĐẠT trực tiếp + 1 đối chiếu dẫn xuất H0 (MIPS `ssh-host-192.168.60.1`); nhãn gốc 3G giữ UNVERIFIED | Chưa thấy log ssh đúng cửa sổ | Như T08 |

## 4. Ma trận đã đối chiếu

Cột "Phạm vi": nguồn yêu cầu; cột "Thiếu": phân loại không gộp bắt buộc với coverage/HOÃN.

| ID | Phạm vi | Nhãn đã đối chiếu | Phân loại phần thiếu | Phần thiếu/giới hạn tối thiểu |
|---|---|---|---|---|
| T05a | design | ĐẠT về mạng ở 3G; FAIL 3D còn nguyên | — | 3G ARM/MIPS internet-tcp ĐẠT. Không dùng lượt sau giải thích FAIL 3D; xem lịch sử riêng. |
| T05b | design | CHƯA KIỂM đúng probe | THIẾU BẮT BUỘC (thiết kế) | UDP DNS 8.8.8.8:53 có tên đánh dấu + đối chứng cùng IP/protocol/port. Nền DNS không thay phép thử. |
| T05c | plan | CHƯA KIỂM; bổ sung, không tự thành gate mới | coverage kế hoạch (không tự là cổng) | ICMP công cộng không được liệt kê trong ma trận thiết kế. Muốn bắt buộc phải chốt phạm vi riêng. |
| T06a | design | ĐẠT phần TCP53; UDP53 là phủ bổ sung | — | Đối chứng thực là TCP connect/DNS từ W, không suy H ping chứng minh TCP53 sống. Các bằng chứng mạng đã được chấp nhận đúng phạm vi. |
| T06b | design | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | ICMP tới LAN DNS, đối chứng ICMP cùng IP. Không thay bằng đối chứng TCP/UDP. |
| T06c | design | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | Một IP LAN khác đã chọn; nếu không có dịch vụ sống thì kiểm quy tắc D6. |
| T07 | design | Mạng: 5 ca ĐẠT trực tiếp + 1 đối chiếu dẫn xuất H0; nhãn gốc 3G giữ UNVERIFIED | — | Closure MIPS đúng. Báo cáo dẫn xuất riêng đủ ghi nhận đối chiếu dưới H0; không cần nối evaluator. Chưa thấy log ssh đúng cửa sổ; giữ thiếu mục bổ sung hoặc chốt rõ chấp nhận thay thế bằng bằng chứng mạng. |
| T08 | design | ĐẠT về mạng; log manager chưa được đối chiếu | ĐẠT về mạng; thiếu nguồn/log (xem §3) | Không biến nhận định mạng thành đã đủ log bổ sung. Log lượt sau không chứng minh nội dung của lượt trước. |
| T09 | design | ĐẠT về mạng với đối chứng TCP; lệch dạng đối chứng thiết kế | ĐẠT về mạng; thiếu nguồn/log (xem §3) | TCP connect từ dbnet cùng đích/cổng đã được chấp nhận về mạng. Không ghi thành mongosh ping/M status. Cần lưu căn cứ chấp nhận dạng thay thế hoặc bổ sung đúng dạng khi có môi trường. |
| T10 | design | ĐẠT về mạng; nguồn manager chưa kiểm | ĐẠT về mạng; thiếu nguồn/log (xem §3) | ctl không phải M. Đóng phần nguồn đúng cùng phép thử T19; không cần lặp probe guest nếu tổng hợp evidence được chấp nhận. |
| T11a | extra probe | ĐẠT riêng listener18080 | — | Không thay hai cổng22/80 hoặc ICMP của thiết kế. |
| T11b | design | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | TCP22 và TCP80, hai cửa sổ riêng, D6 khi không có listener. |
| T11c | design | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | ICMP tới10.200.0.1, đếm khung thực. Không ghi mặc định delta+3 như tiêu chí cố định. |
| T12 | design B1/B2; B4 plan | Giữ ca 4G ĐẠT kiểm quy tắc trong phạm vi đã duyệt; capture OPEN vẫn mở | — | B1/B2 phủ đích thiết kế. Ba received−captured=8 chưa giải thích, nên không ghi toàn bằng chứng host hoàn chỉnh. |
| T12-B3 | plan | CHƯA KIỂM; coverage kế hoạch | coverage kế hoạch (không tự là cổng) | UDP53 tới224.0.0.251 không nằm ở hàng T12 thiết kế. Thiếu B3 không xóa coverage B1/B2. Không tự mở thành bắt buộc. |
| T13 | design | Giữ nhãn gốc 4G; ARM I1 đối chiếu dẫn xuất PASS dưới H0 | — | I1 ARM phân bổ duy nhất đúng. Không sửa evaluator/evidence cũ. Counter closure không giải quyết OPEN host capture×8. |
| T13-I3 | plan | CHƯA KIỂM; coverage kế hoạch | coverage kế hoạch (không tự là cổng) | I2 đã là phép gửi tới fe80 theo thiết kế; curl6/NS của I3 là coverage thêm, không tự thành gate mới. |
| T14 | design | ĐẠT: sáu ca A1/A2/A3 ARM/MIPS giữ nguyên | — | A1/A2 có đối chứng binding sống theo giao kèo; A3 kiểm quy tắc. Không yêu cầu chạy lại do thiếu anchor hoặc cần ARP exchange mới. |
| T15-1 | design | ĐẠT: hai S1 ARM/MIPS giữ nguyên | — | Giữ đúng gratuitous request do kernel, neighbor/restore. Closure ARM A2 thuộc T14, không phải closure S1. |
| T15-2 | deferred D1 | HOÃN ĐÃ DUYỆT — không tính thiếu bắt buộc hiện tại | HOÃN (tách khỏi bắt buộc) | Reply giả, gratuitous dạng reply, htype/hlen/plen tùy ý không thuộc phạm vi đã thực hiện; chỉ mở khi có quyết định mới. |
| T16 | design (D5 limits) | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | MAC52:54:00:de:ad:01, T01 trước/thất bại khi đổi/sau restore. Không gồm giả TAP_MAC; thiếu phép đo không chứng minh chức năng đúng. |
| T17 | design P1; P2/P4/P5 plan | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | Ưu tiên P1 đúng thiết kế; P2 giả manager có giá trị vì bypass phân loại nguồn API nếu nft lọt. P4/P5 giữ coverage kế hoạch; P3 hoãn D1. Không nói đã thử rp_filter với guest. |
| T18 | design | CHƯA KIỂM nguồn poller thật | THIẾU BẮT BUỘC (thiết kế) | Poller sentinel không chứng minh get-file/DNS trong luồng thật. Poller thật và manager logs; 404 No tasks đủ connectivity, chưa chứng minh xử lý tác vụ. |
| T19 | design | CHƯA KIỂM từ M; ctl là evidence thay thế hữu ích | THIẾU BẮT BUỘC (thiết kế) | Đúng M→worker healthcheck200, ghi nguồn/cửa sổ. Không thể đóng chỉ bằng hai closure. |
| T20 | design core (D3); N1-N3 plan | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | Cốt lõi: route M/H không qua worker theo D3, không gửi M/H. N1–N3 W→guest/drop_out/đối chứng guest là coverage bổ sung đã thiết kế, chưa được chạy; N6 chưa duyệt chạy D4. |
| T21a | design | ĐẠT invariant bắt buộc trong lượt R10 đã review; chưa phải toàn host bất biến | — | Không có điều khoản bắt buộc Compose riêng cho phần host. Harness khởi động worker thật trong container riêng, mount poller sentinel. lsmod đổi không vi phạm gate đã duyệt. Phần luồng sản phẩm vẫn tách T18/V1/V2. |
| T21b | design | CHƯA KIỂM liên tục SSH/phiên Claude | THIẾU BẮT BUỘC (thiết kế) | Giữ đúng phiên trong cửa sổ startup/restart có log heartbeat; date chỉ chứng minh tiến trình chạy, cần gắn với phiên SSH thực. Không mặc nhiên dùng ICMP/ping làm bằng chứng phiên SSH. |
| F1a | design | ĐẠT nhánh syntax ở V0 | — | Raw log lỗi guest.nft và exit1; không mở thành chứng minh mọi nhánh V0. |
| F1b | design/plan | CHƯA KIỂM | THIẾU BẮT BUỘC (thiết kế) | Container thử/image thử, không sửa image ghim. Xác nhận dừng trước server/poller/QEMU và lý do thiếu binary. |
| F2 | design | ĐẠT ở V0 | — | ALLOW_VM_INTERNET=true, raw FATAL và exit1. |
| F3 | design | CHƯA KIỂM luồng thật | THIẾU BẮT BUỘC (thiết kế) | Fault khi worker rảnh → task FAILED/lý do đúng, không QEMU. Không lấy V0/harness preboot thay V1. Các biến thể rule/sysctl/neighbor ghi riêng. |
| F4 | design | CHƯA KIỂM luồng thật | THIẾU BẮT BUỘC (thiết kế) | Bản thử hook giữa phase1/2, sau shutdown phase1, không spawn phase2; giữ failure_reason. Không sửa môi trường đang chạy. |
| F5 | design | CHƯA KIỂM restart | THIẾU BẮT BUỘC (thiết kế) | Stop/rm/netns hủy không thay restart. Nhãn restart service Compose đúng thiết kế; thực hiện cần quyết định riêng. |
| F6 | design | CHƯA KIỂM runtime; selftest cấu trúc chỉ offline | THIẾU BẮT BUỘC (thiết kế) | Một container thử nạp cấu trúc khác expected, V0 hoặc V1 từ chối và log diff. Không cần cả V0 lẫn V1 nếu phạm vi chỉ chọn một theo thiết kế. |
| T01/T02-harness | design | ĐẠT riêng download/upload qua guest ARM/MIPS 3A | — | 37/37 không đồng nghĩa đã đi qua poller/phase1/phase2 thật. |
| T03/T04 | design | Giữ scope đã chấp nhận: peer TCP mô phỏng nguồn 2B + một số route từ guest3A | ĐẠT theo scope tổng hợp; xem ghi chú | 3A thử healthcheck/stop/other-file/other-strace; submit-task/docs có ở 2B, không phải đã thử từng route từ cả hai guest. T04 là ba route allowlist khi không current_task. Không tự đòi lặp route đã có nếu chấp nhận tổng hợp hai cấp evidence. |
| T01/T02-runtime; A7/A11/A15 | design+plan | CHƯA KIỂM luồng tác vụ thật | THIẾU BẮT BUỘC (thiết kế) | Đưa thành hàng riêng: download phase1, upload phase2, verify trước mỗi boot, tap/neighbor giữ qua nhiều phase/tác vụ; có thể gộp trial luồng thật cùng F3/F4. |
| D1/D3/D4/D5 + ngoài06B | deferred | HOÃN/GIỚI HẠN — không tự mở scope | HOÃN (tách khỏi bắt buộc) | ARP reply/P3 raw; không probe M/H; N6 chỉ thiết kế; TAP_MAC giả hoãn; mất luật khi guest đang chạy, extra base chain ngoài bảng, fragmentation/IP options/TTL1 không thành bắt buộc. |

## 5. T21 (đã tách)

- **T21a** — invariant host trước/sau khi khởi động worker: ĐẠT các invariant bắt buộc trong lượt R10 đã review (sysctl, nft stateless, IPv4 route, listener, qemu/capture, tap0; IPv6 route/link/addr); lsmod đổi, không là gate, không kết luận toàn host/kernel bất biến và không mở truy tác nhân.
- **T21b** — phiên SSH/Claude không gián đoạn: **CHƯA KIỂM** vì thiếu chứng cứ phiên liên tục có heartbeat gắn với phiên thực; `date`/tiến trình không đủ. Không nêu Compose như điều kiện của T21.

## 6. Thứ tự ưu tiên (review §Tối thiểu còn thiếu), dùng chung môi trường khi không xung đột

| Ưu tiên | Việc | Ghi chú |
|---|---|---|
| 0 — hồ sơ offline | Chấp nhận hai báo cáo closure dẫn xuất theo H0; giữ lịch sử 3D/OPEN 4G; chốt variance log/đối chứng/nguồn; phân loại core vs coverage | Không sửa evaluator chỉ để đổi verdict cũ |
| 1 — probe không đổi cấu hình guest | T05 UDP 8.8.8.8:53; T06 ICMP LAN + IP LAN thứ hai; T11 TCP 22/80 + ICMP (+ xác nhận M→worker cho T10/T19, log đúng cửa sổ nếu còn cần) | ARM→MIPS, mỗi probe một cửa sổ, không chạy song song; B3/I3 chỉ khi điều phối duyệt coverage |
| 2 — T20/D3 | Tra route M/H đúng nguồn (core); N1–N3 từ W + đối chứng guest nếu giữ coverage | Không probe M/H, không N6; `drop_out` đứng trước tap nên không áp delta = pcap |
| 3 — T17 rồi T16 | P1 (core); P2/P4/P5 coverage; M1 đổi MAC | Baseline/restore riêng từng ca (D2); không gửi tiếp sau restore lỗi; mỗi bước dừng để review |
| 4 — V0 âm, không guest | F1 thiếu nft; F6 cấu trúc khác expected | Container thử cô lập, không sửa image ghim |
| 5 — luồng thật có kiểm soát | T18 poller thật; T19 nếu chưa đóng; T21b; F5; T01/T02 phase 1/2, A7/A11/A15; sau baseline mới F3/F4 | Cần duyệt tác động queue/dữ liệu; stop worker không rollback queue |

## 7. Giới hạn

Bản này chỉ đối chiếu hồ sơ và evidence lưu; không chạy root/Docker/guest, không sửa mã/evidence. Số hàng không phải mức nghiệm thu. Các closure là đối chiếu dẫn xuất dưới H0 (xem `CLOSURE-DERIVED-REPORT.md`), không đổi nhãn gốc.

