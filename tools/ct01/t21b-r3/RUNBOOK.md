# CT-01 T21b R3 — phiên SSH liên tục trong cửa sổ startup/restart worker (R3 sửa H3/H4 của review R2)

Hàng T21b: heartbeat gắn với phiên SSH thực trong cửa sổ startup/restart; không dùng ICMP/ping/`date`.

## Thay đổi so với R2
| | R2 | R3 |
|---|---|---|
| H3 | chọn nhịp bằng lọc `[start−3,end+3]` rồi mới kiểm khoảng cách ⇒ khoảng mất nhịp 22 s cắt đầu cửa sổ bị bỏ sót (false PASS, fixture reviewer) | span được **bracket**: nhịp cuối ≤ start và nhịp đầu ≥ end + mọi nhịp giữa; **mọi khoảng** của span (gồm khoảng cắt đầu/cuối) ≤ 3 s ở server **và** ở client (RX monotonic); thiếu bracket ⇒ NOT_MET; không dùng margin |
| Log | append nhiều lần được chấp nhận | đúng **một** HEADER (server và client); heartbeat mở log `x`: run id đã có ⇒ rc 6, không đụng log |
| H4 | `"{1:F3}" -f` theo culture; lệnh inline không kiểm file cũ | `ToString('F3', InvariantCulture)`, UTC `o`; kiểm `Test-Path` trước SSH ở cả .ps1 lẫn lệnh inline; parser từ chối dấu phẩy |
Giữ: full matching server/client (run/seq/iso/epoch/mono/gap), thứ tự/trùng/thiếu, STOP/ABORT/END theo thời điểm (STOP sau cửa sổ chỉ ghi nhận, bên trong chặn), SERVER_SIDE_ONLY khi thiếu client, ngưỡng 3 s không đổi.

## Kiểm (`tests/test_t21b.py`, 38 kiểm)
Fixture reviewer (`tests/fixtures/boundary-*`): R2 trả HELD (false PASS), R3 NOT_MET; clean; gap giữa/cắt đầu/cắt cuối; thiếu bracket đầu/cuối; STOP trước/trong/sau; client giả/hỏng/đảo/trùng/thiếu; gap nhận client; HEADER trùng; dấu phẩy; **đột biến** (chỉ xét nhịp trong cửa sổ) ⇒ fixture reviewer thành HELD (bị B1 bắt); controller (no heartbeat, wrong pin, live, run id reuse).

## Lệnh cho bạn (một lệnh; run id mới do tôi đưa ở thông điệp; tạo file `Downloads\t21b-client-<RUNID>.log`)
Dùng `t21b_client.ps1 -RunId <RUNID>` hoặc dòng inline trong thông điệp (cùng nội dung, có kiểm file cũ và invariant culture). **Một lần duy nhất, không Ctrl-C**: tự kết thúc sau 300 s; nếu phải dừng sớm, báo tôi và dùng run id mới.

## Giới hạn
Chỉ chứng minh: kết nối SSH do lệnh trên tạo không bị gián đoạn (hai phía, mọi khoảng của span) trong cửa sổ startup/restart worker của một lượt F5 riêng; không nói về phiên khác/mạng chung/T21a. R2 giữ lịch sử: lần chạy `t21b-r2-20261011a` bị người dùng ngắt/chạy lại nhiều lần (log có 3 HEADER-session, STOP lúc 05:17:22 giữa lúc lane đang chạy) ⇒ NOT_MET; lane F5 R4 `20261011T051711Z` hoàn tất rc 0 (không dùng làm T21b).
