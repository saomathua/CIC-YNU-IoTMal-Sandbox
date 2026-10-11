# tools/ct01 — mã nguồn đã được chấp nhận (CT-01), import có chọn lọc

Không sửa source/pin; mỗi thư mục giữ nguyên `SHA256SUMS` gốc (manifest của cây đã review, kể cả các tệp lớn không chép: xem `EXCLUDED-LARGE-INPUTS.txt`). Không có bản đề xuất CT-03/CT-02.

| thư mục repo | cây gốc (ngoài repo) | dòng manifest | không chép | sha256 SHA256SUMS |
|---|---|---|---|---|
| `tools/ct01/v0-runtime-r6` | `/home/dathq/projects/ct01-v0-runtime-r6` | 20 | 0 | `4d2e88738e5c60b32f6f276a95b375d6aaae209ba1c17c6e8828ec81b8d02b1c` |
| `tools/ct01/b1-probes-r13n11` | `/home/dathq/projects/ct01-b1probes-r13n11-ops` | 82 | 2 | `476b0d69d559766809c49ec9a5e9208433fcf0741509414f3d188ca0e74ea667` |
| `tools/ct01/spoof-t16-t17-r7` | `/home/dathq/projects/ct01-t1617-r7` | 86 | 2 | `5383df39f32ab587260ea8133fd0ae30d8fa91ea5571b2f1ae2618272b13fc35` |
| `tools/ct01/flow-r4` | `/home/dathq/projects/ct01-flow-r4` | 10 | 2 | `96fcea58141b95239724a5d45e6419315638cc23855e6ec1e3057a35f75d8d60` |
| `tools/ct01/t21b-r3` | `/home/dathq/projects/ct01-t21b-r3` | 5 | 0 | `011bd7c7fd1160a6e6a423b200482c5a280277ebccfe889e8d2d28596f094070` |

Kết luận review gắn với **manifest gốc**, không với cây repo này (cây repo thiếu các tệp lớn nên `sha256sum -c SHA256SUMS` chỉ khớp phần đã chép; dùng EXCLUDED-LARGE-INPUTS để biết phần thiếu).
