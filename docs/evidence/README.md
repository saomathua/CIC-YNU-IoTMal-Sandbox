# Minh chứng

Lưu bằng chứng cho [`KQCaiTien.md`](../../KQCaiTien.md). Quy tắc:

- Không lưu bí mật (mật khẩu, token, `.env`), không lưu mẫu mã độc.
- Output lệnh được rút gọn khi cần; phần che ghi rõ `[đã che]`.
- Đặt tên `taskNN-<nội-dung>.<ext>`; ghi sha256 của tệp nhị phân/log trong bảng dưới.

| Tệp | Nhiệm vụ | Nội dung | sha256 |
|---|---|---|---|
| [`task01-03-baseline-docker-config.md`](task01-03-baseline-docker-config.md) | 01–03 | Khảo sát môi trường, cài Docker, kiểm tra cấu hình tĩnh | — |
| [`task04-build.md`](task04-build.md) | 04 | Tóm tắt kết quả build image | — |
| [`task04-build.log`](task04-build.log) | 04 | Log build đầy đủ (`--progress=plain`) | `3615edb2a21a032048c491dfb84f57b30dcbae5ef64f1d94f938da9621321b10` |
| [`task05-manager-mongo.md`](task05-manager-mongo.md) | 05 | MongoDB + manager, endpoint, cổng, mount, marker lưu trữ | — |
| [`task05-ui-ssh-tunnel.webp`](task05-ui-ssh-tunnel.webp) | 05 | Ảnh `/ui` mở qua SSH tunnel từ Windows (người dùng chụp) | `81778685001998771838c58cb054713db750c397123e60598e52e19322ce64e8` |
| [`task06b1-summary.md`](task06b1-summary.md) | 06B-1 | Triển khai CT-01: unit test, build, kiểm thử nft trong container `--network none` | — |
| [`task06b1/unit-tests.txt`](task06b1/unit-tests.txt) | 06B-1 | `pytest -v`: 107 passed | `36a05ad6de01502892f9081458905b3403c5d0f2d7d51a230c170b3a4ce7d819` |
| [`task06b1/nft-selftest-run1.log`](task06b1/nft-selftest-run1.log) | 06B-1 | Kiểm thử nft lần 1: 20/22 (phát hiện thiếu `dev` trong JSON) | `69ca00d5cb8abad228cb33c4fc5c033a1ebc2e8fef9abab2aae5469b15dfbbef` |
| [`task06b1/nft-selftest-run2.log`](task06b1/nft-selftest-run2.log) | 06B-1 | Kiểm thử nft lần 2: 24/24 | `da99e4b4149ff60e845789fcdbe3b0d072e1be5e177f852651be4cd0078bfe39` |
| [`task06b1/ruleset-loaded.txt`](task06b1/ruleset-loaded.txt) | 06B-1 | `nft list ruleset` trong container kiểm thử | `dd37774b70cf5c50c28ecf7c796d964d84fcd70f3ebb8638e8019613970425da` |
| [`task06b1/packages.txt`](task06b1/packages.txt) | 06B-1 | Phiên bản `nftables`, `libnftables1`, `iproute2` | `0963517769c5bb3a3f8b498f146a2752c890742d7fd4c48d46a2a2e8a04930c6` |
| [`task06b1/build-run1.log`](task06b1/build-run1.log), [`build-run2.log`](task06b1/build-run2.log) | 06B-1 | Log build image worker | `8b7d91da…f268`, `1751e65d…0e0e` |
| [`task06b1r-summary.md`](task06b1r-summary.md) | 06B-1R | Vòng đời QEMU, transaction nft, ghim gói, phạm vi | — |
| [`task06b1r/unit-tests-py312.txt`](task06b1r/unit-tests-py312.txt) | 06B-1R | Unit test trên host, Python 3.12: 117 passed | `0d7d3875199051fccff30a27e17cc0ffb2729b13b2ab74feddd289991a3ae417` |
| [`task06b1r/unit-tests-py310.txt`](task06b1r/unit-tests-py310.txt) | 06B-1R | Unit test trong image, Python 3.10.12: 117 passed | `2af2f2efedb22deace0956a43daf7bfa08bb781631a664bb3fed1be982944c2e` |
| [`task06b1r/nft-selftest-run1.log`](task06b1r/nft-selftest-run1.log) | 06B-1R | Selftest lần 1: 27/29 (lỗi trong script kiểm thử) | `f7a4a56f6a82c13bc6e7eaaf9e29a11c4b5e076f743da00fe92203e7e36f2f21` |
| [`task06b1r/nft-selftest-run2.log`](task06b1r/nft-selftest-run2.log) | 06B-1R | Selftest lần 2: 29/29 | `909aeb51c43e9e32175e87988220e2c6864d4c3b43e71326953dd9cfb485b240` |
| [`task06b1r/packages.txt`](task06b1r/packages.txt) | 06B-1R | Phiên bản gói nft đã ghim, thực tế trong image | `962b08be13af097c2fd371145c3283c952a3b0c9b5d6338a63959d529e08ef4b` |
| [`task06b1r/build.log`](task06b1r/build.log) | 06B-1R | Log build sau khi ghim gói | `d3d3c206c842012bcc06a1868333aace41a934bd76b0831254f53af2eb0f3da2` |
| [`task06b1r/run-unit-py310.sh`](task06b1r/run-unit-py310.sh), [`pytest-wheels.sha256`](task06b1r/pytest-wheels.sha256) | 06B-1R | Script chạy test Python 3.10 offline và sha256 các wheel | `212f9bf8…4df`, `2c4e8651…7c0` |
| [`task06b2a-summary.md`](task06b2a-summary.md) | 06B-2A | `run.sh` và V0 thật trong container test trên `sandboxnet`, chưa có guest | — |
| [`task06b2a/run.log`](task06b2a/run.log) | 06B-2A | Output đầy đủ của harness | `62f432c5562b8c7d50f2d03214ebb2c3ef5abe5cd457e72f834709536a5ef55b` |
| [`task06b2a/harness/`](task06b2a/harness/) | 06B-2A | Script, sentinel, `broken-guest.nft` (sha256 trong summary) | — |
| `task06b2a/ct01-06b2a-*/`, `task06b2a/host-*/`, `task06b2a/host-diff-*.diff` | 06B-2A | Output thô theo từng trường hợp; trạng thái host trước/sau và các khác biệt | — |
| [`task06b2ar-summary.md`](task06b2ar-summary.md) | 06B-2AR | sysctl hiệu lực (`rp_filter` strict, ARP), harness sửa theo review | — |
| [`task06b2ar/run.log`](task06b2ar/run.log) | 06B-2AR | Harness: ALL CHECKS PASSED, exit 0 | `cacc7cb5680c5474351d20a3de4c97944268507277154179c6b4a528696cedd8` |
| [`task06b2ar/build.log`](task06b2ar/build.log) | 06B-2AR | Build image `sha256:d0bf9277…6f42` | `2d05feb13120f303cbfc0894539faa59348840f9fccb5f64aaf05461cb0b9a86` |
| [`task06b2ar/unit-tests-py310.txt`](task06b2ar/unit-tests-py310.txt) | 06B-2AR | Python 3.10.12 trong image: 130 passed | `cb72eace6e9586ab09fda75968dab8d63fc1712021a3583eb53fbeb93bd8d0df` |
| [`task06b2ar/unit-tests-py312.txt`](task06b2ar/unit-tests-py312.txt) | 06B-2AR | Python 3.12 trên host: 130 passed | `a4740a30fdbd89944c28cacc0915d28ecd1e460edaec0a52234342ad8c23d0c3` |
| [`task06b2ar/harness/`](task06b2ar/harness/) | 06B-2AR | `run-06b2ar.sh` (`7308154a…9555`), sentinel, `broken-guest.nft` | — |
| [`task06b2b-summary.md`](task06b2b-summary.md) | 06B-2B | `server.py` thật, API allowlist qua HTTP thật (nguồn guest mô phỏng trên `lo`) | — |
| [`task06b2b/run.log`](task06b2b/run.log) | 06B-2B | Harness: ALL CHECKS PASSED, exit 0 | `cd3f1db85f44142e17185cf82638f83947ee5f1aaf0b56214fc8ee3c9249d5a7` |
| [`task06b2b/ct01-06b2b-http/http-tests.txt`](task06b2b/ct01-06b2b-http/http-tests.txt) | 06B-2B | 42/42 phép thử HTTP | `4cf2325ddb5c90be8217819fca02eddebea56d08c3f8aa0ae7cf3d3471dbb8f5` |
| [`task06b2b/ct01-06b2b-http/server-access-and-deny-log.txt`](task06b2b/ct01-06b2b-http/server-access-and-deny-log.txt) | 06B-2B | Access log của uvicorn và các dòng `guest request denied` | `3cd657f64cc992268d3a39985fc3b80eafda7c930927989bc8e02eb34927b081` |
| [`task06b2b/harness/`](task06b2b/harness/) | 06B-2B | `run-06b2b.sh` (`418097ff…1f67`), `http_tests.py` (`c34cf278…ea32`), sentinel poller | — |
| [`task06b2br-summary.md`](task06b2br-summary.md) | 06B-2BR | Verify phát hiện địa chỉ guest nằm sai interface | — |
| [`task06b2br/run.log`](task06b2br/run.log) | 06B-2BR | Harness: ALL CHECKS PASSED, exit 0 | `639e98128aabfd5be96ac5917ff74ec986c7e730bd01f4bcd62b021f9280195b` |
| [`task06b2br/build.log`](task06b2br/build.log) | 06B-2BR | Build image `sha256:1ab784c7…9153` | `98187d17d6604d3b47a6792849dda3fda454250b9c3e55e0c128c49d323c1d7f` |
| [`task06b2br/unit-tests-py310.txt`](task06b2br/unit-tests-py310.txt) | 06B-2BR | Python 3.10.12 trong image: 142 passed | `1d0ddde994b418401659e5149b3d424d3a48fd0921a75f88050b1fe042979102` |
| [`task06b2br/unit-tests-py312.txt`](task06b2br/unit-tests-py312.txt) | 06B-2BR | Python 3.12 trên host: 142 passed | `e43070cd080085f30806c90eb93a595101170dfc48f985232a2b087686c3a44b` |
| [`task06b2br/harness/`](task06b2br/harness/) | 06B-2BR | `run-06b2br.sh` (`d47b1fa1…0e05`), sentinel | — |
| [`task06b3a-summary.md`](task06b3a-summary.md) | 06B-3A | Boot guest ARM/MIPS thật, liên kết guest → `10.200.0.1:8011` | — |
| [`task06b3a/run1/run.log`](task06b3a/run1/run.log) | 06B-3A | Lần 1: exit 1 (3 FAIL do harness và host ip-addr), giữ làm bằng chứng | `180c7c5542330c4aa6ec58b52bcf7a6eb6ac7ed96f4f38bfa53f22228572fda2` |
| [`task06b3a/run2/run.log`](task06b3a/run2/run.log) | 06B-3A | Lần 2: ALL CHECKS PASSED, ARM 37/37, MIPS 37/37 | `748bba981b84f18759b918db771f27b147c7a60ed437ac051b52e34e75aadf61` |
| [`task06b3a/run2/container/probe/ARM/tap0.pcap`](task06b3a/run2/container/probe/ARM/tap0.pcap) | 06B-3A | Capture `tap0`, ARM | `bf14c6d6bec815ec2bcf49f493474c24941ea24d81f9b374d4a9a4b8a126a723` |
| [`task06b3a/run2/container/probe/MIPS/tap0.pcap`](task06b3a/run2/container/probe/MIPS/tap0.pcap) | 06B-3A | Capture `tap0`, MIPS | `4dcd677b4eb671fa82d3761c9c61cf4b165c310f9af6ff037f2c19f2b6d85a78` |
| [`task06b3a/run2/container/probe/ARM/console.log`](task06b3a/run2/container/probe/ARM/console.log), [`MIPS/console.log`](task06b3a/run2/container/probe/MIPS/console.log) | 06B-3A | Console guest | `8c5ab080…75cf`, `df4f7f37…3ba1` |
| [`task06b3a/run2/pcap-guest-background.txt`](task06b3a/run2/pcap-guest-background.txt) | 06B-3A | Phân loại lưu lượng trong pcap | `b03eb0d87be92327304fe72d75e760ea3e90ae7798d30b20be8e8801fe13903e` |
| [`task06b3a/harness/`](task06b3a/harness/) | 06B-3A | `run-06b3a.sh` (`58bfb13d…da42`), `guest_probe.py` (`02e6bf68…09d6`), sentinel | — |
| [`task06b3b-summary.md`](task06b3b-summary.md) | 06B-3B | Ma trận chặn IPv4 có đối chứng từ guest ARM/MIPS thật | — |
| [`task06b3b/run1/run.log`](task06b3b/run1/run.log) | 06B-3B | Lần 1: exit 1, 15 FAIL (capture phía host crash, lỗi harness), giữ làm bằng chứng | `02d518c8417c52677d42d9969bdc88ace80df5bd406063e6f31f0d6782f66f72` |
| [`task06b3b/run2/run.log`](task06b3b/run2/run.log), [`run3/run.log`](task06b3b/run3/run.log), [`run4/run.log`](task06b3b/run4/run.log) | 06B-3B | Lần 2–4: exit 3, dừng trước khi boot guest (tcpdump `-Z root -w` segfault; regex của harness) | `1f4f12ac…5ac6`, `04211c82…c164`, `1e8e3d00…0c30` |
| [`task06b3b/run3/hostcap/tcpdump-diag.txt`](task06b3b/run3/hostcap/tcpdump-diag.txt) | 06B-3B | Chẩn đoán tcpdump trên `lo`: chỉ `-Z root` + `-w` crash | `8cded01caac57c0e344285fe652ebd131a13f36bfc9f52d62acfdab9ca7cd5cf` |
| [`task06b3b/run5/run.log`](task06b3b/run5/run.log) | 06B-3B | Lần 5: ALL CHECKS PASSED, 20/20 probe ĐẠT, ARM 24/24, MIPS 24/24 | `c3caded61afbde52ab0887ef2d39af27fddb9cf77536828526b7acb2d1f4ef45` |
| [`task06b3b/run5/container/probe/ARM/matrix.json`](task06b3b/run5/container/probe/ARM/matrix.json), [`MIPS/matrix.json`](task06b3b/run5/container/probe/MIPS/matrix.json) | 06B-3B | Ma trận đầy đủ: bộ đếm, phân loại pcap, đối chứng | `fd9ee3a1…50ce`, `695e8588…6296` |
| [`task06b3b/run5/container/probe/ARM/tap0.pcapng`](task06b3b/run5/container/probe/ARM/tap0.pcapng) | 06B-3B | Capture `tap0`, ARM | `ceb95fddc1b4a5a4f876841f3656b1d8a8c2d2efc1349d238da1cde922b10c12` |
| [`task06b3b/run5/container/probe/MIPS/tap0.pcapng`](task06b3b/run5/container/probe/MIPS/tap0.pcapng) | 06B-3B | Capture `tap0`, MIPS | `b7b5c74ec9c8168099ea7ccdb4fc8db6c06196097e8d1663c5923b0eb9eeff3f` |
| [`task06b3b/run5/hostcap/veth.pcap`](task06b3b/run5/hostcap/veth.pcap) | 06B-3B | Capture veth của worker trên host | `908ab6a8f2113d749d1719be7208f913f62b2665a1a3da7455fbad879bc0c66b` |
| [`task06b3b/run5/hostcap/bridge.pcap`](task06b3b/run5/hostcap/bridge.pcap) | 06B-3B | Capture bridge `sandboxnet` trên host | `db285b06de1685c8630c491f66b198b1c3145d85858b37ce5bb960bb2c1714e5` |
| [`task06b3b/run5/hostcap/ens33.pcap`](task06b3b/run5/hostcap/ens33.pcap) | 06B-3B | Capture `ens33` (có bộ lọc) | `80ce6d7516b723ca95ba47fc0698ab12af869e01c2afa2e85c54d0202525ba02` |
| [`task06b3b/run5/ctl/ctl.jsonl`](task06b3b/run5/ctl/ctl.jsonl) | 06B-3B | Log đối chứng MongoDB, manager, IP `eth0` | `2bb8557f164452745650329a97e0e08d8649e015f48cd4ec67efcd08a1716587` |
| [`task06b3b/run5/independent-check.txt`](task06b3b/run5/independent-check.txt) | 06B-3B | Kiểm tra độc lập bằng tcpdump của host | `03e9064baa0371baea698a72c2bceb50dc0522636781b75160cc7a0df4533266` |
| [`task06b3b/harness/`](task06b3b/harness/) | 06B-3B | `run-06b3b.sh` (`f43ec3c4…1e49`), `probe_matrix.py` (`4d7391d8…e457`), `ctl_loop.py` (`4392b397…5340`), `independent_check.sh` (`1f7eb4bf…406e`), sentinel; bản sao theo từng lần tại `runN/harness-copy/` | — |
| [`task06b3c-summary.md`](task06b3c-summary.md) | 06B-3C, 06B-3CR | **Offline:** sửa harness (chữ ký, giám sát capture có heartbeat, netns, manager, thống kê drop từ pcapng ISB); self-test và mutation test | — |
| [`task06b3c/offline-06b3cr/logs/selftest.log`](task06b3c/offline-06b3cr/logs/selftest.log) | 06B-3CR | Self-test offline 68/68 | `c29b8a899871f7de212d8c96dc240e684118ead4729545c7b8b38a73859fd15d` |
| [`task06b3c/offline-06b3cr/logs/mutation-run3-final.txt`](task06b3c/offline-06b3cr/logs/mutation-run3-final.txt) | 06B-3CR | Mutation test: baseline đạt, 26/26 bị bắt, 2 đối chứng đúng loại | `fcd8f29843e2af7c47155ffe01edf2564f5680d44937abb50c3abd62d64b7f49` |
| [`task06b3c/offline-06b3c/`](task06b3c/offline-06b3c/), [`task06b3c/offline-06b3cr/`](task06b3c/offline-06b3cr/) | 06B-3C, 06B-3CR | Diff harness, log, hash (bàn giao gốc, chép nguyên) | xem `SHA256SUMS` trong từng thư mục |
| [`task06b3d-summary.md`](task06b3d-summary.md) | 06B-3D | **Tích hợp thật:** 20 probe IPv4 với harness 06B-3CR; exit 1 (1 FAIL; giả thuyết: lỗi biên cửa sổ của harness) | — |
| [`task06b3d/run1/run.log`](task06b3d/run1/run.log) | 06B-3D | Log harness | `aa6d47123767f4c18ca8dd6e69c70cc813df3e013488d05ad8ba3813b46d8d9f` |
| [`task06b3d/run1/container/probe/ARM/tap0.pcapng`](task06b3d/run1/container/probe/ARM/tap0.pcapng), [`MIPS/tap0.pcapng`](task06b3d/run1/container/probe/MIPS/tap0.pcapng) | 06B-3D | Capture `tap0` (ISB 99/0, 125/0) | `2047b81e…b06d`, `6cabbe9b…cf4` |
| [`task06b3d/run1/hostcap/veth.pcap`](task06b3d/run1/hostcap/veth.pcap), [`bridge.pcap`](task06b3d/run1/hostcap/bridge.pcap), [`ens33.pcap`](task06b3d/run1/hostcap/ens33.pcap) | 06B-3D | Capture phía host | `afbe5d33…425d`, `7a773d4c…19f9`, `64d0c6df…b04e` |
| [`task06b3d/side/heartbeat-samples.tsv`](task06b3d/side/heartbeat-samples.tsv) | 06B-3D | Mẫu heartbeat mỗi giây (bộ ghi mẫu chỉ đọc, không thuộc harness) | `b12d498fd65383d8b4f8262de0bb88721e9ee4f9a6963a99d62f965d2071590e` |
| [`task06b3d/side/independent-check.txt`](task06b3d/side/independent-check.txt) | 06B-3D | Kiểm tra độc lập: chữ ký trên `tap0` và phía host, log đối chứng | `ba5196204a56a00c3e2bb5d155c68a30962ea4a58141b0e4a3bef78314265b1a` |
| [`task06b3d/side/mips-internet-tcp-window-analysis.txt`](task06b3d/side/mips-internet-tcp-window-analysis.txt) | 06B-3D | Phân tích FAIL: lỗi biên cửa sổ thời gian | `f4f557def81c676812e81518e17cccf8d1047b529b8c191cb97a12b853fcbdc1` |
| [`task06b3dr-summary.md`](task06b3dr-summary.md) | 06B-3DR | **Offline:** cửa sổ bộ đếm có mốc thời gian và vùng biên; teardown capture có thời hạn; sửa diễn đạt hồ sơ 06B-3D | — |
| [`task06b3dr/logs/selftest.log`](task06b3dr/logs/selftest.log) | 06B-3DR | Self-test offline 116/116 | `bae3f9ed289bebdcca56f1bcdeb2e48ef91c3c6b4e7f00957b5d0ae004886a5e` |
| [`task06b3dr/logs/mutation-test.txt`](task06b3dr/logs/mutation-test.txt) | 06B-3DR | Mutation test: baseline đạt, 37/37 bị bắt, 2 đối chứng đúng loại | `5c3e152c8e5a7ce96cd52202a1f001291cb605d6db3fab8a48f350493edf897b` |
| [`task06b3dr/ct01-06b3dr-harness-vs-06b3cr.diff`](task06b3dr/ct01-06b3dr-harness-vs-06b3cr.diff) | 06B-3DR | Diff harness so với 06B-3CR | `55f71e5dcac420eebde892b8a33b25eb4f0033a5125fb2e807fa539692412f5e` |
| [`task06b3dr/harness-sha256.txt`](task06b3dr/harness-sha256.txt) | 06B-3DR | Hash các file harness 06B-3DR | `5dfafa960a850fc7130af748e40be664e13019ea39870f2274bc4f0d85f92211` |
| [`task06b3dr1-summary.md`](task06b3dr1-summary.md) | 06B-3DR1 | **Offline:** lỗi đã xác định giữ trước thiếu công cụ/đối chứng; kiểm dữ liệu đo của cửa sổ bộ đếm; đính chính khẳng định quá mức | — |
| [`task06b3dr1/logs/repro-before-after.txt`](task06b3dr1/logs/repro-before-after.txt) | 06B-3DR1 | Tái hiện lỗ hổng trên 06B-3DR và kết quả sau khi sửa | `e6e596ba2f9266ab1eddeb1d92b6be9e54608c1260463b6f3051a4287296413d` |
| [`task06b3dr1/logs/selftest.log`](task06b3dr1/logs/selftest.log) | 06B-3DR1 | Self-test offline 143/143 | `aac3b9f768c1a97c9301a558134abaf86650b970da496d80ec1c4fb9c23efff4` |
| [`task06b3dr1/logs/mutation-test.txt`](task06b3dr1/logs/mutation-test.txt) | 06B-3DR1 | Mutation test: baseline đạt, 48/48 bị bắt, 2 đối chứng đúng loại | `1eb9ad143be1c062c34ac3f7dbf5599ed7109b863fc7a111292c064aae2cc953` |
| [`task06b3dr1/ct01-06b3dr1-harness-vs-06b3dr.diff`](task06b3dr1/ct01-06b3dr1-harness-vs-06b3dr.diff) | 06B-3DR1 | Diff harness so với 06B-3DR | `c52946159a8473a0e3f7b54e9e25d02e96c20b11b9893338af21eee3041943b8` |
| [`task06b3e-summary.md`](task06b3e-summary.md) | 06B-3E | **Tích hợp thật** harness 06B-3DR1, 20 probe IPv4: exit 4 (16 ĐẠT, 4 CHƯA KIỂM CHỨNG do gói biên, 0 FAIL) | — |
| [`task06b3e/run1/run.log`](task06b3e/run1/run.log) | 06B-3E | Log harness | `0774762662e70e15b803acb2043fe9befe971ad6945abb2663ec8a0c97e82488` |
| [`task06b3e/run1/container/probe/ARM/counters-raw.jsonl`](task06b3e/run1/container/probe/ARM/counters-raw.jsonl), [`MIPS/counters-raw.jsonl`](task06b3e/run1/container/probe/MIPS/counters-raw.jsonl) | 06B-3E | Dữ liệu thô các lần đọc nft, kèm `t_start`/`t_end` | `81b917b4…cdfe`, `2561c7d3…0b5a` |
| [`task06b3e/run1/container/probe/ARM/matrix.json`](task06b3e/run1/container/probe/ARM/matrix.json), [`MIPS/matrix.json`](task06b3e/run1/container/probe/MIPS/matrix.json) | 06B-3E | Ma trận kèm đối chiếu theo vùng | `e53fe376…2bcc`, `4e90a4c8…3045` |
| [`task06b3e/run1/container/probe/ARM/tap0.pcapng`](task06b3e/run1/container/probe/ARM/tap0.pcapng), [`MIPS/tap0.pcapng`](task06b3e/run1/container/probe/MIPS/tap0.pcapng) | 06B-3E | Capture `tap0` (ISB 83/0, 125/0) | `102ad948…94ef`, `3bdd523b…d8e4` |
| [`task06b3e/run1/hostcap/veth.pcap`](task06b3e/run1/hostcap/veth.pcap), [`bridge.pcap`](task06b3e/run1/hostcap/bridge.pcap), [`ens33.pcap`](task06b3e/run1/hostcap/ens33.pcap) | 06B-3E | Capture phía host | `39c29c0d…c9b`, `9b10400a…522c`, `5562517c…ad49` |
| [`task06b3e/run1/hostcap/teardown-timeline.txt`](task06b3e/run1/hostcap/teardown-timeline.txt), [`capture-stats.tsv`](task06b3e/run1/hostcap/capture-stats.tsv) | 06B-3E | Mốc teardown; thống kê capture | `e7f7a4d8…f28c`, `6b0580b4…e523` |
| [`task06b3e/side/edge-analysis.txt`](task06b3e/side/edge-analysis.txt) | 06B-3E | Thời gian đọc nft; các gói biên | `fc69098f5621e203160d607293552c97a6324c567701ba37d7256778e23fff0a` |
| [`task06b3e/side/probe-frames-zone-check.txt`](task06b3e/side/probe-frames-zone-check.txt) | 06B-3E | Vùng của mọi gói probe (sau lần chạy) | `0ce71089c56db07fc64da9543135183ac6d3b82c44b884f667c44d7341c35ed5` |
| [`task06b3e/side/heartbeat-samples.tsv`](task06b3e/side/heartbeat-samples.tsv) | 06B-3E | Mẫu heartbeat (bộ ghi mẫu chỉ đọc, không thuộc harness) | `0e5b6d65834a00d7bddff39423b5a42db78b1131e11da45a5529410bb8b749db` |
| [`task06b3e/side/independent-check.txt`](task06b3e/side/independent-check.txt) | 06B-3E | Kiểm tra độc lập: chữ ký, log đối chứng | `e72e7b034bd9e44631361b0ddf4df594a5c55af5847b6b1a7aa6cdbb708d9955` |
| [`task06b3f-summary.md`](task06b3f-summary.md) | 06B-3F | **Offline:** đối chiếu bộ đếm toàn phiên guest (báo cáo riêng, không đổi mã thoát); tiêu chí; đính chính kỳ vọng về biên | — |
| [`task06b3f/ct01-06b3f-harness-vs-06b3dr1.diff`](task06b3f/ct01-06b3f-harness-vs-06b3dr1.diff) | 06B-3F | Diff harness so với 06B-3DR1 | `bd32dfda16736f776a39614ee4e107733499d1c80419811fe4643ba24f6bad45` |
| [`task06b3f/logs/selftest.log`](task06b3f/logs/selftest.log) | 06B-3F | Self-test offline 171/171 | `cd1f380610d65b6dfd503b2f46e5595a387ca95b978628ca9fe63385cb61d2ba` |
| [`task06b3f/logs/mutation-test.txt`](task06b3f/logs/mutation-test.txt) | 06B-3F | Mutation test: baseline đạt, 60/60 bị bắt, 2 đối chứng đúng loại | `67c36d39449438a488b1d123a1e4d6abec852e64b452f3f9bd40db96cdc34a64` |
| [`task06b3f/harness-sha256.txt`](task06b3f/harness-sha256.txt) | 06B-3F | Hash các file harness 06B-3F | `5ec05b1fca0b062b1b91ee7beb5f6b7e7b1678d00e489fda24fe1022825ec17b` |
| [`task06b3fr-summary.md`](task06b3fr-summary.md) | 06B-3FR | **Offline:** sửa tính đầy đủ của phép đo toàn phiên (gói trước cửa sổ, trạng thái QEMU, F1+F2, đủ bộ đếm) | — |
| [`task06b3fr/ct01-06b3fr-harness-vs-06b3f.diff`](task06b3fr/ct01-06b3fr-harness-vs-06b3f.diff) | 06B-3FR | Diff harness so với 06B-3F | `27151c7e9b84e7a711d78e96e740ac6e46bb35e3b68e8183943a4f8cc154843a` |
| [`task06b3fr/logs/repro-before-after.txt`](task06b3fr/logs/repro-before-after.txt) | 06B-3FR | 11 ca hồi quy: 06B-3F báo PASS sai, 06B-3FR đúng | `2a08868641af10a1e698a43039a611a4f8a0845b2083e472ed0b13b60191c420` |
| [`task06b3fr/logs/selftest.log`](task06b3fr/logs/selftest.log) | 06B-3FR | Self-test offline 195/195 | `d0f0da65380f510bc795b5e8a60098a4b6480a2dfc145e6fff69c6735889442a` |
| [`task06b3fr/logs/mutation-test.txt`](task06b3fr/logs/mutation-test.txt) | 06B-3FR | Mutation test lần 2: baseline đạt, 71/71 bị bắt, 2 đối chứng đúng loại | `a2ea1532bea7ce751241d0087d5b1403ed1bf6e3c2f563f7baa9ef5647393cdc` |
| [`task06b3fr/logs/mutation-test-run1-SE1-retargeted.txt`](task06b3fr/logs/mutation-test-run1-SE1-retargeted.txt) | 06B-3FR | Mutation test lần 1 (SE1 bị bắt ở ca khác ca được nhắm) | `6b5a762db147f0b1a975f4a2083935eba018dff5e66d394b3cb4860a0121e36e` |
| [`task06b3fr/harness-sha256.txt`](task06b3fr/harness-sha256.txt) | 06B-3FR | Hash các file harness 06B-3FR | `06163c5bc0e7ee464e5c32764a718a662644995ee111ad43f954c32038edfdfe` |
| [`task06b3fr1-summary.md`](task06b3fr1-summary.md) | 06B-3FR1 | **Offline:** không nuốt lỗi khi quét tiến trình QEMU; ghi rõ lần chạy bị mất log | — |
| [`task06b3fr1/ct01-06b3fr1-harness-vs-06b3fr.diff`](task06b3fr1/ct01-06b3fr1-harness-vs-06b3fr.diff) | 06B-3FR1 | Diff harness so với 06B-3FR | `68f64ec2d4c07b288fad9dcbb64bf000d1159d73a4db17138c8abf7a5693c571` |
| [`task06b3fr1/logs/repro-before-after.txt`](task06b3fr1/logs/repro-before-after.txt) | 06B-3FR1 | PermissionError: 06B-3FR → [] → PASS; 06B-3FR1 → ERROR | `7ff71d7b20cdc2c2db71ff696a2871e99e8e4aae0d9f9edf176bc1797bad99f6` |
| [`task06b3fr1/logs/selftest.log`](task06b3fr1/logs/selftest.log) | 06B-3FR1 | Self-test offline 205/205 (chạy lại) | `90ca466fcd8a57776283a5aae4e5e8c3f4c0bff583386905d4a3a6b8a0035173` |
| [`task06b3fr1/logs/mutation-test.txt`](task06b3fr1/logs/mutation-test.txt), [`mutation-test.status.txt`](task06b3fr1/logs/mutation-test.status.txt) | 06B-3FR1 | Mutation test chạy lại: baseline đạt, 76/76 bị bắt, 2 đối chứng đúng loại; kiểm hash trước/sau | `5011088f…a285`, `aa313544…15ed` |
| [`task06b3fr1/harness-sha256.txt`](task06b3fr1/harness-sha256.txt) | 06B-3FR1 | Hash bản harness đã kiểm thử | `06b1fa73a574643ccad3435fd8ddc135324895e9033ea1a08af9a12acecf0e7c` |
| [`task06b3g-summary.md`](task06b3g-summary.md) | 06B-3G | **Tích hợp thật** phép đo toàn phiên (harness 06B-3FR1), 20 probe IPv4: exit 4 (19 ĐẠT, 1 CHƯA KIỂM CHỨNG do gói biên, 0 FAIL); toàn phiên ARM PASS, MIPS PASS (báo riêng) | — |
| [`task06b3g/run1/run.log`](task06b3g/run1/run.log) | 06B-3G | Log harness | `e02c76f23dc947900fd2ceab5386a0c7baa28ac81a59196df258942982d202a8` |
| [`task06b3g/run1/container/probe/ARM/session.json`](task06b3g/run1/container/probe/ARM/session.json), [`MIPS/session.json`](task06b3g/run1/container/probe/MIPS/session.json) | 06B-3G | Kết luận toàn phiên: A/F1/F2, quét QEMU, capture, đối chiếu | `f48ca3ac…8cbc`, `031a0f38…d6ff6` |
| [`task06b3g/run1/container/probe/ARM/counters-raw.jsonl`](task06b3g/run1/container/probe/ARM/counters-raw.jsonl), [`MIPS/counters-raw.jsonl`](task06b3g/run1/container/probe/MIPS/counters-raw.jsonl) | 06B-3G | Dữ liệu thô các lần đọc nft, kèm `t_start`/`t_end` | `07b84539…68ba`, `68101f2d…9a74` |
| [`task06b3g/run1/container/probe/ARM/matrix.json`](task06b3g/run1/container/probe/ARM/matrix.json), [`MIPS/matrix.json`](task06b3g/run1/container/probe/MIPS/matrix.json) | 06B-3G | Ma trận kèm đối chiếu theo vùng | `26f030a6…1b54`, `2e21b88d…757b` |
| [`task06b3g/run1/container/probe/ARM/tap0.pcapng`](task06b3g/run1/container/probe/ARM/tap0.pcapng), [`MIPS/tap0.pcapng`](task06b3g/run1/container/probe/MIPS/tap0.pcapng) | 06B-3G | Capture `tap0` (ISB 97/0, 125/0) | `50516af3…a2`, `603daafa…71` |
| [`task06b3g/run1/hostcap/veth.pcap`](task06b3g/run1/hostcap/veth.pcap), [`bridge.pcap`](task06b3g/run1/hostcap/bridge.pcap), [`ens33.pcap`](task06b3g/run1/hostcap/ens33.pcap) | 06B-3G | Capture phía host | `4941ef03…99c5`, `4df9633f…9ba4`, `d22194e9…db50c` |
| [`task06b3g/run1/hostcap/teardown-timeline.txt`](task06b3g/run1/hostcap/teardown-timeline.txt), [`capture-stats.tsv`](task06b3g/run1/hostcap/capture-stats.tsv) | 06B-3G | Mốc teardown; thống kê capture | `487e0bea…68e8`, `96678418…42bb` |
| [`task06b3g/side/precheck.txt`](task06b3g/side/precheck.txt) | 06B-3G | Kiểm image ID, container, tiến trình trước khi chạy (sudo, chỉ đọc) | `b12ccc67950de11f0fae4f0db07632c14d6462e71a275ba6c12dc5d50c6d169c` |
| [`task06b3g/side/session-crosscheck.txt`](task06b3g/side/session-crosscheck.txt) | 06B-3G | Kiểm chéo `session.json` với tổng khung `tap0` (tcpdump) | `ebc354a33f51030e8881b830f8de0271c4604e9d7e53d6297b88edfe18cfe336` |
| [`task06b3g/side/raw-reads-check.txt`](task06b3g/side/raw-reads-check.txt) | 06B-3G | JSON nft thô của A/F1/F2 so với `session.json`; thời gian đọc nft | `697d150391c37189ce7d8dfa1dcaaa942cc5b26ff95d5689cabf472032dd3da1` |
| [`task06b3g/side/edge-and-zone-check.txt`](task06b3g/side/edge-and-zone-check.txt) | 06B-3G | Vùng của mọi gói probe; giải mã gói biên | `9542727343090bbbf35162612236156c94060ec6aa29ca9dc728e5e94b9e33d9` |
| [`task06b3g/side/independent-check.txt`](task06b3g/side/independent-check.txt) | 06B-3G | Kiểm tra độc lập: chữ ký, log đối chứng | `baedd05a1f6dc49968519bf487f98cf2c82cd66b1bf8b71a6b52dd6077bf50d1` |
| [`task06b3g/SHA256SUMS`](task06b3g/SHA256SUMS) | 06B-3G | Hash mọi file trong `task06b3g/` (trừ 6 file `__pycache__` bị `.gitignore` loại) | `f92445bdeabf207f126199272dace3dd2a2724ecf807f4bb8893506938801680` |
| [`../ct01-remaining-tests-plan.md`](../ct01-remaining-tests-plan.md) | 06B-4A | **Kế hoạch** (chưa chạy): T12, T13, T14–T15, T16, T17, T20; ánh xạ bộ đếm ARP; mục IPv4 và fail-closed còn thiếu | — |
| [`task06b4a/guest-static-inventory.txt`](task06b4a/guest-static-inventory.txt) | 06B-4A | Danh mục **tĩnh** ảnh guest ARM/MIPS (debugfs, không boot): phiên bản OpenWrt/BusyBox, công cụ, cấu hình mạng/firewall/dịch vụ | `38d2ef44cac91ce42326aa8674f1e49d36da6797fc1fa49754799646b894f689` |
| [`task06b4a/guest_static_inventory.sh`](task06b4a/guest_static_inventory.sh) | 06B-4A | Script tạo danh mục tĩnh (chỉ đọc) | `2eaaa5c0c3ba57241d1be6f3a5f661ae7058f57f2a9662ca4f598a6ff2aef5d6` |
| [`task06b4b-summary.md`](task06b4b-summary.md) | 06B-4B | **Offline:** harness đo L2/ARP/IPv6 (bản mới `ct01-06b4b`); sửa kế hoạch theo review; cổng probe mới 31000–31299 | — |
| [`task06b4b/ct01-06b4b-harness-vs-06b3fr1.diff`](task06b4b/ct01-06b4b-harness-vs-06b3fr1.diff) | 06B-4B | Diff harness so với 06B-3FR1 | `48ce02a68a0024c4cc99582cb3fc490da468957efb97db1c4448cc5087f13745` |
| [`task06b4b/harness-sha256.txt`](task06b4b/harness-sha256.txt) | 06B-4B | Hash bản harness đã kiểm thử | `26726abdbc2441798861151adc2f28de52254e6694c78049fe88764aa677850b` |
| [`task06b4b/logs/selftest-l2.log`](task06b4b/logs/selftest-l2.log) | 06B-4B | Self-test L2 167/167 (gồm hồi quy 06B-3G) | `0094395d4f4a8d09215c4fc9a189a66a205faf80861f5cbe27ea37143daf6e25` |
| [`task06b4b/logs/mutation-l2.txt`](task06b4b/logs/mutation-l2.txt) | 06B-4B | Mutation L2: 56/56 bị bắt, 2 đối chứng đúng loại | `f199a37ebf020da25ff2f97d029259ecb573f70623bdb0b571c9f147e4a02ccd` |
| [`task06b4b/logs/selftest-legacy.log`](task06b4b/logs/selftest-legacy.log), [`mutation-legacy.txt`](task06b4b/logs/mutation-legacy.txt) | 06B-4B | Self-test cũ 205/205 và mutation cũ 76/76 + 2 trên bản mới | `ac308a4d…fe5912`, `c0279ee9…6ccef` |
| [`task06b4b/guest-static-inventory.txt`](task06b4b/guest-static-inventory.txt), [`guest_static_inventory.sh`](task06b4b/guest_static_inventory.sh) | 06B-4B | Danh mục tĩnh chạy lại bằng script đã sửa (scratch `mktemp`) | `d98bed39…d930`, `d5f72d7b…461b` |
| [`task06b4b/SHA256SUMS`](task06b4b/SHA256SUMS) | 06B-4B | Hash mọi file trong `task06b4b/` | `f3830a5ec3ade557d8852449d5e9fb3af2a3ddb904662066931ddbc597afc66d` |
| [`task06b4br-summary.md`](task06b4br-summary.md) | 06B-4BR | **Offline:** chữ ký trên capture bị cắt bởi snaplen; phân biệt gói bị cắt / file hỏng / gói dị dạng | — |
| [`task06b4br/ct01-06b4br-harness-vs-06b4b.diff`](task06b4br/ct01-06b4br-harness-vs-06b4b.diff) | 06B-4BR | Diff harness so với 06B-4B | `81dc6774e4ddc9555c66de2d119c89bd3816adf96869b059114924549a2b2c8d` |
| [`task06b4br/harness-sha256.txt`](task06b4br/harness-sha256.txt) | 06B-4BR | Hash bản harness đã kiểm thử | `23cb6145f910b49cf37f7121ff3884db692d64d8cda72d34002107e7ed914c7e` |
| [`task06b4br/logs/repro-before-after.txt`](task06b4br/logs/repro-before-after.txt) | 06B-4BR | ICMP 1705 B sau NAT, cắt 512: 06B-4B → 0; 06B-4BR → `icmp_size=1` | `066544b15086895a0b828d58d44102a9dc3d0a2d5402fb538557b8a3c88b43ff` |
| [`task06b4br/logs/selftest-l2.log`](task06b4br/logs/selftest-l2.log) | 06B-4BR | Self-test L2 195/195 | `7f187a84c0453897bf8d3a87c09f6a0e42594f6f33e3126e4ba2365d6820ffe6` |
| [`task06b4br/logs/mutation-l2.txt`](task06b4br/logs/mutation-l2.txt) | 06B-4BR | Mutation L2: 69/69 + 2 đối chứng | `19a1ff64680027d44ec6698284d73d8e4e38b2a89140e0d3789189433c27b5a6` |
| [`task06b4br/logs/selftest-legacy.log`](task06b4br/logs/selftest-legacy.log), [`mutation-legacy.txt`](task06b4br/logs/mutation-legacy.txt) | 06B-4BR | Self-test cũ 205/205; mutation cũ 76/76 + 2 | `28c6174d…8e45`, `32753c87…4ea7` |
| [`task06b4br/SHA256SUMS`](task06b4br/SHA256SUMS) | 06B-4BR | Hash mọi file trong `task06b4br/` | `1c8fa4df6e6bcda6467c8d99fd00003d078805b2a2902c8fa0970757260ddd7e` |
| [`task06b4c-summary.md`](task06b4c-summary.md) | 06B-4C | **Tích hợp thật** harness 06B-4BR, 20 probe IPv4: exit 4 (17 ĐẠT, 3 CHƯA KIỂM CHỨNG, 0 FAIL); toàn phiên ARM/MIPS PASS; capture `ens33` không lọc, cảnh báo veth, `sigscan_l2` hoạt động | — |
| [`task06b4c/run1/run.log`](task06b4c/run1/run.log) | 06B-4C | Log harness | `9e8bca0d01d483a47487f0cb859046202d82a1a427684baf0481805754cad7cd` |
| [`task06b4c/run1/hostcap/ens33.pcap`](task06b4c/run1/hostcap/ens33.pcap) | 06B-4C | Capture `ens33` không lọc, snaplen 512 (có lưu lượng khác của host) | `3c1e67645ebff9284f815a8ccd4de791cce903a2efb4af5c859304ab24a907dc` |
| [`task06b4c/side/l2-observation.txt`](task06b4c/side/l2-observation.txt) | 06B-4C | Quan sát ARP/L2 bằng `l2frames.py` trên `tap0` đã lưu (không phải probe mới) | `9ed80d14ae98ba78936e7800c57f6d5ce7cf7927bdf41cc72b5197ad3609bee3` |
| [`task06b4c/side/alert-and-ens33-check.txt`](task06b4c/side/alert-and-ens33-check.txt) | 06B-4C | Bộ lọc cảnh báo trên dữ liệu thật; snaplen/cắt của `ens33` | `4fdc342a03d8107602ab81c3a02955fc0a6f8d5dde0966bd95defa4e135e782d` |
| [`task06b4c/SHA256SUMS`](task06b4c/SHA256SUMS) | 06B-4C | Hash mọi file trong `task06b4c/` | `41868db911208951f19cfbea8285cbfbff21bf4c90317b04e98990b41940cbd9` |
| [`task06b4d1-summary.md`](task06b4d1-summary.md) | 06B-4D1 | **Offline:** bộ đánh giá L2/ARP từ file capture (`l2eval.py`); chưa triển khai T12–T15 | — |
| [`task06b4d1/ct01-06b4d1-harness-vs-06b4br.diff`](task06b4d1/ct01-06b4d1-harness-vs-06b4br.diff) | 06B-4D1 | Diff harness so với 06B-4BR (3 file mới) | `871729722c56714cf494b214b2c7add9f207dcfef7d9a0a80ff6ca1c169ac7e7` |
| [`task06b4d1/logs/selftest-l2eval.log`](task06b4d1/logs/selftest-l2eval.log) | 06B-4D1 | Self-test 46/46 | `821610a3d407dcb619e2219c611ffe91abfb9a872ed178e866dc38fa6e2ddf2b` |
| [`task06b4d1/logs/mutation-l2eval.txt`](task06b4d1/logs/mutation-l2eval.txt) | 06B-4D1 | Mutation 13/13 + 2 đối chứng | `aaec34be65c2662c38b1f40610f968a201d435cd662e36208deeccc5c6cff757` |
| [`task06b4d1/SHA256SUMS`](task06b4d1/SHA256SUMS) | 06B-4D1 | Hash mọi file trong `task06b4d1/` | `b5709988e5c85109906da0f3e3409c0c090bd042d2f3706e134ec8a978ad0f4c` |
| [`task06b4d1r-summary.md`](task06b4d1r-summary.md) | 06B-4D1R | **Offline:** sửa danh sách lớp rỗng/trùng/sai và kiểm cấu trúc JSON bộ đếm trong `l2eval.py` | — |
| [`task06b4d1r/ct01-06b4d1r-analyzer-vs-06b4d1.diff`](task06b4d1r/ct01-06b4d1r-analyzer-vs-06b4d1.diff) | 06B-4D1R | Diff bộ phân tích so với 06B-4D1 | `fb5f0290b3d2418e09dd1d31ec9776c2a1ffb41f12a3d7882cfe9beeae6885fa` |
| [`task06b4d1r/logs/repro-before-after.txt`](task06b4d1r/logs/repro-before-after.txt) | 06B-4D1R | 4 ca reviewer: trước PASS/exception, sau ERROR có lý do | `5d336d71f27082555ef3c25b9f5389298dca4eddcd35c14d6af9a3efd5d10747` |
| [`task06b4d1r/logs/selftest-l2eval.log`](task06b4d1r/logs/selftest-l2eval.log) | 06B-4D1R | Self-test 72/72 | `96c534ad57792541e2ce4dfcab052a25b81ea3dfb5f5517015ed1dda824c6988` |
| [`task06b4d1r/logs/mutation-l2eval.txt`](task06b4d1r/logs/mutation-l2eval.txt) | 06B-4D1R | Mutation 26/26 + 2 đối chứng | `aad310de73b95cfc9b2c6604f11daeea2b9bbb44316ab7a4eb1bfa9cb8ca61a0` |
| [`task06b4d1r/SHA256SUMS`](task06b4d1r/SHA256SUMS) | 06B-4D1R | Hash mọi file trong `task06b4d1r/` | `e3056cda53d5b02c059d1b7e0ce70003132e92049486aaadb2494bb27a63b696` |
| [`task06b4e-summary.md`](task06b4e-summary.md) | 06B-4E | **Offline:** chuẩn bị T12–T13 (ICMP broadcast/multicast, ICMPv6) bằng ping/ping6 của guest; chưa chạy | — |
| [`task06b4e/ct01-06b4e-harness-vs-06b4d1r.diff`](task06b4e/ct01-06b4e-harness-vs-06b4d1r.diff) | 06B-4E | Diff harness so với 06B-4D1R (3 file mới) | `6cb9222994ea4eee028653644e39af178098778f574a8cd511f337b2e90db636` |
| [`task06b4e/prepared-cases.txt`](task06b4e/prepared-cases.txt) | 06B-4E | 5 ca đã chuẩn bị (lệnh, lớp mong đợi) | `ddc639284bac1c7d335724213447a2abe53dede6cc81ef664313aa950a718db3` |
| [`task06b4e/logs/selftest-icmp.log`](task06b4e/logs/selftest-icmp.log) | 06B-4E | Self-test 55/55 | `30d52a0e2ad43318cccc780be41ae59e16580901c7a545741ef0e92fc7351bf8` |
| [`task06b4e/logs/mutation-icmp.txt`](task06b4e/logs/mutation-icmp.txt) | 06B-4E | Mutation 19/19 + 2 đối chứng | `bd92ea469519633829c0551de566ac64b4109b79de5d25c36cb91f0e9c7b8b5d` |
| [`task06b4e/SHA256SUMS`](task06b4e/SHA256SUMS) | 06B-4E | Hash mọi file trong `task06b4e/` | `b18f5eb8832d821d1c21cc3ab5b22eed00948537fb533e8f03b876ef0fd7bf42` |
| [`task06b4er-summary.md`](task06b4er-summary.md) | 06B-4ER | **Offline:** liên kết trước nhóm đánh giá từ record; NS T13-I2 nhận diện theo target (sửa `l2frames.decode`: thêm `ns_target`) | — |
| [`task06b4er/ct01-06b4er-harness-vs-06b4e.diff`](task06b4er/ct01-06b4er-harness-vs-06b4e.diff) | 06B-4ER | Diff harness so với 06B-4E (4 file, gồm `l2frames.py`) | `5f790964e4065363aaf45473898858a8c98fcc064aab821439acc1ece283bb72` |
| [`task06b4er/logs/repro-before-after.txt`](task06b4er/logs/repro-before-after.txt) | 06B-4ER | 2 ca reviewer: trước ĐẠT sai, sau CHƯA KIỂM CHỨNG | `e598b340406319fe13b470ce605f98207217ba8732ecbc696eb65bfb5e95aec5` |
| [`task06b4er/logs/selftest-icmp.log`](task06b4er/logs/selftest-icmp.log) | 06B-4ER | Self-test ICMP 79/79 | `d25611413d731cf9180790349e14e76266edcea9c32fb40eb01d70d2499f354c` |
| [`task06b4er/logs/mutation-icmp.txt`](task06b4er/logs/mutation-icmp.txt) | 06B-4ER | Mutation ICMP 28/28 + 2 đối chứng | `56c65660491d8467585b1149eecf628ea02316da2fdc20dd784693866747627f` |
| [`task06b4er/SHA256SUMS`](task06b4er/SHA256SUMS) | 06B-4ER | Hash mọi file trong `task06b4er/` | `1ffc25f42900cfbcc3913a74575fc5647f661364eb052b711bca41e6bcffd40d` |
| [`task06b4f-summary.md`](task06b4f-summary.md) | 06B-4F | **Offline, chưa chạy tích hợp:** nối 5 ca ICMP (T12-B1/B2/B4, T13-I1/I2) vào harness (`CT01_SUITE=icmp`, `icmp_harness.py`, `run-06b4f.sh`) | — |
| [`task06b4f/ct01-06b4f-harness-vs-06b4e.diff`](task06b4f/ct01-06b4f-harness-vs-06b4e.diff) | 06B-4F | Diff harness so với 06B-4ER (`probe_matrix.py` + 4 file mới) | `90f59172ca1112dc287f7c148a28a973a3458931c97299b32f8a8fd7eecb430e` |
| [`task06b4f/logs/selftest-icmp-wiring.log`](task06b4f/logs/selftest-icmp-wiring.log) | 06B-4F | Self-test wiring 92/92 (container/guest giả) | `bb9aca7502651f9214a5fa970d54f8043de58b5f004ce8105c7956323d0c3307` |
| [`task06b4f/logs/mutation-icmp-wiring.txt`](task06b4f/logs/mutation-icmp-wiring.txt) | 06B-4F | Mutation wiring 26/26 + 2 đối chứng | `7b194ce2a4662f64dc3ab72d5696061538f33cde5cb6a98aeddd8629d3d435b2` |
| [`task06b4f/logs/selftest-sh.log`](task06b4f/logs/selftest-sh.log) | 06B-4F | `selftest.sh` hồi quy (205 PASS) | `731c35975de319412501f2d37c6f17aa309e075a11e6d47903c700f1266edb74` |
| [`task06b4f/logs/mutation-test-sh.log`](task06b4f/logs/mutation-test-sh.log) | 06B-4F | `mutation_test.sh` hồi quy 78/78 | `6763daf6aabecacc57de4fc2a29eba4ada92ecde1c739092a1816214b3d70d75` |
| [`task06b4f/SHA256SUMS`](task06b4f/SHA256SUMS) | 06B-4F | Hash mọi file trong `task06b4f/` | `52dbe9d6dab27b06e906adf6a7dcc53767c9991cb00dff2cfb3252702370219e` |
| [`task06b4fr-summary.md`](task06b4fr-summary.md) | 06B-4FR | **Offline, chưa chạy tích hợp:** sửa 2 lỗi review 06B-4F (P1 kiểm cảnh báo trước lệnh guest; P2 đủ xác nhận hạ tầng bắt buộc trong `--outcome`) | — |
| [`task06b4fr/ct01-06b4fr-harness-vs-06b4f.diff`](task06b4fr/ct01-06b4fr-harness-vs-06b4f.diff) | 06B-4FR | Diff harness so với 06B-4F (5 file) | `e86022108f3767496bb8cafa358ef7bbb6d0b36acfdb26d396df172abc81b21b` |
| [`task06b4fr/logs/repro-before-after.txt`](task06b4fr/logs/repro-before-after.txt) | 06B-4FR | Tái hiện: P1 ping T12-B2 gửi/không gửi; P2 sai 21/26 → 0/26 | `80ebda1c60173ed3a7e2262c83bcbc3e94ef970c6fd0c511dde41f2f42b6019e` |
| [`task06b4fr/logs/selftest-icmp-wiring.log`](task06b4fr/logs/selftest-icmp-wiring.log) | 06B-4FR | Self-test wiring 129/129 | `f1088f2beb4d2ff14ef65b5901d7ddbbbd50e4b5bf7bc512f3e6e2c20be41f00` |
| [`task06b4fr/logs/mutation-icmp-wiring.txt`](task06b4fr/logs/mutation-icmp-wiring.txt) | 06B-4FR | Mutation wiring 33/33 + 2 đối chứng | `a0ebcde1e45cd1ecf5a530a916f4f3157be61d430bd91568170a9f60e145794b` |
| [`task06b4fr/logs/selftest-sh.log`](task06b4fr/logs/selftest-sh.log) | 06B-4FR | `selftest.sh` hồi quy (205 PASS) | `444f51d48b6cbb3deac7f92998b2fcc5ce8a8befd7c3f92b0730bbaea1b7b255` |
| [`task06b4fr/SHA256SUMS`](task06b4fr/SHA256SUMS) | 06B-4FR | Hash mọi file trong `task06b4fr/` | `f3abe320b5c8388b83338f7e5169f896e30540d8c214c36a81965fd5801b32a7` |
| [`task06b4g-summary.md`](task06b4g-summary.md) | 06B-4G | **[KC] Tích hợp một lần:** 5 ca ICMP T12–T13, ARM rồi MIPS; exit 4: 9/10 ĐẠT (kiểm quy tắc), ARM T13-I1 CHƯA KIỂM CHỨNG (gói biên), 0 FAIL, 3 mục mở tcpdump | — |
| [`task06b4g/precheck/precheck.txt`](task06b4g/precheck/precheck.txt) | 06B-4G | Precheck chỉ đọc (image, manager, container, tiến trình, output, AppArmor) | `32343607b853af90094ed477912d575fe2242a6594897b3c8150ac665b5503c5` |
| [`task06b4g/run1/run.log`](task06b4g/run1/run.log) | 06B-4G | Log lần chạy (exit 4) | `8a49e49343aa1bbb6b8cdb8bcaee1e13a1a0d80fac530013ddc73af810c10603` |
| [`task06b4g/run1/container/probe/ARM/icmp-eval.json`](task06b4g/run1/container/probe/ARM/icmp-eval.json) | 06B-4G | Đánh giá 5 ca ARM | `93641b6232c5809bdfec1677b8f60c7f3701e1eb5e1bbeb1b095b4a8852dd078` |
| [`task06b4g/run1/container/probe/MIPS/icmp-eval.json`](task06b4g/run1/container/probe/MIPS/icmp-eval.json) | 06B-4G | Đánh giá 5 ca MIPS | `b0858052b381aaf4ab3f468ae677aa146865f0ce7967422eb4e503cdc07677b9` |
| [`task06b4g/run1/container/probe/ARM/tap0.pcapng`](task06b4g/run1/container/probe/ARM/tap0.pcapng) | 06B-4G | Capture `tap0` ARM (78 khung) | `920066756cd1b2dd620c84004740942dc58163907f90b79a2a0f23e569ce1777` |
| [`task06b4g/run1/container/probe/MIPS/tap0.pcapng`](task06b4g/run1/container/probe/MIPS/tap0.pcapng) | 06B-4G | Capture `tap0` MIPS (115 khung) | `72b877eec947d8eedec2d2db4c2482924785739f17ab67aaa0f4b9f1272912b4` |
| [`task06b4g/crosscheck.txt`](task06b4g/crosscheck.txt) | 06B-4G | Kiểm chéo độc lập: 10/10 ca khớp | `3f9a68471d3136ce7b3d33ad1b3c2fc85deeb664a4fcbb0b4a328e91d29512e0` |
| [`task06b4g/SHA256SUMS`](task06b4g/SHA256SUMS) | 06B-4G | Hash mọi file trong `task06b4g/` | `4bec69a1474d8ea8b4190f5411b51de493b24891ce02603c41496f2a20d2cbf3` |
| [`task06b4h-summary.md`](task06b4h-summary.md) | 06B-4H | Đính chính hồ sơ 06B-4G; **offline:** chuẩn bị T14 A1/A2/A3, T15 S1 (`arp_cases.py`), chưa nối run script | — |
| [`task06b4h/ct01-06b4h-harness-vs-06b4fr.diff`](task06b4h/ct01-06b4h-harness-vs-06b4fr.diff) | 06B-4H | Diff harness so với 06B-4FR (3 file mới) | `962e0f5b4070c553b06431f41d0c9a8fdc57b66e4bd2378dc038a20742d36313` |
| [`task06b4h/prepared-cases.txt`](task06b4h/prepared-cases.txt) | 06B-4H | Lệnh guest của 4 ca (ARM `eth1`, MIPS `br-lan`) | `47662187f62158a806c5e209db1ef6e57a72525a5273084e9b1dbca9e0438bcc` |
| [`task06b4h/logs/selftest-arp.log`](task06b4h/logs/selftest-arp.log) | 06B-4H | Self-test ARP 90/90 | `103ac7fa9810ac907bd1493d8f33665e5573ceb806045b5d9424413599b63c3a` |
| [`task06b4h/logs/mutation-arp.txt`](task06b4h/logs/mutation-arp.txt) | 06B-4H | Mutation ARP 29/29 + 2 đối chứng | `d05390fb84205128c486c1cad7d7a0769a14a35a78bd27eaa718213069180c67` |
| [`task06b4h/crosscheck-06b4g-v2.txt`](task06b4h/crosscheck-06b4g-v2.txt) | 06B-4H | Cross-check 06B-4G chạy lại với `zone()` đúng định nghĩa: số đếm giống hệt | `fb36bbc4ed83341cb0e502084955c6c3693625545516acf6cc3e980e3f402433` |
| [`task06b4h/SHA256SUMS`](task06b4h/SHA256SUMS) | 06B-4H | Hash mọi file trong `task06b4h/` | `77b83defc543c09389cc5f3547bb5338e73a7242bd2b96602d628a7b3baafd4b` |
| [`task06b4hr-summary.md`](task06b4hr-summary.md) | 06B-4HR | **Offline:** sửa 5 lỗi Codex trong T14/T15 (opcode S1, neighbor, giao kèo hồ sơ, rc ping, FAIL thắng lỗi đo); chưa nối tích hợp | — |
| [`task06b4hr/ct01-06b4hr-harness-vs-06b4h.diff`](task06b4hr/ct01-06b4hr-harness-vs-06b4h.diff) | 06B-4HR | Diff harness so với 06B-4H (3 file) | `f8225daf30ff2f7df0594803895f6b9a356aa2619527f472f64adca2cbb745c0` |
| [`task06b4hr/codex-reproductions-before-after.txt`](task06b4hr/codex-reproductions-before-after.txt) | 06B-4HR | Script Codex chạy lại trên 4H/4HR: trước/sau | `d95083a36a1a150fffd1b8cc06b9a2bf80c86c06dab367804cdf779fe430918b` |
| [`task06b4hr/logs/selftest-arp.log`](task06b4hr/logs/selftest-arp.log) | 06B-4HR | Self-test ARP 146/146 | `0d2df4a72bdefc73844ac31bc7ce557dbd8a0ac541c001b2cdb7d908cb81f551` |
| [`task06b4hr/logs/selftest-arp-new-tests-on-06b4h-code.log`](task06b4hr/logs/selftest-arp-new-tests-on-06b4h-code.log) | 06B-4HR | Test mới trên mã 4H: 47 test F hỏng | `e9ee778e1c8eb722dac4d9d06b27f5c1e862bbe967da9b0c5e8e1076701cc32e` |
| [`task06b4hr/logs/mutation-arp.txt`](task06b4hr/logs/mutation-arp.txt) | 06B-4HR | Mutation ARP 48/48 + 2 đối chứng | `8c3c67de95f7254eafe3d7d2b003995899b0220e7b77c735e781e1e454ca5b39` |
| [`task06b4hr/SHA256SUMS`](task06b4hr/SHA256SUMS) | 06B-4HR | Hash mọi file trong `task06b4hr/` | `063873ec108dfd4003626215f4e478d3b8b7bc8c8850c730ac3435773714163d` |
| [`task06b4hr1-summary.md`](task06b4hr1-summary.md) | 06B-4HR1 | **Offline:** sửa HR1–HR5 (baseline/restore, binding bắt buộc, nhánh chưa bắt đầu, hàng neighbor hỏng, callback đối chứng); chưa nối tích hợp | — |
| [`task06b4hr1/ct01-06b4hr1-harness-vs-06b4hr.diff`](task06b4hr1/ct01-06b4hr1-harness-vs-06b4hr.diff) | 06B-4HR1 | Diff harness so với 06B-4HR (3 file) | `2c5577ef9c425568b40a32e6b9c35bace966680f2711d701f94479f44fdcb78c` |
| [`task06b4hr1/codex-reproductions-before-after.txt`](task06b4hr1/codex-reproductions-before-after.txt) | 06B-4HR1 | 4 script Codex chạy lại trên 4HR/4HR1: trước/sau | `687cba300566be6defa94c5587c204d5edd8caf7c67101d53cf080651f148417` |
| [`task06b4hr1/logs/selftest-arp.log`](task06b4hr1/logs/selftest-arp.log) | 06B-4HR1 | Self-test ARP 212/212 | `f0b621ad961d6c2f73130b9b5ef13c5dc8a25c2cc5179d80084a9178ce56a952` |
| [`task06b4hr1/logs/selftest-arp-new-tests-on-06b4hr-code.log`](task06b4hr1/logs/selftest-arp-new-tests-on-06b4hr-code.log) | 06B-4HR1 | Test mới trên mã 4HR: 51/66 test H hỏng | `20bc0477883c98e654fa80dc13c4df586e16e6c5e92f207d933394377bd33171` |
| [`task06b4hr1/logs/mutation-arp.txt`](task06b4hr1/logs/mutation-arp.txt) | 06B-4HR1 | Mutation ARP 71/71 + 2 đối chứng | `8185258c92e5db86e00768d0a7bd47ed5fe45fe0eff762e1771b273fb0f9f701` |
| [`task06b4hr1/SHA256SUMS`](task06b4hr1/SHA256SUMS) | 06B-4HR1 | Hash mọi file trong `task06b4hr1/` | `f80873525975f049ffef83aa20803f3023f6fbdea872f02e599e2c160c520176` |
| [`task06b4hr2-summary.md`](task06b4hr2-summary.md) | 06B-4HR2 | **Offline:** sửa R1 (neighbor `neigh_dynamic` mang cờ PERMANENT, khóa ở hai nhóm) trong baseline và `restore.after`; chưa nối tích hợp | — |
| [`task06b4hr2/ct01-06b4hr2-harness-vs-06b4hr1.diff`](task06b4hr2/ct01-06b4hr2-harness-vs-06b4hr1.diff) | 06B-4HR2 | Diff harness so với 06B-4HR1 (3 file) | `375660c3dd94f6a50ef30022b0f92d7b4e944f1a72b1ed7a2ec4d77320e6dae6` |
| [`task06b4hr2/codex-reproductions-before-after.txt`](task06b4hr2/codex-reproductions-before-after.txt) | 06B-4HR2 | Script Codex chạy lại trên 4HR1/4HR2 (R1: exit 0 → 2) | `4a591a27c6e4b0141b653359df5515cbc6c3d0cf0b524835c1076206878231e8` |
| [`task06b4hr2/logs/selftest-arp.log`](task06b4hr2/logs/selftest-arp.log) | 06B-4HR2 | Self-test ARP 224/224 | `b71e62d58306e4b277a2e4984e2ae44bd2c5ef68f2b0876079fbae9accfa3301` |
| [`task06b4hr2/logs/mutation-arp.txt`](task06b4hr2/logs/mutation-arp.txt) | 06B-4HR2 | Mutation ARP 75/75 + 2 đối chứng | `d9a62b90196ababda9e8dfb9829a69568967c1b5b0d2ec52e7fde68e09b8ac12` |
| [`task06b4hr2/SHA256SUMS`](task06b4hr2/SHA256SUMS) | 06B-4HR2 | Hash mọi file trong `task06b4hr2/` | `73951341777a119b7332b3b3fad6ebbd6417ca95f40670b794a1dfd4d081d13a` |
| [`task06b4i-summary.md`](task06b4i-summary.md) | 06B-4I | **Offline:** nối ARP (T14 A1/A2/A3, T15 S1) vào harness: `arp_harness.py`, nhánh `CT01_SUITE=arp`, collector `ip -j neigh show` trong netns worker, đối chứng sống A1/A2, `run-06b4i.sh` (chưa chạy); chưa chạy guest | — |
| [`task06b4i/ct01-06b4i-harness-vs-06b4hr2.diff`](task06b4i/ct01-06b4i-harness-vs-06b4hr2.diff) | 06B-4I | Diff harness so với 06B-4HR2 (6 file) | `802ac054ddc188841a7288bd81cdb6bf5dd14c3d7627768d4086b2f288490222` |
| [`task06b4i/harness-sha256.txt`](task06b4i/harness-sha256.txt) | 06B-4I | Hash 35 file của `ct01-06b4i` | `c07f18ae6ee760f9639da12c2d55448c274539832e8c549d8993f858dff93e9a` |
| [`task06b4i/logs/selftest-arp-wiring.log`](task06b4i/logs/selftest-arp-wiring.log) | 06B-4I | Self-test phần nối 116/116 (`probe_matrix.main()` thật, stub) | `2e3cb0eed2dafb6490ce6f4e2fd2fb29c35d578b2ded68bf9ae272612ed0c90e` |
| [`task06b4i/logs/mutation-arp-wiring.txt`](task06b4i/logs/mutation-arp-wiring.txt) | 06B-4I | Mutation phần nối 37/37 + 2 đối chứng | `79ac3c86105dba0f5f1e782027901e3d49c533dab4c70cdef7d6c54bfcc34df1` |
| [`task06b4i/fixtures/fixtures-summary.json`](task06b4i/fixtures/fixtures-summary.json) | 06B-4I | Fixture 10 kịch bản nối (mô phỏng) | `1abf7997920d23811a9a6a1be99b7496bd660baa90689cc30aec14a1f2ac7267` |
| [`task06b4i/SHA256SUMS`](task06b4i/SHA256SUMS) | 06B-4I | Hash mọi file trong `task06b4i/` | `229df5759d56dbacc81540371dbc8ce2f4f812e3e50c501e72e4bfaa9b0a7746` |
| [`task06b4ir1-summary.md`](task06b4ir1-summary.md) | 06B-4IR1 | **Offline:** sửa I1 (guard khởi động/topology, mọi suite), I2 (interface ctl theo MAC endpoint `sandboxnet`), I3 (schema/payload/trùng của log ctl); chưa chạy guest | — |
| [`task06b4ir1/ct01-06b4ir1-harness-vs-06b4i.diff`](task06b4ir1/ct01-06b4ir1-harness-vs-06b4i.diff) | 06B-4IR1 | Diff harness so với 06B-4I (6 file) | `9964b1a4d398c289f798b2a191ccc05575d42f6db1b4a651d974077e297d7497` |
| [`task06b4ir1/harness-sha256.txt`](task06b4ir1/harness-sha256.txt) | 06B-4IR1 | Hash 35 file của `ct01-06b4ir1` | `33d522f062be9545a68ef3b92f4bb039c5d0402c1fc608c80808ed876ac844d9` |
| [`task06b4ir1/logs/selftest-arp-wiring.log`](task06b4ir1/logs/selftest-arp-wiring.log) | 06B-4IR1 | Self-test phần nối 159/159 | `7a4cad62cd220c3039ca936488812da9ee12b92512531dbe4478e52b27465eb4` |
| [`task06b4ir1/logs/mutation-arp-wiring.txt`](task06b4ir1/logs/mutation-arp-wiring.txt) | 06B-4IR1 | Mutation phần nối 60/60 + 2 đối chứng | `8d9248f7411787189be884d1b571f138ed432df35013f59f36fee3dea39f6d67` |
| [`task06b4ir1/logs/codex-repro-variant-fixed-before-after.txt`](task06b4ir1/logs/codex-repro-variant-fixed-before-after.txt) | 06B-4IR1 | Fixture I2/I3 của Codex áp đúng biến thể: 4I PASS → 4IR1 UNVERIFIED | `94926031366dc47b93d3d45bee0ea2f08ba2b152f575d65ae29c8f0011e25f05` |
| [`task06b4ir1/SHA256SUMS`](task06b4ir1/SHA256SUMS) | 06B-4IR1 | Hash mọi file trong `task06b4ir1/` | `5197b2e90052d3f3f914db346dd8841ee29d06256b72faa7016e718f35c2acd1` |
| [`task06b4ir2-summary.md`](task06b4ir2-summary.md) | 06B-4IR2 | **Offline:** sửa IR1-R1 (handoff guard sang nhánh IPv4/ICMP/ARP) và IR1-R2 (MAC endpoint toàn 0/nhóm bị từ chối); chưa chạy guest | — |
| [`task06b4ir2/ct01-06b4ir2-harness-vs-06b4ir1.diff`](task06b4ir2/ct01-06b4ir2-harness-vs-06b4ir1.diff) | 06B-4IR2 | Diff harness so với 06B-4IR1 (5 file) | `46082f6cca49be952fa089fce30d80026df4ad82c5b10d8d30b87e9d4824c69e` |
| [`task06b4ir2/harness-sha256.txt`](task06b4ir2/harness-sha256.txt) | 06B-4IR2 | Hash 35 file của `ct01-06b4ir2` | `e50a67abdcd066dacf30a48c27c2d6cf5d2ffd78fe11eb973b5b58945750f32f` |
| [`task06b4ir2/logs/selftest-arp-wiring.log`](task06b4ir2/logs/selftest-arp-wiring.log) | 06B-4IR2 | Self-test phần nối 182/182 | `e10f2d028f66702a037fb3d23395eacfcd1482cc4584b8563b3893015dbb56af` |
| [`task06b4ir2/logs/mutation-arp-wiring.txt`](task06b4ir2/logs/mutation-arp-wiring.txt) | 06B-4IR2 | Mutation phần nối 67/67 + 2 đối chứng | `b520875b30d9488d06773cde2fcbe557f8433b7c88cd0884e69218f99b8a694e` |
| [`task06b4ir2/logs/codex-targeted-after-4IR2.txt`](task06b4ir2/logs/codex-targeted-after-4IR2.txt) | 06B-4IR2 | `targeted.py` của Codex trên 4IR2 (`ipv4-handoff` 0 lệnh sau sự cố; `cfg-zero-mac` UNVERIFIED) | `55f14b268097507de7bb18a8ebb51dfe11db3f0902d159100bee8ad6c8683ec3` |
| [`task06b4ir2/SHA256SUMS`](task06b4ir2/SHA256SUMS) | 06B-4IR2 | Hash mọi file trong `task06b4ir2/` | `f25802d57fd7ad7daed7e5c2bfa519498dc0a42a2459aeb023d2d8a66c555bfd` |
| [`task06b4ir2-precheck-summary.md`](task06b4ir2-precheck-summary.md) | precheck 06B-4IR2 | **Chỉ đọc, không sudo:** manifest, run script tĩnh, host khớp 06B-4G; mục Docker chưa kiểm (không có quyền); parser offline trên mẫu host; rủi ro R-MIPS | — |
| [`task06b4ir2-precheck/parsed/offline-parsers.json`](task06b4ir2-precheck/parsed/offline-parsers.json) | precheck 06B-4IR2 | Kết quả parser hiện có trên mẫu host và evidence 06B-4G | `ed43aab17f0a896733675ddf99c022221f4ccfaf5552357656e3cfd1d0b989a3` |
| [`task06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh`](task06b4ir2-precheck/precheck-06b4ir2-docker-readonly.sh) | precheck 06B-4IR2 | Script Docker chỉ đọc soạn sẵn, **chưa chạy** | `7c86f9ae41dbc64f2fc7fa9c55727003783ea0a306282e04eba3437973f04769` |
| [`task06b4ir2-precheck/SHA256SUMS`](task06b4ir2-precheck/SHA256SUMS) | precheck 06B-4IR2 | Hash mọi file trong `task06b4ir2-precheck/` | `54a5cd85e1b13ec6a617ce5c88a556071d3640f5cda3ef67c07afb21977df19d` |
| [`task06b4ir3-summary.md`](task06b4ir3-summary.md) | 06B-4IR3 | **Offline:** sửa PC-1 (dừng giữa kiến trúc), PC-2 (collector/evaluator precheck), PC-3 (admin link state trong `guest_state`), PC-4 (quy trình root); chưa chạy root/guest | — |
| [`task06b4ir3/ct01-06b4ir3-harness-vs-06b4ir2.diff`](task06b4ir3/ct01-06b4ir3-harness-vs-06b4ir2.diff) | 06B-4IR3 | Diff harness so với 06B-4IR2 (9 file) | `699dc2aaf7c87817ef567771de8f020a61fe1c586a59f33eb28e93bd1afddc02` |
| [`task06b4ir3/harness-sha256.txt`](task06b4ir3/harness-sha256.txt) | 06B-4IR3 | Hash 35 file của `ct01-06b4ir3` | `e244249df23dd66abd5988dda05e033ab8b35544c6640d88cc21c18a1a10e2d0` |
| [`task06b4ir3/SHA256SUMS`](task06b4ir3/SHA256SUMS) | 06B-4IR3 | Hash mọi file trong `task06b4ir3/` | `9643b220bc7a842df83f5b6237abdfefb425bfc07952c06703cbadafdbd9d9ef` |
| [`task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt`](task06b4ir3-precheck-scripts/precheck-scripts-sha256.txt) | 06B-4IR3 | Manifest script precheck mới (collector `6604fbda18cb26f5…`) | `b160afd22c8908e06165d5fed41059f58400f145fedb7925f05ea119a5b82fee` |
| [`task06b4ir3-precheck-scripts/SHA256SUMS`](task06b4ir3-precheck-scripts/SHA256SUMS) | 06B-4IR3 | Hash mọi file trong `task06b4ir3-precheck-scripts/` | `b245774aca8071e997e12988da446d2b899c3f382cac9507ecec6af923513f9c` |
