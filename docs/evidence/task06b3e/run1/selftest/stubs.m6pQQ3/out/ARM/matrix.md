| probe | dst | probe pkts | expected counter = delta | pcap certain (same class) | reconciliation (all classes) | verdict |
|---|---|---|---|---|---|---|
| clean | tcp 1.1.1.1:443 | 3 | drop_public=3 | 3 | PASS | ĐẠT |
| ipv6-during-read-a | tcp 1.1.1.1:443 | 3 | drop_public=3 | 3 | UNVERIFIED | CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm) |
