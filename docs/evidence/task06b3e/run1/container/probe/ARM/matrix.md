| probe | dst | probe pkts | expected counter = delta | pcap certain (same class) | reconciliation (all classes) | verdict |
|---|---|---|---|---|---|---|
| internet-tcp | tcp 1.1.1.1:443 | 3 | drop_public=7 | 7 | PASS | ĐẠT |
| lan-dns-udp | udp 192.168.177.2:53 | 4 | drop_private=4 | 4 | PASS | ĐẠT |
| lan-dns-tcp | tcp 192.168.177.2:53 | 3 | drop_private=3 | 3 | PASS | ĐẠT |
| ssh-host-192.168.60.1 | tcp 192.168.60.1:22 | 3 | drop_private=3 | 3 | PASS | ĐẠT |
| ssh-host-192.168.177.128 | tcp 192.168.177.128:22 | 3 | drop_private=3 | 3 | PASS | ĐẠT |
| ssh-host-172.18.0.1 | tcp 172.18.0.1:22 | 3 | drop_private=3 | 3 | UNVERIFIED | CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm) |
| manager | tcp 192.168.60.10:8011 | 3 | drop_private=3 | 3 | UNVERIFIED | CHƯA KIỂM CHỨNG (gói ở biên cửa sổ bộ đếm) |
| mongodb | tcp 172.18.0.2:27017 | 3 | drop_private=3 | 3 | PASS | ĐẠT |
| worker-eth0 | tcp 192.168.60.2:8011 | 3 | drop_private=3 | 3 | PASS | ĐẠT |
| tap0-other-port-listener | tcp 10.200.0.1:18080 | 3 | drop_worker_other=3 | 3 | PASS | ĐẠT |
