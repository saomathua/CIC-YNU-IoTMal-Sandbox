| probe | dst | probe pkts | expected counter = delta | pcap (same class) | verdict |
|---|---|---|---|---|---|
| internet-tcp | tcp 1.1.1.1:443 | 4 | drop_public=8 | 8 | FAIL |
| lan-dns-udp | udp 192.168.177.2:53 | 4 | drop_private=4 | 4 | ĐẠT |
| lan-dns-tcp | tcp 192.168.177.2:53 | 4 | drop_private=4 | 4 | ĐẠT |
| ssh-host-192.168.60.1 | tcp 192.168.60.1:22 | 4 | drop_private=4 | 4 | ĐẠT |
| ssh-host-192.168.177.128 | tcp 192.168.177.128:22 | 4 | drop_private=4 | 4 | ĐẠT |
| ssh-host-172.18.0.1 | tcp 172.18.0.1:22 | 4 | drop_private=4 | 4 | ĐẠT |
| manager | tcp 192.168.60.10:8011 | 4 | drop_private=4 | 4 | ĐẠT |
| mongodb | tcp 172.18.0.2:27017 | 4 | drop_private=4 | 4 | ĐẠT |
| worker-eth0 | tcp 192.168.60.2:8011 | 4 | drop_private=4 | 4 | ĐẠT |
| tap0-other-port-listener | tcp 10.200.0.1:18080 | 4 | drop_worker_other=4 | 4 | ĐẠT |
