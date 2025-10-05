#!/bin/bash
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
echo "Suricata IDS started on eth1 and logging to 192.168.30.10:514."
tail -f /var/log/suricata/fast.log
