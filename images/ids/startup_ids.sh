#!/bin/bash
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
