#!/bin/bash
# FIX: Wait for the eth1 interface to be created by Containerlab
echo "Waiting for interface eth1 to appear..."
while ! ip link show eth1 > /dev/null 2>&1; do
    sleep 1
done
echo "Interface eth1 found. Starting Suricata."
# Original command
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
echo "Suricata IDS started on eth1 and logging to 192.168.30.10:514."
tail -f /var/log/suricata/fast.log