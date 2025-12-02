#!/bin/bash
echo "Starting tcpdump on Webserver..."
sudo docker exec clab-dmz-project-sun-webserver tcpdump -i eth1 -n -c 20 > /tmp/webserver_dump.txt 2>&1 &
TCPDUMP_PID=$!

sleep 2

echo "Running curl from WAF (Attack)..."
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf curl -v "http://192.168.60.20/cmd.exe"

echo "Waiting for tcpdump..."
sleep 5
kill $TCPDUMP_PID 2>/dev/null

echo "Tcpdump output:"
cat /tmp/webserver_dump.txt
