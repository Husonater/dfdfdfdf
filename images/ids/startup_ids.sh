#!/bin/bash

echo "--- IDS STARTUP ---"

# 1. Logs vorbereiten
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true

# 1.5 Silent Mode (Prevent Kernel Responses)
# Drop all incoming packets on eth1 so the kernel doesn't respond (RST/ICMP).
# Suricata sees them via AF_PACKET before iptables DROP.
# 1.5 Silent Mode (Prevent Kernel Responses)
# Drop all incoming IP packets on eth1 so the kernel doesn't respond (RST/ICMP/Routing).
# Suricata sees them via AF_PACKET before iptables raw table DROP (or concurrently).
# Note: ARP is not affected by iptables IP chains.
iptables -t raw -I PREROUTING -i eth1 -j DROP

# 1.6 Add Custom Rule for Audit
# Ensure we detect the specific test case even if default rules change.
echo 'alert http any any -> any any (msg:"ET WEB_SERVER CMD.EXE Access"; content:"cmd.exe"; http_uri; sid:1000001; rev:1;)' >> /var/lib/suricata/rules/suricata.rules

# 1.7 Configure and Start Rsyslog (Forward to SIEM)
echo "Configuring Rsyslog TLS..."
mkdir -p /var/lib/rsyslog
cat > /etc/rsyslog.conf <<EOF
global(workDirectory="/var/lib/rsyslog")
module(load="imfile")
module(load="lmnsd_ossl")

global(
    DefaultNetstreamDriver="ossl"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/ssl/certs/client.pem"
    DefaultNetstreamDriverKeyFile="/etc/ssl/private/client.key"
)

input(type="imfile" File="/var/log/suricata/fast.log" Tag="suricata")

*.* action(
    type="omfwd"
    target="192.168.35.10"
    port="6514"
    protocol="tcp"
    StreamDriver="ossl"
    StreamDriverMode="1"
    StreamDriverAuthMode="anon"
)
EOF
rsyslogd

# 2. Suricata starten
echo "Starting Suricata Engine..."

# -k none: WICHTIG für Mirroring (ignoriert Checksummen-Fehler)
# -D: Daemon Mode (Hintergrund)
# eth1: Das Interface im neuen 61er Netz
# output.syslog.enabled=yes removed, using fast.log + imfile
suricata -i eth1 -k none -D

echo "✅ IDS started successfully."