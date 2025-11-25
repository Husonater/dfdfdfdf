#!/bin/bash

echo "--- IDS STARTUP ---"

# 1. Logs vorbereiten
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true

# 2. Suricata starten
echo "Starting Suricata Engine..."

# -k none: WICHTIG für Mirroring (ignoriert Checksummen-Fehler)
# -D: Daemon Mode (Hintergrund)
# eth1: Das Interface im neuen 61er Netz
suricata -i eth1 -k none --set output.syslog.enabled=yes --set output.syslog.address=192.168.35.10 --set output.syslog.port=514 -D

echo "✅ IDS started successfully."