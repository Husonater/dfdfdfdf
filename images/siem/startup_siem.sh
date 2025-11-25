#!/bin/bash

echo "--- SIEM STARTUP ---"

# 1. Logs vorbereiten
mkdir -p /var/log/siem_logs
touch /var/log/siem_logs/suricata_alerts.log
chmod 666 /var/log/siem_logs/suricata_alerts.log

# 2. Rsyslog starten
echo "Starting Rsyslog..."
rsyslogd

# 3. Container am Leben halten
echo "SIEM is running..."
tail -f /var/log/siem_logs/suricata_alerts.log
