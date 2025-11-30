#!/bin/bash
# Angriffsszenario 2: Port Scanning
# Simuliert einen Nmap-Port-Scan

echo "=== Port Scanning Angriff Szenario ==="
echo "Dieser Angriff simuliert einen Nmap-Port-Scan"
echo ""

TARGET_HOST="${1:-webserver}"
ATTACKER="${2:-attacker-internet}"

echo "[+] Starte Port Scan von $ATTACKER gegen $TARGET_HOST"

# Installiere nmap falls nicht vorhanden
sudo docker exec clab-dmz-project-sun-$ATTACKER bash -c "
    if ! command -v nmap &> /dev/null; then
        echo '[*] Installiere nmap...'
        apt-get update -qq && apt-get install -y nmap -qq
    fi
"

# Verschiedene Scan-Typen
echo "[*] TCP SYN Scan (Stealth Scan)..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    nmap -sS -p 1-1000 $TARGET_HOST 2>/dev/null || true

sleep 2

echo "[*] TCP Connect Scan..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    nmap -sT -p 1-1000 $TARGET_HOST 2>/dev/null || true

sleep 2

echo "[*] UDP Scan..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    nmap -sU -p 53,67,68,69,123,161,162 $TARGET_HOST 2>/dev/null || true

sleep 2

echo "[*] Aggressive Scan mit OS Detection..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    nmap -A -T4 $TARGET_HOST 2>/dev/null || true

echo ""
echo "[+] Port Scan abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'port scan' oder 'reconnaissance'"
