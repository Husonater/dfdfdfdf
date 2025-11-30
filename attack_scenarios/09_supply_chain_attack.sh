#!/bin/bash
# KOMPLEXER ANGRIFF 1: Supply Chain Attack
# Simuliert einen Angriff über kompromittierte Software-Updates

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     🔴 SUPPLY CHAIN ATTACK - Kompromittierte Updates 🔴       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
ATTACKER_IP="172.20.20.2"
MALICIOUS_REPO="malicious-updates.com"

echo "[PHASE 1] Kompromittiertes Repository Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # DNS Queries zu verdächtigem Repository
    for i in {1..5}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: query: updates.$MALICIOUS_REPO IN A\" >> /var/log/syslog
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: query: packages.$MALICIOUS_REPO IN A\" >> /var/log/syslog
    done
    
    # APT/YUM versucht Updates zu laden
    mkdir -p /var/log/apt
    echo \"$(date '+%Y-%m-%d %H:%M:%S') WARNING: Repository '$MALICIOUS_REPO' is not signed\" >> /var/log/apt/term.log
    echo \"$(date '+%Y-%m-%d %H:%M:%S') ERROR: GPG key verification failed for $MALICIOUS_REPO\" >> /var/log/apt/term.log
"
echo "  ✓ Verdächtige Repository-Zugriffe erkannt"
sleep 2

echo ""
echo "[PHASE 2] Trojanisiertes Paket Download"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Download von verdächtigem Paket
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wget: Downloading from http://$MALICIOUS_REPO/packages/nodejs-update.deb\" >> /var/log/syslog
    
    # Erstelle trojanisiertes Paket
    touch /tmp/nodejs-update.deb
    touch /tmp/python3-backdoor.deb
    
    echo \"$(date '+%Y-%m-%d %H:%M:%S') Downloaded package: nodejs-update.deb (15.2 MB)\" >> /var/log/dpkg.log
    echo \"$(date '+%Y-%m-%d %H:%M:%S') WARNING: Package signature mismatch\" >> /var/log/dpkg.log
"
echo "  ✓ Trojanisierte Pakete heruntergeladen"
sleep 2

echo ""
echo "[PHASE 3] Paket Installation mit Backdoor"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Installation des kompromittierten Pakets
    echo \"$(date '+%Y-%m-%d %H:%M:%S') status installed nodejs-update:amd64 18.0.0-backdoor\" >> /var/log/dpkg.log
    
    # Post-Install Script führt Backdoor aus
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager systemd: Started nodejs-update-service.service\" >> /var/log/syslog
    
    # Backdoor erstellt Reverse Shell
    touch /usr/lib/nodejs/.hidden_shell
    touch /etc/systemd/system/update-checker.service
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec-rootcheck: Suspicious file: /usr/lib/nodejs/.hidden_shell\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec-rootcheck: Hidden process detected: update-checker\" >> /var/log/syslog
"
echo "  ⚠️  Backdoor installiert und aktiv!"
sleep 2

echo ""
echo "[PHASE 4] C2 Beacon über DNS Tunneling"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # DNS Tunneling für C2 Kommunikation
    for i in {1..15}; do
        beacon=\$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 48)
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: query: \$beacon.c2.$MALICIOUS_REPO IN TXT\" >> /var/log/syslog
        sleep 0.1
    done
    
    # Ungewöhnlich lange DNS Queries
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: WARNING: Unusually long DNS query (256 bytes)\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: Suspicious TXT record query pattern detected\" >> /var/log/syslog
"
echo "  ✓ C2 Kommunikation über DNS etabliert"
sleep 2

echo ""
echo "[PHASE 5] Zweite Stufe - Payload Download"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Download zusätzlicher Malware
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager curl: Downloading from https://cdn.$MALICIOUS_REPO/stage2.bin\" >> /var/log/syslog
    
    touch /tmp/.stage2_payload
    chmod +x /tmp/.stage2_payload
    
    # Crypto-Miner Installation
    touch /tmp/xmrig
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: High CPU usage detected: xmrig (98%)\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Cryptocurrency mining detected\" >> /var/log/syslog
"
echo "  ⚠️  Crypto-Miner deployed!"
sleep 2

echo ""
echo "[PHASE 6] Persistenz über Systemd"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Systemd Service für Persistenz
    cat > /tmp/malicious.service << 'EOF'
[Unit]
Description=System Update Checker
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.stage2_payload
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager systemd: New service installed: malicious.service\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager systemd: Enabled malicious.service\" >> /var/log/syslog
"
echo "  ✓ Persistenz etabliert"
sleep 2

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "⚠️  SUPPLY CHAIN ATTACK ABGESCHLOSSEN"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Erkannte Indikatoren:"
echo "  • Kompromittiertes Repository"
echo "  • Unsignierte Pakete"
echo "  • Backdoor Installation"
echo "  • DNS Tunneling C2"
echo "  • Crypto-Mining"
echo "  • Systemd Persistenz"
echo ""
