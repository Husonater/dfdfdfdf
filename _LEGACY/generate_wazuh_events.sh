#!/bin/bash
# Generiert Test-Alerts direkt in Wazuh durch Schreiben in überwachte Log-Dateien

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║    Generiere Wazuh Security Events (Verbesserte Version)      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"

# Funktion zum Hinzufügen von syslog Monitoring
configure_wazuh_syslog() {
    echo "[*] Konfiguriere Wazuh zum Lesen von Syslog..."
    
    echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
        # Backup der Konfiguration
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
        
        # Füge syslog monitoring hinzu (falls nicht vorhanden)
        if ! grep -q "/var/log/syslog" /var/ossec/etc/ossec.conf; then
            sed -i "/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>" /var/ossec/etc/ossec.conf
            
            echo "  [✓] Syslog Monitoring hinzugefügt"
            
            # Restart Wazuh
            /var/ossec/bin/wazuh-control restart
            sleep 5
        else
            echo "  [*] Syslog Monitoring bereits konfiguriert"
        fi
    '
}

# Konfiguriere zuerst Wazuh
configure_wazuh_syslog

echo ""
echo "[+] Generiere Security Events..."
echo ""

# SSH Brute Force
echo "[1/7] SSH Brute Force..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    for i in {1..10}; do
        echo "$(date "+%b %d %H:%M:%S") wazuh-manager sshd[12345]: Failed password for invalid user admin from 172.20.20.2 port 52341 ssh2" >> /var/log/auth.log
    done
    for i in {1..5}; do
        echo "$(date "+%b %d %H:%M:%S") wazuh-manager sshd[12346]: Failed password for root from 172.20.20.2 port 52342 ssh2" >> /var/log/auth.log
    done
'
echo "  ✓ Generiert"

sleep 2

# Web Attacks
echo "[2/7] Web Attacks..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    mkdir -p /var/log/apache2
    echo "172.20.20.2 - - [$(date "+%d/%b/%Y:%H:%M:%S %z")] \"GET /login.php?user=admin%27%20OR%20%271%27=%271 HTTP/1.1\" 403 512 \"-\" \"Mozilla/5.0\"" >> /var/log/apache2/access.log
    echo "172.20.20.2 - - [$(date "+%d/%b/%Y:%H:%M:%S %z")] \"GET /search.php?q=<script>alert(XSS)</script> HTTP/1.1\" 403 512 \"-\" \"Mozilla/5.0\"" >> /var/log/apache2/access.log
    echo "172.20.20.2 - - [$(date "+%d/%b/%Y:%H:%M:%S %z")] \"GET /download.php?file=../../../../etc/passwd HTTP/1.1\" 403 512 \"-\" \"Mozilla/5.0\"" >> /var/log/apache2/access.log
'
echo "  ✓ Generiert"

sleep 2

# Sudo Abuse
echo "[3/7] Privilege Escalation..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    for i in {1..5}; do
        echo "$(date "+%b %d %H:%M:%S") wazuh-manager sudo: hacker : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash" >> /var/log/auth.log
    done
'
echo "  ✓ Generiert"

sleep 2

# File Integrity
echo "[4/7] File Integrity Violations..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    # Trigger syscheck
    touch /etc/passwd
    echo "test" >> /tmp/suspicious_file
'
echo "  ✓ Generiert"

sleep 2

# Rootkit Detection
echo "[5/7] Rootkit/Malware Detection..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    echo "$(date "+%b %d %H:%M:%S") wazuh-manager ossec-rootcheck: File /tmp/malware.sh is a possible trojan or rootkit." >> /var/log/syslog
    echo "$(date "+%b %d %H:%M:%S") wazuh-manager ossec-rootcheck: Suspicious file found: /tmp/.hidden_backdoor" >> /var/log/syslog
'
echo "  ✓ Generiert"

sleep 2

# Port Scan
echo "[6/7] Port Scan Detection..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    for port in 22 23 80 443 3306 5432 8080 8443; do
        echo "$(date "+%b %d %H:%M:%S") wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=172.20.20.2 DST=172.20.20.5 PROTO=TCP SPT=54321 DPT=$port" >> /var/log/syslog
    done
'
echo "  ✓ Generiert"

sleep 2

# Multiple Failed Logins
echo "[7/7] Multiple Failed Logins..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    for user in admin root oracle postgres mysql; do
        echo "$(date "+%b %d %H:%M:%S") wazuh-manager sshd[12347]: Failed password for $user from 172.20.20.2 port 52343 ssh2" >> /var/log/auth.log
    done
'
echo "  ✓ Generiert"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✓ Alle Events generiert!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Warte 10 Sekunden auf Wazuh-Verarbeitung..."
sleep 10

echo ""
echo "[+] Aktuelle Alerts (letzte 20):"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager tail -40 /var/ossec/logs/alerts/alerts.log | grep -E "Rule:|Alert" | tail -20

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "📊 WAZUH DASHBOARD ÖFFNEN:"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "URL:      https://localhost:8443"
echo "Username: admin"
echo "Password: SecretPassword123!"
echo ""
echo "Navigation:"
echo "  1. Klicke auf das Hamburger-Menü (☰) oben links"
echo "  2. Wähle 'Security events' oder 'Threat Hunting'"
echo "  3. Filtere nach: timestamp:>=now-5m"
echo ""
echo "Wichtige Filter:"
echo "  • rule.level:>=7           (Kritische Events)"
echo "  • rule.groups:authentication_failed"
echo "  • rule.groups:web"
echo "  • data.srcip:172.20.20.2"
echo ""
