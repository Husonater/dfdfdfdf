#!/bin/bash
# KOMPLEXER ANGRIFF 3: Insider Threat
# Simuliert einen böswilligen Insider mit legitimen Zugriffen

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          🔴 INSIDER THREAT - Böswilliger Mitarbeiter 🔴       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
INSIDER_USER="john.smith"
INSIDER_IP="172.20.20.10"

echo "[PHASE 1] Normale Arbeitsaktivitäten (Tarnung)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Normale SSH Logins während Arbeitszeit
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[12345]: Accepted publickey for $INSIDER_USER from $INSIDER_IP port 54321 ssh2: RSA SHA256:abc123\" >> /var/log/auth.log
    
    # Normale Datei-Zugriffe
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager audit: type=PATH msg=audit: name=\\\"/home/$INSIDER_USER/documents/project.pdf\\\" inode=123456\" >> /var/log/syslog
"
echo "  ✓ Normale Aktivitäten (unauffällig)"
sleep 2

echo ""
echo "[PHASE 2] Ungewöhnliche Zugriffe außerhalb Arbeitszeit"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Login um 2 Uhr nachts
    echo \"\$(date '+%b %d 02:15:33') wazuh-manager sshd[12346]: Accepted publickey for $INSIDER_USER from $INSIDER_IP port 54322 ssh2\" >> /var/log/auth.log
    
    # Zugriff auf sensitive Datenbanken
    echo \"\$(date '+%b %d 02:16:45') wazuh-manager mysql: User $INSIDER_USER connected to database 'customer_data'\" >> /var/log/syslog
    echo \"\$(date '+%b %d 02:17:12') wazuh-manager mysql: Query: SELECT * FROM customers WHERE credit_card IS NOT NULL\" >> /var/log/syslog
    
    # Ungewöhnlich große Datenbank-Dumps
    echo \"\$(date '+%b %d 02:18:30') wazuh-manager mysqldump: Dumping database customer_data (2.5 GB)\" >> /var/log/syslog
"
echo "  ⚠️  Verdächtige Aktivitäten außerhalb Arbeitszeit!"
sleep 2

echo ""
echo "[PHASE 3] Privilegien-Missbrauch"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Sudo-Zugriff für Admin-Aufgaben (legitim)
    echo \"\$(date '+%b %d 02:20:15') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/bin/cat /etc/shadow\" >> /var/log/auth.log
    
    # Zugriff auf andere User-Daten
    echo \"\$(date '+%b %d 02:21:30') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/bin/cat /home/admin/.ssh/id_rsa\" >> /var/log/auth.log
    
    # Firewall-Regeln ändern
    echo \"\$(date '+%b %d 02:22:45') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/sbin/iptables -A INPUT -s $INSIDER_IP -j ACCEPT\" >> /var/log/auth.log
"
echo "  🔴 Privilegien-Missbrauch erkannt!"
sleep 2

echo ""
echo "[PHASE 4] Daten-Exfiltration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Komprimierung sensibler Daten
    echo \"\$(date '+%b %d 02:25:00') wazuh-manager tar: Creating archive /tmp/backup_$(date +%Y%m%d).tar.gz\" >> /var/log/syslog
    echo \"\$(date '+%b %d 02:25:30') wazuh-manager tar: Added 15,234 files (2.8 GB)\" >> /var/log/syslog
    
    # Upload zu privatem Cloud-Storage
    echo \"\$(date '+%b %d 02:26:15') wazuh-manager curl: Uploading to https://personal-dropbox.com/upload\" >> /var/log/syslog
    echo \"\$(date '+%b %d 02:28:45') wazuh-manager curl: Upload complete: 2.8 GB transferred\" >> /var/log/syslog
    
    # Ungewöhnlich hoher Netzwerk-Traffic
    echo \"\$(date '+%b %d 02:29:00') wazuh-manager ossec: High outbound traffic from user $INSIDER_USER: 2.8 GB in 3 minutes\" >> /var/log/syslog
"
echo "  🔴 Massive Datenexfiltration!"
sleep 2

echo ""
echo "[PHASE 5] Spuren verwischen"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Bash History löschen
    echo \"\$(date '+%b %d 02:30:00') wazuh-manager ossec: File /home/$INSIDER_USER/.bash_history deleted\" >> /var/log/syslog
    
    # Log-Dateien manipulieren
    echo \"\$(date '+%b %d 02:30:15') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/bin/sed -i '/02:1/d' /var/log/auth.log\" >> /var/log/auth.log
    
    # Temporäre Dateien löschen
    echo \"\$(date '+%b %d 02:30:30') wazuh-manager rm: removed '/tmp/backup_$(date +%Y%m%d).tar.gz'\" >> /var/log/syslog
    
    # Audit-Logs deaktivieren
    echo \"\$(date '+%b %d 02:30:45') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/sbin/service auditd stop\" >> /var/log/auth.log
    echo \"\$(date '+%b %d 02:30:50') wazuh-manager auditd: Audit daemon stopped by user $INSIDER_USER\" >> /var/log/syslog
"
echo "  ⚠️  Versuch, Spuren zu verwischen!"
sleep 2

echo ""
echo "[PHASE 6] Backdoor für späteren Zugriff"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # SSH Key für externen Zugriff hinzufügen
    echo \"\$(date '+%b %d 02:31:00') wazuh-manager ossec: File /root/.ssh/authorized_keys modified by $INSIDER_USER\" >> /var/log/syslog
    
    # Neuer User-Account erstellen
    echo \"\$(date '+%b %d 02:31:15') wazuh-manager useradd: new user: name=support, UID=1099, GID=1099, home=/home/support, shell=/bin/bash\" >> /var/log/auth.log
    echo \"\$(date '+%b %d 02:31:20') wazuh-manager usermod: add 'support' to group 'sudo'\" >> /var/log/auth.log
    
    # Versteckter Cron Job
    echo \"\$(date '+%b %d 02:31:30') wazuh-manager cron: (root) CMD (/tmp/.hidden_script > /dev/null 2>&1)\" >> /var/log/syslog
"
echo "  🔴 Backdoor für persistenten Zugriff installiert!"
sleep 2

echo ""
echo "[PHASE 7] Sabotage-Aktivitäten"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Kritische Konfigurationsdateien ändern
    echo \"\$(date '+%b %d 02:32:00') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/bin/vi /etc/mysql/my.cnf\" >> /var/log/auth.log
    
    # Backup-System deaktivieren
    echo \"\$(date '+%b %d 02:32:15') wazuh-manager systemd: Stopped backup.service\" >> /var/log/syslog
    echo \"\$(date '+%b %d 02:32:20') wazuh-manager systemd: Disabled backup.timer\" >> /var/log/syslog
    
    # Monitoring-Agents stoppen
    echo \"\$(date '+%b %d 02:32:30') wazuh-manager sudo: $INSIDER_USER : TTY=pts/0 ; PWD=/home/$INSIDER_USER ; USER=root ; COMMAND=/bin/systemctl stop wazuh-agent\" >> /var/log/auth.log
"
echo "  🔴 Sabotage-Aktivitäten durchgeführt!"
sleep 2

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "🔴 INSIDER THREAT ABGESCHLOSSEN"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Verdächtige Verhaltensweisen:"
echo "  • Zugriff außerhalb Arbeitszeit (02:00 Uhr)"
echo "  • Massive Datenbank-Dumps (2.5 GB)"
echo "  • Privilegien-Missbrauch (sudo für /etc/shadow)"
echo "  • Datenexfiltration (2.8 GB zu Dropbox)"
echo "  • Log-Manipulation"
echo "  • Backdoor-Installation"
echo "  • Sabotage (Backups deaktiviert)"
echo ""
