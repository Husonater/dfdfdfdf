#!/bin/bash
# KOMPLEXER ANGRIFF 5: Multi-Vector Ransomware Campaign
# Simuliert einen modernen Ransomware-Angriff mit mehreren Vektoren

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      🔴 RANSOMWARE CAMPAIGN - Multi-Vector Attack 🔴          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
ATTACKER_IP="172.20.20.2"
RANSOM_GROUP="DarkSide2.0"

echo "[PHASE 1] Initial Infection - Phishing Email"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Email mit Malicious Attachment
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager postfix: Email received from phishing@evil-domain.com\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager postfix: Attachment: Invoice_2025.pdf.exe (suspicious double extension)\" >> /var/log/syslog
    
    # User öffnet Attachment
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious file execution: Invoice_2025.pdf.exe\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: File downloaded from: http://malicious-cdn.com/loader.exe\" >> /var/log/syslog
"
echo "  ⚠️  Phishing erfolgreich - Malware heruntergeladen!"
sleep 2

echo ""
echo "[PHASE 2] Dropper & Loader Execution"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Dropper entpackt Payload
    touch /tmp/loader.exe
    touch /tmp/.ransomware_payload
    
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Process loader.exe created child process: .ransomware_payload\" >> /var/log/syslog
    
    # Anti-VM/Sandbox Checks
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious system checks: cpuid, rdtsc timing analysis\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Process checking for VirtualBox, VMware, QEMU artifacts\" >> /var/log/syslog
    
    # Privilege Escalation Exploit
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: Exploit attempt detected: UAC bypass via fodhelper.exe\" >> /var/log/syslog
"
echo "  ✓ Dropper ausgeführt - Payload entpackt"
sleep 2

echo ""
echo "[PHASE 3] Network Reconnaissance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # SMB Scanning
    for ip in 172.20.20.{1..20}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: SMB connection attempt to \$ip:445\" >> /var/log/syslog
    done
    
    # Active Directory Enumeration
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ldapsearch: Querying AD for all computers\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager net: Enumerating domain controllers\" >> /var/log/syslog
    
    # Network Share Discovery
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager smbclient: Scanning for accessible network shares\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Found 15 accessible SMB shares\" >> /var/log/syslog
"
echo "  ✓ Netzwerk kartiert - Ziele identifiziert"
sleep 2

echo ""
echo "[PHASE 4] Lateral Movement & Propagation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # PSExec-style Lateral Movement
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sshd[12345]: Connection from 172.20.20.5 using stolen credentials\" >> /var/log/auth.log
    
    # WMI Remote Execution
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wmi: Remote command execution on 172.20.20.6\" >> /var/log/syslog
    
    # EternalBlue-style Exploit
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: SMB exploit attempt: buffer overflow in srv2.sys\" >> /var/log/syslog
    
    # Ransomware kopiert sich selbst
    for host in webserver db-backend client-internal; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager scp: Copying ransomware to $host:/tmp/.payload\" >> /var/log/syslog
    done
"
echo "  🔴 Ransomware auf 3 weitere Hosts verbreitet!"
sleep 2

echo ""
echo "[PHASE 5] Credential Theft & Privilege Escalation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Mimikatz-style Credential Dumping
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: LSASS memory dump detected\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Credentials extracted: 25 users, 15 NTLM hashes\" >> /var/log/syslog
    
    # Domain Admin Compromise
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Domain Admin credentials obtained\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager su: (to root) DOMAIN\\\\Administrator on none\" >> /var/log/auth.log
"
echo "  🔴 Domain Admin kompromittiert!"
sleep 2

echo ""
echo "[PHASE 6] Data Exfiltration (Double Extortion)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Sensitive Data Discovery
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager find: Searching for *.doc, *.xls, *.pdf, *.sql, *.zip\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Found 5,234 sensitive files (45 GB)\" >> /var/log/syslog
    
    # Compression
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager 7z: Compressing stolen data: exfil_$(date +%Y%m%d).7z\" >> /var/log/syslog
    
    # Upload to Attacker Infrastructure
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager curl: Uploading to https://leak-site.$RANSOM_GROUP.onion\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Large data transfer: 45 GB uploaded in 2 hours\" >> /var/log/syslog
"
echo "  🔴 45 GB Daten exfiltriert - Double Extortion!"
sleep 2

echo ""
echo "[PHASE 7] Backup Destruction"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Volume Shadow Copies löschen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager vssadmin: Deleting all shadow copies\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wbadmin: Deleting system backup catalog\" >> /var/log/syslog
    
    # Backup-Server angreifen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ssh: Connecting to backup-server\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager rm: Deleting /backup/* (recursive)\" >> /var/log/syslog
    
    # Cloud Backups löschen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager aws: Deleting S3 backup buckets\" >> /var/log/syslog
"
echo "  🔴 Alle Backups zerstört!"
sleep 2

echo ""
echo "[PHASE 8] Encryption Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Ransomware startet Verschlüsselung
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Mass file encryption detected\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: 15,234 files encrypted with .${RANSOM_GROUP} extension\" >> /var/log/syslog
    
    # Kritische Systeme verschlüsselt
    for system in database webserver fileserver mailserver; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: $system: All files encrypted\" >> /var/log/syslog
        touch /tmp/\${system}_encrypted.${RANSOM_GROUP}
    done
    
    # Hohe I/O Last durch Verschlüsselung
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Abnormal disk I/O: 500 MB/s write operations\" >> /var/log/syslog
"
echo "  🔴 VERSCHLÜSSELUNG AKTIV - 15,234 Dateien betroffen!"
sleep 2

echo ""
echo "[PHASE 9] Ransom Note Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Ransom Note erstellen
    cat > /tmp/README_DECRYPT.txt << EOF
╔════════════════════════════════════════════════════════════════╗
║                    YOUR FILES ARE ENCRYPTED                    ║
╚════════════════════════════════════════════════════════════════╝

All your files have been encrypted with military-grade encryption.

🔒 ENCRYPTED: 15,234 files (45 GB)
📤 EXFILTRATED: 45 GB of sensitive data
💰 RANSOM: 50 Bitcoin (~\$2,000,000 USD)

⏰ DEADLINE: 72 hours
   After deadline: Ransom DOUBLES + Data PUBLISHED

🌐 PAYMENT PORTAL: http://payment.$RANSOM_GROUP.onion
🔑 YOUR ID: $(uuidgen)

⚠️  DO NOT:
   - Contact law enforcement (data will be published)
   - Try to decrypt (files will be corrupted)
   - Restore from backups (they are deleted)

We have already published proof of breach on our leak site.
Pay within 72 hours or your data goes public.

- $RANSOM_GROUP Team
EOF
    
    # Ransom Note überall platzieren
    for dir in /home /var/www /root /tmp; do
        cp /tmp/README_DECRYPT.txt \$dir/ 2>/dev/null || true
    done
    
    # Desktop Wallpaper ändern
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Desktop wallpaper changed to ransom note\" >> /var/log/syslog
    
    # Email an alle User
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager sendmail: Mass email sent: 'Your files are encrypted'\" >> /var/log/syslog
"
echo "  🔴 Ransom Note deployed!"
sleep 2

echo ""
echo "[PHASE 10] Cleanup & Anti-Forensics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Event Logs löschen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wevtutil: Clearing Security event log\" >> /var/log/syslog
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wevtutil: Clearing System event log\" >> /var/log/syslog
    
    # Ransomware selbst löschen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager rm: Deleting ransomware binary\" >> /var/log/syslog
    
    # Netzwerk-Verbindungen trennen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager iptables: Blocking all outbound connections\" >> /var/log/syslog
"
echo "  ⚠️  Spuren verwischt!"
sleep 2

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "💀 RANSOMWARE ATTACK ABGESCHLOSSEN 💀"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "SCHADEN:"
echo "  🔒 15,234 Dateien verschlüsselt (45 GB)"
echo "  📤 45 GB sensitive Daten exfiltriert"
echo "  💰 Lösegeld: 50 Bitcoin (~\$2,000,000)"
echo "  ⏰ Deadline: 72 Stunden"
echo "  🗑️  Alle Backups zerstört"
echo "  🌐 4 Hosts kompromittiert"
echo ""
echo "ANGRIFFSKETTE:"
echo "  1. Phishing Email → Malware Download"
echo "  2. Privilege Escalation → Domain Admin"
echo "  3. Lateral Movement → 4 Hosts"
echo "  4. Data Exfiltration → 45 GB"
echo "  5. Backup Destruction"
echo "  6. Mass Encryption → 15,234 Files"
echo "  7. Ransom Note → Double Extortion"
echo ""
