#!/bin/bash
# Angriffsszenario 6: Privilege Escalation
# Simuliert Versuche zur Rechteausweitung

echo "=== Privilege Escalation Angriff Szenario ==="
echo "Dieser Angriff simuliert Privilege Escalation Versuche"
echo ""

TARGET_NODE="${1:-webserver}"
SUDO_PASSWORD="${2:-Destiny2004}"

echo "[+] Starte Privilege Escalation Simulation auf $TARGET_NODE"

# Sudo-Missbrauch Versuche
echo "[*] Simuliere sudo-Missbrauch..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    # Mehrere fehlgeschlagene sudo-Versuche
    for i in {1..5}; do
        echo 'wrongpassword' | sudo -S whoami 2>/dev/null || true
        sleep 1
    done
"

# SUID Binary Suche
echo "[*] Suche nach SUID Binaries..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    find / -perm -4000 -type f 2>/dev/null | head -20
"

# Kernel Exploit Simulation
echo "[*] Simuliere Kernel Exploit Versuche..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    # Dirty COW Simulation (harmlos)
    echo '[*] Checking kernel version for exploits...'
    uname -a
    
    # Erstelle verdächtiges Exploit-Skript
    cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
// Fake kernel exploit
int main() {
    setuid(0);
    system(\"/bin/bash\");
    return 0;
}
EOF
    
    # Kompiliere (wird fehlschlagen, aber erzeugt Logs)
    gcc /tmp/exploit.c -o /tmp/exploit 2>/dev/null || true
    rm -f /tmp/exploit.c /tmp/exploit
"

# /etc/passwd und /etc/shadow Zugriff
echo "[*] Versuche Zugriff auf sensitive Dateien..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    # Mehrere Versuche /etc/shadow zu lesen
    for i in {1..3}; do
        cat /etc/shadow 2>/dev/null || true
        sleep 1
    done
    
    # Versuche /etc/passwd zu modifizieren
    echo 'hacker:x:0:0:root:/root:/bin/bash' >> /etc/passwd 2>/dev/null || true
"

# Capabilities Missbrauch
echo "[*] Prüfe Capabilities..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    if command -v getcap &> /dev/null; then
        getcap -r / 2>/dev/null | head -10
    fi
"

# Docker Escape Versuch (Simulation)
echo "[*] Simuliere Container Escape Versuch..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    # Prüfe auf Docker Socket
    ls -la /var/run/docker.sock 2>/dev/null || true
    
    # Prüfe auf privilegierte Container
    cat /proc/self/status | grep Cap 2>/dev/null || true
    
    # Versuche Host-Dateisystem zu mounten
    mount -t proc none /proc 2>/dev/null || true
"

# Cron Job Manipulation
echo "[*] Versuche Cron Manipulation..."
sudo docker exec clab-dmz-project-sun-$TARGET_NODE bash -c "
    # Versuche root crontab zu lesen
    crontab -l -u root 2>/dev/null || true
    
    # Versuche eigenen Cron Job hinzuzufügen
    echo '* * * * * /tmp/backdoor.sh' | crontab - 2>/dev/null || true
    crontab -r 2>/dev/null || true
"

echo ""
echo "[+] Privilege Escalation Simulation abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'privilege escalation', 'sudo', 'suid', 'unauthorized access'"
