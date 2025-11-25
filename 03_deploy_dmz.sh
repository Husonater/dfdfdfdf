#!/bin/bash
set -e

# ========================================================
# KONFIGURATION
# ========================================================
COMPOSE_FILE="docker-compose.yml"
TOPO_FILE="dmz-project-sun.clab.yml"

echo "--- 3. BUILDING IMAGES ---"
# Wir bauen sicherheitshalber alles neu, besonders Firewall, WAF und IDS
sudo docker compose -f "$COMPOSE_FILE" build

echo "--- 4. DEPLOYING TOPOLOGY ---"
# Startet das Lab neu mit der optimierten Verkabelung
sudo containerlab deploy --topo "$TOPO_FILE" --reconfigure

echo "--- 5. WAITING FOR STABILIZATION (15s) ---"
sleep 15

echo "--- 6. CONFIGURING NETWORK ---"

# Hilfsfunktion (mit IP Forwarding Aktivierung)
clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    if [ "$(sudo docker inspect -f '{{.State.Running}}' $CONTAINER 2>/dev/null)" != "true" ]; then
        echo "CRITICAL: Container $CONTAINER is DOWN!"
        return 1
    fi
    sudo docker exec "$CONTAINER" /bin/sh -c "sysctl -w net.ipv4.ip_forward=1" > /dev/null 2>&1 || true
    echo "Configuring $1..."
    sudo docker exec "$CONTAINER" /bin/sh -c "$2"
}

# --- A. ROUTERS & ENDPOINTS (IPs & Routes) ---

# 1. Edge Router
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
# Routen zu allen internen Netzen via Firewall (10.2)
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.35.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.60.0/24 via 192.168.10.2" # Webserver Netz
clab_exec edge-router "ip route add 192.168.61.0/24 via 192.168.10.2" # IDS Netz
clab_exec edge-router "ip route add 192.168.70.0/24 via 192.168.10.2" # DB Netz

# 2. Internal Router (Vereinfacht: Nur noch Client & SIEM)
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth1" # Transit zur FW
clab_exec internal-router "ip addr add 192.168.35.1/24 dev eth2" # SIEM
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3" # Client
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.30.1" 

# 3. WAF (Bleibt im DMZ Front Netz)
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

# 4. Firewall (Der zentrale Knoten)
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1" # Outside
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2" # WAF
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3" # Transit Intern
clab_exec firewall-in "ip addr add 192.168.60.1/24 dev eth4" # Webserver Netz
clab_exec firewall-in "ip addr add 192.168.61.1/24 dev eth5" # IDS Netz (WICHTIG für Routing!)
clab_exec firewall-in "ip addr add 192.168.70.1/24 dev eth6" # DB Netz

clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"
# Routen zu den internen Netzen hinter dem Internal Router
clab_exec firewall-in "ip route add 192.168.35.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.40.0/24 via 192.168.30.2" 

# 5. Webserver (Neues Netz 60.0)
clab_exec webserver "ip addr add 192.168.60.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.60.1" 

# 6. IDS (Neues Netz 61.0 - Separat für sauberes Mirroring)
clab_exec ids-dmz "ip addr add 192.168.61.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.61.1"
# Promiscuous Mode aktivieren (Wichtig für Mirroring Empfang!)
clab_exec ids-dmz "ip link set dev eth1 promisc on"

# 7. Attacker
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route replace default via 172.16.1.1 dev eth1"

# 8. Client
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 9. SIEM
clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

# 10. Database
clab_exec db-backend "ip addr add 192.168.70.10/24 dev eth1"
clab_exec db-backend "ip route del default || true"
clab_exec db-backend "ip route add default via 192.168.70.1"

# --- LOG-DATEI VORBEREITUNG ---
echo "Creating Firewall log file..."
sudo docker exec clab-dmz-project-sun-firewall-in touch /fw.log
sudo docker exec clab-dmz-project-sun-firewall-in chmod 644 /fw.log

echo "--- 7. STARTING SERVICES ---"

# SIEM Syslog Daemon
# SIEM Syslog Daemon handled by startup script

# IDS Start (Lädt Regeln + Engine)
sudo docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

# WAF Nginx
echo "Starting WAF Nginx..."
sudo docker exec -d clab-dmz-project-sun-reverse-proxy-waf nginx -g "daemon off;" 
sleep 3
if sudo docker exec clab-dmz-project-sun-reverse-proxy-waf ps aux | grep "nginx: master" > /dev/null; then
    echo "✅ WAF started successfully."
else
    echo "❌ ERROR: WAF failed to start."
fi

# FIREWALL (Regeln + Logging Pipeline)
echo "--- 8. INITIALIZING FIREWALL ---"
clab_exec firewall-in "/usr/local/bin/init_firewall.sh"

echo "--- READY ---"