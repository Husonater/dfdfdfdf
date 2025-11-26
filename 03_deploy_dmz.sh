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

# Dynamic Port Selection for SIEM Overlay
# Check if port 9090 (or current in file) is in use and find next available
CURRENT_PORT=$(grep -oP '(?<=- )\d+(?=:5000)' "$TOPO_FILE" || echo "9090")
NEW_PORT=$CURRENT_PORT

while sudo lsof -i -P -n | grep ":$NEW_PORT (LISTEN)" >/dev/null; do
    echo "Port $NEW_PORT is in use, trying next..."
    ((NEW_PORT++))
done

if [ "$NEW_PORT" != "$CURRENT_PORT" ]; then
    echo "Updating SIEM Overlay port from $CURRENT_PORT to $NEW_PORT in $TOPO_FILE"
    sed -i "s/- $CURRENT_PORT:5000/- $NEW_PORT:5000/" "$TOPO_FILE"
else
    echo "Port $NEW_PORT is available."
fi

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

# 1. Edge Firewall
# eth1: Internet (172.16.1.1)
# eth2: Link to Internal Firewall (192.168.10.1)
# eth3: Mirror Port to IDS
clab_exec edge-firewall "ip addr add 172.16.1.1/24 dev eth1 || true"
clab_exec edge-firewall "ip addr add 192.168.10.1/24 dev eth2 || true"
clab_exec edge-firewall "ip link set dev eth3 up || true" # Mirror port interface
# Route to internal networks via Internal Firewall
clab_exec edge-firewall "ip route replace 192.168.0.0/16 via 192.168.10.2 || true"

# 2. Internal Firewall
# eth1: Link to Edge Firewall (192.168.10.2)
# eth2: SIEM (192.168.35.1)
# eth3: Client (192.168.40.1)
# eth4: WAF (192.168.50.1)
clab_exec internal-firewall "ip addr add 192.168.10.2/24 dev eth1 || true"
clab_exec internal-firewall "ip addr add 192.168.35.1/24 dev eth2 || true"
clab_exec internal-firewall "ip addr add 192.168.50.1/24 dev eth4 || true"
clab_exec internal-firewall "ip link set dev eth5 up || true" # Mirror port to IDS
# Default route out via Edge Firewall
clab_exec internal-firewall "ip route del default || true"
clab_exec internal-firewall "ip route add default via 192.168.10.1"

# 3. SIEM
clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1 || true"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

# 4. Client
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1 || true"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 5. WAF & Webserver
# WAF
clab_exec reverse-proxy-waf "ip addr add 192.168.50.10/24 dev eth1 || true"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.50.1"
# Webserver (Behind WAF, private link)
# Using 10.0.0.0/24 for WAF<->Webserver link to isolate it
clab_exec reverse-proxy-waf "ip addr add 10.0.0.1/24 dev eth2 || true"
clab_exec webserver "ip addr add 10.0.0.2/24 dev eth1 || true"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 10.0.0.1"

# 6. IDS
# Connected to Edge Firewall mirror port (eth1) and Internal Firewall mirror port (eth2)
clab_exec ids-dmz "ip link set dev eth1 promisc on || true"
clab_exec ids-dmz "ip link set dev eth1 up || true"
clab_exec ids-dmz "ip link set dev eth2 promisc on || true"
clab_exec ids-dmz "ip link set dev eth2 up || true"
# Optional: Assign management IP if needed, but primarily for sniffing
clab_exec ids-dmz "ip addr add 192.168.55.10/24 dev eth1 || true" 

# 7. Attacker
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1 || true"
clab_exec attacker-internet "ip route replace default via 172.16.1.1 dev eth1 || true"


# --- LOG-DATEI VORBEREITUNG ---
echo "Creating Firewall log file..."
sudo docker exec clab-dmz-project-sun-edge-firewall touch /fw.log
sudo docker exec clab-dmz-project-sun-edge-firewall chmod 644 /fw.log

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
clab_exec edge-firewall "/usr/local/bin/init_firewall.sh"

echo "--- READY ---"