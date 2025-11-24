#!/bin/bash
set -e

# ========================================================
# KONFIGURATION
# ========================================================
COMPOSE_FILE="docker-compose.yml"
TOPO_FILE="dmz-project-sun.clab.yml"

echo "--- 3. BUILDING IMAGES ---"
sudo docker compose -f "$COMPOSE_FILE" build

echo "--- 4. DEPLOYING TOPOLOGY ---"
sudo containerlab deploy --topo "$TOPO_FILE" --reconfigure

echo "--- 5. WAITING FOR STABILIZATION (15s) ---"
sleep 15

echo "--- 6. CONFIGURING NETWORK ---"

# Hilfsfunktion
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

# --- ROUTERS & ENDPOINTS (IPs & Routes) ---

# 1. Edge Router
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.25.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.35.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"

# 2. Internal Router
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth1"
clab_exec internal-router "ip addr add 192.168.35.1/24 dev eth2"
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-router "ip addr add 192.168.25.1/24 dev eth5"
clab_exec internal-router "ip addr add 192.168.22.1/24 dev eth7"
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.30.1" 
clab_exec internal-router "iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.25.0/24 -j DROP"

# 3. WAF
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

# 4. Firewall (Nur IPs & Routen, Rest macht das Skript im Image)
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"
clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"
clab_exec firewall-in "ip route add 192.168.25.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.22.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.35.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.40.0/24 via 192.168.30.2" 

# 5. Webserver
clab_exec webserver "ip addr add 192.168.25.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.25.1"

# 6. IDS
clab_exec ids-dmz "ip addr add 192.168.22.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.22.1"

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

echo "--- 7. STARTING SERVICES ---"

# SIEM Syslog
sudo docker exec -d clab-dmz-project-sun-siem-backend rsyslogd -n

# IDS
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

# FIREWALL (Der neue, saubere Teil)
echo "--- 8. INITIALIZING FIREWALL ---"
clab_exec firewall-in "/usr/local/bin/init_firewall.sh"

echo "--- READY ---"