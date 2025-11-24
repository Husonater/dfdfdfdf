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
# Führt die Änderungen in der YAML-Datei aus
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

# --- A. ROUTERS & ENDPOINTS (IPs & Routes) ---

# 1. Edge Router
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
# NEU: Route zum neuen Webserver/IDS Netz (192.168.60.x)
clab_exec edge-router "ip route add 192.168.60.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.35.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"
# ALTE Routen (25.0/24, 22.0/24) wurden entfernt

# 2. Internal Router (Entfernt alle alten DMZ-Rollen)
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth1" # Transit zur FW
clab_exec internal-router "ip addr add 192.168.35.1/24 dev eth2" # SIEM
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3" # Client
# ALTE IPs 25.1 und 22.1 entfernt
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.30.1" 
# ALTE iptables DROP-Regel entfernt (Policy gehört auf die Firewall-in!)

# 3. WAF (Bleibt in 192.168.20.0/24)
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

# 4. Firewall (Muss die neue Schnittstelle bekommen)
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2" # WAF-Netz
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3" # Transit Intern
# NEU: Webserver/IDS Netz (eth4)
clab_exec firewall-in "ip addr add 192.168.60.1/24 dev eth4"
# eth5 wird nicht konfiguriert (IDS ist passiv am Mirror Port oder auf eth5)
clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"
# Routen zu internen Subnetzen
clab_exec firewall-in "ip route add 192.168.35.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.40.0/24 via 192.168.30.2" 
# ALTE Routen 25.0 und 22.0 via 30.2 entfernt

# 5. Webserver (NEU: In 192.168.60.0/24)
clab_exec webserver "ip addr add 192.168.60.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.60.1" # FW ist Gateway

# 6. IDS (NEU: In 192.168.60.0/24)
clab_exec ids-dmz "ip addr add 192.168.60.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.60.1" 

# 7. Attacker (Unverändert)
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route replace default via 172.16.1.1 dev eth1"

# 8. Client (Unverändert)
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 9. SIEM (Unverändert)
clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

# --- LOG-DATEI ERSTELLEN ---
echo "Creating Firewall log file /fw.log..."
sudo docker exec clab-dmz-project-sun-firewall-in touch /fw.log
sudo docker exec clab-dmz-project-sun-firewall-in chmod 644 /fw.log

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

# FIREWALL (Die Regeln müssen noch an 192.168.60.20 angepasst werden!)
echo "--- 8. INITIALIZING FIREWALL (ulogd/rsyslog/iptables) ---"
clab_exec firewall-in "/usr/local/bin/init_firewall.sh"

echo "--- READY ---"