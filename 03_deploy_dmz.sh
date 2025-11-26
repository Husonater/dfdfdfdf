#!/bin/bash
set -e

# ========================================================
# KONFIGURATION
# ========================================================
COMPOSE_FILE="docker-compose.yml"
TOPO_FILE="dmz-project-sun.clab.yml"

echo "--- 3. BUILDING IMAGES ---"
# Wir bauen sicherheitshalber alles neu
docker compose -f "$COMPOSE_FILE" build

# Check if port 9098 is in use
PORT=9098
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; then
    echo "Port $PORT is already in use. Killing process..."
    lsof -Pi :$PORT -sTCP:LISTEN -t | xargs kill -9
    echo "Process killed."
else
    echo "Port $PORT is available."
fi

echo "--- 4. DEPLOYING TOPOLOGY ---"
# Hard Cleanup: Remove all lab containers manually
docker ps -a --filter "name=clab-dmz-project-sun" -q | xargs -r docker rm -f

# Altes Lab zerstören
containerlab destroy --topo "$TOPO_FILE" --cleanup || true

# Startet das Lab neu
containerlab deploy --topo "$TOPO_FILE" --reconfigure

echo "--- 5. WAITING FOR STABILIZATION (15s) ---"
sleep 15

echo "--- 6. CONFIGURING NETWORK ---"

# Hilfsfunktion (mit IP Forwarding Aktivierung)
clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER 2>/dev/null)" != "true" ]; then
        echo "CRITICAL: Container $CONTAINER is DOWN!"
        return 1
    fi
    docker exec "$CONTAINER" /bin/sh -c "sysctl -w net.ipv4.ip_forward=1" > /dev/null 2>&1 || true
    echo "Configuring $1..."
    docker exec "$CONTAINER" /bin/sh -c "$2"
}

# --- A. IP ADRESSEN & ROUTING ---

# 1. Attacker (Internet)
# eth1 -> Edge Firewall eth1
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route replace default via 172.16.1.1"

# 2. Edge Firewall
# eth1 -> Internet (172.16.1.1)
# eth2 -> Internal Firewall (192.168.10.1) - Transit
# eth3 -> IDS (Mirror)
clab_exec edge-firewall "ip addr add 172.16.1.1/24 dev eth1"
clab_exec edge-firewall "ip addr add 192.168.10.1/24 dev eth2"
clab_exec edge-firewall "ip link set dev eth3 up" # Mirror Port
# Route alles interne zur Internal Firewall
clab_exec edge-firewall "ip route add 192.168.0.0/16 via 192.168.10.2"

# 3. Internal Firewall (Core Switch/Router)
# eth1 -> Edge Firewall (192.168.10.2)
# eth2 -> SIEM (192.168.35.1)
# eth3 -> Client (192.168.40.1)
# eth4 -> WAF (192.168.20.1)
# eth5 -> IDS (Mirror)
clab_exec internal-firewall "ip addr add 192.168.10.2/24 dev eth1"
clab_exec internal-firewall "ip addr add 192.168.35.1/24 dev eth2"
clab_exec internal-firewall "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-firewall "ip addr add 192.168.20.1/24 dev eth4"
clab_exec internal-firewall "ip link set dev eth5 up" # Mirror Port
# Default Route ins Internet
clab_exec internal-firewall "ip route del default || true"
clab_exec internal-firewall "ip route add default via 192.168.10.1"
# Route zum Webserver (hinter WAF)
clab_exec internal-firewall "ip route add 192.168.60.0/24 via 192.168.20.10"

# 4. WAF
# eth1 -> Internal Firewall (192.168.20.10)
# eth2 -> Webserver (192.168.60.1)
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip addr add 192.168.60.1/24 dev eth2"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

# 5. Webserver
# eth1 -> WAF (192.168.60.20)
clab_exec webserver "ip addr add 192.168.60.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.60.1"

# 6. SIEM
# eth1 -> Internal Firewall (192.168.35.10)
clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

# 7. Client Internal
# eth1 -> Internal Firewall (192.168.40.10)
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 8. IDS
# eth1 -> Edge Firewall Mirror (Monitor)
# eth2 -> Internal Firewall Mirror (Monitor)
# eth3? -> Management IP? (Wir nutzen hier kein Management Network, IDS sniffed nur)
clab_exec ids-dmz "ip link set dev eth1 promisc on"
clab_exec ids-dmz "ip link set dev eth1 up"
clab_exec ids-dmz "ip link set dev eth2 promisc on"
clab_exec ids-dmz "ip link set dev eth2 up"
# IDS braucht eine IP um Logs zu senden! Wir geben ihm eine am Internal Firewall Mirror Port (Hack, oder wir bräuchten ein Mgmt Netz)
# Besser: Wir nutzen eth2 (Internal FW) auch als Mgmt Interface.
clab_exec ids-dmz "ip addr add 192.168.10.30/24 dev eth2" # Hängt an Internal FW eth5? Nein, eth5 ist Mirror.
# WARNUNG: Die Topologie hat keine dedizierte Mgmt-Leitung für das IDS.
# Das IDS hängt an Mirror Ports. Mirror Ports leiten normalerweise keinen Traffic ZURÜCK.
# Für diese Demo nehmen wir an, dass die Verbindung "Internal Firewall -> IDS" (eth5 <-> eth2) bidirektional ist.
clab_exec internal-firewall "ip addr add 192.168.99.1/24 dev eth5"
clab_exec ids-dmz "ip addr add 192.168.99.30/24 dev eth2"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.99.1"


# --- LOG-DATEI VORBEREITUNG ---
echo "Creating Firewall log file..."
docker exec clab-dmz-project-sun-edge-firewall touch /fw.log
docker exec clab-dmz-project-sun-edge-firewall chmod 644 /fw.log
docker exec clab-dmz-project-sun-internal-firewall touch /fw.log
docker exec clab-dmz-project-sun-internal-firewall chmod 644 /fw.log

echo "--- 7. STARTING SERVICES ---"

# IDS Start
docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

# WAF Start
echo "Starting WAF..."
docker exec -d clab-dmz-project-sun-reverse-proxy-waf /usr/local/bin/startup_waf.sh

# Firewalls Init
echo "Initializing Firewalls..."
clab_exec edge-firewall "/usr/local/bin/init_firewall.sh"
clab_exec internal-firewall "/usr/local/bin/init_firewall.sh"

echo "--- READY ---"