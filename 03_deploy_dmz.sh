#!/bin/bash
set -e

# --------------------------------------------------------
# DMZ Deployment (SECURITY HARDENED)
# --------------------------------------------------------

echo "--- 3. BUILDING IMAGES ---"
sudo docker compose -f docker-compose.build.yaml build

echo "--- 4. DEPLOYING TOPOLOGY ---"
sudo containerlab deploy --topo dmz_topology.yaml

echo "--- 5. WAITING FOR STABILIZATION (15s) ---"
sleep 15

echo "--- 6. CONFIGURING NETWORK ---"

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

# --- ROUTERS & ENDPOINTS ---
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.25.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.35.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"

clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth1"
clab_exec internal-router "ip addr add 192.168.35.1/24 dev eth2"
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-router "ip addr add 192.168.25.1/24 dev eth5"
clab_exec internal-router "ip addr add 192.168.22.1/24 dev eth7"
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.30.1" 
# Verhindert, dass der Client (VLAN 40) direkt auf den Webserver (VLAN 25) zugreift.
# Der Traffic muss über die Firewall (Gateway) laufen, aber da sie am gleichen Router hängen,
# müssen wir den direkten "Kurzschluss" hier verbieten.
clab_exec internal-router "iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.25.0/24 -j DROP"
# ------------------------------------------------

clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"
clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"
clab_exec firewall-in "ip route add 192.168.25.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.22.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.35.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.40.0/24 via 192.168.30.2" 

clab_exec webserver "ip addr add 192.168.25.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.25.1"

clab_exec ids-dmz "ip addr add 192.168.22.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.22.1"

clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route replace default via 172.16.1.1 dev eth1"

clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

echo "--- 7. STARTING SERVICES ---"
sudo docker exec -d clab-dmz-project-sun-siem-backend rsyslogd -n
sudo docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

echo "Starting WAF Nginx (Manual)..."
sudo docker exec -d clab-dmz-project-sun-reverse-proxy-waf nginx -g "daemon off;" 
sleep 3
if sudo docker exec clab-dmz-project-sun-reverse-proxy-waf ps aux | grep "nginx: master" > /dev/null; then
    echo "✅ WAF started successfully."
else
    echo "❌ ERROR: WAF failed to start."
fi

echo "--- 8. FIREWALL RULES (HARDENED) ---"
# Reset
clab_exec firewall-in "iptables -F && iptables -t nat -F"
clab_exec firewall-in "iptables -P INPUT DROP"
clab_exec firewall-in "iptables -P FORWARD DROP"
clab_exec firewall-in "iptables -P OUTPUT ACCEPT"

# 1. Self-Traffic & ICMP (Ping allowed to interface)
clab_exec firewall-in "iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
clab_exec firewall-in "iptables -A INPUT -p icmp -j ACCEPT"

# 2. Forwarding - ALLOW LIST
# State Tracking (Allow replies)
clab_exec firewall-in "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"

# Internet -> WAF (HTTP/HTTPS Only)
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT"

# WAF -> Webserver (HTTP Only)
clab_exec firewall-in "iptables -A FORWARD -s 192.168.20.10 -d 192.168.25.20 -p tcp --dport 80 -j ACCEPT"

# Client -> SIEM (Management Only)
clab_exec firewall-in "iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.35.0/24 -j ACCEPT"

# 3. EXPLICIT DENY (The Fix for 'CONNECTED UNSAFE')
# This ensures that if the Policy fails, this rule catches the traffic.
clab_exec firewall-in "iptables -A FORWARD -j DROP"

echo "--- READY ---"