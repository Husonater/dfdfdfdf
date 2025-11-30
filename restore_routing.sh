#!/bin/bash
set -e

# Hilfsfunktion (mit IP Forwarding Aktivierung)
clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER 2>/dev/null)" != "true" ]; then
        echo "CRITICAL: Container $CONTAINER is DOWN!"
        return 1
    fi
    docker exec -u 0 "$CONTAINER" /bin/sh -c "sysctl -w net.ipv4.ip_forward=1" > /dev/null 2>&1 || true
    echo "Configuring $1..."
    docker exec -u 0 "$CONTAINER" /bin/sh -c "$2"
}

echo "Restoring DMZ Routing..."

# Helper to add mgmt route
add_mgmt_route() {
    docker exec -u 0 "clab-dmz-project-sun-$1" ip route add 172.20.20.0/24 dev eth0 || true
}

# 1. Attacker (Internet)
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1 || true"
clab_exec attacker-internet "ip route replace default via 172.16.1.1"
add_mgmt_route attacker-internet

# 2. Edge Firewall
clab_exec edge-firewall "ip addr add 172.16.1.1/24 dev eth1 || true"
clab_exec edge-firewall "ip addr add 192.168.10.1/24 dev eth2 || true"
clab_exec edge-firewall "ip link set dev eth3 up || true" # Mirror Port
clab_exec edge-firewall "ip route add 192.168.0.0/16 via 192.168.10.2 || true"

# 3. Internal Firewall (Core Switch/Router)
clab_exec internal-firewall "ip addr add 192.168.10.2/24 dev eth1 || true"
clab_exec internal-firewall "ip addr add 192.168.35.1/24 dev eth2 || true"
clab_exec internal-firewall "ip addr add 192.168.40.1/24 dev eth3 || true"
clab_exec internal-firewall "ip addr add 192.168.20.1/24 dev eth4 || true"
clab_exec internal-firewall "ip link set dev eth5 up || true" # Mirror Port
clab_exec internal-firewall "ip route del default || true"
clab_exec internal-firewall "ip route add default via 192.168.10.1"
clab_exec internal-firewall "ip route add 192.168.60.0/24 via 192.168.20.10 || true"
add_mgmt_route internal-firewall

# 4. WAF
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1 || true"
clab_exec reverse-proxy-waf "ip addr add 192.168.60.1/24 dev eth2 || true"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"
add_mgmt_route reverse-proxy-waf

# 5. Webserver
clab_exec webserver "ip addr add 192.168.60.20/24 dev eth1 || true"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.60.1"
add_mgmt_route webserver

# 6. Wazuh Manager
clab_exec wazuh-manager "ip addr add 192.168.35.10/24 dev eth1 || true"
clab_exec wazuh-manager "ip route del default || true"
clab_exec wazuh-manager "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-manager

# 6a. SIEM Switch (L2 Bridge)
clab_exec siem-switch "apk add --no-cache bridge-utils || true"
clab_exec siem-switch "brctl addbr br0 || true"
clab_exec siem-switch "brctl addif br0 eth1 || true"
clab_exec siem-switch "brctl addif br0 eth2 || true"
clab_exec siem-switch "brctl addif br0 eth3 || true"
clab_exec siem-switch "brctl addif br0 eth4 || true"
clab_exec siem-switch "ip link set dev br0 up || true"
clab_exec siem-switch "ip link set dev eth1 up || true"
clab_exec siem-switch "ip link set dev eth2 up || true"
clab_exec siem-switch "ip link set dev eth3 up || true"
clab_exec siem-switch "ip link set dev eth4 up || true"

# 6b. Wazuh Indexer
clab_exec wazuh-indexer "ip addr add 192.168.35.11/24 dev eth1 || true"
clab_exec wazuh-indexer "ip route del default || true"
clab_exec wazuh-indexer "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-indexer

# 6c. Wazuh Dashboard
clab_exec wazuh-dashboard "ip addr add 192.168.35.12/24 dev eth1 || true"
clab_exec wazuh-dashboard "ip route del default || true"
clab_exec wazuh-dashboard "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-dashboard

# 7. Client Internal
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1 || true"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"
add_mgmt_route client-internal

# 8. IDS
clab_exec ids-dmz "ip link set dev eth1 promisc on || true"
clab_exec ids-dmz "ip link set dev eth1 up || true"
clab_exec ids-dmz "ip link set dev eth2 promisc on || true"
clab_exec ids-dmz "ip link set dev eth2 up || true"
clab_exec edge-firewall "ip addr add 192.168.61.1/24 dev eth3 || true"
clab_exec ids-dmz "ip addr add 192.168.61.30/24 dev eth1 || true"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.61.1"
add_mgmt_route ids-dmz

# 9. Database
clab_exec internal-firewall "ip addr add 192.168.70.1/24 dev eth6 || true"
clab_exec db-backend "ip addr add 192.168.70.10/24 dev eth1 || true"
clab_exec db-backend "ip route del default || true"
clab_exec db-backend "ip route add default via 192.168.70.1"
add_mgmt_route db-backend

echo "Routing restored!"
