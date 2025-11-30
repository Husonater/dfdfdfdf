#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[+] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# 1. Deploy Topology
log "Deploying DMZ Topology..."
sudo containerlab deploy -t dmz-project-sun.clab.yml --reconfigure

# 2. Restore Routing
log "Restoring Network Routing..."
# Helper to add mgmt route
add_mgmt_route() {
    docker exec -u 0 "clab-dmz-project-sun-$1" ip route add 172.20.20.0/24 dev eth0 || true
}

clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER 2>/dev/null)" != "true" ]; then
        error "Container $CONTAINER is DOWN!"
        return 1
    fi
    docker exec -u 0 "$CONTAINER" /bin/sh -c "sysctl -w net.ipv4.ip_forward=1" > /dev/null 2>&1 || true
    # echo "Configuring $1..."
    docker exec -u 0 "$CONTAINER" /bin/sh -c "$2"
}

# Attacker
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1 || true"
clab_exec attacker-internet "ip route replace default via 172.16.1.1"
clab_exec attacker-internet "apt-get update && apt-get install -y sshpass || true"
add_mgmt_route attacker-internet

# Edge Firewall
clab_exec edge-firewall "ip addr add 172.16.1.1/24 dev eth1 || true"
clab_exec edge-firewall "ip addr add 192.168.10.1/24 dev eth2 || true"
clab_exec edge-firewall "ip link set dev eth3 up || true"
clab_exec edge-firewall "ip route add 192.168.0.0/16 via 192.168.10.2 || true"
clab_exec edge-firewall "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || true"

# Internal Firewall
clab_exec internal-firewall "ip addr add 192.168.10.2/24 dev eth1 || true"
clab_exec internal-firewall "ip addr add 192.168.35.1/24 dev eth2 || true"
clab_exec internal-firewall "ip addr add 192.168.40.1/24 dev eth3 || true"
clab_exec internal-firewall "ip addr add 192.168.20.1/24 dev eth4 || true"
clab_exec internal-firewall "ip link set dev eth5 up || true"
clab_exec internal-firewall "ip route del default || true"
clab_exec internal-firewall "ip route add default via 192.168.10.1"
clab_exec internal-firewall "ip route add 192.168.60.0/24 via 192.168.20.10 || true"
add_mgmt_route internal-firewall

# WAF
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1 || true"
clab_exec reverse-proxy-waf "ip addr add 192.168.60.1/24 dev eth2 || true"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"
add_mgmt_route reverse-proxy-waf

# Webserver
clab_exec webserver "ip addr add 192.168.60.20/24 dev eth1 || true"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.60.1"
clab_exec webserver "apt-get update && apt-get install -y openssh-server && service ssh start || true"
add_mgmt_route webserver

# Wazuh Manager
clab_exec wazuh-manager "ip addr add 192.168.35.10/24 dev eth1 || true"
clab_exec wazuh-manager "ip route del default || true"
clab_exec wazuh-manager "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-manager

# SIEM Switch
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

# Wazuh Indexer
clab_exec wazuh-indexer "ip addr add 192.168.35.11/24 dev eth1 || true"
clab_exec wazuh-indexer "ip route del default || true"
clab_exec wazuh-indexer "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-indexer

# Wazuh Dashboard
clab_exec wazuh-dashboard "ip addr add 192.168.35.12/24 dev eth1 || true"
clab_exec wazuh-dashboard "ip route del default || true"
clab_exec wazuh-dashboard "ip route add default via 192.168.35.1"
add_mgmt_route wazuh-dashboard

# Client Internal
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1 || true"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"
add_mgmt_route client-internal

# IDS
clab_exec ids-dmz "ip link set dev eth1 promisc on || true"
clab_exec ids-dmz "ip link set dev eth1 up || true"
clab_exec ids-dmz "ip link set dev eth2 promisc on || true"
clab_exec ids-dmz "ip link set dev eth2 up || true"
clab_exec edge-firewall "ip addr add 192.168.61.1/24 dev eth3 || true"
clab_exec ids-dmz "ip addr add 192.168.61.30/24 dev eth1 || true"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.61.1"
add_mgmt_route ids-dmz

# Database
clab_exec internal-firewall "ip addr add 192.168.70.1/24 dev eth6 || true"
clab_exec db-backend "ip addr add 192.168.70.10/24 dev eth1 || true"
clab_exec db-backend "ip route del default || true"
clab_exec db-backend "ip route add default via 192.168.70.1"
add_mgmt_route db-backend


# 3. Fix Wazuh Indexer
log "Configuring Wazuh Indexer..."
# Copy all certificates
docker cp root-ca.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/root-ca.pem
docker cp indexer.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer.pem
docker cp indexer-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer-key.pem
docker cp admin.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin.pem
docker cp admin-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin-key.pem

# Fix permissions
docker exec clab-dmz-project-sun-wazuh-indexer chmod 400 /usr/share/wazuh-indexer/certs/indexer-key.pem
docker exec clab-dmz-project-sun-wazuh-indexer chmod 400 /usr/share/wazuh-indexer/certs/admin-key.pem
docker exec clab-dmz-project-sun-wazuh-indexer chown -R wazuh-indexer:wazuh-indexer /usr/share/wazuh-indexer/certs

# Update opensearch.yml to use our certificates
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemcert_filepath:.*|plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemkey_filepath:.*|plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemtrustedcas_filepath:.*|plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem|g' /usr/share/wazuh-indexer/opensearch.yml

docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemcert_filepath:.*|plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemkey_filepath:.*|plugins.security.ssl.http.pemkey_filepath: certs/indexer-key.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemtrustedcas_filepath:.*|plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem|g' /usr/share/wazuh-indexer/opensearch.yml

# Fix internal users and admin DN
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG|\$2y\$12\$Ao4b78h7RuRvArs5hkfo2ebILdfE/luW1c5aYFlnlC6Cy8vme8unO|g' /usr/share/wazuh-indexer/opensearch-security/internal_users.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US|CN=admin,OU=Wazuh,O=Wazuh,L=San Jose,ST=California,C=US|g' /usr/share/wazuh-indexer/opensearch.yml

docker restart clab-dmz-project-sun-wazuh-indexer
log "Waiting for Indexer to restart (30s)..."
sleep 30
docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk clab-dmz-project-sun-wazuh-indexer bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -icl -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost


# 4. Fix Wazuh Manager
log "Configuring Wazuh Manager..."
docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /etc/filebeat/certs
docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager.pem
docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager-key.pem
docker cp root-ca.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/root-ca.pem
docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /var/ossec/api/configuration/ssl
docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.crt
docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.key
docker exec clab-dmz-project-sun-wazuh-manager chown -R wazuh:wazuh /var/ossec/api/configuration/ssl
docker exec clab-dmz-project-sun-wazuh-manager chmod 600 /var/ossec/api/configuration/ssl/server.key
docker exec clab-dmz-project-sun-wazuh-manager chmod 644 /var/ossec/api/configuration/ssl/server.crt

# Fix Wazuh Manager Cluster Utils (Critical for API)
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's/NODE_IP/127.0.0.1/g' /var/ossec/framework/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's/NODE_IP/127.0.0.1/g' /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i "s/'nodes': \[\]/'nodes': ['127.0.0.1']/" /var/ossec/framework/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i "s/'nodes': \[\]/'nodes': ['127.0.0.1']/" /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager rm -rf /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/__pycache__

# Configure Filebeat
cat <<EOF > filebeat.yml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.enabled: false
output.elasticsearch:
  hosts: ['https://wazuh-indexer:9200']
  username: 'admin'
  password: 'SecretPassword123!'
  ssl.verification_mode: full
  ssl.certificate_authorities: ['/etc/filebeat/certs/root-ca.pem']
  ssl.certificate: '/etc/filebeat/certs/wazuh-manager.pem'
  ssl.key: '/etc/filebeat/certs/wazuh-manager-key.pem'

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq
EOF
docker cp filebeat.yml clab-dmz-project-sun-wazuh-manager:/etc/filebeat/filebeat.yml
docker restart clab-dmz-project-sun-wazuh-manager
log "Waiting for Manager to restart (15s)..."
sleep 15


# 5. Fix Wazuh Dashboard
log "Configuring Wazuh Dashboard..."
docker exec clab-dmz-project-sun-wazuh-dashboard mkdir -p /usr/share/wazuh-dashboard/certs
docker cp dashboard.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/certs/dashboard.pem
docker cp dashboard-key.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/certs/dashboard-key.pem
docker cp root-ca.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/certs/root-ca.pem
docker exec clab-dmz-project-sun-wazuh-dashboard chmod 600 /usr/share/wazuh-dashboard/certs/dashboard-key.pem
docker exec clab-dmz-project-sun-wazuh-dashboard chmod 644 /usr/share/wazuh-dashboard/certs/dashboard.pem
docker exec clab-dmz-project-sun-wazuh-dashboard chmod 644 /usr/share/wazuh-dashboard/certs/root-ca.pem
docker exec clab-dmz-project-sun-wazuh-dashboard chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/certs

# Clean up existing SSL config to avoid duplicates
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i '/server.ssl.key/d' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i '/server.ssl.certificate/d' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i '/opensearch.ssl.certificateAuthorities/d' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

# Apply new config
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/wazuh.indexer/wazuh-indexer/g' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/opensearch.ssl.verificationMode: certificate/opensearch.ssl.verificationMode: none/g' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/server.ssl.enabled: true/server.ssl.enabled: true\nserver.ssl.certificate: \/usr\/share\/wazuh-dashboard\/certs\/dashboard.pem\nserver.ssl.key: \/usr\/share\/wazuh-dashboard\/certs\/dashboard-key.pem\nopensearch.ssl.certificateAuthorities: ["\/usr\/share\/wazuh-dashboard\/certs\/root-ca.pem"]/' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/username: wazuh-wui/username: wazuh/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/password: wazuh-wui/password: wazuh/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/validate_ssl: true/validate_ssl: false/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
# docker exec -u 0 clab-dmz-project-sun-wazuh-dashboard bash -c "cat /usr/share/wazuh-dashboard/certs/root-ca.pem >> /usr/share/wazuh-dashboard/node_modules/@opensearch-project/opensearch/lib/Connection.js" || true # Hacky trust - REMOVED, causes SyntaxError
docker restart clab-dmz-project-sun-wazuh-dashboard


# 6. Install/Fix Agents
log "Installing/Checking Wazuh Agents..."
HOSTS=(
    "clab-dmz-project-sun-webserver"
    "clab-dmz-project-sun-reverse-proxy-waf"
    "clab-dmz-project-sun-db-backend"
    "clab-dmz-project-sun-edge-firewall"
    "clab-dmz-project-sun-internal-firewall"
)
WAZUH_MANAGER="172.20.20.8"

for host in "${HOSTS[@]}"; do
    log "Processing $host..."
    
    # Check if wazuh-agent is installed
    if ! docker exec "$host" dpkg -l | grep -q "wazuh-agent"; then
        log "Installing Wazuh Agent on $host..."
        docker cp wazuh-agent_4.7.3-1_amd64.deb "$host":/tmp/wazuh-agent.deb
        docker exec "$host" bash -c "apt-get update -qq && apt-get install -f -y && apt-get install -y lsb-release curl gnupg"
        docker exec "$host" dpkg -i /tmp/wazuh-agent.deb || docker exec "$host" apt-get install -f -y
    fi
    
    log "Configuring Agent on $host..."
    docker exec "$host" sed -i "s/<address>MANAGER_IP<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf
    
    log "Registering Agent on $host..."
    docker exec "$host" /var/ossec/bin/agent-auth -m $WAZUH_MANAGER || true
    
    log "Starting Agent on $host..."
    docker exec "$host" pkill -f wazuh || true
    sleep 2
    docker exec "$host" /var/ossec/bin/wazuh-control start
done


# 7. Apply Firewall Rules
log "Applying Firewall Rules..."

# Edge Firewall
docker exec clab-dmz-project-sun-edge-firewall bash -c "
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix 'EDGE-FW-INPUT-DROP: '
iptables -A FORWARD -j LOG --log-prefix 'EDGE-FW-FORWARD-DROP: '
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
"

# Internal Firewall
docker exec clab-dmz-project-sun-internal-firewall bash -c "
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth4 -o eth4 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i eth4 -o eth4 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -p tcp --dport 3306 -j ACCEPT
iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT
iptables -A FORWARD -o eth2 -p tcp --dport 1514 -j ACCEPT
iptables -A FORWARD -o eth2 -p udp --dport 514 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix 'INT-FW-INPUT-DROP: '
iptables -A FORWARD -j LOG --log-prefix 'INT-FW-FORWARD-DROP: '
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
"

log "Running final Wazuh Cluster fix..."
bash fix_wazuh_cluster.sh

log "DMZ Secure Startup Complete!"
log "Dashboard: https://localhost:8443 (admin / SecretPassword123!)"
log "You can now run attack scenarios."
