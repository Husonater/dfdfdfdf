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
PORT=443
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
    docker exec -u 0 "$CONTAINER" /bin/sh -c "sysctl -w net.ipv4.ip_forward=1" > /dev/null 2>&1 || true
    echo "Configuring $1..."
    docker exec -u 0 "$CONTAINER" /bin/sh -c "$2"
}

configure_wazuh_certs() {
    echo "Configuring Wazuh Certificates..."
    mkdir -p certs
    
    # Check if certs exist, if not generate
    if [ ! -f certs/root-ca.pem ]; then
    # Generate Certificates Manually (to ensure DNS SANs are correct)
    echo "Generating Wazuh Certificates..."
    
    # Create config files
    cat > root-ca.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = Wazuh Root CA
EOF

    cat > indexer.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-indexer

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.11
DNS.1 = wazuh-indexer
EOF

    cat > manager.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-manager

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.8
DNS.1 = wazuh-manager
EOF

    cat > dashboard.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-dashboard

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.12
DNS.1 = wazuh-dashboard
EOF

    cat > admin.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = admin

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

    # Generate Root CA
    openssl genrsa -out root-ca.key 4096
    openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.pem -config root-ca.cnf

    # Generate Indexer Cert
    openssl genrsa -out indexer-key.pem 2048
    openssl req -new -key indexer-key.pem -out indexer.csr -config indexer.cnf
    openssl x509 -req -in indexer.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out indexer.pem -days 3650 -sha256 -extensions v3_req -extfile indexer.cnf

    # Generate Manager Cert
    openssl genrsa -out wazuh-manager-key.pem 2048
    openssl req -new -key wazuh-manager-key.pem -out wazuh-manager.csr -config manager.cnf
    openssl x509 -req -in wazuh-manager.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out wazuh-manager.pem -days 3650 -sha256 -extensions v3_req -extfile manager.cnf

    # Generate Dashboard Cert
    openssl genrsa -out dashboard-key.pem 2048
    openssl req -new -key dashboard-key.pem -out dashboard.csr -config dashboard.cnf
    openssl x509 -req -in dashboard.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out dashboard.pem -days 3650 -sha256 -extensions v3_req -extfile dashboard.cnf

    # Generate Admin Cert
    openssl genrsa -out admin-key.pem 2048
    openssl req -new -key admin-key.pem -out admin.csr -config admin.cnf
    openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out admin.pem -days 3650 -sha256 -extensions v3_req -extfile admin.cnf

    # Cleanup
    rm *.csr *.cnf *.srl
    fi

    echo "Distributing certificates..."
    
    # Indexer
    docker cp indexer.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer.pem
    docker cp indexer-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer-key.pem
    docker cp root-ca.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/root-ca.pem
    docker cp admin.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin.pem
    docker cp admin-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin-key.pem

    # Dashboard
    docker cp dashboard.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/dashboard.pem
    docker cp dashboard-key.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/dashboard-key.pem
    docker cp root-ca.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/root-ca.pem

    # Manager
    docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /etc/filebeat/certs
    docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager.pem
    docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager-key.pem
    docker cp root-ca.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/root-ca.pem

    # Manager API Certs
    docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /var/ossec/api/configuration/ssl
    docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.crt
    docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.key
    docker exec clab-dmz-project-sun-wazuh-manager chown -R wazuh:wazuh /var/ossec/api/configuration/ssl
    docker exec clab-dmz-project-sun-wazuh-manager chmod 600 /var/ossec/api/configuration/ssl/server.key
    docker exec clab-dmz-project-sun-wazuh-manager chmod 644 /var/ossec/api/configuration/ssl/server.crt
    
    # Update opensearch.yml with correct admin_dn
    docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US|CN=admin,OU=Wazuh,O=Wazuh,L=San Jose,ST=California,C=US|g' /usr/share/wazuh-indexer/opensearch.yml

    # Distribute certs (This block is now redundant due to the manual generation and distribution above, but keeping for context if needed)
    # echo "Distributing certificates..."
    # Indexer
    # docker cp certs/wazuh-indexer.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer.pem
    # docker cp certs/wazuh-indexer-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer-key.pem
    # docker cp certs/root-ca.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/root-ca.pem
    # docker cp certs/admin.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin.pem
    # docker cp certs/admin-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin-key.pem
    
    # Dashboard
    # docker cp certs/wazuh-dashboard.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/dashboard.pem
    # docker cp certs/wazuh-dashboard-key.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/dashboard-key.pem
    # docker cp certs/root-ca.pem clab-dmz-project-sun-wazuh-dashboard:/usr/share/wazuh-dashboard/config/certs/root-ca.pem
    # Fix dashboard config
    docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/wazuh.indexer/wazuh-indexer/g' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
    
    # Fix Dashboard API Credentials
    docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/username: wazuh-wui/username: admin/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/password: wazuh-wui/password: SecretPassword123!/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    
    # Manager
    # docker cp certs/wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager.pem
    # docker cp certs/wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager-key.pem
    # docker cp certs/root-ca.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/root-ca.pem

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
    docker cp wazuh-template.json clab-dmz-project-sun-wazuh-manager:/etc/filebeat/wazuh-template.json
    docker cp filebeat.yml clab-dmz-project-sun-wazuh-manager:/etc/filebeat/filebeat.yml

    # Initialize Security
    echo "Initializing Wazuh Security..."
    docker restart clab-dmz-project-sun-wazuh-indexer
    echo "Waiting for Indexer to restart..."
    sleep 20
    # Fix admin password hash
    docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG|\$2y\$12\$Ao4b78h7RuRvArs5hkfo2ebILdfE/luW1c5aYFlnlC6Cy8vme8unO|g' /usr/share/wazuh-indexer/opensearch-security/internal_users.yml
    
    docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk clab-dmz-project-sun-wazuh-indexer bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -icl -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost

    # Restart others
    echo "Restarting Manager and Dashboard..."
    docker restart clab-dmz-project-sun-wazuh-manager clab-dmz-project-sun-wazuh-dashboard
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

# 6. Wazuh Manager
# eth1 -> SIEM Switch (192.168.35.10)
clab_exec wazuh-manager "ip addr add 192.168.35.10/24 dev eth1"
clab_exec wazuh-manager "ip route del default || true"
clab_exec wazuh-manager "ip route add default via 192.168.35.1"

# Enable logall in default config
echo "Enabling logall in Wazuh configuration..."
clab_exec wazuh-manager "sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/g' /var/ossec/etc/ossec.conf"
clab_exec wazuh-manager "sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/g' /var/ossec/etc/ossec.conf"

# Restarting Wazuh Manager service to apply configuration (still good practice to ensure clean state)
echo "Restarting Wazuh Manager service..."
clab_exec wazuh-manager "/var/ossec/bin/wazuh-control restart"

# 6a. SIEM Switch (L2 Bridge)
clab_exec siem-switch "apk add --no-cache bridge-utils"
clab_exec siem-switch "brctl addbr br0"
clab_exec siem-switch "brctl addif br0 eth1"
clab_exec siem-switch "brctl addif br0 eth2"
clab_exec siem-switch "brctl addif br0 eth3"
clab_exec siem-switch "brctl addif br0 eth4"
clab_exec siem-switch "ip link set dev br0 up"
clab_exec siem-switch "ip link set dev eth1 up"
clab_exec siem-switch "ip link set dev eth2 up"
clab_exec siem-switch "ip link set dev eth3 up"
clab_exec siem-switch "ip link set dev eth4 up"

# 6b. Wazuh Indexer
# eth1 -> SIEM Switch (192.168.35.11)
clab_exec wazuh-indexer "ip addr add 192.168.35.11/24 dev eth1"
clab_exec wazuh-indexer "ip route del default || true"
clab_exec wazuh-indexer "ip route add default via 192.168.35.1"

# 6c. Wazuh Dashboard
# eth1 -> SIEM Switch (192.168.35.12)
clab_exec wazuh-dashboard "ip addr add 192.168.35.12/24 dev eth1"
clab_exec wazuh-dashboard "ip route del default || true"
clab_exec wazuh-dashboard "ip route add default via 192.168.35.1"

# Configure Wazuh Certs and Security
configure_wazuh_certs

# 7. Client Internal
# eth1 -> Internal Firewall (192.168.40.10)
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 8. IDS
# eth1 -> Edge Firewall (Mirror/Mgmt) - 192.168.61.x
# eth2 -> Internal Firewall (Mirror)
clab_exec ids-dmz "ip link set dev eth1 promisc on"
clab_exec ids-dmz "ip link set dev eth1 up"
clab_exec ids-dmz "ip link set dev eth2 promisc on"
clab_exec ids-dmz "ip link set dev eth2 up"

# Configure Management/Log IP on eth1 (connected to Edge Firewall eth3)
clab_exec edge-firewall "ip addr add 192.168.61.1/24 dev eth3"
clab_exec ids-dmz "ip addr add 192.168.61.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.61.1"

# 9. Database
# eth1 -> Internal Firewall (192.168.70.10)
clab_exec internal-firewall "ip addr add 192.168.70.1/24 dev eth6"
clab_exec db-backend "ip addr add 192.168.70.10/24 dev eth1"
clab_exec db-backend "ip route del default || true"
clab_exec db-backend "ip route add default via 192.168.70.1"


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

# Fix Wazuh Cluster Configuration
echo "Applying Wazuh Cluster Fixes..."
bash fix_wazuh_cluster.sh

echo "--- READY ---"