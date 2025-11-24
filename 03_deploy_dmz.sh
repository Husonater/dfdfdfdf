#!/bin/bash
set -e

# --------------------------------------------------------
# DMZ Deployment Script (STABLE + MODULE FIX)
# --------------------------------------------------------

echo "--- 0. CLEANUP ---"
sudo containerlab destroy --topo dmz_topology.yaml --cleanup || true
sudo docker rm -f $(sudo docker ps -a -q --filter "label=containerlab=dmz-project-sun") 2>/dev/null || true
sudo docker network prune -f >/dev/null 2>&1
sudo rm -rf images config || true

echo "--- 1. GENERATING TOPOLOGY FILE ---"
cat > dmz_topology.yaml <<EOF
name: dmz-project-sun
topology:
  nodes:
    attacker-internet:
      kind: linux
      image: attacker:latest
    edge-router:
      kind: linux
      image: frrouting/frr:latest
    firewall-in:
      kind: linux
      image: firewall:latest
    reverse-proxy-waf:
      kind: linux
      image: waf:latest
    internal-router:
      kind: linux
      image: frrouting/frr:latest
    webserver:
      kind: linux
      image: webserver:latest
    ids-dmz:
      kind: linux
      image: ids:latest
    siem-backend:
      kind: linux
      image: siem:latest
    client-internal:
      kind: linux
      image: attacker:latest

  links:
    - endpoints: ["attacker-internet:eth1", "edge-router:eth2"]
    - endpoints: ["edge-router:eth1", "firewall-in:eth1"]
    - endpoints: ["firewall-in:eth2", "reverse-proxy-waf:eth1"]
    - endpoints: ["firewall-in:eth3", "internal-router:eth1"]
    - endpoints: ["internal-router:eth2", "siem-backend:eth1"]
    - endpoints: ["internal-router:eth3", "client-internal:eth1"]
    - endpoints: ["internal-router:eth5", "webserver:eth1"]
    - endpoints: ["internal-router:eth7", "ids-dmz:eth1"]
EOF

echo "--- 2. CREATING DIRECTORY STRUCTURE ---"
mkdir -p images/waf images/ids images/siem images/attacker images/webserver images/firewall config/waf

# --- DOCKERFILES ---

# 1. ATTACKER
cat > images/attacker/Dockerfile <<EOF
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y iproute2 iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump procps && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
EOF

# 2. IDS
cat > images/ids/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog procps curl && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
CMD ["sleep", "infinity"]
EOF

# 3. SIEM
cat > images/siem/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash procps tcpdump && rm -rf /var/lib/apt/lists/*
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
CMD ["sleep", "infinity"]
EOF

# 4. WAF (SLEEP STRATEGY)
cat > images/waf/Dockerfile <<EOF
FROM owasp/modsecurity-crs:nginx-alpine
USER root
RUN apk update && apk add --no-cache iproute2 bash curl net-tools

# Logs
RUN mkdir -p /var/log/nginx && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

# Configs direkt kopieren
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf

# Permissions fixen
RUN chmod -R 777 /var/log/nginx /etc/nginx /var/run

# CRITICAL: Entrypoint leeren & Sleep
ENTRYPOINT []
CMD ["sleep", "infinity"]
EOF

# 5. WEBSERVER
cat > images/webserver/Dockerfile <<EOF
FROM php:8.2-apache
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
RUN echo "<h1>Webserver is running!</h1><p>Client IP: \$_SERVER['REMOTE_ADDR']</p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
EOF

# 6. FIREWALL
cat > images/firewall/Dockerfile <<EOF
FROM alpine:latest
RUN apk update && apk add bash iproute2 iptables conntrack-tools
CMD ["sleep", "infinity"]
EOF

# --- CONFIG FILES ---

# FIX: Explicit Load Module + Correct Config Structure
cat > images/waf/nginx.conf <<EOF
# 1. Modul explizit laden (Der Pfad ist Standard für nginx-alpine Images)
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;

worker_processes auto;
error_log /dev/stderr warn;
pid /var/run/nginx.pid;
events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /dev/stdout;
    sendfile on;
    keepalive_timeout 65;

    # 2. ModSecurity Global aktivieren
    modsecurity on;
    # Hinweis: Wir laden hier KEINE Rules, nur im Location Block, um Duplikate zu vermeiden
    
    server {
        listen 80;
        server_name localhost;
        
        location / {
            # 3. Rules laden (vermeidet "Duplicate Rule ID" Fehler)
            modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
            
            proxy_pass http://192.168.25.20;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
EOF

cat > images/waf/modsecurity.conf <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0

# Test-Regel für SQL Injection Check
SecRule ARGS "1' OR '1'='1" "id:1001,phase:2,log,deny,status:403,msg:'SQL Injection Test Blocked'"
EOF

cat > images/ids/startup_ids.sh <<'EOF'
#!/bin/bash
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true
sleep 5
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.35.10 --set output.syslog.port=514 -D
EOF
chmod +x images/ids/startup_ids.sh

cat > images/siem/rsyslog_receiver.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfile" file="/var/log/siem_logs/suricata_alerts.log")
EOF

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

# --- EDGE ROUTER ---
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.25.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.35.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"

# --- DMZ WAF ---
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.1"

# --- FIREWALL ---
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"
clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"
clab_exec firewall-in "ip route add 192.168.25.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.22.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.35.0/24 via 192.168.30.2" 
clab_exec firewall-in "ip route add 192.168.40.0/24 via 192.168.30.2" 

# --- INTERNAL ROUTER ---
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth1"
clab_exec internal-router "ip addr add 192.168.35.1/24 dev eth2"
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-router "ip addr add 192.168.25.1/24 dev eth5"
clab_exec internal-router "ip addr add 192.168.22.1/24 dev eth7"
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.30.1" 

# --- OTHERS ---
clab_exec webserver "ip addr add 192.168.25.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.25.1"

clab_exec ids-dmz "ip addr add 192.168.22.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.22.1"

# --- ENDPOINTS ---
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route replace default via 172.16.1.1 dev eth1"

clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

clab_exec siem-backend "ip addr add 192.168.35.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.35.1"

echo "--- 7. STARTING SERVICES (MANUAL) ---"
sudo docker exec -d clab-dmz-project-sun-siem-backend rsyslogd -n
sudo docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

echo "Starting WAF Nginx..."
# Start Nginx in background
sudo docker exec -d clab-dmz-project-sun-reverse-proxy-waf nginx -g "daemon off;" 
sleep 2

# Check
if sudo docker exec clab-dmz-project-sun-reverse-proxy-waf ps aux | grep "nginx: master" > /dev/null; then
    echo "WAF started successfully."
else
    echo "ERROR: WAF failed to start. Logs:"
    sudo docker exec clab-dmz-project-sun-reverse-proxy-waf nginx -t || true
fi

echo "--- 8. FIREWALL RULES ---"
clab_exec firewall-in "iptables -F && iptables -t nat -F"
clab_exec firewall-in "iptables -P INPUT DROP"
clab_exec firewall-in "iptables -P FORWARD DROP"
clab_exec firewall-in "iptables -P OUTPUT ACCEPT"

# Traffic Rules
clab_exec firewall-in "iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
clab_exec firewall-in "iptables -A INPUT -p icmp -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p icmp -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -s 192.168.20.10 -d 192.168.25.20 -p tcp --dport 80 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.35.0/24 -j ACCEPT"

echo "--- READY ---"