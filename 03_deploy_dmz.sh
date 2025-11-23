#!/bin/bash
set -e

# --------------------------------------------------------
# DMZ Deployment Script (FINAL FIX: Routing Crash Resolved)
# --------------------------------------------------------

echo "--- 0. CLEANUP & PREPARATION ---"
sudo containerlab destroy --topo dmz_topology.yaml --cleanup || true

echo "--- 1. CREATING DIRECTORY STRUCTURE ---"
mkdir -p images/waf images/ids images/siem images/attacker images/webserver images/firewall config/waf

# --- DOCKERFILES ---
cat > images/attacker/Dockerfile <<EOF
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y iproute2 iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
EOF

cat > images/ids/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog procps && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
CMD ["sleep", "infinity"]
EOF

cat > images/siem/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash procps && rm -rf /var/lib/apt/lists/*
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
CMD ["sleep", "infinity"]
EOF

cat > images/waf/Dockerfile <<EOF
FROM owasp/modsecurity-crs:nginx-alpine
USER root
RUN apk update && apk add --no-cache iproute2 bash
RUN mkdir -p /etc/nginx/modsecurity.d
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf
RUN chmod -R 0777 /etc/nginx/modsecurity.d || true
RUN chown -R nginx:nginx /etc/nginx/modsecurity.d || true
CMD ["sleep", "infinity"]
EOF

cat > images/webserver/Dockerfile <<EOF
FROM php:8.2-apache
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
RUN echo "<h1>Webserver is running!</h1><p>Client IP: \$_SERVER['REMOTE_ADDR']</p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
EOF

cat > images/firewall/Dockerfile <<EOF
FROM alpine:latest
RUN apk update && apk add bash iproute2 iptables
CMD ["sleep", "infinity"]
EOF

# --- CONFIG FILES ---
cat > images/waf/nginx.conf <<EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    sendfile on;
    keepalive_timeout 65;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
    server {
        listen 80;
        server_name localhost;
        location / {
            modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
            proxy_pass http://192.168.20.20;
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
EOF

cat > images/ids/startup_ids.sh <<'EOF'
#!/bin/bash
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
EOF
chmod +x images/ids/startup_ids.sh

cat > images/siem/rsyslog_receiver.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfile" file="/var/log/siem_logs/suricata_alerts.log")
EOF

echo "--- 2. BUILDING IMAGES ---"
sudo docker compose -f docker-compose.build.yaml build

echo "--- 3. DEPLOYING TOPOLOGY ---"
sudo containerlab deploy --topo dmz_topology.yaml

echo "--- 4. CONFIGURING NETWORK (IPs & Routes) ---"

clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    echo "Configuring $1..."
    sudo docker exec "$CONTAINER" /bin/sh -c "$2"
}

# --- EDGE ROUTER ---
# eth1 -> Firewall (192.168.10.x)
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth1"
# eth2 -> Internet/Attacker (NEW SUBNET: 172.16.1.x)
clab_exec edge-router "ip addr add 172.16.1.1/24 dev eth2"
# Routes
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"
clab_exec edge-router "sysctl -w net.ipv4.ip_forward=1"

# --- FIREWALL ---
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"
clab_exec firewall-in "sysctl -w net.ipv4.ip_forward=1"
# FIX: Delete default route before adding new one to prevent crash
clab_exec firewall-in "ip route del default || true"
clab_exec firewall-in "ip route add default via 192.168.10.1"

# --- DMZ Components ---
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip addr add 192.168.20.11/24 dev eth2"
clab_exec reverse-proxy-waf "ip route del default || true"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.2"

clab_exec webserver "ip addr add 192.168.20.20/24 dev eth1"
clab_exec webserver "ip route del default || true"
clab_exec webserver "ip route add default via 192.168.20.2"

clab_exec ids-dmz "ip addr add 192.168.20.30/24 dev eth1"
clab_exec ids-dmz "ip route del default || true"
clab_exec ids-dmz "ip route add default via 192.168.20.2"

# --- Internal Router ---
clab_exec internal-router "ip addr add 192.168.20.2/24 dev eth1"
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth2"
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-router "sysctl -w net.ipv4.ip_forward=1"
clab_exec internal-router "ip route del default || true"
clab_exec internal-router "ip route add default via 192.168.20.1"

# --- ENDPOINTS ---
# 1. Attacker (172.16.1.x)
clab_exec attacker-internet "ip addr add 172.16.1.10/24 dev eth1"
clab_exec attacker-internet "ip route del default || true"
clab_exec attacker-internet "ip route add default via 172.16.1.1"

# 2. Client Internal
clab_exec client-internal "ip addr add 192.168.40.10/24 dev eth1"
clab_exec client-internal "ip route del default || true"
clab_exec client-internal "ip route add default via 192.168.40.1"

# 3. SIEM
clab_exec siem-backend "ip addr add 192.168.30.10/24 dev eth1"
clab_exec siem-backend "ip route del default || true"
clab_exec siem-backend "ip route add default via 192.168.30.2"

echo "--- 5. STARTING SERVICES ---"
sudo docker exec -d clab-dmz-project-sun-siem-backend rsyslogd -n
sudo docker exec -d clab-dmz-project-sun-reverse-proxy-waf nginx
sudo docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

echo "--- 6. FIREWALL RULES ---"
clab_exec firewall-in "iptables -P FORWARD DROP"
clab_exec firewall-in "iptables -F && iptables -t nat -F"
clab_exec firewall-in "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.30.0/24 -j ACCEPT"

echo "--- READY ---"