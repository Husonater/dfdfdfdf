#!/bin/bash
set -e # Stop script immediately if any command fails

# --------------------------------------------------------
# DMZ Deployment Script (Fixed for Race Conditions)
# --------------------------------------------------------

echo "--- 0. CLEANUP & PREPARATION ---"
# Clean up any previous lab instances to avoid "file exists" errors
sudo containerlab destroy --topo dmz_topology.yaml --cleanup || true

echo "--- 1. CREATING DIRECTORY STRUCTURE AND CONFIGS ---"

mkdir -p images/waf images/ids images/siem images/attacker images/webserver images/firewall config/waf

# --- DOCKERFILES (Using 'sleep infinity' to ensure stability during network linking) ---

# 1. ATTACKER
cat > images/attacker/Dockerfile <<EOF
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y iproute2 iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
EOF

# 2. IDS (Suricata)
cat > images/ids/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog procps && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
# Start sleeping to let Containerlab link interfaces first
CMD ["sleep", "infinity"]
EOF

# 3. SIEM (Rsyslog)
cat > images/siem/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash procps && rm -rf /var/lib/apt/lists/*
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
CMD ["sleep", "infinity"]
EOF

# 4. WAF (Nginx/ModSec)
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
RUN apk update && apk add bash iproute2 iptables
CMD ["sleep", "infinity"]
EOF

# --- CONFIGURATION FILES ---

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
# Script to manually start Suricata after network is ready
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true

# Start Suricata in background (Daemon mode)
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
EOF
chmod +x images/ids/startup_ids.sh

cat > images/siem/rsyslog_receiver.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfile" file="/var/log/siem_logs/suricata_alerts.log")
EOF

echo "--- 2. BUILDING IMAGES ---"
# Use standard build to avoid WSL/BuildX context issues
sudo docker compose -f docker-compose.build.yaml build

echo "--- 3. DEPLOYING TOPOLOGY ---"
sudo containerlab deploy --topo dmz_topology.yaml

echo "--- 4. CONFIGURING NETWORK (IPs & Routes) ---"

# Helper function to execute commands inside containers
clab_exec() {
    CONTAINER=clab-dmz-project-sun-$1
    echo "Configuring $1..."
    # We use -d (detach) for background services, but here we wait for ip commands
    sudo docker exec "$CONTAINER" /bin/sh -c "$2"
}

# --- Edge Router ---
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth2"
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2"
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2"
clab_exec edge-router "sysctl -w net.ipv4.ip_forward=1"

# --- Firewall ---
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"
clab_exec firewall-in "sysctl -w net.ipv4.ip_forward=1"

# --- DMZ Components ---
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1"
clab_exec reverse-proxy-waf "ip addr add 192.168.20.11/24 dev eth2"
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.2"

clab_exec webserver "ip addr add 192.168.20.20/24 dev eth1"
clab_exec webserver "ip route add default via 192.168.20.2"

clab_exec ids-dmz "ip addr add 192.168.20.30/24 dev eth1"
clab_exec ids-dmz "ip route add default via 192.168.20.2"

# --- Internal Router ---
clab_exec internal-router "ip addr add 192.168.20.2/24 dev eth1"
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth2"
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"
clab_exec internal-router "sysctl -w net.ipv4.ip_forward=1"

# --- Endpoints ---
clab_exec client-internal "ip route add default via 192.168.40.1"
clab_exec siem-backend "ip route add default via 192.168.30.2"
clab_exec attacker-internet "ip route add default via 192.168.10.1"

echo "--- 5. STARTING APPLICATION SERVICES ---"
# Now that network interfaces exist, we start the services manually.

echo "Starting SIEM Rsyslog..."
sudo docker exec -d clab-dmz-project-sun-siem-backend rsyslogd -n

echo "Starting WAF Nginx..."
sudo docker exec -d clab-dmz-project-sun-reverse-proxy-waf nginx

echo "Starting IDS Suricata..."
sudo docker exec clab-dmz-project-sun-ids-dmz /usr/local/bin/startup_ids.sh

echo "--- 6. APPLYING FIREWALL RULES ---"
# Reset Rules
clab_exec firewall-in "iptables -F && iptables -t nat -F"
clab_exec firewall-in "iptables -P FORWARD DROP"

# Allow Established
clab_exec firewall-in "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"

# Allow HTTP/HTTPS from Internet to WAF
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT"

echo "--- DEPLOYMENT SUCCESSFUL ---"
echo "Lab is ready. You can now test connectivity."