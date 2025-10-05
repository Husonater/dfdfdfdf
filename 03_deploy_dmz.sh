#!/bin/bash
# --- DMZ Deployment and Configuration Script (Phase 2) ---
# Automated deployment of the DMZ topology using Docker Compose and Containerlab.
# This script executes all necessary steps for image building, topology deployment,
# and initial network configuration (IPs, Routing, Firewall rules).

# --------------------------------------------------------
# 0.5. CREATE DIRECTORY STRUCTURE AND COPY CONFIGS
# (Stellt sicher, dass alle Dockerfiles und Configs fuer den Build vorhanden sind)
# --------------------------------------------------------
echo "--- 0.5. CREATING DIRECTORY STRUCTURE AND COPYING CONFIGS ---"

# Create all necessary directories
mkdir -p images/waf images/ids images/siem images/attacker images/webserver images/firewall config/waf

# --- DOCKERFILE DEFINITIONEN (Diese Files werden im Build-Kontext benoetigt) ---

# Dockerfile for Attacker (kali-linux base)
cat > images/attacker/Dockerfile <<EOF
FROM kalilinux/kali-rolling
# Install basic network and attack tools
RUN apt-get update && apt-get install -y iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump -y && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
EOF

# Dockerfile for IDS (Suricata on Debian base)
cat > images/ids/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
CMD ["/usr/local/bin/startup_ids.sh"]
EOF

# Dockerfile for SIEM (Rsyslog receiver)
cat > images/siem/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash && rm -rf /var/lib/apt/lists/*
# Kopiere rsyslog config
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
# Startet rsyslog und haelt den Container am Laufen
CMD ["bash", "-c", "rsyslogd -n & tail -f /var/log/siem_logs/suricata_alerts.log"]
EOF

# Dockerfile for WAF (Nginx with ModSecurity)
cat > images/waf/Dockerfile <<EOF
FROM owasp/modsecurity-crs:nginx-alpine
# Standard-ModSecurity/Nginx-Image mit OWASP CRS
# Das Image bringt ModSecurity und Nginx bereits mit.
RUN mkdir -p /etc/nginx/modsecurity.d
# Kopiere die custom configs
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf
CMD ["nginx", "-g", "daemon off;"]
EOF

# Dockerfile for Webserver
cat > images/webserver/Dockerfile <<EOF
FROM php:8.2-apache
# Installiere grundlegende Tools
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
# Einfache Index-Seite (simuliert die unternehmenskritische Anwendung)
RUN echo "<h1>Webserver is running!</h1><p>Client IP: \$_SERVER['REMOTE_ADDR']</p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
EOF

# Dockerfile for Firewall (Zusaetzliches Image, um die IP-Tools zu haben)
cat > images/firewall/Dockerfile <<EOF
FROM alpine:latest
RUN apk update && apk add bash iproute2 iptables
CMD ["sleep", "infinity"]
EOF

# --- KONFIGURATIONEN (Wird in Dockerfiles kopiert) ---
cat > images/waf/nginx.conf <<EOF
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" ' '\$status \$body_bytes_sent "\$http_referer" ' '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
    server {
        listen 80;
        server_name localhost;
        location / {
            include /etc/nginx/modsecurity.d/modsecurity-crs.conf;
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
SecAuditLogParts ABIFHZ
SecAuditLog /var/log/modsec_audit.log
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0
SecMarker my_unique_marker
EOF
cat > images/ids/startup_ids.sh <<EOF
#!/bin/bash
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.30.10 --set output.syslog.port=514 -D
echo "Suricata IDS started on eth1 and logging to 192.168.30.10:514."
tail -f /var/log/suricata/fast.log
EOF
chmod +x images/ids/startup_ids.sh
cat > images/siem/rsyslog_receiver.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfile" file="/var/log/siem_logs/suricata_alerts.log")
EOF

echo "Directory structure and initial configurations created."

# --------------------------------------------------------
# 1. IMAGE BUILD (with Docker Compose)
# --------------------------------------------------------
echo "--- 1. BUILDING CUSTOM DOCKER IMAGES (WAF, IDS, SIEM, ATTACKER) ---"
# Fix: Using legacy docker-compose syntax to avoid WSL BuildX errors.
sudo docker-compose -f docker-compose.build.yaml build
if [ $? -ne 0 ]; then
    echo "FATAL ERROR: Docker image build failed. Aborting."
    exit 1
fi
echo "Docker images successfully built."

# --------------------------------------------------------
# 2. CONTAINERLAB DEPLOYMENT
# --------------------------------------------------------
echo "--- 2. CONTAINERLAB DEPLOYMENT ---"
# Zuerst destroy, um sauberen Start zu gewaehrleisten.
sudo containerlab destroy --topo dmz_topology.yaml > /dev/null 2>&1
# Deploy
sudo containerlab deploy --topo dmz_topology.yaml
if [ $? -ne 0 ]; then
    echo "FATAL ERROR: Containerlab deployment failed. Aborting. Check dmz_topology.yaml for conflicts."
    exit 1
fi
echo "Containerlab topology deployed successfully."
sleep 5 # Kurze Wartezeit, um sicherzustellen, dass alle Container hochgefahren sind


# --------------------------------------------------------
# 3. Initial IP and Routing Configuration
# --------------------------------------------------------

# Die Netzwerke:
# 192.168.10.0/24: Internet/External Net (Edge-Router <-> Firewall)
# 192.168.20.0/24: DMZ Net (Firewall <-> WAF/IDS/Internal-Router)
# 192.168.30.0/24: Backend Net (Internal-Router <-> SIEM)
# 192.168.40.0/24: Client/Internal Net (Internal-Router <-> Client)

echo "--- 3. CONFIGURING IP ADDRESSES AND ROUTES ---"

# Hilfsfunktion, um Befehle in Containern auszuführen
clab_exec() {
    # FIX: Verwende /bin/sh, da es universeller ist und den "bash: executable file not found" Fehler behebt
    sudo docker exec -it clab-dmz-project-sun-$1 /bin/sh -c "$2"
}

# --- EDGE ROUTER Konfiguration (Internet) ---
clab_exec edge-router "ip addr add 192.168.10.1/24 dev eth2"  # Zum Internet-Netz
clab_exec edge-router "ip route add 192.168.20.0/24 via 192.168.10.2" # Route zur DMZ
clab_exec edge-router "ip route add 192.168.30.0/24 via 192.168.10.2" # Route zum Backend
clab_exec edge-router "ip route add 192.168.40.0/24 via 192.168.10.2" # Route zum Client-Netz
clab_exec edge-router "sysctl -w net.ipv4.ip_forward=1"       # IP-Forwarding aktivieren

# --- FIREWALL Konfiguration ---
clab_exec firewall-in "ip addr add 192.168.10.2/24 dev eth1"  # Zum Edge-Router (Internet)
clab_exec firewall-in "ip addr add 192.168.20.1/24 dev eth2"  # Zur DMZ
clab_exec firewall-in "ip addr add 192.168.30.1/24 dev eth3"  # Zum Internal-Router (Backend)
clab_exec firewall-in "sysctl -w net.ipv4.ip_forward=1"       # IP-Forwarding aktivieren

# --- FIREWALL IPtables Setup (Grundregeln) ---
echo "Configuring basic firewall rules..."
# * FLUSH all current rules
clab_exec firewall-in "iptables -F"
clab_exec firewall-in "iptables -X"
clab_exec firewall-in "iptables -t nat -F"
clab_exec firewall-in "iptables -t nat -X"
clab_exec firewall-in "iptables -t filter -P INPUT DROP"  # Default DROP IN
clab_exec firewall-in "iptables -t filter -P FORWARD DROP" # Default DROP FORWARD
clab_exec firewall-in "iptables -t filter -P OUTPUT ACCEPT" # Default ACCEPT OUT

# * ERLAUBEN: Traffic von Edge-Router (Internet) -> WAF/Proxy (Port 80/443)
WAF_IP="192.168.20.10" 
clab_exec firewall-in "iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 80 -d ${WAF_IP} -j ACCEPT"
clab_exec firewall-in "iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 443 -d ${WAF_IP} -j ACCEPT"

# * ERLAUBEN: Antworten auf erlaubten Verkehr
clab_exec firewall-in "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"

# * VERWEIGERN: DMZ -> Backend (standardmäßig blockieren)
clab_exec firewall-in "iptables -A FORWARD -i eth2 -o eth3 -j DROP"

# --- DMZ KOMPONENTEN Konfiguration (nur IPs) ---
clab_exec reverse-proxy-waf "ip addr add 192.168.20.10/24 dev eth1" # DMZ-Eingang
clab_exec reverse-proxy-waf "ip addr add 192.168.20.11/24 dev eth2" # Verbindung Internal Router
clab_exec webserver "ip addr add 192.168.20.20/24 dev eth1"
clab_exec ids-dmz "ip addr add 192.168.20.30/24 dev eth1" # IDS-Monitoring

# --- INTERNAL ROUTER Konfiguration ---
clab_exec internal-router "ip addr add 192.168.20.2/24 dev eth1"  # Zur DMZ (Hauptverbindung zur Firewall)
clab_exec internal-router "ip addr add 192.168.30.2/24 dev eth2"  # Zum Backend
clab_exec internal-router "ip addr add 192.168.40.1/24 dev eth3"  # Zum Client-Netz
clab_exec internal-router "ip addr add 192.168.20.4/24 dev eth4"  # Zum WAF-Proxy (eth4)
clab_exec internal-router "ip addr add 192.168.20.5/24 dev eth5"  # Zum Webserver (eth5)
clab_exec internal-router "ip addr add 192.168.20.6/24 dev eth7"  # Zum IDS (eth7)
clab_exec internal-router "sysctl -w net.ipv4.ip_forward=1"       # IP-Forwarding aktivieren

# Setze Default Gateways (Routen)
clab_exec reverse-proxy-waf "ip route add default via 192.168.20.2" # Über Internal Router, dann zur FW
clab_exec webserver "ip route add default via 192.168.20.2" # Über Internal Router
clab_exec ids-dmz "ip route add default via 192.168.20.2" # Über Internal Router
clab_exec client-internal "ip route add default via 192.168.40.1" # Über Internal Router
clab_exec siem-backend "ip route add default via 192.168.30.2" # Über Internal Router
clab_exec attacker-internet "ip route add default via 192.168.10.1" # Über Edge Router

echo "--- DEPLOYMENT COMPLETED ---"
echo "DMZ is running. Next step: Service Configuration and Attack Testing."
