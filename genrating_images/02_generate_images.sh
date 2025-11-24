#!/bin/bash
set -e

echo "--- 2. CREATING DIRECTORY STRUCTURE ---"
mkdir -p ../images/waf ../images/ids ../images/siem ../images/attacker ../images/webserver ../images/firewall ../config/waf


# 1. ATTACKER
cat > ../images/attacker/Dockerfile <<EOF
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y iproute2 iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump procps && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
EOF

# 2. IDS
cat > ../images/ids/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog procps curl && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
CMD ["sleep", "infinity"]
EOF

# 3. SIEM
cat > ../images/siem/Dockerfile <<EOF
FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash procps tcpdump && rm -rf /var/lib/apt/lists/*
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
CMD ["sleep", "infinity"]
EOF

# 4. WAF (MANUAL CONTROL)
cat > ../images/waf/Dockerfile <<EOF
FROM owasp/modsecurity-crs:nginx-alpine
USER root
RUN apk update && apk add --no-cache iproute2 bash curl net-tools

# Logs auf stdout
RUN mkdir -p /var/log/nginx && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

# Configs direkt kopieren
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf

# Permissions
RUN chmod -R 777 /var/log/nginx /etc/nginx /var/run

# Entrypoint leeren & Sleep -> KEIN AUTOSTART
ENTRYPOINT []
CMD ["sleep", "infinity"]
EOF

# 5. WEBSERVER
cat > ../images/webserver/Dockerfile <<EOF
FROM php:8.2-apache
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
RUN echo "<h1>Webserver is running!</h1><p>Client IP: \$_SERVER['REMOTE_ADDR']</p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
EOF

# 6. FIREWALL
cat > ../images/firewall/Dockerfile <<EOF
FROM alpine:latest
RUN apk update && apk add bash iproute2 iptables conntrack-tools
CMD ["sleep", "infinity"]
EOF

# --- CONFIG FILES ---

# Nginx Config: MINIMAL & SAFE
cat > ../images/waf/nginx.conf <<EOF
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;

# Run as root to avoid permission issues
user root;
worker_processes 1;
error_log /dev/stderr warn;
pid /var/run/nginx.pid;
events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /dev/stdout;
    sendfile on;
    keepalive_timeout 65;

    # ModSecurity aktivieren
    modsecurity on;
    
    server {
        listen 80;
        server_name localhost;
        
        location / {
            # Rules laden
            modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
            
            proxy_pass http://192.168.25.20;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
EOF

# ModSecurity: SAFE MODE (No Audit Log, Custom Rule Only)
cat > ../images/waf/modsecurity.conf <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Audit Engine AUS = Kein Crash
SecAuditEngine Off
SecDebugLogLevel 0

# UNSERE TEST REGEL (Blockt SQLi mit 403)
SecRule ARGS "1' OR '1'='1" "id:1001,phase:2,log,deny,status:403,msg:'SQL Injection Test Blocked'"
EOF

cat > ../images/ids/startup_ids.sh <<'EOF'
#!/bin/bash
mkdir -p /var/log/suricata
touch /var/log/suricata/fast.log
rm -f /var/run/suricata.pid || true
sleep 5
suricata -i eth1 --set output.syslog.enabled=yes --set output.syslog.address=192.168.35.10 --set output.syslog.port=514 -D
EOF
chmod +x ../images/ids/startup_ids.sh

cat > ../images/siem/rsyslog_receiver.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfile" file="/var/log/siem_logs/suricata_alerts.log")
EOF

echo "Success"