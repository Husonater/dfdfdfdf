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

cat > ../images/waf/modsecurity.conf <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0

# --- MANUAL SECURITY RULES ---

# 1. SQL Injection
SecRule ARGS "1' OR '1'='1" "id:1001,phase:2,log,deny,status:403,msg:'SQL Injection Blocked'"

# 2. Path Traversal (Schaut auch in Parameter ARGS, nicht nur URI)
SecRule REQUEST_URI|ARGS "\.\./" "id:1002,phase:2,log,deny,status:403,msg:'Path Traversal Blocked'"

# 3. XSS
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES "<script>" "id:1003,phase:2,log,deny,status:403,msg:'XSS Blocked'"

# 4. Shell Injection (ERWEITERT: Blockiert jetzt auch 'cat /etc' und ';')
SecRule ARGS "cmd=|/bin/sh|/bin/bash|cat /etc|;cat" "id:1004,phase:2,log,deny,status:403,msg:'Shell Injection Blocked'"
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

# NGINX (Run as root = No Permission Crashes)
cat > ../images/waf/nginx.conf <<EOF
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
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
    modsecurity on;
    
    server {
        listen 80;
        server_name localhost;
        location / {
            modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
            proxy_pass http://192.168.25.20;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
EOF

# MODSECURITY (NO AUDIT = NO CRASH / ALL RULES ADDED)
cat > ../images/waf/modsecurity.conf <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
# CRITICAL: Turn off Audit to prevent Disk I/O crashes
SecAuditEngine Off
SecDebugLogLevel 0

# --- MANUAL SECURITY RULES ---

# 1. SQL Injection (Block ' OR '1'='1)
SecRule ARGS "1' OR '1'='1" "id:1001,phase:2,log,deny,status:403,msg:'SQL Injection Blocked'"

# 2. Path Traversal (Block ../..)
SecRule REQUEST_URI "\.\./" "id:1002,phase:1,log,deny,status:403,msg:'Path Traversal Blocked'"

# 3. XSS (Block <script>)
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES "<script>" "id:1003,phase:2,log,deny,status:403,msg:'XSS Blocked'"

# 4. Shell Injection (Block cmd= or /bin/sh)
SecRule ARGS "cmd=|/bin/sh|/bin/bash" "id:1004,phase:2,log,deny,status:403,msg:'Shell Injection Blocked'"
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