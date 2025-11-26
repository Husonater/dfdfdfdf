#!/bin/bash

echo "--- WAF STARTUP ---"

# 1. Configure Rsyslog for TLS
echo "Configuring Rsyslog TLS..."
cat > /etc/rsyslog.conf <<EOF
module(load="imuxsock")
module(load="imudp")
input(type="imudp" port="514")

module(load="lmnsd_ossl")

global(
    DefaultNetstreamDriver="ossl"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/ssl/certs/client.pem"
    DefaultNetstreamDriverKeyFile="/etc/ssl/private/client.key"
)

# Forward everything to SIEM via TLS
*.* action(
    type="omfwd"
    target="192.168.35.10"
    port="6514"
    protocol="tcp"
    StreamDriver="ossl"
    StreamDriverMode="1"
    StreamDriverAuthMode="anon"
)
EOF

# 2. Start Rsyslog
rsyslogd

# 3. Start Nginx
echo "Starting Nginx..."
nginx -g "daemon off;"
