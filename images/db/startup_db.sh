#!/bin/bash

echo "--- DB STARTUP ---"

# 1. Configure Rsyslog for TLS
echo "Configuring Rsyslog TLS..."
cat > /etc/rsyslog.conf <<EOF
module(load="imuxsock")
module(load="lmnsd_ossl")

global(
    DefaultNetstreamDriver="ossl"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/ssl/certs/client.pem"
    DefaultNetstreamDriverKeyFile="/etc/ssl/private/client.key"
)

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

# 3. Start MariaDB
echo "Starting MariaDB..."
exec mariadbd
