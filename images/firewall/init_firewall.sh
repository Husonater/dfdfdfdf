#!/bin/bash

echo "--- 🔥 FIREWALL INITIALIZATION ---"

# 1. LOGGING KONFIGURATION (Bleibt gleich)
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
    port="514"
    protocol="udp"
)
EOF
pkill rsyslogd || true
rsyslogd

# 2. FIREWALL REGELN (IPTABLES)
echo "Setting iptables rules..."

# Reset
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Default Policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# --- 🔥 WICHTIG: MIRRORING MUSS ZUERST KOMMEN! ---
# Wir nutzen die MANGLE Tabelle, PREROUTING Chain.
# Das passiert, BEVOR das Routing oder Filter-Regeln greifen.
echo "Activating IDS Mirroring (Priority)..."

# Regel 1: Zum Webserver hin
iptables -t mangle -I PREROUTING 1 -d 192.168.60.20 -j TEE --gateway 192.168.61.30

# Regel 2: Vom Webserver weg
iptables -t mangle -I PREROUTING 1 -s 192.168.60.20 -j TEE --gateway 192.168.61.30

# --- A. BASIS REGELN (Bleibt gleich) ---
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# --- B. ZUGRIFFSREGELN (Bleibt gleich) ---
# Internet -> WAF
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT

# WAF -> Webserver (HTTP)
iptables -A FORWARD -s 192.168.20.10 -d 192.168.60.20 -p tcp --dport 80 -j ACCEPT

# Client -> SIEM
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.35.0/24 -j ACCEPT
# WAF -> SIEM
iptables -A FORWARD -s 192.168.20.10 -d 192.168.35.10 -p udp --dport 514 -j ACCEPT
# IDS -> SIEM (Syslog)
iptables -A FORWARD -s 192.168.61.30 -d 192.168.35.10 -p udp --dport 514 -j ACCEPT

# Webserver -> Database (MySQL)
iptables -A FORWARD -s 192.168.60.20 -d 192.168.70.10 -p tcp --dport 3306 -j ACCEPT
# Database -> SIEM (Syslog)
iptables -A FORWARD -s 192.168.70.10 -d 192.168.35.10 -p udp --dport 514 -j ACCEPT

# --- D. LOGGING & DROP (Bleibt gleich) ---
iptables -A FORWARD -j NFLOG --nflog-group 1 --nflog-prefix "FW-DROP: "
iptables -A FORWARD -j DROP

# 3. LOG COLLECTOR (Bleibt gleich)
echo "Starting TCPDUMP Logger Pipeline..."
pkill tcpdump || true
tcpdump -i nflog:1 -n -l -q 2>/dev/null | logger -t firewall -p local0.warn &

echo "✅ Firewall & Logging Pipeline active!"