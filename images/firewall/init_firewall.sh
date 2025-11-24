#!/bin/bash

# --- 1. LOGGING CONFIG ---
echo "Konfiguriere Logging zum SIEM..."
if ! grep -q "@192.168.35.10:514" /etc/rsyslog.conf; then
    echo '*.* @192.168.35.10:514' >> /etc/rsyslog.conf
fi

# Rsyslog starten
pkill rsyslogd || true
rsyslogd

# Ulogd starten (Der Übersetzer von Firewall zu Syslog)
# Wir starten ihn als Daemon (-d)
pkill ulogd || true
ulogd -d -c /etc/ulogd.conf

# --- 2. FIREWALL REGELN ---
echo "Setze Firewall Regeln..."

iptables -F
iptables -t nat -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# A. Self-Traffic & ICMP
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

# B. Forwarding - ALLOW LIST
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT
iptables -A FORWARD -s 192.168.20.10 -d 192.168.25.20 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.35.0/24 -j ACCEPT

# C. LOGGING (Das ist neu!)
# Statt "-j LOG" nutzen wir "-j NFLOG".
# group 1 passt zu unserer ulogd.conf
# prefix funktioniert hier auch.
iptables -A FORWARD -j NFLOG --nflog-group 1 --nflog-prefix "FW-DROP: "

# D. EXPLICIT DENY
iptables -A FORWARD -j DROP

echo "✅ Firewall (mit NFLOG) gestartet!"