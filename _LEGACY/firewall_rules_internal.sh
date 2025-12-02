#!/bin/bash
# Internal Firewall Rules (DMZ → Backend)

SUDO_PASSWORD="Destiny2004"

echo "Applying Internal Firewall Rules..."

echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-internal-firewall bash << 'RULES'
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies: DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow WAF → Webserver (HTTP/HTTPS)
iptables -A FORWARD -i eth4 -o eth4 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i eth4 -o eth4 -p tcp --dport 443 -j ACCEPT

# Allow Webserver → Database (MySQL/PostgreSQL)
iptables -A FORWARD -p tcp --dport 3306 -j ACCEPT
iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT

# Allow to SIEM (Wazuh)
iptables -A FORWARD -o eth2 -p tcp --dport 1514 -j ACCEPT
iptables -A FORWARD -o eth2 -p udp --dport 514 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "INT-FW-INPUT-DROP: "
iptables -A FORWARD -j LOG --log-prefix "INT-FW-FORWARD-DROP: "

# Save rules
iptables-save > /etc/iptables/rules.v4

echo "Internal Firewall rules applied!"
iptables -L -n -v
RULES

echo "  ✓ Internal Firewall configured"
