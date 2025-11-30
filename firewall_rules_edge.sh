#!/bin/bash
# Edge Firewall Rules (Internet → DMZ)

SUDO_PASSWORD="Destiny2004"

echo "Applying Edge Firewall Rules..."

echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-edge-firewall bash << 'RULES'
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

# Allow HTTP/HTTPS from Internet to DMZ
iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 443 -j ACCEPT

# Allow SSH for management (optional, remove in production)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "EDGE-FW-INPUT-DROP: "
iptables -A FORWARD -j LOG --log-prefix "EDGE-FW-FORWARD-DROP: "

# Save rules
iptables-save > /etc/iptables/rules.v4

echo "Edge Firewall rules applied!"
iptables -L -n -v
RULES

echo "  ✓ Edge Firewall configured"
