#!/bin/bash

# --- 1. CONFIG: RSYSLOG ---
echo "Konfiguriere Logging..."

# Rsyslog Config (Der Standard-Syslog-Forwarding-Mechanismus)
if ! grep -q "@192.168.35.10:514" /etc/rsyslog.conf; then
    echo '*.* @192.168.35.10:514' >> /etc/rsyslog.conf
fi

# Rsyslog starten
pkill rsyslogd || true
rsyslogd

# --- 2. FIREWALL REGELN ---
echo "Setze Firewall Regeln..."
iptables -F
iptables -t nat -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
# (usw. Deine Allow-Regeln bleiben hier)
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -d 192.168.20.10 --dport 443 -j ACCEPT

# 🔥 KORREKTUR: WAF -> Webserver IP muss auf 192.168.60.20 umgestellt werden
iptables -A FORWARD -s 192.168.20.10 -d 192.168.60.20 -p tcp --dport 80 -j ACCEPT

iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.35.0/24 -j ACCEPT

# LOGGING-SCHNITTSTELLE (Muss auf NFLOG bleiben!)
iptables -A FORWARD -j NFLOG --nflog-group 1 --nflog-prefix "FW-DROP: "

# DROP
iptables -A FORWARD -j DROP

# --- NEU: IDS PACKET MIRRORING (TEE TARGET) ---
# Setzt den Webserver (192.168.60.20) als kritischen Überwachungspunkt.

# 1. SPIEGELUNG EINGEHEND: Traffic, der ZUM Webserver geht (Attacken, WAF-Forward)
# Das Paket wird dupliziert und die Kopie an die IDS-IP gesendet.
iptables -t mangle -A PREROUTING -d 192.168.60.20 -j TEE --gateway 192.168.60.30

# 2. SPIEGELUNG AUSGEHEND: Traffic, der VOM Webserver kommt (Antworten, Egress)
# Das ist wichtig, um die vollständige Kommunikation zu sehen.
iptables -t mangle -A PREROUTING -s 192.168.60.20 -j TEE --gateway 192.168.60.30

# --- 3. LOG COLLECTOR STARTEN (Die robuste Pipeline) ---
echo "Starte Log-Collector Pipeline (TCPDUMP)..."

# TCPDUMP liest NFLOG-Schnittstelle, formatiert und schickt an lokalen rsyslog (der es weiterleitet)
pkill tcpdump || true
tcpdump -i nflog:1 -n -l -q 2>/dev/null | logger -t firewall -p local0.warn &

echo "✅ Firewall & Logging Pipeline aktiv!"