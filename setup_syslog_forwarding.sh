#!/bin/bash
# Konfiguriert Syslog-Forwarding von Containern zu Wazuh
# Einfachere Alternative zur Agent-Installation

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        Syslog-Forwarding zu Wazuh Manager konfigurieren       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"
WAZUH_MANAGER="wazuh-manager"
SYSLOG_PORT="514"

# Container die überwacht werden sollen
CONTAINERS=(
    "webserver"
    "reverse-proxy-waf"
    "edge-firewall"
    "internal-firewall"
)

configure_syslog() {
    local container=$1
    local full_name="clab-dmz-project-sun-$container"
    
    echo "[+] Konfiguriere Syslog für: $container"
    
    if ! echo "$SUDO_PASSWORD" | sudo -S docker ps | grep -q "$full_name"; then
        echo "  [!] Container läuft nicht, überspringe..."
        return 1
    fi
    
    echo "$SUDO_PASSWORD" | sudo -S docker exec $full_name bash -c "
        # Installiere rsyslog falls nicht vorhanden
        if ! command -v rsyslogd &> /dev/null; then
            echo '  [*] Installiere rsyslog...'
            apt-get update -qq && apt-get install -y rsyslog -qq 2>/dev/null
        fi
        
        # Konfiguriere rsyslog zum Forwarding
        echo '  [*] Konfiguriere rsyslog forwarding...'
        cat > /etc/rsyslog.d/wazuh.conf << 'EOF'
# Forward all logs to Wazuh Manager
*.* @$WAZUH_MANAGER:$SYSLOG_PORT
EOF
        
        # Starte rsyslog
        echo '  [*] Starte rsyslog...'
        service rsyslog restart 2>/dev/null || rsyslogd
        
        echo '  [✓] Syslog forwarding konfiguriert'
    " 2>&1 | grep -E '^\s+\[' 
    
    sleep 1
}

echo "Konfiguriere Syslog-Forwarding..."
echo ""

for container in "${CONTAINERS[@]}"; do
    configure_syslog "$container"
    echo ""
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✓ Syslog-Forwarding konfiguriert!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Hinweis: Dies ist eine Basis-Konfiguration."
echo "Für bessere Erkennung erstellen wir lokale Log-Events im Wazuh Manager."
echo ""
