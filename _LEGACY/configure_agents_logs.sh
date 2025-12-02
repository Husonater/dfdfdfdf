#!/bin/bash
# configure_agents_logs.sh
# Configures Wazuh Agents to monitor standard Linux logs (syslog, auth.log)

AGENTS=("clab-dmz-project-sun-webserver" "clab-dmz-project-sun-db-backend" "clab-dmz-project-sun-reverse-proxy-waf")
SUDO_PASSWORD="Destiny2004"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       Configuring Wazuh Agents Log Monitoring                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

for AGENT in "${AGENTS[@]}"; do
    echo "[*] Processing $AGENT..."
    
    # Check if container runs
    if ! echo "$SUDO_PASSWORD" | sudo -S docker ps | grep -q "$AGENT"; then
        echo "  [!] Container not found or not running. Skipping."
        continue
    fi

    echo "$SUDO_PASSWORD" | sudo -S docker exec $AGENT bash -c '
        # Backup configuration
        if [ ! -f /var/ossec/etc/ossec.conf.bak_logs ]; then
            cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_logs
        fi
        
        CHANGED=0
        
        # Check and add syslog/auth.log monitoring if missing
        # We use a single block insertion for cleaner config if both are missing, 
        # or check individually. simpler to just append if missing.
        
        if ! grep -q "/var/log/syslog" /var/ossec/etc/ossec.conf; then
            sed -i "/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>" /var/ossec/etc/ossec.conf
            echo "  [+] Added /var/log/syslog monitoring"
            CHANGED=1
        fi
        
        if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
            sed -i "/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>" /var/ossec/etc/ossec.conf
            echo "  [+] Added /var/log/auth.log monitoring"
            CHANGED=1
        fi
        
        if [ $CHANGED -eq 1 ]; then
            echo "  [*] Restarting Wazuh Agent..."
            /var/ossec/bin/wazuh-control restart
            echo "  [✓] Agent restarted successfully"
        else
            echo "  [=] Logs already configured"
        fi
    '
    echo ""
done

echo "Done! Agents are now monitoring system logs."
