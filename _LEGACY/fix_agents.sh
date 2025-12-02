#!/bin/bash
HOSTS=(
    "clab-dmz-project-sun-webserver"
    "clab-dmz-project-sun-reverse-proxy-waf"
    "clab-dmz-project-sun-db-backend"
    "clab-dmz-project-sun-edge-firewall"
    "clab-dmz-project-sun-internal-firewall"
)

WAZUH_MANAGER="172.20.20.8"

for host in "${HOSTS[@]}"; do
    echo "Fixing $host..."
    sudo docker exec "$host" bash -c "apt-get update && apt-get install -f -y && apt-get install -y lsb-release curl gnupg && dpkg --configure -a"
    
    # Check if wazuh-agent is installed
    if ! sudo docker exec "$host" dpkg -l | grep -q "wazuh-agent"; then
        echo "Installing Wazuh Agent on $host..."
        sudo docker cp wazuh-agent_4.7.3-1_amd64.deb "$host":/tmp/wazuh-agent.deb
        sudo docker exec "$host" dpkg -i /tmp/wazuh-agent.deb || sudo docker exec "$host" apt-get install -f -y
    fi
    
    echo "Configuring Wazuh Agent on $host..."
    sudo docker exec "$host" sed -i "s/<address>MANAGER_IP<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf
    
    echo "Registering Agent on $host..."
    sudo docker exec "$host" /var/ossec/bin/agent-auth -m $WAZUH_MANAGER
    
    echo "Starting Agent on $host..."
    sudo docker exec "$host" service wazuh-agent restart || sudo docker exec "$host" /var/ossec/bin/wazuh-control restart
done
