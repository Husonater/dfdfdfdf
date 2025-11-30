#!/bin/bash
HOSTS=(
    "clab-dmz-project-sun-db-backend"
    "clab-dmz-project-sun-edge-firewall"
    "clab-dmz-project-sun-internal-firewall"
)

for host in "${HOSTS[@]}"; do
    echo "Restarting Wazuh Agent on $host..."
    
    # Kill existing processes
    sudo docker exec "$host" pkill -f wazuh || true
    
    # Wait a bit
    sleep 2
    
    # Start agent using wazuh-control
    sudo docker exec "$host" /var/ossec/bin/wazuh-control start
    
    echo "Agent restarted on $host"
done
