#!/bin/bash
# Wazuh Agent Installation auf allen Hosts

SUDO_PASSWORD="Destiny2004"
WAZUH_MANAGER="172.20.20.8"

HOSTS=(
    "clab-dmz-project-sun-webserver"
    "clab-dmz-project-sun-reverse-proxy-waf"
    "clab-dmz-project-sun-db-backend"
    "clab-dmz-project-sun-edge-firewall"
    "clab-dmz-project-sun-internal-firewall"
)

echo "Installing Wazuh Agents on all hosts..."
echo ""

for host in "${HOSTS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing on: $host"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo "$SUDO_PASSWORD" | sudo -S docker exec "$host" bash << AGENT_INSTALL
# Update package list
apt-get update -qq

# Fix any broken installs from previous attempts
apt-get install -f -y

# Install dependencies
apt-get install -y curl apt-transport-https lsb-release gnupg

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

# Update again
apt-get update -qq

# Install Wazuh Agent
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent

# Configure agent
sed -i "s/<address>MANAGER_IP<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf

# Register agent
/var/ossec/bin/agent-auth -m $WAZUH_MANAGER

# Start agent
service wazuh-agent start || /var/ossec/bin/wazuh-control start

echo "Agent installed and started on $host"
AGENT_INSTALL
    
    if [ $? -eq 0 ]; then
        echo "  ✓ Agent successfully installed on $host"
    else
        echo "  ✗ Failed to install agent on $host"
    fi
    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking agent status on Wazuh Manager..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager \
    /var/ossec/bin/agent_control -l

echo ""
echo "Wazuh Agent installation complete!"
