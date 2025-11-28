#!/bin/bash
set -e

# Fix NODE_IP in Python files
echo "Patching Wazuh Python files..."
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's/NODE_IP/127.0.0.1/g' /var/ossec/framework/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i "s/'nodes': \['127.0.0.1'\]/'nodes': []/g" /var/ossec/framework/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's/NODE_IP/127.0.0.1/g' /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/utils.py
docker exec clab-dmz-project-sun-wazuh-manager sed -i "s/'nodes': \['127.0.0.1'\]/'nodes': []/g" /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/utils.py

# Clear Python cache
echo "Clearing Python cache..."
docker exec clab-dmz-project-sun-wazuh-manager rm -rf /var/ossec/framework/python/lib/python3.9/site-packages/wazuh-4.7.3-py3.9.egg/wazuh/core/cluster/__pycache__

# Fix ossec.conf
echo "Fixing ossec.conf..."
docker exec clab-dmz-project-sun-wazuh-manager sed -i '/<nodes>/,/<\/nodes>/d' /var/ossec/etc/ossec.conf
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's|<key></key>|<key>b14ac37f9eeacfa4d1725c633ae4ecc3</key>|' /var/ossec/etc/ossec.conf
docker exec clab-dmz-project-sun-wazuh-manager sed -i 's/<disabled>yes<\/disabled>/<disabled>no<\/disabled>/' /var/ossec/etc/ossec.conf

# Restart Manager
echo "Restarting Wazuh Manager..."
docker restart clab-dmz-project-sun-wazuh-manager
echo "Waiting for Manager to start..."
sleep 20
docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/wazuh-control status
echo "Done!"
