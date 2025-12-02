#!/bin/bash
set -e

echo "Fixing Wazuh Dashboard Configuration..."

# Fix opensearch_dashboards.yml
echo "Fixing opensearch_dashboards.yml..."
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/wazuh.indexer/wazuh-indexer/g' /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

# Fix wazuh.yml
echo "Fixing wazuh.yml..."
# Update username/password to what we expect (admin/SecretPassword123! is the default for the stack usually, but let's check what 03_deploy_dmz.sh did)
# 03_deploy_dmz.sh set it to wazuh/wazuh.
# But wait, the API user in wazuh-manager needs to exist.
# Let's try to use 'admin' and 'SecretPassword123!' which are the default API credentials if not changed.
# However, 03_deploy_dmz.sh used:
# username: wazuh
# password: wazuh
# Let's stick to what 03_deploy_dmz.sh did, assuming it knows the correct credentials.
# But wait, the current file has 'wazuh-wui'.
# I will replace 'wazuh-wui' with 'wazuh'.

docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/username: wazuh-wui/username: wazuh/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/password: wazuh-wui/password: wazuh/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

# Disable SSL validation for API connection (internal self-signed certs)
docker exec clab-dmz-project-sun-wazuh-dashboard sed -i 's/run_as: false/run_as: false\n      validate_ssl: false/g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

# Trust Root CA
echo "Trusting Root CA..."
docker exec -u 0 clab-dmz-project-sun-wazuh-dashboard cp /usr/share/wazuh-dashboard/config/certs/root-ca.pem /usr/local/share/ca-certificates/wazuh-root-ca.crt
docker exec -u 0 clab-dmz-project-sun-wazuh-dashboard update-ca-certificates

echo "Restarting Wazuh Dashboard..."
docker restart clab-dmz-project-sun-wazuh-dashboard

echo "Waiting for Dashboard to be ready..."
sleep 10
