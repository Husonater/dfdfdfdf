#!/bin/bash
set -e

echo "Fixing Wazuh Indexer Security..."

# Copy certificates to Indexer
echo "Copying certificates to Indexer..."
docker cp indexer.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer.pem
docker cp indexer-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer-key.pem
docker cp root-ca.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/root-ca.pem
docker cp admin.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin.pem
docker cp admin-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin-key.pem

# Fix admin password hash
echo "Fixing admin password hash..."
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG|\$2y\$12\$Ao4b78h7RuRvArs5hkfo2ebILdfE/luW1c5aYFlnlC6Cy8vme8unO|g' /usr/share/wazuh-indexer/opensearch-security/internal_users.yml

# Fix admin_dn in opensearch.yml
echo "Fixing admin_dn in opensearch.yml..."
# The current config has: CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US
# The cert has: CN=admin,OU=Wazuh,O=Wazuh,L=San Jose,ST=California,C=US
# We need to replace the config line to match the cert.
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US|CN=admin,OU=Wazuh,O=Wazuh,L=San Jose,ST=California,C=US|g' /usr/share/wazuh-indexer/opensearch.yml

# Restart Indexer to load new certs and config
echo "Restarting Wazuh Indexer..."
docker restart clab-dmz-project-sun-wazuh-indexer

echo "Waiting for Indexer to start (30s)..."
sleep 30

# Run securityadmin.sh
echo "Running securityadmin.sh..."
docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk clab-dmz-project-sun-wazuh-indexer bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -icl -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost

echo "Wazuh Indexer Security Initialized!"

echo "Restarting Wazuh Dashboard to reconnect..."
docker restart clab-dmz-project-sun-wazuh-dashboard
