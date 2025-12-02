#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[+] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if certificates exist
if [ ! -f "root-ca.pem" ] || [ ! -f "indexer.pem" ] || [ ! -f "indexer-key.pem" ] || [ ! -f "admin.pem" ] || [ ! -f "admin-key.pem" ]; then
    error "Certificates missing! Please run generate_certs.sh first."
    exit 1
fi

log "Copying certificates to Wazuh Indexer..."
docker cp root-ca.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/root-ca.pem
docker cp indexer.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer.pem
docker cp indexer-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/indexer-key.pem
docker cp admin.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin.pem
docker cp admin-key.pem clab-dmz-project-sun-wazuh-indexer:/usr/share/wazuh-indexer/certs/admin-key.pem

log "Configuring opensearch.yml..."
# Update transport layer certs
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemcert_filepath:.*|plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemkey_filepath:.*|plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.transport.pemtrustedcas_filepath:.*|plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem|g' /usr/share/wazuh-indexer/opensearch.yml

# Update HTTP layer certs
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemcert_filepath:.*|plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemkey_filepath:.*|plugins.security.ssl.http.pemkey_filepath: certs/indexer-key.pem|g' /usr/share/wazuh-indexer/opensearch.yml
docker exec clab-dmz-project-sun-wazuh-indexer sed -i 's|plugins.security.ssl.http.pemtrustedcas_filepath:.*|plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem|g' /usr/share/wazuh-indexer/opensearch.yml

# Fix permissions
docker exec clab-dmz-project-sun-wazuh-indexer chmod 400 /usr/share/wazuh-indexer/certs/indexer-key.pem
docker exec clab-dmz-project-sun-wazuh-indexer chmod 400 /usr/share/wazuh-indexer/certs/admin-key.pem
docker exec clab-dmz-project-sun-wazuh-indexer chown -R wazuh-indexer:wazuh-indexer /usr/share/wazuh-indexer/certs

log "Restarting Wazuh Indexer..."
docker restart clab-dmz-project-sun-wazuh-indexer
log "Waiting for Indexer to restart (30s)..."
sleep 30

log "Running Security Admin..."
docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk clab-dmz-project-sun-wazuh-indexer bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -icl -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost

log "Done!"
