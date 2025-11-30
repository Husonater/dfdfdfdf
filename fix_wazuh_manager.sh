#!/bin/bash
set -e

echo "Fixing Wazuh Manager Certificates..."

# Copy certificates to Manager
echo "Copying certificates to Manager..."
docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /etc/filebeat/certs
docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager.pem
docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/wazuh-manager-key.pem
docker cp root-ca.pem clab-dmz-project-sun-wazuh-manager:/etc/filebeat/certs/root-ca.pem

# Copy API certs
echo "Copying API certificates..."
docker exec clab-dmz-project-sun-wazuh-manager mkdir -p /var/ossec/api/configuration/ssl
docker cp wazuh-manager.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.crt
docker cp wazuh-manager-key.pem clab-dmz-project-sun-wazuh-manager:/var/ossec/api/configuration/ssl/server.key
docker exec clab-dmz-project-sun-wazuh-manager chown -R wazuh:wazuh /var/ossec/api/configuration/ssl
docker exec clab-dmz-project-sun-wazuh-manager chmod 600 /var/ossec/api/configuration/ssl/server.key
docker exec clab-dmz-project-sun-wazuh-manager chmod 644 /var/ossec/api/configuration/ssl/server.crt

# Configure Filebeat
echo "Configuring Filebeat..."
cat <<EOF > filebeat.yml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.enabled: false
output.elasticsearch:
  hosts: ['https://wazuh-indexer:9200']
  username: 'admin'
  password: 'SecretPassword123!'
  ssl.verification_mode: full
  ssl.certificate_authorities: ['/etc/filebeat/certs/root-ca.pem']
  ssl.certificate: '/etc/filebeat/certs/wazuh-manager.pem'
  ssl.key: '/etc/filebeat/certs/wazuh-manager-key.pem'

logging.metrics.enabled: false

seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq
EOF
docker cp filebeat.yml clab-dmz-project-sun-wazuh-manager:/etc/filebeat/filebeat.yml

# Restart Manager
echo "Restarting Wazuh Manager..."
docker restart clab-dmz-project-sun-wazuh-manager

echo "Waiting for Manager to start..."
sleep 10
