#!/bin/bash
# Wazuh Backup Script

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUDO_PASSWORD="Destiny2004"

mkdir -p "$BACKUP_DIR"

echo "Starting Wazuh Backup..."

# Backup Wazuh Manager Data
echo "Backing up Wazuh Manager..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager \
  tar czf /tmp/wazuh-manager-backup.tar.gz \
  /var/ossec/data \
  /var/ossec/logs/alerts \
  /var/ossec/etc/ossec.conf

echo "$SUDO_PASSWORD" | sudo -S docker cp \
  clab-dmz-project-sun-wazuh-manager:/tmp/wazuh-manager-backup.tar.gz \
  "$BACKUP_DIR/wazuh-manager-$TIMESTAMP.tar.gz"

# Backup Wazuh Indexer Data
echo "Backing up Wazuh Indexer..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-indexer \
  tar czf /tmp/wazuh-indexer-backup.tar.gz \
  /var/lib/wazuh-indexer

echo "$SUDO_PASSWORD" | sudo -S docker cp \
  clab-dmz-project-sun-wazuh-indexer:/tmp/wazuh-indexer-backup.tar.gz \
  "$BACKUP_DIR/wazuh-indexer-$TIMESTAMP.tar.gz"

echo "Backup complete!"
echo "Files:"
ls -lh "$BACKUP_DIR/"*$TIMESTAMP*

# Cleanup old backups (keep last 7 days)
find "$BACKUP_DIR" -name "wazuh-*.tar.gz" -mtime +7 -delete

echo "Old backups cleaned up (kept last 7 days)"
