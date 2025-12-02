#!/bin/bash
# Setup daily backup cron job

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Add to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * cd $SCRIPT_DIR && ./backup_wazuh.sh >> ./backups/backup.log 2>&1") | crontab -

echo "Cron job added: Daily backup at 2 AM"
crontab -l | grep backup_wazuh
