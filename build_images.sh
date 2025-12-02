#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+] $1${NC}"
}

log "Building Docker Images..."

# Attacker
log "Building attacker:latest..."
sudo docker build -t attacker:latest images/attacker

# Database
log "Building db:latest..."
sudo docker build -t db:latest images/db

# Firewall
log "Building firewall:latest..."
sudo docker build -t firewall:latest images/firewall

# IDS
log "Building ids:latest..."
sudo docker build -t ids:latest images/ids

# WAF
log "Building waf:latest..."
sudo docker build -t waf:latest images/waf

# Webserver
log "Building webserver:latest..."
sudo docker build -t webserver:latest images/webserver

# Wazuh Manager
log "Building wazuh-manager:latest..."
sudo docker build -t wazuh-manager:latest images/wazuh_manager

# Wazuh Indexer
log "Building wazuh-indexer:latest..."
sudo docker build -t wazuh-indexer:latest images/wazuh_indexer

# Wazuh Dashboard
log "Building wazuh-dashboard:latest..."
sudo docker build -t wazuh-dashboard:latest images/wazuh_dashboard

log "All images built successfully!"
