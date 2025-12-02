#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[+] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

log "Starting dependency installation for DMZ Lab..."

# 1. Fix DNS for Client Internal (Google DNS)
log "Configuring DNS for client-internal..."
docker exec clab-dmz-project-sun-client-internal bash -c "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"

# 2. Attacker
log "Installing tools on attacker-internet (sshpass, nmap)..."
docker exec clab-dmz-project-sun-attacker-internet apt-get update -qq
docker exec clab-dmz-project-sun-attacker-internet apt-get install -y sshpass nmap curl wget net-tools iputils-ping

# 3. Webserver
log "Installing SSH and tools on webserver..."
docker exec clab-dmz-project-sun-webserver apt-get update -qq
docker exec clab-dmz-project-sun-webserver apt-get install -y openssh-server lsb-release curl gnupg rsyslog net-tools

# 4. SIEM Switch
log "Installing bridge-utils on siem-switch..."
docker exec clab-dmz-project-sun-siem-switch apk add --no-cache bridge-utils

# 5. Other Agents (WAF, DB, Firewalls, IDS, Client)
AGENTS=(
    "clab-dmz-project-sun-reverse-proxy-waf"
    "clab-dmz-project-sun-db-backend"
    "clab-dmz-project-sun-edge-firewall"
    "clab-dmz-project-sun-internal-firewall"
    "clab-dmz-project-sun-ids-dmz"
    "clab-dmz-project-sun-client-internal"
)

for agent in "${AGENTS[@]}"; do
    log "Processing $agent..."
    
    # Fix DNS for all agents just in case
    docker exec "$agent" bash -c "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
    
    log "Updating apt cache on $agent..."
    docker exec "$agent" apt-get update -qq || warn "Apt update failed on $agent, continuing..."
    
    log "Installing dependencies on $agent (lsb-release, curl, gnupg, rsyslog)..."
    docker exec "$agent" apt-get install -y lsb-release curl gnupg rsyslog net-tools iputils-ping || warn "Package install failed on $agent"
done

log "Dependency installation complete!"
