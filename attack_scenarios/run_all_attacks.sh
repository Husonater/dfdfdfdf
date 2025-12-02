#!/bin/bash
# Master-Skript zum Ausführen aller Angriffsszenarien

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        Wazuh SIEM - Angriffsszenario Simulation Suite         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO_PASSWORD="Destiny2004"

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[INFO]${NC} Starte Angriffssimulation..."
echo -e "${YELLOW}[WARN]${NC} Stelle sicher, dass Wazuh läuft und Agents verbunden sind!"
echo ""

# Funktion zum Ausführen eines Szenarios
run_scenario() {
    local script=$1
    local name=$2
    local delay=${3:-10}
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[+] Starte: $name${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    
    if [ -f "$script" ]; then
        chmod +x "$script"
        bash "$script"
        echo -e "${BLUE}[INFO]${NC} Warte $delay Sekunden vor nächstem Angriff..."
        sleep $delay
    else
        echo -e "${RED}[ERROR]${NC} Skript nicht gefunden: $script"
    fi
}

# Automatisierte Ausführung aller verifizierten Angriffe
echo -e "${GREEN}[+] Führe alle verifizierten Angriffe aus...${NC}"

# 1. SSH Brute Force (Simple Version)
run_scenario "$SCRIPT_DIR/01_brute_force_ssh_simple.sh" "SSH Brute Force (Simple)" 10

# 2. Port Scan
run_scenario "$SCRIPT_DIR/02_port_scan.sh" "Port Scanning" 10

# 3. Web Attacks
run_scenario "$SCRIPT_DIR/03_web_attacks.sh" "Web Application Attacks" 10

# 4. DoS Attack (Optional - if script exists and works)
if [ -f "$SCRIPT_DIR/04_dos_attack.sh" ]; then
    run_scenario "$SCRIPT_DIR/04_dos_attack.sh" "DoS Attack" 10
fi

# 5. Malware Simulation (Optional)
if [ -f "$SCRIPT_DIR/05_malware_simulation.sh" ]; then
    run_scenario "$SCRIPT_DIR/05_malware_simulation.sh" "Malware Simulation" 10
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Angriffssimulation abgeschlossen!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}[INFO]${NC} Nächste Schritte:"
echo "  1. Öffne Wazuh Dashboard: https://localhost:8443"
echo "  2. Login: admin / SecretPassword123!"
echo "  3. Navigiere zu 'Security Events' oder 'Threat Hunting'"
echo "  4. Filtere nach den verschiedenen Angriffstypen"
echo ""
echo -e "${YELLOW}[TIP]${NC} Nützliche Suchbegriffe in Wazuh:"
echo "  - rule.level:>=7 (Hochprioritäts-Alerts)"
echo "  - rule.groups:authentication_failed"
echo "  - rule.groups:web_attack"
echo "  - rule.groups:network_scan"
echo "  - data.srcip:attacker-internet"
echo ""
