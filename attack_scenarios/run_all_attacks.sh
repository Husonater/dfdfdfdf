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

# Menü
echo "Wähle Ausführungsmodus:"
echo "1) Alle Angriffe sequenziell ausführen"
echo "2) Einzelnen Angriff auswählen"
echo "3) Schnelldemo (verkürzte Versionen)"
echo "4) Beenden"
echo ""
read -p "Auswahl [1-4]: " choice

case $choice in
    1)
        echo -e "${GREEN}[+] Führe alle Angriffe aus...${NC}"
        run_scenario "$SCRIPT_DIR/01_brute_force_ssh.sh" "SSH Brute Force" 15
        run_scenario "$SCRIPT_DIR/02_port_scan.sh" "Port Scanning" 15
        run_scenario "$SCRIPT_DIR/03_web_attacks.sh" "Web Application Attacks" 15
        run_scenario "$SCRIPT_DIR/04_dos_attack.sh" "DoS Attack" 20
        run_scenario "$SCRIPT_DIR/05_malware_simulation.sh" "Malware Simulation" 15
        run_scenario "$SCRIPT_DIR/06_privilege_escalation.sh" "Privilege Escalation" 15
        run_scenario "$SCRIPT_DIR/07_lateral_movement.sh" "Lateral Movement" 15
        ;;
    2)
        echo ""
        echo "Verfügbare Angriffe:"
        echo "1) SSH Brute Force"
        echo "2) Port Scanning"
        echo "3) Web Application Attacks"
        echo "4) DoS Attack"
        echo "5) Malware Simulation"
        echo "6) Privilege Escalation"
        echo "7) Lateral Movement"
        echo ""
        read -p "Wähle Angriff [1-7]: " attack
        
        case $attack in
            1) run_scenario "$SCRIPT_DIR/01_brute_force_ssh.sh" "SSH Brute Force" 0 ;;
            2) run_scenario "$SCRIPT_DIR/02_port_scan.sh" "Port Scanning" 0 ;;
            3) run_scenario "$SCRIPT_DIR/03_web_attacks.sh" "Web Application Attacks" 0 ;;
            4) run_scenario "$SCRIPT_DIR/04_dos_attack.sh" "DoS Attack" 0 ;;
            5) run_scenario "$SCRIPT_DIR/05_malware_simulation.sh" "Malware Simulation" 0 ;;
            6) run_scenario "$SCRIPT_DIR/06_privilege_escalation.sh" "Privilege Escalation" 0 ;;
            7) run_scenario "$SCRIPT_DIR/07_lateral_movement.sh" "Lateral Movement" 0 ;;
            *) echo -e "${RED}[ERROR]${NC} Ungültige Auswahl" ;;
        esac
        ;;
    3)
        echo -e "${GREEN}[+] Schnelldemo-Modus${NC}"
        echo -e "${BLUE}[INFO]${NC} Führe verkürzte Versionen aus..."
        
        # Verkürzte Versionen
        bash "$SCRIPT_DIR/01_brute_force_ssh.sh" webserver attacker-internet &
        sleep 5
        bash "$SCRIPT_DIR/02_port_scan.sh" webserver attacker-internet &
        sleep 5
        bash "$SCRIPT_DIR/03_web_attacks.sh" reverse-proxy-waf attacker-internet &
        
        wait
        ;;
    4)
        echo -e "${BLUE}[INFO]${NC} Beende..."
        exit 0
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} Ungültige Auswahl"
        exit 1
        ;;
esac

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
