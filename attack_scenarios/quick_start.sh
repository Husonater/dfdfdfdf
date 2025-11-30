#!/bin/bash
# Quick Start - Erste Schritte mit den Angriffsszenarien

clear
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Wazuh SIEM - Angriffsszenarien Quick Start          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Farben
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[1/5] Überprüfe Umgebung...${NC}"
echo ""

# Überprüfe ob Container laufen
echo "Überprüfe Container Status:"
if sudo docker ps | grep -q "clab-dmz-project-sun-wazuh-manager"; then
    echo -e "${GREEN}✓${NC} Wazuh Manager läuft"
else
    echo -e "${RED}✗${NC} Wazuh Manager läuft NICHT"
    echo -e "${YELLOW}Starte Container mit: cd /home/jp/dfdfdfdf && ./03_deploy_dmz.sh${NC}"
    exit 1
fi

if sudo docker ps | grep -q "clab-dmz-project-sun-wazuh-dashboard"; then
    echo -e "${GREEN}✓${NC} Wazuh Dashboard läuft"
else
    echo -e "${RED}✗${NC} Wazuh Dashboard läuft NICHT"
fi

if sudo docker ps | grep -q "clab-dmz-project-sun-attacker-internet"; then
    echo -e "${GREEN}✓${NC} Attacker Container läuft"
else
    echo -e "${RED}✗${NC} Attacker Container läuft NICHT"
fi

if sudo docker ps | grep -q "clab-dmz-project-sun-webserver"; then
    echo -e "${GREEN}✓${NC} Webserver Container läuft"
else
    echo -e "${RED}✗${NC} Webserver Container läuft NICHT"
fi

echo ""
echo -e "${BLUE}[2/5] Wazuh Status...${NC}"
echo ""

# Wazuh Manager Status
echo "Wazuh Manager Dienste:"
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | head -10

echo ""
echo -e "${BLUE}[3/5] Dashboard Zugang...${NC}"
echo ""
echo -e "${GREEN}URL:${NC}      https://localhost:8443"
echo -e "${GREEN}Username:${NC} admin"
echo -e "${GREEN}Password:${NC} SecretPassword123!"
echo ""
echo "Öffne das Dashboard in deinem Browser bevor du fortfährst!"
echo ""

read -p "Dashboard geöffnet? (j/n): " dashboard_ready
if [[ ! $dashboard_ready =~ ^[Jj]$ ]]; then
    echo -e "${YELLOW}Bitte öffne zuerst das Dashboard!${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}[4/5] Wähle ein Angriffsszenario...${NC}"
echo ""
echo "Empfohlene Reihenfolge für Anfänger:"
echo ""
echo -e "${GREEN}1)${NC} SSH Brute Force      ${YELLOW}[Einfach, schnell]${NC}"
echo -e "${GREEN}2)${NC} Port Scanning        ${YELLOW}[Einfach, mittel]${NC}"
echo -e "${GREEN}3)${NC} Web Attacks          ${YELLOW}[Mittel, schnell]${NC}"
echo -e "${GREEN}4)${NC} Malware Simulation   ${YELLOW}[Mittel, mittel]${NC}"
echo -e "${GREEN}5)${NC} Privilege Escalation ${YELLOW}[Fortgeschritten]${NC}"
echo -e "${GREEN}6)${NC} Lateral Movement     ${YELLOW}[Fortgeschritten]${NC}"
echo -e "${GREEN}7)${NC} DoS Attack           ${YELLOW}[Fortgeschritten, langsam]${NC}"
echo ""
echo -e "${BLUE}8)${NC} Demo-Modus (3 schnelle Angriffe)"
echo -e "${BLUE}9)${NC} Alle Angriffe sequenziell"
echo ""

read -p "Wähle [1-9]: " choice

echo ""
echo -e "${BLUE}[5/5] Starte Angriff...${NC}"
echo ""

SCRIPT_DIR="/home/jp/dfdfdfdf/attack_scenarios"

case $choice in
    1)
        echo -e "${GREEN}Starte SSH Brute Force...${NC}"
        echo ""
        bash "$SCRIPT_DIR/01_brute_force_ssh.sh" webserver attacker-internet
        ;;
    2)
        echo -e "${GREEN}Starte Port Scanning...${NC}"
        echo ""
        bash "$SCRIPT_DIR/02_port_scan.sh" webserver attacker-internet
        ;;
    3)
        echo -e "${GREEN}Starte Web Attacks...${NC}"
        echo ""
        bash "$SCRIPT_DIR/03_web_attacks.sh" reverse-proxy-waf attacker-internet
        ;;
    4)
        echo -e "${GREEN}Starte Malware Simulation...${NC}"
        echo ""
        bash "$SCRIPT_DIR/05_malware_simulation.sh" webserver
        ;;
    5)
        echo -e "${GREEN}Starte Privilege Escalation...${NC}"
        echo ""
        bash "$SCRIPT_DIR/06_privilege_escalation.sh" webserver
        ;;
    6)
        echo -e "${GREEN}Starte Lateral Movement...${NC}"
        echo ""
        bash "$SCRIPT_DIR/07_lateral_movement.sh" webserver
        ;;
    7)
        echo -e "${GREEN}Starte DoS Attack (30 Sekunden)...${NC}"
        echo ""
        bash "$SCRIPT_DIR/04_dos_attack.sh" webserver attacker-internet 30
        ;;
    8)
        echo -e "${GREEN}Starte Demo-Modus...${NC}"
        echo ""
        echo "1. SSH Brute Force..."
        bash "$SCRIPT_DIR/01_brute_force_ssh.sh" webserver attacker-internet
        sleep 5
        echo ""
        echo "2. Port Scan..."
        bash "$SCRIPT_DIR/02_port_scan.sh" webserver attacker-internet
        sleep 5
        echo ""
        echo "3. Web Attacks..."
        bash "$SCRIPT_DIR/03_web_attacks.sh" reverse-proxy-waf attacker-internet
        ;;
    9)
        echo -e "${GREEN}Starte alle Angriffe...${NC}"
        echo ""
        bash "$SCRIPT_DIR/run_all_attacks.sh"
        ;;
    *)
        echo -e "${RED}Ungültige Auswahl${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Angriff abgeschlossen!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Nächste Schritte:${NC}"
echo ""
echo "1. Gehe zum Wazuh Dashboard: https://localhost:8443"
echo "2. Navigiere zu 'Security Events'"
echo "3. Suche nach aktuellen Alerts (letzte 15 Minuten)"
echo ""
echo -e "${YELLOW}Nützliche Suchfilter:${NC}"
echo "  • rule.level:>=7           (Kritische Events)"
echo "  • data.srcip:*             (Nach Quell-IP)"
echo "  • timestamp:>=now-15m      (Letzte 15 Minuten)"
echo ""
echo -e "${BLUE}Weitere Hilfe:${NC}"
echo "  • Dokumentation: cat $SCRIPT_DIR/README.md"
echo "  • Dashboard Guide: bash $SCRIPT_DIR/wazuh_dashboard_guide.sh"
echo ""
echo "Viel Erfolg! 🔒"
echo ""
