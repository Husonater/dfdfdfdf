#!/bin/bash
# Master-Skript für alle komplexen Angriffsszenarien

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         🔥 KOMPLEXE ANGRIFFSSZENARIEN - MASTER SUITE 🔥       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}Verfügbare komplexe Angriffsszenarien:${NC}"
echo ""
echo -e "${GREEN}STANDARD ANGRIFFE (1-7):${NC}"
echo "  1) SSH Brute Force"
echo "  2) Port Scanning"
echo "  3) Web Application Attacks"
echo "  4) DoS Attack"
echo "  5) Malware Simulation"
echo "  6) Privilege Escalation"
echo "  7) Lateral Movement"
echo ""
echo -e "${YELLOW}ERWEITERTE ANGRIFFE:${NC}"
echo "  8) APT - Advanced Persistent Threat (9 Phasen)"
echo ""
echo -e "${RED}HOCHKOMPLEXE ANGRIFFE (NEU!):${NC}"
echo "  9)  Supply Chain Attack"
echo "  10) Zero-Day Exploit Chain"
echo "  11) Insider Threat"
echo "  12) Fileless Attack (Living off the Land)"
echo "  13) Ransomware Campaign (Double Extortion)"
echo ""
echo -e "${MAGENTA}SPEZIAL-MODI:${NC}"
echo "  14) Alle Standard-Angriffe (1-7)"
echo "  15) Alle Erweiterten Angriffe (8-13)"
echo "  16) ALLE ANGRIFFE (Vollständige Demo)"
echo "  17) Zufällige Auswahl (3 Angriffe)"
echo ""

read -p "Wähle Szenario [1-17]: " choice

run_attack() {
    local script=$1
    local name=$2
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}▶ Starte: $name${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    if [ -f "$script" ]; then
        chmod +x "$script"
        bash "$script"
        echo -e "${GREEN}✓ Abgeschlossen: $name${NC}"
        sleep 3
    else
        echo -e "${RED}✗ Skript nicht gefunden: $script${NC}"
    fi
}

case $choice in
    1) run_attack "$SCRIPT_DIR/01_brute_force_ssh.sh" "SSH Brute Force" ;;
    2) run_attack "$SCRIPT_DIR/02_port_scan.sh" "Port Scanning" ;;
    3) run_attack "$SCRIPT_DIR/03_web_attacks.sh" "Web Application Attacks" ;;
    4) run_attack "$SCRIPT_DIR/04_dos_attack.sh" "DoS Attack" ;;
    5) run_attack "$SCRIPT_DIR/05_malware_simulation.sh" "Malware Simulation" ;;
    6) run_attack "$SCRIPT_DIR/06_privilege_escalation.sh" "Privilege Escalation" ;;
    7) run_attack "$SCRIPT_DIR/07_lateral_movement.sh" "Lateral Movement" ;;
    8) run_attack "$SCRIPT_DIR/08_apt_full_attack.sh" "APT - Advanced Persistent Threat" ;;
    9) run_attack "$SCRIPT_DIR/09_supply_chain_attack.sh" "Supply Chain Attack" ;;
    10) run_attack "$SCRIPT_DIR/10_zero_day_exploits.sh" "Zero-Day Exploit Chain" ;;
    11) run_attack "$SCRIPT_DIR/11_insider_threat.sh" "Insider Threat" ;;
    12) run_attack "$SCRIPT_DIR/12_fileless_attack.sh" "Fileless Attack" ;;
    13) run_attack "$SCRIPT_DIR/13_ransomware_campaign.sh" "Ransomware Campaign" ;;
    
    14)
        echo -e "${GREEN}Führe alle Standard-Angriffe aus...${NC}"
        for i in {1..7}; do
            run_attack "$SCRIPT_DIR/0${i}_*.sh" "Angriff $i"
        done
        ;;
    
    15)
        echo -e "${YELLOW}Führe alle Erweiterten Angriffe aus...${NC}"
        for i in {8..13}; do
            if [ $i -lt 10 ]; then
                run_attack "$SCRIPT_DIR/0${i}_*.sh" "Angriff $i"
            else
                run_attack "$SCRIPT_DIR/${i}_*.sh" "Angriff $i"
            fi
        done
        ;;
    
    16)
        echo -e "${RED}⚠️  VOLLSTÄNDIGE DEMO - ALLE ANGRIFFE!${NC}"
        echo -e "${YELLOW}Dies wird ca. 20-30 Minuten dauern!${NC}"
        read -p "Fortfahren? (j/n): " confirm
        if [[ $confirm =~ ^[Jj]$ ]]; then
            for script in "$SCRIPT_DIR"/*.sh; do
                if [[ "$script" != *"run_all"* ]] && [[ "$script" != *"quick_start"* ]] && [[ "$script" != *"wazuh_dashboard"* ]]; then
                    name=$(basename "$script" .sh)
                    run_attack "$script" "$name"
                fi
            done
        fi
        ;;
    
    17)
        echo -e "${MAGENTA}Zufällige Auswahl von 3 Angriffen...${NC}"
        attacks=($(ls "$SCRIPT_DIR"/{01..13}_*.sh 2>/dev/null | shuf -n 3))
        for attack in "${attacks[@]}"; do
            name=$(basename "$attack" .sh)
            run_attack "$attack" "$name"
        done
        ;;
    
    *)
        echo -e "${RED}Ungültige Auswahl!${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ ANGRIFFSSIMULATION ABGESCHLOSSEN!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}📊 Wazuh Dashboard öffnen:${NC}"
echo "   URL: https://localhost:8443"
echo "   User: admin / SecretPassword123!"
echo ""
echo -e "${CYAN}🔍 Empfohlene Filter:${NC}"
echo "   • timestamp:>=now-30m"
echo "   • rule.level:>=10"
echo "   • rule.groups:attack"
echo ""
echo -e "${YELLOW}Viel Erfolg beim Analysieren! 🛡️${NC}"
echo ""
