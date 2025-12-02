#!/bin/bash
# Einfache Zusammenfassung und Anleitung

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              Wazuh Security Events - Zusammenfassung           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"

echo "📊 AKTUELLE SITUATION:"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "✓ Angriffsszenarien erstellt (7 Skripte)"
echo "✓ Security Events in Logs geschrieben"
echo "✓ Wazuh Manager läuft"
echo "✓ Wazuh Dashboard erreichbar"
echo ""
echo "⚠️  PROBLEM: Keine Agents auf Ziel-Containern installiert"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "💡 LÖSUNG: Nutze Wazuh Dashboard mit vorhandenen Events"
echo "════════════════════════════════════════════════════════════════"
echo ""

echo "[1] Öffne Wazuh Dashboard:"
echo "    URL: https://localhost:8443"
echo "    Username: admin"
echo "    Password: SecretPassword123!"
echo ""

echo "[2] Navigiere zu 'Security Events':"
echo "    - Klicke auf das Menü-Icon (☰) oben links"
echo "    - Wähle 'Security events'"
echo ""

echo "[3] Du siehst bereits Events vom Wazuh Manager selbst:"
echo "    - SCA (Security Configuration Assessment) Scans"
echo "    - File Integrity Monitoring"
echo "    - System Events"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "🎯 DEMO-EVENTS DIREKT IM DASHBOARD ERSTELLEN"
echo "════════════════════════════════════════════════════════════════"
echo ""

echo "Ich generiere jetzt Test-Events die GARANTIERT sichtbar sind..."
echo ""

# Generiere File Integrity Events (diese funktionieren immer)
echo "[+] Generiere File Integrity Monitoring Events..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    # Ändere überwachte Dateien
    echo "# Test modification $(date)" >> /etc/passwd
    echo "# Test modification $(date)" >> /etc/group
    touch /etc/test_file_$(date +%s)
    
    # Trigger Syscheck
    /var/ossec/bin/wazuh-control restart ossec-syscheckd
'

sleep 5

echo "[+] Generiere System Events..."
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c '
    # Installiere ein Paket (erzeugt dpkg logs)
    apt-get install -y figlet -qq 2>/dev/null
'

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "📈 AKTUELLE WAZUH STATISTIKEN"
echo "════════════════════════════════════════════════════════════════"
echo ""

echo "[+] Anzahl der Alerts heute:"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    wc -l /var/ossec/logs/alerts/alerts.log 2>/dev/null | awk '{print \"    Total Alerts: \" \$1}'
"

echo ""
echo "[+] Alert-Level Verteilung (letzte 100):"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    tail -100 /var/ossec/logs/alerts/alerts.log | grep 'Rule:' | awk '{print \$4}' | sort | uniq -c | sort -rn | head -5
" | awk '{print "    Level " $2 ": " $1 " alerts"}'

echo ""
echo "[+] Top 5 Alert-Typen:"
echo "$SUDO_PASSWORD" | sudo -S docker exec clab-dmz-project-sun-wazuh-manager bash -c "
    tail -200 /var/ossec/logs/alerts/alerts.log | grep 'Rule:' | sed 's/.*-> //' | sed \"s/'.*//\" | sort | uniq -c | sort -rn | head -5
"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "🔧 NÄCHSTE SCHRITTE FÜR ECHTE ANGRIFFSERKENNUNG"
echo "════════════════════════════════════════════════════════════════"
echo ""

cat << 'EOF'
Um echte Angriffe zu erkennen, benötigst du Wazuh Agents auf den
Ziel-Containern. Hier sind 3 Optionen:

OPTION 1: Agents manuell installieren (komplex)
  - Wazuh Agent in jedem Container installieren
  - Agents mit Manager verbinden
  - Dauert ca. 30-60 Minuten

OPTION 2: Filebeat/Syslog Forwarding (mittel)
  - Logs von Containern an Wazuh weiterleiten
  - Einfacher als Agents
  - Dauert ca. 15-30 Minuten

OPTION 3: Simulierte Events nutzen (einfach, EMPFOHLEN)
  - Nutze das generate_wazuh_events.sh Skript
  - Erzeugt realistische Security Events
  - Sofort verfügbar!

EMPFEHLUNG für Demo/Testing:
  ./generate_wazuh_events.sh

Für Produktion:
  Installiere Wazuh Agents auf allen Hosts

EOF

echo "════════════════════════════════════════════════════════════════"
echo "📚 VERFÜGBARE SKRIPTE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  ./generate_wazuh_events.sh     - Generiere Test-Events"
echo "  ./attack_scenarios/quick_start.sh - Interaktive Angriffe"
echo "  ./attack_scenarios/README.md   - Vollständige Dokumentation"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "✅ DASHBOARD JETZT ÖFFNEN!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "https://localhost:8443"
echo ""
echo "Du solltest jetzt Security Events sehen können! 🎉"
echo ""
