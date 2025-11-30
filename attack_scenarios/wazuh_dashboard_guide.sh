#!/bin/bash
# Wazuh Dashboard - Anleitung zur Visualisierung der Angriffe

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Wazuh Dashboard - Angriffe visualisieren und analysieren   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

SUDO_PASSWORD="Destiny2004"

echo "[1] Überprüfe Wazuh Status..."
echo ""

# Überprüfe ob Wazuh läuft
echo "Wazuh Manager Status:"
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null || echo "Fehler beim Abrufen des Status"

echo ""
echo "Wazuh Agents:"
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null || echo "Fehler beim Abrufen der Agents"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "[2] Zugriff auf Wazuh Dashboard"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "URL: https://localhost:8443"
echo "Username: admin"
echo "Password: SecretPassword123!"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "[3] Navigation im Dashboard"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Nach dem Login navigiere zu:"
echo ""
echo "📊 SECURITY EVENTS"
echo "   └─ Zeigt alle erkannten Sicherheitsereignisse"
echo "   └─ Filtere nach: rule.level:>=7 für kritische Events"
echo ""
echo "🔍 THREAT HUNTING"
echo "   └─ Erweiterte Suche und Analyse"
echo "   └─ Erstelle Custom Queries"
echo ""
echo "📈 MODULES"
echo "   ├─ Security Events: Alle Alerts"
echo "   ├─ Integrity Monitoring: Dateiänderungen"
echo "   ├─ Vulnerability Detection: Schwachstellen"
echo "   ├─ MITRE ATT&CK: Taktiken und Techniken"
echo "   └─ Regulatory Compliance: Compliance-Status"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "[4] Wichtige Suchabfragen für Angriffsszenarien"
echo "════════════════════════════════════════════════════════════════"
echo ""

cat << 'EOF'
🔴 SSH BRUTE FORCE:
   rule.groups:authentication_failed AND data.srcip:*
   rule.id:(5710 OR 5712 OR 5720)

🔴 PORT SCANNING:
   rule.groups:recon AND rule.groups:network_scan
   rule.id:(5710 OR 40101 OR 40102)

🔴 WEB ATTACKS:
   rule.groups:web_attack
   rule.groups:sql_injection OR rule.groups:xss
   rule.id:(31100 OR 31101 OR 31103 OR 31106)

🔴 DOS ATTACKS:
   rule.groups:dos OR rule.groups:flood
   rule.level:>=10

🔴 MALWARE:
   rule.groups:malware OR rule.groups:rootkit
   rule.id:(510 OR 511 OR 550)

🔴 PRIVILEGE ESCALATION:
   rule.groups:privilege_escalation
   data.command:*sudo* AND rule.level:>=7

🔴 LATERAL MOVEMENT:
   rule.groups:lateral_movement
   data.srcip:* AND data.dstip:*
   rule.id:(5712 OR 5720 OR 5760)

🔴 ALLE KRITISCHEN EVENTS:
   rule.level:>=12

🔴 NACH ATTACKER IP:
   data.srcip:attacker-internet

🔴 NACH ZEITRAUM (letzte Stunde):
   timestamp:>=now-1h
EOF

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "[5] Dashboard Visualisierungen erstellen"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. Gehe zu 'Visualize' → 'Create visualization'"
echo "2. Wähle Visualisierungstyp:"
echo "   - Bar Chart: Angriffe pro Typ"
echo "   - Pie Chart: Verteilung nach Schweregrad"
echo "   - Line Chart: Zeitverlauf der Angriffe"
echo "   - Heat Map: Angriffe nach Quelle/Ziel"
echo "   - Data Table: Detaillierte Event-Liste"
echo ""
echo "3. Erstelle Dashboard:"
echo "   - Gehe zu 'Dashboard' → 'Create dashboard'"
echo "   - Füge erstellte Visualisierungen hinzu"
echo "   - Speichere als 'Attack Scenarios Dashboard'"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "[6] MITRE ATT&CK Mapping"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Navigiere zu 'MITRE ATT&CK' Modul um zu sehen:"
echo ""
echo "Taktiken (Tactics):"
echo "  - Initial Access (Brute Force)"
echo "  - Execution (Malware)"
echo "  - Persistence (Backdoors)"
echo "  - Privilege Escalation (Sudo Abuse)"
echo "  - Defense Evasion (Rootkits)"
echo "  - Credential Access (Password Dumping)"
echo "  - Discovery (Network Scanning)"
echo "  - Lateral Movement (SSH Pivoting)"
echo "  - Collection (Data Staging)"
echo "  - Exfiltration (Data Transfer)"
echo "  - Impact (DoS)"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "[7] Alert-Statistiken anzeigen"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Zeige letzte Alerts
echo "Letzte 10 Alerts:"
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    tail -20 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
    jq -r '.rule.description' 2>/dev/null || echo "Keine Alerts gefunden oder jq nicht installiert"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "[8] Exportieren von Daten"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Im Dashboard:"
echo "  1. Wähle gewünschte Events aus"
echo "  2. Klicke auf 'Share' → 'CSV Reports'"
echo "  3. Oder nutze 'Reporting' für PDF-Reports"
echo ""

echo "Via CLI:"
echo "  # Alerts exportieren"
echo "  sudo docker exec clab-dmz-project-sun-wazuh-manager \\"
echo "    cat /var/ossec/logs/alerts/alerts.json > alerts_export.json"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "[9] Nützliche Wazuh CLI Befehle"
echo "════════════════════════════════════════════════════════════════"
echo ""

cat << 'EOF'
# Agent Status
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    /var/ossec/bin/agent_control -l

# Letzte Alerts
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    tail -f /var/ossec/logs/alerts/alerts.log

# Regel-Test
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    /var/ossec/bin/wazuh-logtest

# Statistiken
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    /var/ossec/bin/agent_control -s

# Logs in Echtzeit
sudo docker exec clab-dmz-project-sun-wazuh-manager \
    tail -f /var/ossec/logs/ossec.log
EOF

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "[10] Troubleshooting"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Keine Alerts sichtbar?"
echo "  1. Überprüfe Agent-Verbindung"
echo "  2. Prüfe Wazuh Manager Logs"
echo "  3. Verifiziere Indexer-Verbindung"
echo "  4. Checke Filebeat Status"
echo ""
echo "Befehle:"
echo "  sudo docker logs clab-dmz-project-sun-wazuh-manager"
echo "  sudo docker logs clab-dmz-project-sun-wazuh-indexer"
echo "  sudo docker logs clab-dmz-project-sun-wazuh-dashboard"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "✅ Anleitung abgeschlossen!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Viel Erfolg bei der Analyse der Angriffsszenarien! 🔒"
echo ""
