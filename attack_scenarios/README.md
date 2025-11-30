# Wazuh SIEM - Angriffsszenarien Dokumentation

## 📋 Übersicht

Dieses Verzeichnis enthält 7 verschiedene Angriffsszenarien zur Simulation realistischer Cyberangriffe in deiner DMZ-Umgebung. Alle Angriffe werden in Wazuh SIEM erkannt und können im Dashboard visualisiert werden.

## 🎯 Verfügbare Angriffsszenarien

### 1. SSH Brute Force (`01_brute_force_ssh.sh`)
**Beschreibung:** Simuliert einen Brute-Force-Angriff auf SSH-Dienste mit mehreren fehlgeschlagenen Login-Versuchen.

**MITRE ATT&CK:** T1110 - Brute Force

**Wazuh Rules:**
- Rule ID 5710: Multiple authentication failures
- Rule ID 5712: SSHD authentication failed
- Rule ID 5720: Multiple SSHD authentication failures

**Verwendung:**
```bash
cd /home/jp/dfdfdfdf/attack_scenarios
./01_brute_force_ssh.sh [target] [attacker]
# Beispiel: ./01_brute_force_ssh.sh webserver attacker-internet
```

**Erwartete Alerts:**
- Authentication failed
- Brute force attack detected
- Multiple login failures

---

### 2. Port Scanning (`02_port_scan.sh`)
**Beschreibung:** Führt verschiedene Nmap-Scans durch (SYN, TCP Connect, UDP, Aggressive).

**MITRE ATT&CK:** T1046 - Network Service Scanning

**Wazuh Rules:**
- Rule ID 40101: Network scan detected
- Rule ID 40102: Port scan detected

**Verwendung:**
```bash
./02_port_scan.sh [target] [attacker]
# Beispiel: ./02_port_scan.sh webserver attacker-internet
```

**Erwartete Alerts:**
- Port scan detected
- Network reconnaissance
- Multiple connection attempts

---

### 3. Web Application Attacks (`03_web_attacks.sh`)
**Beschreibung:** Simuliert SQL Injection, XSS, Path Traversal und Command Injection Angriffe.

**MITRE ATT&CK:** 
- T1190 - Exploit Public-Facing Application
- T1059 - Command and Scripting Interpreter

**Wazuh Rules:**
- Rule ID 31100: SQL injection attempt
- Rule ID 31101: XSS attempt
- Rule ID 31103: Path traversal attempt
- Rule ID 31106: Command injection attempt

**Verwendung:**
```bash
./03_web_attacks.sh [target] [attacker]
# Beispiel: ./03_web_attacks.sh reverse-proxy-waf attacker-internet
```

**Erwartete Alerts:**
- SQL injection detected
- Cross-site scripting attempt
- Path traversal attack
- Command injection detected

---

### 4. Denial of Service (`04_dos_attack.sh`)
**Beschreibung:** Simuliert DoS-Angriffe (HTTP Flood, SYN Flood, ICMP Flood).

**MITRE ATT&CK:** T1498 - Network Denial of Service

**Wazuh Rules:**
- Rule ID 40301: DoS attack detected
- Rule ID 40302: High traffic volume

**Verwendung:**
```bash
./04_dos_attack.sh [target] [attacker] [duration_seconds]
# Beispiel: ./04_dos_attack.sh webserver attacker-internet 30
```

**Erwartete Alerts:**
- DoS attack detected
- High connection rate
- Network flood detected

---

### 5. Malware Simulation (`05_malware_simulation.sh`)
**Beschreibung:** Simuliert Malware-Aktivitäten (EICAR-Test, C2-Kommunikation, Datenexfiltration).

**MITRE ATT&CK:**
- T1071 - Application Layer Protocol (C2)
- T1041 - Exfiltration Over C2 Channel
- T1547 - Boot or Logon Autostart Execution

**Wazuh Rules:**
- Rule ID 510: Malware detected
- Rule ID 511: Rootkit detected
- Rule ID 550: Integrity checksum changed

**Verwendung:**
```bash
./05_malware_simulation.sh [target_node]
# Beispiel: ./05_malware_simulation.sh webserver
```

**Erwartete Alerts:**
- Malware detected (EICAR)
- Suspicious process activity
- C2 communication detected
- Data exfiltration attempt

---

### 6. Privilege Escalation (`06_privilege_escalation.sh`)
**Beschreibung:** Simuliert Privilege Escalation Versuche (sudo-Missbrauch, SUID, Kernel-Exploits).

**MITRE ATT&CK:**
- T1068 - Exploitation for Privilege Escalation
- T1548 - Abuse Elevation Control Mechanism

**Wazuh Rules:**
- Rule ID 5401: Sudo authentication failed
- Rule ID 5402: Multiple sudo failures
- Rule ID 2830: SUID/SGID file detected

**Verwendung:**
```bash
./06_privilege_escalation.sh [target_node]
# Beispiel: ./06_privilege_escalation.sh webserver
```

**Erwartete Alerts:**
- Privilege escalation attempt
- Unauthorized sudo usage
- Suspicious SUID binary execution
- Kernel exploit attempt

---

### 7. Lateral Movement (`07_lateral_movement.sh`)
**Beschreibung:** Simuliert laterale Bewegung im Netzwerk (SSH-Pivoting, Credential Dumping).

**MITRE ATT&CK:**
- T1021 - Remote Services
- T1003 - OS Credential Dumping
- T1570 - Lateral Tool Transfer

**Wazuh Rules:**
- Rule ID 5712: SSH authentication from unusual source
- Rule ID 5760: Multiple SSH connections
- Rule ID 100100: Credential access detected

**Verwendung:**
```bash
./07_lateral_movement.sh [start_node]
# Beispiel: ./07_lateral_movement.sh webserver
```

**Erwartete Alerts:**
- Lateral movement detected
- Unusual SSH activity
- Credential dumping attempt
- Network reconnaissance

---

## 🚀 Schnellstart

### Alle Angriffe ausführen:
```bash
cd /home/jp/dfdfdfdf/attack_scenarios
chmod +x *.sh
./run_all_attacks.sh
```

### Einzelnen Angriff ausführen:
```bash
./01_brute_force_ssh.sh webserver attacker-internet
```

### Wazuh Dashboard öffnen:
```bash
# URL: https://localhost:8443
# Username: admin
# Password: SecretPassword123!
```

---

## 📊 Visualisierung in Wazuh

### Dashboard-Zugriff:
1. Öffne Browser: `https://localhost:8443`
2. Login mit: `admin` / `SecretPassword123!`
3. Navigiere zu **Security Events**

### Wichtige Suchabfragen:

#### Alle kritischen Events:
```
rule.level:>=12
```

#### SSH Brute Force:
```
rule.groups:authentication_failed AND data.srcip:*
```

#### Web Attacks:
```
rule.groups:web_attack
```

#### Port Scans:
```
rule.groups:recon AND rule.groups:network_scan
```

#### Malware:
```
rule.groups:malware OR rule.groups:rootkit
```

#### Nach Attacker IP filtern:
```
data.srcip:attacker-internet
```

#### Zeitraum (letzte Stunde):
```
timestamp:>=now-1h
```

---

## 🎨 Dashboard Visualisierungen erstellen

### 1. Bar Chart - Angriffe nach Typ:
- Gehe zu: **Visualize** → **Create visualization**
- Typ: **Vertical Bar**
- Y-Axis: Count
- X-Axis: `rule.groups`

### 2. Pie Chart - Schweregrad-Verteilung:
- Typ: **Pie Chart**
- Slice: `rule.level`

### 3. Heat Map - Angriffe nach Quelle/Ziel:
- Typ: **Heat Map**
- Y-Axis: `data.srcip`
- X-Axis: `data.dstip`

### 4. Timeline - Angriffe über Zeit:
- Typ: **Line Chart**
- X-Axis: `@timestamp`
- Y-Axis: Count

---

## 🔍 MITRE ATT&CK Mapping

Die Angriffe decken folgende MITRE ATT&CK Taktiken ab:

| Taktik | Szenario | Technik-ID |
|--------|----------|------------|
| Initial Access | SSH Brute Force | T1110 |
| Execution | Malware Simulation | T1059 |
| Persistence | Malware (Cron Jobs) | T1547 |
| Privilege Escalation | Privilege Escalation | T1068, T1548 |
| Defense Evasion | Malware (Rootkits) | T1014 |
| Credential Access | Lateral Movement | T1003 |
| Discovery | Port Scanning | T1046 |
| Lateral Movement | Lateral Movement | T1021 |
| Collection | Malware (Keylogger) | T1056 |
| Exfiltration | Malware (Data Exfil) | T1041 |
| Impact | DoS Attack | T1498 |

---

## 🛠️ Troubleshooting

### Keine Alerts im Dashboard?

1. **Überprüfe Wazuh Manager Status:**
```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/wazuh-control status
```

2. **Überprüfe Agents:**
```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/agent_control -l
```

3. **Prüfe Logs:**
```bash
sudo docker logs clab-dmz-project-sun-wazuh-manager
sudo docker logs clab-dmz-project-sun-wazuh-indexer
```

4. **Alerts manuell prüfen:**
```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager tail -f /var/ossec/logs/alerts/alerts.log
```

### Container nicht erreichbar?

```bash
# Überprüfe Container Status
sudo docker ps | grep clab-dmz-project-sun

# Überprüfe Netzwerk
sudo docker network inspect clab
```

---

## 📈 Best Practices

1. **Starte mit einzelnen Szenarien** bevor du alle auf einmal ausführst
2. **Warte 10-30 Sekunden** zwischen Angriffen für bessere Visualisierung
3. **Überprüfe Wazuh Dashboard** nach jedem Angriff
4. **Exportiere Reports** für Dokumentation
5. **Erstelle Custom Dashboards** für deine spezifischen Use Cases

---

## 🔐 Sicherheitshinweise

⚠️ **WICHTIG:** Diese Skripte sind NUR für Testzwecke in isolierten Umgebungen!

- Führe diese Angriffe NIEMALS in Produktionsumgebungen aus
- Stelle sicher, dass alle Container isoliert sind
- Verwende diese nur zu Lern- und Testzwecken
- Halte dich an geltende Gesetze und Richtlinien

---

## 📚 Weitere Ressourcen

- [Wazuh Dokumentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Rule Reference](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)

---

## 🤝 Support

Bei Fragen oder Problemen:
1. Überprüfe die Logs
2. Konsultiere die Wazuh Dokumentation
3. Prüfe die Container-Konfiguration

---

**Erstellt:** 2025-11-29  
**Version:** 1.0  
**Autor:** Antigravity AI
