# 🎯 APT ANGRIFF - WAZUH ANALYSE GUIDE

## ☠️ DURCHGEFÜHRTER ANGRIFF

Ein **Advanced Persistent Threat (APT)** wurde erfolgreich simuliert!

### 📊 Angriffs-Phasen (MITRE ATT&CK)

#### **PHASE 1: RECONNAISSANCE** 🔍
- **Taktik:** TA0043 - Reconnaissance
- **Technik:** T1046 - Network Service Scanning
- **Aktivität:** 
  - Port Scanning (21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443)
  - Service Enumeration
- **Wazuh Alerts:** Port Scan Detection

---

#### **PHASE 2: INITIAL ACCESS** 🚪
- **Taktik:** TA0001 - Initial Access
- **Techniken:** 
  - T1110 - Brute Force (50 SSH-Versuche)
  - T1190 - Exploit Public-Facing Application
- **Aktivität:**
  - SSH Brute Force (admin, root, oracle, postgres, mysql, etc.)
  - SQL Injection Angriffe
  - XSS (Cross-Site Scripting)
  - Path Traversal
  - Command Injection
  - **ERFOLG:** Shell-Zugriff als www-data
- **Wazuh Alerts:** 
  - Rule 5760 (Level 5) - SSH authentication failed
  - Rule 5763 (Level 10) - SSH brute force detected
  - Web attack alerts

---

#### **PHASE 3: PERSISTENCE** 🔒
- **Taktik:** TA0003 - Persistence
- **Techniken:**
  - T1053 - Scheduled Task/Job (Cron)
  - T1098 - Account Manipulation (SSH Keys)
  - T1505 - Server Software Component (Backdoor)
- **Aktivität:**
  - Backdoor Installation (/tmp/.hidden_backdoor)
  - Cron Job für Persistenz
  - SSH Key Manipulation
- **Wazuh Alerts:** 
  - Rootcheck - Suspicious files detected
  - File Integrity Monitoring

---

#### **PHASE 4: PRIVILEGE ESCALATION** ⬆️
- **Taktik:** TA0004 - Privilege Escalation
- **Techniken:**
  - T1548 - Abuse Elevation Control Mechanism (Sudo)
  - T1068 - Exploitation for Privilege Escalation
- **Aktivität:**
  - 10 Sudo Abuse Versuche
  - Kernel Exploit Versuch
  - **ERFOLG:** Root-Zugriff erlangt
- **Wazuh Alerts:**
  - Sudo authentication failures
  - Kernel segfault

---

#### **PHASE 5: CREDENTIAL ACCESS** 🔑
- **Taktik:** TA0006 - Credential Access
- **Techniken:**
  - T1003 - OS Credential Dumping
  - T1555 - Credentials from Password Stores
- **Aktivität:**
  - /etc/shadow Zugriff
  - /etc/passwd Zugriff
  - Memory Dumping (mimikatz simulation)
- **Wazuh Alerts:**
  - Unauthorized file access
  - Suspicious process detected

---

#### **PHASE 6: LATERAL MOVEMENT** ↔️
- **Taktik:** TA0008 - Lateral Movement
- **Techniken:**
  - T1021 - Remote Services
  - T1570 - Lateral Tool Transfer
- **Aktivität:**
  - Interne Netzwerk-Reconnaissance (172.20.20.3-10)
  - SSH/RDP Brute Force auf interne Hosts
  - **ERFOLG:** DB-Server kompromittiert
- **Wazuh Alerts:**
  - Multiple SSH connections
  - Internal network scanning

---

#### **PHASE 7: COLLECTION** 📦
- **Taktik:** TA0009 - Collection
- **Techniken:**
  - T1005 - Data from Local System
  - T1039 - Data from Network Shared Drive
- **Aktivität:**
  - Sensitive Daten identifiziert:
    - customer_data.sql
    - credit_cards.csv
    - passwords.txt
    - confidential_docs.zip
  - Daten komprimiert (250MB)
- **Wazuh Alerts:**
  - Suspicious file access
  - Large archive created

---

#### **PHASE 8: EXFILTRATION** 📤
- **Taktik:** TA0010 - Exfiltration
- **Techniken:**
  - T1071 - Application Layer Protocol (C2)
  - T1041 - Exfiltration Over C2 Channel
  - T1048 - Exfiltration Over Alternative Protocol (DNS)
- **Aktivität:**
  - C2 Server Kommunikation (evil-c2.darkweb.onion)
  - 250MB Daten über HTTPS exfiltriert
  - DNS Tunneling als Backup
- **Wazuh Alerts:**
  - C2 communication detected
  - Large data transfer
  - Suspicious DNS queries

---

#### **PHASE 9: IMPACT** 💥
- **Taktik:** TA0040 - Impact
- **Techniken:**
  - T1486 - Data Encrypted for Impact (Ransomware)
  - T1485 - Data Destruction
  - T1498 - Network Denial of Service
- **Aktivität:**
  - Ransomware Deployment (WannaCry simulation)
  - Dateien verschlüsselt (.locked)
  - Datenbank gelöscht
  - System-Logs gelöscht
  - DoS auf Web-Services
- **Wazuh Alerts:**
  - Ransomware detected
  - Critical files deleted
  - High connection rate

---

## 📈 WAZUH DASHBOARD ANALYSE

### Zugriff:
```
URL:      https://localhost:8443
Username: admin
Password: SecretPassword123!
```

### 🔍 Empfohlene Suchabfragen:

#### 1. Alle kritischen Events (Level 10+):
```
rule.level:>=10
```

#### 2. SSH Brute Force Angriffe:
```
rule.groups:authentication_failures
```

#### 3. Web-Angriffe:
```
rule.groups:web
```

#### 4. Rootkit/Malware Detection:
```
rule.groups:rootcheck
```

#### 5. Alle Events vom Attacker:
```
data.srcip:172.20.20.2
```

#### 6. Events der letzten 10 Minuten:
```
timestamp:>=now-10m
```

#### 7. Kombinierte Suche (Kritische SSH-Angriffe):
```
rule.level:>=10 AND rule.groups:authentication_failures
```

---

## 🎨 MITRE ATT&CK Mapping

Navigiere zu **MITRE ATT&CK** im Dashboard um zu sehen:

### Verwendete Taktiken:
- ✅ **TA0043** - Reconnaissance
- ✅ **TA0001** - Initial Access
- ✅ **TA0003** - Persistence
- ✅ **TA0004** - Privilege Escalation
- ✅ **TA0006** - Credential Access
- ✅ **TA0008** - Lateral Movement
- ✅ **TA0009** - Collection
- ✅ **TA0010** - Exfiltration
- ✅ **TA0040** - Impact

### Verwendete Techniken (Auswahl):
- T1046 - Network Service Scanning
- T1110 - Brute Force
- T1190 - Exploit Public-Facing Application
- T1053 - Scheduled Task/Job
- T1548 - Abuse Elevation Control Mechanism
- T1003 - OS Credential Dumping
- T1021 - Remote Services
- T1071 - Application Layer Protocol
- T1486 - Data Encrypted for Impact
- T1485 - Data Destruction

---

## 📊 DASHBOARD VISUALISIERUNGEN ERSTELLEN

### 1. Timeline der Angriffsphasen
- **Typ:** Line Chart
- **X-Axis:** @timestamp
- **Y-Axis:** Count
- **Split:** rule.level

### 2. Alert-Schweregrad Verteilung
- **Typ:** Pie Chart
- **Slice by:** rule.level
- **Filter:** timestamp:>=now-1h

### 3. Top Angriffstypen
- **Typ:** Bar Chart
- **X-Axis:** rule.groups
- **Y-Axis:** Count
- **Top:** 10

### 4. Angriffs-Heatmap
- **Typ:** Heat Map
- **Y-Axis:** data.srcip
- **X-Axis:** rule.groups

### 5. MITRE ATT&CK Coverage
- Nutze das integrierte MITRE ATT&CK Dashboard
- Zeigt alle erkannten Taktiken und Techniken

---

## 🎯 ALERT STATISTIKEN

**Gesamt generierte Alerts:** 6591+

**Alert-Level Verteilung:**
- Level 3: Informational
- Level 5: Low Priority
- Level 10: High Priority (Brute Force, etc.)

**Top Alert-Typen:**
1. SSH Authentication Failed (Rule 5760)
2. SSH Brute Force (Rule 5763)
3. Rootcheck Alerts
4. File Integrity Monitoring
5. Web Attack Detection

---

## 🔧 WEITERE ANALYSEN

### Threat Hunting Queries:

```
# Finde alle erfolgreichen Logins nach Brute Force
rule.id:5715 AND timestamp:>=now-1h

# Finde Backdoor-Aktivitäten
rule.groups:rootcheck AND rule.level:>=7

# Finde Datenexfiltration
rule.description:*transfer* OR rule.description:*upload*

# Finde Ransomware-Aktivität
rule.description:*ransomware* OR rule.description:*encrypted*

# Finde C2 Kommunikation
rule.description:*C2* OR rule.description:*command*control*
```

---

## 📚 NÄCHSTE SCHRITTE

1. **Analysiere im Dashboard:**
   - Öffne https://localhost:8443
   - Gehe zu "Security Events"
   - Nutze die oben genannten Filter

2. **Erstelle Custom Dashboards:**
   - Kombiniere verschiedene Visualisierungen
   - Speichere für zukünftige Analysen

3. **Exportiere Reports:**
   - PDF-Reports für Dokumentation
   - CSV-Export für weitere Analyse

4. **Weitere Angriffe simulieren:**
   ```bash
   cd /home/jp/dfdfdfdf/attack_scenarios
   ./quick_start.sh
   ```

---

## ⚠️ WICHTIG

Dies war eine **Simulation** zu Lern- und Testzwecken!

- Niemals in Produktionsumgebungen ausführen
- Nur in isolierten Test-Umgebungen nutzen
- Halte dich an geltende Gesetze und Richtlinien

---

## 🎉 ZUSAMMENFASSUNG

Du hast erfolgreich einen **vollständigen APT-Angriff** simuliert, der:

✅ 9 Angriffsphasen durchlaufen hat
✅ 6591+ Wazuh Alerts generiert hat
✅ Alle MITRE ATT&CK Taktiken abdeckt
✅ Im Wazuh Dashboard visualisierbar ist

**Viel Spaß beim Analysieren! 🔍🛡️**

---

*Erstellt: 2025-11-29*  
*Angriffsdauer: ~3 Minuten*  
*Generierte Events: 6591+*
