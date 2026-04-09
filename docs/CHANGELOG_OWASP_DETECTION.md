# OWASP Attack Detection - Änderungsprotokoll

## Datum: 2024-12-04

### Zusammenfassung

Implementierung einer vollständigen OWASP-basierten Web Attack Detection Pipeline für SQL Injection, XSS und Path Traversal mit Sichtbarkeit im Wazuh Dashboard.

---

## 🔧 Geänderte Dateien

### 1. ModSecurity Konfiguration

**Datei:** `images/waf/modsecurity.conf`

**Änderungen:**

- ✅ Aktivierung von Audit Logging (JSON-Format)
- ✅ OWASP CRS-basierte Regeln implementiert
- ✅ SQL Injection Detection (942100, 942110)
- ✅ XSS Detection (941100, 941110)
- ✅ Path Traversal Detection (930100, 930110)
- ✅ Command Injection Detection (932100)
- ✅ Detailliertes Logging mit `logdata`
- ✅ OWASP-Tags für bessere Kategorisierung

**Wichtige Konfigurationen:**

```conf
SecAuditEngine RelevantOnly
SecAuditLogFormat JSON
SecAuditLog /var/log/modsec_audit.log
```

**Regex-Patterns:**

- SQL Injection: Union, Select, Boolean, Time-based, Tautologies
- XSS: Script tags, Event handlers, JavaScript protocol, SVG/XML
- Path Traversal: Directory traversal, Encoded paths, Null bytes
- Command Injection: Shell commands, Pipes, Command substitution

---

### 2. Wazuh Decoder

**Datei:** `local_decoder.xml`

**Änderungen:**

- ✅ JSON Decoder für ModSecurity hinzugefügt
- ✅ Legacy Text Decoder beibehalten (Fallback)
- ✅ Simple Message Decoder für kompakte Logs

**Neue Decoder:**

```xml
<decoder name="modsecurity-json">
  <prematch>^{"transaction":</prematch>
</decoder>

<decoder name="modsecurity-json-fields">
  <parent>modsecurity-json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

**Extrahierte Felder:**

- transaction.client_ip
- transaction.request.uri
- transaction.messages[].details.id
- transaction.messages[].message
- transaction.messages[].details.data

---

### 3. Wazuh Rules

**Datei:** `local_rules.xml`

**Änderungen:**

- ✅ Erweiterte Rule-Struktur mit OWASP-Kategorisierung
- ✅ Spezifische Rules für jede OWASP CRS-ID
- ✅ MITRE ATT&CK Mapping hinzugefügt
- ✅ PCI DSS Compliance-Tags
- ✅ Aggregation Rules für Scanner-Detection
- ✅ Burst Detection für automatisierte Angriffe

**Neue Rules:**

| Rule ID | Level | Beschreibung | MITRE |
|---------|-------|--------------|-------|
| 100001 | 5 | ModSecurity Base Event | - |
| 100002 | 5 | ModSecurity JSON Event | - |
| 100010 | 12 | SQL Injection (Generic) | T1190 |
| 100011 | 12 | SQL Injection (942100) | T1190 |
| 100012 | 12 | SQL Injection Tautology (942110) | T1190 |
| 100020 | 12 | XSS (Generic) | T1059 |
| 100021 | 12 | XSS Script/Event (941100) | T1059 |
| 100022 | 12 | XSS HTML Injection (941110) | T1059 |
| 100030 | 12 | Path Traversal (Generic) | T1083 |
| 100031 | 12 | Path Traversal (930100) | T1083 |
| 100032 | 13 | Null Byte Injection (930110) | T1083 |
| 100040 | 13 | Command Injection (Generic) | T1059 |
| 100041 | 13 | Command Injection (932100) | T1059 |
| 100050 | 13 | Shell Injection (Legacy) | T1059 |
| 100060 | 14 | Multiple Attacks (Scanner) | T1595 |
| 100061 | 15 | SQL Injection Burst | T1190 |
| 100062 | 15 | XSS Burst | T1059 |

**Gruppen:**

- `owasp_crs` - Alle OWASP-basierten Alerts
- `sqli` - SQL Injection
- `xss` - Cross-Site Scripting
- `path-traversal` - Path Traversal
- `command-injection` - Command Injection
- `pci_dss_6.5.1` - PCI DSS Compliance
- `pci_dss_6.5.7` - PCI DSS Compliance
- `pci_dss_6.5.8` - PCI DSS Compliance

---

## 📄 Neue Dateien

### 1. Pipeline-Dokumentation

**Datei:** `docs/OWASP_ATTACK_DETECTION_PIPELINE.md`

**Inhalt:**

- Vollständige Pipeline-Architektur
- Komponenten-Details (WAF, Agent, Manager, Filebeat, Indexer, Dashboard)
- Log-Formate und Beispiele
- Troubleshooting-Guide
- MITRE ATT&CK Mapping
- PCI DSS Compliance-Informationen

---

### 2. Pipeline-Diagramme

**Datei:** `docs/OWASP_PIPELINE_DIAGRAMS.md`

**Inhalt:**

- Datenfluss-Diagramm (Mermaid)
- Sequence-Diagramm für Attack Detection
- Rule-Mapping-Diagramm
- MITRE ATT&CK Coverage-Diagramm
- Alert Severity Levels-Diagramm

---

### 3. Quick Start Guide

**Datei:** `docs/OWASP_QUICK_START.md`

**Inhalt:**

- Schnellstart-Anleitung
- Test-Befehle
- Dashboard-Filter
- Troubleshooting
- Manuelle Tests
- Erfolgs-Checkliste

---

### 4. Test-Script

**Datei:** `attack_scenarios/test_owasp_detection.sh`

**Funktionen:**

- Automatisierte Tests für SQLi, XSS, Path Traversal
- Farbige Ausgabe
- Erfolgs-/Fehler-Tracking
- Detaillierte Anweisungen für nächste Schritte

**Verwendung:**

```bash
bash attack_scenarios/test_owasp_detection.sh
```

---

## 🔄 Pipeline-Flow

```
1. Attacker sendet HTTP Request mit Payload
   ↓
2. ModSecurity (WAF) erkennt Angriff mit OWASP CRS
   ↓
3. ModSecurity blockiert (403) und schreibt JSON-Log
   ↓
4. Wazuh Agent liest Log-Datei
   ↓
5. Wazuh Manager decoded und matched Rules
   ↓
6. Wazuh Manager generiert Alert
   ↓
7. Filebeat shipped Alert an Indexer
   ↓
8. Wazuh Indexer speichert in Elasticsearch
   ↓
9. Wazuh Dashboard visualisiert über API
```

---

## 🎯 Erkannte Angriffe

### SQL Injection

- ✅ Union-based: `' UNION SELECT NULL--`
- ✅ Boolean-based: `' OR '1'='1`
- ✅ Tautology: `admin' OR 1=1--`
- ✅ Time-based: `' OR SLEEP(5)--`
- ✅ Stacked queries: `'; DROP TABLE users--`
- ✅ Comment injection: `admin' --`

### Cross-Site Scripting (XSS)

- ✅ Script tags: `<script>alert('XSS')</script>`
- ✅ Event handlers: `<img src=x onerror=alert(1)>`
- ✅ SVG/XML: `<svg/onload=alert(1)>`
- ✅ JavaScript protocol: `javascript:alert(1)`
- ✅ HTML injection: `<iframe src=...>`
- ✅ Data URIs: `data:text/html,...`

### Path Traversal

- ✅ Directory traversal: `../../../../etc/passwd`
- ✅ Encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
- ✅ Windows paths: `..\\..\\windows\\system32`
- ✅ Absolute paths: `/etc/shadow`
- ✅ Null bytes: `file.php%00.jpg`
- ✅ Sensitive files: `/proc/self/environ`

### Command Injection

- ✅ Shell commands: `; ls -la`
- ✅ Pipes: `| cat /etc/passwd`
- ✅ Backticks: `` `whoami` ``
- ✅ Command substitution: `$(cat /etc/shadow)`
- ✅ Shell binaries: `/bin/bash`, `cmd.exe`

---

## 📊 Dashboard-Integration

### Filter-Queries

**Alle OWASP-Angriffe:**

```
rule.groups: "owasp_crs"
```

**SQL Injection:**

```
rule.groups: "sqli" AND rule.groups: "owasp_crs"
```

**XSS:**

```
rule.groups: "xss" AND rule.groups: "owasp_crs"
```

**Path Traversal:**

```
rule.groups: "path-traversal" AND rule.groups: "owasp_crs"
```

**Kritische Angriffe:**

```
rule.level: >=12 AND rule.groups: "owasp_crs"
```

**Scanner-Detection:**

```
rule.id: 100060
```

### Visualisierungen

1. **Attack Timeline** - Line Chart über Zeit
2. **Attack Distribution** - Pie Chart nach Typ
3. **Top Attackers** - Table mit Source IPs
4. **MITRE ATT&CK Heatmap** - Tactic vs Technique
5. **Alert Severity** - Bar Chart nach Level

---

## 🔐 Compliance

### MITRE ATT&CK

- **T1190** - Exploit Public-Facing Application (SQLi)
- **T1059** - Command and Scripting Interpreter (XSS, Cmd Injection)
- **T1083** - File and Directory Discovery (Path Traversal)
- **T1595** - Active Scanning (Scanner Detection)

### PCI DSS

- **6.5.1** - Injection Flaws
- **6.5.7** - Cross-Site Scripting
- **6.5.8** - Improper Access Control
- **11.4** - Intrusion Detection/Prevention

---

## ✅ Testing

### Automatisierter Test

```bash
bash attack_scenarios/test_owasp_detection.sh
```

**Erwartete Ausgabe:**

```
SQL Injection: 4/4 attacks blocked
XSS: 4/4 attacks blocked
Path Traversal: 4/4 attacks blocked
Total Attacks Blocked: 12/12
[✓] ALL ATTACKS BLOCKED!
```

### Vollständige Web-Angriffe

```bash
bash attack_scenarios/03_web_attacks.sh
```

**Erwartete Alerts im Dashboard:**

- ~6 SQL Injection Alerts
- ~5 XSS Alerts
- ~4 Path Traversal Alerts
- ~4 Command Injection Alerts

---

## 🔍 Verifikation

### 1. WAF-Logs prüfen

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf \
  tail -20 /var/log/modsec_audit.log | jq .
```

### 2. Wazuh Alerts prüfen

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager \
  tail -20 /var/ossec/logs/alerts/alerts.json | jq .
```

### 3. Dashboard öffnen

```
URL: https://localhost:8443
Login: admin / SecretPassword123!
Filter: rule.groups: "owasp_crs"
```

---

## 📝 Zusammenfassung

### Was wurde implementiert?

1. ✅ **OWASP CRS-basierte ModSecurity-Regeln**
   - SQL Injection (942xxx)
   - XSS (941xxx)
   - Path Traversal (930xxx)
   - Command Injection (932xxx)

2. ✅ **Wazuh-Integration**
   - JSON Decoder für ModSecurity
   - Spezifische Rules für jede Attack-Kategorie
   - MITRE ATT&CK Mapping
   - PCI DSS Compliance-Tags

3. ✅ **Dashboard-Visualisierung**
   - Filter-Queries für alle Attack-Typen
   - Aggregation Rules für Scanner-Detection
   - Burst Detection für automatisierte Angriffe

4. ✅ **Dokumentation**
   - Pipeline-Architektur
   - Mermaid-Diagramme
   - Quick Start Guide
   - Test-Scripts

### Ergebnis

**Alle SQL Injection, XSS und Path Traversal Angriffe sind jetzt:**

- ✅ Erkannt durch ModSecurity OWASP CRS
- ✅ Geloggt in strukturiertem JSON-Format
- ✅ Analysiert durch Wazuh Manager
- ✅ Visualisiert im Wazuh Dashboard
- ✅ Gemappt zu MITRE ATT&CK Framework
- ✅ PCI DSS-konform

**Die komplette Pipeline von Agent → Wazuh Manager → Filebeat → Indexer → Dashboard ist funktional und nachvollziehbar! 🎉**
