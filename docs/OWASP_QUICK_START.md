# 🛡️ OWASP Web Attack Detection - Quick Start Guide

## Übersicht

Dieses System erkennt und visualisiert **SQL Injection**, **XSS** und **Path Traversal** Angriffe in Echtzeit mit:

- ✅ **ModSecurity** mit OWASP Core Rule Set (CRS)
- ✅ **Wazuh SIEM** für Monitoring und Alerting
- ✅ **Dashboard** für Visualisierung
- ✅ **MITRE ATT&CK** Mapping
- ✅ **PCI DSS** Compliance

---

## 🚀 Quick Start

### 1. Deployment starten

```bash
cd /home/jp/Dokumente/SichereUnternehmensNetzwerke/dfdfdfdf
sudo bash start_dmz_secure.sh
```

**Wartezeit:** ~2-3 Minuten für vollständiges Deployment

---

### 2. Angriffe testen

**Option A: Automatischer Test (empfohlen)**

```bash
bash attack_scenarios/test_owasp_detection.sh
```

**Option B: Vollständige Web-Angriffe**

```bash
bash attack_scenarios/03_web_attacks.sh
```

**Erwartete Ausgabe:**

```
[✓] BLOCKED (403) - Attack detected!
SQL Injection: 4/4 attacks blocked
XSS: 4/4 attacks blocked
Path Traversal: 4/4 attacks blocked
```

---

### 3. Dashboard öffnen

**URL:** <https://localhost:8443>  
**Login:** `admin` / `SecretPassword123!`

**Navigation:**

1. Klicke auf **"Security Events"** (linke Sidebar)
2. Klicke auf **"Events"**
3. Setze Time Range auf **"Last 15 minutes"**

---

### 4. Alerts filtern

**Alle OWASP-Angriffe:**

```
rule.groups: "owasp_crs"
```

**Nur SQL Injection:**

```
rule.groups: "sqli" AND rule.groups: "owasp_crs"
```

**Nur XSS:**

```
rule.groups: "xss" AND rule.groups: "owasp_crs"
```

**Nur Path Traversal:**

```
rule.groups: "path-traversal" AND rule.groups: "owasp_crs"
```

**Kritische Angriffe (Level 12+):**

```
rule.level: >=12 AND rule.groups: "owasp_crs"
```

---

## 📊 Was wird erkannt?

### SQL Injection (Rule 942xxx)

- ✅ Union-based: `' UNION SELECT NULL--`
- ✅ Boolean-based: `' OR '1'='1`
- ✅ Tautology: `admin' OR 1=1--`
- ✅ Time-based: `' OR SLEEP(5)--`
- ✅ Stacked queries: `'; DROP TABLE users--`

### Cross-Site Scripting (Rule 941xxx)

- ✅ Script tags: `<script>alert('XSS')</script>`
- ✅ Event handlers: `<img src=x onerror=alert(1)>`
- ✅ SVG/XML: `<svg/onload=alert(1)>`
- ✅ JavaScript protocol: `javascript:alert(1)`
- ✅ HTML injection: `<iframe src=...>`

### Path Traversal (Rule 930xxx)

- ✅ Directory traversal: `../../../../etc/passwd`
- ✅ Encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
- ✅ Windows paths: `..\\..\\windows\\system32`
- ✅ Absolute paths: `/etc/shadow`
- ✅ Null bytes: `file.php%00.jpg`

### Command Injection (Rule 932xxx)

- ✅ Shell commands: `; ls -la`
- ✅ Pipes: `| cat /etc/passwd`
- ✅ Backticks: `` `whoami` ``
- ✅ Command substitution: `$(cat /etc/shadow)`

---

## 🔍 Troubleshooting

### Problem: Keine Alerts im Dashboard

**1. Prüfe WAF-Logs:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf \
  tail -20 /var/log/modsec_audit.log
```

✅ Sollte JSON-Einträge mit `"msg": "OWASP_CRS: ..."` zeigen

**2. Prüfe Wazuh Agent:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf \
  /var/ossec/bin/wazuh-control status
```

✅ Sollte `wazuh-agentd is running...` zeigen

**3. Prüfe Wazuh Manager Alerts:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager \
  tail -20 /var/ossec/logs/alerts/alerts.json | jq .
```

✅ Sollte Alerts mit `"rule": {"id": "100010"...}` zeigen

**4. Prüfe Filebeat:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager \
  filebeat test output -e
```

✅ Sollte `connection to https://wazuh-indexer:9200... OK` zeigen

**5. Prüfe Indexer:**

```bash
curl -k -u admin:SecretPassword123! \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.groups:owasp_crs&size=5&pretty"
```

✅ Sollte Alerts zurückgeben

---

## 📁 Wichtige Dateien

### Konfiguration

- **ModSecurity Rules:** `images/waf/modsecurity.conf`
- **Wazuh Decoder:** `local_decoder.xml`
- **Wazuh Rules:** `local_rules.xml`

### Dokumentation

- **Pipeline-Details:** `docs/OWASP_ATTACK_DETECTION_PIPELINE.md`
- **Diagramme:** `docs/OWASP_PIPELINE_DIAGRAMS.md`

### Scripts

- **Quick Test:** `attack_scenarios/test_owasp_detection.sh`
- **Full Web Attacks:** `attack_scenarios/03_web_attacks.sh`
- **Deployment:** `start_dmz_secure.sh`

---

## 🎯 Alert-Levels

| Level | Severity | Beschreibung | Beispiel |
|-------|----------|--------------|----------|
| 5 | Info | Base Event | ModSecurity Event erkannt |
| 12 | High | Einzelner Angriff | SQL Injection, XSS, Path Traversal |
| 13 | Critical | Gefährlicher Angriff | Command Injection, Null Byte |
| 14 | Severe | Multiple Angriffe | 5+ Angriffe in 120s (Scanner) |
| 15 | Emergency | Attack Burst | 10+ gleiche Angriffe in 60s |

---

## 🔐 MITRE ATT&CK Mapping

| Attack Type | MITRE Tactic | MITRE Technique | Wazuh Rule |
|-------------|--------------|-----------------|------------|
| SQL Injection | Initial Access | T1190 | 100010-100012 |
| XSS | Execution | T1059 | 100020-100022 |
| Path Traversal | Discovery | T1083 | 100030-100032 |
| Command Injection | Execution | T1059 | 100040-100041 |
| Scanner Detection | Reconnaissance | T1595 | 100060 |

---

## 📈 Dashboard-Visualisierungen

### Empfohlene Dashboards

**1. OWASP Attack Overview**

- Visualization: Bar Chart
- Y-Axis: Count
- X-Axis: rule.description
- Filter: `rule.groups: "owasp_crs"`

**2. Attack Timeline**

- Visualization: Line Chart
- Y-Axis: Count
- X-Axis: @timestamp
- Split Series: rule.groups

**3. Top Attackers**

- Visualization: Table
- Columns: data.srcip, Count
- Sort: Count (Descending)
- Filter: `rule.groups: "owasp_crs"`

**4. MITRE ATT&CK Heatmap**

- Visualization: Heatmap
- Rows: rule.mitre.tactic
- Columns: rule.mitre.technique
- Metric: Count

---

## 🧪 Manuelle Tests

### SQL Injection Test

```bash
sudo docker exec clab-dmz-project-sun-attacker-internet \
  curl -G "http://reverse-proxy-waf/login.php" \
  --data-urlencode "user=' OR '1'='1"
```

### XSS Test

```bash
sudo docker exec clab-dmz-project-sun-attacker-internet \
  curl -G "http://reverse-proxy-waf/search.php" \
  --data-urlencode "q=<script>alert('XSS')</script>"
```

### Path Traversal Test

```bash
sudo docker exec clab-dmz-project-sun-attacker-internet \
  curl -G "http://reverse-proxy-waf/download.php" \
  --data-urlencode "file=../../../../etc/passwd"
```

**Erwartete Antwort:** `403 Forbidden`

---

## 📝 Logs in Echtzeit verfolgen

**WAF Logs:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf \
  tail -f /var/log/modsec_audit.log | jq .
```

**Wazuh Alerts:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager \
  tail -f /var/ossec/logs/alerts/alerts.json | jq .
```

---

## 🔄 Pipeline-Übersicht

```
Attacker → WAF (ModSecurity OWASP CRS) → Wazuh Agent → 
Wazuh Manager → Filebeat → Wazuh Indexer → Dashboard
```

**Jeder Schritt ist sichtbar und nachvollziehbar!**

---

## ✅ Erfolgs-Checkliste

- [ ] Deployment erfolgreich (`start_dmz_secure.sh`)
- [ ] Test-Script zeigt alle Angriffe als "BLOCKED"
- [ ] WAF-Logs enthalten OWASP_CRS-Meldungen
- [ ] Wazuh Agent ist "Active"
- [ ] Wazuh Manager generiert Alerts (Rule 100xxx)
- [ ] Filebeat verbindet zu Indexer
- [ ] Dashboard zeigt Alerts mit Filter `rule.groups: "owasp_crs"`
- [ ] MITRE ATT&CK Tags sind sichtbar

---

## 🆘 Support

Bei Problemen:

1. **Logs prüfen** (siehe Troubleshooting)
2. **Dokumentation lesen** (`docs/OWASP_ATTACK_DETECTION_PIPELINE.md`)
3. **Diagramme ansehen** (`docs/OWASP_PIPELINE_DIAGRAMS.md`)
4. **Container-Status prüfen:** `sudo docker ps`

---

## 🎉 Fertig

Alle SQL Injection, XSS und Path Traversal Angriffe sind jetzt:

- ✅ **Erkannt** durch ModSecurity OWASP CRS
- ✅ **Geloggt** in JSON-Format
- ✅ **Analysiert** durch Wazuh
- ✅ **Visualisiert** im Dashboard
- ✅ **Gemappt** zu MITRE ATT&CK

**Viel Erfolg! 🚀**
