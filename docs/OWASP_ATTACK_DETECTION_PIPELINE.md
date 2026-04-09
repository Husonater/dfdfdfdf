# OWASP Web Attack Detection Pipeline

## SQL Injection, XSS und Path Traversal Sichtbarmachung

### Übersicht

Dieses Dokument beschreibt die komplette Pipeline zur Erkennung und Visualisierung von Web-Angriffen (SQL Injection, XSS, Path Traversal) im Wazuh Dashboard.

---

## 🔄 Pipeline-Architektur

```
┌─────────────────┐
│   Angreifer     │
│  (attacker-     │
│   internet)     │
└────────┬────────┘
         │ HTTP Request mit Payload
         │ (SQLi/XSS/Path Traversal)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 1️⃣  WAF (ModSecurity mit OWASP CRS)                        │
│    - Erkennt Angriffsmuster                                 │
│    - Blockiert Request (403)                                │
│    - Schreibt JSON-Log: /var/log/modsec_audit.log          │
│    - Log-Format: JSON mit allen Details                     │
└────────┬────────────────────────────────────────────────────┘
         │ Log-Datei
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2️⃣  Wazuh Agent (auf WAF)                                  │
│    - Liest: /var/log/modsec_audit.log                      │
│    - Monitored mit localfile (JSON format)                  │
│    - Sendet Logs an Wazuh Manager (Port 1514)              │
└────────┬────────────────────────────────────────────────────┘
         │ Encrypted Agent Protocol
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3️⃣  Wazuh Manager                                          │
│    - Empfängt Logs von Agent                                │
│    - Decoder: local_decoder.xml                             │
│      * modsecurity-json (JSON parsing)                      │
│      * modsecurity (Legacy text parsing)                    │
│    - Rules: local_rules.xml                                 │
│      * 100010-100012: SQL Injection                         │
│      * 100020-100022: XSS                                   │
│      * 100030-100032: Path Traversal                        │
│      * 100040-100041: Command Injection                     │
│    - Generiert Alerts mit Level 12-15                       │
│    - Schreibt in: /var/ossec/logs/alerts/alerts.json       │
└────────┬────────────────────────────────────────────────────┘
         │ Alerts (JSON)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4️⃣  Filebeat                                               │
│    - Liest: /var/ossec/logs/alerts/alerts.json             │
│    - Modul: wazuh                                           │
│    - Transformiert zu Elasticsearch-Format                  │
│    - SSL/TLS Verschlüsselung                                │
└────────┬────────────────────────────────────────────────────┘
         │ HTTPS (Port 9200)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5️⃣  Wazuh Indexer (OpenSearch)                             │
│    - Index: wazuh-alerts-*                                  │
│    - Speichert Alerts mit allen Metadaten                   │
│    - Ermöglicht Queries und Aggregationen                   │
└────────┬────────────────────────────────────────────────────┘
         │ REST API (Port 9200)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ 6️⃣  Wazuh Dashboard (OpenSearch Dashboards)                │
│    - Verbindet zu Indexer via API                           │
│    - Visualisiert Alerts                                    │
│    - Filter: rule.groups, rule.id, rule.description        │
│    - URL: https://localhost:8443                            │
│    - Login: admin / SecretPassword123!                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Komponenten-Details

### 1. ModSecurity (WAF)

**Datei:** `/images/waf/modsecurity.conf`

**OWASP CRS-basierte Regeln:**

#### SQL Injection (ID: 942xxx)

- **942100**: Union/Select/Boolean/Time-based SQLi
  - Patterns: `UNION SELECT`, `' OR 1=1`, `admin' --`, `SLEEP()`, `BENCHMARK()`
  - Transformationen: urlDecodeUni, lowercase, replaceComments
  
- **942110**: Tautology-basierte SQLi
  - Patterns: `1=1`, `'a'='a'`

#### XSS (ID: 941xxx)

- **941100**: Script/Event Handler/JavaScript
  - Patterns: `<script>`, `onerror=`, `javascript:`, `eval()`, `<iframe>`
  - Transformationen: urlDecodeUni, htmlEntityDecode, lowercase

- **941110**: HTML Injection
  - Patterns: `<iframe>`, `<embed>`, `<object>`, `<applet>`

#### Path Traversal (ID: 930xxx)

- **930100**: Directory Traversal
  - Patterns: `../`, `..\\`, `/etc/passwd`, `/proc/self`, `c:\`
  - Transformationen: urlDecodeUni, normalizePath

- **930110**: Null Byte Injection
  - Patterns: `%00`, `\x00`

#### Command Injection (ID: 932xxx)

- **932100**: OS Command Injection
  - Patterns: `; ls`, `| cat`, `` `whoami` ``, `/bin/bash`, `cmd.exe`

**Log-Format:**

```json
{
  "transaction": {
    "client_ip": "172.16.1.10",
    "time_stamp": "2024-12-04T06:00:00+0000",
    "server_id": "...",
    "request": {
      "method": "GET",
      "http_version": 1.1,
      "uri": "/login.php?user=%27+OR+%271%27%3D%271",
      "headers": {...}
    },
    "response": {
      "http_code": 403
    },
    "messages": [
      {
        "message": "OWASP_CRS: SQL Injection Attack Detected",
        "details": {
          "match": "Matched Data: ' or '1'='1 found within ARGS:user",
          "data": "' OR '1'='1",
          "file": "/etc/nginx/modsecurity.d/modsecurity.conf",
          "line": "42",
          "id": "942100",
          "rev": "",
          "msg": "OWASP_CRS: SQL Injection Attack Detected",
          "severity": "CRITICAL",
          "tags": ["attack-sqli", "OWASP_CRS"]
        }
      }
    ]
  }
}
```

---

### 2. Wazuh Agent (auf WAF)

**Konfiguration:** `/var/ossec/etc/ossec.conf` (auf WAF)

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/modsec_audit.log</location>
</localfile>
```

**Funktion:**

- Monitored `/var/log/modsec_audit.log` in Echtzeit
- Parst JSON-Format
- Sendet an Wazuh Manager (172.20.20.8:1514)
- Verschlüsselt mit Agent-Key

---

### 3. Wazuh Manager

#### Decoder (`local_decoder.xml`)

```xml
<!-- JSON Decoder für ModSecurity -->
<decoder name="modsecurity-json">
  <prematch>^{"transaction":</prematch>
</decoder>

<decoder name="modsecurity-json-fields">
  <parent>modsecurity-json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

**Extrahierte Felder:**

- `transaction.client_ip`
- `transaction.request.uri`
- `transaction.messages[].details.id` (Rule ID)
- `transaction.messages[].message` (Attack Type)
- `transaction.messages[].details.data` (Payload)

#### Rules (`local_rules.xml`)

**SQL Injection Detection:**

```xml
<rule id="100010" level="12">
  <if_sid>100001,100002</if_sid>
  <match>SQL Injection</match>
  <description>OWASP_CRS: SQL Injection Attack Detected</description>
  <group>web,appsec,attack,sqli,owasp_crs,pci_dss_6.5.1</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Alert-Levels:**

- Level 12: Einzelner Angriff (SQLi, XSS, Path Traversal)
- Level 13: Kritischer Angriff (Command Injection, Null Byte)
- Level 14: 5+ Angriffe in 120s (Scanner-Verdacht)
- Level 15: 10+ gleiche Angriffe in 60s (Burst)

---

### 4. Filebeat

**Konfiguration:** `filebeat.yml`

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true

output.elasticsearch:
  hosts: ['https://wazuh-indexer:9200']
  username: 'admin'
  password: 'SecretPassword123!'
  ssl.certificate_authorities: ['/etc/filebeat/certs/root-ca.pem']
  ssl.certificate: '/etc/filebeat/certs/wazuh-manager.pem'
  ssl.key: '/etc/filebeat/certs/wazuh-manager-key.pem'
```

**Funktion:**

- Liest `/var/ossec/logs/alerts/alerts.json`
- Transformiert zu Elasticsearch-Dokumenten
- Sendet an Wazuh Indexer (Port 9200)

---

### 5. Wazuh Indexer (OpenSearch)

**Index:** `wazuh-alerts-4.x-YYYY.MM.DD`

**Dokument-Struktur:**

```json
{
  "@timestamp": "2024-12-04T06:00:00.000Z",
  "agent": {
    "name": "reverse-proxy-waf",
    "id": "001"
  },
  "rule": {
    "id": "100010",
    "level": 12,
    "description": "OWASP_CRS: SQL Injection Attack Detected",
    "groups": ["web", "appsec", "attack", "sqli", "owasp_crs"],
    "mitre": {
      "id": ["T1190"],
      "tactic": ["Initial Access"],
      "technique": ["Exploit Public-Facing Application"]
    }
  },
  "data": {
    "srcip": "172.16.1.10",
    "url": "/login.php?user=%27+OR+%271%27%3D%271"
  },
  "decoder": {
    "name": "modsecurity-json"
  }
}
```

---

### 6. Wazuh Dashboard

**URL:** <https://localhost:8443>  
**Login:** admin / SecretPassword123!

#### Dashboard-Queries für Angriffe

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

**Alle OWASP-Angriffe:**

```
rule.groups: "owasp_crs"
```

**Spezifische Rule-IDs:**

- `rule.id: 100010` - SQL Injection (Generic)
- `rule.id: 100011` - SQL Injection (942100)
- `rule.id: 100020` - XSS (Generic)
- `rule.id: 100021` - XSS (941100)
- `rule.id: 100030` - Path Traversal (Generic)
- `rule.id: 100031` - Path Traversal (930100)

---

## 🧪 Testing

### 1. Angriffe ausführen

```bash
cd /home/jp/Dokumente/SichereUnternehmensNetzwerke/dfdfdfdf
bash attack_scenarios/03_web_attacks.sh
```

### 2. Logs überprüfen

**WAF ModSecurity Log:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf tail -f /var/log/modsec_audit.log
```

**Wazuh Agent Status:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf /var/ossec/bin/wazuh-control status
```

**Wazuh Manager Alerts:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json
```

**Filebeat Status:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager filebeat test output
```

### 3. Dashboard überprüfen

1. Öffne: <https://localhost:8443>
2. Login: admin / SecretPassword123!
3. Navigiere zu: **Security Events** → **Events**
4. Filter setzen:
   - Time Range: Last 15 minutes
   - Query: `rule.groups: "owasp_crs"`

**Erwartete Alerts:**

- SQL Injection: ~6 Alerts (verschiedene Payloads)
- XSS: ~5 Alerts
- Path Traversal: ~4 Alerts
- Command Injection: ~4 Alerts

---

## 🔍 Troubleshooting

### Problem: Keine Alerts im Dashboard

**1. WAF-Logs prüfen:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf cat /var/log/modsec_audit.log | grep -i "sql injection"
```

✅ Sollte Einträge zeigen

**2. Agent-Verbindung prüfen:**

```bash
sudo docker exec clab-dmz-project-sun-reverse-proxy-waf /var/ossec/bin/agent_control -l
```

✅ Status sollte "Active" sein

**3. Manager-Decoder testen:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager /var/ossec/bin/wazuh-logtest
# Paste eine Log-Zeile aus modsec_audit.log
```

✅ Sollte Rule 100010/100020/100030 matchen

**4. Filebeat-Output prüfen:**

```bash
sudo docker exec clab-dmz-project-sun-wazuh-manager filebeat test output -e
```

✅ Sollte "connection to <https://wazuh-indexer:9200>... OK" zeigen

**5. Indexer-Query:**

```bash
curl -k -u admin:SecretPassword123! \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.groups:owasp_crs&size=10&pretty"
```

✅ Sollte Alerts zurückgeben

---

## 📊 MITRE ATT&CK Mapping

| Attack Type       | MITRE Tactic      | MITRE Technique | Rule ID |
|-------------------|-------------------|-----------------|---------|
| SQL Injection     | Initial Access    | T1190           | 100010  |
| XSS               | Execution         | T1059           | 100020  |
| Path Traversal    | Discovery         | T1083           | 100030  |
| Command Injection | Execution         | T1059           | 100040  |
| Scanner Detection | Reconnaissance    | T1595           | 100060  |

---

## 🔐 PCI DSS Compliance

Die Regeln erfüllen folgende PCI DSS-Anforderungen:

- **6.5.1**: Injection Flaws (SQL Injection, Command Injection)
- **6.5.7**: Cross-Site Scripting (XSS)
- **6.5.8**: Improper Access Control (Path Traversal)
- **11.4**: Intrusion Detection/Prevention

---

## 📝 Zusammenfassung

✅ **ModSecurity** erkennt Angriffe mit OWASP CRS-Regeln  
✅ **Wazuh Agent** sendet Logs an Manager  
✅ **Wazuh Manager** parsed und generiert Alerts  
✅ **Filebeat** forwarded an Indexer  
✅ **Wazuh Indexer** speichert in Elasticsearch  
✅ **Wazuh Dashboard** visualisiert über API  

**Alle Angriffe sind jetzt sichtbar im Dashboard! 🎉**
