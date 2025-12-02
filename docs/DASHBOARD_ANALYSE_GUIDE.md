# WAZUH DASHBOARD ANALYSE - NÄCHSTE SCHRITTE

## 🎯 Was du im Dashboard machen solltest:

### 1. ZEITFILTER ANPASSEN
**Aktuell:** "Last 24 hours"
**Empfehlung:** Ändere auf "Last 15 minutes" um nur die neuesten Angriffe zu sehen

**So geht's:**
- Klicke oben rechts auf "Last 24 hours"
- Wähle "Last 15 minutes" oder "Last 1 hour"
- Klicke "Refresh"

---

### 2. SECURITY EVENTS DETAILLIERT ANSEHEN

**Navigation:**
1. Klicke auf das ☰ Menü (oben links)
2. Wähle "Security events" (nicht Dashboard)
3. Du siehst jetzt eine detaillierte Liste aller Events

**Wichtige Spalten:**
- **Time** - Wann der Angriff stattfand
- **Agent** - Welcher Host (aktuell nur wazuh-manager)
- **Rule** - Welche Regel ausgelöst wurde
- **Level** - Schweregrad (10+ = kritisch)
- **Description** - Was passiert ist

---

### 3. NACH KRITISCHEN EVENTS FILTERN

**In der Suchleiste eingeben:**

```
rule.level:>=10
```

**Das zeigt dir:**
- SSH Brute Force Attacks (Rule 5763)
- Sudo Abuse (Rule 5404)
- Andere kritische Sicherheitsvorfälle

**Weitere nützliche Filter:**

```
# Nur Authentication Failures
rule.groups:authentication_failed

# Nur erfolgreiche Logins (nach Brute Force!)
rule.id:5715

# Alle Events der letzten 10 Minuten
timestamp:>=now-10m

# Kombiniert: Kritische Auth-Events
rule.level:>=10 AND rule.groups:authentication
```

---

### 4. MITRE ATT&CK ANSEHEN

**Navigation:**
1. ☰ Menü → "MITRE ATT&CK"
2. Du siehst eine Matrix aller erkannten Taktiken

**Erwartete Taktiken:**
- ✅ Initial Access (T1110 - Brute Force)
- ✅ Privilege Escalation (T1548 - Sudo Abuse)
- ✅ Persistence
- ✅ Credential Access

**Klicke auf eine Taktik** um Details zu sehen!

---

### 5. EINZELNE ALERTS UNTERSUCHEN

**Im Security Events Tab:**

1. **Klicke auf einen Alert** in der Liste
2. Du siehst Details wie:
   - Vollständige Log-Nachricht
   - Quell-IP (data.srcip)
   - Ziel-IP (data.dstip)
   - Benutzer (data.srcuser)
   - MITRE ATT&CK Mapping
   - Compliance (PCI DSS, GDPR, etc.)

**Beispiel - SSH Brute Force Alert:**
```
Rule: 5763 (Level 10)
Description: sshd: brute force trying to get access to the system
MITRE: T1110 - Brute Force
Source IP: 172.20.20.2
Failed User: admin, root, oracle, postgres...
```

---

### 6. VISUALISIERUNGEN ERSTELLEN

**Gehe zu: Visualize → Create visualization**

**Empfohlene Visualisierungen:**

#### A) Timeline der Angriffe
- **Typ:** Line Chart
- **Y-Axis:** Count
- **X-Axis:** @timestamp
- **Bucket:** Date Histogram (1 minute intervals)

#### B) Alert-Level Verteilung
- **Typ:** Pie Chart
- **Slice by:** rule.level
- **Filter:** timestamp:>=now-1h

#### C) Top Angriffstypen
- **Typ:** Vertical Bar
- **Y-Axis:** Count
- **X-Axis:** rule.description
- **Top:** 10

#### D) Angriffs-Heatmap
- **Typ:** Heat Map
- **Y-Axis:** data.srcip
- **X-Axis:** rule.groups

---

### 7. DASHBOARD ERSTELLEN

**Schritte:**
1. Gehe zu "Dashboard" → "Create dashboard"
2. Klicke "Add" → Wähle deine Visualisierungen
3. Arrangiere sie nach Belieben
4. Speichere als "APT Attack Analysis"

**Empfohlenes Layout:**
```
┌─────────────────┬─────────────────┐
│  Timeline       │  Alert Levels   │
├─────────────────┼─────────────────┤
│  Top Attacks    │  MITRE ATT&CK   │
├─────────────────┴─────────────────┤
│  Recent Security Events (Table)   │
└───────────────────────────────────┘
```

---

### 8. THREAT HUNTING

**Gehe zu: Threat Hunting**

**Interessante Queries:**

```
# Finde erfolgreiche Logins nach vielen Fehlversuchen
rule.id:5715 AND timestamp:>=now-1h

# Finde Sudo Abuse
rule.id:5404

# Finde alle Events von Attacker IP
data.srcip:172.20.20.2

# Finde Lateral Movement
rule.groups:lateral_movement

# Finde Datenexfiltration
rule.description:*exfil* OR rule.description:*transfer*
```

---

### 9. REPORTS EXPORTIEREN

**PDF Report erstellen:**
1. Gehe zu "Reporting"
2. Wähle "Security events report"
3. Zeitraum: Last 1 hour
4. Klicke "Generate report"
5. Download als PDF

**CSV Export:**
1. In Security Events
2. Wähle Events aus
3. Klicke "Export" → "CSV"

---

### 10. AGENT STATUS ÜBERPRÜFEN

**Gehe zu: Agents**

**Du siehst:**
- **ID 000** - wazuh-manager (Active/Local)
- Status: Active ✅
- Last keep alive: Just now

**Warum nur 1 Agent?**
- Unsere Simulation läuft direkt im Manager
- Für echte Überwachung müssten Agents auf webserver, WAF, etc. installiert werden

---

## 🎨 AKTUELLE DASHBOARD-INTERPRETATION

### Was die Zahlen bedeuten:

**115 Total Events (24h):**
- Das sind die Events im aktuellen Dashboard-Filter
- Ändere auf "Last 15 minutes" um nur neue zu sehen

**90 Authentication Failures:**
- 🎯 **ERFOLG!** Das sind unsere simulierten Angriffe!
- SSH Brute Force mit 50+ Versuchen
- Lateral Movement Versuche

**1 Level 12+ Event:**
- Höchst-kritischer Alert
- Wahrscheinlich: Brute Force Detection
- Oder: Multiple Sudo Failures

**1 Authentication Success:**
- 🔴 **KOMPROMITTIERUNG!**
- Nach Brute Force erfolgreicher Login
- Genau wie im APT-Szenario geplant!

---

## 🔍 NÄCHSTE SCHRITTE

1. ✅ **Zeitfilter auf 15 Min ändern**
2. ✅ **Security Events Tab öffnen**
3. ✅ **Nach rule.level:>=10 filtern**
4. ✅ **Einzelne Alerts durchklicken**
5. ✅ **MITRE ATT&CK Matrix ansehen**
6. ✅ **Dashboard mit Visualisierungen erstellen**

---

## 💡 TIPPS

**Wenn du keine neuen Events siehst:**
- Führe nochmal aus: `./generate_wazuh_events.sh`
- Oder: `./attack_scenarios/08_apt_full_attack.sh`
- Warte 30 Sekunden
- Klicke "Refresh" im Dashboard

**Für bessere Visualisierung:**
- Ändere Zeitfilter auf "Last 15 minutes"
- Nutze Auto-refresh (oben rechts)
- Erstelle Custom Dashboards

**Für Demos:**
- Screenshot von Security Events
- Screenshot von MITRE ATT&CK
- Export als PDF Report

---

Viel Erfolg beim Analysieren! 🔍🛡️
