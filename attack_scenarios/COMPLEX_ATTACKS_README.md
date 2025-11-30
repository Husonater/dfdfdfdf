# 🔥 KOMPLEXE ANGRIFFSSZENARIEN - DOKUMENTATION

## Übersicht

Zusätzlich zu den 7 Standard-Angriffen und dem APT-Szenario wurden **5 hochkomplexe, realistische Angriffsszenarien** erstellt:

---

## 🆕 NEUE KOMPLEXE ANGRIFFE

### 9. Supply Chain Attack (`09_supply_chain_attack.sh`)

**Beschreibung:** Simuliert einen Angriff über kompromittierte Software-Updates

**Angriffskette:**
1. **Kompromittiertes Repository** - Verdächtige Update-Quelle
2. **Trojanisiertes Paket** - Unsignierte Software-Pakete
3. **Backdoor Installation** - Post-Install Scripts mit Malware
4. **DNS Tunneling C2** - Verdeckte Command & Control
5. **Crypto-Mining** - Ressourcen-Missbrauch
6. **Systemd Persistenz** - Dauerhafte Kompromittierung

**MITRE ATT&CK:**
- T1195 - Supply Chain Compromise
- T1071 - Application Layer Protocol (DNS)
- T1496 - Resource Hijacking (Crypto-Mining)
- T1543 - Create or Modify System Process

**Wazuh Detection:**
- Unsignierte Pakete
- Verdächtige Repository-Zugriffe
- DNS Tunneling Patterns
- Hohe CPU-Auslastung (Mining)
- Rootcheck Backdoor Alerts

---

### 10. Zero-Day Exploit Chain (`10_zero_day_exploits.sh`)

**Beschreibung:** Ausnutzung mehrerer Zero-Day Schwachstellen

**Exploit-Kette:**
1. **CVE-2025-12345** - Apache RCE (Shellshock-style)
2. **CVE-2025-67890** - Kernel Privilege Escalation
3. **CVE-2025-11111** - Container Escape
4. **Memory Corruption** - Heap Overflow
5. **Rootkit Installation** - Kernel-Level Persistenz

**MITRE ATT&CK:**
- T1190 - Exploit Public-Facing Application
- T1068 - Exploitation for Privilege Escalation
- T1611 - Escape to Host
- T1014 - Rootkit

**Wazuh Detection:**
- Segmentation Faults
- Kernel Exploits
- Container Escape Attempts
- Rootkit Detection
- Process Hiding

**Schweregrad:** 🔴 KRITISCH (Level 15)

---

### 11. Insider Threat (`11_insider_threat.sh`)

**Beschreibung:** Böswilliger Mitarbeiter mit legitimen Zugriffen

**Phasen:**
1. **Normale Aktivitäten** - Tarnung
2. **Ungewöhnliche Zugriffe** - 2 Uhr nachts Login
3. **Privilegien-Missbrauch** - Sudo für /etc/shadow
4. **Datenexfiltration** - 2.8 GB zu Dropbox
5. **Spuren verwischen** - Log-Manipulation
6. **Backdoor** - Persistenter Zugriff
7. **Sabotage** - Backups deaktiviert

**MITRE ATT&CK:**
- T1078 - Valid Accounts
- T1003 - OS Credential Dumping
- T1041 - Exfiltration Over C2 Channel
- T1070 - Indicator Removal
- T1485 - Data Destruction

**Wazuh Detection:**
- Login außerhalb Arbeitszeit
- Ungewöhnliche Datenbank-Zugriffe
- Massive Datenexfiltration
- Log-Manipulation
- Backup-Deaktivierung

**Besonderheit:** Schwer zu erkennen, da legitime Credentials

---

### 12. Fileless Attack (`12_fileless_attack.sh`)

**Beschreibung:** Living off the Land - keine Malware-Dateien

**Techniken:**
1. **Memory-Only Execution** - Base64-encoded Payloads
2. **LOLBins Abuse** - curl, wget, python, nc
3. **Process Injection** - ptrace, /proc/mem
4. **In-Memory Credentials** - Memory Dumping
5. **DNS/ICMP Tunneling** - Verdeckte C2
6. **Anti-Forensics** - Timestamp Manipulation

**MITRE ATT&CK:**
- T1027 - Obfuscated Files or Information
- T1055 - Process Injection
- T1140 - Deobfuscate/Decode Files
- T1562 - Impair Defenses

**Wazuh Detection:**
- Suspicious bash patterns (curl | bash)
- LOLBins Usage
- Process Injection
- DNS Tunneling
- Memory Manipulation

**Schwierigkeit:** 🔴 SEHR SCHWER zu erkennen

---

### 13. Ransomware Campaign (`13_ransomware_campaign.sh`)

**Beschreibung:** Moderner Ransomware-Angriff mit Double Extortion

**10 Phasen:**
1. **Phishing** - Malicious Email Attachment
2. **Dropper** - Anti-VM Checks, Payload Entpackung
3. **Reconnaissance** - Netzwerk-Kartierung
4. **Lateral Movement** - 4 Hosts kompromittiert
5. **Credential Theft** - Domain Admin
6. **Data Exfiltration** - 45 GB gestohlen
7. **Backup Destruction** - Alle Backups gelöscht
8. **Encryption** - 15,234 Dateien verschlüsselt
9. **Ransom Note** - 50 Bitcoin Lösegeld
10. **Cleanup** - Anti-Forensics

**MITRE ATT&CK:**
- T1566 - Phishing
- T1486 - Data Encrypted for Impact
- T1490 - Inhibit System Recovery
- T1485 - Data Destruction

**Wazuh Detection:**
- Phishing Email
- Mass File Encryption
- Backup Deletion
- High Disk I/O
- Ransom Note Creation

**Schaden:**
- 💰 $2,000,000 Lösegeld
- 🔒 15,234 Dateien verschlüsselt
- 📤 45 GB exfiltriert
- 🗑️ Alle Backups zerstört

---

## 📊 VERGLEICHSTABELLE

| Angriff | Komplexität | Phasen | MITRE Taktiken | Schweregrad |
|---------|-------------|--------|----------------|-------------|
| Supply Chain | ⭐⭐⭐⭐ | 6 | 4 | Hoch |
| Zero-Day | ⭐⭐⭐⭐⭐ | 5 | 4 | Kritisch |
| Insider Threat | ⭐⭐⭐⭐ | 7 | 5 | Hoch |
| Fileless | ⭐⭐⭐⭐⭐ | 7 | 4 | Sehr Hoch |
| Ransomware | ⭐⭐⭐⭐⭐ | 10 | 6 | Kritisch |

---

## 🚀 VERWENDUNG

### Einzelnen Angriff ausführen:
```bash
cd /home/jp/dfdfdfdf/attack_scenarios

# Supply Chain Attack
./09_supply_chain_attack.sh

# Zero-Day Exploits
./10_zero_day_exploits.sh

# Insider Threat
./11_insider_threat.sh

# Fileless Attack
./12_fileless_attack.sh

# Ransomware
./13_ransomware_campaign.sh
```

### Alle komplexen Angriffe:
```bash
./run_complex_attacks.sh
# Wähle Option 15
```

### Vollständige Demo (ALLE Angriffe):
```bash
./run_complex_attacks.sh
# Wähle Option 16
```

---

## 🔍 WAZUH ANALYSE

### Empfohlene Dashboard-Filter:

**Supply Chain:**
```
rule.description:*repository* OR rule.description:*package*
rule.groups:rootcheck
```

**Zero-Day:**
```
rule.level:>=12
rule.description:*exploit* OR rule.description:*kernel*
```

**Insider Threat:**
```
timestamp:>=now-1h AND timestamp:<=now
data.srcuser:john.smith
rule.groups:authentication_success
```

**Fileless:**
```
rule.description:*bash* OR rule.description:*curl*
rule.groups:process_injection
```

**Ransomware:**
```
rule.description:*encrypt* OR rule.description:*ransom*
rule.level:>=10
```

---

## 📈 ERWARTETE ALERTS

### Supply Chain Attack:
- ⚠️ Unsignierte Pakete (Level 7)
- 🔴 DNS Tunneling (Level 10)
- 🔴 Crypto-Mining (Level 12)
- ⚠️ Rootcheck Backdoor (Level 9)

### Zero-Day Exploits:
- 🔴 RCE Attempt (Level 12)
- 🔴 Kernel Exploit (Level 15)
- 🔴 Container Escape (Level 13)
- 🔴 Rootkit Detection (Level 14)

### Insider Threat:
- ⚠️ Unusual Login Time (Level 5)
- 🔴 Privilege Abuse (Level 10)
- 🔴 Mass Data Exfiltration (Level 12)
- ⚠️ Log Manipulation (Level 8)

### Fileless Attack:
- ⚠️ Suspicious Bash (Level 7)
- 🔴 Process Injection (Level 11)
- 🔴 DNS Tunneling (Level 10)
- ⚠️ LOLBins Abuse (Level 6)

### Ransomware:
- 🔴 Mass Encryption (Level 15)
- 🔴 Backup Deletion (Level 13)
- 🔴 Data Exfiltration (Level 12)
- 🔴 Ransom Note (Level 14)

---

## 🎯 LERNZIELE

Diese komplexen Szenarien demonstrieren:

1. **Moderne Angriffstechniken** - Realistische Bedrohungen
2. **Multi-Stage Attacks** - Komplexe Angriffsketten
3. **Evasion Techniques** - Umgehung von Sicherheitsmaßnahmen
4. **MITRE ATT&CK** - Vollständige Taktik-Abdeckung
5. **Wazuh Detection** - SIEM-Erkennungsfähigkeiten

---

## ⚠️ WICHTIGE HINWEISE

- **NUR FÜR TESTZWECKE** in isolierten Umgebungen
- Niemals in Produktionsumgebungen ausführen
- Einige Angriffe erzeugen sehr viele Alerts (>1000)
- Ransomware-Szenario ist besonders intensiv
- Warte zwischen Angriffen für bessere Analyse

---

## 📚 WEITERFÜHRENDE RESSOURCEN

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [Ransomware Playbook](https://www.cisa.gov/stopransomware)
- [Insider Threat Detection](https://www.sans.org/white-papers/)

---

**Erstellt:** 2025-11-29  
**Version:** 2.0  
**Komplexität:** Advanced/Expert Level
