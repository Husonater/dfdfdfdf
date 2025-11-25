#!/bin/bash

# Farben für Output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
CLAB_PREFIX="clab-dmz-project-sun"

print_header() {
    echo -e "\n${BLUE}##########################################################${NC}"
    echo -e "${BLUE}# $1${NC}"
    echo -e "${BLUE}##########################################################${NC}"
}

check_ip() {
    NODE=$1
    INTERFACE=$2
    EXPECTED_IP=$3
    ACTUAL_IP=$(sudo docker exec ${CLAB_PREFIX}-${NODE} ip addr show ${INTERFACE} | grep "inet ${EXPECTED_IP}" | awk '{print $2}')
    if [[ "$ACTUAL_IP" == *"$EXPECTED_IP"* ]]; then
        echo -e "[${GREEN}PASS${NC}] IP $NODE: $EXPECTED_IP"
        ((PASS_COUNT++))
    else
        echo -e "[${RED}FAIL${NC}] IP $NODE: Erwartet $EXPECTED_IP"
        ((FAIL_COUNT++))
    fi
}

expect_success() {
    SOURCE_NODE=$1
    CMD=$2
    DESC=$3
    echo -n "Testing: $DESC ... "
    sudo docker exec ${CLAB_PREFIX}-${SOURCE_NODE} timeout 5s bash -c "$CMD" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SUCCESS${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}FAILED${NC} (Verbindung fehlgeschlagen)"
        ((FAIL_COUNT++))
    fi
}

expect_block() {
    SOURCE_NODE=$1
    CMD=$2
    DESC=$3
    echo -n "Testing: $DESC ... "
    sudo docker exec ${CLAB_PREFIX}-${SOURCE_NODE} timeout 3s bash -c "$CMD" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${GREEN}BLOCKED (OK)${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}CONNECTED (UNSAFE!)${NC}"
        ((FAIL_COUNT++))
    fi
}

check_waf_status() {
    SOURCE=$1
    URL=$2
    EXPECTED_CODE=$3
    DESC=$4
    echo -n "Testing WAF: $DESC ... "
    
    # Added --path-as-is to prevent curl from removing '../' locally
    # Added quotes around "$URL" to handle special chars better
    HTTP_CODE=$(sudo docker exec ${CLAB_PREFIX}-${SOURCE} curl --path-as-is -o /dev/null -s -w "%{http_code}" "$URL")
    
    if [[ "$HTTP_CODE" == "$EXPECTED_CODE" ]]; then
        echo -e "${GREEN}PASS (Code: $HTTP_CODE)${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}FAIL (Got: $HTTP_CODE, Expected: $EXPECTED_CODE)${NC}"
        ((FAIL_COUNT++))
    fi
}

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}      🛡️  ULTIMATE DMZ SECURITY AUDIT  🛡️            ${NC}"
echo -e "${YELLOW}======================================================${NC}"

# ---------------------------------------------------------
# 1. INFRASTRUKTUR & IP CHECK (Updated IPs to 60.x/61.x)
# ---------------------------------------------------------
print_header "1. INFRASTRUKTUR & IP ADRESSEN"
check_ip "attacker-internet" "eth1" "172.16.1.10"
check_ip "edge-router" "eth1" "192.168.10.1"
check_ip "firewall-in" "eth2" "192.168.20.1"
check_ip "reverse-proxy-waf" "eth1" "192.168.20.10"
check_ip "webserver" "eth1" "192.168.60.20"  # NEU
check_ip "ids-dmz" "eth1" "192.168.61.30"    # NEU
check_ip "db-backend" "eth1" "192.168.70.10" # NEU
check_ip "client-internal" "eth1" "192.168.40.10"

# ---------------------------------------------------------
# 2. ROUTING & KONNEKTIVITÄT (Layer 3/4)
# ---------------------------------------------------------
print_header "2. ROUTING & FIREWALL BASIS"

# A. Von Außen (Internet)
expect_success "attacker-internet" "ping -c 1 172.16.1.1" "Internet -> Gateway (Edge Router)"
expect_success "attacker-internet" "nc -z -v -w 2 192.168.20.10 80" "Internet -> WAF (TCP 80 Open)"
expect_block "attacker-internet" "nc -z -v -w 2 192.168.20.10 22" "Internet -> WAF (SSH Closed)"
expect_block "attacker-internet" "ping -c 1 192.168.60.20" "Internet -> Webserver (ICMP Blocked)" # Updated IP
expect_block "attacker-internet" "curl -m 2 192.168.60.20" "Internet -> Webserver (Direct HTTP Bypass)" # Updated IP
expect_block "attacker-internet" "nc -z -v -w 2 192.168.70.10 3306" "Internet -> Database (Direct Access Blocked)" # NEU

# B. Von Innen (Internal Client)
expect_success "client-internal" "ping -c 1 192.168.35.10" "Client -> SIEM (Management Access)"
expect_block "client-internal" "ping -c 1 172.16.1.10" "Client -> Internet (Egress Filter)"
expect_block "client-internal" "curl -m 2 192.168.60.20" "Client -> DMZ Webserver (Segregation)" # Updated IP

# C. Aus der DMZ (Compromised Host Simulation)
expect_block "webserver" "ping -c 1 192.168.40.10" "Webserver -> Internal Client (Lateral Movement Block)"
expect_block "reverse-proxy-waf" "ping -c 1 192.168.35.10" "WAF -> SIEM (Direct Access Blocked)"
expect_success "webserver" "nc -z -v -w 2 192.168.70.10 3306" "Webserver -> Database (MySQL Access Allowed)" # NEU

# ---------------------------------------------------------
# 3. WAF FUNKTIONALITÄT (Layer 7)
# ---------------------------------------------------------
print_header "3. WAF SECURITY CHECKS"

# A. Normaler Traffic (Check if WAF proxies to the new 60.20 IP)
OUTPUT=$(sudo docker exec ${CLAB_PREFIX}-attacker-internet curl -s http://192.168.20.10)
if [[ "$OUTPUT" == *"Webserver is running"* ]]; then
    echo -e "[${GREEN}PASS${NC}] Legitimate Traffic (Proxy Pass funktioniert)"
    ((PASS_COUNT++))
else
    # This check ensures the WAF-Webserver connection is actually working
    echo -e "[${RED}FAIL${NC}] Legitimate Traffic failed (WAF ist nicht verbunden)"
    ((FAIL_COUNT++))
fi

# B. Angriffe (OWASP Top 10 Simulation)
check_waf_status "attacker-internet" "http://192.168.20.10/?id=1%27%20OR%201=1" "403" "Blocking SQL Injection (Union Based)"
check_waf_status "attacker-internet" "http://192.168.20.10/?f=../../etc/passwd" "403" "Blocking Path Traversal"
check_waf_status "attacker-internet" "http://192.168.20.10/?q=%3Cscript%3Ealert(1)%3C/script%3E" "403" "Blocking XSS Attack"
check_waf_status "attacker-internet" "http://192.168.20.10/?cmd=%3Bcat%20/etc/passwd" "403" "Blocking Shell Injection"

# ---------------------------------------------------------
# 4. IDS & SIEM LOGGING (Der finale Funktionstest)
# ---------------------------------------------------------
print_header "4. IDS & SIEM LOGGING KETTE"

# 1. Test TEE Mirroring / IDS Detection (We force a known attack past the WAF by running it internally)
echo "Generating Attack Traffic for IDS (WAF Bypass Simulation)..."

# Führt den Angriff direkt vom WAF-Container auf den Webserver aus.
# Dies muss eine Log-Meldung in Suricata auslösen.
sudo docker exec ${CLAB_PREFIX}-reverse-proxy-waf curl -s "http://192.168.60.20/cmd.exe" > /dev/null

# Warte kurz, bis der Alarm verarbeitet wurde
sleep 30

# 2. Prüfen am SIEM (Check for the Suricata alert signature)
# WICHTIG: Prüft auf die am häufigsten ausgelöste Signatur
SIEM_LOGS=$(sudo docker exec ${CLAB_PREFIX}-siem-backend grep "ET WEB_SERVER" /var/log/siem_logs/suricata_alerts.log | tail -n 1)

if [[ "$SIEM_LOGS" == *"ET WEB_SERVER"* ]]; then
    echo -e "[${GREEN}PASS${NC}] IDS Alert received for attack (Detection Chain OK)"
    ((PASS_COUNT++))
else
    echo -e "[${RED}FAIL${NC}] IDS Alert not received (Mirroring, Rule Match or Syslog Failure)"
    ((FAIL_COUNT++))
fi

# ---------------------------------------------------------
# 5. SIEM LOGGING COMPLETENESS (Check all components)
# ---------------------------------------------------------
print_header "5. SIEM LOGGING COMPLETENESS"

# A. Firewall Logs (Check for dropped packets)
# Wir suchen nach "firewall", da tcpdump -q den Prefix nicht ausgibt.
FW_LOGS=$(sudo docker exec ${CLAB_PREFIX}-siem-backend grep "firewall" /var/log/siem_logs/suricata_alerts.log | tail -n 1)
if [[ -n "$FW_LOGS" ]]; then
    echo -e "[${GREEN}PASS${NC}] Firewall Logs received (FW-DROP detected)"
    ((PASS_COUNT++))
else
    echo -e "[${RED}FAIL${NC}] Firewall Logs NOT received"
    ((FAIL_COUNT++))
fi

# B. WAF Logs (Check for Nginx/ModSecurity logs)
# Wir suchen nach "nginx_waf" oder "nginx_error", das wir in nginx.conf definiert haben.
WAF_LOGS=$(sudo docker exec ${CLAB_PREFIX}-siem-backend grep "nginx_" /var/log/siem_logs/suricata_alerts.log | tail -n 1)
if [[ -n "$WAF_LOGS" ]]; then
    echo -e "[${GREEN}PASS${NC}] WAF Logs received (Nginx Access/Error detected)"
    ((PASS_COUNT++))
else
    echo -e "[${RED}FAIL${NC}] WAF Logs NOT received"
    ((FAIL_COUNT++))
fi

echo -e "\n${YELLOW}======================================================${NC}"
echo -e "AUDIT RESULT:"
echo -e "PASSED: ${GREEN}$PASS_COUNT${NC}"
echo -e "FAILED: ${RED}$FAIL_COUNT${NC}"

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "\n${GREEN}🏆 CONGRATULATIONS! SYSTEM IS SECURE. 🏆${NC}"
else
    echo -e "\n${RED}⚠️  SECURITY RISKS DETECTED! ⚠️${NC}"
fi
echo -e "${YELLOW}======================================================${NC}"