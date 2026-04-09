#!/bin/bash
# OWASP Attack Detection - Quick Test Script
# Testet SQL Injection, XSS und Path Traversal Detection

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  OWASP Web Attack Detection - Quick Test                 ║${NC}"
echo -e "${BLUE}║  Testing: SQL Injection, XSS, Path Traversal              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

TARGET_WAF="192.168.20.10"  # WAF IP address
ATTACKER="attacker-internet"

# Check if containers are running
echo -e "${YELLOW}[*] Checking container status...${NC}"
if ! docker ps | grep -q "clab-dmz-project-sun-reverse-proxy-waf"; then
    echo -e "${RED}[ERROR] WAF container not running! Please start topology first.${NC}"
    exit 1
fi

if ! docker ps | grep -q "clab-dmz-project-sun-$ATTACKER"; then
    echo -e "${RED}[ERROR] Attacker container not running! Please start topology first.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Containers are running${NC}"
echo ""

# Function to send attack and check response
send_attack() {
    local attack_type=$1
    local payload=$2
    local endpoint=$3
    local param=$4
    
    echo -e "${YELLOW}  [→] Testing: $attack_type${NC}"
    echo -e "      Payload: ${BLUE}$payload${NC}"
    
    response=$(sudo docker exec clab-dmz-project-sun-$ATTACKER \
        curl -s -w "\n%{http_code}" -G -A "Mozilla/5.0" \
        "http://$TARGET_WAF$endpoint" \
        --data-urlencode "$param=$payload" 2>/dev/null || echo "000")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" == "403" ]; then
        echo -e "${GREEN}  [✓] BLOCKED (403) - Attack detected!${NC}"
        return 0
    else
        echo -e "${RED}  [✗] NOT BLOCKED ($http_code) - Attack may have passed!${NC}"
        return 1
    fi
}

# Test SQL Injection
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}1. SQL INJECTION TESTS (OWASP CRS 942xxx)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

sqli_count=0
send_attack "Union-based SQLi" "' UNION SELECT NULL,NULL,NULL--" "/" "user" && ((sqli_count++))
sleep 0.5
send_attack "Boolean-based SQLi" "' OR '1'='1" "/" "user" && ((sqli_count++))
sleep 0.5
send_attack "Tautology SQLi" "admin' OR 1=1--" "/" "user" && ((sqli_count++))
sleep 0.5
send_attack "Time-based SQLi" "' OR SLEEP(5)--" "/" "user" && ((sqli_count++))
sleep 0.5

echo -e "${GREEN}SQL Injection: $sqli_count/4 attacks blocked${NC}"
echo ""

# Test XSS
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}2. XSS TESTS (OWASP CRS 941xxx)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

xss_count=0
send_attack "Script Tag XSS" "<script>alert('XSS')</script>" "/" "q" && ((xss_count++))
sleep 0.5
send_attack "Event Handler XSS" "<img src=x onerror=alert('XSS')>" "/" "q" && ((xss_count++))
sleep 0.5
send_attack "SVG XSS" "<svg/onload=alert('XSS')>" "/" "q" && ((xss_count++))
sleep 0.5
send_attack "JavaScript Protocol" "javascript:alert('XSS')" "/" "q" && ((xss_count++))
sleep 0.5

echo -e "${GREEN}XSS: $xss_count/4 attacks blocked${NC}"
echo ""

# Test Path Traversal
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}3. PATH TRAVERSAL TESTS (OWASP CRS 930xxx)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

path_count=0
send_attack "Directory Traversal" "../../../../etc/passwd" "/" "file" && ((path_count++))
sleep 0.5
send_attack "Encoded Traversal" "..%2F..%2F..%2Fetc%2Fpasswd" "/" "file" && ((path_count++))
sleep 0.5
send_attack "Windows Traversal" "..\\..\\..\\windows\\system32\\config\\sam" "/" "file" && ((path_count++))
sleep 0.5
send_attack "Absolute Path" "/etc/shadow" "/" "file" && ((path_count++))
sleep 0.5

echo -e "${GREEN}Path Traversal: $path_count/4 attacks blocked${NC}"
echo ""

# Summary
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

total_blocked=$((sqli_count + xss_count + path_count))
total_tests=12

echo -e "Total Attacks Blocked: ${GREEN}$total_blocked/$total_tests${NC}"
echo ""

if [ $total_blocked -eq $total_tests ]; then
    echo -e "${GREEN}[✓] ALL ATTACKS BLOCKED! OWASP CRS is working correctly!${NC}"
else
    echo -e "${YELLOW}[!] Some attacks were not blocked. Check ModSecurity configuration.${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}NEXT STEPS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "1. ${YELLOW}Check WAF Logs:${NC}"
echo -e "   ${BLUE}sudo docker exec clab-dmz-project-sun-reverse-proxy-waf tail -20 /var/log/modsec_audit.log${NC}"
echo ""
echo -e "2. ${YELLOW}Check Wazuh Manager Alerts:${NC}"
echo -e "   ${BLUE}sudo docker exec clab-dmz-project-sun-wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json | jq .${NC}"
echo ""
echo -e "3. ${YELLOW}Open Wazuh Dashboard:${NC}"
echo -e "   ${BLUE}https://localhost:8443${NC}"
echo -e "   Login: ${GREEN}admin / SecretPassword123!${NC}"
echo ""
echo -e "4. ${YELLOW}Search for Alerts in Dashboard:${NC}"
echo -e "   Query: ${BLUE}rule.groups: \"owasp_crs\"${NC}"
echo ""
echo -e "5. ${YELLOW}Filter by Attack Type:${NC}"
echo -e "   - SQL Injection:   ${BLUE}rule.groups: \"sqli\"${NC}"
echo -e "   - XSS:             ${BLUE}rule.groups: \"xss\"${NC}"
echo -e "   - Path Traversal:  ${BLUE}rule.groups: \"path-traversal\"${NC}"
echo ""
echo -e "${GREEN}[✓] Test completed!${NC}"
