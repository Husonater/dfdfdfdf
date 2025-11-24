#!/bin/bash
# Farben
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
CLAB_PREFIX="clab-dmz-project-sun"

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}      DMZ AUDIT V3 (Final Verfication)             ${NC}"
echo -e "${YELLOW}======================================================${NC}"

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
    sudo docker exec ${CLAB_PREFIX}-${SOURCE_NODE} bash -c "$CMD" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SUCCESS${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}FAILED${NC}"
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
        echo -e "${RED}CONNECTED (UNSAFE)${NC}"
        ((FAIL_COUNT++))
    fi
}

# 1. IP CHECKS
echo -e "\n${YELLOW}--- 1. IP CHECK ---${NC}"
check_ip "firewall-in" "eth2" "192.168.20.1"
check_ip "reverse-proxy-waf" "eth1" "192.168.20.10"
check_ip "webserver" "eth1" "192.168.25.20"

# 2. CONNECTIVITY
echo -e "\n${YELLOW}--- 2. ROUTING & FIREWALL ---${NC}"
expect_success "attacker-internet" "ping -c 1 172.16.1.1" "Attacker -> Gateway"
expect_success "firewall-in" "ping -c 1 192.168.10.1" "Firewall -> Edge"
expect_success "attacker-internet" "curl -m 3 -s http://192.168.20.10" "Internet -> WAF (Port 80)"
expect_block "attacker-internet" "curl -m 3 -s http://192.168.25.20" "Internet -> Backend Direct"

# 3. APP LOGIC
echo -e "\n${YELLOW}--- 3. WAF LOGIC ---${NC}"
OUTPUT=$(sudo docker exec ${CLAB_PREFIX}-attacker-internet curl -s http://192.168.20.10)
if [[ "$OUTPUT" == *"Webserver is running"* ]]; then
    echo -e "[${GREEN}PASS${NC}] WAF Proxy OK"
    ((PASS_COUNT++))
else
    echo -e "[${RED}FAIL${NC}] WAF Content Error"
    ((FAIL_COUNT++))
fi

echo -n "Testing: WAF SQL Injection Blocking ... "
HTTP_CODE=$(sudo docker exec ${CLAB_PREFIX}-attacker-internet curl -o /dev/null -s -w "%{http_code}" "http://192.168.20.10/?id=1' OR '1'='1")
if [[ "$HTTP_CODE" == "403" ]]; then
    echo -e "${GREEN}PASSED (403)${NC}"
    ((PASS_COUNT++))
else
    echo -e "${RED}FAILED (Got $HTTP_CODE)${NC}"
    ((FAIL_COUNT++))
fi

# 4. LOGGING (Test mit logger statt nc)
echo -e "\n${YELLOW}--- 4. SIEM LOGGING ---${NC}"
# Sende Test-Log
sudo docker exec ${CLAB_PREFIX}-ids-dmz bash -c "echo '<13>Test Message from IDS' > /dev/udp/192.168.35.10/514"
sleep 1
# Prüfe ob Log angekommen ist
LOG_CHECK=$(sudo docker exec ${CLAB_PREFIX}-siem-backend grep "Test Message" /var/log/siem_logs/suricata_alerts.log)
if [[ -n "$LOG_CHECK" ]]; then
    echo -e "[${GREEN}PASS${NC}] IDS -> SIEM Log received"
    ((PASS_COUNT++))
else
    echo -e "[${RED}FAIL${NC}] IDS -> SIEM Log missing (Check UDP Routing)"
    ((FAIL_COUNT++))
fi

echo -e "\n${YELLOW}======================================================${NC}"
echo "PASSED: $PASS_COUNT"
echo "FAILED: $FAIL_COUNT"