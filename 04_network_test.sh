#!/bin/bash
# --- Network Connectivity Test Script (FIXED) ---

clab_exec() {
    sudo docker exec -i clab-dmz-project-sun-$1 bash -c "$2"
}

# --- Adress-Variablen ---
# ACHTUNG: Attacker ist jetzt im "Public Internet" Subnetz (172.16.1.x)
ATTACKER_IP="172.16.1.10"
WAF_IP="192.168.20.10"
SIEM_IP="192.168.30.10"
CLIENT_INTERNAL_IP="192.168.40.10"

echo "--- TEST 1: INTERNET (Attacker) -> WAF ---"
echo "1a) Pinging WAF (Sollte fehlschlagen/geblockt sein)..."
clab_exec attacker-internet "ping -c 3 -W 1 ${WAF_IP}" || echo "-> Ping blocked as expected."

echo -e "\n1b) Testing HTTP to WAF (Sollte ERFOLGREICH sein)..."
clab_exec attacker-internet "timeout 5 bash -c '</dev/tcp/${WAF_IP}/80 && echo -e \n-- Connection SUCCESSFUL -- || echo -e \n-- Connection FAILED --'"

echo -e "\n--- TEST 2: INTERN (Client) -> SIEM ---"
clab_exec client-internal "ping -c 3 ${SIEM_IP}"

echo -e "\n--- TEST 3: DMZ (WAF) -> SIEM (MUSS FEHLSCHLAGEN) ---"
clab_exec reverse-proxy-waf "ping -c 3 -W 1 ${SIEM_IP}" || echo "-> Blocked as expected."

echo -e "\n--- SUMMARY ---"
clab_exec firewall-in "iptables -nL FORWARD"