#!/bin/bash
# --- Network Connectivity Test Script (Phase 3 - Funktionalität) ---

echo "--- STARTING BASIC NETWORK CONNECTIVITY TESTS ---"

# Hilfsfunktion, um Befehle in Containern auszuführen
clab_exec() {
    # Fuehrt Befehle im entsprechenden Container aus
    sudo docker exec -i clab-dmz-project-sun-$1 bash -c "$2"
}

# --- Adress-Variablen (basierend auf 03_deploy_dmz.sh) ---
# Netze: .10.x (Internet) | .20.x (DMZ) | .30.x (Backend) | .40.x (Client)
ATTACKER_INTERNET_IP="192.168.10.10"
WAF_IP="192.168.20.10"
SIEM_IP="192.168.30.10"
CLIENT_INTERNAL_IP="192.168.40.10"

# --------------------------------------------------------
# TEST 1: Internet (Attacker) -> WAF (192.168.20.10)
# Erwartung: Ping schlaegt fehl (Firewall blockiert ICMP), aber Curl-Verbindung ist moeglich (Firewall erlaubt Port 80).
echo "--- TEST 1: INTERNET (Attacker) -> WAF ---"
echo "1a) Pinging WAF von Attacker-Internet (192.168.10.10)... (Erwartet: FEHLSCHLAG, da ICMP durch FW blockiert)"
clab_exec attacker-internet "ping -c 3 ${WAF_IP}"

echo -e "\n1b) Testing TCP Port 80 connection to WAF..."
echo "(Erwartet: Erfolg, Verbindung wird aufgebaut, da FW Port 80 erlaubt)"
# 'timeout 5' stellt sicher, dass der Befehl nicht haengt, falls der Port nicht antwortet
clab_exec attacker-internet "timeout 5 bash -c '</dev/tcp/${WAF_IP}/80 && echo -e \n-- Connection SUCCESSFUL -- || echo -e \n-- Connection FAILED --'"


# --------------------------------------------------------
# TEST 2: Interner Client -> Backend SIEM (192.168.30.10)
# Erwartung: Sollte funktionieren (0% loss), da internes Routing aktiv ist.
echo -e "\n--- TEST 2: INTERN (Client) -> SIEM ---"
clab_exec client-internal "ping -c 3 ${SIEM_IP}"


# --------------------------------------------------------
# TEST 3: DMZ WAF -> Backend SIEM (192.168.30.10)
# KRITISCHER TEST: Muss fehlschlagen (100% loss), da die FW Verkehr von eth2 (DMZ) nach eth3 (Backend) blockiert.
echo -e "\n--- TEST 3: DMZ (WAF) -> SIEM (MUSS FEHLSCHLAGEN) ---"
clab_exec reverse-proxy-waf "ping -c 3 ${SIEM_IP}"


# --------------------------------------------------------
# ZUSAMMENFASSUNG DER FIREWALL-REGELN
echo -e "\n--- ZUSAMMENFASSUNG: FIREWALL REGELN ---"
echo "Forward-Kette der Firewall (Ueberpruefen Sie die DROP-Regel fuer DMZ -> Backend):"
clab_exec firewall-in "iptables -t filter -L FORWARD --line-numbers"

echo -e "\n--- TESTS BEENDET ---"
echo "Pruefen Sie: Ping Internet->WAF (Fail), Curl Internet->WAF (Success), Client->SIEM (Success), WAF->SIEM (Fail)."
