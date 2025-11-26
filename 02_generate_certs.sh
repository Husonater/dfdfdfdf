#!/bin/bash
set -e

CERT_DIR="./config/certs"
mkdir -p "$CERT_DIR"

echo "--- 🔐 GENERATING TLS CERTIFICATES ---"

# 1. CA (Certificate Authority)
if [ ! -f "$CERT_DIR/ca.pem" ]; then
    echo "Generating CA..."
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
        -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" \
        -subj "/C=DE/ST=Berlin/L=Berlin/O=DMZ-Lab/OU=Security/CN=DMZ-CA"
else
    echo "CA already exists."
fi

# 2. Server Certificate (for SIEM)
if [ ! -f "$CERT_DIR/siem-server.pem" ]; then
    echo "Generating SIEM Server Cert..."
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/siem-server.key" -out "$CERT_DIR/siem-server.csr" \
        -subj "/C=DE/ST=Berlin/L=Berlin/O=DMZ-Lab/OU=SIEM/CN=siem-backend"
    
    openssl x509 -req -in "$CERT_DIR/siem-server.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/siem-server.pem" -days 3650
else
    echo "SIEM Server Cert already exists."
fi

# 3. Client Certificate (Shared for WAF, IDS, FW, DB)
if [ ! -f "$CERT_DIR/client.pem" ]; then
    echo "Generating Client Cert..."
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
        -subj "/C=DE/ST=Berlin/L=Berlin/O=DMZ-Lab/OU=Clients/CN=dmz-client"
    
    openssl x509 -req -in "$CERT_DIR/client.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/client.pem" -days 3650
else
    echo "Client Cert already exists."
fi

chmod 644 "$CERT_DIR"/*.pem
chmod 600 "$CERT_DIR"/*.key

echo "✅ Certificates generated in $CERT_DIR"
