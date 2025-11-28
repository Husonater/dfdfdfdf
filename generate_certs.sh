#!/bin/bash
set -e

# Create config files
cat > root-ca.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = Wazuh Root CA
EOF

cat > indexer.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-indexer

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.11
DNS.1 = wazuh-indexer
EOF

cat > manager.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-manager

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.8
DNS.1 = wazuh-manager
EOF

cat > dashboard.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = wazuh-dashboard

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 172.20.20.12
DNS.1 = wazuh-dashboard
EOF

cat > admin.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Jose
O = Wazuh
OU = Wazuh
CN = admin

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

# Generate Root CA
openssl genrsa -out root-ca.key 4096
openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.pem -config root-ca.cnf

# Generate Indexer Cert
openssl genrsa -out indexer-key.pem 2048
openssl req -new -key indexer-key.pem -out indexer.csr -config indexer.cnf
openssl x509 -req -in indexer.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out indexer.pem -days 3650 -sha256 -extensions v3_req -extfile indexer.cnf

# Generate Manager Cert
openssl genrsa -out wazuh-manager-key.pem 2048
openssl req -new -key wazuh-manager-key.pem -out wazuh-manager.csr -config manager.cnf
openssl x509 -req -in wazuh-manager.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out wazuh-manager.pem -days 3650 -sha256 -extensions v3_req -extfile manager.cnf

# Generate Dashboard Cert
openssl genrsa -out dashboard-key.pem 2048
openssl req -new -key dashboard-key.pem -out dashboard.csr -config dashboard.cnf
openssl x509 -req -in dashboard.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out dashboard.pem -days 3650 -sha256 -extensions v3_req -extfile dashboard.cnf

# Generate Admin Cert
openssl genrsa -out admin-key.pem 2048
openssl req -new -key admin-key.pem -out admin.csr -config admin.cnf
openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out admin.pem -days 3650 -sha256 -extensions v3_req -extfile admin.cnf

# Cleanup
rm *.csr *.cnf *.srl
