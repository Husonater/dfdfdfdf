FROM debian:latest

# 1. Software installieren (inkl. curl, python3 für Updates und tcpdump für Tests)
RUN apt-get update && apt-get install -y \
    suricata \
    net-tools \
    iproute2 \
    bash \
    rsyslog \
    procps \
    curl \
    tcpdump \
    python3 \
    iptables \
    rsyslog-openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. Regeln AUTOMATISCH beim Bauen herunterladen
# Das verhindert das "0 Rules loaded" Problem
RUN suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update

# Certs
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/client.pem /etc/ssl/certs/client.pem
COPY config/certs/client.key /etc/ssl/private/client.key

# 3. Skripte kopieren
COPY images/ids/startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh

# 4. Dummy-Prozess (Hält den Container am Leben)
CMD ["tail", "-f", "/dev/null"]