FROM debian:bookworm-slim

# Installiere Tools + rsyslog + tcpdump
RUN apt-get update && apt-get install -y \
    bash \
    iproute2 \
    iptables \
    conntrack \
    rsyslog \
    rsyslog-openssl \
    tcpdump \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Certs
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/client.pem /etc/ssl/certs/client.pem
COPY config/certs/client.key /etc/ssl/private/client.key

RUN mkdir -p /var/lib/rsyslog
COPY images/firewall/init_firewall.sh /usr/local/bin/init_firewall.sh
RUN chmod +x /usr/local/bin/init_firewall.sh

CMD ["tail", "-f", "/dev/null"]