FROM alpine:latest

# Installiere Tools + rsyslog + tcpdump
RUN apk update && apk add \
    bash \
    iproute2 \
    iptables \
    conntrack-tools \
    rsyslog \
    tcpdump \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /var/lib/rsyslog
COPY init_firewall.sh /usr/local/bin/init_firewall.sh
RUN chmod +x /usr/local/bin/init_firewall.sh

CMD ["tail", "-f", "/dev/null"]