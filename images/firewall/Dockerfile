FROM alpine:latest

# Installiere Networking-Tools, rsyslog UND ulogd (für Userspace Logging)
RUN apk update && apk add \
    bash \
    iproute2 \
    iptables \
    conntrack-tools \
    rsyslog \
    ulogd

RUN mkdir -p /var/lib/rsyslog

# Skripte und Configs kopieren
COPY init_firewall.sh /usr/local/bin/init_firewall.sh
COPY ulogd.conf /etc/ulogd.conf

RUN chmod +x /usr/local/bin/init_firewall.sh

# Container wach halten
CMD ["tail", "-f", "/dev/null"]