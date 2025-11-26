FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog rsyslog-openssl iproute2 net-tools bash procps tcpdump && rm -rf /var/lib/apt/lists/*
COPY images/siem/rsyslog_receiver.conf /etc/rsyslog.d/
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/siem-server.pem /etc/ssl/certs/siem-server.pem
COPY config/certs/siem-server.key /etc/ssl/private/siem-server.key
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
COPY images/siem/startup_siem.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_siem.sh

CMD ["/usr/local/bin/startup_siem.sh"]
