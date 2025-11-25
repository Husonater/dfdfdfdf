FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash procps tcpdump && rm -rf /var/lib/apt/lists/*
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
RUN touch /var/log/siem_logs/suricata_alerts.log && chmod 666 /var/log/siem_logs/suricata_alerts.log || true
COPY startup_siem.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_siem.sh

CMD ["/usr/local/bin/startup_siem.sh"]
