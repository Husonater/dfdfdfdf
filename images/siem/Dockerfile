FROM debian:latest
RUN apt-get update && apt-get install -y rsyslog iproute2 net-tools bash && rm -rf /var/lib/apt/lists/*
# Kopiere rsyslog config
COPY rsyslog_receiver.conf /etc/rsyslog.d/
RUN mkdir -p /var/log/siem_logs
# Startet rsyslog und haelt den Container am Laufen
CMD ["bash", "-c", "rsyslogd -n & tail -f /var/log/siem_logs/suricata_alerts.log"]
