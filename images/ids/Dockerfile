FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh
CMD ["/usr/local/bin/startup_ids.sh"]
