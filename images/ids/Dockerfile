FROM debian:latest
RUN apt-get update && apt-get install -y suricata net-tools iproute2 bash rsyslog procps curl && rm -rf /var/lib/apt/lists/*
COPY startup_ids.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_ids.sh

# 🔥 KORREKTUR: Definiert einen Dummy-Prozess, um den Container am Laufen zu halten.
# Das eigentliche Startskript wird später über 'docker exec' aufgerufen.
CMD ["tail", "-f", "/dev/null"]