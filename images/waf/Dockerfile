FROM debian:bookworm-slim

# 1. Nginx und ModSecurity Module installieren
# WICHTIG: Wir installieren 'libnginx-mod-http-modsecurity', das bringt Nginx und das Modul mit.
RUN apt-get update && apt-get install -y \
    nginx \
    libnginx-mod-http-modsecurity \
    iproute2 \
    iputils-ping \
    curl \
    procps \
    rsyslog \
    rsyslog-openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. Ordner für ModSecurity Regeln erstellen
RUN mkdir -p /etc/nginx/modsecurity.d

# 3. Konfigurationen kopieren
# Die Dateien müssen lokal im Ordner ./images/waf/ liegen!
COPY images/waf/nginx.conf /etc/nginx/nginx.conf
COPY images/waf/modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf

# Certs
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/client.pem /etc/ssl/certs/client.pem
COPY config/certs/client.key /etc/ssl/private/client.key

COPY images/waf/startup_waf.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_waf.sh

# 4. Logs umleiten (für Docker Logs)
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# 5. Startbefehl
CMD ["/usr/local/bin/startup_waf.sh"]