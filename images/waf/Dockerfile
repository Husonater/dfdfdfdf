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
    && rm -rf /var/lib/apt/lists/*

# 2. Ordner für ModSecurity Regeln erstellen
RUN mkdir -p /etc/nginx/modsecurity.d

# 3. Konfigurationen kopieren
# Die Dateien müssen lokal im Ordner ./images/waf/ liegen!
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf

# 4. Logs umleiten (für Docker Logs)
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# 5. Startbefehl
CMD ["nginx", "-g", "daemon off;"]