FROM php:8.2-apache

# Installiere Netzwerk-Tools UND tcpdump für die Diagnose
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    tcpdump \
    netcat-openbsd \
    rsyslog \
    rsyslog-openssl \
    && rm -rf /var/lib/apt/lists/*

# Certs
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/client.pem /etc/ssl/certs/client.pem
COPY config/certs/client.key /etc/ssl/private/client.key

# Test-Seite erstellen (mit PHP für IP-Anzeige)
RUN echo "<h1>Webserver is running!</h1><p>Client IP: <?php echo \$_SERVER['REMOTE_ADDR']; ?></p>" > /var/www/html/index.php

COPY images/webserver/startup_web.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_web.sh

CMD ["/usr/local/bin/startup_web.sh"]