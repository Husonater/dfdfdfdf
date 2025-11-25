FROM php:8.2-apache

# Installiere Netzwerk-Tools UND tcpdump für die Diagnose
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    tcpdump \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Test-Seite erstellen (mit PHP für IP-Anzeige)
RUN echo "<h1>Webserver is running!</h1><p>Client IP: <?php echo \$_SERVER['REMOTE_ADDR']; ?></p>" > /var/www/html/index.php

CMD ["apache2-foreground"]