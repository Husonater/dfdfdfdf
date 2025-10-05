FROM php:8.2-apache
# Installiere grundlegende Tools
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
# Einfache Index-Seite (simuliert die unternehmenskritische Anwendung)
RUN echo "<h1>Webserver is running!</h1><p>Client IP: $_SERVER['REMOTE_ADDR']</p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
