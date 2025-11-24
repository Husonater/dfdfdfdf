FROM php:8.2-apache
RUN apt-get update && apt-get install -y iproute2 net-tools && rm -rf /var/lib/apt/lists/*
RUN echo "<h1>Webserver is running!</h1><p>Client IP: <?php echo \$_SERVER['REMOTE_ADDR']; ?></p>" > /var/www/html/index.php
CMD ["apache2-foreground"]
