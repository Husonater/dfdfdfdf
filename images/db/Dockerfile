FROM mariadb:latest

# Environment variables for basic setup
ENV MARIADB_ROOT_PASSWORD=rootpassword
ENV MARIADB_DATABASE=dmzdb
ENV MARIADB_USER=dmzuser
ENV MARIADB_PASSWORD=dmzpassword

# Install iproute2 and ping for network debugging
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    rsyslog \
    rsyslog-openssl \
    && rm -rf /var/lib/apt/lists/*

# Certs
COPY config/certs/ca.pem /etc/ssl/certs/ca.pem
COPY config/certs/client.pem /etc/ssl/certs/client.pem
COPY config/certs/client.key /etc/ssl/private/client.key

COPY images/db/startup_db.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/startup_db.sh

CMD ["/usr/local/bin/startup_db.sh"]
