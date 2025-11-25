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
    && rm -rf /var/lib/apt/lists/*

CMD ["mariadbd"]
