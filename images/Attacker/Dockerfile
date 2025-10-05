# Base Image for Client/Attacker node
FROM debian:bullseye-slim

LABEL maintainer="DMZ-Project-Team"
ENV DEBIAN_FRONTEND=noninteractive

# Install essential network tools for penetration testing and connectivity verification
RUN apt update && \
    apt install -y --no-install-recommends \
    nmap \
    curl \
    iproute2 \
    tcpdump \
    netcat-openbsd \
    # Install tool for HTTP/HTTPS requests
    wget \
    # Install a tool for quick ICMP/TCP/UDP testing (optional but useful)
    iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Set default command to keep the container running
CMD ["sleep", "infinity"]
