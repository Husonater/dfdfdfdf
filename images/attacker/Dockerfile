FROM kalilinux/kali-rolling
# Install basic network and attack tools (iproute2 for 'ip', net-tools for 'ifconfig', bash for script compatibility)
RUN apt-get update && apt-get install -y \
    iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump \
    iproute2 bash \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
