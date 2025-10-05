FROM kalilinux/kali-rolling
# Install basic network and attack tools
RUN apt-get update && apt-get install -y iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump -y && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
