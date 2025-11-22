FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y iproute2 iputils-ping nmap curl netcat-openbsd net-tools wget dnsutils tcpdump && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
