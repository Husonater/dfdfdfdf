FROM wazuh/wazuh-manager:4.7.3

USER root

# Install iproute2 for Containerlab networking
RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*
