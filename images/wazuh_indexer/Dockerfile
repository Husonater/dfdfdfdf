FROM wazuh/wazuh-indexer:4.7.3

USER root

# Install iproute2 for Containerlab networking
RUN apt-get update && apt-get install -y iproute2 openssl curl && rm -rf /var/lib/apt/lists/*

USER wazuh-indexer
