#!/bin/bash

# --- DMZ Setup - Phase 2: Base Installation Script (Ubuntu WSL) ---
# This script automates the installation of Docker and Containerlab.
# NOTE: Using direct download links to avoid WSL network/proxy issues.

echo "Starting base installation of Docker and Containerlab..."

# --- 1. Docker Installation ---
echo "1. Installing Docker components..."

# Update package index and install dependencies
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources
echo \
  "deb [arch=\"$(dpkg --print-architecture)\" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  \"$(. /etc/os-release && echo \"$VERSION_CODENAME\")\" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Buildx components (required for docker-compose build)
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add current user to the docker group
sudo usermod -aG docker "$USER"

echo "Docker installed successfully."


# --- 2. Containerlab Installation ---
echo "2. Installing Containerlab..."

# FINAL FIX: Using curl with -L (follow redirects) and saving directly to the bin folder.
# This avoids the complex filename and mv issues.
CLAB_URL="https://github.com/srl-labs/containerlab/releases/latest/download/containerlab-linux-amd64"

# Verwende curl mit -L, um Weiterleitungen (redirects) zu folgen.
if ! sudo curl -L "$CLAB_URL" -o /usr/local/bin/containerlab; then
    echo "ERROR: Failed to download Containerlab from $CLAB_URL. Verify the URL and check if curl is installed."
    exit 1
fi

# Setze die Ausführungsberechtigung
sudo chmod +x /usr/local/bin/containerlab

echo "Containerlab installed successfully."
echo "--------------------------------------------------------"
echo "INSTALLATION COMPLETE!"
echo "You MUST log out and log back into your WSL terminal to run docker and containerlab commands without 'sudo'."
