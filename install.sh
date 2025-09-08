#!/bin/bash
# install.sh - Installation script for MK Script Manager (Ubuntu 20.04 - 24.04)

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

echo "=== Installing MK Script Manager ==="
echo "[*] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get install -y stunnel4 openssl screen wget curl net-tools

echo "[*] Configuring stunnel service..."
if [[ -f /etc/default/stunnel4 ]]; then
  if grep -qs "ENABLED=0" /etc/default/stunnel4; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
else
  echo 'ENABLED=1' > /etc/default/stunnel4
fi

mkdir -p /etc/stunnel
STUNNEL_CERT="/etc/stunnel/stunnel.pem"
if [[ ! -f "$STUNNEL_CERT" ]]; then
  echo "[*] Generating self-signed SSL certificate for stunnel..."
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  chmod 600 "$STUNNEL_CERT"
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# stunnel configuration for SSH-SSL tunneling
sslVersion = TLSv1.3
ciphersuites = TLS_AES_256_GCM_SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_COMPRESSION
options = NO_TICKET

[ssh-tunnel]
accept = 443
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
fi

echo "[*] Starting stunnel service..."
systemctl restart stunnel4
systemctl enable stunnel4

echo "[*] Deploying menu script..."
INSTALL_DIR="/usr/local/bin"

# Check if we're in the cloned repository directory
if [[ -f "menu.sh" ]]; then
  echo "[*] Using local menu.sh from repository..."
  cp -f menu.sh "${INSTALL_DIR}/menu"
  chmod +x "${INSTALL_DIR}/menu"
else
  # Download menu.sh from GitHub if not present locally
  echo "[*] Downloading menu.sh from GitHub..."
  if wget -q https://raw.githubusercontent.com/mkkelati/script4/main/menu.sh -O "${INSTALL_DIR}/menu"; then
    chmod +x "${INSTALL_DIR}/menu"
  else
    echo "[ERROR] Failed to download menu.sh. Please ensure you have internet connection."
    exit 1
  fi
fi

mkdir -p /etc/mk-script
touch /etc/mk-script/users.txt

echo "[*] Verifying installation..."
if [[ -x "${INSTALL_DIR}/menu" ]]; then
  echo "[+] Installation complete! ✓"
  echo ""
  echo "==========================================="
  echo "  MK Script Manager Successfully Installed"
  echo "==========================================="
  echo ""
  echo "To start the SSH management system, run:"
  echo "  menu"
  echo ""
  echo "Or from any directory:"
  echo "  sudo menu"
  echo ""
else
  echo "[ERROR] Installation failed. Menu command not found."
  exit 1
fi
