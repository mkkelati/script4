#!/bin/bash
# MK Script Manager v4.0 - Installation Script
# Compatible with Ubuntu 20.04 - 24.04 LTS

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

clear
echo "==========================================="
echo "    MK Script Manager v4.0 Installer"
echo "==========================================="
echo ""
echo "[*] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1

# Install basic dependencies including net-tools for netstat command
apt-get install -y openssl screen wget curl net-tools iproute2 systemd >/dev/null 2>&1

# Install stunnel4 with proper configuration for newer Ubuntu versions
echo "[*] Installing and configuring stunnel4..."
apt-get install -y stunnel4 >/dev/null 2>&1

# Fix stunnel4 configuration for Ubuntu 22.04/24.04
if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
    echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
else
    echo 'ENABLED=1' > /etc/default/stunnel4
fi

# Create stunnel4 service override for systemd (Ubuntu 22.04/24.04 fix)
mkdir -p /etc/systemd/system/stunnel4.service.d
cat > /etc/systemd/system/stunnel4.service.d/override.conf << 'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
User=stunnel4
Group=stunnel4
RuntimeDirectory=stunnel4
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd daemon
systemctl daemon-reload >/dev/null 2>&1

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

echo "[*] Installing menu system..."
INSTALL_DIR="/usr/local/bin"

# Always download the latest version from GitHub for consistency
echo "[*] Downloading menu script..."
if wget -q https://raw.githubusercontent.com/mkkelati/script4/main/menu.sh -O "${INSTALL_DIR}/menu"; then
  chmod +x "${INSTALL_DIR}/menu"
  echo "[*] Menu system installed successfully"
else
  echo "[ERROR] Failed to download menu script. Check internet connection."
  exit 1
fi

echo "[*] Setting up configuration..."
mkdir -p /etc/mk-script
touch /etc/mk-script/users.txt

# Create password storage directory
mkdir -p /etc/mk-script/senha

echo "[*] Verifying installation..."
if [[ -x "${INSTALL_DIR}/menu" ]]; then
  clear
  echo ""
  echo "==========================================="
  echo "   🚀 MK Script Manager v4.0 Installed"
  echo "==========================================="
  echo ""
  echo "✓ stunnel4 with TLS 1.3 encryption"
  echo "✓ SSH-SSL tunnel on port 443"
  echo "✓ User management system"
  echo "✓ Connection monitoring"
  echo "✓ User Limiter (NEW)"
  echo ""
  echo "🔧 To start the management system:"
  echo "   menu"
  echo ""
  echo "📱 Features: SSH, SSL, User Limits, Monitoring"
  echo "==========================================="
  echo ""
else
  echo "[ERROR] Installation failed. Menu command not found."
  exit 1
fi
