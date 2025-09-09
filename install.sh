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

# Install latest stunnel with proper configuration for newer Ubuntu versions
echo "[*] Installing and configuring latest stunnel..."

# Install build dependencies first
apt-get install -y build-essential libssl-dev zlib1g-dev wget tar >/dev/null 2>&1

# Try to install latest stunnel from source
cd /tmp
echo "[*] Downloading stunnel 5.75 (latest)..."
if wget -q https://www.stunnel.org/downloads/stunnel-5.75.tar.gz; then
    echo "[*] Compiling latest stunnel..."
    tar -xzf stunnel-5.75.tar.gz
    cd stunnel-5.75
    ./configure --prefix=/usr/local --enable-ipv6 >/dev/null 2>&1
    make >/dev/null 2>&1
    make install >/dev/null 2>&1
    
    # Create symlinks for compatibility
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel4 2>/dev/null
    ln -sf /usr/local/bin/stunnel /usr/bin/stunnel 2>/dev/null
    
    # Create proper systemd service for compiled stunnel
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=Stunnel TLS tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/stunnel /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
User=root
Group=root
RuntimeDirectory=stunnel4
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
    
    # Clean up
    cd /
    rm -rf /tmp/stunnel-5.75*
    
    echo "[*] Latest stunnel 5.75 installed successfully with systemd service"
else
    echo "[*] Fallback: Installing stunnel4 from Ubuntu repository..."
    apt-get install -y stunnel4 >/dev/null 2>&1
fi

# Fix stunnel4 configuration for Ubuntu 22.04/24.04
if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
    echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
else
    echo 'ENABLED=1' > /etc/default/stunnel4
fi

# Clean up old systemd overrides and reload daemon
rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null
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
  
  # Create certificate
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
  
  # Combine certificate and key
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  
  # Set proper ownership and permissions for stunnel4 user
  chown stunnel4:stunnel4 "$STUNNEL_CERT" 2>/dev/null || chown root:stunnel4 "$STUNNEL_CERT"
  chmod 640 "$STUNNEL_CERT"
  
  # Fix directory permissions
  chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
  chmod 755 /etc/stunnel
  
  # Clean up individual files
  rm -f /etc/stunnel/key.pem /etc/stunnel/cert.pem
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# Latest stunnel configuration with TLS 1.3 support
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

# Logging
debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tunnel]
accept = 443
connect = 127.0.0.1:22

# TLS 1.3 ciphersuites (your preferred)
ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# TLS 1.2 fallback ciphers
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256

# SSL/TLS version support
sslVersion = all
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
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
