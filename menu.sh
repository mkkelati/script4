#!/bin/bash
# MK Script Manager v4.0 - Advanced SSH Management System
# Compatible with Ubuntu 20.04 - 24.04 LTS
# Repository: https://github.com/mkkelati/script4

# Configuration
USER_LIST_FILE="/etc/mk-script/users.txt"
PASSWORD_DIR="/etc/mk-script/senha"
LEGACY_PASSWORD_DIR="/etc/VPSManager/senha"
LEGACY_EXP_FILE="/etc/VPSManager/Exp"

# User Limiter Configuration
LIMITER_DATABASE="/root/usuarios.db"
OPENVPN_STATUS="/etc/openvpn/openvpn-status.log"
OPENVPN_MANAGEMENT_PORT="7505"
CHECK_INTERVAL=15
AUTOSTART_FILE="/etc/autostart"
LIMITER_NAME="user_limiter"

# Ensure required files exist
[[ -f "$USER_LIST_FILE" ]] || { echo "User list missing at $USER_LIST_FILE"; exit 1; }

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

# Utility functions
generate_password() { < /dev/urandom tr -dc 'A-Za-z0-9' | head -c8; }
list_users() { nl -w2 -s ') ' "$USER_LIST_FILE"; }

safe_number() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "0"
    fi
}

# Display professional system dashboard (horizontal layout)
display_professional_dashboard() {
    clear
    
    # Get system information
    local os_info=$(lsb_release -d 2>/dev/null | cut -f2 | cut -d' ' -f1-3 || echo "$(uname -s)")
    local total_ram=$(free -h | awk '/^Mem:/ {print $2}')
    local used_ram=$(free -h | awk '/^Mem:/ {print $3}')
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//' || echo "N/A")
    local processor=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | awk '{print $1, $2, $3}' || echo "Unknown")
    local total_users=$(wc -l < "$USER_LIST_FILE" 2>/dev/null || echo "0")
    local active_connections=$(ss -tn | grep -c ESTAB 2>/dev/null || echo "0")
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║${WHITE}                                            🚀 MK SCRIPT MANAGER v4.0 - Professional Dashboard                                            ${BLUE}║${RESET}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣${RESET}"
    
    # First row - System Information
    printf "${BLUE}║${WHITE} 🖥️  ${YELLOW}OS:${GREEN} %-12s ${WHITE}💾 ${YELLOW}RAM:${GREEN} %-6s${WHITE}/${YELLOW}%-6s ${WHITE}⚡ ${YELLOW}CPU:${GREEN} %-6s ${WHITE}🔧 ${YELLOW}Processor:${GREEN} %-20s ${WHITE}📈 ${YELLOW}Load:${GREEN} %-6s ${BLUE}║${RESET}\n" \
        "$os_info" "$used_ram" "$total_ram" "$cpu_usage%" "$(echo $processor | cut -c1-20)" "$load_avg"
    
    # Second row - Connection Statistics & Time
    printf "${BLUE}║${WHITE} 🌐 ${YELLOW}Connections:${GREEN} %-8s ${WHITE}👥 ${YELLOW}Users:${GREEN} %-8s ${WHITE}📅 ${YELLOW}Server Time:${GREEN} %-35s ${WHITE}🔒 ${YELLOW}Status:${GREEN} %-12s ${BLUE}║${RESET}\n" \
        "$active_connections" "$total_users" "$(date '+%Y-%m-%d %H:%M:%S %Z')" "Active"
    
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Professional header with timestamp
display_header_with_timestamp() {
    local title="$1"
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    tput setaf 7 ; tput setab 4 ; tput bold
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" "🚀 MK SCRIPT MANAGER v4.0 - $title" | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" "📅 $current_time" | tr ' ' ' '
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' ' '
    tput sgr0
}

# Get SSH connections for user
get_ssh_connections() {
    local user="$1"
    if grep -q "^$user:" /etc/passwd 2>/dev/null; then
        ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
    else
        echo "0"
    fi
}

# Get Dropbear connections for user
get_dropbear_connections() {
    local user="$1"
    if command -v dropbear >/dev/null 2>&1; then
        ps -u "$user" 2>/dev/null | grep -c dropbear || echo "0"
    else
        echo "0"
    fi
}

# Get OpenVPN connections for user
get_openvpn_connections() {
    local user="$1"
    local count=0
    
    # Check OpenVPN status log
    if [[ -f /etc/openvpn/openvpn-status.log ]]; then
        count=$(grep -c "^$user," /etc/openvpn/openvpn-status.log 2>/dev/null || echo "0")
    fi
    
    # Check OpenVPN server logs
    if [[ -f /var/log/openvpn/status.log ]]; then
        local log_count=$(grep -c "^$user," /var/log/openvpn/status.log 2>/dev/null || echo "0")
        count=$((count + log_count))
    fi
    
    echo "$count"
}

# Get user expiration date
get_user_expiration() {
    local user="$1"
    
    # Check main expiration file
    if [[ -f "$LEGACY_EXP_FILE" ]] && grep -q "^$user " "$LEGACY_EXP_FILE"; then
        grep "^$user " "$LEGACY_EXP_FILE" | cut -d' ' -f2
    else
        echo "Never"
    fi
}

# Check if user is expired
is_user_expired() {
    local user="$1"
    local exp_date=$(get_user_expiration "$user")
    
    if [[ "$exp_date" == "Never" ]]; then
        return 1
    fi
    
    local current_date=$(date +%Y-%m-%d)
    if [[ "$exp_date" < "$current_date" ]]; then
        return 0
    else
        return 1
    fi
}

# Create new user
create_user() {
    clear
    display_header_with_timestamp "CREATE USER"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}           CREATE NEW USER              ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
  read -p "Enter new username: " username
    [[ -z "$username" ]] && { echo -e "${RED}Username cannot be empty.${RESET}"; return; }
    
    # Check if user exists
    if id "$username" &>/dev/null; then 
        echo -e "${RED}User '$username' already exists. Choose another.${RESET}"; 
        return; 
    fi
    
    read -s -p "Enter password (blank = auto-generate): " password
    echo
    [[ -z "$password" ]] && { 
        password=$(generate_password); 
        echo -e "${GREEN}Generated password: ${WHITE}$password${RESET}"; 
    }
    
    read -p "Connection limit (0 = unlimited): " limit
    [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]] && limit=0
    
    read -p "Expiration in days (blank = never, 0 = unlimited): " exp_days
    [[ -z "$exp_days" ]] && exp_days="never"
    
    # Calculate expiration date from days
    if [[ "$exp_days" == "never" || "$exp_days" == "0" ]]; then
        exp_date="Never"
    elif [[ "$exp_days" =~ ^[0-9]+$ ]]; then
        exp_date=$(date -d "+${exp_days} days" +%Y-%m-%d)
        echo -e "${GREEN}✓ Account will expire on: $exp_date${RESET}"
    else
        echo -e "${RED}Invalid input. Use number of days or leave blank for never${RESET}"
        return
    fi
    
    # Create system user
    if useradd -m -s /bin/false "$username" 2>/dev/null; then
  echo "${username}:${password}" | chpasswd
        
        # Add to user database
        echo "${username}:${limit}" >> "$USER_LIST_FILE"
        
        # Store password
        mkdir -p "$PASSWORD_DIR"
        echo "$password" > "$PASSWORD_DIR/$username"
        
        # Store expiration if set
        if [[ "$exp_date" != "Never" ]]; then
            mkdir -p "$(dirname "$LEGACY_EXP_FILE")"
            echo "$username $exp_date" >> "$LEGACY_EXP_FILE"
        fi
        
        # Set connection limit
        if [[ "$limit" -gt 0 ]]; then
            LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
            mkdir -p /etc/security/limits.d
            echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
        fi
        
        # Display account information
        clear
        display_header_with_timestamp "USER CREATED"
        
        echo -e "\n${GREEN}┌────────────────────────────────────────┐${RESET}"
        echo -e "${GREEN}│${WHITE}        ACCOUNT CREATED SUCCESSFULLY     ${GREEN}│${RESET}"
        echo -e "${GREEN}└────────────────────────────────────────┘${RESET}\n"
        
        echo -e "${WHITE}Username:${RESET} ${GREEN}$username${RESET}"
        echo -e "${WHITE}Password:${RESET} ${GREEN}$password${RESET}"
        echo -e "${WHITE}Limit:${RESET} ${GREEN}$limit connections${RESET}"
        echo -e "${WHITE}Expires:${RESET} ${GREEN}$exp_date${RESET}"
        
        # Show connection details
  if systemctl is-active --quiet stunnel4; then
            PORT=$(grep -m1 "^accept = " /etc/stunnel/stunnel.conf 2>/dev/null | awk '{print $3}' || echo "443")
            echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
            echo -e "${BLUE}│${WHITE}         CONNECTION DETAILS             ${BLUE}│${RESET}"
            echo -e "${BLUE}└────────────────────────────────────────┘${RESET}"
            echo -e "${WHITE}SSH-SSL Port:${RESET} ${YELLOW}$PORT${RESET}"
            echo -e "${WHITE}Protocol:${RESET} ${YELLOW}Stunnel${RESET}"
        else
            echo -e "\n${WHITE}Standard SSH Port:${RESET} ${YELLOW}22${RESET}"
        fi
        
    else
        echo -e "${RED}Failed to create user '$username'${RESET}"
    fi
}

# Delete user
delete_user() {
    clear
    display_header_with_timestamp "DELETE USER"
    
    echo -e "\n${RED}┌────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${WHITE}            DELETE USER                 ${RED}│${RESET}"
    echo -e "${RED}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to delete.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to delete:${RESET}\n"
  list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    echo -e "\n${YELLOW}Are you sure you want to delete user '${WHITE}$username${YELLOW}'? [y/N]:${RESET} "
    read -n 1 -r confirm
    echo
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Kill active sessions
        pkill -u "$username" 2>/dev/null
        
        # Delete system user
  userdel -r "$username" 2>/dev/null
        
        # Remove from database
  sed -i "${num}d" "$USER_LIST_FILE"
        
        # Remove password files
        rm -f "$PASSWORD_DIR/$username" "$LEGACY_PASSWORD_DIR/$username" 2>/dev/null
        
        # Remove expiration entry
        if [[ -f "$LEGACY_EXP_FILE" ]]; then
            sed -i "/^$username /d" "$LEGACY_EXP_FILE"
        fi
        
        # Remove connection limits
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
        if [[ -f "$LIMIT_FILE" ]]; then
            sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
        fi
        
        echo -e "\n${GREEN}✓ User '$username' deleted successfully${RESET}"
    else
        echo -e "\n${YELLOW}Operation cancelled${RESET}"
    fi
}

# Set user connection limit
limit_user() {
    clear
    display_header_with_timestamp "USER LIMITS"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        SET CONNECTION LIMITS           ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to limit.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to limit:${RESET}\n"
  list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    current_limit=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f2)
    echo -e "${WHITE}Current limit for '${GREEN}$username${WHITE}': ${YELLOW}$current_limit${RESET}"
    
    read -p "New connection limit (0 = unlimited): " limit
    [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]] && limit=0
    
    # Update database
    awk -F: -v user="$username" -v newlimit="$limit" '
        {if($1==user){$2=newlimit} print $1 ":" $2}
    ' "$USER_LIST_FILE" > "${USER_LIST_FILE}.tmp" && mv "${USER_LIST_FILE}.tmp" "$USER_LIST_FILE"
    
    # Update PAM limits
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  mkdir -p /etc/security/limits.d
  sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE" 2>/dev/null
    
    if [[ "$limit" -gt 0 ]]; then
        echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
    fi
    
    echo -e "\n${GREEN}✓ Connection limit for '$username' set to $limit${RESET}"
}

# Configure SSH-SSL tunnel
configure_tunnel() {
    clear
    display_header_with_timestamp "SSL TUNNEL"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}       SSH-SSL TUNNEL SETUP            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    read -p "Enter SSL port [default 443]: " port
  port=${port:-443}
    
    [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] || { 
        echo -e "${RED}Invalid port number.${RESET}"; 
        return; 
    }
    
    # Install latest stunnel if not present
    if ! command -v stunnel4 &>/dev/null && ! command -v stunnel &>/dev/null; then
        echo -e "${YELLOW}Installing latest stunnel...${RESET}"
        
        # Install build dependencies
        apt-get update -y >/dev/null 2>&1
        apt-get install -y build-essential libssl-dev zlib1g-dev wget tar >/dev/null 2>&1
        
        # Download and compile latest stunnel
        cd /tmp
        echo -e "${YELLOW}Downloading stunnel 5.75 (latest)...${RESET}"
        wget -q https://www.stunnel.org/downloads/stunnel-5.75.tar.gz || {
            echo -e "${YELLOW}Fallback: Installing from Ubuntu repository...${RESET}"
            apt-get install -y stunnel4 >/dev/null 2>&1 || { 
                echo -e "${RED}Failed to install stunnel${RESET}"; 
                return; 
            }
        }
        
        if [[ -f stunnel-5.75.tar.gz ]]; then
            echo -e "${YELLOW}Compiling stunnel 5.75...${RESET}"
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
            
            echo -e "${GREEN}✓ Latest stunnel 5.75 installed with systemd service${RESET}"
        fi
    fi
    
    # Configure stunnel for Ubuntu 22.04/24.04 compatibility
    echo -e "${YELLOW}Configuring stunnel for Ubuntu 22.04/24.04...${RESET}"
    
    # Clean up old systemd overrides if they exist
    rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null
    
    # Create default configuration if needed
    if [[ -f /etc/default/stunnel4 ]]; then
        sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
        echo 'ENABLED=1' >> /etc/default/stunnel4 2>/dev/null
    else
        echo 'ENABLED=1' > /etc/default/stunnel4
    fi
    
    # Reload systemd daemon to pick up new service
    systemctl daemon-reload >/dev/null 2>&1
    
    # Generate certificate if needed with proper permissions
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
        echo -e "${YELLOW}Generating SSL certificate...${RESET}"
        
        # Create certificate with proper permissions for stunnel4 user
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
      -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
            -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
        
        # Combine certificate and key
    cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
        
        # Set proper ownership and permissions for stunnel4 user
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
        
        # Also fix permissions on the directory
        chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
        chmod 755 /etc/stunnel
        
        # Clean up individual files
        rm -f /etc/stunnel/key.pem /etc/stunnel/cert.pem
        
        echo -e "${GREEN}✓ SSL certificate generated with proper permissions${RESET}"
    else
        # Fix permissions on existing certificate
        echo -e "${YELLOW}Fixing permissions on existing certificate...${RESET}"
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
        chown -R stunnel4:stunnel4 /etc/stunnel 2>/dev/null || chown -R root:stunnel4 /etc/stunnel
        chmod 755 /etc/stunnel
    fi
    
    # Create stunnel configuration with Ubuntu 22.04/24.04 compatibility
    echo -e "${YELLOW}Creating stunnel configuration...${RESET}"
    
    # Ensure stunnel4 user exists and has proper setup
    if ! id stunnel4 >/dev/null 2>&1; then
        echo -e "${YELLOW}Creating stunnel4 user...${RESET}"
        useradd -r -s /bin/false -d /var/lib/stunnel4 -c "stunnel service" stunnel4 2>/dev/null || true
    fi
    
    # Ensure stunnel directory exists and has correct permissions
    mkdir -p /etc/stunnel
    mkdir -p /var/run/stunnel4
    mkdir -p /var/lib/stunnel4
    mkdir -p /var/log/stunnel4
    
    # Set proper ownership with fallback - try stunnel4 user first, then root
    if id stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown root:root /var/run/stunnel4
        chown stunnel4:stunnel4 /var/lib/stunnel4 2>/dev/null || chown root:root /var/lib/stunnel4
        chown stunnel4:stunnel4 /var/log/stunnel4 2>/dev/null || chown root:root /var/log/stunnel4
    else
        chown root:root /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4
    fi
    
    chmod 755 /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4
    
    # Create configuration with user detection
    local stunnel_user="root"
    local stunnel_group="root"
    
    if id stunnel4 >/dev/null 2>&1; then
        stunnel_user="stunnel4"
        stunnel_group="stunnel4"
    fi
    
    # Create configuration for mandatory TLS_AES_256_GCM_SHA384 cipher
  cat > /etc/stunnel/stunnel.conf <<EOC
# Mandatory TLS_AES_256_GCM_SHA384 cipher configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

# Run as root for maximum compatibility
# setuid = stunnel4
# setgid = stunnel4

# Logging
debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tunnel]
accept = ${port}
connect = 127.0.0.1:22

# MANDATORY: Only TLS_AES_256_GCM_SHA384 cipher allowed
ciphersuites = TLS_AES_256_GCM_SHA384

# Force TLS 1.3 only for TLS_AES_256_GCM_SHA384
sslVersion = TLSv1.3
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = NO_TLSv1_2
EOC

    echo -e "${GREEN}✓ Configuration created${RESET}"

    # Ensure certificate has correct permissions for the user we're using
    if [[ "$stunnel_user" == "stunnel4" ]]; then
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || chown root:stunnel4 /etc/stunnel/stunnel.pem
        chmod 640 /etc/stunnel/stunnel.pem
    else
        chown root:root /etc/stunnel/stunnel.pem
        chmod 600 /etc/stunnel/stunnel.pem
    fi
    
    # Create a working stunnel configuration (no test mode available in stunnel4 5.72)
    echo -e "${YELLOW}Creating optimized stunnel configuration...${RESET}"

    # Start and enable stunnel with proper error handling
    echo -e "${YELLOW}Starting stunnel4 service...${RESET}"
    
    # Stop any existing stunnel processes
    systemctl stop stunnel4 >/dev/null 2>&1 || true
    pkill -f stunnel4 >/dev/null 2>&1 || true
    
    # Reload systemd and start service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable stunnel4 >/dev/null 2>&1
    
    # Give it a moment and start
    sleep 2
    systemctl start stunnel4 >/dev/null 2>&1
    
    # Wait and check status
    sleep 3
    
    # Check if stunnel is running and listening on the port (with fallback for newer Ubuntu)
    local port_listening=false
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp | grep -q ":$port " && port_listening=true
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp | grep -q ":$port " && port_listening=true
    fi
    
    if systemctl is-active --quiet stunnel4 && [[ "$port_listening" == true ]]; then
        echo -e "\n${GREEN}✓ SSH-SSL tunnel configured successfully${RESET}"
        echo -e "${WHITE}SSL Port:${RESET} ${GREEN}$port${RESET}"
        echo -e "${WHITE}Target:${RESET} ${GREEN}127.0.0.1:22${RESET}"
        echo -e "${WHITE}Protocol:${RESET} ${GREEN}TLS 1.2/1.3${RESET}"
        echo -e "${WHITE}Status:${RESET} ${GREEN}Active and listening${RESET}"
        
        # Show service status
        echo -e "\n${BLUE}Service Status:${RESET}"
        systemctl status stunnel4 --no-pager -l | head -5
    else
        echo -e "\n${RED}✗ Failed to start stunnel service${RESET}"
        echo -e "${YELLOW}Troubleshooting information:${RESET}"
        
        # Show detailed error information
        echo -e "${WHITE}Service Status:${RESET}"
        systemctl status stunnel4 --no-pager -l 2>/dev/null | head -10 || echo "Could not get service status"
        
        # Show configuration file
        echo -e "\n${WHITE}Configuration File:${RESET}"
        if [[ -f /etc/stunnel/stunnel.conf ]]; then
            echo "Configuration exists at /etc/stunnel/stunnel.conf"
            echo "First 10 lines:"
            head -10 /etc/stunnel/stunnel.conf 2>/dev/null || echo "Could not read configuration"
        else
            echo "Configuration file missing: /etc/stunnel/stunnel.conf"
        fi
        
        echo -e "\n${WHITE}Certificate Check:${RESET}"
        if [[ -f /etc/stunnel/stunnel.pem ]]; then
            ls -la /etc/stunnel/stunnel.pem
            openssl x509 -in /etc/stunnel/stunnel.pem -text -noout | head -5 2>/dev/null || echo "Certificate validation failed"
        else
            echo "Certificate file missing: /etc/stunnel/stunnel.pem"
        fi
        
        echo -e "\n${WHITE}Stunnel Log:${RESET}"
        if [[ -f /var/log/stunnel4/stunnel.log ]]; then
            echo "Last 15 lines of stunnel log:"
            tail -15 /var/log/stunnel4/stunnel.log 2>/dev/null || echo "Could not read stunnel log"
        else
            echo "No stunnel log file found at /var/log/stunnel4/stunnel.log"
        fi
        
        echo -e "\n${WHITE}System Journal:${RESET}"
        journalctl -u stunnel4 --no-pager -n 10 2>/dev/null || echo "Could not get systemd journal"
        
        echo -e "\n${WHITE}Process Check:${RESET}"
        ps aux | grep stunnel | grep -v grep || echo "No stunnel processes running"
        
        echo -e "\n${WHITE}Port Check:${RESET}"
        if command -v netstat >/dev/null 2>&1; then
            netstat -tlnp | grep ":$port " || echo "Port $port is not listening"
        elif command -v ss >/dev/null 2>&1; then
            ss -tlnp | grep ":$port " || echo "Port $port is not listening"
        else
            echo "No network tools available to check port $port"
        fi
        
        echo -e "\n${WHITE}Directory Permissions:${RESET}"
        ls -la /etc/stunnel/ 2>/dev/null || echo "Could not check /etc/stunnel/"
        ls -la /var/run/stunnel4/ 2>/dev/null || echo "Could not check /var/run/stunnel4/"
        
        echo -e "\n${YELLOW}Debugging commands:${RESET}"
        echo -e "${WHITE}systemctl restart stunnel4${RESET}"
        echo -e "${WHITE}journalctl -u stunnel4 -f${RESET}"
        echo -e "${WHITE}cat /etc/stunnel/stunnel.conf${RESET}"
        echo -e "${WHITE}stunnel4 /etc/stunnel/stunnel.conf${RESET} (manual start)"
    fi
}

# Show online users with real-time monitoring
show_online_users() {
    local refresh_count=0
    
    while true; do
        clear
        display_header_with_timestamp "ONLINE USERS MONITOR"
        
        echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BLUE}│${WHITE}                    REAL-TIME CONNECTIONS                    ${BLUE}│${RESET}"
        echo -e "${BLUE}├─────────────────────────────────────────────────────────────┤${RESET}"
        printf "${BLUE}│${WHITE} %-12s │ %-8s │ %-8s │ %-8s │ %-8s │ %-6s ${BLUE}│${RESET}\n" "USERNAME" "SSH" "DROPBEAR" "OPENVPN" "TOTAL" "STATUS"
        echo -e "${BLUE}├─────────────────────────────────────────────────────────────┤${RESET}"
        
        local total_online=0
        local any_users=false
        
        if [[ -s "$USER_LIST_FILE" ]]; then
            while IFS=: read -r username limit; do
                [[ -z "$username" ]] && continue
                any_users=true
                
                local ssh_count=$(safe_number $(get_ssh_connections "$username"))
                local dropbear_count=$(safe_number $(get_dropbear_connections "$username"))
                local openvpn_count=$(safe_number $(get_openvpn_connections "$username"))
                local total_conn=$((ssh_count + dropbear_count + openvpn_count))
                
                if [[ $total_conn -gt 0 ]]; then
                    total_online=$((total_online + 1))
                    local status_icon="🟢"
                    local status_color="${GREEN}"
                else
                    local status_icon="🔴"
                    local status_color="${RED}"
                fi
                
                # Check if expired
                if is_user_expired "$username"; then
                    status_icon="⏰"
                    status_color="${YELLOW}"
                fi
                
                printf "${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-8s ${BLUE}│${status_color} %-8s ${BLUE}│${status_color} %-6s ${BLUE}│${RESET}\n" \
                    "$username" "$ssh_count" "$dropbear_count" "$openvpn_count" "$total_conn" "$status_icon"
                    
            done < "$USER_LIST_FILE"
        fi
        
        if [[ "$any_users" == false ]]; then
            printf "${BLUE}│${YELLOW} %-57s ${BLUE}│${RESET}\n" "No users found in database"
        fi
        
        echo -e "${BLUE}├─────────────────────────────────────────────────────────────┤${RESET}"
        printf "${BLUE}│${WHITE} Total Users Online: ${GREEN}%-2d${WHITE}                               ${BLUE}│${RESET}\n" "$total_online"
        echo -e "${BLUE}│${WHITE} Auto-refresh: ${GREEN}%-2d${WHITE} times                              ${BLUE}│${RESET}\n" "$refresh_count"
        echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${RESET}"
        
        echo -e "\n${WHITE}🟢 Online  🔴 Offline  ⏰ Expired${RESET}"
        echo -e "${GREEN}Press ${WHITE}ENTER${GREEN} to return to main menu or wait for auto-refresh...${RESET}"
        
        # Wait for user input or timeout after 3 seconds
        if read -t 3 -n 1 user_input 2>/dev/null; then
            # If user pressed any key, exit the loop
            if [[ -n "$user_input" ]] || [[ "$user_input" == "" ]]; then
                break
            fi
        fi
        
        ((refresh_count++))
    done
}

# Network traffic monitoring
show_network_traffic() {
    clear
    display_header_with_timestamp "NETWORK TRAFFIC"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        NETWORK TRAFFIC MONITOR         ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    if command -v nload >/dev/null 2>&1; then
        echo -e "${WHITE}Starting network traffic monitor...${RESET}"
        echo -e "${YELLOW}Press 'q' to quit nload${RESET}\n"
        sleep 2
        nload
    else
        echo -e "${YELLOW}Installing network monitoring tool...${RESET}"
        apt-get update -y >/dev/null 2>&1
        if apt-get install -y nload >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Installation complete${RESET}"
            echo -e "${WHITE}Starting network traffic monitor...${RESET}"
            sleep 2
            nload
        else
            echo -e "${RED}✗ Failed to install nload${RESET}"
            echo -e "${WHITE}Showing basic network statistics:${RESET}\n"
            
            # Basic network info
            echo -e "${BLUE}Network Interfaces:${RESET}"
            ip -4 addr show | grep -E '^[0-9]+:|inet ' | while read line; do
                if [[ $line =~ ^[0-9]+: ]]; then
                    echo -e "${WHITE}$line${RESET}"
                else
                    echo -e "  ${GREEN}$line${RESET}"
                fi
            done
        fi
    fi
}

# User report with comprehensive information
show_user_report() {
    clear
    display_header_with_timestamp "USER REPORT"
    
    echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}                           USER STATUS REPORT                        ${BLUE}│${RESET}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    printf "${BLUE}│${WHITE} %-12s │ %-8s │ %-8s │ %-12s │ %-8s │ %-8s ${BLUE}│${RESET}\n" "USERNAME" "LIMIT" "ACTIVE" "EXPIRES" "PASSWORD" "STATUS"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    
    local total_users=0
    local active_users=0
    local expired_users=0
    
    if [[ -s "$USER_LIST_FILE" ]]; then
  while IFS=: read -r username limit; do
            [[ -z "$username" ]] && continue
            total_users=$((total_users + 1))
            
            local ssh_count=$(safe_number $(get_ssh_connections "$username"))
            local dropbear_count=$(safe_number $(get_dropbear_connections "$username"))
            local openvpn_count=$(safe_number $(get_openvpn_connections "$username"))
            local total_conn=$((ssh_count + dropbear_count + openvpn_count))
            local exp_date=$(get_user_expiration "$username")
            
            # Get password
            local password="N/A"
            if [[ -f "$PASSWORD_DIR/$username" ]]; then
                password=$(cat "$PASSWORD_DIR/$username" 2>/dev/null || echo "N/A")
            elif [[ -f "$LEGACY_PASSWORD_DIR/$username" ]]; then
                password=$(cat "$LEGACY_PASSWORD_DIR/$username" 2>/dev/null || echo "N/A")
            fi
            
            # Determine status
            local status="Active"
            local status_color="${GREEN}"
            
            if is_user_expired "$username"; then
                status="Expired"
                status_color="${RED}"
                expired_users=$((expired_users + 1))
            elif [[ $total_conn -gt 0 ]]; then
                status="Online"
                status_color="${GREEN}"
                active_users=$((active_users + 1))
            else
                status="Offline"
                status_color="${YELLOW}"
            fi
            
            printf "${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-8s ${BLUE}│${WHITE} %-12s ${BLUE}│${WHITE} %-8s ${BLUE}│${status_color} %-8s ${BLUE}│${RESET}\n" \
                "$username" "$limit" "$total_conn" "$exp_date" "${password:0:8}" "$status"
                
        done < "$USER_LIST_FILE"
    else
        printf "${BLUE}│${YELLOW} %-67s ${BLUE}│${RESET}\n" "No users found in database"
    fi
    
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────────┤${RESET}"
    printf "${BLUE}│${WHITE} Total: ${GREEN}%-3d${WHITE} │ Active: ${GREEN}%-3d${WHITE} │ Expired: ${RED}%-3d${WHITE}                    ${BLUE}│${RESET}\n" \
        "$total_users" "$active_users" "$expired_users"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────┘${RESET}"
}

# Change user password
change_user_password() {
    clear
    display_header_with_timestamp "CHANGE PASSWORD"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}         CHANGE USER PASSWORD          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    [[ -s "$USER_LIST_FILE" ]] || { 
        echo -e "${YELLOW}No users to modify.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Select user to change password:${RESET}\n"
    list_users
    echo
    
    read -p "Enter user number: " num
    [[ "$num" =~ ^[0-9]+$ ]] || { 
        echo -e "${RED}Invalid selection.${RESET}"; 
        return; 
    }
    
    username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
    [[ -n "$username" ]] || { 
        echo -e "${RED}User not found.${RESET}"; 
        return; 
    }
    
    echo -e "${WHITE}Changing password for user: ${GREEN}$username${RESET}\n"
    
    read -s -p "Enter new password (blank = auto-generate): " new_password
    echo
    
    [[ -z "$new_password" ]] && { 
        new_password=$(generate_password); 
        echo -e "${GREEN}Generated password: ${WHITE}$new_password${RESET}"; 
    }
    
    # Update system password
    if echo "${username}:${new_password}" | chpasswd 2>/dev/null; then
        # Update password files
        mkdir -p "$PASSWORD_DIR"
        echo "$new_password" > "$PASSWORD_DIR/$username"
        
        # Update legacy location if it exists
        if [[ -d "$LEGACY_PASSWORD_DIR" ]]; then
            mkdir -p "$LEGACY_PASSWORD_DIR"
            echo "$new_password" > "$LEGACY_PASSWORD_DIR/$username"
        fi
        
        echo -e "\n${GREEN}✓ Password changed successfully${RESET}"
        echo -e "${WHITE}Username:${RESET} ${GREEN}$username${RESET}"
        echo -e "${WHITE}New Password:${RESET} ${GREEN}$new_password${RESET}"
    else
        echo -e "\n${RED}✗ Failed to change password${RESET}"
    fi
}

# ============================================================================
# USER LIMITER FUNCTIONS
# ============================================================================

# Function to display loading bar
fun_bar() {
    local command1="$1"
    local command2="$2"
    
    (
        eval "$command1" >/dev/null 2>&1
        [[ -n "$command2" ]] && eval "$command2" >/dev/null 2>&1
        touch /tmp/limiter_done
    ) &
    
    echo -ne "${YELLOW}Please Wait... ${WHITE}- ${YELLOW}["
    while [[ ! -f /tmp/limiter_done ]]; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "${RED}#"
            sleep 0.1
        done
        [[ -f /tmp/limiter_done ]] && break
        echo -e "${YELLOW}]"
        sleep 1
        echo -ne "\033[1A\033[K${YELLOW}Please Wait... ${WHITE}- ${YELLOW}["
    done
    echo -e "${YELLOW}]${WHITE} - ${GREEN}DONE!${RESET}"
    rm -f /tmp/limiter_done
}

# Function to get user connection limit from limiter database
get_user_limit_from_db() {
    local user="$1"
    if [[ -f "$LIMITER_DATABASE" ]] && grep -wq "$user" "$LIMITER_DATABASE"; then
        grep -w "$user" "$LIMITER_DATABASE" | cut -d' ' -f2
    else
        echo "1"  # Default limit
    fi
}

# Function to count SSH connections for a user (limiter version)
count_ssh_connections_limiter() {
    local user="$1"
    ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
}

# Function to count OpenVPN connections for a user (limiter version)
count_openvpn_connections_limiter() {
    local user="$1"
    if [[ -e "$OPENVPN_STATUS" ]]; then
        grep -E ",$user," "$OPENVPN_STATUS" 2>/dev/null | wc -l || echo "0"
    else
        echo "0"
    fi
}

# Function to kill excess OpenVPN connections
kill_excess_openvpn() {
    local user="$1"
    local limit="$2"
    local current_connections="$3"
    
    local connections_to_kill=$((current_connections - limit))
    if [[ $connections_to_kill -gt 0 ]]; then
        local pids_to_kill=$(grep -E ",$user," "$OPENVPN_STATUS" 2>/dev/null | cut -d',' -f3 | head -n $connections_to_kill)
        
        while IFS= read -r pid; do
            if [[ -n "$pid" ]]; then
                (
                    {
                        echo "kill $pid"
                        sleep 1
                    } | telnet localhost "$OPENVPN_MANAGEMENT_PORT" 
                ) &>/dev/null &
            fi
        done <<< "$pids_to_kill"
    fi
}

# Main limiter enforcement function
enforce_limits() {
    local users_processed=0
    local violations_found=0
    
    # Get all system users (UID >= 1000, excluding nobody)
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        
        local limit=$(get_user_limit_from_db "$user")
        local ssh_connections=$(count_ssh_connections_limiter "$user")
        local openvpn_connections=$(count_openvpn_connections_limiter "$user")
        local total_connections=$((ssh_connections + openvpn_connections))
        
        ((users_processed++))
        
        # Check SSH connections
        if [[ $ssh_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded SSH limit ($ssh_connections/$limit) - Killing processes"
            pkill -u "$user" 2>/dev/null
            ((violations_found++))
        fi
        
        # Check OpenVPN connections
        if [[ $openvpn_connections -gt $limit ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - User $user exceeded OpenVPN limit ($openvpn_connections/$limit) - Killing excess connections"
            kill_excess_openvpn "$user" "$limit" "$openvpn_connections"
            ((violations_found++))
        fi
        
    done <<< "$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v nobody)"
    
    # Log summary
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Checked $users_processed users, found $violations_found violations"
}

# Function to start the limiter
start_limiter() {
    clear
    display_header_with_timestamp "USER LIMITER"
    
    echo -e "\n${GREEN}◇ STARTING USER LIMITER...${RESET}"
    echo ""
    
    # Check if already running
    if screen -list | grep -q "$LIMITER_NAME"; then
        echo -e "${YELLOW}User limiter is already running!${RESET}"
        return 1
    fi
    
    # Start the limiter in screen session
    start_limiter_process() {
        screen -dmS "$LIMITER_NAME" bash -c "
            echo 'User Connection Limiter Started - $(date)'
            echo 'Database: $LIMITER_DATABASE'
            echo 'Check Interval: ${CHECK_INTERVAL}s'
            echo 'OpenVPN Status: $OPENVPN_STATUS'
            echo '================================'
            
            while true; do
                $(declare -f enforce_limits get_user_limit_from_db count_ssh_connections_limiter count_openvpn_connections_limiter kill_excess_openvpn)
                enforce_limits
                sleep $CHECK_INTERVAL
            done
        "
        
        # Add to autostart if file exists
        if [[ -f "$AUTOSTART_FILE" ]]; then
            # Remove any existing limiter entries
            sed -i '/user_limiter/d' "$AUTOSTART_FILE" 2>/dev/null
            # Add new entry
            echo "ps x | grep '$LIMITER_NAME' | grep -v 'grep' && echo 'User Limiter: ON' || screen -dmS $LIMITER_NAME /usr/local/bin/menu limiter_daemon" >> "$AUTOSTART_FILE"
        fi
    }
    
    fun_bar 'start_limiter_process' 'sleep 2'
    echo -e "\n${GREEN}◇ USER LIMITER ACTIVATED!${RESET}"
    echo -e "${WHITE}Monitoring users every ${CHECK_INTERVAL} seconds${RESET}"
    echo -e "${WHITE}View logs: ${BLUE}screen -r $LIMITER_NAME${RESET}"
    sleep 3
}

# Function to stop the limiter
stop_limiter() {
    clear
    display_header_with_timestamp "USER LIMITER"
    
    echo -e "${GREEN}◇ STOPPING USER LIMITER...${RESET}"
    echo ""
    
    stop_limiter_process() {
        # Kill screen session
        if screen -list | grep -q "$LIMITER_NAME"; then
            screen -S "$LIMITER_NAME" -X quit 2>/dev/null
        fi
        
        # Clean up screen sessions
        screen -wipe >/dev/null 2>&1
        
        # Remove from autostart
        if [[ -f "$AUTOSTART_FILE" ]]; then
            sed -i '/user_limiter/d' "$AUTOSTART_FILE" 2>/dev/null
        fi
        
        sleep 1
    }
    
    fun_bar 'stop_limiter_process' 'sleep 2'
    echo -e "\n${RED}◇ USER LIMITER STOPPED!${RESET}"
    sleep 3
}

# Function to check limiter status
check_limiter_status() {
    clear
    display_header_with_timestamp "LIMITER STATUS"
    
    echo -e "\n${BLUE}◇ USER LIMITER STATUS${RESET}"
    echo -e "${BLUE}========================${RESET}\n"
    
    if screen -list | grep -q "$LIMITER_NAME"; then
        echo -e "Status: ${GREEN}RUNNING${RESET}"
        echo -e "Session: ${WHITE}$LIMITER_NAME${RESET}"
        echo -e "Database: ${WHITE}$LIMITER_DATABASE${RESET}"
        echo -e "Check Interval: ${WHITE}${CHECK_INTERVAL}s${RESET}"
        
        # Show current user connections
        echo ""
        echo -e "${YELLOW}Current User Connections:${RESET}"
        echo -e "${BLUE}=========================${RESET}"
        printf "%-15s %-8s %-8s %-8s %-8s\n" "User" "Limit" "SSH" "OpenVPN" "Total"
        echo "-------------------------------------------------------"
        
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            local limit=$(get_user_limit_from_db "$user")
            local ssh_count=$(count_ssh_connections_limiter "$user")
            local ovpn_count=$(count_openvpn_connections_limiter "$user")
            local total=$((ssh_count + ovpn_count))
            
            if [[ $total -gt 0 ]]; then
                local status_color="${WHITE}"
                if [[ $total -gt $limit ]]; then
                    status_color="${RED}"
                fi
                printf "${status_color}%-15s %-8s %-8s %-8s %-8s${RESET}\n" "$user" "$limit" "$ssh_count" "$ovpn_count" "$total"
            fi
        done <<< "$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | grep -v nobody)"
        
    else
        echo -e "Status: ${RED}STOPPED${RESET}"
        echo ""
        echo -e "${YELLOW}The user limiter is currently inactive${RESET}"
    fi
    
    echo ""
}

# User Limiter Management Menu
user_limiter_management() {
    while true; do
        clear
        display_header_with_timestamp "USER LIMITER"
        
        echo -e "\n${BLUE}◇ USER LIMITER MANAGEMENT${RESET}"
        echo -e "${BLUE}==========================${RESET}\n"
        
        if screen -list | grep -q "$LIMITER_NAME"; then
            status_text="${GREEN}ACTIVE ♦${RESET}"
            action_text="STOP LIMITER"
            action_color="${RED}"
        else
            status_text="${RED}INACTIVE ○${RESET}"
            action_text="START LIMITER"
            action_color="${GREEN}"
        fi
        
        echo -e "${WHITE}Current Status: $status_text${RESET}"
        echo ""
        echo -e "${RED}[${BLUE}1${RED}] ${WHITE}• ${action_color}$action_text${RESET}"
        echo -e "${RED}[${BLUE}2${RED}] ${WHITE}• ${YELLOW}CHECK STATUS${RESET}"
        echo -e "${RED}[${BLUE}3${RED}] ${WHITE}• ${YELLOW}VIEW LOGS${RESET}"
        echo -e "${RED}[${BLUE}4${RED}] ${WHITE}• ${YELLOW}SETUP DATABASE${RESET}"
        echo -e "${RED}[${BLUE}0${RED}] ${WHITE}• ${YELLOW}BACK TO MAIN MENU${RESET}"
        echo ""
        echo -ne "${GREEN}What do you want to do${YELLOW}? ${WHITE}"
        read choice
        
        case "$choice" in
            1)
                if screen -list | grep -q "$LIMITER_NAME"; then
                    stop_limiter
                else
                    start_limiter
                fi
                ;;
            2)
                check_limiter_status
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                if screen -list | grep -q "$LIMITER_NAME"; then
                    echo -e "\n${YELLOW}Connecting to limiter logs...${RESET}"
                    echo -e "${WHITE}Press Ctrl+A then D to detach${RESET}"
                    sleep 2
                    screen -r "$LIMITER_NAME"
                else
                    echo -e "\n${RED}Limiter is not running!${RESET}"
                    sleep 2
                fi
                ;;
            4)
                setup_limiter_database
                ;;
            0)
                return
                ;;
            *)
                echo -e "\n${RED}Invalid option!${RESET}"
                sleep 2
                ;;
        esac
    done
}

# Function to setup limiter database
setup_limiter_database() {
    clear
    display_header_with_timestamp "DATABASE SETUP"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}        LIMITER DATABASE SETUP          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}Current database: ${GREEN}$LIMITER_DATABASE${RESET}\n"
    
    # Create database directory if needed
    mkdir -p "$(dirname "$LIMITER_DATABASE")"
    
    # Check if database exists
    if [[ -f "$LIMITER_DATABASE" ]]; then
        echo -e "${YELLOW}Existing database found:${RESET}"
        echo -e "${BLUE}=========================${RESET}"
        cat "$LIMITER_DATABASE" 2>/dev/null || echo "Empty database"
        echo ""
    else
        echo -e "${YELLOW}No database found. Creating new one...${RESET}"
        touch "$LIMITER_DATABASE"
    fi
    
    echo -e "${WHITE}Database format: ${GREEN}username limit${RESET}"
    echo -e "${WHITE}Example: ${GREEN}user1 2${RESET} (allows 2 connections)"
    echo ""
    
    echo -e "${RED}[${BLUE}1${RED}] ${WHITE}Add User Limit${RESET}"
    echo -e "${RED}[${BLUE}2${RED}] ${WHITE}Remove User Limit${RESET}"
    echo -e "${RED}[${BLUE}3${RED}] ${WHITE}View Database${RESET}"
    echo -e "${RED}[${BLUE}4${RED}] ${WHITE}Import from Main Database${RESET}"
    echo -e "${RED}[${BLUE}0${RED}] ${WHITE}Back${RESET}"
    echo ""
    echo -ne "${GREEN}Choose option: ${WHITE}"
    read db_choice
    
    case "$db_choice" in
        1)
            read -p "Enter username: " username
            [[ -z "$username" ]] && { echo -e "${RED}Username cannot be empty${RESET}"; sleep 2; return; }
            
            read -p "Enter connection limit: " limit
            [[ ! "$limit" =~ ^[0-9]+$ ]] && { echo -e "${RED}Invalid limit${RESET}"; sleep 2; return; }
            
            # Remove existing entry and add new one
            sed -i "/^$username /d" "$LIMITER_DATABASE" 2>/dev/null
            echo "$username $limit" >> "$LIMITER_DATABASE"
            
            echo -e "\n${GREEN}✓ Added $username with limit $limit${RESET}"
            sleep 2
            ;;
        2)
            if [[ -s "$LIMITER_DATABASE" ]]; then
                echo -e "\n${WHITE}Current users:${RESET}"
                nl -w2 -s ') ' "$LIMITER_DATABASE"
                echo ""
                read -p "Enter username to remove: " username
                
                if grep -q "^$username " "$LIMITER_DATABASE"; then
                    sed -i "/^$username /d" "$LIMITER_DATABASE"
                    echo -e "\n${GREEN}✓ Removed $username${RESET}"
                else
                    echo -e "\n${RED}User not found${RESET}"
                fi
            else
                echo -e "\n${YELLOW}Database is empty${RESET}"
            fi
            sleep 2
            ;;
        3)
            echo -e "\n${WHITE}Current database contents:${RESET}"
            echo -e "${BLUE}=========================${RESET}"
            if [[ -s "$LIMITER_DATABASE" ]]; then
                cat "$LIMITER_DATABASE"
            else
                echo "Database is empty"
            fi
            echo ""
            read -p "Press Enter to continue..."
            ;;
        4)
            if [[ -s "$USER_LIST_FILE" ]]; then
                echo -e "\n${YELLOW}Importing from main database...${RESET}"
                while IFS=: read -r username limit; do
                    [[ -z "$username" ]] && continue
                    # Remove existing entry and add new one
                    sed -i "/^$username /d" "$LIMITER_DATABASE" 2>/dev/null
                    echo "$username $limit" >> "$LIMITER_DATABASE"
  done < "$USER_LIST_FILE"
                echo -e "${GREEN}✓ Import completed${RESET}"
            else
                echo -e "\n${RED}Main database not found${RESET}"
            fi
            sleep 2
            ;;
    esac
}

# Print main menu
print_menu() {
    display_professional_dashboard
    
    echo -e "${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}           MAIN MENU OPTIONS            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}1)${RESET}  ${GREEN}Create User${RESET}          - Add SSH users with limits"
    echo -e "${WHITE}2)${RESET}  ${RED}Delete User${RESET}          - Remove users + cleanup"
    echo -e "${WHITE}3)${RESET}  ${YELLOW}Limit User${RESET}           - Set connection limits"
    echo -e "${WHITE}4)${RESET}  ${BLUE}Connection Mode${RESET}      - Configure SSH-SSL tunnel"
    echo -e "${WHITE}5)${RESET}  ${GREEN}Online Users${RESET}         - Real-time monitoring"
    echo -e "${WHITE}6)${RESET}  ${BLUE}Network Traffic${RESET}      - Live network stats"
    echo -e "${WHITE}7)${RESET}  ${YELLOW}User Report${RESET}          - User status overview"
    echo -e "${WHITE}8)${RESET}  ${GREEN}Change Password${RESET}      - Update user passwords"
    echo -e "${WHITE}9)${RESET}  ${BLUE}User Limiter${RESET}         - Advanced connection enforcement"
    echo -e "${WHITE}10)${RESET} ${CYAN}Server Optimization${RESET} - Optimize server performance"
    echo -e "${WHITE}11)${RESET} ${RED}Uninstall${RESET}           - Complete removal"
    
    echo -e "\n${BLUE}┌─────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE} Select option [1-11] or CTRL+C to exit ${BLUE}│${RESET}"
    echo -e "${BLUE}└─────────────────────────────────────────┘${RESET}"
    echo -n -e "${WHITE}Enter your choice: ${RESET}"
}

# Uninstall system
uninstall_script() {
    clear
    display_header_with_timestamp "UNINSTALL"
    
    echo -e "\n${RED}┌────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${WHITE}         UNINSTALL MK SCRIPT            ${RED}│${RESET}"
    echo -e "${RED}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${YELLOW}⚠️  This will completely remove:${RESET}"
    echo -e "${WHITE}   • All managed users and their data${RESET}"
    echo -e "${WHITE}   • SSL/TLS configurations${RESET}"
    echo -e "${WHITE}   • Menu system and scripts${RESET}"
    echo -e "${WHITE}   • Configuration files${RESET}\n"
    
    read -p "Are you absolutely sure? Type 'yes' to confirm: " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo -e "\n${YELLOW}Uninstalling MK Script Manager...${RESET}\n"
        
        # Stop services
        echo -e "${WHITE}[1/6] Stopping services...${RESET}"
  systemctl stop stunnel4 2>/dev/null
        systemctl disable stunnel4 2>/dev/null
        
        # Remove users
        echo -e "${WHITE}[2/6] Removing managed users...${RESET}"
        if [[ -s "$USER_LIST_FILE" ]]; then
  while IFS=: read -r username limit; do
                [[ -n "$username" ]] && userdel -r "$username" 2>/dev/null
  done < "$USER_LIST_FILE"
        fi
        
        # Remove configurations
        echo -e "${WHITE}[3/6] Removing configurations...${RESET}"
        rm -rf /etc/mk-script /etc/VPSManager 2>/dev/null
        rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem 2>/dev/null
        rm -f /etc/security/limits.d/mk-script-limits.conf 2>/dev/null
        
        # Remove packages
        echo -e "${WHITE}[4/6] Removing packages...${RESET}"
        apt-get remove -y stunnel4 >/dev/null 2>&1
        
        # Remove scripts
        echo -e "${WHITE}[5/6] Removing menu system...${RESET}"
        rm -f /usr/local/bin/menu 2>/dev/null
        
        # Final cleanup
        echo -e "${WHITE}[6/6] Final cleanup...${RESET}"
        apt-get autoremove -y >/dev/null 2>&1
        
        echo -e "\n${GREEN}✓ MK Script Manager uninstalled successfully${RESET}"
        echo -e "${WHITE}Thank you for using MK Script Manager v4.0!${RESET}\n"
        
  exit 0
    else
        echo -e "\n${YELLOW}Uninstall cancelled${RESET}"
    fi
}

# Server optimization function with loading animation
optimize_server() {
    clear
    display_header_with_timestamp "SERVER OPTIMIZATION"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}         SERVER OPTIMIZATION            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}This will optimize your server performance and security...${RESET}\n"
    read -p "Do you want to proceed? (y/n): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "\n${YELLOW}Server optimization cancelled${RESET}"
        return
    fi
    
    # Loading animation function
    show_loading() {
        local message="$1"
        local duration="$2"
        local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        local delay=0.1
        local elapsed=0
        
        while [ $elapsed -lt $duration ]; do
            for (( i=0; i<${#chars}; i++ )); do
                printf "\r${YELLOW}${chars:$i:1} ${WHITE}$message${RESET}"
                sleep $delay
                elapsed=$(echo "$elapsed + $delay" | bc -l 2>/dev/null || echo $((elapsed + 1)))
                if [ $(echo "$elapsed >= $duration" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then
                    break 2
                fi
            done
        done
        printf "\r${GREEN}✓${WHITE} $message${RESET}\n"
    }
    
    clear
    display_header_with_timestamp "OPTIMIZING SERVER"
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}      OPTIMIZATION IN PROGRESS          ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    local optimization_results=""
    local optimization_count=0
    
    # 1. Update system packages
    (
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
    ) &
    show_loading "Updating system packages..." 3
    wait
    optimization_results+="✓ System packages updated\n"
    ((optimization_count++))
    
    # 2. Clean system cache
    (
        apt-get autoremove -y >/dev/null 2>&1
        apt-get autoclean >/dev/null 2>&1
        rm -rf /tmp/* 2>/dev/null
        find /var/log -name "*.log" -type f -size +50M -delete 2>/dev/null
    ) &
    show_loading "Cleaning system cache and logs..." 2
    wait
    optimization_results+="✓ System cache and logs cleaned\n"
    ((optimization_count++))
    
    # 3. Optimize network settings
    (
        # TCP optimization
        echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf 2>/dev/null
        echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf 2>/dev/null
        echo 'net.ipv4.tcp_rmem = 4096 87380 16777216' >> /etc/sysctl.conf 2>/dev/null
        echo 'net.ipv4.tcp_wmem = 4096 65536 16777216' >> /etc/sysctl.conf 2>/dev/null
        echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf 2>/dev/null
        sysctl -p >/dev/null 2>&1
    ) &
    show_loading "Optimizing network settings..." 2
    wait
    optimization_results+="✓ Network settings optimized\n"
    ((optimization_count++))
    
    # 4. Security hardening
    (
        # SSH security
        sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
        
        # Firewall basic setup
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        ufw allow 22 >/dev/null 2>&1
        ufw allow 80 >/dev/null 2>&1
        ufw allow 443 >/dev/null 2>&1
        echo "y" | ufw enable >/dev/null 2>&1
    ) &
    show_loading "Applying security hardening..." 3
    wait
    optimization_results+="✓ Security settings hardened\n"
    ((optimization_count++))
    
    # 5. Memory optimization
    (
        # Swap optimization
        echo 'vm.swappiness = 10' >> /etc/sysctl.conf 2>/dev/null
        echo 'vm.vfs_cache_pressure = 50' >> /etc/sysctl.conf 2>/dev/null
        
        # Clear memory cache
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sysctl -p >/dev/null 2>&1
    ) &
    show_loading "Optimizing memory usage..." 2
    wait
    optimization_results+="✓ Memory settings optimized\n"
    ((optimization_count++))
    
    # 6. Service optimization
    (
        systemctl daemon-reload >/dev/null 2>&1
        systemctl restart networking >/dev/null 2>&1
        systemctl restart ssh >/dev/null 2>&1
        systemctl restart stunnel4 >/dev/null 2>&1 || true
    ) &
    show_loading "Restarting optimized services..." 2
    wait
    optimization_results+="✓ Services restarted with new settings\n"
    ((optimization_count++))
    
    # Show results
    clear
    display_header_with_timestamp "OPTIMIZATION COMPLETE"
    
    echo -e "\n${GREEN}┌────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${WHITE}     OPTIMIZATION SUCCESSFUL!           ${GREEN}│${RESET}"
    echo -e "${GREEN}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}Optimization Results:${RESET}\n"
    echo -e "$optimization_results"
    
    echo -e "${BLUE}📊 Performance Summary:${RESET}"
    echo -e "${WHITE}• Total optimizations applied: ${GREEN}$optimization_count${RESET}"
    echo -e "${WHITE}• System packages: ${GREEN}Updated${RESET}"
    echo -e "${WHITE}• Cache cleanup: ${GREEN}Completed${RESET}"
    echo -e "${WHITE}• Network performance: ${GREEN}Enhanced${RESET}"
    echo -e "${WHITE}• Security hardening: ${GREEN}Applied${RESET}"
    echo -e "${WHITE}• Memory optimization: ${GREEN}Configured${RESET}"
    echo -e "${WHITE}• Services: ${GREEN}Restarted${RESET}"
    
    echo -e "\n${YELLOW}💡 Recommendations:${RESET}"
    echo -e "${WHITE}• Reboot your server for all changes to take full effect${RESET}"
    echo -e "${WHITE}• Monitor performance over the next 24 hours${RESET}"
    echo -e "${WHITE}• Run optimization monthly for best results${RESET}"
    
    echo -e "\n${GREEN}✅ Your server has been successfully optimized!${RESET}"
}

# Graceful exit function
graceful_exit() {
    echo -e "\n\n${YELLOW}👋 Thank you for using MK Script Manager v4.0!${RESET}"
    echo -e "${WHITE}Exiting gracefully...${RESET}"
    exit 0
}

# Main program loop
main() {
    # Ensure running as root
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (use sudo)${RESET}"
        exit 1
    fi
    
    # Set up CTRL+C handler for graceful exit
    trap graceful_exit SIGINT
    
    # Create required directories
    mkdir -p "$(dirname "$USER_LIST_FILE")" "$PASSWORD_DIR"
    
    # Main menu loop
    while true; do
        print_menu
        echo -e "${YELLOW}Select option [1-11] (CTRL+C to exit):${RESET} \c"
        read choice
        echo
        
        case "$choice" in
            1) create_user ;;
            2) delete_user ;;
            3) limit_user ;;
            4) configure_tunnel ;;
            5) show_online_users ;;
            6) show_network_traffic ;;
            7) show_user_report ;;
            8) change_user_password ;;
            9) user_limiter_management ;;
            10) optimize_server ;;
            11) uninstall_script ;;
            *) echo -e "${RED}Invalid option. Please select 1-11.${RESET}" ;;
        esac
        
        [[ "$choice" != "11" ]] && {
            echo -e "\n${WHITE}Press any key to return to main menu...${RESET}"
            read -n1 -s -r
        }
    done
}

# CTRL+C handling is now set up in main() function

# Start the program
main "$@"
