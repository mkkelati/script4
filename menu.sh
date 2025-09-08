#!/bin/bash
# MK Script Manager v4.0 - Advanced SSH Management System
# Compatible with Ubuntu 20.04 - 24.04 LTS
# Repository: https://github.com/mkkelati/script4

# Configuration
USER_LIST_FILE="/etc/mk-script/users.txt"
PASSWORD_DIR="/etc/mk-script/senha"
LEGACY_PASSWORD_DIR="/etc/VPSManager/senha"
LEGACY_EXP_FILE="/etc/VPSManager/Exp"

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
    
    read -p "Expiration date (YYYY-MM-DD, blank = never): " exp_date
    [[ -z "$exp_date" ]] && exp_date="Never"
    
    # Validate date format if provided
    if [[ "$exp_date" != "Never" ]] && ! date -d "$exp_date" >/dev/null 2>&1; then
        echo -e "${RED}Invalid date format. Use YYYY-MM-DD${RESET}"
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
    
    # Install stunnel if not present
    if ! command -v stunnel4 &>/dev/null; then
        echo -e "${YELLOW}Installing stunnel4...${RESET}"
        apt-get update -y >/dev/null 2>&1
        apt-get install -y stunnel4 >/dev/null 2>&1 || { 
            echo -e "${RED}Failed to install stunnel4${RESET}"; 
            return; 
        }
        sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null
    fi
    
    # Generate certificate if needed
    if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
        echo -e "${YELLOW}Generating SSL certificate...${RESET}"
        openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
            -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
            -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem >/dev/null 2>&1
        cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
        chmod 600 /etc/stunnel/stunnel.pem
    fi
    
    # Create stunnel configuration
    cat > /etc/stunnel/stunnel.conf <<EOC
sslVersion = TLSv1.3
ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_COMPRESSION
options = NO_TICKET

[ssh-tunnel]
accept = ${port}
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
    
    # Start and enable stunnel
    systemctl enable stunnel4 >/dev/null 2>&1
    systemctl restart stunnel4 >/dev/null 2>&1
    
    if systemctl is-active --quiet stunnel4; then
        echo -e "\n${GREEN}✓ SSH-SSL tunnel configured successfully${RESET}"
        echo -e "${WHITE}SSL Port:${RESET} ${GREEN}$port${RESET}"
        echo -e "${WHITE}Target:${RESET} ${GREEN}127.0.0.1:22${RESET}"
        echo -e "${WHITE}Protocol:${RESET} ${GREEN}TLS 1.3${RESET}"
    else
        echo -e "\n${RED}✗ Failed to start stunnel service${RESET}"
    fi
}

# Show online users with real-time monitoring
show_online_users() {
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
        echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${RESET}"
        
        echo -e "\n${WHITE}🟢 Online  🔴 Offline  ⏰ Expired${RESET}"
        echo -e "${YELLOW}Press CTRL+C to return to main menu${RESET}"
        
        sleep 3
    done
}

# Print main menu
print_menu() {
    clear
    display_header_with_timestamp "MAIN MENU"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE}           MAIN MENU OPTIONS            ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}\n"
    
    echo -e "${WHITE}1)${RESET} ${GREEN}Create User${RESET}          - Add SSH users with limits"
    echo -e "${WHITE}2)${RESET} ${RED}Delete User${RESET}          - Remove users + cleanup"
    echo -e "${WHITE}3)${RESET} ${YELLOW}Limit User${RESET}           - Set connection limits"
    echo -e "${WHITE}4)${RESET} ${BLUE}Connection Mode${RESET}      - Configure SSH-SSL tunnel"
    echo -e "${WHITE}5)${RESET} ${GREEN}Online Users${RESET}         - Real-time monitoring"
    echo -e "${WHITE}6)${RESET} ${RED}Uninstall${RESET}           - Complete removal"
    
    echo -e "\n${BLUE}┌────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${WHITE} Select option [1-6] or CTRL+C to exit ${BLUE}│${RESET}"
    echo -e "${BLUE}└────────────────────────────────────────┘${RESET}"
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

# Main program loop
main() {
    # Ensure running as root
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (use sudo)${RESET}"
        exit 1
    fi
    
    # Create required directories
    mkdir -p "$(dirname "$USER_LIST_FILE")" "$PASSWORD_DIR"
    
    # Main menu loop
    while true; do
        print_menu
        read choice
        echo
        
        case "$choice" in
            1) create_user ;;
            2) delete_user ;;
            3) limit_user ;;
            4) configure_tunnel ;;
            5) show_online_users ;;
            6) uninstall_script ;;
            *) echo -e "${RED}Invalid option. Please select 1-6.${RESET}" ;;
        esac
        
        [[ "$choice" != "6" ]] && {
            echo -e "\n${WHITE}Press any key to return to main menu...${RESET}"
            read -n1 -s -r
        }
    done
}

# Handle CTRL+C gracefully
trap 'echo -e "\n${YELLOW}Returning to main menu...${RESET}"; sleep 1' INT

# Start the program
main "$@"
