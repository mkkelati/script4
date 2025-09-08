#!/bin/bash
# MK Script Manager - Main Menu (run as root)

USER_LIST_FILE="/etc/mk-script/users.txt"
[[ -f "$USER_LIST_FILE" ]] || { echo "User list missing at $USER_LIST_FILE"; exit 1; }

print_menu() {
  clear
  echo "========================================"
  echo "   MK Script Manager - Main Menu"
  echo "========================================"
  echo "1) Create User"
  echo "2) Delete User"
  echo "3) Limit User"
  echo "4) Connection Mode (SSH-SSL Tunnel)"
  echo "5) Online Users"
  echo "6) User Limiter"
  echo "7) Uninstall"
  echo "========================================"
  echo -n "Select an option [1-7]: "
}

generate_password(){ < /dev/urandom tr -dc 'A-Za-z0-9' | head -c8; }
list_users(){ nl -w2 -s ') ' "$USER_LIST_FILE"; }

create_user() {
  echo ">> Create New User <<"
  read -p "Enter new username: " username
  [[ -z "$username" ]] && { echo "Username cannot be empty."; return; }
  if id "$username" &>/dev/null; then echo "User exists. Choose another."; return; fi
  read -s -p "Enter password (blank = auto): " password; echo
  [[ -z "$password" ]] && { password=$(generate_password); echo "Generated password: $password"; }
  useradd -m -s /usr/sbin/nologin "$username" || { echo "Failed to create user."; return; }
  echo "${username}:${password}" | chpasswd
  echo "${username}:0" >> "$USER_LIST_FILE"
  if systemctl is-active --quiet stunnel4; then
    PORT=$(grep -m1 "^accept = " /etc/stunnel/stunnel.conf | awk '{print $3}')
    [[ -z "$PORT" ]] && PORT="443"
    echo "[+] '$username' created. Connection: SSH over SSL (stunnel) port $PORT."
  else
    echo "[+] '$username' created. Connection: Standard SSH port 22."
  fi
}

delete_user() {
  echo ">> Delete User <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to delete."; return; }
  list_users
  read -p "Enter the number to delete: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  userdel -r "$username" 2>/dev/null
  sed -i "${num}d" "$USER_LIST_FILE"
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  [[ -f "$LIMIT_FILE" ]] && sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE"
  echo "[*] Deleted '$username'."
}

limit_user() {
  echo ">> Limit User Connections <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users to limit."; return; }
  list_users
  read -p "Enter the number to set limit for: " num
  [[ "$num" =~ ^[0-9]+$ ]] || { echo "Invalid."; return; }
  username=$(sed -n "${num}p" "$USER_LIST_FILE" | cut -d: -f1)
  [[ -n "$username" ]] || { echo "Selection not found."; return; }
  read -p "Max simultaneous logins for '$username' (0 = unlimited): " limit
  [[ -z "$limit" || "$limit" -lt 0 ]] && limit=0
  awk -F: -v user="$username" -v newlimit="$limit" '{if($1==user){$2=newlimit} print $1 ":" $2}' "$USER_LIST_FILE" > "${USER_LIST_FILE}.tmp" && mv "${USER_LIST_FILE}.tmp" "$USER_LIST_FILE"
  LIMIT_FILE="/etc/security/limits.d/mk-script-limits.conf"
  mkdir -p /etc/security/limits.d
  sed -i "/^${username}[[:space:]]\+.*maxlogins/d" "$LIMIT_FILE" 2>/dev/null
  [[ "$limit" -gt 0 ]] && echo "${username}    -    maxlogins    $limit" >> "$LIMIT_FILE"
  echo "[*] '$username' limit set to $limit (0 = unlimited)."
}

configure_tunnel() {
  echo ">> Configure SSH-SSL Tunnel <<"
  read -p "Port for stunnel [default 443]: " port
  port=${port:-443}
  [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] || { echo "Invalid port."; return; }
  if ! command -v stunnel &>/dev/null; then
    apt-get update -y && apt-get install -y stunnel4 || { echo "stunnel install failed."; return; }
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
    echo "[*] Generating stunnel certificate..."
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
      -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
      -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
    cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
  fi
  cat > /etc/stunnel/stunnel.conf <<EOC
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
accept = ${port}
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
  systemctl enable stunnel4
  systemctl restart stunnel4
  echo "[*] SSH-SSL tunneling enabled on port $port."
}

show_online_users() {
  echo ">> Online Users <<"
  [[ -s "$USER_LIST_FILE" ]] || { echo "No users created yet."; return; }
  any=0
  while IFS=: read -r username limit; do
    if pgrep -u "$username" sshd >/dev/null 2>&1; then
      [[ "$any" -eq 0 ]] && { echo "Active SSH sessions:"; any=1; }
      echo " - $username"
    fi
  done < "$USER_LIST_FILE"
  [[ "$any" -eq 0 ]] && echo "No active SSH connections for managed users."
}

user_limiter_management() {
  # User Connection Limiter Configuration
  DATABASE="/root/usuarios.db"
  OPENVPN_STATUS="/etc/openvpn/openvpn-status.log"
  OPENVPN_MANAGEMENT_PORT="7505"
  CHECK_INTERVAL=15
  AUTOSTART_FILE="/etc/autostart"
  LIMITER_NAME="user_limiter"
  
  # Colors for display
  RED='\033[1;31m'
  GREEN='\033[1;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[1;36m'
  WHITE='\033[1;37m'
  RESET='\033[0m'
  
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
  
  # Function to get user connection limit from database
  get_user_limit() {
    local user="$1"
    if [[ -f "$DATABASE" ]] && grep -wq "$user" "$DATABASE"; then
      grep -w "$user" "$DATABASE" | cut -d' ' -f2
    else
      echo "1"  # Default limit
    fi
  }
  
  # Function to count SSH connections for a user
  count_ssh_connections() {
    local user="$1"
    ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
  }
  
  # Function to count OpenVPN connections for a user
  count_openvpn_connections() {
    local user="$1"
    if [[ -e "$OPENVPN_STATUS" ]]; then
      grep -E ",${user}," "$OPENVPN_STATUS" 2>/dev/null | wc -l || echo "0"
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
      local pids_to_kill=$(grep -E ",${user}," "$OPENVPN_STATUS" 2>/dev/null | cut -d',' -f3 | head -n $connections_to_kill)
      
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
  
  # Main limiter function
  enforce_limits() {
    local users_processed=0
    local violations_found=0
    
    # Get all system users (UID >= 1000, excluding nobody)
    while IFS= read -r user; do
      [[ -z "$user" ]] && continue
      
      local limit=$(get_user_limit "$user")
      local ssh_connections=$(count_ssh_connections "$user")
      local openvpn_connections=$(count_openvpn_connections "$user")
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
        echo 'Database: $DATABASE'
        echo 'Check Interval: ${CHECK_INTERVAL}s'
        echo 'OpenVPN Status: $OPENVPN_STATUS'
        echo '================================'
        
        while true; do
          $(declare -f enforce_limits get_user_limit count_ssh_connections count_openvpn_connections kill_excess_openvpn)
          enforce_limits
          sleep $CHECK_INTERVAL
        done
      "
      
      # Add to autostart if file exists
      if [[ -f "$AUTOSTART_FILE" ]]; then
        # Remove any existing limiter entries
        sed -i '/user_limiter/d' "$AUTOSTART_FILE" 2>/dev/null
        # Add new entry
        echo "ps x | grep '$LIMITER_NAME' | grep -v 'grep' && echo 'User Limiter: ON' || screen -dmS $LIMITER_NAME /usr/local/bin/menu user_limiter_daemon" >> "$AUTOSTART_FILE"
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
  check_status() {
    clear
    echo -e "${BLUE}◇ USER LIMITER STATUS${RESET}"
    echo -e "${BLUE}========================${RESET}"
    echo ""
    
    if screen -list | grep -q "$LIMITER_NAME"; then
      echo -e "Status: ${GREEN}RUNNING${RESET}"
      echo -e "Session: ${WHITE}$LIMITER_NAME${RESET}"
      echo -e "Database: ${WHITE}$DATABASE${RESET}"
      echo -e "Check Interval: ${WHITE}${CHECK_INTERVAL}s${RESET}"
      
      # Show current user connections
      echo ""
      echo -e "${YELLOW}Current User Connections:${RESET}"
      echo -e "${BLUE}=========================${RESET}"
      printf "%-15s %-8s %-8s %-8s %-8s\n" "User" "Limit" "SSH" "OpenVPN" "Total"
      echo "-------------------------------------------------------"
      
      while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        local limit=$(get_user_limit "$user")
        local ssh_count=$(count_ssh_connections "$user")
        local ovpn_count=$(count_openvpn_connections "$user")
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
  
  # Interactive menu for User Limiter
  while true; do
    clear
    echo -e "${BLUE}◇ USER LIMITER MANAGEMENT${RESET}"
    echo -e "${BLUE}==========================${RESET}"
    echo ""
    
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
    echo -e "${RED}[${BLUE}1${RED}] ${WHITE}• ${YELLOW}$action_text${RESET}"
    echo -e "${RED}[${BLUE}2${RED}] ${WHITE}• ${YELLOW}CHECK STATUS${RESET}"
    echo -e "${RED}[${BLUE}3${RED}] ${WHITE}• ${YELLOW}VIEW LOGS${RESET}"
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
        check_status
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

uninstall_script() {
  echo ">> Uninstall MK Script Manager <<"
  read -p "Are you sure? [y/N]: " c
  [[ "$c" =~ ^[Yy]$ ]] || { echo "Canceled."; return; }
  echo "[*] Removing stunnel..."
  systemctl stop stunnel4 2>/dev/null
  apt-get remove -y stunnel4 >/dev/null 2>&1
  rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem /etc/stunnel/key.pem /etc/stunnel/cert.pem
  rm -f /etc/default/stunnel4
  echo "[*] Removing users..."
  while IFS=: read -r username limit; do
    id "$username" &>/dev/null && userdel -r "$username"
  done < "$USER_LIST_FILE"
  echo "[*] Cleaning files..."
  rm -f /usr/local/bin/menu
  rm -rf /etc/mk-script
  rm -f /etc/security/limits.d/mk-script-limits.conf
  echo "[+] Uninstalled."
  exit 0
}

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
    6) user_limiter_management ;;
    7) uninstall_script ;;
    *) echo "Invalid option. Enter 1-7." ;;
  esac
  [[ "$choice" != "7" ]] && read -n1 -s -r -p "Press any key to return..." && echo
done
