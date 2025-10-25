#!/bin/bash

# Cloud Run SSL/TLS Relay Management - Connection Mode Integration
# To be added as option 2 inside Connection Mode menu

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration files
RELAY_CONFIG="/etc/mk-script/cloudrun-relay.conf"
STUNNEL_RELAY_CONFIG="/etc/stunnel/cloudrun-relay.conf"
RELAY_CERT="/etc/stunnel/cloudrun-relay.pem"
DEFAULT_CLOUDRUN_URL="ssh-ssl-proxy-139069204417.us-central1.run.app"

# Function to check if relay is installed
is_relay_installed() {
    [ -f "$STUNNEL_RELAY_CONFIG" ] && [ -f "$RELAY_CERT" ]
}

# Function to check if relay is running
is_relay_running() {
    systemctl is-active --quiet cloudrun-relay 2>/dev/null
}

# Function to install/setup relay
setup_cloudrun_relay() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}    ${PURPLE}CLOUD RUN RELAY - SETUP & CONFIGURATION${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if is_relay_installed; then
        # Already installed - show management options
        source "$RELAY_CONFIG" 2>/dev/null
        
        echo -e "${BLUE}Status:${NC} $(is_relay_running && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}⏹️  Stopped${NC}")"
        echo -e "${BLUE}Port:${NC}   ${YELLOW}${RELAY_PORT}${NC}"
        echo -e "${BLUE}Cloud Run:${NC} ${YELLOW}${CLOUDRUN_URL}${NC}"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${GREEN}1)${NC} Start Relay"
        echo -e "${GREEN}2)${NC} Stop Relay"
        echo -e "${GREEN}3)${NC} Restart Relay"
        echo -e "${GREEN}4)${NC} View Status & Logs"
        echo -e "${GREEN}5)${NC} Edit Configuration"
        echo -e "${GREEN}6)${NC} Uninstall Relay"
        echo -e "${GREEN}7)${NC} Show HTTP Injector Config"
        echo -e "${RED}0)${NC} Back"
        echo ""
        read -p "Select option: " relay_option
        
        case $relay_option in
            1)
                echo -e "${BLUE}Starting relay...${NC}"
                systemctl start cloudrun-relay
                sleep 2
                is_relay_running && echo -e "${GREEN}✅ Started${NC}" || echo -e "${RED}❌ Failed${NC}"
                sleep 2
                ;;
            2)
                echo -e "${YELLOW}Stopping relay...${NC}"
                systemctl stop cloudrun-relay
                sleep 2
                echo -e "${GREEN}✅ Stopped${NC}"
                sleep 2
                ;;
            3)
                echo -e "${BLUE}Restarting relay...${NC}"
                systemctl restart cloudrun-relay
                sleep 2
                is_relay_running && echo -e "${GREEN}✅ Restarted${NC}" || echo -e "${RED}❌ Failed${NC}"
                sleep 2
                ;;
            4)
                clear
                echo -e "${CYAN}╔═════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}     ${PURPLE}CLOUD RUN RELAY - STATUS${NC}              ${CYAN}║${NC}"
                echo -e "${CYAN}╚═════════════════════════════════════════════════╝${NC}"
                echo ""
                systemctl status cloudrun-relay --no-pager | head -n 15
                echo ""
                echo -e "${BLUE}Recent Logs:${NC}"
                tail -n 10 /var/log/stunnel4/cloudrun-relay.log 2>/dev/null || journalctl -u cloudrun-relay -n 10 --no-pager
                echo ""
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                echo -e "${YELLOW}Current: ${CLOUDRUN_URL}:${RELAY_PORT}${NC}"
                read -p "New Cloud Run URL (Enter to keep): " new_url
                read -p "New Port (Enter to keep): " new_port
                new_url=${new_url:-$CLOUDRUN_URL}
                new_port=${new_port:-$RELAY_PORT}
                
                cat > "$RELAY_CONFIG" << EOF
CLOUDRUN_URL="$new_url"
RELAY_PORT="$new_port"
INSTALL_DATE="$(date)"
EOF
                sed -i "s|accept = .*|accept = 0.0.0.0:${new_port}|g" "$STUNNEL_RELAY_CONFIG"
                sed -i "s|connect = .*|connect = ${new_url}:443|g" "$STUNNEL_RELAY_CONFIG"
                
                systemctl restart cloudrun-relay
                echo -e "${GREEN}✅ Updated and restarted${NC}"
                sleep 2
                ;;
            6)
                echo ""
                read -p "Uninstall relay? (y/n): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    systemctl stop cloudrun-relay 2>/dev/null
                    systemctl disable cloudrun-relay 2>/dev/null
                    rm -f "$STUNNEL_RELAY_CONFIG" "$RELAY_CERT" "$RELAY_CONFIG"
                    rm -f /etc/systemd/system/cloudrun-relay.service
                    systemctl daemon-reload
                    echo -e "${GREEN}✅ Uninstalled${NC}"
                    sleep 2
                fi
                ;;
            7)
                clear
                SERVER_IP=$(curl -s ifconfig.me)
                echo -e "${CYAN}╔═════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}   ${PURPLE}HTTP INJECTOR CONFIGURATION${NC}            ${CYAN}║${NC}"
                echo -e "${CYAN}╚═════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${GREEN}SSH Settings:${NC}"
                echo -e "  Host:     ${YELLOW}(leave empty)${NC}"
                echo -e "  Port:     ${YELLOW}(leave empty)${NC}"
                echo -e "  Username: ${YELLOW}[your_ssh_username]${NC}"
                echo -e "  Password: ${YELLOW}[your_ssh_password]${NC}"
                echo ""
                echo -e "${GREEN}SSL/TLS Settings:${NC}"
                echo -e "  ☑ Enable SSL/TLS"
                echo -e "  Host: ${YELLOW}${SERVER_IP}${NC}"
                echo -e "  Port: ${YELLOW}${RELAY_PORT}${NC}"
                echo ""
                echo -e "${GREEN}SNI Settings:${NC}"
                echo -e "  ☑ Enable SNI"
                echo -e "  Host: ${YELLOW}google.com${NC}"
                echo ""
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${BLUE}Architecture:${NC}"
                echo -e "  [Phone] → [This:${RELAY_PORT}] → [Cloud Run] → [SSH]"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                read -p "Press Enter to continue..."
                ;;
            0)
                return
                ;;
        esac
        
    else
        # Not installed - install it
        echo -e "${YELLOW}Cloud Run Relay is not installed.${NC}"
        echo ""
        echo -e "${BLUE}This relay allows HTTP Injector to connect via Cloud Run${NC}"
        echo -e "${BLUE}by forwarding SSL/TLS connections to HTTPS.${NC}"
        echo ""
        read -p "Install Cloud Run Relay? (y/n): " install_confirm
        
        if [[ ! "$install_confirm" =~ ^[Yy]$ ]]; then
            return
        fi
        
        echo ""
        echo -e "${BLUE}Installing...${NC}"
        
        # Install stunnel if not present
        if ! command -v stunnel4 &> /dev/null; then
            echo -e "${YELLOW}Installing stunnel4...${NC}"
            apt-get update -qq
            apt-get install -y stunnel4 > /dev/null 2>&1
        fi
        
        mkdir -p /etc/mk-script
        
        # Get Cloud Run URL
        echo ""
        read -p "Cloud Run URL (Enter for default): " cloudrun_url
        cloudrun_url=${cloudrun_url:-$DEFAULT_CLOUDRUN_URL}
        
        read -p "Relay Port (Enter for 8443): " relay_port
        relay_port=${relay_port:-8443}
        
        # Save config
        cat > "$RELAY_CONFIG" << EOF
CLOUDRUN_URL="$cloudrun_url"
RELAY_PORT="$relay_port"
INSTALL_DATE="$(date)"
EOF
        
        # Generate certificate
        echo -e "${BLUE}Generating SSL certificate...${NC}"
        openssl req -x509 -newkey rsa:4096 \
            -keyout /tmp/relay-key.pem \
            -out /tmp/relay-cert.pem \
            -days 3650 -nodes \
            -subj "/C=US/ST=State/L=City/O=MKScript/CN=relay" \
            > /dev/null 2>&1
        
        cat /tmp/relay-key.pem /tmp/relay-cert.pem > "$RELAY_CERT"
        chmod 600 "$RELAY_CERT"
        rm -f /tmp/relay-key.pem /tmp/relay-cert.pem
        
        # Create stunnel config
        cat > "$STUNNEL_RELAY_CONFIG" << EOF
foreground = no
output = /var/log/stunnel4/cloudrun-relay.log
pid = /var/run/stunnel4/cloudrun-relay.pid

[cloudrun-relay]
client = no
accept = 0.0.0.0:${relay_port}
cert = ${RELAY_CERT}
connect = ${cloudrun_url}:443
TIMEOUTclose = 0
TIMEOUTidle = 3600
options = NO_SSLv2
options = NO_SSLv3
ciphers = HIGH:!aNULL:!MD5
debug = 5
EOF
        
        # Create systemd service
        cat > /etc/systemd/system/cloudrun-relay.service << EOF
[Unit]
Description=Cloud Run SSL/TLS Relay
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/stunnel4 ${STUNNEL_RELAY_CONFIG}
PIDFile=/var/run/stunnel4/cloudrun-relay.pid
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        
        # Start service
        systemctl daemon-reload
        systemctl enable cloudrun-relay > /dev/null 2>&1
        systemctl start cloudrun-relay
        
        sleep 2
        
        if is_relay_running; then
            clear
            SERVER_IP=$(curl -s ifconfig.me)
            echo -e "${CYAN}╔═════════════════════════════════════════════════╗${NC}"
            echo -e "${CYAN}║${NC}       ${GREEN}✅ RELAY INSTALLED!${NC}                ${CYAN}║${NC}"
            echo -e "${CYAN}╚═════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "${BLUE}HTTP Injector Configuration:${NC}"
            echo -e "  SSL Host: ${GREEN}${SERVER_IP}${NC}"
            echo -e "  SSL Port: ${GREEN}${relay_port}${NC}"
            echo -e "  SNI:      ${GREEN}google.com${NC}"
            echo ""
            echo -e "${YELLOW}Access from Connection Mode menu (option 4.2)${NC}"
        else
            echo -e "${RED}❌ Installation failed${NC}"
            echo -e "${YELLOW}Check: journalctl -u cloudrun-relay -n 20${NC}"
        fi
        
        echo ""
        read -p "Press Enter to continue..."
    fi
}

# Run the function
setup_cloudrun_relay

