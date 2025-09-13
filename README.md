# MK Script Manager v4.0 🚀

Advanced SSH user management system with comprehensive monitoring and SSL tunneling for Ubuntu 20.04–24.04.

## ✨ Features

### 🔐 User Management
- **Create Users** - Advanced user creation with validation and expiration dates
- **Delete Users** - Comprehensive user removal with session management
- **Change Password** - Secure password management with dual storage
- **User Limits** - Connection limit management with PAM integration

### 📊 Monitoring & Reports
- **Online Users** - Real-time user monitoring (SSH, Dropbear, OpenVPN)
- **Network Traffic** - Live network monitoring with nload integration
- **User Report** - Comprehensive user status with expiration tracking
- **User Limiter** - Advanced connection enforcement with automatic violation handling
- **Professional Interface** - Boxed displays with timestamps and status icons
- **Connection Statistics** - Live connection counting with auto-refresh

### 🛡️ Security & Connectivity
- **SSH-SSL Tunneling** - Secure stunnel configuration on port 443
- **TLS 1.3 Encryption** - Advanced cipher suites (ChaCha20-Poly1305)
- **Connection Limits** - Per-user simultaneous connection control
- **Session Management** - Active session detection and control

## 🚀 Quick Install

### ⚡ One-Line Installation
```bash
sudo apt-get update -y && sudo apt-get install -y wget && wget -O install.sh https://raw.githubusercontent.com/mkkelati/script4/main/install.sh && sudo bash install.sh
```

### 🎯 What Gets Installed
- **stunnel4** with TLS 1.3 encryption
- **SSH-SSL tunnel** on port 443
- **Menu system** at `/usr/local/bin/menu`
- **User management database** at `/etc/mk-script/users.txt`
- **Required directories** and permissions

### 🔧 Operation
After installation, run:
```bash
menu
```

## 📱 Menu Options
```
1)  Create User          - Add SSH users with limits
2)  Delete User          - Remove users + cleanup
3)  Limit User           - Set connection limits
4)  Connection Mode      - Configure SSH-SSL tunnel
5)  Online Users         - Real-time monitoring
6)  Network Traffic      - Live network stats
7)  User Report          - User status overview
8)  Change Password      - Update user passwords
9)  User Limiter         - Advanced connection enforcement
10) Server Optimization  - System performance tuning
11) Uninstall           - Complete removal
12) BadVPN Manager      - UDP Gateway for VoIP/OpenVPN
```

## 🔐 Key Features
- **TLS 1.3** with ChaCha20-Poly1305 encryption + **MAXIMUM PERFORMANCE** optimizations
- **Multi-protocol support**: SSH (22), SSL (443) with **128MB buffers**
- **Connection limiting** via PAM with **25 connections per user**
- **Real-time monitoring** with auto-refresh every 3 seconds
- **Advanced User Limiter** with automatic enforcement and violation logging  
- **BadVPN UDP Gateway** optimized for **4,000 users × 25 connections = 100,000 total**
- **TCP Performance Tuning**: BBR congestion control, 128MB network buffers
- **Professional UI** with boxed interfaces and status icons
- **Safe arithmetic operations** with error handling

## ⚡ BadVPN UDP Gateway Manager
The integrated BadVPN Manager provides UDP forwarding capabilities for improved connectivity:

### Features:
- **VoIP Quality Enhancement** - Reduces packet loss for voice calls
- **UDP Traffic Forwarding** - Essential for OpenVPN and other UDP applications
- **Port Management** - Easy port configuration with conflict detection
- **Performance Monitoring** - Real-time connection stats and resource usage
- **Auto-Installation** - Compiles latest BadVPN from source automatically
- **Screen Session Management** - Background process with log access
- **Autostart Integration** - Persistent across reboots

### Configuration:
- **Default Port**: 7300 (configurable)
- **Max Clients**: 4,000 (optimized for 2GB RAM)
- **Max Connections per Client**: 25 (maximum user capacity)
- **Socket Buffer**: 15,000 bytes (enhanced performance)
- **Total Capacity**: 100,000 concurrent connections

## 🛡️ Advanced User Limiter
The integrated User Limiter provides comprehensive connection monitoring and enforcement:

### Features:
- **Multi-protocol Monitoring**: SSH and OpenVPN connection tracking
- **Automatic Enforcement**: Kills excess connections when limits are exceeded
- **Background Operation**: Runs as screen session with configurable intervals
- **Violation Logging**: Detailed logs with timestamps for all violations
- **Database Management**: Separate database for limiter-specific user limits
- **Real-time Status**: Live connection monitoring with violation detection
- **Autostart Support**: Automatic startup on system boot

### User Limiter Database:
```
/root/usuarios.db        # Format: username limit
user1 2                  # Allows 2 simultaneous connections
user2 1                  # Allows 1 connection only
admin 5                  # Allows 5 connections
```

### Management Interface:
- **Start/Stop Service**: Toggle limiter with loading animations
- **Status Monitoring**: Real-time connection tracking display
- **Log Viewing**: Connect to live logs via screen session
- **Database Setup**: Interactive database management tools

## 📊 File Structure
```
/etc/mk-script/users.txt        # User database
/etc/mk-script/senha/           # Password storage
/etc/VPSManager/Exp             # Expiration dates
/etc/stunnel/stunnel.conf       # TLS configuration
/root/usuarios.db               # User Limiter database
/usr/local/bin/menu             # Main script
```

## ⚙️ Technical Notes
- Uses **main branch** from `github.com/mkkelati/script4`
- **TLS cipher**: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`
- **SSL tunnel**: Port 443 → SSH port 22
- **User limits**: Stored in `/etc/security/limits.d/`
- **Database format**: `username:connection_limit`

## 🔧 System Requirements

- **OS**: Ubuntu 20.04 - 24.04 LTS
- **RAM**: Minimum 512MB
- **Storage**: 100MB free space
- **Network**: Internet connection for installation
- **Permissions**: Root access required

## 📱 Mobile Integration

**For HTTP Injector:**
- Protocol: **Stunnel**
- Server Port: **443**
- SSL/TLS: **Enabled**

## 🎨 Professional Interface

### Real-Time Monitoring Display:
```
┌─────────────────────────────────────────────────────────────┐
│                    REAL-TIME CONNECTIONS                    │
├─────────────────────────────────────────────────────────────┤
│ USERNAME     │ SSH      │ DROPBEAR │ OPENVPN  │ TOTAL    │ STATUS │
├─────────────────────────────────────────────────────────────┤
│ user1        │ 2        │ 0        │ 1        │ 3        │ 🟢     │
│ user2        │ 0        │ 0        │ 0        │ 0        │ 🔴     │
├─────────────────────────────────────────────────────────────┤
│ Total Users Online: 1                                       │
└─────────────────────────────────────────────────────────────┘

🟢 Online  🔴 Offline  ⏰ Expired
```

## 🔧 Key Technical Concepts

### Proven Working Connection Detection:
```bash
# SSH Detection - Simple and reliable
get_ssh_connections() {
    local user="$1"
    if grep -q "^$user:" /etc/passwd 2>/dev/null; then
        ps -u "$user" 2>/dev/null | grep -c sshd || echo "0"
    else
        echo "0"
    fi
}
```

### Safe Arithmetic Operations:
```bash
safe_number() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "0"
    fi
}
```

### Real-Time Monitoring Loop:
```bash
# Auto-refresh every 3 seconds
while true; do
    clear
    display_header_with_timestamp
    monitor_all_users
    sleep 3
done
```

## 🔄 Updates & Support

- **Repository**: [https://github.com/mkkelati/script4](https://github.com/mkkelati/script4)
- **Issues**: Report bugs and feature requests
- **Releases**: Check for updates and new features

## 🔄 Uninstall
```bash
menu  # Select option 6
```

This removes all users, configurations, and services completely.

---

© 2025 MK Script Manager v4.0 - Advanced SSH Management System 🚀