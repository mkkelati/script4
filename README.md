# MK Script Manager v4.0 🚀

Advanced SSH user management system with comprehensive monitoring and SSL tunneling for Ubuntu 20.04–24.04.

## ✨ Features

### 🔐 User Management
- **Create Users** - Advanced user creation with validation and expiration dates
- **Delete Users** - Comprehensive user removal with session management
- **User Limits** - Connection limit management with PAM integration

### 📊 Monitoring & Reports
- **Online Users** - Real-time user monitoring (SSH, Dropbear, OpenVPN)
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
1) Create User          - Add SSH users with limits
2) Delete User          - Remove users + cleanup
3) Limit User           - Set connection limits
4) Connection Mode      - Configure SSH-SSL tunnel
5) Online Users         - Real-time monitoring
6) Uninstall           - Complete removal
```

## 🔐 Key Features
- **TLS 1.3** with ChaCha20-Poly1305 encryption
- **Multi-protocol support**: SSH (22), SSL (443)
- **Connection limiting** via PAM
- **Real-time monitoring** with auto-refresh every 3 seconds
- **Professional UI** with boxed interfaces and status icons
- **Safe arithmetic operations** with error handling

## 📊 File Structure
```
/etc/mk-script/users.txt        # User database
/etc/mk-script/senha/           # Password storage
/etc/VPSManager/Exp             # Expiration dates
/etc/stunnel/stunnel.conf       # TLS configuration
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