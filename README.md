# MK Script Manager v2.0 🐉

Advanced SSH user management system with comprehensive monitoring and SSL tunneling for Ubuntu 20.04–24.04.

## ✨ Features

### 🔐 User Management
- **Create Users** - Advanced user creation with validation and OpenVPN integration
- **Delete Users** - Comprehensive user removal with session management
- **Change Password** - Secure password management with dual storage
- **User Limits** - Connection limit management with PAM integration

### 📊 Monitoring & Reports
- **Online Users** - Real-time user monitoring (SSH, OpenVPN, Dropbear)
- **User Report** - Comprehensive user status with expiration tracking
- **Network Traffic** - Live network monitoring with nload integration

### 🛡️ Security & Connectivity
- **SSH-SSL Tunneling** - Secure stunnel configuration on port 443
- **Connection Limits** - Per-user simultaneous connection control
- **Password Validation** - Strong password requirements
- **Session Management** - Active session detection and control

### 🌐 OpenVPN Integration
- **Multiple Host Support** - Vivo, Oi, and custom carrier configurations
- **Auto Certificate Generation** - Seamless OpenVPN profile creation
- **Bulk Configuration** - Generate multiple OVPN files simultaneously
- **Web Download** - Direct download links for OVPN files

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
- **User Limiter** for connection monitoring
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
6) User Limiter         - Advanced connection monitoring & enforcement
7) Uninstall           - Complete removal
```

## 🔐 Key Features
- **TLS 1.3** with advanced encryption
- **Multi-protocol support**: SSH (22), SSL (443)
- **Connection limiting** via PAM
- **User Limiter** for real-time monitoring & enforcement
- **OpenVPN integration** (if available)
- **Real-time monitoring** of active sessions

## 📊 File Structure
```
/etc/mk-script/users.txt        # User database
/etc/mk-script/senha/           # Password storage  
/etc/stunnel/stunnel.conf       # TLS configuration
/usr/local/bin/menu             # Main script
```

## ⚙️ Technical Notes
- Uses **main branch** from `github.com/mkkelati/script4`
- **TLS encryption**: Advanced cipher suites
- **SSL tunnel**: Port 443 → SSH port 22
- **User limits**: Stored in `/etc/security/limits.d/`

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

## 🗂️ File Structure

```
/etc/mk-script/           # Main configuration
├── users.txt            # User database
└── senha/               # Password storage

/etc/VPSManager/          # Legacy compatibility
├── Exp                   # Expired users tracking
└── senha/               # Alternative password storage

/etc/security/limits.d/   # Connection limits
└── mk-script-limits.conf

/var/www/html/openvpn/    # OVPN downloads
```

## 📈 Statistics Tracking

The system tracks:
- Total registered users
- Currently online users
- Expired user accounts
- Connection types (SSH, OpenVPN, Dropbear)
- User activity and session duration

## 🔄 Updates & Support

- **Repository**: [https://github.com/mkkelati/script4](https://github.com/mkkelati/script4)
- **Issues**: Report bugs and feature requests
- **Releases**: Check for updates and new features

## 🔄 Uninstall
```bash
menu  # Select option 7
```

This removes all users, configurations, and services completely.

---

© 2025 MK Script Manager - Advanced SSH Management System 🐉
