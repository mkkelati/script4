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

### One-Line Installation
```bash
sudo apt-get update -y && sudo apt-get install -y wget && wget -O install.sh https://raw.githubusercontent.com/mkkelati/script4/master/install.sh && sudo bash install.sh
```

### Step-by-Step Installation
```bash
sudo apt-get update -y && sudo apt-get install -y wget
wget -O install.sh https://raw.githubusercontent.com/mkkelati/script4/master/install.sh
sudo bash install.sh
```

## 📋 Menu Options

After installation, run the menu system:
```bash
sudo menu
```

**Available Options:**
```
1) Create User          - Add new SSH users with advanced options
2) Delete User          - Remove users with session management
3) Limit User           - Set connection limits per user
4) Connection Mode      - Configure SSH-SSL tunneling
5) Online Users         - Monitor active connections
6) User Limiter         - Advanced connection monitoring & enforcement
7) Uninstall           - Complete system removal
```

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

## 🚫 Uninstall

Use menu option 7 to completely remove the system:
- Removes all managed users
- Cleans configuration files
- Stops and removes services
- Restores system to original state

---

© 2025 MK Script Manager - Advanced SSH Management System 🐉
