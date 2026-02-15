# 🚀 HuntexHPN-SSH-Tunnel

> **High-Performance HPN-SSH Installer & Service Manager**

A robust, repeatable, production-safe installer for **HPN-SSH**  
running alongside your system OpenSSH without touching port **22**.

---

## ✨ Features

✅ Clean side-by-side install with OpenSSH  
✅ Runs on dedicated port (default: **2222**)  
✅ Fully systemd managed  
✅ Auto-fixes common HPN/OpenSSH failures  
✅ Safe defaults (security-first)  
✅ Designed for unstable / high-latency networks  
✅ VPS / Dedicated Server friendly  

---

## ⚡ Usage 

### Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/DavoodHuntex/HuntexHPN-SSH-Tunnel/main/huntex-hpn-ssh-tunnel.sh -o huntex-hpn-ssh-tunnel.sh
chmod +x huntex-hpn-ssh-tunnel.sh
sudo ./huntex-hpn-ssh-tunnel.sh install
```

### ✅ Check Status

```bash
sudo ./huntex-hpn-ssh-tunnel.sh status
```

### 📜 View Logs
```bash
sudo ./huntex-hpn-ssh-tunnel.sh logs
```

### 🧹 Uninstall
```bash
sudo ./huntex-hpn-ssh-tunnel.sh uninstall
```

## 🛠 Default Configuration

| Setting | Value |
|----------|------------|
| **Port** | `2222` |
| **Service** | `hpnsshd` |
| **Install Path** | `/usr/local/hpnssh` |
| **Config Path** | `/etc/hpnssh` |

---

## 📂 Logs & Diagnostics

| Type | Location |
|------|------------|
| **Runtime Log** | `/var/log/hpnsshd.log` |
| **Build Logs** | `/root/hpn-logs/*` |
| **systemd** | `journalctl -u hpnsshd` |

---

## 🔐 Security Defaults (Recommended)

By default, HuntexHPN-SSH-Tunnel uses hardened settings:
**PermitRootLogin prohibit-password**
**PasswordAuthentication no**
**KbdInteractiveAuthentication no**

✔ Key-based authentication only  
✔ Safer production configuration  
✔ Reduced attack surface  

---

## 🔓 Enable Password Authentication (Optional)

If password login is required:

```bash
sudo PASSWORD_AUTH=yes PERMIT_ROOT_LOGIN=yes ./huntex-hpn-ssh-tunnel.sh install
```

**⚠ Security Warning:**
This weakens SSH security.

## 🎛 Environment Overrides
You may override defaults during installation:
```
PORT=2222 \
SERVICE=hpnsshd \
PREFIX=/usr/local/hpnssh \
SYSCONFDIR=/etc/hpnssh \
MAKE_JOBS=1 \
sudo ./huntex-hpn-ssh-tunnel.sh install
```


## 🌍 Connectivity Test
Test your HPN-SSH instance:

ssh -p 2222 root@YOUR_SERVER_IP

## ⚡ Performance Notes
HPN-SSH is optimized for:
**✔ High latency links**
**✔ Packet-loss networks**
**✔ Long-distance tunnels**
**✔ Bulk data transfers**
Significant throughput improvements may be observed on unstable routes.

## 🔗 Upstream Project
HPN-SSH:
https://github.com/rapier1/hpn-ssh
