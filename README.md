cat > README.md <<'EOF'
# HuntexHPN-SSH-Tunnel

A robust, repeatable installer for **HPN-SSH** (High Performance SSH) on Ubuntu using **systemd**.

✅ Builds from source  
✅ Installs into `/usr/local/hpnssh`  
✅ Runs a **separate** SSH daemon on port **2222** (default)  
✅ Keeps system `sshd` on port 22 untouched  
✅ Auto-fixes common failures (privsep user, /var/empty, systemd start-limit)

---

## Quick start

```bash
curl -fsSL <RAW_URL_TO_SCRIPT> -o huntex-hpn-ssh-tunnel.sh
chmod +x huntex-hpn-ssh-tunnel.sh
sudo ./huntex-hpn-ssh-tunnel.sh install
```
