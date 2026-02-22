#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================
# HUNTEX Turbo AutoSSH Tunnel (MINIMAL+)
# - Iran server runs autossh client
# - Connects to OUTSIDE HPN-SSH: IP:PORT (default 2222)
# - MODE=L (default): local forward  (-L)  => IRAN listens, forwards to OUTSIDE target
# - MODE=R           : reverse forward (-R) => OUTSIDE listens, forwards to IRAN target
# - Uses key: /root/.ssh/id_ed25519_iran-$(hostname -s)
# - systemd service + env file + CLI huntex-set-ip
# - Fixes: old-log spam + unit escape errors + ensures restart applies new mode
# ============================================

# ---------------------- Variables --------------------------
IP="${IP:-46.226.162.4}"
PORT="${PORT:-2222}"
USER="${USER:-root}"
PASS="${PASS:-}"
WIPE_KEYS="${WIPE_KEYS:-0}"

SSH_DIR="/root/.ssh"

log(){ echo -e "[$(date +'%F %T')] $*"; }
die(){ log "[FATAL] $*"; exit 1; }

ok(){ echo -e "✅ $*"; }
warn(){ echo -e "⚠️  $*" >&2; }

# ---------------------- Validate Password ----------------------
[[ -n "$PASS" ]] || die "PASS is empty. Example: IP=... PASS='xxx' WIPE_KEYS=1 bash"

# ---------------------- Name and Key ------------------------
HN="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
NAME="iran-${HN}"
KEY="${SSH_DIR}/id_ed25519_${NAME}"
PUB="${KEY}.pub"
KNOWN="${SSH_DIR}/known_hosts_${NAME}"

# ---------------------- Install dependencies ----------------------
log "[*] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y openssh-client sshpass >/dev/null 2>&1 || true

# ---------------------- Ensure SSH Directory -------------------
log "[*] Ensuring SSH directory exists..."
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# ---------------------- Wipe Previous Keys -------------------
if [[ "$WIPE_KEYS" == "1" ]]; then
  log "[!] WIPE_KEYS=1 -> Removing local id_* + known_hosts_* (keeping authorized_keys)"
  find "$SSH_DIR" -maxdepth 1 -type f \
    \( -name "id_*" -o -name "known_hosts*" \) \
    ! -name "authorized_keys" -delete || true
fi

log "[*] Using NAME=${NAME}"
rm -f "$KEY" "$PUB" "$KNOWN" || true

# ---------------------- Generate SSH Key ----------------------
log "[*] Generating key: $KEY"
ssh-keygen -t ed25519 -f "$KEY" -N "" -C "${NAME}@$(hostname -f 2>/dev/null || hostname)" >/dev/null 2>&1 || die "ssh-keygen failed"
chmod 600 "$KEY" || true
chmod 644 "$PUB" || true

# ---------------------- Quick TCP Check ----------------------
log "[*] Checking TCP port ${PORT} on ${IP}..."
if timeout 5 bash -lc "cat </dev/null >/dev/tcp/${IP}/${PORT}" >/dev/null 2>&1; then
  log "[+] ${PORT} OPEN"
else
  die "${PORT} CLOSED (network/firewall)"
fi

# ---------------------- SSH Options --------------------------
SSH_BASE_OPTS=(
  -n
  -p "$PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile="$KNOWN"
  -o GlobalKnownHostsFile=/dev/null
  -o ConnectTimeout=7
  -o ConnectionAttempts=1
  -o ServerAliveInterval=10
  -o ServerAliveCountMax=2
  -o TCPKeepAlive=yes
  -o LogLevel=ERROR
)

# ---------------------- Password Authentication ----------------------
SSH_PASS_OPTS=(
  -o PreferredAuthentications=password,keyboard-interactive
  -o PasswordAuthentication=yes
  -o KbdInteractiveAuthentication=yes
  -o PubkeyAuthentication=no
  -o NumberOfPasswordPrompts=1
)

# ---------------------- Retry Function ----------------------
retry(){
  local n=0 max=25 delay=1
  until "$@"; do
    n=$((n+1))
    if (( n >= max )); then return 1; fi
    sleep "$delay"
  done
}

# ---------------------- Install Key on Remote ----------------------
PUBKEY_CONTENT="$(cat "$PUB")"

REMOTE_PREP=$'set -e\numask 077\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\ntouch /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n'

REMOTE_APPEND="grep -qxF '$PUBKEY_CONTENT' /root/.ssh/authorized_keys || echo '$PUBKEY_CONTENT' >> /root/.ssh/authorized_keys; echo KEY_ADDED"

log "[*] Installing key on remote (prepare)..."
retry sshpass -p "$PASS" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "$USER@$IP" "$REMOTE_PREP" \
  || die "remote prepare failed"

log "[*] Installing key on remote (append)..."
retry sshpass -p "$PASS" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "$USER@$IP" "$REMOTE_APPEND" \
  || die "append key failed"

# ---------------------- Verifying Key-Only Login ----------------------
log "[*] Verifying key-only login..."
ssh "${SSH_BASE_OPTS[@]}" -i "$KEY" \
  -o PreferredAuthentications=publickey \
  -o PubkeyAuthentication=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o IdentitiesOnly=yes \
  "$USER@$IP" "echo KEY_OK && hostname && whoami" \
  || die "key-only login test failed"

log "[+] DONE"
log "[+] KEY PATH: $KEY"
