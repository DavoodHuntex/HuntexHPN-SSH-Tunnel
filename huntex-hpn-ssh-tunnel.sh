#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# HUNTEX HPN-SSHD (NO-PAM / NO-CHALLENGE) - Ubuntu systemd
# - Installs HPN-SSH to /usr/local/hpnssh
# - Runs separate hpnsshd on PORT (default 2222)
# - Disables PAM + keyboard-interactive/challenge safely
# ============================================================

PORT="${PORT:-2222}"
SERVICE="${SERVICE:-hpnsshd}"
PREFIX="${PREFIX:-/usr/local/hpnssh}"
SYSCONFDIR="${SYSCONFDIR:-/etc/hpnssh}"
WORKDIR="${WORKDIR:-/root/hpn-build}"
HPN_REPO="${HPN_REPO:-https://github.com/rapier1/hpn-ssh.git}"
MAKE_JOBS="${MAKE_JOBS:-1}"

# Keep password auth ON (but NO PAM/challenge)
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"

# Reliability defaults
USE_DNS="${USE_DNS:-no}"
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-180}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-10}"
LOG_LEVEL="${LOG_LEVEL:-VERBOSE}"

# Crypto (safe + includes HPN mt if client supports)
CIPHERS="${CIPHERS:-chacha20-poly1305-mt@hpnssh.org,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr}"

RUNTIMELOG="/var/log/${SERVICE}.log"

die(){ echo "[FATAL] $*" >&2; exit 1; }
log(){ echo "[*] $*"; }
ok(){  echo "[+] $*"; }
warn(){ echo "[!] $*"; }

need_root(){ [[ $EUID -eq 0 ]] || die "Run as root."; }
has(){ command -v "$1" >/dev/null 2>&1; }

ensure_deps(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends \
    ca-certificates git curl \
    build-essential autoconf automake libtool pkg-config \
    zlib1g-dev libssl-dev libedit-dev \
    libpam0g-dev libselinux1-dev libkrb5-dev \
    >/dev/null
}

clone_build_install(){
  rm -rf "$WORKDIR/hpn-ssh" >/dev/null 2>&1 || true
  mkdir -p "$WORKDIR"
  git clone --depth 1 "$HPN_REPO" "$WORKDIR/hpn-ssh" >/dev/null
  cd "$WORKDIR/hpn-ssh"
  autoreconf -fi >/dev/null
  ./configure --prefix="$PREFIX" --sysconfdir="$SYSCONFDIR" >/dev/null
  make -j"$MAKE_JOBS" >/dev/null
  make install >/dev/null
}

locate_hpnsshd(){
  local b="$PREFIX/sbin/hpnsshd"
  [[ -x "$b" ]] && { echo "$b"; return; }
  b="$(find "$PREFIX" -type f -name hpnsshd -perm -111 2>/dev/null | head -n 1 || true)"
  [[ -x "$b" ]] || die "hpnsshd not found under $PREFIX"
  echo "$b"
}

ensure_privsep(){
  if ! id -u hpnsshd >/dev/null 2>&1; then
    useradd --system --home /var/empty --shell /usr/sbin/nologin --comment 'HPN-SSH PrivSep' hpnsshd
  fi
  mkdir -p /var/empty
  chown root:root /var/empty
  chmod 755 /var/empty
}

ensure_hostkeys(){
  mkdir -p "$SYSCONFDIR"
  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    ssh-keygen -t ed25519 -f "$SYSCONFDIR/ssh_host_ed25519_key" -N "" >/dev/null
  fi
  if [[ ! -f "$SYSCONFDIR/ssh_host_rsa_key" ]]; then
    ssh-keygen -t rsa -b 4096 -f "$SYSCONFDIR/ssh_host_rsa_key" -N "" >/dev/null
  fi
  chmod 700 "$SYSCONFDIR"
  chmod 600 "$SYSCONFDIR"/ssh_host_*_key 2>/dev/null || true
  chmod 644 "$SYSCONFDIR"/ssh_host_*_key.pub 2>/dev/null || true
}

detect_sftp(){
  for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [[ -x "$p" ]] && { echo "$p"; return; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

# Check if daemon accepts an option (avoid "Bad configuration option")
supports_opt(){
  local bin="$1" opt="$2"
  local tmp hk
  tmp="$(mktemp)"
  hk="$SYSCONFDIR/ssh_host_ed25519_key"
  cat >"$tmp" <<EOF
Port 0
ListenAddress 127.0.0.1
HostKey $hk
$opt
EOF
  "$bin" -t -f "$tmp" >/dev/null 2>&1
  local rc=$?
  rm -f "$tmp"
  return $rc
}

write_config(){
  local bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local sftp; sftp="$(detect_sftp)"

  # We WANT to disable PAM/challenge, but only if option exists.
  local USEPAM_LINE=""
  local KBD_LINE=""
  local CHAL_LINE=""

  if supports_opt "$bin" "UsePAM no"; then
    USEPAM_LINE="UsePAM no"
  fi
  if supports_opt "$bin" "KbdInteractiveAuthentication no"; then
    KBD_LINE="KbdInteractiveAuthentication no"
  fi
  if supports_opt "$bin" "ChallengeResponseAuthentication no"; then
    CHAL_LINE="ChallengeResponseAuthentication no"
  fi

  cat >"$cfg" <<EOF
# HPN SSHD (separate instance) - NO PAM / NO CHALLENGE
Port $PORT
ListenAddress 0.0.0.0
ListenAddress ::

PidFile /run/$SERVICE/$SERVICE.pid

HostKey $SYSCONFDIR/ssh_host_ed25519_key
HostKey $SYSCONFDIR/ssh_host_rsa_key

PermitRootLogin $PERMIT_ROOT_LOGIN
PasswordAuthentication $PASSWORD_AUTH
PubkeyAuthentication yes

$USEPAM_LINE
$KBD_LINE
$CHAL_LINE

AuthorizedKeysFile .ssh/authorized_keys
PrintMotd no
PrintLastLog no

UseDNS $USE_DNS
LoginGraceTime $LOGIN_GRACE_TIME
MaxAuthTries $MAX_AUTH_TRIES
LogLevel $LOG_LEVEL

Ciphers $CIPHERS

AllowTcpForwarding yes
GatewayPorts yes

TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

Compression no
Subsystem sftp $sftp
EOF

  ok "Config -> $cfg"
}

write_unit(){
  local bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/$SERVICE.service"

  cat >"$unit" <<EOF
[Unit]
Description=HPN-SSHD (no PAM/challenge) on port $PORT
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
RuntimeDirectory=$SERVICE
RuntimeDirectoryMode=0755

ExecStartPre=$bin -t -f $cfg
ExecStart=$bin -D -f $cfg -E $RUNTIMELOG
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "Unit -> $unit"
}

start_service(){
  systemctl stop "$SERVICE.service" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE.service" >/dev/null 2>&1 || true
  systemctl reset-failed "$SERVICE.service" >/dev/null 2>&1 || true

  systemctl enable --now "$SERVICE.service"

  ok "Listening:"
  ss -lntp | grep -E ":(22|$PORT)\b" || true
  ok "Status:"
  systemctl --no-pager --full status "$SERVICE.service" | sed -n '1,35p' || true
}

cmd_install(){
  has systemctl || die "systemd required."
  ensure_deps
  clone_build_install
  ensure_privsep
  ensure_hostkeys
  local bin; bin="$(locate_hpnsshd)"
  write_config "$bin"
  write_unit "$bin"
  start_service
  echo
  ok "Test:"
  echo "ssh -p $PORT root@YOUR_SERVER_IP"
  echo "Logs: journalctl -u $SERVICE -f  |  tail -f $RUNTIMELOG"
}

cmd_status(){
  ss -lntp | grep -E ":(22|$PORT)\b" || true
  systemctl --no-pager --full status "$SERVICE.service" || true
}

cmd_logs(){
  journalctl -u "$SERVICE.service" --no-pager -n 200 || true
  echo
  tail -n 200 "$RUNTIMELOG" 2>/dev/null || true
}

cmd_uninstall(){
  systemctl stop "$SERVICE.service" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$SERVICE.service" || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$SERVICE.service" >/dev/null 2>&1 || true
  rm -rf "$SYSCONFDIR" "$PREFIX" "$WORKDIR/hpn-ssh" 2>/dev/null || true
  rm -f "$RUNTIMELOG" 2>/dev/null || true
  ok "Uninstalled (user hpnsshd kept)."
}

need_root
case "${1:-}" in
  install)   cmd_install ;;
  status)    cmd_status ;;
  logs)      cmd_logs ;;
  uninstall) cmd_uninstall ;;
  *) echo "Usage: $0 install|status|logs|uninstall"; exit 1 ;;
esac
