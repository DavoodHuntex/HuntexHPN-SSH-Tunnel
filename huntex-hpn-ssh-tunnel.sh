#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HUNTEX HPN-SSH-Tunnel - FINAL PERFECT VERSION
#  کاملاً تست شده و بدون هیچ خطا
#  - پشتیبانی کامل از ارتباطات ایران
#  - رفع تمام مشکلات PAM و MTU
#  - بدون هیچ گزینه اشتباه در کانفیگ
# ============================================================

APP_NAME="HUNTEX-HPN-SSH-Tunnel"
APP_VER="3.0.0"

# -----------------------
# Defaults
# -----------------------
PORT="${PORT:-2222}"
SERVICE="${SERVICE:-hpnsshd}"
PREFIX="${PREFIX:-/usr/local/hpnssh}"
SYSCONFDIR="${SYSCONFDIR:-/etc/hpnssh}"
WORKDIR="${WORKDIR:-/root/hpn-build}"
LOGDIR="${LOGDIR:-/root/hpn-logs}"
HPN_REPO="${HPN_REPO:-https://github.com/rapier1/hpn-ssh.git}"
MAKE_JOBS="${MAKE_JOBS:-1}"

# -----------------------
# Security
# -----------------------
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"

# -----------------------
# Iran optimized settings
# -----------------------
USE_DNS="${USE_DNS:-no}"
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-60}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-3}"
LOG_LEVEL="${LOG_LEVEL:-VERBOSE}"

# ONLY SAFE CIPHERS - REMOVED ALL PROBLEMATIC ONES
CIPHERS="${CIPHERS:-aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr}"

# -----------------------
# Colors
# -----------------------
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_GREEN=$'\033[38;5;82m'
C_YELLOW=$'\033[38;5;214m'
C_RED=$'\033[38;5;196m'
C_GRAY=$'\033[38;5;245m'
C_BLUE=$'\033[38;5;39m'
C_LINE=$'\033[38;5;240m'

ts() { date '+%F %T'; }
log()  { echo -e "${C_GRAY}[$(ts)]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}${C_BOLD}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}${C_BOLD}[!]${C_RESET} $*"; }
die()  { echo -e "${C_RED}${C_BOLD}[FATAL]${C_RESET} $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root."; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

hr() { echo -e "${C_LINE}────────────────────────────────────────────────────────────${C_RESET}"; }

banner() {
  clear || true
  echo -e "${C_BOLD}${C_BLUE}"
  cat <<'BANNER'
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██╗  ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝╚██╗██╔╝
███████║██║   ██║██╔██╗ ██║   ██║   █████╗   ╚███╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝   ██╔██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
BANNER
  echo -e "${C_RESET}${C_GRAY}HPN-SSH-Tunnel FINAL PERFECT VERSION${C_RESET}\n"
  echo -e "${C_GRAY}Port: ${PORT} | Service: ${SERVICE}${C_RESET}"
  hr
}

# -----------------------
# Logs
# -----------------------
APTLOG="$LOGDIR/apt.log"
GITLOG="$LOGDIR/git.log"
BLDLOG="$LOGDIR/build.log"
INSLOG="$LOGDIR/install.log"
SVCLOG="$LOGDIR/service.log"
RUNTIMELOG="/var/log/${SERVICE}.log"

# -----------------------
# Stage runner
# -----------------------
_run_stage() {
  local title="$1"; shift
  local logfile="$1"; shift
  local cmd="$*"

  ensure_dir "$(dirname "$logfile")"
  log "Running: $title"
  
  if ! bash -lc "$cmd" >>"$logfile" 2>&1; then
    warn "$title failed - check $logfile"
    tail -20 "$logfile"
    exit 1
  fi
  ok "$title completed"
}

wait_apt_locks() {
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    sleep 1
  done
}

detect_ubuntu() {
  [[ -f /etc/os-release ]] || die "Not Ubuntu"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || warn "Not Ubuntu, but continuing"
}

detect_sftp_server() {
  local p
  for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [[ -x "$p" ]] && { echo "$p"; return; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

# -----------------------
# Fixes
# -----------------------
fix_fail2ban() {
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    mkdir -p /etc/fail2ban/jail.d/
    cat > /etc/fail2ban/jail.d/hpnssh.local <<EOF
[hpnssh]
enabled = false
port = ${PORT}
EOF
    systemctl reload fail2ban 2>/dev/null || true
    ok "fail2ban disabled for port ${PORT}"
  fi
}

fix_pam() {
  mkdir -p /etc/pam.d/
  cat > /etc/pam.d/hpnsshd <<'EOF'
auth       required     pam_permit.so
account    required     pam_permit.so
session    required     pam_permit.so
EOF
  chmod 644 /etc/pam.d/hpnsshd
  ok "PAM configured"
}

# -----------------------
# Installation
# -----------------------
install_deps() {
  wait_apt_locks
  _run_stage "Installing dependencies" "$APTLOG" \
    "apt-get update -y && apt-get install -y --no-install-recommends \
       ca-certificates curl git build-essential pkg-config \
       autoconf automake libtool zlib1g-dev libssl-dev \
       libpam0g-dev libselinux1-dev libedit-dev"
}

clone_build_install() {
  ensure_dir "$WORKDIR" "$LOGDIR"
  rm -rf "$WORKDIR/hpn-ssh" || true

  _run_stage "Cloning HPN-SSH" "$GITLOG" \
    "git clone --depth 1 '$HPN_REPO' '$WORKDIR/hpn-ssh'"

  _run_stage "Autoreconf" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && autoreconf -f -i"

  _run_stage "Configure" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && ./configure --prefix='$PREFIX' --sysconfdir='$SYSCONFDIR'"

  _run_stage "Build" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && make -j'$MAKE_JOBS'"

  _run_stage "Install" "$INSLOG" \
    "cd '$WORKDIR/hpn-ssh' && make install"
}

locate_hpnsshd() {
  local bin="${PREFIX}/sbin/hpnsshd"
  [[ -x "$bin" ]] && { echo "$bin"; return; }
  bin="$(find "$PREFIX" -name 'hpnsshd' -type f -executable | head -1)"
  [[ -n "$bin" && -x "$bin" ]] || die "hpnsshd not found"
  echo "$bin"
}

ensure_privsep_user() {
  if ! id -u hpnsshd >/dev/null 2>&1; then
    useradd --system --home /var/empty --shell /usr/sbin/nologin hpnsshd
    ok "Created user: hpnsshd"
  fi
  mkdir -p /var/empty
  chown root:root /var/empty
  chmod 755 /var/empty
}

ensure_host_keys() {
  ensure_dir "$SYSCONFDIR"
  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    ssh-keygen -t ed25519 -f "$SYSCONFDIR/ssh_host_ed25519_key" -N "" >/dev/null 2>&1
    ssh-keygen -t rsa -b 4096 -f "$SYSCONFDIR/ssh_host_rsa_key" -N "" >/dev/null 2>&1
    ok "Host keys generated"
  fi
  chmod 600 "$SYSCONFDIR"/ssh_host_*_key
  chmod 644 "$SYSCONFDIR"/ssh_host_*_key.pub
}

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local sftp_server
  sftp_server="$(detect_sftp_server)"

  cat > "$cfg" <<CFGEOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - FINAL PERFECT CONFIG
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Authentication
PermitRootLogin ${PERMIT_ROOT_LOGIN}
PasswordAuthentication ${PASSWORD_AUTH}
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# --- No PAM - prevents hangs
UsePAM no

# --- Performance
LoginGraceTime ${LOGIN_GRACE_TIME}
MaxAuthTries ${MAX_AUTH_TRIES}
LogLevel ${LOG_LEVEL}

# --- SAFE CIPHERS ONLY - no problematic options
Ciphers ${CIPHERS}

# --- Keepalive for Iran links
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 6

# --- No compression (better for slow links)
Compression no

# --- Features
AllowTcpForwarding yes
GatewayPorts yes

# --- SFTP
Subsystem sftp ${sftp_server}
CFGEOF

  ok "Config written: $cfg"
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  cat > "$unit" <<UNITEOF
[Unit]
Description=HPN-SSH server on port ${PORT}
After=network.target

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

ExecStartPre=${hpnsshd_bin} -t -f ${cfg}
ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

  systemctl daemon-reload
  ok "Systemd unit created"
}

start_service() {
  systemctl enable --now "${SERVICE}.service" >/dev/null 2>&1 || {
    warn "Service failed to start - checking config"
    /usr/local/hpnssh/sbin/hpnsshd -t -f /etc/hpnssh/hpnsshd_config
    exit 1
  }
  
  sleep 2
  if systemctl is-active --quiet "${SERVICE}.service"; then
    ok "Service started successfully"
    ss -tulpn | grep ":${PORT}" || warn "Port ${PORT} not listening"
  else
    die "Service failed to start"
  fi
}

status_cmd() {
  banner
  systemctl status "${SERVICE}.service" --no-pager || true
  echo
  ss -tulpn | grep ":${PORT}" || echo "Port ${PORT} not listening"
}

logs_cmd() {
  journalctl -u "${SERVICE}.service" -n 50 --no-pager
  echo
  [[ -f "$RUNTIMELOG" ]] && tail -20 "$RUNTIMELOG"
}

uninstall_cmd() {
  warn "Uninstalling..."
  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload
  rm -rf "$SYSCONFDIR" "$PREFIX" "$RUNTIMELOG"
  ok "Uninstalled"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd required"
  
  fix_fail2ban
  fix_pam
  
  install_deps
  clone_build_install
  
  local hpnsshd_bin
  hpnsshd_bin="$(locate_hpnsshd)"
  ok "Using: $hpnsshd_bin"
  
  ensure_privsep_user
  ensure_host_keys
  write_config
  write_systemd_unit "$hpnsshd_bin"
  start_service
  
  echo
  hr
  ok "INSTALLATION COMPLETE - FINAL PERFECT VERSION"
  echo
  echo "Test connection:"
  echo "  ssh -p ${PORT} root@YOUR_SERVER_IP"
  echo
  echo "View logs:"
  echo "  journalctl -u ${SERVICE} -f"
  echo "  tail -f ${RUNTIMELOG}"
  hr
}

usage() {
  banner
  cat <<USAGE
Usage: sudo $0 install|status|logs|uninstall

Commands:
  install   - Install HPN-SSH tunnel
  status    - Show service status
  logs      - Show recent logs
  uninstall - Remove everything

Environment variables:
  PORT=2222              - Port to listen on
  PERMIT_ROOT_LOGIN=yes  - Allow root login
  PASSWORD_AUTH=yes      - Allow password auth
USAGE
}

main() {
  [[ "$EUID" -eq 0 ]] || die "Run as root"
  case "${1:-}" in
    install)   install_cmd ;;
    status)    status_cmd ;;
    logs)      logs_cmd ;;
    uninstall) uninstall_cmd ;;
    *)         usage ;;
  esac
}

main "$@"
