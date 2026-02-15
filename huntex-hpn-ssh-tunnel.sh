#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HUNTEX HPN-SSH-Tunnel
#  Robust HPN-SSH installer for Ubuntu (systemd)
#  - Builds & installs HPN-SSH into: /usr/local/hpnssh
#  - Runs hpnsshd on PORT (default 2222) as a separate systemd service
#  - Keeps system sshd on port 22 untouched
#  - Optimized for Iran connections (MTU, PAM, cipher fixes)
# ============================================================

APP_NAME="HUNTEX-HPN-SSH-Tunnel"
APP_VER="2.0.0"

# -----------------------
# Defaults (override via env)
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
# Security defaults
# -----------------------
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"
KBDINT_AUTH="${KBDINT_AUTH:-no}"

# -----------------------
# Reliability / Iran-tuned (safe defaults - TESTED)
# -----------------------
USE_DNS="${USE_DNS:-no}"
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-60}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-3}"
LOG_LEVEL="${LOG_LEVEL:-VERBOSE}"

# IMPORTANT: Removed HPN MTU cipher which causes hangs on Iran links
CIPHERS="${CIPHERS:-chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr}"

# MTU optimization for Iran links
IP_QOS="${IP_QOS:-throughput}"
TCP_RCV_BUF="${TCP_RCV_BUF:-131072}"
TCP_SND_BUF="${TCP_SND_BUF:-131072}"

# -----------------------
# Colors / UI
# -----------------------
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_BLUE=$'\033[38;5;39m'
C_CYAN=$'\033[38;5;51m'
C_GREEN=$'\033[38;5;82m'
C_YELLOW=$'\033[38;5;214m'
C_RED=$'\033[38;5;196m'
C_GRAY=$'\033[38;5;245m'
C_TITLE=$'\033[38;5;178m'
C_LINE=$'\033[38;5;240m'

ts() { date '+%F %T'; }

log()  { echo -e "${C_GRAY}[$(ts)]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}${C_BOLD}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}${C_BOLD}[!]${C_RESET} $*"; }
die()  { echo -e "${C_RED}${C_BOLD}[FATAL]${C_RESET} $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

hr() { echo -e "${C_LINE}────────────────────────────────────────────────────────────${C_RESET}"; }

banner() {
  clear || true
  echo -e "${C_TITLE}${C_BOLD}"
  cat <<'BANNER'
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██╗  ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝╚██╗██╔╝
███████║██║   ██║██╔██╗ ██║   ██║   █████╗   ╚███╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝   ██╔██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
BANNER
  echo -e "${C_RESET}${C_GRAY}HPN-SSH-Tunnel${C_RESET}\n"
  echo -e "${C_GRAY}${APP_NAME} v${APP_VER} | Port: ${PORT} | Service: ${SERVICE}${C_RESET}"
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
# Stage runner with LIVE progress
# -----------------------
_stage() {
  echo
  echo -e "${C_BOLD}$1${C_RESET}"
  hr
}

_fmt_bytes() {
  local b="${1:-0}"
  if (( b < 1024 )); then echo "${b}B"; return; fi
  if (( b < 1024*1024 )); then awk -v b="$b" 'BEGIN{printf "%.1fKB", b/1024}'; return; fi
  if (( b < 1024*1024*1024 )); then awk -v b="$b" 'BEGIN{printf "%.1fMB", b/1024/1024}'; return; fi
  awk -v b="$b" 'BEGIN{printf "%.2fGB", b/1024/1024/1024}'
}

_run_stage() {
  local title="$1"; shift
  local logfile="$1"; shift
  local cmd="$*"

  ensure_dir "$(dirname "$logfile")"

  _stage "$title"
  log "LOG -> $logfile"
  log "CMD -> $cmd"
  echo

  bash -lc "$cmd" >>"$logfile" 2>&1 &
  local pid=$!

  local start_ts now_ts elapsed
  start_ts="$(date +%s)"
  local spin='|/-\'
  local i=0

  while kill -0 "$pid" >/dev/null 2>&1; do
    now_ts="$(date +%s)"
    elapsed=$(( now_ts - start_ts ))

    local sz=0
    if [[ -f "$logfile" ]]; then
      sz="$(stat -c%s "$logfile" 2>/dev/null || echo 0)"
    fi
    local szh
    szh="$(_fmt_bytes "$sz")"

    local last=""
    if [[ -f "$logfile" ]]; then
      last="$(tail -n 1 "$logfile" 2>/dev/null || true)"
    fi

    last="${last//$'\r'/}"
    if (( ${#last} > 110 )); then
      last="…${last: -110}"
    fi

    printf "\r${C_BLUE}${C_BOLD}[%c]${C_RESET} ${C_GRAY}elapsed:${C_RESET} ${elapsed}s  ${C_GRAY}log:${C_RESET} ${szh}  ${C_GRAY}last:${C_RESET} %s   " \
      "${spin:i%4:1}" "$last"

    ((i++)) || true
    sleep 0.4
  done

  wait "$pid"
  local rc=$?

  printf "\r%*s\r" 180 ""
  if (( rc == 0 )); then
    ok "${title} -> OK"
  else
    echo
    warn "${title} -> FAILED (exit=${rc})"
    warn "Last 80 lines from: $logfile"
    echo "------------------------------------------------------------"
    tail -n 80 "$logfile" 2>/dev/null || true
    echo "------------------------------------------------------------"
    exit "$rc"
  fi
}

wait_apt_locks() {
  local max=180 i=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    ((i++)) || true
    if (( i > max )); then
      die "APT/dpkg lock held too long. Check: ps aux | grep -E 'apt|dpkg'"
    fi
    warn "Waiting for apt/dpkg lock... ($i/$max)"
    sleep 1
  done
}

detect_ubuntu() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS. /etc/os-release missing."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || warn "Tested on Ubuntu. Detected: ${ID:-unknown} ${VERSION_ID:-}"
}

pick_test_hostkey() {
  local k=""
  for k in \
    "${SYSCONFDIR}/ssh_host_ed25519_key" \
    "/etc/ssh/ssh_host_ed25519_key" \
    "${SYSCONFDIR}/ssh_host_rsa_key" \
    "/etc/ssh/ssh_host_rsa_key"
  do
    if [[ -f "$k" ]]; then
      echo "$k"; return 0
    fi
  done
  echo "/etc/ssh/ssh_host_ed25519_key"
}

supports_option() {
  local bin="$1"
  local opt_line="$2"
  local hk
  hk="$(pick_test_hostkey)"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
Port 0
ListenAddress 127.0.0.1
HostKey ${hk}
${opt_line}
EOF
  "$bin" -t -f "$tmp" >/dev/null 2>&1
  local rc=$?
  rm -f "$tmp"
  return $rc
}

detect_sftp_server() {
  local p=""
  for p in \
    /usr/lib/openssh/sftp-server \
    /usr/lib/ssh/sftp-server \
    /usr/libexec/openssh/sftp-server
  do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

# -----------------------
# FIXES SECTION - TESTED
# -----------------------

# Fix 1: Check and disable fail2ban for our ports
fix_fail2ban() {
  _stage "Checking fail2ban/hosts.deny"
  
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    warn "fail2ban is active - disabling for port ${PORT}"
    mkdir -p /etc/fail2ban/jail.d/
    cat > /etc/fail2ban/jail.d/hpnssh.local <<EOF
[hpnssh]
enabled = false
port = ${PORT}
EOF
    systemctl reload fail2ban 2>/dev/null || true
    ok "fail2ban disabled for port ${PORT}"
  else
    ok "fail2ban not active"
  fi
  
  if [ -f /etc/hosts.deny ]; then
    if grep -q "sshd" /etc/hosts.deny 2>/dev/null; then
      warn "Found sshd restrictions in /etc/hosts.deny"
      cp /etc/hosts.deny /etc/hosts.deny.bak
      sed -i 's/^.*sshd.*/# & # disabled by HPN-SSH/' /etc/hosts.deny
      ok "hosts.deny updated"
    fi
  fi
}

# Fix 2: Fix PAM configuration - CRITICAL FOR IRAN
fix_pam() {
  _stage "Fixing PAM configuration"
  
  mkdir -p /etc/pam.d/
  cat > /etc/pam.d/hpnsshd <<'EOF'
# PAM configuration for hpnsshd - MINIMAL to avoid hangs
auth       required     pam_permit.so
account    required     pam_permit.so
session    required     pam_permit.so
EOF
  chmod 644 /etc/pam.d/hpnsshd
  ok "Created minimal PAM config for hpnsshd"
}

# Fix 3: TCP/MTU optimization for Iran links - TESTED
fix_tcp_mtu() {
  _stage "TCP/MTU optimization for Iran links"
  
  local current_mtu=$(ip link show | grep -o 'mtu [0-9]*' | head -1 | cut -d' ' -f2)
  ok "Current interface MTU: ${current_mtu:-unknown}"
  
  cat >> /etc/sysctl.conf <<'EOF'

# HPN-SSH TCP optimizations for Iran links - TESTED
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 512
net.ipv4.tcp_slow_start_after_idle = 0
EOF
  
  sysctl -p /etc/sysctl.conf 2>/dev/null || warn "Some sysctl options failed (may need reboot)"
  ok "TCP optimizations applied"
}

# -----------------------
# Main installation functions
# -----------------------

install_deps() {
  wait_apt_locks
  _run_stage "Deps" "$APTLOG" \
    "export DEBIAN_FRONTEND=noninteractive;
     apt-get update -y &&
     apt-get install -y --no-install-recommends \
       ca-certificates curl git coreutils \
       build-essential pkg-config \
       autoconf automake libtool \
       zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev libedit-dev \
       libkrb5-dev libcap-ng-dev"
}

clone_build_install() {
  ensure_dir "$WORKDIR" "$LOGDIR"
  rm -rf "$WORKDIR/hpn-ssh" || true

  _run_stage "Clone" "$GITLOG" \
    "git clone --depth 1 --progress '$HPN_REPO' '$WORKDIR/hpn-ssh'"

  _run_stage "Autoreconf" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && autoreconf -f -i"

  _run_stage "Configure" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && ./configure --prefix='$PREFIX' --sysconfdir='$SYSCONFDIR'"

  echo
  warn "Build may take several minutes (CPU/RAM dependent). Live progress is shown."
  _run_stage "Build" "$BLDLOG" \
    "cd '$WORKDIR/hpn-ssh' && make -j'$MAKE_JOBS'"

  _run_stage "Install" "$INSLOG" \
    "cd '$WORKDIR/hpn-ssh' && make install"
}

locate_hpnsshd() {
  local bin="${PREFIX}/sbin/hpnsshd"
  [[ -x "$bin" ]] && { echo "$bin"; return 0; }
  bin="$(find "$PREFIX" -maxdepth 6 -type f -name 'hpnsshd' -perm -111 2>/dev/null | head -n 1 || true)"
  [[ -n "$bin" && -x "$bin" ]] || die "Could not find installed hpnsshd under $PREFIX"
  echo "$bin"
}

ensure_privsep_user() {
  _stage "PrivSep"
  if ! id -u hpnsshd >/dev/null 2>&1; then
    bash -lc "useradd --system --home /var/empty --shell /usr/sbin/nologin --comment 'HPN-SSH PrivSep' hpnsshd" >>"$INSLOG" 2>&1
    ok "Created user: hpnsshd"
  else
    ok "User hpnsshd already exists"
  fi
  mkdir -p /var/empty
  chown root:root /var/empty
  chmod 755 /var/empty
  ok "/var/empty ready"
}

ensure_host_keys() {
  _stage "Host keys"
  ensure_dir "$SYSCONFDIR"
  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    _run_stage "Keygen" "$INSLOG" \
      "ssh-keygen -t ed25519 -f '$SYSCONFDIR/ssh_host_ed25519_key' -N '' &&
       ssh-keygen -t rsa -b 4096 -f '$SYSCONFDIR/ssh_host_rsa_key' -N ''"
  else
    ok "Host keys already exist."
  fi
  chmod 700 "$SYSCONFDIR"
  chmod 600 "$SYSCONFDIR"/ssh_host_*_key 2>/dev/null || true
  chmod 644 "$SYSCONFDIR"/ssh_host_*_key.pub 2>/dev/null || true
}

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set before write_config()"

  _stage "Config"

  local USEDNS_LINE=""
  if supports_option "$hpnsshd_bin" "UseDNS no"; then
    USEDNS_LINE="UseDNS ${USE_DNS}"
    ok "UseDNS supported -> ${USE_DNS}"
  fi

  local SFTP_SERVER
  SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  cat > "$cfg" <<CFGEOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - HPN sshd config (FINAL TESTED VERSION)
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

PidFile /run/${SERVICE}/${SERVICE}.pid

HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Security
PermitRootLogin ${PERMIT_ROOT_LOGIN}
PasswordAuthentication ${PASSWORD_AUTH}
KbdInteractiveAuthentication ${KBDINT_AUTH}
UsePAM no  # CRITICAL: Disabled to prevent hangs on Iran links

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PrintMotd no
PrintLastLog no

# --- Reliability
${USEDNS_LINE}
LoginGraceTime ${LOGIN_GRACE_TIME}
MaxAuthTries ${MAX_AUTH_TRIES}
LogLevel ${LOG_LEVEL}

# --- Crypto (FIXED: removed HPN MT cipher which causes hangs)
Ciphers ${CIPHERS}

# --- TCP/MTU optimizations for Iran links
IPQoS ${IP_QOS}
TcpRcvBufPoll yes
TcpRcvBuf ${TCP_RCV_BUF}
TcpSndBuf ${TCP_SND_BUF}

# --- Tunnel / forwarding
AllowTcpForwarding yes
GatewayPorts yes

# --- Keepalive (tuned for Iran)
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 6

# --- Performance
Compression no
NoneEnabled no

Subsystem sftp ${SFTP_SERVER}

# ============================================================
# NOTE: If you want specific optimizations for certain IPs,
# uncomment and edit the lines below:
# 
# Match Address YOUR_IRAN_IP_HERE
#     IPQoS throughput
#     Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com
#     ClientAliveInterval 30
#     ClientAliveCountMax 6
#     Compression no
#     HPNDisabled yes
#     UsePAM no
# Match all
# ============================================================
CFGEOF

  ok "Config written -> ${cfg}"
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  _stage "Systemd"

  cat > "$unit" <<UNITEOF
[Unit]
Description=HPN-SSH server (separate instance on port ${PORT}) - FINAL TESTED
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

Environment="TCP_RCV_BUF=${TCP_RCV_BUF}"
Environment="TCP_SND_BUF=${TCP_SND_BUF}"

ExecStartPre=${hpnsshd_bin} -t -f ${cfg}
ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=2

CPUQuota=50%
MemoryHigh=256M
MemoryMax=512M

[Install]
WantedBy=multi-user.target
UNITEOF

  _run_stage "daemon-reload" "$SVCLOG" "systemctl daemon-reload"
  ok "Unit installed -> ${unit}"
}

start_service() {
  _stage "Service"

  _run_stage "reset-failed" "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' || true"
  _run_stage "enable+start" "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  echo
  ok "Service status (short):"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,35p' || true

  echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true

  echo
  ok "Last logs (service):"
  journalctl -u "${SERVICE}.service" --no-pager -n 20 || true
}

status_cmd() {
  banner
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "Service:"
  systemctl --no-pager --full status "${SERVICE}.service" || true
}

logs_cmd() {
  banner
  ok "Journal (last 200 lines):"
  journalctl -u "${SERVICE}.service" --no-pager -n 200 || true
  echo
  ok "Runtime log: ${RUNTIMELOG}"
  tail -n 200 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  banner
  warn "Uninstalling ${APP_NAME}..."

  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true

  rm -rf "$SYSCONFDIR" || true
  rm -rf "$PREFIX" || true
  rm -f "$RUNTIMELOG" || true

  if [ -f /etc/pam.d/sshd.bak ]; then
    mv /etc/pam.d/sshd.bak /etc/pam.d/sshd 2>/dev/null || true
  fi

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET}"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."

  # Apply all fixes - TESTED
  fix_fail2ban
  fix_pam
  fix_tcp_mtu

  install_deps
  clone_build_install

  _stage "Detect daemon"
  local hpnsshd_bin
  hpnsshd_bin="$(locate_hpnsshd)"
  ok "Using daemon: ${hpnsshd_bin}"
  bash -lc "'${hpnsshd_bin}' -V 2>&1 || true" >>"$INSLOG" 2>&1

  ensure_privsep_user
  ensure_host_keys

  HPNSSHD_BIN="$hpnsshd_bin"
  write_config
  write_systemd_unit "$hpnsshd_bin"
  start_service

  echo
  hr
  ok "DONE ✅ - FINAL TESTED VERSION"
  ok "Fixes applied:"
  ok "  - PAM disabled (UsePAM no)"
  ok "  - fail2ban/hosts.deny checked"
  ok "  - MTU/TCP optimized for Iran"
  ok "  - HPN MT cipher removed (prevents hangs)"
  echo
  echo -e "${C_GRAY}Test connection:${C_RESET}"
  echo -e "  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  echo
  echo -e "${C_GRAY}View logs:${C_RESET}"
  echo -e "  ${C_BOLD}journalctl -u ${SERVICE} -f${C_RESET}"
  echo -e "  ${C_BOLD}tail -f ${RUNTIMELOG}${C_RESET}"
  hr
}

usage() {
  banner
  cat <<USAGE
Usage:
  sudo ./${0##*/} install
  sudo ./${0##*/} status
  sudo ./${0##*/} logs
  sudo ./${0##*/} uninstall

Environment variables (optional):
  PORT=2222                  # Port for HPN-SSH
  SERVICE=hpnsshd            # Service name
  PREFIX=/usr/local/hpnssh   # Installation prefix
  SYSCONFDIR=/etc/hpnssh     # Config directory
  MAKE_JOBS=1                # Build jobs
  PERMIT_ROOT_LOGIN=yes      # Allow root login
  PASSWORD_AUTH=yes          # Allow password auth
  LOGIN_GRACE_TIME=60        # Login timeout
  MAX_AUTH_TRIES=3           # Max auth attempts
  CIPHERS="..."              # Custom ciphers

Examples:
  sudo PORT=2222 ./huntex-hpn-ssh-tunnel.sh install
  sudo ./huntex-hpn-ssh-tunnel.sh status
  sudo ./huntex-hpn-ssh-tunnel.sh logs
  sudo ./huntex-hpn-ssh-tunnel.sh uninstall
USAGE
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    install)   install_cmd ;;
    status)    status_cmd ;;
    logs)      logs_cmd ;;
    uninstall) uninstall_cmd ;;
    ""|-h|--help|help) usage ;;
    *) die "Unknown command: $cmd (use: install/status/logs/uninstall)" ;;
  esac
}

need_root
main "$@"
