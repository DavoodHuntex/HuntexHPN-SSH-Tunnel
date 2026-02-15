#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HuntexHPN-SSH-Tunnel
#  Robust HPN-SSH installer for Ubuntu (systemd)
#  - Builds & installs HPN-SSH into: /usr/local/hpnssh
#  - Runs hpnsshd on PORT (default 2222) as a separate systemd service
#  - Keeps system sshd on port 22 untouched
#  - Auto-fixes common failures:
#      * "Privilege separation user hpnsshd does not exist"
#      * missing /var/empty
#      * systemd start-limit after repeated failures
#      * config test before start
#
#  Commands:
#    ./huntex-hpn-ssh-tunnel.sh install
#    ./huntex-hpn-ssh-tunnel.sh status
#    ./huntex-hpn-ssh-tunnel.sh logs
#    ./huntex-hpn-ssh-tunnel.sh uninstall
#
#  Environment overrides (optional):
#    PORT=2222
#    SERVICE=hpnsshd
#    PREFIX=/usr/local/hpnssh
#    SYSCONFDIR=/etc/hpnssh
#    WORKDIR=/root/hpn-build
#    LOGDIR=/root/hpn-logs
#    HPN_REPO=https://github.com/rapier1/hpn-ssh.git
#    MAKE_JOBS=1
#
#  Security toggles (recommended defaults are safer):
#    PERMIT_ROOT_LOGIN=prohibit-password   (or "yes")
#    PASSWORD_AUTH=no                      (or "yes")
#    KBDINT_AUTH=no                        (or "yes")
#
# ============================================================

APP_NAME="HuntexHPN-SSH-Tunnel"
APP_VER="1.0.0"


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

# Security defaults (safe-ish for public servers)
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-prohibit-password}" # recommended; set "yes" if you insist
PASSWORD_AUTH="${PASSWORD_AUTH:-no}"                        # recommended; set "yes" to allow passwords
KBDINT_AUTH="${KBDINT_AUTH:-no}"                            # recommended; set "yes" to allow keyboard-interactive

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

hr() { echo -e "${C_CYAN}════════════════════════════════════════════════════════════${C_RESET}"; }
title() {
  hr
  echo -e "${C_TITLE}${C_BOLD}${APP_NAME}${C_RESET} ${C_GRAY}v${APP_VER}${C_RESET}"
  echo -e "${C_GRAY}HPN-SSH separate instance on port ${C_BOLD}${PORT}${C_RESET}${C_GRAY}; system sshd stays on 22${C_RESET}"
  hr
}
ts() { date '+%F %T'; }
log()  { echo -e "${C_GRAY}[$(ts)]${C_RESET} $*"; }
step() { echo -e "${C_BLUE}${C_BOLD}[*]${C_RESET} ${C_BLUE}$*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}${C_BOLD}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}${C_BOLD}[!]${C_RESET} $*"; }
die()  { echo -e "${C_RED}${C_BOLD}[FATAL]${C_RESET} $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

# -----------------------
# Logging
# -----------------------
APTLOG="$LOGDIR/apt.log"
GITLOG="$LOGDIR/git.log"
BLDLOG="$LOGDIR/build.log"
INSLOG="$LOGDIR/install.log"
SVCLOG="$LOGDIR/service.log"
RUNTIMELOG="/var/log/${SERVICE}.log"

runlog() {
  local logfile="$1"; shift
  ensure_dir "$(dirname "$logfile")"
  log "LOG: $logfile"
  log "CMD: $*"
  bash -lc "$*" >>"$logfile" 2>&1
}

wait_apt_locks() {
  local max=180
  local i=0
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
  [[ "${ID:-}" == "ubuntu" ]] || warn "This script is tested on Ubuntu. Detected: ${ID:-unknown} ${VERSION_ID:-}"
}

# -----------------------
# Core actions
# -----------------------
install_deps() {
  step "Installing build dependencies (apt)..."
  wait_apt_locks
  runlog "$APTLOG" "export DEBIAN_FRONTEND=noninteractive;
    apt-get update -y &&
    apt-get install -y --no-install-recommends \
      ca-certificates curl git coreutils \
      build-essential pkg-config \
      autoconf automake libtool \
      zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev libedit-dev \
      libkrb5-dev libcap-ng-dev"
  ok "Dependencies installed."
}

clone_build_install() {
  step "Preparing workdir: ${WORKDIR}"
  ensure_dir "$WORKDIR" "$LOGDIR"
  rm -rf "$WORKDIR/hpn-ssh" || true

  step "Cloning HPN-SSH source..."
  runlog "$GITLOG" "git clone --depth 1 '$HPN_REPO' '$WORKDIR/hpn-ssh'"

  step "Autoreconf..."
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && autoreconf -f -i"

  step "Configure..."
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && ./configure --prefix='$PREFIX' --sysconfdir='$SYSCONFDIR'"

  step "Build (make -j${MAKE_JOBS})..."
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && make -j'$MAKE_JOBS'"

  step "Install..."
  runlog "$INSLOG" "cd '$WORKDIR/hpn-ssh' && make install"
  ok "HPN-SSH installed to ${PREFIX}"
}

locate_hpnsshd() {
  local bin="${PREFIX}/sbin/hpnsshd"
  if [[ -x "$bin" ]]; then
    echo "$bin"; return 0
  fi
  bin="$(find "$PREFIX" -maxdepth 6 -type f -name 'hpnsshd' -perm -111 2>/dev/null | head -n 1 || true)"
  [[ -n "$bin" && -x "$bin" ]] || die "Could not find installed hpnsshd under $PREFIX"
  echo "$bin"
}

ensure_privsep_user() {
  # Fix for: "Privilege separation user hpnsshd does not exist"
  step "Ensuring PrivSep user 'hpnsshd' + /var/empty..."
  if ! id -u hpnsshd >/dev/null 2>&1; then
    runlog "$INSLOG" "useradd --system --home /var/empty --shell /usr/sbin/nologin --comment 'HPN-SSH PrivSep' hpnsshd"
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
  step "Ensuring host keys under ${SYSCONFDIR}..."
  ensure_dir "$SYSCONFDIR"

  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    runlog "$INSLOG" "ssh-keygen -t ed25519 -f '$SYSCONFDIR/ssh_host_ed25519_key' -N ''"
    runlog "$INSLOG" "ssh-keygen -t rsa -b 4096 -f '$SYSCONFDIR/ssh_host_rsa_key' -N ''"
    ok "Host keys generated."
  else
    ok "Host keys already exist."
  fi

  # sshd is picky about permissions
  chmod 700 "$SYSCONFDIR"
  chmod 600 "$SYSCONFDIR"/ssh_host_*_key 2>/dev/null || true
  chmod 644 "$SYSCONFDIR"/ssh_host_*_key.pub 2>/dev/null || true
}

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  step "Writing config: ${cfg}"

  cat > "$cfg" <<CFGEOF
# ============================================================
# HuntexHPN-SSH-Tunnel - HPN sshd config (separate instance)
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

# Keep pid under systemd runtime dir
PidFile /run/${SERVICE}/${SERVICE}.pid

# Host keys (generated by installer)
HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Security knobs (override by env at install time)
PermitRootLogin ${PERMIT_ROOT_LOGIN}
PasswordAuthentication ${PASSWORD_AUTH}
KbdInteractiveAuthentication ${KBDINT_AUTH}
UsePAM yes

# --- Tunnel / forwarding
AllowTcpForwarding yes
GatewayPorts yes

# --- Keepalive
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

# --- Quality
Compression no
LogLevel VERBOSE

# Use your system sftp-server (Ubuntu path)
Subsystem sftp /usr/lib/openssh/sftp-server
CFGEOF

  ok "Config written."
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  step "Creating systemd unit: ${unit}"
  cat > "$unit" <<UNITEOF
[Unit]
Description=HPN-SSH server (separate instance on port ${PORT})
After=network.target

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

# Validate config before starting
ExecStartPre=${hpnsshd_bin} -t -f ${cfg}

ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=2

# Avoid aggressive restart loops
StartLimitIntervalSec=60
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
UNITEOF

  runlog "$SVCLOG" "systemctl daemon-reload"
  ok "systemd unit installed."
}

start_service() {
  step "Enabling + starting ${SERVICE}..."
  runlog "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' || true"
  runlog "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  # show short status
  echo
  ok "Service status:"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,60p' || true
  echo

  ok "Listening ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
}

status_cmd() {
  title
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "Service:"
  systemctl --no-pager --full status "${SERVICE}.service" || true
}

logs_cmd() {
  title
  ok "Journal (last 120 lines):"
  journalctl -u "${SERVICE}.service" --no-pager -n 120 || true
  echo
  ok "Runtime log: ${RUNTIMELOG}"
  tail -n 120 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  title
  warn "Uninstalling ${APP_NAME}..."
  warn "This removes: service + config + install prefix."
  warn "It does NOT remove: user 'hpnsshd' and /var/empty (safe)."

  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true

  rm -rf "$SYSCONFDIR" || true
  rm -rf "$PREFIX" || true
  rm -f "$RUNTIMELOG" || true

  ok "Uninstalled."
  ok "If you want to remove the privsep user too (optional):"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  title
  detect_ubuntu

  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? Install iproute2 if needed."

  install_deps
  clone_build_install

  local hpnsshd_bin
  hpnsshd_bin="$(locate_hpnsshd)"
  ok "Using daemon: ${hpnsshd_bin}"
  runlog "$INSLOG" "'${hpnsshd_bin}' -V 2>&1 || true"

  ensure_privsep_user
  ensure_host_keys
  write_config
  write_systemd_unit "$hpnsshd_bin"
  start_service

  hr
  ok "DONE ✅"
  echo -e "${C_GRAY}Connect test from another server:${C_RESET}"
  echo -e "  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  hr
  echo -e "${C_YELLOW}${C_BOLD}NOTE:${C_RESET} ${C_GRAY}If you set PASSWORD_AUTH=no (default), use SSH keys. Set PASSWORD_AUTH=yes to allow passwords.${C_RESET}"
}

usage() {
  cat <<USAGE
${APP_NAME} v${APP_VER}

Usage:
  sudo ./${0##*/} install
  sudo ./${0##*/} status
  sudo ./${0##*/} logs
  sudo ./${0##*/} uninstall

Env overrides:
  PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh MAKE_JOBS=1
  PERMIT_ROOT_LOGIN=prohibit-password|yes
  PASSWORD_AUTH=no|yes
  KBDINT_AUTH=no|yes
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

main "$@"

chmod +x huntex-hpn-ssh-tunnel.sh
