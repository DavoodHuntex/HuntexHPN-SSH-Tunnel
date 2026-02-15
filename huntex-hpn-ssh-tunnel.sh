#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HUNTEX HPN-SSH-Tunnel
#  Robust HPN-SSH installer for Ubuntu (systemd)
#  - Builds & installs HPN-SSH into: /usr/local/hpnssh
#  - Runs hpnsshd on PORT (default 2222) as a separate systemd service
#  - Keeps system sshd on port 22 untouched
#  - Auto-detects support for UsePAM/UseDNS/Ciphers/MACs to avoid "Unsupported option"
# ============================================================

APP_NAME="HUNTEX HPN-SSH-Tunnel"
APP_VER="1.0.10"

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
# Security defaults (YOU asked: password must work)
# -----------------------
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"
KBDINT_AUTH="${KBDINT_AUTH:-yes}"

# -----------------------
# Reliability / Iran-tuned (safe defaults)
# -----------------------
USE_DNS="${USE_DNS:-no}"
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-60}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-6}"
LOG_LEVEL="${LOG_LEVEL:-DEBUG2}"   # later you can lower to VERBOSE

# Prefer standard OpenSSH cipher set (avoid weird edge cases)
CIPHERS="${CIPHERS:-chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr}"
MACS="${MACS:-hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512}"

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

ts() { date '+%F %T'; }

info() { echo -e "${C_CYAN}${C_BOLD}[INFO]${C_RESET} $*"; }
step() { echo -e "${C_BLUE}${C_BOLD}[STEP]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}${C_BOLD}[ OK ]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}${C_BOLD}[WARN]${C_RESET} $*"; }
die()  { echo -e "${C_RED}${C_BOLD}[FATAL]${C_RESET} $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

# -----------------------
# Logging files
# -----------------------
APTLOG="$LOGDIR/apt.log"
GITLOG="$LOGDIR/git.log"
BLDLOG="$LOGDIR/build.log"
INSLOG="$LOGDIR/install.log"
SVCLOG="$LOGDIR/service.log"
RUNTIMELOG="/var/log/${SERVICE}.log"

# -----------------------
# Clean screen + banner
# -----------------------
clear_screen() { printf "\033c"; }

banner() {
  clear_screen
  echo -e "${C_TITLE}${C_BOLD}"
  cat <<'BANNER'
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██╗  ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝╚██╗██╔╝
███████║██║   ██║██╔██╗ ██║   ██║   █████╗   ╚███╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝   ██╔██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
BANNER
  echo -e "${C_RESET}${C_GRAY}HPN-SSH-Tunnel${C_RESET}"
  echo -e "${C_GRAY}${APP_NAME} v${APP_VER} | Port: ${PORT} | Service: ${SERVICE}${C_RESET}"
  echo
}

# -----------------------
# Progress (overall)
# -----------------------
TOTAL_STEPS=8
CUR_STEP=0

progress_bar() {
  local cur="$1" total="$2"
  local width=26
  local filled=$(( cur * width / total ))
  local empty=$(( width - filled ))
  local pct=$(( cur * 100 / total ))
  printf "${C_GRAY}Progress: [${C_GREEN}%0.s█${C_GRAY}%0.s░${C_GRAY}] %3d%% (%d/%d)${C_RESET}\n" \
    $(seq 1 $filled 2>/dev/null || true) \
    $(seq 1 $empty 2>/dev/null || true) \
    "$pct" "$cur" "$total"
}

next_step() {
  CUR_STEP=$((CUR_STEP+1))
  echo
  progress_bar "$CUR_STEP" "$TOTAL_STEPS"
  step "$1"
}

# -----------------------
# Spinner for long commands
# -----------------------
_spinner_pid=""
start_spinner() {
  local msg="$1"
  echo -ne "${C_GRAY}[$(ts)]${C_RESET} ${msg} ${C_DIM}(working...)${C_RESET} "
  ( while :; do for c in '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
  _spinner_pid="$!"
}

stop_spinner_ok() {
  [[ -n "${_spinner_pid}" ]] && kill "${_spinner_pid}" >/dev/null 2>&1 || true
  _spinner_pid=""
  echo -e "\b ${C_GREEN}${C_BOLD}done${C_RESET}"
}

stop_spinner_fail() {
  [[ -n "${_spinner_pid}" ]] && kill "${_spinner_pid}" >/dev/null 2>&1 || true
  _spinner_pid=""
  echo -e "\b ${C_RED}${C_BOLD}failed${C_RESET}"
}

runlog() {
  local logfile="$1"; shift
  local cmd="$*"
  ensure_dir "$(dirname "$logfile")"

  echo -e "${C_GRAY}[$(ts)]${C_RESET} log -> ${C_CYAN}${logfile}${C_RESET}"
  echo -e "${C_GRAY}[$(ts)]${C_RESET} cmd -> ${C_DIM}${cmd}${C_RESET}"
  start_spinner "running"

  if bash -lc "$cmd" >>"$logfile" 2>&1; then
    stop_spinner_ok
  else
    stop_spinner_fail
    echo -e "${C_YELLOW}${C_BOLD}Last 30 log lines:${C_RESET}"
    tail -n 30 "$logfile" 2>/dev/null || true
    return 1
  fi
}

wait_apt_locks() {
  local max=180 i=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
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

# -----------------------
# Option detection (robust)
# - Fixes false-negatives by using an existing HostKey in test config
# -----------------------
pick_test_hostkey() {
  local k=""
  for k in \
    "${SYSCONFDIR}/ssh_host_ed25519_key" \
    "/etc/ssh/ssh_host_ed25519_key" \
    "${SYSCONFDIR}/ssh_host_rsa_key" \
    "/etc/ssh/ssh_host_rsa_key"
  do
    [[ -f "$k" ]] && { echo "$k"; return 0; }
  done
  echo "/etc/ssh/ssh_host_ed25519_key"
}

supports_option() {
  local bin="$1"
  local opt_line="$2"
  local hk tmp rc
  hk="$(pick_test_hostkey)"
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
Port 0
ListenAddress 127.0.0.1
HostKey ${hk}
${opt_line}
EOF
  "$bin" -t -f "$tmp" >/dev/null 2>&1
  rc=$?
  rm -f "$tmp"
  return "$rc"
}

detect_sftp_server() {
  local p=""
  for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

# -----------------------
# Core actions
# -----------------------
install_deps() {
  next_step "Installing build dependencies"
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
  next_step "Cloning & building HPN-SSH"
  ensure_dir "$WORKDIR" "$LOGDIR"
  runlog "$GITLOG" "rm -rf '$WORKDIR/hpn-ssh' || true"
  runlog "$GITLOG" "git clone --depth 1 '$HPN_REPO' '$WORKDIR/hpn-ssh'"
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && autoreconf -f -i"
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && ./configure --prefix='$PREFIX' --sysconfdir='$SYSCONFDIR'"
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && make -j'$MAKE_JOBS'"
  runlog "$INSLOG" "cd '$WORKDIR/hpn-ssh' && make install"
  ok "HPN-SSH installed to ${PREFIX}"
}

locate_hpnsshd() {
  local bin="${PREFIX}/sbin/hpnsshd"
  [[ -x "$bin" ]] && { echo "$bin"; return 0; }
  bin="$(find "$PREFIX" -maxdepth 6 -type f -name 'hpnsshd' -perm -111 2>/dev/null | head -n 1 || true)"
  [[ -n "$bin" && -x "$bin" ]] || die "Could not find installed hpnsshd under $PREFIX"
  echo "$bin"
}

ensure_privsep_user() {
  next_step "Ensuring PrivSep user + /var/empty"
  if ! id -u hpnsshd >/dev/null 2>&1; then
    runlog "$INSLOG" "useradd --system --home /var/empty --shell /usr/sbin/nologin --comment 'HPN-SSH PrivSep' hpnsshd"
    ok "Created user: hpnsshd"
  else
    ok "User hpnsshd already exists"
  fi
  runlog "$INSLOG" "mkdir -p /var/empty && chown root:root /var/empty && chmod 755 /var/empty"
  ok "/var/empty ready"
}

ensure_host_keys() {
  next_step "Ensuring host keys"
  ensure_dir "$SYSCONFDIR"
  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    runlog "$INSLOG" "ssh-keygen -t ed25519 -f '$SYSCONFDIR/ssh_host_ed25519_key' -N ''"
    runlog "$INSLOG" "ssh-keygen -t rsa -b 4096 -f '$SYSCONFDIR/ssh_host_rsa_key' -N ''"
    ok "Host keys generated."
  else
    ok "Host keys already exist."
  fi
  runlog "$INSLOG" "chmod 700 '$SYSCONFDIR' && chmod 600 '$SYSCONFDIR'/ssh_host_*_key 2>/dev/null || true; chmod 644 '$SYSCONFDIR'/ssh_host_*_key.pub 2>/dev/null || true"
}

write_config() {
  next_step "Writing hpnsshd config (safe autodetect)"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set before write_config()"

  local USEPAM_LINE="" USEDNS_LINE="" CIPHERS_LINE="" MACS_LINE=""

  if supports_option "$hpnsshd_bin" "UsePAM yes"; then
    USEPAM_LINE="UsePAM yes"
    ok "UsePAM supported -> enabled"
  else
    ok "UsePAM not supported -> omitted"
  fi

  if supports_option "$hpnsshd_bin" "UseDNS no"; then
    USEDNS_LINE="UseDNS ${USE_DNS}"
    ok "UseDNS supported -> ${USE_DNS}"
  else
    ok "UseDNS not supported -> omitted"
  fi

  if supports_option "$hpnsshd_bin" "Ciphers ${CIPHERS}"; then
    CIPHERS_LINE="Ciphers ${CIPHERS}"
    ok "Ciphers supported -> set"
  else
    ok "Ciphers not supported -> omitted"
  fi

  if supports_option "$hpnsshd_bin" "MACs ${MACS}"; then
    MACS_LINE="MACs ${MACS}"
    ok "MACs supported -> set"
  else
    ok "MACs not supported -> omitted"
  fi

  local SFTP_SERVER
  SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  ensure_dir "$SYSCONFDIR"
  cat >"$cfg" <<CFGEOF
# ============================================================
# ${APP_NAME} - HPN sshd config (separate instance)
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
${USEPAM_LINE}

# --- Reliability
${USEDNS_LINE}
LoginGraceTime ${LOGIN_GRACE_TIME}
MaxAuthTries ${MAX_AUTH_TRIES}
LogLevel ${LOG_LEVEL}

# --- Crypto (only if supported)
${CIPHERS_LINE}
${MACS_LINE}

# --- Tunnel / forwarding
AllowTcpForwarding yes
GatewayPorts yes

# --- Keepalive
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

Compression no
Subsystem sftp ${SFTP_SERVER}
CFGEOF

  ok "Config written: ${cfg}"
}

write_systemd_unit() {
  next_step "Installing systemd unit"
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  cat >"$unit" <<UNITEOF
[Unit]
Description=HPN-SSH server (separate instance on port ${PORT})
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

ExecStartPre=${hpnsshd_bin} -t -f ${cfg}
ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNITEOF

  runlog "$SVCLOG" "systemctl daemon-reload"
  ok "systemd unit installed."
}

start_service() {
  next_step "Starting service"
  runlog "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' || true"
  runlog "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  echo
  ok "Service status (short):"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,35p' || true
  echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
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
  ok "Runtime log: ${RUNTIMELOG} (last 200)"
  tail -n 200 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  banner
  next_step "Uninstalling"
  warn "Removes: service + config + install prefix."
  warn "Does NOT remove: user 'hpnsshd' and /var/empty (safe)."

  runlog "$SVCLOG" "systemctl stop '${SERVICE}.service' 2>/dev/null || true"
  runlog "$SVCLOG" "systemctl disable '${SERVICE}.service' 2>/dev/null || true"
  runlog "$SVCLOG" "rm -f '/etc/systemd/system/${SERVICE}.service' && systemctl daemon-reload || true"
  runlog "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' 2>/dev/null || true"
  runlog "$INSLOG" "rm -rf '$SYSCONFDIR' '$PREFIX' || true"
  runlog "$INSLOG" "rm -f '$RUNTIMELOG' || true"

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET} sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."

  install_deps
  clone_build_install

  next_step "Detecting daemon"
  local hpnsshd_bin
  hpnsshd_bin="$(locate_hpnsshd)"
  ok "Using daemon: ${hpnsshd_bin}"
  runlog "$INSLOG" "'${hpnsshd_bin}' -V 2>&1 || true"

  ensure_privsep_user
  ensure_host_keys

  HPNSSHD_BIN="$hpnsshd_bin"
  write_config
  write_systemd_unit "$hpnsshd_bin"
  start_service

  echo
  progress_bar "$TOTAL_STEPS" "$TOTAL_STEPS"
  ok "DONE ✅"
  echo -e "${C_GRAY}Test:${C_RESET}  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  echo -e "${C_GRAY}Logs:${C_RESET}  ${C_BOLD}journalctl -u ${SERVICE} -f${C_RESET}  |  ${C_BOLD}tail -f ${RUNTIMELOG}${C_RESET}"
}

usage() {
  banner
  cat <<USAGE
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
  USE_DNS=no
  LOGIN_GRACE_TIME=60
  MAX_AUTH_TRIES=6
  LOG_LEVEL=DEBUG2|VERBOSE
  CIPHERS="..."
  MACS="..."
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
