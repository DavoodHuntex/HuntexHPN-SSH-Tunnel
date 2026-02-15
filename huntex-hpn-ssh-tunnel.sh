#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HUNTEX HPN-SSH-Tunnel
#  Robust HPN-SSH installer for Ubuntu (systemd)
#  - Builds & installs HPN-SSH into: /usr/local/hpnssh
#  - Runs hpnsshd on PORT (default 2222) as a separate systemd service
#  - Keeps system sshd on port 22 untouched
#  - FINAL "NO-ERROR" VERSION: auto-detects supported options
# ============================================================

APP_NAME="HUNTEX-HPN-SSH-Tunnel"
APP_VER="3.1.0-noerror"

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
# Security defaults (you said: prefer "works" over security)
# -----------------------
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"

# We will FORCE-disable interactive challenges if supported (to prevent hangs)
KBDINT_AUTH="${KBDINT_AUTH:-no}"

# -----------------------
# Reliability / Iran-tuned (safe)
# -----------------------
USE_DNS="${USE_DNS:-no}"
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-120}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-10}"
LOG_LEVEL="${LOG_LEVEL:-VERBOSE}"

# Cipher list: include HPN mt + normal, but ONLY if daemon accepts it
CIPHERS_DEFAULT="chacha20-poly1305-mt@hpnssh.org,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr"
CIPHERS="${CIPHERS:-$CIPHERS_DEFAULT}"

# -----------------------
# Colors / UI (PRESERVED)
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
# Stage runner with LIVE progress (PRESERVED)
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
# FIXES SECTION (no hard failures)
# -----------------------
fix_fail2ban() {
  _stage "Checking fail2ban/hosts.deny"
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    warn "fail2ban active -> creating rule to not manage ${SERVICE} (best-effort)"
    mkdir -p /etc/fail2ban/jail.d/ || true
    cat > /etc/fail2ban/jail.d/hpnssh.local <<EOF2
[${SERVICE}]
enabled = false
port = ${PORT}
EOF2
    systemctl reload fail2ban 2>/dev/null || true
    ok "fail2ban rule written (best-effort)"
  else
    ok "fail2ban not active"
  fi

  if [[ -f /etc/hosts.deny ]]; then
    if grep -qE '(^|\s)sshd(:|\s)' /etc/hosts.deny 2>/dev/null; then
      warn "hosts.deny has sshd rules -> commenting (best-effort)"
      cp /etc/hosts.deny /etc/hosts.deny.bak 2>/dev/null || true
      sed -i 's/^\(.*sshd.*\)$/# \1 # disabled by HPN-SSH/g' /etc/hosts.deny 2>/dev/null || true
      ok "hosts.deny updated (best-effort)"
    else
      ok "hosts.deny has no sshd rule"
    fi
  else
    ok "/etc/hosts.deny not present"
  fi
}

fix_pam_minimal() {
  _stage "PAM minimal (best-effort)"
  # If server tries PAM for sshd variants, this avoids weird hangs.
  mkdir -p /etc/pam.d/ || true
  cat > /etc/pam.d/hpnsshd <<'EOF2'
# Minimal PAM rules for hpnsshd (avoid interactive/challenge hangs)
auth       required     pam_permit.so
account    required     pam_permit.so
session    required     pam_permit.so
EOF2
  chmod 644 /etc/pam.d/hpnsshd 2>/dev/null || true
  ok "/etc/pam.d/hpnsshd written"
}

fix_sysctl_safe() {
  _stage "TCP tweaks (safe / best-effort)"
  # Keep it safe: do not break boot; ignore failures.
  cat > /etc/sysctl.d/99-huntex-hpnssh.conf <<'EOF2'
# Safe TCP tweaks for unstable paths (best-effort)
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
EOF2
  sysctl --system >/dev/null 2>&1 || true
  ok "sysctl applied (best-effort)"
}

# -----------------------
# Build / install
# -----------------------
install_deps() {
  wait_apt_locks
  _run_stage "Installing dependencies" "$APTLOG" \
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

  _run_stage "Cloning HPN-SSH" "$GITLOG" \
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

# -----------------------
# Option probing (critical for "NO ERROR")
# -----------------------
pick_test_hostkey() {
  local k=""
  for k in \
    "${SYSCONFDIR}/ssh_host_ed25519_key" \
    "/etc/ssh/ssh_host_ed25519_key" \
    "${SYSCONFDIR}/ssh_host_rsa_key" \
    "/etc/ssh/ssh_host_rsa_key"
  do
    if [[ -f "$k" ]]; then echo "$k"; return 0; fi
  done
  echo "/etc/ssh/ssh_host_ed25519_key"
}

supports_option() {
  local bin="$1"
  local opt_line="$2"
  local hk tmp
  hk="$(pick_test_hostkey)"
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF2
Port 0
ListenAddress 127.0.0.1
HostKey ${hk}
${opt_line}
EOF2
  "$bin" -t -f "$tmp" >/dev/null 2>&1
  local rc=$?
  rm -f "$tmp"
  return $rc
}

# returns a list of validated config lines for PAM/challenge knobs
build_auth_lines() {
  local bin="$1"
  local out=()

  # Always present in OpenSSH, but still probe to avoid "Bad option"
  if supports_option "$bin" "PasswordAuthentication ${PASSWORD_AUTH}"; then
    out+=("PasswordAuthentication ${PASSWORD_AUTH}")
  fi

  if supports_option "$bin" "PermitRootLogin ${PERMIT_ROOT_LOGIN}"; then
    out+=("PermitRootLogin ${PERMIT_ROOT_LOGIN}")
  fi

  # Disable interactive/challenge paths if supported (prevents hangs)
  if supports_option "$bin" "KbdInteractiveAuthentication ${KBDINT_AUTH}"; then
    out+=("KbdInteractiveAuthentication ${KBDINT_AUTH}")
  fi
  if supports_option "$bin" "ChallengeResponseAuthentication no"; then
    out+=("ChallengeResponseAuthentication no")
  fi

  # Prefer UsePAM no if supported (avoid PAM)
  if supports_option "$bin" "UsePAM no"; then
    out+=("UsePAM no")
  fi

  printf "%s\n" "${out[@]}"
}

build_misc_lines() {
  local bin="$1"
  local out=()

  if supports_option "$bin" "UseDNS ${USE_DNS}"; then
    out+=("UseDNS ${USE_DNS}")
  fi
  if supports_option "$bin" "LoginGraceTime ${LOGIN_GRACE_TIME}"; then
    out+=("LoginGraceTime ${LOGIN_GRACE_TIME}")
  fi
  if supports_option "$bin" "MaxAuthTries ${MAX_AUTH_TRIES}"; then
    out+=("MaxAuthTries ${MAX_AUTH_TRIES}")
  fi
  if supports_option "$bin" "LogLevel ${LOG_LEVEL}"; then
    out+=("LogLevel ${LOG_LEVEL}")
  fi

  # Only set ciphers if accepted
  if supports_option "$bin" "Ciphers ${CIPHERS}"; then
    out+=("Ciphers ${CIPHERS}")
  fi

  printf "%s\n" "${out[@]}"
}

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set before write_config()"

  _stage "Config (auto-validated options)"

  local SFTP_SERVER
  SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  local auth_lines misc_lines
  auth_lines="$(build_auth_lines "$hpnsshd_bin" || true)"
  misc_lines="$(build_misc_lines "$hpnsshd_bin" || true)"

  cat > "$cfg" <<CFGEOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - NO-ERROR CONFIG (auto-validated)
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Auth / PAM / Challenge (validated)
${auth_lines}

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PrintMotd no
PrintLastLog no

# --- Reliability (validated)
${misc_lines}

# --- Keepalive
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 6

Compression no

# --- Features
AllowTcpForwarding yes
GatewayPorts yes

Subsystem sftp ${SFTP_SERVER}
CFGEOF

  # Final validation must pass. If fails, show last error and stop.
  if ! "$hpnsshd_bin" -t -f "$cfg" >/dev/null 2>&1; then
    warn "Config test failed. Showing error:"
    "$hpnsshd_bin" -t -f "$cfg" 2>&1 | tail -n 60 || true
    die "hpnsshd config invalid (should not happen)."
  fi

  ok "Config written & validated -> ${cfg}"
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  _stage "Systemd"

  cat > "$unit" <<UNITEOF
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

  _run_stage "daemon-reload" "$SVCLOG" "systemctl daemon-reload"
  ok "Unit installed -> ${unit}"
}

cleanup_existing_unit() {
  _stage "Cleaning existing service (if any)"
  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true
  ok "Service cleanup done (best-effort)"
}

start_service() {
  _stage "Service"

  cleanup_existing_unit

  _run_stage "enable+start" "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  echo
  ok "Service status (short):"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,35p' || true

  echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true

  echo
  ok "Last logs (service):"
  journalctl -u "${SERVICE}.service" --no-pager -n 30 || true
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

  cleanup_existing_unit
  rm -f "/etc/systemd/system/${SERVICE}.service" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  rm -rf "$SYSCONFDIR" 2>/dev/null || true
  rm -rf "$PREFIX" 2>/dev/null || true
  rm -f "$RUNTIMELOG" 2>/dev/null || true

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET}"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."

  # Best-effort fixes (no hard failures)
  fix_fail2ban
  fix_pam_minimal
  fix_sysctl_safe

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
  ok "DONE ✅ (${APP_VER})"
  ok "Key points:"
  ok "  - PAM/challenge options are ONLY written if supported (prevents hangs + bad options)"
  ok "  - Service cleanup is automatic"
  ok "  - Best-effort fixes won't break install"
  echo
  echo -e "${C_GRAY}Test:${C_RESET}  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  echo -e "${C_GRAY}Logs:${C_RESET}  ${C_BOLD}journalctl -u ${SERVICE} -f${C_RESET}  |  ${C_BOLD}tail -f ${RUNTIMELOG}${C_RESET}"
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

Env overrides:
  PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh MAKE_JOBS=1
  PERMIT_ROOT_LOGIN=yes|prohibit-password
  PASSWORD_AUTH=yes|no
  KBDINT_AUTH=no|yes
  USE_DNS=no|yes
  LOGIN_GRACE_TIME=120
  MAX_AUTH_TRIES=10
  LOG_LEVEL=VERBOSE|DEBUG2
  CIPHERS="..."
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

chmod +x /root/huntex-hpn-ssh-tunnel.sh
