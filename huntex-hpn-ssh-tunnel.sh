#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
#  HUNTEX HPN-SSH-Tunnel
#  Robust HPN-SSH installer for Ubuntu (systemd)
#  - Builds & installs HPN-SSH into: /usr/local/hpnssh
#  - Runs hpnsshd on PORT (default 2222) as a separate systemd service
#  - Keeps system sshd on port 22 untouched
#
#  Commands:
#    ./huntex-hpn-ssh-tunnel.sh install
#    ./huntex-hpn-ssh-tunnel.sh status
#    ./huntex-hpn-ssh-tunnel.sh logs
#    ./huntex-hpn-ssh-tunnel.sh uninstall
#
#  Env overrides:
#    PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh
#    WORKDIR=/root/hpn-build LOGDIR=/root/hpn-logs HPN_REPO=... MAKE_JOBS=1
#
#  Security toggles:
#    PERMIT_ROOT_LOGIN=yes|prohibit-password
#    PASSWORD_AUTH=yes|no
#    KBDINT_AUTH=yes|no
#
#  Reliability / Crypto:
#    USE_DNS=no LOGIN_GRACE_TIME=60 MAX_AUTH_TRIES=6 LOG_LEVEL=VERBOSE|DEBUG2
#    CIPHERS="..." MACS="..."
# ============================================================

APP_NAME="HUNTEX-HPN-SSH-Tunnel"
APP_VER="1.0.9"

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
# Security defaults (password must work)
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
LOG_LEVEL="${LOG_LEVEL:-DEBUG2}"

# Prefer standard OpenSSH cipher set (avoid weird edge cases)
CIPHERS="${CIPHERS:-chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr}"
MACS="${MACS:-hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512}"

# Make output verbose for accurate live progress
MAKE_VERBOSE="${MAKE_VERBOSE:-1}"   # 1 -> V=1

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

# -----------------------
# Paths / logs
# -----------------------
APTLOG="$LOGDIR/apt.log"
GITLOG="$LOGDIR/git.log"
BLDLOG="$LOGDIR/build.log"
INSLOG="$LOGDIR/install.log"
SVCLOG="$LOGDIR/service.log"
RUNTIMELOG="/var/log/${SERVICE}.log"

# -----------------------
# Helpers
# -----------------------
ts() { date '+%F %T'; }

log()  { echo -e "${C_GRAY}[$(ts)]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}${C_BOLD}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}${C_BOLD}[!]${C_RESET} $*"; }
die()  { echo -e "${C_RED}${C_BOLD}[FATAL]${C_RESET} $*" >&2; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

# Bold stage header exactly as you asked
stage() {
  echo
  echo -e "${C_TITLE}${C_BOLD}$1${C_RESET}"
  echo -e "${C_GRAY}────────────────────────────────────────────────────────────${C_RESET}"
}

# Clean screen + big logo exactly "HUNTEX"
banner() {
  clear || true
  echo -e "${C_TITLE}${C_BOLD}"
  cat <<'BANNER'
██╗  ██╗██╗   ██╗███╗   ███╗████████╗███████╗██╗  ██╗
██║  ██║██║   ██║████╗ ████║╚══██╔══╝██╔════╝╚██╗██╔╝
███████║██║   ██║██╔████╔██║   ██║   █████╗   ╚███╔╝
██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝   ██╔██╗
██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
BANNER
  echo -e "${C_RESET}${C_GRAY}HPN-SSH-Tunnel${C_RESET}\n"
  echo -e "${C_GRAY}${APP_NAME} v${APP_VER} | Port: ${C_BOLD}${PORT}${C_RESET}${C_GRAY} | Service: ${C_BOLD}${SERVICE}${C_RESET}"
  echo
}

runlog() {
  local logfile="$1"; shift
  ensure_dir "$(dirname "$logfile")"
  log "LOG -> $logfile"
  log "CMD -> $*"
  bash -lc "$*" >>"$logfile" 2>&1
}

wait_apt_locks() {
  local max=180 i=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    ((i++)) || true
    (( i > max )) && die "APT/dpkg lock held too long. Check: ps aux | grep -E 'apt|dpkg'"
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
# Option support detection (fix UsePAM/UseDNS unsupported)
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
  return $rc
}

detect_sftp_server() {
  local p=""
  for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

# -----------------------
# LIVE, REAL progress for Build (accurate)
# -----------------------
count_compile_units() {
  local dir="$1"
  local vflag=""
  [[ "${MAKE_VERBOSE}" == "1" ]] && vflag="V=1"

  ( cd "$dir" && make -n -j1 ${vflag} 2>/dev/null | \
    grep -E '(^|[[:space:]])(gcc|cc|clang|g\+\+|c\+\+|clang\+\+|libtool)[[:space:]]' | \
    grep -E '([[:space:]]-c[[:space:]]|--mode=compile|[[:space:]]compile[[:space:]]).*' | wc -l \
  ) || echo 0
}

progress_bar() {
  local pct="$1"
  local w=30
  local fill=$(( pct*w/100 ))
  local empty=$(( w-fill ))
  printf "["
  printf "%0.s#" $(seq 1 $fill) 2>/dev/null || true
  printf "%0.s-" $(seq 1 $empty) 2>/dev/null || true
  printf "]"
}

make_with_live_progress() {
  local dir="$1"
  local jobs="$2"
  local logfile="$3"

  ensure_dir "$(dirname "$logfile")"

  local vflag=""
  [[ "${MAKE_VERBOSE}" == "1" ]] && vflag="V=1"

  local total done lastpct
  total="$(count_compile_units "$dir")"
  [[ "$total" =~ ^[0-9]+$ ]] || total=0
  (( total < 1 )) && total=1

  echo -e "${C_GRAY}units:${C_RESET} ${C_BOLD}${total}${C_RESET}  ${C_GRAY}(estimated from make -n)${C_RESET}"
  done=0
  lastpct=-1

  # Real-time line buffering for progress
  set +e
  (
    cd "$dir" || exit 1
    stdbuf -oL -eL make -j"$jobs" ${vflag} 2>&1
  ) | tee -a "$logfile" | while IFS= read -r line; do
      # Count compile-like lines
      if echo "$line" | grep -Eq '(^|[[:space:]])(gcc|cc|clang|g\+\+|c\+\+|clang\+\+)[[:space:]].*([[:space:]]-c[[:space:]]).*' \
         || echo "$line" | grep -Eq 'libtool:.*(--mode=compile|compile).*' ; then
        done=$((done+1))
        local pct=$(( done*100/total ))
        (( pct > 100 )) && pct=100
        if (( pct != lastpct )); then
          printf "\rProgress %s %3d%%  (%d/%d)   " "$(progress_bar "$pct")" "$pct" "$done" "$total"
          lastpct="$pct"
        fi
      fi

      # Show only important errors in console (full in log)
      if echo "$line" | grep -Eqi '(error:|undefined reference|No rule to make target|FAILED|Stop\.)'; then
        printf "\n${C_RED}${C_BOLD}%s${C_RESET}\n" "$line"
      fi
    done

  local rc=${PIPESTATUS[0]}
  set -e
  printf "\rProgress %s %3d%%  (%d/%d)   \n" "$(progress_bar 100)" 100 "$done" "$total"

  ((rc==0)) || { echo -e "${C_RED}${C_BOLD}Build failed${C_RESET} (see ${logfile})"; return 1; }
}

# -----------------------
# Actions
# -----------------------
install_deps() {
  stage "Deps"
  step_line
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

# compact step line to keep logs tidy
step_line() {
  echo -e "${C_BLUE}${C_BOLD}[*]${C_RESET} ${C_BLUE}working...${C_RESET}"
}

clone_build_install() {
  stage "Source"
  ensure_dir "$WORKDIR" "$LOGDIR"
  rm -rf "$WORKDIR/hpn-ssh" || true

  log "workdir -> $WORKDIR"
  log "repo   -> $HPN_REPO"

  runlog "$GITLOG" "git clone --depth 1 '$HPN_REPO' '$WORKDIR/hpn-ssh'"
  ok "Cloned."

  stage "Autoreconf"
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && autoreconf -f -i"
  ok "Autoreconf OK."

  stage "Configure"
  runlog "$BLDLOG" "cd '$WORKDIR/hpn-ssh' && ./configure --prefix='$PREFIX' --sysconfdir='$SYSCONFDIR'"
  ok "Configure OK."

  stage "Build"
  # Live accurate progress here
  make_with_live_progress "$WORKDIR/hpn-ssh" "$MAKE_JOBS" "$BLDLOG"
  ok "Build OK."

  stage "Install"
  runlog "$INSLOG" "cd '$WORKDIR/hpn-ssh' && make install"
  ok "Installed to ${PREFIX}"
}

locate_hpnsshd() {
  local bin="${PREFIX}/sbin/hpnsshd"
  [[ -x "$bin" ]] && { echo "$bin"; return 0; }
  bin="$(find "$PREFIX" -maxdepth 6 -type f -name 'hpnsshd' -perm -111 2>/dev/null | head -n 1 || true)"
  [[ -n "$bin" && -x "$bin" ]] || die "Could not find installed hpnsshd under $PREFIX"
  echo "$bin"
}

ensure_privsep_user() {
  stage "PrivSep"
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
  stage "HostKeys"
  ensure_dir "$SYSCONFDIR"

  if [[ ! -f "$SYSCONFDIR/ssh_host_ed25519_key" ]]; then
    runlog "$INSLOG" "ssh-keygen -t ed25519 -f '$SYSCONFDIR/ssh_host_ed25519_key' -N ''"
    runlog "$INSLOG" "ssh-keygen -t rsa -b 4096 -f '$SYSCONFDIR/ssh_host_rsa_key' -N ''"
    ok "Host keys generated."
  else
    ok "Host keys already exist."
  fi

  chmod 700 "$SYSCONFDIR"
  chmod 600 "$SYSCONFDIR"/ssh_host_*_key 2>/dev/null || true
  chmod 644 "$SYSCONFDIR"/ssh_host_*_key.pub 2>/dev/null || true
}

write_config() {
  stage "Config"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set"

  local USEPAM_LINE=""
  if supports_option "$hpnsshd_bin" "UsePAM yes"; then
    USEPAM_LINE="UsePAM yes"
    ok "UsePAM supported -> enabled"
  else
    ok "UsePAM unsupported -> skipped"
  fi

  local USEDNS_LINE=""
  if supports_option "$hpnsshd_bin" "UseDNS no"; then
    USEDNS_LINE="UseDNS ${USE_DNS}"
    ok "UseDNS supported -> ${USE_DNS}"
  else
    ok "UseDNS unsupported -> skipped"
  fi

  local SFTP_SERVER
  SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  ensure_dir "$SYSCONFDIR"
  cat > "$cfg" <<CFGEOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - hpnsshd config (separate instance)
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

# --- Crypto (avoid HPN-only cipher surprises)
Ciphers ${CIPHERS}
MACs ${MACS}

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

  ok "Config written -> ${cfg}"
}

write_systemd_unit() {
  stage "Systemd"
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

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

  runlog "$SVCLOG" "systemctl daemon-reload"
  ok "Unit written -> ${unit}"
}

start_service() {
  stage "Start"
  runlog "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' || true"
  runlog "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  ok "Service status (short):"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,35p' || true

  echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true

  echo
  ok "Recent logs (last 20):"
  journalctl -u "${SERVICE}.service" --no-pager -n 20 || true
}

status_cmd() {
  banner
  stage "Status"
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "Service:"
  systemctl --no-pager --full status "${SERVICE}.service" || true
}

logs_cmd() {
  banner
  stage "Logs"
  ok "Journal (last 200):"
  journalctl -u "${SERVICE}.service" --no-pager -n 200 || true
  echo
  ok "Runtime log: ${RUNTIMELOG}"
  tail -n 200 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  banner
  stage "Uninstall"
  warn "Removing service + config + install prefix"
  warn "NOT removing user 'hpnsshd' and /var/empty (safe)"

  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true

  rm -rf "$SYSCONFDIR" || true
  rm -rf "$PREFIX" || true
  rm -f "$RUNTIMELOG" || true

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET}"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  banner
  detect_ubuntu

  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."
  has_cmd stdbuf || warn "'stdbuf' missing? (coreutils) progress may be less smooth."

  install_deps
  clone_build_install

  stage "Daemon"
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

  stage "Done"
  ok "DONE ✅"
  echo -e "${C_GRAY}Test:${C_RESET}  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  echo -e "${C_GRAY}Logs:${C_RESET}  ${C_BOLD}journalctl -u ${SERVICE} -f${C_RESET}  |  ${C_BOLD}tail -f ${RUNTIMELOG}${C_RESET}"
  echo -e "${C_GRAY}Files:${C_RESET} ${C_BOLD}${LOGDIR}${C_RESET}  (${C_DIM}apt.log git.log build.log install.log service.log${C_RESET})"
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
  PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh WORKDIR=/root/hpn-build LOGDIR=/root/hpn-logs
  MAKE_JOBS=1 HPN_REPO=https://github.com/rapier1/hpn-ssh.git

Security:
  PERMIT_ROOT_LOGIN=prohibit-password|yes
  PASSWORD_AUTH=no|yes
  KBDINT_AUTH=no|yes

Reliability:
  USE_DNS=no
  LOGIN_GRACE_TIME=60
  MAX_AUTH_TRIES=6
  LOG_LEVEL=DEBUG2|VERBOSE

Crypto:
  CIPHERS="chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr"
  MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
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
```0
