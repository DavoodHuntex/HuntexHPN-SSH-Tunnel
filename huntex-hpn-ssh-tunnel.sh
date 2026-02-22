#!/usr/bin/env bash
set -Eeuo pipefail

: <<'TXT'
============================================================

HUNTEX HPN-SSH-Tunnel (STABLE / LOW-ERROR edition)

Builds & installs HPN-SSH into: /usr/local/hpnssh
Runs hpnsshd on PORT (default 2222) as separate systemd service
Keeps system sshd on port 22 untouched
Uses PASSWORD + KBDINT auth by default (lowest error)
Raises limits (MaxStartups/NOFILE/backlog) for many tunnels

============================================================
TXT

APP_NAME="HUNTEX-HPN-SSH-Tunnel"
APP_VER="3.2.1-stable"   # bumped (same logic, just fixes)

: <<'TXT'
---

Defaults (override via env)

---
TXT

PORT="${PORT:-2222}"
SERVICE="${SERVICE:-hpnsshd}"
PREFIX="${PREFIX:-/usr/local/hpnssh}"
SYSCONFDIR="${SYSCONFDIR:-/etc/hpnssh}"
WORKDIR="${WORKDIR:-/root/hpn-build}"
LOGDIR="${LOGDIR:-/root/hpn-logs}"
HPN_REPO="${HPN_REPO:-https://github.com/rapier1/hpn-ssh.git}"
MAKE_JOBS="${MAKE_JOBS:-1}"

: <<'TXT'
---

Auth defaults (lowest error)

---
TXT

PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-yes}"
PASSWORD_AUTH="${PASSWORD_AUTH:-yes}"
KBDINT_AUTH="${KBDINT_AUTH:-yes}"   # keep this ON (your working case)

: <<'TXT'
---

Reliability / Limits (raised)

---
TXT

USE_DNS="${USE_DNS:-no}"

# IMPORTANT: these defaults are now SAFE for 2c/4GB under reconnect storms
# You can override via env if you want.
LOGIN_GRACE_TIME="${LOGIN_GRACE_TIME:-60}"   # was 300
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-10}"       # was 50
LOG_LEVEL="${LOG_LEVEL:-ERROR}"

: <<'TXT'
IMPORTANT: reduce annoying drops during reconnect storms
(values are now "safe-high" not "crazy-high")
TXT

# was 2000:30:8000 -> can explode RAM/CPU under storms
MAX_STARTUPS="${MAX_STARTUPS:-200:30:800}"

# was 500 -> per-source storms eat the box alive
PER_SOURCE_MAX_STARTUPS="${PER_SOURCE_MAX_STARTUPS:-30}"

PER_SOURCE_NETBLOCK_SIZE="${PER_SOURCE_NETBLOCK_SIZE:-32}"
PER_SOURCE_PENALTIES="${PER_SOURCE_PENALTIES:-no}"

: <<'TXT'
Keepalive (balanced)
TXT

CLIENT_ALIVE_INTERVAL="${CLIENT_ALIVE_INTERVAL:-30}"
CLIENT_ALIVE_COUNTMAX="${CLIENT_ALIVE_COUNTMAX:-6}"

: <<'TXT'
systemd limits
TXT

LIMIT_NOFILE="${LIMIT_NOFILE:-1048576}"
TASKS_MAX="${TASKS_MAX:-infinity}"

: <<'TXT'
Optional: disable fail2ban/hosts.deny interference (security not important)
TXT

DISABLE_FAIL2BAN="${DISABLE_FAIL2BAN:-1}"
DISABLE_HOSTS_DENY="${DISABLE_HOSTS_DENY:-1}"

: <<'TXT'
HPN + compatible ciphers (applied only if daemon accepts it)
TXT

CIPHERS_DEFAULT="chacha20-poly1305-mt@hpnssh.org,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr"
CIPHERS="${CIPHERS:-$CIPHERS_DEFAULT}"

: <<'TXT'
---

Colors / UI

---
TXT

C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_BLUE=$'\033[38;5;39m'
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
  echo -e "${C_RESET}${C_GRAY}HPN-SSH-Tunnel (stable/low-error)${C_RESET}\n"
  echo -e "${C_GRAY}${APP_NAME} v${APP_VER} | Port: ${PORT} | Service: ${SERVICE}${C_RESET}"
  hr
}

: <<'TXT'
---

Logs

---
TXT

APTLOG="$LOGDIR/apt.log"
GITLOG="$LOGDIR/git.log"
BLDLOG="$LOGDIR/build.log"
INSLOG="$LOGDIR/install.log"
SVCLOG="$LOGDIR/service.log"
RUNTIMELOG="/var/log/${SERVICE}.log"

_stage() { echo; echo -e "${C_BOLD}$1${C_RESET}"; hr; }

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
    local szh; szh="$(_fmt_bytes "$sz")"

    local last=""
    if [[ -f "$logfile" ]]; then
      last="$(tail -n 1 "$logfile" 2>/dev/null || true)"
    fi
    last="${last//$'\r'/}"
    if (( ${#last} > 110 )); then last="…${last: -110}"; fi

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
  for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  echo "/usr/lib/openssh/sftp-server"
}

apply_sysctl_tuning() {
  _stage "Kernel tuning (safe, for many tunnels)"
  local f="/etc/sysctl.d/99-huntex-hpnsshd.conf"
  cat >"$f" <<'EOF'
# Huntex HPNSSHD safe TCP tuning (helps bursts / backlog)
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Keepalive (safe)
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
EOF
  sysctl --system >/dev/null 2>&1 || true
  ok "sysctl applied -> $f"
}

disable_fail2ban_hostsdeny_best_effort() {
  _stage "Best-effort: disable fail2ban/hosts.deny interference"
  if (( DISABLE_FAIL2BAN == 1 )); then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      warn "fail2ban active -> stopping+disabling (security not important)"
      systemctl stop fail2ban 2>/dev/null || true
      systemctl disable fail2ban 2>/dev/null || true
      ok "fail2ban disabled"
    else
      ok "fail2ban not active"
    fi
  else
    ok "DISABLE_FAIL2BAN=0 (skipped)"
  fi

  if (( DISABLE_HOSTS_DENY == 1 )); then
    if [[ -f /etc/hosts.deny ]] && grep -qE '(^|\s)sshd(:|\s)' /etc/hosts.deny 2>/dev/null; then
      warn "hosts.deny has sshd rules -> commenting (best-effort)"
      cp /etc/hosts.deny /etc/hosts.deny.bak 2>/dev/null || true
      sed -i 's/^\(.*sshd.*\)$/# \1 # disabled by HPN-SSH/g' /etc/hosts.deny 2>/dev/null || true
      ok "hosts.deny updated"
    else
      ok "hosts.deny ok / not present"
    fi
  else
    ok "DISABLE_HOSTS_DENY=0 (skipped)"
  fi
}

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
       libkrb5-dev libcap-ng-dev iproute2 procps"
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
  warn "Build may take several minutes. Live progress is shown."
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

: <<'TXT'
---

Option probing (prevents "Unsupported option ..." errors)

---
TXT

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

  cat >"$tmp" <<EOF
Port 65534
ListenAddress 127.0.0.1
HostKey ${hk}
${opt_line}
EOF

  "$bin" -t -f "$tmp" >/dev/null 2>&1
  local rc=$?
  rm -f "$tmp"
  return $rc
}

add_if_supported() {
  local bin="$1"; shift
  local line="$*"
  if supports_option "$bin" "$line"; then
    echo "$line"
  fi
}

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set before write_config()"

  _stage "Config (validated only)"
  local SFTP_SERVER; SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  local auth_block misc_block cipher_line

  # OPT: low-overhead knobs (only if daemon accepts)
  # FIX: Do NOT emit UsePAM at all (some HPN builds don't support it)
  auth_block="$(
    add_if_supported "$hpnsshd_bin" "PermitRootLogin ${PERMIT_ROOT_LOGIN}"
    add_if_supported "$hpnsshd_bin" "PasswordAuthentication ${PASSWORD_AUTH}"
    add_if_supported "$hpnsshd_bin" "KbdInteractiveAuthentication ${KBDINT_AUTH}"

    add_if_supported "$hpnsshd_bin" "GSSAPIAuthentication no"
    add_if_supported "$hpnsshd_bin" "KerberosAuthentication no"
    add_if_supported "$hpnsshd_bin" "X11Forwarding no"
    add_if_supported "$hpnsshd_bin" "AllowAgentForwarding no"
    add_if_supported "$hpnsshd_bin" "PermitTunnel no"
  )"

  misc_block="$(
    add_if_supported "$hpnsshd_bin" "UseDNS ${USE_DNS}"
    add_if_supported "$hpnsshd_bin" "LoginGraceTime ${LOGIN_GRACE_TIME}"
    add_if_supported "$hpnsshd_bin" "MaxAuthTries ${MAX_AUTH_TRIES}"
    add_if_supported "$hpnsshd_bin" "LogLevel ${LOG_LEVEL}"

    add_if_supported "$hpnsshd_bin" "MaxStartups ${MAX_STARTUPS}"
    add_if_supported "$hpnsshd_bin" "PerSourceMaxStartups ${PER_SOURCE_MAX_STARTUPS}"
    add_if_supported "$hpnsshd_bin" "PerSourceNetBlockSize ${PER_SOURCE_NETBLOCK_SIZE}"
    add_if_supported "$hpnsshd_bin" "PerSourcePenalties ${PER_SOURCE_PENALTIES}"
  )"

  cipher_line="$(add_if_supported "$hpnsshd_bin" "Ciphers ${CIPHERS}" || true)"

  cat > "$cfg" <<EOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - STABLE / LOW-ERROR CONFIG (validated)
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Auth (validated)
${auth_block}

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PrintMotd no
PrintLastLog no

# --- Reliability (validated)
${misc_block}

# --- Crypto (only if accepted)
${cipher_line}

# --- Keepalive
TCPKeepAlive yes
ClientAliveInterval ${CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${CLIENT_ALIVE_COUNTMAX}

Compression no
AllowTcpForwarding yes
GatewayPorts yes

Subsystem sftp ${SFTP_SERVER}
EOF

  # hard cleanup: if someone previously had UsePAM in this file, remove it
  sed -i '/^\s*UsePAM\s\+/Id' "$cfg" 2>/dev/null || true

  if ! "$hpnsshd_bin" -t -f "$cfg" >/dev/null 2>&1; then
    warn "Config test failed. Error:"
    "$hpnsshd_bin" -t -f "$cfg" 2>&1 | tail -n 120 || true
    die "hpnsshd config invalid."
  fi

  ok "Config written & validated -> ${cfg}"
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"
  local ovr_dir="/etc/systemd/system/${SERVICE}.service.d"
  local ovr="${ovr_dir}/override.conf"

  _stage "Systemd"
  cat > "$unit" <<EOF
[Unit]
Description=HPN-SSH server (separate instance on port ${PORT})
After=network.target

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

ExecStartPre=${hpnsshd_bin} -t -f ${cfg}
ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p "$ovr_dir"
  cat >"$ovr" <<EOF
[Service]
LimitNOFILE=${LIMIT_NOFILE}
TasksMax=${TASKS_MAX}
EOF

  _run_stage "daemon-reload" "$SVCLOG" "systemctl daemon-reload"
  ok "Unit installed -> ${unit}"
  ok "Override -> ${ovr} (LimitNOFILE=${LIMIT_NOFILE}, TasksMax=${TASKS_MAX})"
}

cleanup_existing_unit() {
  _stage "Cleaning existing service (best-effort)"
  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true
  ok "Service cleanup done"
}

start_service() {
  _stage "Service"
  _run_stage "enable+start" "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true

  echo
  ok "Last logs:"
  journalctl -u "${SERVICE}.service" --no-pager -n 40 || true
}

restart_only_cmd() {
  banner
  _stage "Restart-only (no rebuild)"
  local hpnsshd_bin
  hpnsshd_bin="$(locate_hpnsshd)"
  ok "Using daemon: ${hpnsshd_bin}"

  ensure_privsep_user
  ensure_host_keys

  HPNSSHD_BIN="$hpnsshd_bin"
  write_config
  write_systemd_unit "$hpnsshd_bin"

  _run_stage "restart" "$SVCLOG" "systemctl restart '${SERVICE}.service'"
  ok "Restarted ${SERVICE} successfully"
  echo
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "UsePAM check:"
  grep -n 'UsePAM' "${SYSCONFDIR}/hpnsshd_config" >/dev/null 2>&1 && warn "UsePAM still present (unexpected)" || ok "UsePAM: REMOVED ✅"
}

status_cmd() {
  banner
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "Service:"
  systemctl --no-pager --full status "${SERVICE}.service" || true
  echo
  ok "Limits:"
  systemctl show "${SERVICE}.service" -p LimitNOFILE -p TasksMax || true
  echo
  ok "Config pressure knobs:"
  grep -nE 'MaxStartups|PerSourceMaxStartups|LoginGraceTime|MaxAuthTries' "${SYSCONFDIR}/hpnsshd_config" 2>/dev/null || true
}

logs_cmd() {
  banner
  ok "Journal (last 250 lines):"
  journalctl -u "${SERVICE}.service" --no-pager -n 250 || true
  echo
  ok "Runtime log: ${RUNTIMELOG}"
  tail -n 200 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  banner
  warn "Uninstalling ${APP_NAME}..."
  cleanup_existing_unit
  rm -f "/etc/systemd/system/${SERVICE}.service" 2>/dev/null || true
  rm -rf "/etc/systemd/system/${SERVICE}.service.d" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  rm -rf "$SYSCONFDIR" 2>/dev/null || true
  rm -rf "$PREFIX" 2>/dev/null || true
  rm -f "$RUNTIMELOG" 2>/dev/null || true
  rm -f /etc/sysctl.d/99-huntex-hpnsshd.conf 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET}"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."

  disable_fail2ban_hostsdeny_best_effort
  apply_sysctl_tuning

  # If already installed, do restart-only (fast path)
  if [[ -x "${PREFIX}/sbin/hpnsshd" ]]; then
    warn "HPN-SSH already installed -> applying config + restarting (no rebuild)"
    restart_only_cmd
    return 0
  fi

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
  ok "Low-error behavior enabled:"
  ok "  - PasswordAuthentication yes"
  ok "  - KbdInteractiveAuthentication yes"
  ok "  - SAFE MaxStartups / PerSourceMaxStartups / LoginGraceTime / MaxAuthTries"
  ok "  - LimitNOFILE=${LIMIT_NOFILE}"
  echo
  echo -e "${C_GRAY}Useful:${C_RESET}"
  echo -e "  ${C_DIM}systemctl status ${SERVICE} --no-pager -l${C_RESET}"
  echo -e "  ${C_DIM}journalctl -u ${SERVICE} -n 200 --no-pager${C_RESET}"
  echo -e "  ${C_DIM}tail -n 200 ${RUNTIMELOG}${C_RESET}"
  hr
}

usage() {
  banner
  cat <<USAGE
Usage:
  sudo ./${0##*/} install
  sudo ./${0##*/} restart
  sudo ./${0##*/} status
  sudo ./${0##*/} logs
  sudo ./${0##*/} uninstall

Env overrides (main):
  PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh MAKE_JOBS=1
  PASSWORD_AUTH=yes KBDINT_AUTH=yes PERMIT_ROOT_LOGIN=yes

  # pressure knobs (override if you insist)
  LOGIN_GRACE_TIME=60 MAX_AUTH_TRIES=10 LOG_LEVEL=ERROR
  MAX_STARTUPS="200:30:800" PER_SOURCE_MAX_STARTUPS=30
  PER_SOURCE_NETBLOCK_SIZE=32 PER_SOURCE_PENALTIES=no

  LIMIT_NOFILE=1048576 TASKS_MAX=infinity
  DISABLE_FAIL2BAN=1 DISABLE_HOSTS_DENY=1
USAGE
}

main() {
  local cmd="${
