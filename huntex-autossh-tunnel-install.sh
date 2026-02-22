#!/usr/bin/env bash
set -Eeuo pipefail

# allow: bash script.sh IP=... PORT=...
for _arg in "$@"; do
  [[ "$_arg" == *=* ]] || continue
  # shellcheck disable=SC2163
  export "$_arg"
done

_have_tty()  { [[ -t 1 ]]; }
_have_tput() { command -v tput >/dev/null 2>&1; }

_full_reset_screen() {
  _have_tty || return 0
  # reset + clear + wipe scrollback
  printf '\e[0m\e[H\e[2J\e[3J' || true
  if _have_tput; then
    tput sgr0 >/dev/null 2>&1 || true
    tput reset >/dev/null 2>&1 || true
    printf '\e[H\e[2J\e[3J' || true
  fi
}

# Colors (Silver + Mustard inspired)
if _have_tty && _have_tput; then
  SILVER="$(tput setaf 7)"
  MUSTARD="$(tput setaf 3)"
  DIM="$(tput dim)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
  REDC="$(tput setaf 1)"
else
  SILVER=""; MUSTARD=""; DIM=""; BOLD=""; RESET=""
  REDC=$'\e[31m'
fi

_hr() { printf "%s\n" "${DIM}${SILVER}────────────────────────────────────────────────────────────${RESET}"; }

_box() {
  local title="${1:-}"
  local subtitle="${2:-}"
  local width=58
  local tpad=$(( width - ${#title} )); (( tpad < 0 )) && tpad=0
  local spad=$(( width - ${#subtitle} )); (( spad < 0 )) && spad=0

  _hr
  printf "%s┌──────────────────────────────────────────────────────────┐%s\n" "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${BOLD}${MUSTARD}${title}${RESET}" \
    "$tpad" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${DIM}${SILVER}${subtitle}${RESET}" \
    "$spad" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s└──────────────────────────────────────────────────────────┘%s\n" "${DIM}${SILVER}" "${RESET}"
  _hr
}

phase() { printf "%s▶%s %s%s%s\n" "${DIM}${SILVER}" "${RESET}" "${BOLD}${MUSTARD}" "$*" "${RESET}"; }
ok()    { printf "%s✅%s  %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*"; }
warn()  { printf "%s⚠️ %s%s\n" "${BOLD}${MUSTARD}" "$*" "${RESET}" >&2; }
die()   { printf "%s❌%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*" >&2; exit 1; }

need_root(){ [[ "${EUID:-0}" -eq 0 ]] || die "Run as root (sudo)."; }

SERVICE="${SERVICE:-huntex-autossh-tunnel}"

IP="${IP:-46.226.162.4}"
PORT="${PORT:-2222}"
USER="${USER:-root}"

LHOST="${LHOST:-0.0.0.0}"
LPORT="${LPORT:-443}"

RHOST="${RHOST:-127.0.0.1}"
RPORT="${RPORT:-443}"

HNAME="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
NAME="${NAME:-iran-${HNAME}}"
KEY="${KEY:-/root/.ssh/id_ed25519_${NAME}}"

SSH_DIR="/root/.ssh"
KNOWN="${SSH_DIR}/known_hosts_${SERVICE}"

ENV_FILE="/etc/default/${SERVICE}"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
SETIP_BIN="/usr/local/bin/huntex-set-ip"
LOGFILE="/var/log/${SERVICE}.log"

install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client ca-certificates coreutils iproute2 procps >/dev/null 2>&1 || true

  # -------------------- LIMIT TUNING (IRAN) --------------------
  # هدف: جلوگیری از لگ/قطعی در بار بالا (FD + backlog + port range + keepalive)
  # کاملاً مینیمال و امن (بدون دستکاری‌های ریسکی مثل tcp_tw_reuse)
  local SYSCTL_FILE="/etc/sysctl.d/99-huntex-tunnel.conf"
  cat >"${SYSCTL_FILE}" <<'EOF'
# HUNTEX tunnel tuning (IRAN)
# raise file descriptor ceilings
fs.file-max = 2097152
fs.nr_open  = 2097152

# accept queue/backlog for bursts
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192

# ephemeral ports for many outgoing conns
net.ipv4.ip_local_port_range = 10240 65535

# quicker cleanup + stable keepalive (helps long-lived tunnels)
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# faster fail on dead paths (reduce long stalls)
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
EOF

  # apply sysctl best-effort (some VPS kernels may not expose all knobs)
  if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
  fi

  # shell/session limits (useful for interactive tools; systemd gets its own LimitNOFILE below)
  local LIMITS_FILE="/etc/security/limits.d/99-huntex-nofile.conf"
  cat >"${LIMITS_FILE}" <<'EOF'
# HUNTEX nofile (IRAN)
*    soft  nofile  1048576
*    hard  nofile  1048576
root soft  nofile  1048576
root hard  nofile  1048576
EOF
  # -----------------------------------------------------------
}

ensure_prereqs(){
  command -v autossh >/dev/null 2>&1 || die "autossh not found"
  command -v ssh >/dev/null 2>&1 || die "ssh not found"
  command -v ssh-keyscan >/dev/null 2>&1 || die "ssh-keyscan not found"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
  command -v ss >/dev/null 2>&1 || die "ss not found (install iproute2)"
}

ensure_key(){
  install -d -m 700 "$SSH_DIR" >/dev/null 2>&1 || true
  [[ -f "$KEY" ]] || die "SSH key not found: $KEY"
  chmod 600 "$KEY" >/dev/null 2>&1 || true
}

write_env(){
  cat >"$ENV_FILE" <<EOF
IP=${IP}
PORT=${PORT}
USER=${USER}
LHOST=${LHOST}
LPORT=${LPORT}
RHOST=${RHOST}
RPORT=${RPORT}
NAME=${NAME}
KEY=${KEY}
KNOWN=${KNOWN}
LOGFILE=${LOGFILE}
EOF
  chmod 600 "$ENV_FILE" >/dev/null 2>&1 || true
  ok "env -> $ENV_FILE"
}

write_setip(){
  cat >"$SETIP_BIN" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="huntex-autossh-tunnel"
ENV_FILE="/etc/default/huntex-autossh-tunnel"

NEW_IP="${1:-}"
[[ -n "$NEW_IP" ]] || { echo "Usage: huntex-set-ip NEW_IP"; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "❌ Env not found: $ENV_FILE"; exit 2; }

if ! [[ "$NEW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "❌ Invalid IP: $NEW_IP"
  exit 3
fi

if grep -q '^IP=' "$ENV_FILE"; then
  sed -i "s/^IP=.*/IP=${NEW_IP}/" "$ENV_FILE"
else
  echo "IP=${NEW_IP}" >> "$ENV_FILE"
fi

systemctl daemon-reload
systemctl restart "${SERVICE}.service" || true

echo "✅ Updated IP to ${NEW_IP} and restarted ${SERVICE}"
echo "check: systemctl --no-pager -l status ${SERVICE}.service | sed -n '1,80p'"
echo "logs : journalctl -u ${SERVICE}.service -n 120 --no-pager"
echo "file : tail -n 120 /var/log/${SERVICE}.log"
EOF
  chmod +x "$SETIP_BIN" >/dev/null 2>&1 || true
  ok "cli -> $SETIP_BIN"
}

write_unit(){
  # IMPORTANT: use ENV variables at runtime (ExecStartPre/ExecStart),
  # do NOT expand them here (avoid quoting hell)
  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=HUNTEX AutoSSH Tunnel (${SERVICE})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}

Environment=AUTOSSH_GATETIME=0

# -------------------- LIMITS (IRAN) --------------------
# prevent FD exhaustion under load; avoid random drops/rejects
LimitNOFILE=1048576
LimitNPROC=1048576
TasksMax=infinity
# ------------------------------------------------------

ExecStartPre=/usr/bin/install -d -m 700 /root/.ssh
ExecStartPre=/usr/bin/install -m 600 /dev/null \${LOGFILE}
ExecStartPre=/usr/bin/rm -f \${KNOWN}
ExecStartPre=/bin/bash -lc '/usr/bin/ssh-keyscan -p "\${PORT}" -H "\${IP}" > "\${KNOWN}" 2>>"\${LOGFILE}"'
ExecStartPre=/usr/bin/chmod 600 \${KNOWN}
ExecStartPre=/usr/bin/test -f \${KEY}

StandardOutput=append:\${LOGFILE}
StandardError=append:\${LOGFILE}

ExecStart=/usr/bin/autossh -M 0 -N \\
  -p "\${PORT}" \\
  -i "\${KEY}" \\
  -L "\${LHOST}:\${LPORT}:\${RHOST}:\${RPORT}" \\
  -o StrictHostKeyChecking=no \\
  -o UserKnownHostsFile="\${KNOWN}" \\
  -o PreferredAuthentications=publickey \\
  -o PubkeyAuthentication=yes \\
  -o PasswordAuthentication=no \\
  -o KbdInteractiveAuthentication=no \\
  -o IdentitiesOnly=yes \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=15 \\
  -o ServerAliveCountMax=3 \\
  -o TCPKeepAlive=yes \\
  -o ConnectTimeout=7 \\
  -o ConnectionAttempts=1 \\
  -o LogLevel=ERROR \\
  "\${USER}@\${IP}"

Restart=always
RestartSec=2
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF
  ok "unit -> $UNIT_FILE"
}

_is_listening_local(){
  ss -lntH "sport = :${LPORT}" | grep -q .
}

_fail_minimal(){
  # bold + red
  printf "%s%s❌  FAILED%s\n" "${BOLD}" "${REDC}" "${RESET}"
  echo "check: systemctl --no-pager -l status ${SERVICE}.service | sed -n '1,80p'"
  echo "logs : journalctl -u ${SERVICE}.service -n 120 --no-pager"
  echo "file : tail -n 120 ${LOGFILE}"
  exit 5
}

enable_start_and_verify(){
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "${SERVICE}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE}.service" >/dev/null 2>&1 || _fail_minimal

  sleep 1
  systemctl is-active --quiet "${SERVICE}.service" || _fail_minimal
  _is_listening_local || _fail_minimal

  printf "%s✅%s  OK  %s%s:%s%s → %s%s:%s%s  via  %s%s@%s:%s%s\n" \
    "${BOLD}${MUSTARD}" "${RESET}" \
    "${SILVER}" "${LHOST}" "${MUSTARD}" "${LPORT}" \
    "${SILVER}" "${RHOST}" "${MUSTARD}" "${RPORT}" \
    "${SILVER}" "${USER}" "${IP}" "${PORT}" "${RESET}"
}

main(){
  need_root
  _full_reset_screen

  _box "HUNTEX AutoSSH Tunnel" "Silver + Mustard (Install + Verify)"
  printf "%s•%s OUTSIDE: %s%s@%s:%s%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${SILVER}${USER}${RESET}" "${SILVER}" "${IP}" "${MUSTARD}" "${PORT}${RESET}"
  printf "%s•%s FORWARD: %s%s:%s%s → %s%s:%s%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${SILVER}${LHOST}${RESET}" "${MUSTARD}" "${LPORT}${RESET}" \
    "${SILVER}${RHOST}${RESET}" "${MUSTARD}" "${RPORT}${RESET}"
  _hr

  phase "Phase 1 — Packages"
  install_pkgs
  ok "packages ready"

  phase "Phase 2 — Prereqs"
  ensure_prereqs
  ok "prereqs OK"

  phase "Phase 3 — SSH key"
  ensure_key
  ok "key OK"

  phase "Phase 4 — Env + CLI"
  write_env
  write_setip

  phase "Phase 5 — systemd unit"
  write_unit

  phase "Phase 6 — Start + Verify"
  enable_start_and_verify

  _hr
  echo "check: systemctl --no-pager -l status ${SERVICE}.service | sed -n '1,80p'"
  echo "logs : journalctl -u ${SERVICE}.service -n 120 --no-pager"
  echo "file : tail -n 120 ${LOGFILE}"
  echo "ip   : huntex-set-ip NEW_IP"
}

main "$@"
