#!/usr/bin/env bash
set -Eeuo pipefail

for _arg in "$@"; do
  [[ "$_arg" == *=* ]] || continue
  export "$_arg"
done

_have_tty(){ [[ -t 1 ]]; }

_full_reset_screen(){
  _have_tty || return 0
  printf '\e[0m\e[H\e[2J\e[3J' >/dev/null 2>&1 || true
}

_have_tput(){ command -v tput >/dev/null 2>&1; }

if _have_tty && _have_tput; then
  SILVER="$(tput setaf 7)"
  MUSTARD="$(tput setaf 3)"
  DIM="$(tput dim)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  SILVER=""; MUSTARD=""; DIM=""; BOLD=""; RESET=""
fi

_hr(){ printf "%s\n" "${DIM}${SILVER}────────────────────────────────────────────────────────────${RESET}"; }
_pad(){ printf '%*s' "$1" ''; }

_box(){
  local title="${1:-}" subtitle="${2:-}" width=58
  local tpad=$(( width - ${#title} )); ((tpad<0)) && tpad=0
  local spad=$(( width - ${#subtitle} )); ((spad<0)) && spad=0
  _hr
  printf "%s┌──────────────────────────────────────────────────────────┐%s\n" "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%s%s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${BOLD}${MUSTARD}${title}${RESET}" \
    "$(_pad "$tpad")" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${DIM}${SILVER}${subtitle}${RESET}" \
    "$(_pad "$spad")" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s└──────────────────────────────────────────────────────────┘%s\n" "${DIM}${SILVER}" "${RESET}"
  _hr
}

phase(){ printf "%s▶%s %s%s%s\n" "${DIM}${SILVER}" "${RESET}" "${BOLD}${MUSTARD}" "$*" "${RESET}"; }
ok(){    printf "%s✅%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*"; }
die(){   printf "%sFAILED%s\n" "${BOLD}${MUSTARD}" "${RESET}" >&2; [[ -n "${1:-}" ]] && printf "%s\n" "$1" >&2; exit 1; }

need_root(){ [[ "${EUID:-0}" -eq 0 ]] || die "Run as root (sudo)."; }

SERVICE="${SERVICE:-huntex-autossh-tunnel}"

MODE="${MODE:-L}"
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

validate_mode(){
  case "${MODE}" in
    L|R) ;;
    *) die "MODE must be L or R (got: ${MODE})" ;;
  esac
}

install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client ca-certificates coreutils >/dev/null 2>&1 || true
}

ensure_prereqs(){
  command -v autossh >/dev/null 2>&1 || die "autossh not found"
  command -v ssh >/dev/null 2>&1 || die "ssh not found"
  command -v ssh-keyscan >/dev/null 2>&1 || die "ssh-keyscan not found"
  command -v timeout >/dev/null 2>&1 || die "timeout not found"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
  command -v ss >/dev/null 2>&1 || true
}

ensure_key(){
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" || true
  [[ -f "$KEY" ]] || die "SSH key not found: $KEY"
  chmod 600 "$KEY" || true
}

write_env(){
  cat >"$ENV_FILE" <<EOF
MODE=${MODE}
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
  chmod 600 "$ENV_FILE" || true
  ok "env -> $ENV_FILE"
}

write_setip(){
  cat >"$SETIP_BIN" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
SERVICE="${SERVICE}"
ENV_FILE="${ENV_FILE}"

NEW_IP="\${1:-}"
[[ -n "\$NEW_IP" ]] || { echo "Usage: huntex-set-ip NEW_IP"; exit 1; }
[[ -f "\$ENV_FILE" ]] || { echo "Env not found: \$ENV_FILE"; exit 2; }

if ! [[ "\$NEW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\$ ]]; then
  echo "Invalid IP: \$NEW_IP"
  exit 3
fi

if grep -q '^IP=' "\$ENV_FILE"; then
  sed -i "s/^IP=.*/IP=\${NEW_IP}/" "\$ENV_FILE"
else
  echo "IP=\${NEW_IP}" >> "\$ENV_FILE"
fi

systemctl daemon-reload
systemctl restart "\${SERVICE}.service"
sleep 1
systemctl --no-pager --full status "\${SERVICE}.service" | sed -n '1,18p' || true
EOF
  chmod +x "$SETIP_BIN" || true
  ok "cli -> $SETIP_BIN"
}

write_unit(){
  local DESC
  if [[ "${MODE}" = "L" ]]; then
    DESC="${LHOST}:${LPORT} -> ${RHOST}:${RPORT}"
  else
    DESC="REMOTE ${RHOST}:${RPORT} -> LOCAL ${LHOST}:${LPORT}"
  fi

  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=HUNTEX Turbo AutoSSH Tunnel (${DESC} via ${USER}@${IP}:${PORT})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}

Environment=AUTOSSH_GATETIME=0
Environment=AUTOSSH_LOGLEVEL=0

ExecStartPre=/bin/bash -lc 'mkdir -p /root/.ssh; chmod 700 /root/.ssh; : > "\${LOGFILE}"; chmod 600 "\${LOGFILE}" || true'
ExecStartPre=/bin/bash -lc 'rm -f "\${KNOWN}" || true; timeout 7 ssh-keyscan -p "\${PORT}" -H "\${IP}" > "\${KNOWN}" 2>/dev/null || true; chmod 600 "\${KNOWN}" || true'
ExecStartPre=/bin/bash -lc '[[ -f "\${KEY}" ]] || { echo "Missing KEY: \${KEY}" >> "\${LOGFILE}"; exit 3; }'
ExecStartPre=/bin/bash -lc 'timeout 10 ssh -p "\${PORT}" -i "\${KEY}" "\${USER}@\${IP}" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile="\${KNOWN}" -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=7 -o ConnectionAttempts=1 "echo AUTH_OK" >> "\${LOGFILE}" 2>&1 || { echo "Key auth failed" >> "\${LOGFILE}"; exit 4; }'

ExecStart=/bin/bash -lc '
  if [[ "\${MODE}" = "L" ]]; then
    FWD="-L \${LHOST}:\${LPORT}:\${RHOST}:\${RPORT}"
  else
    FWD="-R \${RHOST}:\${RPORT}:\${LHOST}:\${LPORT}"
  fi
  exec /usr/bin/autossh -M 0 -N \
    -p "\${PORT}" -i "\${KEY}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile="\${KNOWN}" \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o IdentitiesOnly=yes \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -o TCPKeepAlive=yes \
    -o ConnectTimeout=7 \
    -o ConnectionAttempts=1 \
    "\${FWD}" "\${USER}@\${IP}" >> "\${LOGFILE}" 2>&1
'

Restart=always
RestartSec=2
TimeoutStartSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
  ok "unit -> $UNIT_FILE"
}

_is_listening_local(){
  command -v ss >/dev/null 2>&1 || return 1
  ss -lntH "sport = :${LPORT}" | grep -q .
}

_fail_minimal(){
  local start_ts="$1"
  printf "%sFAILED%s\n" "${BOLD}${MUSTARD}" "${RESET}" >&2
  journalctl -u "${SERVICE}.service" -b --since "${start_ts}" -n 25 --no-pager 2>/dev/null || true
  tail -n 40 "${LOGFILE}" 2>/dev/null || true
  printf "\n%sCheck:%s systemctl status %s.service\n" "${DIM}${SILVER}" "${RESET}" "${SERVICE}" >&2
  printf "%sLogs:%s journalctl -u %s.service -n 200 --no-pager\n" "${DIM}${SILVER}" "${RESET}" "${SERVICE}" >&2
  printf "%sFile:%s tail -n 200 %s\n" "${DIM}${SILVER}" "${RESET}" "${LOGFILE}" >&2
  exit 5
}

enable_start(){
  local START_TS
  START_TS="$(date +'%Y-%m-%d %H:%M:%S')"

  systemctl daemon-reload
  systemctl enable "${SERVICE}.service" >/dev/null 2>&1 || true

  systemctl restart "${SERVICE}.service" >/dev/null 2>&1 || _fail_minimal "${START_TS}"
  sleep 1

  systemctl is-active --quiet "${SERVICE}.service" || _fail_minimal "${START_TS}"

  if [[ "${MODE}" = "L" ]]; then
    if command -v ss >/dev/null 2>&1; then
      _is_listening_local || _fail_minimal "${START_TS}"
    fi
    ok "listening -> ${LHOST}:${LPORT}"
  else
    ok "started (MODE=R)"
  fi
}

main(){
  need_root
  _full_reset_screen

  _box "HUNTEX Turbo AutoSSH Tunnel" "Silver + Mustard (Install + Verify)"
  printf "%s•%s OUTSIDE: %s@%s:%s\n" "${DIM}${SILVER}" "${RESET}" "${USER}" "${IP}" "${PORT}"
  printf "%s•%s MODE: %s  %s:%s → %s:%s\n" "${DIM}${SILVER}" "${RESET}" "${MODE}" "${LHOST}" "${LPORT}" "${RHOST}" "${RPORT}"
  _hr

  phase "Phase 0 — Validate"; validate_mode; ok "mode OK"
  phase "Phase 1 — Packages"; install_pkgs; ok "packages ready"
  phase "Phase 2 — Prerequisites"; ensure_prereqs; ok "prereqs OK"
  phase "Phase 3 — SSH key"; ensure_key; ok "key OK"
  phase "Phase 4 — Env + CLI"; write_env; write_setip
  phase "Phase 5 — systemd unit"; write_unit
  phase "Phase 6 — Start + Verify"; enable_start

  _hr
  ok "DONE"
  printf "%sLogs:%s %s\n" "${DIM}${SILVER}" "${RESET}" "${LOGFILE}"
  printf "%sCheck:%s systemctl status %s.service\n" "${DIM}${SILVER}" "${RESET}" "${SERVICE}"
  printf "%sLogs:%s journalctl -u %s.service -n 200 --no-pager\n" "${DIM}${SILVER}" "${RESET}" "${SERVICE}"
}

main "$@"
