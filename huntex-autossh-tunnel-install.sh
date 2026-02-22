#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# HUNTEX Turbo AutoSSH Tunnel (MINIMAL+)
# - Iran server runs autossh client
# - Connects to OUTSIDE HPN-SSH: IP:PORT (default 2222)
# - MODE=L (default): local forward  (-L)  => IRAN listens, forwards to OUTSIDE target
# - MODE=R           : reverse forward (-R) => OUTSIDE listens, forwards to IRAN target
# - Uses key: /root/.ssh/id_ed25519_iran-$(hostname -s)
# - systemd service + env file + CLI huntex-set-ip
# - Fixes: old-log spam + unit escape errors + ensures restart applies new mode
# ============================================================

# -------------------- UI (Silver + Mustard) --------------------
_have_tty()  { [[ -t 1 ]]; }
_have_tput() { command -v tput >/dev/null 2>&1; }

_full_reset_screen() {
  if _have_tty; then
    # Termius-friendly reset (avoid RIS \033c)
    if _have_tput; then
      tput sgr0 >/dev/null 2>&1 || true
      tput reset >/dev/null 2>&1 || true
    else
      printf '\e[0m\e[H\e[2J'
    fi
    # wipe scrollback too
    printf '\e[3J\e[H\e[2J'
  fi
}

if _have_tty && _have_tput; then
  SILVER="$(tput setaf 7)"
  MUSTARD="$(tput setaf 3)"
  DIM="$(tput dim)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  SILVER=""; MUSTARD=""; DIM=""; BOLD=""; RESET=""
fi

# Backward-compatible color vars (avoid unbound variable with -u)
RED="${RED:-${MUSTARD}}"
GREEN="${GREEN:-${MUSTARD}}"
YELLOW="${YELLOW:-${MUSTARD}}"
CYAN="${CYAN:-${SILVER}}"

_hr() { printf "%s\n" "${DIM}${SILVER}────────────────────────────────────────────────────────────${RESET}"; }
_pad() { printf '%*s' "$1" ''; }

_box() {
  local title="${1:-No Title}"
  local subtitle="${2:-No Subtitle}"
  local width=58

  local tpad=$(( width - ${#title} ))
  local spad=$(( width - ${#subtitle} ))
  (( tpad < 0 )) && tpad=0
  (( spad < 0 )) && spad=0

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

phase() { printf "%s▶%s %s%s%s\n" "${DIM}${SILVER}" "${RESET}" "${BOLD}${MUSTARD}" "$*" "${RESET}"; }
ok()    { printf "%s✅%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*"; }
warn()  { printf "%s⚠️ %s%s\n" "${BOLD}${MUSTARD}" "$*" "${RESET}" >&2; }
die()   { printf "%s❌ %s%s\n" "${BOLD}${MUSTARD}" "$*" "${RESET}" >&2; exit 1; }
log()   { printf "%s[%s] %s%s\n" "${DIM}${SILVER}" "$(date +'%F %T')" "${RESET}" "$*"; }

need_root(){ [[ "${EUID:-0}" -eq 0 ]] || die "Run as root (sudo)."; }

# -------------------- Original Script --------------------
SERVICE="${SERVICE:-huntex-autossh-tunnel}"

# Forward mode: L or R
MODE="${MODE:-L}"   # L=local forward (-L), R=reverse forward (-R)

# OUTSIDE (HPN-SSH server)
IP="${IP:-46.226.162.4}"
PORT="${PORT:-2222}"
USER="${USER:-root}"

# LOCAL endpoint (on IRAN)
LHOST="${LHOST:-0.0.0.0}"
LPORT="${LPORT:-443}"

# REMOTE endpoint (on OUTSIDE)
RHOST="${RHOST:-127.0.0.1}"
RPORT="${RPORT:-443}"

# Key naming: iran-[hostname]
HNAME="$(hostname -s 2>/dev/null || hostname || echo unknown)"
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
    *) die "MODE must be L or R (got: ${MODE})";;
  esac
}

install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client ca-certificates coreutils >/dev/null 2>&1 || true
}

ensure_prereqs(){
  command -v autossh >/dev/null 2>&1 || die "autossh not found (apt install failed?)"
  command -v ssh >/dev/null 2>&1 || die "ssh not found (openssh-client missing?)"
  command -v ssh-keyscan >/dev/null 2>&1 || die "ssh-keyscan missing (openssh-client broken?)"
  command -v timeout >/dev/null 2>&1 || die "timeout missing (coreutils missing?)"
  command -v systemctl >/dev/null 2>&1 || die "systemd required (systemctl not found)"
  command -v ss >/dev/null 2>&1 || warn "ss not found (install iproute2) — some checks will be skipped."
}

ensure_key(){
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" || true
  [[ -f "$KEY" ]] || die "SSH key not found: $KEY (run key-setup first so this key exists + is authorized on OUTSIDE)"
  chmod 600 "$KEY" || true
}

write_env(){
  cat >"$ENV_FILE" <<EOF
# HUNTEX AutoSSH env for ${SERVICE}
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
  ok "Wrote env -> $ENV_FILE"
}

write_setip(){
  cat >"$SETIP_BIN" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="${SERVICE}"
ENV_FILE="${ENV_FILE}"

NEW_IP="\${1:-}"
if [[ -z "\$NEW_IP" ]]; then
  echo "Usage: huntex-set-ip NEW_IP"
  exit 1
fi

[[ -f "\$ENV_FILE" ]] || { echo "❌ Env file not found: \$ENV_FILE"; exit 2; }

if ! [[ "\$NEW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\$ ]]; then
  echo "❌ Invalid IP format: \$NEW_IP"
  exit 3
fi

START_TS="\$(date +'%Y-%m-%d %H:%M:%S')"

echo "→ Updating IP to: \$NEW_IP"
if grep -q '^IP=' "\$ENV_FILE"; then
  sed -i "s/^IP=.*/IP=\${NEW_IP}/" "\$ENV_FILE"
else
  echo "IP=\${NEW_IP}" >> "\$ENV_FILE"
fi

echo "→ Restarting \${SERVICE}.service ..."
systemctl daemon-reload
systemctl restart "\${SERVICE}.service"
sleep 1

echo
systemctl --no-pager --full status "\${SERVICE}.service" | sed -n '1,28p' || true

MODE="\$(grep -E '^MODE=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
LPORT="\$(grep -E '^LPORT=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
RPORT="\$(grep -E '^RPORT=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
USER="\$(grep -E '^USER=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
IP="\$(grep -E '^IP=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
PORT="\$(grep -E '^PORT=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
KEY="\$(grep -E '^KEY=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"
KNOWN="\$(grep -E '^KNOWN=' "\$ENV_FILE" | head -n1 | cut -d= -f2 || true)"

echo
if [[ "\${MODE:-L}" = "L" ]]; then
  if command -v ss >/dev/null 2>&1 && ss -lntH "sport = :\${LPORT}" | grep -q .; then
    echo "✅ Tunnel is listening locally on \${LHOST}:\${LPORT}"
  else
    echo "❌ Tunnel not listening locally on \${LHOST}:\${LPORT}"
    journalctl -u "\${SERVICE}.service" -b --since "\${START_TS}" -n 200 --no-pager || true
    exit 4
  fi
else
  for i in 1 2 3 4 5; do
    if timeout 10 ssh -p "\${PORT}" -i "\${KEY}" "\${USER}@\${IP}" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="\${KNOWN}" \
      -o PreferredAuthentications=publickey \
      -o PubkeyAuthentication=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o IdentitiesOnly=yes \
      "command -v ss >/dev/null 2>&1 && ss -lntH \\"sport = :\${RPORT}\\" | grep -q LISTEN" >/dev/null 2>&1; then
      echo "✅ Tunnel is listening on remote OUTSIDE port \${RPORT}"
      exit 0
    fi
    sleep 2
  done

  echo "❌ Tunnel not listening on remote OUTSIDE port \${RPORT}"
  journalctl -u "\${SERVICE}.service" -b --since "\${START_TS}" -n 200 --no-pager || true
  exit 4
fi
EOF
  chmod +x "$SETIP_BIN" || true
  ok "Installed CLI -> $SETIP_BIN  (use: huntex-set-ip x.x.x.x)"
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
Description=HUNTEX Turbo AutoSSH Tunnel (MODE=${MODE} | ${DESC} via ${USER}@${IP}:${PORT})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}

Environment=AUTOSSH_GATETIME=0
Environment=AUTOSSH_POLL=10
Environment=AUTOSSH_FIRST_POLL=5
Environment=AUTOSSH_LOGLEVEL=0

ExecStartPre=/bin/bash -lc 'mkdir -p /root/.ssh; chmod 700 /root/.ssh; : > "${LOGFILE}"; chmod 600 "${LOGFILE}" || true'
ExecStartPre=/bin/bash -lc 'if [[ "${MODE}" = "L" ]] && command -v ss >/dev/null 2>&1; then ss -lntH "sport = :${LPORT}" | grep -q . && { echo "Port ${LPORT} already in use" >> "${LOGFILE}"; exit 1; } || true; fi'
ExecStartPre=/bin/bash -lc 'timeout 5 bash -lc "cat </dev/null >/dev/tcp/${IP}/${PORT}" >/dev/null 2>&1 || { echo "TCP ${IP}:${PORT} unreachable" >> "${LOGFILE}"; exit 2; }'
ExecStartPre=/bin/bash -lc 'rm -f "${KNOWN}" || true; timeout 7 ssh-keyscan -p "${PORT}" -H "${IP}" > "${KNOWN}" 2>/dev/null || true; chmod 600 "${KNOWN}" || true'
ExecStartPre=/bin/bash -lc '[[ -f "${KEY}" ]] || { echo "Missing KEY: ${KEY}" >> "${LOGFILE}"; exit 3; }; chmod 600 "${KEY}" || true'
ExecStartPre=/bin/bash -lc 'timeout 12 ssh -p "${PORT}" -i "${KEY}" "${USER}@${IP}" \
-o BatchMode=yes \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile="${KNOWN}" \
-o PreferredAuthentications=publickey \
-o PubkeyAuthentication=yes \
-o PasswordAuthentication=no \
-o KbdInteractiveAuthentication=no \
-o IdentitiesOnly=yes \
-o ExitOnForwardFailure=yes \
-o ConnectTimeout=7 \
-o ConnectionAttempts=1 \
"echo AUTH_OK" >> "${LOGFILE}" 2>&1 || { echo "Key auth failed" >> "${LOGFILE}"; tail -n 80 "${LOGFILE}" || true; exit 4; }'

ExecStart=/bin/bash -lc '/usr/bin/autossh -M 0 -N \
-p "${PORT}" \
-i "${KEY}" \
-o BatchMode=yes \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile="${KNOWN}" \
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
'"'"'$(if [[ "${MODE}" = "L" ]]; then
          echo "-L ${LHOST}:${LPORT}:${RHOST}:${RPORT}"
        else
          echo "-R ${RHOST}:${RPORT}:${LHOST}:${LPORT}"
        fi)'"'"' \
  "${USER}@${IP}" >> "${LOGFILE}" 2>&1'

Restart=always
RestartSec=2
TimeoutStartSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF

  ok "Wrote unit -> $UNIT_FILE"
}

enable_start(){
  local START_TS
  START_TS="$(date +'%Y-%m-%d %H:%M:%S')"

  systemctl daemon-reload
  systemctl enable "${SERVICE}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE}.service"

  echo
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,32p' || true
  echo

  if [[ "${MODE}" = "L" ]]; then
    if command -v ss >/dev/null 2>&1 && ss -lntH "sport = :${LPORT}" | grep -q .; then
      ok "Tunnel is listening locally on ${LHOST}:${LPORT}"
    else
      warn "Tunnel may not be listening yet. Showing logs:"
      journalctl -u "${SERVICE}.service" -b --since "${START_TS}" -n 200 --no-pager || true
      tail -n 120 "${LOGFILE}" 2>/dev/null || true
      exit 5
    fi
  else
    local i
    for i in 1 2 3 4 5; do
      if timeout 10 ssh -p "${PORT}" -i "${KEY}" "${USER}@${IP}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="${KNOWN}" \
        -o PreferredAuthentications=publickey \
        -o PubkeyAuthentication=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o IdentitiesOnly=yes \
        "command -v ss >/dev/null 2>&1 && ss -lntH \"sport = :${RPORT}\" | grep -q LISTEN" >/dev/null 2>&1; then
        ok "Tunnel is listening on remote OUTSIDE ${RHOST}:${RPORT}"
        return 0
      fi
      sleep 2
    done

    warn "Tunnel may not be listening remotely yet. Showing logs:"
    journalctl -u "${SERVICE}.service" -b --since "${START_TS}" -n 200 --no-pager || true
    tail -n 120 "${LOGFILE}" 2>/dev/null || true
    exit 5
  fi
}

main(){
  need_root
  _full_reset_screen

  _box "HUNTEX Turbo AutoSSH Tunnel" "Silver + Mustard (Install + Verify)"
  printf "%s•%s OUTSIDE:%s %s@%s:%s%s\n" \
    "${DIM}${SILVER}" "${RESET}" "${RESET}" \
    "${SILVER}${USER}${RESET}" "${SILVER}${IP}${RESET}" "${MUSTARD}${PORT}${RESET}" "${RESET}"
  if [[ "${MODE}" = "L" ]]; then
    printf "%s•%s MODE:%s %s  %s→%s %s\n" \
      "${DIM}${SILVER}" "${RESET}" "${RESET}" \
      "${MUSTARD}L${RESET}" \
      "${SILVER}${LHOST}:${LPORT}${RESET}" "${RESET}" "${SILVER}${RHOST}:${RPORT}${RESET}"
  else
    printf "%s•%s MODE:%s %s  %s→%s %s\n" \
      "${DIM}${SILVER}" "${RESET}" "${RESET}" \
      "${MUSTARD}R${RESET}" \
      "${SILVER}${RHOST}:${RPORT}${RESET}" "${RESET}" "${SILVER}${LHOST}:${LPORT}${RESET}"
  fi
  _hr

  phase "Phase 0 — Validate"
  validate_mode
  ok "mode OK"

  phase "Phase 1 — Packages"
  install_pkgs
  ok "packages ready"

  phase "Phase 2 — Prerequisites"
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
  enable_start

  _hr
  ok "DONE"
  printf "%sLogs:%s %s\n" "${DIM}${SILVER}" "${RESET}" "${SILVER}${LOGFILE}${RESET}"
  printf "%sChange IP:%s %s\n" "${DIM}${SILVER}" "${RESET}" "${SILVER}huntex-set-ip NEW_IP${RESET}"
}

main "$@"
