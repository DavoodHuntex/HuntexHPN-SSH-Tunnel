#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================
# HUNTEX Turbo AutoSSH Tunnel (MINIMAL+)
# - Iran server runs autossh client
# - Connects to OUTSIDE HPN-SSH: IP:PORT (default 2222)
# - MODE=L (default): local forward  (-L)  => IRAN listens, forwards to OUTSIDE target
# - MODE=R           : reverse forward (-R) => OUTSIDE listens, forwards to IRAN target
# - Uses key: /root/.ssh/id_ed25519_iran-$(hostname -s)
# - systemd service + env file + CLI huntex-set-ip
# - Fixes: old-log spam + unit escape errors + ensures restart applies new mode
# ==========================================

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

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }
warn(){ echo "⚠️  $*" >&2; }
log(){ echo "[$(date +'%F %T')] $*"; }

need_root(){ [[ "${EUID:-0}" -eq 0 ]] || die "Run as root (sudo)."; }

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
    echo "✅ Tunnel is listening locally on \${LPORT}"
  else
    echo "❌ Tunnel not listening locally on \${LPORT}"
    journalctl -u "\${SERVICE}.service" -b --since "\${START_TS}" -n 200 --no-pager || true
    exit 4
  fi
else
  # MODE=R: verify remote listener exists (retry)
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

  # IMPORTANT:
  # - No \${...} in unit file (systemd escape bug)
  # - Use bash -lc so normal ${VAR} expands at runtime
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

# Prepare log + ssh dir (truncate log each start)
ExecStartPre=/bin/bash -lc 'mkdir -p /root/.ssh; chmod 700 /root/.ssh; : > "${LOGFILE}"; chmod 600 "${LOGFILE}" || true'

# Fail if local port already in use (only MODE=L)
ExecStartPre=/bin/bash -lc 'if [[ "${MODE}" = "L" ]] && command -v ss >/dev/null 2>&1; then ss -lntH "sport = :${LPORT}" | grep -q . && { echo "Port ${LPORT} already in use" >> "${LOGFILE}"; exit 1; } || true; fi'

# TCP reachability to outside SSH port
ExecStartPre=/bin/bash -lc 'timeout 5 bash -lc "cat </dev/null >/dev/tcp/${IP}/${PORT}" >/dev/null 2>&1 || { echo "TCP ${IP}:${PORT} unreachable" >> "${LOGFILE}"; exit 2; }'

# Refresh dedicated known_hosts (no prompt ever)
ExecStartPre=/bin/bash -lc 'rm -f "${KNOWN}" || true; timeout 7 ssh-keyscan -p "${PORT}" -H "${IP}" > "${KNOWN}" 2>/dev/null || true; chmod 600 "${KNOWN}" || true'

# Fail-fast key existence
ExecStartPre=/bin/bash -lc '[[ -f "${KEY}" ]] || { echo "Missing KEY: ${KEY}" >> "${LOGFILE}"; exit 3; }; chmod 600 "${KEY}" || true'

# Fail-fast key-only auth test
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

# Main tunnel
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

  # IMPORTANT: always restart so new MODE/args apply
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
    # MODE=R: verify remote listener exists (retry)
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
  validate_mode
  install_pkgs
  ensure_prereqs
  ensure_key

  log "[*] MODE=${MODE}"
  log "[*] Using NAME=${NAME}"
  log "[*] KEY=${KEY}"
  log "[*] OUTSIDE=${USER}@${IP}:${PORT}"

  if [[ "${MODE}" = "L" ]]; then
    log "[*] LOCAL LISTEN=${LHOST}:${LPORT} -> OUTSIDE TARGET=${RHOST}:${RPORT}"
  else
    log "[*] REMOTE LISTEN=${RHOST}:${RPORT} -> LOCAL TARGET=${LHOST}:${LPORT}"
  fi

  write_env
  write_setip
  write_unit
  enable_start

  echo
  ok "DONE"
  echo "Logs: ${LOGFILE}"
  echo "Change IP later: huntex-set-ip NEW_IP"
}

main "$@"
