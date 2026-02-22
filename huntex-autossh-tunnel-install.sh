#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================
# HUNTEX Turbo AutoSSH Tunnel (FINAL+)
# - Iran server runs autossh client
# - Connects to OUTSIDE HPN-SSH: IP:PORT (default 2222)
# - MODE=L (default): local forward  (-L)  => IRAN listens, forwards to OUTSIDE target
# - MODE=R           : reverse forward (-R) => OUTSIDE listens, forwards to IRAN target
# - Uses key: /root/.ssh/id_ed25519_iran-$(hostname -s)
# - NO prompt, FAIL-FAST, auto reconnect
# - systemd service + env file + CLI huntex-set-ip
#
# Fixes (ONLY):
#  1) Ensure local "ss" exists by installing iproute2 (avoid skipped checks)
#  2) MODE=R remote-listener check: fallback (ss/netstat/lsof) to avoid false negatives
#  3) MODE=R preflight: verify remote AllowTcpForwarding (and GatewayPorts if needed)
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
  # FIX#1: include iproute2 so "ss" exists
  apt-get install -y autossh openssh-client sshpass ca-certificates coreutils iproute2 >/dev/null 2>&1 || true
}

ensure_prereqs(){
  command -v autossh >/dev/null 2>&1 || die "autossh not found (apt install failed?)"
  command -v ssh >/dev/null 2>&1 || die "ssh not found (openssh-client missing?)"
  command -v ssh-keyscan >/dev/null 2>&1 || die "ssh-keyscan missing (openssh-client broken?)"
  command -v timeout >/dev/null 2>&1 || die "timeout missing (coreutils missing?)"
  command -v systemctl >/dev/null 2>&1 || die "systemd required (systemctl not found)"
  # After iproute2 install, ss should exist; still guard:
  command -v ss >/dev/null 2>&1 || die "ss not found (iproute2 install failed?)"
}

ensure_key(){
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" || true
  [[ -f "$KEY" ]] || die "SSH key not found: $KEY (run your key-setup first on IRAN so this key exists + is authorized on OUTSIDE)"
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

START_TS="\$(date '+%Y-%m-%d %H:%M:%S')"

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
systemctl --no-pager --full status "\${SERVICE}.service" | sed -n '1,22p' || true

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
  if ss -lntH "sport = :\${LPORT}" | grep -q .; then
    echo "✅ Tunnel is listening locally on \${LPORT}"
  else
    echo "❌ Tunnel not listening locally on \${LPORT}"
    journalctl -u "\${SERVICE}.service" -b --since "\${START_TS}" -n 200 --no-pager || true
    exit 4
  fi
else
  # MODE=R: check remote listener (retry; FIX#2: fallback to netstat/lsof if ss missing)
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
      '(
          if command -v ss >/dev/null 2>&1; then
            ss -lntH "sport = :'\${RPORT}'" | grep -q LISTEN
          elif command -v netstat >/dev/null 2>&1; then
            netstat -lnt 2>/dev/null | awk "{print \\\$4}" | grep -Eq "(:|\.)'\${RPORT}'\$"
          elif command -v lsof >/dev/null 2>&1; then
            lsof -nP -iTCP:"'\${RPORT}'" -sTCP:LISTEN >/dev/null 2>&1
          else
            exit 2
          fi
        )' >/dev/null 2>&1; then
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
  local FWD_DESC FWD_ARG

  if [[ "${MODE}" = "L" ]]; then
    FWD_DESC="${LHOST}:${LPORT} -> ${RHOST}:${RPORT}"
    FWD_ARG="-L \${LHOST}:\${LPORT}:\${RHOST}:\${RPORT}"
  else
    FWD_DESC="REMOTE ${RHOST}:${RPORT} -> LOCAL ${LHOST}:${LPORT}"
    FWD_ARG="-R \${RHOST}:\${RPORT}:\${LHOST}:\${LPORT}"
  fi

  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=HUNTEX Turbo AutoSSH Tunnel (MODE=${MODE} | ${FWD_DESC} via ${USER}@${IP}:${PORT})
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

ExecStartPre=/bin/bash -lc 'mkdir -p /root/.ssh; chmod 700 /root/.ssh; : > "\${LOGFILE}"; chmod 600 "\${LOGFILE}" || true'

# Fail if local port already in use (only in MODE=L)
ExecStartPre=/bin/bash -lc 'if [[ "\${MODE}" = "L" ]]; then ss -lntH "sport = :\${LPORT}" | grep -q . && { echo "Port \${LPORT} already in use" >> "\${LOGFILE}"; exit 1; } || true; fi'

# TCP reachability to outside SSH port
ExecStartPre=/bin/bash -lc 'timeout 5 bash -lc "cat </dev/null >/dev/tcp/\${IP}/\${PORT}" >/dev/null 2>&1 || { echo "TCP \${IP}:\${PORT} unreachable" >> "\${LOGFILE}"; exit 2; }'

# Refresh dedicated known_hosts
ExecStartPre=/bin/bash -lc 'rm -f "\${KNOWN}" || true; timeout 7 ssh-keyscan -p "\${PORT}" -H "\${IP}" > "\${KNOWN}" 2>/dev/null || true; chmod 600 "\${KNOWN}" || true'

# Fail-fast key-only auth test
ExecStartPre=/bin/bash -lc '[[ -f "\${KEY}" ]] || { echo "Missing KEY: \${KEY}" >> "\${LOGFILE}"; exit 3; }; chmod 600 "\${KEY}" || true'
ExecStartPre=/bin/bash -lc 'timeout 12 ssh -p "\${PORT}" -i "\${KEY}" "\${USER}@\${IP}" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile="\${KNOWN}" \
  -o PreferredAuthentications=publickey \
  -o PubkeyAuthentication=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o IdentitiesOnly=yes \
  -o ExitOnForwardFailure=yes \
  -o ConnectTimeout=7 \
  -o ConnectionAttempts=1 \
  "echo AUTH_OK" >> "\${LOGFILE}" 2>&1 || { echo "Key auth failed" >> "\${LOGFILE}"; tail -n 80 "\${LOGFILE}" || true; exit 4; }'

# FIX#3: MODE=R preflight remote permissions (AllowTcpForwarding; GatewayPorts if non-local RHOST)
ExecStartPre=/bin/bash -lc 'if [[ "\${MODE}" = "R" ]]; then \
  timeout 12 ssh -p "\${PORT}" -i "\${KEY}" "\${USER}@\${IP}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile="\${KNOWN}" \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o IdentitiesOnly=yes \
    "bash -lc '\'' \
      CFG=\"/etc/hpnssh/hpnsshd_config\"; \
      if [[ -f \"\$CFG\" ]]; then \
        ATF=\$(grep -iE \"^\\s*AllowTcpForwarding\\s+\" \"\$CFG\" | tail -n1 | awk \"{print tolower(\\\$2)}\"); \
        [[ \"\$ATF\" = \"yes\" || -z \"\$ATF\" ]] || { echo \"AllowTcpForwarding is not yes\"; exit 21; }; \
        RH=\"\${RHOST}\"; \
        if [[ \"\$RH\" != \"127.0.0.1\" && \"\$RH\" != \"::1\" && \"\$RH\" != \"localhost\" ]]; then \
          GP=\$(grep -iE \"^\\s*GatewayPorts\\s+\" \"\$CFG\" | tail -n1 | awk \"{print tolower(\\\$2)}\"); \
          [[ \"\$GP\" = \"yes\" ]] || { echo \"GatewayPorts is not yes (needed for non-local RHOST)\"; exit 22; }; \
        fi; \
      fi; \
      exit 0 \
    '\''" >> "\${LOGFILE}" 2>&1 || { echo "MODE=R preflight failed (forwarding settings)"; tail -n 120 "\${LOGFILE}" || true; exit 6; }; \
fi'

ExecStart=/usr/bin/autossh -M 0 -N \
  -p \${PORT} \
  -i "\${KEY}" \
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
  ${FWD_ARG} \
  \${USER}@\${IP} >> "\${LOGFILE}" 2>&1

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
  START_TS="$(date '+%Y-%m-%d %H:%M:%S')"

  systemctl daemon-reload
  systemctl enable --now "${SERVICE}.service"

  echo
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,22p' || true
  echo

  if [[ "${MODE}" = "L" ]]; then
    if ss -lntH "sport = :${LPORT}" | grep -q .; then
      ok "Tunnel is listening locally on ${LHOST}:${LPORT}"
    else
      warn "Tunnel may not be listening yet. Showing logs:"
      journalctl -u "${SERVICE}.service" -b --since "${START_TS}" -n 200 --no-pager || true
      tail -n 120 "${LOGFILE}" 2>/dev/null || true
      exit 5
    fi
  else
    # MODE=R: verify remote listener exists (retry; FIX#2 fallback)
    local i ok_remote=0
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
        '(
          if command -v ss >/dev/null 2>&1; then
            ss -lntH "sport = :'"${RPORT}"'" | grep -q LISTEN
          elif command -v netstat >/dev/null 2>&1; then
            netstat -lnt 2>/dev/null | awk "{print \\\$4}" | grep -Eq "(:|\.)'"${RPORT}"'\$"
          elif command -v lsof >/dev/null 2>&1; then
            lsof -nP -iTCP:'"${RPORT}"' -sTCP:LISTEN >/dev/null 2>&1
          else
            exit 2
          fi
        )' >/dev/null 2>&1; then
        ok_remote=1
        ok "Tunnel is listening on remote OUTSIDE ${RHOST}:${RPORT}"
        break
      fi
      sleep 2
    done

    if [[ "${ok_remote}" -ne 1 ]]; then
      warn "Tunnel may not be listening remotely yet. Showing logs:"
      journalctl -u "${SERVICE}.service" -b --since "${START_TS}" -n 200 --no-pager || true
      tail -n 120 "${LOGFILE}" 2>/dev/null || true
      exit 5
    fi
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
