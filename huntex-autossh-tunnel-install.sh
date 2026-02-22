#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="${SERVICE:-huntex-autossh-tunnel}"
ENV_FILE="/etc/default/${SERVICE}"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
RUNNER="/usr/local/bin/huntex-autossh-run"
SETIP_BIN="/usr/local/bin/huntex-set-ip"
LOGFILE="/var/log/${SERVICE}.log"
SSH_DIR="/root/.ssh"

for a in "$@"; do
  [[ "$a" == *=* ]] || continue
  export "$a"
done

need_root(){ [[ "${EUID:-0}" -eq 0 ]] || { echo "need root"; exit 10; }; }

tty_clear(){
  local T="/dev/tty"
  [[ -w "$T" ]] || return 0
  printf '\033[0m\033[H\033[2J\033[3J' >"$T" 2>/dev/null || true
}

banner(){
  echo "HUNTEX AutoSSH Tunnel"
  echo "service: ${SERVICE}"
  echo
}

say_ok(){  printf "✅ OK\n"; }
say_fail(){ printf "❌ FAILED\n"; }

validate_mode(){
  MODE="${MODE:-L}"
  [[ "$MODE" == "L" || "$MODE" == "R" ]] || { echo "MODE must be L or R"; exit 11; }
}

install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y autossh openssh-client ca-certificates coreutils iproute2 >/dev/null 2>&1 || true
  command -v autossh >/dev/null 2>&1 || { echo "autossh missing"; exit 12; }
  command -v ssh >/dev/null 2>&1 || { echo "ssh missing"; exit 13; }
  command -v ssh-keyscan >/dev/null 2>&1 || { echo "ssh-keyscan missing"; exit 14; }
  command -v systemctl >/dev/null 2>&1 || { echo "systemctl missing"; exit 15; }
  command -v timeout >/dev/null 2>&1 || { echo "timeout missing"; exit 16; }
}

init_vars(){
  MODE="${MODE:-L}"
  IP="${IP:-46.226.162.4}"
  PORT="${PORT:-2222}"
  USER="${USER:-root}"
  LHOST="${LHOST:-0.0.0.0}"
  LPORT="${LPORT:-443}"
  RHOST="${RHOST:-127.0.0.1}"
  RPORT="${RPORT:-443}"

  local hn
  hn="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
  NAME="${NAME:-iran-${hn}}"

  KEY="${KEY:-${SSH_DIR}/id_ed25519_${NAME}}"
  KNOWN="${KNOWN:-${SSH_DIR}/known_hosts_${SERVICE}}"
}

ensure_key_exists(){
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR" || true
  [[ -f "$KEY" ]] || { echo "SSH key not found: $KEY"; exit 17; }
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
}

write_runner(){
  cat >"$RUNNER" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/etc/default/huntex-autossh-tunnel"
[[ -f "$ENV_FILE" ]] || { echo "env missing: $ENV_FILE" >&2; exit 20; }
source "$ENV_FILE"

: "${MODE:=L}"
: "${IP:?}"
: "${PORT:=2222}"
: "${USER:=root}"
: "${LHOST:=0.0.0.0}"
: "${LPORT:=443}"
: "${RHOST:=127.0.0.1}"
: "${RPORT:=443}"
: "${KEY:?}"
: "${KNOWN:=/root/.ssh/known_hosts_huntex-autossh-tunnel}"
: "${LOGFILE:=/var/log/huntex-autossh-tunnel.log}"

mkdir -p /root/.ssh
chmod 700 /root/.ssh || true
: > "$LOGFILE" || true
chmod 600 "$LOGFILE" || true

rm -f "$KNOWN" || true
timeout 7 ssh-keyscan -p "$PORT" -H "$IP" > "$KNOWN" 2>/dev/null || true
chmod 600 "$KNOWN" || true

[[ -f "$KEY" ]] || { echo "Missing KEY: $KEY" >>"$LOGFILE"; exit 21; }
chmod 600 "$KEY" || true

SSH_OPTS=(
  -p "$PORT" -i "$KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile="$KNOWN"
  -o PreferredAuthentications=publickey
  -o PubkeyAuthentication=yes
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o IdentitiesOnly=yes
  -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
  -o TCPKeepAlive=yes
  -o ConnectTimeout=7
  -o ConnectionAttempts=1
  -o LogLevel=ERROR
)

if ! timeout 10 ssh "${SSH_OPTS[@]}" "${USER}@${IP}" "echo AUTH_OK" >>"$LOGFILE" 2>&1; then
  echo "Key auth failed" >>"$LOGFILE"
  exit 22
fi

if [[ "$MODE" == "L" ]]; then
  FWD=( -L "${LHOST}:${LPORT}:${RHOST}:${RPORT}" )
else
  FWD=( -R "${RHOST}:${RPORT}:${LHOST}:${LPORT}" )
fi

exec /usr/bin/autossh -M 0 -N \
  "${SSH_OPTS[@]}" \
  "${FWD[@]}" \
  "${USER}@${IP}" >>"$LOGFILE" 2>&1
EOF
  chmod +x "$RUNNER"
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
  echo "Invalid IP: \$NEW_IP"; exit 3
fi
if grep -q '^IP=' "\$ENV_FILE"; then
  sed -i "s/^IP=.*/IP=\${NEW_IP}/" "\$ENV_FILE"
else
  echo "IP=\${NEW_IP}" >> "\$ENV_FILE"
fi
systemctl daemon-reload
systemctl restart "\${SERVICE}.service"
sleep 1
systemctl --no-pager -l status "\${SERVICE}.service" | sed -n '1,35p' || true
EOF
  chmod +x "$SETIP_BIN"
}

write_unit(){
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
ExecStart=${RUNNER}
Restart=always
RestartSec=2
TimeoutStartSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
}

fail_reason_one_liner(){
  journalctl -u "${SERVICE}.service" -n 40 --no-pager 2>/dev/null \
    | grep -E 'Permission denied|Key auth failed|Unbalanced quoting|remote port forwarding failed|ExitOnForwardFailure|Connection timed out|No route to host|refused|FAILED' \
    | tail -n 1 || true
}

print_checks(){
  echo "check: systemctl --no-pager -l status ${SERVICE}.service | sed -n '1,80p'"
  echo "logs : journalctl -u ${SERVICE}.service -n 120 --no-pager"
  echo "file : tail -n 120 ${LOGFILE}"
}

verify_minimal(){
  systemctl daemon-reload
  systemctl enable "${SERVICE}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE}.service" >/dev/null 2>&1 || return 1
  sleep 1

  systemctl is-active --quiet "${SERVICE}.service" || return 1

  if command -v ss >/dev/null 2>&1; then
    if [[ "${MODE}" == "L" ]]; then
      ss -lntH "sport = :${LPORT}" | grep -q . || return 1
    fi
  fi
  return 0
}

main(){
  need_root
  tty_clear
  banner

  init_vars
  validate_mode
  install_pkgs
  ensure_key_exists

  write_env
  write_runner
  write_setip
  write_unit

  if verify_minimal; then
    say_ok
    print_checks
    exit 0
  else
    say_fail
    r="$(fail_reason_one_liner)"
    [[ -n "${r:-}" ]] && echo "reason: $r"
    print_checks
    exit 1
  fi
}

main "$@"
