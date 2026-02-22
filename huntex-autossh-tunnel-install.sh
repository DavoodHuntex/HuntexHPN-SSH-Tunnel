#!/usr/bin/env bash
set -Eeuo pipefail

# ------------------------------------------------------------
# HUNTEX AutoSSH Tunnel Installer (GitHub-ready)
# - Works with: curl ... | MODE=... IP=... bash
# - Works with: curl ... | bash -s -- MODE=... IP=...
# - Writes:
#   /etc/default/huntex-autossh-tunnel
#   /usr/local/bin/huntex-autossh-run
#   /usr/local/bin/huntex-set-ip
#   /etc/systemd/system/huntex-autossh-tunnel.service
# - Minimal output: ✅ OK or ❌ FAILED + check commands
# ------------------------------------------------------------

SERVICE="${SERVICE:-huntex-autossh-tunnel}"
ENV_FILE="/etc/default/${SERVICE}"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
RUNNER="/usr/local/bin/huntex-autossh-run"
SETIP_BIN="/usr/local/bin/huntex-set-ip"
LOGFILE="/var/log/${SERVICE}.log"
SSH_DIR="/root/.ssh"

# ---------- accept KEY=VAL passed after bash -s -- ----------
for a in "$@"; do
  [[ "$a" == *=* ]] || continue
  # shellcheck disable=SC2163
  export "$a"
done

# ---------- screen reset (Termius-friendly) ----------
_have_tty(){ [[ -t 1 ]]; }
_reset_screen(){
  _have_tty || return 0
  # do NOT use RIS; Termius sometimes behaves weird. Use clear+scrollback wipe.
  printf '\033[0m\033[H\033[2J\033[3J' || true
}

# ---------- minimal UI ----------
say_ok(){  printf "✅ OK\n"; }
say_fail(){ printf "❌ FAILED\n"; }

need_root(){
  [[ "${EUID:-0}" -eq 0 ]] || { echo "need root (sudo)"; exit 10; }
}

validate_mode(){
  MODE="${MODE:-L}"
  [[ "$MODE" == "L" || "$MODE" == "R" ]] || { echo "MODE must be L or R"; exit 11; }
}

install_pkgs(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  # iproute2 for ss (optional but recommended)
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
# shellcheck disable=SC1090
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

[[ -f "$KEY" ]] || { echo "Missing KEY: $KEY" >> "$LOGFILE"; exit 21; }
chmod 600 "$KEY" || true

SSH_OPTS=(
  -p "$PORT"
  -i "$KEY"
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

# quick auth check
if ! timeout 10 ssh "${SSH_OPTS[@]}" "${USER}@${IP}" "echo AUTH_OK" >>"$LOGFILE" 2>&1; then
  echo "Key auth failed" >>"$LOGFILE"
  exit 22
fi

if [[ "$MODE" == "L" ]]; then
  # IRAN listens locally; forward to remote target (on MID side)
  FWD=( -L "${LHOST}:${LPORT}:${RHOST}:${RPORT}" )
else
  # OUTSIDE listens remotely; forward back to local target
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
systemctl --no-pager --full status "\${SERVICE}.service" | sed -n '1,25p' || true
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

verify_minimal(){
  local start_ts
  start_ts="$(date +'%Y-%m-%d %H:%M:%S')"

  systemctl daemon-reload
  systemctl enable "${SERVICE}.service" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE}.service" >/dev/null 2>&1 || return 1

  sleep 1
  systemctl is-active --quiet "${SERVICE}.service" || return 1

  # Optional: if ss exists, ensure listener exists for MODE=L on LPORT
  if command -v ss >/dev/null 2>&1; then
    if [[ "${MODE}" == "L" ]]; then
      ss -lntH "sport = :${LPORT}" | grep -q . || return 1
    fi
  fi

  return 0
}

print_checks(){
  echo "check: systemctl --no-pager --full status ${SERVICE}.service | sed -n '1,60p'"
  echo "logs : journalctl -u ${SERVICE}.service -n 120 --no-pager"
  echo "file : tail -n 120 ${LOGFILE}"
}

main(){
  need_root
  _reset_screen

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
    print_checks
    exit 1
  fi
}

main "$@"
