#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================
# HUNTEX Turbo AutoSSH Tunnel (MINIMAL+)
# ============================================

# -------------------- UI (Silver + Mustard) --------------------
_have_tty()  { [[ -t 1 ]]; }
_have_tput() { command -v tput >/dev/null 2>&1; }

_full_reset_screen() {
_full_reset_screen() {
  if _have_tty; then
    # Termius-friendly reset (avoids RIS)
    if command -v tput >/dev/null 2>&1; then
      tput sgr0 || true
      tput reset || true
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

_hr() { printf "%s\n" "${DIM}${SILVER}────────────────────────────────────────────────────────────${RESET}"; }

_box() {
  local title="${1:-No Title}" subtitle="${2:-}"
  _hr
  printf "%s┌──────────────────────────────────────────────────────────┐%s\n" "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${BOLD}${MUSTARD}${title}${RESET}" \
    "$((58 - ${#title}))" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${DIM}${SILVER}${subtitle}${RESET}" \
    "$((58 - ${#subtitle}))" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s└──────────────────────────────────────────────────────────┘%s\n" "${DIM}${SILVER}" "${RESET}"
  _hr
}

phase() { printf "%s▶%s %s%s%s\n" "${DIM}${SILVER}" "${RESET}" "${BOLD}${MUSTARD}" "$*" "${RESET}"; }
log(){  printf "%s[%s]%s %s\n" "${DIM}${SILVER}" "$(date +'%F %T')" "${RESET}" "$*"; }
die(){  printf "%s❌%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*" >&2; exit 1; }
ok(){   printf "%s✅%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*"; }
warn(){ printf "%s⚠️ %s%s\n" "${BOLD}${MUSTARD}" "$*" "${RESET}" >&2; }

# ---------------------- Variables --------------------------
IP="${IP:-46.226.162.4}"
PORT="${PORT:-2222}"
USER="${USER:-root}"
PASS="${PASS:-}"
WIPE_KEYS="${WIPE_KEYS:-0}"

SSH_DIR="/root/.ssh"

main() {

  _full_reset_screen
  _box "HUNTEX KEY SETUP" "Silver + Mustard (Key Install + Verify)"

  printf "%s•%s Target: %s%s@%s:%s%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${SILVER}${USER}${RESET}" \
    "${SILVER}${IP}${RESET}" \
    "${MUSTARD}${PORT}${RESET}"
  _hr

  [[ -n "$PASS" ]] || die "PASS is empty. Example: IP=... PASS='xxx' WIPE_KEYS=1 bash"

  HN="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
  NAME="iran-${HN}"
  KEY="${SSH_DIR}/id_ed25519_${NAME}"
  PUB="${KEY}.pub"
  KNOWN="${SSH_DIR}/known_hosts_${NAME}"

  phase "Phase 0 — Dependencies"
  log "Installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y openssh-client sshpass >/dev/null 2>&1 || true
  ok "Dependencies ready"

  phase "Phase 1 — SSH directory"
  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR"
  ok "SSH directory ready"

  phase "Phase 2 — Local cleanup"
  if [[ "$WIPE_KEYS" == "1" ]]; then
    find "$SSH_DIR" -maxdepth 1 -type f \
      \( -name "id_*" -o -name "known_hosts*" \) \
      ! -name "authorized_keys" -delete || true
    ok "Local keys wiped"
  else
    ok "Cleanup skipped"
  fi

  rm -f "$KEY" "$PUB" "$KNOWN" || true

  phase "Phase 3 — Generate key"
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "${NAME}@$(hostname -f 2>/dev/null || hostname)" >/dev/null 2>&1 || die "ssh-keygen failed"
  chmod 600 "$KEY" || true
  chmod 644 "$PUB" || true
  ok "Key generated"

  phase "Phase 4 — TCP check"
  if timeout 5 bash -lc "cat </dev/null >/dev/tcp/${IP}/${PORT}" >/dev/null 2>&1; then
    ok "Port ${PORT} OPEN"
  else
    die "Port ${PORT} CLOSED"
  fi

  SSH_BASE_OPTS=(
    -n
    -p "$PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="$KNOWN"
    -o GlobalKnownHostsFile=/dev/null
    -o ConnectTimeout=7
    -o ConnectionAttempts=1
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=2
    -o TCPKeepAlive=yes
    -o LogLevel=ERROR
  )

  SSH_PASS_OPTS=(
    -o PreferredAuthentications=password,keyboard-interactive
    -o PasswordAuthentication=yes
    -o KbdInteractiveAuthentication=yes
    -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1
  )

  retry(){
    local n=0 max=25 delay=1
    until "$@"; do
      n=$((n+1))
      if (( n >= max )); then return 1; fi
      sleep "$delay"
    done
  }

  PUBKEY_CONTENT="$(cat "$PUB")"

  REMOTE_PREP=$'set -e\numask 077\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\ntouch /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n'

  REMOTE_APPEND="grep -qxF '$PUBKEY_CONTENT' /root/.ssh/authorized_keys || echo '$PUBKEY_CONTENT' >> /root/.ssh/authorized_keys; echo KEY_ADDED"

  phase "Phase 5 — Remote install"
  retry sshpass -p "$PASS" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "$USER@$IP" "$REMOTE_PREP" \
    || die "remote prepare failed"
  ok "Remote prepare OK"

  retry sshpass -p "$PASS" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "$USER@$IP" "$REMOTE_APPEND" \
    || die "append key failed"
  ok "Key installed"

  phase "Phase 6 — Verify key-only login"
  ssh "${SSH_BASE_OPTS[@]}" -i "$KEY" \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o IdentitiesOnly=yes \
    "$USER@$IP" "echo KEY_OK && hostname && whoami" \
    || die "key-only login test failed"

  ok "DONE"
  log "KEY PATH: $KEY"
  _hr
}

main "$@"


