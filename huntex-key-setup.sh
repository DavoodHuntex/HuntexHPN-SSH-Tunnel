#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================
# HUNTEX KEY SETUP (Install + Verify)
# ============================================

_have_tty()  { [[ -t 1 ]]; }
_have_tput() { command -v tput >/dev/null 2>&1; }

_full_reset_screen() {
  _have_tty || return 0
  # Termius-friendly (avoid RIS/reset side-effects)
  printf '\e[0m\e[2J\e[H\e[3J' || true
}

# ---- UI (Silver + Mustard) ----
SILVER=""; MUSTARD=""; DIM=""; BOLD=""; RESET=""
if _have_tty && _have_tput; then
  SILVER="$(tput setaf 7 || true)"
  MUSTARD="$(tput setaf 3 || true)"
  DIM="$(tput dim || true)"
  BOLD="$(tput bold || true)"
  RESET="$(tput sgr0 || true)"
fi

_hr() { printf "%s\n" "${DIM}${SILVER}────────────────────────────────────────────────────────────${RESET}"; }

_box() {
  local title="${1:-}" subtitle="${2:-}"
  _hr
  printf "%s┌──────────────────────────────────────────────────────────┐%s\n" "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${BOLD}${MUSTARD}${title}${RESET}" \
    "" "$((58 - ${#title}))" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s│%s %s%s%*s%s│%s\n" \
    "${DIM}${SILVER}" "${RESET}" \
    "${DIM}${SILVER}${subtitle}${RESET}" \
    "" "$((58 - ${#subtitle}))" "" \
    "${DIM}${SILVER}" "${RESET}"
  printf "%s└──────────────────────────────────────────────────────────┘%s\n" "${DIM}${SILVER}" "${RESET}"
  _hr
}

phase() { printf "%s▶%s %s%s%s\n" "${DIM}${SILVER}" "${RESET}" "${BOLD}${MUSTARD}" "$*" "${RESET}"; }
log()   { printf "%s[%s]%s %s\n" "${DIM}${SILVER}" "$(date +'%F %T')" "${RESET}" "$*"; }
ok()    { printf "%s✅%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*"; }
warn()  { printf "%s⚠️ %s%s\n" "${BOLD}${MUSTARD}" "$*" "${RESET}" >&2; }
die()   { printf "%s❌%s %s\n" "${BOLD}${MUSTARD}" "${RESET}" "$*" >&2; exit 1; }

# ---- Variables ----
IP="${IP:-46.226.162.4}"
PORT="${PORT:-2222}"
USER="${USER:-root}"
PASS="${PASS:-}"
WIPE_KEYS="${WIPE_KEYS:-0}"

SSH_DIR="/root/.ssh"

main() {
  _full_reset_screen
  _box "HUNTEX KEY SETUP" "Silver + Mustard (Key Install + Verify)"

  printf "%s•%s Target:%s %s@%s:%s\n" \
    "${DIM}${SILVER}" "${RESET}" "${RESET}" \
    "${SILVER}${USER}${RESET}" "${SILVER}${IP}${RESET}" "${MUSTARD}${PORT}${RESET}"
  _hr

  [[ -n "${PASS}" ]] || die "PASS is empty. Example: IP=... PASS='xxx' WIPE_KEYS=1 bash"

  # ---- NAME = iran-[hostname] ----
  local hn name key pub known
  hn="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
  name="iran-${hn}"
  key="${SSH_DIR}/id_ed25519_${name}"
  pub="${key}.pub"
  known="${SSH_DIR}/known_hosts_${name}"

  phase "Phase 0 — Dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y openssh-client sshpass >/dev/null 2>&1 || true
  ok "deps ready"

  phase "Phase 1 — SSH directory"
  mkdir -p "${SSH_DIR}"
  chmod 700 "${SSH_DIR}" || true
  ok "ssh dir ready"

  phase "Phase 2 — Local cleanup"
  if [[ "${WIPE_KEYS}" == "1" ]]; then
    log "WIPE_KEYS=1 -> removing local id_* + known_hosts* (keeping authorized_keys)"
    find "${SSH_DIR}" -maxdepth 1 -type f \
      \( -name "id_*" -o -name "known_hosts*" \) \
      ! -name "authorized_keys" -delete || true
    ok "wiped"
  else
    ok "skipped"
  fi

  rm -f "${key}" "${pub}" "${known}" || true

  phase "Phase 3 — Generate key"
  ssh-keygen -t ed25519 -f "${key}" -N "" -C "${name}@$(hostname -f 2>/dev/null || hostname)" >/dev/null 2>&1 \
    || die "ssh-keygen failed"
  chmod 600 "${key}" || true
  chmod 644 "${pub}" || true
  ok "key generated"

  phase "Phase 4 — TCP check"
  if timeout 5 bash -lc "cat </dev/null >/dev/tcp/${IP}/${PORT}" >/dev/null 2>&1; then
    ok "port ${PORT} open"
  else
    die "port ${PORT} closed (network/firewall)"
  fi

  # ---- SSH options ----
  local -a SSH_BASE_OPTS SSH_PASS_OPTS
  SSH_BASE_OPTS=(
    -n
    -p "${PORT}"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile="${known}"
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

  retry() {
    local n=0 max=25 delay=1
    until "$@"; do
      n=$((n+1))
      (( n >= max )) && return 1
      sleep "${delay}"
    done
  }

  local pubkey_content remote_prep remote_append
  pubkey_content="$(cat "${pub}")"

  remote_prep=$'set -e\numask 077\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\ntouch /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n'
  remote_append="grep -qxF '${pubkey_content}' /root/.ssh/authorized_keys || echo '${pubkey_content}' >> /root/.ssh/authorized_keys; echo KEY_ADDED"

  phase "Phase 5 — Remote install"
  retry sshpass -p "${PASS}" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "${USER}@${IP}" "${remote_prep}" \
    || die "remote prepare failed"
  retry sshpass -p "${PASS}" ssh "${SSH_BASE_OPTS[@]}" "${SSH_PASS_OPTS[@]}" "${USER}@${IP}" "${remote_append}" \
    || die "append key failed"
  ok "installed"

  phase "Phase 6 — Verify key-only login"
  ssh "${SSH_BASE_OPTS[@]}" -i "${key}" \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o IdentitiesOnly=yes \
    "${USER}@${IP}" "echo KEY_OK && hostname && whoami" \
    || die "key-only login test failed"
  ok "verified"

  _hr
  ok "DONE"
  log "KEY PATH: ${key}"
}

main "$@"
```0
