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

write_config() {
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local hpnsshd_bin="${HPNSSHD_BIN:-}"
  [[ -n "$hpnsshd_bin" && -x "$hpnsshd_bin" ]] || die "Internal error: HPNSSHD_BIN not set before write_config()"

  _stage "Config"

  local USEPAM_LINE=""
  if supports_option "$hpnsshd_bin" "UsePAM yes"; then
    USEPAM_LINE="UsePAM yes"
    ok "UsePAM supported -> enabled"
  else
    ok "UsePAM NOT supported -> skipped"
  fi

  local USEDNS_LINE=""
  if supports_option "$hpnsshd_bin" "UseDNS no"; then
    USEDNS_LINE="UseDNS ${USE_DNS}"
    ok "UseDNS supported -> ${USE_DNS}"
  else
    ok "UseDNS NOT supported -> skipped"
  fi

  local SFTP_SERVER
  SFTP_SERVER="$(detect_sftp_server)"
  ok "sftp-server -> ${SFTP_SERVER}"

  cat > "$cfg" <<CFGEOF
# ============================================================
# HUNTEX HPN-SSH-Tunnel - HPN sshd config (separate instance)
# ============================================================

Port ${PORT}
ListenAddress 0.0.0.0
ListenAddress ::

PidFile /run/${SERVICE}/${SERVICE}.pid

HostKey ${SYSCONFDIR}/ssh_host_ed25519_key
HostKey ${SYSCONFDIR}/ssh_host_rsa_key

# --- Security
PermitRootLogin ${PERMIT_ROOT_LOGIN}
PasswordAuthentication ${PASSWORD_AUTH}
KbdInteractiveAuthentication ${KBDINT_AUTH}
${USEPAM_LINE}

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# reduce post-auth noise (helps weak links)
PrintMotd no
PrintLastLog no

# --- Reliability
${USEDNS_LINE}
LoginGraceTime ${LOGIN_GRACE_TIME}
MaxAuthTries ${MAX_AUTH_TRIES}
LogLevel ${LOG_LEVEL}

# --- Crypto (compatible + HPN)
Ciphers ${CIPHERS}

# --- Tunnel / forwarding
AllowTcpForwarding yes
GatewayPorts yes

# --- Keepalive
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

Compression no
Subsystem sftp ${SFTP_SERVER}
CFGEOF

  ok "Config written -> ${cfg}"
}

write_systemd_unit() {
  local hpnsshd_bin="$1"
  local cfg="$SYSCONFDIR/hpnsshd_config"
  local unit="/etc/systemd/system/${SERVICE}.service"

  _stage "Systemd"

  cat > "$unit" <<UNITEOF
[Unit]
Description=HPN-SSH server (separate instance on port ${PORT})
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
RuntimeDirectory=${SERVICE}
RuntimeDirectoryMode=0755

ExecStartPre=${hpnsshd_bin} -t -f ${cfg}
ExecStart=${hpnsshd_bin} -D -f ${cfg} -E ${RUNTIMELOG}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNITEOF

  _run_stage "daemon-reload" "$SVCLOG" "systemctl daemon-reload"
  ok "Unit installed -> ${unit}"
}

start_service() {
  _stage "Service"

  _run_stage "reset-failed" "$SVCLOG" "systemctl reset-failed '${SERVICE}.service' || true"
  _run_stage "enable+start" "$SVCLOG" "systemctl enable --now '${SERVICE}.service'"

  echo
  ok "Service status (short):"
  systemctl --no-pager --full status "${SERVICE}.service" | sed -n '1,35p' || true
echo
  ok "Listening:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true

  echo
  ok "Last logs (service):"
  journalctl -u "${SERVICE}.service" --no-pager -n 20 || true
}

status_cmd() {
  banner
  ok "Ports:"
  ss -lntp | grep -E ":(22|${PORT})\b" || true
  echo
  ok "Service:"
  systemctl --no-pager --full status "${SERVICE}.service" || true
}

logs_cmd() {
  banner
  ok "Journal (last 200 lines):"
  journalctl -u "${SERVICE}.service" --no-pager -n 200 || true
  echo
  ok "Runtime log: ${RUNTIMELOG}"
  tail -n 200 "${RUNTIMELOG}" 2>/dev/null || true
}

uninstall_cmd() {
  banner
  warn "Uninstalling ${APP_NAME}..."
  warn "Removes: service + config + install prefix."
  warn "Does NOT remove: user 'hpnsshd' and /var/empty (safe)."

  systemctl stop "${SERVICE}.service" 2>/dev/null || true
  systemctl disable "${SERVICE}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "${SERVICE}.service" 2>/dev/null || true

  rm -rf "$SYSCONFDIR" || true
  rm -rf "$PREFIX" || true
  rm -f "$RUNTIMELOG" || true

  ok "Uninstalled."
  echo -e "${C_GRAY}Optional cleanup:${C_RESET}"
  echo -e "  ${C_DIM}sudo userdel hpnsshd 2>/dev/null; sudo rm -rf /var/empty${C_RESET}"
}

install_cmd() {
  banner
  detect_ubuntu
  has_cmd systemctl || die "systemd is required (systemctl not found)."
  has_cmd ss || warn "'ss' not found? install iproute2."

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
  ok "DONE ✅"
  echo -e "${C_GRAY}Test:${C_RESET}  ${C_BOLD}ssh -p ${PORT} root@YOUR_SERVER_IP${C_RESET}"
  echo -e "${C_GRAY}Logs:${C_RESET}  ${C_BOLD}journalctl -u ${SERVICE} -f${C_RESET}  |  ${C_BOLD}tail -f ${RUNTIMELOG}${C_RESET}"
  hr
}

usage() {
  banner
  cat <<USAGE
Usage:
  sudo ./${0##*/} install
  sudo ./${0##*/} status
  sudo ./${0##*/} logs
  sudo ./${0##*/} uninstall

Env overrides:
  PORT=2222 SERVICE=hpnsshd PREFIX=/usr/local/hpnssh SYSCONFDIR=/etc/hpnssh MAKE_JOBS=1
  PERMIT_ROOT_LOGIN=prohibit-password|yes
  PASSWORD_AUTH=no|yes
  KBDINT_AUTH=no|yes
  USE_DNS=no
  LOGIN_GRACE_TIME=180
  MAX_AUTH_TRIES=6
  LOG_LEVEL=DEBUG2|VERBOSE
  CIPHERS="..."
USAGE
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    install)   install_cmd ;;
    status)    status_cmd ;;
    logs)      logs_cmd ;;
    uninstall) uninstall_cmd ;;
    ""|-h|--help|help) usage ;;
    *) die "Unknown command: $cmd (use: install/status/logs/uninstall)" ;;
  esac
}

need_root
main "$@"
