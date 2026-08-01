#!/usr/bin/env bash
# fxpool-proxy one-shot install / run / systemd helper.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BINARY_NAME="fxpool-proxy"
SERVICE_BASENAME="fxpool-proxy"
UNIT_NAME="${SERVICE_BASENAME}.service"
ENV_FILE="$SCRIPT_DIR/${SERVICE_BASENAME}.env"
UNIT_SYSTEM="/etc/systemd/system/${UNIT_NAME}"
UNIT_USER="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/${UNIT_NAME}"

env_get() {
  local suffix="$1" def="${2:-}"
  local fx="FXPOOL_${suffix}" ipp="IPP_${suffix}"
  if [[ -n "${!fx:-}" ]]; then
    printf '%s' "${!fx}"
  elif [[ -n "${!ipp:-}" ]]; then
    printf '%s' "${!ipp}"
  else
    printf '%s' "$def"
  fi
}

die() { echo "error: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

resolve_service_name() {
  if [[ -n "${FXPOOL_SERVICE_NAME:-}" ]]; then
    printf '%s' "$FXPOOL_SERVICE_NAME"
  elif [[ -n "${IPP_SERVICE_NAME:-}" ]]; then
    printf '%s' "$IPP_SERVICE_NAME"
  else
    printf '%s' "$UNIT_NAME"
  fi
}

systemd_mode() {
  if [[ "$(id -u)" -eq 0 ]]; then
    printf 'system'
  elif systemctl --user show-environment >/dev/null 2>&1; then
    printf 'user'
  else
    printf 'none'
  fi
}

systemctl_cmd() {
  local mode
  mode="$(systemd_mode)"
  case "$mode" in
    system) systemctl "$@" ;;
    user) systemctl --user "$@" ;;
    *) die "systemd is unavailable" ;;
  esac
}

unit_path() {
  case "$(systemd_mode)" in
    system) printf '%s' "$UNIT_SYSTEM" ;;
    user) printf '%s' "$UNIT_USER" ;;
    *) die "systemd is unavailable" ;;
  esac
}

ensure_binary() {
  local binary
  binary="$(env_get BINARY "$SCRIPT_DIR/$BINARY_NAME")"
  if [[ "$binary" == */* ]]; then
    if [[ ! -x "$binary" ]]; then
      info "building $BINARY_NAME"
      command -v go >/dev/null 2>&1 || die "go not found; install Go 1.24+ or set FXPOOL_BINARY"
      (cd "$SCRIPT_DIR" && go build -trimpath -o "$binary" "./cmd/$BINARY_NAME")
      chmod 755 "$binary"
    fi
    [[ -x "$binary" ]] || die "binary is not executable: $binary"
  else
    command -v -- "$binary" >/dev/null 2>&1 || die "binary unavailable: $binary"
  fi
  printf '%s' "$binary"
}

write_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    info "keeping existing env file: $ENV_FILE"
    return 0
  fi
  umask 077
  cat >"$ENV_FILE" <<'EOF'
# fxpool-proxy environment (mode 0600). Do not commit this file.
# FXPOOL_BIND=127.0.0.1
# FXPOOL_ADVERTISE_HOST=127.0.0.1
# FXPOOL_ROTATE_MODE=random
# FXPOOL_REFRESH_BEFORE_START=1
# FXPOOL_COUNTRIES=
# FXPOOL_LIMIT=
# FXPOOL_LISTEN_USER=
# FXPOOL_LISTEN_PASS=
EOF
  chmod 600 "$ENV_FILE"
  info "wrote $ENV_FILE (edit listen auth / bind before exposing non-loopback)"
}

write_unit() {
  local binary mode path user
  binary="$(ensure_binary)"
  mode="$(systemd_mode)"
  [[ "$mode" != none ]] || die "systemd is required for install"
  path="$(unit_path)"
  mkdir -p "$(dirname -- "$path")"

  user="$(id -un)"
  if [[ "$mode" == system ]]; then
    cat >"$path" <<EOF
[Unit]
Description=fxpool-proxy (Firefox IP Protection proxy pool)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$SCRIPT_DIR/install.sh run
Restart=on-failure
RestartSec=5
User=$user
Group=$(id -gn)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  else
    cat >"$path" <<EOF
[Unit]
Description=fxpool-proxy (Firefox IP Protection proxy pool)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$SCRIPT_DIR/install.sh run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF
  fi
  info "wrote unit: $path"
}

cmd_install() {
  local mode svc
  mkdir -p logs tokens data export
  chmod 700 logs tokens data export 2>/dev/null || true
  ensure_binary >/dev/null
  write_env_file
  write_unit
  mode="$(systemd_mode)"
  svc="$(resolve_service_name)"
  systemctl_cmd daemon-reload
  systemctl_cmd enable --now "$svc"
  sleep 1
  systemctl_cmd --no-pager --full status "$svc" || true
  info "install complete ($mode unit)"
  info "env: $ENV_FILE"
  info "exports after run: export/socks5.txt export/http.txt export/pool.json"
  info "import credentials if needed: ./fxpool-proxy import-credentials BUNDLE --delete-source"
}

cmd_run() {
  local binary bind advertise rotate refresh limit countries
  if [[ -n "${FXPOOL_PYTHON:-${IPP_PYTHON:-}}" ]]; then
    echo "FXPOOL_PYTHON/IPP_PYTHON is deprecated and ignored; configure FXPOOL_BINARY" >&2
  fi
  # Optional EnvironmentFile for foreground runs.
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  fi
  binary="$(ensure_binary)"
  bind="$(env_get BIND 127.0.0.1)"
  advertise="$(env_get ADVERTISE_HOST "$bind")"
  rotate="$(env_get ROTATE_MODE random)"
  refresh="$(env_get REFRESH_BEFORE_START 1)"
  limit="$(env_get LIMIT)"
  countries="$(env_get COUNTRIES)"
  case "$rotate" in random|rr) ;; *) die "FXPOOL_ROTATE_MODE must be 'random' or 'rr'" ;; esac
  case "$refresh" in 0|1) ;; *) die "FXPOOL_REFRESH_BEFORE_START must be '0' or '1'" ;; esac
  if [[ -n "$limit" && ( ! "$limit" =~ ^[0-9]+$ || "$limit" == 0 ) ]]; then
    die "FXPOOL_LIMIT must be a positive integer or empty"
  fi
  mkdir -p logs tokens data export
  if [[ "$refresh" == 1 ]]; then
    "$binary" token-refresh || echo "Startup token refresh failed; trying last-known-good token" >&2
  fi
  local cmd=("$binary" run --bind "$bind" --advertise-host "$advertise" --rotate-mode "$rotate")
  [[ -n "$countries" ]] && cmd+=(--countries "$countries")
  [[ -n "$limit" ]] && cmd+=(--limit "$limit")
  exec "${cmd[@]}"
}

cmd_restart() {
  local svc
  svc="$(resolve_service_name)"
  systemctl_cmd restart "$svc"
  sleep 2
  systemctl_cmd --no-pager --full status "$svc" || true
  info "listen auth: FXPOOL_LISTEN_USER / FXPOOL_LISTEN_PASS (env file or flags)"
  info "exports: export/socks5.txt export/http.txt export/pool.json"
}

cmd_status() {
  systemctl_cmd --no-pager --full status "$(resolve_service_name)"
}

cmd_stop() {
  systemctl_cmd stop "$(resolve_service_name)"
}

cmd_uninstall() {
  local svc path mode
  svc="$(resolve_service_name)"
  mode="$(systemd_mode)"
  [[ "$mode" != none ]] || die "systemd is unavailable"
  path="$(unit_path)"
  systemctl_cmd disable --now "$svc" 2>/dev/null || true
  rm -f "$path"
  systemctl_cmd daemon-reload
  info "removed unit $path (env/binary/data left in place)"
}

usage() {
  cat <<EOF
usage: $0 [install|run|restart|status|stop|uninstall]

  install    build binary, write env+systemd unit, enable --now (default)
  run        foreground: optional token-refresh then fxpool-proxy run
  restart    systemctl restart
  status     systemctl status
  stop       systemctl stop
  uninstall  disable and remove the unit file

Environment: FXPOOL_* (IPP_* still accepted). Optional file: $ENV_FILE
EOF
}

main() {
  local action="${1:-install}"
  case "$action" in
    -h|--help|help) usage ;;
    install) cmd_install ;;
    run) cmd_run ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    uninstall) cmd_uninstall ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
