#!/usr/bin/env bash
# VeilGate installer — https://veilgate.dev/install
# Usage: curl -sSL https://veilgate.dev/install | bash
#        curl -sSL https://veilgate.dev/install | sudo bash -s -- --upstream http://localhost:3000

set -euo pipefail

REPO="C0oki3s/veilgate"
BINARY="veilgate"
ADMIN_BINARY="veilgate-admin"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/veilgate"
DATA_DIR="/var/lib/veilgate"
SERVICE_USER="veilgate"
SERVICE_GROUP="veilgate"
# Matches rules_dir: "~/.veilgate/rules" at runtime because the veilgate
# service user's home directory is DATA_DIR.
RULES_DIR="${DATA_DIR}/.veilgate/rules"
SERVICE_FILE="/etc/systemd/system/veilgate.service"
ADMIN_SERVICE_FILE="/etc/systemd/system/veilgate-admin.service"

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; CYAN="\033[36m"; RESET="\033[0m"
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi

info()  { echo -e "${GREEN}[veilgate]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[veilgate]${RESET} $*"; }
error() { echo -e "${RED}[veilgate]${RESET} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}$*${RESET}"; }

# ── usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: curl -sSL https://veilgate.dev/install | sudo bash -s -- [FLAGS]

Flags:
  --upstream URL          Upstream application address  (default: http://127.0.0.1:3000)
  --listen ADDR           Proxy listen address          (default: :8080)
  --admin-listen ADDR     Admin UI listen address       (default: 127.0.0.1:8888)
  --metrics-listen ADDR   Metrics listener address      (default: 127.0.0.1:9090)
  --secret SECRET         Challenge signing secret      (default: prompt or generate)
  --user USER             Service user                  (default: veilgate)
  --no-service            Skip systemd service install
  --no-rules              Skip community rules install
  --no-admin              Skip admin UI install
  -h, --help              Show this help

Examples:
  sudo bash install.sh --upstream http://localhost:3000
  sudo bash install.sh --upstream http://localhost:3000 --listen :443 --no-rules
  sudo bash install.sh --upstream http://localhost:3000 --admin-listen 0.0.0.0:8888
EOF
}

# ── argument defaults ─────────────────────────────────────────────────────────
UPSTREAM=""
LISTEN=":8080"
ADMIN_LISTEN="127.0.0.1:8888"
METRICS_LISTEN="127.0.0.1:9090"
SECRET=""
SECRET_PROVIDED=false
NO_SERVICE=false
NO_RULES=false
NO_ADMIN=false

require_value() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" || "${2:0:1}" == "-" ]]; then
    echo -e "${RED}[veilgate]${RESET} Missing value for ${flag}" >&2
    echo "" >&2
    usage >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --upstream)       require_value "$1" "${2:-}"; UPSTREAM="$2";        shift 2 ;;
    --listen)         require_value "$1" "${2:-}"; LISTEN="$2";          shift 2 ;;
    --admin-listen)   require_value "$1" "${2:-}"; ADMIN_LISTEN="$2";    shift 2 ;;
    --metrics-listen) require_value "$1" "${2:-}"; METRICS_LISTEN="$2";  shift 2 ;;
    --secret)         require_value "$1" "${2:-}"; SECRET="$2"; SECRET_PROVIDED=true; shift 2 ;;
    --user)           require_value "$1" "${2:-}"; SERVICE_USER="$2"; SERVICE_GROUP="$2"; shift 2 ;;
    --no-service)     NO_SERVICE=true;      shift ;;
    --no-rules)       NO_RULES=true;        shift ;;
    --no-admin)       NO_ADMIN=true;        shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo -e "${RED}[veilgate]${RESET} Unknown flag: $1" >&2; echo "" >&2; usage >&2; exit 1 ;;
  esac
done

# ── platform detection ────────────────────────────────────────────────────────
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *)      error "Unsupported OS: $os. Install from source: https://github.com/${REPO}" ;;
  esac

  case "$arch" in
    x86_64|amd64)   arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    *)              error "Unsupported arch: $arch. Install from source: https://github.com/${REPO}" ;;
  esac

  echo "${os}_${arch}"
}

# ── latest release from GitHub (returns "" if none published yet) ─────────────
latest_version() {
  curl -sf "https://api.github.com/repos/${REPO}/releases/latest" \
    2>/dev/null \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/' \
    || true
}

# BIN_PATH / ADMIN_BIN_PATH are set by download_binary or build_from_source.
BIN_PATH=""
ADMIN_BIN_PATH=""
BIN_TMPDIR=""

# ── download pre-built release binary ────────────────────────────────────────
# Downloads both veilgate and veilgate-admin from the same release.
# Sets BIN_PATH on success (and ADMIN_BIN_PATH when the admin asset exists);
# returns 1 if the main binary asset does not exist.
download_binary() {
  local version="$1" platform="$2"
  local ver_clean="${version#v}"
  local asset="${BINARY}_${ver_clean}_${platform}.tar.gz"
  local admin_asset="${ADMIN_BINARY}_${ver_clean}_${platform}.tar.gz"
  local base_url="https://github.com/${REPO}/releases/download/${version}"
  local checksum_url="${base_url}/checksums.txt"
  local tmpdir
  tmpdir="$(mktemp -d)"

  info "Downloading ${asset}…"
  if ! curl -sSfL "${base_url}/${asset}" -o "${tmpdir}/${asset}" 2>/dev/null; then
    rm -rf "$tmpdir"
    return 1
  fi

  if [[ "$NO_ADMIN" == false ]]; then
    info "Downloading ${admin_asset}…"
    if ! curl -sSfL "${base_url}/${admin_asset}" -o "${tmpdir}/${admin_asset}" 2>/dev/null; then
      warn "Admin binary asset not found in this release — will build from source."
    fi
  fi

  if curl -sSfL "$checksum_url" -o "${tmpdir}/checksums.txt" 2>/dev/null; then
    info "Verifying checksums…"
    for a in "$asset" "$admin_asset"; do
      [[ -f "${tmpdir}/${a}" ]] || continue
      local expected
      expected="$(grep "${a}" "${tmpdir}/checksums.txt" || true)"
      if [[ -z "$expected" ]]; then
        warn "${a} not listed in checksums.txt — skipping verification."
      else
        echo "$expected" | (cd "$tmpdir" && sha256sum -c --quiet) \
          || { rm -rf "$tmpdir"; error "Checksum mismatch for ${a} — download may be corrupted."; }
      fi
    done
  else
    warn "No checksums.txt in this release — skipping verification."
  fi

  tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
  BIN_PATH="${tmpdir}/${BINARY}"

  if [[ -f "${tmpdir}/${admin_asset}" ]]; then
    tar -xzf "${tmpdir}/${admin_asset}" -C "$tmpdir"
    ADMIN_BIN_PATH="${tmpdir}/${ADMIN_BINARY}"
  fi

  BIN_TMPDIR="$tmpdir"
}

# ── build from source (fallback when no release binary exists) ───────────────
build_from_source() {
  command -v go &>/dev/null \
    || error "No prebuilt binary available and 'go' is not installed.\nInstall Go from https://go.dev/dl/ or use Docker:\n  docker run -d --network host -e VEILGATE_SECRET=\$(openssl rand -hex 32) ghcr.io/c0oki3s/veilgate:latest"

  local goversion
  goversion="$(go version | awk '{print $3}' | sed 's/go//')"
  info "Building from source with Go ${goversion}…"

  local tmpdir
  tmpdir="$(mktemp -d)"

  git clone --depth 1 "https://github.com/${REPO}.git" "${tmpdir}/src" -q
  (cd "${tmpdir}/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "${tmpdir}/${BINARY}" ./cmd/veilgate)
  BIN_PATH="${tmpdir}/${BINARY}"

  if [[ "$NO_ADMIN" == false ]]; then
    info "Building admin binary from source…"
    (cd "${tmpdir}/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "${tmpdir}/${ADMIN_BINARY}" ./cmd/admin)
    ADMIN_BIN_PATH="${tmpdir}/${ADMIN_BINARY}"
  fi

  BIN_TMPDIR="$tmpdir"
}

generate_secret() {
  openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32
}

read_from_tty() {
  local prompt="$1" default="$2" reply=""
  if [[ -r /dev/tty ]]; then
    read -r -p "$prompt" reply </dev/tty || true
  else
    read -r -p "$prompt" reply || true
  fi
  if [[ -z "$reply" ]]; then
    reply="$default"
  fi
  printf '%s' "$reply"
}

resolve_secret() {
  if [[ -n "$SECRET" ]]; then
    :
  elif [[ -r /dev/tty ]]; then
    local reply=""
    read -r -s -p "Enter VeilGate challenge secret (blank to generate): " reply </dev/tty || true
    echo >/dev/tty
    SECRET="$reply"
  fi

  if [[ -z "$SECRET" ]]; then
    SECRET="$(generate_secret)"
    info "Generated challenge secret."
  else
    info "Using provided challenge secret."
  fi

  if [[ ${#SECRET} -lt 32 ]]; then
    error "Challenge secret must be at least 32 characters."
  fi
  if [[ "$SECRET" =~ [[:space:]\"\\] ]]; then
    error "Challenge secret must not contain whitespace, quotes, or backslashes."
  fi
}

ensure_service_user() {
  if id "$SERVICE_USER" &>/dev/null; then
    SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
    local existing_home
    existing_home="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
    if [[ "$existing_home" != "$DATA_DIR" ]]; then
      warn "User ${SERVICE_USER} already exists with home ${existing_home}; systemd rules_dir '~/.veilgate/rules' will resolve there at runtime."
      RULES_DIR="${existing_home}/.veilgate/rules"
      warn "Installing community rules into ${RULES_DIR} to match that runtime expansion."
    fi
    return
  fi

  local create="y"
  if [[ -r /dev/tty ]]; then
    create="$(read_from_tty "Create system user '${SERVICE_USER}' with home '${DATA_DIR}'? [Y/n] " "y")"
  fi
  case "$create" in
    y|Y|yes|YES)
      useradd --system --user-group --home "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
      SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
      info "Created service user: ${SERVICE_USER}"
      ;;
    *)
      error "Service user ${SERVICE_USER} is required. Re-run with --user <existing-user> or allow creation."
      ;;
  esac
}

run_as_service_user() {
  if command -v runuser &>/dev/null; then
    runuser -u "$SERVICE_USER" -- "$@"
  elif command -v sudo &>/dev/null; then
    sudo -u "$SERVICE_USER" "$@"
  else
    error "Need runuser or sudo to run commands as ${SERVICE_USER}."
  fi
}

restore_selinux_contexts() {
  if command -v restorecon &>/dev/null; then
    restorecon -R "$CONFIG_DIR" "$DATA_DIR" /var/log/veilgate 2>/dev/null || true
  fi
}

update_config_secret() {
  local cfg="${CONFIG_DIR}/veilgate.yaml" tmp
  tmp="$(mktemp)"
  awk -v secret="$SECRET" '
    BEGIN { in_challenge=0; wrote=0 }
    /^challenge:[[:space:]]*$/ {
      in_challenge=1
      print
      next
    }
    in_challenge && /^[^[:space:]]/ {
      if (!wrote) {
        print "  secret: \"" secret "\""
        wrote=1
      }
      in_challenge=0
    }
    in_challenge && /^[[:space:]]+secret:[[:space:]]*/ {
      if (!wrote) {
        print "  secret: \"" secret "\""
        wrote=1
      }
      next
    }
    { print }
    END {
      if (in_challenge && !wrote) {
        print "  secret: \"" secret "\""
      }
    }
  ' "$cfg" > "$tmp"
  install -m 0640 -o root -g "$SERVICE_GROUP" "$tmp" "$cfg"
  rm -f "$tmp"
}

# ── write default config ──────────────────────────────────────────────────────
write_config() {
  local upstream="$1" secret="$2"
  cat > "${CONFIG_DIR}/veilgate.yaml" <<EOF
listen: "${LISTEN}"
upstream: "${upstream}"
mode: "observe"

rules_dir: "~/.veilgate/rules"

challenge:
  secret: "${secret}"
  difficulty: 4
  ttl_minutes: 30

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 80
  window_seconds: 60
  trusted_ips: []
  trusted_proxies: []
  honeypot_paths:
    - "/.env"
    - "/.git/config"
    - "/wp-login.php"
    - "/phpmyadmin"
    - "/admin"
    - "/shell.php"

verifiers: {}

metrics:
  listen: "${METRICS_LISTEN}"

persist:
  enabled: true
  path: "${DATA_DIR}/events.db"
  dump_path: "${DATA_DIR}/dumps"
EOF
}

# ── proxy systemd service ─────────────────────────────────────────────────────
write_service() {
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=VeilGate — tarpit + deception proxy for AI pentest agents
Documentation=https://veilgate.dev/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}

ExecStart=/usr/local/bin/veilgate -config /etc/veilgate/veilgate.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
KillSignal=SIGTERM

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid

ReadWritePaths=/var/lib/veilgate /var/log/veilgate

RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
IPAddressAllow=::1/128 fc00::/7 fe80::/10

RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot
SystemCallArchitectures=native

LimitNOFILE=65536
LimitNPROC=512
TasksMax=256

StandardOutput=journal
StandardError=journal
SyslogIdentifier=veilgate

[Install]
WantedBy=multi-user.target
UNIT
  chown root:root "$SERVICE_FILE"
  chmod 0644 "$SERVICE_FILE"
}

# ── admin UI systemd service ──────────────────────────────────────────────────
write_admin_service() {
  cat > "$ADMIN_SERVICE_FILE" <<UNIT
[Unit]
Description=VeilGate Admin UI — configuration dashboard for the VeilGate proxy
Documentation=https://veilgate.dev/docs
After=network-online.target veilgate.service
Wants=network-online.target
PartOf=veilgate.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}

ExecStart=/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --db ${DATA_DIR}/admin.db \
  --audit-log ${DATA_DIR}/admin-audit.log \
  --addr ${ADMIN_LISTEN}

Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
KillSignal=SIGTERM

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid

ReadWritePaths=/etc/veilgate /var/lib/veilgate /var/log/veilgate

RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot
SystemCallArchitectures=native

LimitNOFILE=4096
LimitNPROC=256
TasksMax=128

StandardOutput=journal
StandardError=journal
SyslogIdentifier=veilgate-admin

[Install]
WantedBy=multi-user.target
UNIT
  chown root:root "$ADMIN_SERVICE_FILE"
  chmod 0644 "$ADMIN_SERVICE_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'BANNER'
 __   __   _ _  ___        _
 \ \ / /__(_) |/ __|__ _  | |_ ___
  \ V / -_) | | (_ / _` | |  _/ -_)
   \_/\___|_|_|\___\__,_|  \__\___|

BANNER
echo -e "${RESET}"

# Check we have curl and tar
for cmd in curl tar; do
  command -v "$cmd" &>/dev/null || error "Required tool not found: $cmd"
done

# Must be root (or sudo) for system-wide install
if [[ $EUID -ne 0 ]]; then
  error "Run as root or with sudo: curl -sSL https://veilgate.dev/install | sudo bash"
fi

step "1/7  Detecting platform…"
PLATFORM="$(detect_platform)"
info "Platform: ${PLATFORM}"

step "2/7  Fetching latest release…"
VERSION="$(latest_version)"
if [[ -z "$VERSION" ]]; then
  warn "No published release found — will build from source."
  VERSION="dev"
fi
info "Version: ${VERSION}"

step "3/7  Downloading binaries…"
if [[ "$VERSION" == "dev" ]]; then
  build_from_source
elif ! download_binary "$VERSION" "$PLATFORM"; then
  warn "Release ${VERSION} has no prebuilt binary for ${PLATFORM} — building from source."
  build_from_source
fi

# If the main binary downloaded but admin wasn't in the release, build it now.
if [[ "$NO_ADMIN" == false && -z "$ADMIN_BIN_PATH" && -n "$BIN_TMPDIR" ]]; then
  warn "Admin binary not in release assets — building from source."
  command -v go &>/dev/null || { warn "Go not found — skipping admin binary. Install Go and re-run to enable the admin UI."; NO_ADMIN=true; }
  if [[ "$NO_ADMIN" == false ]]; then
    if [[ ! -d "${BIN_TMPDIR}/src" ]]; then
      command -v git &>/dev/null || { warn "Git not found — skipping admin binary. Install Git and Go, then re-run to enable the admin UI."; NO_ADMIN=true; }
    fi
    if [[ "$NO_ADMIN" == false && ! -d "${BIN_TMPDIR}/src" ]]; then
      git clone --depth 1 "https://github.com/${REPO}.git" "${BIN_TMPDIR}/src" -q
    fi
  fi
  if [[ "$NO_ADMIN" == false ]]; then
    (cd "${BIN_TMPDIR}/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "${BIN_TMPDIR}/${ADMIN_BINARY}" ./cmd/admin)
    ADMIN_BIN_PATH="${BIN_TMPDIR}/${ADMIN_BINARY}"
  fi
fi

step "4/7  Installing binaries…"
install -m 0755 "$BIN_PATH" "${INSTALL_DIR}/${BINARY}"
info "Installed ${BINARY} → ${INSTALL_DIR}/${BINARY}"

if [[ "$NO_ADMIN" == false && -n "$ADMIN_BIN_PATH" ]]; then
  install -m 0755 "$ADMIN_BIN_PATH" "${INSTALL_DIR}/${ADMIN_BINARY}"
  info "Installed ${ADMIN_BINARY} → ${INSTALL_DIR}/${ADMIN_BINARY}"
elif [[ "$NO_ADMIN" == false ]]; then
  warn "Could not obtain ${ADMIN_BINARY} — skipping admin UI. Run with --no-admin to suppress this warning."
  NO_ADMIN=true
fi
rm -rf "$BIN_TMPDIR"

step "5/7  Setting up config and data directories…"
ensure_service_user

install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR" "${DATA_DIR}/dumps" /var/log/veilgate
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "${DATA_DIR}/.veilgate" "$RULES_DIR"
touch "${DATA_DIR}/admin.db" "${DATA_DIR}/admin-audit.log"
chown "$SERVICE_USER:$SERVICE_GROUP" "${DATA_DIR}/admin.db" "${DATA_DIR}/admin-audit.log"
chmod 0600 "${DATA_DIR}/admin.db" "${DATA_DIR}/admin-audit.log"

# Community rules
if [[ "$NO_RULES" == false ]]; then
  info "Installing community rules…"
  run_as_service_user "${INSTALL_DIR}/${BINARY}" update-rules --dir "${RULES_DIR}" --no-backup
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "${DATA_DIR}/.veilgate"
  find "${RULES_DIR}" -type d -exec chmod 0750 {} +
  find "${RULES_DIR}" -type f -exec chmod 0640 {} +
  # Rules dir must be writable so the ML miner can write learned.yaml on every tick.
  chmod u+w "${RULES_DIR}"
else
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "${DATA_DIR}/.veilgate"
  chmod 0750 "${RULES_DIR}"
fi

# Config (only write if it doesn't already exist)
if [[ ! -f "${CONFIG_DIR}/veilgate.yaml" ]]; then
  resolve_secret
  if [[ -z "$UPSTREAM" ]]; then
    warn "No --upstream provided. Defaulting to http://127.0.0.1:3000 — edit ${CONFIG_DIR}/veilgate.yaml to change."
    UPSTREAM="http://127.0.0.1:3000"
  fi
  write_config "$UPSTREAM" "$SECRET"
  info "Config written to ${CONFIG_DIR}/veilgate.yaml"
else
  info "Config already exists — skipping (${CONFIG_DIR}/veilgate.yaml)"
  if [[ "$SECRET_PROVIDED" == true ]]; then
    resolve_secret
    update_config_secret
    info "Updated challenge secret in ${CONFIG_DIR}/veilgate.yaml"
  fi
fi
chown root:"$SERVICE_GROUP" "${CONFIG_DIR}/veilgate.yaml"
chmod 0640 "${CONFIG_DIR}/veilgate.yaml"
restore_selinux_contexts

step "6/7  Installing proxy systemd service…"
if [[ "$NO_SERVICE" == false ]] && command -v systemctl &>/dev/null; then
  write_service
  systemctl daemon-reload
  systemctl enable --now veilgate
  info "veilgate.service enabled and started."
else
  warn "Skipping proxy systemd service (--no-service or systemctl not found)."
  info "Start manually: ${INSTALL_DIR}/${BINARY} -config ${CONFIG_DIR}/veilgate.yaml"
fi

step "7/7  Installing admin UI systemd service…"
if [[ "$NO_ADMIN" == false ]] && [[ "$NO_SERVICE" == false ]] && command -v systemctl &>/dev/null; then
  write_admin_service
  systemctl daemon-reload
  systemctl enable --now veilgate-admin
  info "veilgate-admin.service enabled and started."
elif [[ "$NO_ADMIN" == false ]]; then
  warn "Skipping admin systemd service (--no-service or systemctl not found)."
  info "Start manually: ${INSTALL_DIR}/${ADMIN_BINARY} --config ${CONFIG_DIR}/veilgate.yaml --db ${DATA_DIR}/admin.db --audit-log ${DATA_DIR}/admin-audit.log --addr ${ADMIN_LISTEN}"
fi

INSTALLED_VERSION="$("${INSTALL_DIR}/${BINARY}" -version 2>/dev/null || echo "$VERSION")"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD} VeilGate ${INSTALLED_VERSION} installed successfully${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${BOLD}Proxy${RESET}"
echo -e "    Config:   ${CONFIG_DIR}/veilgate.yaml"
echo -e "    Logs:     journalctl -u veilgate -f"
echo -e "    Metrics:  http://${METRICS_LISTEN}/metrics"
echo ""
if [[ "$NO_ADMIN" == false ]]; then
  echo -e "  ${BOLD}Admin Dashboard${RESET}   ${CYAN}http://${ADMIN_LISTEN}${RESET}"
  echo -e "    Username: ${BOLD}admin${RESET}"
  echo -e "    Password: ${BOLD}veilgate${RESET}  ${YELLOW}← you will be prompted to change on first login${RESET}"
  echo -e "    Logs:     journalctl -u veilgate-admin -f"
  echo ""
  if [[ "$ADMIN_LISTEN" == "127.0.0.1:"* ]]; then
    echo -e "  ${YELLOW}The admin UI is bound to localhost only.${RESET}"
    echo -e "  To access from your machine, SSH-tunnel to the port:"
    echo -e "    ${CYAN}ssh -L 8888:127.0.0.1:8888 <your-server>${RESET}"
    echo -e "  Then open: ${CYAN}http://localhost:8888${RESET}"
    echo ""
  fi
fi
echo -e "  ${BOLD}Docs:${RESET}     https://veilgate.dev"
echo -e "  ${BOLD}Issues:${RESET}   https://github.com/${REPO}/issues"
echo ""
echo -e "${YELLOW}VeilGate starts in observe mode — it logs but does not block.${RESET}"
echo -e "${YELLOW}Once you've reviewed traffic in the dashboard, switch mode:${RESET}"
echo -e "  Edit ${CONFIG_DIR}/veilgate.yaml →  mode: \"challenge\"  or  mode: \"tarpit\""
echo -e "  Then: systemctl restart veilgate"
echo ""
