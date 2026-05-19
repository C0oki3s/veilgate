#!/usr/bin/env bash
# VeilGate installer — https://veilgate.dev/install
# Usage: curl -sSL https://veilgate.dev/install | bash
#        curl -sSL https://veilgate.dev/install | bash -s -- --upstream http://localhost:3000

set -euo pipefail

REPO="C0oki3s/veilgate"
BINARY="veilgate"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/veilgate"
DATA_DIR="/var/lib/veilgate"
RULES_DIR="${DATA_DIR}/.veilgate/rules"
RULES_REPO="https://github.com/C0oki3s/veilgate-rules.git"
SERVICE_FILE="/etc/systemd/system/veilgate.service"

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
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
  --metrics-listen ADDR   Metrics listener address      (default: 127.0.0.1:9090)
  --no-service            Skip systemd service install
  --no-rules              Skip community rules clone
  -h, --help              Show this help

Examples:
  sudo bash install.sh --upstream http://localhost:3000
  sudo bash install.sh --upstream http://localhost:3000 --listen :443 --no-rules
EOF
}

# ── argument defaults ─────────────────────────────────────────────────────────
UPSTREAM=""
LISTEN=":8080"
METRICS_LISTEN="127.0.0.1:9090"
NO_SERVICE=false
NO_RULES=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --upstream)       UPSTREAM="$2";        shift 2 ;;
    --listen)         LISTEN="$2";          shift 2 ;;
    --metrics-listen) METRICS_LISTEN="$2";  shift 2 ;;
    --no-service)     NO_SERVICE=true;      shift ;;
    --no-rules)       NO_RULES=true;        shift ;;
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

# BIN_PATH is set by download_binary or build_from_source (avoids the
# bash set -e / command-substitution interaction where var=$(func) swallows
# failures and the EXIT trap deletes tmpdir before the caller installs).
BIN_PATH=""
BIN_TMPDIR=""

# ── download pre-built release binary ────────────────────────────────────────
# Sets BIN_PATH on success; returns 1 if the binary asset does not exist.
download_binary() {
  local version="$1" platform="$2"
  # GoReleaser strips the leading "v" from version in asset filenames,
  # but the tag (with "v") is still used in the download URL path.
  local ver_clean="${version#v}"
  local asset="${BINARY}_${ver_clean}_${platform}.tar.gz"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local checksum_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"
  local tmpdir
  tmpdir="$(mktemp -d)"

  info "Downloading ${asset}…"
  if ! curl -sSfL "$url" -o "${tmpdir}/${asset}" 2>/dev/null; then
    rm -rf "$tmpdir"
    return 1
  fi

  if curl -sSfL "$checksum_url" -o "${tmpdir}/checksums.txt" 2>/dev/null; then
    info "Verifying checksum…"
    local expected
    expected="$(grep "${asset}" "${tmpdir}/checksums.txt" || true)"
    if [[ -z "$expected" ]]; then
      warn "Asset not listed in checksums.txt — skipping verification."
    else
      echo "$expected" | (cd "$tmpdir" && sha256sum -c --quiet) \
        || { rm -rf "$tmpdir"; error "Checksum mismatch — download may be corrupted."; }
    fi
  else
    warn "No checksums.txt in this release — skipping verification."
  fi

  tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
  BIN_PATH="${tmpdir}/${BINARY}"
  BIN_TMPDIR="$tmpdir"
}

# ── build from source (fallback when no release binary exists) ───────────────
# Sets BIN_PATH on success; calls error() and exits if Go is unavailable.
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
  BIN_TMPDIR="$tmpdir"
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

# ── systemd service ───────────────────────────────────────────────────────────
write_service() {
  cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=VeilGate — tarpit + deception proxy for AI pentest agents
Documentation=https://veilgate.dev/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=veilgate
Group=veilgate

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

step "1/6  Detecting platform…"
PLATFORM="$(detect_platform)"
info "Platform: ${PLATFORM}"

step "2/6  Fetching latest release…"
VERSION="$(latest_version)"
if [[ -z "$VERSION" ]]; then
  warn "No published release found — will build from source."
  VERSION="dev"
fi
info "Version: ${VERSION}"

step "3/6  Downloading binary…"
if [[ "$VERSION" == "dev" ]]; then
  build_from_source
elif ! download_binary "$VERSION" "$PLATFORM"; then
  warn "Release ${VERSION} has no prebuilt binary for ${PLATFORM} — building from source."
  build_from_source
fi

step "4/6  Installing binary…"
install -m 0755 "$BIN_PATH" "${INSTALL_DIR}/${BINARY}"
rm -rf "$BIN_TMPDIR"
info "Installed to ${INSTALL_DIR}/${BINARY}"

step "5/6  Setting up config and data directories…"
# Service user
if ! id veilgate &>/dev/null; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin veilgate
  info "Created service user: veilgate"
fi

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "${DATA_DIR}/dumps" /var/log/veilgate
chown -R veilgate:veilgate "$DATA_DIR" /var/log/veilgate
chown root:veilgate "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# Community rules
if [[ "$NO_RULES" == false ]]; then
  if command -v git &>/dev/null; then
    if [[ -d "${RULES_DIR}/.git" ]]; then
      info "Updating community rules…"
      git -C "${RULES_DIR}" pull --ff-only -q
    else
      # Do NOT pre-create the directory — git clone creates it itself.
      # Pre-creating it causes "already exists" errors on some git versions.
      info "Cloning community rules…"
      mkdir -p "$(dirname "$RULES_DIR")"
      git clone --depth 1 "$RULES_REPO" "${RULES_DIR}" -q
    fi
    chown -R veilgate:veilgate "${DATA_DIR}/.veilgate"
    chmod -R g+r "${RULES_DIR}"
    # Rules dir must be writable by the veilgate user so the ML miner can
    # write learned.yaml on every tick.
    chmod g+w "${RULES_DIR}"
  else
    warn "git not found — skipping community rules. Install git and re-run, or clone manually:"
    warn "  git clone --depth 1 ${RULES_REPO} ${RULES_DIR}"
    # Create an empty dir so VeilGate starts without crashing on missing rules_dir.
    mkdir -p "${RULES_DIR}"
    chown -R veilgate:veilgate "${DATA_DIR}/.veilgate"
    chmod 770 "${RULES_DIR}"
  fi
else
  # --no-rules: create an empty dir so VeilGate has a valid rules_dir to watch.
  mkdir -p "${RULES_DIR}"
  chown -R veilgate:veilgate "${DATA_DIR}/.veilgate"
  chmod 770 "${RULES_DIR}"
fi

# Config (only write if it doesn't already exist)
if [[ ! -f "${CONFIG_DIR}/veilgate.yaml" ]]; then
  if [[ -z "$UPSTREAM" ]]; then
    warn "No --upstream provided. Defaulting to http://127.0.0.1:3000 — edit ${CONFIG_DIR}/veilgate.yaml to change."
    UPSTREAM="http://127.0.0.1:3000"
  fi
  SECRET="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  write_config "$UPSTREAM" "$SECRET"
  chmod 640 "${CONFIG_DIR}/veilgate.yaml"
  chown root:veilgate "${CONFIG_DIR}/veilgate.yaml"
  info "Config written to ${CONFIG_DIR}/veilgate.yaml"
else
  info "Config already exists — skipping (${CONFIG_DIR}/veilgate.yaml)"
fi

step "6/6  Installing systemd service…"
if [[ "$NO_SERVICE" == false ]] && command -v systemctl &>/dev/null; then
  write_service
  systemctl daemon-reload
  systemctl enable --now veilgate
  info "Service enabled and started."
  echo ""
  info "Status:  systemctl status veilgate"
  info "Logs:    journalctl -u veilgate -f"
else
  warn "Skipping systemd service setup (--no-service or systemctl not found)."
  info "Start manually: ${INSTALL_DIR}/${BINARY} -config ${CONFIG_DIR}/veilgate.yaml"
fi

INSTALLED_VERSION="$("${INSTALL_DIR}/${BINARY}" -version 2>/dev/null || echo "$VERSION")"
echo ""
echo -e "${GREEN}${BOLD}VeilGate ${INSTALLED_VERSION} installed successfully.${RESET}"
echo ""
echo -e "  Config:   ${CONFIG_DIR}/veilgate.yaml"
echo -e "  Logs:     journalctl -u veilgate -f"
echo -e "  Metrics:  http://${METRICS_LISTEN}/metrics"
echo -e "  Docs:     https://veilgate.dev"
echo ""
echo -e "${YELLOW}Start in observe mode, review metrics, then switch mode: challenge → tarpit${RESET}"
echo -e "  Edit ${CONFIG_DIR}/veilgate.yaml and set: mode: \"challenge\""
echo ""
