#!/usr/bin/env bash
# =============================================================================
# IntentOS — Linux Universal Installer
# Supports: Ubuntu/Debian, Fedora/RHEL/CentOS, Arch, openSUSE
# Preserves ALL existing software, files, and settings.
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; }
log_step()  { echo -e "\n${BOLD}${BLUE}──${NC} ${BOLD}$*${NC}"; }
banner() {
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║         IntentOS Upgrade Layer           ║"
    echo "  ║   AI · Security · Communication · Safe   ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Configuration ─────────────────────────────────────────────────────────────
INTENTOS_USER="intentos"
INTENTOS_HOME="/opt/intentos"
INTENTOS_VENV="${INTENTOS_HOME}/venv"
INTENTOS_LOG="/var/log/intentos"
INTENTOS_RUN="/var/run/intentos"
SERVICE_FILE="/etc/systemd/system/intentos.service"
DESKTOP_FILE="/usr/share/applications/intentos.desktop"
REPO_URL="https://github.com/dmang69/cautious-octo-dollop"

# Source directory (when installing from local clone)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Checks ────────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This installer must be run as root (use: sudo bash install.sh)"
        exit 1
    fi
}

check_existing() {
    if systemctl is-active --quiet intentos 2>/dev/null; then
        log_warn "IntentOS is already running.  Upgrading in place…"
        systemctl stop intentos || true
    fi
}

detect_distro() {
    if command -v apt-get &>/dev/null; then
        DISTRO="debian"
        PKG_INSTALL="apt-get install -y -q"
        PKG_UPDATE="apt-get update -q"
    elif command -v dnf &>/dev/null; then
        DISTRO="fedora"
        PKG_INSTALL="dnf install -y -q"
        PKG_UPDATE="dnf check-update -q || true"
    elif command -v yum &>/dev/null; then
        DISTRO="rhel"
        PKG_INSTALL="yum install -y -q"
        PKG_UPDATE="yum check-update -q || true"
    elif command -v pacman &>/dev/null; then
        DISTRO="arch"
        PKG_INSTALL="pacman -S --noconfirm --quiet"
        PKG_UPDATE="pacman -Sy --quiet"
    elif command -v zypper &>/dev/null; then
        DISTRO="suse"
        PKG_INSTALL="zypper install -y -q"
        PKG_UPDATE="zypper refresh -q"
    else
        log_error "Unsupported package manager.  Supported: apt, dnf, yum, pacman, zypper"
        exit 1
    fi
    log_info "Detected distro family: ${DISTRO}"
}

# ── Install system packages ───────────────────────────────────────────────────
install_dependencies() {
    log_step "Installing system dependencies"
    ${PKG_UPDATE} 2>/dev/null || true

    if [[ "${DISTRO}" == "debian" ]]; then
        ${PKG_INSTALL} python3 python3-pip python3-venv curl wget git 2>/dev/null
    elif [[ "${DISTRO}" == "fedora" || "${DISTRO}" == "rhel" ]]; then
        ${PKG_INSTALL} python3 python3-pip curl wget git 2>/dev/null
    elif [[ "${DISTRO}" == "arch" ]]; then
        ${PKG_INSTALL} python python-pip curl wget git 2>/dev/null
    elif [[ "${DISTRO}" == "suse" ]]; then
        ${PKG_INSTALL} python3 python3-pip curl wget git 2>/dev/null
    fi

    # Verify python3 is available
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 installation failed.  Please install python3 manually."
        exit 1
    fi

    PY_VER=$(python3 --version 2>&1)
    log_info "Python: ${PY_VER}"
}

# ── Create service user ────────────────────────────────────────────────────────
create_user() {
    log_step "Creating system user"
    if id "${INTENTOS_USER}" &>/dev/null; then
        log_info "User '${INTENTOS_USER}' already exists"
    else
        useradd --system --home-dir "${INTENTOS_HOME}" \
                --shell /bin/false --comment "IntentOS daemon" \
                "${INTENTOS_USER}"
        log_info "Created system user '${INTENTOS_USER}'"
    fi
}

# ── Copy application files ─────────────────────────────────────────────────────
install_app() {
    log_step "Installing application to ${INTENTOS_HOME}"

    mkdir -p "${INTENTOS_HOME}" "${INTENTOS_LOG}" "${INTENTOS_RUN}"

    if [[ -d "${REPO_ROOT}/platform" ]]; then
        # Installing from local clone
        cp -r "${REPO_ROOT}/platform/." "${INTENTOS_HOME}/"
        log_info "Copied from local repository"
    else
        # Fetch from GitHub
        log_info "Downloading from GitHub…"
        if command -v git &>/dev/null; then
            git clone --depth=1 "${REPO_URL}" /tmp/intentos-src 2>/dev/null || true
            if [[ -d /tmp/intentos-src/platform ]]; then
                cp -r /tmp/intentos-src/platform/. "${INTENTOS_HOME}/"
                rm -rf /tmp/intentos-src
            fi
        fi
    fi

    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_HOME}"
    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_LOG}"
    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_RUN}"
    log_info "Application files installed"
}

# ── Create virtual environment and install Python deps ───────────────────────
setup_venv() {
    log_step "Setting up Python virtual environment"

    python3 -m venv "${INTENTOS_VENV}"
    "${INTENTOS_VENV}/bin/pip" install --upgrade pip -q

    if [[ -f "${INTENTOS_HOME}/requirements.txt" ]]; then
        "${INTENTOS_VENV}/bin/pip" install -r "${INTENTOS_HOME}/requirements.txt" -q
        log_info "Python dependencies installed"
    else
        "${INTENTOS_VENV}/bin/pip" install flask -q
        log_info "Core dependencies installed"
    fi

    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_VENV}"
}

# ── Install systemd service ────────────────────────────────────────────────────
install_service() {
    log_step "Installing systemd service"

    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=IntentOS Upgrade Layer — AI Security & Communication Daemon
Documentation=https://github.com/dmang69/cautious-octo-dollop
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${INTENTOS_USER}
Group=${INTENTOS_USER}
WorkingDirectory=${INTENTOS_HOME}
Environment="INTENTOS_LOG_DIR=${INTENTOS_LOG}"
Environment="INTENTOS_PID=${INTENTOS_RUN}/daemon.pid"
Environment="INTENTOS_STATUS=${INTENTOS_RUN}/status.json"
Environment="PATH=${INTENTOS_VENV}/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INTENTOS_VENV}/bin/python ${INTENTOS_HOME}/daemon/intentos_daemon.py \\
          --host 127.0.0.1 --port 5000
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=append:${INTENTOS_LOG}/stdout.log
StandardError=append:${INTENTOS_LOG}/stderr.log
LimitNOFILE=65536

# Hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${INTENTOS_LOG} ${INTENTOS_RUN} ${INTENTOS_HOME}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable intentos
    systemctl start intentos
    log_info "systemd service installed and started"
}

# ── Install desktop entry ──────────────────────────────────────────────────────
install_desktop_entry() {
    log_step "Installing desktop entry"

    cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=IntentOS Control Surface
Comment=AI-powered security and communication upgrade layer
Exec=xdg-open http://localhost:5000
Icon=utilities-system-monitor
Categories=System;Security;
Keywords=AI;security;privacy;IntentOS;
StartupNotify=false
EOF

    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database -q /usr/share/applications/ || true
    fi
    log_info "Desktop entry installed"
}

# ── Create convenience CLI ─────────────────────────────────────────────────────
install_cli() {
    log_step "Installing intentos CLI"

    cat > /usr/local/bin/intentos <<'CLISCRIPT'
#!/usr/bin/env bash
# IntentOS management CLI
CMD="${1:-status}"
case "$CMD" in
    start)   systemctl start  intentos; echo "IntentOS started."  ;;
    stop)    systemctl stop   intentos; echo "IntentOS stopped."  ;;
    restart) systemctl restart intentos; echo "IntentOS restarted." ;;
    status)  systemctl status intentos ;;
    logs)    journalctl -u intentos -n ${2:-50} --no-pager ;;
    open)    xdg-open http://localhost:5000 2>/dev/null || \
             echo "Open: http://localhost:5000" ;;
    *)       echo "Usage: intentos {start|stop|restart|status|logs|open}" ;;
esac
CLISCRIPT

    chmod +x /usr/local/bin/intentos
    log_info "CLI installed: 'intentos start|stop|status|logs|open'"
}

# ── Post-install summary ───────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}✓ IntentOS installed successfully!${NC}"
    echo ""
    echo "  Control Surface:  http://localhost:5000"
    echo "  Service status:   systemctl status intentos"
    echo "  Logs:             journalctl -u intentos -f"
    echo "  CLI:              intentos {start|stop|restart|status|logs|open}"
    echo ""
    echo -e "${YELLOW}Your existing apps, files, and settings were not modified.${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    banner
    check_root
    check_existing
    detect_distro
    install_dependencies
    create_user
    install_app
    setup_venv
    install_service
    install_desktop_entry
    install_cli
    print_summary
}

main "$@"
