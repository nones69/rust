#!/usr/bin/env bash
# =============================================================================
# IntentOS — Linux Upgrade Script
# Upgrades an existing IntentOS installation in place.
# Preserves ALL user configuration, logs, and custom settings.
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
    echo "  ║         ── In-Place Upgrade ──           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Configuration ─────────────────────────────────────────────────────────────
INTENTOS_USER="intentos"
INTENTOS_HOME="/opt/intentos"
INTENTOS_VENV="${INTENTOS_HOME}/venv"
INTENTOS_LOG="/var/log/intentos"
INTENTOS_RUN="/var/run/intentos"
REPO_URL="https://github.com/dmang69/cautious-octo-dollop"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Checks ────────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use: sudo bash upgrade.sh)"
        exit 1
    fi
}

check_installed() {
    if [[ ! -d "${INTENTOS_HOME}" ]]; then
        log_error "IntentOS does not appear to be installed at ${INTENTOS_HOME}."
        log_error "Run install.sh first."
        exit 1
    fi
    log_info "Existing installation found at ${INTENTOS_HOME}"
}

# ── Stop service before upgrade ────────────────────────────────────────────────
stop_service() {
    log_step "Stopping IntentOS service"
    if systemctl is-active --quiet intentos 2>/dev/null; then
        systemctl stop intentos
        log_info "Service stopped"
    else
        log_warn "Service was not running — continuing"
    fi
}

# ── Back up current configuration ─────────────────────────────────────────────
backup_config() {
    log_step "Backing up configuration"
    local backup_dir
    backup_dir="$(mktemp -d -t intentos-upgrade-backup-XXXXXXXXXX)"
    chmod 700 "${backup_dir}"

    # Preserve any user-created config files
    for cfg in config.json settings.json daemon.conf; do
        if [[ -f "${INTENTOS_HOME}/${cfg}" ]]; then
            cp "${INTENTOS_HOME}/${cfg}" "${backup_dir}/"
            log_info "Backed up: ${cfg}"
        fi
    done

    # Preserve any custom hook scripts
    if [[ -d "${INTENTOS_HOME}/hooks" ]]; then
        cp -r "${INTENTOS_HOME}/hooks" "${backup_dir}/"
        log_info "Backed up: hooks/"
    fi

    export BACKUP_DIR="${backup_dir}"
    log_info "Backup saved to: ${backup_dir}"
}

# ── Update application files ───────────────────────────────────────────────────
upgrade_app() {
    log_step "Upgrading application files"

    if [[ -d "${REPO_ROOT}/platform" ]]; then
        # Upgrading from local clone
        cp -r "${REPO_ROOT}/platform/." "${INTENTOS_HOME}/"
        log_info "Updated from local repository"
    else
        # Fetch latest from GitHub
        log_info "Downloading latest release from GitHub…"
        if command -v git &>/dev/null; then
            local tmp_src="/tmp/intentos-upgrade-src"
            rm -rf "${tmp_src}"
            local git_err
            git_err=$(git clone --depth=1 "${REPO_URL}" "${tmp_src}" 2>&1) || {
                log_error "Failed to clone repository: ${git_err}"
                exit 1
            }
            if [[ -d "${tmp_src}/platform" ]]; then
                cp -r "${tmp_src}/platform/." "${INTENTOS_HOME}/"
                rm -rf "${tmp_src}"
            fi
        fi
    fi

    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_HOME}"
    log_info "Application files upgraded"
}

# ── Restore configuration ──────────────────────────────────────────────────────
restore_config() {
    log_step "Restoring configuration"
    if [[ -n "${BACKUP_DIR:-}" && -d "${BACKUP_DIR}" ]]; then
        for f in "${BACKUP_DIR}"/*; do
            [[ -e "$f" ]] || continue
            base="$(basename "$f")"
            if [[ -d "$f" ]]; then
                cp -r "$f" "${INTENTOS_HOME}/${base}"
            else
                cp "$f" "${INTENTOS_HOME}/${base}"
            fi
            log_info "Restored: ${base}"
        done
    else
        log_warn "No backup directory found — skipping restore"
    fi
}

# ── Upgrade Python dependencies ────────────────────────────────────────────────
upgrade_venv() {
    log_step "Upgrading Python dependencies"

    if [[ ! -d "${INTENTOS_VENV}" ]]; then
        log_warn "Virtual environment not found — creating a new one"
        python3 -m venv "${INTENTOS_VENV}"
    fi

    "${INTENTOS_VENV}/bin/pip" install --upgrade pip -q

    if [[ -f "${INTENTOS_HOME}/requirements.txt" ]]; then
        "${INTENTOS_VENV}/bin/pip" install --upgrade -r "${INTENTOS_HOME}/requirements.txt" || {
            log_error "Failed to upgrade Python dependencies. Check requirements.txt."
            exit 1
        }
        log_info "Python dependencies upgraded"
    else
        "${INTENTOS_VENV}/bin/pip" install --upgrade flask || {
            log_error "Failed to upgrade core dependencies."
            exit 1
        }
        log_info "Core dependencies upgraded"
    fi

    chown -R "${INTENTOS_USER}:${INTENTOS_USER}" "${INTENTOS_VENV}"
}

# ── Reload and restart the service ────────────────────────────────────────────
restart_service() {
    log_step "Restarting IntentOS service"
    systemctl daemon-reload
    systemctl enable intentos 2>/dev/null || true
    systemctl start intentos
    log_info "Service restarted"
}

# ── Print upgrade summary ──────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}✓ IntentOS upgraded successfully!${NC}"
    echo ""
    echo "  Control Surface:  http://localhost:5000"
    echo "  Service status:   systemctl status intentos"
    echo "  Logs:             journalctl -u intentos -f"
    echo ""
    if [[ -n "${BACKUP_DIR:-}" ]]; then
        echo -e "${YELLOW}Pre-upgrade backup:  ${BACKUP_DIR}${NC}"
    fi
    echo -e "${YELLOW}Your existing apps, files, and settings were not modified.${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    banner
    check_root
    check_installed
    stop_service
    backup_config
    upgrade_app
    restore_config
    upgrade_venv
    restart_service
    print_summary
}

main "$@"
