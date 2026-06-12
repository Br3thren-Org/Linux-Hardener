#!/usr/bin/env bash
# harden.sh — main entrypoint for Linux Hardener
# Sources all modules and orchestrates hardening in audit, apply, dry-run, or rollback mode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "${0}") <mode> [options]

Modes:
  --apply       Apply all hardening changes to the system
  --audit       Report on current system state without making changes
  --dry-run     Show what would be changed without applying
  --rollback    Restore files from the most recent backup

Options:
  --config PATH     Path to config file (default: ${SCRIPT_DIR}/config/hardener.conf)
  --modules LIST    Comma-separated list of modules to run (default: all)
  --luks-mode MODE  LUKS deployment strategy: auto | bare-metal | virtual
                    (default: auto — detect the environment at runtime)
  --luks-only       Run only the LUKS encryption module
  --verbose         Enable verbose/debug output
  --help, -h        Show this help message

Modules (execution order):
  packages    Install/verify required security packages
  services    Disable unnecessary or dangerous services
  auth        Harden local authentication and PAM settings
  ssh         Harden SSH server configuration
  ssh_crypto  Modern-only SSH kex/cipher/MAC policy + AllowGroups scoping
  firewall    Configure host-based firewall rules
  sysctl      Apply kernel hardening via sysctl
  kernel_cmdline  Boot-time kernel mitigations (optional; KERNEL_CMDLINE_HARDEN=yes)
  filesystem  Set secure mount options and file permissions
  logging     Configure system logging and audit rules
  remote_syslog  Forward logs to a remote collector (optional; RSYSLOG_REMOTE_HOST)
  integrity   Deploy file-integrity monitoring (AIDE)
  systemd_hardening  Apply security sandboxing to systemd services
  luks        At-rest encryption (optional; LUKS_ENABLED=yes in config/luks.conf)

Examples:
  sudo $(basename "${0}") --audit
  sudo $(basename "${0}") --apply
  sudo $(basename "${0}") --dry-run --modules ssh,sysctl
  sudo $(basename "${0}") --apply --config /etc/hardener.conf --verbose
  sudo $(basename "${0}") --rollback
EOF
}

# ─── Argument Parsing ─────────────────────────────────────────────────────────

parse_args() {
    local config_default="${SCRIPT_DIR}/config/hardener.conf"

    # Expose via globals
    RUN_MODE=""
    CONFIG_FILE="${config_default}"
    MODULE_FILTER=""
    VERBOSE="false"
    LUKS_MODE_OVERRIDE=""

    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --apply)
                RUN_MODE="apply"
                shift
                ;;
            --audit)
                RUN_MODE="audit"
                shift
                ;;
            --dry-run)
                RUN_MODE="dry-run"
                shift
                ;;
            --rollback)
                RUN_MODE="rollback"
                shift
                ;;
            --config)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --config requires a PATH argument\n' >&2
                    exit 1
                fi
                CONFIG_FILE="${2}"
                shift 2
                ;;
            --modules)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --modules requires a LIST argument\n' >&2
                    exit 1
                fi
                MODULE_FILTER="${2}"
                shift 2
                ;;
            --luks-mode)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --luks-mode requires a MODE argument (auto|bare-metal|virtual)\n' >&2
                    exit 1
                fi
                case "${2}" in
                    auto|bare-metal|virtual) LUKS_MODE_OVERRIDE="${2}" ;;
                    *)
                        printf 'ERROR: invalid --luks-mode: %s (use auto|bare-metal|virtual)\n' "${2}" >&2
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --luks-only)
                MODULE_FILTER="luks"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                printf 'ERROR: Unknown option: %s\n' "${1}" >&2
                usage
                exit 1
                ;;
        esac
    done

    if [[ -z "${RUN_MODE}" ]]; then
        printf 'ERROR: A mode (--apply, --audit, --dry-run, --rollback) is required.\n' >&2
        usage
        exit 1
    fi

    export RUN_MODE CONFIG_FILE MODULE_FILTER VERBOSE LUKS_MODE_OVERRIDE
}

# ─── Root Check ───────────────────────────────────────────────────────────────

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        printf 'ERROR: %s must be run as root (use sudo).\n' "$(basename "${0}")" >&2
        exit 1
    fi
}

# ─── Module Runner ────────────────────────────────────────────────────────────

run_module() {
    local module_name="${1}"

    # Skip if module is not in the filter list (when a filter is set)
    if ! should_run_module "${module_name}"; then
        log_debug "Skipping module (filtered): ${module_name}"
        return 0
    fi

    log_info "═══ Module: ${module_name} ═══"

    # Always run audit if the function exists
    if declare -f "${module_name}_audit" > /dev/null 2>&1; then
        "${module_name}_audit" || true
    fi

    case "${RUN_MODE}" in
        apply|dry-run)
            if declare -f "${module_name}_apply" > /dev/null 2>&1; then
                local exit_code=0
                "${module_name}_apply" || exit_code=$?
                case "${exit_code}" in
                    0)
                        log_success "Module ${module_name}: apply succeeded"
                        ;;
                    2)
                        log_info "Module ${module_name}: already compliant / skipped"
                        ;;
                    *)
                        log_error "Module ${module_name}: apply failed (exit ${exit_code})"
                        (( CHANGES_FAILED++ )) || true
                        ;;
                esac
            fi
            ;;
        rollback)
            if declare -f "${module_name}_rollback" > /dev/null 2>&1; then
                local exit_code=0
                "${module_name}_rollback" || exit_code=$?
                if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 2 ]]; then
                    log_error "Module ${module_name}: rollback failed (exit ${exit_code})"
                    (( CHANGES_FAILED++ )) || true
                fi
            fi
            ;;
        audit)
            # audit functions already called above; nothing more to do
            ;;
    esac
}

# ─── Module List ─────────────────────────────────────────────────────────────

readonly MODULES=(
    packages
    services
    auth
    ssh
    ssh_crypto
    firewall
    sysctl
    kernel_cmdline
    filesystem
    logging
    remote_syslog
    integrity
    systemd_hardening
    luks
)

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    require_root

    # Source foundational library — all utilities live here
    # shellcheck source=lib/common.sh
    source "${SCRIPT_DIR}/lib/common.sh"

    log_init
    load_config "${CONFIG_FILE}"

    # LUKS module config: config/luks.conf wins over LUKS_* values in the main
    # config; the --luks-mode CLI flag wins over both.
    if [[ -f "${SCRIPT_DIR}/config/luks.conf" ]]; then
        # shellcheck source=config/luks.conf
        source "${SCRIPT_DIR}/config/luks.conf"
        log_info "LUKS config loaded from: ${SCRIPT_DIR}/config/luks.conf"
    fi
    if [[ -n "${LUKS_MODE_OVERRIDE:-}" ]]; then
        LUKS_MODE="${LUKS_MODE_OVERRIDE}"
        log_info "LUKS mode overridden via CLI: ${LUKS_MODE}"
    fi

    # DRY_RUN=yes in the config demotes an apply run to dry-run globally
    if [[ "${DRY_RUN:-no}" == "yes" && "${RUN_MODE}" == "apply" ]]; then
        RUN_MODE="dry-run"
        log_warn "DRY_RUN=yes in config — running in dry-run mode (no changes will be written)"
    fi

    detect_distro

    # Source distro-specific adapter
    case "${DISTRO_FAMILY}" in
        debian)
            # shellcheck source=lib/distro/debian.sh
            source "${SCRIPT_DIR}/lib/distro/debian.sh"
            ;;
        rhel)
            # shellcheck source=lib/distro/rhel.sh
            source "${SCRIPT_DIR}/lib/distro/rhel.sh"
            ;;
        *)
            log_error "Unsupported distro family: ${DISTRO_FAMILY}"
            exit 1
            ;;
    esac

    # Source all hardening module files. Core modules live in lib/<name>.sh;
    # optional feature modules live in modules/NN_<name>.sh (numeric prefix).
    local module
    for module in "${MODULES[@]}"; do
        local module_file="${SCRIPT_DIR}/lib/${module}.sh"
        if [[ ! -f "${module_file}" ]]; then
            local candidate
            for candidate in "${SCRIPT_DIR}/modules/"[0-9]*"_${module}.sh"; do
                if [[ -f "${candidate}" ]]; then
                    module_file="${candidate}"
                    break
                fi
            done
        fi
        if [[ -f "${module_file}" ]]; then
            # shellcheck source=/dev/null
            source "${module_file}"
        else
            log_warn "Module file not found, skipping source: ${module_file}"
        fi
    done

    # Source rollback library
    # shellcheck source=lib/rollback.sh
    source "${SCRIPT_DIR}/lib/rollback.sh"

    # Mode-specific setup
    case "${RUN_MODE}" in
        apply)
            init_backup_dir
            ;;
        rollback)
            local latest_link="${HARDENER_STATE_DIR}/backups/latest"
            if [[ ! -L "${latest_link}" ]]; then
                log_error "No backup found at: ${latest_link}"
                exit 1
            fi
            BACKUP_DIR="$(readlink -f "${latest_link}")"
            if [[ ! -d "${BACKUP_DIR}" ]]; then
                log_error "Backup directory does not exist: ${BACKUP_DIR}"
                exit 1
            fi
            log_info "Rolling back from: ${BACKUP_DIR}"
            ;;
    esac

    # Run each module in order
    for module in "${MODULES[@]}"; do
        run_module "${module}"
    done

    # Post-run actions
    if [[ "${RUN_MODE}" == "apply" ]]; then
        write_results_json
    fi

    print_summary

    if [[ "${CHANGES_FAILED}" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
