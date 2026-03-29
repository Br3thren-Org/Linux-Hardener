#!/usr/bin/env bash
# lib/common.sh — foundational library sourced by all modules
# Do NOT add set -euo pipefail here; the caller (harden.sh) owns that.

# ─── Constants ──────────────────────────────────────────────────────────────

readonly HARDENER_VERSION="1.0.0"
readonly HARDENER_STATE_DIR="/var/lib/linux-hardener"
readonly HARDENER_LOG_DIR="/var/log/linux-hardener"

# ─── Globals (populated by init functions) ───────────────────────────────────

: "${DISTRO_FAMILY:=}"    # "debian" or "rhel"
: "${DISTRO_ID:=}"        # "debian", "ubuntu", "rocky", "almalinux"
: "${DISTRO_VERSION:=}"   # "12", "24.04", "9"
: "${DISTRO_CODENAME:=}"  # "bookworm", "noble", etc.
: "${RUN_MODE:=}"         # "audit", "dry-run", "apply", "rollback"
: "${BACKUP_DIR:=}"
: "${LOG_FILE:=}"
: "${CONFIG_FILE:=}"
: "${VERBOSE:=false}"
: "${MODULE_FILTER:=}"
declare -g CHANGES_APPLIED=0
declare -g CHANGES_SKIPPED=0
declare -g CHANGES_FAILED=0
declare -g AUDIT_FINDINGS=0

# ─── Logging ─────────────────────────────────────────────────────────────────

log_init() {
    mkdir -p "${HARDENER_LOG_DIR}"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    LOG_FILE="${HARDENER_LOG_DIR}/hardener_${timestamp}.log"
    touch "${LOG_FILE}"
    log_info "Linux Hardener v${HARDENER_VERSION} starting"
    log_info "Mode: ${RUN_MODE:-unset}  Distro: ${DISTRO_ID:-unknown}  Config: ${CONFIG_FILE:-none}"
}

log_msg() {
    local level="${1}"
    local message="${2}"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S')"
    local line="[${timestamp}] [${level}] ${message}"

    # Skip DEBUG unless VERBOSE is enabled
    if [[ "${level}" == "DEBUG" && "${VERBOSE}" != "true" ]]; then
        return 0
    fi

    if [[ -n "${LOG_FILE}" ]]; then
        printf '%s\n' "${line}" >> "${LOG_FILE}"
    fi
    printf '%s\n' "${line}"
}

log_info()    { log_msg "INFO"    "${1}"; }
log_warn()    { log_msg "WARN"    "${1}"; }
log_error()   { log_msg "ERROR"   "${1}"; }
log_debug()   { log_msg "DEBUG"   "${1}"; }
log_success() { log_msg "SUCCESS" "${1}"; }

# log_change what why risk validation rollback
log_change() {
    local what="${1}"
    local why="${2}"
    local risk="${3:-low}"
    local validation="${4:-}"
    local rollback="${5:-}"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S')"

    local entry
    entry="$(printf '[%s] [CHANGE] what=%q why=%q risk=%q validation=%q rollback=%q' \
        "${timestamp}" "${what}" "${why}" "${risk}" "${validation}" "${rollback}")"

    if [[ -n "${LOG_FILE}" ]]; then
        printf '%s\n' "${entry}" >> "${LOG_FILE}"
    fi
    printf '%s\n' "${entry}"
}

# ─── Distro Detection ─────────────────────────────────────────────────────────

detect_distro() {
    local os_release="/etc/os-release"
    if [[ ! -f "${os_release}" ]]; then
        log_error "Cannot detect distro: ${os_release} not found"
        return 1
    fi

    local id="" version_id="" version_codename="" id_like=""

    # Parse key=value pairs, stripping surrounding quotes
    while IFS='=' read -r key raw_val; do
        # Strip surrounding single or double quotes
        local val="${raw_val#\"}"
        val="${val%\"}"
        val="${val#\'}"
        val="${val%\'}"
        case "${key}" in
            ID)               id="${val}" ;;
            VERSION_ID)       version_id="${val}" ;;
            VERSION_CODENAME) version_codename="${val}" ;;
            ID_LIKE)          id_like="${val}" ;;
        esac
    done < "${os_release}"

    DISTRO_ID="${id}"
    DISTRO_VERSION="${version_id}"
    DISTRO_CODENAME="${version_codename}"

    # Determine family from ID and ID_LIKE
    case "${id}" in
        debian|ubuntu)
            DISTRO_FAMILY="debian" ;;
        rocky|almalinux|rhel|centos)
            DISTRO_FAMILY="rhel" ;;
        *)
            # Check ID_LIKE for derivatives
            case "${id_like}" in
                *debian*|*ubuntu*)
                    DISTRO_FAMILY="debian" ;;
                *rhel*|*centos*|*fedora*)
                    DISTRO_FAMILY="rhel" ;;
                *)
                    log_error "Unsupported distro: id='${id}' id_like='${id_like}'"
                    return 1 ;;
            esac ;;
    esac

    log_info "Detected distro: id=${DISTRO_ID} version=${DISTRO_VERSION} codename=${DISTRO_CODENAME} family=${DISTRO_FAMILY}"
    return 0
}

# ─── Config Loading ───────────────────────────────────────────────────────────

load_config() {
    local path="${1}"
    if [[ ! -f "${path}" ]]; then
        log_error "Config file not found: ${path}"
        return 1
    fi

    CONFIG_FILE="${path}"
    # shellcheck source=/dev/null
    source "${path}"

    apply_profile_defaults

    # Scan for unfilled placeholders (skip comment lines)
    local placeholders=()
    while IFS= read -r line; do
        local trimmed="${line#"${line%%[![:space:]]*}"}"
        if [[ "${trimmed}" == "#"* ]]; then
            continue
        fi
        if [[ "${line}" == *"__PLACEHOLDER__"* ]]; then
            placeholders+=("${line}")
        fi
    done < "${path}"

    if [[ ${#placeholders[@]} -gt 0 ]]; then
        log_error "Config file '${path}' contains unreplaced __PLACEHOLDER__ values:"
        local p
        for p in "${placeholders[@]}"; do
            log_error "  ${p}"
        done
        exit 1
    fi

    log_info "Config loaded from: ${path}"
    return 0
}

apply_profile_defaults() {
    case "${HARDENING_PROFILE:-aggressive}" in
        standard)
            : "${NOEXEC_TMP:=false}"
            : "${ENABLE_PASSWORD_POLICY:=false}"
            : "${ENABLE_FAIL2BAN:=false}"
            : "${ENABLE_AUDITD:=false}"
            : "${ENABLE_AIDE:=false}"
            : "${ENABLE_UNATTENDED_UPGRADES:=false}"
            ;;
        aggressive|*)
            : "${NOEXEC_TMP:=true}"
            : "${ENABLE_PASSWORD_POLICY:=true}"
            : "${ENABLE_FAIL2BAN:=true}"
            : "${ENABLE_AUDITD:=true}"
            : "${ENABLE_AIDE:=true}"
            : "${ENABLE_UNATTENDED_UPGRADES:=true}"
            ;;
    esac
}

# ─── Backup Helpers ───────────────────────────────────────────────────────────

init_backup_dir() {
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    BACKUP_DIR="${HARDENER_STATE_DIR}/backups/${timestamp}"
    mkdir -p "${BACKUP_DIR}"

    local latest_link="${HARDENER_STATE_DIR}/backups/latest"
    # Remove old symlink if it exists, then create a new one
    if [[ -L "${latest_link}" ]]; then
        rm -f "${latest_link}"
    fi
    ln -s "${BACKUP_DIR}" "${latest_link}"
    log_info "Backup directory initialized: ${BACKUP_DIR}"
}

backup_file() {
    local src="${1}"
    if [[ ! -e "${src}" ]]; then
        log_debug "backup_file: source does not exist, skipping: ${src}"
        return 0
    fi

    if [[ -z "${BACKUP_DIR}" ]]; then
        log_warn "backup_file: BACKUP_DIR not set, skipping backup of ${src}"
        return 1
    fi

    local dest_dir="${BACKUP_DIR}$(dirname "${src}")"
    mkdir -p "${dest_dir}"
    cp -a "${src}" "${dest_dir}/"
    log_debug "Backed up: ${src} -> ${dest_dir}/"
}

restore_file() {
    local src="${1}"
    if [[ -z "${BACKUP_DIR}" ]]; then
        log_error "restore_file: BACKUP_DIR not set"
        return 1
    fi

    local backup_copy="${BACKUP_DIR}${src}"
    if [[ ! -e "${backup_copy}" ]]; then
        log_error "restore_file: no backup found for ${src} at ${backup_copy}"
        return 1
    fi

    local dest_dir
    dest_dir="$(dirname "${src}")"
    mkdir -p "${dest_dir}"
    cp -a "${backup_copy}" "${dest_dir}/"
    log_info "Restored: ${backup_copy} -> ${dest_dir}/"
}

# ─── Mode Guards ─────────────────────────────────────────────────────────────

is_audit_mode()    { [[ "${RUN_MODE}" == "audit" ]]; }
is_dry_run()       { [[ "${RUN_MODE}" == "dry-run" ]]; }
is_apply_mode()    { [[ "${RUN_MODE}" == "apply" ]]; }
is_rollback_mode() { [[ "${RUN_MODE}" == "rollback" ]]; }

should_write() { is_apply_mode; }

guarded_write() {
    local description="${1}"
    shift
    if is_dry_run; then
        log_info "[DRY-RUN] Would execute: ${description} (cmd: $*)"
        return 0
    fi
    if is_apply_mode; then
        log_debug "Executing: ${description}"
        "$@"
        return $?
    fi
    log_debug "guarded_write: skipped in mode '${RUN_MODE}' — ${description}"
    return 0
}

# ─── Atomic File Writing ──────────────────────────────────────────────────────

write_file_atomic() {
    local dest="${1}"
    local content="${2}"
    local tmp_file="${dest}.tmp"

    backup_file "${dest}"

    printf '%s' "${content}" > "${tmp_file}"
    mv "${tmp_file}" "${dest}"
    log_debug "Atomically wrote: ${dest}"
}

write_file_if_changed() {
    local dest="${1}"
    local content="${2}"
    local description="${3}"

    if [[ -f "${dest}" ]]; then
        local current_content
        current_content="$(cat "${dest}")"
        if [[ "${current_content}" == "${content}" ]]; then
            log_debug "No change needed: ${dest}"
            (( CHANGES_SKIPPED++ )) || true
            return 2
        fi
    fi

    write_file_atomic "${dest}" "${content}"
    log_info "Applied change: ${description} -> ${dest}"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Module Filter ────────────────────────────────────────────────────────────

should_run_module() {
    local name="${1}"
    if [[ -z "${MODULE_FILTER}" ]]; then
        return 0
    fi

    local filter
    IFS=',' read -ra filter <<< "${MODULE_FILTER}"
    local item
    for item in "${filter[@]}"; do
        if [[ "${item}" == "${name}" ]]; then
            return 0
        fi
    done
    return 1
}

# ─── Package Manager Abstraction ─────────────────────────────────────────────

pkg_install() {
    case "${DISTRO_FAMILY}" in
        debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        rhel)
            dnf install -y "$@" ;;
        *)
            log_error "pkg_install: unsupported distro family '${DISTRO_FAMILY}'"
            return 1 ;;
    esac
}

pkg_remove() {
    case "${DISTRO_FAMILY}" in
        debian)
            apt-get purge -y "$@" ;;
        rhel)
            dnf remove -y "$@" ;;
        *)
            log_error "pkg_remove: unsupported distro family '${DISTRO_FAMILY}'"
            return 1 ;;
    esac
}

pkg_is_installed() {
    local package="${1}"
    case "${DISTRO_FAMILY}" in
        debian)
            dpkg -l "${package}" 2>/dev/null | grep -q '^ii' ;;
        rhel)
            rpm -q "${package}" &>/dev/null ;;
        *)
            log_error "pkg_is_installed: unsupported distro family '${DISTRO_FAMILY}'"
            return 1 ;;
    esac
}

pkg_update() {
    case "${DISTRO_FAMILY}" in
        debian)
            apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
        rhel)
            dnf update --security -y ;;
        *)
            log_error "pkg_update: unsupported distro family '${DISTRO_FAMILY}'"
            return 1 ;;
    esac
}

# ─── Service Helpers ──────────────────────────────────────────────────────────

svc_is_active()  { systemctl is-active  --quiet "${1}"; }
svc_is_enabled() { systemctl is-enabled --quiet "${1}"; }

svc_exists() {
    local name="${1}"
    systemctl list-unit-files "${name}.service" 2>/dev/null | grep -q "${name}.service"
}

svc_disable() {
    local service="${1}"
    local reason="${2}"

    if ! svc_exists "${service}"; then
        log_debug "svc_disable: service '${service}' does not exist, skipping"
        return 2
    fi

    # Already stopped, disabled, and masked — nothing to do
    if ! svc_is_active "${service}" && ! svc_is_enabled "${service}"; then
        log_debug "svc_disable: '${service}' already inactive and disabled, skipping"
        (( CHANGES_SKIPPED++ )) || true
        return 2
    fi

    log_change \
        "Disable service: ${service}" \
        "${reason}" \
        "low" \
        "systemctl is-enabled ${service}" \
        "systemctl unmask ${service} && systemctl enable ${service} && systemctl start ${service}"

    if ! should_write; then
        log_info "[DRY-RUN] Would disable service: ${service}"
        return 0
    fi

    systemctl stop    "${service}" 2>/dev/null || true
    systemctl disable "${service}" 2>/dev/null || true
    systemctl mask    "${service}" 2>/dev/null || true
    log_success "Service disabled and masked: ${service}"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Sysctl Helpers ───────────────────────────────────────────────────────────

sysctl_get() {
    local key="${1}"
    sysctl -n "${key}" 2>/dev/null
}

sysctl_check() {
    local key="${1}"
    local expected="${2}"
    local current
    current="$(sysctl_get "${key}")"
    if [[ "${current}" == "${expected}" ]]; then
        return 0
    fi
    log_debug "sysctl_check: ${key} current='${current}' expected='${expected}'"
    return 1
}

# ─── Summary and Results ─────────────────────────────────────────────────────

print_summary() {
    printf '\n'
    printf '═%.0s' {1..60}
    printf '\n'
    printf ' Linux Hardener v%s — Run Summary\n' "${HARDENER_VERSION}"
    printf '═%.0s' {1..60}
    printf '\n'
    printf ' Mode    : %s\n' "${RUN_MODE:-unknown}"
    printf ' Distro  : %s %s\n' "${DISTRO_ID:-unknown}" "${DISTRO_VERSION:-}"
    printf ' Profile : %s\n' "${HARDENING_PROFILE:-none}"
    printf '─%.0s' {1..60}
    printf '\n'
    printf ' Applied : %d\n' "${CHANGES_APPLIED}"
    printf ' Skipped : %d\n' "${CHANGES_SKIPPED}"
    printf ' Failed  : %d\n' "${CHANGES_FAILED}"
    printf ' Findings: %d\n' "${AUDIT_FINDINGS}"
    printf '─%.0s' {1..60}
    printf '\n'
    printf ' Log     : %s\n' "${LOG_FILE:-n/a}"
    printf '═%.0s' {1..60}
    printf '\n\n'
}

write_results_json() {
    local out_file="${HARDENER_STATE_DIR}/last-run.json"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    mkdir -p "${HARDENER_STATE_DIR}"

    # Build JSON manually to avoid requiring jq at runtime
    cat > "${out_file}" <<EOF
{
  "version": "${HARDENER_VERSION}",
  "timestamp": "${timestamp}",
  "distro": {
    "id": "${DISTRO_ID}",
    "family": "${DISTRO_FAMILY}",
    "version": "${DISTRO_VERSION}",
    "codename": "${DISTRO_CODENAME}"
  },
  "mode": "${RUN_MODE}",
  "profile": "${HARDENING_PROFILE:-}",
  "counters": {
    "applied": ${CHANGES_APPLIED},
    "skipped": ${CHANGES_SKIPPED},
    "failed": ${CHANGES_FAILED},
    "findings": ${AUDIT_FINDINGS}
  },
  "backup_dir": "${BACKUP_DIR}",
  "log_file": "${LOG_FILE}"
}
EOF

    log_info "Results written to: ${out_file}"
}
