#!/usr/bin/env bash
# lib/auth.sh — authentication hardening module (sourced by harden.sh)
# Provides: auth_audit, auth_apply, auth_rollback
# Requires: lib/common.sh to be sourced first.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly AUTH_TIMEOUT_FILE="/etc/profile.d/99-hardener-timeout.sh"
readonly AUTH_USB_CONF="/etc/modprobe.d/99-hardener-usb.conf"
readonly AUTH_FIREWIRE_CONF="/etc/modprobe.d/99-hardener-firewire.conf"
readonly AUTH_PROTOCOLS_CONF="/etc/modprobe.d/99-hardener-protocols.conf"
readonly AUTH_IPTABLES_CONF="/etc/modprobe.d/99-hardener-iptables.conf"
readonly AUTH_PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly AUTH_LOGIN_DEFS="/etc/login.defs"

# ─── Audit ────────────────────────────────────────────────────────────────────

auth_audit() {
    log_info "auth: running audit checks"

    _auth_audit_login_banner
    _auth_audit_cron_restrict
    _auth_audit_shell_timeout
    _auth_audit_usb_storage
    _auth_audit_password_policy
    _auth_audit_login_defs
}

_auth_audit_login_banner() {
    if [[ "${ENABLE_LOGIN_BANNER:-false}" != "true" ]]; then
        log_debug "auth_audit: login banner check skipped (ENABLE_LOGIN_BANNER != true)"
        return 0
    fi

    local issue_net="/etc/issue.net"
    if [[ ! -s "${issue_net}" ]]; then
        log_warn "FINDING: ${issue_net} is missing or empty — login banner not configured"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "auth_audit: login banner present (${issue_net})"
    fi
}

_auth_audit_cron_restrict() {
    if [[ ! -f "/etc/cron.allow" ]]; then
        log_warn "FINDING: /etc/cron.allow not present — cron not restricted"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "auth_audit: /etc/cron.allow exists"
    fi
}

_auth_audit_shell_timeout() {
    local found=false
    local conf_file

    # Search all files in /etc/profile.d/ for a TMOUT= assignment
    for conf_file in /etc/profile.d/*.sh; do
        [[ -f "${conf_file}" ]] || continue
        if grep -q 'TMOUT=' "${conf_file}" 2>/dev/null; then
            found=true
            log_debug "auth_audit: TMOUT found in ${conf_file}"
            break
        fi
    done

    if [[ "${found}" == "false" ]]; then
        log_warn "FINDING: TMOUT not set in /etc/profile.d/ — idle shell timeout not configured"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "auth_audit: shell TMOUT is configured"
    fi
}

_auth_audit_usb_storage() {
    local found=false
    local conf_file

    for conf_file in /etc/modprobe.d/*.conf; do
        [[ -f "${conf_file}" ]] || continue
        if grep -q 'blacklist usb-storage' "${conf_file}" 2>/dev/null; then
            found=true
            log_debug "auth_audit: usb-storage blacklisted in ${conf_file}"
            break
        fi
    done

    if [[ "${found}" == "false" ]]; then
        log_warn "FINDING: usb-storage not blacklisted in /etc/modprobe.d/ — USB storage is not disabled"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "auth_audit: usb-storage is blacklisted"
    fi
}

_auth_audit_password_policy() {
    if [[ "${ENABLE_PASSWORD_POLICY:-false}" != "true" ]]; then
        log_debug "auth_audit: password policy check skipped (ENABLE_PASSWORD_POLICY != true)"
        return 0
    fi

    local pkg_name
    pkg_name="$(_auth_pwquality_pkg_name)"

    if ! pkg_is_installed "${pkg_name}"; then
        log_warn "FINDING: ${pkg_name} not installed — password quality policy not enforced"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "auth_audit: ${pkg_name} is installed"
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

auth_apply() {
    log_info "auth: applying hardening"

    _auth_apply_login_banner
    _auth_apply_cron_restrict
    _auth_apply_shell_timeout
    _auth_apply_usb_blacklist
    _auth_apply_firewire_blacklist
    _auth_apply_protocol_blacklist
    _auth_apply_iptables_blacklist
    _auth_apply_password_policy
    _auth_apply_login_defs
}

_auth_apply_login_banner() {
    if [[ "${ENABLE_LOGIN_BANNER:-false}" != "true" ]]; then
        log_info "auth_apply: login banner skipped (ENABLE_LOGIN_BANNER != true)"
        return 0
    fi

    local banner_text
    banner_text="$(_auth_read_banner_text)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write login banner to /etc/issue and /etc/issue.net"
        return 0
    fi

    write_file_if_changed "/etc/issue"     "${banner_text}" "Set /etc/issue login banner"
    write_file_if_changed "/etc/issue.net" "${banner_text}" "Set /etc/issue.net login banner"

    log_change \
        "Login banner written to /etc/issue and /etc/issue.net" \
        "Display legal warning to deter unauthorized access" \
        "low" \
        "cat /etc/issue.net" \
        "truncate -s 0 /etc/issue && truncate -s 0 /etc/issue.net"
}

_auth_read_banner_text() {
    # 1. Explicit LOGIN_BANNER_FILE relative to SCRIPT_DIR
    if [[ -n "${LOGIN_BANNER_FILE:-}" ]]; then
        local explicit_path="${SCRIPT_DIR}/${LOGIN_BANNER_FILE}"
        if [[ -f "${explicit_path}" ]]; then
            cat "${explicit_path}"
            return 0
        fi
        log_warn "auth: LOGIN_BANNER_FILE '${explicit_path}' not found, falling back"
    fi

    # 2. Default bundled banner
    local default_banner="${SCRIPT_DIR}/config/ssh-banner.txt"
    if [[ -f "${default_banner}" ]]; then
        cat "${default_banner}"
        return 0
    fi

    # 3. Hardcoded fallback
    printf '%s\n' \
        "========================================================================" \
        "                     AUTHORIZED ACCESS ONLY" \
        "" \
        "  This system is for authorized users only. All activity is monitored" \
        "  and logged. Unauthorized access attempts will be reported." \
        "========================================================================"
}

_auth_apply_cron_restrict() {
    if ! should_write; then
        log_info "[DRY-RUN] Would restrict cron/at access to root only"
        return 0
    fi

    # cron.allow — only root may use cron
    write_file_if_changed "/etc/cron.allow" "root" "Restrict cron to root only"
    chmod 600 /etc/cron.allow

    # Remove cron.deny (allow-list takes precedence; deny-list is redundant and confusing)
    if [[ -f "/etc/cron.deny" ]]; then
        backup_file "/etc/cron.deny"
        rm -f "/etc/cron.deny"
        log_info "auth_apply: removed /etc/cron.deny"
    fi

    # at.allow — only root may use at
    write_file_if_changed "/etc/at.allow" "root" "Restrict at to root only"
    chmod 600 /etc/at.allow

    # Remove at.deny
    if [[ -f "/etc/at.deny" ]]; then
        backup_file "/etc/at.deny"
        rm -f "/etc/at.deny"
        log_info "auth_apply: removed /etc/at.deny"
    fi

    log_change \
        "cron and at restricted to root via allow-lists" \
        "Prevent non-root users from scheduling arbitrary jobs" \
        "medium" \
        "cat /etc/cron.allow && cat /etc/at.allow" \
        "rm -f /etc/cron.allow /etc/at.allow"
}

_auth_apply_shell_timeout() {
    local timeout="${SHELL_TIMEOUT:-900}"

    local content
    content="$(cat <<EOF
# Hardener: auto-logout idle shells after ${timeout}s
readonly TMOUT=${timeout}
export TMOUT
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write shell timeout (${timeout}s) to ${AUTH_TIMEOUT_FILE}"
        return 0
    fi

    write_file_if_changed "${AUTH_TIMEOUT_FILE}" "${content}" "Set idle shell timeout to ${timeout}s"

    log_change \
        "Shell idle timeout set to ${timeout}s via ${AUTH_TIMEOUT_FILE}" \
        "Automatically log out idle interactive shells to reduce attack surface" \
        "low" \
        "grep TMOUT ${AUTH_TIMEOUT_FILE}" \
        "rm -f ${AUTH_TIMEOUT_FILE}"
}

_auth_apply_usb_blacklist() {
    local content
    content="$(cat <<'EOF'
# Hardener: disable USB storage (not needed on cloud VPS)
blacklist usb-storage
install usb-storage /bin/true
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would blacklist usb-storage in ${AUTH_USB_CONF}"
        return 0
    fi

    write_file_if_changed "${AUTH_USB_CONF}" "${content}" "Blacklist usb-storage kernel module"

    log_change \
        "usb-storage blacklisted via ${AUTH_USB_CONF}" \
        "Prevent mounting of USB mass-storage devices on cloud VPS" \
        "low" \
        "cat ${AUTH_USB_CONF}" \
        "rm -f ${AUTH_USB_CONF}"
}

_auth_apply_firewire_blacklist() {
    local content
    content="$(cat <<'EOF'
# Hardener: disable firewire storage (STRG-1846)
blacklist firewire-ohci
blacklist firewire-sbp2
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would blacklist firewire modules in ${AUTH_FIREWIRE_CONF}"
        return 0
    fi

    write_file_if_changed "${AUTH_FIREWIRE_CONF}" "${content}" "Blacklist firewire kernel modules"

    log_change \
        "firewire-ohci and firewire-sbp2 blacklisted via ${AUTH_FIREWIRE_CONF}" \
        "Prevent firewire storage access on cloud VPS (Lynis STRG-1846)" \
        "low" \
        "cat ${AUTH_FIREWIRE_CONF}" \
        "rm -f ${AUTH_FIREWIRE_CONF}"
}

_auth_apply_protocol_blacklist() {
    local content
    content="$(cat <<'EOF'
# Hardener: disable uncommon network protocols (NETW-3200)
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would blacklist uncommon network protocols in ${AUTH_PROTOCOLS_CONF}"
        return 0
    fi

    write_file_if_changed "${AUTH_PROTOCOLS_CONF}" "${content}" "Blacklist uncommon network protocol modules"

    log_change \
        "dccp, sctp, rds, tipc disabled via ${AUTH_PROTOCOLS_CONF}" \
        "Reduce kernel attack surface by disabling unused network protocols (Lynis NETW-3200)" \
        "low" \
        "cat ${AUTH_PROTOCOLS_CONF}" \
        "rm -f ${AUTH_PROTOCOLS_CONF}"
}

_auth_apply_iptables_blacklist() {
    # Only apply on Debian — RHEL uses firewalld which relies on iptables kernel modules
    if [[ "${DISTRO_FAMILY:-}" != "debian" ]]; then
        log_debug "auth_apply: iptables blacklist skipped (not debian)"
        return 0
    fi

    local content
    content="$(cat <<'EOF'
# Hardener: prevent iptables modules from loading (using nftables instead)
install ip_tables /bin/true
install ip6_tables /bin/true
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would blacklist iptables modules in ${AUTH_IPTABLES_CONF}"
        return 0
    fi

    write_file_if_changed "${AUTH_IPTABLES_CONF}" "${content}" "Blacklist iptables kernel modules (prefer nftables)"

    log_change \
        "ip_tables and ip6_tables blacklisted via ${AUTH_IPTABLES_CONF}" \
        "Prevent FIRE-4512 warning: iptables modules loaded without rules (using nftables instead)" \
        "low" \
        "cat ${AUTH_IPTABLES_CONF}" \
        "rm -f ${AUTH_IPTABLES_CONF}"
}

_auth_apply_password_policy() {
    if [[ "${ENABLE_PASSWORD_POLICY:-false}" != "true" ]]; then
        log_info "auth_apply: password policy skipped (ENABLE_PASSWORD_POLICY != true)"
        return 0
    fi

    local pkg_name
    pkg_name="$(_auth_pwquality_pkg_name)"

    if ! should_write; then
        log_info "[DRY-RUN] Would install ${pkg_name} and write ${AUTH_PWQUALITY_CONF}"
        return 0
    fi

    if ! pkg_is_installed "${pkg_name}"; then
        log_info "auth_apply: installing ${pkg_name}"
        pkg_install "${pkg_name}"
    else
        log_debug "auth_apply: ${pkg_name} already installed"
    fi

    local content
    content="$(cat <<'EOF'
# Hardener: password quality requirements
minlen = 12
retry = 3
minclass = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
)"

    write_file_if_changed "${AUTH_PWQUALITY_CONF}" "${content}" "Apply password quality policy"

    log_change \
        "Password quality policy written to ${AUTH_PWQUALITY_CONF}" \
        "Enforce minimum password complexity to reduce brute-force risk" \
        "medium" \
        "cat ${AUTH_PWQUALITY_CONF}" \
        "rm -f ${AUTH_PWQUALITY_CONF}"
}

_auth_audit_login_defs() {
    if [[ ! -f "${AUTH_LOGIN_DEFS}" ]]; then
        log_debug "auth_audit: ${AUTH_LOGIN_DEFS} not found, skipping login.defs checks"
        return 0
    fi

    local -A expected_vals=(
        [SHA_CRYPT_MIN_ROUNDS]=5000
        [SHA_CRYPT_MAX_ROUNDS]=5000
        [PASS_MIN_DAYS]=1
        [PASS_MAX_DAYS]=365
        [PASS_WARN_AGE]=14
        [UMASK]=027
    )

    local key expected current
    for key in "${!expected_vals[@]}"; do
        expected="${expected_vals[${key}]}"
        current="$(grep -E "^[[:space:]]*${key}[[:space:]]" "${AUTH_LOGIN_DEFS}" 2>/dev/null | awk '{print $2}' | tail -1)"
        if [[ -z "${current}" || "${current}" != "${expected}" ]]; then
            log_warn "FINDING: ${AUTH_LOGIN_DEFS} ${key}='${current:-unset}', expected '${expected}'"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "auth_audit: ${AUTH_LOGIN_DEFS} ${key}=${current} (OK)"
        fi
    done
}

# _auth_set_login_defs_value — idempotent setter for a key in /etc/login.defs
# If the key exists (commented or uncommented), replace the line; otherwise append.
_auth_set_login_defs_value() {
    local key="${1}"
    local value="${2}"

    local current
    current="$(grep -E "^[[:space:]]*${key}[[:space:]]" "${AUTH_LOGIN_DEFS}" 2>/dev/null | awk '{print $2}' | tail -1)"

    if [[ "${current}" == "${value}" ]]; then
        log_debug "_auth_set_login_defs_value: ${key}=${value} already set (OK)"
        return 0
    fi

    log_info "auth_apply: setting ${key}=${value} in ${AUTH_LOGIN_DEFS} (was '${current:-unset}')"

    # Remove ALL existing lines (commented or not) that set this key
    sed -i "/^[[:space:]#]*${key}[[:space:]]/d" "${AUTH_LOGIN_DEFS}"
    # Append the single canonical value
    printf '%s\t%s\n' "${key}" "${value}" >> "${AUTH_LOGIN_DEFS}"
}

_auth_apply_login_defs() {
    if [[ ! -f "${AUTH_LOGIN_DEFS}" ]]; then
        log_warn "auth_apply: ${AUTH_LOGIN_DEFS} not found, skipping login.defs hardening"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would harden ${AUTH_LOGIN_DEFS} (SHA_CRYPT_MIN/MAX_ROUNDS, PASS_MIN/MAX_DAYS, PASS_WARN_AGE, UMASK)"
        return 0
    fi

    backup_file "${AUTH_LOGIN_DEFS}"

    _auth_set_login_defs_value "SHA_CRYPT_MIN_ROUNDS" "5000"
    _auth_set_login_defs_value "SHA_CRYPT_MAX_ROUNDS" "5000"
    _auth_set_login_defs_value "PASS_MIN_DAYS"        "1"
    _auth_set_login_defs_value "PASS_MAX_DAYS"        "365"
    _auth_set_login_defs_value "PASS_WARN_AGE"        "14"
    _auth_set_login_defs_value "UMASK"                "027"

    log_change \
        "Hardened ${AUTH_LOGIN_DEFS}: SHA_CRYPT_MIN_ROUNDS, SHA_CRYPT_MAX_ROUNDS, PASS_MIN/MAX_DAYS, PASS_WARN_AGE, UMASK" \
        "Apply password ageing policy and secure default umask (Lynis AUTH-9230/9286/9328)" \
        "medium" \
        "grep -E 'SHA_CRYPT_MIN_ROUNDS|SHA_CRYPT_MAX_ROUNDS|PASS_MIN_DAYS|PASS_MAX_DAYS|PASS_WARN_AGE|^UMASK' ${AUTH_LOGIN_DEFS}" \
        "restore_file ${AUTH_LOGIN_DEFS}"
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

auth_rollback() {
    log_info "auth: rolling back changes"

    local restore_targets=(
        "/etc/issue"
        "/etc/issue.net"
        "/etc/cron.allow"
        "/etc/at.allow"
        "${AUTH_PWQUALITY_CONF}"
        "${AUTH_LOGIN_DEFS}"
    )

    local target
    for target in "${restore_targets[@]}"; do
        restore_file "${target}" || true
    done

    # Remove files written by this module that have no meaningful "original" state
    if [[ -f "${AUTH_TIMEOUT_FILE}" ]]; then
        rm -f "${AUTH_TIMEOUT_FILE}"
        log_info "auth_rollback: removed ${AUTH_TIMEOUT_FILE}"
    fi

    if [[ -f "${AUTH_USB_CONF}" ]]; then
        rm -f "${AUTH_USB_CONF}"
        log_info "auth_rollback: removed ${AUTH_USB_CONF}"
    fi

    if [[ -f "${AUTH_FIREWIRE_CONF}" ]]; then
        rm -f "${AUTH_FIREWIRE_CONF}"
        log_info "auth_rollback: removed ${AUTH_FIREWIRE_CONF}"
    fi

    if [[ -f "${AUTH_PROTOCOLS_CONF}" ]]; then
        rm -f "${AUTH_PROTOCOLS_CONF}"
        log_info "auth_rollback: removed ${AUTH_PROTOCOLS_CONF}"
    fi

    if [[ -f "${AUTH_IPTABLES_CONF}" ]]; then
        rm -f "${AUTH_IPTABLES_CONF}"
        log_info "auth_rollback: removed ${AUTH_IPTABLES_CONF}"
    fi

    log_success "auth: rollback complete"
}

# ─── Internal Helpers ─────────────────────────────────────────────────────────

# Returns the correct pam_pwquality package name for the detected distro family.
_auth_pwquality_pkg_name() {
    case "${DISTRO_FAMILY:-}" in
        debian) printf 'libpam-pwquality' ;;
        rhel)   printf 'libpwquality'     ;;
        *)
            log_warn "_auth_pwquality_pkg_name: unknown DISTRO_FAMILY '${DISTRO_FAMILY}', defaulting to libpam-pwquality"
            printf 'libpam-pwquality'
            ;;
    esac
}
