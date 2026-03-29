#!/usr/bin/env bash
# lib/auth.sh — authentication hardening module (sourced by harden.sh)
# Provides: auth_audit, auth_apply, auth_rollback
# Requires: lib/common.sh to be sourced first.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly AUTH_TIMEOUT_FILE="/etc/profile.d/99-hardener-timeout.sh"
readonly AUTH_USB_CONF="/etc/modprobe.d/99-hardener-usb.conf"
readonly AUTH_PWQUALITY_CONF="/etc/security/pwquality.conf"

# ─── Audit ────────────────────────────────────────────────────────────────────

auth_audit() {
    log_info "auth: running audit checks"

    _auth_audit_login_banner
    _auth_audit_cron_restrict
    _auth_audit_shell_timeout
    _auth_audit_usb_storage
    _auth_audit_password_policy
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
    _auth_apply_password_policy
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

# ─── Rollback ─────────────────────────────────────────────────────────────────

auth_rollback() {
    log_info "auth: rolling back changes"

    local restore_targets=(
        "/etc/issue"
        "/etc/issue.net"
        "/etc/cron.allow"
        "/etc/at.allow"
        "${AUTH_PWQUALITY_CONF}"
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
