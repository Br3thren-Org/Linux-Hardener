#!/usr/bin/env bash
# lib/ssh.sh — SSH hardening module (audit / apply / rollback)
# Sourced by harden.sh after lib/common.sh.  All log_*, backup_file,
# restore_file, write_file_if_changed, should_write, guarded_write helpers
# from common.sh are available here.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly SSH_DROPIN_PATH="/etc/ssh/sshd_config.d/99-hardening.conf"
readonly SSH_MAIN_CONFIG="/etc/ssh/sshd_config"
readonly SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"

# ─── Internal helpers ─────────────────────────────────────────────────────────

# _ssh_get_effective_value — query the effective sshd config for a given key
# Uses `sshd -T` to resolve the merged / final value, lowercase output.
_ssh_get_effective_value() {
    local key="${1}"
    sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}' | tr '[:upper:]' '[:lower:]'
}

# _ssh_check_setting — compare effective sshd setting to expected value, log findings
# Returns 0 if compliant, 1 if non-compliant, 2 if value cannot be determined.
_ssh_check_setting() {
    local key="${1}"
    local expected="${2}"

    local actual
    actual="$(_ssh_get_effective_value "${key}")"

    if [[ -z "${actual}" ]]; then
        log_warn "ssh_audit: cannot determine value for '${key}' (sshd -T failed or key absent)"
        (( AUDIT_FINDINGS++ )) || true
        return 2
    fi

    local expected_lower
    expected_lower="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"

    if [[ "${actual}" == "${expected_lower}" ]]; then
        log_debug "ssh_audit: ${key}=${actual} (OK)"
        return 0
    fi

    log_warn "FINDING: SSH setting '${key}' is '${actual}', expected '${expected_lower}'"
    (( AUDIT_FINDINGS++ )) || true
    return 1
}

# ─── Audit ────────────────────────────────────────────────────────────────────

ssh_audit() {
    log_info "ssh_audit: auditing SSH server configuration"

    # --- Check for Include directive in sshd_config ---
    if ! grep -qiE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/" "${SSH_MAIN_CONFIG}" 2>/dev/null; then
        log_msg "NOTE" "ssh_audit: ${SSH_MAIN_CONFIG} does not contain an Include directive for ${SSH_DROPIN_DIR}/"
    else
        log_debug "ssh_audit: ${SSH_MAIN_CONFIG} includes ${SSH_DROPIN_DIR}/ (OK)"
    fi

    # --- Verify expected effective settings via sshd -T ---
    _ssh_check_setting "permitrootlogin"       "${SSH_PERMIT_ROOT_LOGIN:-prohibit-password}"
    _ssh_check_setting "passwordauthentication" "${SSH_PASSWORD_AUTH:-no}"
    _ssh_check_setting "x11forwarding"          "no"
    _ssh_check_setting "maxauthtries"           "3"
    _ssh_check_setting "allowtcpforwarding"     "${SSH_ALLOW_TCP_FORWARDING:-no}"
    _ssh_check_setting "allowagentforwarding"   "${SSH_ALLOW_AGENT_FORWARDING:-no}"

    # --- Check whether the drop-in file exists ---
    if [[ -f "${SSH_DROPIN_PATH}" ]]; then
        log_info "ssh_audit: drop-in file exists: ${SSH_DROPIN_PATH} (OK)"
    else
        log_warn "FINDING: SSH hardening drop-in file is missing: ${SSH_DROPIN_PATH}"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

ssh_apply() {
    log_info "ssh_apply: applying SSH hardening configuration"

    # --- Ensure the drop-in directory exists ---
    if [[ ! -d "${SSH_DROPIN_DIR}" ]]; then
        if should_write; then
            mkdir -p "${SSH_DROPIN_DIR}"
            log_info "ssh_apply: created directory ${SSH_DROPIN_DIR}"
        else
            log_info "[DRY-RUN] Would create directory: ${SSH_DROPIN_DIR}"
        fi
    fi

    # --- Ensure sshd_config has an Include directive ---
    if ! grep -qiE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/" "${SSH_MAIN_CONFIG}" 2>/dev/null; then
        log_info "ssh_apply: ${SSH_MAIN_CONFIG} lacks Include directive — adding it"
        log_change \
            "Prepend Include directive to ${SSH_MAIN_CONFIG}" \
            "Allow drop-in configs in ${SSH_DROPIN_DIR}/ to be loaded by sshd" \
            "low" \
            "grep -qiE 'Include.*sshd_config\\.d' ${SSH_MAIN_CONFIG}" \
            "restore_file ${SSH_MAIN_CONFIG}"

        if should_write; then
            backup_file "${SSH_MAIN_CONFIG}"
            local original_content
            original_content="$(cat "${SSH_MAIN_CONFIG}")"
            printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n%s' "${original_content}" \
                > "${SSH_MAIN_CONFIG}.tmp"
            mv "${SSH_MAIN_CONFIG}.tmp" "${SSH_MAIN_CONFIG}"
            log_info "ssh_apply: Include directive prepended to ${SSH_MAIN_CONFIG}"
        else
            log_info "[DRY-RUN] Would prepend Include directive to ${SSH_MAIN_CONFIG}"
        fi
    else
        log_debug "ssh_apply: ${SSH_MAIN_CONFIG} already has Include directive (OK)"
    fi

    # --- Build drop-in config content ---
    local dropin_content
    dropin_content="$(cat <<EOF
# /etc/ssh/sshd_config.d/99-hardening.conf
# Generated by Linux Hardener — do not edit manually.
# To customise, adjust the config variables and re-run harden.sh --apply.

PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN:-prohibit-password}
PasswordAuthentication ${SSH_PASSWORD_AUTH:-no}
ChallengeResponseAuthentication no
MaxAuthTries 3
LoginGraceTime 30
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding ${SSH_ALLOW_TCP_FORWARDING:-no}
AllowAgentForwarding ${SSH_ALLOW_AGENT_FORWARDING:-no}
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 2
Compression no
TCPKeepAlive no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
UsePAM yes
LogLevel VERBOSE
Banner /etc/issue.net
MaxStartups 10:30:60
AllowStreamLocalForwarding no
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write SSH drop-in config to ${SSH_DROPIN_PATH}"
        log_debug "Drop-in content (preview):"
        log_debug "${dropin_content}"
        return 0
    fi

    # --- Write drop-in via write_file_if_changed ---
    local write_result=0
    write_file_if_changed "${SSH_DROPIN_PATH}" "${dropin_content}" \
        "SSH hardening drop-in config" || write_result=$?

    # write_result=2 means no change needed; that is fine
    if [[ "${write_result}" -ne 0 && "${write_result}" -ne 2 ]]; then
        log_error "ssh_apply: failed to write ${SSH_DROPIN_PATH}"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    # --- Enforce permissions ---
    chmod 600 "${SSH_DROPIN_PATH}"
    log_debug "ssh_apply: set permissions 600 on ${SSH_DROPIN_PATH}"

    # --- Validate config before reloading ---
    log_info "ssh_apply: validating configuration with 'sshd -t'"
    if ! sshd -t 2>/tmp/sshd_validate_err; then
        local err_output
        err_output="$(cat /tmp/sshd_validate_err)"
        log_error "ssh_apply: sshd -t validation FAILED — reverting drop-in"
        log_error "sshd validation error: ${err_output}"

        # Revert the drop-in
        rm -f "${SSH_DROPIN_PATH}"
        log_warn "ssh_apply: removed invalid drop-in file ${SSH_DROPIN_PATH}"

        (( CHANGES_FAILED++ )) || true
        return 1
    fi
    log_info "ssh_apply: configuration validated successfully"

    # --- Reload sshd ---
    log_change \
        "SSH hardening drop-in written: ${SSH_DROPIN_PATH}" \
        "Apply CIS/STIG-aligned SSH restrictions to reduce attack surface" \
        "medium" \
        "sshd -T | grep -i 'passwordauthentication no'" \
        "ssh_rollback"

    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || {
        log_error "ssh_apply: failed to reload sshd — check service status manually"
        (( CHANGES_FAILED++ )) || true
        return 1
    }

    log_success "ssh_apply: sshd reloaded with hardened configuration"
    return 0
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

ssh_rollback() {
    log_info "ssh_rollback: reverting SSH hardening changes"

    # --- Remove the drop-in file ---
    if [[ -f "${SSH_DROPIN_PATH}" ]]; then
        rm -f "${SSH_DROPIN_PATH}"
        log_info "ssh_rollback: removed drop-in file ${SSH_DROPIN_PATH}"
    else
        log_debug "ssh_rollback: drop-in file not present, nothing to remove"
    fi

    # --- Restore the main sshd_config from backup ---
    restore_file "${SSH_MAIN_CONFIG}" || {
        log_warn "ssh_rollback: no backup found for ${SSH_MAIN_CONFIG} — skipping restore"
    }

    # --- Reload sshd ---
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || {
        log_error "ssh_rollback: failed to reload sshd after rollback — check service status"
        return 1
    }

    log_success "ssh_rollback: sshd reloaded with restored configuration"
    return 0
}
