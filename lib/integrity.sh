#!/usr/bin/env bash
# lib/integrity.sh — integrity monitoring module: fail2ban and AIDE (audit / apply / rollback)
# Sourced by harden.sh after lib/common.sh and the distro-specific adapter.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly FAIL2BAN_JAIL_CONF="/etc/fail2ban/jail.d/99-hardening.conf"
readonly AIDE_CRON_PATH="/etc/cron.daily/aide-check"

# ─── Audit ────────────────────────────────────────────────────────────────────

integrity_audit() {
    log_info "integrity_audit: checking integrity monitoring tools"

    if [[ "${ENABLE_FAIL2BAN:-false}" == "true" ]]; then
        # Check 1: fail2ban command exists
        if ! command -v fail2ban-server &>/dev/null; then
            log_warn "FINDING: fail2ban is not installed"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "integrity_audit: fail2ban-server command present (OK)"
        fi

        # Check 2: fail2ban service is active
        if ! svc_is_active fail2ban; then
            log_warn "FINDING: fail2ban service is not active"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "integrity_audit: fail2ban service is active (OK)"
        fi
    fi

    if [[ "${ENABLE_AIDE:-false}" == "true" ]]; then
        # Check 3: aide command exists
        if ! command -v aide &>/dev/null; then
            log_warn "FINDING: aide command not found — AIDE is not installed"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "integrity_audit: aide command present (OK)"
        fi

        # Check 4: AIDE database exists
        if [[ ! -f "/var/lib/aide/aide.db" ]]; then
            log_warn "FINDING: AIDE database not found at /var/lib/aide/aide.db"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "integrity_audit: AIDE database exists (OK)"
        fi
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

integrity_apply() {
    log_info "integrity_apply: applying integrity monitoring configuration"

    if [[ "${ENABLE_FAIL2BAN:-false}" == "true" ]]; then
        _integrity_apply_fail2ban
    fi

    if [[ "${ENABLE_AIDE:-false}" == "true" ]]; then
        _integrity_apply_aide
    fi
}

_integrity_apply_fail2ban() {
    log_info "integrity_apply: configuring fail2ban"

    # Install fail2ban if not present
    if ! command -v fail2ban-server &>/dev/null; then
        log_info "integrity_apply: fail2ban not installed, installing now"
        if should_write; then
            # RHEL-family needs EPEL for fail2ban; Fedora has it in main repos
            if [[ "${DISTRO_FAMILY:-}" == "rhel" && "${DISTRO_ID:-}" != "fedora" ]]; then
                dnf install -y epel-release 2>/dev/null || true
            fi
            pkg_install fail2ban || {
                log_error "integrity_apply: failed to install fail2ban"
                (( CHANGES_FAILED++ )) || true
                return 1
            }
        else
            log_info "[DRY-RUN] Would install fail2ban"
        fi
    else
        log_debug "integrity_apply: fail2ban already installed (OK)"
    fi

    # Build jail config content
    local jail_content
    jail_content="$(cat <<EOF
[DEFAULT]
banaction = %(banaction_allports)s

[sshd]
enabled = true
port = ${SSH_PORT:-22}
maxretry = ${FAIL2BAN_MAXRETRY:-5}
bantime = ${FAIL2BAN_BANTIME:-600}
findtime = 600
backend = systemd
logpath = %(sshd_log)s
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write fail2ban jail config to ${FAIL2BAN_JAIL_CONF}"
        log_debug "Jail config content (preview):"
        log_debug "${jail_content}"
    else
        # Ensure parent directory exists
        mkdir -p "$(dirname "${FAIL2BAN_JAIL_CONF}")"

        local write_result=0
        write_file_if_changed "${FAIL2BAN_JAIL_CONF}" "${jail_content}" \
            "fail2ban hardening jail config" || write_result=$?

        if [[ "${write_result}" -ne 0 && "${write_result}" -ne 2 ]]; then
            log_error "integrity_apply: failed to write ${FAIL2BAN_JAIL_CONF}"
            (( CHANGES_FAILED++ )) || true
            return 1
        fi

        # DEB-0880: copy jail.conf to jail.local to prevent update overwriting
        if [[ -f /etc/fail2ban/jail.conf ]] && [[ ! -f /etc/fail2ban/jail.local ]]; then
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            log_info "integrity_apply: copied jail.conf to jail.local for update protection (Lynis DEB-0880)"
        fi

        # Enable and restart fail2ban
        systemctl enable fail2ban 2>/dev/null || {
            log_warn "integrity_apply: failed to enable fail2ban service"
        }
        systemctl restart fail2ban 2>/dev/null || {
            log_error "integrity_apply: failed to restart fail2ban service"
            (( CHANGES_FAILED++ )) || true
            return 1
        }

        log_change \
            "fail2ban jail config written: ${FAIL2BAN_JAIL_CONF}" \
            "Protect SSH and other services from brute-force attacks" \
            "low" \
            "systemctl is-active fail2ban" \
            "integrity_rollback"

        log_success "integrity_apply: fail2ban configured and restarted"
    fi
}

_integrity_apply_aide() {
    log_info "integrity_apply: configuring AIDE file-integrity monitoring"

    # Install AIDE if not present
    if ! command -v aide &>/dev/null; then
        log_info "integrity_apply: AIDE not installed, installing now"
        if should_write; then
            case "${DISTRO_FAMILY}" in
                debian)
                    pkg_install aide aide-common || {
                        log_error "integrity_apply: failed to install aide aide-common"
                        (( CHANGES_FAILED++ )) || true
                        return 1
                    }
                    ;;
                rhel)
                    pkg_install aide || {
                        log_error "integrity_apply: failed to install aide"
                        (( CHANGES_FAILED++ )) || true
                        return 1
                    }
                    ;;
                *)
                    log_error "integrity_apply: unsupported DISTRO_FAMILY '${DISTRO_FAMILY}' for AIDE install"
                    (( CHANGES_FAILED++ )) || true
                    return 1
                    ;;
            esac
        else
            log_info "[DRY-RUN] Would install AIDE"
        fi
    else
        log_debug "integrity_apply: AIDE already installed (OK)"
    fi

    # Configure AIDE to use SHA512 checksums (FINT-4402)
    if should_write; then
        local aide_conf_main
        if [[ -f "/etc/aide/aide.conf" ]]; then
            aide_conf_main="/etc/aide/aide.conf"
        elif [[ -f "/etc/aide.conf" ]]; then
            aide_conf_main="/etc/aide.conf"
        fi

        if [[ -n "${aide_conf_main:-}" ]]; then
            # Check if SHA512 is already in the checksum config
            if ! grep -qE '^\s*(Checksums|CONTENT_EX|DATAONLY).*sha512' "${aide_conf_main}" 2>/dev/null; then
                # Add SHA512 to default checksum group or create a drop-in
                local aide_dropin_dir="/etc/aide/aide.conf.d"
                [[ ! -d "${aide_dropin_dir}" ]] && aide_dropin_dir=""

                if [[ -n "${aide_dropin_dir}" ]]; then
                    local sha_dropin="${aide_dropin_dir}/99_hardener_sha512"
                    local sha_content="# Hardener: use SHA512 for checksums (FINT-4402)
CONTENT_EX = sha512+ftype+p+u+g+n+acl+selinux+xattrs"
                    write_file_if_changed "${sha_dropin}" "${sha_content}" "Configure AIDE SHA512 checksums"
                else
                    # Append to main config
                    backup_file "${aide_conf_main}"
                    if ! grep -q 'sha512' "${aide_conf_main}" 2>/dev/null; then
                        printf '\n# Hardener: use SHA512 for checksums (FINT-4402)\nCONTENT_EX = sha512+ftype+p+u+g+n+acl+selinux+xattrs\n' >> "${aide_conf_main}"
                        log_info "integrity_apply: added SHA512 to AIDE config"
                        (( CHANGES_APPLIED++ )) || true
                    fi
                fi
            else
                log_debug "integrity_apply: AIDE already uses SHA512 checksums (OK)"
            fi
        fi
    fi

    # Initialise the database if neither aide.db nor aide.db.gz exists
    if [[ ! -f "/var/lib/aide/aide.db" && ! -f "/var/lib/aide/aide.db.gz" ]]; then
        log_info "integrity_apply: AIDE database not found, initialising"

        if should_write; then
            # Locate aide config file
            local aide_conf_path
            if [[ -f "/etc/aide/aide.conf" ]]; then
                aide_conf_path="/etc/aide/aide.conf"
            elif [[ -f "/etc/aide.conf" ]]; then
                aide_conf_path="/etc/aide.conf"
            else
                log_error "integrity_apply: cannot find AIDE config file at /etc/aide/aide.conf or /etc/aide.conf"
                (( CHANGES_FAILED++ )) || true
                return 1
            fi

            log_info "integrity_apply: running aide --init (this may take several minutes)"
            if ! timeout 300 aide --init --config="${aide_conf_path}"; then
                log_error "integrity_apply: aide --init failed or timed out"
                (( CHANGES_FAILED++ )) || true
                return 1
            fi

            # Copy new database into place
            local new_db
            # aide --init typically writes aide.db.new or aide.db.new.gz
            if [[ -f "/var/lib/aide/aide.db.new" ]]; then
                new_db="/var/lib/aide/aide.db.new"
                cp "${new_db}" "/var/lib/aide/aide.db"
            elif [[ -f "/var/lib/aide/aide.db.new.gz" ]]; then
                new_db="/var/lib/aide/aide.db.new.gz"
                cp "${new_db}" "/var/lib/aide/aide.db.gz"
            else
                log_warn "integrity_apply: aide --init did not produce an expected output database"
            fi

            log_info "integrity_apply: AIDE database initialised"
        else
            log_info "[DRY-RUN] Would run aide --init to initialise database"
        fi
    else
        log_debug "integrity_apply: AIDE database already exists (OK)"
    fi

    # Determine aide config path for the cron script
    local aide_conf_path
    if [[ -f "/etc/aide/aide.conf" ]]; then
        aide_conf_path="/etc/aide/aide.conf"
    else
        aide_conf_path="/etc/aide.conf"
    fi

    # Write daily cron job
    local cron_content
    cron_content="$(cat <<EOF
#!/bin/bash
/usr/bin/aide --check --config=${aide_conf_path} 2>&1 | /usr/bin/logger -t aide-check
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write AIDE daily cron to ${AIDE_CRON_PATH}"
        log_debug "Cron content (preview):"
        log_debug "${cron_content}"
    else
        local write_result=0
        write_file_if_changed "${AIDE_CRON_PATH}" "${cron_content}" \
            "AIDE daily integrity check cron" || write_result=$?

        if [[ "${write_result}" -ne 0 && "${write_result}" -ne 2 ]]; then
            log_error "integrity_apply: failed to write ${AIDE_CRON_PATH}"
            (( CHANGES_FAILED++ )) || true
            return 1
        fi

        chmod 755 "${AIDE_CRON_PATH}"
        log_debug "integrity_apply: set permissions 755 on ${AIDE_CRON_PATH}"

        log_change \
            "AIDE daily cron written: ${AIDE_CRON_PATH}" \
            "Run AIDE file-integrity checks daily and log results via syslog" \
            "low" \
            "test -x ${AIDE_CRON_PATH}" \
            "integrity_rollback"

        log_success "integrity_apply: AIDE daily cron configured"
    fi
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

integrity_rollback() {
    log_info "integrity_rollback: reverting integrity monitoring changes"

    # Remove fail2ban jail config and restart fail2ban
    if [[ -f "${FAIL2BAN_JAIL_CONF}" ]]; then
        rm -f "${FAIL2BAN_JAIL_CONF}"
        log_info "integrity_rollback: removed fail2ban jail config ${FAIL2BAN_JAIL_CONF}"

        if svc_is_active fail2ban; then
            systemctl restart fail2ban 2>/dev/null || {
                log_warn "integrity_rollback: failed to restart fail2ban after removing jail config"
            }
            log_info "integrity_rollback: fail2ban restarted"
        fi
    else
        log_debug "integrity_rollback: fail2ban jail config not present, nothing to remove"
    fi

    # Remove AIDE daily cron job
    if [[ -f "${AIDE_CRON_PATH}" ]]; then
        rm -f "${AIDE_CRON_PATH}"
        log_info "integrity_rollback: removed AIDE daily cron ${AIDE_CRON_PATH}"
    else
        log_debug "integrity_rollback: AIDE cron not present, nothing to remove"
    fi

    log_success "integrity_rollback: integrity monitoring changes reverted"
}
