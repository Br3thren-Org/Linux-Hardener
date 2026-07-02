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

        # Check 4: AIDE database exists (gzip-configured systems produce .gz)
        if [[ ! -f "/var/lib/aide/aide.db" && ! -f "/var/lib/aide/aide.db.gz" ]]; then
            log_warn "FINDING: AIDE database not found at /var/lib/aide/aide.db(.gz)"
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

# _integrity_clear_listbugs_pin — a previously aborted install can leave an
# apt-listbugs pin (Pin-Priority: -30000) that makes fail2ban's candidate
# "(none)" forever. The pinned bugs (#1037437, #770171) concern the sshd jail
# needing rsyslog — irrelevant here because our jail uses backend=systemd.
_integrity_clear_listbugs_pin() {
    local pin_file="/etc/apt/preferences.d/apt-listbugs"
    [[ -f "${pin_file}" ]] || return 0
    grep -q '^Package: fail2ban$' "${pin_file}" || return 0

    backup_file "${pin_file}"
    # Drop the fail2ban stanza (RFC822-style paragraph incl. leading comments)
    awk -v RS= -v ORS='\n\n' '!/^Package: fail2ban$/ && !/\nPackage: fail2ban\n/' \
        "${pin_file}" > "${pin_file}.tmp"
    if grep -q '[^[:space:]]' "${pin_file}.tmp"; then
        mv "${pin_file}.tmp" "${pin_file}"
    else
        rm -f "${pin_file}.tmp" "${pin_file}"
    fi
    log_info "integrity_apply: removed apt-listbugs pin blocking fail2ban installation"
}

_integrity_apply_fail2ban() {
    log_info "integrity_apply: configuring fail2ban"

    # Install fail2ban if not present
    if ! command -v fail2ban-server &>/dev/null; then
        if should_write && [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _integrity_clear_listbugs_pin
        fi
        log_info "integrity_apply: fail2ban not installed, installing now"
        if should_write; then
            # RHEL-family needs EPEL for fail2ban; Fedora has it in main repos
            if [[ "${DISTRO_FAMILY:-}" == "rhel" && "${DISTRO_ID:-}" != "fedora" ]]; then
                dnf install -y epel-release 2>/dev/null || true
            fi
            # python3-systemd is only a Recommends of fail2ban and many cloud
            # images disable Install-Recommends — without it the jail's
            # systemd backend dies with "No module named 'systemd'".
            pkg_install fail2ban python3-systemd || {
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

    # Build jail config content. banaction must match the active firewall:
    # the fail2ban default (iptables-*) loads iptables kernel modules next to
    # our nftables ruleset and triggers Lynis FIRE-4512 ("iptables modules
    # loaded, but no rules active"). On RHEL, fail2ban-firewalld already sets
    # banaction via jail.d/00-firewalld.conf — do not override it there.
    local jail_default=""
    if [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
        jail_default="[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
"
    fi

    local jail_content
    jail_content="$(cat <<EOF
${jail_default}
[sshd]
enabled = true
port = ${SSH_PORT:-22}
maxretry = ${FAIL2BAN_MAXRETRY:-5}
bantime = ${FAIL2BAN_BANTIME:-600}
findtime = 600
backend = systemd
# No logpath: with backend=systemd the jail reads the journal directly.
# Setting logpath forces file-based discovery and aborts the server on
# journald-only hosts (no /var/log/auth.log without rsyslog — Debian #770171).
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

        # DEB-0880 (config survives package updates): use a minimal stub, NOT a
        # copy of jail.conf — fail2ban reads jail.local AFTER jail.d/*.conf, so
        # a full copy re-overrides every jail.d setting with stock defaults
        # (e.g. resets the sshd jail to the file backend, killing the server on
        # journald-only hosts). Repair existing unmodified copies in place.
        local jail_local="/etc/fail2ban/jail.local"
        local stub_needed=false
        if [[ ! -f "${jail_local}" ]]; then
            stub_needed=true
        elif [[ -f /etc/fail2ban/jail.conf ]] && cmp -s /etc/fail2ban/jail.conf "${jail_local}"; then
            # Unmodified copy made by older hardener versions — safe to replace
            backup_file "${jail_local}"
            stub_needed=true
            log_info "integrity_apply: replacing jail.conf copy at ${jail_local} (it overrode jail.d settings)"
        fi
        if [[ "${stub_needed}" == "true" ]]; then
            cat > "${jail_local}" <<'EOF'
# Managed by linux-hardener (Lynis DEB-0880) — do not edit by hand.
# Local configuration lives in /etc/fail2ban/jail.d/99-hardening.conf.
# NOTE: fail2ban reads jail.local after jail.d/*.conf — keep this file empty
# of jail definitions or it will override them.
EOF
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

        # fail2ban-server parses jails asynchronously after the unit reports
        # started — a broken jail kills the daemon a moment later, so verify.
        sleep 3
        if ! svc_is_active fail2ban; then
            log_error "integrity_apply: fail2ban died after restart — check 'journalctl -u fail2ban'"
            (( CHANGES_FAILED++ )) || true
            return 1
        fi

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
    local checksums_changed=false
    if should_write; then
        local aide_conf_main
        if [[ -f "/etc/aide/aide.conf" ]]; then
            aide_conf_main="/etc/aide/aide.conf"
        elif [[ -f "/etc/aide.conf" ]]; then
            aide_conf_main="/etc/aide.conf"
        fi

        if [[ -n "${aide_conf_main:-}" ]]; then
            # SHA512 must be visible in the MAIN config file: Lynis FINT-4402
            # greps only aide.conf itself, so a conf.d drop-in never clears the
            # finding. Debian's stock "Checksums = H" hides the algorithms
            # behind a macro — replace it with an explicit definition.
            if ! grep -qE '^\s*(Checksums|CONTENT_EX|DATAONLY).*sha512' "${aide_conf_main}" 2>/dev/null; then
                backup_file "${aide_conf_main}"
                if grep -qE '^\s*Checksums\s*=' "${aide_conf_main}"; then
                    sed -i -E 's/^\s*Checksums\s*=.*/Checksums = sha512/' "${aide_conf_main}"
                else
                    printf '\n# Hardener: use SHA512 for checksums (FINT-4402)\nChecksums = sha512\n' >> "${aide_conf_main}"
                fi
                checksums_changed=true
                log_info "integrity_apply: AIDE checksums set to SHA512 in ${aide_conf_main}"
                (( CHANGES_APPLIED++ )) || true
            else
                log_debug "integrity_apply: AIDE already uses SHA512 checksums (OK)"
            fi
        fi
    fi

    # Initialise the database if missing — or REinitialise after a checksum
    # change: comparing against a database built with the old attribute set
    # floods every daily check with spurious differences.
    if [[ ! -f "/var/lib/aide/aide.db" && ! -f "/var/lib/aide/aide.db.gz" ]] \
            || [[ "${checksums_changed}" == "true" ]]; then
        log_info "integrity_apply: AIDE database missing or checksum set changed — initialising"

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

    # The daily checks below depend on a RUNNING cron daemon. Minimal cloud
    # images (e.g. Fedora) ship none, and sometimes cron is installed (pulled
    # in as a dependency) but enabled-not-started — so ensure both presence
    # AND active state, not just one.
    local cron_svc="cron"
    [[ "${DISTRO_FAMILY:-}" == "rhel" ]] && cron_svc="crond"

    if should_write; then
        if ! command -v crond &>/dev/null && ! command -v cron &>/dev/null; then
            local cron_pkg="cron"
            [[ "${DISTRO_FAMILY:-}" == "rhel" ]] && cron_pkg="cronie"
            log_info "integrity_apply: no cron daemon found — installing ${cron_pkg}"
            pkg_install "${cron_pkg}" \
                || log_warn "integrity_apply: failed to install ${cron_pkg} — daily checks will not run"
        fi
        # Start + enable whenever the service exists but is not active
        if svc_exists "${cron_svc}" && ! svc_is_active "${cron_svc}"; then
            if systemctl enable --now "${cron_svc}" 2>/dev/null; then
                log_info "integrity_apply: ${cron_svc} enabled and started"
                (( CHANGES_APPLIED++ )) || true
            else
                log_warn "integrity_apply: could not start ${cron_svc} — daily checks will not run until it is active"
            fi
        fi
    else
        log_info "[DRY-RUN] Would ensure a cron daemon is installed, enabled, and started"
    fi

    # Write daily cron job. Resolve the binary path at write time — RHEL
    # installs aide at /usr/sbin/aide, Debian at /usr/bin/aide.
    local aide_bin
    aide_bin="$(command -v aide 2>/dev/null || printf '/usr/bin/aide')"
    local cron_content
    cron_content="$(cat <<EOF
#!/bin/bash
${aide_bin} --check --config=${aide_conf_path} 2>&1 | /usr/bin/logger -t aide-check
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
