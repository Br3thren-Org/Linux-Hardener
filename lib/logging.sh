#!/usr/bin/env bash
# lib/logging.sh — logging/audit hardening module: audit, apply, rollback
# Sourced by harden.sh after lib/common.sh and the distro-specific adapter.
# Provides: logging_audit, logging_apply, logging_rollback
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly AUDIT_RULES_PATH="/etc/audit/rules.d/99-hardening.rules"
readonly AUDITD_CONF="/etc/audit/auditd.conf"
readonly JOURNAL_DIR="/var/log/journal"

# ─── Audit ────────────────────────────────────────────────────────────────────

logging_audit() {
    log_info "logging: running audit checks"

    _logging_audit_ntp_sync
    _logging_audit_time_sync_service
    _logging_audit_syslog
    _logging_audit_auditd
    _logging_audit_journald_persistence
}

_logging_audit_ntp_sync() {
    local ntp_synced
    ntp_synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"

    if [[ "${ntp_synced}" == "yes" ]]; then
        log_info "logging_audit: NTP synchronized (OK)"
    else
        log_warn "FINDING: NTP not synchronized (timedatectl NTPSynchronized=${ntp_synced:-unknown})"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

_logging_audit_time_sync_service() {
    local found=false
    local svc

    for svc in chrony chronyd systemd-timesyncd; do
        if svc_is_active "${svc}" 2>/dev/null; then
            found=true
            log_info "logging_audit: time sync service active: ${svc} (OK)"
            break
        fi
    done

    if [[ "${found}" == "false" ]]; then
        log_warn "FINDING: no time sync service running (checked: chrony, chronyd, systemd-timesyncd)"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

_logging_audit_syslog() {
    local found=false
    local svc

    for svc in rsyslog syslog-ng systemd-journald; do
        if svc_is_active "${svc}" 2>/dev/null; then
            found=true
            log_info "logging_audit: syslog service active: ${svc} (OK)"
            break
        fi
    done

    if [[ "${found}" == "false" ]]; then
        log_warn "FINDING: no syslog service running (checked: rsyslog, syslog-ng, systemd-journald)"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

_logging_audit_auditd() {
    if [[ "${ENABLE_AUDITD:-false}" != "true" ]]; then
        log_debug "logging_audit: auditd checks skipped (ENABLE_AUDITD != true)"
        return 0
    fi

    if ! svc_is_active auditd 2>/dev/null; then
        log_warn "FINDING: auditd is not active (ENABLE_AUDITD=true)"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "logging_audit: auditd is active (OK)"
    fi

    if [[ ! -f "${AUDIT_RULES_PATH}" ]]; then
        log_warn "FINDING: audit rules file missing: ${AUDIT_RULES_PATH}"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_info "logging_audit: audit rules file present: ${AUDIT_RULES_PATH} (OK)"
    fi
}

_logging_audit_journald_persistence() {
    if [[ -d "${JOURNAL_DIR}" ]]; then
        log_info "logging_audit: journald persistence directory present: ${JOURNAL_DIR} (OK)"
    else
        log_warn "FINDING: ${JOURNAL_DIR} does not exist — journald logs are not persistent"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

logging_apply() {
    log_info "logging: applying hardening"

    _logging_apply_time_sync
    _logging_apply_journald_persistence
    _logging_apply_auditd
}

_logging_apply_time_sync() {
    local has_sync=false
    local svc

    for svc in chrony chronyd systemd-timesyncd; do
        if svc_is_active "${svc}" 2>/dev/null; then
            has_sync=true
            log_debug "logging_apply: time sync service already running: ${svc}"
            break
        fi
    done

    if [[ "${has_sync}" == "true" ]]; then
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would install chrony and enable it for time synchronization"
        return 0
    fi

    log_info "logging_apply: no time sync service running — installing chrony"
    pkg_install chrony

    systemctl enable chrony 2>/dev/null || systemctl enable chronyd 2>/dev/null || true
    systemctl start  chrony 2>/dev/null || systemctl start  chronyd 2>/dev/null || true

    log_change \
        "Installed and enabled chrony for NTP time synchronization" \
        "System clock must be synchronized for accurate log timestamps and audit trails" \
        "low" \
        "systemctl is-active chrony || systemctl is-active chronyd" \
        "systemctl stop chrony; systemctl disable chrony; pkg_remove chrony"
    (( CHANGES_APPLIED++ )) || true
}

_logging_apply_journald_persistence() {
    if [[ -d "${JOURNAL_DIR}" ]]; then
        log_debug "logging_apply: ${JOURNAL_DIR} already exists, skipping"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would create ${JOURNAL_DIR} and enable journald persistence"
        return 0
    fi

    log_info "logging_apply: creating ${JOURNAL_DIR} for journald persistence"
    mkdir -p "${JOURNAL_DIR}"
    systemd-tmpfiles --create --prefix "${JOURNAL_DIR}" 2>/dev/null || true
    systemctl restart systemd-journald 2>/dev/null || true

    log_change \
        "Created ${JOURNAL_DIR} and enabled journald persistence" \
        "Persistent journal ensures logs survive reboots for forensic and compliance purposes" \
        "low" \
        "test -d ${JOURNAL_DIR}" \
        "rm -rf ${JOURNAL_DIR}; systemctl restart systemd-journald"
    (( CHANGES_APPLIED++ )) || true
}

_logging_apply_auditd() {
    if [[ "${ENABLE_AUDITD:-false}" != "true" ]]; then
        log_info "logging_apply: auditd setup skipped (ENABLE_AUDITD != true)"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would install auditd, write audit rules (${AUDITD_RULES:-minimal}), and configure auditd.conf"
        return 0
    fi

    _logging_install_auditd
    _logging_write_audit_rules
    _logging_configure_auditd_conf
    _logging_enable_auditd
}

_logging_install_auditd() {
    local pkg_name
    pkg_name="$(_logging_auditd_pkg_name)"

    if pkg_is_installed "${pkg_name}"; then
        log_debug "logging_apply: ${pkg_name} already installed"
        return 0
    fi

    log_info "logging_apply: installing ${pkg_name}"
    pkg_install "${pkg_name}"
    (( CHANGES_APPLIED++ )) || true
}

_logging_write_audit_rules() {
    local rules_content
    rules_content="$(_logging_build_audit_rules)"

    local rc=0
    write_file_if_changed "${AUDIT_RULES_PATH}" "${rules_content}" \
        "Write audit rules (${AUDITD_RULES:-minimal}) to ${AUDIT_RULES_PATH}" || rc=$?

    if [[ "${rc}" -eq 0 ]]; then
        log_change \
            "Audit rules written to ${AUDIT_RULES_PATH}" \
            "Track security-relevant file access and system events per ${AUDITD_RULES:-minimal} policy" \
            "low" \
            "test -f ${AUDIT_RULES_PATH}" \
            "rm -f ${AUDIT_RULES_PATH}; augenrules --load 2>/dev/null || true"
    fi
}

_logging_build_audit_rules() {
    # Minimal rule set — covers critical security-sensitive files and events
    local minimal_rules
    minimal_rules="$(cat <<'RULES'
# ── Linux Hardener audit rules ────────────────────────────────────────────────
# Generated by lib/logging.sh — do not edit manually.

# Delete all existing rules
-D

# Increase the buffers to reduce the chance of events being lost
-b 8192

# Identity files
-w /etc/shadow              -p wa -k identity
-w /etc/passwd              -p wa -k identity
-w /etc/gshadow             -p wa -k identity
-w /etc/group               -p wa -k identity

# Privilege escalation
-w /etc/sudoers             -p wa -k sudo_changes
-w /etc/sudoers.d/          -p wa -k sudo_changes

# SSH daemon configuration
-w /etc/ssh/sshd_config     -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/  -p wa -k sshd_config

# Login/session tracking
-w /var/log/faillog         -p wa -k logins
-w /var/log/lastlog         -p wa -k logins
-w /var/log/tallylog        -p wa -k logins

# Crontab changes
-w /etc/crontab             -p wa -k cron
-w /etc/cron.d/             -p wa -k cron
-w /etc/cron.daily/         -p wa -k cron
-w /etc/cron.weekly/        -p wa -k cron
-w /etc/cron.monthly/       -p wa -k cron

# Kernel module loading
-w /sbin/insmod             -p x  -k modules
-w /sbin/rmmod              -p x  -k modules
-w /sbin/modprobe           -p x  -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime           -p wa -k time_change

# Note: -e 2 (immutable) removed — it prevents audit-rules.service from reloading on modern auditd
RULES
)"

    if [[ "${AUDITD_RULES:-minimal}" == "minimal" ]]; then
        printf '%s\n' "${minimal_rules}"
        return 0
    fi

    # cis-basic extends minimal with network config, session files, and cron dirs
    cat <<'RULES'
# ── Linux Hardener audit rules (cis-basic) ────────────────────────────────────
# Generated by lib/logging.sh — do not edit manually.

# Delete all existing rules
-D

# Increase the buffers to reduce the chance of events being lost
-b 8192

# Identity files
-w /etc/shadow              -p wa -k identity
-w /etc/passwd              -p wa -k identity
-w /etc/gshadow             -p wa -k identity
-w /etc/group               -p wa -k identity

# Privilege escalation
-w /etc/sudoers             -p wa -k sudo_changes
-w /etc/sudoers.d/          -p wa -k sudo_changes

# SSH daemon configuration
-w /etc/ssh/sshd_config     -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/  -p wa -k sshd_config

# Login/session tracking
-w /var/log/faillog         -p wa -k logins
-w /var/log/lastlog         -p wa -k logins
-w /var/log/tallylog        -p wa -k logins

# Crontab changes
-w /etc/crontab             -p wa -k cron
-w /etc/cron.d/             -p wa -k cron
-w /etc/cron.daily/         -p wa -k cron
-w /etc/cron.weekly/        -p wa -k cron
-w /etc/cron.monthly/       -p wa -k cron

# Kernel module loading
-w /sbin/insmod             -p x  -k modules
-w /sbin/rmmod              -p x  -k modules
-w /sbin/modprobe           -p x  -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime           -p wa -k time_change

# Network configuration (cis-basic)
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system_locale
-w /etc/issue               -p wa -k system_locale
-w /etc/issue.net           -p wa -k system_locale
-w /etc/hosts               -p wa -k system_locale
-w /etc/sysconfig/network   -p wa -k system_locale

# Session files (cis-basic)
-w /var/run/utmp            -p wa -k session
-w /var/log/wtmp            -p wa -k logins
-w /var/log/btmp            -p wa -k logins

# Cron directories (cis-basic)
-w /etc/cron.hourly/        -p wa -k cron
-w /var/spool/cron/         -p wa -k cron

# Note: -e 2 (immutable) removed — it prevents audit-rules.service from reloading on modern auditd
RULES
}

_logging_configure_auditd_conf() {
    if [[ ! -f "${AUDITD_CONF}" ]]; then
        log_debug "logging_apply: ${AUDITD_CONF} not found, skipping auditd.conf configuration"
        return 0
    fi

    backup_file "${AUDITD_CONF}"

    local changed=false

    # max_log_file=50
    if ! grep -q '^\s*max_log_file\s*=' "${AUDITD_CONF}" 2>/dev/null; then
        printf 'max_log_file = 50\n' >> "${AUDITD_CONF}"
        changed=true
    else
        sed -i 's/^\s*max_log_file\s*=.*/max_log_file = 50/' "${AUDITD_CONF}"
        changed=true
    fi

    # num_logs=5
    if ! grep -q '^\s*num_logs\s*=' "${AUDITD_CONF}" 2>/dev/null; then
        printf 'num_logs = 5\n' >> "${AUDITD_CONF}"
        changed=true
    else
        sed -i 's/^\s*num_logs\s*=.*/num_logs = 5/' "${AUDITD_CONF}"
        changed=true
    fi

    # max_log_file_action=rotate
    if ! grep -q '^\s*max_log_file_action\s*=' "${AUDITD_CONF}" 2>/dev/null; then
        printf 'max_log_file_action = rotate\n' >> "${AUDITD_CONF}"
        changed=true
    else
        sed -i 's/^\s*max_log_file_action\s*=.*/max_log_file_action = rotate/' "${AUDITD_CONF}"
        changed=true
    fi

    if [[ "${changed}" == "true" ]]; then
        log_info "logging_apply: auditd.conf updated (max_log_file=50, num_logs=5, max_log_file_action=rotate)"
        log_change \
            "Updated ${AUDITD_CONF}: max_log_file=50 num_logs=5 max_log_file_action=rotate" \
            "Prevent auditd log files from filling disk; rotate automatically" \
            "low" \
            "grep -E 'max_log_file|num_logs|max_log_file_action' ${AUDITD_CONF}" \
            "restore_file ${AUDITD_CONF}"
        (( CHANGES_APPLIED++ )) || true
    fi
}

_logging_enable_auditd() {
    systemctl enable auditd 2>/dev/null || true
    systemctl start  auditd 2>/dev/null || true

    # Prefer augenrules --load if available; fall back to restart
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || {
            log_warn "logging_apply: augenrules --load failed — falling back to auditd restart"
            systemctl restart auditd 2>/dev/null || true
        }
    else
        systemctl restart auditd 2>/dev/null || true
    fi

    log_success "logging_apply: auditd enabled and running"
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

logging_rollback() {
    log_info "logging: rolling back changes"

    # Remove generated audit rules file
    if [[ -f "${AUDIT_RULES_PATH}" ]]; then
        rm -f "${AUDIT_RULES_PATH}"
        log_info "logging_rollback: removed ${AUDIT_RULES_PATH}"
    else
        log_debug "logging_rollback: ${AUDIT_RULES_PATH} not present, skipping"
    fi

    # Restore auditd.conf from backup
    restore_file "${AUDITD_CONF}" || true

    # Restart auditd to pick up restored configuration
    if svc_is_active auditd 2>/dev/null; then
        if command -v augenrules &>/dev/null; then
            augenrules --load 2>/dev/null || systemctl restart auditd 2>/dev/null || true
        else
            systemctl restart auditd 2>/dev/null || true
        fi
        log_info "logging_rollback: auditd restarted with restored configuration"
    fi

    log_success "logging: rollback complete"
}

# ─── Internal Helpers ─────────────────────────────────────────────────────────

# Returns the correct auditd package name for the detected distro family.
_logging_auditd_pkg_name() {
    case "${DISTRO_FAMILY:-}" in
        debian) printf 'auditd'  ;;
        rhel)   printf 'audit'   ;;
        *)
            log_warn "_logging_auditd_pkg_name: unknown DISTRO_FAMILY '${DISTRO_FAMILY}', defaulting to auditd"
            printf 'auditd'
            ;;
    esac
}
