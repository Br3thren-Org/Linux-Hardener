#!/usr/bin/env bash
# modules/50_remote_syslog.sh — forward logs to a remote collector
# Provides: remote_syslog_audit, remote_syslog_apply, remote_syslog_rollback
#
# Ships auth/kernel/security-relevant logs off-box so a successful attacker
# cannot scrub them (Lynis LOGG-2154). Pure config change: a bounded disk
# queue retries while the collector is unreachable, and local logging
# (journald persistence is handled by the logging module) is never blocked.
# Sourced by harden.sh. Do NOT add set -euo pipefail here.

: "${RSYSLOG_REMOTE_HOST:=}"        # host:port — empty disables the module
: "${RSYSLOG_REMOTE_PROTOCOL:=tcp}" # tcp | tls
: "${RSYSLOG_REMOTE_CERT:=}"        # CA cert for tls

readonly RSYSLOG_REMOTE_CONF="/etc/rsyslog.d/99-hardener-remote.conf"

# ─── Helpers ──────────────────────────────────────────────────────────────────

_rsl_host() { printf '%s' "${RSYSLOG_REMOTE_HOST%%:*}"; }
_rsl_port() {
    local port="${RSYSLOG_REMOTE_HOST##*:}"
    if [[ "${port}" == "${RSYSLOG_REMOTE_HOST}" || -z "${port}" ]]; then
        # No port given — protocol default
        [[ "${RSYSLOG_REMOTE_PROTOCOL}" == "tls" ]] && port=6514 || port=514
    fi
    printf '%s' "${port}"
}

# _rsl_build_conf — print the rsyslog forwarding config
_rsl_build_conf() {
    local host port
    host="$(_rsl_host)"
    port="$(_rsl_port)"

    cat <<EOF
# Managed by linux-hardener (modules/50_remote_syslog.sh) — do not edit by hand.
# Forward auth, kernel, and warning-or-worse logs to ${host}:${port}
# (${RSYSLOG_REMOTE_PROTOCOL}). Bounded disk-assisted queue: survives collector
# outages and restarts without ever blocking local logging or filling the disk.
EOF

    if [[ "${RSYSLOG_REMOTE_PROTOCOL}" == "tls" ]]; then
        cat <<EOF
\$DefaultNetstreamDriverCAFile ${RSYSLOG_REMOTE_CERT}
\$DefaultNetstreamDriver gtls
\$ActionSendStreamDriverMode 1
\$ActionSendStreamDriverAuthMode x509/certvalid
EOF
    fi

    cat <<EOF
\$ActionQueueType LinkedList
\$ActionQueueFileName hardener_remote_fwd
\$ActionQueueMaxDiskSpace 100m
\$ActionQueueSaveOnShutdown on
\$ActionResumeRetryCount -1
auth,authpriv.*;kern.*;*.warn @@${host}:${port}
EOF
}

_rsl_syntax_ok() {
    rsyslogd -N1 &>/dev/null
}

# ─── Audit ────────────────────────────────────────────────────────────────────

remote_syslog_audit() {
    if [[ -z "${RSYSLOG_REMOTE_HOST}" ]]; then
        log_info "remote_syslog_audit: skipped (RSYSLOG_REMOTE_HOST not set)"
        return 0
    fi

    log_info "remote_syslog_audit: checking remote log forwarding"

    if [[ ! -f "${RSYSLOG_REMOTE_CONF}" ]]; then
        log_warn "FINDING: remote log forwarding not configured (${RSYSLOG_REMOTE_CONF} missing) — logs can be scrubbed by an attacker (LOGG-2154)"
        (( AUDIT_FINDINGS++ )) || true
        return 0
    fi

    if ! svc_is_active rsyslog; then
        log_warn "FINDING: forwarding configured but rsyslog is not active"
        (( AUDIT_FINDINGS++ )) || true
    fi

    if command -v rsyslogd &>/dev/null && ! _rsl_syntax_ok; then
        log_warn "FINDING: rsyslog configuration fails syntax check (rsyslogd -N1)"
        (( AUDIT_FINDINGS++ )) || true
    fi
    return 0
}

# ─── Apply ────────────────────────────────────────────────────────────────────

remote_syslog_apply() {
    if [[ -z "${RSYSLOG_REMOTE_HOST}" ]]; then
        log_info "remote_syslog: disabled (RSYSLOG_REMOTE_HOST not set) — skipping"
        return 2
    fi

    case "${RSYSLOG_REMOTE_PROTOCOL}" in
        tcp) : ;;
        tls)
            if [[ -z "${RSYSLOG_REMOTE_CERT}" || ! -f "${RSYSLOG_REMOTE_CERT}" ]]; then
                log_error "remote_syslog: RSYSLOG_REMOTE_PROTOCOL=tls but RSYSLOG_REMOTE_CERT is missing (${RSYSLOG_REMOTE_CERT:-unset})"
                (( CHANGES_FAILED++ )) || true
                return 1
            fi
            ;;
        *)
            log_error "remote_syslog: invalid RSYSLOG_REMOTE_PROTOCOL '${RSYSLOG_REMOTE_PROTOCOL}' (tcp|tls)"
            (( CHANGES_FAILED++ )) || true
            return 1
            ;;
    esac

    local content
    content="$(_rsl_build_conf)"

    if [[ "${DRY_RUN:-no}" == "yes" ]] || ! should_write; then
        log_info "[DRY-RUN] Would write ${RSYSLOG_REMOTE_CONF}:"
        log_info "${content}"
        log_info "[DRY-RUN] Would install rsyslog if missing and restart it"
        return 0
    fi

    # ── Ensure rsyslog (+ TLS driver) is installed ───────────────────────────
    if ! command -v rsyslogd &>/dev/null; then
        log_info "remote_syslog: installing rsyslog"
        if ! pkg_install rsyslog; then
            # RHEL-family fallback: ship the journal directly
            if [[ "${DISTRO_FAMILY}" == "rhel" ]] && pkg_install systemd-journal-remote; then
                _rsl_journal_upload_fallback
                return $?
            fi
            log_error "remote_syslog: could not install rsyslog"
            (( CHANGES_FAILED++ )) || true
            return 1
        fi
    fi
    if [[ "${RSYSLOG_REMOTE_PROTOCOL}" == "tls" ]] && ! pkg_is_installed rsyslog-gnutls; then
        pkg_install rsyslog-gnutls || {
            log_error "remote_syslog: rsyslog-gnutls required for TLS forwarding"
            (( CHANGES_FAILED++ )) || true
            return 1
        }
    fi

    # ── Write config, validate, restart ─────────────────────────────────────
    local write_rc=0
    write_file_if_changed "${RSYSLOG_REMOTE_CONF}" "${content}" \
        "Remote syslog forwarding to ${RSYSLOG_REMOTE_HOST}" || write_rc=$?
    if [[ "${write_rc}" -eq 2 ]] && svc_is_active rsyslog; then
        log_debug "remote_syslog: configuration already current"
        return 2
    fi

    if ! _rsl_syntax_ok; then
        log_error "remote_syslog: rsyslogd -N1 rejected the configuration — removing it"
        rsyslogd -N1 2>&1 | head -3 | while IFS= read -r line; do log_error "remote_syslog:   ${line}"; done
        rm -f "${RSYSLOG_REMOTE_CONF}"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    log_change \
        "Forward auth/kern/warn logs to ${RSYSLOG_REMOTE_HOST} (${RSYSLOG_REMOTE_PROTOCOL})" \
        "Off-box log copies survive host compromise (Lynis LOGG-2154)" \
        "low" \
        "rsyslogd -N1 && logger test && check collector" \
        "rm -f ${RSYSLOG_REMOTE_CONF} && systemctl restart rsyslog"

    systemctl enable rsyslog &>/dev/null || true
    if ! systemctl restart rsyslog 2>/dev/null; then
        log_error "remote_syslog: rsyslog failed to restart — removing forwarding config"
        rm -f "${RSYSLOG_REMOTE_CONF}"
        systemctl restart rsyslog 2>/dev/null || true
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    # Emit a traceable test message; delivery is the collector's side to
    # confirm, but local acceptance + active daemon prove the pipeline.
    local marker="linux-hardener-test-$(date +%s)"
    logger -p auth.info "${marker}" 2>/dev/null || true
    log_info "remote_syslog: test message sent (marker: ${marker}) — verify receipt on ${RSYSLOG_REMOTE_HOST}"

    log_success "remote_syslog: forwarding active to ${RSYSLOG_REMOTE_HOST} (${RSYSLOG_REMOTE_PROTOCOL})"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# _rsl_journal_upload_fallback — RHEL-family fallback when rsyslog is
# unavailable: push the journal with systemd-journal-upload.
_rsl_journal_upload_fallback() {
    log_info "remote_syslog: configuring systemd-journal-upload fallback"

    mkdir -p /etc/systemd/journal-upload.conf.d
    local scheme="http"
    [[ "${RSYSLOG_REMOTE_PROTOCOL}" == "tls" ]] && scheme="https"
    cat > /etc/systemd/journal-upload.conf.d/99-hardener.conf <<EOF
# Managed by linux-hardener — do not edit by hand
[Upload]
URL=${scheme}://$(_rsl_host):$(_rsl_port)
EOF
    if [[ "${RSYSLOG_REMOTE_PROTOCOL}" == "tls" ]]; then
        printf 'TrustedCertificateFile=%s\n' "${RSYSLOG_REMOTE_CERT}" \
            >> /etc/systemd/journal-upload.conf.d/99-hardener.conf
    fi

    if systemctl enable --now systemd-journal-upload.service 2>/dev/null; then
        log_success "remote_syslog: journal upload active to $(_rsl_host):$(_rsl_port)"
        (( CHANGES_APPLIED++ )) || true
        return 0
    fi
    log_error "remote_syslog: systemd-journal-upload failed to start"
    (( CHANGES_FAILED++ )) || true
    return 1
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

remote_syslog_rollback() {
    log_info "remote_syslog_rollback: removing remote forwarding"

    local changed=false
    if [[ -f "${RSYSLOG_REMOTE_CONF}" ]]; then
        rm -f "${RSYSLOG_REMOTE_CONF}"
        systemctl restart rsyslog 2>/dev/null || true
        changed=true
        log_info "remote_syslog_rollback: removed ${RSYSLOG_REMOTE_CONF}"
    fi
    if [[ -f /etc/systemd/journal-upload.conf.d/99-hardener.conf ]]; then
        rm -f /etc/systemd/journal-upload.conf.d/99-hardener.conf
        systemctl disable --now systemd-journal-upload.service 2>/dev/null || true
        changed=true
        log_info "remote_syslog_rollback: removed journal-upload config"
    fi

    [[ "${changed}" == "true" ]] \
        && log_success "remote_syslog_rollback: complete" \
        || log_debug "remote_syslog_rollback: nothing to remove"
    return 0
}
