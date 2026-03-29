#!/usr/bin/env bash
# lib/services.sh — service hardening module: audit, apply, rollback
# Sourced by harden.sh (or modules/services.sh). Requires lib/common.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Service Lists ────────────────────────────────────────────────────────────

readonly -a DISABLE_SERVICES=(
    "avahi-daemon|mDNS service discovery — not needed on headless cloud VPS"
    "cups|Printing service — not needed on server"
    "cups-browsed|CUPS browsing — not needed on server"
    "rpcbind|NFS/RPC port mapper — not needed unless using NFS"
    "ModemManager|Modem management — no modems on cloud VPS"
    "bluetooth|Bluetooth stack — no Bluetooth on cloud VPS"
)

# Pipe-delimited: name|reason  (handled conditionally in apply)
readonly CONDITIONAL_SERVICES="postfix|Local MTA — disable if no local mail delivery needed"

readonly -a PROTECTED_SERVICES=(
    sshd
    ssh
    systemd-resolved
    cloud-init
    cloud-config
    cloud-final
    qemu-guest-agent
    cron
    crond
    rsyslog
    systemd-journald
    chrony
    chronyd
    systemd-timesyncd
    NetworkManager
    systemd-networkd
    dbus
)

# ─── services_audit ───────────────────────────────────────────────────────────

services_audit() {
    log_info "services_audit: checking service state"

    local entry name reason

    # Check DISABLE_SERVICES — flag any that are still active or enabled
    for entry in "${DISABLE_SERVICES[@]}"; do
        name="${entry%%|*}"
        reason="${entry#*|}"

        if ! svc_exists "${name}"; then
            log_debug "services_audit: '${name}' not present on this system"
            continue
        fi

        if svc_is_active "${name}" || svc_is_enabled "${name}"; then
            log_warn "FINDING: service '${name}' is active/enabled and should be disabled (${reason})"
            (( AUDIT_FINDINGS++ )) || true
        fi
    done

    # Check CONDITIONAL_SERVICES — note if active
    local cond_name cond_reason
    cond_name="${CONDITIONAL_SERVICES%%|*}"
    cond_reason="${CONDITIONAL_SERVICES#*|}"

    if svc_exists "${cond_name}"; then
        if svc_is_active "${cond_name}" || svc_is_enabled "${cond_name}"; then
            log_info "NOTE: conditional service '${cond_name}' is active/enabled (${cond_reason})"
        fi
    fi

    # Check PROTECTED_SERVICES — warn if expected service is missing/inactive
    local svc
    for svc in "${PROTECTED_SERVICES[@]}"; do
        if ! svc_exists "${svc}"; then
            log_debug "services_audit: protected service '${svc}' not found on this system"
            continue
        fi

        if ! svc_is_active "${svc}"; then
            log_warn "FINDING: protected service '${svc}' exists but is NOT active"
            (( AUDIT_FINDINGS++ )) || true
        fi
    done
}

# ─── services_apply ───────────────────────────────────────────────────────────

services_apply() {
    log_info "services_apply: disabling unnecessary services"

    local entry name reason

    # Disable each service in DISABLE_SERVICES
    for entry in "${DISABLE_SERVICES[@]}"; do
        name="${entry%%|*}"
        reason="${entry#*|}"
        svc_disable "${name}" "${reason}" || true
    done

    # Handle postfix conditionally: only disable if it exists, is active, and
    # has no queued mail (non-empty queue means something is relying on it).
    local cond_name cond_reason
    cond_name="${CONDITIONAL_SERVICES%%|*}"
    cond_reason="${CONDITIONAL_SERVICES#*|}"

    if svc_exists "${cond_name}" && svc_is_active "${cond_name}"; then
        local queued_count=0
        queued_count="$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || true)"

        if [[ "${queued_count}" -gt 0 ]]; then
            log_info "services_apply: skipping '${cond_name}' — ${queued_count} message(s) in mail queue"
        else
            svc_disable "${cond_name}" "${cond_reason}" || true
        fi
    else
        log_debug "services_apply: '${cond_name}' not present or already inactive, skipping"
    fi
}

# ─── services_rollback ────────────────────────────────────────────────────────

services_rollback() {
    log_info "services_rollback: unmasking disabled/conditional services"

    local entry name

    # Unmask DISABLE_SERVICES (do not re-enable or start — just unmask)
    for entry in "${DISABLE_SERVICES[@]}"; do
        name="${entry%%|*}"

        if ! svc_exists "${name}"; then
            log_debug "services_rollback: '${name}' not present, skipping unmask"
            continue
        fi

        log_info "services_rollback: unmasking '${name}'"
        systemctl unmask "${name}" 2>/dev/null || true
    done

    # Unmask conditional service
    local cond_name
    cond_name="${CONDITIONAL_SERVICES%%|*}"

    if svc_exists "${cond_name}"; then
        log_info "services_rollback: unmasking '${cond_name}'"
        systemctl unmask "${cond_name}" 2>/dev/null || true
    fi
}
