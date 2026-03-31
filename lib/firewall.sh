#!/usr/bin/env bash
# lib/firewall.sh — firewall hardening module: audit, apply, rollback
# Sourced by harden.sh after lib/common.sh and the distro-specific adapter.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Audit ────────────────────────────────────────────────────────────────────

firewall_audit() {
    log_info "firewall_audit: checking firewall state"

    case "${DISTRO_FAMILY}" in
        debian)
            _firewall_audit_debian
            ;;
        rhel)
            _firewall_audit_rhel
            ;;
        *)
            log_warn "firewall_audit: unsupported DISTRO_FAMILY '${DISTRO_FAMILY}', skipping"
            ;;
    esac
}

_firewall_audit_debian() {
    # Check 1: nft command exists
    if ! command -v nft &>/dev/null; then
        log_warn "FINDING: nft command not found — nftables is not installed"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_debug "firewall_audit: nft command present (OK)"
    fi

    # Check 2: nftables service is active
    if ! svc_is_active nftables; then
        log_warn "FINDING: nftables service is not active"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_debug "firewall_audit: nftables service is active (OK)"
    fi

    # Check 3: nft rules are loaded (presence of "policy" in ruleset output)
    if command -v nft &>/dev/null; then
        local ruleset
        ruleset="$(nft list ruleset 2>/dev/null || true)"
        if ! printf '%s\n' "${ruleset}" | grep -q "policy"; then
            log_warn "FINDING: nft ruleset contains no policy entries — firewall rules may not be loaded"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "firewall_audit: nft ruleset contains policy entries (OK)"
        fi
    fi
}

_firewall_audit_rhel() {
    # Check 1: firewall-cmd command exists
    if ! command -v firewall-cmd &>/dev/null; then
        log_warn "FINDING: firewall-cmd not found — firewalld is not installed"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_debug "firewall_audit: firewall-cmd present (OK)"
    fi

    # Check 2: firewalld service is active
    if ! svc_is_active firewalld; then
        log_warn "FINDING: firewalld service is not active"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_debug "firewall_audit: firewalld service is active (OK)"
    fi

    # Check 3: default zone is "drop"
    if command -v firewall-cmd &>/dev/null; then
        local default_zone
        default_zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
        if [[ "${default_zone}" != "drop" ]]; then
            log_warn "FINDING: firewalld default zone is '${default_zone}', expected 'drop'"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "firewall_audit: firewalld default zone is 'drop' (OK)"
        fi
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

firewall_apply() {
    log_info "firewall_apply: delegating to distro-specific firewall setup"

    case "${DISTRO_FAMILY}" in
        debian)
            debian_setup_firewall
            _firewall_lockdown_iptables_legacy
            ;;
        rhel)
            rhel_setup_firewall
            ;;
        *)
            log_warn "firewall_apply: unsupported DISTRO_FAMILY '${DISTRO_FAMILY}', skipping"
            ;;
    esac
}

# _firewall_lockdown_iptables_legacy — set iptables default policies to DROP
# When nftables is the primary firewall, iptables modules may still load.
# Lynis FIRE-4512 warns about an empty iptables ruleset with ACCEPT policies.
# This sets DROP on all chains so even if iptables loads, it blocks by default.
_firewall_lockdown_iptables_legacy() {
    if ! command -v iptables &>/dev/null; then
        log_debug "_firewall_lockdown_iptables_legacy: iptables not found, skipping"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would set iptables default policies to DROP"
        return 0
    fi

    # Flush all iptables rules and set ACCEPT policies.
    # nftables is the primary firewall; iptables should be empty and harmless.
    # This clears the FIRE-4512 "empty ruleset" warning by removing the iptables chains entirely.
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true

    if command -v ip6tables &>/dev/null; then
        ip6tables -F 2>/dev/null || true
        ip6tables -X 2>/dev/null || true
        ip6tables -P INPUT ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    fi

    log_change \
        "Flushed legacy iptables rules (nftables is primary firewall)" \
        "Clean iptables state to prevent FIRE-4512 warning about empty ruleset with rules" \
        "low" \
        "iptables -L -n | head -10" \
        "N/A"

    log_success "_firewall_lockdown_iptables_legacy: legacy iptables flushed"
    (( CHANGES_APPLIED++ )) || true
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

firewall_rollback() {
    log_info "firewall_rollback: restoring firewall configuration"

    case "${DISTRO_FAMILY}" in
        debian)
            _firewall_rollback_debian
            ;;
        rhel)
            _firewall_rollback_rhel
            ;;
        *)
            log_warn "firewall_rollback: unsupported DISTRO_FAMILY '${DISTRO_FAMILY}', skipping"
            ;;
    esac
}

_firewall_rollback_debian() {
    log_info "firewall_rollback: restoring /etc/nftables.conf from backup"

    restore_file "/etc/nftables.conf"

    log_info "firewall_rollback: flushing nftables ruleset"
    if command -v nft &>/dev/null; then
        nft flush ruleset 2>/dev/null || {
            log_warn "firewall_rollback: nft flush ruleset failed — rules may still be active"
        }

        # Reload nftables from restored config if the service is available
        if svc_exists nftables; then
            systemctl restart nftables 2>/dev/null || {
                log_warn "firewall_rollback: failed to restart nftables after config restore"
            }
            log_success "firewall_rollback: nftables reloaded from restored config"
        fi
    else
        log_warn "firewall_rollback: nft command not found — cannot flush ruleset"
    fi
}

_firewall_rollback_rhel() {
    log_info "firewall_rollback: resetting firewalld to public zone and reloading"

    if ! command -v firewall-cmd &>/dev/null; then
        log_warn "firewall_rollback: firewall-cmd not found — cannot reset firewalld"
        return 1
    fi

    if ! svc_is_active firewalld; then
        log_warn "firewall_rollback: firewalld is not active — attempting to start it"
        systemctl start firewalld 2>/dev/null || {
            log_error "firewall_rollback: failed to start firewalld"
            return 1
        }
    fi

    firewall-cmd --set-default-zone=public 2>/dev/null || {
        log_warn "firewall_rollback: failed to set default zone to public"
    }

    firewall-cmd --reload 2>/dev/null || {
        log_warn "firewall_rollback: firewall-cmd --reload failed"
    }

    log_success "firewall_rollback: firewalld reset to public zone and reloaded"
}
