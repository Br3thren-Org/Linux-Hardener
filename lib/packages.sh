#!/usr/bin/env bash
# lib/packages.sh — package hardening module (audit / apply / rollback)
# Sourced by harden.sh (or modules/packages.sh) after lib/common.sh and the
# distro-specific adapter.  All log_*, pkg_*, should_write, backup_file,
# restore_file helpers from common.sh are available here.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly UNNECESSARY_PACKAGES=(
    telnet
    rsh-client
    rsh-server
    talk
    talkd
    xinetd
    ypbind
    ypserv
    tftp
    tftp-server
)

# ─── Audit ────────────────────────────────────────────────────────────────────

packages_audit() {
    log_info "packages_audit: checking for unnecessary packages and update availability"

    # --- unnecessary packages present on the system ---
    local pkg
    for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
        if pkg_is_installed "${pkg}"; then
            log_warn "FINDING: unnecessary package installed: ${pkg}"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "packages_audit: ${pkg} not installed (OK)"
        fi
    done

    # --- available update count (Debian only) ---
    if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
        local update_count
        update_count="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)"
        if [[ "${update_count}" -gt 0 ]]; then
            log_warn "FINDING: ${update_count} package update(s) available (run apt-get upgrade)"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_info "packages_audit: no pending apt upgrades detected"
        fi
    fi

    # --- unattended-upgrades / dnf-automatic consistency check ---
    if [[ "${ENABLE_UNATTENDED_UPGRADES:-false}" == "true" ]]; then
        case "${DISTRO_FAMILY}" in
            debian)
                if ! pkg_is_installed unattended-upgrades; then
                    log_warn "FINDING: ENABLE_UNATTENDED_UPGRADES=true but unattended-upgrades is not installed"
                    (( AUDIT_FINDINGS++ )) || true
                else
                    log_info "packages_audit: unattended-upgrades package is installed (OK)"
                fi
                ;;
            rhel)
                if ! pkg_is_installed dnf-automatic; then
                    log_warn "FINDING: ENABLE_UNATTENDED_UPGRADES=true but dnf-automatic is not installed"
                    (( AUDIT_FINDINGS++ )) || true
                else
                    log_info "packages_audit: dnf-automatic package is installed (OK)"
                fi
                ;;
        esac
    fi
}

# ─── Apply ────────────────────────────────────────────────────────────────────

packages_apply() {
    log_info "packages_apply: applying security updates and removing unnecessary packages"

    # --- security updates ---
    case "${DISTRO_FAMILY}" in
        debian)
            debian_security_update
            ;;
        rhel)
            rhel_security_update
            ;;
        *)
            log_warn "packages_apply: unknown DISTRO_FAMILY '${DISTRO_FAMILY}', skipping security update"
            ;;
    esac

    # --- remove unnecessary packages ---
    local pkg
    for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
        if pkg_is_installed "${pkg}"; then
            log_info "Removing unnecessary package: ${pkg}"

            log_change \
                "Remove package: ${pkg}" \
                "Unnecessary on headless cloud VPS, reduces attack surface" \
                "low" \
                "! pkg_is_installed ${pkg}" \
                "pkg_install ${pkg}"

            if should_write; then
                pkg_remove "${pkg}" || {
                    log_warn "Failed to remove ${pkg} (possible dependency conflict); continuing"
                    (( CHANGES_FAILED++ )) || true
                }
                (( CHANGES_APPLIED++ )) || true
            else
                log_info "[DRY-RUN] Would remove package: ${pkg}"
                (( CHANGES_SKIPPED++ )) || true
            fi
        else
            log_debug "packages_apply: ${pkg} not installed, skipping removal"
        fi
    done

    # --- configure unattended upgrades ---
    case "${DISTRO_FAMILY}" in
        debian)
            debian_enable_unattended_upgrades
            ;;
        rhel)
            rhel_enable_unattended_upgrades
            ;;
        *)
            log_warn "packages_apply: unknown DISTRO_FAMILY '${DISTRO_FAMILY}', skipping unattended-upgrades setup"
            ;;
    esac
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

packages_rollback() {
    log_info "packages_rollback: starting package module rollback"

    # Removed packages and applied updates cannot be automatically reversed.
    log_warn "Removed packages and applied security updates cannot be automatically rolled back."
    log_warn "To reinstall a removed package, run: pkg_install <package-name>"
    log_warn "To revert updates, restore from a full system snapshot or backup."

    # Restore unattended-upgrades / dnf-automatic configuration files from backup.
    case "${DISTRO_FAMILY}" in
        debian)
            restore_file "/etc/apt/apt.conf.d/50unattended-upgrades"
            restore_file "/etc/apt/apt.conf.d/20auto-upgrades"
            ;;
        rhel)
            restore_file "/etc/dnf/automatic.conf"
            ;;
        *)
            log_warn "packages_rollback: unknown DISTRO_FAMILY '${DISTRO_FAMILY}', skipping config restore"
            ;;
    esac

    log_info "packages_rollback: configuration files restored (where backups existed)"
}
