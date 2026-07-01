#!/usr/bin/env bash
# lib/sysctl.sh — kernel hardening via sysctl drop-in
# Sourced by harden.sh. Requires lib/common.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Constants ────────────────────────────────────────────────────────────────

# zz- prefix: sysctl applies drop-ins in lexicographic order across /etc and
# /usr/lib, and vendor files like Debian's 99-protect-links.conf (which resets
# fs.protected_fifos to 1) sort after "99-hardening" and would override us —
# both at apply time and on every boot.
readonly SYSCTL_DROPIN="/etc/sysctl.d/zz-hardening.conf"
readonly SYSCTL_DROPIN_LEGACY="/etc/sysctl.d/99-hardening.conf"

# ─── Static Settings ─────────────────────────────────────────────────────────

readonly -a SYSCTL_SETTINGS=(
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "kernel.randomize_va_space=2"
    "kernel.yama.ptrace_scope=1"
    "kernel.sysrq=0"
    "fs.suid_dumpable=0"
    "net.ipv4.tcp_timestamps=0"
    # Additional KRNL-6000 hardening
    "dev.tty.ldisc_autoload=0"
    "kernel.perf_event_paranoid=3"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    # Filesystem hardening — protect FIFOs/regular files in world-writable dirs
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
    "kernel.core_uses_pid=1"
)

# ─── Conditional Settings ─────────────────────────────────────────────────────

# Returns additional settings based on config flags (one per line via echo).
_get_conditional_settings() {
    local -a extras=()

    if [[ "${RESTRICT_DMESG:-false}" == "true" ]]; then
        extras+=("kernel.dmesg_restrict=1")
    fi

    if [[ "${RESTRICT_KPTR:-false}" == "true" ]]; then
        extras+=("kernel.kptr_restrict=2")
    fi

    # accept_ra=0 stops refreshing SLAAC/RA-learned routes: on a host whose
    # IPv6 default route came from Router Advertisements, the route expires
    # after apply and IPv6 connectivity silently dies — a delayed lockout on
    # IPv6-only management paths. Only disable RA when the current IPv6
    # config does not depend on it. (log to stderr: stdout is the value list)
    if ip -6 route show default 2>/dev/null | grep -q 'proto ra'; then
        log_warn "sysctl: IPv6 default route is RA-learned — keeping accept_ra enabled to preserve IPv6 connectivity" >&2
    else
        extras+=("net.ipv6.conf.default.accept_ra=0")
        extras+=("net.ipv6.conf.all.accept_ra=0")
    fi

    local entry
    for entry in "${extras[@]}"; do
        printf '%s\n' "${entry}"
    done
}

# ─── Internal: build combined settings array ──────────────────────────────────

# Populates the named array variable with SYSCTL_SETTINGS + conditional extras.
# Usage: _build_all_settings result_array_name
_build_all_settings() {
    local -n _result_ref="${1}"
    _result_ref=("${SYSCTL_SETTINGS[@]}")

    local line
    while IFS= read -r line; do
        [[ -n "${line}" ]] && _result_ref+=("${line}")
    done < <(_get_conditional_settings)
}

# ─── Internal: key availability check ────────────────────────────────────────

_sysctl_key_exists() {
    local key="${1}"
    sysctl -n "${key}" &>/dev/null
}

# ─── Internal: group settings by prefix ──────────────────────────────────────

# Writes a section header comment appropriate for the key prefix.
_section_comment_for_key() {
    local key="${1}"
    case "${key}" in
        net.*)    printf '# Network hardening\n' ;;
        kernel.*) printf '# Kernel hardening\n' ;;
        fs.*)     printf '# Filesystem hardening\n' ;;
        *)        printf '# Miscellaneous\n' ;;
    esac
}

# ─── sysctl_audit ─────────────────────────────────────────────────────────────

sysctl_audit() {
    log_info "sysctl_audit: checking kernel parameter compliance"

    local -a all_settings=()
    _build_all_settings all_settings

    local entry key expected current
    for entry in "${all_settings[@]}"; do
        key="${entry%%=*}"
        expected="${entry#*=}"

        if ! _sysctl_key_exists "${key}"; then
            log_debug "sysctl_audit: key unavailable on this kernel, skipping: ${key}"
            continue
        fi

        # Special case: ip_forward being enabled is a NOTE, not automatically wrong
        if [[ "${key}" == "net.ipv4.ip_forward" && "${expected}" == "1" ]]; then
            current="$(sysctl_get "${key}")"
            if [[ "${current}" == "1" ]]; then
                log_warn "NOTE: net.ipv4.ip_forward=1 (routing/forwarding is enabled — review if intentional)"
            fi
            continue
        fi

        current="$(sysctl_get "${key}")"

        if [[ "${current}" != "${expected}" ]]; then
            log_warn "FINDING: ${key} is '${current}', expected '${expected}'"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "sysctl_audit: ${key}=${current} (OK)"
        fi
    done
}

# ─── sysctl_apply ─────────────────────────────────────────────────────────────

sysctl_apply() {
    log_info "sysctl_apply: writing sysctl hardening drop-in and applying settings"

    local -a all_settings=()
    _build_all_settings all_settings

    # Build drop-in file content, grouping settings by prefix with section comments.
    local content=""
    local last_prefix="" current_prefix entry key expected

    for entry in "${all_settings[@]}"; do
        key="${entry%%=*}"
        expected="${entry#*=}"

        # Determine prefix group (net, kernel, fs, or other)
        current_prefix="${key%%.*}"

        # Emit section header on prefix change
        if [[ "${current_prefix}" != "${last_prefix}" ]]; then
            [[ -n "${content}" ]] && content+=$'\n'
            local section_comment
            section_comment="$(_section_comment_for_key "${key}")"
            content+="${section_comment}"$'\n'
            last_prefix="${current_prefix}"
        fi

        if ! _sysctl_key_exists "${key}"; then
            log_debug "sysctl_apply: key unavailable, adding comment placeholder: ${key}"
            content+="# UNAVAILABLE: ${key}=${expected}"$'\n'
            continue
        fi

        content+="${key} = ${expected}"$'\n'
    done

    # Dry-run: show what would be written without touching the filesystem
    if is_dry_run; then
        log_info "[DRY-RUN] Would write ${SYSCTL_DROPIN}:"
        log_info "${content}"
        return 0
    fi

    if ! is_apply_mode; then
        log_debug "sysctl_apply: skipped in mode '${RUN_MODE}'"
        return 0
    fi

    # Ensure parent directory exists
    mkdir -p "$(dirname "${SYSCTL_DROPIN}")"

    # Migrate installs that used the old 99- name (superseded by zz-)
    if [[ -f "${SYSCTL_DROPIN_LEGACY}" ]]; then
        rm -f "${SYSCTL_DROPIN_LEGACY}"
        log_info "sysctl_apply: removed legacy drop-in ${SYSCTL_DROPIN_LEGACY}"
    fi

    # Write (only if content changed)
    local write_rc=0
    write_file_if_changed "${SYSCTL_DROPIN}" "${content}" "sysctl hardening drop-in" || write_rc=$?

    if [[ "${write_rc}" -eq 2 ]]; then
        log_info "sysctl_apply: drop-in already up to date, no reload needed"
        return 0
    fi

    log_change \
        "Write sysctl drop-in: ${SYSCTL_DROPIN}" \
        "Apply kernel hardening parameters per CIS/STIG baseline" \
        "low" \
        "sysctl --system && sysctl -n <key> for each entry" \
        "rm -f ${SYSCTL_DROPIN} && sysctl --system"

    # Apply all sysctl settings from the new drop-in
    log_info "sysctl_apply: reloading all sysctl settings with 'sysctl --system'"
    if ! sysctl --system; then
        log_error "sysctl_apply: 'sysctl --system' returned a non-zero exit code"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    # Verify each applied setting
    local verify_failures=0
    for entry in "${all_settings[@]}"; do
        key="${entry%%=*}"
        expected="${entry#*=}"

        if ! _sysctl_key_exists "${key}"; then
            log_debug "sysctl_apply: verify skipped (key unavailable): ${key}"
            continue
        fi

        local actual
        actual="$(sysctl_get "${key}")"
        if [[ "${actual}" != "${expected}" ]]; then
            log_warn "sysctl_apply: verification failed for ${key}: got '${actual}', expected '${expected}'"
            (( verify_failures++ )) || true
        else
            log_debug "sysctl_apply: verified ${key}=${actual}"
        fi
    done

    if [[ "${verify_failures}" -gt 0 ]]; then
        log_error "sysctl_apply: ${verify_failures} setting(s) failed verification after apply"
        (( CHANGES_FAILED += verify_failures )) || true
    else
        log_success "sysctl_apply: all settings verified successfully"
    fi

    _sysctl_modules_disabled_unit
}

# ─── kernel.modules_disabled (opt-in, Lynis KRNL-6000) ──────────────────────

readonly _SYSCTL_MODLOCK_UNIT="/etc/systemd/system/hardener-modules-disabled.service"

# kernel.modules_disabled=1 is a ONE-WAY switch (until reboot): once set, no
# kernel module can be loaded at all. It must NOT go into sysctl.d — applied
# early in boot it races module autoloading (netfilter, filesystems) and can
# break boot. Instead a oneshot unit flips it at the very end of boot.
# Disabled by default: it also breaks anything that loads modules on demand
# later (the LUKS module needs dm-crypt/loop, USB recovery, new mounts).
_sysctl_modules_disabled_unit() {
    if [[ "${ENABLE_MODULES_DISABLED:-false}" != "true" ]]; then
        log_debug "sysctl_apply: kernel.modules_disabled unit skipped (ENABLE_MODULES_DISABLED != true)"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would install ${_SYSCTL_MODLOCK_UNIT} (sets kernel.modules_disabled=1 at end of boot)"
        return 0
    fi

    local unit_content
    unit_content="$(cat <<'EOF'
# Managed by linux-hardener — do not edit by hand.
# Locks kernel module loading once boot is complete (KRNL-6000).
# One-way until reboot: anything needing a new module afterwards will fail.
[Unit]
Description=Disable kernel module loading (linux-hardener)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/sysctl -w kernel.modules_disabled=1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
)"

    local write_rc=0
    write_file_if_changed "${_SYSCTL_MODLOCK_UNIT}" "${unit_content}" \
        "kernel.modules_disabled late-boot unit" || write_rc=$?
    if [[ "${write_rc}" -ne 0 && "${write_rc}" -ne 2 ]]; then
        (( CHANGES_FAILED++ )) || true
        return 1
    fi
    systemctl daemon-reload
    systemctl enable hardener-modules-disabled.service &>/dev/null

    log_change \
        "Enable kernel.modules_disabled=1 at end of boot" \
        "Prevent kernel module loading after boot completes (Lynis KRNL-6000)" \
        "high" \
        "sysctl -n kernel.modules_disabled (after reboot)" \
        "systemctl disable hardener-modules-disabled.service; rm -f ${_SYSCTL_MODLOCK_UNIT}; reboot"

    log_info "sysctl_apply: module-loading lock installed — takes effect at the END of the next boot"
}

# ─── sysctl_rollback ──────────────────────────────────────────────────────────

sysctl_rollback() {
    log_info "sysctl_rollback: removing hardening drop-in and reloading sysctl"

    local dropin removed=false
    for dropin in "${SYSCTL_DROPIN}" "${SYSCTL_DROPIN_LEGACY}"; do
        if [[ -f "${dropin}" ]]; then
            rm -f "${dropin}"
            log_info "sysctl_rollback: removed ${dropin}"
            removed=true
        fi
    done
    if [[ "${removed}" == "false" ]]; then
        log_debug "sysctl_rollback: drop-in not present, nothing to remove"
    fi

    if [[ -f "${_SYSCTL_MODLOCK_UNIT}" ]]; then
        systemctl disable hardener-modules-disabled.service &>/dev/null || true
        rm -f "${_SYSCTL_MODLOCK_UNIT}"
        systemctl daemon-reload 2>/dev/null || true
        log_info "sysctl_rollback: removed module-loading lock unit (effective after reboot)"
    fi

    log_info "sysctl_rollback: reloading sysctl settings with 'sysctl --system'"
    if ! sysctl --system; then
        log_error "sysctl_rollback: 'sysctl --system' returned a non-zero exit code"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    log_success "sysctl_rollback: kernel parameters restored to pre-hardening state"
}
