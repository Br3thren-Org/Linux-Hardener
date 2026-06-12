#!/usr/bin/env bash
# modules/15_kernel_cmdline.sh — kernel command-line hardening
# Provides: kernel_cmdline_audit, kernel_cmdline_apply, kernel_cmdline_rollback
#
# Adds well-tested boot-time mitigations to GRUB_CMDLINE_LINUX and regenerates
# the bootloader config with the same verify-or-revert safety used elsewhere
# in the framework. Never reboots — parameters take effect on the next boot
# (orchestrate.sh owns reboots).
#
# Conditional parameters:
#   lockdown=integrity   only with Secure Boot enabled AND kernel support
#                        (/sys/kernel/security/lockdown) — without SB it adds
#                        breakage risk for no enforcement benefit
#   tsx=off              only when the CPU exposes TSX (rtm cpuinfo flag)
# Sourced by harden.sh. Do NOT add set -euo pipefail here.

: "${KERNEL_CMDLINE_HARDEN:=no}"
: "${KERNEL_CMDLINE_EXTRA:=}"

readonly _KCMD_GRUB_DEFAULT="/etc/default/grub"

# Unconditional, well-tested mitigations
readonly -a _KCMD_BASE_PARAMS=(
    "init_on_alloc=1"
    "init_on_free=1"
    "slab_nomerge"
    "page_alloc.shuffle=1"
    "randomize_kstack_offset=on"
    "vsyscall=none"
    "spectre_v2=on"
    "spec_store_bypass_disable=seccomp"
)

# ─── Parameter Selection ──────────────────────────────────────────────────────

# _kcmd_wanted_params — print the full parameter list for this host, one per
# line. ONLY parameters go to stdout (the caller captures it); any logging is
# redirected to stderr so it never pollutes the captured parameter list.
_kcmd_wanted_params() {
    local p
    for p in "${_KCMD_BASE_PARAMS[@]}"; do
        printf '%s\n' "${p}"
    done

    # tsx=off only matters on CPUs that have TSX at all
    if grep -q '^flags.*\brtm\b' /proc/cpuinfo 2>/dev/null; then
        printf 'tsx=off\n'
    fi

    # lockdown=integrity: Secure Boot + kernel lockdown LSM support required
    if [[ -e /sys/kernel/security/lockdown ]]; then
        if [[ "${LUKS_ENV_SECUREBOOT:-}" == "enabled" ]]; then
            printf 'lockdown=integrity\n'
        else
            log_warn "kernel_cmdline: Secure Boot is not enabled — skipping lockdown=integrity (no enforcement benefit, real breakage risk)" >&2
        fi
    else
        log_debug "kernel_cmdline: kernel has no lockdown LSM — skipping lockdown=integrity" >&2
    fi

    # Operator extras
    if [[ -n "${KERNEL_CMDLINE_EXTRA}" ]]; then
        local extra
        for extra in ${KERNEL_CMDLINE_EXTRA}; do
            printf '%s\n' "${extra}"
        done
    fi
}

# _kcmd_param_in_cmdline <param> [cmdline] — present in the given cmdline?
_kcmd_param_in_cmdline() {
    local param="${1}"
    local cmdline="${2:-$(cat /proc/cmdline 2>/dev/null)}"
    grep -qw -- "${param}" <<< "${cmdline}"
}

# ─── Audit ────────────────────────────────────────────────────────────────────

kernel_cmdline_audit() {
    if [[ "${KERNEL_CMDLINE_HARDEN}" != "yes" ]]; then
        log_info "kernel_cmdline_audit: skipped (KERNEL_CMDLINE_HARDEN != yes)"
        return 0
    fi

    log_info "kernel_cmdline_audit: checking active kernel parameters"

    # Environment detection feeds the lockdown decision
    declare -f luks_env_detect &>/dev/null && luks_env_detect &>/dev/null

    local param missing_live=() missing_cfg=()
    while IFS= read -r param; do
        [[ -n "${param}" ]] || continue
        _kcmd_param_in_cmdline "${param}" || missing_live+=("${param}")
        if [[ -f "${_KCMD_GRUB_DEFAULT}" ]] \
                && ! grep -E '^GRUB_CMDLINE_LINUX=' "${_KCMD_GRUB_DEFAULT}" | grep -qw -- "${param}"; then
            missing_cfg+=("${param}")
        fi
    done < <(_kcmd_wanted_params)

    if [[ ${#missing_cfg[@]} -gt 0 ]]; then
        log_warn "FINDING: kernel parameters not configured in GRUB: ${missing_cfg[*]}"
        (( AUDIT_FINDINGS++ )) || true
    elif [[ ${#missing_live[@]} -gt 0 ]]; then
        log_warn "kernel_cmdline_audit: configured but not active yet (reboot pending): ${missing_live[*]}"
    else
        log_debug "kernel_cmdline_audit: all requested parameters active (OK)"
    fi

    # lockdown actually engaged?
    if _kcmd_param_in_cmdline "lockdown=integrity" && [[ -e /sys/kernel/security/lockdown ]]; then
        if grep -q '\[integrity\]' /sys/kernel/security/lockdown 2>/dev/null; then
            log_debug "kernel_cmdline_audit: lockdown=integrity engaged (OK)"
        else
            log_warn "FINDING: lockdown=integrity on cmdline but not engaged: $(cat /sys/kernel/security/lockdown 2>/dev/null)"
            (( AUDIT_FINDINGS++ )) || true
        fi
    fi
    return 0
}

# ─── Apply ────────────────────────────────────────────────────────────────────

kernel_cmdline_apply() {
    if [[ "${KERNEL_CMDLINE_HARDEN}" != "yes" ]]; then
        log_info "kernel_cmdline: disabled (KERNEL_CMDLINE_HARDEN != yes) — skipping"
        return 2
    fi

    if [[ ! -f "${_KCMD_GRUB_DEFAULT}" ]]; then
        log_warn "kernel_cmdline: ${_KCMD_GRUB_DEFAULT} not found (non-GRUB boot?) — skipping"
        return 2
    fi

    # Secure Boot / virtualization context for the lockdown decision + warning
    declare -f luks_env_detect &>/dev/null && luks_env_detect &>/dev/null

    local -a wanted=() missing=()
    local param
    while IFS= read -r param; do
        [[ -n "${param}" ]] && wanted+=("${param}")
    done < <(_kcmd_wanted_params)

    local current_line
    current_line="$(grep -E '^GRUB_CMDLINE_LINUX=' "${_KCMD_GRUB_DEFAULT}" | tail -1)"
    for param in "${wanted[@]}"; do
        grep -qw -- "${param}" <<< "${current_line}" || missing+=("${param}")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_info "kernel_cmdline: all parameters already configured — skipping"
        (( CHANGES_SKIPPED++ )) || true
        return 2
    fi

    if [[ "${DRY_RUN:-no}" == "yes" ]] || ! should_write; then
        log_info "[DRY-RUN] Would append to GRUB_CMDLINE_LINUX: ${missing[*]}"
        return 0
    fi

    if [[ "${LUKS_ENV_TYPE:-}" == "virtual" ]] && printf '%s\n' "${wanted[@]}" | grep -q '^lockdown='; then
        log_warn "kernel_cmdline: WARNING — on a VPS, lockdown=integrity blocks unsigned kernel modules; provider guest tools or custom kernels may stop loading"
    fi

    log_change \
        "Append kernel parameters: ${missing[*]}" \
        "Boot-time memory-safety and speculative-execution mitigations" \
        "high" \
        "cat /proc/cmdline (after reboot)" \
        "Restore ${_KCMD_GRUB_DEFAULT} from backup and regenerate GRUB config"

    backup_file "${_KCMD_GRUB_DEFAULT}"

    # Append missing params inside the existing quoted value
    local additions="${missing[*]}"
    sed -i -E "s/^(GRUB_CMDLINE_LINUX=\")([^\"]*)\"/\1\2 ${additions}\"/" "${_KCMD_GRUB_DEFAULT}"
    # Normalize accidental double spaces
    sed -i -E 's/^(GRUB_CMDLINE_LINUX=")\s+/\1/; s/\s+"/"/' "${_KCMD_GRUB_DEFAULT}"

    # ── Regenerate, verify, revert on failure ────────────────────────────────
    local regen_ok=true grub_cfg="" script_check=""
    if command -v update-grub &>/dev/null; then
        grub_cfg="/boot/grub/grub.cfg"
        script_check="grub-script-check"
        update-grub 2>/dev/null || regen_ok=false
    elif command -v grub2-mkconfig &>/dev/null; then
        grub_cfg="/boot/grub2/grub.cfg"
        script_check="grub2-script-check"
        grub2-mkconfig -o "${grub_cfg}" 2>/dev/null || regen_ok=false
        # BLS-based EL9+: push the new cmdline into the loader entries too
        if command -v grubby &>/dev/null; then
            grubby --update-kernel=ALL --args="${additions}" 2>/dev/null \
                || log_warn "kernel_cmdline: grubby update failed — BLS entries may lag /etc/default/grub"
        fi
    else
        log_error "kernel_cmdline: no GRUB regeneration tool found"
        restore_file "${_KCMD_GRUB_DEFAULT}" || true
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    if [[ "${regen_ok}" == "true" && -n "${script_check}" ]] && command -v "${script_check}" &>/dev/null; then
        "${script_check}" "${grub_cfg}" 2>/dev/null || regen_ok=false
    fi

    if [[ "${regen_ok}" != "true" ]]; then
        log_error "kernel_cmdline: GRUB regeneration/verification FAILED — reverting"
        restore_file "${_KCMD_GRUB_DEFAULT}" || true
        if command -v update-grub &>/dev/null; then
            update-grub 2>/dev/null || true
        elif command -v grub2-mkconfig &>/dev/null; then
            grub2-mkconfig -o "${grub_cfg}" 2>/dev/null || true
            command -v grubby &>/dev/null && grubby --update-kernel=ALL --remove-args="${additions}" 2>/dev/null
        fi
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    log_success "kernel_cmdline: parameters configured (${missing[*]}) — active after the next reboot"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

kernel_cmdline_rollback() {
    log_info "kernel_cmdline_rollback: restoring bootloader configuration"

    if ! restore_file "${_KCMD_GRUB_DEFAULT}" 2>/dev/null; then
        log_debug "kernel_cmdline_rollback: no ${_KCMD_GRUB_DEFAULT} backup in this run"
        return 0
    fi

    if command -v update-grub &>/dev/null; then
        update-grub 2>/dev/null || log_warn "kernel_cmdline_rollback: update-grub failed"
    elif command -v grub2-mkconfig &>/dev/null; then
        grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null \
            || log_warn "kernel_cmdline_rollback: grub2-mkconfig failed"
        if command -v grubby &>/dev/null; then
            local all_params
            all_params="$(_kcmd_wanted_params | tr '\n' ' ')"
            grubby --update-kernel=ALL --remove-args="${all_params}" 2>/dev/null || true
        fi
    fi

    log_success "kernel_cmdline_rollback: complete (effective after reboot)"
    return 0
}
