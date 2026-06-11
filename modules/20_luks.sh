#!/usr/bin/env bash
# modules/20_luks.sh — LUKS encryption module (runtime, environment-adaptive)
# Sourced by harden.sh after lib/common.sh and the distro adapter.
# Provides: luks_preflight, luks_audit, luks_apply, luks_rollback.
#
# Fully optional and DISABLED by default (LUKS_ENABLED=no in config/luks.conf).
# Bare-metal hosts get root-FDE hardening + TPM2 + optional dropbear;
# virtual hosts get encrypted data volumes/containers and swap, with the
# root disk, bootloader, and initramfs never touched.
# Do NOT add set -euo pipefail here; the caller owns that.

_LUKS_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/luks.d"

# shellcheck source=luks.d/env-detect.sh
source "${_LUKS_MODULE_DIR}/env-detect.sh"
# shellcheck source=luks.d/common.sh
source "${_LUKS_MODULE_DIR}/common.sh"
# shellcheck source=luks.d/kms.sh
source "${_LUKS_MODULE_DIR}/kms.sh"
# shellcheck source=luks.d/vps.sh
source "${_LUKS_MODULE_DIR}/vps.sh"
# shellcheck source=luks.d/baremetal.sh
source "${_LUKS_MODULE_DIR}/baremetal.sh"

# Config defaults (config/luks.conf overrides these when loaded)
: "${LUKS_ENABLED:=no}"
: "${LUKS_MODE:=auto}"
: "${LUKS_ROOT_ENCRYPT:=no}"
: "${LUKS_TPM2:=auto}"
: "${LUKS_TPM2_PCRS:=0+1+2+3+7}"
: "${LUKS_CLOUD_KMS_PROVIDER:=none}"
: "${LUKS_SWAP_ENCRYPT:=yes}"
: "${LUKS_DATA_PATH:=/var/lib/encrypted-data}"
: "${LUKS_DATA_DEVICES:=}"
: "${LUKS_CONTAINER_FILE:=/var/lib/luks/data.img}"
: "${LUKS_CONTAINER_SIZE_MB:=2048}"
: "${LUKS_SWAPFILE_SIZE_MB:=1024}"
: "${LUKS_SWAP_DEVICE:=}"
: "${LUKS_BIND_SENSITIVE:=no}"
: "${LUKS_BIND_EXTRA_DIRS:=}"
: "${LUKS_NBDE:=no}"
: "${LUKS_TANG_URL:=}"
: "${LUKS_DROPBEAR:=no}"
: "${LUKS_DROPBEAR_PORT:=2222}"
: "${LUKS_CIPHER:=auto}"
: "${LUKS_KEY_SIZE:=512}"
: "${LUKS_PBKDF:=argon2id}"
: "${LUKS_PBKDF_MEMORY:=1048576}"
: "${LUKS_PBKDF_ITERATIONS:=4}"
: "${LUKS_PBKDF_PARALLEL:=4}"
: "${LUKS_HEADER_BACKUP_DIR:=/var/backups/luks-headers}"
: "${LUKS_HEADER_BACKUP_SECONDARY:=}"
: "${LUKS_FORCE:=no}"

# ─── Preflight ────────────────────────────────────────────────────────────────

# luks_preflight — readiness check for the detected environment.
# Returns:
#   0 — ready to apply
#   1 — needs user intervention (explained in the log)
#   2 — unsupported environment (or module disabled)
luks_preflight() {
    if [[ "${LUKS_ENABLED}" != "yes" ]]; then
        log_info "luks: disabled (LUKS_ENABLED=no) — enable in config/luks.conf"
        return 2
    fi

    luks_env_detect

    # Containers share the host kernel and have no device ownership: no path.
    if [[ "${LUKS_ENV_VIRT}" == "container" ]]; then
        log_error "luks: running inside a container — block-device encryption is not applicable"
        return 2
    fi

    # cryptsetup must exist or be installable
    if ! command -v cryptsetup &>/dev/null; then
        if is_apply_mode; then
            _luks_require_tools || {
                log_error "luks: cryptsetup unavailable and could not be installed"
                return 1
            }
        else
            log_warn "luks: cryptsetup not installed (would be installed in apply mode)"
        fi
    fi

    if [[ "${LUKS_ENV_TYPE}" == "bare-metal" ]]; then
        # Unencrypted root + explicit request for root FDE → operator decision
        if [[ "${LUKS_ENV_ROOT_LUKS}" != "yes" && "${LUKS_ROOT_ENCRYPT}" == "yes" ]]; then
            log_warn "luks: root FDE requested but root is unencrypted — offline re-encryption or re-provisioning required (docs/LUKS.md)"
            return 1
        fi
        if [[ "${LUKS_DROPBEAR}" == "yes" && "${LUKS_ENV_BOOT_WRITABLE}" != "yes" ]]; then
            log_warn "luks: dropbear requested but /boot or initramfs tooling is not accessible"
            return 1
        fi
    else
        # VPS path: need either listed devices, or room for the container
        if [[ -z "${LUKS_DATA_DEVICES}" ]]; then
            local avail_mb
            avail_mb="$(df -Pm "$(dirname "${LUKS_CONTAINER_FILE}")" 2>/dev/null | awk 'NR==2{print $4}')"
            if [[ -n "${avail_mb}" && "${avail_mb}" -lt $(( LUKS_CONTAINER_SIZE_MB + LUKS_CONTAINER_SIZE_MB / 10 )) ]]; then
                log_warn "luks: no data devices configured and insufficient space (${avail_mb}MB) for a ${LUKS_CONTAINER_SIZE_MB}MB container"
                return 1
            fi
        fi
    fi

    log_info "luks: preflight OK (${LUKS_ENV_TYPE} path)"
    return 0
}

# ─── Audit ────────────────────────────────────────────────────────────────────

luks_audit() {
    log_info "luks_audit: checking at-rest encryption state"

    luks_env_detect

    # Root encryption expectation differs by environment
    if [[ "${LUKS_ENV_TYPE}" == "bare-metal" ]]; then
        if [[ "${LUKS_ENV_ROOT_LUKS}" == "yes" ]]; then
            log_debug "luks_audit: root device is LUKS-encrypted (OK)"
        else
            log_warn "FINDING: bare-metal root device (${LUKS_ENV_ROOT_DEV}) is not LUKS-encrypted"
            (( AUDIT_FINDINGS++ )) || true
        fi
        _luks_bm_boot_status
    else
        # VPS: expect at least one non-root LUKS device when enabled
        local crypt_count
        crypt_count="$(lsblk -rno TYPE 2>/dev/null | grep -c '^crypt$' || true)"
        if [[ "${crypt_count}" -ge 1 ]]; then
            log_debug "luks_audit: ${crypt_count} dm-crypt mapping(s) active (OK)"
        elif [[ "${LUKS_ENABLED}" == "yes" ]]; then
            log_warn "FINDING: no LUKS-encrypted volumes present on this VPS"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_info "luks_audit: no encrypted volumes (module disabled — informational)"
        fi
    fi

    # Swap encryption
    local swaps
    swaps="$(swapon --show=NAME --noheadings 2>/dev/null || true)"
    if [[ -n "${swaps}" ]]; then
        local plain
        plain="$(grep -v '^/dev/\(mapper/\|dm-\|zram\)' <<< "${swaps}" || true)"
        if [[ -n "${plain}" ]]; then
            log_warn "FINDING: plaintext swap active: ${plain//$'\n'/, }"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "luks_audit: all active swap is encrypted or zram (OK)"
        fi
    fi

    # crypttab validity
    if [[ -f "${LUKS_CRYPTTAB}" ]]; then
        if _luks_crypttab_check; then
            log_debug "luks_audit: /etc/crypttab is valid (OK)"
        else
            log_warn "FINDING: /etc/crypttab contains invalid entries"
            (( AUDIT_FINDINGS++ )) || true
        fi
    fi

    # Key-slot policy + header backups for known LUKS devices
    local dev
    while IFS= read -r dev; do
        [[ -n "${dev}" ]] || continue
        _luks_slot_audit "${dev}" || true
    done < <(lsblk -rpno NAME,FSTYPE 2>/dev/null | awk '$2=="crypto_LUKS"{print $1}')

    if [[ "${LUKS_ENABLED}" == "yes" && ! -d "${LUKS_HEADER_BACKUP_DIR}" ]]; then
        log_warn "FINDING: no LUKS header backups at ${LUKS_HEADER_BACKUP_DIR}"
        (( AUDIT_FINDINGS++ )) || true
    fi

    return 0
}

# ─── Apply ────────────────────────────────────────────────────────────────────

luks_apply() {
    if [[ "${LUKS_ENABLED}" != "yes" ]]; then
        log_info "luks: module disabled (LUKS_ENABLED=no) — skipping"
        return 2
    fi

    local pf_rc=0
    luks_preflight || pf_rc=$?
    case "${pf_rc}" in
        1)
            log_error "luks: preflight requires user intervention — see warnings above"
            return 1
            ;;
        2)
            log_error "luks: unsupported environment — skipping"
            return 2
            ;;
    esac

    _luks_require_tools || return 1
    _luks_entropy_ready || return 1
    _luks_benchmark_cipher

    case "${LUKS_ENV_TYPE}" in
        bare-metal)
            luks_baremetal_apply
            ;;
        virtual)
            luks_vps_apply
            ;;
        *)
            log_error "luks: unknown environment type '${LUKS_ENV_TYPE}'"
            return 1
            ;;
    esac

    # Final consistency check — never leave a crypttab we cannot vouch for
    if should_write && [[ -f "${LUKS_CRYPTTAB}" ]]; then
        if ! _luks_crypttab_check; then
            log_error "luks: post-apply crypttab validation FAILED — review ${LUKS_CRYPTTAB} before rebooting"
            return 1
        fi
    fi

    return 0
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

# Reverts configuration changes only. Encrypted data is left intact and
# recoverable (no luksErase, no key destruction) — closing mappings and
# removing entries makes the volumes inert, not destroyed.
luks_rollback() {
    log_info "luks_rollback: reverting LUKS module configuration"

    restore_file "${LUKS_CRYPTTAB}" 2>/dev/null \
        || log_debug "luks_rollback: no crypttab backup to restore"
    restore_file /etc/fstab 2>/dev/null \
        || log_debug "luks_rollback: no fstab backup to restore"

    # Disable the loop-container unit and unmount what we created
    if [[ -f /etc/systemd/system/luks-data.service ]]; then
        systemctl disable --now luks-data.service 2>/dev/null || true
        rm -f /etc/systemd/system/luks-data.service /usr/local/sbin/luks-mount-data.sh
        systemctl daemon-reload 2>/dev/null || true
        log_info "luks_rollback: removed luks-data.service"
    fi

    # Unwind bind mounts
    local entry dir
    while IFS='|' read -r _ dir _; do
        [[ -n "${dir}" ]] || continue
        if mountpoint -q "${dir}" 2>/dev/null; then
            umount "${dir}" 2>/dev/null && log_info "luks_rollback: unbound ${dir}"
        fi
    done < <(_luks_state_entries "bind")

    # Deactivate encrypted swap; restored fstab re-enables original swap
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q '^/dev/mapper/cryptswap'; then
        swapoff /dev/mapper/cryptswap 2>/dev/null || true
        cryptsetup close cryptswap 2>/dev/null || true
        log_info "luks_rollback: encrypted swap deactivated"
    fi
    # Un-comment swap entries we disabled
    if [[ -f /etc/fstab ]] && grep -q '^#disabled-by-linux-hardener ' /etc/fstab; then
        sed -i 's@^#disabled-by-linux-hardener @@' /etc/fstab
        swapon -a 2>/dev/null || true
        log_info "luks_rollback: original swap entries re-enabled"
    fi

    # Close data mappings (data preserved; reopen with the keyfiles in /etc/luks)
    local name mnt
    while IFS='|' read -r _ name _ mnt _; do
        [[ -n "${name}" ]] || continue
        mountpoint -q "${mnt}" 2>/dev/null && umount "${mnt}" 2>/dev/null
        cryptsetup status "${name}" &>/dev/null && cryptsetup close "${name}" 2>/dev/null
        log_info "luks_rollback: closed ${name} (data intact; keyfile retained in ${LUKS_KEY_DIR})"
    done < <(_luks_state_entries "volume"; _luks_state_entries "container")

    log_success "luks_rollback: complete (encrypted data and keys preserved)"
    return 0
}
