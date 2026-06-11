#!/usr/bin/env bash
# modules/luks.d/baremetal.sh — bare-metal server LUKS path
# Hardens an existing LUKS root (TPM2 enrollment, header backup, key-slot
# policy, performance flags), encrypts non-root data/swap volumes, and
# optionally installs dropbear-initramfs for remote unlock.
#
# In-place encryption of a mounted root filesystem is impossible; an
# unencrypted root is reported as "needs user intervention" with pointers to
# luks/provision-encrypted.sh and the offline procedure in docs/LUKS.md.
# Sourced by modules/20_luks.sh. Do NOT add set -euo pipefail here.

# ─── Root Volume Hardening ────────────────────────────────────────────────────

# _luks_bm_root_crypt_dev — print the LUKS block device backing / (the parent
# of the crypt mapping), or nothing if root is not encrypted.
_luks_bm_root_crypt_dev() {
    [[ "${LUKS_ENV_ROOT_LUKS}" == "yes" ]] || return 1
    local crypt_name
    crypt_name="$(lsblk -sno NAME,TYPE "${LUKS_ENV_ROOT_DEV}" 2>/dev/null | awk '$2=="crypt"{print $1; exit}')"
    [[ -n "${crypt_name}" ]] || return 1
    # The parent of the crypt mapping is the LUKS container device
    lsblk -sno NAME,TYPE "/dev/mapper/${crypt_name}" 2>/dev/null \
        | awk '$2=="part" || $2=="disk" || $2=="raid1" || $2~"raid"{print "/dev/"$1; exit}'
}

# _luks_bm_harden_root — header backup, slot audit, workqueue flags, and
# optional TPM2 enrollment for an already-encrypted root.
_luks_bm_harden_root() {
    local root_luks_dev
    root_luks_dev="$(_luks_bm_root_crypt_dev)" || {
        log_debug "luks-bm: root is not on LUKS — nothing to harden"
        return 2
    }

    log_info "luks-bm: root LUKS container: ${root_luks_dev}"

    _luks_slot_audit "${root_luks_dev}" || true

    if ! should_write; then
        log_info "[DRY-RUN] Would back up root LUKS header and apply performance flags on ${root_luks_dev}"
    else
        # Header backup encrypted with an ephemeral passphrase printed ONCE to
        # the operator (we do not know the root volume's passphrase and never
        # ask for it non-interactively).
        local backup_pass
        backup_pass="$(_luks_gen_passphrase)"
        if _luks_backup_header "${root_luks_dev}" "root" "${backup_pass}"; then
            log_warn "luks-bm: ROOT HEADER BACKUP PASSPHRASE (store offline, shown once): ${backup_pass}"
        fi

        # Workqueue flags on the active root mapping need the volume key only
        # for --persistent refresh; skip if we cannot do it non-interactively.
        local crypt_name
        crypt_name="$(lsblk -sno NAME,TYPE "${LUKS_ENV_ROOT_DEV}" 2>/dev/null | awk '$2=="crypt"{print $1; exit}')"
        if [[ -n "${crypt_name}" ]] && ! _luks_dev_rotational "${root_luks_dev}"; then
            cryptsetup refresh --persistent \
                --perf-no_read_workqueue --perf-no_write_workqueue \
                --disable-keyring "${crypt_name}" 2>/dev/null \
                && log_info "luks-bm: workqueue-bypass flags persisted on root mapping" \
                || log_debug "luks-bm: could not refresh root mapping non-interactively (flags can be set via crypttab options)"
        fi
    fi

    _luks_bm_tpm2_enroll "${root_luks_dev}"
    return 0
}

# ─── TPM2 Enrollment ──────────────────────────────────────────────────────────

# _luks_bm_tpm2_enroll <device>
# Enroll the LUKS device for TPM2 auto-unlock via systemd-cryptenroll. PCR
# policy: configured banks (default 0+1+2+3+7) when Secure Boot is enabled;
# PCR 7 only when it is not (boot-path PCRs churn on every firmware/loader
# update without SB enforcement and would strand the machine at the
# passphrase prompt). The passphrase slot is always retained.
_luks_bm_tpm2_enroll() {
    local device="${1}"

    case "${LUKS_TPM2:-auto}" in
        no)
            log_debug "luks-bm: TPM2 enrollment disabled by config"
            return 2
            ;;
        yes)
            if [[ "${LUKS_ENV_TPM2}" != "yes" ]]; then
                log_error "luks-bm: LUKS_TPM2=yes but no usable TPM2 device found"
                return 1
            fi
            ;;
        auto)
            if [[ "${LUKS_ENV_TPM2}" != "yes" ]]; then
                log_info "luks-bm: no TPM2 device — staying on passphrase + keyfile unlock"
                _luks_bm_keyfile_fallback "${device}"
                return 2
            fi
            ;;
    esac

    if ! command -v systemd-cryptenroll &>/dev/null; then
        log_warn "luks-bm: systemd-cryptenroll not available (systemd >= 248 required) — TPM2 enrollment skipped"
        return 1
    fi

    local pcrs
    if [[ "${LUKS_ENV_SECUREBOOT}" == "enabled" ]]; then
        pcrs="${LUKS_TPM2_PCRS:-0+1+2+3+7}"
        log_info "luks-bm: Secure Boot enabled — sealing against PCRs ${pcrs}"
    else
        pcrs="7"
        log_warn "luks-bm: Secure Boot disabled — sealing against PCR 7 only (0-3 churn without SB)"
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would enroll ${device} for TPM2 unlock (PCRs ${pcrs})"
        return 0
    fi

    if systemd-cryptenroll "${device}" 2>/dev/null | grep -q tpm2; then
        log_debug "luks-bm: ${device} already has a TPM2 enrollment"
        (( CHANGES_SKIPPED++ )) || true
        return 2
    fi

    log_change \
        "Enroll ${device} for TPM2 auto-unlock (PCRs ${pcrs})" \
        "Unattended unlock bound to measured boot state on trusted hardware" \
        "medium" \
        "systemd-cryptenroll ${device} | grep tpm2" \
        "systemd-cryptenroll --wipe-slot=tpm2 ${device}"

    # systemd-cryptenroll needs an existing secret to authorize the new slot;
    # it prompts on the controlling TTY when no credential is supplied.
    if systemd-cryptenroll \
            --tpm2-device=auto \
            --tpm2-pcrs="${pcrs}" \
            "${device}"; then
        log_success "luks-bm: TPM2 enrollment complete on ${device}"
        (( CHANGES_APPLIED++ )) || true
    else
        log_error "luks-bm: TPM2 enrollment failed on ${device} (passphrase unlock unaffected)"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    # crypttab: let systemd try the TPM2 token at boot
    if [[ -f "${LUKS_CRYPTTAB}" ]]; then
        backup_file "${LUKS_CRYPTTAB}"
        local uuid
        uuid="$(blkid -s UUID -o value "${device}" 2>/dev/null)"
        # Append tpm2-device=auto to the matching entry if not present
        if [[ -n "${uuid}" ]] && grep -q "${uuid}" "${LUKS_CRYPTTAB}" \
                && ! grep "${uuid}" "${LUKS_CRYPTTAB}" | grep -q 'tpm2-device='; then
            sed -i -E "s@^([^#]+UUID=${uuid}[[:space:]]+[^[:space:]]+[[:space:]]+)([^[:space:]]+)\$@\1\2,tpm2-device=auto@" "${LUKS_CRYPTTAB}"
            if ! _luks_crypttab_check; then
                restore_file "${LUKS_CRYPTTAB}"
                log_error "luks-bm: crypttab tpm2 option broke validation — reverted"
                return 1
            fi
            log_info "luks-bm: tpm2-device=auto added to crypttab for ${device}"
            _luks_bm_regen_initramfs
        fi
    fi
    return 0
}

# _luks_bm_keyfile_fallback <device>
# No TPM2: ensure an /etc/luks/ recovery keyfile slot exists alongside the
# passphrase (the "passphrase + keyfile in /etc/luks/" policy).
_luks_bm_keyfile_fallback() {
    local device="${1}"
    local keyfile="${LUKS_KEY_DIR}/root-recovery.key"

    if [[ -f "${keyfile}" ]]; then
        log_debug "luks-bm: recovery keyfile already present: ${keyfile}"
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would add a recovery keyfile slot from ${keyfile} to ${device}"
        return 0
    fi

    _luks_gen_keyfile "${keyfile}"
    log_info "luks-bm: adding recovery keyfile slot to ${device} (will prompt for an existing passphrase)"
    if cryptsetup luksAddKey "${device}" "${keyfile}"; then
        log_success "luks-bm: recovery keyfile enrolled: ${keyfile} (mode 0400, dir 0700)"
        _luks_state_record "root-keyfile" "${device}" "${keyfile}"
    else
        rm -f "${keyfile}"
        log_warn "luks-bm: recovery keyfile enrollment skipped (no passphrase provided)"
    fi
}

# ─── Encrypted /boot Audit ────────────────────────────────────────────────────

# Audit-only: converting /boot to LUKS1 in place is documented in docs/LUKS.md,
# not automated — a broken /boot is unrecoverable without console access.
_luks_bm_boot_status() {
    local boot_src boot_types
    boot_src="$(findmnt -no SOURCE /boot 2>/dev/null || true)"
    if [[ -z "${boot_src}" ]]; then
        log_debug "luks-bm: /boot is not a separate mount"
        return 0
    fi

    boot_types="$(lsblk -sno TYPE "${boot_src}" 2>/dev/null || true)"
    if grep -qw crypt <<< "${boot_types}"; then
        log_info "luks-bm: /boot is encrypted"
    else
        log_warn "FINDING: /boot (${boot_src}) is not encrypted — GRUB2 LUKS1 /boot or TPM2-bound kernel verification recommended (docs/LUKS.md)"
        (( AUDIT_FINDINGS++ )) || true
    fi

    local grub_default="/etc/default/grub"
    if [[ -f "${grub_default}" ]] && grep -q '^GRUB_ENABLE_CRYPTODISK=y' "${grub_default}"; then
        log_debug "luks-bm: GRUB_ENABLE_CRYPTODISK=y present"
    fi
}

# ─── Dropbear Remote Unlock ───────────────────────────────────────────────────

# _luks_bm_dropbear — opt-in SSH unlock in the initramfs for headless
# colocated servers. Debian family only (dropbear-initramfs packaging);
# RHEL-family hosts get a documented pointer instead.
_luks_bm_dropbear() {
    [[ "${LUKS_DROPBEAR:-no}" == "yes" ]] || return 2

    if [[ "${LUKS_ENV_ROOT_LUKS}" != "yes" ]]; then
        log_warn "luks-bm: dropbear requested but root is not LUKS — nothing to unlock remotely"
        return 1
    fi

    if [[ "${DISTRO_FAMILY}" != "debian" ]]; then
        log_warn "luks-bm: dropbear-initramfs is Debian-family only; for RHEL use clevis-dracut or console unlock (docs/LUKS.md)"
        return 1
    fi

    if [[ "${LUKS_ENV_BOOT_WRITABLE}" != "yes" ]]; then
        log_error "luks-bm: /boot or initramfs tooling not accessible — refusing to install dropbear"
        return 1
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would install dropbear-initramfs on port ${LUKS_DROPBEAR_PORT}"
        return 0
    fi

    log_change \
        "Install dropbear-initramfs (port ${LUKS_DROPBEAR_PORT}) for remote LUKS unlock" \
        "Headless unlock of encrypted root over SSH" \
        "high" \
        "lsinitramfs /boot/initrd.img-\$(uname -r) | grep dropbear" \
        "apt-get purge dropbear-initramfs && update-initramfs -u"

    pkg_install dropbear-initramfs || {
        log_error "luks-bm: dropbear-initramfs installation failed"
        return 1
    }

    local db_dir db_conf
    if [[ -d /etc/dropbear/initramfs ]]; then
        db_dir="/etc/dropbear/initramfs"           # Debian 12+
    else
        db_dir="/etc/dropbear-initramfs"           # older layout
    fi
    db_conf="${db_dir}/dropbear.conf"
    [[ -f "${db_conf}" ]] || db_conf="${db_dir}/config"

    backup_file "${db_conf}"
    # -s: no password logins  -j/-k: no local/remote port forwarding
    cat > "${db_conf}" <<EOF
# Managed by linux-hardener (modules/20_luks.sh) — do not edit by hand
DROPBEAR_OPTIONS="-p ${LUKS_DROPBEAR_PORT} -s -j -k"
EOF

    # Authorized keys: root's keys unlock the disk
    local auth_src="/root/.ssh/authorized_keys"
    if [[ -s "${auth_src}" ]]; then
        # Restrict unlock sessions to cryptroot-unlock only
        sed 's@^@command="cryptroot-unlock" @' "${auth_src}" > "${db_dir}/authorized_keys"
        chmod 0600 "${db_dir}/authorized_keys"
    else
        log_warn "luks-bm: ${auth_src} is empty — add a key to ${db_dir}/authorized_keys before rebooting"
    fi

    # Validate crypttab BEFORE baking it into the initramfs
    if ! _luks_crypttab_check; then
        log_error "luks-bm: crypttab invalid — initramfs NOT regenerated"
        return 1
    fi
    _luks_bm_regen_initramfs || return 1

    # Print the initramfs host key fingerprint for out-of-band verification
    local hostkey fp
    for hostkey in "${db_dir}"/dropbear_*_host_key; do
        [[ -f "${hostkey}" ]] || continue
        if command -v dropbearkey &>/dev/null; then
            fp="$(dropbearkey -y -f "${hostkey}" 2>/dev/null | grep -A1 '^Public' | tail -1 || true)"
            log_info "luks-bm: dropbear host key: ${fp:-$(basename "${hostkey}")}"
        fi
    done
    log_success "luks-bm: dropbear remote unlock ready on port ${LUKS_DROPBEAR_PORT} (run 'cryptroot-unlock' after ssh)"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Initramfs / GRUB Regeneration ───────────────────────────────────────────

_luks_bm_regen_initramfs() {
    if [[ "${LUKS_ENV_BOOT_WRITABLE}" != "yes" ]]; then
        log_error "luks-bm: boot environment not writable — initramfs left untouched"
        return 1
    fi

    log_info "luks-bm: regenerating initramfs"
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u -k all || { log_error "luks-bm: update-initramfs failed"; return 1; }
    elif command -v dracut &>/dev/null; then
        dracut --force --regenerate-all || { log_error "luks-bm: dracut failed"; return 1; }
    else
        log_error "luks-bm: no initramfs tool found"
        return 1
    fi
    log_success "luks-bm: initramfs regenerated"
    return 0
}

# ─── Bare-Metal Path Orchestrator ─────────────────────────────────────────────

luks_baremetal_apply() {
    log_info "luks: applying bare-metal path"

    if [[ "${LUKS_ENV_ROOT_LUKS}" == "yes" ]]; then
        _luks_bm_harden_root
    elif [[ "${LUKS_ROOT_ENCRYPT:-no}" == "yes" ]]; then
        log_error "luks-bm: root is NOT encrypted and cannot be encrypted in place from a running system."
        log_error "luks-bm: options:"
        log_error "luks-bm:   1. Re-provision with full FDE: luks/provision-encrypted.sh (wipes the host)"
        log_error "luks-bm:   2. Offline re-encryption from a live ISO: cryptsetup reencrypt --encrypt --reduce-device-size 32M <dev> (see docs/LUKS.md)"
        (( CHANGES_FAILED++ )) || true
    else
        log_info "luks-bm: root not encrypted and LUKS_ROOT_ENCRYPT=no — hardening non-root volumes only"
    fi

    # Non-root data volumes and swap reuse the VPS machinery — the safety
    # gate refuses the root disk in both paths.
    if [[ -n "${LUKS_DATA_DEVICES:-}" ]]; then
        _luks_vps_data_volumes
    fi
    _luks_vps_swap
    _luks_bm_dropbear
    _luks_bm_boot_status

    return 0
}
