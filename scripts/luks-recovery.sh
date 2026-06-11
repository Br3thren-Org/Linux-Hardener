#!/usr/bin/env bash
# scripts/luks-recovery.sh — bare-metal LUKS recovery toolkit
# Restore headers, add temporary recovery passphrases, and regenerate the
# initramfs/GRUB safely. Run from the installed system or a live ISO chroot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

HEADER_BACKUP_DIR="${LUKS_HEADER_BACKUP_DIR:-/var/backups/luks-headers}"

usage() {
    cat <<EOF
Usage: $(basename "${0}") <command> [args]

Commands:
  restore-header <device> <backup-file>
        Restore a LUKS header from a backup created by the hardener.
        .gpg backups are decrypted first (you will be prompted for the
        backup passphrase); SHA-512 checksums are verified when present.
        DESTRUCTIVE to the current header — requires typed confirmation.

  add-temp-key <device>
        Add a temporary recovery passphrase to a free key slot. Prints the
        slot number so you can remove it later with:
            cryptsetup luksKillSlot <device> <slot>

  regen-boot
        Validate /etc/crypttab, then regenerate the initramfs and GRUB
        configuration (update-initramfs/dracut + grub-mkconfig, distro-aware).

  list-backups
        List header backups under ${HEADER_BACKUP_DIR}.

Examples:
  sudo $(basename "${0}") list-backups
  sudo $(basename "${0}") restore-header /dev/sda3 /var/backups/luks-headers/root-20260611_120000.header.img.gpg
  sudo $(basename "${0}") add-temp-key /dev/sda3
  sudo $(basename "${0}") regen-boot
EOF
}

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "${1}"; }
die()  { printf 'ERROR: %s\n' "${1}" >&2; exit 1; }

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "must be run as root"
}

# ─── restore-header ───────────────────────────────────────────────────────────

cmd_restore_header() {
    local device="${1:-}" backup="${2:-}"
    [[ -n "${device}" && -n "${backup}" ]] || { usage; exit 1; }
    [[ -b "${device}" ]] || die "not a block device: ${device}"
    [[ -f "${backup}" ]] || die "backup not found: ${backup}"

    local workdir img
    workdir="$(mktemp -d /dev/shm/luks-recovery.XXXXXX)"
    trap 'rm -rf "${workdir}"' EXIT
    img="${workdir}/header.img"

    # Decrypt if GPG-wrapped
    if [[ "${backup}" == *.gpg ]]; then
        log "decrypting ${backup} (enter the header backup passphrase)"
        gpg --decrypt --output "${img}" "${backup}" || die "GPG decryption failed"
        # Verify against the checksum of the original plaintext image if present
        local sums="${backup%.gpg}.sha512"
        if [[ -f "${sums}" ]]; then
            ( cd "${workdir}" && sha512sum -c <(awk -v f="header.img" '{print $1"  "f}' "${sums}") ) \
                || die "SHA-512 verification FAILED — backup may be corrupt"
            log "SHA-512 checksum verified"
        else
            log "WARNING: no .sha512 sidecar found — skipping integrity verification"
        fi
    else
        cp "${backup}" "${img}"
        if [[ -f "${backup}.sha512" ]]; then
            sha512sum -c <(awk -v f="${img}" '{print $1"  "f}' "${backup}.sha512") \
                || die "SHA-512 verification FAILED — backup may be corrupt"
            log "SHA-512 checksum verified"
        fi
    fi

    cryptsetup luksDump --header "${img}" /dev/null &>/dev/null \
        || cryptsetup isLuks "${img}" 2>/dev/null \
        || log "WARNING: could not pre-validate the header image"

    printf '\n!!! This OVERWRITES the LUKS header on %s.\n' "${device}"
    printf '!!! A wrong header makes ALL data permanently unreadable.\n'
    printf 'Type the device path (%s) to confirm: ' "${device}"
    local confirm
    read -r confirm
    [[ "${confirm}" == "${device}" ]] || die "confirmation mismatch — aborted"

    cryptsetup luksHeaderRestore "${device}" --header-backup-file "${img}" --batch-mode \
        || die "luksHeaderRestore failed"
    log "header restored to ${device}"
    log "verify now with: cryptsetup open --test-passphrase ${device}"
}

# ─── add-temp-key ─────────────────────────────────────────────────────────────

cmd_add_temp_key() {
    local device="${1:-}"
    [[ -n "${device}" ]] || { usage; exit 1; }
    [[ -b "${device}" ]] || die "not a block device: ${device}"
    cryptsetup isLuks "${device}" || die "${device} is not a LUKS device"

    local before after slot
    before="$(cryptsetup luksDump "${device}" \
        | awk '/^Keyslots:/{ks=1; next} /^[A-Z]/{ks=0} ks && /^  [0-9]+: luks/{gsub(":","",$1); print $1}')"

    log "adding a temporary recovery passphrase (you will be prompted for an EXISTING secret first)"
    cryptsetup luksAddKey "${device}" || die "luksAddKey failed"

    after="$(cryptsetup luksDump "${device}" \
        | awk '/^Keyslots:/{ks=1; next} /^[A-Z]/{ks=0} ks && /^  [0-9]+: luks/{gsub(":","",$1); print $1}')"
    slot="$(comm -13 <(sort <<< "${before}") <(sort <<< "${after}") | head -1)"

    log "temporary passphrase added in key slot ${slot:-unknown}"
    log "REMOVE IT after recovery:  cryptsetup luksKillSlot ${device} ${slot:-<slot>}"
}

# ─── regen-boot ───────────────────────────────────────────────────────────────

cmd_regen_boot() {
    [[ -d /boot && -w /boot ]] || die "/boot is not writable — mount it (and /boot/efi) first"

    # Never bake a broken crypttab into the initramfs
    log "validating /etc/crypttab"
    (
        RUN_MODE=audit VERBOSE=false LOG_FILE=/dev/null
        AUDIT_FINDINGS=0
        # shellcheck source=../lib/common.sh
        source "${PARENT_DIR}/lib/common.sh"
        # shellcheck source=../modules/luks.d/common.sh
        source "${PARENT_DIR}/modules/luks.d/common.sh"
        _luks_crypttab_check
    ) || die "/etc/crypttab failed validation — fix it before regenerating the initramfs"

    log "regenerating initramfs"
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u -k all || die "update-initramfs failed"
    elif command -v dracut &>/dev/null; then
        dracut --force --regenerate-all || die "dracut failed"
    else
        die "no initramfs tool found (update-initramfs/dracut)"
    fi

    log "regenerating GRUB configuration"
    if command -v update-grub &>/dev/null; then
        update-grub || die "update-grub failed"
    elif command -v grub2-mkconfig &>/dev/null; then
        grub2-mkconfig -o /boot/grub2/grub.cfg || die "grub2-mkconfig failed"
    elif command -v grub-mkconfig &>/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg || die "grub-mkconfig failed"
    else
        die "no GRUB config generator found"
    fi

    log "boot environment regenerated — keep a live ISO at hand for the first reboot"
}

# ─── list-backups ─────────────────────────────────────────────────────────────

cmd_list_backups() {
    if [[ ! -d "${HEADER_BACKUP_DIR}" ]]; then
        log "no backup directory at ${HEADER_BACKUP_DIR}"
        return 0
    fi
    find "${HEADER_BACKUP_DIR}" -maxdepth 1 -name '*.header.img*' ! -name '*.sha512' \
        -printf '%TY-%Tm-%Td %TH:%TM  %s bytes  %p\n' 2>/dev/null | sort
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    local cmd="${1:-}"
    case "${cmd}" in
        restore-header) require_root; shift; cmd_restore_header "$@" ;;
        add-temp-key)   require_root; shift; cmd_add_temp_key "$@" ;;
        regen-boot)     require_root; cmd_regen_boot ;;
        list-backups)   cmd_list_backups ;;
        -h|--help|help|"") usage ;;
        *) printf 'ERROR: unknown command: %s\n\n' "${cmd}" >&2; usage; exit 1 ;;
    esac
}

main "$@"
