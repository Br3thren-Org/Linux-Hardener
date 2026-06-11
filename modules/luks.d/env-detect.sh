#!/usr/bin/env bash
# modules/luks.d/env-detect.sh — runtime environment classification for the LUKS module
# Sourced by modules/20_luks.sh after lib/common.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Globals populated by luks_env_detect ────────────────────────────────────

: "${LUKS_ENV_TYPE:=}"          # "bare-metal" | "virtual"
: "${LUKS_ENV_VIRT:=}"          # hypervisor name, "container", or "none"
: "${LUKS_ENV_FIRMWARE:=}"      # "uefi" | "bios"
: "${LUKS_ENV_SECUREBOOT:=}"    # "enabled" | "disabled" | "unknown"
: "${LUKS_ENV_TPM2:=}"          # "yes" | "no"
: "${LUKS_ENV_BOOT_WRITABLE:=}" # "yes" | "no"
: "${LUKS_ENV_ROOT_LUKS:=}"     # "yes" | "no"
: "${LUKS_ENV_ROOT_DEV:=}"      # block device backing /

# DMI strings that indicate a hypervisor when systemd-detect-virt is unavailable
readonly _LUKS_ENV_DMI_VIRT_RE='KVM|QEMU|VMware|VirtualBox|Xen|HVM domU|Virtual Machine|OpenStack|Amazon EC2|Google Compute Engine|Alibaba Cloud|Droplet|Standard PC|Parallels|Bochs|Cloud Server|UpCloud|Hetzner vServer'

# ─── Hypervisor Detection ─────────────────────────────────────────────────────

# _luks_env_detect_virt — sets LUKS_ENV_VIRT and LUKS_ENV_TYPE.
# Precedence: systemd-detect-virt > DMI (dmidecode, /sys) > virt-what.
_luks_env_detect_virt() {
    LUKS_ENV_VIRT="none"

    # 1. systemd-detect-virt — authoritative on systemd hosts
    if command -v systemd-detect-virt &>/dev/null; then
        local virt
        if virt="$(systemd-detect-virt 2>/dev/null)"; then
            LUKS_ENV_VIRT="${virt}"
        else
            # exit != 0 means "none" detected
            LUKS_ENV_VIRT="none"
        fi
        # Distinguish container virtualization explicitly
        if systemd-detect-virt --container --quiet 2>/dev/null; then
            LUKS_ENV_VIRT="container"
        fi
    else
        # 2. DMI product name — dmidecode first, sysfs as unprivileged fallback
        local product=""
        if command -v dmidecode &>/dev/null; then
            product="$(dmidecode -s system-product-name 2>/dev/null || true)"
        fi
        if [[ -z "${product}" && -r /sys/class/dmi/id/product_name ]]; then
            product="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
        fi
        local vendor=""
        if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
            vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)"
        fi
        if [[ "${product} ${vendor}" =~ ${_LUKS_ENV_DMI_VIRT_RE} ]]; then
            LUKS_ENV_VIRT="dmi:${product:-${vendor}}"
        fi

        # 3. virt-what — needs root, last resort
        if [[ "${LUKS_ENV_VIRT}" == "none" ]] && command -v virt-what &>/dev/null; then
            local vw
            vw="$(virt-what 2>/dev/null | head -1 || true)"
            [[ -n "${vw}" ]] && LUKS_ENV_VIRT="${vw}"
        fi

        # Hypervisor CPU flag is a strong hint even without tools
        if [[ "${LUKS_ENV_VIRT}" == "none" ]] && grep -q '^flags.*\bhypervisor\b' /proc/cpuinfo 2>/dev/null; then
            LUKS_ENV_VIRT="unknown-hypervisor"
        fi
    fi

    if [[ "${LUKS_ENV_VIRT}" == "none" ]]; then
        LUKS_ENV_TYPE="bare-metal"
    else
        LUKS_ENV_TYPE="virtual"
    fi
}

# ─── Firmware & Secure Boot ───────────────────────────────────────────────────

_luks_env_detect_firmware() {
    if [[ -d /sys/firmware/efi ]]; then
        LUKS_ENV_FIRMWARE="uefi"
    else
        LUKS_ENV_FIRMWARE="bios"
        LUKS_ENV_SECUREBOOT="disabled"
        return 0
    fi

    LUKS_ENV_SECUREBOOT="unknown"

    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state="$(mokutil --sb-state 2>/dev/null || true)"
        case "${sb_state}" in
            *enabled*)  LUKS_ENV_SECUREBOOT="enabled"  ;;
            *disabled*) LUKS_ENV_SECUREBOOT="disabled" ;;
        esac
    fi

    if [[ "${LUKS_ENV_SECUREBOOT}" == "unknown" ]] && command -v bootctl &>/dev/null; then
        local bc_state
        bc_state="$(bootctl status 2>/dev/null | grep -i 'secure boot' || true)"
        case "${bc_state}" in
            *enabled*)  LUKS_ENV_SECUREBOOT="enabled"  ;;
            *disabled*) LUKS_ENV_SECUREBOOT="disabled" ;;
        esac
    fi

    # Raw efivar: byte 5 of SecureBoot-<guid> is 1 when enabled
    if [[ "${LUKS_ENV_SECUREBOOT}" == "unknown" ]]; then
        local efivar
        for efivar in /sys/firmware/efi/efivars/SecureBoot-*; do
            [[ -r "${efivar}" ]] || continue
            local byte
            byte="$(od -An -tu1 -j4 -N1 "${efivar}" 2>/dev/null | tr -d ' ')"
            case "${byte}" in
                1) LUKS_ENV_SECUREBOOT="enabled"  ;;
                0) LUKS_ENV_SECUREBOOT="disabled" ;;
            esac
            break
        done
    fi
}

# ─── TPM2 ─────────────────────────────────────────────────────────────────────

_luks_env_detect_tpm2() {
    LUKS_ENV_TPM2="no"

    if [[ ! -c /dev/tpmrm0 && ! -c /dev/tpm0 ]]; then
        return 0
    fi

    # Device node exists; verify it answers if tooling is available
    if command -v tpm2_getcap &>/dev/null; then
        if tpm2_getcap properties-fixed &>/dev/null; then
            LUKS_ENV_TPM2="yes"
        fi
    else
        # No tooling to disprove it — trust the device node
        LUKS_ENV_TPM2="yes"
    fi
}

# ─── Boot / Initramfs Accessibility ──────────────────────────────────────────

# Can we safely modify /boot and regenerate the initramfs and GRUB config?
_luks_env_detect_boot_access() {
    LUKS_ENV_BOOT_WRITABLE="no"

    [[ -d /boot && -w /boot ]] || return 0

    # Need an initramfs regeneration tool
    if ! command -v update-initramfs &>/dev/null && ! command -v dracut &>/dev/null; then
        return 0
    fi

    # Need a GRUB config generator (BIOS or UEFI GRUB)
    if ! command -v grub-mkconfig &>/dev/null && ! command -v grub2-mkconfig &>/dev/null; then
        return 0
    fi

    LUKS_ENV_BOOT_WRITABLE="yes"
}

# ─── Root Device LUKS Status ──────────────────────────────────────────────────

# _luks_env_detect_root_luks — walks the device chain under / looking for a
# dm-crypt layer. Sets LUKS_ENV_ROOT_LUKS and LUKS_ENV_ROOT_DEV.
_luks_env_detect_root_luks() {
    LUKS_ENV_ROOT_LUKS="no"
    LUKS_ENV_ROOT_DEV=""

    local root_src
    root_src="$(findmnt -no SOURCE / 2>/dev/null || true)"
    [[ -n "${root_src}" ]] || return 0
    # Strip btrfs subvolume suffixes like /dev/sda2[/root]
    root_src="${root_src%%\[*}"
    LUKS_ENV_ROOT_DEV="${root_src}"

    [[ -b "${root_src}" ]] || return 0

    # Inspect the root device and every ancestor for a crypt layer
    local types
    types="$(lsblk -sno TYPE "${root_src}" 2>/dev/null || true)"
    if grep -qw 'crypt' <<< "${types}"; then
        LUKS_ENV_ROOT_LUKS="yes"
    fi
}

# ─── Orchestrator ─────────────────────────────────────────────────────────────

# luks_env_detect — classify the host. Honours LUKS_MODE override for the
# bare-metal/virtual decision; hardware probes always run.
luks_env_detect() {
    _luks_env_detect_virt
    _luks_env_detect_firmware
    _luks_env_detect_tpm2
    _luks_env_detect_boot_access
    _luks_env_detect_root_luks

    case "${LUKS_MODE:-auto}" in
        bare-metal|baremetal)
            LUKS_ENV_TYPE="bare-metal"
            log_info "luks_env: type forced to bare-metal via LUKS_MODE"
            ;;
        virtual|vps)
            LUKS_ENV_TYPE="virtual"
            log_info "luks_env: type forced to virtual via LUKS_MODE"
            ;;
        auto|*)
            : # keep detected value
            ;;
    esac

    log_info "luks_env: type=${LUKS_ENV_TYPE} virt=${LUKS_ENV_VIRT} firmware=${LUKS_ENV_FIRMWARE} secureboot=${LUKS_ENV_SECUREBOOT} tpm2=${LUKS_ENV_TPM2} boot_writable=${LUKS_ENV_BOOT_WRITABLE} root_luks=${LUKS_ENV_ROOT_LUKS}"
    return 0
}
