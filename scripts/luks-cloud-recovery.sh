#!/usr/bin/env bash
# scripts/luks-cloud-recovery.sh — VPS LUKS recovery toolkit
# Re-mounts loopback/data volumes when KMS or automation is unavailable and
# prints provider console recovery guidance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

STATE_FILE="/var/lib/linux-hardener/luks-state"
LUKS_CONF="${PARENT_DIR}/config/luks.conf"

usage() {
    cat <<EOF
Usage: $(basename "${0}") <command>

Commands:
  remount       Re-attach and mount every encrypted volume recorded by the
                hardener. Tries, in order: the local keyfile in /etc/luks/,
                cloud-KMS retrieval (if configured), then an interactive
                passphrase prompt.
  status        Show the state of all hardener-managed encrypted volumes.
  instructions  Print step-by-step provider console/VNC recovery guidance.

Examples:
  sudo $(basename "${0}") status
  sudo $(basename "${0}") remount
EOF
}

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "${1}"; }
die() { printf 'ERROR: %s\n' "${1}" >&2; exit 1; }

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "must be run as root"
}

load_conf() {
    # shellcheck source=../config/luks.conf
    [[ -f "${LUKS_CONF}" ]] && source "${LUKS_CONF}"
    # KMS helpers (used best-effort; they need the same config)
    if [[ -f "${PARENT_DIR}/modules/luks.d/kms.sh" ]]; then
        log_info()    { log "${1}"; }
        log_warn()    { log "WARN: ${1}"; }
        log_error()   { log "ERROR: ${1}"; }
        log_debug()   { :; }
        log_success() { log "${1}"; }
        should_write() { return 0; }
        pkg_install() { return 1; }
        _luks_state_entries() {
            [[ -f "${STATE_FILE}" ]] || return 0
            grep "^${1}|" "${STATE_FILE}" 2>/dev/null || true
        }
        # shellcheck source=../modules/luks.d/kms.sh
        source "${PARENT_DIR}/modules/luks.d/kms.sh"
    fi
}

# ─── Unlock helpers ───────────────────────────────────────────────────────────

# open_volume <source> <name> <keyfile>
# Source may be a block device or a container file (loop-attached here).
# Key resolution order: local keyfile -> KMS retrieval -> passphrase prompt.
open_volume() {
    local src="${1}" name="${2}" keyfile="${3}"

    if cryptsetup status "${name}" &>/dev/null; then
        log "${name}: already open"
        return 0
    fi

    local dev="${src}"
    if [[ -f "${src}" && ! -b "${src}" ]]; then
        dev="$(losetup --find --show "${src}")" || die "losetup failed for ${src}"
        log "${name}: container attached at ${dev}"
    fi

    # 1. Local keyfile
    if [[ -f "${keyfile}" ]]; then
        if cryptsetup open --key-file "${keyfile}" "${dev}" "${name}" 2>/dev/null; then
            log "${name}: opened with local keyfile"
            return 0
        fi
        log "${name}: local keyfile did not unlock the volume"
    else
        log "${name}: local keyfile missing (${keyfile})"
    fi

    # 2. Cloud KMS escrow
    if [[ "${LUKS_CLOUD_KMS_PROVIDER:-none}" != "none" ]] && declare -f _luks_kms_retrieve &>/dev/null; then
        log "${name}: attempting key retrieval from ${LUKS_CLOUD_KMS_PROVIDER} KMS"
        local tmpkey
        tmpkey="$(mktemp /dev/shm/luks-key.XXXXXX)"
        if _luks_kms_retrieve "${name}" "${tmpkey}"; then
            if cryptsetup open --key-file "${tmpkey}" "${dev}" "${name}" 2>/dev/null; then
                shred -u "${tmpkey}" 2>/dev/null || rm -f "${tmpkey}"
                log "${name}: opened with KMS-escrowed key"
                return 0
            fi
        fi
        shred -u "${tmpkey}" 2>/dev/null || rm -f "${tmpkey}"
        log "${name}: KMS retrieval failed or key rejected"
    fi

    # 3. Interactive passphrase. Read from the terminal explicitly: this
    # function runs inside `while read < state-file` loops — with inherited
    # stdin cryptsetup would consume the remaining state entries as the
    # "passphrase" and the loop would end early.
    if [[ ! -r /dev/tty ]]; then
        log "ERROR: ${name}: no keyfile/KMS and no terminal for a passphrase prompt"
        return 1
    fi
    log "${name}: falling back to interactive passphrase"
    if cryptsetup open "${dev}" "${name}" < /dev/tty; then
        log "${name}: opened with passphrase"
        return 0
    fi

    log "ERROR: could not unlock ${name}"
    return 1
}

# ─── remount ──────────────────────────────────────────────────────────────────

cmd_remount() {
    [[ -f "${STATE_FILE}" ]] || die "no hardener LUKS state at ${STATE_FILE} — nothing to remount"

    local failed=0
    local kind name src mnt keyfile
    while IFS='|' read -r kind name src mnt keyfile; do
        case "${kind}" in
            volume|container) : ;;
            *) continue ;;
        esac
        log "── ${name} (${src}) -> ${mnt}"
        if ! open_volume "${src}" "${name}" "${keyfile}"; then
            (( failed++ )) || true
            continue
        fi
        mkdir -p "${mnt}"
        if mountpoint -q "${mnt}"; then
            log "${name}: ${mnt} already mounted"
        elif mount "/dev/mapper/${name}" "${mnt}"; then
            log "${name}: mounted at ${mnt}"
        else
            log "ERROR: mount failed for ${name} at ${mnt}"
            (( failed++ )) || true
        fi
    done < "${STATE_FILE}"

    # Restore bind mounts that depend on the data filesystem
    while IFS='|' read -r kind dir target; do
        [[ "${kind}" == "bind" ]] || continue
        if ! mountpoint -q "${dir}" && [[ -d "${target}" ]]; then
            mount --bind "${target}" "${dir}" \
                && log "bind: ${dir} restored" \
                || { log "ERROR: bind mount failed for ${dir}"; (( failed++ )) || true; }
        fi
    done < "${STATE_FILE}"

    if [[ ${failed} -gt 0 ]]; then
        die "${failed} volume(s) could not be recovered — see 'instructions' for console recovery"
    fi
    log "all recorded volumes recovered"
}

# ─── status ───────────────────────────────────────────────────────────────────

cmd_status() {
    if [[ ! -f "${STATE_FILE}" ]]; then
        log "no hardener LUKS state at ${STATE_FILE}"
        return 0
    fi
    printf '%-12s %-12s %-35s %s\n' "KIND" "NAME" "SOURCE" "STATE"
    local kind name src mnt _
    while IFS='|' read -r kind name src mnt _; do
        case "${kind}" in
            volume|container)
                local state="closed"
                if cryptsetup status "${name}" &>/dev/null; then
                    state="open"
                    mountpoint -q "${mnt}" 2>/dev/null && state="open+mounted"
                fi
                printf '%-12s %-12s %-35s %s\n' "${kind}" "${name}" "${src}" "${state}"
                ;;
            cryptswap)
                local state="inactive"
                # swapon reports the resolved /dev/dm-N node — compare real paths
                if [[ -e /dev/mapper/cryptswap ]] && swapon --show=NAME --noheadings 2>/dev/null \
                        | grep -qx "$(readlink -f /dev/mapper/cryptswap)"; then
                    state="active"
                fi
                printf '%-12s %-12s %-35s %s\n' "swap" "cryptswap" "${name}" "${state}"
                ;;
        esac
    done < "${STATE_FILE}"
}

# ─── instructions ─────────────────────────────────────────────────────────────

cmd_instructions() {
    cat <<'EOF'
════════════════════════════════════════════════════════════════════
 VPS LUKS recovery via the provider console
════════════════════════════════════════════════════════════════════

The root filesystem of this VPS is NOT encrypted by the hardener, so
the instance always boots and is always reachable over the provider's
console — encrypted DATA volumes are what need recovery.

1. Open the provider's web console / VNC:
     Hetzner:       Cloud Console -> server -> "Console" (top right)
     DigitalOcean:  Droplet -> Access -> "Launch Droplet Console"
     AWS EC2:       Instance -> Connect -> "EC2 serial console"
     GCP:           Instance -> "Connect to serial console"
     Vultr/Linode/OVH/Ionos: server view -> Console/VNC/KVM button

2. Log in as root (or your sudo user) on the console.

3. Inspect what the hardener manages:
     sudo scripts/luks-cloud-recovery.sh status

4. Recover the volumes:
     sudo scripts/luks-cloud-recovery.sh remount
   You will be prompted for the volume passphrase if both the local
   keyfile (/etc/luks/*.key) and the cloud KMS are unavailable.

5. If a keyfile was lost but you have a GPG header backup:
     ls /var/backups/luks-headers/
     # restore with scripts/luks-recovery.sh restore-header (same tool
     # works for data volumes on VPSs)

6. If the instance does not boot at all, the cause is NOT this module
   (it never touches the root disk, bootloader, or initramfs on a
   VPS). Use the provider's rescue system and check recent changes to
   /etc/fstab — all hardener entries carry "nofail" and cannot hang
   boot by themselves.

Key locations:
  /etc/luks/*.key                    local keyfiles (mode 0400)
  /var/backups/luks-headers/         GPG-encrypted header backups
  /var/lib/linux-hardener/luks-state what the hardener created
════════════════════════════════════════════════════════════════════
EOF
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    local cmd="${1:-}"
    case "${cmd}" in
        remount)      require_root; load_conf; cmd_remount ;;
        status)       require_root; load_conf; cmd_status ;;
        instructions) cmd_instructions ;;
        -h|--help|help|"") usage ;;
        *) printf 'ERROR: unknown command: %s\n\n' "${cmd}" >&2; usage; exit 1 ;;
    esac
}

main "$@"
