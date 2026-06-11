#!/usr/bin/env bash
# modules/luks.d/common.sh — shared helpers for the runtime LUKS module
# Sourced by modules/20_luks.sh after lib/common.sh and env-detect.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Paths & State ────────────────────────────────────────────────────────────

readonly LUKS_KEY_DIR="/etc/luks"
readonly LUKS_STATE_FILE="${HARDENER_STATE_DIR}/luks-state"
readonly LUKS_CRYPTTAB="/etc/crypttab"

# Selected at apply time by _luks_benchmark_cipher
: "${LUKS_SELECTED_CIPHER:=aes-xts-plain64}"

# _luks_state_record <kind> <detail...>
# Append a record of something we created, for rollback and recovery.
# Format: kind|field1|field2|...
_luks_state_record() {
    mkdir -p "$(dirname "${LUKS_STATE_FILE}")"
    local IFS='|'
    printf '%s\n' "$*" >> "${LUKS_STATE_FILE}"
}

# _luks_state_entries <kind> — print recorded entries of one kind
_luks_state_entries() {
    local kind="${1}"
    [[ -f "${LUKS_STATE_FILE}" ]] || return 0
    grep "^${kind}|" "${LUKS_STATE_FILE}" 2>/dev/null || true
}

# ─── Tooling ──────────────────────────────────────────────────────────────────

_luks_require_tools() {
    local missing=()
    command -v cryptsetup &>/dev/null || missing+=(cryptsetup)
    command -v gpg        &>/dev/null || missing+=(gnupg2)
    if ! command -v pwgen &>/dev/null && ! command -v openssl &>/dev/null; then
        missing+=(pwgen)
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would install: ${missing[*]}"
        return 0
    fi

    log_info "luks: installing required tools: ${missing[*]}"
    pkg_install "${missing[@]}" || {
        log_error "luks: failed to install required tools: ${missing[*]}"
        return 1
    }
}

# ─── Entropy ──────────────────────────────────────────────────────────────────

# _luks_entropy_ready — ensure the CRNG is usable before key generation.
# Kernels >= 5.6 expose a fully-seeded getrandom() pool and pin
# entropy_avail at 256, so the legacy >3000 threshold only applies to
# older kernels; there we install haveged/rng-tools and wait.
_luks_entropy_ready() {
    local kver kmajor kminor
    kver="$(uname -r)"
    kmajor="${kver%%.*}"
    kminor="${kver#*.}"; kminor="${kminor%%.*}"

    if [[ "${kmajor}" -gt 5 || ( "${kmajor}" -eq 5 && "${kminor}" -ge 6 ) ]]; then
        log_debug "luks: kernel ${kver} >= 5.6 — CRNG always seeded"
        return 0
    fi

    local avail
    avail="$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)"
    if [[ "${avail}" -gt 3000 ]]; then
        return 0
    fi

    log_warn "luks: entropy_avail=${avail} (<3000) — installing entropy daemon"
    if ! should_write; then
        log_info "[DRY-RUN] Would install haveged and wait for entropy > 3000"
        return 0
    fi

    pkg_install haveged 2>/dev/null || pkg_install rng-tools 2>/dev/null || {
        log_error "luks: could not install an entropy daemon"
        return 1
    }
    systemctl enable --now haveged 2>/dev/null || systemctl enable --now rngd 2>/dev/null || true

    local i
    for i in $(seq 1 60); do
        avail="$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)"
        [[ "${avail}" -gt 3000 ]] && return 0
        sleep 1
    done

    log_error "luks: entropy still ${avail} after 60s — refusing to generate keys"
    return 1
}

# ─── Cipher Benchmark ─────────────────────────────────────────────────────────

# _luks_benchmark_cipher — pick the fastest cipher for this CPU.
# Sets LUKS_SELECTED_CIPHER. aes-xts-plain64 wins ties (AES-NI hardware);
# xchacha20/adiantum wins on CPUs without AES acceleration.
_luks_benchmark_cipher() {
    if [[ "${LUKS_CIPHER:-auto}" != "auto" ]]; then
        LUKS_SELECTED_CIPHER="${LUKS_CIPHER}"
        log_info "luks: cipher fixed by config: ${LUKS_SELECTED_CIPHER}"
        return 0
    fi

    local bench
    bench="$(cryptsetup benchmark 2>/dev/null || true)"
    if [[ -z "${bench}" ]]; then
        LUKS_SELECTED_CIPHER="aes-xts-plain64"
        log_warn "luks: cryptsetup benchmark failed — defaulting to ${LUKS_SELECTED_CIPHER}"
        return 0
    fi

    # Parse encryption MiB/s for 512b XTS variants and adiantum
    local aes serpent adiantum
    aes="$(awk '$1=="aes-xts" && $2=="512b" {gsub(",",".",$3); print int($3); exit}' <<< "${bench}")"
    serpent="$(awk '$1=="serpent-xts" && $2=="512b" {gsub(",",".",$3); print int($3); exit}' <<< "${bench}")"
    adiantum="$(awk '$1=="xchacha20,aes-adiantum" {gsub(",",".",$3); print int($3); exit}' <<< "${bench}")"
    aes="${aes:-0}"; serpent="${serpent:-0}"; adiantum="${adiantum:-0}"

    log_info "luks: benchmark MiB/s — aes-xts:${aes} serpent-xts:${serpent} adiantum:${adiantum}"

    LUKS_SELECTED_CIPHER="aes-xts-plain64"
    local best="${aes}"
    if [[ "${serpent}" -gt "${best}" ]]; then
        LUKS_SELECTED_CIPHER="serpent-xts-plain64"
        best="${serpent}"
    fi
    if [[ "${adiantum}" -gt "${best}" ]]; then
        LUKS_SELECTED_CIPHER="xchacha20,aes-adiantum-plain64"
    fi
    log_info "luks: selected cipher: ${LUKS_SELECTED_CIPHER}"
}

# ─── Key Material ─────────────────────────────────────────────────────────────

# _luks_gen_passphrase — print a 64-char high-entropy passphrase
_luks_gen_passphrase() {
    if command -v pwgen &>/dev/null; then
        pwgen -s 64 1
    elif command -v openssl &>/dev/null; then
        openssl rand -base64 64 | tr -d '\n=+/' | cut -c1-64
    else
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64
        printf '\n'
    fi
}

# _luks_gen_keyfile <path> — 512 bytes of random key material, mode 0400
_luks_gen_keyfile() {
    local path="${1}"
    mkdir -p "$(dirname "${path}")"
    chmod 0700 "$(dirname "${path}")"
    ( umask 277; dd if=/dev/urandom of="${path}" bs=512 count=1 status=none )
    chmod 0400 "${path}"
}

# ─── Format ───────────────────────────────────────────────────────────────────

# _luks_format <device> <keyfile>
# luksFormat with the configured cipher / key size / argon2id parameters.
_luks_format() {
    local device="${1}"
    local keyfile="${2}"

    cryptsetup luksFormat \
        --batch-mode \
        --type luks2 \
        --cipher "${LUKS_SELECTED_CIPHER}" \
        --key-size "${LUKS_KEY_SIZE:-512}" \
        --pbkdf "${LUKS_PBKDF:-argon2id}" \
        --pbkdf-memory "${LUKS_PBKDF_MEMORY:-1048576}" \
        --pbkdf-force-iterations "${LUKS_PBKDF_ITERATIONS:-4}" \
        --pbkdf-parallel "${LUKS_PBKDF_PARALLEL:-4}" \
        --key-file "${keyfile}" \
        "${device}"
}

# ─── Header Backup ────────────────────────────────────────────────────────────

# _luks_backup_header <device> <name> <passphrase-or-keyfile>
# Backs up the LUKS header, generates a SHA-512 checksum, encrypts the backup
# with GPG (AES256 symmetric, keyed with the volume secret) and replicates to
# the optional secondary location. The plaintext header image is shredded.
_luks_backup_header() {
    local device="${1}"
    local name="${2}"
    local secret="${3}"   # path to keyfile, or literal passphrase

    local dir="${LUKS_HEADER_BACKUP_DIR:-/var/backups/luks-headers}"
    mkdir -p "${dir}"
    chmod 0700 "${dir}"

    local ts img
    ts="$(date +%Y%m%d_%H%M%S)"
    img="${dir}/${name}-${ts}.header.img"

    cryptsetup luksHeaderBackup "${device}" --header-backup-file "${img}" || {
        log_error "luks: header backup failed for ${device}"
        return 1
    }
    chmod 0600 "${img}"

    sha512sum "${img}" > "${img}.sha512"

    # Symmetric GPG encryption keyed with the volume secret
    local pass
    if [[ -f "${secret}" ]]; then
        pass="$(od -An -tx1 "${secret}" | tr -d ' \n')"
    else
        pass="${secret}"
    fi
    if printf '%s' "${pass}" | gpg --batch --yes --symmetric \
            --cipher-algo AES256 --passphrase-fd 0 \
            --output "${img}.gpg" "${img}" 2>/dev/null; then
        shred -u "${img}" 2>/dev/null || rm -f "${img}"
        chmod 0600 "${img}.gpg"
        log_success "luks: header backup written: ${img}.gpg"
    else
        log_warn "luks: GPG encryption of header backup failed — keeping plaintext ${img} (mode 0600)"
    fi

    # Secondary replication: s3:// URI or a mounted path (e.g. USB)
    local secondary="${LUKS_HEADER_BACKUP_SECONDARY:-}"
    if [[ -n "${secondary}" ]]; then
        local artifact="${img}.gpg"
        [[ -f "${artifact}" ]] || artifact="${img}"
        case "${secondary}" in
            s3://*)
                if command -v aws &>/dev/null; then
                    aws s3 cp "${artifact}" "${secondary%/}/$(basename "${artifact}")" 2>/dev/null \
                        && aws s3 cp "${img}.sha512" "${secondary%/}/$(basename "${img}.sha512")" 2>/dev/null \
                        || log_warn "luks: secondary header upload to ${secondary} failed"
                else
                    log_warn "luks: LUKS_HEADER_BACKUP_SECONDARY is s3:// but aws CLI is missing"
                fi
                ;;
            *)
                if [[ -d "${secondary}" ]]; then
                    cp "${artifact}" "${img}.sha512" "${secondary}/" 2>/dev/null \
                        || log_warn "luks: secondary header copy to ${secondary} failed"
                else
                    log_warn "luks: secondary backup location not mounted: ${secondary}"
                fi
                ;;
        esac
    fi

    _luks_state_record "header-backup" "${device}" "${img}.gpg"
    return 0
}

# ─── Key Slot Policy ──────────────────────────────────────────────────────────

# _luks_slot_count <device> — print the number of active key slots
_luks_slot_count() {
    local device="${1}"
    cryptsetup luksDump "${device}" 2>/dev/null \
        | awk '/^Keyslots:/{ks=1; next} /^[A-Z]/{ks=0} ks && /^  [0-9]+: luks2/{n++} END{print n+0}'
}

# _luks_slot_audit <device>
# Policy: at most 2 active slots (primary passphrase + keyfile/recovery).
# We only ever *report* on volumes we did not create — killing slots we cannot
# verify could destroy the only working unlock path.
_luks_slot_audit() {
    local device="${1}"
    local count
    count="$(_luks_slot_count "${device}")"
    if [[ "${count}" -gt 2 ]]; then
        log_warn "FINDING: ${device} has ${count} active key slots (policy: max 2 — primary + recovery)"
        (( AUDIT_FINDINGS++ )) || true
        return 1
    fi
    log_debug "luks: ${device} key slots: ${count} (OK)"
    return 0
}

# ─── Performance Flags ────────────────────────────────────────────────────────

# _luks_dev_rotational <device> — 0 if the backing disk is rotational
_luks_dev_rotational() {
    local device="${1}"
    local disk rot
    disk="$(lsblk -sno NAME,TYPE "${device}" 2>/dev/null | awk '$2=="disk"{print $1; exit}')"
    [[ -n "${disk}" ]] || return 1
    rot="$(cat "/sys/block/${disk}/queue/rotational" 2>/dev/null || echo 1)"
    [[ "${rot}" == "1" ]]
}

# _luks_workqueue_opts <device>
# Print the crypttab performance options appropriate for the backing disk:
# queue bypass for SSD/NVMe, nothing for rotational disks.
_luks_workqueue_opts() {
    local device="${1}"
    if _luks_dev_rotational "${device}"; then
        printf ''
    else
        printf 'no-read-workqueue,no-write-workqueue'
    fi
}

# _luks_apply_workqueue_flags <device> <mapper-name> <keyfile>
# Persist the queue-bypass flags into the LUKS2 header for open mappings.
_luks_apply_workqueue_flags() {
    local device="${1}"
    local name="${2}"
    local keyfile="${3}"

    if _luks_dev_rotational "${device}"; then
        log_debug "luks: ${device} is rotational — keeping default workqueues"
        return 0
    fi

    cryptsetup refresh \
        --persistent \
        --perf-no_read_workqueue \
        --perf-no_write_workqueue \
        --key-file "${keyfile}" \
        "${name}" 2>/dev/null \
        && log_info "luks: persisted no-read/write-workqueue flags on ${name}" \
        || log_warn "luks: could not persist workqueue flags on ${name} (older cryptsetup?)"
}

# ─── crypttab Validation ──────────────────────────────────────────────────────

# Options this module knows are valid in /etc/crypttab (superset of what we
# write; used for syntax sanity, not strict enforcement).
readonly _LUKS_CRYPTTAB_OPT_RE='^(luks|plain|swap|tmp|discard|noauto|nofail|readonly|read-only|tries=[0-9]+|timeout=[0-9a-z]+|x-systemd\..+|tpm2-device=.+|tpm2-pcrs=.+|fido2-device=.+|keyfile-size=[0-9]+|keyfile-offset=[0-9]+|key-slot=[0-9]+|cipher=.+|size=[0-9]+|hash=.+|offset=[0-9]+|skip=[0-9]+|sector-size=[0-9]+|same-cpu-crypt|submit-from-crypt-cpus|no-read-workqueue|no-write-workqueue|initramfs|keyscript=.+|header=.+|loud|quiet)$'

# _luks_crypttab_check [file]
# Validate a crypttab. Returns 0 if every entry is sound, 1 otherwise,
# logging each problem with its line number.
_luks_crypttab_check() {
    local file="${1:-${LUKS_CRYPTTAB}}"
    [[ -f "${file}" ]] || { log_debug "luks: ${file} does not exist"; return 0; }
    [[ -r "${file}" ]] || { log_warn "luks: ${file} not readable (need root) — validation skipped"; return 0; }

    local rc=0 lineno=0
    local name src key opts extra
    while read -r name src key opts extra; do
        (( lineno++ )) || true
        [[ -z "${name}" || "${name}" == \#* ]] && continue

        if [[ -n "${extra}" ]]; then
            log_error "luks: crypttab:${lineno}: too many fields"
            rc=1
            continue
        fi

        if [[ ! "${name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
            log_error "luks: crypttab:${lineno}: invalid mapping name '${name}'"
            rc=1
        fi

        if [[ -z "${src}" ]]; then
            log_error "luks: crypttab:${lineno}: missing source device"
            rc=1
        else
            case "${src}" in
                UUID=*)
                    if command -v blkid &>/dev/null && ! blkid -U "${src#UUID=}" &>/dev/null; then
                        log_error "luks: crypttab:${lineno}: UUID does not resolve: ${src}"
                        rc=1
                    fi
                    ;;
                /dev/*|/var/*|/srv/*|/*.img)
                    # Loop-backed sources are files; block sources must exist.
                    if [[ ! -e "${src}" ]]; then
                        log_error "luks: crypttab:${lineno}: source does not exist: ${src}"
                        rc=1
                    fi
                    ;;
            esac
        fi

        case "${key:-none}" in
            none|-|/dev/urandom|/dev/random) : ;;
            /*)
                if [[ ! -f "${key}" ]]; then
                    log_error "luks: crypttab:${lineno}: keyfile missing: ${key}"
                    rc=1
                fi
                ;;
            *)
                log_error "luks: crypttab:${lineno}: unrecognised key field: ${key}"
                rc=1
                ;;
        esac

        if [[ -n "${opts:-}" ]]; then
            local opt opts_arr
            IFS=',' read -ra opts_arr <<< "${opts}"
            for opt in "${opts_arr[@]}"; do
                if [[ ! "${opt}" =~ ${_LUKS_CRYPTTAB_OPT_RE} ]]; then
                    log_warn "luks: crypttab:${lineno}: unknown option '${opt}'"
                fi
            done
        fi
    done < "${file}"

    return "${rc}"
}

# _luks_crypttab_dryrun
# Best-effort boot-parse of the new crypttab in an isolated overlay via
# systemd-nspawn; falls back to our static validator when nspawn is absent.
_luks_crypttab_dryrun() {
    if command -v systemd-nspawn &>/dev/null; then
        if systemd-nspawn --quiet --volatile=overlay --directory=/ \
                --bind-ro="${LUKS_CRYPTTAB}":/etc/crypttab \
                /usr/lib/systemd/system-generators/systemd-cryptsetup-generator \
                /tmp/cryptgen.out /tmp/cryptgen.out /tmp/cryptgen.out \
                &>/dev/null; then
            log_debug "luks: crypttab generator dry-run OK (nspawn overlay)"
            return 0
        fi
        log_warn "luks: systemd-cryptsetup-generator dry-run reported a problem"
        return 1
    fi
    log_debug "luks: systemd-nspawn unavailable — static crypttab validation only"
    return 0
}

# _luks_crypttab_add <name> <src> <key> <opts>
# Backup, append (idempotent), validate; restore the previous crypttab if
# validation fails so a broken entry can never persist.
_luks_crypttab_add() {
    local name="${1}" src="${2}" key="${3}" opts="${4}"

    touch "${LUKS_CRYPTTAB}"
    chmod 0600 "${LUKS_CRYPTTAB}"

    if awk -v n="${name}" '$1==n{found=1}END{exit !found}' "${LUKS_CRYPTTAB}" 2>/dev/null; then
        log_debug "luks: crypttab entry '${name}' already present"
        return 0
    fi

    backup_file "${LUKS_CRYPTTAB}"
    local saved
    saved="$(cat "${LUKS_CRYPTTAB}")"

    printf '%s %s %s %s\n' "${name}" "${src}" "${key}" "${opts}" >> "${LUKS_CRYPTTAB}"

    if ! _luks_crypttab_check "${LUKS_CRYPTTAB}" || ! _luks_crypttab_dryrun; then
        printf '%s' "${saved}" > "${LUKS_CRYPTTAB}"
        log_error "luks: new crypttab entry '${name}' failed validation — reverted"
        return 1
    fi

    _luks_state_record "crypttab" "${name}"
    log_info "luks: crypttab entry added: ${name}"
    return 0
}

# ─── Target Safety Gate ───────────────────────────────────────────────────────

# _luks_is_safe_target <device>
# The no-break gate. Refuses any device that could take the system down:
#   - hosts / /boot /usr /var (directly or via any child/holder)
#   - is (or backs) active swap
#   - already referenced in fstab or crypttab
#   - carries an existing filesystem/RAID/LVM signature (unless LUKS_FORCE=yes)
#   - is the physical disk backing the root filesystem
_luks_is_safe_target() {
    local device="${1}"

    if [[ ! -b "${device}" ]]; then
        log_error "luks: not a block device: ${device}"
        return 1
    fi

    local real
    real="$(readlink -f "${device}")"

    # Root/boot/usr/var anywhere in the device's subtree (children + the dev itself)
    local mounts
    mounts="$(lsblk -no MOUNTPOINTS "${real}" 2>/dev/null | grep -v '^$' || true)"
    local mp
    while IFS= read -r mp; do
        [[ -z "${mp}" ]] && continue
        case "${mp}" in
            /|/boot|/boot/efi|/usr|/var|/home|\[SWAP\])
                log_error "luks: ${device} (or a partition on it) is mounted at '${mp}' — refusing"
                return 1
                ;;
            *)
                log_error "luks: ${device} has an active mount at '${mp}' — refusing"
                return 1
                ;;
        esac
    done <<< "${mounts}"

    # The disk backing the root filesystem is always off-limits
    local root_disk dev_disk
    root_disk="$(lsblk -sno NAME,TYPE "${LUKS_ENV_ROOT_DEV:-/dev/null}" 2>/dev/null | awk '$2=="disk"{print $1; exit}')"
    dev_disk="$(lsblk -sno NAME,TYPE "${real}" 2>/dev/null | awk '$2=="disk"{print $1; exit}')"
    if [[ -n "${root_disk}" && "${dev_disk}" == "${root_disk}" ]]; then
        log_error "luks: ${device} is on the root disk (/dev/${root_disk}) — refusing"
        return 1
    fi

    # Active swap on the device or any partition of it
    if swapon --show=NAME --noheadings 2>/dev/null | grep -qx "${real}\(p\?[0-9]\+\)\?"; then
        log_error "luks: ${device} is active swap — refusing"
        return 1
    fi

    # Already referenced in fstab or crypttab
    local id
    for id in "${device}" "${real}" "UUID=$(blkid -s UUID -o value "${real}" 2>/dev/null || echo __none__)"; do
        if grep -qsE "(^|[[:space:]])${id}([[:space:]]|$)" /etc/fstab "${LUKS_CRYPTTAB}" 2>/dev/null; then
            log_error "luks: ${device} is referenced in fstab/crypttab — refusing"
            return 1
        fi
    done

    # Existing data signature
    local sigs
    sigs="$(wipefs -n "${real}" 2>/dev/null | tail -n +2 || true)"
    if [[ -n "${sigs}" && "${LUKS_FORCE:-no}" != "yes" ]]; then
        log_error "luks: ${device} carries existing signatures (set LUKS_FORCE=yes to override):"
        while IFS= read -r line; do log_error "luks:   ${line}"; done <<< "${sigs}"
        return 1
    fi

    log_debug "luks: ${device} passed the safety gate"
    return 0
}
