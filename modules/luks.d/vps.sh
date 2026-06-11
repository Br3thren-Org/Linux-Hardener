#!/usr/bin/env bash
# modules/luks.d/vps.sh — VPS / cloud-instance LUKS path
# Data-at-rest encryption WITHOUT touching the root disk, bootloader, or
# initramfs. Sourced by modules/20_luks.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

readonly _LUKS_VPS_HELPER="/usr/local/sbin/luks-mount-data.sh"
readonly _LUKS_VPS_UNIT="/etc/systemd/system/luks-data.service"

# ─── Data Volumes (dedicated block devices) ──────────────────────────────────

# _luks_vps_data_volumes — encrypt every device in LUKS_DATA_DEVICES.
# First volume mounts at LUKS_DATA_PATH, additional ones at LUKS_DATA_PATH<N>.
_luks_vps_data_volumes() {
    [[ -n "${LUKS_DATA_DEVICES:-}" ]] || return 2

    local devices=()
    IFS=',' read -ra devices <<< "${LUKS_DATA_DEVICES}"

    local i=0 device
    for device in "${devices[@]}"; do
        device="$(echo "${device}" | tr -d '[:space:]')"
        [[ -n "${device}" ]] || continue

        local name="enc-data${i}"
        local mountpoint="${LUKS_DATA_PATH}"
        [[ ${i} -gt 0 ]] && mountpoint="${LUKS_DATA_PATH}${i}"

        if cryptsetup status "${name}" &>/dev/null; then
            log_debug "luks-vps: ${name} already mapped — skipping"
            (( CHANGES_SKIPPED++ )) || true
            (( i++ )) || true
            continue
        fi

        if ! _luks_is_safe_target "${device}"; then
            log_error "luks-vps: ${device} failed the safety gate — skipped"
            (( CHANGES_FAILED++ )) || true
            (( i++ )) || true
            continue
        fi

        if ! should_write; then
            log_info "[DRY-RUN] Would LUKS-format ${device} as ${name}, mount at ${mountpoint}"
            (( i++ )) || true
            continue
        fi

        log_change \
            "LUKS2-encrypt ${device} -> /dev/mapper/${name} at ${mountpoint}" \
            "At-rest encryption for data volume" \
            "high" \
            "cryptsetup status ${name}" \
            "umount ${mountpoint}; cryptsetup close ${name}; remove crypttab/fstab entries"

        _luks_encrypt_data_device "${device}" "${name}" "${mountpoint}" || {
            (( CHANGES_FAILED++ )) || true
            (( i++ )) || true
            continue
        }

        (( CHANGES_APPLIED++ )) || true
        (( i++ )) || true
    done
    return 0
}

# _luks_encrypt_data_device <device> <name> <mountpoint>
# Format, open, mkfs, mount, and persist (crypttab + fstab) one data volume.
# Shared by the VPS and bare-metal paths.
_luks_encrypt_data_device() {
    local device="${1}" name="${2}" mountpoint="${3}"

    local keyfile="${LUKS_KEY_DIR}/${name}.key"
    _luks_gen_keyfile "${keyfile}"

    _luks_format "${device}" "${keyfile}" || {
        log_error "luks-vps: luksFormat failed on ${device}"
        return 1
    }

    cryptsetup open --key-file "${keyfile}" "${device}" "${name}" || {
        log_error "luks-vps: failed to open ${device} as ${name}"
        return 1
    }

    mkfs.ext4 -q -L "${name}" "/dev/mapper/${name}" || {
        log_error "luks-vps: mkfs failed on /dev/mapper/${name}"
        cryptsetup close "${name}"
        return 1
    }

    mkdir -p "${mountpoint}"
    chmod 0750 "${mountpoint}"
    mount "/dev/mapper/${name}" "${mountpoint}" || {
        log_error "luks-vps: mount of ${name} at ${mountpoint} failed"
        cryptsetup close "${name}"
        return 1
    }

    # Persist: crypttab (validated, reverts on failure) + fstab with nofail so
    # a failed unlock can never hang boot.
    local uuid wq_opts opts
    uuid="$(blkid -s UUID -o value "${device}")"
    wq_opts="$(_luks_workqueue_opts "${device}")"
    opts="luks,discard,nofail"
    [[ -n "${wq_opts}" ]] && opts="${opts},${wq_opts}"

    _luks_crypttab_add "${name}" "UUID=${uuid}" "${keyfile}" "${opts}" || {
        umount "${mountpoint}" 2>/dev/null
        cryptsetup close "${name}"
        return 1
    }

    backup_file /etc/fstab
    if ! grep -qsE "[[:space:]]${mountpoint}[[:space:]]" /etc/fstab; then
        printf '/dev/mapper/%s  %s  ext4  defaults,nofail,x-systemd.device-timeout=30s  0  2\n' \
            "${name}" "${mountpoint}" >> /etc/fstab
    fi

    _luks_apply_workqueue_flags "${device}" "${name}" "${keyfile}"
    _luks_backup_header "${device}" "${name}" "${keyfile}"
    _luks_kms_escrow "${keyfile}" "${name}" || true
    _luks_state_record "volume" "${name}" "${device}" "${mountpoint}" "${keyfile}"

    log_success "luks-vps: ${device} encrypted and mounted at ${mountpoint}"
    return 0
}

# ─── Loopback Container (no secondary device available) ──────────────────────

# _luks_vps_loop_container — sparse file + loop device + LUKS2, mounted at
# LUKS_DATA_PATH. Persistence is handled by a generated systemd service
# because crypttab loop-source ordering differs across distros.
_luks_vps_loop_container() {
    local container="${LUKS_CONTAINER_FILE}"
    local name="enc-data"
    local keyfile="${LUKS_KEY_DIR}/${name}.key"

    if cryptsetup status "${name}" &>/dev/null; then
        log_debug "luks-vps: loop container already mapped — skipping"
        (( CHANGES_SKIPPED++ )) || true
        return 2
    fi

    if [[ -f "${container}" && "${LUKS_FORCE:-no}" != "yes" ]]; then
        if ! cryptsetup isLuks "${container}" 2>/dev/null; then
            log_error "luks-vps: ${container} exists but is not LUKS — refusing (LUKS_FORCE=yes to override)"
            return 1
        fi
        log_info "luks-vps: existing LUKS container found at ${container} — reusing"
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would create ${LUKS_CONTAINER_SIZE_MB}MB LUKS container at ${container}, mount at ${LUKS_DATA_PATH}"
        return 0
    fi

    # Space check: container size + 10% headroom on the target filesystem
    local avail_mb
    avail_mb="$(df -Pm "$(dirname "${container}")" 2>/dev/null | awk 'NR==2{print $4}')"
    if [[ -n "${avail_mb}" && "${avail_mb}" -lt $(( LUKS_CONTAINER_SIZE_MB + LUKS_CONTAINER_SIZE_MB / 10 )) ]]; then
        log_error "luks-vps: insufficient space for ${LUKS_CONTAINER_SIZE_MB}MB container (only ${avail_mb}MB free)"
        return 1
    fi

    log_change \
        "Create LUKS loopback container ${container} (${LUKS_CONTAINER_SIZE_MB}MB) at ${LUKS_DATA_PATH}" \
        "At-rest encryption for sensitive data without a secondary block device" \
        "medium" \
        "cryptsetup status ${name} && findmnt ${LUKS_DATA_PATH}" \
        "systemctl disable luks-data.service; umount ${LUKS_DATA_PATH}; cryptsetup close ${name}"

    mkdir -p "$(dirname "${container}")"
    chmod 0700 "$(dirname "${container}")"

    if [[ ! -f "${container}" ]]; then
        if ! fallocate -l "${LUKS_CONTAINER_SIZE_MB}M" "${container}" 2>/dev/null; then
            dd if=/dev/zero of="${container}" bs=1M count="${LUKS_CONTAINER_SIZE_MB}" status=none || {
                log_error "luks-vps: could not allocate ${container}"
                return 1
            }
        fi
        chmod 0600 "${container}"
        _luks_gen_keyfile "${keyfile}"
        _luks_format "${container}" "${keyfile}" || {
            log_error "luks-vps: luksFormat failed on ${container}"
            rm -f "${container}"
            return 1
        }
        local fresh=yes
    fi
    [[ -f "${keyfile}" ]] || {
        log_error "luks-vps: keyfile ${keyfile} missing for existing container"
        return 1
    }

    local loopdev
    loopdev="$(losetup --find --show "${container}")" || {
        log_error "luks-vps: losetup failed for ${container}"
        return 1
    }

    cryptsetup open --key-file "${keyfile}" "${loopdev}" "${name}" || {
        log_error "luks-vps: failed to open container as ${name}"
        losetup -d "${loopdev}"
        return 1
    }

    if [[ "${fresh:-no}" == "yes" ]]; then
        mkfs.ext4 -q -L "${name}" "/dev/mapper/${name}" || {
            log_error "luks-vps: mkfs failed on container"
            cryptsetup close "${name}"; losetup -d "${loopdev}"
            return 1
        }
    fi

    mkdir -p "${LUKS_DATA_PATH}"
    chmod 0750 "${LUKS_DATA_PATH}"
    mount "/dev/mapper/${name}" "${LUKS_DATA_PATH}" || {
        log_error "luks-vps: mount at ${LUKS_DATA_PATH} failed"
        cryptsetup close "${name}"; losetup -d "${loopdev}"
        return 1
    }

    _luks_vps_write_mount_unit "${container}" "${name}" "${keyfile}" "${LUKS_DATA_PATH}"
    _luks_backup_header "${container}" "${name}" "${keyfile}"
    _luks_kms_escrow "${keyfile}" "${name}" || true
    _luks_state_record "container" "${name}" "${container}" "${LUKS_DATA_PATH}" "${keyfile}"

    (( CHANGES_APPLIED++ )) || true
    log_success "luks-vps: encrypted container mounted at ${LUKS_DATA_PATH}"
    return 0
}

# _luks_vps_write_mount_unit <container> <name> <keyfile> <mountpoint>
# Generated helper + systemd unit that re-attaches the loop device, opens the
# LUKS mapping, and mounts it on every boot. ExecStart failures do not block
# boot (the unit is not a dependency of any essential target).
_luks_vps_write_mount_unit() {
    local container="${1}" name="${2}" keyfile="${3}" mountpoint="${4}"

    cat > "${_LUKS_VPS_HELPER}" <<EOF
#!/usr/bin/env bash
# Generated by linux-hardener (modules/20_luks.sh) — do not edit by hand.
# Attaches and mounts the LUKS loopback data container.
set -euo pipefail

CONTAINER="${container}"
NAME="${name}"
KEYFILE="${keyfile}"
MOUNTPOINT="${mountpoint}"

case "\${1:-start}" in
    start)
        if ! cryptsetup status "\${NAME}" &>/dev/null; then
            LOOPDEV="\$(losetup --find --show "\${CONTAINER}")"
            cryptsetup open --key-file "\${KEYFILE}" "\${LOOPDEV}" "\${NAME}"
        fi
        mountpoint -q "\${MOUNTPOINT}" || mount "/dev/mapper/\${NAME}" "\${MOUNTPOINT}"
        ;;
    stop)
        mountpoint -q "\${MOUNTPOINT}" && umount "\${MOUNTPOINT}"
        if cryptsetup status "\${NAME}" &>/dev/null; then
            LOOPDEV="\$(cryptsetup status "\${NAME}" | awk '/device:/{print \$2}')"
            cryptsetup close "\${NAME}"
            [[ -n "\${LOOPDEV}" ]] && losetup -d "\${LOOPDEV}" 2>/dev/null || true
        fi
        ;;
esac
EOF
    chmod 0700 "${_LUKS_VPS_HELPER}"

    cat > "${_LUKS_VPS_UNIT}" <<EOF
# Generated by linux-hardener (modules/20_luks.sh) — do not edit by hand.
[Unit]
Description=LUKS encrypted data container (${mountpoint})
DefaultDependencies=no
After=local-fs.target
Before=multi-user.target
ConditionPathExists=${container}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${_LUKS_VPS_HELPER} start
ExecStop=${_LUKS_VPS_HELPER} stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable luks-data.service &>/dev/null
    log_info "luks-vps: persistence unit installed: ${_LUKS_VPS_UNIT}"
}

# ─── Encrypted Swap ───────────────────────────────────────────────────────────

# _luks_vps_swap — replace plaintext swap with dm-crypt swap keyed from
# /dev/urandom on every boot. Uses a dedicated device when configured,
# otherwise a swapfile (loop-attached automatically by systemd-cryptsetup).
_luks_vps_swap() {
    [[ "${LUKS_SWAP_ENCRYPT:-yes}" == "yes" ]] || return 2

    # Already done?
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q '^/dev/\(mapper/\|dm-\)'; then
        log_debug "luks: swap is already encrypted — skipping"
        (( CHANGES_SKIPPED++ )) || true
        return 2
    fi

    local swap_src
    if [[ -n "${LUKS_SWAP_DEVICE:-}" ]]; then
        swap_src="${LUKS_SWAP_DEVICE}"
        if ! _luks_is_safe_target "${swap_src}"; then
            # Allow re-using the device that currently backs plaintext swap:
            # it is "unsafe" only because it is active swap, which we replace.
            local active_swaps
            active_swaps="$(swapon --show=NAME --noheadings 2>/dev/null)"
            if ! grep -qx "$(readlink -f "${swap_src}")" <<< "${active_swaps}"; then
                log_error "luks: swap device ${swap_src} failed the safety gate"
                return 1
            fi
        fi
    else
        swap_src="/var/lib/luks/swapfile"
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would disable plaintext swap and enable dm-crypt swap on ${swap_src}"
        return 0
    fi

    log_change \
        "Encrypted swap on ${swap_src} (random key per boot)" \
        "Prevent secrets in swapped memory from persisting on disk" \
        "medium" \
        "swapon --show | grep /dev/mapper/cryptswap" \
        "Remove cryptswap from crypttab/fstab, restore original swap entries"

    # 1. Retire existing plaintext swap
    local old_swaps
    old_swaps="$(swapon --show=NAME --noheadings 2>/dev/null || true)"
    if [[ -n "${old_swaps}" ]]; then
        backup_file /etc/fstab
        swapoff -a 2>/dev/null || log_warn "luks: swapoff -a failed — continuing"
        # Comment out swap entries rather than deleting them
        sed -i.luks-bak -E 's@^([^#].*[[:space:]]swap[[:space:]].*)@#disabled-by-linux-hardener \1@' /etc/fstab
        rm -f /etc/fstab.luks-bak
        _luks_state_record "plainswap-disabled" "${old_swaps//$'\n'/,}"
        log_info "luks: plaintext swap disabled: ${old_swaps//$'\n'/, }"
    fi

    # 2. Create the swapfile if no dedicated device
    if [[ "${swap_src}" == /var/lib/luks/swapfile ]]; then
        if [[ ! -f "${swap_src}" ]]; then
            mkdir -p "$(dirname "${swap_src}")"
            chmod 0700 "$(dirname "${swap_src}")"
            # Swap cannot live on sparse files — preallocate fully
            dd if=/dev/zero of="${swap_src}" bs=1M count="${LUKS_SWAPFILE_SIZE_MB:-1024}" status=none || {
                log_error "luks: could not allocate swapfile ${swap_src}"
                return 1
            }
            chmod 0600 "${swap_src}"
        fi
    fi

    # 3. crypttab entry: 'swap' option re-formats with a fresh random key each
    #    boot; systemd-cryptsetup loop-attaches file sources automatically.
    _luks_crypttab_add "cryptswap" "${swap_src}" "/dev/urandom" \
        "swap,cipher=aes-xts-plain64,size=512,sector-size=4096" || return 1

    backup_file /etc/fstab
    if ! grep -qsE '^/dev/mapper/cryptswap[[:space:]]' /etc/fstab; then
        printf '/dev/mapper/cryptswap  none  swap  sw,nofail  0  0\n' >> /etc/fstab
    fi

    # 4. Activate now without rebooting. The generator-created unit exists on
    #    every systemd distro (the systemd-cryptsetup binary itself lives
    #    outside PATH on Debian/RHEL, so do not gate on command -v).
    #    restart (not start): a stale "active (exited)" instance from a prior
    #    boot makes start a silent no-op.
    systemctl daemon-reload
    if systemctl restart systemd-cryptsetup@cryptswap.service 2>/dev/null \
            && swapon /dev/mapper/cryptswap 2>/dev/null; then
        log_success "luks: encrypted swap active on /dev/mapper/cryptswap"
    else
        log_warn "luks: encrypted swap configured — will activate on next boot"
    fi

    _luks_state_record "cryptswap" "${swap_src}"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Sensitive Directory Bind Mounts (opt-in) ────────────────────────────────

# _luks_vps_bind_sensitive — relocate /etc/ssh (+ extras) into the encrypted
# data filesystem and bind-mount back. /etc/shadow is deliberately excluded:
# PAM must be able to read it before any unlock can happen.
_luks_vps_bind_sensitive() {
    [[ "${LUKS_BIND_SENSITIVE:-no}" == "yes" ]] || return 2

    if ! mountpoint -q "${LUKS_DATA_PATH}" 2>/dev/null; then
        log_warn "luks: ${LUKS_DATA_PATH} is not mounted — skipping sensitive bind mounts"
        return 1
    fi

    local dirs=( "/etc/ssh" )
    if [[ -n "${LUKS_BIND_EXTRA_DIRS:-}" ]]; then
        local extra_arr
        IFS=',' read -ra extra_arr <<< "${LUKS_BIND_EXTRA_DIRS}"
        dirs+=( "${extra_arr[@]}" )
    fi

    local vault="${LUKS_DATA_PATH}/sensitive"

    local dir
    for dir in "${dirs[@]}"; do
        dir="$(echo "${dir}" | tr -d '[:space:]')"
        [[ -d "${dir}" ]] || { log_warn "luks: bind source missing: ${dir}"; continue; }
        case "${dir}" in
            /etc/shadow*|/etc/passwd*|/etc/group*|/etc/pam.d*)
                log_warn "luks: refusing to relocate ${dir} — required before unlock at boot"
                continue
                ;;
        esac

        local slug="${dir#/}"
        slug="${slug//\//_}"
        local target="${vault}/${slug}"

        if mountpoint -q "${dir}" 2>/dev/null; then
            log_debug "luks: ${dir} already bind-mounted — skipping"
            (( CHANGES_SKIPPED++ )) || true
            continue
        fi

        if ! should_write; then
            log_info "[DRY-RUN] Would relocate ${dir} into ${target} and bind-mount back"
            continue
        fi

        mkdir -p "${target}"
        # Preserve everything: modes, owners, ACLs, xattrs
        if command -v rsync &>/dev/null; then
            rsync -aAX "${dir}/" "${target}/" || { log_error "luks: rsync of ${dir} failed"; continue; }
        else
            cp -a "${dir}/." "${target}/" || { log_error "luks: copy of ${dir} failed"; continue; }
        fi

        mount --bind "${target}" "${dir}" || { log_error "luks: bind mount of ${dir} failed"; continue; }

        backup_file /etc/fstab
        if ! grep -qsF " ${dir} " /etc/fstab; then
            printf '%s  %s  none  bind,nofail,x-systemd.requires-mounts-for=%s  0  0\n' \
                "${target}" "${dir}" "${LUKS_DATA_PATH}" >> /etc/fstab
        fi

        _luks_state_record "bind" "${dir}" "${target}"
        (( CHANGES_APPLIED++ )) || true
        log_success "luks: ${dir} now backed by encrypted storage"
    done
    return 0
}

# ─── VPS Path Orchestrator ────────────────────────────────────────────────────

luks_vps_apply() {
    log_info "luks: applying VPS path (root disk, bootloader, and initramfs untouched)"

    # Hard guarantee: nothing in this path may reference the root disk.
    # _luks_is_safe_target enforces it per device; this is the belt to that
    # braces — bail out if the data path config points into /boot.
    case "${LUKS_DATA_PATH}" in
        /boot*|/) log_error "luks: invalid LUKS_DATA_PATH '${LUKS_DATA_PATH}'"; return 1 ;;
    esac

    if [[ -n "${LUKS_DATA_DEVICES:-}" ]]; then
        _luks_vps_data_volumes
    else
        _luks_vps_loop_container
    fi

    _luks_vps_swap
    _luks_vps_bind_sensitive

    # Optional NBDE binding on the data volumes we created
    if [[ "${LUKS_NBDE:-no}" == "yes" ]]; then
        local entry
        while IFS='|' read -r _ name device _ _; do
            [[ -n "${device}" ]] && _luks_nbde_bind "${device}"
        done < <(_luks_state_entries "volume")
    fi

    return 0
}
