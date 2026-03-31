#!/usr/bin/env bash
# engine.sh — Core LUKS encryption engine
# Runs inside rescue/recovery environment over SSH.
# Assumes disks are available and the system is in rescue mode.
# Do not run on a live production system.
set -euo pipefail

# ─── Globals (set by caller or via arguments) ────────────────────────────────

: "${ENGINE_DISKS:=auto}"
: "${ENGINE_RAID_LEVEL:=none}"
: "${ENGINE_RAID_CHUNK:=512}"
: "${ENGINE_FILESYSTEM:=ext4}"
: "${ENGINE_BOOT_SIZE:=512}"
: "${ENGINE_EFI_SIZE:=256}"
: "${ENGINE_CIPHER:=aes-xts-plain64}"
: "${ENGINE_KEY_SIZE:=512}"
: "${ENGINE_DISTRO:=debian-12}"
: "${ENGINE_SSH_PUBKEY:=}"
: "${ENGINE_DROPBEAR_PORT:=2222}"
: "${ENGINE_PROVISION_USER:=}"
: "${ENGINE_DRY_RUN:=false}"

# Internal state
declare -g _ENGINE_STEP=0
declare -g _ENGINE_STATUS_FILE="/tmp/luks-engine-status"
declare -g _ENGINE_LUKS_DEVICE=""
declare -g _ENGINE_ROOT_DEVICE=""
declare -g _ENGINE_BOOT_DEVICE=""
declare -g _ENGINE_EFI_DEVICE=""
declare -g _ENGINE_MOUNT="/mnt/target"
declare -a _ENGINE_DETECTED_DISKS=()
declare -g _ENGINE_DISTRO_FAMILY=""
declare -g _ENGINE_DISTRO_ID=""
declare -g _ENGINE_DISTRO_CODENAME=""

# ─── Logging ─────────────────────────────────────────────────────────────────

_engine_log() {
    local level="${1}"
    local msg="${2}"
    printf '[%s] [%s] %s\n' "$(date '+%H:%M:%S')" "${level}" "${msg}"
}

_engine_info()  { _engine_log "INFO"  "${1}"; }
_engine_warn()  { _engine_log "WARN"  "${1}"; }
_engine_error() { _engine_log "ERROR" "${1}"; }
_engine_ok()    { _engine_log "OK"    "${1}"; }

# ─── Checkpoint System ───────────────────────────────────────────────────────

_engine_checkpoint() {
    local step_name="${1}"
    (( _ENGINE_STEP++ )) || true
    printf '%d|%s|%s\n' "${_ENGINE_STEP}" "${step_name}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "${_ENGINE_STATUS_FILE}"
    _engine_info "Step ${_ENGINE_STEP}: ${step_name}"
}

_engine_fail() {
    local msg="${1}"
    _engine_error "FAILED at step ${_ENGINE_STEP}: ${msg}"
    _engine_error "Server left in rescue mode for manual inspection."
    _engine_error "Status file: ${_ENGINE_STATUS_FILE}"
    exit 1
}

# ─── Distro Parsing ──────────────────────────────────────────────────────────

_engine_parse_distro() {
    local image="${ENGINE_DISTRO}"

    # Parse "debian-12", "ubuntu-24.04", "rocky-9", "alma-9"
    _ENGINE_DISTRO_ID="${image%%-*}"
    local version="${image#*-}"

    case "${_ENGINE_DISTRO_ID}" in
        debian)
            _ENGINE_DISTRO_FAMILY="debian"
            case "${version}" in
                12) _ENGINE_DISTRO_CODENAME="bookworm" ;;
                13) _ENGINE_DISTRO_CODENAME="trixie" ;;
                *)  _ENGINE_DISTRO_CODENAME="trixie" ;;
            esac
            ;;
        ubuntu)
            _ENGINE_DISTRO_FAMILY="debian"
            case "${version}" in
                24.04) _ENGINE_DISTRO_CODENAME="noble" ;;
                22.04) _ENGINE_DISTRO_CODENAME="jammy" ;;
                *)     _ENGINE_DISTRO_CODENAME="noble" ;;
            esac
            ;;
        rocky|alma)
            _ENGINE_DISTRO_FAMILY="rhel"
            _ENGINE_DISTRO_CODENAME=""
            ;;
        *)
            _engine_fail "Unsupported distro: ${_ENGINE_DISTRO_ID}"
            ;;
    esac

    _engine_info "Distro: id=${_ENGINE_DISTRO_ID} family=${_ENGINE_DISTRO_FAMILY} codename=${_ENGINE_DISTRO_CODENAME}"
}

# ─── Step 1: Detect Disks ────────────────────────────────────────────────────

engine_detect_disks() {
    _engine_checkpoint "Detect disks"

    if [[ "${ENGINE_DISKS}" == "auto" ]]; then
        # Find all non-removable, non-loopback block devices
        local disk
        while IFS= read -r disk; do
            [[ -n "${disk}" ]] || continue
            _ENGINE_DETECTED_DISKS+=("${disk}")
        done < <(lsblk -dpno NAME,TYPE,RM 2>/dev/null \
            | awk '$2 == "disk" && $3 == "0" { print $1 }')

        if [[ ${#_ENGINE_DETECTED_DISKS[@]} -eq 0 ]]; then
            _engine_fail "No disks detected. Check lsblk output."
        fi
    else
        # Parse comma-separated list
        IFS=',' read -ra _ENGINE_DETECTED_DISKS <<< "${ENGINE_DISKS}"
        local d
        for d in "${_ENGINE_DETECTED_DISKS[@]}"; do
            if [[ ! -b "${d}" ]]; then
                _engine_fail "Disk not found: ${d}"
            fi
        done
    fi

    local disk_count="${#_ENGINE_DETECTED_DISKS[@]}"
    _engine_info "Detected ${disk_count} disk(s): ${_ENGINE_DETECTED_DISKS[*]}"

    # Auto-select RAID level
    if [[ "${disk_count}" -eq 1 ]]; then
        ENGINE_RAID_LEVEL="none"
        _engine_info "Single disk — RAID disabled"
    elif [[ "${ENGINE_RAID_LEVEL}" == "none" && "${disk_count}" -gt 1 ]]; then
        ENGINE_RAID_LEVEL="raid1"
        _engine_info "Multiple disks detected, defaulting to raid1"
    fi

    # Validate RAID level vs disk count
    _engine_validate_raid "${disk_count}"
}

_engine_validate_raid() {
    local disk_count="${1}"

    case "${ENGINE_RAID_LEVEL}" in
        none)
            return 0
            ;;
        raid0)
            if [[ "${disk_count}" -lt 2 ]]; then
                _engine_fail "raid0 requires at least 2 disks, found ${disk_count}"
            fi
            _engine_warn "raid0 provides NO redundancy — data loss if any disk fails"
            ;;
        raid1)
            if [[ "${disk_count}" -lt 2 ]]; then
                _engine_fail "raid1 requires at least 2 disks, found ${disk_count}"
            fi
            ;;
        raid5)
            if [[ "${disk_count}" -lt 3 ]]; then
                _engine_fail "raid5 requires at least 3 disks, found ${disk_count}"
            fi
            ;;
        raid6)
            if [[ "${disk_count}" -lt 4 ]]; then
                _engine_fail "raid6 requires at least 4 disks, found ${disk_count}"
            fi
            ;;
        raid10)
            if [[ "${disk_count}" -lt 4 ]]; then
                _engine_fail "raid10 requires at least 4 disks, found ${disk_count}"
            fi
            if (( disk_count % 2 != 0 )); then
                _engine_fail "raid10 requires even disk count, found ${disk_count}"
            fi
            ;;
        *)
            _engine_fail "Unknown RAID level: ${ENGINE_RAID_LEVEL}"
            ;;
    esac
}

# ─── Step 2: Pre-Flight Validation ───────────────────────────────────────────

engine_preflight() {
    _engine_checkpoint "Pre-flight validation"

    local missing_tools=()
    local required_tools=(cryptsetup sgdisk wipefs lsblk mkfs.ext4 mount umount chroot)

    if [[ "${ENGINE_FILESYSTEM}" == "xfs" ]]; then
        required_tools+=(mkfs.xfs)
    fi

    if [[ "${ENGINE_RAID_LEVEL}" != "none" ]]; then
        required_tools+=(mdadm)
    fi

    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            required_tools+=(debootstrap)
            ;;
        rhel)
            required_tools+=(dnf)
            ;;
    esac

    local tool
    for tool in "${required_tools[@]}"; do
        if ! command -v "${tool}" &>/dev/null; then
            missing_tools+=("${tool}")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        _engine_error "Missing required tools: ${missing_tools[*]}"
        _engine_info "Attempting to install missing tools..."
        apt-get update -y &>/dev/null && \
            apt-get install -y cryptsetup gdisk debootstrap mdadm dosfstools xfsprogs &>/dev/null || \
            _engine_fail "Could not install missing tools: ${missing_tools[*]}"
    fi

    # Stop any existing RAID arrays and close LUKS volumes
    _engine_info "Cleaning up existing RAID/LUKS/mounts..."
    # Close any open LUKS volumes
    local dm
    for dm in /dev/mapper/crypt-*; do
        [[ -b "${dm}" ]] && cryptsetup luksClose "$(basename "${dm}")" 2>/dev/null || true
    done
    # Stop all mdadm arrays
    mdadm --stop --scan 2>/dev/null || true
    # Deactivate LVM volume groups
    vgchange -an 2>/dev/null || true
    sleep 2

    # Check disks are not mounted
    local disk
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        # Unmount all partitions on this disk
        local part
        for part in "${disk}"*; do
            if grep -q "^${part}" /proc/mounts 2>/dev/null; then
                _engine_warn "Partition ${part} is mounted — unmounting"
                umount -l "${part}" 2>/dev/null || true
            fi
        done
    done
    sleep 1

    # Check minimum disk size (8GB)
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        local size_bytes
        size_bytes="$(blockdev --getsize64 "${disk}" 2>/dev/null || printf '0')"
        local size_gb=$(( size_bytes / 1073741824 ))
        if [[ "${size_gb}" -lt 8 ]]; then
            _engine_fail "Disk ${disk} is ${size_gb}GB — minimum 8GB required"
        fi
        _engine_info "Disk ${disk}: ${size_gb}GB"
    done

    # Validate SSH public key
    if [[ -z "${ENGINE_SSH_PUBKEY}" ]]; then
        _engine_fail "ENGINE_SSH_PUBKEY is empty — cannot configure Dropbear"
    fi

    _engine_ok "Pre-flight checks passed"
}

# ─── Step 3: Partition Disks ─────────────────────────────────────────────────

engine_partition() {
    _engine_checkpoint "Partition disks"

    local disk
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        _engine_info "Partitioning ${disk}"

        if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
            _engine_info "[DRY-RUN] Would partition ${disk} with boot=${ENGINE_BOOT_SIZE}MB efi=${ENGINE_EFI_SIZE}MB"
            continue
        fi

        # Wipe existing partition table
        wipefs -a "${disk}" &>/dev/null || true
        sgdisk -Z "${disk}" &>/dev/null || true

        # Create GPT partition table
        local part_num=1

        # Partition 1: BIOS Boot Partition (1MB, required for GRUB on GPT with BIOS)
        sgdisk -n "${part_num}:0:+1M" -t "${part_num}:ef02" \
            -c "${part_num}:bios-boot" "${disk}"
        (( part_num++ )) || true

        # Partition 2: /boot
        sgdisk -n "${part_num}:0:+${ENGINE_BOOT_SIZE}M" -t "${part_num}:8300" \
            -c "${part_num}:boot" "${disk}"
        (( part_num++ )) || true

        # Partition 3: /boot/efi (if EFI size > 0)
        if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
            sgdisk -n "${part_num}:0:+${ENGINE_EFI_SIZE}M" -t "${part_num}:ef00" \
                -c "${part_num}:efi" "${disk}"
            (( part_num++ )) || true
        fi

        # Partition 4 (or 3): LUKS (remaining space)
        sgdisk -n "${part_num}:0:0" -t "${part_num}:8309" \
            -c "${part_num}:luks" "${disk}"

        # Force kernel to re-read partition table
        partprobe "${disk}" 2>/dev/null || true
        sleep 2
    done

    # Determine partition device names (handles nvme naming: nvme0n1p1 vs sda1)
    # Layout: p1=bios-boot, p2=/boot, p3=/boot/efi (optional), p4=LUKS
    local first_disk="${_ENGINE_DETECTED_DISKS[0]}"
    local part_suffix=""
    if [[ "${first_disk}" == *"nvme"* ]] || [[ "${first_disk}" == *"loop"* ]]; then
        part_suffix="p"
    fi

    # p1 is BIOS boot (no device needed — GRUB uses it directly)
    _ENGINE_BOOT_DEVICE="${first_disk}${part_suffix}2"
    if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
        _ENGINE_EFI_DEVICE="${first_disk}${part_suffix}3"
        _ENGINE_LUKS_DEVICE="${first_disk}${part_suffix}4"
    else
        _ENGINE_EFI_DEVICE=""
        _ENGINE_LUKS_DEVICE="${first_disk}${part_suffix}3"
    fi

    _engine_ok "Partitioning complete"
}

# ─── Step 4: Assemble RAID ───────────────────────────────────────────────────

engine_assemble_raid() {
    if [[ "${ENGINE_RAID_LEVEL}" == "none" ]]; then
        _engine_info "RAID: disabled (single disk)"
        return 0
    fi

    _engine_checkpoint "Assemble RAID"

    local disk_count="${#_ENGINE_DETECTED_DISKS[@]}"
    local level="${ENGINE_RAID_LEVEL}"
    local chunk="${ENGINE_RAID_CHUNK}"

    # Collect partition devices for each array
    local boot_parts=()
    local efi_parts=()
    local data_parts=()

    # Layout: p1=bios-boot (skip), p2=/boot, p3=/boot/efi (optional), p4=LUKS
    local disk part_suffix
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        part_suffix=""
        if [[ "${disk}" == *"nvme"* ]] || [[ "${disk}" == *"loop"* ]]; then
            part_suffix="p"
        fi

        boot_parts+=("${disk}${part_suffix}2")
        if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
            efi_parts+=("${disk}${part_suffix}3")
            data_parts+=("${disk}${part_suffix}4")
        else
            data_parts+=("${disk}${part_suffix}3")
        fi
    done

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would create ${level} arrays: md0(boot) md1(efi) md2(data)"
        _ENGINE_BOOT_DEVICE="/dev/md0"
        _ENGINE_EFI_DEVICE="/dev/md1"
        _ENGINE_LUKS_DEVICE="/dev/md2"
        return 0
    fi

    # Stop any existing arrays
    mdadm --stop /dev/md0 /dev/md1 /dev/md2 &>/dev/null || true

    # Zero superblocks
    local part
    for part in "${boot_parts[@]}" "${efi_parts[@]}" "${data_parts[@]}"; do
        mdadm --zero-superblock "${part}" &>/dev/null || true
    done

    local mdadm_opts=(--run --force --metadata=1.2)

    # md0: boot (always raid1 for bootability regardless of data RAID level)
    mdadm --create /dev/md0 "${mdadm_opts[@]}" \
        --level=raid1 \
        --raid-devices="${disk_count}" \
        "${boot_parts[@]}" || _engine_fail "Failed to create md0 (boot)"
    _ENGINE_BOOT_DEVICE="/dev/md0"

    # md1: EFI (raid1 for bootability)
    if [[ ${#efi_parts[@]} -gt 0 ]]; then
        mdadm --create /dev/md1 "${mdadm_opts[@]}" \
            --level=raid1 \
            --raid-devices="${disk_count}" \
            "${efi_parts[@]}" || _engine_fail "Failed to create md1 (efi)"
        _ENGINE_EFI_DEVICE="/dev/md1"
    fi

    # md2: data (user-selected RAID level)
    local data_opts=("${mdadm_opts[@]}" --level="${level}" --raid-devices="${disk_count}")
    if [[ "${level}" != "raid1" ]]; then
        data_opts+=(--chunk="${chunk}")
    fi

    mdadm --create /dev/md2 "${data_opts[@]}" \
        "${data_parts[@]}" || _engine_fail "Failed to create md2 (data)"
    _ENGINE_LUKS_DEVICE="/dev/md2"

    _engine_ok "RAID assembled: boot=md0(raid1) data=md2(${level})"
}

# ─── Step 5: Create LUKS Volume ──────────────────────────────────────────────

engine_create_luks() {
    _engine_checkpoint "Create LUKS volume"

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would luksFormat ${_ENGINE_LUKS_DEVICE} with ${ENGINE_CIPHER}/${ENGINE_KEY_SIZE}"
        return 0
    fi

    # LUKS format — passphrase is read from stdin (fd 0)
    printf '%s' "${ENGINE_PASSPHRASE}" | cryptsetup luksFormat \
        --type luks2 \
        --cipher "${ENGINE_CIPHER}" \
        --key-size "${ENGINE_KEY_SIZE}" \
        --hash sha256 \
        --pbkdf argon2id \
        --batch-mode \
        "${_ENGINE_LUKS_DEVICE}" - \
        || _engine_fail "cryptsetup luksFormat failed on ${_ENGINE_LUKS_DEVICE}"

    _engine_ok "LUKS volume created on ${_ENGINE_LUKS_DEVICE}"
}

# ─── Step 6: Open and Format ─────────────────────────────────────────────────

engine_open_and_format() {
    _engine_checkpoint "Open LUKS and format filesystem"

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would open LUKS as crypt-root and mkfs.${ENGINE_FILESYSTEM}"
        return 0
    fi

    # Open LUKS
    printf '%s' "${ENGINE_PASSPHRASE}" | cryptsetup luksOpen \
        "${_ENGINE_LUKS_DEVICE}" crypt-root - \
        || _engine_fail "cryptsetup luksOpen failed"

    _ENGINE_ROOT_DEVICE="/dev/mapper/crypt-root"

    # Format root
    case "${ENGINE_FILESYSTEM}" in
        ext4)
            mkfs.ext4 -q -L root "${_ENGINE_ROOT_DEVICE}" \
                || _engine_fail "mkfs.ext4 failed on ${_ENGINE_ROOT_DEVICE}"
            ;;
        xfs)
            mkfs.xfs -f -L root "${_ENGINE_ROOT_DEVICE}" \
                || _engine_fail "mkfs.xfs failed on ${_ENGINE_ROOT_DEVICE}"
            ;;
    esac

    # Format boot
    mkfs.ext4 -q -L boot "${_ENGINE_BOOT_DEVICE}" \
        || _engine_fail "mkfs.ext4 failed on ${_ENGINE_BOOT_DEVICE}"

    # Format EFI if present
    if [[ -n "${_ENGINE_EFI_DEVICE}" ]]; then
        mkfs.vfat -F 32 -n EFI "${_ENGINE_EFI_DEVICE}" \
            || _engine_fail "mkfs.vfat failed on ${_ENGINE_EFI_DEVICE}"
    fi

    # Mount target
    mkdir -p "${_ENGINE_MOUNT}"
    mount "${_ENGINE_ROOT_DEVICE}" "${_ENGINE_MOUNT}"
    mkdir -p "${_ENGINE_MOUNT}/boot"
    mount "${_ENGINE_BOOT_DEVICE}" "${_ENGINE_MOUNT}/boot"
    if [[ -n "${_ENGINE_EFI_DEVICE}" ]]; then
        mkdir -p "${_ENGINE_MOUNT}/boot/efi"
        mount "${_ENGINE_EFI_DEVICE}" "${_ENGINE_MOUNT}/boot/efi"
    fi

    _engine_ok "Filesystems created and mounted at ${_ENGINE_MOUNT}"
}

# ─── Step 7: Install Base OS ─────────────────────────────────────────────────

engine_install_os() {
    _engine_checkpoint "Install base OS"

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would install ${_ENGINE_DISTRO_ID} into ${_ENGINE_MOUNT}"
        return 0
    fi

    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            _engine_install_debian
            ;;
        rhel)
            _engine_install_rhel
            ;;
    esac

    _engine_ok "Base OS installed"
}

_engine_install_debian() {
    local mirror="http://deb.debian.org/debian"
    if [[ "${_ENGINE_DISTRO_ID}" == "ubuntu" ]]; then
        mirror="http://archive.ubuntu.com/ubuntu"
    fi

    _engine_info "Running debootstrap: ${_ENGINE_DISTRO_CODENAME} from ${mirror}"

    debootstrap \
        --arch amd64 \
        "${_ENGINE_DISTRO_CODENAME}" \
        "${_ENGINE_MOUNT}" \
        "${mirror}" \
        || _engine_fail "debootstrap failed"

    # Mount virtual filesystems for chroot
    _engine_mount_vfs

    # Detect UEFI vs BIOS for GRUB package selection
    local grub_pkg="grub-pc"
    if [[ -d /sys/firmware/efi ]]; then
        grub_pkg="grub-efi-amd64"
        _engine_info "UEFI boot detected — using ${grub_pkg}"
    else
        _engine_info "BIOS boot detected — using ${grub_pkg}"
    fi

    # Install essential packages inside chroot
    chroot "${_ENGINE_MOUNT}" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y \
            linux-image-amd64 \
            ${grub_pkg} \
            cryptsetup \
            cryptsetup-initramfs \
            dropbear-initramfs \
            openssh-server \
            sudo \
            curl \
            iproute2 \
            ifupdown \
            net-tools \
            busybox
    " || _engine_fail "Failed to install packages in chroot"

    # Install mdadm if RAID is used
    if [[ "${ENGINE_RAID_LEVEL}" != "none" ]]; then
        chroot "${_ENGINE_MOUNT}" bash -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y mdadm
        " || _engine_fail "Failed to install mdadm in chroot"
    fi
}

_engine_install_rhel() {
    local release_pkg=""
    case "${_ENGINE_DISTRO_ID}" in
        rocky)
            release_pkg="https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/r/rocky-release-9.5-1.2.el9.noarch.rpm"
            ;;
        alma)
            release_pkg="https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/Packages/almalinux-release-9.5-1.el9.noarch.rpm"
            ;;
    esac

    _engine_info "Running dnf installroot for ${_ENGINE_DISTRO_ID}"

    # Install release package first to get repos
    rpm --root="${_ENGINE_MOUNT}" --import /etc/pki/rpm-gpg/RPM-GPG-KEY-* 2>/dev/null || true
    dnf --installroot="${_ENGINE_MOUNT}" --releasever=9 -y install \
        "${release_pkg}" 2>/dev/null || true

    dnf --installroot="${_ENGINE_MOUNT}" --releasever=9 -y install \
        @core \
        kernel \
        grub2-pc \
        cryptsetup \
        openssh-server \
        sudo \
        iproute \
        NetworkManager \
        dracut-crypt-ssh \
        || _engine_fail "dnf installroot failed"

    if [[ "${ENGINE_RAID_LEVEL}" != "none" ]]; then
        dnf --installroot="${_ENGINE_MOUNT}" --releasever=9 -y install mdadm \
            || _engine_fail "Failed to install mdadm"
    fi

    _engine_mount_vfs
}

_engine_mount_vfs() {
    mount --bind /dev  "${_ENGINE_MOUNT}/dev"
    mount --bind /dev/pts "${_ENGINE_MOUNT}/dev/pts"
    mount -t proc proc "${_ENGINE_MOUNT}/proc"
    mount -t sysfs sys "${_ENGINE_MOUNT}/sys"
}

# ─── Step 8: Configure Chroot ────────────────────────────────────────────────

engine_configure() {
    _engine_checkpoint "Configure chroot"

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would configure fstab, crypttab, dropbear, grub inside chroot"
        return 0
    fi

    _engine_configure_fstab
    _engine_configure_crypttab
    _engine_configure_dropbear
    _engine_configure_networking
    _engine_configure_grub
    _engine_configure_user
    _engine_configure_mdadm

    _engine_ok "Chroot configuration complete"
}

_engine_configure_fstab() {
    local luks_uuid
    luks_uuid="$(blkid -s UUID -o value "${_ENGINE_LUKS_DEVICE}")"
    local boot_uuid
    boot_uuid="$(blkid -s UUID -o value "${_ENGINE_BOOT_DEVICE}")"

    local fstab_content="/dev/mapper/crypt-root  /          ${ENGINE_FILESYSTEM}  defaults  0 1
UUID=${boot_uuid}      /boot      ext4    defaults  0 2"

    if [[ -n "${_ENGINE_EFI_DEVICE}" ]]; then
        local efi_uuid
        efi_uuid="$(blkid -s UUID -o value "${_ENGINE_EFI_DEVICE}")"
        fstab_content="${fstab_content}
UUID=${efi_uuid}       /boot/efi  vfat    umask=0077  0 1"
    fi

    fstab_content="${fstab_content}
tmpfs                  /tmp       tmpfs   defaults,noatime,mode=1777  0 0"

    printf '%s\n' "${fstab_content}" > "${_ENGINE_MOUNT}/etc/fstab"
    _engine_info "fstab configured"
}

_engine_configure_crypttab() {
    local luks_uuid
    luks_uuid="$(blkid -s UUID -o value "${_ENGINE_LUKS_DEVICE}")"

    printf 'crypt-root UUID=%s none luks,discard\n' "${luks_uuid}" \
        > "${_ENGINE_MOUNT}/etc/crypttab"
    _engine_info "crypttab configured: UUID=${luks_uuid}"
}

_engine_configure_dropbear() {
    _engine_info "Configuring Dropbear in initramfs"

    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            _engine_configure_dropbear_debian
            ;;
        rhel)
            _engine_configure_dropbear_rhel
            ;;
    esac
}

_engine_configure_dropbear_debian() {
    # Set Dropbear port
    local dropbear_conf="${_ENGINE_MOUNT}/etc/dropbear/initramfs/dropbear.conf"
    mkdir -p "$(dirname "${dropbear_conf}")"
    printf 'DROPBEAR_OPTIONS="-p %s -s -j -k"\n' "${ENGINE_DROPBEAR_PORT}" \
        > "${dropbear_conf}"

    # Install SSH public key for Dropbear
    local dropbear_authkeys="${_ENGINE_MOUNT}/etc/dropbear/initramfs/authorized_keys"
    printf '%s\n' "${ENGINE_SSH_PUBKEY}" > "${dropbear_authkeys}"
    chmod 600 "${dropbear_authkeys}"

    # Rebuild initramfs with Dropbear
    chroot "${_ENGINE_MOUNT}" update-initramfs -u \
        || _engine_fail "update-initramfs failed"

    _engine_info "Dropbear configured (port ${ENGINE_DROPBEAR_PORT})"
}

_engine_configure_dropbear_rhel() {
    # dracut-crypt-ssh configuration
    local dracut_conf="${_ENGINE_MOUNT}/etc/dracut.conf.d/crypt-ssh.conf"
    mkdir -p "$(dirname "${dracut_conf}")"

    cat > "${dracut_conf}" <<EOF
dropbear_port="${ENGINE_DROPBEAR_PORT}"
dropbear_acl="/root/.ssh/authorized_keys_dropbear"
EOF

    # Install SSH public key
    local authkeys="${_ENGINE_MOUNT}/root/.ssh/authorized_keys_dropbear"
    mkdir -p "${_ENGINE_MOUNT}/root/.ssh"
    chmod 700 "${_ENGINE_MOUNT}/root/.ssh"
    printf '%s\n' "${ENGINE_SSH_PUBKEY}" > "${authkeys}"
    chmod 600 "${authkeys}"

    # Rebuild initramfs with dracut-crypt-ssh
    chroot "${_ENGINE_MOUNT}" dracut --force --add "crypt-ssh" \
        || _engine_fail "dracut rebuild failed"

    _engine_info "dracut-crypt-ssh configured (port ${ENGINE_DROPBEAR_PORT})"
}

_engine_configure_networking() {
    _engine_info "Configuring initramfs networking"

    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            # Configure initramfs IP (DHCP)
            local initramfs_conf="${_ENGINE_MOUNT}/etc/initramfs-tools/initramfs.conf"
            if [[ -f "${initramfs_conf}" ]]; then
                if grep -q '^IP=' "${initramfs_conf}"; then
                    sed -i 's/^IP=.*/IP=dhcp/' "${initramfs_conf}"
                else
                    printf '\nIP=dhcp\n' >> "${initramfs_conf}"
                fi
            else
                mkdir -p "$(dirname "${initramfs_conf}")"
                printf 'IP=dhcp\n' > "${initramfs_conf}"
            fi

            # Configure real OS networking — detect primary interface and use DHCP
            local primary_iface
            primary_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)"
            primary_iface="${primary_iface:-eth0}"
            _engine_info "Configuring networking for interface ${primary_iface}"

            mkdir -p "${_ENGINE_MOUNT}/etc/network"
            cat > "${_ENGINE_MOUNT}/etc/network/interfaces" <<NETEOF
# Loopback
auto lo
iface lo inet loopback

# Primary network interface (DHCP)
auto ${primary_iface}
iface ${primary_iface} inet dhcp
NETEOF

            # Also configure systemd-networkd as fallback
            mkdir -p "${_ENGINE_MOUNT}/etc/systemd/network"
            cat > "${_ENGINE_MOUNT}/etc/systemd/network/20-dhcp.network" <<NETEOF
[Match]
Name=e* en*

[Network]
DHCP=yes
NETEOF
            chroot "${_ENGINE_MOUNT}" systemctl enable systemd-networkd 2>/dev/null || true

            # Enable networking service
            chroot "${_ENGINE_MOUNT}" systemctl enable networking 2>/dev/null || true

            # Rebuild initramfs with network config
            chroot "${_ENGINE_MOUNT}" update-initramfs -u || true
            ;;
        rhel)
            # dracut network module — add kernel cmdline
            local dracut_net="${_ENGINE_MOUNT}/etc/dracut.conf.d/network.conf"
            printf 'add_dracutmodules+=" network "\nkernel_cmdline="ip=dhcp rd.neednet=1"\n' \
                > "${dracut_net}"
            # NetworkManager should handle real OS networking via DHCP
            chroot "${_ENGINE_MOUNT}" systemctl enable NetworkManager 2>/dev/null || true
            chroot "${_ENGINE_MOUNT}" dracut --force || true
            ;;
    esac
}

_engine_configure_grub() {
    _engine_info "Configuring GRUB with LUKS support"

    local luks_uuid
    luks_uuid="$(blkid -s UUID -o value "${_ENGINE_LUKS_DEVICE}")"

    local grub_default="${_ENGINE_MOUNT}/etc/default/grub"
    cat > "${grub_default}" <<EOF
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="${_ENGINE_DISTRO_ID}"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="cryptdevice=UUID=${luks_uuid}:crypt-root ip=dhcp"
GRUB_ENABLE_CRYPTODISK=y
EOF

    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            if [[ -d /sys/firmware/efi ]]; then
                # UEFI: mount efivarfs into chroot and install
                mount -t efivarfs efivarfs "${_ENGINE_MOUNT}/sys/firmware/efi/efivars" 2>/dev/null || true

                # Use --removable to install to fallback EFI path (EFI/BOOT/BOOTX64.EFI)
                # This avoids NVRAM registration issues in rescue/chroot environments
                chroot "${_ENGINE_MOUNT}" grub-install \
                    --target=x86_64-efi \
                    --efi-directory=/boot/efi \
                    --bootloader-id=debian \
                    --removable \
                    --recheck \
                    || _engine_fail "grub-install (UEFI) failed"
            else
                # BIOS: install to all disks (BIOS boot partition handles embedding)
                local disk
                for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
                    chroot "${_ENGINE_MOUNT}" grub-install "${disk}" \
                        || _engine_fail "grub-install failed on ${disk}"
                done
            fi
            chroot "${_ENGINE_MOUNT}" update-grub \
                || _engine_fail "update-grub failed"
            ;;
        rhel)
            local disk
            for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
                chroot "${_ENGINE_MOUNT}" grub2-install "${disk}" \
                    || _engine_fail "grub2-install failed on ${disk}"
            done
            chroot "${_ENGINE_MOUNT}" grub2-mkconfig -o /boot/grub2/grub.cfg \
                || _engine_fail "grub2-mkconfig failed"
            ;;
    esac

    _engine_info "GRUB installed and configured"
}

_engine_configure_user() {
    # Set up root SSH access — install both Dropbear key and user's main SSH key
    mkdir -p "${_ENGINE_MOUNT}/root/.ssh"
    chmod 700 "${_ENGINE_MOUNT}/root/.ssh"
    printf '%s\n' "${ENGINE_SSH_PUBKEY}" > "${_ENGINE_MOUNT}/root/.ssh/authorized_keys"
    # Also add the user's main SSH key (from the rescue environment) if different
    if [[ -f /root/.ssh/authorized_keys ]]; then
        local main_key
        while IFS= read -r main_key; do
            [[ -z "${main_key}" || "${main_key}" == "#"* ]] && continue
            if ! grep -qF "${main_key}" "${_ENGINE_MOUNT}/root/.ssh/authorized_keys" 2>/dev/null; then
                printf '%s\n' "${main_key}" >> "${_ENGINE_MOUNT}/root/.ssh/authorized_keys"
                _engine_info "Added rescue-environment SSH key to root authorized_keys"
            fi
        done < /root/.ssh/authorized_keys
    fi
    chmod 600 "${_ENGINE_MOUNT}/root/.ssh/authorized_keys"
    _engine_info "Root SSH keys configured"

    if [[ -z "${ENGINE_PROVISION_USER}" ]]; then
        return 0
    fi

    local user="${ENGINE_PROVISION_USER}"
    _engine_info "Creating user: ${user}"

    chroot "${_ENGINE_MOUNT}" useradd -m -s /bin/bash "${user}" \
        || _engine_fail "useradd failed for ${user}"

    # SSH key
    local ssh_dir="${_ENGINE_MOUNT}/home/${user}/.ssh"
    mkdir -p "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    printf '%s\n' "${ENGINE_SSH_PUBKEY}" > "${ssh_dir}/authorized_keys"
    chmod 600 "${ssh_dir}/authorized_keys"
    chroot "${_ENGINE_MOUNT}" chown -R "${user}:${user}" "/home/${user}/.ssh"

    # Passwordless sudo
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${user}" \
        > "${_ENGINE_MOUNT}/etc/sudoers.d/90-luks-${user}"
    chmod 440 "${_ENGINE_MOUNT}/etc/sudoers.d/90-luks-${user}"

    _engine_info "User ${user} created with SSH key and sudo"
}

_engine_configure_mdadm() {
    if [[ "${ENGINE_RAID_LEVEL}" == "none" ]]; then
        return 0
    fi

    _engine_info "Saving mdadm configuration"

    mdadm --detail --scan >> "${_ENGINE_MOUNT}/etc/mdadm/mdadm.conf" 2>/dev/null || \
        mdadm --detail --scan >> "${_ENGINE_MOUNT}/etc/mdadm.conf" 2>/dev/null || true

    # Ensure initramfs includes mdadm
    case "${_ENGINE_DISTRO_FAMILY}" in
        debian)
            chroot "${_ENGINE_MOUNT}" update-initramfs -u || true
            ;;
        rhel)
            chroot "${_ENGINE_MOUNT}" dracut --force --add "mdraid" || true
            ;;
    esac
}

# ─── Step 9: Finalize ────────────────────────────────────────────────────────

engine_finalize() {
    _engine_checkpoint "Finalize"

    if [[ "${ENGINE_DRY_RUN}" == "true" ]]; then
        _engine_info "[DRY-RUN] Would unmount and close LUKS"
        _engine_ok "Dry run complete — all steps validated"
        return 0
    fi

    # Enable SSH on boot
    chroot "${_ENGINE_MOUNT}" systemctl enable ssh 2>/dev/null || \
        chroot "${_ENGINE_MOUNT}" systemctl enable sshd 2>/dev/null || true

    # Set hostname
    printf 'luks-server\n' > "${_ENGINE_MOUNT}/etc/hostname"

    # Unmount virtual filesystems
    umount -l "${_ENGINE_MOUNT}/dev/pts" 2>/dev/null || true
    umount -l "${_ENGINE_MOUNT}/dev"     2>/dev/null || true
    umount -l "${_ENGINE_MOUNT}/proc"    2>/dev/null || true
    umount -l "${_ENGINE_MOUNT}/sys"     2>/dev/null || true

    # Unmount target filesystems
    if [[ -n "${_ENGINE_EFI_DEVICE}" ]]; then
        umount "${_ENGINE_MOUNT}/boot/efi" 2>/dev/null || true
    fi
    umount "${_ENGINE_MOUNT}/boot" 2>/dev/null || true
    umount "${_ENGINE_MOUNT}"      2>/dev/null || true

    # Close LUKS
    cryptsetup luksClose crypt-root 2>/dev/null || true

    # Stop RAID arrays (they'll reassemble on boot)
    if [[ "${ENGINE_RAID_LEVEL}" != "none" ]]; then
        mdadm --stop /dev/md0 /dev/md1 /dev/md2 &>/dev/null || true
    fi

    _engine_ok "Finalization complete — ready for reboot"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

engine_main() {
    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf ' LUKS Engine — Full Disk Encryption Setup\n'
    printf '────────────────────────────────────────────────────────────\n'
    printf ' Distro    : %s (%s)\n' "${ENGINE_DISTRO}" "${_ENGINE_DISTRO_FAMILY}"
    printf ' Disks     : %s\n' "${ENGINE_DISKS}"
    printf ' RAID      : %s\n' "${ENGINE_RAID_LEVEL}"
    printf ' Filesystem: %s\n' "${ENGINE_FILESYSTEM}"
    printf ' Cipher    : %s / %s-bit\n' "${ENGINE_CIPHER}" "${ENGINE_KEY_SIZE}"
    printf ' Dry-run   : %s\n' "${ENGINE_DRY_RUN}"
    printf '════════════════════════════════════════════════════════════\n\n'

    # Initialize status file
    printf '' > "${_ENGINE_STATUS_FILE}"

    _engine_parse_distro
    engine_detect_disks
    engine_preflight
    engine_partition
    engine_assemble_raid
    engine_create_luks
    engine_open_and_format
    engine_install_os
    engine_configure
    engine_finalize

    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf ' LUKS Engine — Complete\n'
    printf ' Steps completed: %d\n' "${_ENGINE_STEP}"
    printf ' Status file: %s\n' "${_ENGINE_STATUS_FILE}"
    printf '════════════════════════════════════════════════════════════\n'
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    engine_main
fi
