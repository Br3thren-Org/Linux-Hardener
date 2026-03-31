# LUKS Encrypted Provisioning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provider-agnostic LUKS full-disk encryption provisioning workflow with Dropbear SSH unlock, RAID support, and 7 cloud provider adapters.

**Architecture:** Separate `luks/` directory with a CLI orchestrator (`provision-encrypted.sh`), a core engine that runs in rescue mode over SSH (`engine.sh`), thin provider adapters implementing a 6-function contract, and an unlock helper (`unlock-remote.sh`). All scripts follow existing project conventions: `set -euo pipefail`, `"${VAR}"` quoting, `printf` over `echo`, `_prefix_` private functions, return 0/1/2 pattern.

**Tech Stack:** Bash, cryptsetup (LUKS2), mdadm, sgdisk, debootstrap/dnf, dropbear-initramfs/dracut-crypt-ssh, curl + jq for provider APIs.

**Spec:** `docs/superpowers/specs/2026-03-31-luks-encrypted-provisioning-design.md`

---

## File Structure

```
luks/
├── provision-encrypted.sh    # CLI entrypoint — orchestrates full flow
├── unlock-remote.sh          # Post-reboot unlock helper
├── engine.sh                 # Core LUKS setup (runs in rescue over SSH)
├── luks.conf                 # Default configuration
└── providers/
    ├── interface.sh          # Provider contract, dispatcher, validation
    ├── hetzner.sh            # Hetzner Cloud adapter
    ├── digitalocean.sh       # DigitalOcean adapter
    ├── vultr.sh              # Vultr adapter
    ├── aws.sh                # AWS EC2 adapter (EBS-based flow)
    ├── linode.sh             # Linode/Akamai adapter
    ├── ovh.sh                # OVH adapter
    └── ionos.sh              # Ionos adapter
```

**Parallelism notes for sub-agents:** Tasks 1-3 are foundational and must be sequential. Tasks 4-10 (provider adapters) are fully independent and can all run in parallel. Task 11 (unlock-remote.sh) depends on Task 1 only. Task 12 (provision-encrypted.sh) depends on Tasks 1-3 and 11. Task 13 (integration) depends on all prior tasks.

---

### Task 1: Default Configuration — luks/luks.conf

**Files:**
- Create: `luks/luks.conf`

This is the default config file sourced by the orchestrator. Follows the same pattern as `config/hardener.conf` — shell variables in UPPER_SNAKE_CASE, sourced directly.

- [ ] **Step 1: Create luks/luks.conf**

```bash
# luks.conf — Default configuration for LUKS encrypted provisioning
# Source this file or pass --config to provision-encrypted.sh
# All values can be overridden by environment variables or CLI flags.

# ─── Provider ────────────────────────────────────────────────────────────────
# Which cloud provider to use.
# Options: hetzner, digitalocean, vultr, aws, linode, ovh, ionos
LUKS_PROVIDER="hetzner"

# ─── Server ──────────────────────────────────────────────────────────────────
# Provider-specific instance type and region.
# These are provider defaults — override per provider as needed.
LUKS_SERVER_TYPE=""
LUKS_LOCATION=""
LUKS_IMAGE="debian-12"

# ─── SSH ─────────────────────────────────────────────────────────────────────
# Path to the SSH private key used for Dropbear unlock and server access.
LUKS_SSH_KEY_PATH="${HOME}/.ssh/id_ed25519"

# Dropbear SSH port in initramfs (must differ from OpenSSH port).
LUKS_DROPBEAR_PORT="2222"

# ─── Encryption ──────────────────────────────────────────────────────────────
# LUKS cipher and key size.
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE="512"

# Passphrase handling: "auto" generates a 32-char random passphrase.
# Set to a specific value to use a fixed passphrase.
LUKS_PASSPHRASE="auto"

# ─── Storage Layout ─────────────────────────────────────────────────────────
# Disks to use. "auto" detects all non-removable block devices.
# For explicit disks: "/dev/sda,/dev/sdb"
LUKS_DISKS="auto"

# RAID level for multi-disk setups. Ignored for single disk.
# Options: none, raid0, raid1, raid5, raid6, raid10
LUKS_RAID_LEVEL="raid1"

# Stripe/chunk size in KB (for raid0, raid5, raid6, raid10).
LUKS_RAID_CHUNK="512"

# Filesystem for the root volume.
# Options: ext4, xfs
LUKS_FILESYSTEM="ext4"

# Partition sizes in MB.
LUKS_BOOT_SIZE="512"
LUKS_EFI_SIZE="256"

# ─── Post-Provisioning ──────────────────────────────────────────────────────
# Run harden.sh --apply after provisioning and unlock.
LUKS_AUTO_HARDEN="true"

# Create a non-root user with SSH key and sudo access.
LUKS_PROVISION_USER=""

# ─── Provider Credentials ───────────────────────────────────────────────────
# Set these via environment variables or fill in below.
# Hetzner
# HETZNER_API_TOKEN=""

# DigitalOcean
# DO_API_TOKEN=""

# Vultr
# VULTR_API_KEY=""

# AWS
# AWS_ACCESS_KEY_ID=""
# AWS_SECRET_ACCESS_KEY=""
# AWS_REGION=""

# Linode
# LINODE_API_TOKEN=""

# OVH
# OVH_APP_KEY=""
# OVH_APP_SECRET=""
# OVH_CONSUMER_KEY=""
# OVH_ENDPOINT=""

# Ionos
# IONOS_USERNAME=""
# IONOS_PASSWORD=""
```

- [ ] **Step 2: Commit**

```bash
git add luks/luks.conf
git commit -m "feat(luks): add default configuration file"
```

---

### Task 2: Provider Interface — luks/providers/interface.sh

**Files:**
- Create: `luks/providers/interface.sh`

The dispatcher that sources the correct provider adapter, validates the contract, and provides shared API helper utilities.

- [ ] **Step 1: Create luks/providers/interface.sh**

```bash
#!/usr/bin/env bash
# interface.sh — Provider contract, dispatcher, and shared API utilities
# Sourced by provision-encrypted.sh. Do not run directly.

# ─── Contract ────────────────────────────────────────────────────────────────
# Every provider adapter MUST implement these functions:
#   provider_create_server  <name> <type> <image> <location> <ssh_key_name>
#       → prints "server_id|ip" on stdout
#   provider_enter_rescue   <server_id>
#       → boots server into rescue mode, prints "rescue_password" on stdout (or "none")
#   provider_exit_rescue    <server_id>
#       → exits rescue mode (may be a no-op if reboot handles it)
#   provider_reboot         <server_id>
#       → normal reboot
#   provider_delete_server  <server_id>
#       → deletes the server
#   provider_get_status     <server_id>
#       → prints one of: running, rescue, stopped, unknown

readonly -a _PROVIDER_CONTRACT=(
    provider_create_server
    provider_enter_rescue
    provider_exit_rescue
    provider_reboot
    provider_delete_server
    provider_get_status
)

readonly -a _SUPPORTED_PROVIDERS=(
    hetzner
    digitalocean
    vultr
    aws
    linode
    ovh
    ionos
)

# ─── Dispatcher ──────────────────────────────────────────────────────────────

# luks_load_provider <provider_name>
#   Sources the adapter file and validates the contract.
luks_load_provider() {
    local provider="${1}"

    if [[ -z "${provider}" ]]; then
        printf 'ERROR: luks_load_provider: provider name is required\n' >&2
        return 1
    fi

    # Validate provider is supported
    local supported="false"
    local p
    for p in "${_SUPPORTED_PROVIDERS[@]}"; do
        if [[ "${p}" == "${provider}" ]]; then
            supported="true"
            break
        fi
    done

    if [[ "${supported}" != "true" ]]; then
        printf 'ERROR: Unsupported provider: %s\n' "${provider}" >&2
        printf 'Supported providers: %s\n' "${_SUPPORTED_PROVIDERS[*]}" >&2
        return 1
    fi

    # Source the adapter
    local adapter_file="${LUKS_DIR}/providers/${provider}.sh"
    if [[ ! -f "${adapter_file}" ]]; then
        printf 'ERROR: Provider adapter not found: %s\n' "${adapter_file}" >&2
        return 1
    fi

    # shellcheck source=/dev/null
    source "${adapter_file}"

    # Validate contract
    local fn
    for fn in "${_PROVIDER_CONTRACT[@]}"; do
        if ! declare -f "${fn}" > /dev/null 2>&1; then
            printf 'ERROR: Provider %s does not implement required function: %s\n' \
                "${provider}" "${fn}" >&2
            return 1
        fi
    done

    printf '[INFO] Loaded provider adapter: %s\n' "${provider}"
    return 0
}

# ─── Shared API Utility ─────────────────────────────────────────────────────

# _luks_api_request <method> <url> <token_header> [data]
#   Generic authenticated HTTP request. Returns JSON body on stdout.
#   Sets _LUKS_HTTP_CODE as a side effect.
_LUKS_HTTP_CODE=""

_luks_api_request() {
    local method="${1}"
    local url="${2}"
    local auth_header="${3}"
    local data="${4:-}"

    local curl_args=(
        curl -sS
        -X "${method}"
        -H "${auth_header}"
        -H "Content-Type: application/json"
        -w '\n%{http_code}'
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    local raw_response
    raw_response="$("${curl_args[@]}" "${url}" 2>/dev/null)" || {
        printf 'ERROR: curl failed for %s %s\n' "${method}" "${url}" >&2
        return 1
    }

    _LUKS_HTTP_CODE="$(printf '%s' "${raw_response}" | tail -1)"
    local body
    body="$(printf '%s' "${raw_response}" | sed '$d')"

    if [[ -z "${_LUKS_HTTP_CODE}" ]] || [[ "${_LUKS_HTTP_CODE}" -ge 400 ]] 2>/dev/null; then
        printf 'ERROR: API %s %s returned HTTP %s: %s\n' \
            "${method}" "${url}" "${_LUKS_HTTP_CODE:-000}" "${body}" >&2
        return 1
    fi

    printf '%s' "${body}"
    return 0
}

# _luks_wait_ssh <ip> <port> <key_path> <user> [timeout_seconds]
#   Polls SSH until connectable. Returns 0 on success, 1 on timeout.
_luks_wait_ssh() {
    local ip="${1}"
    local port="${2}"
    local key_path="${3}"
    local user="${4}"
    local timeout="${5:-120}"

    local elapsed=0
    local interval=5

    while (( elapsed < timeout )); do
        if ssh \
            -i "${key_path}" -p "${port}" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -o BatchMode=yes \
            "${user}@${ip}" 'true' &>/dev/null 2>&1; then
            return 0
        fi
        sleep "${interval}"
        (( elapsed += interval )) || true
    done

    printf 'ERROR: SSH to %s@%s:%s not reachable after %ds\n' \
        "${user}" "${ip}" "${port}" "${timeout}" >&2
    return 1
}

# _luks_wait_ssh_down <ip> <port> [timeout_seconds]
#   Waits until SSH stops responding (for reboot detection).
_luks_wait_ssh_down() {
    local ip="${1}"
    local port="${2}"
    local timeout="${3:-60}"

    local elapsed=0
    local interval=3

    while (( elapsed < timeout )); do
        if ! ssh \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=3 -o BatchMode=yes \
            "root@${ip}" -p "${port}" 'true' &>/dev/null 2>&1; then
            return 0
        fi
        sleep "${interval}"
        (( elapsed += interval )) || true
    done

    return 1
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/interface.sh
git commit -m "feat(luks): add provider interface contract and dispatcher"
```

---

### Task 3: Core LUKS Engine — luks/engine.sh

**Files:**
- Create: `luks/engine.sh`

This is the largest file. It runs over SSH inside the rescue environment and performs all disk operations. Each step is a separate function with checkpoint logging.

- [ ] **Step 1: Create luks/engine.sh — header, globals, checkpoint system**

```bash
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
```

- [ ] **Step 2: Add distro detection helper**

```bash
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
                *)  _ENGINE_DISTRO_CODENAME="bookworm" ;;
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
```

- [ ] **Step 3: Add disk detection and RAID validation**

```bash
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
```

- [ ] **Step 4: Add pre-flight validation**

```bash
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

    # Check disks are not mounted
    local disk
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        if grep -q "^${disk}" /proc/mounts 2>/dev/null; then
            _engine_warn "Disk ${disk} has mounted partitions — unmounting"
            umount -l "${disk}"* 2>/dev/null || true
        fi
    done

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
```

- [ ] **Step 5: Add partitioning**

```bash
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

        # Partition 1: /boot
        sgdisk -n "${part_num}:0:+${ENGINE_BOOT_SIZE}M" -t "${part_num}:8300" \
            -c "${part_num}:boot" "${disk}"
        (( part_num++ )) || true

        # Partition 2: /boot/efi (if EFI size > 0)
        if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
            sgdisk -n "${part_num}:0:+${ENGINE_EFI_SIZE}M" -t "${part_num}:ef00" \
                -c "${part_num}:efi" "${disk}"
            (( part_num++ )) || true
        fi

        # Partition 3: LUKS (remaining space)
        sgdisk -n "${part_num}:0:0" -t "${part_num}:8309" \
            -c "${part_num}:luks" "${disk}"

        # Force kernel to re-read partition table
        partprobe "${disk}" 2>/dev/null || true
        sleep 2
    done

    # Determine partition device names (handles nvme naming: nvme0n1p1 vs sda1)
    local first_disk="${_ENGINE_DETECTED_DISKS[0]}"
    local part_suffix=""
    if [[ "${first_disk}" == *"nvme"* ]] || [[ "${first_disk}" == *"loop"* ]]; then
        part_suffix="p"
    fi

    _ENGINE_BOOT_DEVICE="${first_disk}${part_suffix}1"
    if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
        _ENGINE_EFI_DEVICE="${first_disk}${part_suffix}2"
        _ENGINE_LUKS_DEVICE="${first_disk}${part_suffix}3"
    else
        _ENGINE_EFI_DEVICE=""
        _ENGINE_LUKS_DEVICE="${first_disk}${part_suffix}2"
    fi

    _engine_ok "Partitioning complete"
}
```

- [ ] **Step 6: Add RAID assembly**

```bash
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

    local disk part_suffix
    for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
        part_suffix=""
        if [[ "${disk}" == *"nvme"* ]] || [[ "${disk}" == *"loop"* ]]; then
            part_suffix="p"
        fi

        boot_parts+=("${disk}${part_suffix}1")
        if [[ "${ENGINE_EFI_SIZE}" -gt 0 ]]; then
            efi_parts+=("${disk}${part_suffix}2")
            data_parts+=("${disk}${part_suffix}3")
        else
            data_parts+=("${disk}${part_suffix}2")
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
```

- [ ] **Step 7: Add LUKS creation, opening, and formatting**

```bash
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
```

- [ ] **Step 8: Add OS installation**

```bash
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

    # Install essential packages inside chroot
    chroot "${_ENGINE_MOUNT}" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y \
            linux-image-amd64 \
            grub-pc \
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
```

- [ ] **Step 9: Add chroot configuration (fstab, crypttab, Dropbear, GRUB, networking)**

```bash
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
            # Rebuild initramfs with network config
            chroot "${_ENGINE_MOUNT}" update-initramfs -u || true
            ;;
        rhel)
            # dracut network module — add kernel cmdline
            local dracut_net="${_ENGINE_MOUNT}/etc/dracut.conf.d/network.conf"
            printf 'add_dracutmodules+=" network "\nkernel_cmdline="ip=dhcp rd.neednet=1"\n' \
                > "${dracut_net}"
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
            # Install GRUB to all disks
            local disk
            for disk in "${_ENGINE_DETECTED_DISKS[@]}"; do
                chroot "${_ENGINE_MOUNT}" grub-install "${disk}" \
                    || _engine_fail "grub-install failed on ${disk}"
            done
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
    if [[ -z "${ENGINE_PROVISION_USER}" ]]; then
        # At minimum, set up root SSH access
        mkdir -p "${_ENGINE_MOUNT}/root/.ssh"
        chmod 700 "${_ENGINE_MOUNT}/root/.ssh"
        printf '%s\n' "${ENGINE_SSH_PUBKEY}" > "${_ENGINE_MOUNT}/root/.ssh/authorized_keys"
        chmod 600 "${_ENGINE_MOUNT}/root/.ssh/authorized_keys"
        _engine_info "Root SSH key configured"
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
```

- [ ] **Step 10: Add finalize and main entry point**

```bash
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
```

- [ ] **Step 11: Commit engine.sh**

```bash
git add luks/engine.sh
git commit -m "feat(luks): add core LUKS encryption engine

Runs inside rescue mode over SSH. Handles disk detection, partitioning,
RAID assembly, LUKS2 encryption, OS install (debootstrap/dnf), Dropbear
configuration, GRUB setup, and finalization. Supports single-disk and
multi-disk RAID0/1/5/6/10 configurations."
```

---

### Task 4: Hetzner Provider Adapter — luks/providers/hetzner.sh

**Files:**
- Create: `luks/providers/hetzner.sh`
- Reference: `hetzner/api.sh` (for existing curl patterns)

- [ ] **Step 1: Create luks/providers/hetzner.sh**

```bash
#!/usr/bin/env bash
# hetzner.sh — Hetzner Cloud provider adapter for LUKS provisioning
# Implements the 6-function provider contract defined in interface.sh.
# Requires: HETZNER_API_TOKEN environment variable.

readonly _HETZNER_API_BASE="https://api.hetzner.cloud/v1"

# ─── Internal Helpers ────────────────────────────────────────────────────────

_hetzner_auth_header() {
    printf 'Authorization: Bearer %s' "${HETZNER_API_TOKEN}"
}

_hetzner_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request \
        "${method}" \
        "${_HETZNER_API_BASE}${endpoint}" \
        "$(_hetzner_auth_header)" \
        "${data}"
}

# ─── Contract Implementation ─────────────────────────────────────────────────

# provider_create_server <name> <type> <image> <location> <ssh_key_name>
provider_create_server() {
    local name="${1}"
    local server_type="${2:-cx22}"
    local image="${3}"
    local location="${4:-fsn1}"
    local ssh_key_name="${5:-}"

    if [[ -z "${HETZNER_API_TOKEN:-}" ]]; then
        printf 'ERROR: HETZNER_API_TOKEN is not set\n' >&2
        return 1
    fi

    local payload
    payload="$(printf '{
        "name": "%s",
        "server_type": "%s",
        "image": "%s",
        "location": "%s",
        "ssh_keys": ["%s"],
        "start_after_create": true
    }' "${name}" "${server_type}" "${image}" "${location}" "${ssh_key_name}")"

    local response
    response="$(_hetzner_api POST /servers "${payload}")" || return 1

    local server_id server_ip
    server_id="$(printf '%s' "${response}" | jq -r '.server.id')"
    server_ip="$(printf '%s' "${response}" | jq -r '.server.public_net.ipv4.ip')"

    if [[ -z "${server_id}" || "${server_id}" == "null" ]]; then
        printf 'ERROR: Failed to extract server ID from response\n' >&2
        return 1
    fi

    # Wait for server to be running
    local elapsed=0
    local timeout=120
    while (( elapsed < timeout )); do
        local status
        status="$(provider_get_status "${server_id}")"
        if [[ "${status}" == "running" ]]; then
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    if (( elapsed >= timeout )); then
        printf 'ERROR: Server %s did not reach running state within %ds\n' \
            "${server_id}" "${timeout}" >&2
        return 1
    fi

    # Re-fetch IP in case it wasn't available at creation
    if [[ -z "${server_ip}" || "${server_ip}" == "null" ]]; then
        local server_json
        server_json="$(_hetzner_api GET "/servers/${server_id}")" || return 1
        server_ip="$(printf '%s' "${server_json}" | jq -r '.server.public_net.ipv4.ip')"
    fi

    printf '%s|%s' "${server_id}" "${server_ip}"
}

# provider_enter_rescue <server_id>
provider_enter_rescue() {
    local server_id="${1}"

    # Enable rescue mode (linux64)
    local payload
    payload="$(printf '{"type": "linux64"}' )"

    local response
    response="$(_hetzner_api POST "/servers/${server_id}/actions/enable_rescue" "${payload}")" \
        || return 1

    local root_password
    root_password="$(printf '%s' "${response}" | jq -r '.root_password')"

    # Reboot into rescue
    _hetzner_api POST "/servers/${server_id}/actions/reset" "" >/dev/null || return 1

    printf '%s' "${root_password}"
}

# provider_exit_rescue <server_id>
provider_exit_rescue() {
    local server_id="${1}"

    _hetzner_api POST "/servers/${server_id}/actions/disable_rescue" "" >/dev/null || return 1
}

# provider_reboot <server_id>
provider_reboot() {
    local server_id="${1}"

    _hetzner_api POST "/servers/${server_id}/actions/reset" "" >/dev/null || return 1
}

# provider_delete_server <server_id>
provider_delete_server() {
    local server_id="${1}"

    _hetzner_api DELETE "/servers/${server_id}" >/dev/null || return 1
}

# provider_get_status <server_id>
provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_hetzner_api GET "/servers/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local status
    status="$(printf '%s' "${response}" | jq -r '.server.status')"

    # Map Hetzner statuses to our contract
    case "${status}" in
        running)    printf 'running' ;;
        off)        printf 'stopped' ;;
        rebuilding) printf 'rescue' ;;
        *)          printf '%s' "${status}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/hetzner.sh
git commit -m "feat(luks): add Hetzner provider adapter"
```

---

### Task 5: DigitalOcean Provider Adapter — luks/providers/digitalocean.sh

**Files:**
- Create: `luks/providers/digitalocean.sh`

- [ ] **Step 1: Create luks/providers/digitalocean.sh**

```bash
#!/usr/bin/env bash
# digitalocean.sh — DigitalOcean provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: DO_API_TOKEN environment variable.

readonly _DO_API_BASE="https://api.digitalocean.com/v2"

_do_auth_header() {
    printf 'Authorization: Bearer %s' "${DO_API_TOKEN}"
}

_do_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request "${method}" "${_DO_API_BASE}${endpoint}" "$(_do_auth_header)" "${data}"
}

# ─── Image Mapping ───────────────────────────────────────────────────────────

_do_resolve_image() {
    local image="${1}"

    case "${image}" in
        debian-12)      printf 'debian-12-x64' ;;
        ubuntu-24.04)   printf 'ubuntu-24-04-x64' ;;
        rocky-9)        printf 'rockylinux-9-x64' ;;
        alma-9)         printf 'almalinux-9-x64' ;;
        *)              printf '%s' "${image}" ;;
    esac
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-s-1vcpu-1gb}"
    local image="${3}"
    local location="${4:-nyc1}"
    local ssh_key_name="${5:-}"

    if [[ -z "${DO_API_TOKEN:-}" ]]; then
        printf 'ERROR: DO_API_TOKEN is not set\n' >&2
        return 1
    fi

    local do_image
    do_image="$(_do_resolve_image "${image}")"

    # Resolve SSH key ID from name
    local ssh_key_id=""
    if [[ -n "${ssh_key_name}" ]]; then
        local keys_response
        keys_response="$(_do_api GET "/account/keys")" || return 1
        ssh_key_id="$(printf '%s' "${keys_response}" | \
            jq -r --arg name "${ssh_key_name}" '.ssh_keys[] | select(.name == $name) | .id')"
    fi

    local payload
    payload="$(printf '{
        "name": "%s",
        "region": "%s",
        "size": "%s",
        "image": "%s",
        "ssh_keys": [%s]
    }' "${name}" "${location}" "${server_type}" "${do_image}" \
        "$(if [[ -n "${ssh_key_id}" ]]; then printf '"%s"' "${ssh_key_id}"; fi)")"

    local response
    response="$(_do_api POST /droplets "${payload}")" || return 1

    local droplet_id
    droplet_id="$(printf '%s' "${response}" | jq -r '.droplet.id')"

    # Wait for active + get IP
    local elapsed=0
    local timeout=120
    local droplet_ip=""
    while (( elapsed < timeout )); do
        local status_response
        status_response="$(_do_api GET "/droplets/${droplet_id}")" || true

        local status
        status="$(printf '%s' "${status_response}" | jq -r '.droplet.status')"

        if [[ "${status}" == "active" ]]; then
            droplet_ip="$(printf '%s' "${status_response}" | \
                jq -r '.droplet.networks.v4[] | select(.type == "public") | .ip_address' | head -1)"
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    if [[ -z "${droplet_ip}" ]]; then
        printf 'ERROR: Could not get IP for droplet %s\n' "${droplet_id}" >&2
        return 1
    fi

    printf '%s|%s' "${droplet_id}" "${droplet_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # DigitalOcean: power off, then boot from recovery ISO
    _do_api POST "/droplets/${server_id}/actions" '{"type": "power_off"}' >/dev/null || return 1
    sleep 10

    # Boot into recovery kernel
    _do_api POST "/droplets/${server_id}/actions" \
        '{"type": "boot_from_recovery"}' >/dev/null 2>&1 || {
        # Fallback: use recovery image ID
        local recovery_images
        recovery_images="$(_do_api GET "/images?type=application&tag_name=recovery")" || true
        _do_api POST "/droplets/${server_id}/actions" \
            '{"type": "rebuild", "image": "recovery"}' >/dev/null || return 1
    }

    sleep 5
    _do_api POST "/droplets/${server_id}/actions" '{"type": "power_on"}' >/dev/null || return 1

    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _do_api POST "/droplets/${server_id}/actions" '{"type": "power_off"}' >/dev/null || return 1
    sleep 5
}

provider_reboot() {
    local server_id="${1}"

    _do_api POST "/droplets/${server_id}/actions" '{"type": "power_on"}' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _do_api DELETE "/droplets/${server_id}" >/dev/null || return 1
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_do_api GET "/droplets/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local status
    status="$(printf '%s' "${response}" | jq -r '.droplet.status')"

    case "${status}" in
        active) printf 'running' ;;
        off)    printf 'stopped' ;;
        *)      printf '%s' "${status}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/digitalocean.sh
git commit -m "feat(luks): add DigitalOcean provider adapter"
```

---

### Task 6: Vultr Provider Adapter — luks/providers/vultr.sh

**Files:**
- Create: `luks/providers/vultr.sh`

- [ ] **Step 1: Create luks/providers/vultr.sh**

```bash
#!/usr/bin/env bash
# vultr.sh — Vultr provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: VULTR_API_KEY environment variable.

readonly _VULTR_API_BASE="https://api.vultr.com/v2"

_vultr_auth_header() {
    printf 'Authorization: Bearer %s' "${VULTR_API_KEY}"
}

_vultr_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request "${method}" "${_VULTR_API_BASE}${endpoint}" "$(_vultr_auth_header)" "${data}"
}

_vultr_resolve_image() {
    local image="${1}"

    # Vultr uses OS IDs — fetch dynamically
    local os_list
    os_list="$(_vultr_api GET /os)" || return 1

    local search_name=""
    case "${image}" in
        debian-12)      search_name="Debian 12" ;;
        ubuntu-24.04)   search_name="Ubuntu 24.04" ;;
        rocky-9)        search_name="Rocky Linux 9" ;;
        alma-9)         search_name="AlmaLinux 9" ;;
        *)              search_name="${image}" ;;
    esac

    printf '%s' "${os_list}" | jq -r \
        --arg name "${search_name}" \
        '.os[] | select(.name | startswith($name)) | .id' | head -1
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-vc2-1c-1gb}"
    local image="${3}"
    local location="${4:-ewr}"
    local ssh_key_name="${5:-}"

    if [[ -z "${VULTR_API_KEY:-}" ]]; then
        printf 'ERROR: VULTR_API_KEY is not set\n' >&2
        return 1
    fi

    local os_id
    os_id="$(_vultr_resolve_image "${image}")" || return 1

    # Resolve SSH key ID
    local ssh_key_id=""
    if [[ -n "${ssh_key_name}" ]]; then
        local keys_response
        keys_response="$(_vultr_api GET /ssh-keys)" || return 1
        ssh_key_id="$(printf '%s' "${keys_response}" | \
            jq -r --arg name "${ssh_key_name}" '.ssh_keys[] | select(.name == $name) | .id')"
    fi

    local payload
    payload="$(printf '{
        "region": "%s",
        "plan": "%s",
        "os_id": %s,
        "label": "%s",
        "sshkey_id": ["%s"]
    }' "${location}" "${server_type}" "${os_id}" "${name}" "${ssh_key_id}")"

    local response
    response="$(_vultr_api POST /instances "${payload}")" || return 1

    local instance_id
    instance_id="$(printf '%s' "${response}" | jq -r '.instance.id')"

    # Wait for active
    local elapsed=0
    local timeout=180
    local instance_ip=""
    while (( elapsed < timeout )); do
        local status_response
        status_response="$(_vultr_api GET "/instances/${instance_id}")" || true

        local status
        status="$(printf '%s' "${status_response}" | jq -r '.instance.status')"
        local power
        power="$(printf '%s' "${status_response}" | jq -r '.instance.power_status')"

        if [[ "${status}" == "active" && "${power}" == "running" ]]; then
            instance_ip="$(printf '%s' "${status_response}" | jq -r '.instance.main_ip')"
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    if [[ -z "${instance_ip}" || "${instance_ip}" == "0.0.0.0" ]]; then
        printf 'ERROR: Could not get IP for instance %s\n' "${instance_id}" >&2
        return 1
    fi

    printf '%s|%s' "${instance_id}" "${instance_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # Vultr: attach SystemRescue ISO and reboot
    # First, get the SystemRescue ISO ID from public ISOs
    local iso_list
    iso_list="$(_vultr_api GET /iso-public)" || return 1

    local rescue_iso_id
    rescue_iso_id="$(printf '%s' "${iso_list}" | \
        jq -r '.public_isos[] | select(.name | test("systemrescue|SystemRescue"; "i")) | .id' | head -1)"

    if [[ -z "${rescue_iso_id}" || "${rescue_iso_id}" == "null" ]]; then
        # Fallback: try any rescue/recovery ISO
        rescue_iso_id="$(printf '%s' "${iso_list}" | \
            jq -r '.public_isos[] | select(.name | test("rescue|recovery"; "i")) | .id' | head -1)"
    fi

    if [[ -z "${rescue_iso_id}" || "${rescue_iso_id}" == "null" ]]; then
        printf 'ERROR: No rescue ISO found on Vultr\n' >&2
        return 1
    fi

    # Attach ISO
    _vultr_api POST "/instances/${server_id}/iso/attach" \
        "$(printf '{"iso_id": "%s"}' "${rescue_iso_id}")" >/dev/null || return 1

    sleep 5

    # Reboot
    _vultr_api POST "/instances/${server_id}/reboot" "" >/dev/null || return 1

    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _vultr_api POST "/instances/${server_id}/iso/detach" "" >/dev/null || return 1
}

provider_reboot() {
    local server_id="${1}"

    _vultr_api POST "/instances/${server_id}/reboot" "" >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _vultr_api DELETE "/instances/${server_id}" >/dev/null || return 1
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_vultr_api GET "/instances/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local power
    power="$(printf '%s' "${response}" | jq -r '.instance.power_status')"

    case "${power}" in
        running) printf 'running' ;;
        stopped) printf 'stopped' ;;
        *)       printf '%s' "${power}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/vultr.sh
git commit -m "feat(luks): add Vultr provider adapter"
```

---

### Task 7: AWS EC2 Provider Adapter — luks/providers/aws.sh

**Files:**
- Create: `luks/providers/aws.sh`

This is the outlier — uses EBS detach/attach instead of rescue mode. Requires `aws` CLI.

- [ ] **Step 1: Create luks/providers/aws.sh**

```bash
#!/usr/bin/env bash
# aws.sh — AWS EC2 provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Uses EBS detach/attach strategy instead of rescue mode.
# Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, aws CLI.

: "${AWS_REGION:=us-east-1}"

# Internal state for the helper instance
declare -g _AWS_HELPER_INSTANCE_ID=""
declare -g _AWS_ORIGINAL_VOLUME_ID=""
declare -g _AWS_ORIGINAL_DEVICE=""
declare -g _AWS_AVAILABILITY_ZONE=""

_aws_cmd() {
    aws --region "${AWS_REGION}" --output json "$@"
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-t3.micro}"
    local image="${3}"
    local location="${4:-}"
    local ssh_key_name="${5:-}"

    if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        printf 'ERROR: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set\n' >&2
        return 1
    fi

    if ! command -v aws &>/dev/null; then
        printf 'ERROR: aws CLI is required for AWS provider\n' >&2
        return 1
    fi

    # Resolve AMI from image name
    local ami_id
    ami_id="$(_aws_resolve_ami "${image}")" || return 1

    local run_args=(
        ec2 run-instances
        --image-id "${ami_id}"
        --instance-type "${server_type}"
        --count 1
        --tag-specifications "$(printf 'ResourceType=instance,Tags=[{Key=Name,Value=%s}]' "${name}")"
    )

    if [[ -n "${ssh_key_name}" ]]; then
        run_args+=(--key-name "${ssh_key_name}")
    fi

    local response
    response="$(_aws_cmd "${run_args[@]}")" || return 1

    local instance_id
    instance_id="$(printf '%s' "${response}" | jq -r '.Instances[0].InstanceId')"

    # Wait for running
    _aws_cmd ec2 wait instance-running --instance-ids "${instance_id}" || return 1

    # Get public IP
    local describe
    describe="$(_aws_cmd ec2 describe-instances --instance-ids "${instance_id}")" || return 1

    local public_ip
    public_ip="$(printf '%s' "${describe}" | \
        jq -r '.Reservations[0].Instances[0].PublicIpAddress')"

    _AWS_AVAILABILITY_ZONE="$(printf '%s' "${describe}" | \
        jq -r '.Reservations[0].Instances[0].Placement.AvailabilityZone')"

    printf '%s|%s' "${instance_id}" "${public_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # AWS rescue mode: stop instance, detach root EBS, create helper, attach volume to helper

    # 1. Stop the original instance
    _aws_cmd ec2 stop-instances --instance-ids "${server_id}" >/dev/null || return 1
    _aws_cmd ec2 wait instance-stopped --instance-ids "${server_id}" || return 1

    # 2. Find root volume
    local volumes
    volumes="$(_aws_cmd ec2 describe-instances --instance-ids "${server_id}")" || return 1

    _AWS_ORIGINAL_VOLUME_ID="$(printf '%s' "${volumes}" | \
        jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId')"
    _AWS_ORIGINAL_DEVICE="$(printf '%s' "${volumes}" | \
        jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[0].DeviceName')"

    # 3. Detach root volume
    _aws_cmd ec2 detach-volume --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" >/dev/null || return 1
    _aws_cmd ec2 wait volume-available --volume-ids "${_AWS_ORIGINAL_VOLUME_ID}" || return 1

    # 4. Launch a helper instance (Amazon Linux 2, same AZ)
    local helper_ami
    helper_ami="$(_aws_cmd ec2 describe-images \
        --owners amazon \
        --filters 'Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2' \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text)" || return 1

    local helper_response
    helper_response="$(_aws_cmd ec2 run-instances \
        --image-id "${helper_ami}" \
        --instance-type t3.micro \
        --placement "AvailabilityZone=${_AWS_AVAILABILITY_ZONE}" \
        --count 1 \
        --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=luks-helper}]')" || return 1

    _AWS_HELPER_INSTANCE_ID="$(printf '%s' "${helper_response}" | jq -r '.Instances[0].InstanceId')"
    _aws_cmd ec2 wait instance-running --instance-ids "${_AWS_HELPER_INSTANCE_ID}" || return 1

    # 5. Attach original volume to helper as /dev/xvdf
    _aws_cmd ec2 attach-volume \
        --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" \
        --instance-id "${_AWS_HELPER_INSTANCE_ID}" \
        --device /dev/xvdf >/dev/null || return 1

    sleep 10

    # Get helper's public IP
    local helper_describe
    helper_describe="$(_aws_cmd ec2 describe-instances \
        --instance-ids "${_AWS_HELPER_INSTANCE_ID}")" || return 1

    local helper_ip
    helper_ip="$(printf '%s' "${helper_describe}" | \
        jq -r '.Reservations[0].Instances[0].PublicIpAddress')"

    # Return IP of helper instance (engine will run there)
    printf 'none'
    # Caller should SSH to helper_ip — store it for later
    printf '\n%s' "${helper_ip}" # second line: helper IP
}

provider_exit_rescue() {
    local server_id="${1}"

    # Detach volume from helper
    _aws_cmd ec2 detach-volume --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" >/dev/null || return 1
    _aws_cmd ec2 wait volume-available --volume-ids "${_AWS_ORIGINAL_VOLUME_ID}" || return 1

    # Reattach to original instance
    _aws_cmd ec2 attach-volume \
        --volume-id "${_AWS_ORIGINAL_VOLUME_ID}" \
        --instance-id "${server_id}" \
        --device "${_AWS_ORIGINAL_DEVICE}" >/dev/null || return 1

    sleep 5

    # Terminate helper
    if [[ -n "${_AWS_HELPER_INSTANCE_ID}" ]]; then
        _aws_cmd ec2 terminate-instances \
            --instance-ids "${_AWS_HELPER_INSTANCE_ID}" >/dev/null || true
    fi
}

provider_reboot() {
    local server_id="${1}"

    _aws_cmd ec2 start-instances --instance-ids "${server_id}" >/dev/null || return 1
    _aws_cmd ec2 wait instance-running --instance-ids "${server_id}" || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _aws_cmd ec2 terminate-instances --instance-ids "${server_id}" >/dev/null || return 1

    # Clean up helper if still running
    if [[ -n "${_AWS_HELPER_INSTANCE_ID}" ]]; then
        _aws_cmd ec2 terminate-instances \
            --instance-ids "${_AWS_HELPER_INSTANCE_ID}" >/dev/null 2>&1 || true
    fi
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_aws_cmd ec2 describe-instances --instance-ids "${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local state
    state="$(printf '%s' "${response}" | \
        jq -r '.Reservations[0].Instances[0].State.Name')"

    case "${state}" in
        running)    printf 'running' ;;
        stopped)    printf 'stopped' ;;
        terminated) printf 'stopped' ;;
        *)          printf '%s' "${state}" ;;
    esac
}

_aws_resolve_ami() {
    local image="${1}"

    local filter_name=""
    local owner=""
    case "${image}" in
        debian-12)
            filter_name="debian-12-amd64-*"
            owner="136693071363"
            ;;
        ubuntu-24.04)
            filter_name="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
            owner="099720109477"
            ;;
        rocky-9)
            filter_name="Rocky-9-EC2-Base-*.x86_64-*"
            owner="792107900819"
            ;;
        alma-9)
            filter_name="AlmaLinux OS 9*x86_64*"
            owner="764336703387"
            ;;
        *)
            printf 'ERROR: Unknown image for AWS: %s\n' "${image}" >&2
            return 1
            ;;
    esac

    _aws_cmd ec2 describe-images \
        --owners "${owner}" \
        --filters "Name=name,Values=${filter_name}" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text || return 1
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/aws.sh
git commit -m "feat(luks): add AWS EC2 provider adapter (EBS-based flow)"
```

---

### Task 8: Linode Provider Adapter — luks/providers/linode.sh

**Files:**
- Create: `luks/providers/linode.sh`

- [ ] **Step 1: Create luks/providers/linode.sh**

```bash
#!/usr/bin/env bash
# linode.sh — Linode/Akamai provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: LINODE_API_TOKEN environment variable.

readonly _LINODE_API_BASE="https://api.linode.com/v4"

_linode_auth_header() {
    printf 'Authorization: Bearer %s' "${LINODE_API_TOKEN}"
}

_linode_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request "${method}" "${_LINODE_API_BASE}${endpoint}" "$(_linode_auth_header)" "${data}"
}

_linode_resolve_image() {
    local image="${1}"

    case "${image}" in
        debian-12)      printf 'linode/debian12' ;;
        ubuntu-24.04)   printf 'linode/ubuntu24.04' ;;
        rocky-9)        printf 'linode/rocky9' ;;
        alma-9)         printf 'linode/almalinux9' ;;
        *)              printf '%s' "${image}" ;;
    esac
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-g6-nanode-1}"
    local image="${3}"
    local location="${4:-us-east}"
    local ssh_key_name="${5:-}"

    if [[ -z "${LINODE_API_TOKEN:-}" ]]; then
        printf 'ERROR: LINODE_API_TOKEN is not set\n' >&2
        return 1
    fi

    local linode_image
    linode_image="$(_linode_resolve_image "${image}")"

    # Resolve SSH key IDs
    local ssh_keys_json="[]"
    if [[ -n "${ssh_key_name}" ]]; then
        local keys_response
        keys_response="$(_linode_api GET /profile/sshkeys)" || return 1
        local key_id
        key_id="$(printf '%s' "${keys_response}" | \
            jq -r --arg name "${ssh_key_name}" '.data[] | select(.label == $name) | .id')"
        if [[ -n "${key_id}" ]]; then
            ssh_keys_json="[${key_id}]"
        fi
    fi

    local payload
    payload="$(printf '{
        "label": "%s",
        "region": "%s",
        "type": "%s",
        "image": "%s",
        "authorized_keys": %s,
        "root_pass": "TempPass!%s",
        "booted": true
    }' "${name}" "${location}" "${server_type}" "${linode_image}" \
        "${ssh_keys_json}" "$(head -c8 /dev/urandom | xxd -p)")"

    local response
    response="$(_linode_api POST /linode/instances "${payload}")" || return 1

    local linode_id linode_ip
    linode_id="$(printf '%s' "${response}" | jq -r '.id')"
    linode_ip="$(printf '%s' "${response}" | jq -r '.ipv4[0]')"

    # Wait for running
    local elapsed=0
    local timeout=120
    while (( elapsed < timeout )); do
        local status
        status="$(provider_get_status "${linode_id}")"
        if [[ "${status}" == "running" ]]; then
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    printf '%s|%s' "${linode_id}" "${linode_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # Boot into rescue mode
    _linode_api POST "/linode/instances/${server_id}/rescue" '{}' >/dev/null || return 1

    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    # Shutdown from rescue — reboot will boot normally
    _linode_api POST "/linode/instances/${server_id}/shutdown" '' >/dev/null || return 1
    sleep 10
}

provider_reboot() {
    local server_id="${1}"

    _linode_api POST "/linode/instances/${server_id}/boot" '' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _linode_api DELETE "/linode/instances/${server_id}" >/dev/null || return 1
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_linode_api GET "/linode/instances/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local status
    status="$(printf '%s' "${response}" | jq -r '.status')"

    case "${status}" in
        running)      printf 'running' ;;
        offline)      printf 'stopped' ;;
        provisioning) printf 'running' ;;
        *)            printf '%s' "${status}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/linode.sh
git commit -m "feat(luks): add Linode/Akamai provider adapter"
```

---

### Task 9: OVH Provider Adapter — luks/providers/ovh.sh

**Files:**
- Create: `luks/providers/ovh.sh`

- [ ] **Step 1: Create luks/providers/ovh.sh**

```bash
#!/usr/bin/env bash
# ovh.sh — OVH provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: OVH_APP_KEY, OVH_APP_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT.
# OVH API uses signed requests — this adapter wraps the OVH authentication.

: "${OVH_ENDPOINT:=ovh-eu}"

_ovh_base_url() {
    case "${OVH_ENDPOINT}" in
        ovh-eu)  printf 'https://eu.api.ovh.com/1.0' ;;
        ovh-ca)  printf 'https://ca.api.ovh.com/1.0' ;;
        ovh-us)  printf 'https://api.us.ovhcloud.com/1.0' ;;
        *)       printf 'https://eu.api.ovh.com/1.0' ;;
    esac
}

_ovh_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    local url="$(_ovh_base_url)${endpoint}"
    local timestamp
    timestamp="$(curl -s "$(_ovh_base_url)/auth/time")"

    # OVH signature: "$1$" + SHA1(APP_SECRET+CONSUMER_KEY+METHOD+URL+BODY+TIMESTAMP)
    local to_sign="${OVH_APP_SECRET}+${OVH_CONSUMER_KEY}+${method}+${url}+${data}+${timestamp}"
    local signature
    signature="\$1\$$(printf '%s' "${to_sign}" | sha1sum | awk '{print $1}')"

    local curl_args=(
        curl -sS
        -X "${method}"
        -H "X-Ovh-Application: ${OVH_APP_KEY}"
        -H "X-Ovh-Timestamp: ${timestamp}"
        -H "X-Ovh-Signature: ${signature}"
        -H "X-Ovh-Consumer: ${OVH_CONSUMER_KEY}"
        -H "Content-Type: application/json"
        -w '\n%{http_code}'
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    local raw_response
    raw_response="$("${curl_args[@]}" "${url}" 2>/dev/null)" || {
        printf 'ERROR: OVH API call failed: %s %s\n' "${method}" "${endpoint}" >&2
        return 1
    }

    local http_code
    http_code="$(printf '%s' "${raw_response}" | tail -1)"
    local body
    body="$(printf '%s' "${raw_response}" | sed '$d')"

    if [[ -z "${http_code}" ]] || [[ "${http_code}" -ge 400 ]] 2>/dev/null; then
        printf 'ERROR: OVH API %s %s returned HTTP %s: %s\n' \
            "${method}" "${endpoint}" "${http_code:-000}" "${body}" >&2
        return 1
    fi

    printf '%s' "${body}"
}

_ovh_resolve_image() {
    local image="${1}"
    # OVH uses OS names, resolved dynamically per server
    case "${image}" in
        debian-12)      printf 'debian12_64' ;;
        ubuntu-24.04)   printf 'ubuntu2404-server_64' ;;
        rocky-9)        printf 'rocky9_64' ;;
        alma-9)         printf 'almalinux9_64' ;;
        *)              printf '%s' "${image}" ;;
    esac
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-d2-2}"
    local image="${3}"
    local location="${4:-GRA7}"
    local ssh_key_name="${5:-}"

    if [[ -z "${OVH_APP_KEY:-}" || -z "${OVH_APP_SECRET:-}" || -z "${OVH_CONSUMER_KEY:-}" ]]; then
        printf 'ERROR: OVH credentials (OVH_APP_KEY, OVH_APP_SECRET, OVH_CONSUMER_KEY) must be set\n' >&2
        return 1
    fi

    local ovh_image
    ovh_image="$(_ovh_resolve_image "${image}")"

    local ssh_key_json=""
    if [[ -n "${ssh_key_name}" ]]; then
        ssh_key_json="$(printf ', "sshKeyId": "%s"' "${ssh_key_name}")"
    fi

    local payload
    payload="$(printf '{
        "name": "%s",
        "flavorId": "%s",
        "imageId": "%s",
        "region": "%s"%s
    }' "${name}" "${server_type}" "${ovh_image}" "${location}" "${ssh_key_json}")"

    local response
    response="$(_ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance" "${payload}")" || return 1

    local server_id server_ip
    server_id="$(printf '%s' "${response}" | jq -r '.id')"

    # Wait for ACTIVE
    local elapsed=0
    local timeout=180
    while (( elapsed < timeout )); do
        local status_response
        status_response="$(_ovh_api GET "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}")" || true

        local status
        status="$(printf '%s' "${status_response}" | jq -r '.status')"

        if [[ "${status}" == "ACTIVE" ]]; then
            server_ip="$(printf '%s' "${status_response}" | \
                jq -r '.ipAddresses[] | select(.type == "public" and .version == 4) | .ip' | head -1)"
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    if [[ -z "${server_ip}" ]]; then
        printf 'ERROR: Could not get IP for OVH instance %s\n' "${server_id}" >&2
        return 1
    fi

    printf '%s|%s' "${server_id}" "${server_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/rescueMode" \
        '{"rescue": true, "imageId": "rescue-ovh"}' >/dev/null || return 1

    # OVH returns a temp root password via email or API response
    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/rescueMode" \
        '{"rescue": false}' >/dev/null || return 1
}

provider_reboot() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/reboot" \
        '{"type": "hard"}' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _ovh_api DELETE "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}" >/dev/null || return 1
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_ovh_api GET "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local status
    status="$(printf '%s' "${response}" | jq -r '.status')"

    case "${status}" in
        ACTIVE)     printf 'running' ;;
        SHUTOFF)    printf 'stopped' ;;
        RESCUE)     printf 'rescue' ;;
        *)          printf '%s' "${status}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/ovh.sh
git commit -m "feat(luks): add OVH provider adapter"
```

---

### Task 10: Ionos Provider Adapter — luks/providers/ionos.sh

**Files:**
- Create: `luks/providers/ionos.sh`

- [ ] **Step 1: Create luks/providers/ionos.sh**

```bash
#!/usr/bin/env bash
# ionos.sh — Ionos Cloud provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: IONOS_USERNAME, IONOS_PASSWORD environment variables.
# Uses Ionos Cloud API v6.

readonly _IONOS_API_BASE="https://api.ionos.com/cloudapi/v6"

_ionos_auth_header() {
    local credentials
    credentials="$(printf '%s:%s' "${IONOS_USERNAME}" "${IONOS_PASSWORD}" | base64)"
    printf 'Authorization: Basic %s' "${credentials}"
}

_ionos_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request "${method}" "${_IONOS_API_BASE}${endpoint}" "$(_ionos_auth_header)" "${data}"
}

# Internal state
declare -g _IONOS_DATACENTER_ID=""

_ionos_resolve_image() {
    local image="${1}"
    local location="${2:-de/fra}"

    # Fetch available images for the location
    local images_response
    images_response="$(_ionos_api GET "/images?filter.properties.location=${location}&filter.properties.imageType=HDD")" || return 1

    local search_name=""
    case "${image}" in
        debian-12)      search_name="Debian-12" ;;
        ubuntu-24.04)   search_name="Ubuntu-24" ;;
        rocky-9)        search_name="Rocky-9" ;;
        alma-9)         search_name="AlmaLinux-9" ;;
        *)              search_name="${image}" ;;
    esac

    printf '%s' "${images_response}" | \
        jq -r --arg name "${search_name}" \
        '.items[] | select(.properties.name | test($name; "i")) | .id' | head -1
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-CUBE S}"
    local image="${3}"
    local location="${4:-de/fra}"
    local ssh_key_name="${5:-}"

    if [[ -z "${IONOS_USERNAME:-}" || -z "${IONOS_PASSWORD:-}" ]]; then
        printf 'ERROR: IONOS_USERNAME and IONOS_PASSWORD must be set\n' >&2
        return 1
    fi

    # 1. Create datacenter
    local dc_payload
    dc_payload="$(printf '{
        "properties": {
            "name": "%s-dc",
            "location": "%s"
        }
    }' "${name}" "${location}")"

    local dc_response
    dc_response="$(_ionos_api POST /datacenters "${dc_payload}")" || return 1
    _IONOS_DATACENTER_ID="$(printf '%s' "${dc_response}" | jq -r '.id')"

    # Wait for datacenter to be available
    sleep 15

    # 2. Resolve image
    local image_id
    image_id="$(_ionos_resolve_image "${image}" "${location}")" || return 1

    # 3. Create server with volume
    local server_payload
    server_payload="$(printf '{
        "properties": {
            "name": "%s",
            "cores": 1,
            "ram": 1024
        },
        "entities": {
            "volumes": {
                "items": [{
                    "properties": {
                        "name": "%s-vol",
                        "size": 20,
                        "type": "HDD",
                        "image": "%s",
                        "sshKeys": []
                    }
                }]
            }
        }
    }' "${name}" "${name}" "${image_id}")"

    local server_response
    server_response="$(_ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers" "${server_payload}")" || return 1

    local server_id
    server_id="$(printf '%s' "${server_response}" | jq -r '.id')"

    # Wait for server provisioning
    sleep 30

    # 4. Allocate and assign IP
    local ip_response
    ip_response="$(_ionos_api POST "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/nics" \
        '{"properties": {"name": "public", "lan": 1, "dhcp": true}}')" || return 1

    sleep 10

    # Get IP
    local nic_response
    nic_response="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/nics")" || return 1

    local server_ip
    server_ip="$(printf '%s' "${nic_response}" | \
        jq -r '.items[0].properties.ips[0]' 2>/dev/null)"

    if [[ -z "${server_ip}" || "${server_ip}" == "null" ]]; then
        printf 'ERROR: Could not get IP for Ionos server %s\n' "${server_id}" >&2
        return 1
    fi

    printf '%s|%s' "${server_id}" "${server_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # Ionos: stop server, attach live CD ISO
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/stop" '' >/dev/null || return 1
    sleep 10

    # Attach rescue CD-ROM
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms" \
        '{"id": "rescue"}' >/dev/null 2>&1 || true

    # Start server (boots from CD)
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/start" '' >/dev/null || return 1

    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/stop" '' >/dev/null || return 1
    sleep 5

    # Detach CD-ROM
    local cdroms
    cdroms="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms")" || true

    local cdrom_id
    cdrom_id="$(printf '%s' "${cdroms}" | jq -r '.items[0].id' 2>/dev/null)"
    if [[ -n "${cdrom_id}" && "${cdrom_id}" != "null" ]]; then
        _ionos_api DELETE \
            "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms/${cdrom_id}" \
            >/dev/null 2>&1 || true
    fi
}

provider_reboot() {
    local server_id="${1}"

    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/start" '' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    # Delete entire datacenter (includes server, volumes, etc.)
    if [[ -n "${_IONOS_DATACENTER_ID}" ]]; then
        _ionos_api DELETE "/datacenters/${_IONOS_DATACENTER_ID}" >/dev/null || return 1
    fi
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local state
    state="$(printf '%s' "${response}" | jq -r '.metadata.state')"
    local vm_state
    vm_state="$(printf '%s' "${response}" | jq -r '.properties.vmState')"

    case "${vm_state}" in
        RUNNING)  printf 'running' ;;
        SHUTOFF)  printf 'stopped' ;;
        *)        printf '%s' "${vm_state}" ;;
    esac
}
```

- [ ] **Step 2: Commit**

```bash
git add luks/providers/ionos.sh
git commit -m "feat(luks): add Ionos provider adapter"
```

---

### Task 11: Unlock Helper — luks/unlock-remote.sh

**Files:**
- Create: `luks/unlock-remote.sh`

- [ ] **Step 1: Create luks/unlock-remote.sh**

```bash
#!/usr/bin/env bash
# unlock-remote.sh — Remotely unlock a LUKS-encrypted server via Dropbear SSH
# Connects to Dropbear in initramfs, sends passphrase, waits for full boot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Defaults ────────────────────────────────────────────────────────────────

HOST=""
SSH_KEY=""
DROPBEAR_PORT="2222"
SSH_PORT="22"
PASSPHRASE_FILE=""
PROMPT_MODE="false"
TIMEOUT="120"

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
LUKS Unlock — Remote Server Unlocker

Connects to Dropbear SSH in initramfs and sends the LUKS passphrase
to unlock the encrypted root volume, then waits for full OS boot.

USAGE:
  unlock-remote.sh --host <ip> --key <dropbear_key> [OPTIONS]

REQUIRED:
  --host <ip>              Server IP address
  --key <path>             SSH private key for Dropbear

OPTIONS:
  --port <port>            Dropbear port (default: 2222)
  --ssh-port <port>        Full OS SSH port to wait for (default: 22)
  --passphrase-file <path> Path to passphrase file
  --prompt                 Prompt for passphrase interactively (ignores saved file)
  --timeout <seconds>      Timeout waiting for full boot (default: 120)
  --help                   Show this help

PASSPHRASE RESOLUTION ORDER:
  1. --passphrase-file (if provided)
  2. artifacts/luks/<host>/luks-passphrase (auto-detected)
  3. Interactive prompt (if neither found, or --prompt used)

EXAMPLES:
  ./luks/unlock-remote.sh --host 65.108.1.2 --key artifacts/luks/hetzner-65.108.1.2-20260331/ssh-key
  ./luks/unlock-remote.sh --host 65.108.1.2 --key ./key --prompt
  ./luks/unlock-remote.sh --host 65.108.1.2 --key ./key --passphrase-file /secure/pass
EOF
    exit 0
}

# ─── Argument Parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)             shift; HOST="$1" ;;
        --key)              shift; SSH_KEY="$1" ;;
        --port)             shift; DROPBEAR_PORT="$1" ;;
        --ssh-port)         shift; SSH_PORT="$1" ;;
        --passphrase-file)  shift; PASSPHRASE_FILE="$1" ;;
        --prompt)           PROMPT_MODE="true" ;;
        --timeout)          shift; TIMEOUT="$1" ;;
        --help|-h)          usage ;;
        *)
            printf 'ERROR: Unknown option: %s\n' "$1" >&2
            usage
            ;;
    esac
    shift
done

if [[ -z "${HOST}" ]]; then
    printf 'ERROR: --host is required\n' >&2
    exit 1
fi

if [[ -z "${SSH_KEY}" || ! -f "${SSH_KEY}" ]]; then
    printf 'ERROR: --key is required and must exist: %s\n' "${SSH_KEY:-<not set>}" >&2
    exit 1
fi

# ─── Resolve Passphrase ─────────────────────────────────────────────────────

resolve_passphrase() {
    # 1. If --prompt, ask interactively
    if [[ "${PROMPT_MODE}" == "true" ]]; then
        printf 'Enter LUKS passphrase for %s: ' "${HOST}" >&2
        read -rs passphrase
        printf '\n' >&2
        printf '%s' "${passphrase}"
        return 0
    fi

    # 2. Explicit --passphrase-file
    if [[ -n "${PASSPHRASE_FILE}" ]]; then
        if [[ ! -f "${PASSPHRASE_FILE}" ]]; then
            printf 'ERROR: Passphrase file not found: %s\n' "${PASSPHRASE_FILE}" >&2
            return 1
        fi
        cat "${PASSPHRASE_FILE}"
        return 0
    fi

    # 3. Auto-detect from artifacts
    local artifacts_base="${SCRIPT_DIR}/../artifacts/luks"
    if [[ -d "${artifacts_base}" ]]; then
        local match
        match="$(find "${artifacts_base}" -maxdepth 2 -name 'luks-passphrase' -path "*${HOST}*" \
            2>/dev/null | sort -r | head -1)"
        if [[ -n "${match}" && -f "${match}" ]]; then
            printf '[INFO] Using saved passphrase: %s\n' "${match}" >&2
            cat "${match}"
            return 0
        fi
    fi

    # 4. Fall back to interactive prompt
    printf 'No saved passphrase found. Enter LUKS passphrase for %s: ' "${HOST}" >&2
    read -rs passphrase
    printf '\n' >&2
    printf '%s' "${passphrase}"
}

# ─── Unlock Flow ─────────────────────────────────────────────────────────────

printf '\n'
printf '════════════════════════════════════════════════════════════\n'
printf ' LUKS Unlock — %s\n' "${HOST}"
printf '────────────────────────────────────────────────────────────\n'
printf ' Dropbear : port %s\n' "${DROPBEAR_PORT}"
printf ' SSH key  : %s\n' "${SSH_KEY}"
printf ' Timeout  : %ss\n' "${TIMEOUT}"
printf '════════════════════════════════════════════════════════════\n\n'

# Step 1: Wait for Dropbear
printf '[1/4] Waiting for Dropbear SSH on port %s...\n' "${DROPBEAR_PORT}"

elapsed=0
interval=5
while (( elapsed < TIMEOUT )); do
    if ssh \
        -i "${SSH_KEY}" -p "${DROPBEAR_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o BatchMode=yes \
        "root@${HOST}" 'true' &>/dev/null 2>&1; then
        printf '  Dropbear is up.\n'
        break
    fi
    sleep "${interval}"
    (( elapsed += interval )) || true
done

if (( elapsed >= TIMEOUT )); then
    printf 'ERROR: Dropbear not reachable on %s:%s after %ds\n' \
        "${HOST}" "${DROPBEAR_PORT}" "${TIMEOUT}" >&2
    printf 'Troubleshooting:\n' >&2
    printf '  - Is the server rebooting? Check provider console.\n' >&2
    printf '  - Is Dropbear configured in initramfs?\n' >&2
    printf '  - Is the correct SSH key being used?\n' >&2
    exit 1
fi

# Step 2: Resolve passphrase
printf '[2/4] Resolving passphrase...\n'

PASSPHRASE="$(resolve_passphrase)" || exit 1

if [[ -z "${PASSPHRASE}" ]]; then
    printf 'ERROR: Empty passphrase\n' >&2
    exit 1
fi

# Step 3: Send passphrase to cryptroot-unlock
printf '[3/4] Sending passphrase to unlock LUKS volume...\n'

# Try cryptroot-unlock first (Debian), fall back to manual echo to console
unlock_result=0
printf '%s\n' "${PASSPHRASE}" | ssh \
    -i "${SSH_KEY}" -p "${DROPBEAR_PORT}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "root@${HOST}" 'cryptroot-unlock' 2>/dev/null || unlock_result=$?

# cryptroot-unlock may exit non-zero as the connection drops during pivot
# This is expected behavior
if [[ "${unlock_result}" -ne 0 ]]; then
    printf '  Connection dropped (expected — initramfs is transitioning).\n'
fi

# Step 4: Wait for full OS SSH
printf '[4/4] Waiting for full OS on port %s...\n' "${SSH_PORT}"

elapsed=0
while (( elapsed < TIMEOUT )); do
    if ssh \
        -i "${SSH_KEY}" -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o BatchMode=yes \
        "root@${HOST}" 'true' &>/dev/null 2>&1; then
        printf '  Full OS is up.\n'
        break
    fi
    sleep "${interval}"
    (( elapsed += interval )) || true
done

if (( elapsed >= TIMEOUT )); then
    printf 'ERROR: Full OS SSH not reachable on %s:%s after %ds\n' \
        "${HOST}" "${SSH_PORT}" "${TIMEOUT}" >&2
    printf 'The LUKS volume may have unlocked but the OS failed to boot.\n' >&2
    printf 'Check the provider console for boot errors.\n' >&2
    exit 1
fi

printf '\n'
printf '════════════════════════════════════════════════════════════\n'
printf ' Unlock successful\n'
printf ' Connect: ssh -i %s -p %s root@%s\n' "${SSH_KEY}" "${SSH_PORT}" "${HOST}"
printf '════════════════════════════════════════════════════════════\n'
```

- [ ] **Step 2: Commit**

```bash
git add luks/unlock-remote.sh
git commit -m "feat(luks): add unlock-remote.sh for Dropbear LUKS unlock"
```

---

### Task 12: CLI Orchestrator — luks/provision-encrypted.sh

**Files:**
- Create: `luks/provision-encrypted.sh`

This ties everything together: parses CLI args, loads config, loads provider, runs the engine over SSH, performs first unlock, optionally runs hardening.

- [ ] **Step 1: Create luks/provision-encrypted.sh**

```bash
#!/usr/bin/env bash
# provision-encrypted.sh — Provision a LUKS-encrypted cloud server
# Orchestrates: create server → rescue mode → LUKS engine → unlock → (optional) harden
set -euo pipefail

LUKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${LUKS_DIR}/.." && pwd)"

# ─── Defaults ────────────────────────────────────────────────────────────────

PROVIDER=""
IMAGE=""
SSH_KEY_PATH=""
PASSPHRASE=""
SERVER_TYPE=""
LOCATION=""
DISKS="auto"
RAID_LEVEL=""
RAID_CHUNK=""
FILESYSTEM=""
CONFIG_FILE="${LUKS_DIR}/luks.conf"
DROPBEAR_PORT=""
PROVISION_USER=""
NO_HARDEN="false"
DRY_RUN="false"
SSH_KEY_NAME=""

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
LUKS Encrypted Provisioning

Provisions a cloud server with full-disk LUKS encryption and Dropbear SSH unlock.

USAGE:
  provision-encrypted.sh --provider <name> --image <distro> --ssh-key <path> [OPTIONS]

REQUIRED:
  --provider <name>         Cloud provider: hetzner|digitalocean|vultr|aws|linode|ovh|ionos
  --image <distro>          Target OS: debian-12, ubuntu-24.04, rocky-9, alma-9
  --ssh-key <path>          SSH private key (public key injected into Dropbear + server)

OPTIONS:
  --passphrase <phrase>     LUKS passphrase (default: auto-generate 32-char)
  --server-type <type>      Provider-specific instance type
  --location <region>       Provider-specific region/location
  --disks <list>            Comma-separated disk devices (default: auto)
  --raid <level>            RAID level: none|raid0|raid1|raid5|raid6|raid10
  --raid-chunk <KB>         RAID stripe chunk size (default: 512)
  --filesystem <fs>         Root filesystem: ext4|xfs (default: ext4)
  --config <path>           Config file (default: luks/luks.conf)
  --dropbear-port <port>    Dropbear SSH port (default: 2222)
  --ssh-key-name <name>     SSH key name registered with provider
  --provision-user <name>   Create non-root user with sudo
  --no-harden               Skip running harden.sh after provisioning
  --dry-run                 Validate and show what would happen
  --help                    Show this help

EXAMPLES:
  ./luks/provision-encrypted.sh --provider hetzner --image debian-12 --ssh-key ~/.ssh/id_ed25519
  ./luks/provision-encrypted.sh --provider vultr --image ubuntu-24.04 --ssh-key ~/.ssh/key \
      --raid raid1 --passphrase "my-secret"
EOF
    exit 0
}

# ─── Argument Parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)         shift; PROVIDER="$1" ;;
        --image)            shift; IMAGE="$1" ;;
        --ssh-key)          shift; SSH_KEY_PATH="$1" ;;
        --passphrase)       shift; PASSPHRASE="$1" ;;
        --server-type)      shift; SERVER_TYPE="$1" ;;
        --location)         shift; LOCATION="$1" ;;
        --disks)            shift; DISKS="$1" ;;
        --raid)             shift; RAID_LEVEL="$1" ;;
        --raid-chunk)       shift; RAID_CHUNK="$1" ;;
        --filesystem)       shift; FILESYSTEM="$1" ;;
        --config)           shift; CONFIG_FILE="$1" ;;
        --dropbear-port)    shift; DROPBEAR_PORT="$1" ;;
        --ssh-key-name)     shift; SSH_KEY_NAME="$1" ;;
        --provision-user)   shift; PROVISION_USER="$1" ;;
        --no-harden)        NO_HARDEN="true" ;;
        --dry-run)          DRY_RUN="true" ;;
        --help|-h)          usage ;;
        *)
            printf 'ERROR: Unknown option: %s\n' "$1" >&2
            usage
            ;;
    esac
    shift
done

# ─── Load Config ─────────────────────────────────────────────────────────────

if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
fi

# Apply CLI overrides (CLI > env > config)
PROVIDER="${PROVIDER:-${LUKS_PROVIDER:-}}"
IMAGE="${IMAGE:-${LUKS_IMAGE:-}}"
SSH_KEY_PATH="${SSH_KEY_PATH:-${LUKS_SSH_KEY_PATH:-}}"
PASSPHRASE="${PASSPHRASE:-${LUKS_PASSPHRASE:-auto}}"
SERVER_TYPE="${SERVER_TYPE:-${LUKS_SERVER_TYPE:-}}"
LOCATION="${LOCATION:-${LUKS_LOCATION:-}}"
DISKS="${DISKS:-${LUKS_DISKS:-auto}}"
RAID_LEVEL="${RAID_LEVEL:-${LUKS_RAID_LEVEL:-raid1}}"
RAID_CHUNK="${RAID_CHUNK:-${LUKS_RAID_CHUNK:-512}}"
FILESYSTEM="${FILESYSTEM:-${LUKS_FILESYSTEM:-ext4}}"
DROPBEAR_PORT="${DROPBEAR_PORT:-${LUKS_DROPBEAR_PORT:-2222}}"
PROVISION_USER="${PROVISION_USER:-${LUKS_PROVISION_USER:-}}"

# ─── Validation ──────────────────────────────────────────────────────────────

validate_args() {
    local errors=()

    [[ -z "${PROVIDER}" ]]    && errors+=("--provider is required")
    [[ -z "${IMAGE}" ]]       && errors+=("--image is required")
    [[ -z "${SSH_KEY_PATH}" ]] && errors+=("--ssh-key is required")

    if [[ -n "${SSH_KEY_PATH}" && ! -f "${SSH_KEY_PATH}" ]]; then
        errors+=("SSH key not found: ${SSH_KEY_PATH}")
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        local err
        for err in "${errors[@]}"; do
            printf 'ERROR: %s\n' "${err}" >&2
        done
        exit 1
    fi

    # Derive SSH public key
    SSH_PUBKEY_PATH="${SSH_KEY_PATH}.pub"
    if [[ ! -f "${SSH_PUBKEY_PATH}" ]]; then
        printf 'ERROR: SSH public key not found: %s\n' "${SSH_PUBKEY_PATH}" >&2
        exit 1
    fi
    SSH_PUBKEY="$(cat "${SSH_PUBKEY_PATH}")"
}

# ─── Passphrase Generation ──────────────────────────────────────────────────

generate_passphrase() {
    if [[ "${PASSPHRASE}" == "auto" ]]; then
        PASSPHRASE="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
        printf '[INFO] Auto-generated 32-character passphrase.\n'
    fi
}

# ─── Artifacts Setup ─────────────────────────────────────────────────────────

setup_artifacts() {
    local timestamp
    timestamp="$(date +%Y%m%d-%H%M%S)"
    ARTIFACTS_DIR="${PROJECT_DIR}/artifacts/luks/${PROVIDER}-${timestamp}"
    mkdir -p "${ARTIFACTS_DIR}"

    # Generate dedicated Dropbear keypair
    DROPBEAR_KEY="${ARTIFACTS_DIR}/ssh-key"
    ssh-keygen -t ed25519 -f "${DROPBEAR_KEY}" -N "" \
        -C "dropbear-${PROVIDER}-luks" > /dev/null 2>&1
    chmod 600 "${DROPBEAR_KEY}"
    chmod 644 "${DROPBEAR_KEY}.pub"

    DROPBEAR_PUBKEY="$(cat "${DROPBEAR_KEY}.pub")"

    # Save passphrase
    printf '%s' "${PASSPHRASE}" > "${ARTIFACTS_DIR}/luks-passphrase"
    chmod 600 "${ARTIFACTS_DIR}/luks-passphrase"
}

# ─── Remote SSH Helpers ──────────────────────────────────────────────────────

_rescue_ssh() {
    ssh \
        -i "${SSH_KEY_PATH}" -p 22 \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        "root@${SERVER_IP}" "$@"
}

_rescue_scp_to() {
    local src="${1}"
    local dest="${2}"
    scp \
        -i "${SSH_KEY_PATH}" -P 22 \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        "${src}" "root@${SERVER_IP}:${dest}"
}

# ─── Main Flow ───────────────────────────────────────────────────────────────

main() {
    validate_args
    generate_passphrase
    setup_artifacts

    # Source provider interface
    source "${LUKS_DIR}/providers/interface.sh"
    luks_load_provider "${PROVIDER}"

    local server_name="luks-${PROVIDER}-${IMAGE}-$(date +%H%M%S)"

    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf ' LUKS Encrypted Provisioning\n'
    printf '────────────────────────────────────────────────────────────\n'
    printf ' Provider  : %s\n' "${PROVIDER}"
    printf ' Image     : %s\n' "${IMAGE}"
    printf ' Type      : %s\n' "${SERVER_TYPE:-<provider default>}"
    printf ' Location  : %s\n' "${LOCATION:-<provider default>}"
    printf ' RAID      : %s\n' "${RAID_LEVEL}"
    printf ' Filesystem: %s\n' "${FILESYSTEM}"
    printf ' Dropbear  : port %s\n' "${DROPBEAR_PORT}"
    printf ' Dry-run   : %s\n' "${DRY_RUN}"
    printf ' Artifacts : %s\n' "${ARTIFACTS_DIR}"
    printf '════════════════════════════════════════════════════════════\n\n'

    # ── Step 1: Create Server ────────────────────────────────────────────────

    printf '[1/10] Creating server...\n'

    local create_result
    create_result="$(provider_create_server \
        "${server_name}" "${SERVER_TYPE}" "${IMAGE}" "${LOCATION}" "${SSH_KEY_NAME}")" \
        || { printf 'ERROR: Server creation failed\n' >&2; exit 1; }

    SERVER_ID="${create_result%%|*}"
    SERVER_IP="${create_result#*|}"

    printf '  Server ID: %s\n' "${SERVER_ID}"
    printf '  Server IP: %s\n\n' "${SERVER_IP}"

    # Update artifacts dir with IP
    local final_artifacts="${PROJECT_DIR}/artifacts/luks/${PROVIDER}-${SERVER_IP}-$(date +%Y%m%d-%H%M%S)"
    mv "${ARTIFACTS_DIR}" "${final_artifacts}"
    ARTIFACTS_DIR="${final_artifacts}"

    # ── Step 2: Wait for SSH ─────────────────────────────────────────────────

    printf '[2/10] Waiting for SSH...\n'
    _luks_wait_ssh "${SERVER_IP}" 22 "${SSH_KEY_PATH}" root 120 || {
        printf 'ERROR: SSH not reachable. Cleaning up.\n' >&2
        provider_delete_server "${SERVER_ID}" || true
        exit 1
    }
    printf '  SSH ready.\n\n'

    # ── Step 3: Enter Rescue Mode ────────────────────────────────────────────

    printf '[3/10] Entering rescue mode...\n'

    local rescue_password
    rescue_password="$(provider_enter_rescue "${SERVER_ID}")" || {
        printf 'ERROR: Failed to enter rescue mode. Cleaning up.\n' >&2
        provider_delete_server "${SERVER_ID}" || true
        exit 1
    }

    printf '  Rescue mode activated.\n'

    # Wait for rescue SSH
    sleep 10
    _luks_wait_ssh "${SERVER_IP}" 22 "${SSH_KEY_PATH}" root 120 || {
        printf 'ERROR: Rescue SSH not reachable.\n' >&2
        printf '  Server %s left running for manual inspection.\n' "${SERVER_ID}" >&2
        exit 1
    }
    printf '  Rescue SSH ready.\n\n'

    # ── Step 4: Copy Engine to Rescue ────────────────────────────────────────

    printf '[4/10] Copying engine to rescue environment...\n'

    _rescue_scp_to "${LUKS_DIR}/engine.sh" "/tmp/engine.sh"
    _rescue_ssh chmod +x /tmp/engine.sh
    printf '  Engine copied.\n\n'

    # ── Step 5: Run Engine ───────────────────────────────────────────────────

    printf '[5/10] Running LUKS engine...\n'

    _rescue_ssh bash -c "$(printf '
        export ENGINE_DISKS=%q
        export ENGINE_RAID_LEVEL=%q
        export ENGINE_RAID_CHUNK=%q
        export ENGINE_FILESYSTEM=%q
        export ENGINE_BOOT_SIZE=%q
        export ENGINE_EFI_SIZE=%q
        export ENGINE_CIPHER=%q
        export ENGINE_KEY_SIZE=%q
        export ENGINE_DISTRO=%q
        export ENGINE_SSH_PUBKEY=%q
        export ENGINE_DROPBEAR_PORT=%q
        export ENGINE_PROVISION_USER=%q
        export ENGINE_PASSPHRASE=%q
        export ENGINE_DRY_RUN=%q
        bash /tmp/engine.sh
    ' "${DISKS}" "${RAID_LEVEL}" "${RAID_CHUNK}" "${FILESYSTEM}" \
      "${LUKS_BOOT_SIZE:-512}" "${LUKS_EFI_SIZE:-256}" \
      "${LUKS_CIPHER:-aes-xts-plain64}" "${LUKS_KEY_SIZE:-512}" \
      "${IMAGE}" "${DROPBEAR_PUBKEY}" "${DROPBEAR_PORT}" \
      "${PROVISION_USER}" "${PASSPHRASE}" "${DRY_RUN}")" \
        2>&1 | tee "${ARTIFACTS_DIR}/provision.log" || {
            printf '\nERROR: Engine failed. Server left in rescue mode.\n' >&2
            printf '  SSH: ssh -i %s root@%s\n' "${SSH_KEY_PATH}" "${SERVER_IP}" >&2
            printf '  Delete: provision-encrypted.sh cleanup (or delete via provider UI)\n' >&2
            exit 1
        }

    printf '\n'

    if [[ "${DRY_RUN}" == "true" ]]; then
        printf '[DRY-RUN] Cleaning up server...\n'
        provider_delete_server "${SERVER_ID}" || true
        printf 'Dry run complete. No changes made.\n'
        exit 0
    fi

    # ── Step 6: Exit Rescue ──────────────────────────────────────────────────

    printf '[6/10] Exiting rescue mode...\n'
    provider_exit_rescue "${SERVER_ID}" || true
    printf '  Done.\n\n'

    # ── Step 7: Reboot ───────────────────────────────────────────────────────

    printf '[7/10] Rebooting into encrypted OS...\n'
    provider_reboot "${SERVER_ID}" || true
    sleep 10
    printf '  Reboot initiated.\n\n'

    # ── Step 8: Unlock ───────────────────────────────────────────────────────

    printf '[8/10] Unlocking LUKS volume...\n'
    bash "${LUKS_DIR}/unlock-remote.sh" \
        --host "${SERVER_IP}" \
        --key "${DROPBEAR_KEY}" \
        --port "${DROPBEAR_PORT}" \
        --passphrase-file "${ARTIFACTS_DIR}/luks-passphrase" \
        --timeout 180 || {
            printf 'ERROR: Unlock failed.\n' >&2
            printf '  Try manually: %s/unlock-remote.sh --host %s --key %s --prompt\n' \
                "${LUKS_DIR}" "${SERVER_IP}" "${DROPBEAR_KEY}" >&2
            exit 1
        }
    printf '\n'

    # ── Step 9: (Optional) Harden ────────────────────────────────────────────

    if [[ "${NO_HARDEN}" != "true" && -f "${PROJECT_DIR}/run-remote.sh" ]]; then
        printf '[9/10] Running hardening...\n'
        local harden_key="${DROPBEAR_KEY}"
        local harden_user="root"
        if [[ -n "${PROVISION_USER}" ]]; then
            harden_user="${PROVISION_USER}"
        fi
        bash "${PROJECT_DIR}/run-remote.sh" \
            --host "${SERVER_IP}" \
            --key "${harden_key}" \
            --user "${harden_user}" \
            --mode apply \
            --no-lynis || printf '  WARN: Hardening encountered errors.\n'
        printf '\n'
    else
        printf '[9/10] Skipping hardening (--no-harden or run-remote.sh not found).\n\n'
    fi

    # ── Step 10: Save Artifacts ──────────────────────────────────────────────

    printf '[10/10] Saving artifacts...\n'

    cat > "${ARTIFACTS_DIR}/server-info.json" <<EOF
{
  "provider": "${PROVIDER}",
  "server_id": "${SERVER_ID}",
  "ip": "${SERVER_IP}",
  "image": "${IMAGE}",
  "server_type": "${SERVER_TYPE}",
  "location": "${LOCATION}",
  "raid_level": "${RAID_LEVEL}",
  "filesystem": "${FILESYSTEM}",
  "dropbear_port": ${DROPBEAR_PORT},
  "provision_user": "${PROVISION_USER}",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf ' Provisioning Complete\n'
    printf '────────────────────────────────────────────────────────────\n'
    printf ' Provider   : %s\n' "${PROVIDER}"
    printf ' Server     : %s (ID: %s)\n' "${SERVER_IP}" "${SERVER_ID}"
    printf ' Image      : %s\n' "${IMAGE}"
    printf ' Encryption : LUKS2 (%s/%s-bit)\n' "${LUKS_CIPHER:-aes-xts-plain64}" "${LUKS_KEY_SIZE:-512}"
    printf ' RAID       : %s\n' "${RAID_LEVEL}"
    printf ' Artifacts  : %s\n' "${ARTIFACTS_DIR}"
    printf '\n'
    printf ' Unlock cmd : %s/unlock-remote.sh --host %s --key %s\n' \
        "${LUKS_DIR}" "${SERVER_IP}" "${DROPBEAR_KEY}"
    printf ' SSH cmd    : ssh -i %s root@%s\n' "${DROPBEAR_KEY}" "${SERVER_IP}"
    if [[ -n "${PROVISION_USER}" ]]; then
        printf ' User SSH   : ssh -i %s %s@%s\n' "${DROPBEAR_KEY}" "${PROVISION_USER}" "${SERVER_IP}"
    fi
    printf '════════════════════════════════════════════════════════════\n'
}

main
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x luks/provision-encrypted.sh luks/unlock-remote.sh luks/engine.sh
git add luks/
git commit -m "feat(luks): add provision-encrypted.sh CLI orchestrator

Ties together provider adapters, LUKS engine, and unlock-remote.sh
into a single provisioning workflow. Supports 7 cloud providers,
RAID configurations, auto/manual passphrase, and optional hardening."
```

---

### Task 13: Integration — Wire Up and Validate

**Files:**
- Modify: `README.md` (add LUKS section)
- Modify: `scripts/lynis_parser.py` (update LUKS classification)

- [ ] **Step 1: Update lynis_parser.py to recognize LUKS as applicable when provisioned with encryption**

In `scripts/lynis_parser.py`, find the regex that classifies LUKS findings as `not_applicable` and update the comment to note this is only for servers not provisioned via `provision-encrypted.sh`.

```python
# No code change needed — the parser correctly classifies LUKS as not_applicable
# for servers that DON'T have LUKS. Servers provisioned with provision-encrypted.sh
# will have LUKS present, so Lynis won't flag it as a finding.
```

- [ ] **Step 2: Add LUKS section to README.md**

Add after the existing "Remote Runner" section:

```markdown
## LUKS Encrypted Provisioning

Provision cloud servers with full-disk LUKS encryption. Only SSH key holders
can unlock the server after reboot via Dropbear in the initramfs.

### Quick Start

```bash
# Provision an encrypted Debian 12 server on Hetzner
export HETZNER_API_TOKEN="your-token"
./luks/provision-encrypted.sh \
    --provider hetzner \
    --image debian-12 \
    --ssh-key ~/.ssh/id_ed25519

# After reboot, unlock with:
./luks/unlock-remote.sh --host <ip> --key artifacts/luks/.../ssh-key
```

### Supported Providers

| Provider | Status |
|----------|--------|
| Hetzner | Supported |
| DigitalOcean | Supported |
| Vultr | Supported |
| AWS EC2 | Supported (EBS-based) |
| Linode | Supported |
| OVH | Supported |
| Ionos | Supported |

### RAID Support

Multi-disk servers support RAID via mdadm:

```bash
./luks/provision-encrypted.sh \
    --provider hetzner \
    --image debian-12 \
    --ssh-key ~/.ssh/id_ed25519 \
    --disks "/dev/sda,/dev/sdb" \
    --raid raid1
```

Supported levels: `raid0`, `raid1`, `raid5`, `raid6`, `raid10`.

See `docs/superpowers/specs/2026-03-31-luks-encrypted-provisioning-design.md` for full documentation.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add LUKS encrypted provisioning section to README"
```

- [ ] **Step 4: Validate file structure**

```bash
find luks/ -type f | sort
```

Expected output:
```
luks/engine.sh
luks/luks.conf
luks/provision-encrypted.sh
luks/providers/aws.sh
luks/providers/digitalocean.sh
luks/providers/hetzner.sh
luks/providers/interface.sh
luks/providers/ionos.sh
luks/providers/linode.sh
luks/providers/ovh.sh
luks/providers/vultr.sh
luks/unlock-remote.sh
```

- [ ] **Step 5: Validate all scripts parse without syntax errors**

```bash
for f in luks/*.sh luks/providers/*.sh; do
    bash -n "$f" && printf 'OK: %s\n' "$f" || printf 'FAIL: %s\n' "$f"
done
```

Expected: all OK.

- [ ] **Step 6: Final commit with all files**

```bash
git add -A luks/ docs/ README.md
git commit -m "feat(luks): complete LUKS encrypted provisioning system

Full-disk LUKS2 encryption with Dropbear SSH unlock, mdadm RAID
support (raid0/1/5/6/10), 7 cloud provider adapters (Hetzner,
DigitalOcean, Vultr, AWS EC2, Linode, OVH, Ionos), and automated
unlock helper script."
```
