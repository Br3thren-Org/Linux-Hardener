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

    # Update key paths after directory rename
    DROPBEAR_KEY="${ARTIFACTS_DIR}/ssh-key"

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
        2>&1 | tee "${ARTIFACTS_DIR}/provision.log"
    local engine_rc=${PIPESTATUS[0]}

    # Engine SSH may return non-zero if connection drops during finalize (unmount/close)
    # Check the status file on the server to determine if engine actually succeeded
    if [[ "${engine_rc}" -ne 0 ]]; then
        printf '  Engine SSH exited with code %d — checking status on server...\n' "${engine_rc}"
        local status_check
        status_check="$(_rescue_ssh 'cat /tmp/luks-engine-status 2>/dev/null | tail -1' 2>/dev/null || true)"
        if [[ "${status_check}" == *"Finalize"* ]]; then
            printf '  Engine completed successfully (finalize step reached).\n'
        else
            printf '\nERROR: Engine failed. Server left in rescue mode.\n' >&2
            printf '  SSH: ssh -i %s root@%s\n' "${SSH_KEY_PATH}" "${SERVER_IP}" >&2
            exit 1
        fi
    fi

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
