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

# Unlock LUKS: upload passphrase via SSH cat, then run cryptsetup + kill askpass
# Dropbear initramfs doesn't have scp, so we use SSH stdin redirection
unlock_result=0

# Step A: upload passphrase to a temp file on the initramfs
printf '%s' "${PASSPHRASE}" | ssh \
    -i "${SSH_KEY}" -p "${DROPBEAR_PORT}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "root@${HOST}" 'cat > /tmp/.lp && chmod 600 /tmp/.lp' 2>/dev/null || {
        printf '  WARN: passphrase upload may have failed.\n'
    }

# Step B: write passphrase to the cryptsetup passfifo (the proper Debian unlock method)
# This is the FIFO that the cryptroot init script reads from — writing to it
# triggers the actual unlock and boot continuation in one step.
ssh \
    -i "${SSH_KEY}" -p "${DROPBEAR_PORT}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "root@${HOST}" '
        # Method 1: Write to passfifo (Debian standard method)
        if [ -p /lib/cryptsetup/passfifo ]; then
            echo "Writing passphrase to passfifo..."
            cat /tmp/.lp > /lib/cryptsetup/passfifo
            rm -f /tmp/.lp
            echo "Boot should continue now"
        else
            # Method 2: Direct cryptsetup + kill askpass (fallback)
            LUKS_DEV=$(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null | head -1)
            echo "Unlocking $LUKS_DEV directly..."
            cat /tmp/.lp | cryptsetup luksOpen "$LUKS_DEV" crypt-root -
            rm -f /tmp/.lp
            kill $(pidof askpass) 2>/dev/null || true
            echo "LUKS unlocked"
        fi
    ' 2>/dev/null || unlock_result=$?

# Connection drops as initramfs pivots to real root — expected
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
