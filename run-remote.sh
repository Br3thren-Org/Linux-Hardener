#!/usr/bin/env bash
# run-remote.sh — Run Linux Hardener against any remote machine
# Usage: ./run-remote.sh --host <ip> --user <user> --key <ssh_key> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Defaults ────────────────────────────────────────────────────────────────

HOST=""
USER="root"
SSH_KEY_PATH="${HOME}/.ssh/id_ed25519"
SSH_PORT=22
MODE="apply"
COLLECT_ARTIFACTS="true"
RUN_LYNIS="true"
RUN_VALIDATION="true"
CONFIG_FILE="${SCRIPT_DIR}/config/hardener.conf"
MODULE_FILTER=""
PROVISION_USER=""

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
Linux Hardener — Remote Runner

Hardens any machine you can SSH into. Copies the framework, runs hardening,
validates, optionally runs Lynis before/after, and collects artifacts.

USAGE:
  run-remote.sh --host <ip> --key <ssh_key> [OPTIONS]

REQUIRED:
  --host <ip|hostname>   Target machine
  --key <path>           SSH private key path

OPTIONS:
  --user <user>          SSH user (default: root)
  --port <port>          SSH port (default: 22)
  --mode <mode>          apply | audit | dry-run (default: apply)
  --config <path>        Config file (default: config/hardener.conf)
  --modules <list>       Comma-separated module filter (e.g., ssh,firewall)
  --provision-user <name> Create a new user with SSH key and sudo, then run
                         hardening as that user. Generates a keypair locally
                         under artifacts/ and saves credentials there.
  --no-lynis             Skip Lynis audits
  --no-validate          Skip post-hardening validation
  --no-artifacts         Don't collect artifacts back
  --help                 Show this help

EXAMPLES:
  ./run-remote.sh --host 192.168.1.100 --key ~/.ssh/id_ed25519
  ./run-remote.sh --host 10.0.0.5 --user admin --key ~/.ssh/mykey --mode audit
  ./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey --modules ssh,firewall,sysctl
  ./run-remote.sh --host 10.0.0.5 --key ~/.ssh/root_key --provision-user hardener
EOF
    exit 0
}

# ─── Argument Parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)         shift; HOST="$1" ;;
        --user)         shift; USER="$1" ;;
        --key)          shift; SSH_KEY_PATH="$1" ;;
        --port)         shift; SSH_PORT="$1" ;;
        --mode)         shift; MODE="$1" ;;
        --config)       shift; CONFIG_FILE="$1" ;;
        --modules)      shift; MODULE_FILTER="$1" ;;
        --provision-user) shift; PROVISION_USER="$1" ;;
        --no-lynis)     RUN_LYNIS="false" ;;
        --no-validate)  RUN_VALIDATION="false" ;;
        --no-artifacts) COLLECT_ARTIFACTS="false" ;;
        --help|-h)      usage ;;
        *)
            printf 'ERROR: Unknown option: %s\n' "$1" >&2
            usage
            ;;
    esac
    shift
done

if [[ -z "${HOST}" ]]; then
    printf 'ERROR: --host is required\n' >&2
    usage
fi

if [[ ! -f "${SSH_KEY_PATH}" ]]; then
    printf 'ERROR: SSH key not found: %s\n' "${SSH_KEY_PATH}" >&2
    exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
    printf 'ERROR: Config file not found: %s\n' "${CONFIG_FILE}" >&2
    exit 1
fi

# ─── SSH Helpers ─────────────────────────────────────────────────────────────

remote_exec() {
    if [[ "${USER}" == "root" ]]; then
        ssh \
            -i "${SSH_KEY_PATH}" -p "${SSH_PORT}" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 -o BatchMode=yes \
            "root@${HOST}" "$@"
    else
        ssh \
            -i "${SSH_KEY_PATH}" -p "${SSH_PORT}" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 -o BatchMode=yes \
            "${USER}@${HOST}" sudo "$@"
    fi
}

remote_exec_raw() {
    ssh \
        -i "${SSH_KEY_PATH}" -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        "${USER}@${HOST}" "$@"
}

remote_copy_to() {
    local src="$1"
    local dest="$2"
    scp \
        -i "${SSH_KEY_PATH}" -P "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -r "${src}" "${USER}@${HOST}:${dest}"
}

remote_copy_from() {
    local src="$1"
    local dest="$2"
    scp \
        -i "${SSH_KEY_PATH}" -P "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        -r "${USER}@${HOST}:${src}" "${dest}"
}

# ─── Setup ───────────────────────────────────────────────────────────────────

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
ARTIFACTS_DIR="${SCRIPT_DIR}/artifacts/remote-${HOST}-${TIMESTAMP}"
REMOTE_DIR="/opt/linux-hardener"

mkdir -p "${ARTIFACTS_DIR}"

printf '\n'
printf '════════════════════════════════════════════════════════════\n'
printf ' Linux Hardener — Remote Runner\n'
printf '────────────────────────────────────────────────────────────\n'
printf ' Target : %s@%s:%s\n' "${USER}" "${HOST}" "${SSH_PORT}"
printf ' Mode   : %s\n' "${MODE}"
printf ' Key    : %s\n' "${SSH_KEY_PATH}"
printf ' Config : %s\n' "${CONFIG_FILE}"
if [[ -n "${MODULE_FILTER}" ]]; then
    printf ' Modules: %s\n' "${MODULE_FILTER}"
fi
if [[ -n "${PROVISION_USER}" ]]; then
    printf ' Provision: creating user "%s" with SSH key and sudo\n' "${PROVISION_USER}"
fi
printf ' Output : %s\n' "${ARTIFACTS_DIR}"
printf '════════════════════════════════════════════════════════════\n\n'

# ─── Step 1: Test SSH Connectivity ───────────────────────────────────────────

printf '[1/8] Testing SSH connectivity...\n'
if ! remote_exec_raw "echo ok" &>/dev/null; then
    printf 'ERROR: Cannot SSH to %s@%s:%s\n' "${USER}" "${HOST}" "${SSH_PORT}" >&2
    exit 1
fi
printf '  Connected.\n\n'

# ─── Step 1.5: Provision User (optional) ────────────────────────────────────

if [[ -n "${PROVISION_USER}" ]]; then
    printf '[1.5/8] Provisioning user "%s"...\n' "${PROVISION_USER}"

    PROVISION_KEY_DIR="${ARTIFACTS_DIR}/provisioned-keys"
    PROVISION_KEY_PATH="${PROVISION_KEY_DIR}/${PROVISION_USER}"
    mkdir -p "${PROVISION_KEY_DIR}"

    # Generate a dedicated keypair for the new user
    if [[ ! -f "${PROVISION_KEY_PATH}" ]]; then
        ssh-keygen -t ed25519 -f "${PROVISION_KEY_PATH}" -N "" \
            -C "${PROVISION_USER}@${HOST}-hardener" > /dev/null 2>&1
        printf '  Generated keypair: %s\n' "${PROVISION_KEY_PATH}"
    else
        printf '  Keypair already exists: %s\n' "${PROVISION_KEY_PATH}"
    fi

    PROVISION_PUBKEY="$(cat "${PROVISION_KEY_PATH}.pub")"

    # Create user, set up SSH key, grant passwordless sudo — all in one remote call
    # This runs as the INITIAL user (root or sudo-capable user provided via --user/--key)
    remote_exec bash -c "
        set -euo pipefail

        NEW_USER='${PROVISION_USER}'

        # Create user if not exists
        if ! id \"\${NEW_USER}\" &>/dev/null; then
            useradd -m -s /bin/bash \"\${NEW_USER}\"
            echo \"  Created user: \${NEW_USER}\"
        else
            echo \"  User already exists: \${NEW_USER}\"
        fi

        # Set up SSH authorized_keys
        SSHDIR=\"/home/\${NEW_USER}/.ssh\"
        mkdir -p \"\${SSHDIR}\"
        chmod 700 \"\${SSHDIR}\"

        PUBKEY='${PROVISION_PUBKEY}'
        if ! grep -qF \"\${PUBKEY}\" \"\${SSHDIR}/authorized_keys\" 2>/dev/null; then
            echo \"\${PUBKEY}\" >> \"\${SSHDIR}/authorized_keys\"
            echo \"  Added SSH public key\"
        else
            echo \"  SSH key already present\"
        fi
        chmod 600 \"\${SSHDIR}/authorized_keys\"
        chown -R \"\${NEW_USER}:\${NEW_USER}\" \"\${SSHDIR}\"

        # Grant passwordless sudo
        SUDOFILE=\"/etc/sudoers.d/90-hardener-\${NEW_USER}\"
        echo \"\${NEW_USER} ALL=(ALL) NOPASSWD:ALL\" > \"\${SUDOFILE}\"
        chmod 440 \"\${SUDOFILE}\"
        echo \"  Granted passwordless sudo via \${SUDOFILE}\"
    "

    # Verify we can connect as the new user
    printf '  Verifying SSH as %s...\n' "${PROVISION_USER}"
    if ssh \
        -i "${PROVISION_KEY_PATH}" -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        "${PROVISION_USER}@${HOST}" "echo ok" &>/dev/null; then
        printf '  Verified: can SSH as %s\n' "${PROVISION_USER}"
    else
        printf 'ERROR: Cannot SSH as provisioned user %s\n' "${PROVISION_USER}" >&2
        exit 1
    fi

    # Switch to the provisioned user for all remaining operations
    ORIGINAL_USER="${USER}"
    ORIGINAL_KEY="${SSH_KEY_PATH}"
    USER="${PROVISION_USER}"
    SSH_KEY_PATH="${PROVISION_KEY_PATH}"

    printf '  Switched to user: %s (key: %s)\n' "${USER}" "${SSH_KEY_PATH}"

    # Save credentials summary
    cat > "${PROVISION_KEY_DIR}/README.txt" <<CREDEOF
Provisioned User Credentials
=============================
Host:        ${HOST}:${SSH_PORT}
Username:    ${PROVISION_USER}
Private key: ${PROVISION_KEY_PATH}
Public key:  ${PROVISION_KEY_PATH}.pub
Sudo:        passwordless via /etc/sudoers.d/90-hardener-${PROVISION_USER}
Created:     $(date -u +%Y-%m-%dT%H:%M:%SZ)
Created by:  ${ORIGINAL_USER} via run-remote.sh

SSH command:
  ssh -i ${PROVISION_KEY_PATH} -p ${SSH_PORT} ${PROVISION_USER}@${HOST}
CREDEOF

    printf '  Credentials saved to: %s/\n\n' "${PROVISION_KEY_DIR}"
fi

# ─── Step 2: Bootstrap ───────────────────────────────────────────────────────

printf '[2/8] Copying framework to target...\n'
remote_exec mkdir -p "${REMOTE_DIR}"
remote_copy_to "${SCRIPT_DIR}/lib/"      "${REMOTE_DIR}/lib"
remote_copy_to "${SCRIPT_DIR}/scripts/"  "${REMOTE_DIR}/scripts"
remote_copy_to "${SCRIPT_DIR}/config/"   "${REMOTE_DIR}/config"
remote_copy_to "${SCRIPT_DIR}/harden.sh" "${REMOTE_DIR}/harden.sh"
remote_exec chmod +x "${REMOTE_DIR}/harden.sh" "${REMOTE_DIR}/scripts/lynis_runner.sh" "${REMOTE_DIR}/scripts/validate.sh"

# Ensure python3 is available
remote_exec bash -c "command -v python3 || (apt-get update -y && apt-get install -y python3 || dnf install -y python3)" &>/dev/null || true
printf '  Done.\n\n'

# ─── Step 3: Pre-Hardening Lynis ────────────────────────────────────────────

if [[ "${RUN_LYNIS}" == "true" ]]; then
    printf '[3/8] Installing Lynis and running pre-hardening audit...\n'
    remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" install &>/dev/null || {
        printf '  WARN: Lynis install failed, skipping Lynis audits.\n'
        RUN_LYNIS="false"
    }
    if [[ "${RUN_LYNIS}" == "true" ]]; then
        remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" run pre-hardening > "${ARTIFACTS_DIR}/lynis-pre.log" 2>&1 || true
        printf '  Pre-hardening audit complete.\n\n'
    fi
else
    printf '[3/8] Skipping Lynis (--no-lynis).\n\n'
fi

# ─── Step 4: Run Hardening ──────────────────────────────────────────────────

printf '[4/8] Running hardener in %s mode...\n' "${MODE}"

harden_args=("${REMOTE_DIR}/harden.sh" "--${MODE}" "--config" "${REMOTE_DIR}/config/hardener.conf")
if [[ -n "${MODULE_FILTER}" ]]; then
    harden_args+=("--modules" "${MODULE_FILTER}")
fi

remote_exec "${harden_args[@]}" 2>&1 | tee "${ARTIFACTS_DIR}/harden.log"
printf '\n'

# ─── Step 5: Validation ─────────────────────────────────────────────────────

if [[ "${RUN_VALIDATION}" == "true" ]] && [[ "${MODE}" == "apply" ]]; then
    printf '[5/8] Running post-hardening validation...\n'
    remote_exec "${REMOTE_DIR}/scripts/validate.sh" 2>&1 | tee "${ARTIFACTS_DIR}/validate.log"
    printf '\n'
else
    printf '[5/8] Skipping validation (%s mode).\n\n' "${MODE}"
fi

# ─── Step 6: Post-Hardening Lynis ───────────────────────────────────────────

if [[ "${RUN_LYNIS}" == "true" ]] && [[ "${MODE}" == "apply" ]]; then
    printf '[6/8] Running post-hardening Lynis audit...\n'
    remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" run post-hardening > "${ARTIFACTS_DIR}/lynis-post.log" 2>&1 || true
    printf '  Post-hardening audit complete.\n\n'
else
    printf '[6/8] Skipping post-Lynis.\n\n'
fi

# ─── Step 7: Collect Artifacts ───────────────────────────────────────────────

if [[ "${COLLECT_ARTIFACTS}" == "true" ]]; then
    printf '[7/8] Collecting artifacts...\n'

    remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" collect /tmp/hardener-artifacts &>/dev/null || true
    remote_copy_from "/tmp/hardener-artifacts/" "${ARTIFACTS_DIR}/lynis/" 2>/dev/null || true
    remote_copy_from "/var/lib/linux-hardener/last-run.json" "${ARTIFACTS_DIR}/" 2>/dev/null || true
    remote_copy_from "/var/lib/linux-hardener/validation.json" "${ARTIFACTS_DIR}/" 2>/dev/null || true

    # Parse Lynis results locally
    local_pre="${ARTIFACTS_DIR}/lynis/pre-hardening/lynis-report.dat"
    local_post="${ARTIFACTS_DIR}/lynis/post-hardening/lynis-report.dat"

    if [[ -f "${local_pre}" ]] && [[ -f "${local_post}" ]]; then
        # Detect remote distro for labeling
        local distro_label
        distro_label="$(remote_exec_raw "sed -n 's/^ID=//p' /etc/os-release | tr -d '\"'")-$(remote_exec_raw "sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '\"'")" 2>/dev/null || distro_label="unknown"

        python3 "${SCRIPT_DIR}/scripts/lynis_parser.py" \
            "${local_pre}" "${local_post}" \
            "${ARTIFACTS_DIR}/summary.json" \
            "${distro_label}" \
            "${SCRIPT_DIR}/config/auto-remediate.conf" \
            2>/dev/null || true

        if [[ -f "${ARTIFACTS_DIR}/summary.json" ]]; then
            python3 "${SCRIPT_DIR}/scripts/report_generator.py" \
                "${ARTIFACTS_DIR}/summary.json" \
                "${ARTIFACTS_DIR}" \
                2>/dev/null || true
        fi
    fi

    printf '  Artifacts saved to: %s\n\n' "${ARTIFACTS_DIR}"
else
    printf '[7/8] Skipping artifact collection.\n\n'
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

printf '════════════════════════════════════════════════════════════\n'
printf ' Complete\n'
printf ' Target   : %s@%s\n' "${USER}" "${HOST}"
printf ' Mode     : %s\n' "${MODE}"
printf ' Artifacts: %s\n' "${ARTIFACTS_DIR}"

if [[ -f "${ARTIFACTS_DIR}/summary.json" ]]; then
    python3 -c "
import json, sys
d = json.load(open('${ARTIFACTS_DIR}/summary.json'))
print(f\" Score    : {d['pre']['hardening_index']} -> {d['post']['hardening_index']} (+{d['delta']['hardening_index_numeric']})\")
" 2>/dev/null || true
fi

if [[ -n "${PROVISION_USER}" ]]; then
    printf '\n'
    printf ' ── Provisioned User ──────────────────────────────────────\n'
    printf ' Username : %s\n' "${PROVISION_USER}"
    printf ' SSH key  : %s\n' "${PROVISION_KEY_PATH}"
    printf ' Sudo     : passwordless\n'
    printf ' Connect  : ssh -i %s -p %s %s@%s\n' "${PROVISION_KEY_PATH}" "${SSH_PORT}" "${PROVISION_USER}" "${HOST}"
fi

printf '════════════════════════════════════════════════════════════\n'
