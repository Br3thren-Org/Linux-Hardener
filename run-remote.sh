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
  --no-lynis             Skip Lynis audits
  --no-validate          Skip post-hardening validation
  --no-artifacts         Don't collect artifacts back
  --help                 Show this help

EXAMPLES:
  ./run-remote.sh --host 192.168.1.100 --key ~/.ssh/id_ed25519
  ./run-remote.sh --host 10.0.0.5 --user admin --key ~/.ssh/mykey --mode audit
  ./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey --modules ssh,firewall,sysctl
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
printf ' Output : %s\n' "${ARTIFACTS_DIR}"
printf '════════════════════════════════════════════════════════════\n\n'

# ─── Step 1: Test SSH Connectivity ───────────────────────────────────────────

printf '[1/7] Testing SSH connectivity...\n'
if ! remote_exec_raw "echo ok" &>/dev/null; then
    printf 'ERROR: Cannot SSH to %s@%s:%s\n' "${USER}" "${HOST}" "${SSH_PORT}" >&2
    exit 1
fi
printf '  Connected.\n\n'

# ─── Step 2: Bootstrap ───────────────────────────────────────────────────────

printf '[2/7] Copying framework to target...\n'
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
    printf '[3/7] Installing Lynis and running pre-hardening audit...\n'
    remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" install &>/dev/null || {
        printf '  WARN: Lynis install failed, skipping Lynis audits.\n'
        RUN_LYNIS="false"
    }
    if [[ "${RUN_LYNIS}" == "true" ]]; then
        remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" run pre-hardening > "${ARTIFACTS_DIR}/lynis-pre.log" 2>&1 || true
        printf '  Pre-hardening audit complete.\n\n'
    fi
else
    printf '[3/7] Skipping Lynis (--no-lynis).\n\n'
fi

# ─── Step 4: Run Hardening ──────────────────────────────────────────────────

printf '[4/7] Running hardener in %s mode...\n' "${MODE}"

harden_args=("${REMOTE_DIR}/harden.sh" "--${MODE}" "--config" "${REMOTE_DIR}/config/hardener.conf")
if [[ -n "${MODULE_FILTER}" ]]; then
    harden_args+=("--modules" "${MODULE_FILTER}")
fi

remote_exec "${harden_args[@]}" 2>&1 | tee "${ARTIFACTS_DIR}/harden.log"
printf '\n'

# ─── Step 5: Validation ─────────────────────────────────────────────────────

if [[ "${RUN_VALIDATION}" == "true" ]] && [[ "${MODE}" == "apply" ]]; then
    printf '[5/7] Running post-hardening validation...\n'
    remote_exec "${REMOTE_DIR}/scripts/validate.sh" 2>&1 | tee "${ARTIFACTS_DIR}/validate.log"
    printf '\n'
else
    printf '[5/7] Skipping validation (%s mode).\n\n' "${MODE}"
fi

# ─── Step 6: Post-Hardening Lynis ───────────────────────────────────────────

if [[ "${RUN_LYNIS}" == "true" ]] && [[ "${MODE}" == "apply" ]]; then
    printf '[6/7] Running post-hardening Lynis audit...\n'
    remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" run post-hardening > "${ARTIFACTS_DIR}/lynis-post.log" 2>&1 || true
    printf '  Post-hardening audit complete.\n\n'
else
    printf '[6/7] Skipping post-Lynis.\n\n'
fi

# ─── Step 7: Collect Artifacts ───────────────────────────────────────────────

if [[ "${COLLECT_ARTIFACTS}" == "true" ]]; then
    printf '[7/7] Collecting artifacts...\n'

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
    printf '[7/7] Skipping artifact collection.\n\n'
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

printf '════════════════════════════════════════════════════════════\n'
