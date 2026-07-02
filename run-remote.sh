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
ADMIN_USER=""
AUTOMATION_USER=""
LOCK_ROOT="auto"        # auto = disable root SSH when an admin user is provisioned

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
  --provision-user <name> Create a new user with SSH key and passwordless sudo,
                         then run hardening as that user (legacy single-account
                         flow). Generates a keypair under artifacts/.

ACCESS MODEL (recommended two-account posture):
  --admin-user <name>    Create a human admin: SSH key login + PASSWORD-required
                         sudo (added to sudo/wheel; a sudo password is generated
                         and shown once). Key theft alone can't escalate.
  --automation-user <name>
                         Create an automation account for Ansible etc.: SSH key
                         login + NOPASSWD sudo. Key + Ansible inventory snippet
                         saved under artifacts/accounts/.
  --lock-root            Disable root SSH login (PermitRootLogin no). Default
                         when --admin-user is set; applied only after a non-root
                         sudo account is verified reachable (no lockout).
  --keep-root-ssh        Keep root SSH (prohibit-password) even with --admin-user.

  --no-lynis             Skip Lynis audits
  --no-validate          Skip post-hardening validation
  --no-artifacts         Don't collect artifacts back
  --help                 Show this help

EXAMPLES:
  ./run-remote.sh --host 192.168.1.100 --key ~/.ssh/id_ed25519
  ./run-remote.sh --host 10.0.0.5 --user admin --key ~/.ssh/mykey --mode audit
  ./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey --modules ssh,firewall,sysctl
  # Human admin (password sudo) + Ansible account, root SSH disabled:
  ./run-remote.sh --host 10.0.0.5 --key ~/.ssh/root_key \
      --admin-user liam --automation-user ansible
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
        --provision-user)  shift; PROVISION_USER="$1" ;;
        --admin-user)      shift; ADMIN_USER="$1" ;;
        --automation-user) shift; AUTOMATION_USER="$1" ;;
        --lock-root)       LOCK_ROOT="true" ;;
        --keep-root-ssh)   LOCK_ROOT="false" ;;
        --no-lynis)     RUN_LYNIS="false" ;;
        --no-validate)  RUN_VALIDATION="false" ;;
        --no-artifacts) COLLECT_ARTIFACTS="false" ;;
        --help|-h)      usage ;;
        *)
            printf 'ERROR: Unknown option: %s\n' "$1" >&2
            exit 1
            ;;
    esac
    shift
done

if [[ -z "${HOST}" ]]; then
    printf 'ERROR: --host is required\n' >&2
    exit 1
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
    local ssh_base=(
        ssh
        -i "${SSH_KEY_PATH}" -p "${SSH_PORT}"
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o ConnectTimeout=10 -o BatchMode=yes
    )
    if [[ "${USER}" == "root" ]]; then
        "${ssh_base[@]}" "root@${HOST}" "$@"
    else
        "${ssh_base[@]}" "${USER}@${HOST}" sudo "$@"
    fi
}

# remote_exec_script — pipe a script to remote bash via stdin (handles multi-line safely)
remote_exec_script() {
    local ssh_base=(
        ssh
        -i "${SSH_KEY_PATH}" -p "${SSH_PORT}"
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o ConnectTimeout=10 -o BatchMode=yes
    )
    if [[ "${USER}" == "root" ]]; then
        "${ssh_base[@]}" "root@${HOST}" bash -s
    else
        "${ssh_base[@]}" "${USER}@${HOST}" sudo bash -s
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

# ─── Account provisioning helpers ────────────────────────────────────────────

# _ssh_as <user> <key> [remote-cmd] — can we SSH in as <user> with <key>?
_ssh_as() {
    ssh -i "${2}" -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o BatchMode=yes \
        "${1}@${HOST}" "${3:-true}" &>/dev/null
}

# _provision_account <username> <admin|automation> <pubkey> <password-or-empty>
# Runs over the current (root/sudo) connection: creates the user, installs the
# SSH key, adds it to the distro sudo group, and sets sudo policy by type —
#   admin      : password-required sudo (a password is set; NOPASSWD removed)
#   automation : passwordless sudo (for Ansible), no interactive password
_provision_account() {
    local acct="$1" atype="$2" pubkey="$3" acct_pw="$4"
    remote_exec_script <<ACCT_EOF
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:\${PATH}"
NEW_USER='${acct}'
ATYPE='${atype}'
PUBKEY='${pubkey}'

id "\${NEW_USER}" &>/dev/null || useradd -m -s /bin/bash "\${NEW_USER}"

SSHDIR="/home/\${NEW_USER}/.ssh"
mkdir -p "\${SSHDIR}"; chmod 700 "\${SSHDIR}"
grep -qF "\${PUBKEY}" "\${SSHDIR}/authorized_keys" 2>/dev/null \
    || printf '%s\n' "\${PUBKEY}" >> "\${SSHDIR}/authorized_keys"
chmod 600 "\${SSHDIR}/authorized_keys"
chown -R "\${NEW_USER}:\${NEW_USER}" "\${SSHDIR}"

# Add to the distro's sudo group (Debian: sudo, RHEL: wheel)
SUDO_GRP=""
getent group sudo  >/dev/null 2>&1 && SUDO_GRP=sudo
getent group wheel >/dev/null 2>&1 && SUDO_GRP=wheel
[ -n "\${SUDO_GRP}" ] && usermod -aG "\${SUDO_GRP}" "\${NEW_USER}"

if [ "\${ATYPE}" = admin ]; then
    # Group membership already prompts for a password on sudo; set that
    # password and drop any stale NOPASSWD grant for this user.
    printf '%s:%s\n' "\${NEW_USER}" '${acct_pw}' | chpasswd
    rm -f "/etc/sudoers.d/90-hardener-\${NEW_USER}" "/etc/sudoers.d/91-automation-\${NEW_USER}"
    echo "  admin '\${NEW_USER}': key login + password-required sudo (group \${SUDO_GRP:-none})"
else
    # Automation (Ansible): passwordless sudo, account has no usable password.
    SUDOFILE="/etc/sudoers.d/91-automation-\${NEW_USER}"
    TMPSUDO="\$(mktemp)"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "\${NEW_USER}" > "\${TMPSUDO}"
    if visudo -cf "\${TMPSUDO}" >/dev/null 2>&1; then
        install -m 440 "\${TMPSUDO}" "\${SUDOFILE}"
        echo "  automation '\${NEW_USER}': key login + NOPASSWD sudo (group \${SUDO_GRP:-none})"
    else
        echo "  ERROR: generated sudoers for '\${NEW_USER}' failed visudo -c — not installed" >&2
    fi
    rm -f "\${TMPSUDO}"
    passwd -l "\${NEW_USER}" >/dev/null 2>&1 || true
fi
ACCT_EOF
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
        ssh-keygen -t rsa -b 4096 -f "${PROVISION_KEY_PATH}" -N "" \
            -C "${PROVISION_USER}@${HOST}-hardener" > /dev/null 2>&1
        chmod 600 "${PROVISION_KEY_PATH}"
        chmod 644 "${PROVISION_KEY_PATH}.pub"
        printf '  Generated keypair: %s\n' "${PROVISION_KEY_PATH}"
    else
        chmod 600 "${PROVISION_KEY_PATH}"
        printf '  Keypair already exists: %s\n' "${PROVISION_KEY_PATH}"
    fi

    PROVISION_PUBKEY="$(cat "${PROVISION_KEY_PATH}.pub")"

    # Create user, set up SSH key, grant passwordless sudo — all in one remote call
    # This runs as the INITIAL user (root or sudo-capable user provided via --user/--key)
    # Uses heredoc piped to remote_exec_script to handle multi-line safely
    remote_exec_script <<PROVISION_EOF
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:\${PATH}"

NEW_USER='${PROVISION_USER}'

# Create user if not exists
if ! id "\${NEW_USER}" &>/dev/null; then
    useradd -m -s /bin/bash "\${NEW_USER}"
    echo "  Created user: \${NEW_USER}"
else
    echo "  User already exists: \${NEW_USER}"
fi

# Set up SSH authorized_keys
SSHDIR="/home/\${NEW_USER}/.ssh"
mkdir -p "\${SSHDIR}"
chmod 700 "\${SSHDIR}"

PUBKEY='${PROVISION_PUBKEY}'
if ! grep -qF "\${PUBKEY}" "\${SSHDIR}/authorized_keys" 2>/dev/null; then
    echo "\${PUBKEY}" >> "\${SSHDIR}/authorized_keys"
    echo "  Added SSH public key"
else
    echo "  SSH key already present"
fi
chmod 600 "\${SSHDIR}/authorized_keys"
chown -R "\${NEW_USER}:\${NEW_USER}" "\${SSHDIR}"

# Grant passwordless sudo
SUDOFILE="/etc/sudoers.d/90-hardener-\${NEW_USER}"
echo "\${NEW_USER} ALL=(ALL) NOPASSWD:ALL" > "\${SUDOFILE}"
chmod 440 "\${SUDOFILE}"
echo "  Granted passwordless sudo via \${SUDOFILE}"
PROVISION_EOF

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

# ─── Step 1.6: Access accounts (admin / automation) ─────────────────────────

if [[ -n "${ADMIN_USER}" || -n "${AUTOMATION_USER}" ]]; then
    printf '[1.6/8] Provisioning access accounts...\n'
    ACCOUNTS_DIR="${ARTIFACTS_DIR}/accounts"
    mkdir -p "${ACCOUNTS_DIR}"; chmod 700 "${ACCOUNTS_DIR}"

    if [[ -n "${ADMIN_USER}" ]]; then
        ADMIN_KEY="${ACCOUNTS_DIR}/${ADMIN_USER}"
        [[ -f "${ADMIN_KEY}" ]] || ssh-keygen -t ed25519 -f "${ADMIN_KEY}" -N "" \
            -C "${ADMIN_USER}@${HOST}-admin" >/dev/null 2>&1
        chmod 600 "${ADMIN_KEY}"; chmod 644 "${ADMIN_KEY}.pub"
        # Bounded read + bash slice: `tr < /dev/urandom | head -c N` makes tr
        # die by SIGPIPE (141) when head closes early, which aborts this
        # top-level script under `set -o pipefail`.
        ADMIN_PW="$(head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
        ADMIN_PW="${ADMIN_PW:0:24}"
        _provision_account "${ADMIN_USER}" admin "$(cat "${ADMIN_KEY}.pub")" "${ADMIN_PW}"
        if _ssh_as "${ADMIN_USER}" "${ADMIN_KEY}"; then
            printf '  Verified SSH as admin "%s".\n' "${ADMIN_USER}"
        else
            printf 'ERROR: cannot SSH as admin "%s" — aborting before any root lockdown.\n' "${ADMIN_USER}" >&2
            exit 1
        fi
        cat > "${ACCOUNTS_DIR}/${ADMIN_USER}.README.txt" <<EOF
Admin account — SSH key login, password-required sudo
Host        : ${HOST}:${SSH_PORT}
Username    : ${ADMIN_USER}
Private key : ${ADMIN_KEY}
SSH         : ssh -i ${ADMIN_KEY} -p ${SSH_PORT} ${ADMIN_USER}@${HOST}
Sudo        : requires the password below (member of sudo/wheel)
Sudo pass   : ${ADMIN_PW}
Created     : $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
        chmod 600 "${ACCOUNTS_DIR}/${ADMIN_USER}.README.txt"
        printf '  Admin "%s" sudo password (SHOWN ONCE, saved to accounts/): %s\n' "${ADMIN_USER}" "${ADMIN_PW}"
    fi

    if [[ -n "${AUTOMATION_USER}" ]]; then
        AUTO_KEY="${ACCOUNTS_DIR}/${AUTOMATION_USER}"
        [[ -f "${AUTO_KEY}" ]] || ssh-keygen -t ed25519 -f "${AUTO_KEY}" -N "" \
            -C "${AUTOMATION_USER}@${HOST}-automation" >/dev/null 2>&1
        chmod 600 "${AUTO_KEY}"; chmod 644 "${AUTO_KEY}.pub"
        _provision_account "${AUTOMATION_USER}" automation "$(cat "${AUTO_KEY}.pub")" ""
        if _ssh_as "${AUTOMATION_USER}" "${AUTO_KEY}" 'sudo -n true'; then
            printf '  Verified SSH + passwordless sudo as automation "%s".\n' "${AUTOMATION_USER}"
        else
            printf '  WARN: could not verify key+NOPASSWD-sudo as "%s" — check manually.\n' "${AUTOMATION_USER}"
        fi
        cat > "${ACCOUNTS_DIR}/${AUTOMATION_USER}.README.txt" <<EOF
Automation account — SSH key login, passwordless sudo (for Ansible)
Host        : ${HOST}:${SSH_PORT}
Username    : ${AUTOMATION_USER}
Private key : ${AUTO_KEY}
SSH         : ssh -i ${AUTO_KEY} -p ${SSH_PORT} ${AUTOMATION_USER}@${HOST}
Sudo        : NOPASSWD (all) via /etc/sudoers.d/91-automation-${AUTOMATION_USER}
Created     : $(date -u +%Y-%m-%dT%H:%M:%SZ)

Ansible inventory line:
  ${HOST} ansible_user=${AUTOMATION_USER} ansible_ssh_private_key_file=${AUTO_KEY} ansible_become=true ansible_become_method=sudo
EOF
        chmod 600 "${ACCOUNTS_DIR}/${AUTOMATION_USER}.README.txt"
        printf '  Automation key + Ansible inventory saved: %s\n' "${ACCOUNTS_DIR}/${AUTOMATION_USER}.README.txt"
    fi
    printf '\n'
fi

# Resolve the root-lock decision (auto = disable root SSH when an admin exists)
if [[ "${LOCK_ROOT}" == "auto" ]]; then
    if [[ -n "${ADMIN_USER}" ]]; then LOCK_ROOT="true"; else LOCK_ROOT="false"; fi
fi

# ─── Step 2: Bootstrap ───────────────────────────────────────────────────────

printf '[2/8] Copying framework to target...\n'
remote_exec mkdir -p "${REMOTE_DIR}"
remote_exec chown "${USER}:${USER}" "${REMOTE_DIR}"

# Stage a sanitized copy of config/: HETZNER_* values (API token, key name)
# are control-machine credentials and must never land on the target.
STAGED_CONFIG_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGED_CONFIG_DIR}"' EXIT
cp -R "${SCRIPT_DIR}/config/." "${STAGED_CONFIG_DIR}/"
for staged_conf in "${STAGED_CONFIG_DIR}"/*.conf "${STAGED_CONFIG_DIR}"/*.conf.example; do
    [[ -f "${staged_conf}" ]] || continue
    grep -v '^HETZNER_' "${staged_conf}" > "${staged_conf}.sanitized" || true
    mv "${staged_conf}.sanitized" "${staged_conf}"
done

remote_copy_to "${SCRIPT_DIR}/lib/"      "${REMOTE_DIR}/lib"
remote_copy_to "${SCRIPT_DIR}/modules/"  "${REMOTE_DIR}/modules"
remote_copy_to "${SCRIPT_DIR}/scripts/"  "${REMOTE_DIR}/scripts"
remote_copy_to "${STAGED_CONFIG_DIR}/"   "${REMOTE_DIR}/config"
remote_copy_to "${SCRIPT_DIR}/harden.sh" "${REMOTE_DIR}/harden.sh"
remote_exec chmod +x "${REMOTE_DIR}/harden.sh" "${REMOTE_DIR}/scripts/lynis_runner.sh" "${REMOTE_DIR}/scripts/validate.sh"

# Ensure python3 is available
remote_exec_script <<'BOOTSTRAP_EOF'
command -v python3 || (apt-get update -y && apt-get install -y python3 || dnf install -y python3)
BOOTSTRAP_EOF
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

# Guarded: harden.sh exits 1 by design when any module fails — that must not
# abort this script before validation/Lynis/artifact collection run. The
# failure is propagated via the final exit code instead.
HARDEN_RC=0
remote_exec "${harden_args[@]}" 2>&1 | tee "${ARTIFACTS_DIR}/harden.log" || HARDEN_RC=$?
if [[ ${HARDEN_RC} -ne 0 ]]; then
    printf '  WARN: hardener exited with code %d — continuing to collect diagnostics.\n' "${HARDEN_RC}"
fi
printf '\n'

# ─── Step 5: Validation ─────────────────────────────────────────────────────

VALIDATE_RC=0
if [[ "${RUN_VALIDATION}" == "true" ]] && [[ "${MODE}" == "apply" ]]; then
    printf '[5/8] Running post-hardening validation...\n'
    remote_exec "${REMOTE_DIR}/scripts/validate.sh" 2>&1 | tee "${ARTIFACTS_DIR}/validate.log" || VALIDATE_RC=$?
    if [[ ${VALIDATE_RC} -ne 0 ]]; then
        printf '  WARN: validation exited with code %d.\n' "${VALIDATE_RC}"
    fi
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

    # Root-owned unpredictable path — a fixed /tmp name could be pre-created
    # (or symlinked) by an unprivileged local user on a multi-user target.
    REMOTE_COLLECT_DIR="$(remote_exec_script 2>/dev/null <<'COLLECT_EOF' | tail -1 | tr -d '[:space:]'
mkdir -p /var/lib/linux-hardener
mktemp -d /var/lib/linux-hardener/collect.XXXXXX
COLLECT_EOF
)" || REMOTE_COLLECT_DIR=""
    if [[ -n "${REMOTE_COLLECT_DIR}" ]]; then
        remote_exec "${REMOTE_DIR}/scripts/lynis_runner.sh" collect "${REMOTE_COLLECT_DIR}" &>/dev/null || true
        # scp runs as ${USER}: make the root-created artifacts readable
        remote_exec chown -R "${USER}:" "${REMOTE_COLLECT_DIR}" 2>/dev/null || true
        remote_copy_from "${REMOTE_COLLECT_DIR}/" "${ARTIFACTS_DIR}/lynis/" 2>/dev/null || true
        remote_exec rm -rf "${REMOTE_COLLECT_DIR}" 2>/dev/null || true
    else
        printf '  WARN: could not create remote collection directory — skipping Lynis artifact copy.\n'
    fi
    remote_copy_from "/var/lib/linux-hardener/last-run.json" "${ARTIFACTS_DIR}/" 2>/dev/null || true
    remote_copy_from "/var/lib/linux-hardener/validation.json" "${ARTIFACTS_DIR}/" 2>/dev/null || true

    # Parse Lynis results locally
    local_pre="${ARTIFACTS_DIR}/lynis/pre-hardening/lynis-report.dat"
    local_post="${ARTIFACTS_DIR}/lynis/post-hardening/lynis-report.dat"

    if [[ -f "${local_pre}" ]] && [[ -f "${local_post}" ]]; then
        # Detect remote distro for labeling.
        # (No `local` here — this is top-level script code, not a function;
        # `local` would error and abort under set -e.)
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

# ─── Step 7.5: Disable root SSH login (optional, done last) ─────────────────
# Last so the earlier steps' root SSH connections keep working. Guarded: only
# proceeds once a non-root sudo account is confirmed reachable.

if [[ "${LOCK_ROOT}" == "true" && "${MODE}" == "apply" ]]; then
    printf '[7.5/8] Disabling root SSH login...\n'

    ROOT_LOCK_OK="false"
    if [[ -n "${ADMIN_USER}" ]] && _ssh_as "${ADMIN_USER}" "${ACCOUNTS_DIR}/${ADMIN_USER}"; then
        ROOT_LOCK_OK="true"
    elif [[ -n "${AUTOMATION_USER}" ]] && _ssh_as "${AUTOMATION_USER}" "${ACCOUNTS_DIR}/${AUTOMATION_USER}" 'sudo -n true'; then
        ROOT_LOCK_OK="true"
    fi

    if [[ "${ROOT_LOCK_OK}" != "true" ]]; then
        printf '  WARN: no non-root sudo account verified reachable — leaving root SSH enabled to avoid lockout.\n\n'
    else
        # Early-sorting drop-in: sshd keeps the FIRST value per keyword, so
        # 00- overrides the hardener's 99-hardening.conf PermitRootLogin.
        remote_exec_script <<'ROOTOFF_EOF'
set -euo pipefail
mkdir -p /etc/ssh/sshd_config.d /run/sshd
printf '# Managed by linux-hardener (run-remote --lock-root)\nPermitRootLogin no\n' \
    > /etc/ssh/sshd_config.d/00-hardener-root-off.conf
chmod 600 /etc/ssh/sshd_config.d/00-hardener-root-off.conf
err="$(mktemp)"
if sshd -t 2>"${err}"; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    echo "  Root SSH login disabled (PermitRootLogin no)."
else
    rm -f /etc/ssh/sshd_config.d/00-hardener-root-off.conf
    echo "  ERROR: sshd -t rejected the root-off drop-in; reverted:"; cat "${err}"
fi
rm -f "${err}"
ROOTOFF_EOF
        printf '\n'
    fi
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

if [[ -n "${ADMIN_USER}" ]]; then
    printf '\n'
    printf ' ── Admin account (key login + password sudo) ─────────────\n'
    printf ' Username : %s\n' "${ADMIN_USER}"
    printf ' SSH key  : %s\n' "${ADMIN_KEY}"
    printf ' Sudo     : requires password (see accounts/%s.README.txt)\n' "${ADMIN_USER}"
    printf ' Connect  : ssh -i %s -p %s %s@%s\n' "${ADMIN_KEY}" "${SSH_PORT}" "${ADMIN_USER}" "${HOST}"
fi

if [[ -n "${AUTOMATION_USER}" ]]; then
    printf '\n'
    printf ' ── Automation account (Ansible; key + NOPASSWD sudo) ─────\n'
    printf ' Username : %s\n' "${AUTOMATION_USER}"
    printf ' SSH key  : %s\n' "${AUTO_KEY}"
    printf ' Ansible  : ansible_user=%s ansible_ssh_private_key_file=%s ansible_become=true\n' "${AUTOMATION_USER}" "${AUTO_KEY}"
fi

if [[ "${LOCK_ROOT}" == "true" ]]; then
    printf '\n Root SSH : disabled (PermitRootLogin no)\n'
fi

printf '════════════════════════════════════════════════════════════\n'

# Propagate hardening/validation failures so CI callers see them
if [[ ${HARDEN_RC} -ne 0 ]]; then
    printf 'Hardening reported failures (exit %d) — see %s/harden.log\n' "${HARDEN_RC}" "${ARTIFACTS_DIR}" >&2
    exit "${HARDEN_RC}"
fi
if [[ ${VALIDATE_RC} -ne 0 ]]; then
    printf 'Validation reported failures (exit %d) — see %s/validate.log\n' "${VALIDATE_RC}" "${ARTIFACTS_DIR}" >&2
    exit "${VALIDATE_RC}"
fi
