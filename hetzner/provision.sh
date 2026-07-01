#!/usr/bin/env bash
# hetzner/provision.sh — Provision Hetzner cloud test servers for each image
# Usage: HETZNER_IMAGES=debian-12,ubuntu-24.04 ./hetzner/provision.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source Hetzner API helpers
# shellcheck source=hetzner/api.sh
source "${SCRIPT_DIR}/api.sh"

# ─── Config (read from environment) ──────────────────────────────────────────

HETZNER_SERVER_TYPE="${HETZNER_SERVER_TYPE:-cx23}"
HETZNER_LOCATION="${HETZNER_LOCATION:-nbg1}"
HETZNER_SSH_KEY_NAME="${HETZNER_SSH_KEY_NAME:-}"
HETZNER_SSH_KEY_PATH="${HETZNER_SSH_KEY_PATH:-${HOME}/.ssh/id_ed25519}"
# Expand a leading ~ (unlike env/config, ssh -i does not do tilde expansion)
HETZNER_SSH_KEY_PATH="${HETZNER_SSH_KEY_PATH/#\~/${HOME}}"
HETZNER_IMAGES="${HETZNER_IMAGES:-debian-12}"

# ─── Build ID ─────────────────────────────────────────────────────────────────

BUILD_ID="$(date +%Y%m%d-%H%M%S)-$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
readonly BUILD_ID

# ─── Prerequisites ────────────────────────────────────────────────────────────

check_prerequisites() {
    local errors=0

    if [[ -z "${HETZNER_API_TOKEN:-}" ]]; then
        printf '[ERROR] HETZNER_API_TOKEN is not set\n' >&2
        (( errors++ )) || true
    fi

    if [[ -z "${HETZNER_SSH_KEY_NAME}" ]]; then
        printf '[ERROR] HETZNER_SSH_KEY_NAME is not set\n' >&2
        (( errors++ )) || true
    fi

    if ! command -v jq &>/dev/null; then
        printf '[ERROR] jq is not installed or not in PATH\n' >&2
        (( errors++ )) || true
    fi

    if ! command -v hcloud &>/dev/null; then
        printf '[WARN] hcloud CLI not found — will use REST API fallback\n' >&2
    fi

    if (( errors > 0 )); then
        printf '[ERROR] %d prerequisite check(s) failed\n' "${errors}" >&2
        return 1
    fi

    return 0
}

# ─── SSH Connectivity Poll ────────────────────────────────────────────────────

# wait_for_ssh <ip> [timeout_seconds]
wait_for_ssh() {
    local ip="${1}"
    local timeout="${2:-120}"
    local elapsed=0
    local interval=5

    printf '[INFO] Waiting for SSH on %s (timeout %ds)...\n' "${ip}" "${timeout}" >&2

    while (( elapsed < timeout )); do
        if ssh \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            -o BatchMode=yes \
            -i "${HETZNER_SSH_KEY_PATH}" \
            "root@${ip}" \
            'true' &>/dev/null; then
            printf '[INFO] SSH is available on %s after %ds\n' "${ip}" "${elapsed}" >&2
            return 0
        fi

        sleep "${interval}"
        (( elapsed += interval )) || true
    done

    printf '[ERROR] SSH not available on %s after %ds\n' "${ip}" "${timeout}" >&2
    return 1
}

# ─── Server Creation ──────────────────────────────────────────────────────────

# create_server <image>
# Prints "id|name|ip|image" as the last line on success
create_server() {
    local image="${1}"
    local server_name="hardener-test-${image}-${BUILD_ID}"
    local server_id=""
    local server_ip=""
    local used_hcloud=false

    printf '[INFO] Creating server: %s (image=%s type=%s location=%s)\n' \
        "${server_name}" "${image}" "${HETZNER_SERVER_TYPE}" "${HETZNER_LOCATION}" >&2

    # ── Primary: hcloud CLI ───────────────────────────────────────────────────
    if command -v hcloud &>/dev/null; then
        local hcloud_output
        if hcloud_output="$(
            hcloud server create \
                --name "${server_name}" \
                --type "${HETZNER_SERVER_TYPE}" \
                --image "${image}" \
                --location "${HETZNER_LOCATION}" \
                --ssh-key "${HETZNER_SSH_KEY_NAME}" \
                -o json 2>/dev/null
        )"; then
            server_id="$(printf '%s' "${hcloud_output}" | jq -r '.server.id // empty')"
            server_ip="$(printf '%s' "${hcloud_output}" | jq -r '.server.public_net.ipv4.ip // empty')"
            if [[ -n "${server_id}" && -n "${server_ip}" ]]; then
                used_hcloud=true
                printf '[INFO] hcloud created server id=%s ip=%s\n' "${server_id}" "${server_ip}" >&2
            else
                printf '[WARN] hcloud output missing server id/ip — falling back to REST API\n' >&2
            fi
        else
            printf '[WARN] hcloud server create failed — falling back to REST API\n' >&2
        fi
    fi

    # ── Fallback: REST API ────────────────────────────────────────────────────
    if [[ "${used_hcloud}" == "false" ]]; then
        # hetzner_api_create_server returns "id|ip" on stdout
        local api_response
        if ! api_response="$(
            hetzner_api_create_server \
                "${server_name}" \
                "${HETZNER_SERVER_TYPE}" \
                "${image}" \
                "${HETZNER_LOCATION}" \
                "${HETZNER_SSH_KEY_NAME}"
        )"; then
            printf '[ERROR] Failed to create server %s via API\n' "${server_name}" >&2
            return 1
        fi

        server_id="$(printf '%s' "${api_response}" | cut -d'|' -f1)"
        if [[ -z "${server_id}" ]]; then
            printf '[ERROR] API returned empty server ID for %s\n' "${server_name}" >&2
            return 1
        fi

        # Wait until server reaches "running" state, then fetch confirmed IP
        hetzner_api_wait_running "${server_id}"

        server_ip="$(hetzner_api_get_ip "${server_id}")"
        if [[ -z "${server_ip}" ]]; then
            printf '[ERROR] Could not get IP for server %s (id=%s)\n' "${server_name}" "${server_id}" >&2
            return 1
        fi

        printf '[INFO] API created server id=%s ip=%s\n' "${server_id}" "${server_ip}" >&2
    fi

    # Record the server BEFORE the SSH wait: if wait_for_ssh times out and
    # aborts the run, this log is the only trace of the billing server.
    if [[ -n "${CREATED_SERVERS_LOG:-}" ]]; then
        printf '%s|%s|%s|%s\n' "${server_id}" "${server_name}" "${server_ip}" "${image}" \
            >> "${CREATED_SERVERS_LOG}"
    fi

    # ── Wait for SSH ──────────────────────────────────────────────────────────
    wait_for_ssh "${server_ip}" 120

    # Final output line consumed by caller — stdout only, no INFO noise
    printf '%s|%s|%s|%s\n' "${server_id}" "${server_name}" "${server_ip}" "${image}"
}

# ─── Manifest ─────────────────────────────────────────────────────────────────

# write_manifest <path> <json_entry...> — write entries as a JSON array
write_manifest() {
    local manifest_path="${1}"
    shift
    local entries=("$@")
    {
        printf '[\n'
        local i
        for (( i=0; i<${#entries[@]}; i++ )); do
            if (( i < ${#entries[@]} - 1 )); then
                printf '%s,\n' "${entries[$i]}"
            else
                printf '%s\n' "${entries[$i]}"
            fi
        done
        printf ']\n'
    } > "${manifest_path}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    check_prerequisites

    # Print header
    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf ' Hetzner Provisioner\n'
    printf '────────────────────────────────────────────────────────────\n'
    printf ' BUILD_ID    : %s\n' "${BUILD_ID}"
    printf ' Images      : %s\n' "${HETZNER_IMAGES}"
    printf ' Server type : %s\n' "${HETZNER_SERVER_TYPE}"
    printf ' Location    : %s\n' "${HETZNER_LOCATION}"
    printf '════════════════════════════════════════════════════════════\n\n'

    # Create artifacts directory for this build
    local artifacts_dir="${PROJECT_ROOT}/artifacts/${BUILD_ID}"
    mkdir -p "${artifacts_dir}"
    printf '[INFO] Artifacts directory: %s\n' "${artifacts_dir}"

    # Every created server is appended here immediately — if provisioning
    # aborts mid-run, this file lists what needs manual teardown.
    CREATED_SERVERS_LOG="${artifacts_dir}/created-servers.log"
    : > "${CREATED_SERVERS_LOG}"

    # Split comma-separated image list
    local images_array=()
    IFS=',' read -ra images_array <<< "${HETZNER_IMAGES}"

    # Provision each image and collect results. The manifest is REWRITTEN
    # after every successful server so a mid-run failure leaves a usable
    # servers.json for teardown of the servers created so far.
    local manifest_path="${artifacts_dir}/servers.json"
    local json_entries=()
    local image
    for image in "${images_array[@]}"; do
        # Trim whitespace
        image="${image#"${image%%[![:space:]]*}"}"
        image="${image%"${image##*[![:space:]]}"}"

        printf '[INFO] Provisioning image: %s\n' "${image}"

        # create_server writes progress to stderr; stdout carries only "id|name|ip|image"
        local result_line
        result_line="$(create_server "${image}")"

        local srv_id srv_name srv_ip srv_image
        IFS='|' read -r srv_id srv_name srv_ip srv_image <<< "${result_line}"

        printf '[INFO] Provisioned: id=%s name=%s ip=%s image=%s\n' \
            "${srv_id}" "${srv_name}" "${srv_ip}" "${srv_image}"

        # Build JSON object for this server (avoid jq dependency for building)
        json_entries+=("$(
            printf '  {\n    "id": %s,\n    "name": "%s",\n    "ip": "%s",\n    "image": "%s",\n    "build_id": "%s"\n  }' \
                "${srv_id}" "${srv_name}" "${srv_ip}" "${srv_image}" "${BUILD_ID}"
        )")

        write_manifest "${manifest_path}" "${json_entries[@]}"
    done

    printf '\n[INFO] Manifest written: %s\n' "${manifest_path}"
    printf '[INFO] BUILD_ID: %s\n' "${BUILD_ID}"

    # Final line — BUILD_ID for orchestrator capture
    printf '%s\n' "${BUILD_ID}"
}

main "$@"
