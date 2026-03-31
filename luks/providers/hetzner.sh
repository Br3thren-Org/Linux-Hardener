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

    # Enable rescue mode (linux64) with SSH keys for key-based auth
    local ssh_keys_json="[]"
    if [[ -n "${SSH_KEY_NAME:-}" ]]; then
        # Resolve SSH key ID from name
        local keys_response
        keys_response="$(curl -sS -H "$(_hetzner_auth_header)" "${_HETZNER_API_BASE}/ssh_keys" 2>/dev/null)"
        local key_id
        key_id="$(printf '%s' "${keys_response}" | jq -r --arg name "${SSH_KEY_NAME}" \
            '.ssh_keys[] | select(.name == $name) | .id' 2>/dev/null)"
        if [[ -n "${key_id}" && "${key_id}" != "null" ]]; then
            ssh_keys_json="[${key_id}]"
        fi
    fi

    local payload
    payload="$(printf '{"type": "linux64", "ssh_keys": %s}' "${ssh_keys_json}")"

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
