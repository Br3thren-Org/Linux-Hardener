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
