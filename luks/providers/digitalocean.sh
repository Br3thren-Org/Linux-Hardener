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
