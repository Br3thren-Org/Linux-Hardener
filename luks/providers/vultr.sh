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
