#!/usr/bin/env bash
# ionos.sh — Ionos Cloud provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: IONOS_USERNAME, IONOS_PASSWORD environment variables.
# Uses Ionos Cloud API v6.

readonly _IONOS_API_BASE="https://api.ionos.com/cloudapi/v6"

_ionos_auth_header() {
    local credentials
    credentials="$(printf '%s:%s' "${IONOS_USERNAME}" "${IONOS_PASSWORD}" | base64)"
    printf 'Authorization: Basic %s' "${credentials}"
}

_ionos_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    _luks_api_request "${method}" "${_IONOS_API_BASE}${endpoint}" "$(_ionos_auth_header)" "${data}"
}

# Internal state
declare -g _IONOS_DATACENTER_ID=""

_ionos_resolve_image() {
    local image="${1}"
    local location="${2:-de/fra}"

    # Fetch available images for the location
    local images_response
    images_response="$(_ionos_api GET "/images?filter.properties.location=${location}&filter.properties.imageType=HDD")" || return 1

    local search_name=""
    case "${image}" in
        debian-12)      search_name="Debian-12" ;;
        ubuntu-24.04)   search_name="Ubuntu-24" ;;
        rocky-9)        search_name="Rocky-9" ;;
        alma-9)         search_name="AlmaLinux-9" ;;
        *)              search_name="${image}" ;;
    esac

    printf '%s' "${images_response}" | \
        jq -r --arg name "${search_name}" \
        '.items[] | select(.properties.name | test($name; "i")) | .id' | head -1
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-CUBE S}"
    local image="${3}"
    local location="${4:-de/fra}"
    local ssh_key_name="${5:-}"

    if [[ -z "${IONOS_USERNAME:-}" || -z "${IONOS_PASSWORD:-}" ]]; then
        printf 'ERROR: IONOS_USERNAME and IONOS_PASSWORD must be set\n' >&2
        return 1
    fi

    # 1. Create datacenter
    local dc_payload
    dc_payload="$(printf '{
        "properties": {
            "name": "%s-dc",
            "location": "%s"
        }
    }' "${name}" "${location}")"

    local dc_response
    dc_response="$(_ionos_api POST /datacenters "${dc_payload}")" || return 1
    _IONOS_DATACENTER_ID="$(printf '%s' "${dc_response}" | jq -r '.id')"

    # Wait for datacenter to be available
    sleep 15

    # 2. Resolve image
    local image_id
    image_id="$(_ionos_resolve_image "${image}" "${location}")" || return 1

    # 3. Create server with volume
    local server_payload
    server_payload="$(printf '{
        "properties": {
            "name": "%s",
            "cores": 1,
            "ram": 1024
        },
        "entities": {
            "volumes": {
                "items": [{
                    "properties": {
                        "name": "%s-vol",
                        "size": 20,
                        "type": "HDD",
                        "image": "%s",
                        "sshKeys": []
                    }
                }]
            }
        }
    }' "${name}" "${name}" "${image_id}")"

    local server_response
    server_response="$(_ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers" "${server_payload}")" || return 1

    local server_id
    server_id="$(printf '%s' "${server_response}" | jq -r '.id')"

    # Wait for server provisioning
    sleep 30

    # 4. Allocate and assign IP
    local ip_response
    ip_response="$(_ionos_api POST "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/nics" \
        '{"properties": {"name": "public", "lan": 1, "dhcp": true}}')" || return 1

    sleep 10

    # Get IP
    local nic_response
    nic_response="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/nics")" || return 1

    local server_ip
    server_ip="$(printf '%s' "${nic_response}" | \
        jq -r '.items[0].properties.ips[0]' 2>/dev/null)"

    if [[ -z "${server_ip}" || "${server_ip}" == "null" ]]; then
        printf 'ERROR: Could not get IP for Ionos server %s\n' "${server_id}" >&2
        return 1
    fi

    printf '%s|%s' "${server_id}" "${server_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    # Ionos: stop server, attach live CD ISO
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/stop" '' >/dev/null || return 1
    sleep 10

    # Attach rescue CD-ROM
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms" \
        '{"id": "rescue"}' >/dev/null 2>&1 || true

    # Start server (boots from CD)
    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/start" '' >/dev/null || return 1

    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/stop" '' >/dev/null || return 1
    sleep 5

    # Detach CD-ROM
    local cdroms
    cdroms="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms")" || true

    local cdrom_id
    cdrom_id="$(printf '%s' "${cdroms}" | jq -r '.items[0].id' 2>/dev/null)"
    if [[ -n "${cdrom_id}" && "${cdrom_id}" != "null" ]]; then
        _ionos_api DELETE \
            "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/cdroms/${cdrom_id}" \
            >/dev/null 2>&1 || true
    fi
}

provider_reboot() {
    local server_id="${1}"

    _ionos_api POST \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}/start" '' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    # Delete entire datacenter (includes server, volumes, etc.)
    if [[ -n "${_IONOS_DATACENTER_ID}" ]]; then
        _ionos_api DELETE "/datacenters/${_IONOS_DATACENTER_ID}" >/dev/null || return 1
    fi
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_ionos_api GET \
        "/datacenters/${_IONOS_DATACENTER_ID}/servers/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local state
    state="$(printf '%s' "${response}" | jq -r '.metadata.state')"
    local vm_state
    vm_state="$(printf '%s' "${response}" | jq -r '.properties.vmState')"

    case "${vm_state}" in
        RUNNING)  printf 'running' ;;
        SHUTOFF)  printf 'stopped' ;;
        *)        printf '%s' "${vm_state}" ;;
    esac
}
