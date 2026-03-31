#!/usr/bin/env bash
# ovh.sh — OVH provider adapter for LUKS provisioning
# Implements the 6-function provider contract.
# Requires: OVH_APP_KEY, OVH_APP_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT.
# OVH API uses signed requests — this adapter wraps the OVH authentication.

: "${OVH_ENDPOINT:=ovh-eu}"

_ovh_base_url() {
    case "${OVH_ENDPOINT}" in
        ovh-eu)  printf 'https://eu.api.ovh.com/1.0' ;;
        ovh-ca)  printf 'https://ca.api.ovh.com/1.0' ;;
        ovh-us)  printf 'https://api.us.ovhcloud.com/1.0' ;;
        *)       printf 'https://eu.api.ovh.com/1.0' ;;
    esac
}

_ovh_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    local url="$(_ovh_base_url)${endpoint}"
    local timestamp
    timestamp="$(curl -s "$(_ovh_base_url)/auth/time")"

    # OVH signature: "$1$" + SHA1(APP_SECRET+CONSUMER_KEY+METHOD+URL+BODY+TIMESTAMP)
    local to_sign="${OVH_APP_SECRET}+${OVH_CONSUMER_KEY}+${method}+${url}+${data}+${timestamp}"
    local signature
    signature="\$1\$$(printf '%s' "${to_sign}" | sha1sum | awk '{print $1}')"

    local curl_args=(
        curl -sS
        -X "${method}"
        -H "X-Ovh-Application: ${OVH_APP_KEY}"
        -H "X-Ovh-Timestamp: ${timestamp}"
        -H "X-Ovh-Signature: ${signature}"
        -H "X-Ovh-Consumer: ${OVH_CONSUMER_KEY}"
        -H "Content-Type: application/json"
        -w '\n%{http_code}'
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    local raw_response
    raw_response="$("${curl_args[@]}" "${url}" 2>/dev/null)" || {
        printf 'ERROR: OVH API call failed: %s %s\n' "${method}" "${endpoint}" >&2
        return 1
    }

    local http_code
    http_code="$(printf '%s' "${raw_response}" | tail -1)"
    local body
    body="$(printf '%s' "${raw_response}" | sed '$d')"

    if [[ -z "${http_code}" ]] || [[ "${http_code}" -ge 400 ]] 2>/dev/null; then
        printf 'ERROR: OVH API %s %s returned HTTP %s: %s\n' \
            "${method}" "${endpoint}" "${http_code:-000}" "${body}" >&2
        return 1
    fi

    printf '%s' "${body}"
}

_ovh_resolve_image() {
    local image="${1}"
    # OVH uses OS names, resolved dynamically per server
    case "${image}" in
        debian-12)      printf 'debian12_64' ;;
        ubuntu-24.04)   printf 'ubuntu2404-server_64' ;;
        rocky-9)        printf 'rocky9_64' ;;
        alma-9)         printf 'almalinux9_64' ;;
        *)              printf '%s' "${image}" ;;
    esac
}

# ─── Contract Implementation ─────────────────────────────────────────────────

provider_create_server() {
    local name="${1}"
    local server_type="${2:-d2-2}"
    local image="${3}"
    local location="${4:-GRA7}"
    local ssh_key_name="${5:-}"

    if [[ -z "${OVH_APP_KEY:-}" || -z "${OVH_APP_SECRET:-}" || -z "${OVH_CONSUMER_KEY:-}" ]]; then
        printf 'ERROR: OVH credentials (OVH_APP_KEY, OVH_APP_SECRET, OVH_CONSUMER_KEY) must be set\n' >&2
        return 1
    fi

    local ovh_image
    ovh_image="$(_ovh_resolve_image "${image}")"

    local ssh_key_json=""
    if [[ -n "${ssh_key_name}" ]]; then
        ssh_key_json="$(printf ', "sshKeyId": "%s"' "${ssh_key_name}")"
    fi

    local payload
    payload="$(printf '{
        "name": "%s",
        "flavorId": "%s",
        "imageId": "%s",
        "region": "%s"%s
    }' "${name}" "${server_type}" "${ovh_image}" "${location}" "${ssh_key_json}")"

    local response
    response="$(_ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance" "${payload}")" || return 1

    local server_id server_ip
    server_id="$(printf '%s' "${response}" | jq -r '.id')"

    # Wait for ACTIVE
    local elapsed=0
    local timeout=180
    while (( elapsed < timeout )); do
        local status_response
        status_response="$(_ovh_api GET "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}")" || true

        local status
        status="$(printf '%s' "${status_response}" | jq -r '.status')"

        if [[ "${status}" == "ACTIVE" ]]; then
            server_ip="$(printf '%s' "${status_response}" | \
                jq -r '.ipAddresses[] | select(.type == "public" and .version == 4) | .ip' | head -1)"
            break
        fi
        sleep 5
        (( elapsed += 5 )) || true
    done

    if [[ -z "${server_ip}" ]]; then
        printf 'ERROR: Could not get IP for OVH instance %s\n' "${server_id}" >&2
        return 1
    fi

    printf '%s|%s' "${server_id}" "${server_ip}"
}

provider_enter_rescue() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/rescueMode" \
        '{"rescue": true, "imageId": "rescue-ovh"}' >/dev/null || return 1

    # OVH returns a temp root password via email or API response
    printf 'none'
}

provider_exit_rescue() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/rescueMode" \
        '{"rescue": false}' >/dev/null || return 1
}

provider_reboot() {
    local server_id="${1}"

    _ovh_api POST "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}/reboot" \
        '{"type": "hard"}' >/dev/null || return 1
}

provider_delete_server() {
    local server_id="${1}"

    _ovh_api DELETE "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}" >/dev/null || return 1
}

provider_get_status() {
    local server_id="${1}"

    local response
    response="$(_ovh_api GET "/cloud/project/${OVH_PROJECT_ID:-}/instance/${server_id}")" || {
        printf 'unknown'
        return 1
    }

    local status
    status="$(printf '%s' "${response}" | jq -r '.status')"

    case "${status}" in
        ACTIVE)     printf 'running' ;;
        SHUTOFF)    printf 'stopped' ;;
        RESCUE)     printf 'rescue' ;;
        *)          printf '%s' "${status}" ;;
    esac
}
