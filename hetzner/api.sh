# hetzner/api.sh — Hetzner Cloud REST API helpers
# Sourced by provision.sh and teardown.sh. Do NOT add set -euo pipefail here;
# the caller owns that. Requires: curl, jq, HETZNER_API_TOKEN in environment.

# ─── Constants ───────────────────────────────────────────────────────────────

readonly HETZNER_API_BASE="https://api.hetzner.cloud/v1"

# ─── Core Request Wrapper ────────────────────────────────────────────────────

# hetzner_api <method> <endpoint> [data]
#   Authenticated curl wrapper. Returns raw JSON response on stdout.
#   Exits non-zero on HTTP/transport error.
hetzner_api() {
    local method="${1}"
    local endpoint="${2}"
    local data="${3:-}"

    if [[ -z "${HETZNER_API_TOKEN:-}" ]]; then
        printf 'ERROR: HETZNER_API_TOKEN is not set\n' >&2
        return 1
    fi

    local url="${HETZNER_API_BASE}${endpoint}"
    local curl_args=(
        -sf
        -X "${method}"
        -H "Authorization: Bearer ${HETZNER_API_TOKEN}"
        -H "Content-Type: application/json"
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    curl "${curl_args[@]}" "${url}"
}

# ─── Server Lifecycle ────────────────────────────────────────────────────────

# hetzner_api_create_server <name> <server_type> <image> <location> <ssh_key_name>
#   POST /servers. On success prints "id|ip" to stdout.
#   Returns 1 on API error.
hetzner_api_create_server() {
    local name="${1}"
    local server_type="${2}"
    local image="${3}"
    local location="${4}"
    local ssh_key_name="${5}"

    if [[ -z "${name}" || -z "${server_type}" || -z "${image}" || -z "${location}" || -z "${ssh_key_name}" ]]; then
        printf 'ERROR: hetzner_api_create_server requires name, server_type, image, location, ssh_key_name\n' >&2
        return 1
    fi

    local payload
    payload="$(printf '{"name":"%s","server_type":"%s","image":"%s","location":"%s","ssh_keys":["%s"]}' \
        "${name}" "${server_type}" "${image}" "${location}" "${ssh_key_name}")"

    local response
    if ! response="$(hetzner_api POST /servers "${payload}")"; then
        printf 'ERROR: API request to POST /servers failed\n' >&2
        return 1
    fi

    local server_id ip
    server_id="$(printf '%s' "${response}" | jq -r '.server.id // empty')"
    ip="$(printf '%s' "${response}" | jq -r '.server.public_net.ipv4.ip // empty')"

    if [[ -z "${server_id}" || -z "${ip}" ]]; then
        printf 'ERROR: Failed to extract server id/ip from response: %s\n' "${response}" >&2
        return 1
    fi

    printf '%s|%s\n' "${server_id}" "${ip}"
}

# hetzner_api_delete_server <server_id>
#   DELETE /servers/{id}. Returns curl exit code.
hetzner_api_delete_server() {
    local server_id="${1}"

    if [[ -z "${server_id}" ]]; then
        printf 'ERROR: hetzner_api_delete_server requires server_id\n' >&2
        return 1
    fi

    hetzner_api DELETE "/servers/${server_id}"
}

# hetzner_api_get_server <server_id>
#   GET /servers/{id}. Prints full JSON to stdout.
hetzner_api_get_server() {
    local server_id="${1}"

    if [[ -z "${server_id}" ]]; then
        printf 'ERROR: hetzner_api_get_server requires server_id\n' >&2
        return 1
    fi

    hetzner_api GET "/servers/${server_id}"
}

# ─── Polling ─────────────────────────────────────────────────────────────────

# hetzner_api_wait_running <server_id> [timeout_seconds]
#   Polls every 5 s until server status == "running" or timeout (default 120 s).
#   Returns 0 when running, 1 on timeout or error.
hetzner_api_wait_running() {
    local server_id="${1}"
    local timeout="${2:-120}"

    if [[ -z "${server_id}" ]]; then
        printf 'ERROR: hetzner_api_wait_running requires server_id\n' >&2
        return 1
    fi

    local elapsed=0
    local interval=5
    local status response

    while (( elapsed < timeout )); do
        response="$(hetzner_api GET "/servers/${server_id}")" || {
            printf 'ERROR: Failed to poll server %s status\n' "${server_id}" >&2
            return 1
        }

        status="$(printf '%s' "${response}" | jq -r '.server.status // empty')"

        if [[ "${status}" == "running" ]]; then
            return 0
        fi

        sleep "${interval}"
        (( elapsed += interval ))
    done

    printf 'ERROR: Timed out after %ds waiting for server %s to reach running state (last status: %s)\n' \
        "${timeout}" "${server_id}" "${status:-unknown}" >&2
    return 1
}

# ─── Query Helpers ────────────────────────────────────────────────────────────

# hetzner_api_get_ip <server_id>
#   Prints the public IPv4 address of the server to stdout.
hetzner_api_get_ip() {
    local server_id="${1}"

    if [[ -z "${server_id}" ]]; then
        printf 'ERROR: hetzner_api_get_ip requires server_id\n' >&2
        return 1
    fi

    local response
    if ! response="$(hetzner_api GET "/servers/${server_id}")"; then
        printf 'ERROR: API request for server %s failed\n' "${server_id}" >&2
        return 1
    fi

    local ip
    ip="$(printf '%s' "${response}" | jq -r '.server.public_net.ipv4.ip // empty')"

    if [[ -z "${ip}" ]]; then
        printf 'ERROR: No IPv4 address found for server %s\n' "${server_id}" >&2
        return 1
    fi

    printf '%s\n' "${ip}"
}

# hetzner_api_list_servers [name_pattern]
#   GET /servers?name=<pattern>. Prints "id|name|ip|status" per server line.
#   If name_pattern is empty, lists all servers.
hetzner_api_list_servers() {
    local name_pattern="${1:-}"

    local endpoint="/servers"
    if [[ -n "${name_pattern}" ]]; then
        endpoint="/servers?name=${name_pattern}"
    fi

    local response
    if ! response="$(hetzner_api GET "${endpoint}")"; then
        printf 'ERROR: API request to GET %s failed\n' "${endpoint}" >&2
        return 1
    fi

    printf '%s' "${response}" \
        | jq -r '.servers[] | "\(.id)|\(.name)|\(.public_net.ipv4.ip)|\(.status)"'
}
