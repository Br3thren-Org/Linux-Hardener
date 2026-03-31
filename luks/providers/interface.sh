#!/usr/bin/env bash
# interface.sh — Provider contract, dispatcher, and shared API utilities
# Sourced by provision-encrypted.sh. Do not run directly.

# ─── Contract ────────────────────────────────────────────────────────────────
# Every provider adapter MUST implement these functions:
#   provider_create_server  <name> <type> <image> <location> <ssh_key_name>
#       → prints "server_id|ip" on stdout
#   provider_enter_rescue   <server_id>
#       → boots server into rescue mode, prints "rescue_password" on stdout (or "none")
#   provider_exit_rescue    <server_id>
#       → exits rescue mode (may be a no-op if reboot handles it)
#   provider_reboot         <server_id>
#       → normal reboot
#   provider_delete_server  <server_id>
#       → deletes the server
#   provider_get_status     <server_id>
#       → prints one of: running, rescue, stopped, unknown

readonly -a _PROVIDER_CONTRACT=(
    provider_create_server
    provider_enter_rescue
    provider_exit_rescue
    provider_reboot
    provider_delete_server
    provider_get_status
)

readonly -a _SUPPORTED_PROVIDERS=(
    hetzner
    digitalocean
    vultr
    aws
    linode
    ovh
    ionos
)

# ─── Dispatcher ──────────────────────────────────────────────────────────────

# luks_load_provider <provider_name>
#   Sources the adapter file and validates the contract.
luks_load_provider() {
    local provider="${1}"

    if [[ -z "${provider}" ]]; then
        printf 'ERROR: luks_load_provider: provider name is required\n' >&2
        return 1
    fi

    # Validate provider is supported
    local supported="false"
    local p
    for p in "${_SUPPORTED_PROVIDERS[@]}"; do
        if [[ "${p}" == "${provider}" ]]; then
            supported="true"
            break
        fi
    done

    if [[ "${supported}" != "true" ]]; then
        printf 'ERROR: Unsupported provider: %s\n' "${provider}" >&2
        printf 'Supported providers: %s\n' "${_SUPPORTED_PROVIDERS[*]}" >&2
        return 1
    fi

    # Source the adapter
    local adapter_file="${LUKS_DIR}/providers/${provider}.sh"
    if [[ ! -f "${adapter_file}" ]]; then
        printf 'ERROR: Provider adapter not found: %s\n' "${adapter_file}" >&2
        return 1
    fi

    # shellcheck source=/dev/null
    source "${adapter_file}"

    # Validate contract
    local fn
    for fn in "${_PROVIDER_CONTRACT[@]}"; do
        if ! declare -f "${fn}" > /dev/null 2>&1; then
            printf 'ERROR: Provider %s does not implement required function: %s\n' \
                "${provider}" "${fn}" >&2
            return 1
        fi
    done

    printf '[INFO] Loaded provider adapter: %s\n' "${provider}"
    return 0
}

# ─── Shared API Utility ─────────────────────────────────────────────────────

# _luks_api_request <method> <url> <token_header> [data]
#   Generic authenticated HTTP request. Returns JSON body on stdout.
#   Sets _LUKS_HTTP_CODE as a side effect.
_LUKS_HTTP_CODE=""

_luks_api_request() {
    local method="${1}"
    local url="${2}"
    local auth_header="${3}"
    local data="${4:-}"

    local curl_args=(
        curl -sS
        -X "${method}"
        -H "${auth_header}"
        -H "Content-Type: application/json"
        -w '\n%{http_code}'
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    local raw_response
    raw_response="$("${curl_args[@]}" "${url}" 2>/dev/null)" || {
        printf 'ERROR: curl failed for %s %s\n' "${method}" "${url}" >&2
        return 1
    }

    _LUKS_HTTP_CODE="$(printf '%s' "${raw_response}" | tail -1)"
    local body
    body="$(printf '%s' "${raw_response}" | sed '$d')"

    if [[ -z "${_LUKS_HTTP_CODE}" ]] || [[ "${_LUKS_HTTP_CODE}" -ge 400 ]] 2>/dev/null; then
        printf 'ERROR: API %s %s returned HTTP %s: %s\n' \
            "${method}" "${url}" "${_LUKS_HTTP_CODE:-000}" "${body}" >&2
        return 1
    fi

    printf '%s' "${body}"
    return 0
}

# _luks_wait_ssh <ip> <port> <key_path> <user> [timeout_seconds]
#   Polls SSH until connectable. Returns 0 on success, 1 on timeout.
_luks_wait_ssh() {
    local ip="${1}"
    local port="${2}"
    local key_path="${3}"
    local user="${4}"
    local timeout="${5:-120}"

    local elapsed=0
    local interval=5

    while (( elapsed < timeout )); do
        if ssh \
            -i "${key_path}" -p "${port}" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -o BatchMode=yes \
            "${user}@${ip}" 'true' &>/dev/null 2>&1; then
            return 0
        fi
        sleep "${interval}"
        (( elapsed += interval )) || true
    done

    printf 'ERROR: SSH to %s@%s:%s not reachable after %ds\n' \
        "${user}" "${ip}" "${port}" "${timeout}" >&2
    return 1
}

# _luks_wait_ssh_down <ip> <port> [timeout_seconds]
#   Waits until SSH stops responding (for reboot detection).
_luks_wait_ssh_down() {
    local ip="${1}"
    local port="${2}"
    local timeout="${3:-60}"

    local elapsed=0
    local interval=3

    while (( elapsed < timeout )); do
        if ! ssh \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=3 -o BatchMode=yes \
            "root@${ip}" -p "${port}" 'true' &>/dev/null 2>&1; then
            return 0
        fi
        sleep "${interval}"
        (( elapsed += interval )) || true
    done

    return 1
}
