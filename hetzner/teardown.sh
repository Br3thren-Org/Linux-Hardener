#!/usr/bin/env bash
# hetzner/teardown.sh — Delete Hetzner test servers provisioned by this project.
# Usage:
#   teardown.sh [manifest_file]          Delete servers listed in manifest (default: servers.json)
#   teardown.sh --build-id <id>          Delete servers from artifacts/<id>/servers.json
#   teardown.sh --all-test-servers       Delete all servers matching "hardener-test-*"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=hetzner/api.sh
source "${SCRIPT_DIR}/api.sh"

# ─── Constants ───────────────────────────────────────────────────────────────

readonly DEFAULT_MANIFEST="servers.json"
readonly TEST_SERVER_PATTERN="hardener-test"

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "${0}") [options]

Options:
  [manifest_file]          Path to servers.json manifest (default: ${DEFAULT_MANIFEST})
  --build-id <id>          Use manifest at artifacts/<id>/servers.json
  --all-test-servers       Delete all Hetzner servers matching "${TEST_SERVER_PATTERN}*"
  --help, -h               Show this help message

The manifest file must be JSON with an array of objects containing "id" and "name" fields.
Requires HETZNER_API_TOKEN in environment when falling back to the REST API.
EOF
}

# ─── Helper: delete a single server ──────────────────────────────────────────

# delete_server <id> <name>
#   Tries hcloud first; falls back to hetzner_api_delete_server.
#   Returns 0 on success, 1 on failure.
delete_server() {
    local server_id="${1}"
    local server_name="${2}"

    if [[ -z "${server_id}" || -z "${server_name}" ]]; then
        printf 'ERROR: delete_server requires id and name\n' >&2
        return 1
    fi

    # Attempt hcloud CLI first
    if command -v hcloud &>/dev/null; then
        if hcloud server delete "${server_id}" 2>/dev/null; then
            printf 'DELETED (hcloud): %s (id=%s)\n' "${server_name}" "${server_id}"
            return 0
        fi
        printf 'WARN: hcloud delete failed for %s (id=%s); trying REST API fallback\n' \
            "${server_name}" "${server_id}" >&2
    fi

    # Fallback: REST API
    if hetzner_api_delete_server "${server_id}"; then
        printf 'DELETED (api):   %s (id=%s)\n' "${server_name}" "${server_id}"
        return 0
    fi

    printf 'ERROR: Failed to delete server %s (id=%s)\n' "${server_name}" "${server_id}" >&2
    return 1
}

# ─── Verify a server no longer exists ────────────────────────────────────────

# verify_deleted <id> <name>
#   Returns 0 if the server is gone (API returns 404 or empty), 1 if still present.
verify_deleted() {
    local server_id="${1}"
    local server_name="${2}"

    # Try hcloud first
    if command -v hcloud &>/dev/null; then
        if ! hcloud server describe "${server_id}" &>/dev/null; then
            return 0
        fi
        printf 'WARN: Server %s (id=%s) still visible via hcloud after delete\n' \
            "${server_name}" "${server_id}" >&2
        return 1
    fi

    # Fallback: REST API
    local response
    if response="$(hetzner_api GET "/servers/${server_id}" 2>/dev/null)"; then
        local found_name
        found_name="$(printf '%s' "${response}" | jq -r '.server.name // empty')"
        if [[ -n "${found_name}" ]]; then
            printf 'WARN: Server %s (id=%s) still present via API after delete\n' \
                "${server_name}" "${server_id}" >&2
            return 1
        fi
    fi

    return 0
}

# ─── Teardown from manifest ──────────────────────────────────────────────────

# teardown_from_manifest <manifest_path>
#   Reads a JSON array from manifest_path, deletes each server, reports totals.
teardown_from_manifest() {
    local manifest="${1}"

    if [[ -z "${manifest}" ]]; then
        printf 'ERROR: teardown_from_manifest requires a manifest path\n' >&2
        return 1
    fi

    if [[ ! -f "${manifest}" ]]; then
        printf 'ERROR: Manifest not found: %s\n' "${manifest}" >&2
        return 1
    fi

    local deleted=0
    local failed=0
    local total=0

    while IFS= read -r entry; do
        local server_id server_name
        server_id="$(printf '%s' "${entry}" | jq -r '.id // empty')"
        server_name="$(printf '%s' "${entry}" | jq -r '.name // empty')"

        if [[ -z "${server_id}" || -z "${server_name}" ]]; then
            printf 'WARN: Skipping entry with missing id or name: %s\n' "${entry}" >&2
            (( failed++ )) || true
            (( total++ )) || true
            continue
        fi

        (( total++ )) || true

        if delete_server "${server_id}" "${server_name}"; then
            verify_deleted "${server_id}" "${server_name}" || true
            (( deleted++ )) || true
        else
            (( failed++ )) || true
        fi
    done < <(jq -c '.[]' "${manifest}")

    printf '\nTeardown complete: %d deleted, %d failed (total: %d)\n' \
        "${deleted}" "${failed}" "${total}"

    if (( failed > 0 )); then
        return 1
    fi
    return 0
}

# ─── Teardown all test servers ───────────────────────────────────────────────

# teardown_all_test_servers()
#   Lists all servers matching "hardener-test-*", deletes each.
teardown_all_test_servers() {
    local deleted=0
    local failed=0
    local total=0

    printf 'Searching for servers matching "%s-*"...\n' "${TEST_SERVER_PATTERN}"

    # Build a list of "id|name" entries
    local entries=()

    if command -v hcloud &>/dev/null; then
        # Use hcloud server list -o json, then filter with jq
        local hcloud_json
        if ! hcloud_json="$(hcloud server list -o json 2>/dev/null)"; then
            printf 'WARN: hcloud server list failed; trying REST API fallback\n' >&2
        else
            while IFS= read -r line; do
                entries+=("${line}")
            done < <(printf '%s' "${hcloud_json}" \
                | jq -r --arg pat "${TEST_SERVER_PATTERN}" \
                    '.[] | select(.name | startswith($pat)) | "\(.id)|\(.name)"')
        fi
    fi

    # API fallback if hcloud not available or returned nothing
    if (( ${#entries[@]} == 0 )); then
        local api_list
        if ! api_list="$(hetzner_api GET "/servers" 2>/dev/null)"; then
            printf 'ERROR: Failed to list servers via REST API\n' >&2
            return 1
        fi
        while IFS= read -r line; do
            entries+=("${line}")
        done < <(printf '%s' "${api_list}" \
            | jq -r --arg pat "${TEST_SERVER_PATTERN}" \
                '.servers[] | select(.name | startswith($pat)) | "\(.id)|\(.name)"')
    fi

    if (( ${#entries[@]} == 0 )); then
        printf 'No servers matching "%s-*" found.\n' "${TEST_SERVER_PATTERN}"
        return 0
    fi

    printf 'Found %d server(s) to delete.\n' "${#entries[@]}"

    for entry in "${entries[@]}"; do
        local server_id server_name
        server_id="${entry%%|*}"
        server_name="${entry##*|}"

        (( total++ )) || true

        if delete_server "${server_id}" "${server_name}"; then
            verify_deleted "${server_id}" "${server_name}" || true
            (( deleted++ )) || true
        else
            (( failed++ )) || true
        fi
    done

    printf '\nTeardown complete: %d deleted, %d failed (total: %d)\n' \
        "${deleted}" "${failed}" "${total}"

    if (( failed > 0 )); then
        return 1
    fi
    return 0
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    if [[ $# -eq 0 ]]; then
        # Default: use servers.json in the current directory
        teardown_from_manifest "${DEFAULT_MANIFEST}"
        return
    fi

    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;

        --build-id)
            if [[ $# -lt 2 || -z "${2:-}" ]]; then
                printf 'ERROR: --build-id requires a build ID argument\n' >&2
                usage >&2
                exit 1
            fi
            local build_id="${2}"
            local manifest_path
            manifest_path="$(pwd)/artifacts/${build_id}/servers.json"
            printf 'Using manifest: %s\n' "${manifest_path}"
            teardown_from_manifest "${manifest_path}"
            ;;

        --all-test-servers)
            teardown_all_test_servers
            ;;

        -*)
            printf 'ERROR: Unknown option: %s\n' "${1}" >&2
            usage >&2
            exit 1
            ;;

        *)
            # Treat argument as a manifest file path
            printf 'Using manifest: %s\n' "${1}"
            teardown_from_manifest "${1}"
            ;;
    esac
}

main "$@"
