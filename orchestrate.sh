#!/usr/bin/env bash
# orchestrate.sh — Main test cycle orchestrator for Linux Hardener
# Runs on the CONTROL MACHINE (Mac/workstation), NOT on the target server.
# Provisions Hetzner servers, bootstraps the framework, runs hardening,
# collects Lynis artifacts, and generates reports.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Defaults (overridden by config or flags) ─────────────────────────────────

HETZNER_API_TOKEN="${HETZNER_API_TOKEN:-}"
HETZNER_SSH_KEY_NAME="${HETZNER_SSH_KEY_NAME:-}"
HETZNER_SSH_KEY_PATH="${HETZNER_SSH_KEY_PATH:-~/.ssh/id_ed25519}"
HETZNER_SERVER_TYPE="${HETZNER_SERVER_TYPE:-cx22}"
HETZNER_LOCATION="${HETZNER_LOCATION:-fsn1}"
HETZNER_IMAGES="${HETZNER_IMAGES:-debian-12,ubuntu-24.04,rocky-9,alma-9}"

KEEP_ON_FAILURE="${KEEP_ON_FAILURE:-false}"
ENABLE_ITERATION="${ENABLE_ITERATION:-true}"
MAX_ITERATIONS="${MAX_ITERATIONS:-3}"
MIN_SCORE_DELTA="${MIN_SCORE_DELTA:-1}"
ENABLE_REBOOT_TEST="${ENABLE_REBOOT_TEST:-false}"
PARALLEL_TESTS="${PARALLEL_TESTS:-true}"

# ─── Flag state ───────────────────────────────────────────────────────────────

FLAG_CONFIG=""
FLAG_KEEP_ON_FAILURE="false"
FLAG_NO_ITERATE="false"
FLAG_SKIP_TEARDOWN="false"
FLAG_IMAGES=""

# ─── Overall pass tracking ────────────────────────────────────────────────────

OVERALL_PASS="true"

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "${0}") [options]

Runs the full Linux Hardener test cycle against Hetzner cloud servers.
Provisions, bootstraps, hardens, collects artifacts, and tears down.

Options:
  --config PATH          Path to config file (default: config/hardener.conf)
  --keep-on-failure      Keep servers alive if any test fails (for debugging)
  --no-iterate           Disable iteration loop even if ENABLE_ITERATION=true
  --skip-teardown        Do not tear down servers at the end
  --images LIST          Comma-separated image list (overrides config)
  --help, -h             Show this help message

Environment:
  HETZNER_API_TOKEN      Hetzner Cloud API token (required)
  HETZNER_SSH_KEY_NAME   Name of the SSH key registered in Hetzner (required)
  HETZNER_SSH_KEY_PATH   Path to local private key (default: ~/.ssh/id_ed25519)

Examples:
  $(basename "${0}")
  $(basename "${0}") --config /etc/hardener.conf --images debian-12,ubuntu-24.04
  $(basename "${0}") --keep-on-failure --skip-teardown
EOF
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --config)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --config requires a PATH argument\n' >&2
                    exit 1
                fi
                FLAG_CONFIG="${2}"
                shift 2
                ;;
            --keep-on-failure)
                FLAG_KEEP_ON_FAILURE="true"
                shift
                ;;
            --no-iterate)
                FLAG_NO_ITERATE="true"
                shift
                ;;
            --skip-teardown)
                FLAG_SKIP_TEARDOWN="true"
                shift
                ;;
            --images)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --images requires a LIST argument\n' >&2
                    exit 1
                fi
                FLAG_IMAGES="${2}"
                shift 2
                ;;
            --build-id)
                if [[ $# -lt 2 ]]; then
                    printf 'ERROR: --build-id requires an ID argument\n' >&2
                    exit 1
                fi
                FLAG_BUILD_ID="${2}"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                printf 'ERROR: Unknown option: %s\n' "${1}" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
}

# ─── Config loading ───────────────────────────────────────────────────────────

load_config() {
    local config_path="${FLAG_CONFIG:-${SCRIPT_DIR}/config/hardener.conf}"

    if [[ -f "${config_path}" ]]; then
        printf '[INFO] Loading config: %s\n' "${config_path}"
        # shellcheck source=/dev/null
        source "${config_path}"
    elif [[ -n "${FLAG_CONFIG}" ]]; then
        printf 'ERROR: Config file not found: %s\n' "${config_path}" >&2
        exit 1
    fi

    # Apply flag overrides (flags take precedence over config file)
    if [[ "${FLAG_KEEP_ON_FAILURE}" == "true" ]]; then
        KEEP_ON_FAILURE="true"
    fi

    if [[ "${FLAG_NO_ITERATE}" == "true" ]]; then
        ENABLE_ITERATION="false"
    fi

    if [[ -n "${FLAG_IMAGES}" ]]; then
        HETZNER_IMAGES="${FLAG_IMAGES}"
    fi

    # Resolve ~ in SSH key path
    SSH_KEY_PATH="${HETZNER_SSH_KEY_PATH/#\~/$HOME}"
}

# ─── Local prerequisites ──────────────────────────────────────────────────────

check_local_prerequisites() {
    printf '[INFO] Checking local prerequisites...\n'

    local missing=()

    for cmd in ssh scp jq python3; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        printf 'ERROR: Required commands not found: %s\n' "${missing[*]}" >&2
        exit 1
    fi

    if [[ -z "${SSH_KEY_PATH:-}" ]] || [[ ! -f "${SSH_KEY_PATH}" ]]; then
        printf 'ERROR: SSH key not found at: %s\n' "${SSH_KEY_PATH:-<unset>}" >&2
        printf '       Set HETZNER_SSH_KEY_PATH in config or environment.\n' >&2
        exit 1
    fi

    if [[ -z "${HETZNER_API_TOKEN:-}" ]]; then
        printf 'ERROR: HETZNER_API_TOKEN is not set.\n' >&2
        exit 1
    fi

    printf '[INFO] Prerequisites OK.\n'
}

# ─── SSH / SCP helpers ────────────────────────────────────────────────────────

# remote_exec <ip> <command...>
remote_exec() {
    local ip="${1}"
    shift
    ssh \
        -i "${SSH_KEY_PATH}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        "root@${ip}" \
        "$@"
}

# remote_copy_to <ip> <src> <dest>
remote_copy_to() {
    local ip="${1}"
    local src="${2}"
    local dest="${3}"
    scp \
        -i "${SSH_KEY_PATH}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -r \
        "${src}" \
        "root@${ip}:${dest}"
}

# remote_copy_from <ip> <src> <dest>
remote_copy_from() {
    local ip="${1}"
    local src="${2}"
    local dest="${3}"
    scp \
        -i "${SSH_KEY_PATH}" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -r \
        "root@${ip}:${src}" \
        "${dest}"
}

# ─── Iteration loop ───────────────────────────────────────────────────────────

# run_iteration <ip> <image> <artifacts_dir>
run_iteration() {
    local ip="${1}"
    local image="${2}"
    local artifacts_dir="${3}"

    local iteration=0

    while (( iteration < MAX_ITERATIONS )); do
        (( iteration++ )) || true

        printf '[INFO] [%s] Iteration %d/%d\n' "${image}" "${iteration}" "${MAX_ITERATIONS}"

        # Check safe_to_remediate count from summary.json
        local summary_json="${artifacts_dir}/summary.json"
        if [[ ! -f "${summary_json}" ]]; then
            printf '[WARN] [%s] summary.json not found — stopping iteration.\n' "${image}"
            break
        fi

        local safe_count
        safe_count="$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    warn_safe = len(data.get('classification', {}).get('warnings', {}).get('safe_to_remediate', []))
    sugg_safe = len(data.get('classification', {}).get('suggestions', {}).get('safe_to_remediate', []))
    print(warn_safe + sugg_safe)
except Exception:
    print(0)
" "${summary_json}" 2>/dev/null || printf '0')"

        if [[ "${safe_count}" -eq 0 ]]; then
            printf '[INFO] [%s] No safe-to-remediate items remain — stopping iteration.\n' "${image}"
            break
        fi

        printf '[INFO] [%s] %d safe-to-remediate item(s) found — re-applying hardening.\n' \
            "${image}" "${safe_count}"

        # Re-run harden --apply
        if ! remote_exec "${ip}" "cd /opt/linux-hardener && bash harden.sh --apply" \
                >> "${artifacts_dir}/harden-apply-iter${iteration}.log" 2>&1; then
            printf '[WARN] [%s] Iteration %d: harden --apply failed — stopping.\n' "${image}" "${iteration}"
            break
        fi

        # Re-run Lynis post-hardening
        local post_label="post-hardening-iter${iteration}"
        if ! remote_exec "${ip}" "cd /opt/linux-hardener && bash scripts/lynis_runner.sh run ${post_label}" \
                >> "${artifacts_dir}/lynis-iter${iteration}.log" 2>&1; then
            printf '[WARN] [%s] Iteration %d: Lynis run failed — stopping.\n' "${image}" "${iteration}"
            break
        fi

        # Collect new Lynis artifacts
        remote_exec "${ip}" \
            "cd /opt/linux-hardener && bash scripts/lynis_runner.sh collect /tmp/lynis-collect-iter${iteration}" \
            >> "${artifacts_dir}/collect-iter${iteration}.log" 2>&1 || true
        remote_copy_from "${ip}" "/tmp/lynis-collect-iter${iteration}" \
            "${artifacts_dir}/lynis-iter${iteration}" || true

        # Parse with lynis_parser.py
        local pre_dat="${artifacts_dir}/lynis-collected/pre-hardening/lynis-report.dat"
        local post_dat="${artifacts_dir}/lynis-iter${iteration}/${post_label}/lynis-report.dat"
        local iter_summary="${artifacts_dir}/summary-iter${iteration}.json"

        if [[ -f "${pre_dat}" && -f "${post_dat}" ]]; then
            python3 "${SCRIPT_DIR}/scripts/lynis_parser.py" \
                "${pre_dat}" \
                "${post_dat}" \
                "${iter_summary}" \
                "${image}" \
                "${SCRIPT_DIR}/config/auto-remediate.conf" \
                >> "${artifacts_dir}/parse-iter${iteration}.log" 2>&1 || true
        fi

        # Check score delta
        if [[ -f "${iter_summary}" ]]; then
            local delta
            delta="$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    print(data.get('delta', {}).get('hardening_index_numeric', 0))
except Exception:
    print(0)
" "${iter_summary}" 2>/dev/null || printf '0')"

            printf '[INFO] [%s] Iteration %d: score delta = %s\n' "${image}" "${iteration}" "${delta}"

            if (( delta < MIN_SCORE_DELTA )); then
                printf '[INFO] [%s] Score delta %d < MIN_SCORE_DELTA %d — stopping iteration.\n' \
                    "${image}" "${delta}" "${MIN_SCORE_DELTA}"
                break
            fi

            # Update summary.json for next iteration check
            cp "${iter_summary}" "${summary_json}"
        else
            printf '[WARN] [%s] Iteration %d: summary JSON not produced — stopping.\n' "${image}" "${iteration}"
            break
        fi
    done
}

# ─── Per-server workflow ──────────────────────────────────────────────────────

# test_server <server_ip> <server_image> <server_name>
test_server() {
    local server_ip="${1}"
    local server_image="${2}"
    local server_name="${3}"

    local artifacts_dir="${SCRIPT_DIR}/artifacts/${BUILD_ID}/${server_image}"
    mkdir -p "${artifacts_dir}"

    local server_pass="true"

    printf '\n[INFO] ══════════════════════════════════════════════════\n'
    printf '[INFO]  Testing server: %s (%s) ip=%s\n' "${server_name}" "${server_image}" "${server_ip}"
    printf '[INFO] ══════════════════════════════════════════════════\n\n'

    # ── 1. Bootstrap ─────────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 1: Bootstrap\n' "${server_image}"

    remote_exec "${server_ip}" "mkdir -p /opt/linux-hardener"

    remote_copy_to "${server_ip}" "${SCRIPT_DIR}/lib/"      "/opt/linux-hardener/lib"
    remote_copy_to "${server_ip}" "${SCRIPT_DIR}/scripts/"  "/opt/linux-hardener/scripts"
    remote_copy_to "${server_ip}" "${SCRIPT_DIR}/config/"   "/opt/linux-hardener/config"
    remote_copy_to "${server_ip}" "${SCRIPT_DIR}/harden.sh" "/opt/linux-hardener/harden.sh"

    remote_exec "${server_ip}" \
        "chmod +x /opt/linux-hardener/harden.sh /opt/linux-hardener/scripts/*.sh"

    # Install python3 if missing
    remote_exec "${server_ip}" '
        if ! command -v python3 &>/dev/null; then
            if command -v apt-get &>/dev/null; then
                apt-get install -y python3
            elif command -v dnf &>/dev/null; then
                dnf install -y python3
            fi
        fi
    '

    # ── 2. Install Lynis ──────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 2: Install Lynis\n' "${server_image}"

    if ! remote_exec "${server_ip}" \
            "cd /opt/linux-hardener && bash scripts/lynis_runner.sh install" \
            >> "${artifacts_dir}/lynis-install.log" 2>&1; then
        printf '[ERROR] [%s] Lynis installation failed.\n' "${server_image}" >&2
        server_pass="false"
        OVERALL_PASS="false"
        return 1
    fi

    # ── 3. Pre-hardening Lynis ────────────────────────────────────────────────

    printf '[INFO] [%s] Step 3: Pre-hardening Lynis audit\n' "${server_image}"

    if ! remote_exec "${server_ip}" \
            "cd /opt/linux-hardener && bash scripts/lynis_runner.sh run pre-hardening" \
            >> "${artifacts_dir}/lynis-pre.log" 2>&1; then
        printf '[WARN] [%s] Pre-hardening Lynis run failed — continuing.\n' "${server_image}"
    fi

    # ── 4. Audit mode ─────────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 4: Hardening audit (--audit)\n' "${server_image}"

    remote_exec "${server_ip}" \
        "cd /opt/linux-hardener && bash harden.sh --audit" \
        >> "${artifacts_dir}/harden-audit.log" 2>&1 || true

    # ── 5. Apply mode ─────────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 5: Apply hardening (--apply)\n' "${server_image}"

    if ! remote_exec "${server_ip}" \
            "cd /opt/linux-hardener && bash harden.sh --apply" \
            2>&1 | tee "${artifacts_dir}/harden-apply.log"; then
        printf '[ERROR] [%s] harden --apply failed.\n' "${server_image}" >&2
        server_pass="false"
        OVERALL_PASS="false"
    fi

    # ── 6. Validation ─────────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 6: Post-hardening validation\n' "${server_image}"

    local validation_exit=0
    if ! remote_exec "${server_ip}" \
            "cd /opt/linux-hardener && bash scripts/validate.sh" \
            2>&1 | tee "${artifacts_dir}/validate.log"; then
        validation_exit=1
        printf '[ERROR] [%s] Validation failed.\n' "${server_image}" >&2
        server_pass="false"
        OVERALL_PASS="false"
    fi

    # ── 7. Post-hardening Lynis ───────────────────────────────────────────────

    printf '[INFO] [%s] Step 7: Post-hardening Lynis audit\n' "${server_image}"

    if ! remote_exec "${server_ip}" \
            "cd /opt/linux-hardener && bash scripts/lynis_runner.sh run post-hardening" \
            >> "${artifacts_dir}/lynis-post.log" 2>&1; then
        printf '[WARN] [%s] Post-hardening Lynis run failed — continuing.\n' "${server_image}"
    fi

    # ── 8. Collect artifacts ──────────────────────────────────────────────────

    printf '[INFO] [%s] Step 8: Collecting artifacts\n' "${server_image}"

    remote_exec "${server_ip}" \
        "cd /opt/linux-hardener && bash scripts/lynis_runner.sh collect /tmp/lynis-collect" \
        >> "${artifacts_dir}/collect.log" 2>&1 || true

    mkdir -p "${artifacts_dir}/lynis-collected"

    remote_copy_from "${server_ip}" "/tmp/lynis-collect" "${artifacts_dir}/lynis-collected" || true

    # Also pull server state (last-run.json, validation.json)
    remote_copy_from "${server_ip}" "/var/lib/linux-hardener" "${artifacts_dir}/server-state" || true

    # ── 9. Parse reports ──────────────────────────────────────────────────────

    printf '[INFO] [%s] Step 9: Parsing Lynis reports\n' "${server_image}"

    local pre_dat="${artifacts_dir}/lynis-collected/lynis-collect/pre-hardening/lynis-report.dat"
    local post_dat="${artifacts_dir}/lynis-collected/lynis-collect/post-hardening/lynis-report.dat"
    local summary_json="${artifacts_dir}/summary.json"

    if [[ -f "${pre_dat}" && -f "${post_dat}" ]]; then
        python3 "${SCRIPT_DIR}/scripts/lynis_parser.py" \
            "${pre_dat}" \
            "${post_dat}" \
            "${summary_json}" \
            "${server_image}" \
            "${SCRIPT_DIR}/config/auto-remediate.conf" \
            >> "${artifacts_dir}/parse.log" 2>&1 || true

        python3 "${SCRIPT_DIR}/scripts/report_generator.py" \
            "${summary_json}" \
            "${artifacts_dir}" \
            >> "${artifacts_dir}/report.log" 2>&1 || true
    else
        printf '[WARN] [%s] Lynis .dat files not found — skipping parse.\n' "${server_image}"
    fi

    # ── 10. Iterate ───────────────────────────────────────────────────────────

    if [[ "${ENABLE_ITERATION}" == "true" ]] && [[ -f "${summary_json}" ]]; then
        printf '[INFO] [%s] Step 10: Iteration loop\n' "${server_image}"
        run_iteration "${server_ip}" "${server_image}" "${artifacts_dir}"
    fi

    # ── 11. Optional reboot test ──────────────────────────────────────────────

    if [[ "${ENABLE_REBOOT_TEST}" == "true" ]]; then
        printf '[INFO] [%s] Step 11: Reboot test\n' "${server_image}"

        remote_exec "${server_ip}" "reboot" || true

        # Wait for SSH to come back
        local elapsed=0
        local timeout=180
        local interval=10
        printf '[INFO] [%s] Waiting for server to come back after reboot...\n' "${server_image}"

        while (( elapsed < timeout )); do
            if remote_exec "${server_ip}" "echo reboot-ok" &>/dev/null 2>&1; then
                printf '[INFO] [%s] Server is back after reboot.\n' "${server_image}"
                break
            fi
            sleep "${interval}"
            (( elapsed += interval )) || true
        done

        if (( elapsed >= timeout )); then
            printf '[WARN] [%s] Server did not come back within %ds after reboot.\n' \
                "${server_image}" "${timeout}"
            server_pass="false"
            OVERALL_PASS="false"
        else
            printf '[INFO] [%s] Post-reboot validation\n' "${server_image}"
            if ! remote_exec "${server_ip}" \
                    "cd /opt/linux-hardener && bash scripts/validate.sh" \
                    2>&1 | tee "${artifacts_dir}/validate-post-reboot.log"; then
                printf '[WARN] [%s] Post-reboot validation failed.\n' "${server_image}"
                server_pass="false"
                OVERALL_PASS="false"
            fi
        fi
    fi

    # ── Per-server summary ────────────────────────────────────────────────────

    if [[ "${server_pass}" == "true" ]]; then
        printf '[PASS] [%s] All steps completed successfully.\n' "${server_image}"
    else
        printf '[FAIL] [%s] One or more steps failed.\n' "${server_image}"
    fi

    [[ "${server_pass}" == "true" ]]
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    load_config
    check_local_prerequisites

    # ── Header ───────────────────────────────────────────────────────────────

    printf '\n'
    printf '=%.0s' {1..60}
    printf '\n'
    printf ' Linux Hardener -- Test Orchestrator\n'
    printf ' Date    : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf ' Images  : %s\n' "${HETZNER_IMAGES}"
    printf ' Parallel: %s\n' "${PARALLEL_TESTS}"
    printf ' Iterate : %s (max=%s delta>=%s)\n' \
        "${ENABLE_ITERATION}" "${MAX_ITERATIONS}" "${MIN_SCORE_DELTA}"
    printf '=%.0s' {1..60}
    printf '\n\n'

    # ── Provision ────────────────────────────────────────────────────────────

    if [[ -n "${FLAG_BUILD_ID:-}" ]]; then
        BUILD_ID="${FLAG_BUILD_ID}"
        export BUILD_ID
        printf '[INFO] Reusing existing build: %s (skipping provisioning)\n' "${BUILD_ID}"
    else
        printf '[INFO] Provisioning servers via hetzner/provision.sh...\n'

        local provision_output
        if ! provision_output="$(
            HETZNER_API_TOKEN="${HETZNER_API_TOKEN}" \
            HETZNER_SSH_KEY_NAME="${HETZNER_SSH_KEY_NAME}" \
            HETZNER_SSH_KEY_PATH="${SSH_KEY_PATH}" \
            HETZNER_SERVER_TYPE="${HETZNER_SERVER_TYPE}" \
            HETZNER_LOCATION="${HETZNER_LOCATION}" \
            HETZNER_IMAGES="${HETZNER_IMAGES}" \
            bash "${SCRIPT_DIR}/hetzner/provision.sh" 2>&1
        )"; then
            printf 'ERROR: Provisioning failed:\n%s\n' "${provision_output}" >&2
            exit 1
        fi

        printf '%s\n' "${provision_output}"

        # Build ID is the last line of provision.sh output
        BUILD_ID="$(printf '%s' "${provision_output}" | tail -n1)"
        export BUILD_ID

        if [[ -z "${BUILD_ID}" ]]; then
            printf 'ERROR: Could not determine BUILD_ID from provision output.\n' >&2
            exit 1
        fi
    fi

    printf '[INFO] BUILD_ID: %s\n' "${BUILD_ID}"
    printf '[INFO] Artifacts: %s/artifacts/%s\n' "${SCRIPT_DIR}" "${BUILD_ID}"

    # ── Load servers manifest ─────────────────────────────────────────────────

    local manifest="${SCRIPT_DIR}/artifacts/${BUILD_ID}/servers.json"
    if [[ ! -f "${manifest}" ]]; then
        printf 'ERROR: servers.json not found at: %s\n' "${manifest}" >&2
        exit 1
    fi

    local server_count
    server_count="$(jq '. | length' "${manifest}")"

    if [[ "${server_count}" -eq 0 ]]; then
        printf 'ERROR: No servers found in manifest: %s\n' "${manifest}" >&2
        exit 1
    fi

    printf '[INFO] %d server(s) to test.\n' "${server_count}"

    # ── Test loop ─────────────────────────────────────────────────────────────

    local pids=()
    local server_results=()

    while IFS= read -r server_json; do
        local server_ip server_image server_name
        server_ip="$(printf '%s' "${server_json}" | jq -r '.ip')"
        server_image="$(printf '%s' "${server_json}" | jq -r '.image')"
        server_name="$(printf '%s' "${server_json}" | jq -r '.name')"

        if [[ "${PARALLEL_TESTS}" == "true" ]]; then
            (
                if ! test_server "${server_ip}" "${server_image}" "${server_name}"; then
                    exit 1
                fi
            ) &
            pids+=($!)
        else
            if ! test_server "${server_ip}" "${server_image}" "${server_name}"; then
                server_results+=("FAIL:${server_image}")
                OVERALL_PASS="false"
            else
                server_results+=("PASS:${server_image}")
            fi
        fi
    done < <(jq -c '.[]' "${manifest}")

    # Wait for parallel jobs and collect results
    if [[ "${PARALLEL_TESTS}" == "true" ]]; then
        local idx=0
        for pid in "${pids[@]}"; do
            if wait "${pid}"; then
                server_results+=("PASS:job${idx}")
            else
                server_results+=("FAIL:job${idx}")
                OVERALL_PASS="false"
            fi
            (( idx++ )) || true
        done
    fi

    # ── Aggregate reports ─────────────────────────────────────────────────────

    printf '\n[INFO] Generating aggregate report...\n'

    local artifacts_root="${SCRIPT_DIR}/artifacts/${BUILD_ID}"

    python3 "${SCRIPT_DIR}/scripts/report_generator.py" \
        --aggregate \
        "${artifacts_root}" \
        "${artifacts_root}" \
        >> "${artifacts_root}/aggregate-report.log" 2>&1 || true

    # ── Teardown decision ─────────────────────────────────────────────────────

    local do_teardown="true"

    if [[ "${FLAG_SKIP_TEARDOWN}" == "true" ]]; then
        do_teardown="false"
        printf '[INFO] --skip-teardown set -- servers will NOT be deleted.\n'
    elif [[ "${KEEP_ON_FAILURE}" == "true" && "${OVERALL_PASS}" == "false" ]]; then
        do_teardown="false"
        printf '[INFO] --keep-on-failure set and test failed -- servers will NOT be deleted.\n'
    fi

    if [[ "${do_teardown}" == "true" ]]; then
        printf '[INFO] Tearing down servers...\n'
        HETZNER_API_TOKEN="${HETZNER_API_TOKEN}" \
            bash "${SCRIPT_DIR}/hetzner/teardown.sh" "${manifest}" || true
    else
        # Print SSH commands for manual access
        printf '\n[INFO] Servers are still running. SSH access:\n'
        while IFS= read -r server_json; do
            local sip sname
            sip="$(printf '%s' "${server_json}" | jq -r '.ip')"
            sname="$(printf '%s' "${server_json}" | jq -r '.name')"
            printf '  ssh -i %s root@%s  # %s\n' "${SSH_KEY_PATH}" "${sip}" "${sname}"
        done < <(jq -c '.[]' "${manifest}")
        printf '\nTo tear down manually:\n'
        printf '  bash %s/hetzner/teardown.sh %s\n' "${SCRIPT_DIR}" "${manifest}"
    fi

    # ── Final summary ─────────────────────────────────────────────────────────

    printf '\n'
    printf '=%.0s' {1..60}
    printf '\n'
    printf ' Linux Hardener -- Final Summary\n'
    printf ' BUILD_ID  : %s\n' "${BUILD_ID}"
    printf ' Artifacts : %s/artifacts/%s\n' "${SCRIPT_DIR}" "${BUILD_ID}"
    printf '\n'

    local result
    for result in "${server_results[@]}"; do
        local status="${result%%:*}"
        local label="${result##*:}"
        printf '  [%s] %s\n' "${status}" "${label}"
    done

    printf '\n'
    if [[ "${OVERALL_PASS}" == "true" ]]; then
        printf ' Overall result: PASS\n'
    else
        printf ' Overall result: FAIL\n'
    fi
    printf '=%.0s' {1..60}
    printf '\n\n'

    if [[ "${OVERALL_PASS}" != "true" ]]; then
        exit 1
    fi
}

main "$@"
