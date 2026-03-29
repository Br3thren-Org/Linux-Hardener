#!/usr/bin/env bash
# scripts/lynis_runner.sh — Lynis audit runner for Linux Hardener
# Runs ON the target server. Sources common.sh for shared helpers.
# Self-contained: initializes minimal globals for standalone use.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Minimal globals for standalone use ──────────────────────────────────────

RUN_MODE="apply"
VERBOSE="true"
LOG_FILE="/dev/null"

# ─── Constants ────────────────────────────────────────────────────────────────

readonly LYNIS_ARTIFACT_BASE="/var/lib/linux-hardener/lynis"
readonly LYNIS_LOG="/var/log/lynis.log"
readonly LYNIS_REPORT="/var/log/lynis-report.dat"

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "${0}") <subcommand> [args]

Subcommands:
  install                Install Lynis using the distro adapter
  run <label>            Run a Lynis audit and store artifacts under <label>
  collect <output_dir>   Copy Lynis artifacts to <output_dir>

Environment:
  LYNIS_SOURCE    Installation source: package (default), cisofy-repo, github
  LYNIS_QUICK     Set to "true" to pass --quick to lynis audit

Examples:
  sudo $(basename "${0}") install
  sudo $(basename "${0}") run baseline
  sudo $(basename "${0}") collect /tmp/lynis-artifacts
EOF
}

# ─── Lynis binary discovery ───────────────────────────────────────────────────

find_lynis_binary() {
    local bin=""

    if command -v lynis &>/dev/null; then
        bin="$(command -v lynis)"
    elif [[ -x "/opt/lynis/lynis" ]]; then
        bin="/opt/lynis/lynis"
    fi

    if [[ -z "${bin}" ]]; then
        printf 'ERROR: lynis binary not found. Run "%s install" first.\n' \
            "$(basename "${0}")" >&2
        return 1
    fi

    printf '%s' "${bin}"
}

# ─── Subcommand: install ──────────────────────────────────────────────────────

cmd_install() {
    # Source common.sh for log helpers, detect_distro, pkg_install, etc.
    # shellcheck source=../lib/common.sh
    source "${PARENT_DIR}/lib/common.sh"

    detect_distro

    case "${DISTRO_FAMILY}" in
        debian)
            # shellcheck source=../lib/distro/debian.sh
            source "${PARENT_DIR}/lib/distro/debian.sh"
            debian_install_lynis
            ;;
        rhel)
            # shellcheck source=../lib/distro/rhel.sh
            source "${PARENT_DIR}/lib/distro/rhel.sh"
            rhel_install_lynis
            ;;
        *)
            printf 'ERROR: Unsupported distro family: %s\n' "${DISTRO_FAMILY}" >&2
            return 1
            ;;
    esac

    # Verify installation
    local bin
    if ! bin="$(find_lynis_binary)"; then
        printf 'ERROR: Lynis installation verification failed: binary not found.\n' >&2
        return 1
    fi

    printf 'Lynis installed at: %s\n' "${bin}"
    printf 'Version: '
    "${bin}" --version
}

# ─── Subcommand: run <label> ──────────────────────────────────────────────────

cmd_run() {
    local label="${1:-}"
    if [[ -z "${label}" ]]; then
        printf 'ERROR: "run" requires a <label> argument.\n' >&2
        usage >&2
        return 1
    fi

    # Validate label: alphanumeric, dashes, underscores only
    if [[ ! "${label}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        printf 'ERROR: Invalid label "%s". Use only letters, digits, dashes, and underscores.\n' \
            "${label}" >&2
        return 1
    fi

    local artifact_dir="${LYNIS_ARTIFACT_BASE}/${label}"
    mkdir -p "${artifact_dir}"

    local bin
    bin="$(find_lynis_binary)"

    # Build quick flag from environment
    local quick_flag=""
    if [[ "${LYNIS_QUICK:-false}" == "true" ]]; then
        quick_flag="--quick"
    fi

    # Clear previous lynis log/report so we only capture this run
    rm -f "${LYNIS_LOG}" "${LYNIS_REPORT}"

    local stdout_log="${artifact_dir}/lynis-stdout.log"

    printf '[INFO] Starting Lynis audit (label: %s)\n' "${label}"
    printf '[INFO] Artifacts will be stored in: %s\n' "${artifact_dir}"

    # Run lynis, tee output to stdout log and to terminal
    # lynis writes its detailed log to /var/log/lynis.log and
    # machine-readable report to /var/log/lynis-report.dat
    # shellcheck disable=SC2086
    "${bin}" audit system --no-colors --no-log ${quick_flag} \
        | tee "${stdout_log}"

    # Copy lynis log and report to artifact dir
    if [[ -f "${LYNIS_LOG}" ]]; then
        cp "${LYNIS_LOG}" "${artifact_dir}/lynis.log"
    else
        printf '[WARN] %s not found after audit run.\n' "${LYNIS_LOG}"
    fi

    if [[ -f "${LYNIS_REPORT}" ]]; then
        cp "${LYNIS_REPORT}" "${artifact_dir}/lynis-report.dat"
    else
        printf '[WARN] %s not found after audit run.\n' "${LYNIS_REPORT}"
    fi

    # ── Extract metrics from report.dat ──────────────────────────────────────

    local hardening_index="N/A"
    local warning_count=0
    local suggestion_count=0
    local tests_performed=0

    if [[ -f "${artifact_dir}/lynis-report.dat" ]]; then
        local report="${artifact_dir}/lynis-report.dat"

        # hardening_index value (e.g. hardening_index=72)
        local hi_line
        hi_line="$(grep -m1 '^hardening_index=' "${report}" 2>/dev/null || true)"
        if [[ -n "${hi_line}" ]]; then
            hardening_index="${hi_line#hardening_index=}"
        fi

        # Count warning[] entries
        warning_count="$(grep -c '^warning\[\]=' "${report}" 2>/dev/null || true)"

        # Count suggestion[] entries
        suggestion_count="$(grep -c '^suggestion\[\]=' "${report}" 2>/dev/null || true)"

        # tests_performed value
        local tp_line
        tp_line="$(grep -m1 '^tests_performed=' "${report}" 2>/dev/null || true)"
        if [[ -n "${tp_line}" ]]; then
            tests_performed="${tp_line#tests_performed=}"
        fi
    fi

    # ── Print formatted summary ───────────────────────────────────────────────

    printf '\n'
    printf '═%.0s' {1..60}
    printf '\n'
    printf ' Lynis Audit Summary — %s\n' "${label}"
    printf '═%.0s' {1..60}
    printf '\n'
    printf ' Hardening Index : %s\n' "${hardening_index}"
    printf ' Warnings        : %d\n' "${warning_count}"
    printf ' Suggestions     : %d\n' "${suggestion_count}"
    printf ' Tests Performed : %s\n' "${tests_performed}"
    printf '─%.0s' {1..60}
    printf '\n'
    printf ' Artifacts       : %s\n' "${artifact_dir}"
    printf '═%.0s' {1..60}
    printf '\n\n'

    # ── Write quick-summary.txt ───────────────────────────────────────────────

    local summary_file="${artifact_dir}/quick-summary.txt"
    printf 'label=%s\n'            "${label}"            > "${summary_file}"
    printf 'hardening_index=%s\n'  "${hardening_index}"  >> "${summary_file}"
    printf 'warning_count=%d\n'    "${warning_count}"    >> "${summary_file}"
    printf 'suggestion_count=%d\n' "${suggestion_count}" >> "${summary_file}"
    printf 'tests_performed=%s\n'  "${tests_performed}"  >> "${summary_file}"
    printf 'artifact_dir=%s\n'     "${artifact_dir}"     >> "${summary_file}"
    printf 'timestamp=%s\n'        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${summary_file}"

    printf '[INFO] Quick summary written to: %s\n' "${summary_file}"
}

# ─── Subcommand: collect <output_dir> ────────────────────────────────────────

cmd_collect() {
    local output_dir="${1:-}"
    if [[ -z "${output_dir}" ]]; then
        printf 'ERROR: "collect" requires an <output_dir> argument.\n' >&2
        usage >&2
        return 1
    fi

    mkdir -p "${output_dir}"

    # Copy lynis artifact tree
    if [[ -d "${LYNIS_ARTIFACT_BASE}" ]]; then
        cp -r "${LYNIS_ARTIFACT_BASE}/." "${output_dir}/"
        printf '[INFO] Copied Lynis artifacts from %s to %s\n' \
            "${LYNIS_ARTIFACT_BASE}" "${output_dir}"
    else
        printf '[WARN] No Lynis artifacts found at %s (has "run" been called?)\n' \
            "${LYNIS_ARTIFACT_BASE}"
    fi

    # Copy last-run.json if present
    local last_run_json="/var/lib/linux-hardener/last-run.json"
    if [[ -f "${last_run_json}" ]]; then
        cp "${last_run_json}" "${output_dir}/last-run.json"
        printf '[INFO] Copied %s to %s\n' "${last_run_json}" "${output_dir}"
    fi

    printf '[INFO] Collection complete: %s\n' "${output_dir}"
}

# ─── Entrypoint ───────────────────────────────────────────────────────────────

main() {
    if [[ $# -eq 0 ]]; then
        usage >&2
        exit 1
    fi

    local subcommand="${1}"
    shift

    case "${subcommand}" in
        install)
            cmd_install
            ;;
        run)
            cmd_run "${@}"
            ;;
        collect)
            cmd_collect "${@}"
            ;;
        --help|-h|help)
            usage
            exit 0
            ;;
        *)
            printf 'ERROR: Unknown subcommand: %s\n' "${subcommand}" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
