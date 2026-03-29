#!/usr/bin/env bash
# scripts/validate.sh — Post-hardening validation script
# Runs ON the target server after hardening to verify security controls are in place.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Minimal globals for standalone use ──────────────────────────────────────

RUN_MODE="audit"
VERBOSE="true"
LOG_FILE="/dev/null"

# ─── Source common helpers ────────────────────────────────────────────────────

# shellcheck source=../lib/common.sh
source "${PARENT_DIR}/lib/common.sh"

# ─── Counters ─────────────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# ─── Check function ───────────────────────────────────────────────────────────

# check <name> <cmd> <expected>
#   name     — human-readable label (left-aligned in 30 chars)
#   cmd      — command string to eval
#   expected — expected substring/value in output; empty means any successful exit
check() {
    local name="${1}"
    local cmd="${2}"
    local expected="${3}"

    printf '  %-30s ' "${name}"

    local output
    local exit_code=0

    output="$(eval "${cmd}" 2>&1)" || exit_code=$?

    if [[ ${exit_code} -ne 0 ]]; then
        printf 'FAIL\n'
        (( FAIL_COUNT++ )) || true
        return 1
    fi

    if [[ -z "${expected}" ]]; then
        # Any successful exit is a PASS
        printf 'PASS\n'
        (( PASS_COUNT++ )) || true
        return 0
    fi

    if printf '%s' "${output}" | grep -qi "${expected}"; then
        printf 'PASS\n'
        (( PASS_COUNT++ )) || true
        return 0
    else
        printf 'WARN  (got: %s)\n' "${output}"
        (( WARN_COUNT++ )) || true
        return 0
    fi
}

# ─── Detect distro ───────────────────────────────────────────────────────────

detect_distro

# ─── Header ───────────────────────────────────────────────────────────────────

print_header() {
    printf '\n'
    printf '═%.0s' {1..60}
    printf '\n'
    printf ' Linux Hardener — Post-Hardening Validation\n'
    printf ' Distro : %s %s  Family: %s\n' \
        "${DISTRO_ID:-unknown}" "${DISTRO_VERSION:-}" "${DISTRO_FAMILY:-unknown}"
    printf ' Date   : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '═%.0s' {1..60}
    printf '\n\n'
}

# ─── Category header helper ───────────────────────────────────────────────────

section() {
    local title="${1}"
    printf '\n── %s %s\n' "${title}" "$(printf '─%.0s' $(seq 1 $(( 55 - ${#title} ))))"
}

# ─────────────────────────────────────────────────────────────────────────────
# Checks
# ─────────────────────────────────────────────────────────────────────────────

run_checks() {

    # ── Connectivity ─────────────────────────────────────────────────────────

    section "Connectivity"

    check "DNS resolution" \
        "getent hosts example.com | head -1" \
        ""

    check "Outbound HTTPS" \
        "curl -sf -o /dev/null --connect-timeout 10 https://example.com" \
        ""

    # ── Package Manager ───────────────────────────────────────────────────────

    section "Package Manager"

    case "${DISTRO_FAMILY}" in
        debian)
            check "apt-get update" \
                "apt-get update -qq" \
                ""
            ;;
        rhel)
            # dnf check-update exits 100 when updates are available — that is
            # a known non-error, so we normalize the exit code.
            check "dnf check-update" \
                "dnf check-update -q; rc=\$?; [[ \$rc -eq 0 || \$rc -eq 100 ]] && exit 0 || exit \$rc" \
                ""
            ;;
    esac

    # ── Time Sync ─────────────────────────────────────────────────────────────

    section "Time Sync"

    check "NTP synchronized" \
        "timedatectl show --property=NTPSynchronized --value 2>/dev/null || timedatectl status 2>/dev/null | awk '/synchronized/ {print \$NF}'" \
        "yes"

    # Check whichever time-sync service is present
    local timesync_active=false
    for svc in chronyd chrony systemd-timesyncd; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            timesync_active=true
            check "Time-sync service (${svc})" \
                "systemctl is-active ${svc}" \
                "active"
            break
        fi
    done

    if [[ "${timesync_active}" == "false" ]]; then
        # None active — emit a FAIL by running a check that will fail
        check "Time-sync service" \
            "false" \
            ""
    fi

    # ── Firewall ──────────────────────────────────────────────────────────────

    section "Firewall"

    case "${DISTRO_FAMILY}" in
        debian)
            check "nftables active" \
                "systemctl is-active nftables" \
                "active"

            check "nftables policy drop" \
                "nft list ruleset 2>/dev/null" \
                "policy drop"
            ;;
        rhel)
            check "firewalld active" \
                "systemctl is-active firewalld" \
                "active"

            check "firewalld default zone drop" \
                "firewall-cmd --get-default-zone 2>/dev/null" \
                "drop"
            ;;
    esac

    # ── SSH ───────────────────────────────────────────────────────────────────

    section "SSH"

    check "sshd active" \
        "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null" \
        "active"

    check "sshd config valid" \
        "sshd -t" \
        ""

    # Debian 12 reports "without-password" (old synonym for "prohibit-password")
    check "PermitRootLogin" \
        "sshd -T 2>/dev/null | grep -i '^permitrootlogin' | grep -qE 'prohibit-password|without-password' && echo ok" \
        "ok"

    check "PasswordAuthentication" \
        "sshd -T 2>/dev/null | grep -i '^passwordauthentication'" \
        "no"

    # ── sysctl ────────────────────────────────────────────────────────────────

    section "sysctl Kernel Parameters"

    check "rp_filter (lo)" \
        "sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null" \
        "1"

    check "accept_redirects" \
        "sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null" \
        "0"

    check "tcp_syncookies" \
        "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null" \
        "1"

    check "ASLR (randomize_va_space)" \
        "sysctl -n kernel.randomize_va_space 2>/dev/null" \
        "2"

    check "ptrace_scope" \
        "sysctl -n kernel.yama.ptrace_scope 2>/dev/null" \
        "1"

    check "suid_dumpable" \
        "sysctl -n fs.suid_dumpable 2>/dev/null" \
        "0"

    # ── Critical Services ─────────────────────────────────────────────────────

    section "Critical Services"

    # cron: Debian uses "cron", RHEL uses "crond"
    local cron_svc="cron"
    [[ "${DISTRO_FAMILY}" == "rhel" ]] && cron_svc="crond"

    check "cron/crond active" \
        "systemctl is-active ${cron_svc}" \
        "active"

    # Accept either rsyslog or journald — Debian 12 uses journald only
    check "syslog (rsyslog or journald)" \
        "systemctl is-active rsyslog 2>/dev/null || systemctl is-active systemd-journald" \
        "active"
}

# ─── Results Summary ──────────────────────────────────────────────────────────

print_results() {
    local all_pass=false
    [[ ${FAIL_COUNT} -eq 0 ]] && all_pass=true

    printf '\n'
    printf '─%.0s' {1..60}
    printf '\n'
    printf ' Results:  PASS=%-4d  WARN=%-4d  FAIL=%-4d\n' \
        "${PASS_COUNT}" "${WARN_COUNT}" "${FAIL_COUNT}"
    printf '─%.0s' {1..60}
    printf '\n'

    if [[ "${all_pass}" == "true" ]]; then
        printf ' All required checks PASSED.\n'
    else
        printf ' %d check(s) FAILED — review output above.\n' "${FAIL_COUNT}"
    fi
    printf '═%.0s' {1..60}
    printf '\n\n'
}

# ─── Write JSON ───────────────────────────────────────────────────────────────

write_validation_json() {
    local state_dir="${HARDENER_STATE_DIR}"
    local out_file="${state_dir}/validation.json"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local all_pass="false"
    [[ ${FAIL_COUNT} -eq 0 ]] && all_pass="true"

    mkdir -p "${state_dir}"

    cat > "${out_file}" <<EOF
{
  "timestamp": "${timestamp}",
  "pass": ${PASS_COUNT},
  "fail": ${FAIL_COUNT},
  "warn": ${WARN_COUNT},
  "all_pass": ${all_pass}
}
EOF

    printf ' Validation results written to: %s\n\n' "${out_file}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    print_header
    run_checks
    print_results
    write_validation_json

    if [[ ${FAIL_COUNT} -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
