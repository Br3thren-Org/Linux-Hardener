#!/usr/bin/env bash
# lib/filesystem.sh — filesystem hardening module: audit, apply, rollback
# Sourced by harden.sh after lib/common.sh and the distro-specific adapter.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Sensitive File Definitions ───────────────────────────────────────────────
# Each entry is "path|expected_mode|expected_owner|expected_group"

readonly -a SENSITIVE_FILES=(
    "/etc/shadow|0640|root|shadow"
    "/etc/gshadow|0640|root|shadow"
    "/etc/passwd|0644|root|root"
    "/etc/group|0644|root|root"
    "/etc/crontab|0600|root|root"
    "/etc/ssh/sshd_config|0600|root|root"
    "/etc/cron.d|0700|root|root"
    "/etc/cron.daily|0700|root|root"
    "/etc/cron.hourly|0700|root|root"
    "/etc/cron.weekly|0700|root|root"
    "/etc/cron.monthly|0700|root|root"
)

# Drop-in paths managed by this module
readonly _FS_LIMITS_CONF="/etc/security/limits.d/99-hardening.conf"
readonly _FS_COREDUMP_CONF="/etc/systemd/coredump.conf.d/99-hardening.conf"

# ─── Internal Helpers ─────────────────────────────────────────────────────────

# _fs_is_separate_mount <path>
# Returns 0 if <path> is a separate mount point (not part of the root fs).
_fs_is_separate_mount() {
    local path="${1}"
    local root_dev mount_dev
    root_dev="$(stat -c '%d' / 2>/dev/null)"
    mount_dev="$(stat -c '%d' "${path}" 2>/dev/null)"
    [[ -n "${root_dev}" && -n "${mount_dev}" && "${mount_dev}" != "${root_dev}" ]]
}

# _fs_get_mount_opts <path>
# Prints the current mount options for <path> from /proc/mounts.
_fs_get_mount_opts() {
    local path="${1}"
    awk -v mp="${path}" '$2 == mp { print $4 }' /proc/mounts 2>/dev/null | head -1
}

# _fs_check_mount_opt <path> <option>
# Returns 0 if <option> is present in the current mount options for <path>.
_fs_check_mount_opt() {
    local path="${1}"
    local opt="${2}"
    local opts
    opts="$(_fs_get_mount_opts "${path}")"
    [[ ",${opts}," == *",${opt},"* ]]
}

# _fs_get_file_mode <path>
# Prints the octal mode of <path> (e.g. "0640").
_fs_get_file_mode() {
    local path="${1}"
    stat -c '%a' "${path}" 2>/dev/null
}

# _fs_get_file_owner <path>
# Prints the owner username of <path>.
_fs_get_file_owner() {
    local path="${1}"
    stat -c '%U' "${path}" 2>/dev/null
}

# _fs_get_file_group <path>
# Prints the group name of <path>.
_fs_get_file_group() {
    local path="${1}"
    stat -c '%G' "${path}" 2>/dev/null
}

# _fs_mode_is_more_permissive <actual_mode> <expected_mode>
# Returns 0 if actual mode grants MORE permissions than expected (i.e. is less secure).
# Compares octal integers: higher numeric value means more permissive.
_fs_mode_is_more_permissive() {
    local actual="${1}"
    local expected="${2}"
    # Strip leading zero for arithmetic comparison
    local a_int e_int
    a_int="$(printf '%d' "0${actual#0}"  2>/dev/null || printf '0')"
    e_int="$(printf '%d' "0${expected#0}" 2>/dev/null || printf '0')"
    [[ "${a_int}" -gt "${e_int}" ]]
}

# _fs_fstab_has_opt <device_or_path> <option>
# Returns 0 if /etc/fstab contains <option> for the entry matching <device_or_path>.
_fs_fstab_has_opt() {
    local target="${1}"
    local opt="${2}"
    awk -v t="${target}" -v o="${opt}" '
        /^#/ { next }
        $2 == t {
            n = split($4, opts, ",")
            for (i=1; i<=n; i++) {
                if (opts[i] == o) { found=1; exit }
            }
        }
        END { exit (found ? 0 : 1) }
    ' /etc/fstab 2>/dev/null
}

# _fs_fstab_add_opts <mountpoint> <opts_to_add>
# Adds comma-separated opts to the existing fstab options for <mountpoint>.
# If the mount is not in fstab, adds a tmpfs entry.
_fs_fstab_add_opts() {
    local mountpoint="${1}"
    local new_opts="${2}"

    # Read current fstab into variable to manipulate
    local fstab_content
    fstab_content="$(cat /etc/fstab)"

    local updated_content
    updated_content="$(
        printf '%s\n' "${fstab_content}" | awk \
            -v mp="${mountpoint}" \
            -v extra_opts="${new_opts}" '
        /^#/ || NF == 0 { print; next }
        $2 == mp {
            # Merge extra_opts into existing options field ($4)
            n = split(extra_opts, new, ",")
            for (i=1; i<=n; i++) {
                opt = new[i]
                if (index("," $4 ",", "," opt ",") == 0) {
                    $4 = $4 "," opt
                }
            }
            print
            next
        }
        { print }
    ')"

    # If the mountpoint was not in fstab at all, append a new entry
    if ! printf '%s\n' "${fstab_content}" | awk -v mp="${mountpoint}" '$2==mp{found=1}END{exit !found}'; then
        updated_content="${updated_content}
tmpfs  ${mountpoint}  tmpfs  defaults,${new_opts}  0  0"
    fi

    printf '%s\n' "${updated_content}" > /etc/fstab
}

# ─── filesystem_audit ─────────────────────────────────────────────────────────

filesystem_audit() {
    log_info "filesystem_audit: checking mount options and file permissions"

    # ── /tmp mount options ────────────────────────────────────────────────────
    if _fs_is_separate_mount /tmp; then
        local check_opts=( nodev nosuid )
        if [[ "${NOEXEC_TMP:-true}" == "true" ]]; then
            check_opts+=( noexec )
        fi

        local opt
        for opt in "${check_opts[@]}"; do
            if ! _fs_check_mount_opt /tmp "${opt}"; then
                log_warn "FINDING: /tmp mount is missing option '${opt}'"
                (( AUDIT_FINDINGS++ )) || true
            else
                log_debug "filesystem_audit: /tmp has '${opt}' (OK)"
            fi
        done
    else
        log_info "filesystem_audit: /tmp is not a separate mount — skipping mount option checks"
    fi

    # ── /dev/shm mount options ────────────────────────────────────────────────
    local shm_opts=( nodev nosuid noexec )
    local opt
    for opt in "${shm_opts[@]}"; do
        if ! _fs_check_mount_opt /dev/shm "${opt}"; then
            log_warn "FINDING: /dev/shm mount is missing option '${opt}'"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "filesystem_audit: /dev/shm has '${opt}' (OK)"
        fi
    done

    # ── Sensitive file permissions ────────────────────────────────────────────
    local entry path expected_mode expected_owner expected_group
    for entry in "${SENSITIVE_FILES[@]}"; do
        path="${entry%%|*}"
        local rest="${entry#*|}"
        expected_mode="${rest%%|*}"
        rest="${rest#*|}"
        expected_owner="${rest%%|*}"
        expected_group="${rest#*|}"

        if [[ ! -e "${path}" ]]; then
            log_debug "filesystem_audit: '${path}' does not exist, skipping"
            continue
        fi

        local actual_mode actual_owner actual_group
        actual_mode="$(_fs_get_file_mode "${path}")"
        actual_owner="$(_fs_get_file_owner "${path}")"
        actual_group="$(_fs_get_file_group "${path}")"

        # Pad actual_mode to 4 digits for consistent comparison
        if [[ "${#actual_mode}" -lt 4 ]]; then
            actual_mode="0${actual_mode}"
        fi

        if _fs_mode_is_more_permissive "${actual_mode}" "${expected_mode}"; then
            log_warn "FINDING: ${path} mode is ${actual_mode} (expected ${expected_mode} or stricter)"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "filesystem_audit: ${path} mode=${actual_mode} (OK)"
        fi

        if [[ "${actual_owner}" != "${expected_owner}" ]]; then
            log_warn "FINDING: ${path} owner is '${actual_owner}' (expected '${expected_owner}')"
            (( AUDIT_FINDINGS++ )) || true
        fi

        if [[ "${actual_group}" != "${expected_group}" ]]; then
            log_warn "FINDING: ${path} group is '${actual_group}' (expected '${expected_group}')"
            (( AUDIT_FINDINGS++ )) || true
        fi
    done

    # ── Core dump limits ──────────────────────────────────────────────────────
    if [[ -f "${_FS_LIMITS_CONF}" ]]; then
        if grep -q "hard core 0" "${_FS_LIMITS_CONF}" && grep -q "soft core 0" "${_FS_LIMITS_CONF}"; then
            log_debug "filesystem_audit: core dump limits present in ${_FS_LIMITS_CONF} (OK)"
        else
            log_warn "FINDING: ${_FS_LIMITS_CONF} exists but does not disable core dumps"
            (( AUDIT_FINDINGS++ )) || true
        fi
    else
        log_warn "FINDING: core dump limits not configured — ${_FS_LIMITS_CONF} does not exist"
        (( AUDIT_FINDINGS++ )) || true
    fi

    if [[ -f "${_FS_COREDUMP_CONF}" ]]; then
        if grep -q "Storage=none" "${_FS_COREDUMP_CONF}" && grep -q "ProcessSizeMax=0" "${_FS_COREDUMP_CONF}"; then
            log_debug "filesystem_audit: systemd coredump config present (OK)"
        else
            log_warn "FINDING: ${_FS_COREDUMP_CONF} exists but does not disable systemd core dumps"
            (( AUDIT_FINDINGS++ )) || true
        fi
    else
        log_warn "FINDING: systemd coredump drop-in not configured — ${_FS_COREDUMP_CONF} does not exist"
        (( AUDIT_FINDINGS++ )) || true
    fi
}

# ─── filesystem_apply ─────────────────────────────────────────────────────────

filesystem_apply() {
    log_info "filesystem_apply: hardening mount options and file permissions"

    # ── 1. /tmp mount options ─────────────────────────────────────────────────
    if _fs_is_separate_mount /tmp; then
        local tmp_opts
        if [[ "${HARDENING_PROFILE:-aggressive}" == "aggressive" ]]; then
            tmp_opts="nodev,nosuid,noexec"
        else
            tmp_opts="nodev,nosuid"
        fi

        if ! should_write; then
            log_info "[DRY-RUN] Would add '${tmp_opts}' to /tmp fstab entry and remount"
        else
            log_change \
                "Add ${tmp_opts} to /tmp mount options in /etc/fstab" \
                "Prevent execution of binaries and device files from /tmp" \
                "medium" \
                "mount | grep ' /tmp '" \
                "Restore /etc/fstab from backup and remount with defaults"

            backup_file "/etc/fstab"
            _fs_fstab_add_opts "/tmp" "${tmp_opts}"
            mount -o "remount,${tmp_opts}" /tmp 2>/dev/null || \
                log_warn "filesystem_apply: failed to remount /tmp — a reboot may be required"

            log_success "filesystem_apply: /tmp mount options updated"
            (( CHANGES_APPLIED++ )) || true
        fi

        # Install package manager hooks to handle noexec around installs
        case "${DISTRO_FAMILY}" in
            debian)
                debian_setup_tmp_hook || true
                ;;
            rhel)
                rhel_setup_tmp_hook || true
                ;;
        esac
    else
        log_info "filesystem_apply: /tmp is not a separate mount — skipping fstab update"
    fi

    # ── 2. /dev/shm mount options ─────────────────────────────────────────────
    local shm_needed_opts="nodev,nosuid,noexec"
    local shm_missing=false

    local opt
    for opt in nodev nosuid noexec; do
        if ! _fs_check_mount_opt /dev/shm "${opt}"; then
            shm_missing=true
            break
        fi
    done

    if [[ "${shm_missing}" == "true" ]]; then
        if ! should_write; then
            log_info "[DRY-RUN] Would add '${shm_needed_opts}' to /dev/shm fstab entry and remount"
        else
            log_change \
                "Add ${shm_needed_opts} to /dev/shm mount options in /etc/fstab" \
                "Prevent execution and device files in shared memory" \
                "medium" \
                "mount | grep '/dev/shm'" \
                "Restore /etc/fstab from backup and remount with defaults"

            backup_file "/etc/fstab"
            _fs_fstab_add_opts "/dev/shm" "${shm_needed_opts}"
            mount -o "remount,${shm_needed_opts}" /dev/shm 2>/dev/null || \
                log_warn "filesystem_apply: failed to remount /dev/shm — a reboot may be required"

            log_success "filesystem_apply: /dev/shm mount options updated"
            (( CHANGES_APPLIED++ )) || true
        fi
    else
        log_debug "filesystem_apply: /dev/shm already has required options — skipping"
        (( CHANGES_SKIPPED++ )) || true
    fi

    # ── 3. Sensitive file permissions ─────────────────────────────────────────
    local entry path expected_mode expected_owner expected_group
    for entry in "${SENSITIVE_FILES[@]}"; do
        path="${entry%%|*}"
        local rest="${entry#*|}"
        expected_mode="${rest%%|*}"
        rest="${rest#*|}"
        expected_owner="${rest%%|*}"
        expected_group="${rest#*|}"

        if [[ ! -e "${path}" ]]; then
            log_debug "filesystem_apply: '${path}' does not exist, skipping"
            continue
        fi

        local actual_mode actual_owner actual_group
        actual_mode="$(_fs_get_file_mode "${path}")"
        actual_owner="$(_fs_get_file_owner "${path}")"
        actual_group="$(_fs_get_file_group "${path}")"

        # Pad actual_mode for comparison
        if [[ "${#actual_mode}" -lt 4 ]]; then
            actual_mode="0${actual_mode}"
        fi

        local needs_chmod=false needs_chown=false
        if _fs_mode_is_more_permissive "${actual_mode}" "${expected_mode}"; then
            needs_chmod=true
        fi
        if [[ "${actual_owner}" != "${expected_owner}" || "${actual_group}" != "${expected_group}" ]]; then
            needs_chown=true
        fi

        if [[ "${needs_chmod}" == "false" && "${needs_chown}" == "false" ]]; then
            log_debug "filesystem_apply: ${path} permissions already correct — skipping"
            (( CHANGES_SKIPPED++ )) || true
            continue
        fi

        if ! should_write; then
            log_info "[DRY-RUN] Would set ${path} to mode=${expected_mode} owner=${expected_owner}:${expected_group}"
            continue
        fi

        log_change \
            "Set ${path} mode=${expected_mode} owner=${expected_owner}:${expected_group}" \
            "Restrict access to sensitive system file" \
            "low" \
            "stat -c '%a %U %G' ${path}" \
            "chmod ${actual_mode} ${path} && chown ${actual_owner}:${actual_group} ${path}"

        if [[ "${needs_chmod}" == "true" ]]; then
            chmod "${expected_mode}" "${path}" 2>/dev/null || {
                log_error "filesystem_apply: chmod ${expected_mode} ${path} failed"
                (( CHANGES_FAILED++ )) || true
                continue
            }
        fi

        if [[ "${needs_chown}" == "true" ]]; then
            chown "${expected_owner}:${expected_group}" "${path}" 2>/dev/null || {
                log_error "filesystem_apply: chown ${expected_owner}:${expected_group} ${path} failed"
                (( CHANGES_FAILED++ )) || true
                continue
            }
        fi

        log_success "filesystem_apply: ${path} permissions updated"
        (( CHANGES_APPLIED++ )) || true
    done

    # ── 4. Core dump configuration ────────────────────────────────────────────

    # PAM limits drop-in
    local limits_content
    limits_content="$(cat <<'EOF'
# Managed by linux-hardener — do not edit by hand
# Disable core dumps for all users
* hard core 0
* soft core 0
EOF
)"

    if ! should_write; then
        log_info "[DRY-RUN] Would write ${_FS_LIMITS_CONF}"
        log_info "[DRY-RUN] Would write ${_FS_COREDUMP_CONF}"
    else
        mkdir -p "$(dirname "${_FS_LIMITS_CONF}")"
        write_file_if_changed \
            "${_FS_LIMITS_CONF}" \
            "${limits_content}" \
            "Disable core dumps via PAM limits drop-in"

        log_change \
            "Write ${_FS_LIMITS_CONF}" \
            "Prevent sensitive process memory from being written to disk as core dumps" \
            "low" \
            "ulimit -c" \
            "rm -f ${_FS_LIMITS_CONF}"

        # systemd coredump drop-in
        local coredump_content
        coredump_content="$(cat <<'EOF'
# Managed by linux-hardener — do not edit by hand
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
)"

        mkdir -p "$(dirname "${_FS_COREDUMP_CONF}")"
        write_file_if_changed \
            "${_FS_COREDUMP_CONF}" \
            "${coredump_content}" \
            "Disable systemd coredump storage via drop-in"

        log_change \
            "Write ${_FS_COREDUMP_CONF}" \
            "Prevent systemd from capturing core dumps" \
            "low" \
            "cat ${_FS_COREDUMP_CONF}" \
            "rm -f ${_FS_COREDUMP_CONF}"
    fi
}

# ─── filesystem_rollback ──────────────────────────────────────────────────────

filesystem_rollback() {
    log_info "filesystem_rollback: restoring filesystem configuration"

    # ── Restore /etc/fstab ────────────────────────────────────────────────────
    if restore_file "/etc/fstab"; then
        log_info "filesystem_rollback: /etc/fstab restored from backup"

        # Attempt to remount /tmp and /dev/shm with defaults from restored fstab
        mount -o remount,defaults /tmp    2>/dev/null || \
            log_warn "filesystem_rollback: failed to remount /tmp — a reboot may be required"
        mount -o remount,defaults /dev/shm 2>/dev/null || \
            log_warn "filesystem_rollback: failed to remount /dev/shm — a reboot may be required"
    else
        log_warn "filesystem_rollback: no /etc/fstab backup found — skipping fstab restore"
    fi

    # ── Remove core dump drop-ins ─────────────────────────────────────────────
    if [[ -f "${_FS_LIMITS_CONF}" ]]; then
        rm -f "${_FS_LIMITS_CONF}"
        log_info "filesystem_rollback: removed ${_FS_LIMITS_CONF}"
    else
        log_debug "filesystem_rollback: ${_FS_LIMITS_CONF} not present, skipping"
    fi

    if [[ -f "${_FS_COREDUMP_CONF}" ]]; then
        rm -f "${_FS_COREDUMP_CONF}"
        log_info "filesystem_rollback: removed ${_FS_COREDUMP_CONF}"
        # Reload systemd configuration to pick up the removed drop-in
        systemctl daemon-reload 2>/dev/null || true
    else
        log_debug "filesystem_rollback: ${_FS_COREDUMP_CONF} not present, skipping"
    fi

    log_success "filesystem_rollback: complete"
}
