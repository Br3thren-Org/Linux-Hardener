#!/usr/bin/env bash
# lib/rollback.sh — backup management helpers for rollback operations
# Sourced by harden.sh after lib/common.sh.
# Provides rollback_list_backups and rollback_cleanup_old.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly ROLLBACK_MAX_BACKUPS=5

# ─── List Backups ─────────────────────────────────────────────────────────────

rollback_list_backups() {
    local backups_dir="${HARDENER_STATE_DIR}/backups"

    if [[ ! -d "${backups_dir}" ]]; then
        log_info "rollback_list_backups: backups directory does not exist: ${backups_dir}"
        return 0
    fi

    log_info "rollback_list_backups: listing backups in ${backups_dir}"

    local found=0
    local entry
    for entry in "${backups_dir}"/*/; do
        # Skip the "latest" symlink
        [[ -L "${entry%/}" ]] && continue
        [[ ! -d "${entry}" ]] && continue

        local name
        name="$(basename "${entry}")"

        local file_count
        file_count="$(find "${entry}" -type f 2>/dev/null | wc -l | tr -d ' ')"

        log_info "  ${name}  (${file_count} files)"
        (( found++ )) || true
    done

    if [[ "${found}" -eq 0 ]]; then
        log_info "rollback_list_backups: no backup directories found"
    else
        log_info "rollback_list_backups: ${found} backup(s) found"
    fi
}

# ─── Cleanup Old Backups ──────────────────────────────────────────────────────

rollback_cleanup_old() {
    local backups_dir="${HARDENER_STATE_DIR}/backups"

    if [[ ! -d "${backups_dir}" ]]; then
        log_debug "rollback_cleanup_old: backups directory does not exist, nothing to clean"
        return 0
    fi

    log_info "rollback_cleanup_old: keeping latest ${ROLLBACK_MAX_BACKUPS} backups, removing older ones"

    # Collect non-symlink backup directories, sorted newest-first (sort -r on name)
    local -a all_backups=()
    local entry
    for entry in "${backups_dir}"/*/; do
        # Skip "latest" symlink and non-directories
        [[ -L "${entry%/}" ]] && continue
        [[ ! -d "${entry}" ]] && continue
        all_backups+=("${entry%/}")
    done

    # Sort newest-first by directory name (timestamps sort lexicographically)
    local -a sorted_backups=()
    while IFS= read -r line; do
        sorted_backups+=("${line}")
    done < <(printf '%s\n' "${all_backups[@]}" | sort -r)

    local total="${#sorted_backups[@]}"

    if [[ "${total}" -le "${ROLLBACK_MAX_BACKUPS}" ]]; then
        log_debug "rollback_cleanup_old: ${total} backup(s) present, no cleanup needed"
        return 0
    fi

    # Remove everything beyond the newest ROLLBACK_MAX_BACKUPS entries
    local i
    for (( i = ROLLBACK_MAX_BACKUPS; i < total; i++ )); do
        local old_dir="${sorted_backups[${i}]}"
        log_info "rollback_cleanup_old: removing old backup: ${old_dir}"
        rm -rf "${old_dir}" || {
            log_warn "rollback_cleanup_old: failed to remove ${old_dir}"
        }
    done

    log_success "rollback_cleanup_old: cleanup complete, kept ${ROLLBACK_MAX_BACKUPS} most recent backup(s)"
}
