#!/usr/bin/env bash
# modules/25_ssh_crypto.sh — SSH crypto policy and access scoping
# Provides: ssh_crypto_audit, ssh_crypto_apply, ssh_crypto_rollback
#
# Eliminates weak SSH key exchange / cipher / MAC algorithms and optionally
# scopes logins to named groups, without breaking modern OpenSSH clients.
#
# Lock-out safety: a config reload never kills the current SSH session, but a
# broken algorithm set would block every FUTURE connection. After reloading,
# the module performs a real SSH handshake against localhost: an output of
# "Permission denied" proves kex/cipher/MAC negotiation succeeded (auth is
# expected to fail), while "no matching ..." proves the crypto is broken and
# triggers an immediate revert + reload. This is deterministic and safe for
# unattended runs — unlike an `at`-based rollback timer, it cannot revert a
# good config just because nobody confirmed it.
# Sourced by harden.sh. Do NOT add set -euo pipefail here.

readonly SSH_CRYPTO_DROPIN="/etc/ssh/sshd_config.d/25-hardener-crypto.conf"

# Algorithm policy (modern OpenSSH >= 8.0 clients)
readonly _SSHC_KEX="curve25519-sha256,curve25519-sha256@libssh.org"
readonly _SSHC_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
readonly _SSHC_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
# ed25519 preferred; rsa-sha2-512 retained for 4096-bit RSA keys, with the
# size floor enforced via RequiredRSASize where sshd supports it (>= 9.1).
readonly _SSHC_HOSTKEYALGS="ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"

# Config defaults
: "${SSH_MODERN_CRYPTO:=yes}"
: "${SSH_ALLOWED_GROUPS:=}"
: "${SSH_LOGIN_GRACE_TIME:=20}"
# Raise the RHEL SYSTEM-WIDE crypto policy to FUTURE. OFF by default: FUTURE
# rejects TLS certificates with keys it considers too weak, and several distro
# package mirrors (notably mirrors.rockylinux.org) present such certs — turning
# it on breaks dnf/yum downloads system-wide. The sshd drop-in below already
# enforces modern SSH crypto deterministically without this side effect.
: "${SSH_CRYPTO_SYSTEM_POLICY:=no}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

_sshc_sshd_t() {
    # Effective server config; sshd -T needs root
    sshd -T 2>/dev/null
}

# _sshc_weak_algos — print any weak algorithms present in the effective config
_sshc_weak_algos() {
    _sshc_sshd_t | awk '
        $1=="kexalgorithms" || $1=="ciphers" || $1=="macs" || $1=="hostkeyalgorithms" {print}
    ' | grep -oE 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|[a-z0-9-]*-cbc|hmac-sha1(-96)?(,|$)|hmac-md5[a-z0-9@.-]*' \
      | sed 's/,$//' | sort -u
}

# _sshc_supports <directive> — does this sshd accept the directive?
_sshc_supports() {
    local directive="${1}"
    local probe
    probe="$(mktemp)"
    printf '%s\n' "${directive}" > "${probe}"
    local rc=0
    # Validate the directive in isolation against a minimal config
    if sshd -t -f "${probe}" 2>&1 | grep -qiE 'bad configuration|unsupported|unknown'; then
        rc=1
    fi
    rm -f "${probe}"
    return "${rc}"
}

# _sshc_build_dropin — print the drop-in content for the current config values
_sshc_build_dropin() {
    cat <<EOF
# Managed by linux-hardener (modules/25_ssh_crypto.sh) — do not edit by hand.
# Modern-only SSH crypto policy. Sorts before 50-redhat.conf /
# 99-hardening.conf; sshd keeps the FIRST value it sees per keyword.
KexAlgorithms ${_SSHC_KEX}
Ciphers ${_SSHC_CIPHERS}
MACs ${_SSHC_MACS}
HostKeyAlgorithms ${_SSHC_HOSTKEYALGS}
LoginGraceTime ${SSH_LOGIN_GRACE_TIME}
EOF
    if _sshc_supports "RequiredRSASize 4096"; then
        printf 'RequiredRSASize 4096\n'
    fi
    if [[ -n "${SSH_ALLOWED_GROUPS}" ]]; then
        printf 'AllowGroups %s\n' "${SSH_ALLOWED_GROUPS}"
    fi
}

# _sshc_handshake_probe — real kex/cipher/MAC negotiation against localhost.
# Returns 0 if the handshake completes (auth failure expected and fine),
# 1 if algorithm negotiation itself fails.
_sshc_handshake_probe() {
    local port
    port="$(_sshc_sshd_t | awk '$1=="port"{print $2; exit}')"
    port="${port:-22}"

    local out
    out="$(ssh -p "${port}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o NumberOfPasswordPrompts=0 \
        "hardener-probe@127.0.0.1" true 2>&1 || true)"

    if grep -qiE 'no matching (key exchange|cipher|mac|host key)' <<< "${out}"; then
        log_error "ssh_crypto: handshake probe FAILED: $(head -1 <<< "${out}")"
        return 1
    fi
    if grep -qiE 'permission denied|no supported authentication|too many authentication' <<< "${out}"; then
        log_debug "ssh_crypto: handshake probe OK (negotiation succeeded, auth denied as expected)"
        return 0
    fi
    if grep -qiE 'connection refused|timed out|connection closed by remote host before' <<< "${out}"; then
        log_error "ssh_crypto: handshake probe could not connect: $(head -1 <<< "${out}")"
        return 1
    fi
    # Unexpected success or unknown output — treat connectivity as proven
    log_debug "ssh_crypto: handshake probe output: $(head -1 <<< "${out}")"
    return 0
}

_sshc_reload_sshd() {
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null \
        || systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
}

# ─── Audit ────────────────────────────────────────────────────────────────────

ssh_crypto_audit() {
    if [[ "${SSH_MODERN_CRYPTO}" != "yes" ]]; then
        log_info "ssh_crypto_audit: skipped (SSH_MODERN_CRYPTO != yes)"
        return 0
    fi

    log_info "ssh_crypto_audit: checking effective sshd crypto"

    if ! command -v sshd &>/dev/null; then
        log_warn "ssh_crypto_audit: sshd not installed — skipping"
        return 0
    fi

    local weak
    weak="$(_sshc_weak_algos)"
    if [[ -n "${weak}" ]]; then
        log_warn "FINDING: weak SSH algorithms active: ${weak//$'\n'/, }"
        (( AUDIT_FINDINGS++ )) || true
    else
        log_debug "ssh_crypto_audit: no weak kex/cipher/MAC algorithms active (OK)"
    fi

    if [[ ! -f "${SSH_CRYPTO_DROPIN}" ]]; then
        log_warn "FINDING: SSH crypto policy drop-in missing: ${SSH_CRYPTO_DROPIN}"
        (( AUDIT_FINDINGS++ )) || true
    fi

    if [[ -n "${SSH_ALLOWED_GROUPS}" ]]; then
        local groups_eff
        groups_eff="$(_sshc_sshd_t | awk '$1=="allowgroups"{$1=""; print}' | tr -d ' ')"
        if [[ -z "${groups_eff}" ]]; then
            log_warn "FINDING: SSH_ALLOWED_GROUPS configured but no AllowGroups restriction active"
            (( AUDIT_FINDINGS++ )) || true
        fi
    fi
    return 0
}

# ─── Apply ────────────────────────────────────────────────────────────────────

ssh_crypto_apply() {
    if [[ "${SSH_MODERN_CRYPTO}" != "yes" ]]; then
        log_info "ssh_crypto: disabled (SSH_MODERN_CRYPTO != yes) — skipping"
        return 2
    fi
    if ! command -v sshd &>/dev/null; then
        log_warn "ssh_crypto: sshd not installed — skipping"
        return 2
    fi

    # Lock-out guard: every group in AllowGroups must have at least one member
    # (or be a user's primary group) BEFORE we restrict logins to it.
    if [[ -n "${SSH_ALLOWED_GROUPS}" ]]; then
        local grp ok_members=false
        for grp in ${SSH_ALLOWED_GROUPS}; do
            if ! getent group "${grp}" &>/dev/null; then
                log_error "ssh_crypto: AllowGroups group '${grp}' does not exist — refusing (create it and add your admin user first)"
                return 1
            fi
            if [[ -n "$(getent group "${grp}" | cut -d: -f4)" ]] \
                    || awk -F: -v g="$(getent group "${grp}" | cut -d: -f3)" '$4==g{found=1}END{exit !found}' /etc/passwd; then
                ok_members=true
            fi
        done
        if [[ "${ok_members}" != "true" ]]; then
            log_error "ssh_crypto: no user is a member of '${SSH_ALLOWED_GROUPS}' — applying would lock everyone out, refusing"
            return 1
        fi
    fi

    local content
    content="$(_sshc_build_dropin)"

    if [[ "${DRY_RUN:-no}" == "yes" ]] || ! should_write; then
        log_info "[DRY-RUN] Would write ${SSH_CRYPTO_DROPIN}:"
        log_info "${content}"
        [[ "${DISTRO_FAMILY}" == "rhel" ]] && \
            log_info "[DRY-RUN] Would raise system-wide crypto policy to FUTURE (update-crypto-policies)"
        return 0
    fi

    # ── RHEL family: optionally raise the system-wide crypto policy. OFF by
    # default — FUTURE breaks dnf TLS to mirrors with "too weak" certs. The
    # sshd drop-in below is the deterministic SSH-hardening mechanism either way.
    if [[ "${SSH_CRYPTO_SYSTEM_POLICY}" == "yes" && "${DISTRO_FAMILY}" == "rhel" ]] \
            && command -v update-crypto-policies &>/dev/null; then
        local current_policy
        current_policy="$(update-crypto-policies --show 2>/dev/null || echo unknown)"
        case "${current_policy}" in
            LEGACY*)
                log_warn "ssh_crypto: system crypto policy is LEGACY (explicitly chosen) — leaving it untouched"
                ;;
            FUTURE*)
                log_debug "ssh_crypto: system crypto policy already FUTURE"
                ;;
            *)
                if update-crypto-policies --set FUTURE &>/dev/null; then
                    printf '%s\n' "${current_policy}" > "${HARDENER_STATE_DIR}/crypto-policy.prev" 2>/dev/null || true
                    log_change \
                        "System crypto policy ${current_policy} -> FUTURE" \
                        "Disallow legacy TLS/SSH crypto system-wide" \
                        "medium" \
                        "update-crypto-policies --show" \
                        "update-crypto-policies --set ${current_policy}"
                    log_success "ssh_crypto: system crypto policy raised to FUTURE (was ${current_policy})"
                    (( CHANGES_APPLIED++ )) || true
                else
                    log_warn "ssh_crypto: update-crypto-policies --set FUTURE failed — relying on the sshd drop-in only"
                fi
                ;;
        esac
    fi

    # ── Write the drop-in, validate, reload, live-probe ──────────────────────
    mkdir -p "$(dirname "${SSH_CRYPTO_DROPIN}")"

    local write_rc=0
    write_file_if_changed "${SSH_CRYPTO_DROPIN}" "${content}" \
        "SSH modern crypto policy drop-in" || write_rc=$?
    if [[ "${write_rc}" -eq 2 ]]; then
        log_debug "ssh_crypto: drop-in already up to date"
        # still verify the running daemon matches the file
        if _sshc_weak_algos | grep -q .; then
            log_info "ssh_crypto: drop-in current but weak algos active — reloading sshd"
            _sshc_reload_sshd
        fi
        return 2
    fi

    if ! sshd -t 2>/tmp/.sshc-err; then
        log_error "ssh_crypto: sshd -t rejected the new configuration:"
        while IFS= read -r line; do log_error "ssh_crypto:   ${line}"; done < /tmp/.sshc-err
        rm -f /tmp/.sshc-err "${SSH_CRYPTO_DROPIN}"
        log_error "ssh_crypto: drop-in removed — sshd untouched"
        (( CHANGES_FAILED++ )) || true
        return 1
    fi
    rm -f /tmp/.sshc-err

    log_change \
        "SSH crypto policy: ${SSH_CRYPTO_DROPIN} (kex/ciphers/MACs/host keys, LoginGraceTime=${SSH_LOGIN_GRACE_TIME}${SSH_ALLOWED_GROUPS:+, AllowGroups=${SSH_ALLOWED_GROUPS}})" \
        "Remove weak SSH algorithms; scope logins (Lynis SSH-7408)" \
        "high" \
        "sshd -T | grep -E 'kexalgorithms|ciphers|macs'" \
        "rm -f ${SSH_CRYPTO_DROPIN} && systemctl reload sshd"

    _sshc_reload_sshd

    # Live handshake probe: revert immediately if negotiation breaks.
    # Existing sessions (including this one) are unaffected by reloads.
    if ! _sshc_handshake_probe; then
        log_error "ssh_crypto: REVERTING — new connections could not negotiate"
        rm -f "${SSH_CRYPTO_DROPIN}"
        _sshc_reload_sshd
        (( CHANGES_FAILED++ )) || true
        return 1
    fi

    # Confirm no weak algorithms survive in the effective config
    local weak
    weak="$(_sshc_weak_algos)"
    if [[ -n "${weak}" ]]; then
        log_warn "ssh_crypto: weak algorithms still effective after apply: ${weak//$'\n'/, }"
    fi

    log_success "ssh_crypto: modern crypto policy active (handshake probe passed)"
    (( CHANGES_APPLIED++ )) || true
    return 0
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

ssh_crypto_rollback() {
    log_info "ssh_crypto_rollback: removing crypto policy drop-in"

    if [[ -f "${SSH_CRYPTO_DROPIN}" ]]; then
        rm -f "${SSH_CRYPTO_DROPIN}"
        _sshc_reload_sshd
        log_info "ssh_crypto_rollback: removed ${SSH_CRYPTO_DROPIN} and reloaded sshd"
    fi

    if [[ -f "${HARDENER_STATE_DIR}/crypto-policy.prev" ]] && command -v update-crypto-policies &>/dev/null; then
        local prev
        prev="$(cat "${HARDENER_STATE_DIR}/crypto-policy.prev")"
        update-crypto-policies --set "${prev}" &>/dev/null \
            && log_info "ssh_crypto_rollback: system crypto policy restored to ${prev}"
        rm -f "${HARDENER_STATE_DIR}/crypto-policy.prev"
    fi

    log_success "ssh_crypto_rollback: complete"
    return 0
}
