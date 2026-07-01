#!/usr/bin/env bash
# modules/luks.d/kms.sh — key escrow (AWS KMS / GCP KMS / Vault) and
# network-bound disk encryption (clevis + tang) for the runtime LUKS module.
# Escrow is OPTIONAL and best-effort: the local keyfile/passphrase always
# remains the primary unlock path; escrow failure is a warning, never fatal.
# Sourced by modules/20_luks.sh. Do NOT add set -euo pipefail here.

# ─── Escrow ───────────────────────────────────────────────────────────────────

# _luks_kms_escrow <keyfile> <name>
# Encrypt the keyfile with the configured KMS using the instance's own
# identity (IAM role / service account / Vault token) and store the blob
# remotely. Returns 0 on success or when escrow is disabled; 1 on failure.
_luks_kms_escrow() {
    local keyfile="${1}" name="${2}"
    local provider="${LUKS_CLOUD_KMS_PROVIDER:-none}"

    [[ "${provider}" == "none" || -z "${provider}" ]] && return 0

    if [[ ! -f "${keyfile}" ]]; then
        log_warn "luks-kms: keyfile not found for escrow: ${keyfile}"
        return 1
    fi

    case "${provider}" in
        aws)   _luks_kms_escrow_aws   "${keyfile}" "${name}" ;;
        gcp)   _luks_kms_escrow_gcp   "${keyfile}" "${name}" ;;
        vault) _luks_kms_escrow_vault "${keyfile}" "${name}" ;;
        *)
            log_warn "luks-kms: unknown provider '${provider}' — keys stay local only"
            return 1
            ;;
    esac
}

_luks_kms_escrow_aws() {
    local keyfile="${1}" name="${2}"

    command -v aws &>/dev/null || { log_warn "luks-kms: aws CLI missing — escrow skipped"; return 1; }
    [[ -n "${LUKS_KMS_AWS_KEY_ID:-}" ]] || { log_warn "luks-kms: LUKS_KMS_AWS_KEY_ID not set"; return 1; }

    # Verify we actually have instance credentials before trying
    if ! aws sts get-caller-identity &>/dev/null; then
        log_warn "luks-kms: no usable AWS identity (instance role?) — escrow skipped"
        return 1
    fi

    local blob
    blob="$(mktemp /dev/shm/.luks-escrow.XXXXXX)"
    if ! aws kms encrypt \
            --key-id "${LUKS_KMS_AWS_KEY_ID}" \
            --plaintext "fileb://${keyfile}" \
            --query CiphertextBlob --output text > "${blob}" 2>/dev/null; then
        log_warn "luks-kms: aws kms encrypt failed for ${name}"
        rm -f "${blob}"
        return 1
    fi

    local rc=1
    if [[ -n "${LUKS_KMS_AWS_S3_BUCKET:-}" ]]; then
        aws s3 cp "${blob}" "s3://${LUKS_KMS_AWS_S3_BUCKET}/luks/${name}.key.kms" &>/dev/null && rc=0
    else
        aws ssm put-parameter --name "/luks/${name}" --type SecureString \
            --value "file://${blob}" --overwrite &>/dev/null && rc=0
    fi
    rm -f "${blob}"

    if [[ ${rc} -eq 0 ]]; then
        log_success "luks-kms: keyfile for ${name} escrowed to AWS KMS"
    else
        log_warn "luks-kms: escrow upload failed for ${name} (S3/SSM)"
    fi
    return "${rc}"
}

_luks_kms_escrow_gcp() {
    local keyfile="${1}" name="${2}"

    command -v gcloud &>/dev/null || { log_warn "luks-kms: gcloud CLI missing — escrow skipped"; return 1; }
    [[ -n "${LUKS_KMS_GCP_KEYRING:-}" ]] || { log_warn "luks-kms: LUKS_KMS_GCP_KEYRING not set"; return 1; }

    local blob
    blob="$(mktemp /dev/shm/.luks-escrow.XXXXXX)"
    if ! gcloud kms encrypt \
            --key "${LUKS_KMS_GCP_KEYRING}" \
            --plaintext-file "${keyfile}" \
            --ciphertext-file "${blob}" &>/dev/null; then
        log_warn "luks-kms: gcloud kms encrypt failed for ${name}"
        rm -f "${blob}"
        return 1
    fi

    local rc=1
    if [[ -n "${LUKS_KMS_GCP_BUCKET:-}" ]]; then
        gcloud storage cp "${blob}" "gs://${LUKS_KMS_GCP_BUCKET}/luks/${name}.key.kms" &>/dev/null && rc=0
    else
        log_warn "luks-kms: LUKS_KMS_GCP_BUCKET not set — nowhere to store the blob"
    fi
    rm -f "${blob}"

    [[ ${rc} -eq 0 ]] && log_success "luks-kms: keyfile for ${name} escrowed to GCP KMS"
    return "${rc}"
}

_luks_kms_escrow_vault() {
    local keyfile="${1}" name="${2}"

    command -v vault &>/dev/null || { log_warn "luks-kms: vault CLI missing — escrow skipped"; return 1; }
    if [[ -z "${VAULT_ADDR:-}" ]]; then
        log_warn "luks-kms: VAULT_ADDR not set — escrow skipped"
        return 1
    fi

    local b64
    b64="$(base64 -w0 "${keyfile}" 2>/dev/null || base64 "${keyfile}" | tr -d '\n')"
    if vault kv put "${LUKS_KMS_VAULT_PATH:-secret/luks}/${name}" keyfile_b64="${b64}" &>/dev/null; then
        log_success "luks-kms: keyfile for ${name} escrowed to Vault"
        return 0
    fi
    log_warn "luks-kms: vault kv put failed for ${name}"
    return 1
}

# ─── Retrieval (used by luks-cloud-recovery.sh and boot-time best effort) ────

# _luks_kms_retrieve <name> <dest>
# Fetch and decrypt an escrowed keyfile. Returns 0 and writes <dest> (0400)
# on success.
_luks_kms_retrieve() {
    local name="${1}" dest="${2}"
    local provider="${LUKS_CLOUD_KMS_PROVIDER:-none}"

    case "${provider}" in
        aws)
            command -v aws &>/dev/null || return 1
            local blob
            blob="$(mktemp /dev/shm/.luks-retrieve.XXXXXX)"
            if [[ -n "${LUKS_KMS_AWS_S3_BUCKET:-}" ]]; then
                aws s3 cp "s3://${LUKS_KMS_AWS_S3_BUCKET}/luks/${name}.key.kms" "${blob}" &>/dev/null || return 1
            else
                aws ssm get-parameter --name "/luks/${name}" --with-decryption \
                    --query Parameter.Value --output text > "${blob}" 2>/dev/null || return 1
            fi
            base64 -d "${blob}" > "${blob}.bin" 2>/dev/null
            ( umask 277; aws kms decrypt \
                --ciphertext-blob "fileb://${blob}.bin" \
                --query Plaintext --output text 2>/dev/null | base64 -d > "${dest}" )
            local rc=$?
            rm -f "${blob}" "${blob}.bin"
            [[ ${rc} -eq 0 && -s "${dest}" ]] || { rm -f "${dest}"; return 1; }
            ;;
        gcp)
            command -v gcloud &>/dev/null || return 1
            [[ -n "${LUKS_KMS_GCP_BUCKET:-}" ]] || return 1
            local blob
            blob="$(mktemp /dev/shm/.luks-retrieve.XXXXXX)"
            gcloud storage cp "gs://${LUKS_KMS_GCP_BUCKET}/luks/${name}.key.kms" "${blob}" &>/dev/null || return 1
            ( umask 277; gcloud kms decrypt \
                --key "${LUKS_KMS_GCP_KEYRING}" \
                --ciphertext-file "${blob}" \
                --plaintext-file "${dest}" &>/dev/null )
            local rc=$?
            rm -f "${blob}"
            [[ ${rc} -eq 0 && -s "${dest}" ]] || { rm -f "${dest}"; return 1; }
            ;;
        vault)
            command -v vault &>/dev/null || return 1
            local b64
            b64="$(vault kv get -field=keyfile_b64 "${LUKS_KMS_VAULT_PATH:-secret/luks}/${name}" 2>/dev/null)" || return 1
            ( umask 277; printf '%s' "${b64}" | base64 -d > "${dest}" )
            [[ -s "${dest}" ]] || { rm -f "${dest}"; return 1; }
            ;;
        *)
            return 1
            ;;
    esac

    chmod 0400 "${dest}"
    return 0
}

# ─── Network-Bound Disk Encryption (clevis + tang) ────────────────────────────

# _luks_nbde_bind <device>
# Bind a LUKS device to a Tang server for automated in-VPC unlock. Strictly
# opt-in (LUKS_NBDE=yes + LUKS_TANG_URL); the existing keyfile/passphrase slot
# is always retained so a dead Tang server degrades to manual unlock.
_luks_nbde_bind() {
    local device="${1}"

    [[ "${LUKS_NBDE:-no}" == "yes" ]] || return 0
    if [[ -z "${LUKS_TANG_URL:-}" ]]; then
        log_warn "luks-nbde: LUKS_NBDE=yes but LUKS_TANG_URL is empty — skipped"
        return 1
    fi

    if ! should_write; then
        log_info "[DRY-RUN] Would bind ${device} to Tang server ${LUKS_TANG_URL}"
        return 0
    fi

    if ! command -v clevis &>/dev/null; then
        local pkgs=( clevis clevis-luks )
        [[ "${DISTRO_FAMILY}" == "debian" ]] && pkgs+=( clevis-systemd )
        [[ "${DISTRO_FAMILY}" == "rhel" ]] && pkgs+=( clevis-systemd )
        pkg_install "${pkgs[@]}" || {
            log_error "luks-nbde: failed to install clevis"
            return 1
        }
    fi

    # Reachability probe — never bind to a server we cannot see
    if ! curl -sf --connect-timeout 10 "${LUKS_TANG_URL%/}/adv" -o /dev/null 2>/dev/null; then
        log_warn "luks-nbde: Tang server unreachable at ${LUKS_TANG_URL} — binding skipped (passphrase fallback remains)"
        return 1
    fi

    # Already bound?
    if command -v clevis &>/dev/null && clevis luks list -d "${device}" 2>/dev/null | grep -q tang; then
        log_debug "luks-nbde: ${device} already bound to Tang"
        return 0
    fi

    local keyfile
    keyfile="$(_luks_state_entries "volume" | awk -F'|' -v d="${device}" '$3==d{print $5; exit}')"

    # Pin the Tang advertisement when a thumbprint is configured — `-y` alone
    # trusts whatever keys the (typically plain-HTTP) Tang endpoint serves at
    # bind time, so a MITM could substitute their own.
    local tang_cfg="{\"url\":\"${LUKS_TANG_URL}\"}"
    if [[ -n "${LUKS_TANG_THUMBPRINT:-}" ]]; then
        tang_cfg="{\"url\":\"${LUKS_TANG_URL}\",\"thp\":\"${LUKS_TANG_THUMBPRINT}\"}"
    else
        log_warn "luks-nbde: LUKS_TANG_THUMBPRINT not set — trusting the Tang advertisement unverified (set it to pin the server key)"
    fi
    local bind_args=( luks bind -y -d "${device}" tang "${tang_cfg}" )

    local rc=1
    if [[ -n "${keyfile}" && -f "${keyfile}" ]]; then
        clevis "${bind_args[@]}" -k "${keyfile}" &>/dev/null && rc=0
    else
        clevis "${bind_args[@]}" &>/dev/null && rc=0
    fi

    if [[ ${rc} -eq 0 ]]; then
        systemctl enable clevis-luks-askpass.path &>/dev/null || true
        _luks_state_record "nbde" "${device}" "${LUKS_TANG_URL}"
        log_success "luks-nbde: ${device} bound to Tang at ${LUKS_TANG_URL} (passphrase slot retained)"
    else
        log_warn "luks-nbde: clevis bind failed for ${device}"
    fi
    return "${rc}"
}
