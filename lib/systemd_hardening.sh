#!/usr/bin/env bash
# lib/systemd-hardening.sh — systemd service sandboxing module
# Deploys security override files for services flagged UNSAFE by systemd-analyze security.
# Sourced by harden.sh after lib/common.sh.
# Do NOT add set -euo pipefail here; the caller owns that.

# ─── Constants ────────────────────────────────────────────────────────────────

readonly _SYSHARDEN_OVERRIDE_DIR="/etc/systemd/system"
readonly _SYSHARDEN_MARKER="# Managed by linux-hardener — do not edit by hand"

# ─── Service Override Definitions ─────────────────────────────────────────────
# Each entry: "service_name|override_content"
# Override content uses ␤ as newline placeholder (replaced at write time).

_sysharden_common_directives() {
    cat <<'EOF'
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
EOF
}

# Returns override content for a specific service.
# Services that need relaxed settings get tailored overrides.
_sysharden_override_for() {
    local service="${1}"

    case "${service}" in
        ssh|sshd)
            # Use ProtectSystem=full (not strict) because sshd needs /var/run write access
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=no
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
EOF
            ;;
        cron)
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
            ;;
        fail2ban)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_AUDIT_READ
ReadWritePaths=/var/run/fail2ban /var/lib/fail2ban /var/log
EOF
            ;;
        unattended-upgrades)
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
            ;;
        lynis)
            # Lynis needs broad read access but doesn't need write access
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
ReadWritePaths=/var/log /var/lib/linux-hardener
EOF
            ;;
        rc-local)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
EOF
            ;;
        auditd)
            # auditd needs CAP_AUDIT_CONTROL and write to /var/log/audit
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_SYS_NICE
ReadWritePaths=/var/log/audit
EOF
            ;;
        mdmonitor|mdmonitor-oneshot)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK
EOF
            ;;
        systemd-rfkill)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
EOF
            ;;
        systemd-initctl)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
EOF
            ;;
        systemd-bsod)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
EOF
            ;;
        sshd-keygen|sshd@sshd-keygen)
            # One-shot key generation — can be heavily sandboxed
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/etc/ssh
EOF
            ;;
        atd)
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
            ;;
        acpid)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK
EOF
            ;;
        getty@*|serial-getty@*)
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
            ;;
        qemu-guest-agent)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_VSOCK
ReadWritePaths=/var/run
EOF
            ;;
        polkit)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK
EOF
            ;;
        firewalld)
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
EOF
            ;;
        udisks2)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK
EOF
            ;;
        resolvconf)
            cat <<'EOF'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/resolvconf /etc/resolv.conf
EOF
            ;;
        crond)
            # RHEL name for cron — same policy as cron
            cat <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
            ;;
        *)
            # Generic hardening for services without special requirements
            printf '[Service]\n'
            _sysharden_common_directives
            printf 'PrivateDevices=yes\n'
            printf 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n'
            ;;
    esac
}

# ─── Services to Harden ──────────────────────────────────────────────────────

readonly -a _SYSHARDEN_SERVICES=(
    ssh
    cron
    crond
    fail2ban
    unattended-upgrades
    lynis
    rc-local
    auditd
    mdmonitor
    mdmonitor-oneshot
    systemd-rfkill
    systemd-initctl
    systemd-bsod
    sshd@sshd-keygen
    atd
    acpid
    "getty@tty1"
    "serial-getty@ttyS0"
    "serial-getty@ttyS1"
    qemu-guest-agent
    polkit
    firewalld
    udisks2
    resolvconf
)

# _sysharden_svc_exists — check if a service (or template instance) exists
_sysharden_svc_exists() {
    local name="${1}"
    # For template instances like getty@tty1, check the template unit
    if [[ "${name}" == *@* ]]; then
        local template="${name%%@*}@"
        systemctl list-unit-files "${template}.service" 2>/dev/null | grep -q "${template}.service"
    else
        svc_exists "${name}"
    fi
}

# ─── systemd_hardening_audit ─────────────────────────────────────────────────

systemd_hardening_audit() {
    log_info "systemd_hardening_audit: checking service security exposure"

    local service override_dir
    for service in "${_SYSHARDEN_SERVICES[@]}"; do
        if ! _sysharden_svc_exists "${service}"; then
            log_debug "systemd_hardening_audit: '${service}' not present, skipping"
            continue
        fi

        override_dir="${_SYSHARDEN_OVERRIDE_DIR}/${service}.service.d"
        if [[ ! -f "${override_dir}/99-hardening.conf" ]]; then
            log_warn "FINDING: ${service}.service has no hardening override"
            (( AUDIT_FINDINGS++ )) || true
        else
            log_debug "systemd_hardening_audit: ${service} has hardening override (OK)"
        fi
    done
}

# ─── systemd_hardening_apply ─────────────────────────────────────────────────

systemd_hardening_apply() {
    log_info "systemd_hardening_apply: deploying service sandboxing overrides"

    local service override_dir override_file content
    local any_changed=false

    for service in "${_SYSHARDEN_SERVICES[@]}"; do
        if ! _sysharden_svc_exists "${service}"; then
            log_debug "systemd_hardening_apply: '${service}' not present, skipping"
            continue
        fi

        override_dir="${_SYSHARDEN_OVERRIDE_DIR}/${service}.service.d"
        override_file="${override_dir}/99-hardening.conf"

        content="${_SYSHARDEN_MARKER}
$(_sysharden_override_for "${service}")
"

        if ! should_write; then
            log_info "[DRY-RUN] Would write ${override_file}"
            continue
        fi

        mkdir -p "${override_dir}"

        local write_rc=0
        write_file_if_changed "${override_file}" "${content}" "Systemd hardening for ${service}" || write_rc=$?

        if [[ "${write_rc}" -eq 2 ]]; then
            log_debug "systemd_hardening_apply: ${service} override already up to date"
            continue
        fi

        log_change \
            "Deploy systemd security override for ${service}.service" \
            "Sandbox ${service} to reduce attack surface (systemd-analyze security)" \
            "medium" \
            "systemd-analyze security ${service}.service" \
            "rm -f ${override_file} && rmdir --ignore-fail-on-non-empty ${override_dir} && systemctl daemon-reload"

        any_changed=true
    done

    if [[ "${any_changed}" == "true" ]]; then
        log_info "systemd_hardening_apply: reloading systemd daemon"
        systemctl daemon-reload

        # Restart affected services to pick up new overrides
        for service in "${_SYSHARDEN_SERVICES[@]}"; do
            # Skip getty/serial-getty — restarting drops console sessions
            [[ "${service}" == getty@* || "${service}" == serial-getty@* ]] && continue
            if _sysharden_svc_exists "${service}" && svc_is_active "${service}"; then
                # auditd refuses systemctl restart; use service command instead
                if [[ "${service}" == "auditd" ]]; then
                    log_info "systemd_hardening_apply: reloading auditd via service command"
                    service auditd restart 2>/dev/null || {
                        log_warn "systemd_hardening_apply: auditd restart failed — override applies after reboot"
                    }
                else
                    log_info "systemd_hardening_apply: restarting ${service} to apply overrides"
                    systemctl restart "${service}" 2>/dev/null || {
                        log_warn "systemd_hardening_apply: failed to restart ${service} — override may need tuning"
                        (( CHANGES_FAILED++ )) || true
                    }
                fi
            fi
        done

        log_success "systemd_hardening_apply: service overrides deployed"
    else
        log_info "systemd_hardening_apply: no changes needed"
    fi
}

# ─── systemd_hardening_rollback ───────────────────────────────────────────────

systemd_hardening_rollback() {
    log_info "systemd_hardening_rollback: removing service hardening overrides"

    local service override_dir override_file
    local any_removed=false

    for service in "${_SYSHARDEN_SERVICES[@]}"; do
        override_dir="${_SYSHARDEN_OVERRIDE_DIR}/${service}.service.d"
        override_file="${override_dir}/99-hardening.conf"

        if [[ -f "${override_file}" ]]; then
            rm -f "${override_file}"
            rmdir --ignore-fail-on-non-empty "${override_dir}" 2>/dev/null || true
            log_info "systemd_hardening_rollback: removed ${override_file}"
            any_removed=true
        fi
    done

    if [[ "${any_removed}" == "true" ]]; then
        systemctl daemon-reload
        log_success "systemd_hardening_rollback: overrides removed and daemon reloaded"
    else
        log_debug "systemd_hardening_rollback: no overrides found to remove"
    fi
}
