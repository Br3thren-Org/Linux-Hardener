#!/usr/bin/env bash
# lib/distro/debian.sh — Debian/Ubuntu-specific hardening adapters
# Sourced by harden.sh after lib/common.sh when DISTRO_FAMILY == "debian".
# All functions from common.sh (log_*, should_write, write_file_if_changed,
# pkg_install, etc.) are available here.

# ─── Security Updates ────────────────────────────────────────────────────────

debian_security_update() {
    log_info "Running Debian security update"

    if ! should_write; then
        log_info "[DRY-RUN] Would run: apt-get update && apt-get upgrade -y"
        return 0
    fi

    log_change \
        "apt-get update && apt-get upgrade -y" \
        "Apply all available security patches" \
        "medium" \
        "apt-get -s upgrade | grep -i upgraded" \
        "N/A — package updates cannot be automatically reversed"

    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    log_success "Debian security update complete"
}

# ─── Unattended Upgrades ─────────────────────────────────────────────────────

debian_enable_unattended_upgrades() {
    if [[ "${ENABLE_UNATTENDED_UPGRADES:-false}" != "true" ]]; then
        log_info "Skipping unattended-upgrades (ENABLE_UNATTENDED_UPGRADES != true)"
        return 0
    fi

    log_info "Configuring unattended-upgrades"

    if ! should_write; then
        log_info "[DRY-RUN] Would install and configure unattended-upgrades"
        return 0
    fi

    pkg_install unattended-upgrades

    # Determine the security origin label for this distro
    local origin_label
    case "${DISTRO_ID:-}" in
        ubuntu)
            origin_label="${DISTRO_ID^}"   # "Ubuntu"
            ;;
        *)
            origin_label="Debian"
            ;;
    esac

    local uu_conf
    uu_conf="$(cat <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "${origin_label}:\${distro_codename}-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
)"

    local auto_conf
    auto_conf="$(cat <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
)"

    write_file_if_changed \
        "/etc/apt/apt.conf.d/50unattended-upgrades" \
        "${uu_conf}" \
        "Configure unattended-upgrades security-only origins"

    write_file_if_changed \
        "/etc/apt/apt.conf.d/20auto-upgrades" \
        "${auto_conf}" \
        "Enable APT periodic unattended upgrades"

    log_change \
        "Unattended-upgrades enabled" \
        "Automatically apply security updates without manual intervention" \
        "low" \
        "unattended-upgrade --dry-run" \
        "apt-get purge -y unattended-upgrades && rm -f /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/20auto-upgrades"

    log_success "Unattended-upgrades configured"
}

# ─── Firewall (nftables) ─────────────────────────────────────────────────────

debian_setup_firewall() {
    log_info "Setting up nftables firewall"

    if ! should_write; then
        log_info "[DRY-RUN] Would install nftables and write /etc/nftables.conf"
        return 0
    fi

    pkg_install nftables

    local ssh_port="${SSH_PORT:-22}"

    # Build allowed TCP input rules
    local tcp_rules=""
    local raw_tcp="${FIREWALL_ALLOWED_TCP_IN:-${ssh_port}}"
    local port
    IFS=',' read -ra _ports <<< "${raw_tcp}"
    for port in "${_ports[@]}"; do
        port="${port// /}"
        [[ -z "${port}" ]] && continue
        tcp_rules+="        tcp dport ${port} accept"$'\n'
    done

    # Build allowed UDP input rules
    local udp_rules=""
    if [[ -n "${FIREWALL_ALLOWED_UDP_IN:-}" ]]; then
        IFS=',' read -ra _ports <<< "${FIREWALL_ALLOWED_UDP_IN}"
        for port in "${_ports[@]}"; do
            port="${port// /}"
            [[ -z "${port}" ]] && continue
            udp_rules+="        udp dport ${port} accept"$'\n'
        done
    fi

    local nft_conf
    nft_conf="$(cat <<EOF
#!/usr/sbin/nft -f
# Managed by linux-hardener — do not edit by hand

flush ruleset

table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iifname "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # Drop invalid packets
        ct state invalid drop

        # Allow ICMPv4
        ip protocol icmp accept

        # Allow ICMPv6
        meta l4proto ipv6-icmp accept

        # Allowed TCP ports
${tcp_rules}
        # Allowed UDP ports
${udp_rules}
        # Log and drop everything else
        log prefix "nftables-drop: " flags all drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
)"

    write_file_if_changed \
        "/etc/nftables.conf" \
        "${nft_conf}" \
        "Write nftables firewall ruleset"

    log_change \
        "nftables firewall configured" \
        "Restrict inbound traffic to allowed ports; default-drop policy" \
        "high" \
        "nft list ruleset" \
        "systemctl stop nftables && nft flush ruleset"

    systemctl enable nftables
    systemctl restart nftables
    log_success "nftables firewall enabled and active"
}

# ─── /tmp noexec Hook for APT ─────────────────────────────────────────────────

debian_setup_tmp_hook() {
    if [[ "${NOEXEC_TMP:-false}" != "true" ]]; then
        log_info "Skipping /tmp noexec APT hook (NOEXEC_TMP != true)"
        return 0
    fi

    log_info "Configuring APT hooks to toggle /tmp exec/noexec around package operations"

    if ! should_write; then
        log_info "[DRY-RUN] Would write hardener-tmp exec/noexec scripts and APT hook config"
        return 0
    fi

    local exec_script="/usr/local/sbin/hardener-tmp-exec.sh"
    local noexec_script="/usr/local/sbin/hardener-tmp-noexec.sh"
    local apt_hook_conf="/etc/apt/apt.conf.d/99-hardener-tmp"

    local exec_content
    exec_content="$(cat <<'EOF'
#!/usr/bin/env bash
# Managed by linux-hardener — temporarily remount /tmp with exec
# Called by APT DPkg::Pre-Invoke hook before package operations.
mount -o remount,exec /tmp || true
EOF
)"

    local noexec_content
    noexec_content="$(cat <<'EOF'
#!/usr/bin/env bash
# Managed by linux-hardener — re-apply noexec on /tmp
# Called by APT DPkg::Post-Invoke hook after package operations.
mount -o remount,noexec /tmp || true
EOF
)"

    local hook_conf
    hook_conf="$(cat <<EOF
// Managed by linux-hardener
// Temporarily allow exec on /tmp during package installation, then restore noexec.
DPkg::Pre-Invoke  "${exec_script}";
DPkg::Post-Invoke "${noexec_script}";
EOF
)"

    write_file_if_changed "${exec_script}"   "${exec_content}"   "Write /tmp exec remount script"
    write_file_if_changed "${noexec_script}" "${noexec_content}" "Write /tmp noexec remount script"

    chmod 755 "${exec_script}" "${noexec_script}"

    write_file_if_changed "${apt_hook_conf}" "${hook_conf}" "Write APT hook to toggle /tmp noexec"

    log_change \
        "APT /tmp noexec hooks installed" \
        "Prevent /tmp noexec from blocking package installs" \
        "low" \
        "cat ${apt_hook_conf}" \
        "rm -f ${exec_script} ${noexec_script} ${apt_hook_conf}"

    log_success "/tmp noexec APT hooks configured"
}

# ─── Lynis Installation ───────────────────────────────────────────────────────

debian_install_lynis() {
    log_info "Installing Lynis (source: ${LYNIS_SOURCE:-package})"

    case "${LYNIS_SOURCE:-package}" in
        package)
            if pkg_is_installed lynis; then
                log_info "Lynis already installed via package manager, skipping"
                return 0
            fi
            if ! should_write; then
                log_info "[DRY-RUN] Would run: apt-get install -y lynis"
                return 0
            fi
            pkg_install lynis
            log_success "Lynis installed via apt"
            ;;

        cisofy-repo)
            if pkg_is_installed lynis; then
                log_info "Lynis already installed, skipping CISOfy repo setup"
                return 0
            fi
            if ! should_write; then
                log_info "[DRY-RUN] Would add CISOfy repo and install lynis"
                return 0
            fi
            pkg_install apt-transport-https ca-certificates curl gnupg

            # Import CISOfy GPG key
            curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key \
                | gpg --dearmor -o /usr/share/keyrings/cisofy-software-public.gpg

            local repo_entry
            repo_entry="deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main"

            write_file_if_changed \
                "/etc/apt/sources.list.d/cisofy-lynis.list" \
                "${repo_entry}" \
                "Add CISOfy Lynis repository"

            DEBIAN_FRONTEND=noninteractive apt-get update -y
            pkg_install lynis
            log_success "Lynis installed from CISOfy repository"
            ;;

        github)
            if [[ -x "/opt/lynis/lynis" ]]; then
                log_info "Lynis already present at /opt/lynis, skipping clone"
                return 0
            fi
            if ! should_write; then
                log_info "[DRY-RUN] Would clone Lynis from GitHub to /opt/lynis"
                return 0
            fi
            pkg_install git
            git clone --depth 1 https://github.com/CISOfy/lynis.git /opt/lynis
            log_success "Lynis cloned to /opt/lynis"
            ;;

        *)
            log_warn "Unknown LYNIS_SOURCE '${LYNIS_SOURCE}'; skipping Lynis installation"
            ;;
    esac
}
