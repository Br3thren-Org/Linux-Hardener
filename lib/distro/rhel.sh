#!/usr/bin/env bash
# lib/distro/rhel.sh — RHEL/Rocky/AlmaLinux-specific hardening adapters
# Sourced by harden.sh after lib/common.sh when DISTRO_FAMILY == "rhel".
# All functions from common.sh (log_*, should_write, write_file_if_changed,
# pkg_install, etc.) are available here.

# ─── Security Updates ────────────────────────────────────────────────────────

rhel_security_update() {
    log_info "Running RHEL security update"

    if ! should_write; then
        log_info "[DRY-RUN] Would run: dnf update -y --security"
        return 0
    fi

    log_change \
        "dnf update -y --security" \
        "Apply all available security patches" \
        "medium" \
        "dnf updateinfo list security" \
        "N/A — package updates cannot be automatically reversed"

    dnf update -y --security
    log_success "RHEL security update complete"
}

# ─── Unattended Upgrades (dnf-automatic) ─────────────────────────────────────

rhel_enable_unattended_upgrades() {
    if [[ "${ENABLE_UNATTENDED_UPGRADES:-false}" != "true" ]]; then
        log_info "Skipping dnf-automatic (ENABLE_UNATTENDED_UPGRADES != true)"
        return 0
    fi

    log_info "Configuring dnf-automatic for security updates"

    if ! should_write; then
        log_info "[DRY-RUN] Would install dnf-automatic and configure /etc/dnf/automatic.conf"
        return 0
    fi

    pkg_install dnf-automatic

    local auto_conf
    auto_conf="$(cat <<'EOF'
# Managed by linux-hardener — do not edit by hand
[commands]
upgrade_type = security
random_sleep = 0
network_online_timeout = 60
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[email]
email_from = root@localhost
email_to = root
email_host = localhost

[base]
debuglevel = 1
EOF
)"

    write_file_if_changed \
        "/etc/dnf/automatic.conf" \
        "${auto_conf}" \
        "Configure dnf-automatic for security-only updates"

    log_change \
        "dnf-automatic configured and timer enabled" \
        "Automatically apply security updates without manual intervention" \
        "low" \
        "systemctl is-enabled dnf-automatic.timer" \
        "systemctl disable --now dnf-automatic.timer"

    systemctl enable --now dnf-automatic.timer
    log_success "dnf-automatic configured and timer enabled"
}

# ─── Firewall (firewalld) ─────────────────────────────────────────────────────

rhel_setup_firewall() {
    log_info "Setting up firewalld"

    if ! should_write; then
        log_info "[DRY-RUN] Would install and configure firewalld"
        return 0
    fi

    pkg_install firewalld

    systemctl enable --now firewalld

    # Set default zone to drop — deny everything not explicitly permitted
    firewall-cmd --set-default-zone=drop

    # Allow SSH — use service name for port 22, otherwise add port directly
    local ssh_port="${SSH_PORT:-22}"
    if [[ "${ssh_port}" == "22" ]]; then
        firewall-cmd --permanent --zone=drop --add-service=ssh
    else
        firewall-cmd --permanent --zone=drop --add-port="${ssh_port}/tcp"
    fi

    # Add extra allowed TCP ports
    if [[ -n "${FIREWALL_ALLOWED_TCP_IN:-}" ]]; then
        local port
        IFS=',' read -ra _ports <<< "${FIREWALL_ALLOWED_TCP_IN}"
        for port in "${_ports[@]}"; do
            port="${port// /}"
            # Skip SSH port — already handled above
            [[ -z "${port}" || "${port}" == "${ssh_port}" ]] && continue
            firewall-cmd --permanent --zone=drop --add-port="${port}/tcp"
        done
    fi

    # Add extra allowed UDP ports
    if [[ -n "${FIREWALL_ALLOWED_UDP_IN:-}" ]]; then
        local port
        IFS=',' read -ra _ports <<< "${FIREWALL_ALLOWED_UDP_IN}"
        for port in "${_ports[@]}"; do
            port="${port// /}"
            [[ -z "${port}" ]] && continue
            firewall-cmd --permanent --zone=drop --add-port="${port}/udp"
        done
    fi

    # Allow ICMP types needed for basic diagnostics
    # Use --add-icmp-block-inversion so that listed ICMP types are ALLOWED
    # (the "drop" zone blocks all ICMP by default; inversion flips the block list to an allow list)
    firewall-cmd --permanent --zone=drop --add-icmp-block-inversion
    local icmp_types=(
        echo-request
        echo-reply
        destination-unreachable
        time-exceeded
    )
    local icmp_type
    for icmp_type in "${icmp_types[@]}"; do
        firewall-cmd --permanent --zone=drop --add-icmp-block="${icmp_type}"
    done

    log_change \
        "firewalld configured with default-drop zone" \
        "Restrict inbound traffic to allowed ports; default-drop policy" \
        "high" \
        "firewall-cmd --list-all --zone=drop" \
        "systemctl stop firewalld && systemctl disable firewalld"

    firewall-cmd --reload
    log_success "firewalld configured and active"
}

# ─── /tmp noexec Toggle Hook for DNF ─────────────────────────────────────────

rhel_setup_tmp_hook() {
    if [[ "${NOEXEC_TMP:-false}" != "true" ]]; then
        log_info "Skipping /tmp noexec DNF plugin (NOEXEC_TMP != true)"
        return 0
    fi

    log_info "Configuring DNF plugin to toggle /tmp exec/noexec around package operations"

    if ! should_write; then
        log_info "[DRY-RUN] Would write hardener-tmp-toggle.sh and DNF plugin"
        return 0
    fi

    local toggle_script="/usr/local/sbin/hardener-tmp-toggle.sh"
    local plugin_conf="/etc/dnf/plugins/hardener-tmp-remount.conf"
    local plugin_py="/usr/lib/python3/dist-packages/dnf-plugins/hardener_tmp_remount.py"

    # Resolve the correct dnf plugin directory
    local dnf_plugin_dir
    dnf_plugin_dir="$(python3 -c \
        "import site; print(next(p for p in site.getsitepackages() if 'site-packages' in p))" \
        2>/dev/null)/dnf-plugins"
    if [[ -z "${dnf_plugin_dir}" || ! -d "$(dirname "${dnf_plugin_dir}")" ]]; then
        dnf_plugin_dir="/usr/lib/python3/dist-packages/dnf-plugins"
    fi
    plugin_py="${dnf_plugin_dir}/hardener_tmp_remount.py"

    mkdir -p "${dnf_plugin_dir}"

    local toggle_content
    toggle_content="$(cat <<'EOF'
#!/usr/bin/env bash
# Managed by linux-hardener
# Usage: hardener-tmp-toggle.sh exec|noexec
set -euo pipefail

mode="${1:-}"

case "${mode}" in
    exec)
        mount -o remount,exec /tmp
        ;;
    noexec)
        mount -o remount,noexec /tmp
        ;;
    *)
        printf 'Usage: %s exec|noexec\n' "$(basename "$0")" >&2
        exit 1
        ;;
esac
EOF
)"

    local plugin_conf_content
    plugin_conf_content="$(cat <<'EOF'
[main]
enabled = 1
EOF
)"

    local plugin_py_content
    plugin_py_content="$(cat <<EOF
# Managed by linux-hardener — do not edit by hand
"""
hardener_tmp_remount — DNF plugin that temporarily lifts noexec on /tmp
before package transactions and restores it afterwards.
"""

import subprocess
import dnf

TOGGLE_SCRIPT = "${toggle_script}"


class HardenerTmpRemountPlugin(dnf.Plugin):
    name = "hardener-tmp-remount"

    def pre_transaction(self):
        try:
            subprocess.run([TOGGLE_SCRIPT, "exec"], check=True)
        except Exception as exc:  # pylint: disable=broad-except
            self.base.logger.warning(
                "hardener-tmp-remount: failed to remount /tmp exec: %s", exc
            )

    def post_transaction(self):
        try:
            subprocess.run([TOGGLE_SCRIPT, "noexec"], check=True)
        except Exception as exc:  # pylint: disable=broad-except
            self.base.logger.warning(
                "hardener-tmp-remount: failed to remount /tmp noexec: %s", exc
            )
EOF
)"

    write_file_if_changed "${toggle_script}"   "${toggle_content}"       "Write /tmp exec/noexec toggle script"
    chmod 755 "${toggle_script}"

    write_file_if_changed "${plugin_conf}"     "${plugin_conf_content}"  "Write DNF plugin config"
    write_file_if_changed "${plugin_py}"       "${plugin_py_content}"    "Write DNF hardener-tmp-remount plugin"

    log_change \
        "DNF /tmp noexec plugin installed" \
        "Prevent /tmp noexec from blocking package installs" \
        "low" \
        "cat ${plugin_conf}" \
        "rm -f ${toggle_script} ${plugin_conf} ${plugin_py}"

    log_success "/tmp noexec DNF plugin configured"
}

# ─── Lynis Installation ───────────────────────────────────────────────────────

rhel_install_lynis() {
    log_info "Installing Lynis (source: ${LYNIS_SOURCE:-package})"

    case "${LYNIS_SOURCE:-package}" in
        package)
            if pkg_is_installed lynis; then
                log_info "Lynis already installed, skipping"
                return 0
            fi
            if ! should_write; then
                log_info "[DRY-RUN] Would run: dnf install -y epel-release lynis"
                return 0
            fi
            # Lynis lives in EPEL on RHEL-family systems
            dnf install -y epel-release
            pkg_install lynis
            log_success "Lynis installed via dnf (EPEL)"
            ;;

        cisofy-repo)
            if pkg_is_installed lynis; then
                log_info "Lynis already installed, skipping CISOfy repo setup"
                return 0
            fi
            if ! should_write; then
                log_info "[DRY-RUN] Would add CISOfy yum repo and install lynis"
                return 0
            fi

            local repo_content
            repo_content="$(cat <<'EOF'
[lynis]
name=CISOfy Software - Lynis package
baseurl=https://packages.cisofy.com/community/lynis/rpm/
enabled=1
gpgcheck=1
gpgkey=https://packages.cisofy.com/keys/cisofy-software-rpmsign-public.key
priority=2
EOF
)"

            write_file_if_changed \
                "/etc/yum.repos.d/cisofy-lynis.repo" \
                "${repo_content}" \
                "Add CISOfy Lynis yum repository"

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
