# Linux Hardener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a modular Linux hardening framework targeting 90+ Lynis score on fresh Hetzner cloud instances, with automated test orchestration and safe iteration.

**Architecture:** Bash modules (sourced by a single entrypoint) handle all hardening logic with distro-specific adapters. Python scripts handle Lynis parsing and JSON report generation. A separate Hetzner orchestration layer provisions/tears down test servers and drives the full test cycle.

**Tech Stack:** Bash (set -euo pipefail), Python 3 (stdlib only), hcloud CLI, Hetzner REST API (curl), nftables/firewalld, Lynis, jq.

---

## Phase 1: Foundation (Tasks 1-4)

### Task 1: Project scaffolding and config

**Files:**
- Create: `.gitignore`
- Create: `config/hardener.conf.example`
- Create: `config/auto-remediate.conf`
- Create: `config/ssh-banner.txt`

- [ ] **Step 1: Create .gitignore**

- [ ] **Step 2: Create config/hardener.conf.example** with all settings documented, aggressive profile default, __PLACEHOLDER__ for secrets

- [ ] **Step 3: Create config/auto-remediate.conf** with whitelist of safe Lynis test IDs

- [ ] **Step 4: Create config/ssh-banner.txt** with authorized access warning

- [ ] **Step 5: Commit**

---

### Task 2: Core library — common.sh

**Files:**
- Create: `lib/common.sh`

Contains: logging (log_init, log_info/warn/error/debug/success, log_change), distro detection (detect_distro via /etc/os-release), config loading (load_config, apply_profile_defaults, placeholder check), backup helpers (init_backup_dir, backup_file, restore_file), mode guards (is_audit_mode, is_dry_run, is_apply_mode, should_write, guarded_write), atomic file writing (write_file_atomic, write_file_if_changed), module filter (should_run_module), package manager abstraction (pkg_install, pkg_remove, pkg_is_installed, pkg_update), service helpers (svc_is_active, svc_is_enabled, svc_exists, svc_disable), sysctl helpers (sysctl_get, sysctl_check), summary output (print_summary), JSON results (write_results_json).

Global counters: CHANGES_APPLIED, CHANGES_SKIPPED, CHANGES_FAILED, AUDIT_FINDINGS.

State dir: /var/lib/linux-hardener. Log dir: /var/log/linux-hardener.

- [ ] **Step 1: Create lib/common.sh** with all functions above
- [ ] **Step 2: Commit**

---

### Task 3: Distro-specific adapters

**Files:**
- Create: `lib/distro/debian.sh`
- Create: `lib/distro/rhel.sh`

**debian.sh** contains: debian_security_update (apt upgrade), debian_enable_unattended_upgrades (unattended-upgrades package, security-only, no auto-reboot), debian_setup_firewall (nftables default-deny INPUT, allow SSH/ICMP/established/loopback, configurable extra ports), debian_setup_tmp_hook (dpkg pre/post hooks to remount /tmp exec during installs), debian_install_lynis (apt/cisofy-repo/github).

**rhel.sh** contains: rhel_security_update (dnf update --security), rhel_enable_unattended_upgrades (dnf-automatic, security-only), rhel_setup_firewall (firewalld drop zone, SSH service, ICMP types), rhel_setup_tmp_hook (DNF plugin for /tmp remount), rhel_install_lynis (EPEL/cisofy-repo/github).

- [ ] **Step 1: Create lib/distro/debian.sh**
- [ ] **Step 2: Create lib/distro/rhel.sh**
- [ ] **Step 3: Commit**

---

### Task 4: Main entrypoint — harden.sh

**Files:**
- Create: `harden.sh`

Handles: argument parsing (--apply/--audit/--dry-run/--rollback, --config, --modules, --verbose, --help), root check, sourcing lib/common.sh, distro detection, sourcing distro adapter, sourcing all module files in order (packages, services, auth, ssh, firewall, sysctl, filesystem, logging, integrity), backup dir init for apply mode, module runner loop (audit always, apply/rollback conditionally), results JSON output, summary printing.

Module execution order: packages -> services -> auth -> ssh -> firewall -> sysctl -> filesystem -> logging -> integrity.

- [ ] **Step 1: Create harden.sh**
- [ ] **Step 2: chmod +x harden.sh**
- [ ] **Step 3: Commit**

---

## Phase 2: Hardening Modules (Tasks 5-13)

### Task 5: packages.sh module

**Files:**
- Create: `lib/packages.sh`

UNNECESSARY_PACKAGES list: telnet, rsh-client, rsh-server, talk, talkd, xinetd, ypbind, ypserv, tftp, tftp-server.

packages_audit(): check for unnecessary packages, available updates, unattended upgrades status.
packages_apply(): run security updates via distro adapter, remove unnecessary packages (only if installed, skip on dependency errors), enable unattended upgrades via distro adapter.
packages_rollback(): restore unattended upgrade configs from backup, note that removed packages and updates cannot be auto-rolled back.

- [ ] **Step 1: Create lib/packages.sh**
- [ ] **Step 2: Commit**

---

### Task 6: services.sh module

**Files:**
- Create: `lib/services.sh`

DISABLE_SERVICES: avahi-daemon, cups, cups-browsed, rpcbind, ModemManager, bluetooth (each with rationale string).
CONDITIONAL_SERVICES: postfix (only disable if no queued mail).
PROTECTED_SERVICES: sshd, ssh, systemd-resolved, cloud-init, cloud-config, cloud-final, qemu-guest-agent, cron, crond, rsyslog, systemd-journald, chrony, chronyd, systemd-timesyncd, NetworkManager, systemd-networkd, dbus.

services_audit(): check disabled services still active, verify protected services running.
services_apply(): disable each in DISABLE_SERVICES via svc_disable, conditionally handle postfix (check mail queue first).
services_rollback(): unmask all disabled services (don't auto-enable, just unmask).

- [ ] **Step 1: Create lib/services.sh**
- [ ] **Step 2: Commit**

---

### Task 7: auth.sh module

**Files:**
- Create: `lib/auth.sh`

auth_audit(): check banner exists, cron.allow present, TMOUT set, USB storage blacklisted, pam_pwquality installed.
auth_apply(): write login banners to /etc/issue and /etc/issue.net (from config/ssh-banner.txt), create /etc/cron.allow with root only (chmod 600, remove cron.deny), create /etc/at.allow similarly, write TMOUT to /etc/profile.d/99-hardener-timeout.sh (readonly), blacklist usb-storage via /etc/modprobe.d/99-hardener-usb.conf, install and configure pam_pwquality (minlen=12, retry=3, minclass=3) via /etc/security/pwquality.conf.
auth_rollback(): restore all files from backup, remove drop-ins.

- [ ] **Step 1: Create lib/auth.sh**
- [ ] **Step 2: Commit**

---

### Task 8: ssh.sh module

**Files:**
- Create: `lib/ssh.sh`

SSH_DROPIN_PATH: /etc/ssh/sshd_config.d/99-hardening.conf

ssh_audit(): check sshd_config.d support, test current settings via sshd -T against expected values, check drop-in exists.
ssh_apply(): ensure sshd_config.d dir exists, add Include directive if missing, write drop-in with all settings (PermitRootLogin prohibit-password, PasswordAuthentication no, MaxAuthTries 3, LoginGraceTime 30, X11Forwarding no, AllowTcpForwarding configurable, AllowAgentForwarding no, ClientAliveInterval 300, ClientAliveCountMax 2, MaxSessions 3, PermitEmptyPasswords no, HostbasedAuthentication no, LogLevel VERBOSE, Banner /etc/issue.net), validate with sshd -t before reload, revert on validation failure.
ssh_rollback(): remove drop-in, restore sshd_config, reload.

- [ ] **Step 1: Create lib/ssh.sh**
- [ ] **Step 2: Commit**

---

### Task 9: firewall.sh module

**Files:**
- Create: `lib/firewall.sh`

firewall_audit(): check nftables/firewalld installed and active, verify rules/zone.
firewall_apply(): delegate to debian_setup_firewall or rhel_setup_firewall.
firewall_rollback(): restore nftables.conf/flush rules (Debian), reset firewalld to public zone (RHEL).

- [ ] **Step 1: Create lib/firewall.sh**
- [ ] **Step 2: Commit**

---

### Task 10: sysctl.sh module

**Files:**
- Create: `lib/sysctl.sh`

SYSCTL_DROPIN: /etc/sysctl.d/99-hardening.conf

SYSCTL_SETTINGS array: rp_filter=1 (all/default), accept_redirects=0 (all/default, ipv4/ipv6), secure_redirects=0, send_redirects=0 (all/default), accept_source_route=0 (all/default, ipv4/ipv6), log_martians=1 (all/default), tcp_syncookies=1, icmp_echo_ignore_broadcasts=1, icmp_ignore_bogus_error_responses=1, randomize_va_space=2, yama.ptrace_scope=1, suid_dumpable=0. Conditional: dmesg_restrict=1, kptr_restrict=2.

sysctl_audit(): check each value, warn about ip_forward if enabled.
sysctl_apply(): build drop-in content (skip unavailable keys), write atomically, apply with sysctl --system, verify each value.
sysctl_rollback(): remove drop-in, reload.

- [ ] **Step 1: Create lib/sysctl.sh**
- [ ] **Step 2: Commit**

---

### Task 11: filesystem.sh module

**Files:**
- Create: `lib/filesystem.sh`

SENSITIVE_FILES array with path/mode/owner/group tuples.

filesystem_audit(): check /tmp and /dev/shm mount options, check file permissions, check core dump limits.
filesystem_apply(): set /tmp mount options in fstab (nodev,nosuid,noexec for aggressive, nodev,nosuid for standard), remount, set up distro-specific package hooks; set /dev/shm options; chmod sensitive files; write core dump limits to /etc/security/limits.d/99-hardening.conf and /etc/systemd/coredump.conf.d/99-hardening.conf.
filesystem_rollback(): restore fstab, remove limits drop-ins, remount defaults.

- [ ] **Step 1: Create lib/filesystem.sh**
- [ ] **Step 2: Commit**

---

### Task 12: logging.sh module

**Files:**
- Create: `lib/logging.sh`

logging_audit(): check NTP sync (timedatectl), check time sync service running, check syslog running, check auditd if enabled, check journald persistence.
logging_apply(): ensure time sync (install chrony if needed), enable journald persistent storage (/var/log/journal), install and configure auditd if enabled (minimal or cis-basic rule sets, capped log size 50MB x 5 rotations).
logging_rollback(): remove audit rules, restore auditd.conf.

- [ ] **Step 1: Create lib/logging.sh**
- [ ] **Step 2: Commit**

---

### Task 13: integrity.sh and rollback.sh modules

**Files:**
- Create: `lib/integrity.sh`
- Create: `lib/rollback.sh`

**integrity.sh:**
integrity_audit(): check fail2ban and AIDE installation/running status.
integrity_apply(): install/configure fail2ban (SSH jail, configurable retries/bantime) via /etc/fail2ban/jail.d/99-hardening.conf; install/initialize AIDE (timeout 300s on init, daily cron check).
integrity_rollback(): remove fail2ban jail, remove AIDE cron.

**rollback.sh:**
rollback_list_backups(): list available backups with file counts.
rollback_cleanup_old(): keep max 5 backups, remove oldest.

- [ ] **Step 1: Create lib/integrity.sh**
- [ ] **Step 2: Create lib/rollback.sh**
- [ ] **Step 3: Commit**

---

## Phase 3: Lynis Integration (Tasks 14-16)

### Task 14: Lynis runner script

**Files:**
- Create: `scripts/lynis_runner.sh`

Subcommands: install (via distro adapter), run <label> (audit system, capture stdout/log/dat, extract metrics, write quick-summary.txt), collect <output_dir> (copy all artifacts).

- [ ] **Step 1: Create scripts/lynis_runner.sh**
- [ ] **Step 2: chmod +x, commit**

---

### Task 15: Lynis parser (Python)

**Files:**
- Create: `scripts/lynis_parser.py`

Functions: parse_dat_file (parse lynis-report.dat into dict), parse_finding (split pipe-delimited finding), compute_diff (set operations on warning/suggestion IDs), classify_findings (whitelist-based classification: safe_to_remediate, needs_human_review, not_applicable), build_summary (full JSON structure with pre/post/delta/remaining/classification).

CLI: lynis_parser.py <pre_dat> <post_dat> <output_json> [distro] [auto_remediate_conf], or --single <dat> <output>.

- [ ] **Step 1: Create scripts/lynis_parser.py**
- [ ] **Step 2: chmod +x, commit**

---

### Task 16: Report generator (Python)

**Files:**
- Create: `scripts/report_generator.py`

Functions: generate_text_report (human-readable text with score, warnings, suggestions, classification, trade-offs, recommendations), generate_aggregate (cross-distro table from summary.json files).

CLI: report_generator.py <summary_json> <output_dir>, or --aggregate <artifacts_dir> <output_dir>.

- [ ] **Step 1: Create scripts/report_generator.py**
- [ ] **Step 2: chmod +x, commit**

---

## Phase 4: Validation and Hetzner Orchestration (Tasks 17-21)

### Task 17: Validation script

**Files:**
- Create: `scripts/validate.sh`

Checks: DNS resolution (dig), outbound HTTPS (curl), package manager (apt/dnf), NTP sync (timedatectl), time sync service running, firewall active (nftables/firewalld), SSH active and config valid, sysctl values (rp_filter, accept_redirects, syncookies, ASLR, ptrace, suid_dumpable), critical services (cron, rsyslog, journald). Outputs pass/fail/warn counts and JSON to /var/lib/linux-hardener/validation.json.

- [ ] **Step 1: Create scripts/validate.sh**
- [ ] **Step 2: chmod +x, commit**

---

### Task 18: Hetzner API helpers

**Files:**
- Create: `hetzner/api.sh`

Functions: hetzner_api (authenticated curl wrapper), hetzner_api_create_server, hetzner_api_delete_server, hetzner_api_get_server, hetzner_api_wait_running (poll with timeout), hetzner_api_get_ip, hetzner_api_list_servers (by name pattern).

- [ ] **Step 1: Create hetzner/api.sh**
- [ ] **Step 2: Commit**

---

### Task 19: Hetzner provisioning

**Files:**
- Create: `hetzner/provision.sh`

Flow: check prerequisites (API token, SSH key, jq), generate build ID, for each image: create server (hcloud CLI primary, API fallback), wait for running, wait for SSH (120s timeout, 5s poll), write manifest entry. Output: artifacts/<build_id>/servers.json with id/name/ip/image/build_id per server.

- [ ] **Step 1: Create hetzner/provision.sh**
- [ ] **Step 2: chmod +x, commit**

---

### Task 20: Hetzner teardown

**Files:**
- Create: `hetzner/teardown.sh`

Subcommands: <manifest_file> (delete servers from manifest), --build-id <id> (find manifest by build ID), --all-test-servers (delete all servers matching hardener-test-* pattern). Uses hcloud CLI primary, API fallback.

- [ ] **Step 1: Create hetzner/teardown.sh**
- [ ] **Step 2: chmod +x, commit**

---

### Task 21: Test orchestrator

**Files:**
- Create: `orchestrate.sh`

Flags: --config, --keep-on-failure, --no-iterate, --skip-teardown, --images.

Flow: check local prerequisites (ssh, scp, jq, python3, SSH key, API token), provision servers, for each server (parallel or sequential based on config): bootstrap (SCP framework, install python3/lynis), pre-hardening Lynis, audit mode, apply mode, validation, post-hardening Lynis, collect artifacts, parse and generate reports, iterate if enabled (check safe-to-remediate count, re-run hardening, re-run Lynis, check score delta, stop conditions), optional reboot test. Then: aggregate cross-distro results, teardown (unless skip/keep flags).

Iteration loop: max MAX_ITERATIONS passes, stop if no safe items remain, stop if score delta below MIN_SCORE_DELTA, stop if remediation fails.

- [ ] **Step 1: Create orchestrate.sh**
- [ ] **Step 2: chmod +x, commit**

---

## Phase 5: Documentation (Task 22)

### Task 22: README

**Files:**
- Modify: `README.md`

Sections: Overview, Quick Start (standalone), Quick Start (Hetzner test cycle), Configuration Reference, Module Descriptions, Project Structure, Rollback Guide, Artifacts Structure, Operational Risks and Caveats, Extending.

- [ ] **Step 1: Write README.md**
- [ ] **Step 2: Commit**

---

## Verification Checklist

- [ ] shellcheck passes on all .sh files
- [ ] python3 -m py_compile passes on all .py files
- [ ] All scripts have set -euo pipefail
- [ ] All scripts are executable
- [ ] No hardcoded secrets
- [ ] .gitignore covers artifacts/ and config/hardener.conf
- [ ] Config example has __PLACEHOLDER__ for all secrets
