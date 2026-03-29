# Linux Hardener — Design Specification

**Date:** 2026-03-29
**Status:** Approved
**Author:** Design collaboration

---

## Overview

A modular Linux hardening framework in Bash with Python reporting, paired with a Hetzner Cloud test harness that provisions fresh servers, applies hardening, runs Lynis audits, and iterates safely. Target: 90+ Lynis hardening index on fresh cloud instances while staying production-safe, auditable, and distro-aware.

## Target Platforms

- Debian 12
- Ubuntu 24.04
- Rocky Linux 9
- AlmaLinux 9

All selectable via config. The hardening framework works standalone on any target; the Hetzner harness is for automated testing.

---

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Bash (hardening) + Python (reporting) | Bash is native to targets; Python handles structured data |
| SSH model | Key pre-provisioned via hcloud, password auth disabled by default | Hetzner-native, config toggle for other environments |
| Hetzner API | Hybrid — hcloud CLI primary, REST API fallback | Readable scripts, complete coverage |
| RHEL images | Rocky + Alma selectable | Both RHEL-compatible, available on Hetzner |
| Iteration | Auto-iterate with whitelist, max 3 passes, stop on plateau | Conservative automation, human gate for risky items |
| Artifacts | Text + JSON | Human-readable logs, machine-parseable summaries |
| Default profile | Aggressive (90+ target) | Standard profile available for conservative use |

---

## Project Structure

```
Linux-Hardener/
├── harden.sh                    # Main entrypoint — sources lib/, dispatches modes
├── orchestrate.sh               # Hetzner test cycle orchestrator
├── config/
│   ├── hardener.conf.example    # Template config (tokens, images, SSH key, thresholds)
│   ├── auto-remediate.conf      # Whitelist of safe-to-auto-remediate Lynis findings
│   └── ssh-banner.txt           # Login banner text
├── lib/
│   ├── common.sh                # Logging, backup, distro detection, dry-run helpers
│   ├── packages.sh              # Package updates, unnecessary package removal
│   ├── ssh.sh                   # SSH hardening (drop-in config approach)
│   ├── firewall.sh              # nftables/firewalld setup, preserve SSH
│   ├── sysctl.sh                # Kernel network hardening, ASLR, ptrace
│   ├── filesystem.sh            # Mount options, permissions, core dumps
│   ├── services.sh              # Service audit — enable/disable with rationale
│   ├── auth.sh                  # Login banners, cron permissions, PAM tweaks
│   ├── logging.sh               # Auditd, time sync, rsyslog validation
│   ├── integrity.sh             # AIDE setup, fail2ban
│   └── rollback.sh              # Restore from backups, undo sysctl, remove drop-ins
├── lib/distro/
│   ├── debian.sh                # Debian/Ubuntu-specific logic (apt, ufw fallback, etc.)
│   └── rhel.sh                  # Rocky/Alma-specific logic (dnf, firewalld, SELinux)
├── scripts/
│   ├── lynis_runner.sh          # Install Lynis, run before/after audits, collect artifacts
│   ├── lynis_parser.py          # Parse Lynis output -> JSON summaries
│   ├── report_generator.py      # Final report: score delta, findings, recommendations
│   └── validate.sh              # Post-hardening validation checks
├── hetzner/
│   ├── provision.sh             # Create server via hcloud CLI + API fallback
│   ├── teardown.sh              # Destroy servers, cleanup
│   └── api.sh                   # REST API helper functions (polling, metadata)
├── artifacts/                   # .gitignored — timestamped results stored here
├── docs/
│   └── superpowers/specs/
├── .gitignore
└── README.md
```

### Key structural decisions

- `lib/` modules are sourced, not executed — `harden.sh` is the single entrypoint
- `lib/distro/` isolates distro-specific logic; common modules call helper functions that resolve at runtime
- `hetzner/` is fully separate from hardening logic
- Drop-in configs instead of editing vendor files (e.g., `/etc/ssh/sshd_config.d/99-hardening.conf`)
- Every `lib/` module exposes: `<module>_audit()`, `<module>_apply()`, `<module>_rollback()` functions

---

## Hardening Script Architecture

### Modes

| Mode | Flag | Behavior |
|---|---|---|
| Audit | `--audit` | Read-only scan, reports what would change, exits with finding count |
| Dry-run | `--dry-run` | Like apply, but skips all write operations, logs what it would do |
| Apply | `--apply` | Backs up files, applies hardening, logs every change |
| Rollback | `--rollback` | Restores backups created by the most recent apply run |

### Execution flow

1. Parse args (mode, config path, verbosity, optional module filter)
2. Source `lib/common.sh` — detect distro, set up logging, load config
3. Source `lib/distro/{debian,rhel}.sh` based on detection
4. Source all `lib/*.sh` modules
5. Create timestamped backup directory: `/var/lib/linux-hardener/backups/<timestamp>/`
6. For each module in defined order:
   - Log module start
   - Call `<module>_audit()` — always runs, reports current state
   - If mode is apply: call `<module>_apply()`
   - Each apply function: backs up target, writes drop-in/sets value, logs WHAT/WHY/RISK/VALIDATION/ROLLBACK, returns 0 (success), 1 (failed), 2 (skipped/already compliant)
7. Write machine-readable results to `/var/lib/linux-hardener/last-run.json`
8. Exit with summary

### Module execution order (dependency-aware)

1. `packages` — update first, some modules need installed packages
2. `services` — disable unnecessary services before configuring remaining ones
3. `auth` — PAM, banners, cron permissions
4. `ssh` — depends on auth decisions
5. `firewall` — after SSH is configured so we know what port to preserve
6. `sysctl` — kernel tuning
7. `filesystem` — mount options, permissions
8. `logging` — auditd, time sync
9. `integrity` — AIDE/fail2ban last

### Idempotency

- Every `_apply()` checks current state first
- If already compliant: logs "SKIP: already configured", returns 2
- Drop-in files written atomically (write to temp, then mv)
- sysctl values checked before writing

### Config-driven behavior

- Each module reads settings from `hardener.conf`
- Module filter flag (`--modules ssh,sysctl,firewall`) to run a subset
- Aggressive settings on by default in aggressive profile, documented with risk notes

---

## Hardening Modules — Scope

### packages.sh
- Run security updates (`apt upgrade` / `dnf update --security`)
- Remove known-unnecessary packages: `telnet`, `rsh`, `talk`, `xinetd` (only if present)
- Enable unattended security upgrades (aggressive profile, auto-reboot disabled)
- Will NOT auto-remove packages with dependents

### services.sh
- Disable with rationale: `avahi-daemon`, `cups`, `rpcbind`, `ModemManager`, `bluetooth`, `postfix` (if no local mail)
- Will NOT touch: `systemd-resolved`, `cloud-init`, `qemu-guest-agent`, `cron`, `rsyslog/journald`, `chrony/systemd-timesyncd`
- Each service gets a logged reason

### ssh.sh
- Writes `/etc/ssh/sshd_config.d/99-hardening.conf` (drop-in)
- `PermitRootLogin`: `prohibit-password`
- `PasswordAuthentication`: `no` (configurable)
- `MaxAuthTries`: `3`
- `LoginGraceTime`: `30`
- `X11Forwarding`: `no`
- `AllowTcpForwarding`: `no` (configurable)
- `ClientAliveInterval`: `300`, `ClientAliveCountMax`: `2`
- `AllowAgentForwarding`: `no`
- Will NOT change SSH port by default

### firewall.sh
- Debian: `nftables` with default-deny INPUT, allow established/related, allow SSH, allow ICMP, allow loopback, permit all OUTPUT
- RHEL: `firewalld` with drop zone, SSH service, ICMP
- Will NOT restrict OUTPUT by default
- Will NOT block ICMP entirely

### sysctl.sh
- Writes `/etc/sysctl.d/99-hardening.conf` (drop-in)
- Reverse path filtering: `rp_filter=1`
- Disable ICMP redirects (accept and send)
- Disable source routing (IPv4 and IPv6)
- Log martians
- SYN cookies
- Ignore broadcast pings and bogus ICMP errors
- Full ASLR: `randomize_va_space=2`
- Restrict ptrace: `yama.ptrace_scope=1`
- No core dumps from SUID: `suid_dumpable=0`
- Restrict dmesg: `dmesg_restrict=1`
- Restrict kernel pointers: `kptr_restrict=2`
- Disable secure redirects
- Will NOT set `ip_forward=0` without checking first
- Will NOT disable IPv6

### filesystem.sh
- `nodev,nosuid,noexec` on `/tmp` (aggressive profile combines all three; standard profile uses `nodev,nosuid` only; dpkg/rpm hooks remount exec during package installs)
- `nodev,nosuid,noexec` on `/dev/shm`
- Permissions: `/etc/shadow` 0640, `/etc/gshadow` 0640, `/etc/crontab` 0600, `/etc/ssh/sshd_config` 0600
- Core dump restriction via `/etc/security/limits.d/99-hardening.conf`

### auth.sh
- Login banner to `/etc/issue` and `/etc/issue.net`
- Restrict cron to root via `/etc/cron.allow`
- Shell timeout `TMOUT=900` via `/etc/profile.d/99-hardening.sh`
- Password policy via pam_pwquality: `minlen=12`, `retry=3` (aggressive profile)
- USB storage blacklist via modprobe
- Will NOT set account lockout policies

### logging.sh
- Validate time sync: chrony or systemd-timesyncd running and synchronized
- Validate syslog: rsyslog or journald active
- Install and enable auditd (aggressive profile)
- Minimal audit rules: file access to `/etc/shadow`, `/etc/passwd`, login events
- Capped log size

### integrity.sh
- Install and configure fail2ban (aggressive profile): SSH jail, 5 retries, 10min ban
- Install and initialize AIDE (aggressive profile): database init, daily cron check
- Will NOT install rkhunter/chkrootkit (recommendation in final report only)

---

## Lynis Integration

### Installation
- Debian: `apt install lynis` (distro repos, or CISOfy repo if configured)
- RHEL: `dnf install lynis` from EPEL
- Fallback: clone from GitHub to `/opt/lynis`

### Audit workflow
1. Pre-hardening audit: `lynis audit system --no-colors --quick`
2. Capture stdout, `/var/log/lynis.log`, `/var/log/lynis-report.dat`
3. Apply hardening
4. Post-hardening audit (same capture)
5. Diff: resolved, new, unchanged findings
6. Calculate score delta

### Parser output (`summary.json`)

```json
{
  "timestamp": "2026-03-29T14:30:22Z",
  "distro": "debian-12",
  "lynis_version": "3.1.1",
  "pre": {
    "hardening_index": 62,
    "warnings": 4,
    "suggestions": 38,
    "tests_performed": 256
  },
  "post": {
    "hardening_index": 91,
    "warnings": 1,
    "suggestions": 12,
    "tests_performed": 256
  },
  "delta": {
    "hardening_index": "+29",
    "warnings_resolved": 3,
    "suggestions_resolved": 26,
    "new_warnings": 0,
    "new_suggestions": 0
  },
  "remaining": {
    "warnings": [],
    "suggestions": []
  },
  "classification": {
    "safe_to_remediate": [],
    "needs_human_review": [],
    "not_applicable": []
  }
}
```

### Score integrity
- Never suppress findings via custom profiles to inflate scores
- Skipped findings documented in `classification.not_applicable` with reasons
- Final report separates cosmetic score gains from substantive security improvements

---

## Hetzner Orchestration

### Provisioning (`hetzner/provision.sh`)
1. Validate: hcloud CLI, API token, SSH key registered
2. Generate build ID: `<timestamp>_<random-4-chars>`
3. For each configured image:
   - Create server: `hardener-test-<distro>-<build-id>`
   - Type from config (default: cx22)
   - Location from config (default: fsn1)
   - hcloud CLI primary, REST API fallback
   - Wait for running state
   - Poll SSH readiness (120s timeout, 5s intervals)
4. Write `servers.json` manifest

### Test runner (`orchestrate.sh`)
1. Provision servers
2. For each server (parallel via background jobs):
   - Create local artifacts dir
   - SCP framework to server
   - Bootstrap: install Python3, Lynis
   - Pre-hardening Lynis audit
   - `harden.sh --audit`
   - `harden.sh --apply`
   - `validate.sh`
   - Post-hardening Lynis audit
   - Collect all artifacts
   - Run parser and report generator locally
   - If iteration enabled: auto-remediate whitelisted items, re-run Lynis, repeat up to MAX_ITERATIONS
3. Aggregate cross-distro summary
4. Teardown (unless `--keep-on-failure` and validation failed)

### Teardown (`hetzner/teardown.sh`)
- Read `servers.json`, delete each server
- Verify deletion
- Log cost estimate

### Validation checks

| Check | Method | Pass criteria |
|---|---|---|
| SSH | `ssh echo ok` | Returns "ok" |
| Package manager | `apt update` / `dnf check-update` | No error |
| DNS | `dig +short example.com` | Returns IP |
| Outbound | `curl -sf https://example.com` | Exit 0 |
| Time sync | `timedatectl NTPSynchronized` | "yes" |
| Firewall | `nft list` / `firewall-cmd --state` | Active |
| sysctl | Read `/proc/sys/...` | Matches config |
| Services | `systemctl is-active sshd cron rsyslog` | All active |
| Reboot | Optional: reboot, re-validate | All pass |

---

## Safe Iteration Logic

### Auto-remediate whitelist (`config/auto-remediate.conf`)
Format: `LYNIS_TEST_ID | risk_level | remediation_type | description`

Only low-risk items with known safe remediation. Everything else classified as `needs_human_review` or `not_applicable`.

### Stop conditions (first match stops iteration)
1. `iteration_count >= MAX_ITERATIONS` (default: 3)
2. Score delta from last iteration is 0
3. No remaining items match whitelist
4. A remediation attempt fails

### Final report
- Score before/after/delta
- All changes applied with rationale
- Validation results
- Remaining warnings and suggestions with classification
- Trade-offs and caveats
- Manual follow-up recommendations
- Cross-distro aggregate when multiple images tested

---

## Configuration

### Profiles
- `aggressive` (default for test harness): all modules enabled, targets 90+
- `standard`: conservative defaults, targets ~80

Individual settings override profile. Profile sets defaults, not locks.

### Placeholder handling
Scripts check for `__PLACEHOLDER__` values and exit with clear error listing which values need to be set.

### Key settings
- SSH: port, root login, password auth, forwarding
- Firewall: output restriction, allowed ports
- Filesystem: noexec on /tmp
- Auth: shell timeout, password policy, banner
- Services: fail2ban, auditd, AIDE, unattended upgrades
- Sysctl: IPv6, dmesg restrict, kptr restrict
- Hetzner: token, SSH key, server type, location, images
- Orchestration: keep-on-failure, iteration, parallelism, reboot test

---

## Assumptions

1. Target servers are fresh cloud instances with no existing applications
2. Root access via SSH key available at provision time
3. Control machine has `hcloud`, `ssh`, `scp`, `python3`, `jq` installed
4. Hetzner API token has read/write server permissions
5. Dual-stack networking (Hetzner default)
6. Servers have internet access
7. No existing firewall rules to preserve
8. SELinux left in distro default (enforcing on Rocky/Alma, absent on Debian/Ubuntu)

---

## Operational Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SSH lockout from misconfigured drop-in | Low | Critical | Validation checks SSH before teardown; --keep-on-failure; Hetzner console |
| noexec /tmp breaks package installs | Medium | Medium | dpkg/rpm hooks remount during installs |
| Auditd performance degradation | Low | Low | Minimal ruleset, capped log size |
| Hetzner rate limiting | Medium | Low | Sequential provisioning, retry with backoff |
| Lynis version differences | Medium | Low | Version logged, parser handles variations |
| Unattended upgrades unexpected reboot | Low | Medium | Auto-reboot disabled |
| Cost runaway from forgotten servers | Low | Medium | Default teardown, naming convention |
| AIDE init timeout | Low | Low | Timeout on init, skip non-critical paths |

---

## Intentionally Not Remediated

| Lynis Finding | Reason |
|---|---|
| Separate /var, /var/log, /home partitions | Requires re-provisioning; Hetzner single partition images |
| Full disk encryption (LUKS) | Requires console access for unlock on boot |
| AppArmor enforcing (Debian/Ubuntu) | Requires per-service profiles |
| Kernel module signing | Requires custom kernel build |
| Bootloader password | Breaks cloud console and automated reboots |

---

## What This Framework Does NOT Do

- Harden application stacks (nginx, postgres, etc.)
- Manage users beyond root
- Configure TLS certificates
- Set up VPN/WireGuard
- Multi-server orchestration
- Replace CIS benchmark tools
- Work on non-systemd distributions
