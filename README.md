# Linux Hardener

A modular Linux hardening framework targeting 90+ Lynis score on fresh cloud instances, with automated Hetzner Cloud test orchestration.

Production-safe, auditable, reversible, distro-aware. Every change includes a reason, risk note, validation step, and rollback path.

## Supported Platforms

- Debian 12
- Ubuntu 24.04
- Rocky Linux 9
- AlmaLinux 9

## Quick Start — Standalone Hardening

```bash
# 1. Copy and configure
cp config/hardener.conf.example config/hardener.conf
# Edit config/hardener.conf — set your preferences

# 2. Audit (read-only, shows what would change)
sudo ./harden.sh --audit --config config/hardener.conf

# 3. Dry-run (shows changes without writing)
sudo ./harden.sh --dry-run --config config/hardener.conf

# 4. Apply hardening
sudo ./harden.sh --apply --config config/hardener.conf

# 5. Rollback if needed
sudo ./harden.sh --rollback
```

### Run specific modules only

```bash
sudo ./harden.sh --apply --modules ssh,firewall,sysctl
```

## Quick Start — Hetzner Test Cycle

```bash
# 1. Configure
cp config/hardener.conf.example config/hardener.conf
# Set HETZNER_API_TOKEN and HETZNER_SSH_KEY_NAME

# 2. Run full test cycle
./orchestrate.sh

# 3. Run with options
./orchestrate.sh --keep-on-failure          # Keep servers if validation fails
./orchestrate.sh --images debian-12,rocky-9  # Test specific distros
./orchestrate.sh --no-iterate               # Skip iteration loop
./orchestrate.sh --skip-teardown            # Don't destroy servers
```

## Profiles

| Profile | Target Score | Default Modules |
|---|---|---|
| `aggressive` (default) | 90+ | All modules enabled: auditd, fail2ban, AIDE, unattended upgrades, password policy, noexec /tmp |
| `standard` | ~80 | Conservative: optional modules disabled |

Set via `HARDENING_PROFILE` in config. Individual settings always override the profile.

## Project Structure

```
Linux-Hardener/
├── harden.sh                 # Main entrypoint
├── orchestrate.sh            # Hetzner test orchestrator
├── config/
│   ├── hardener.conf.example # Config template
│   ├── auto-remediate.conf   # Lynis auto-fix whitelist
│   └── ssh-banner.txt        # Login banner
├── lib/
│   ├── common.sh             # Core: logging, detection, helpers
│   ├── packages.sh           # Package updates, cleanup
│   ├── services.sh           # Service audit/disable
│   ├── auth.sh               # Banners, cron, PAM, USB
│   ├── ssh.sh                # SSH drop-in hardening
│   ├── firewall.sh           # nftables/firewalld
│   ├── sysctl.sh             # Kernel parameter hardening
│   ├── filesystem.sh         # Mount options, permissions
│   ├── logging.sh            # Auditd, time sync, journald
│   ├── integrity.sh          # Fail2ban, AIDE
│   ├── rollback.sh           # Backup management
│   └── distro/
│       ├── debian.sh          # Debian/Ubuntu specifics
│       └── rhel.sh            # Rocky/Alma specifics
├── scripts/
│   ├── lynis_runner.sh       # Install/run Lynis audits
│   ├── lynis_parser.py       # Parse Lynis → JSON
│   ├── report_generator.py   # Final reports
│   └── validate.sh           # Post-hardening checks
├── hetzner/
│   ├── provision.sh          # Create test servers
│   ├── teardown.sh           # Destroy test servers
│   └── api.sh                # REST API helpers
└── artifacts/                # Test results (.gitignored)
```

## Modes

| Mode | Flag | Behavior |
|---|---|---|
| Audit | `--audit` | Read-only scan, reports findings |
| Dry-run | `--dry-run` | Shows what would change, no writes |
| Apply | `--apply` | Backs up files, applies hardening |
| Rollback | `--rollback` | Restores from most recent backup |

## Modules (Execution Order)

| # | Module | What It Does |
|---|---|---|
| 1 | `packages` | Security updates, remove unnecessary packages, enable auto-updates |
| 2 | `services` | Disable avahi, cups, rpcbind, ModemManager, bluetooth; protect critical services |
| 3 | `auth` | Login banners, cron/at restrictions, shell timeout, USB blacklist, password policy |
| 4 | `ssh` | Drop-in config: key-only auth, MaxAuthTries 3, disable forwarding, VERBOSE logging |
| 5 | `firewall` | nftables (Debian) / firewalld (RHEL): default-deny INPUT, allow SSH + ICMP |
| 6 | `sysctl` | 22+ kernel params: rp_filter, ASLR, ptrace scope, ICMP hardening, SYN cookies |
| 7 | `filesystem` | Mount options (noexec /tmp, /dev/shm), file permissions, core dump restriction |
| 8 | `logging` | Time sync (chrony), journald persistence, auditd with minimal/CIS-basic rules |
| 9 | `integrity` | Fail2ban SSH jail, AIDE file integrity monitoring |

## Rollback

Every `--apply` run creates a timestamped backup at `/var/lib/linux-hardener/backups/<timestamp>/`. The most recent is symlinked as `latest`.

```bash
# Rollback all changes from last apply
sudo ./harden.sh --rollback

# Manually inspect backups
ls /var/lib/linux-hardener/backups/
```

Drop-in configs are removed, original files restored, and services reloaded.

**Not auto-reversible:** removed packages, applied system updates.

## Configuration Reference

See `config/hardener.conf.example` for all options with comments. Key settings:

| Setting | Default (aggressive) | Description |
|---|---|---|
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | Key auth only for root |
| `SSH_PASSWORD_AUTH` | `no` | Disable password authentication |
| `NOEXEC_TMP` | `true` | Add noexec to /tmp (with pkg manager hooks) |
| `ENABLE_AUDITD` | `true` | Install and configure auditd |
| `ENABLE_FAIL2BAN` | `true` | SSH brute-force protection |
| `ENABLE_AIDE` | `true` | File integrity monitoring |
| `ENABLE_UNATTENDED_UPGRADES` | `true` | Auto security patches (no auto-reboot) |
| `ENABLE_PASSWORD_POLICY` | `true` | pam_pwquality (minlen=12) |

## Hetzner Test Cycle

The orchestrator provisions fresh servers, applies hardening, runs Lynis before/after, validates, and tears down:

```
Provision → Bootstrap → Pre-Lynis → Audit → Apply → Validate → Post-Lynis → Iterate → Aggregate → Teardown
```

### Iteration

With `ENABLE_ITERATION=true`, the orchestrator auto-remediates low-risk Lynis findings from `config/auto-remediate.conf` up to `MAX_ITERATIONS` times. Stops when:
- No more whitelisted items remain
- Score improvement drops below `MIN_SCORE_DELTA`
- Max iterations reached

### Artifacts

```
artifacts/<build-id>/
├── servers.json                    # Server manifest
├── aggregate-summary.json          # Cross-distro results
├── debian-12/
│   ├── pre-hardening/
│   │   ├── lynis-report.dat
│   │   └── quick-summary.txt
│   ├── post-hardening/
│   │   ├── lynis-report.dat
│   │   └── quick-summary.txt
│   ├── hardening.log
│   ├── validation.log
│   ├── summary.json
│   └── final-report.txt
└── rocky-9/
    └── ...
```

## Validation Checks

After hardening, `validate.sh` verifies:
- SSH connectivity
- Package manager works
- DNS resolution
- Outbound HTTPS
- NTP synchronized
- Firewall active with correct rules
- sysctl values applied
- Critical services running

## Operational Risks and Caveats

**SSH lockout**: The SSH module validates config with `sshd -t` before reloading. If validation fails, it reverts automatically. Use `--keep-on-failure` in the orchestrator for debugging.

**noexec /tmp**: Can break package installations. Mitigated with dpkg/dnf hooks that temporarily remount /tmp during installs.

**Auditd overhead**: Uses minimal ruleset by default. On very small instances (1 vCPU), may add noticeable overhead. Disable via `ENABLE_AUDITD=false`.

**Not remediated (by design)**:
- Separate `/var`, `/var/log`, `/home` partitions (requires re-provisioning)
- Full disk encryption (requires console access)
- AppArmor enforcing mode (requires per-service profiles)
- Bootloader password (breaks cloud console)
- Kernel module signing (requires custom kernel)

## Prerequisites

**On target servers**: None (the framework installs what it needs).

**On control machine** (for Hetzner orchestration):
- `ssh`, `scp`
- `jq`
- `python3`
- `hcloud` CLI (recommended, REST API fallback available)

## Extending

Add a new hardening module:

1. Create `lib/mymodule.sh` with `mymodule_audit()`, `mymodule_apply()`, `mymodule_rollback()`
2. Add `mymodule` to the module list in `harden.sh`
3. Add any config settings to `hardener.conf.example`

All functions from `lib/common.sh` are available: `log_info`, `write_file_if_changed`, `backup_file`, `should_write`, `pkg_install`, `svc_disable`, etc.
