# Linux Hardener

A modular Linux hardening framework that achieves **85 Lynis hardening index** on fresh cloud instances, with automated Hetzner Cloud test orchestration and remote deployment to any SSH-accessible machine.

Production-safe, auditable, reversible, distro-aware. Every change includes a reason, risk note, validation step, and rollback path.

## Tested Results

| Distro | Before | After | Delta | Validation |
|---|---|---|---|---|
| Debian 12 | 61 | **83** | +22 | 19/19 PASS |
| Debian 13 (Trixie) | ~58 | **85** | +27 | 19/19 PASS |
| Ubuntu 24.04 | 58 | **78** | +20 | 19/19 PASS |
| Rocky Linux 9 | 66 | **83** | +17 | 19/19 PASS |
| AlmaLinux 9 | 66 | **83** | +17 | 19/19 PASS |

## Supported Platforms

- Debian 12 / 13
- Ubuntu 24.04
- Rocky Linux 9
- AlmaLinux 9

## Quick Start — Harden Any Remote Machine

```bash
# 1. Copy and configure
cp config/hardener.conf.example config/hardener.conf
# Edit config/hardener.conf — set your preferences

# 2. Harden a remote machine (as root)
./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey

# 3. Harden with a non-root user (uses sudo)
./run-remote.sh --host 10.0.0.5 --user admin --key ~/.ssh/mykey

# 4. Create a dedicated user, then harden as that user
./run-remote.sh --host 10.0.0.5 --user root --key ~/.ssh/mykey --provision-user hardener

# 5. Audit only (no changes)
./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey --mode audit

# 6. Harden specific modules only
./run-remote.sh --host 10.0.0.5 --key ~/.ssh/mykey --modules ssh,firewall,sysctl
```

### Remote Runner Options

```
REQUIRED:
  --host <ip|hostname>     Target machine
  --key <path>             SSH private key path

OPTIONS:
  --user <user>            SSH user (default: root)
  --port <port>            SSH port (default: 22)
  --mode <mode>            apply | audit | dry-run (default: apply)
  --config <path>          Config file (default: config/hardener.conf)
  --modules <list>         Comma-separated module filter
  --provision-user <name>  Create user with SSH key and sudo, then harden as that user
  --no-lynis               Skip Lynis audits
  --no-validate            Skip post-hardening validation
  --no-artifacts           Don't collect artifacts back
```

### User Provisioning

`--provision-user` creates a dedicated user on the target:
- Generates an RSA 4096 keypair locally (saved in artifacts)
- Creates the user with home directory and bash shell
- Installs the public key in `~/.ssh/authorized_keys`
- Grants passwordless sudo via `/etc/sudoers.d/`
- Switches all subsequent operations to run as that user
- Prints the SSH connection command at the end

## LUKS Encrypted Provisioning

Provision cloud servers with full-disk LUKS encryption. Only SSH key holders
can unlock the server after reboot via Dropbear in the initramfs.

### Quick Start

```bash
# Provision an encrypted Debian 12 server on Hetzner
export HETZNER_API_TOKEN="your-token"
./luks/provision-encrypted.sh \
    --provider hetzner \
    --image debian-12 \
    --ssh-key ~/.ssh/id_ed25519

# After reboot, unlock with:
./luks/unlock-remote.sh --host <ip> --key artifacts/luks/.../ssh-key
```

### Supported Providers

| Provider | Status |
|----------|--------|
| Hetzner | Supported |
| DigitalOcean | Supported |
| Vultr | Supported |
| AWS EC2 | Supported (EBS-based) |
| Linode | Supported |
| OVH | Supported |
| Ionos | Supported |

### RAID Support

Multi-disk servers support RAID via mdadm:

```bash
./luks/provision-encrypted.sh \
    --provider hetzner \
    --image debian-12 \
    --ssh-key ~/.ssh/id_ed25519 \
    --disks "/dev/sda,/dev/sdb" \
    --raid raid1
```

Supported levels: `raid0`, `raid1`, `raid5`, `raid6`, `raid10`.

See `docs/superpowers/specs/2026-03-31-luks-encrypted-provisioning-design.md` for full documentation.

## Quick Start — Standalone (On Target)

```bash
# Copy the framework to the server, then:
sudo ./harden.sh --apply --config config/hardener.conf

# Audit only (read-only, shows what would change)
sudo ./harden.sh --audit --config config/hardener.conf

# Dry-run (shows changes without writing)
sudo ./harden.sh --dry-run --config config/hardener.conf

# Run specific modules only
sudo ./harden.sh --apply --modules ssh,firewall,sysctl

# Rollback
sudo ./harden.sh --rollback
```

## Quick Start — Hetzner Test Cycle

Automated testing against fresh cloud instances:

```bash
# 1. Configure (set HETZNER_API_TOKEN and HETZNER_SSH_KEY_NAME)
cp config/hardener.conf.example config/hardener.conf

# 2. Run full test cycle across all distros
./orchestrate.sh

# 3. Test specific distros
./orchestrate.sh --images debian-12,rocky-9

# 4. Keep servers alive on failure for debugging
./orchestrate.sh --keep-on-failure

# 5. Skip auto-teardown
./orchestrate.sh --skip-teardown
```

The orchestrator provisions fresh servers, applies hardening, runs Lynis before/after, validates, iterates, and tears down automatically.

## Profiles

| Profile | Target Score | Modules Enabled |
|---|---|---|
| `aggressive` (default) | 83-85 | All: auditd, fail2ban, AIDE, rkhunter, unattended upgrades, password policy, noexec /tmp |
| `standard` | ~70 | Conservative: optional modules disabled |

Set via `HARDENING_PROFILE` in config. Individual settings always override the profile.

## What Gets Hardened

### 37+ changes applied across 9 modules:

**Packages** — Security updates, remove unnecessary packages (telnet, rsh, xinetd, etc.), install security tools (libpam-tmpdir, needrestart, debsums, rkhunter, acct, sysstat), enable unattended security upgrades, restrict compiler access.

**Services** — Disable avahi-daemon, cups, rpcbind, ModemManager, bluetooth. Conditionally disable postfix. Protect critical services (sshd, cloud-init, cron, chrony, journald).

**Authentication** — Login banners on /etc/issue and /etc/issue.net, restrict cron/at to root only, shell idle timeout (TMOUT=900), password policy via pam_pwquality (minlen=12), login.defs hardening (SHA_CRYPT_MIN/MAX_ROUNDS, password aging, UMASK 027).

**Kernel Modules** — Blacklist USB storage, firewire, unused protocols (dccp, sctp, rds, tipc), iptables modules (when using nftables).

**SSH** — Drop-in config at `/etc/ssh/sshd_config.d/99-hardening.conf`: key-only auth, PermitRootLogin prohibit-password, MaxAuthTries 3, disable X11/TCP/agent forwarding, Compression off, TCPKeepAlive off, VERBOSE logging, banner. Validates with `sshd -t` before reload, reverts on failure.

**Firewall** — nftables (Debian/Ubuntu) with default-deny INPUT, allow SSH + ICMP + established. firewalld (Rocky/Alma) with drop zone. Configurable extra ports.

**Kernel Parameters** — 28 sysctl settings via drop-in: rp_filter, ASLR, ptrace scope, SYN cookies, ICMP hardening, dmesg/kptr restriction, BPF hardening, IPv6 RA disable, core dump prevention.

**Logging** — Time sync validation (chrony/timesyncd), journald persistence, auditd with minimal or CIS-basic rules monitoring shadow/passwd/sudoers/sshd/cron/kernel modules/time changes.

**Integrity** — Fail2ban SSH jail (5 retries, 10min ban), AIDE file integrity with daily cron check and SHA512 checksums, rkhunter rootkit scanner, debsums weekly package verification.

## Project Structure

```
Linux-Hardener/
├── harden.sh                 # Main entrypoint (run on target)
├── run-remote.sh             # Remote runner (run from control machine)
├── orchestrate.sh            # Hetzner test orchestrator
├── config/
│   ├── hardener.conf.example # Config template
│   ├── auto-remediate.conf   # Lynis auto-fix whitelist
│   └── ssh-banner.txt        # Login banner
├── lib/
│   ├── common.sh             # Core: logging, detection, helpers
│   ├── packages.sh           # Package updates, security tools
│   ├── services.sh           # Service audit/disable
│   ├── auth.sh               # Banners, cron, PAM, kernel modules, login.defs
│   ├── ssh.sh                # SSH drop-in hardening
│   ├── firewall.sh           # nftables/firewalld
│   ├── sysctl.sh             # Kernel parameter hardening (28 params)
│   ��── filesystem.sh         # Mount options, permissions, core dumps
│   ├── logging.sh            # Auditd, time sync, journald
│   ├── integrity.sh          # Fail2ban, AIDE, rkhunter
│   ├── rollback.sh           # Backup management
│   └── distro/
│       ├── debian.sh          # Debian/Ubuntu specifics
│       └── rhel.sh            # Rocky/Alma specifics
├── scripts/
│   ├── lynis_runner.sh       # Install/run Lynis audits
│   ├── lynis_parser.py       # Parse Lynis → JSON
│   ├── report_generator.py   # Final reports + cross-distro aggregation
│   └── validate.sh           # Post-hardening checks (19 checks)
├── hetzner/
│   ├── provision.sh          # Create test servers (hcloud + API fallback)
│   ├── teardown.sh           # Destroy test servers
│   └── api.sh                # Hetzner REST API helpers
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
| 1 | `packages` | Security updates, remove unnecessary packages, install security tools, enable auto-updates |
| 2 | `services` | Disable avahi, cups, rpcbind, ModemManager, bluetooth; protect critical services |
| 3 | `auth` | Banners, cron/at restrictions, shell timeout, kernel module blacklists, password policy, login.defs |
| 4 | `ssh` | Drop-in config: key-only auth, MaxAuthTries 3, disable forwarding, Compression off, VERBOSE logging |
| 5 | `firewall` | nftables (Debian) / firewalld (RHEL): default-deny INPUT, allow SSH + ICMP |
| 6 | `sysctl` | 28 kernel params: rp_filter, ASLR, ptrace, BPF hardening, ICMP, SYN cookies, IPv6 RA |
| 7 | `filesystem` | Mount options (noexec /tmp, /dev/shm), file permissions, core dump restriction |
| 8 | `logging` | Time sync (chrony), journald persistence, auditd with minimal/CIS-basic rules |
| 9 | `integrity` | Fail2ban SSH jail, AIDE with SHA512, rkhunter, debsums weekly verification |

## Rollback

Every `--apply` run creates a timestamped backup at `/var/lib/linux-hardener/backups/<timestamp>/`. The most recent is symlinked as `latest`.

```bash
# Rollback all changes from last apply
sudo ./harden.sh --rollback

# Manually inspect backups
ls /var/lib/linux-hardener/backups/
```

Drop-in configs are removed, original files restored, services reloaded, kernel modules unmasked.

**Not auto-reversible:** removed packages, applied system updates.

## Configuration Reference

See `config/hardener.conf.example` for all options. Key settings:

| Setting | Default (aggressive) | Description |
|---|---|---|
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | Key auth only for root |
| `SSH_PASSWORD_AUTH` | `no` | Disable password authentication |
| `NOEXEC_TMP` | `true` | Add noexec to /tmp (with pkg manager hooks) |
| `ENABLE_AUDITD` | `true` | Install and configure auditd |
| `ENABLE_FAIL2BAN` | `true` | SSH brute-force protection |
| `ENABLE_AIDE` | `true` | File integrity monitoring (SHA512) |
| `ENABLE_UNATTENDED_UPGRADES` | `true` | Auto security patches (no auto-reboot) |
| `ENABLE_PASSWORD_POLICY` | `true` | pam_pwquality (minlen=12, 3 char classes) |
| `SHELL_TIMEOUT` | `900` | Idle shell logout in seconds |
| `AUDITD_RULES` | `minimal` | Audit rule set: `minimal` or `cis-basic` |

## Validation Checks (19)

After hardening, `validate.sh` verifies:

| Category | Checks |
|---|---|
| Connectivity | DNS resolution, outbound HTTPS |
| Package Manager | apt-get update / dnf check-update |
| Time Sync | NTP synchronized, chrony/timesyncd active |
| Firewall | nftables/firewalld active, policy drop confirmed |
| SSH | sshd active, config valid, PermitRootLogin, PasswordAuthentication |
| Kernel | rp_filter, accept_redirects, syncookies, ASLR, ptrace_scope, suid_dumpable |
| Services | cron active, syslog (rsyslog or journald) active |

## Hetzner Test Cycle

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
│   │   └── ...
│   ├── hardening.log
│   ├── validation.log
│   ├── summary.json
│   └── final-report.txt
└─��� rocky-9/
    └── ...

artifacts/remote-<host>-<timestamp>/
├── provisioned-keys/               # Generated SSH keys (if --provision-user)
│   ├── <username>                   # Private key (600)
│   ├── <username>.pub               # Public key (644)
│   └── README.txt                   # Connection details
├── harden.log
├── validate.log
├── lynis-pre.log
├── lynis-post.log
├── summary.json
└── last-run.json
```

## Operational Risks and Caveats

**SSH lockout**: The SSH module validates config with `sshd -t` (3 retries) before reloading. Creates `/run/sshd` if missing (Ubuntu upgrade issue). If validation fails, it reverts automatically.

**noexec /tmp**: Can break package installations. Mitigated with dpkg/dnf hooks that temporarily remount /tmp during installs.

**Auditd**: Uses minimal ruleset by default. Immutable flag (`-e 2`) removed for compatibility with auditd 4.0+. On very small instances, disable via `ENABLE_AUDITD=false`.

**iptables blacklist**: On Debian, iptables kernel modules are blacklisted since nftables is used. Not applied on RHEL (firewalld needs iptables modules).

**Not remediated (by design)**:
- Separate `/var`, `/home` partitions (requires re-provisioning)
- Full disk encryption (requires console access)
- AppArmor enforcing mode (requires per-service profiles)
- GRUB bootloader password (breaks cloud console and remote reboot)
- Kernel module signing (requires custom kernel build)
- External syslog server (requires separate infrastructure)
- SSH port change (kept at 22 by design, configurable)

## Prerequisites

**On target servers**: None (the framework installs what it needs).

**On control machine** (for remote runner / Hetzner orchestration):
- `ssh`, `scp`
- `jq`
- `python3`
- `hcloud` CLI (optional, REST API fallback available)

## Extending

Add a new hardening module:

1. Create `lib/mymodule.sh` with `mymodule_audit()`, `mymodule_apply()`, `mymodule_rollback()`
2. Add `mymodule` to the module list in `harden.sh`
3. Add any config settings to `hardener.conf.example`

All functions from `lib/common.sh` are available: `log_info`, `write_file_if_changed`, `backup_file`, `should_write`, `pkg_install`, `svc_disable`, etc.
