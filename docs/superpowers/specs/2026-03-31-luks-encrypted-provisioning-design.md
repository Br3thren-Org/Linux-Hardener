# LUKS Encrypted Provisioning — Design Specification

**Date:** 2026-03-31
**Status:** Approved
**Scope:** Separate provisioning workflow for full-disk LUKS encryption with Dropbear SSH unlock

---

## Overview

A provider-agnostic provisioning workflow that creates cloud servers with full root LUKS encryption. Only holders of the SSH key can unlock the server after reboot via Dropbear in the initramfs. Supports single-disk and multi-disk RAID configurations across 7 cloud providers.

## Requirements

- Full root encryption (everything except `/boot` and `/boot/efi`)
- Dropbear SSH in initramfs for key-holder-only unlock
- Passphrase: auto-generate by default, `--passphrase` for manual, stored locally in artifacts
- `unlock-remote.sh` convenience script for automated unlock
- Provider-agnostic core engine with thin adapters per provider
- RAID support: raid0, raid1, raid5, raid6, raid10 via mdadm
- Providers: Hetzner (first), DigitalOcean, Vultr, AWS EC2, Linode, OVH, Ionos

---

## Architecture

### System Layers

```
┌─────────────────────────────────────────────────┐
│           provision-encrypted.sh                │
│  (CLI entrypoint — orchestrates the full flow)  │
└──────────────┬──────────────────┬───────────────┘
               │                  │
    ┌──────────▼──────────┐  ┌───▼────────────────┐
    │  Provider Adapters  │  │  LUKS Core Engine   │
    │  luks/providers/    │  │  luks/engine.sh     │
    ├─────────────────────┤  ├─────────────────────┤
    │ hetzner.sh          │  │ partition_disk()     │
    │ digitalocean.sh     │  │ assemble_raid()      │
    │ vultr.sh            │  │ create_luks()        │
    │ aws.sh              │  │ install_os()         │
    │ linode.sh           │  │ setup_dropbear()     │
    │ ovh.sh              │  │ configure_fstab()    │
    │ ionos.sh            │  │ finalize()           │
    └─────────────────────┘  └─────────────────────┘
               │
    ┌──────────▼──────────┐
    │  unlock-remote.sh   │
    │  (post-reboot tool) │
    └─────────────────────┘
```

### File Layout

```
luks/
├── provision-encrypted.sh    # Main CLI entrypoint
├── unlock-remote.sh          # Unlock helper
├── engine.sh                 # Core LUKS setup (provider-agnostic)
├── luks.conf                 # Default config
└── providers/
    ├── interface.sh          # Provider contract + dispatcher
    ├── hetzner.sh
    ├── digitalocean.sh
    ├── vultr.sh
    ├── aws.sh
    ├── linode.sh
    ├── ovh.sh
    └── ionos.sh
```

---

## Provider Adapter Interface

Each provider adapter implements 6 functions:

```bash
provider_create_server()      # Create server, return server_id|ip
provider_enter_rescue()       # Boot into rescue/recovery, return rescue SSH details
provider_exit_rescue()        # Exit rescue mode
provider_reboot()             # Normal reboot after LUKS setup
provider_delete_server()      # Teardown
provider_get_status()         # Return server state (running/rescue/stopped)
```

The dispatcher (`interface.sh`) sources the correct adapter based on `--provider` and validates all required functions exist.

### Provider Rescue Methods

| Provider | Rescue Method | Notes |
|----------|--------------|-------|
| Hetzner | API: enable rescue → reboot | Returns temp root password. Existing `api.sh` covers most of this |
| DigitalOcean | Recovery ISO via API | Boot from DO recovery kernel |
| Vultr | Custom ISO mount via API | Mount SystemRescue ISO |
| AWS EC2 | EBS detach/attach flow | Stop instance → detach EBS → attach to helper → encrypt → reattach |
| Linode | Rescue mode via API | Boots into Finnix recovery |
| OVH | Netboot rescue via API | Provides temp root password |
| Ionos | DCD rescue via API | Live CD boot option |

### AWS Exception

AWS has no rescue mode. Its adapter uses a different internal strategy:
1. `provider_enter_rescue()` → stops instance, detaches root EBS, attaches to a helper instance
2. Engine runs on the helper against the detached volume
3. `provider_exit_rescue()` → reattaches encrypted volume, starts original instance

The core engine sees the same interface regardless.

### Provider Credentials

| Provider | Required Env Vars |
|----------|------------------|
| Hetzner | `HETZNER_API_TOKEN` |
| DigitalOcean | `DO_API_TOKEN` |
| Vultr | `VULTR_API_KEY` |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` |
| Linode | `LINODE_API_TOKEN` |
| OVH | `OVH_APP_KEY`, `OVH_APP_SECRET`, `OVH_CONSUMER_KEY`, `OVH_ENDPOINT` |
| Ionos | `IONOS_USERNAME`, `IONOS_PASSWORD` |

---

## Core LUKS Engine

### Disk Layout — Single Disk

```
/dev/sda
├── sda1  →  /boot      (512MB, ext4, unencrypted)
├── sda2  →  /boot/efi  (256MB, FAT32, EFI only)
└── sda3  →  LUKS container
    └── /dev/mapper/crypt-root  →  / (ext4)
```

### Disk Layout — Multi-Disk RAID

```
/dev/sda                        /dev/sdb
├── sda1  ──┐                   ├── sdb1  ──┐
│           ├→ md0 → /boot      │           ┘
├── sda2  ──┐                   ├── sdb2  ──┐
│           ├→ md1 → /boot/efi  │           ┘
└── sda3  ──┐                   └── sdb3  ──┐
            ├→ md2 (RAID array)             ┘
            └→ LUKS container
               └→ /dev/mapper/crypt-root → / (ext4)
```

### Engine Steps

1. **Detect disks** — probe `lsblk` for non-removable block devices. Validate against RAID level minimum disk count. If `LUKS_DISKS="auto"` and multiple disks are found, default to `raid1` unless `LUKS_RAID_LEVEL` is explicitly set. If only one disk is found, use single-disk mode regardless of RAID setting.
2. **Partition all disks** — identical GPT layout on each disk via `sgdisk`.
3. **Assemble RAID** (if multi-disk) — `mdadm --create` with configured level and chunk size. Creates md0 (boot), md1 (efi if applicable), md2 (data). Writes `mdadm.conf` into chroot.
4. **Create LUKS volume** — `cryptsetup luksFormat` on md2 (RAID) or sda3 (single). LUKS2, aes-xts-plain64, 512-bit key. Passphrase piped via stdin.
5. **Open and format** — `cryptsetup luksOpen`, then `mkfs.ext4` (or xfs) on mapped device.
6. **Install base OS** — Debian/Ubuntu: `debootstrap`. RHEL/Rocky/Alma: `dnf --installroot`.
7. **Configure chroot** — fstab, crypttab, Dropbear/dracut-crypt-ssh, SSH public key in initramfs, kernel + GRUB with LUKS support, initramfs networking, user account.
8. **Finalize** — unmount, close LUKS, signal ready for reboot.

### RAID Configuration

```bash
LUKS_DISKS="auto"           # "auto" or comma-separated: "/dev/sda,/dev/sdb"
LUKS_RAID_LEVEL="raid1"     # raid0, raid1, raid5, raid6, raid10, none
LUKS_RAID_CHUNK="512"       # Chunk size in KB
LUKS_FILESYSTEM="ext4"      # ext4 or xfs
LUKS_BOOT_SIZE="512"        # /boot size in MB
LUKS_EFI_SIZE="256"         # EFI partition size in MB (0 for BIOS)
```

### RAID Validation Rules

| RAID Level | Min Disks | Notes |
|-----------|-----------|-------|
| none | 1 | Single disk mode |
| raid0 | 2 | Warns: no redundancy |
| raid1 | 2 | Default for 2 disks |
| raid5 | 3 | Parity |
| raid6 | 4 | Double parity |
| raid10 | 4 | Even disk count required |

### Distro Support Matrix

| Distro | Install Method | Dropbear Package | initramfs Tool |
|--------|---------------|-----------------|----------------|
| Debian 12 | debootstrap | `dropbear-initramfs` | `update-initramfs` |
| Ubuntu 24.04 | debootstrap | `dropbear-initramfs` | `update-initramfs` |
| Rocky 9 | dnf --installroot | `dracut-crypt-ssh` | `dracut` |
| Alma 9 | dnf --installroot | `dracut-crypt-ssh` | `dracut` |

---

## Passphrase Management

### Lifecycle

- **Provisioning:** auto-generated (32-char alphanumeric) or user-provided via `--passphrase`
- **Storage:** saved to `artifacts/luks/<provider>-<host>-<timestamp>/luks-passphrase` with chmod 600
- **Unlock:** `unlock-remote.sh` reads saved file, falls back to interactive prompt
- **Security:** never appears in process arguments, always piped via stdin

### Artifacts Layout

```
artifacts/luks/<provider>-<host>-<timestamp>/
├── luks-passphrase       # 600 perms, deletable after memorizing
├── ssh-key               # Dropbear SSH private key
├── ssh-key.pub           # Injected into initramfs
├── provision.log         # Full provisioning log
└── server-info.json      # Provider, IP, server ID, disk layout, RAID config
```

### unlock-remote.sh Interface

```bash
# Auto — reads saved passphrase
./luks/unlock-remote.sh --host 65.108.x.x --key artifacts/luks/.../ssh-key

# Manual prompt
./luks/unlock-remote.sh --host 65.108.x.x --key artifacts/luks/.../ssh-key --prompt

# Custom port and passphrase file
./luks/unlock-remote.sh --host 65.108.x.x --key artifacts/luks/.../ssh-key \
    --port 2222 --passphrase-file /path/to/passphrase
```

### Unlock Flow

1. Resolve passphrase: `--passphrase-file` → saved artifact file → interactive prompt
2. SSH to Dropbear on port 2222 with initramfs SSH key
3. Send passphrase via `cryptroot-unlock` (Debian) or `systemd-tty-ask-password-agent` (RHEL)
4. Dropbear drops connection as initramfs hands off to real OS
5. Poll SSH on port 22 until full OS reachable (120s timeout)
6. Print success and connection command

### Security

- Passphrase piped via stdin, never in `ps` output
- Dropbear uses a separate SSH key from the main server key
- `server-info.json` never contains the passphrase
- `--prompt` flag for users who don't want passphrase saved to disk

---

## CLI Interface

### provision-encrypted.sh

```bash
./luks/provision-encrypted.sh \
    --provider <provider>       # Required: hetzner|digitalocean|vultr|aws|linode|ovh|ionos
    --image <distro>            # Required: debian-12, ubuntu-24.04, rocky-9, alma-9
    --ssh-key <path>            # Required: SSH key for Dropbear + server access
    [--passphrase <phrase>]     # Manual passphrase (default: auto-generate)
    [--server-type <type>]      # Provider-specific instance type
    [--location <region>]       # Provider-specific region
    [--disks <list>]            # Comma-separated devices (default: auto)
    [--raid <level>]            # raid0|raid1|raid5|raid6|raid10|none (default: raid1 if multi-disk)
    [--raid-chunk <KB>]         # Stripe chunk size (default: 512)
    [--filesystem <fs>]         # ext4|xfs (default: ext4)
    [--config <path>]           # Config file (default: luks/luks.conf)
    [--dropbear-port <port>]    # Dropbear SSH port (default: 2222)
    [--provision-user <name>]   # Create user with SSH key + sudo
    [--no-harden]               # Skip auto-hardening after provisioning
    [--dry-run]                 # Validate everything without destructive actions
```

### Orchestration Flow

```
provision-encrypted.sh
├─ 1. Parse args + load luks.conf
├─ 2. Validate provider credentials
├─ 3. provider_create_server()
├─ 4. provider_enter_rescue()
├─ 5. Wait for rescue SSH readiness
├─ 6. Copy engine.sh to rescue environment
├─ 7. Run engine over SSH:
│     ├─ detect/validate disks
│     ├─ partition all disks
│     ├─ assemble RAID (if multi-disk)
│     ├─ create LUKS volume
│     ├─ install base OS
│     ├─ configure chroot
│     └─ finalize
├─ 8. provider_exit_rescue()
├─ 9. provider_reboot()
├─ 10. unlock-remote.sh (automatic first unlock)
├─ 11. Wait for full OS SSH
├─ 12. (Optional) run harden.sh --apply
└─ 13. Save artifacts + print summary
```

### Integration with Existing Tools

The encrypted provisioning is a separate path from the existing `orchestrate.sh`. After provisioning + unlock, the server is a normal SSH-accessible machine — `run-remote.sh` and `harden.sh` work unchanged.

---

## Error Handling

### Three Failure Zones

**Zone 1 — Provider API failures (before rescue mode):**
- Server creation fails → clean error, no cleanup needed
- Rescue mode entry fails → delete server, exit
- Credentials validated upfront before any API calls

**Zone 2 — Engine failures (inside rescue mode):**
- Every engine step is checkpointed to a status file
- On failure: stop immediately, print failed step and error, leave server in rescue mode
- Server is never rebooted on failure (half-configured LUKS is unbootable)
- Message: "Server left in rescue mode at step X. SSH in to debug or delete the server."

**Zone 3 — Post-encryption failures (reboot/unlock):**
- Dropbear doesn't come up → print troubleshooting guidance
- Full OS doesn't boot → re-enter rescue via provider adapter
- `unlock-remote.sh` has `--timeout` flag (default 120s)

### Pre-Flight Validation

Before touching any disk:
- All required tools available in rescue (`cryptsetup`, `sgdisk`, `debootstrap`/`dnf`, `mdadm` if RAID)
- Disk count matches RAID level requirements
- Disks are not mounted / in use
- Network connectivity for package downloads
- Sufficient disk space (minimum 8GB per disk)
- SSH public key is valid and readable

---

## Testing

| Layer | Method |
|-------|--------|
| Provider adapters | Integration tests with `--dry-run`: create → rescue → teardown |
| Engine (single disk) | Full run on cheapest Hetzner instance (cx22, Debian 12) |
| Engine (RAID) | Hetzner dedicated or Vultr bare metal (multi-disk) |
| unlock-remote.sh | Validated as part of every provisioning (step 10) |
| Passphrase management | Verify file permissions, prompt fallback, stdin piping |
| Cross-provider | One full run per provider, cheapest server type |

### --dry-run Flag

Runs the full flow without destructive commands:
1. Validates credentials and config
2. Creates server, enters rescue
3. SSHs into rescue, runs pre-flight checks
4. Prints exact commands that would execute
5. Tears down server
