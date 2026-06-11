# LUKS At-Rest Encryption — Runtime Module

The runtime LUKS module (`modules/20_luks.sh`) adds at-rest encryption to an
**already-installed** host. It detects whether it is running on bare metal or
under a hypervisor and applies the strategy that is safe for that environment.

It is **optional and disabled by default** — nothing happens until you set
`LUKS_ENABLED=yes` in `config/luks.conf`.

> **Runtime module vs. provisioning system.** This repository contains two
> LUKS systems. The `luks/` directory (`provision-encrypted.sh`) **wipes a
> server from rescue mode** and installs a fresh OS with full root encryption —
> use it for new machines. The runtime module documented here hardens an
> existing machine **without reinstalling** and never destroys data.

---

## Decision Matrix: Bare-Metal vs. VPS

| Capability                          | Bare-Metal              | VPS / Cloud Instance |
|-------------------------------------|-------------------------|----------------------|
| Root full-disk encryption (FDE)     | Hardened if present¹    | **Never attempted**  |
| Encrypted secondary data volumes    | Yes                     | Yes                  |
| Encrypted loopback data container   | Yes (fallback)          | Yes (default)        |
| Encrypted swap (random key per boot)| Yes                     | Yes                  |
| TPM2 auto-unlock (systemd-cryptenroll) | Yes, with PCR policy | No (TPM2 rarely exposed²) |
| Secure Boot PCR sealing (0,1,2,3,7) | Yes, when SB enabled    | n/a                  |
| Dropbear SSH unlock in initramfs    | Yes (opt-in, Debian family) | No (initramfs untouched) |
| Cloud KMS key escrow (AWS/GCP/Vault)| Possible                | Yes (primary option) |
| NBDE (clevis + tang)                | Yes (opt-in)            | Yes (opt-in)         |
| Bootloader / initramfs modification | Only with `LUKS_DROPBEAR=yes` or TPM2 crypttab updates | **Never** |
| Header backup (GPG + SHA-512)       | Yes                     | Yes                  |
| Sensitive-dir bind mounts (/etc/ssh)| Opt-in                  | Opt-in               |

¹ A mounted root filesystem cannot be encrypted in place. If the root is
already LUKS the module hardens it; if not, `luks_preflight` returns 1 and
points you at the offline procedure below or `luks/provision-encrypted.sh`.

² If your cloud offers vTPM (e.g. AWS NitroTPM, GCP Shielded VM), force the
bare-metal path with `--luks-mode bare-metal` after verifying `/dev/tpmrm0`
exists — but only if you also control boot (see warnings).

---

## Threat Model

**What at-rest encryption protects against**

| Threat                                    | Bare-Metal | VPS |
|-------------------------------------------|------------|-----|
| Stolen / resold / RMA'd disks              | ✅          | ✅ (provider disk handling) |
| Datacenter physical theft                  | ✅          | ✅ (same) |
| Provider snapshot/backup of detached volumes | n/a      | ✅ (data volumes only) |
| Cold-boot attack on powered-off machine    | ✅          | partially |
| Malicious hypervisor / host operator       | ❌          | ❌ **— understand this** |
| Live memory scraping                       | ❌          | ❌  |
| Compromised running OS                     | ❌          | ❌  |

**The hypervisor trust boundary (VPS).** On any VPS the provider's hypervisor
can read your RAM, and therefore your mounted LUKS master keys, at any time.
VPS encryption protects data at rest — detached volumes, deleted-instance
disk remnants, provider media disposal — not data in use. If a malicious
provider is in your threat model, no software configuration on their
hypervisor saves you; you need bare metal or confidential-computing VMs.

**Physical tampering (bare-metal).** TPM2 sealing against PCRs 0–3 and 7
detects firmware/bootloader tampering: a modified boot chain changes the PCR
values and the TPM refuses to release the key, falling back to the
passphrase prompt. This defeats opportunistic evil-maid attacks but not a
patient attacker with hardware implants. Keep Secure Boot enabled; without
it the module seals against PCR 7 only, a much weaker policy.

---

## Configuration

All settings live in `config/luks.conf` (every key is documented inline).
The essentials:

```bash
LUKS_ENABLED=yes              # master switch (default: no)
LUKS_MODE=auto                # auto | bare-metal | virtual
LUKS_DATA_DEVICES=""          # e.g. "/dev/sdb" — empty = loopback container
LUKS_DATA_PATH=/var/lib/encrypted-data
LUKS_SWAP_ENCRYPT=yes
LUKS_CLOUD_KMS_PROVIDER=none  # aws | gcp | vault | none
LUKS_NBDE=no                  # clevis+tang, explicit opt-in
LUKS_TPM2=auto                # bare-metal TPM2 enrollment
LUKS_DROPBEAR=no              # remote unlock, explicit opt-in
```

Cryptography defaults (overridable): LUKS2, `aes-xts-plain64`, 512-bit key,
argon2id with memory=1048576 KiB, iterations=4, parallel=4. With
`LUKS_CIPHER=auto` the module runs `cryptsetup benchmark` at apply time and
picks the fastest of aes-xts / serpent-xts / xchacha20-adiantum — Adiantum
typically wins on CPUs without AES-NI.

### Running

```bash
# See what would happen (recommended first step)
sudo ./harden.sh --dry-run --luks-only

# Audit current encryption posture (also runs with the full module set)
sudo ./harden.sh --audit

# Apply only the LUKS module
sudo ./harden.sh --apply --luks-only

# Force a path instead of auto-detection
sudo ./harden.sh --apply --luks-only --luks-mode virtual
```

`luks_preflight` return codes: `0` ready, `1` needs user intervention (the
log says exactly what), `2` unsupported environment (containers) or module
disabled.

---

## Deployment Guide — VPS / Cloud Instance

> ⚠️ **Do not attempt root FDE on VPSs without provider support.** Encrypting
> the root disk or modifying the bootloader/initramfs on a VPS routinely
> breaks boot, provider console access, rescue mode, and snapshot restore.
> The module enforces this: on the virtual path the root disk, bootloader,
> and initramfs are never touched, and every device passes a safety gate
> that refuses anything mounted, swapped, fstab-referenced, or signatured.

1. **(Optional) attach a secondary volume** in the provider panel
   (DigitalOcean Volume, Hetzner Volume, EBS, etc.). Without one, the module
   creates a `LUKS_CONTAINER_SIZE_MB` loopback container instead.
2. **Configure** `config/luks.conf`:
   ```bash
   LUKS_ENABLED=yes
   LUKS_DATA_DEVICES="/dev/sdb"        # or "" for the loopback container
   LUKS_SWAP_ENCRYPT=yes
   ```
3. **Dry-run, then apply:**
   ```bash
   sudo ./harden.sh --dry-run --luks-only
   sudo ./harden.sh --apply  --luks-only
   ```
4. **What you get:**
   - LUKS2 volume(s) mounted at `/var/lib/encrypted-data` (keyfiles in
     `/etc/luks/`, mode 0400; crypttab/fstab entries carry `nofail` so a
     failed unlock can never hang boot)
   - plaintext swap replaced by `/dev/mapper/cryptswap`, keyed from
     `/dev/urandom` on every boot — swap contents die with the power
   - GPG-encrypted header backups in `/var/backups/luks-headers/`
5. **Verify:** `sudo ./scripts/validate.sh` (Encryption section) and
   `lsblk` / `swapon --show`.
6. **Reboot test** while you still have console access.

**Key management options (VPS has no TPM2):**

- *Default:* keyfile in `/etc/luks/` on the (unencrypted) root disk. This
  protects detached/recycled **data volumes**, not a snapshot of the root
  disk itself — pair it with KMS escrow if that matters to you.
- *Cloud KMS escrow* (`LUKS_CLOUD_KMS_PROVIDER=aws|gcp|vault`): the keyfile
  is encrypted with KMS using the instance's IAM role / service account and
  stored remotely (S3/SSM/GCS/Vault KV). `luks-cloud-recovery.sh remount`
  retrieves it when the local keyfile is gone.
- *NBDE* (`LUKS_NBDE=yes` + `LUKS_TANG_URL`): clevis binds the volume to a
  Tang server inside your VPC. Binding only happens if Tang answers a probe,
  and the passphrase slot is always kept as fallback.

**Sensitive bind mounts** (`LUKS_BIND_SENSITIVE=yes`, default off): relocates
`/etc/ssh` (+ `LUKS_BIND_EXTRA_DIRS`) into the encrypted filesystem and
bind-mounts it back. `/etc/shadow`, `/etc/passwd`, and `/etc/pam.d` are
deliberately refused — they must be readable before any unlock can happen at
boot. Understand the trade-off: if the volume fails to unlock, sshd will not
start until you recover via the provider console.

---

## Deployment Guide — Bare-Metal Server

> ⚠️ **Always test initramfs changes on bare-metal with a live ISO ready.**
> Dropbear installation, TPM2 crypttab updates, and `regen-boot` all rebuild
> the initramfs. The module validates `/etc/crypttab` before every rebuild,
> but firmware quirks are real. Have out-of-band console (IPMI/iKVM) or a
> live USB within reach for the first reboot.

**Case A — root is already LUKS** (installer-time encryption or
`luks/provision-encrypted.sh`):

1. Set `LUKS_ENABLED=yes` (and optionally `LUKS_TPM2=yes`,
   `LUKS_DROPBEAR=yes`, `LUKS_DATA_DEVICES=...`).
2. `sudo ./harden.sh --apply --luks-only`. The module:
   - backs up the root LUKS header (GPG-encrypted; the one-time backup
     passphrase is printed once — **store it offline immediately**)
   - audits key slots (policy: max 2 — primary + recovery)
   - persists `no-read-workqueue`/`no-write-workqueue` on SSD/NVMe mappings
   - enrolls TPM2 auto-unlock: PCRs `0+1+2+3+7` with Secure Boot, PCR `7`
     only without (PCRs 0–3 churn on firmware updates without SB and would
     strand you at the passphrase prompt) — the passphrase slot is always
     retained
   - without TPM2: enrolls a recovery keyfile in `/etc/luks/` alongside your
     passphrase
   - encrypts additional `LUKS_DATA_DEVICES` and swap exactly like the VPS
     path
   - opt-in: installs `dropbear-initramfs` (port `LUKS_DROPBEAR_PORT`,
     password logins and port forwarding disabled, sessions forced to
     `cryptroot-unlock`) and prints the initramfs host-key fingerprint —
     verify it out-of-band on first connect.
3. Reboot once with console access available; confirm TPM2 unlock works,
   then test that the passphrase still works too
   (`sudo systemd-cryptenroll <dev>` lists the enrolled slots).

**Case B — root is NOT encrypted:** the module will not (cannot) convert it
live. Options:

1. *Re-provision* with `luks/provision-encrypted.sh` (destroys the host —
   for cloud/colo machines with a rescue mode).
2. *Offline re-encryption* from a live ISO (advanced, take a full backup
   first):
   ```bash
   # from the live environment, root fs unmounted:
   e2fsck -f /dev/sdX2
   resize2fs /dev/sdX2 <size-minus-32M>          # make room for the header
   cryptsetup reencrypt --encrypt --reduce-device-size 32M /dev/sdX2
   # then: open, mount, chroot, add crypttab + GRUB_ENABLE_CRYPTODISK,
   # rebuild initramfs and grub config — see your distro's documentation.
   ```
   Afterwards re-run the module to get TPM2/dropbear/header backups.

**Encrypted /boot:** GRUB2 can open LUKS1 (and, since GRUB 2.12, some LUKS2)
`/boot` volumes with `GRUB_ENABLE_CRYPTODISK=y`. The module *audits* and
reports unencrypted `/boot` but does not convert it — combine TPM2-sealed
root with an unencrypted-but-measured `/boot`/ESP instead, which Secure Boot
+ PCR policy already protects against tampering.

---

## Performance Expectations

Run `cryptsetup benchmark` yourself; rough expectations:

| Backend                         | Overhead with aes-xts (AES-NI) |
|---------------------------------|--------------------------------|
| NVMe SSD, queue bypass flags on | 5–15 % throughput, near-zero latency cost |
| NVMe SSD, default workqueues    | up to 30–50 % on high-IOPS small reads |
| SATA SSD                        | 5–10 % |
| Rotational disk                 | negligible (disk is the bottleneck; workqueues left on) |
| Cloud block storage (EBS/DO/Hetzner volumes) | usually negligible — provider IOPS caps dominate long before AES does |
| Loopback container              | extra file-layer indirection; fine for secrets/configs, wrong for databases — use a real volume |
| CPU without AES-NI              | use Adiantum (`LUKS_CIPHER=auto` picks it): 2–4× faster than aes-xts in software |

The module auto-applies `no-read-workqueue`/`no-write-workqueue`
(persistent LUKS2 flags) on non-rotational backends and leaves rotational
disks alone.

argon2id at memory=1 GiB makes each unlock attempt cost ~1 GiB RAM and a few
seconds of CPU — that is the point (brute-force resistance). On hosts with
< 2 GiB RAM lower `LUKS_PBKDF_MEMORY` to 524288.

---

## Recovery

| Scenario | Tool |
|----------|------|
| Corrupted LUKS header (bare-metal or VPS) | `scripts/luks-recovery.sh restore-header <dev> <backup.gpg>` |
| Forgotten passphrase, keyfile intact | `scripts/luks-recovery.sh add-temp-key <dev>` then set a new one |
| Broken initramfs/GRUB after changes | boot live ISO → chroot → `scripts/luks-recovery.sh regen-boot` |
| VPS data volumes won't mount | `scripts/luks-cloud-recovery.sh remount` (keyfile → KMS → passphrase) |
| Locked out of VPS entirely | `scripts/luks-cloud-recovery.sh instructions` (provider console walkthrough) |
| What did the hardener create? | `scripts/luks-cloud-recovery.sh status`, state in `/var/lib/linux-hardener/luks-state` |

Header backups live in `/var/backups/luks-headers/` as
`<name>-<timestamp>.header.img.gpg` with `.sha512` sidecars, optionally
replicated to `LUKS_HEADER_BACKUP_SECONDARY` (an `s3://` URI on VPSs, a
mounted USB path on bare-metal).

`harden.sh --rollback` reverts the module's *configuration* (crypttab,
fstab, units, mappings closed) but deliberately preserves all encrypted data
and keyfiles — volumes become inert, not destroyed.

---

## Validation

`scripts/validate.sh` gains an **Encryption (LUKS)** section when
`LUKS_ENABLED=yes`:

- `/etc/crypttab` exists and passes structural validation
- all active swap is dm-crypt (or zram) backed
- bare-metal: the root device chain contains a `crypt` layer
- VPS: at least one non-root LUKS volume is active

These checks complement the Lynis run (`CRYP-7902` and friends); enabling
the module does not regress any existing Lynis score or sysctl parameter —
it only ever *adds* encrypted storage.
