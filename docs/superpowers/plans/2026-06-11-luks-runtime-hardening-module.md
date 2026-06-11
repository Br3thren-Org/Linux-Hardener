# LUKS Runtime Hardening Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, disabled-by-default LUKS encryption module to the runtime hardener that detects bare-metal vs. virtual environments and applies the appropriate at-rest encryption strategy without ever breaking boot.

**Architecture:** A new `modules/20_luks.sh` entry module (audit/apply/rollback contract, same as `lib/*.sh` modules) sources helper libraries from `modules/luks.d/`: environment detection, shared LUKS helpers, a bare-metal path, a VPS path, and a KMS/NBDE key-management layer. `harden.sh` gains `--luks-mode` and `--luks-only` flags and sources the module after the existing ten. Recovery tooling lives in `scripts/`, validation checks extend `scripts/validate.sh`, and `docs/LUKS.md` documents the decision matrix and threat model.

**Tech Stack:** bash 4+, cryptsetup/LUKS2, systemd-cryptenroll, dropbear-initramfs, clevis+tang, aws/gcloud/vault CLIs (optional), gpg, losetup/dm-crypt.

**Relationship to the existing `luks/` directory:** `luks/` is the *provisioning-time* system — it wipes disks from a rescue environment and installs a fresh OS with root FDE. This plan adds the *runtime* system that hardens an already-installed host. They share nothing at the code level (the engine assumes rescue mode); `docs/LUKS.md` explains when to use which.

**Key design decision — no in-place root encryption:** Encrypting a mounted root filesystem from the running system is impossible (`cryptsetup reencrypt --encrypt` requires the device offline). Therefore:
- Bare-metal with root already on LUKS → harden it (TPM2 enrollment, perf flags, header backup, key-slot policy) and encrypt remaining data/swap volumes.
- Bare-metal with unencrypted root → `luks_preflight` returns 1 (needs user intervention) and points at `luks/provision-encrypted.sh` or an offline `cryptsetup reencrypt` procedure documented in `docs/LUKS.md`.
- VPS → never touch the root device, bootloader, or initramfs. Encrypt secondary volumes / loopback containers only.

---

### Task 1: Environment detection — `modules/luks.d/env-detect.sh`

**Files:** Create `modules/luks.d/env-detect.sh`

Functions (all prefixed `_luks_env_`), populating globals `LUKS_ENV_TYPE` (`bare-metal`|`virtual`), `LUKS_ENV_VIRT` (hypervisor name or `none`), `LUKS_ENV_FIRMWARE` (`uefi`|`bios`), `LUKS_ENV_SECUREBOOT` (`enabled`|`disabled`|`unknown`), `LUKS_ENV_TPM2` (`yes`|`no`), `LUKS_ENV_BOOT_WRITABLE` (`yes`|`no`), `LUKS_ENV_ROOT_LUKS` (`yes`|`no`), `LUKS_ENV_ROOT_DEV`:

- [ ] `_luks_env_detect_virt` — precedence: `systemd-detect-virt` (exit 0 → name; `none` → bare metal), then `dmidecode -s system-product-name` / `/sys/class/dmi/id/product_name` matched against `(KVM|QEMU|VMware|VirtualBox|Xen|HVM domU|Virtual Machine|OpenStack|Amazon EC2|Google Compute Engine|Alibaba|Droplet)`, then `virt-what` if installed. Container detection (`systemd-detect-virt --container`) → classify `virtual` and set `LUKS_ENV_VIRT=container` (preflight will return 2 for containers).
- [ ] `_luks_env_detect_firmware` — `[[ -d /sys/firmware/efi ]]` → uefi else bios; Secure Boot via `mokutil --sb-state` or `bootctl status` or reading `/sys/firmware/efi/efivars/SecureBoot-*` byte 5.
- [ ] `_luks_env_detect_tpm2` — `[[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]` AND (if installed) `tpm2_getcap properties-fixed` succeeds.
- [ ] `_luks_env_detect_boot_access` — /boot exists, is writable, on a local block device, and an initramfs regeneration tool exists (`update-initramfs` or `dracut`) plus `grub-mkconfig`/`grub2-mkconfig`.
- [ ] `_luks_env_detect_root_luks` — walk `lsblk -no PKNAME,TYPE` / `lsblk -s` from the root mount source; root is LUKS if any ancestor is `type=crypt` with `cryptsetup status` reporting LUKS.
- [ ] `luks_env_detect` — orchestrator honouring `LUKS_MODE` override (`bare-metal`/`virtual` skip auto-detection of type but still probe firmware/TPM/boot); logs a one-line classification summary.
- [ ] Verify: `bash -n`, then source with mocked commands and assert classification on this Fedora host.
- [ ] Commit: `feat(luks): environment detection library`

### Task 2: Runtime LUKS config — `config/luks.conf`

**Files:** Create `config/luks.conf`

- [ ] All keys with safe defaults, module disabled: `LUKS_ENABLED=no`, `LUKS_MODE=auto`, `LUKS_ROOT_ENCRYPT=no`, `LUKS_TPM2=auto`, `LUKS_TPM2_PCRS="0+1+2+3+7"`, `LUKS_CLOUD_KMS_PROVIDER=none`, `LUKS_SWAP_ENCRYPT=yes`, `LUKS_DATA_PATH=/var/lib/encrypted-data`, `LUKS_DATA_DEVICES=""`, `LUKS_CONTAINER_SIZE_MB=2048`, `LUKS_CONTAINER_FILE=/var/lib/luks/data.img`, `LUKS_BIND_SENSITIVE=no`, `LUKS_NBDE=no`, `LUKS_TANG_URL=""`, `LUKS_DROPBEAR=no`, `LUKS_DROPBEAR_PORT=2222`, `LUKS_CIPHER=auto`, `LUKS_KEY_SIZE=512`, `LUKS_PBKDF=argon2id`, `LUKS_PBKDF_MEMORY=1048576`, `LUKS_PBKDF_ITERATIONS=4`, `LUKS_PBKDF_PARALLEL=4`, `LUKS_HEADER_BACKUP_DIR=/var/backups/luks-headers`, `LUKS_HEADER_BACKUP_SECONDARY=""`, `LUKS_FORCE=no`. Every key commented.
- [ ] Commit: `feat(luks): runtime config with safe defaults (disabled)`

### Task 3: Shared helpers — `modules/luks.d/common.sh`

**Files:** Create `modules/luks.d/common.sh`

- [ ] `_luks_require_tools` — install `cryptsetup` (+ distro names for `pwgen`, `gpg`) via `pkg_install`.
- [ ] `_luks_entropy_ready` — kernel ≥ 5.6 → always ready (CRNG); else require `entropy_avail > 3000`, installing `haveged`/`rng-tools` and polling up to 60 s.
- [ ] `_luks_benchmark_cipher` — run `cryptsetup benchmark`, parse MiB/s for `aes-xts` 512b, `serpent-xts` 512b, `xchacha20,aes-adiantum`; pick fastest (aes-xts wins ties); honour explicit `LUKS_CIPHER != auto`.
- [ ] `_luks_gen_passphrase` — `pwgen -s 64 1` with `openssl rand`/`/dev/urandom`+tr fallback.
- [ ] `_luks_format` — luksFormat type luks2 with configured cipher/key-size/argon2id params (`--pbkdf-memory`, `--pbkdf-force-iterations`, `--pbkdf-parallel`).
- [ ] `_luks_backup_header <dev> <name>` — luksHeaderBackup → `${LUKS_HEADER_BACKUP_DIR}/<name>-<ts>.img`, SHA-512 sidecar, `gpg --symmetric --cipher-algo AES256 --batch` with the volume passphrase, remove plaintext, chmod 0600, replicate to `LUKS_HEADER_BACKUP_SECONDARY` (s3:// via aws CLI, else cp to path).
- [ ] `_luks_slot_audit <dev>` — count active key slots via `cryptsetup luksDump`; warn if > 2.
- [ ] `_luks_workqueue_flags <dev>` — rotational check via `/sys/block/*/queue/rotational`; on non-rotational `cryptsetup refresh --persistent --perf-no_read_workqueue --perf-no_write_workqueue`; emit matching crypttab options.
- [ ] `_luks_crypttab_check` — validate `/etc/crypttab`: 2–4 fields, name syntax, source device resolvable (`UUID=` via blkid, path exists, or `/dev/urandom`), keyfile exists or `none`/`-`, options from a known-good set; returns non-zero with line numbers on failure.
- [ ] `_luks_crypttab_add <name> <src> <key> <opts>` — backup `/etc/crypttab`, append if absent, run `_luks_crypttab_check`, **restore backup on validation failure**; then dry-run boot parse in `systemd-nspawn --volatile=overlay` if available (best-effort, parse-only fallback).
- [ ] `_luks_is_safe_target <dev>` — refuse if: device (or any holder/parent) hosts `/`, `/boot`, `/usr`, `/var`; device is in active `swapon`; appears in fstab/crypttab; has an existing filesystem/RAID/LVM signature (`wipefs -n`) unless `LUKS_FORCE=yes`; is the disk backing the root partition. This is the no-break gate both paths use.
- [ ] Verify: `bash -n` + smoke-source asserting `_luks_crypttab_check` passes/fails on crafted fixtures under `/tmp`.
- [ ] Commit: `feat(luks): shared LUKS helpers (benchmark, header backup, crypttab safety)`

### Task 4: VPS path — `modules/luks.d/vps.sh`

**Files:** Create `modules/luks.d/vps.sh`

- [ ] `_luks_vps_data_volume` — for each device in `LUKS_DATA_DEVICES` (or none): `_luks_is_safe_target`, entropy gate, format LUKS2, open as `enc-data-N`, mkfs.ext4, mount under `LUKS_DATA_PATH`, crypttab + fstab entries (keyfile in `/etc/luks/` 0400, dir 0700).
- [ ] `_luks_vps_loop_container` — fallback when no secondary device: `fallocate` `LUKS_CONTAINER_FILE` (size `LUKS_CONTAINER_SIZE_MB`), loop-attach, format/open/mkfs/mount at `LUKS_DATA_PATH`; persistence via a generated systemd service (`luks-data.service`: losetup + cryptsetup open --key-file + mount, with `Before=multi-user.target`) because crypttab loop ordering is unreliable across distros.
- [ ] `_luks_vps_swap` — if `LUKS_SWAP_ENCRYPT=yes`: disable existing plaintext swap (fstab comment-out + swapoff), create `/var/lib/luks/swapfile` (or dedicated volume if listed), crypttab line `cryptswap <dev> /dev/urandom swap,cipher=aes-xts-plain64,size=512` for random-key swap; loop-backed swap goes through the same generated unit.
- [ ] `_luks_vps_bind_sensitive` — only when `LUKS_BIND_SENSITIVE=yes` (default no — unlock failure must never lock out logins): rsync `/etc/ssh` + app-secret dirs into `${LUKS_DATA_PATH}/sensitive`, bind-mount via fstab `x-systemd.requires=` entries. `/etc/shadow` is explicitly NOT relocated (PAM needs it before unlock); documented.
- [ ] Root-volume guard: every entry point re-asserts the target is not the root/boot device even if config says otherwise.
- [ ] Verify + Commit: `feat(luks): VPS data-at-rest path (volumes, loop container, encrypted swap)`

### Task 5: Key management — `modules/luks.d/kms.sh`

**Files:** Create `modules/luks.d/kms.sh`

- [ ] `_luks_kms_escrow <keyfile> <name>` dispatch on `LUKS_CLOUD_KMS_PROVIDER`: `aws` → `aws kms encrypt` + upload to `LUKS_KMS_S3_BUCKET` (or SSM SecureString); `gcp` → `gcloud kms encrypt` + GCS; `vault` → `vault kv put`. Each verifies CLI presence + instance identity first and degrades to a logged warning (passphrase path remains primary).
- [ ] `_luks_kms_retrieve <name> <dest>` — inverse, used by `luks-cloud-recovery.sh` and the boot unit (ExecStartPre best-effort, falling back to local keyfile).
- [ ] `_luks_nbde_bind <dev>` — only when `LUKS_NBDE=yes` and `LUKS_TANG_URL` set: install clevis (+`clevis-luks`), `clevis luks bind -d <dev> tang '{"url":"..."}'` after reachability probe (`curl ${url}/adv`); passphrase slot always retained as fallback.
- [ ] Verify + Commit: `feat(luks): cloud KMS escrow and opt-in clevis/tang NBDE`

### Task 6: Bare-metal path — `modules/luks.d/baremetal.sh`

**Files:** Create `modules/luks.d/baremetal.sh`

- [ ] `_luks_bm_root_status` — if root already LUKS: header backup, slot audit, workqueue flags, optionally TPM2 enroll. If not and `LUKS_ROOT_ENCRYPT=yes`: log the offline procedure + pointer to `luks/provision-encrypted.sh`, mark needs-intervention (no destructive action ever).
- [ ] `_luks_bm_tpm2_enroll <dev>` — requires `LUKS_ENV_TPM2=yes` + `systemd-cryptenroll`; PCR bank from `LUKS_TPM2_PCRS` (default `0+1+2+3+7`, only `7` if Secure Boot disabled — drop boot-path PCRs that churn without SB); `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=<pcrs> <dev>`; add `tpm2-device=auto` to the crypttab options of that volume; keep passphrase slot.
- [ ] `_luks_bm_data_swap` — reuse the VPS volume/swap functions for non-root devices (same safety gate).
- [ ] `_luks_bm_dropbear` — opt-in `LUKS_DROPBEAR=yes`, debian-family only (package `dropbear-initramfs`): install, write `/etc/dropbear/initramfs/dropbear.conf` (port, `-s -j -k`), copy root's authorized_keys, regenerate initramfs **only after** `_luks_crypttab_check` passes, print host-key fingerprint via `dropbearkey -y`.
- [ ] `_luks_bm_encrypted_boot_note` — audit-only: report whether /boot is encrypted and whether GRUB has `GRUB_ENABLE_CRYPTODISK=y`; converting /boot in place is documented, not automated.
- [ ] Verify + Commit: `feat(luks): bare-metal path (TPM2 enrollment, dropbear, root hardening)`

### Task 7: Module entry — `modules/20_luks.sh`

**Files:** Create `modules/20_luks.sh`

- [ ] Sources the four `luks.d/` libraries relative to its own path.
- [ ] `luks_preflight` — returns **0** ready, **1** needs user intervention (unencrypted bare-metal root with `LUKS_ROOT_ENCRYPT=yes`, missing cryptsetup it can't install, no free target & no space for a container), **2** unsupported (container, `LUKS_ENABLED=no` counts as 2-skip for the runner).
- [ ] `luks_audit` — environment classification, root-LUKS status, crypttab validity, encrypted-swap status, slot counts, header-backup presence; increments `AUDIT_FINDINGS`.
- [ ] `luks_apply` — gate on `LUKS_ENABLED`, run preflight, dispatch bare-metal vs VPS path, then common hardening (header backups, workqueue flags, KMS escrow, NBDE), honouring dry-run via the existing `should_write`/log conventions; returns 2 when skipped.
- [ ] `luks_rollback` — restore `/etc/crypttab` + `/etc/fstab` from backup, disable generated units, close+detach loop containers (never luksErase — data stays recoverable), re-enable plaintext swap it disabled.
- [ ] Verify + Commit: `feat(luks): 20_luks module entry (preflight/audit/apply/rollback)`

### Task 8: Wire into `harden.sh`

**Files:** Modify `harden.sh` (usage text, `parse_args`, `MODULES`, module sourcing)

- [ ] Add `--luks-mode <auto|bare-metal|virtual>` (exports `LUKS_MODE`, default auto) and `--luks-only` (sets `MODULE_FILTER=luks`).
- [ ] Append `luks` to `MODULES`; source `modules/20_luks.sh` (path differs from `lib/`, so handle it where modules are sourced); load `config/luks.conf` if present after the main config (main config wins — it is sourced... actually luks.conf is sourced first so hardener.conf overrides; document).
- [ ] Verify: `bash -n harden.sh`; `--help` shows new flags; running `--audit --luks-only` as non-root still hits the root check (expected).
- [ ] Commit: `feat(luks): wire LUKS module into harden.sh (--luks-mode, --luks-only)`

### Task 9: Validation — `scripts/validate.sh`

**Files:** Modify `scripts/validate.sh` (new section before "Critical Services")

- [ ] Section `Encryption (LUKS)` gated on `LUKS_ENABLED=yes` in `config/luks.conf` (else prints a skip note): crypttab present + `_luks_crypttab_check`-style validation; `swapon --show=NAME` entries all `/dev/mapper/*` or `/dev/dm-*` (or zram); bare-metal → root device is crypt; virtual → at least one non-root LUKS device (`lsblk -no TYPE` contains crypt).
- [ ] Commit: `feat(luks): post-hardening LUKS validation checks`

### Task 10: Recovery scripts

**Files:** Create `scripts/luks-recovery.sh`, `scripts/luks-cloud-recovery.sh`

- [ ] `luks-recovery.sh` (bare-metal): subcommands `restore-header <dev> <backup>` (gpg-decrypt if `.gpg`, sha512 verify, `luksHeaderRestore` after interactive confirmation), `add-temp-key <dev>` (luksAddKey into a free slot, prints slot for later `luksKillSlot`), `regen-boot` (initramfs + grub regeneration with crypttab validation first, distro-aware update-initramfs/dracut + grub-mkconfig/grub2-mkconfig).
- [ ] `luks-cloud-recovery.sh` (VPS): `remount` (KMS retrieve → fallback interactive passphrase; losetup + open + mount loop containers and data volumes from saved state), `instructions` (prints provider console/VNC recovery steps).
- [ ] Both standalone (`set -euo pipefail`, own arg parsing, root check), `bash -n` + `--help` smoke test.
- [ ] Commit: `feat(luks): recovery tooling for bare-metal and VPS`

### Task 11: Documentation — `docs/LUKS.md` + README

**Files:** Create `docs/LUKS.md`; modify `README.md` (module table/feature list)

- [ ] Decision matrix (bare-metal vs VPS capability table), threat model (at-rest, hypervisor trust boundary, physical tampering), step-by-step deployment for both paths, runtime vs provisioning (`luks/`) comparison, performance expectations (NVMe vs cloud block storage, workqueue flags), recovery procedures, and the two warning callouts ("Do not attempt root FDE on VPSs without provider support", "Always test initramfs changes on bare-metal with a live ISO ready").
- [ ] Commit: `docs(luks): runtime LUKS module documentation`

### Task 12: Final verification

- [ ] `bash -n` every new/modified script; smoke-source the module chain with `RUN_MODE=audit` and stubbed `log_*` functions; confirm `luks_preflight` exists and env detection classifies this host.
- [ ] Confirm no changes to `lib/sysctl.sh` or other modules (no Lynis regression vector); module disabled by default.
- [ ] Commit any fixes: `chore(luks): final verification fixes`
