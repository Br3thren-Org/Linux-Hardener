# SSH Crypto, Kernel Command Line & Remote Syslog

Three optional, config-gated hardening modules. All are idempotent, respect
`DRY_RUN=yes`, log to `/var/log/linux-hardener/`, and run safely through
`orchestrate.sh`. None conflict with the LUKS (`modules/20_luks.sh`) or
firewall (`lib/firewall.sh`, nftables) modules.

| Module | File | Config gate | Default |
|--------|------|-------------|---------|
| SSH crypto policy | `modules/25_ssh_crypto.sh` | `SSH_MODERN_CRYPTO=yes` | on |
| Kernel command line | `modules/15_kernel_cmdline.sh` | `KERNEL_CMDLINE_HARDEN=yes` | off |
| Remote syslog | `modules/50_remote_syslog.sh` | `RSYSLOG_REMOTE_HOST` set | off |

---

## 1. SSH Crypto Policy (`modules/25_ssh_crypto.sh`)

Writes `/etc/ssh/sshd_config.d/25-hardener-crypto.conf`. On RHEL-family hosts
it also raises the system-wide policy with `update-crypto-policies --set
FUTURE` (unless the host explicitly sits on `LEGACY`), so the whole TLS/SSH
stack moves together; the sshd drop-in still pins the algorithms
deterministically.

**Config keys**

```ini
SSH_MODERN_CRYPTO="yes"      # default yes
SSH_ALLOWED_GROUPS=""        # e.g. "ssh-users admins"; empty = no restriction
SSH_LOGIN_GRACE_TIME=20      # seconds
```

**Lock-out safety.** A reload never drops the current session. After reload
the module runs a real SSH handshake against `127.0.0.1`: if kex/cipher/MAC
negotiation fails (`no matching ...`) it deletes the drop-in and reloads sshd
again — automatically, with no `at` timer to misfire. `AllowGroups` is refused
unless at least one real user belongs to every listed group.

### Expected `sshd -T` output

After apply, these lines must read exactly:

```
kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
hostkeyalgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com
logingracetime 20
```

With `SSH_ALLOWED_GROUPS="ssh-users"` you also get `allowgroups ssh-users`,
and on OpenSSH ≥ 9.1 `requiredrsasize 4096`.

Verify weak crypto is gone (each must print nothing):

```bash
sshd -T | grep -E 'diffie-hellman-group(1|14)-sha1'   # no DH-SHA1
sshd -T | grep -- '-cbc'                              # no CBC ciphers
sshd -T | grep -E 'hmac-(sha1|md5)'                   # no SHA1/MD5 MACs
```

`scripts/validate.sh` runs exactly these and reports PASS/FAIL.

### Client compatibility

The policy requires OpenSSH ≥ 7.3 (curve25519, ETM MACs, chacha20). Every
maintained client qualifies. Truly ancient clients (RHEL 6, PuTTY < 0.68)
will fail to connect — intended.

### Expected log noise: RSA host key

`RequiredRSASize 4096` enforces the spec's "disable RSA < 4096" rule. Most
cloud images ship a 3072-bit RSA **host** key, so after apply you will see:

```
sshd: Host key /etc/ssh/ssh_host_rsa_key: Invalid key length
```

This is benign — connections use the Ed25519 host key, which every modern
client prefers. To silence it, regenerate a 4096-bit RSA host key
(`ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""`) or remove the
RSA host key entirely if all your clients support Ed25519.

### Live-test status

All three modules were validated end-to-end on fresh Hetzner debian-12 and
rocky-9 instances: SSH crypto applied **over an active SSH session** without
lock-out (handshake probe confirmed, auto-revert proven against an
unnegotiable config), the RHEL `update-crypto-policies --set FUTURE` path,
kernel parameters active in `/proc/cmdline` after reboot, remote-syslog
end-to-end delivery including queue-and-flush across a collector outage, and
clean rollback of all three.

---

## 2. Kernel Command Line (`modules/15_kernel_cmdline.sh`)

Appends mitigations to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, regenerates
the bootloader config (`update-grub` / `grub2-mkconfig`, plus `grubby` for
BLS-based EL9+), verifies it with `grub-script-check`, and **reverts on any
failure**. Never reboots.

**Config keys**

```ini
KERNEL_CMDLINE_HARDEN="no"   # default off
KERNEL_CMDLINE_EXTRA=""      # extra space-separated params appended verbatim
```

**Parameters applied**

Always: `init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1
randomize_kstack_offset=on vsyscall=none spectre_v2=on
spec_store_bypass_disable=seccomp`

Conditional:
- `tsx=off` — only when the CPU reports the `rtm` flag in `/proc/cpuinfo`.
- `lockdown=integrity` — only when the kernel exposes
  `/sys/kernel/security/lockdown` **and** Secure Boot is enabled. Without
  Secure Boot the module logs a warning and skips it (no enforcement benefit,
  real risk of blocking module loads).

### Expected `/proc/cmdline` (after reboot)

On a typical AES-NI VPS without Secure Boot or TSX, the appended portion reads:

```
... init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none spectre_v2=on spec_store_bypass_disable=seccomp
```

A bare-metal host with Secure Boot and a TSX-capable Intel CPU additionally
shows `lockdown=integrity` and `tsx=off`. Confirm lockdown actually engaged:

```bash
cat /sys/kernel/security/lockdown      # -> none [integrity] confidentiality
```

> ⚠️ **VPS / provider warnings.** On a VPS the module prints a warning before
> applying `lockdown=integrity` — it blocks unsigned kernel modules and can
> stop provider guest agents or custom kernels from loading; only enable it
> with a provider kernel that signs its modules. Some providers (e.g. certain
> Hetzner/DO images) **override GRUB** or boot a pinned kernel via their own
> pipeline — there `/etc/default/grub` edits have no effect and the validation
> check stays at "pending-reboot". Verify on a disposable instance first.
> Always keep console/VNC access available for the first reboot after enabling
> this module.

---

## 3. Remote Syslog (`modules/50_remote_syslog.sh`)

Forwards `auth`, `authpriv`, `kern`, and warning-or-worse messages to a remote
collector via `/etc/rsyslog.d/99-hardener-remote.conf`. A bounded disk-assisted
queue (100 MB) survives collector outages without blocking local logging.
Clears Lynis **LOGG-2154**. Local journald persistence is handled separately by
the logging module, so the host always keeps its own copy.

**Config keys**

```ini
RSYSLOG_REMOTE_HOST=""        # "host:port"; empty disables. Port default 514/tls 6514
RSYSLOG_REMOTE_PROTOCOL="tcp" # tcp | tls
RSYSLOG_REMOTE_CERT=""        # CA cert (PEM) — required for tls
```

If rsyslog is absent it is installed (Debian/Ubuntu and RHEL); where rsyslog
cannot be installed on the RHEL family the module falls back to
`systemd-journal-upload`. TLS additionally pulls in `rsyslog-gnutls`.

### Sample receiver config (for testing)

On the collector, accept TCP syslog on 514:

```
# /etc/rsyslog.d/00-receiver.conf  (collector side)
module(load="imtcp")
input(type="imtcp" port="514")

# Store each sender under its own file
template(name="PerHost" type="string"
         string="/var/log/remote/%HOSTNAME%/messages.log")
*.* ?PerHost
```

For TLS (port 6514), on the collector:

```
module(load="imtcp"
       StreamDriver.Name="gtls"
       StreamDriver.Mode="1"
       StreamDriver.AuthMode="x509/certvalid")
global(DefaultNetstreamDriver="gtls"
       DefaultNetstreamDriverCAFile="/etc/ssl/syslog/ca.pem"
       DefaultNetstreamDriverCertFile="/etc/ssl/syslog/collector-cert.pem"
       DefaultNetstreamDriverKeyFile="/etc/ssl/syslog/collector-key.pem")
input(type="imtcp" port="6514")
```

### Verifying delivery

Apply emits a traceable marker:

```bash
# sender
logger -p auth.info "linux-hardener-test-<epoch>"   # done automatically on apply
rsyslogd -N1                                         # config syntax (validate.sh runs this)

# collector
grep linux-hardener-test /var/log/remote/<sender-host>/messages.log
```

`scripts/validate.sh` confirms `rsyslog` is active, `rsyslogd -N1` passes, and
the forwarding rule is present. Actual receipt is the collector's side to
confirm.

---

## Ordering & interaction notes

Execution order (from `harden.sh`): `ssh → ssh_crypto → … → kernel_cmdline →
… → remote_syslog → integrity → systemd_hardening → luks`.

- **ssh_crypto** runs after the base `ssh` module so its drop-in
  (`25-hardener-crypto.conf`) sorts before the base `99-hardening.conf`; sshd
  keeps the first value per keyword, so crypto settings win cleanly.
- **kernel_cmdline** is independent of LUKS: it only edits `GRUB_CMDLINE_LINUX`
  and never touches `cryptdevice`/`rd.luks.*` arguments the LUKS provisioning
  path manages.
- **remote_syslog** complements the firewall module — if you set
  `FIREWALL_RESTRICT_OUTPUT=true`, add the collector's port to the egress
  allowlist or forwarding silently queues then drops after 100 MB.
