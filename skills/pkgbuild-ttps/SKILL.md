---
name: pkgbuild-ttps
description: PKGBUILD structural red flags and AUR policy violations
---

# PKGBUILD Red Flags

## Privilege Escalation

- Any use of `sudo` in PKGBUILD, `install=`, or build functions.
- `chmod u+s` (setuid) on arbitrary binaries.
- `chmod 777` — world-writable files, especially on executables or configs.
- `chown root:root` with unusual permissions.

## System File Modification

Flag any attempt to modify files outside the package prefix (`$pkgdir`):
- Writing to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- Modifying `/boot`, kernel images, or initramfs
- Writing to `/usr/bin`, `/usr/lib` outside of proper package installation
- Modifying other packages' files

## Information Exfiltration

Signs a PKGBUILD might exfiltrate data:
- `curl`/`wget` POSTing data to external servers
- Sending `$HOME`, `.ssh`, `.gnupg`, or environment variables over the network
- Telemetry or phone-home commands with unique identifiers
- Reading and transmitting `/proc/cpuinfo`, `hostname`, `whoami`
- Git push to unauthorized remotes during build

## Persistence Mechanisms

- Installing systemd services that auto-start and phone home
- Adding cron jobs or systemd timers
- Modifying `.bashrc`, `.profile`, `.xinitrc` for the user
- Creating SSH authorized_keys entries

## Cryptomining / Resource Abuse

- Downloads of mining binaries (xmrig, cpuminer, monero-wallet-gui etc.)
- Unusual CPU/memory-intensive operations during build
- Connections to mining pool URLs
- Hidden background processes left running after build

## Credential Theft (June 2026 Campaign Pattern)

The atomic-lockfile malware specifically targeted these credentials:

- API calls to `api.openai.com`, `api.github.com`, `discord.com/api` for token validation
- SSH key exfiltration (`~/.ssh/id_*`)
- Browser cookie theft (Discord tokens, GitHub PATs, npm tokens, Slack sessions)
- Vault/cloud provider token theft
- Data uploaded to temp.sh or Tor C2 endpoints
- Any network requests in post_install that transmit files or environment variables
- NPM packages whose lifecycle scripts (`preinstall`, `postinstall`) do network I/O

## Known Malicious Domains & Endpoints

Flag any reference to these domains associated with prior campaigns:

- Tor C2: `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion`
- File upload: `temp.sh`
- Suspicious npm packages: `atomic-lockfile`, `js-digest`, `lockfile-js`, `nextfile-js`

## AUR Policy Violations

While not necessarily malicious, these indicate poor practice:
- `pkgver()` functions that use `git` with unauthenticated remotes
- No checksums for downloadable sources
- Use of `SKIP` in checksum arrays without explanation
- Duplicate package functionality (check if package shadows an official repo)
- Missing or misleading `pkgdesc`
- Unquoted variables that could expand to malicious paths
- `.hook` files — extremely rare, almost never legitimate. Their presence alone is a red flag (used in June 2026 campaign)
