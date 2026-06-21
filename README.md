# aurdit

Audit AUR PKGBUILDs for malicious changes using LLM-powered analysis.

Compares sequential PKGBUILD versions to detect anomalous changes, supply chain attacks, obfuscated code, persistence mechanisms, and credential theft using skills files of TTPs derived from recent supply chain attacks.

This is somewhat experimental, Seems to have a decently high rate of detecting recent attacks, Not at all a replacement for reading changes yourself :)

## Install

```bash
git clone https://github.com/Alfredooe/aurdit
cd aurdit
make build
```

Requires Go 1.24+ and `DEEPSEEK_API_KEY` in your environment, This uses the official deepseek APIs. Ultimately it's just completions, Switch the provider as you need. I use this because it's cheap.

## Usage

```bash
# Audit a single package (compares last 5 versions by default)
aurdit dodgypackagename

# Compare last 10 versions
aurdit dodgypackagename --history 10

# Audit a specific commit
aurdit premake-git --commit 232b22dd0aaedfa9fde1800710e0d52e4f4b542d

# Stream LLM output as it runs
aurdit dodgypackagename -v

# Machine-readable JSON
aurdit dodgypackagename --json | jq .

# Check all installed AUR packages for pending updates and audit each
aurdit check

# Same, with JSON output
aurdit check --json | jq .
```

## What it checks

- Supply chain: source URL changes, maintainer changes, typosquatting, orphan hijacking
- Obfuscation: base64, eval, curl|bash, hidden commands in .install files
- Persistence: systemd services, shell config injection, cron jobs
- Credential theft: SSH key access, token exfiltration, C2 endpoints
- Dependency risks: npm/bun/pip in depends, new install hooks

Findings are labeled with [MITRE ATT&CK](https://attack.mitre.org/) technique IDs.

Example output targetting known malicious commit from the June 2026 campaign:

```json
$ aurdit premake-git --commit 232b22dd --json | jq .
{
  "package": "premake-git",
  "verdict": {
    "verdict": "MALICIOUS",
    "confidence": "HIGH",
    "summary": "This PKGBUILD is malicious. The install= script contains
      a post_install() that runs 'npm install atomic-lockfile' — a known
      malicious package from the June 2026 supply chain attack wave.",
    "findings": [
      {
        "severity": "CRITICAL",
        "ttp": "T1195.002",
        "line": 1,
        "detail": "Install file contains post_install() running
          'npm install atomic-lockfile' in /tmp."
      },
      {
        "severity": "HIGH",
        "ttp": "T1059.004",
        "line": 10,
        "detail": "'npm' in depends=() — premake is a C tool with no
          legitimate need for Node.js at runtime."
      },
      {
        "severity": "MEDIUM",
        "ttp": "T1027",
        "line": 12,
        "detail": "Malicious payload hidden in .install file rather than the
          PKGBUILD, avoiding casual review."
      }
    ]
  }
}
```

## How it works

Criteria are defined in `skills/` as Markdown files the LLM loads as reference:

- `supplychain-ttps/` — dependency confusion, typosquatting, commit forgery
- `obfuscation-ttps/` — shell obfuscation, systemd persistence, eBPF rootkit
- `pkgbuild-ttps/` — privilege escalation, credential theft, known IOCs

Skills are compiled into the binary. Edit `configs/aurdit.yaml` to customize the
audit persona without recompiling.

## Config

`configs/aurdit.yaml` is embedded at build time. Override at runtime with
`~/.config/aurdit/config.yaml`:

```yaml
instruction: |
  Custom audit persona here.
model: deepseek-chat
base_url: https://api.deepseek.com/v1
```

## Integration

You can use a Paru PreBuildCommand hook to run this prior to makepkg, Seems to work decently.

### paru PreBuildCommand hook

paru's `PreBuildCommand` runs before `makepkg` — exit non-zero to abort the build.

Create `~/.config/paru/prebuild-hook`:

```bash
#!/bin/sh
output=$(aurdit "$PKGBASE" --json 2>/dev/null) || exit 0
verdict=$(echo "$output" | jq -r '.verdict.verdict')
case "$verdict" in
    SAFE) exit 0 ;;
    SUSPICIOUS|MALICIOUS)
        echo "$output" | jq .
        exit 1 ;;
esac
```

```bash
chmod +x ~/.config/paru/prebuild-hook
```

Then in `~/.config/paru/paru.conf`:

```ini
[bin]
PreBuildCommand = ~/.config/paru/prebuild-hook
```

### Scripting

```bash
# Find suspicious AUR updates
aurdit check --json | jq '.[] | select(.verdict.verdict != "SAFE")'

# Block in CI
aurdit <pkg> --json | jq -e '.verdict.verdict == "SAFE"' >/dev/null
```
