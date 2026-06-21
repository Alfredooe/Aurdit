---
name: supplychain-ttps
description: Techniques for detecting supply chain attacks in AUR PKGBUILDs
---

# Supply Chain Attack Detection

## Malicious Source URLs

Attackers may replace legitimate source URLs with malicious ones. Check:

- Does the source URL point to the official upstream project, or a lookalike domain?
- Typosquatting: `githib.com`, `githab.com`, `gitlab.co`, `sorceforge.net`
- Is the domain newly registered or uses a free dynamic DNS service?
- Does the URL use HTTPS? HTTP sources are trivially MITM-able.
- Wildcard or variable URLs that make the actual target opaque.

## Dependency Confusion

- Check `depends=()` and `makedepends=()` for package names that shadow official repositories.
- AUR packages should not depend on packages that exist in `extra` or `core` with similar names.
- Look for dependencies on obscure or orphaned AUR packages that may have been hijacked.

## Checksum Mismatches

- `md5sums=()` and `sha256sums=()` should match the declared sources exactly.
- Missing checksums (or `SKIP`) on downloadable sources is a red flag.
- Checksums that don't include a known-good upstream verification step.

## Maintainer Changes

- Sudden changes in maintainer or author email addresses.
- Packages transferred to a new maintainer who immediately introduces suspicious changes.
- Orphaned packages adopted and weaponized within a single commit.

## Unusual Source Types

- Source pointing to pre-compiled binaries instead of source tarballs.
- Source using `git+https://` on a random fork instead of the upstream repo.
- Source arrays that download from IPFS, Tor, or other anonymized networks without justification.
- Sources that use short URL redirects (bit.ly, tinyurl, etc.) obscuring the real target.

## npm / bun / pip install Abuse (June 2026 Campaign Pattern)

The June 2026 atomic-lockfile attack injected package manager install commands directly
into PKGBUILD and .install files. This is a critical red flag.

- `npm install <package>` in any file is ALWAYS suspicious — PKGBUILDs should never install npm packages during build
- `bun install <package>` — same red flag as npm; seen in js-digest wave of June 2026 campaign
- `pip install <package>` — equally suspicious in build scripts
- Any runtime or package manager that fetches from registries during `build()` or `package()`
- Pre/post install hooks (npm `preinstall`, `postinstall`) that execute arbitrary code
- NPM packages with embedded ELF binaries (base64-decoded or shell-script droppers)

## Orphan Package Hijacking (June 2026 Campaign Pattern)

The attackers specifically targeted orphaned (unmaintained) AUR packages:

- Packages adopted by brand-new accounts (days old) that immediately push malicious commits
- Monitor for accounts with no history adopting multiple orphans simultaneously
- Single-commit attacks: one commit that adds malicious code without legitimate version bumps
- Legitimate-sounding commit messages ("update to latest version") that mask malicious changes

## Commit Forgery (June 2026 Campaign Pattern)

Attackers used git commit forgery to impersonate legitimate maintainers:

- The `aroja` identity was forged in the June 2026 attack — the real maintainer was impersonated
- Verify the commit author email matches the known maintainer email from AUR RPC
- Git commit author/committer fields can be set arbitrarily — they are NOT proof of identity
