# assessor

Comprehensive, evidence-first security and configuration assessment for running Linux hosts.

`assessor` inspects a live Linux system across 16 domains — SSH, kernel, auth/PAM,
filesystem, network, packages/CVEs, logging, crypto, containers, MAC (SELinux/AppArmor),
and more — and emits a prioritized report where every finding carries the **exact
file, line, or command output** it was derived from. No agent, no daemon, no phone-home:
it's a single static binary you run with `sudo`.

```
sudo assessor run --profile server
```

## Why

Most hardening scanners tell you *what* is wrong. `assessor` shows you *the evidence* —
the offending `sshd_config` line, the world-writable path, the unsigned kernel module,
the package version that matches a CVE — so a finding is verifiable and a remediation is
actionable. It also tracks state over time, so you can diff a host against its own
baseline and see exactly what drifted.

## Features

- **86 checks across 16 buckets**, each with severity, description, CIS references where
  applicable, and concrete remediation commands.
- **Evidence-first findings** — file/line citations, SHA-256 of inspected content, and
  raw command output attached to every finding.
- **Profiles** — `server`, `workstation`, `cis-l1`, or your own YAML, to scope checks to a
  host's role.
- **Baseline & drift** — snapshot a host, then `diff` future runs against it, including
  line-level diffs of inventory-shaped evidence (SUID files, listeners, timers, CVE IDs).
- **CVE matching** — scan installed packages against a cached NVD/OSV feed.
- **Multiple report formats** — colorized TTY, machine-readable JSON, and PDF/HTML.
- **Parallel, panic-isolated execution** — a check that crashes is reported as an error,
  not a process abort.

## Install

Requires Go 1.25+.

```bash
git clone https://github.com/t3rmit3/assessor
cd assessor
go build -o assessor ./cmd/assessor
```

This produces a standalone static binary. Move it onto the target host and run it as root.

## Usage

`assessor` requires root (it reads `/etc/shadow`, audit config, host keys, etc.). Use
`--skip-root-check` only for debugging.

### Run an assessment

```bash
# Full run with the default (server) profile, colorized TTY output
sudo assessor run

# Workstation profile, also write JSON and PDF reports
sudo assessor run --profile workstation --json report.json --pdf report.pdf

# Limit scope to specific buckets or check IDs
sudo assessor run --bucket ssh,kernel
sudo assessor run --id ssh.sshd.hardening --id auth.uid_zero.unique
```

The process exits with code **2** if any check fails, making it CI-friendly.

### List available checks

```bash
assessor list
```

```
ssh.sshd.hardening      [high]  ssh — sshd_config hardening directives  (server,workstation,cis-l1)
auth.uid_zero.unique    [critical]  auth — Only one account has UID 0  (server,workstation,cis-l1)
...
```

### Baseline and diff

```bash
# Capture a baseline snapshot (defaults to /var/lib/assessor)
sudo assessor run --snapshot

# Later, diff the current state against the newest snapshot
sudo assessor diff

# Diff against a specific snapshot, machine-readable
sudo assessor diff --previous /var/lib/assessor/snapshot-20260101T120000Z.json --json
```

The diff reports newly-failing checks, resolved checks, status changes, and line-level
evidence changes for tracked inventories.

### CVE feed

```bash
# Sync OSV's distro feeds into a local cache (default source)
sudo assessor cve sync --out /var/lib/assessor/cve.json

# Limit to specific ecosystems
sudo assessor cve sync --ecosystem Debian,Ubuntu

# Use the cache during a run
sudo assessor run --cve-db /var/lib/assessor/cve.json
```

`cve sync` defaults to `--source osv`, which pulls OSV's per-distro ecosystem
feeds (Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma). OSV package names line up
with what the on-host package listers report, so matches actually land. The
alternative `--source nvd` (set `NVD_API_KEY` to avoid rate limits) is broad but
CPE-based — its product names don't map cleanly onto distro package names, so
distro matching is unreliable.

## Key flags (`run`)

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | `server` | Profile filter (`server`, `workstation`, `cis-l1`, …) |
| `--bucket` | — | Limit to bucket(s) |
| `--id` | — | Limit to specific check ID(s) |
| `--parallel` | `8` | Max concurrent checks |
| `--json` | — | Write JSON report to path |
| `--pdf` | — | Write PDF report to path |
| `--cve-db` | — | Path to cached CVE feed JSON |
| `--snapshot` | `false` | Save report as a baseline snapshot |
| `--profile-dir` | `profiles` | Directory of profile YAML files |
| `--skip-root-check` | `false` | Permit non-root run (debug only) |

## Check buckets

| Bucket | Checks | Examples |
|--------|:-----:|----------|
| `auth` | 10 | unique UID 0, empty/weak passwords, sudoers NOPASSWD, PAM pwquality/faillock, shadow perms |
| `ssh` | 6 | sshd hardening, authorized_keys perms, host-key algorithms, rate limits, banner |
| `kernel` | 8 | sysctl hardening, cmdline, module signing/blocklist, lockdown mode, boot perms, GRUB password |
| `fs` | 7 | LUKS encryption, mount hardening, SUID inventory, world-writable/unowned files, encrypted swap |
| `network` | 6 | firewall active & default policy, listening inventory, IPv6 posture, DNS resolvers |
| `packages` | 6 | CVE scan, pending updates, signed repos, running-vs-installed kernel, auto-update, distro EOL |
| `webdb` | 9 | nginx/apache TLS, postgres/mysql/mongodb/redis bind & auth exposure |
| `forensic` | 7 | recently-modified binaries, package integrity, LD_PRELOAD, hidden PIDs, unsigned modules, shell-history secrets |
| `logging` | 6 | auditd running & rules, journald persistence, rsyslog forwarding, logrotate, log perms |
| `containers` | 6 | docker daemon/socket, kubelet auth, libvirt socket, rootless runtime, privileged containers |
| `crypto` | 3 | certificate expiry, weak keys, system crypto policy |
| `mac` | 4 | SELinux/AppArmor enforcing mode, unconfined processes, complain-mode count |
| `services` | 4 | failed units, unit hardening coverage, unwanted services, timer inventory |
| `cron` | 2 | cron/at allowlist, world-writable cron files |
| `time` | 2 | NTP sync, timezone set |

Run `assessor list` for the full, authoritative list.

## Profiles

Profiles live in `profiles/*.yaml` and scope which checks run for a host's role. The
schema supports `include_buckets`, `exclude_buckets`, `include_ids`, and `exclude_ids`;
exclusions always win. An empty profile matches everything, and a name with no matching
YAML falls back to the inline `profiles:` metadata on each check.

```yaml
name: server
description: Headless server profile — strict baseline.
include_buckets: [kernel, auth, ssh, fs, network, services, packages, ...]
exclude_ids:
  - fs.suid.inventory          # review by hand, don't gate on it
```

Add your own profile to the `profiles/` directory (or point `--profile-dir` elsewhere)
and select it with `--profile <name>`.

## How it works

```
cmd/assessor       CLI (cobra): run, list, diff, cve
internal/engine    check registry + parallel runner (panic-isolated, severity-sorted)
internal/sysfacts  host facts gathered once (distro, kernel, tooling, package manager)
internal/finding   core types: Metadata, Finding, Evidence, Report
internal/profiles  YAML profile loader + match logic
internal/baseline  snapshot save/load + diff (incl. line-level evidence diffs)
internal/cve       NVD/OSV ingest, version comparison, package matching
internal/evidence  helpers for building file/line evidence
internal/report    tty / json / pdf renderers
checks/<bucket>    the checks themselves; each self-registers via init()
```

Each check implements a small interface:

```go
type Check interface {
    Meta() finding.Metadata
    Run(ctx context.Context, facts sysfacts.Facts) finding.Finding
}
```

and registers itself with `engine.Register(...)` in an `init()` function. The `main`
package imports each bucket for its side effects, so adding a check is: write the file,
register it, done.

## Adding a check

1. Create a file under `checks/<bucket>/`.
2. Define a type implementing `Meta()` and `Run()`.
3. Return a `finding.Finding` with a `Status`, `Message`, attached `Evidence`, and a
   `Remediation`. Mark evidence `Tracked: true` if it's an inventory whose line set
   should be diffed over time.
4. Call `engine.Register(yourCheck{})` in `init()`.

See `checks/ssh/sshd_config.go` for a representative example.

## Development

```bash
go build ./...
go test ./...
```

Notes:
- PDF output shells out to headless Chrome/Chromium (falling back to `wkhtmltopdf`); if
  neither is installed, use `--json` and render elsewhere.
- TTY output honors `NO_COLOR` and auto-disables color when not writing to a terminal.

## License

MIT — see [LICENSE](LICENSE).

## Status

Early development (`0.1.0-dev`). Check coverage and feed ingestion are actively expanding.
CI (build, `go vet`, `gofmt`, and `go test -race`) runs on every push and PR.
