# EMBA - Agent Guide

## Overview
EMBA (Embedded Linux Analyzer) is a firmware security analysis and SBOM tool. It is written entirely in **Bash** and runs as `sudo ./emba`. All code must pass strict mode (`-S` flag) and ShellCheck.

## Key Commands
| Action | Command |
|---|---|
| Install deps | `sudo ./installer.sh -d` |
| Default scan | `sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-scan.emba` |
| SBOM scan | `sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-sbom.emba` |
| Emulation scan | `sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-scan-emulation.emba` |
| All scan profiles | `./scan-profiles/*.emba` |
| GUI launcher | `./launcher` (requires `zenity`) |

## Verification (CI checks + unit tests)
```bash
# Unit tests (bats framework, ~140 tests across 11 suites)
./tests/run.sh

# ShellCheck + semgrep on all .sh files
./check_project.sh           # with --fast for quicker runs
./check_project.sh --fast

# Format check (2-space indent, no tabs)
shfmt -d -i 2 .

# ShellCheck standalone
shellcheck -x -o require-variable-braces ./emba ./modules/*.sh ./helpers/*.sh

# Strict mode runtime test
sudo ./emba -S -l ~/log -f ~/firmware -p ./scan-profiles/quick-scan.emba
```

## Architecture
- `./emba` — main entrypoint (bash), sources helpers then loads modules
- `./modules/` — scan modules, **ordered by prefix** (alphanumeric sorting via `sort -V`):
  - `P*` — extraction (binwalk, UEFI, ubifs, etc.)
  - `S*` — static analysis (binary checks, kernel, passwords, etc.)
  - `L*` — live/emulation checks (nmap, SNMP, web, metasploit)
  - `F*` — final aggregation (SBOM, aggregator, tag builder)
  - `D*` — firmware diffing
- `./helpers/` — imported helper libraries (`helpers_emba_*.sh`)
- `./installer/` — per-component install scripts (`I*`, `IF*`, `IL*`, `IP*`)
- `./config/` — configuration (profile triggers, CVEs, blacklists, version identifiers)
- `./scan-profiles/` — `.emba` profile files that enable/disable modules
- `./external/` — gitignored; prebuilt kernel images + tool binaries for emulation

## Code Conventions
- **Indent**: 2 spaces, no tabs. Enforced by `shfmt`.
- **Functions**: `snake_case()`. One blank line between functions.
- **Global vars**: `CAPITALIZED_WITH_UNDERSCORES`.
- **Local vars**: `l`-prefixed `UPPER_SNAKE_CASE` (e.g., `lMODULE_FILE`).
- **Strict mode**: All scripts must pass `wickStrictModeFail` (loaded via `installer/wickStrictModeFail.sh`).
- **ShellCheck**: Do not disable checks; fix the issue instead.
- **Copyright header**: GPLv3, Siemens Energy AG, on every new file.

## Docker
Primary deployment method. Build - uses Dockerfile (Kali base):
```bash
BUILDKIT_NO_CLIENT_TOKEN=1 DOCKER_BUILDKIT=1 sudo -E docker compose --progress=plain build --no-cache --pull 
```
Run: EMBA is automatically starting up the required docker images.

Mounts: `FIRMWARE`, `LOG`, `EMBA` env vars required. Container runs privileged.

## Merging / PRs
- Base on `master`. Use `git rebase -i` to structure logical commits.
- After each commit, EMBA must work (no temporary breakage).
- All CI must pass: ShellCheck, shfmt, semgrep, `check_project.sh`.
- Target OS: Kali Linux rolling / Ubuntu 22.04 LTS.
