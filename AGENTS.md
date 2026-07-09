# Repository Guidelines

## Project Structure & Module Organization

EMBA is a Bash-based firmware security analyzer. The main entry points are `emba` and `installer.sh`. Core analysis logic lives in `modules/`, with prefixes such as `P*` for preparation/extraction, `S*` for static checks, `L*` for emulation checks, `F*` for aggregation, and `Q*` for connectors. Shared utilities and report assets are in `helpers/`. Installation code is in `installer/`, scan presets in `scan-profiles/`, configuration and templates in `config/`, docs in `docs/`, and regression checks in `tests/`. Read `docs/repository-modernization-assessment.md` before broad refactors.

## Build, Test, and Development Commands

- `sudo ./installer.sh -d`: install default dependencies.
- `sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-scan.emba`: run a default firmware scan.
- `./check_project.sh`: run lint and project checks for shell scripts, JSON, Docker Compose, semgrep, permissions, comments, and copyright headers.
- `./check_project.sh --fast`: run checks against changed files only.
- `bash tests/test_cpe_identifiers.sh`: run the CI CPE regression test.
- `git ls-files '*.sh' 'emba' 'installer.sh' 'check_project.sh' | xargs -r bash -n`: validate Bash syntax quickly.

## Coding Style & Naming Conventions

Use Bash with 2-space indentation and no tabs. Prefer `[[ ... ]]`, `${VARIABLE}` braces, `$(...)`, local variables, and strict-mode-compatible code. Function names use `snake_case`; globals use uppercase with underscores; local variables should start with `l`; nameref locals should start with `lr`. Quote variables, initialize before use, and avoid indirect globals. New files need the project GPLv3/SPDX header; copy the pattern from nearby files.

## Testing Guidelines

Run `./check_project.sh` before opening a PR; it wraps ShellCheck, semgrep, shfmt expectations, and project-specific checks. For targeted edits, also run `bash -n` on touched scripts and relevant tests. New behavior should be strict-mode compatible and, when feasible, covered by `tests/test_<feature>.sh`.

## Commit & Pull Request Guidelines

Recent commits use concise imperative subjects, for example `Add CI workflow for Bash syntax and CPE tests` or `Update Snyk database`. Keep commits separate: one fix, feature, or refactor per commit. Base work on current `master` unless coordinating with `next`. PRs should describe the change, list validation commands, link issues, and include screenshots or report snippets when output changes. Fix ShellCheck warnings instead of disabling them.

## Security & Configuration Tips

Do not commit firmware samples, generated logs, secrets, tokens, or local `external/` dependency trees. When adding a required binary, update dependency checks and installer support in the same change.
