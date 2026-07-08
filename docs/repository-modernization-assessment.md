# EMBA Repository Modernization Assessment

Date: 2026-07-08

This assessment reviewed the repository structure, shell orchestration, modules, helpers, installer, scan profiles, Docker setup, GitHub workflows, SBOM/CPE/PURL generation, extraction flow, and local validation behavior. It is intentionally a planning document. It does not propose a rewrite, CLI behavior change, scan profile change, or SBOM format change as an immediate step.

## 1. Executive Summary

The biggest repository-wide issue is not a single broken module. It is that EMBA is a large, stateful Bash framework whose behavior is spread across sourced modules, exported globals, generated CSV/JSON side effects, Docker assumptions, and external tools. The codebase is functional and already has useful structure, but modernization needs to reduce repeated filesystem work, make generated SBOM/CPE data easier to validate, and add small regression tests before deeper refactors.

The first improvements should be:

- Make validation cheaper and more visible: add `bash -n` on a supported Linux Bash, run the existing CPE test in CI, and add SBOM JSON/schema smoke tests.
- Preserve and expand the existing `P99_CSV_LOG` inventory pattern. Many modules already read from it instead of rescanning the firmware tree, for example `helpers/helpers_emba_prepare.sh:474`, `helpers/helpers_emba_prepare.sh:493`, and `helpers/helpers_emba_prepare.sh:528`.
- Add focused helper/index layers for repeated SBOM duplicate lookup and dependency lookup. `helpers/helpers_emba_sbom_helpers.sh:179`, `helpers/helpers_emba_sbom_helpers.sh:182`, `helpers/helpers_emba_sbom_helpers.sh:195`, and `modules/S08_main_package_sbom.sh:147` repeatedly scan generated JSON files.
- Separate CPE correctness work into its own task. Field count handling has a central helper and a test, but part selection and OS/application distinction are still caller-dependent.
- Improve Docker/installer compatibility documentation and CI coverage, especially for Ubuntu 24.04, Docker Compose v2, non-Kali Linux hosts, and unsupported macOS/ARM64 host execution.

Do not touch these areas first:

- Do not rewrite the framework out of Bash.
- Do not change module naming, module group ordering, CLI flags, or scan profile semantics.
- Do not change the CycloneDX output shape from `modules/F15_cyclonedx_sbom.sh` in the first pass.
- Do not replace binwalk/unblob extraction behavior until there are sample firmware smoke tests.
- Do not mass-fix shellcheck/shfmt output without first adding regression tests around representative scans.

## 2. Architecture Overview

EMBA is organized around a Bash entrypoint, helper libraries, module groups, scan profiles, installer modules, Docker wrappers, and generated logs/reports.

Major source areas:

- `emba`: main entrypoint and phase orchestrator.
- `helpers/`: shared defaults, parameter parsing, path utilities, logging, dependency checks, SBOM helpers, HTML generation, emulation helpers, and maintenance scripts.
- `modules/`: phase modules. Top-level modules are named by phase prefix: `P`, `D`, `S`, `L`, `F`, and `Q`.
- `modules/S08_main_package_sbom_modules/`: package ecosystem SBOM submodules loaded by S08.
- `installer/`: modular installer actions sourced by `installer.sh`.
- `scan-profiles/`: Bash profiles that set module/profile behavior and are sourced at runtime.
- `config/`: identifiers, static file lists, report templates, banners, and generated/version data.
- `.github/workflows/`: lint, formatting, security, update, Docker, and scheduled smoke workflows.

The main entrypoint dynamically loads helpers from `helpers/helpers_emba_*.sh` (`emba:23`) and modules from `modules/*.sh` (`emba:39`). Module execution is selected by group in `run_modules()` (`emba:86`). The function locates group files by prefix, applies module blacklist handling, sources P/D modules for thread settings, and runs modules either inline or in the background with PID tracking (`emba:105`, `emba:117`, `emba:127`, `emba:169`).

The major phases are:

- Dependency and setup: parameters, defaults, dependency checks, profile sourcing, log directories, Docker handling, and firmware path preparation (`emba:373`, `emba:443`, `emba:461`, `emba:506`, `emba:691`).
- Pre-checking: P modules extract and prepare firmware metadata (`emba:876`). P02 fingerprints firmware and detects archive/encryption types (`modules/P02_firmware_bin_file_check.sh:21`), P50/P55 run binwalk/unblob extraction (`modules/P50_binwalk_extractor.sh:24`, `modules/P55_unblob_extractor.sh:24`), P60 performs deeper recursive extraction (`modules/P60_deep_extractor.sh:22`), P65 extracts package archives (`modules/P65_package_extractor.sh:22`), and P99 finalizes analysis preparation (`modules/P99_prepare_analyzer.sh:27`).
- Diff mode: D modules run when two firmware inputs are provided (`emba:913`).
- Static firmware checks: S modules run after extraction and preparation (`emba:943`).
- System emulation: L modules run serially when full emulation is enabled (`emba:973`).
- Reporting: F modules run at the end (`emba:997`), including CycloneDX SBOM generation in F15.
- Quest/connector work: Q modules run in a second container or background process (`emba:849`), for example Dependency-Track upload waits for F15 completion in `modules/Q20_dependency_track_connector.sh:39`.

Scan profiles are sourced directly (`emba:461`), which means they can set globals and module selection without a separate schema. This is flexible but makes validation harder.

Docker usage is built around two Compose services. The main `emba` service is privileged, mounts the firmware, logs, repository, external feeds, `/dev`, and several tmpfs paths (`docker-compose.yml:3`, `docker-compose.yml:9`, `docker-compose.yml:35`). The `emba_quest` service is read-only, uses `network_mode: host`, and runs with `no-new-privileges` (`docker-compose.yml:56`, `docker-compose.yml:77`, `docker-compose.yml:82`). The main script starts both containers in default Docker mode (`emba:772`, `emba:782`).

Final reports are primarily built from log files, CSV files, JSON component files, and HTML report output. F15 reads per-component SBOM JSON files from `SBOM_LOG_PATH`, manually concatenates component/dependency arrays, emits a CycloneDX 1.5 JSON document, and converts it to XML, protobuf, and SPDX JSON (`modules/F15_cyclonedx_sbom.sh:111`, `modules/F15_cyclonedx_sbom.sh:148`, `modules/F15_cyclonedx_sbom.sh:171`, `modules/F15_cyclonedx_sbom.sh:199`).

## 3. Performance Assessment

The repository already has a valuable performance pattern: build a backend inventory once, then read from it. Several older direct `find` pipelines are commented out and replaced with `P99_CSV_LOG` reads in `helpers/helpers_emba_prepare.sh:473`, `helpers/helpers_emba_prepare.sh:491`, `helpers/helpers_emba_prepare.sh:523`, and `helpers/helpers_emba_prepare.sh:636`. This is the right direction and should be expanded.

Likely runtime bottlenecks:

- Recursive extraction and inventory rebuilds. P50, P55, P60, and P65 each collect files and call `binary_architecture_threader` after extraction (`modules/P50_binwalk_extractor.sh:85`, `modules/P55_unblob_extractor.sh:90`, `modules/P60_deep_extractor.sh:61`, `modules/P65_package_extractor.sh:68`). This is necessary today, but repeated full-tree file enumeration and per-file `file`/checksum work can dominate large firmware scans.
- Deep extraction rounds. P60 can run up to four rounds and processes `FILE_ARR_LIMITED` with checksum tracking (`modules/P60_deep_extractor.sh:137`, `modules/P60_deep_extractor.sh:172`). This is high value but high risk for runtime and disk growth.
- Package extraction scans. P65 independently scans for RPM, APK, IPK, and DEB files with `find ... -exec md5sum` (`modules/P65_package_extractor.sh:107`, `modules/P65_package_extractor.sh:137`, `modules/P65_package_extractor.sh:166`, `modules/P65_package_extractor.sh:209`).
- SBOM duplicate handling. `build_sbom_json_hashes_arr()` computes three hashes and repeatedly greps/finds the SBOM output directory for duplicate SHA-512/name/version matches (`helpers/helpers_emba_sbom_helpers.sh:147`, `helpers/helpers_emba_sbom_helpers.sh:179`, `helpers/helpers_emba_sbom_helpers.sh:195`, `helpers/helpers_emba_sbom_helpers.sh:244`).
- SBOM dependency tree creation. S08 starts one worker per component and then each worker greps component JSON files by name/source (`modules/S08_main_package_sbom.sh:79`, `modules/S08_main_package_sbom.sh:85`, `modules/S08_main_package_sbom.sh:147`).
- F15 manual JSON assembly. It validates each component with `json_pp`, appends files, and then converts to other formats (`modules/F15_cyclonedx_sbom.sh:128`, `modules/F15_cyclonedx_sbom.sh:135`, `modules/F15_cyclonedx_sbom.sh:199`).
- Regex-heavy modules such as S99 are explicitly marked with performance concerns (`modules/S99_grepit.sh:5845`).
- Emulation and decompilation modules are inherently slow and should be optimized only with representative samples: L10, S115/S116, S14/S15/S16, S17/S18, and S26.

Repository metrics from inspection:

- 269 tracked shell entry/script files.
- 92 top-level modules, 22 S08 SBOM submodules, 27 helpers, 27 installer modules, 12 scan profiles, and 18 GitHub workflow files.
- Static text search found roughly 439 `find`, 1,829 `grep`, 115 `md5sum`, 21 `sha256sum`, 23 `sha512sum`, 1,064 `file`, and 92 `strings` occurrences under the main shell code paths. These are not all problems, but they show where runtime cost accumulates.

Low-risk performance improvements:

- Add timing/log summaries per module and per major helper path so future changes are measured.
- Use `P99_CSV_LOG` more consistently for package archive discovery where semantics are equivalent.
- Add an SBOM component index file keyed by SHA-512, name/version, and group during component creation. Use it for duplicate and dependency lookup before falling back to `grep`.
- Avoid repeated `jq` extraction of the same fields inside tight loops by reading name/version/bom-ref/group once into a small TSV index.
- Add helper functions for common file inventory queries, but keep the returned data identical to existing pipelines.

Risky rewrites to postpone:

- Replacing the extraction pipeline.
- Changing module concurrency semantics.
- Changing SBOM output assembly format.
- Moving orchestration from Bash to another language.
- Changing scan profile behavior.

## 4. Compatibility Assessment

The supported path is Linux-first, Docker-first, and strongly aligned with Kali/Ubuntu. Documentation says code needs to work on latest Kali Linux and Ubuntu 22.04 LTS, with other distributions not currently tested (`CONTRIBUTING.md:35`). The installer recognizes RHEL/Fedora/Rocky/CentOS but otherwise requires Debian-like systems (`installer.sh:208`).

Docker compatibility observations:

- The Dockerfile uses `kalilinux/kali-rolling` (`Dockerfile:1`), which is convenient for tooling but weak for reproducibility.
- Docker build requires BuildKit bind mounts (`Dockerfile:7`).
- Compose service images are pinned to `embeddedanalyzer/emba:2.0.2b` while Trivy scans `embeddedanalyzer/emba:latest`, which can diverge (`docker-compose.yml:4`, `.github/workflows/trivy.yml:45`).
- The main container is privileged and mounts `/dev` (`docker-compose.yml:9`, `docker-compose.yml:42`), so Docker Desktop/macOS/Windows behavior will differ from native Linux.
- Docker command handling supports both `docker compose` and legacy `docker-compose` (`installer.sh:352`, `installer.sh:388`, `installer.sh:409`; `helpers/helpers_emba_dependency_check.sh:179`).

Linux distribution and host assumptions:

- Installer detects Ubuntu 22.04/24.04, warns for Ubuntu 20.04, and has special WSL handling (`installer.sh:196`, `installer.sh:216`, `installer.sh:220`).
- Installer warns when architecture is not `x86_64` and when SSSE3 is missing (`installer.sh:241`, `installer.sh:248`). This makes macOS/ARM64 and non-x86 Linux hosts at best unsupported host environments.
- It requires root for installation and for Docker/emulation paths unless the user belongs to the Docker group (`installer.sh:255`, `helpers/helpers_emba_dependency_check.sh:345`).
- It directly uses `/proc`, `/etc/os-release`, `/var/lib/docker`, `df --output`, `lsmod`, `mount`, and Linux-specific tooling in multiple places.

Shell compatibility observations:

- Scripts use `#!/bin/bash -p`, arrays, `mapfile/readarray`, `[[ -v ... ]]`, `|&`, and `&>>`. These require modern Bash behavior and do not parse on macOS default Bash 3.2.
- Local verification with `/bin/bash` version `3.2.57(1)-release (arm64-apple-darwin25)` failed on 28 checked files. Examples include `emba:707`, `installer.sh:181`, `helpers/helpers_emba_path.sh:119`, `modules/P55_unblob_extractor.sh:189`, and `modules/S115_usermode_emulator.sh:696`.
- This is not necessarily a Linux CI failure. It is evidence that host execution on macOS/ARM64 should be documented as unsupported unless using Docker plus a supported Linux shell/toolchain.

Dependency fragility:

- Installer has many external downloads and distro-specific paths. Examples include Docker repository setup (`installer.sh:352`), Homebrew/cyclonedx path assumptions (`helpers/helpers_emba_dependency_check.sh:494`), and external tool installers under `installer/`.
- Online update checks clone a GitHub repository unless `NO_UPDATE_CHECK=1` is set (`helpers/helpers_emba_dependency_check.sh:272`).
- Developer host mode is deprecated/unsupported in help text (`helpers/helpers_emba_print.sh:686`, `installer/helpers.sh:23`) but much code still supports it.

## 5. SBOM and CPE Assessment

Current SBOM flow:

- S08 loads package SBOM submodules from `modules/S08_main_package_sbom_modules` (`modules/S08_main_package_sbom.sh:32`).
- Package submodules identify package-manager artifacts and call shared helpers to build component JSON and CSV rows.
- `helpers/helpers_emba_sbom_helpers.sh` contains the central component, property, hash, CPE, and PURL helpers.
- S09 handles binary-level version identification and untracked-file SBOM entries (`modules/S09_firmware_base_version_check.sh:420`, `modules/S09_firmware_base_version_check.sh:542`).
- F15 combines generated component JSON files into the final CycloneDX 1.5 SBOM and converts it to additional formats (`modules/F15_cyclonedx_sbom.sh:171`, `modules/F15_cyclonedx_sbom.sh:199`).

CPE generation locations:

- `helpers/helpers_emba_sbom_helpers.sh:29` builds direct CPE 2.3 identifiers with a caller-provided part.
- `helpers/helpers_emba_sbom_helpers.sh:44` builds CPEs from colon-separated CSV rules.
- `modules/S09_firmware_base_version_check.sh:662` wraps binary CSV rules and currently calls `build_cpe23_from_csv_rule "a"` at `modules/S09_firmware_base_version_check.sh:676`.
- `modules/S06_distribution_identification.sh` uses `build_cpe23_from_csv_rule "o"` for OS/distribution findings.
- S08 submodules typically use `"a"` for application/library package components.

PURL generation locations:

- `helpers/helpers_emba_sbom_helpers.sh:376` builds package PURLs from package type, OS, package name, version, and architecture.
- `modules/S09_firmware_base_version_check.sh:621` builds binary PURLs with `pkg:binary/...`.

CPE and PURL problems to document for a separate task:

- Part selection is caller-dependent. The helper accepts any `lPART` and does not validate that it is one of `a`, `o`, or `h` (`helpers/helpers_emba_sbom_helpers.sh:29`, `helpers/helpers_emba_sbom_helpers.sh:44`). Binary version detection always uses application part `a` (`modules/S09_firmware_base_version_check.sh:676`), while distribution detection uses OS part `o`. That distinction needs explicit rules and tests, not ad hoc caller choices.
- Field count is improved but should stay under test. `build_cpe23_identifier()` emits 13 fields (`helpers/helpers_emba_sbom_helpers.sh:41`), and `build_cpe23_from_csv_rule()` pads/truncates to 13 fields (`helpers/helpers_emba_sbom_helpers.sh:57`, `helpers/helpers_emba_sbom_helpers.sh:63`). The existing `tests/test_cpe_identifiers.sh` verifies field count and sample OS/application CPEs (`tests/test_cpe_identifiers.sh:25`, `tests/test_cpe_identifiers.sh:37`, `tests/test_cpe_identifiers.sh:43`). This test is valuable and should be wired into CI.
- Colon escaping and normalization are incomplete. Perl CPAN handles `::` manually in one submodule, but the shared helpers do not perform full CPE escaping/URI binding validation.
- OS/application distinction should be tied to source type. Linux distributions, firmware OSes, and kernels should not be generated through the generic application path. Kernel components appear as `linux_kernel_linux_kernel_*.json` in downstream lookup (`modules/S26_kernel_vuln_verifier.sh:158`), so the CPE rules should be explicit.
- PURL construction is manual string concatenation and does not clearly encode names, versions, architectures, distro qualifiers, or namespace rules. It should be validated separately without changing current output in this task.
- License inclusion is disabled by default for Dependency-Track compatibility (`helpers/helpers_emba_sbom_helpers.sh:321`), which affects SBOM quality even if it is intentional.

Recommended follow-up: create a dedicated `fix-cpe-generation` branch that adds tests first, documents expected CPE/PURL behavior, then changes helpers and callers in a narrowly reviewed patch.

## 6. GitHub Workflow / CI Assessment

Existing CI and automation:

- `check_project.yml` runs `./check_project.sh` on push/PR and installs shellcheck, Semgrep, and semgrep rules (`.github/workflows/check_project.yml:5`, `.github/workflows/check_project.yml:25`, `.github/workflows/check_project.yml:32`).
- `shellcheck.yml` runs a shellcheck action with `-x -o require-variable-braces` (`.github/workflows/shellcheck.yml:30`).
- `shfmt_checker.yml` runs `shfmt -d -i 2 .` on push/PR (`.github/workflows/shfmt_checker.yml:26`).
- `semgrep.yml` runs Semgrep on push/PR/schedule (`.github/workflows/semgrep.yml:13`, `.github/workflows/semgrep.yml:46`).
- `default_install.yml` schedules a full install and a sample D-Link firmware scan, then checks for core result files (`.github/workflows/default_install.yml:29`, `.github/workflows/default_install.yml:43`, `.github/workflows/default_install.yml:46`).
- `docker-image.yml` builds the Docker image on schedule/workflow dispatch, but push/PR triggers are commented out (`.github/workflows/docker-image.yml:3`, `.github/workflows/docker-image.yml:35`).
- `trivy.yml` scans `embeddedanalyzer/emba:latest` on schedule/workflow dispatch, but push/PR triggers are commented out (`.github/workflows/trivy.yml:7`, `.github/workflows/trivy.yml:42`).
- Several scheduled updater workflows maintain external data sources.

Missing or weak CI checks:

- No direct `bash -n` syntax job on supported Linux Bash.
- `tests/test_cpe_identifiers.sh` exists but is not visibly run by workflows.
- No SBOM schema validation job for a tiny generated or fixture SBOM.
- No CPE/PURL validation job beyond the standalone CPE test.
- No scan profile parse validation.
- Docker image build and Trivy are not PR checks today.
- The scheduled install scan is useful but expensive and owner-gated; it is not a lightweight PR regression test.

Safe CI roadmap:

1. Add a lightweight `bash -n` job using Ubuntu's Bash over tracked shell files.
2. Run `tests/test_cpe_identifiers.sh` in CI.
3. Add scan profile syntax checks with `bash -n scan-profiles/*.emba` or a safer profile validation helper.
4. Add a small SBOM fixture validation job that checks JSON validity, CycloneDX schema compatibility, CPE field counts, and PURL shape.
5. Add a smoke scan using a tiny synthetic filesystem fixture and a minimal scan profile.
6. Add optional PR Docker build only for Docker-related file changes.
7. Keep full install and real firmware scan scheduled or manually triggered until runtime is predictable.

## 7. Code Quality and Maintainability Assessment

The codebase has clear naming conventions and module grouping, but most modules communicate through exported globals and filesystem side effects. That makes changes easy to start but hard to test.

Maintainability concerns:

- Global variables are pervasive. A coarse static search for uppercase assignments/exports found 845 likely global-style assignments under the main shell paths.
- The framework relies on direct `source` of helpers, modules, and scan profiles (`emba:27`, `emba:48`, `emba:471`), so parse/runtime failures can surface late.
- Some helper functions are already the right abstraction but are not used everywhere. `config_find()` and `config_grep()` centralize configured file lookup (`helpers/helpers_emba_path.sh:255`, `helpers/helpers_emba_path.sh:290`), while several modules still do direct recursive scans.
- Some TODO/dirty comments point to known hard-to-maintain code: SBOM duplicate JSON edits (`helpers/helpers_emba_sbom_helpers.sh:230`), P99 cleanup uncertainty (`modules/P99_prepare_analyzer.sh:68`), system emulation cleanup (`modules/L10_system_emulation.sh:1329`), and S09 globals (`modules/S09_firmware_base_version_check.sh:400`).
- Manual JSON assembly and mutation via `jo`, `jq`, `sed`, temp files, and string replacement is fragile (`helpers/helpers_emba_sbom_helpers.sh:209`, `helpers/helpers_emba_sbom_helpers.sh:231`, `modules/F15_cyclonedx_sbom.sh:119`, `modules/F15_cyclonedx_sbom.sh:193`).
- Error handling often uses `|| true` to preserve scan continuity. That is appropriate for firmware analysis but needs structured warning counters so important failures are visible.
- `check_project.sh` is useful, but it mixes discovery, style, shellcheck, Semgrep, JSON checks, and policy checks in one large script. It should be kept but supplemented with small test scripts.

Good patterns to preserve:

- Module prefixes and phase separation.
- Existing `P99_CSV_LOG` inventory usage.
- Existing CI for shellcheck, shfmt, check_project, Semgrep, and scheduled smoke scans.
- Existing CPE helper tests.
- Docker default execution path for isolation.

Places helper functions or indexes would help:

- SBOM duplicate lookup by SHA/name/version.
- SBOM dependency lookup by group/name.
- File queries over `P99_CSV_LOG`.
- Common package archive discovery.
- Common CPE/PURL validation.
- Common warning/error recording that distinguishes expected firmware-analysis misses from tool/runtime problems.

Hard-to-test modules:

- Extraction modules: P50, P55, P60, P65.
- Emulation modules: L10 and helpers under `modules/L10_system_emulation/`.
- Decompilation and binary analyzers: S14, S15, S16, S17, S18.
- Kernel vulnerability verification: S24/S25/S26.
- Large regex module: S99.
- SBOM merge/finalization: S08 and F15.

## 8. Testing Strategy

Minimal shell module testing should start without changing runtime behavior:

- Syntax: run `bash -n` with a supported Bash version in CI.
- Unit-style shell tests: source only the functions under test, as `tests/test_cpe_identifiers.sh` does with `sed`/`eval` (`tests/test_cpe_identifiers.sh:9`).
- Fixture-based helper tests: provide tiny fake `P99_CSV_LOG`, `SBOM_LOG_PATH`, and `FIRMWARE_PATH` directories under `tests/fixtures/`.
- Golden-output tests: validate generated component JSON fields for one package manager fixture and one binary fixture.

Minimal regression tests:

- CPE field count and part validation for application, OS, kernel, and invalid part.
- PURL shape tests for Debian, OpenWrt/opkg, npm, PyPI, generic binary, and distro qualifiers.
- SBOM component JSON validity after `build_sbom_json_component_arr()`.
- Duplicate merge behavior in `build_sbom_json_hashes_arr()` using two temporary component files.
- Scan profile parse/source validation in a controlled shell environment.

SBOM validation tests:

- Validate every generated component JSON with `jq` or `json_pp`.
- Validate final SBOM against CycloneDX 1.5 schema.
- Ensure required fields exist: `bomFormat`, `specVersion`, `metadata.component`, `components[]`, `bom-ref`, `name`, `type`.
- Ensure CPE values have 13 fields when present.
- Ensure PURLs do not contain unencoded spaces.
- Ensure dependency references point to known `bom-ref` values or are explicitly marked as no-valid-ref if that behavior remains.

CPE validation tests:

- Keep the existing field-count tests.
- Add tests that OS/distribution detections use part `o`.
- Add tests that application/library/package detections use part `a`.
- Add validation that helper functions reject or normalize invalid part values.
- Add escaping tests for colons, spaces, uppercase/lowercase normalization, wildcard handling, and `NA`/`null`.

Smoke tests:

- Tiny extracted Linux-like filesystem directory with `/etc/os-release`, `/bin/busybox` placeholder, one config file, one package metadata file, and one script.
- Tiny firmware archive that exercises P02/P65 without requiring full emulation.
- Optional real firmware scheduled test can stay in `default_install.yml`, but PR tests should be smaller.

## 9. Prioritized Roadmap

Quick wins:

- Add `bash -n` CI on Ubuntu Bash for tracked shell files.
- Add CI execution of `tests/test_cpe_identifiers.sh`.
- Document supported host shell/platform requirements explicitly: native Linux/Kali/Ubuntu or Docker; macOS/ARM64 host mode unsupported.
- Add scan profile validation.
- Add a command to list module/profile metadata without scanning firmware.
- Add module timing summaries to logs.
- Add a small fixture directory under `tests/fixtures/` for SBOM helper tests.

Medium-risk improvements:

- Build an SBOM component index file during component creation and use it in duplicate/dependency lookup.
- Introduce helper functions for common `P99_CSV_LOG` queries.
- Replace selected package archive `find ... md5sum` scans with inventory-based queries where behavior is equivalent.
- Add CycloneDX schema validation in CI.
- Improve CPE/PURL tests and then fix CPE part selection in a dedicated branch.
- Add warning counters for tool failures currently hidden by `|| true`.
- Split `check_project.sh` into callable subcommands while preserving default behavior.

Major refactors:

- Isolate scan state into explicit state files or namespaced variables instead of broad exported globals.
- Define a stable internal schema for `P99_CSV_LOG`, S08 CSV, and SBOM component intermediates.
- Rework extraction orchestration so each extraction pass updates a shared inventory incrementally.
- Move complex JSON assembly to a dedicated, tested helper tool only after output compatibility is locked down.
- Revisit Docker security posture after emulation/extraction requirements are better separated.

Research/experimental ideas:

- Profile representative scans with `strace`, shell timing, and module-level counters.
- Evaluate a small SQLite or TSV index for firmware file inventory and SBOM components.
- Test rootless or reduced-privilege Docker profiles for non-emulation scans.
- Investigate deterministic Docker images instead of `kali-rolling`.
- Explore optional parallelization limits based on I/O pressure rather than only CPU count.

## 10. Suggested Branches / Follow-Up Tasks

Suggested branch: `codex/improve-ci-shellcheck`

Task prompt: Add lightweight CI validation for Bash syntax on Ubuntu Bash and run the existing CPE identifier test. Do not change runtime code. Preserve existing workflows and add only focused validation steps.

Suggested branch: `codex/add-sbom-validation`

Task prompt: Add tests that validate generated SBOM component JSON and final CycloneDX JSON against a small fixture. Do not change the SBOM output format. Start with fixtures and validation scripts only.

Suggested branch: `codex/fix-cpe-generation`

Task prompt: Write failing tests for CPE part values, field count, escaping, OS/application distinction, and invalid part handling. Then update CPE helper/callers narrowly while preserving existing SBOM format.

Suggested branch: `codex/reduce-repeated-filesystem-scans`

Task prompt: Inventory modules that still rescan firmware trees despite equivalent `P99_CSV_LOG` data. Replace one low-risk package/archive discovery path with an inventory-backed helper and prove output equivalence with a fixture.

Suggested branch: `codex/docker-compatibility-cleanup`

Task prompt: Document supported Docker/host platforms and add preflight checks for Compose v2, image tag consistency, and unsupported macOS/ARM64 host execution. Do not change runtime behavior unless the change is a warning-only improvement.

Suggested branch: `codex/scan-profile-review`

Task prompt: Add scan profile validation that detects syntax errors and unknown module references without changing profile semantics. Run it in CI.

Suggested branch: `codex/sbom-component-index`

Task prompt: Add a generated SBOM component index keyed by component name, version, group, SHA-512, and bom-ref. Use it only in one duplicate/dependency lookup path first, and compare output against current behavior.

Suggested branch: `codex/extraction-smoke-fixtures`

Task prompt: Create tiny fixture firmware/filesystem inputs and smoke tests for P02/P60/P65/P99 preparation behavior. Avoid real firmware downloads in PR CI.

## Commands Run During Assessment

Repository inventory and status:

```console
sed -n '1,240p' /Users/linustessendorf/.codex/attachments/e6294b9c-1c84-428c-baf3-93a4c759478a/goal-objective.md
pwd
git status --short
rg --files | sed -n '1,240p'
find . -maxdepth 2 -type d | sort | sed -n '1,240p'
find .github/workflows -maxdepth 1 -type f -print | sort
find modules helpers installer scan-profiles config tests -maxdepth 2 -type f | sort | wc -l
find modules -maxdepth 1 -type f -name '*.sh' | sort | wc -l
find modules/S08_main_package_sbom_modules -maxdepth 1 -type f -name '*.sh' | sort | wc -l
```

Source inspection:

```console
sed -n '1,220p' emba
sed -n '220,520p' emba
sed -n '520,980p' emba
sed -n '1,260p' installer.sh
sed -n '1,260p' helpers/helpers_emba_sbom_helpers.sh
rg -n "build_cpe23|cpe:|purl|purl_type|bom-ref|CycloneDX|cyclonedx|SBOM|CPE|PURL" helpers modules tests config -g '*.sh' -g '*.cfg' -g '*.md'
rg -n "find .*\\$\\{?FIRMWARE|find .*\\$\\{?LOG_DIR|grep -R|grep -r|grep -I[rlq]?|md5sum|sha256sum|sha512sum|strings|file -b|sort -u|du -|stat " modules helpers emba installer.sh -g '*.sh'
rg -n "docker|compose|Ubuntu|Debian|Kali|RHEL|x86_64|ssse3|WSL|macOS|arm64|aarch64|uname -m|/proc|sudo|EUID" README.md Dockerfile docker-compose.yml installer.sh installer helpers modules .github/workflows -g '*.*'
rg -n "shellcheck|shfmt|bash -n|bats|pytest|test|docker build|trivy|semgrep|check_project|on:|pull_request|push:" .github/workflows check_project.sh tests README.md CONTRIBUTING.md
nl -ba modules/F15_cyclonedx_sbom.sh | sed -n '1,220p'
nl -ba modules/S08_main_package_sbom.sh | sed -n '1,260p'
nl -ba modules/S09_firmware_base_version_check.sh | sed -n '420,720p'
nl -ba helpers/helpers_emba_sbom_helpers.sh | sed -n '1,430p'
nl -ba helpers/helpers_emba_prepare.sh | sed -n '450,760p'
nl -ba modules/P99_prepare_analyzer.sh | sed -n '1,220p'
nl -ba helpers/helpers_emba_path.sh | sed -n '1,330p'
nl -ba emba | sed -n '1,180p' && nl -ba emba | sed -n '360,760p' && nl -ba emba | sed -n '760,1060p'
nl -ba modules/P02_firmware_bin_file_check.sh | sed -n '1,280p'
nl -ba modules/P50_binwalk_extractor.sh | sed -n '1,260p'
nl -ba modules/P55_unblob_extractor.sh | sed -n '1,260p'
nl -ba modules/P60_deep_extractor.sh | sed -n '1,220p'
nl -ba modules/P65_package_extractor.sh | sed -n '1,280p'
nl -ba Dockerfile | sed -n '1,220p'
nl -ba docker-compose.yml | sed -n '1,220p'
nl -ba installer.sh | sed -n '180,460p'
nl -ba helpers/helpers_emba_dependency_check.sh | sed -n '160,390p' && nl -ba helpers/helpers_emba_dependency_check.sh | sed -n '460,590p'
nl -ba CONTRIBUTING.md | sed -n '20,105p'
nl -ba .github/workflows/check_project.yml | sed -n '1,120p'
nl -ba .github/workflows/shellcheck.yml | sed -n '1,120p'
nl -ba .github/workflows/shfmt_checker.yml | sed -n '1,120p'
nl -ba .github/workflows/default_install.yml | sed -n '1,110p'
nl -ba .github/workflows/docker-image.yml | sed -n '1,100p'
nl -ba .github/workflows/trivy.yml | sed -n '1,100p'
nl -ba .github/workflows/semgrep.yml | sed -n '1,90p'
nl -ba tests/test_cpe_identifiers.sh | sed -n '1,130p'
rg -n "TODO|Todo|FIXME|dirty|ugly|deprecated|not working|currently.*not|should.*check|need to check" emba helpers installer modules Dockerfile docker-compose.yml README.md CONTRIBUTING.md | sed -n '1,200p'
```

Validation and local tool checks:

```console
bash -n emba installer.sh check_project.sh helpers/*.sh installer/*.sh modules/*.sh modules/S08_main_package_sbom_modules/*.sh modules/L10_system_emulation/*.sh tests/*.sh
command -v shellcheck
command -v shfmt
command -v semgrep
bash tests/test_cpe_identifiers.sh
find . -path ./.git -prune -o -type f \( -name '*.sh' -o -name 'emba' -o -name 'installer.sh' -o -name 'check_project.sh' \) -print | wc -l
bash --version | sed -n '1,2p'
for f in emba installer.sh check_project.sh helpers/*.sh installer/*.sh modules/*.sh modules/S08_main_package_sbom_modules/*.sh modules/L10_system_emulation/*.sh tests/*.sh; do bash -n "$f" >/tmp/emba_bash_n_one.out 2>&1; rc=$?; if [ $rc -ne 0 ]; then printf '%s\n' "== $f =="; sed -n '1,5p' /tmp/emba_bash_n_one.out; fi; done
for tool in shellcheck shfmt semgrep jq jo cyclonedx docker; do printf '%s: ' "$tool"; command -v "$tool" || true; done
find modules helpers installer tests -type f -name '*.sh' | wc -l
command -v bash
ls -l /opt/homebrew/bin/bash /usr/local/bin/bash 2>/dev/null
git ls-files '*.sh' 'emba' 'installer.sh' 'check_project.sh' | wc -l
rg -n "\[\[.*-v |\|&|&>>|declare -n|local -n|mapfile|readarray" emba installer.sh check_project.sh helpers installer modules tests -g '*.sh'
printf 'tracked shell files: '; git ls-files '*.sh' 'emba' 'installer.sh' 'check_project.sh' | wc -l
printf 'modules top-level: '; find modules -maxdepth 1 -type f -name '*.sh' | wc -l
printf 'S08 submodules: '; find modules/S08_main_package_sbom_modules -maxdepth 1 -type f -name '*.sh' | wc -l
printf 'helpers: '; find helpers -maxdepth 1 -type f -name '*.sh' | wc -l
printf 'installer modules: '; find installer -maxdepth 1 -type f -name '*.sh' | wc -l
printf 'scan profiles: '; find scan-profiles -maxdepth 1 -type f -name '*.emba' | wc -l
printf 'workflows: '; find .github/workflows -maxdepth 1 -type f -name '*.yml' | wc -l
printf 'find occurrences: '; rg -o '\bfind\b' emba helpers installer modules check_project.sh | wc -l
printf 'grep occurrences: '; rg -o '\bgrep\b' emba helpers installer modules check_project.sh | wc -l
printf 'md5sum occurrences: '; rg -o '\bmd5sum\b' emba helpers installer modules check_project.sh | wc -l
printf 'sha256sum occurrences: '; rg -o '\bsha256sum\b' emba helpers installer modules check_project.sh | wc -l
printf 'sha512sum occurrences: '; rg -o '\bsha512sum\b' emba helpers installer modules check_project.sh | wc -l
printf 'file command occurrences: '; rg -o '\bfile\b' emba helpers installer modules check_project.sh | wc -l
printf 'strings occurrences: '; rg -o '\bstrings\b' emba helpers installer modules check_project.sh | wc -l
rg -n '^export [A-Z0-9_]+=|^[A-Z0-9_]+=|^[[:space:]]+[A-Z0-9_]+=' modules helpers emba installer.sh -g '*.sh' | wc -l
```

Validation results:

- `bash tests/test_cpe_identifiers.sh` passed with exit code 0.
- `shellcheck`, `shfmt`, `semgrep`, `jo`, and `cyclonedx` were not available in the local environment.
- `jq` was available at `/usr/bin/jq`.
- `docker` was available at `/usr/local/bin/docker`.
- `bash -n` with local `/bin/bash` failed because the machine uses GNU Bash 3.2 on macOS/ARM64, which does not support several Bash features used by EMBA. This should be treated as a host compatibility finding, not as evidence that Ubuntu CI syntax checks will fail.

