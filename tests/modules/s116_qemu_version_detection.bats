#!/usr/bin/env bats

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#

load ../setup.bash

module_log_init() {
  MODULE_LOG_FILE="${LOG_DIR}/s116_qemu_version_detection.txt"
  LOG_FILE="${MODULE_LOG_FILE}"
}

module_end_log() {
  LAST_MODULE_END_LOG_RESULT="${1}:${2}"
}

module_title() { :; }
pre_module_reporter() { :; }
module_wait() { :; }
print_output() { :; }
print_ln() { :; }
store_kill_pids() { :; }
strip_color_codes() { printf "%s\n" "${1:-}"; }
wait_for_pid() {
  local lPID=""
  for lPID in "$@"; do
    wait "${lPID}"
  done
}

version_parsing_logging() {
  printf "%s;%s;%s;%s;%s\n" "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" >>"${VERSION_LOG_CAPTURE_FILE}"
  return 0
}

setup() {
  setup_emba_test_env
  # shellcheck source=modules/S116_qemu_version_detection.sh
  source "${MOD_DIR}/S116_qemu_version_detection.sh"

  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export S09_CSV_LOG="${CSV_DIR}/s09_firmware_base_version_check.csv"
  export VERSION_LOG_CAPTURE_FILE="${TMP_DIR}/s116_version_parsing_calls.log"
  MODULES_EXPORTED=()
  export QEMULATION=1
  export RTOS=0
  export MAIN_LOG_FILE="emba.log"
}

teardown() {
  teardown_emba_test_env
}

@test "S116 exits cleanly when QEMULATION is disabled" {
  export QEMULATION=0
  LAST_MODULE_END_LOG_RESULT=""

  S116_qemu_version_detection

  [ "${LAST_MODULE_END_LOG_RESULT}" = "S116_qemu_version_detection:0" ]
  [ ! -f "${VERSION_LOG_CAPTURE_FILE}" ]
}

@test "version_detection_thread reports normal-mode matches from S115 logs" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_run_1.txt" <<'EOF'
Emulating binary: /usr/bin/busybox
BusyBox v1.36.1
EOF
  cat >"${P99_CSV_LOG}" <<'EOF'
entry;/usr/bin/busybox;3;4;5;6;7;ELF 64-bit;deadbeef
EOF
  cat >"${TMP_DIR}/s116_rule_normal.json" <<'EOF'
{
  "parsing_mode": ["normal"],
  "identifier": "busybox",
  "licenses": ["GPL-2.0"],
  "product_names": ["busybox"],
  "vendor_names": ["busybox"],
  "version_extraction": ["sed -E 's/.*v([0-9.]+)/\\1/'"],
  "grep_commands": ["BusyBox v[0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/usr/bin/busybox"]
}
EOF

  version_detection_thread "${TMP_DIR}/s116_rule_normal.json"

  [ -f "${VERSION_LOG_CAPTURE_FILE}" ]
  grep -q "S116_qemu_version_detection" "${VERSION_LOG_CAPTURE_FILE}"
  grep -q "BusyBox v1.36.1" "${VERSION_LOG_CAPTURE_FILE}"
  grep -q "/usr/bin/busybox" "${VERSION_LOG_CAPTURE_FILE}"
}

@test "version_detection_thread reports strict-mode matches for affected binary logs" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_busybox_1.txt" <<'EOF'
Emulating binary: /usr/bin/busybox
BusyBox v1.35.0
EOF
  cat >"${P99_CSV_LOG}" <<'EOF'
entry;/usr/bin/busybox;3;4;5;6;7;ELF 64-bit;cafebabe
EOF
  cat >"${TMP_DIR}/s116_rule_strict.json" <<'EOF'
{
  "parsing_mode": ["strict"],
  "identifier": "busybox_strict",
  "licenses": ["GPL-2.0"],
  "product_names": ["busybox"],
  "vendor_names": ["busybox"],
  "version_extraction": ["sed -E 's/.*v([0-9.]+)/\\1/'"],
  "strict_grep_commands": ["BusyBox v[0-9]+\\.[0-9]+\\.[0-9]+"],
  "grep_commands": ["BusyBox v[0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/usr/bin/busybox"]
}
EOF

  version_detection_thread "${TMP_DIR}/s116_rule_strict.json"

  [ -f "${VERSION_LOG_CAPTURE_FILE}" ]
  grep -q "BusyBox v1.35.0" "${VERSION_LOG_CAPTURE_FILE}"
  grep -q "busybox_strict" "${VERSION_LOG_CAPTURE_FILE}"
}

@test "version_detection_thread strict mode ignores non-affected binary logs" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_dropbear_1.txt" <<'EOF'
Emulating binary: /usr/bin/dropbear
BusyBox v1.35.0
EOF
  cat >"${P99_CSV_LOG}" <<'EOF'
entry;/usr/bin/dropbear;3;4;5;6;7;ELF 64-bit;beadfeed
EOF
  cat >"${TMP_DIR}/s116_rule_strict_negative.json" <<'EOF'
{
  "parsing_mode": ["strict"],
  "identifier": "busybox_strict",
  "licenses": ["GPL-2.0"],
  "product_names": ["busybox"],
  "vendor_names": ["busybox"],
  "version_extraction": ["sed -E 's/.*v([0-9.]+)/\\1/'"],
  "strict_grep_commands": ["BusyBox v[0-9]+\\.[0-9]+\\.[0-9]+"],
  "grep_commands": ["BusyBox v[0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/usr/bin/busybox"]
}
EOF

  version_detection_thread "${TMP_DIR}/s116_rule_strict_negative.json"

  if [[ -f "${VERSION_LOG_CAPTURE_FILE}" ]]; then
    [ ! -s "${VERSION_LOG_CAPTURE_FILE}" ]
  fi
}

@test "version_detection_thread does not match a binary whose path only starts with the emulated one" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_python3_1.txt" <<'EOT'
Emulating binary: /usr/bin/python3
Python 3.9.2
EOT
  # /usr/bin/python3.11 sorts before /usr/bin/python3; (C and UTF-8 locales) and would be taken by a
  # prefix match
  cat >"${P99_CSV_LOG}" <<'EOT'
entry;/usr/bin/python3.11;3;4;5;6;7;ELF 64-bit;py311000
entry;/usr/bin/python3;3;4;5;6;7;ELF 64-bit;py300000
EOT
  cat >"${TMP_DIR}/s116_rule_prefix.json" <<'EOT'
{
  "parsing_mode": ["normal"],
  "identifier": "python",
  "licenses": ["unknown"],
  "product_names": ["python"],
  "vendor_names": ["python"],
  "version_extraction": ["sed -E 's/Python ([0-9.]+)/\\1/'"],
  "grep_commands": ["Python [0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/usr/bin/python3"]
}
EOT

  version_detection_thread "${TMP_DIR}/s116_rule_prefix.json"

  [ -f "${VERSION_LOG_CAPTURE_FILE}" ]
  grep -q "/usr/bin/python3;3;4;5;6;7;ELF 64-bit;py300000" "${VERSION_LOG_CAPTURE_FILE}"
  run grep -q "py311000" "${VERSION_LOG_CAPTURE_FILE}"
  [ "${status}" -ne 0 ]
}

@test "version_detection_thread prefers the entry with a column starting with ELF" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_foo_1.txt" <<'EOT'
Emulating binary: /usr/bin/foo
foo version 1.2.3
EOT
  # both entries contain ELF after the path, only the second one has a column starting with it
  cat >"${P99_CSV_LOG}" <<'EOT'
entry;/usr/bin/foo;3;4;5;6;7;ASCII text, not an ELF;text0000
entry;/usr/bin/foo;3;4;5;6;7;ELF 64-bit;elf00000
EOT
  cat >"${TMP_DIR}/s116_rule_elf.json" <<'EOT'
{
  "parsing_mode": ["normal"],
  "identifier": "foo",
  "licenses": ["unknown"],
  "product_names": ["foo"],
  "vendor_names": ["foo"],
  "version_extraction": ["sed -E 's/.* ([0-9.]+)/\\1/'"],
  "grep_commands": ["foo version [0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/usr/bin/foo"]
}
EOT

  version_detection_thread "${TMP_DIR}/s116_rule_elf.json"

  [ -f "${VERSION_LOG_CAPTURE_FILE}" ]
  grep -q "ELF 64-bit;elf00000" "${VERSION_LOG_CAPTURE_FILE}"
  run grep -q "text0000" "${VERSION_LOG_CAPTURE_FILE}"
  [ "${status}" -ne 0 ]
}

@test "version_detection_thread does not take ELF in the path itself as an ELF entry" {
  mkdir -p "${LOG_DIR}/s115_usermode_emulator"
  cat >"${LOG_DIR}/s115_usermode_emulator/qemu_tmp_bar_1.txt" <<'EOT'
Emulating binary: /opt/ELFtools/bin/bar
bar version 4.5.6
EOT
  # ELF is only in the path of the first entry, the second one has a column starting with ELF;
  # the first one sorts first and would be taken if ELF were searched anywhere in the line
  cat >"${P99_CSV_LOG}" <<'EOT'
entry;/opt/ELFtools/bin/bar;3;4;5;6;7;ASCII text;text0000
entry;/opt/ELFtools/bin/bar;3;4;5;6;7;ELF 64-bit;elf00000
EOT
  cat >"${TMP_DIR}/s116_rule_elf_path.json" <<'EOT'
{
  "parsing_mode": ["normal"],
  "identifier": "bar",
  "licenses": ["unknown"],
  "product_names": ["bar"],
  "vendor_names": ["bar"],
  "version_extraction": ["sed -E 's/.* ([0-9.]+)/\\1/'"],
  "grep_commands": ["bar version [0-9]+\\.[0-9]+\\.[0-9]+"],
  "affected_paths": ["/opt/ELFtools/bin/bar"]
}
EOT

  version_detection_thread "${TMP_DIR}/s116_rule_elf_path.json"

  [ -f "${VERSION_LOG_CAPTURE_FILE}" ]
  grep -q "ELF 64-bit;elf00000" "${VERSION_LOG_CAPTURE_FILE}"
  run grep -q "text0000" "${VERSION_LOG_CAPTURE_FILE}"
  [ "${status}" -ne 0 ]
}
