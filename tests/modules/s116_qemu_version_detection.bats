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
  LOG_FILE="${LOG_DIR}/s116_qemu_version_detection.txt"
}

module_end_log() {
  LAST_MODULE_END_LOG="${1}:${2}"
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
  export MODULES_EXPORTED=()
  export QEMULATION=1
  export RTOS=0
  export MAIN_LOG_FILE="emba.log"
}

teardown() {
  teardown_emba_test_env
}

@test "S116 exits cleanly when QEMULATION is disabled" {
  export QEMULATION=0
  LAST_MODULE_END_LOG=""

  S116_qemu_version_detection

  [ "${LAST_MODULE_END_LOG}" = "S116_qemu_version_detection:0" ]
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
