#!/bin/bash -p

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

setup() {
  setup_emba_test_env
  # shellcheck source=modules/S06_distribution_identification.sh
  source "${MOD_DIR}/S06_distribution_identification.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "run_distri_identifier_pattern executes config grep command" {
  local lID_FILE="${TMP_DIR}/os-release"
  cat >"${lID_FILE}" <<'EOF'
ID=openwrt
VERSION_ID=23.05.2
EOF

  local lOUT
  lOUT="$(run_distri_identifier_pattern "grep -a -o -E -e '^ID=.*' -e '^VERSION_ID=.*'" "${lID_FILE}")"

  [[ "${lOUT}" == *"ID=openwrt"* ]]
  [[ "${lOUT}" == *"VERSION_ID=23.05.2"* ]]
}

@test "normalize_distri_identifier applies configured transform pipeline" {
  local lOUT
  lOUT="$(normalize_distri_identifier "ID=openwrt VERSION_ID=23.05.2" "sed 's/VERSION_ID=//g' | sed 's/ID=//g'")"

  [ "${lOUT}" = "openwrt 23.05.2" ]
}
