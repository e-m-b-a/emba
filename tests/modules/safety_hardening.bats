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
  export ARCHIVE_PATH="${TMP_DIR}"
  export TAPDEV_0="tap0_test"
  export IMAGE_NAME="image_test"
  export LOG_PATH_MODULE="${LOG_DIR}"
  # shellcheck source=helpers/helpers_emba_system_emulation.sh
  source "${HELP_DIR}/helpers_emba_system_emulation.sh"
  # shellcheck source=helpers/helpers_emba_helpers.sh
  source "${HELP_DIR}/helpers_emba_helpers.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "write_script_exec executes command without eval dependency" {
  local lOUT_FILE="${TMP_DIR}/write_script_exec.out"
  local lSCRIPT_FILE="${TMP_DIR}/run.sh"

  write_script_exec "printf 'ok' > \"${lOUT_FILE}\"" "${lSCRIPT_FILE}" 1

  local lRETRIES=0
  while [[ ! -f "${lOUT_FILE}" && "${lRETRIES}" -lt 20 ]]; do
    sleep 0.1
    lRETRIES=$((lRETRIES + 1))
  done

  [ -f "${lOUT_FILE}" ]
  [ "$(cat "${lOUT_FILE}")" = "ok" ]
  grep -q "printf 'ok'" "${lSCRIPT_FILE}"
}

@test "get_csv_rule keeps shell pipeline behavior" {
  local lRULE=""

  lRULE="$(get_csv_rule "OpenWrt 23.05.2" "sed -E 's/(OpenWrt) ([0-9.]+)/:\\1:openwrt:\\2/'")"

  [ "${lRULE}" = ":OpenWrt:openwrt:23.05.2" ]
}
