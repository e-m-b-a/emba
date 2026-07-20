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

# shellcheck disable=SC1091

load ../setup.bash

setup() {
  setup_emba_test_env
  export DEBUG_SCRIPT=0
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "load_strict_mode_settings enables shell strict mode" {
  run load_strict_mode_settings
  [ "${status}" -eq 0 ]
}

@test "enable_strict_mode does nothing when STRICT_MODE=0" {
  run enable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode does nothing when STRICT_MODE=0" {
  run disable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode with lPRINTER=0 suppresses output" {
  run disable_strict_mode 1 0
  [ "${status}" -eq 0 ]
}
