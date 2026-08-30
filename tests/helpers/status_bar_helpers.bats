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
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_status_bar.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "repeat_char repeats single char" {
  result="$(repeat_char "-" 5)"
  [ "${result}" = "-----" ]
}

@test "repeat_char repeats multiple chars" {
  result="$(repeat_char "=>" 3)"
  [ "${result}" = "=>=>=>" ]
}

@test "repeat_char handles zero count" {
  result="$(repeat_char "-" 0)"
  [ -z "${result}" ]
}

@test "repeat_char handles empty char" {
  result="$(repeat_char "" 5)"
  [ -z "${result}" ]
}

@test "repeat_char handles large count" {
  result="$(repeat_char "x" 100)"
  [ "${#result}" -eq 100 ]
}
