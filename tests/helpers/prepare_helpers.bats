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
  source "${HELP_DIR}/helpers_emba_prepare.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "convert_timeformat converts days to seconds" {
  result="$(convert_timeformat "2d")"
  [ "${result}" = "$((2 * 24 * 3600))" ]
}

@test "convert_timeformat converts hours to seconds" {
  result="$(convert_timeformat "5h")"
  [ "${result}" = "$((5 * 3600))" ]
}

@test "convert_timeformat converts minutes to seconds" {
  result="$(convert_timeformat "30m")"
  [ "${result}" = "$((30 * 60))" ]
}

@test "convert_timeformat returns seconds unchanged" {
  result="$(convert_timeformat "45s")"
  [ "${result}" = "45" ]
}

@test "convert_timeformat handles combined format (days)" {
  result="$(convert_timeformat "1d")"
  [ "${result}" = "86400" ]
}

@test "convert_timeformat handles empty input" {
  result="$(convert_timeformat "")"
  [ -z "${result}" ]
}

@test "convert_timeformat handles plain number as seconds" {
  result="$(convert_timeformat "60")"
  [ "${result}" = "60" ]
}

@test "convert_timeformat handles zero" {
  result="$(convert_timeformat "0s")"
  [ "${result}" = "0" ]
}
