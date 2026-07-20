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
  source "${HELP_DIR}/helpers_emba_html_generator.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "strip_color_tags removes ANSI color codes" {
  result="$(strip_color_tags $'\033[0;32mhello\033[0m')"
  [ "${result}" = "hello" ]
}

@test "strip_color_tags handles plain text" {
  result="$(strip_color_tags "plain text")"
  [ "${result}" = "plain text" ]
}

@test "strip_color_tags removes multiple color codes" {
  result="$(strip_color_tags $'\033[0;31mERROR\033[0m: \033[0;32mOK\033[0m')"
  [ "${result}" = "ERROR: OK" ]
}

@test "strip_color_tags removes control characters" {
  result="$(strip_color_tags $'line1\007line2')"
  [ "${result}" = "line1line2" ]
}

@test "strip_color_tags handles empty input" {
  result="$(strip_color_tags "")"
  [ -z "${result}" ]
}

@test "strip_color_tags handles bold ANSI codes" {
  result="$(strip_color_tags $'\033[1mBOLD\033[0m')"
  [ "${result}" = "BOLD" ]
}
