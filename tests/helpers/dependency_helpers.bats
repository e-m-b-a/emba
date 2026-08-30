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
  source "${HELP_DIR}/helpers_emba_dependency_check.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "version formats single component" {
  result="$(version "1")"
  [ "${result}" = "1000000000" ]
}

@test "version formats two components" {
  result="$(version "1.2")"
  [ "${result}" = "1002000000" ]
}

@test "version formats three components" {
  result="$(version "1.2.3")"
  [ "${result}" = "1002003000" ]
}

@test "version formats four components" {
  result="$(version "1.2.3.4")"
  [ "${result}" = "1002003004" ]
}

@test "version handles leading zeros" {
  result="$(version "0.1.0")"
  [ "${result}" = "0001000000" ]
}

@test "version handles double digits" {
  result="$(version "10.20.30")"
  [ "${result}" = "10020030000" ]
}

@test "version sorts correctly (lower < higher)" {
  local v1 v2
  v1="$(version "2.1.0")"
  v2="$(version "10.0.0")"
  [ "${v1}" -lt "${v2}" ]
}

@test "version sorts correctly (equal)" {
  local v1 v2
  v1="$(version "2.1.0")"
  v2="$(version "2.1.0")"
  [ "${v1}" -eq "${v2}" ]
}

@test "check_emba_version detects current version" {
  # shellcheck disable=SC2030,SC2031
  export EMBA_VERSION="2.0.3"
  run check_emba_version "2.0.3"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"ok"* ]]
}

@test "check_emba_version detects available update" {
  # shellcheck disable=SC2030,SC2031
  export EMBA_VERSION="2.0.3"
  run check_emba_version "9.9.9"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Updates available"* ]]
}

@test "check_emba_version handles empty input" {
  run check_emba_version ""
  [ "${status}" -eq 0 ]
}
