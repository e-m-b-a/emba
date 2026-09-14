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

setup() {
  setup_emba_test_env
  # shellcheck source=helpers/helpers_emba_print.sh
  source "${HELP_DIR}/helpers_emba_print.sh"
  # shellcheck source=modules/S08_main_package_sbom.sh
  source "${MOD_DIR}/S08_main_package_sbom.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "clean_package_details normalizes spaces punctuation and case" {
  result="$(clean_package_details " OpenSSL (FIPS), Inc. ")"
  [ "${result}" = "openssl_fips._inc." ]
}

@test "clean_package_details removes brackets and slashes" {
  result="$(clean_package_details "lib[crypto]/ssl")"
  [ "${result}" = "libcryptossl" ]
}

@test "clean_package_details collapses repeated underscores" {
  result="$(clean_package_details "A__B   C")"
  [ "${result}" = "a_b_c" ]
}

@test "clean_package_details strips quotes" {
  result="$(clean_package_details "\"Quoted\"")"
  [ "${result}" = "quoted" ]
}

@test "clean_package_details removes non printable bytes" {
  local lINPUT=$'abc\x01def'
  result="$(clean_package_details "${lINPUT}")"
  [ "${result}" = "abcdef" ]
}

@test "clean_package_versions keeps plain semantic version" {
  result="$(clean_package_versions "1.2.3")"
  [ "${result}" = "1.2.3" ]
}

@test "clean_package_versions strips kali suffix patterns" {
  result="$(clean_package_versions "1.2.3-0kali1bla")"
  [ "${result}" = "1.2.3" ]
}

@test "clean_package_versions strips ubuntu suffix patterns" {
  result="$(clean_package_versions "1.2.3-0ubuntu1.2")"
  [ "${result}" = "1.2.3" ]
}

@test "clean_package_versions strips epoch prefix" {
  result="$(clean_package_versions "2:1.4.5")"
  [ "${result}" = "1.4.5" ]
}

@test "clean_package_versions rewrites comma as dot" {
  result="$(clean_package_versions "1.2.3,4")"
  [ "${result}" = "1.2.3.4" ]
}
