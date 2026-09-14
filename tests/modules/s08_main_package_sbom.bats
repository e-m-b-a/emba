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

@test "clean_package_details normalizes spaces punctuation and case"
{
  local lRESULT=""
  lRESULT="$(clean_package_details " OpenSSL (FIPS), Inc. ")"
  [ "${lRESULT}" = "openssl_fips._inc." ]
}

@test "clean_package_details removes brackets and slashes" {
  local lRESULT=""
  lRESULT="$(clean_package_details "lib[crypto]/ssl")"
  [ "${lRESULT}" = "libcryptossl" ]
}

@test "clean_package_details collapses repeated underscores" {
  local lRESULT=""
  lRESULT="$(clean_package_details "A__B   C")"
  [ "${lRESULT}" = "a_b_c" ]
}

@test "clean_package_details strips quotes" {
  local lRESULT=""
  lRESULT="$(clean_package_details "\"Quoted\"")"
  [ "${lRESULT}" = "quoted" ]
}

@test "clean_package_details removes non printable bytes" {
  local lINPUT=$'abc\x01def'
  local lRESULT=""
  lRESULT="$(clean_package_details "${lINPUT}")"
  [ "${lRESULT}" = "abcdef" ]
}

@test "clean_package_versions keeps plain semantic version" {
  local lRESULT=""
  lRESULT="$(clean_package_versions "1.2.3")"
  [ "${lRESULT}" = "1.2.3" ]
}

@test "clean_package_versions strips kali suffix patterns" {
  local lRESULT=""
  lRESULT="$(clean_package_versions "1.2.3-0kali1bla")"
  [ "${lRESULT}" = "1.2.3" ]
}

@test "clean_package_versions strips ubuntu suffix patterns" {
  local lRESULT=""
  lRESULT="$(clean_package_versions "1.2.3-0ubuntu1.2")"
  [ "${lRESULT}" = "1.2.3" ]
}

@test "clean_package_versions strips epoch prefix" {
  local lRESULT=""
  lRESULT="$(clean_package_versions "2:1.4.5")"
  [ "${lRESULT}" = "1.4.5" ]
}

@test "clean_package_versions rewrites comma as dot" {
  local lRESULT=""
  lRESULT="$(clean_package_versions "1.2.3,4")"
  [ "${lRESULT}" = "1.2.3.4" ]
}
