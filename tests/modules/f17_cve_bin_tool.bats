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
  # shellcheck source=modules/F17_cve_bin_tool.sh
  source "${MOD_DIR}/F17_cve_bin_tool.sh"

  unset F17_CHECK_ADDITIONAL_VERSIONS
  # lua found as 5.1.5 in the binary and 5.1.5-3 in the package, merged into one component
  export SBOM_ENTRY_LUA='{"name":"lua","version":"5.1.5","properties":[{"name":"EMBA:sbom:1:product_name","value":"lua"},{"name":"EMBA:sbom:version:7:additional_version_identified","value":"5.1.5-3"},{"name":"EMBA:sbom:version:9:additional_version_identified","value":"5.1.5-3"}]}'
  # cve-bin-tool csv output: vendor,product,version,cve_number,...
  export CVE_BIN_TOOL_ROW="lua,lua,5.1.5-3,CVE-2014-5461,HIGH"
}

teardown() {
  teardown_emba_test_env
}

@test "get_additional_versions returns nothing without F17_CHECK_ADDITIONAL_VERSIONS" {
  run get_additional_versions "${SBOM_ENTRY_LUA}"

  [ "${status}" -eq 0 ]
  [ -z "${output}" ]
}

@test "get_additional_versions returns the merged versions once with F17_CHECK_ADDITIONAL_VERSIONS=1" {
  export F17_CHECK_ADDITIONAL_VERSIONS=1

  run get_additional_versions "${SBOM_ENTRY_LUA}"

  [ "${status}" -eq 0 ]
  [ "${output}" = "5.1.5-3" ]
}

@test "get_additional_versions handles a component without properties" {
  export F17_CHECK_ADDITIONAL_VERSIONS=1

  run get_additional_versions '{"name":"zlib","version":"1.2.13"}'

  [ "${status}" -eq 0 ]
  [ -z "${output}" ]
}

@test "set_component_version leaves cve-bin-tool rows untouched without F17_CHECK_ADDITIONAL_VERSIONS" {
  run set_component_version "5.1.5" <<<"${CVE_BIN_TOOL_ROW}"

  [ "${status}" -eq 0 ]
  [ "${output}" = "${CVE_BIN_TOOL_ROW}" ]
}

@test "set_component_version reports the rows under the component version with F17_CHECK_ADDITIONAL_VERSIONS=1" {
  export F17_CHECK_ADDITIONAL_VERSIONS=1

  run set_component_version "5.1.5" <<<"${CVE_BIN_TOOL_ROW}"

  [ "${status}" -eq 0 ]
  [ "${output}" = "lua,lua,5.1.5,CVE-2014-5461,HIGH" ]
}
