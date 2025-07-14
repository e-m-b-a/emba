#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Collects license details and gives a list with binaries, identified version and
#               the corresponding license (if available). The license details are maintained in the
#               configuration files located here: config/bin_version_identifiers


F10_license_summary() {
  module_log_init "${FUNCNAME[0]}"
  module_title "License inventory"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCOUNT_LIC=0
  local lSBOMs_ARR=()
  local lSBOM_FILE=""
  local lPRODUCT=""
  local lVERSION=""
  local lBINARY=""
  local lLICENSE_ARR=()

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    mapfile -t lSBOMs_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 ! -name "*unhandled_file*" -name "*.json")
  fi

  if [[ "${#lSBOMs_ARR[@]}" -gt 0 ]]; then
    for lSBOM_FILE in "${lSBOMs_ARR[@]}"; do

      lPRODUCT=$(jq -r .name "${lSBOM_FILE}" || print_error "[-] F10 - name extraction failed for ${lSBOM_FILE}")
      if [[ -z "${lPRODUCT}" ]]; then
        continue
      fi
      lVERSION=$(jq -r .version "${lSBOM_FILE}" || print_error "[-] F10 - version extraction failed for ${lSBOM_FILE}")
      mapfile -t lLICENSE_ARR < <(jq -r '.licenses[]?.license.name' "${lSBOM_FILE}")
      if [[ "${#lLICENSE_ARR[@]}" -eq 0 ]]; then
        lLICENSE_ARR+=("No license identified")
      fi
      lBINARY=$(jq -r '.properties[]? | select(.name | test("source_path")) | .value' "${lSBOM_FILE}")
      lBINARY="${lBINARY#\'}"
      lBINARY="${lBINARY%\'}"

      print_output "[+] Binary: ${ORANGE}$(basename "${lBINARY}")${GREEN} / Product: ${ORANGE}${lPRODUCT}${GREEN} / Version: ${ORANGE}${lVERSION}${GREEN} / License: ${ORANGE}${lLICENSE_ARR[*]}${NC}"
      ((lCOUNT_LIC+=1))
    done
  else
    print_output "[-] No SBOM details available"
  fi

  module_end_log "${FUNCNAME[0]}" "${lCOUNT_LIC}"
}
