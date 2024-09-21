#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  This module generates a minimal json SBOM from the identified software inventory
#               via cyclonedx - https://github.com/CycloneDX/cyclonedx-cli#csv-format

F21_cyclonedx_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "CycloneDX SBOM converter"
  pre_module_reporter "${FUNCNAME[0]}"
  local BIN_VER_SBOM_ARR=()
  local BIN_VER_SBOM_ENTRY=""
  local BINARY=""
  local VERSION=""
  local NEG_LOG=0

  if ! command -v cyclonedx > /dev/null; then
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

  if [[ -f "${F20_CSV_LOG}" ]] && [[ "$(wc -l "${F20_CSV_LOG}" | awk '{print $1}')" -gt 1 ]]; then
    if [[ -f "${F21_CSV_LOG}" ]]; then
      rm "${F21_CSV_LOG}"
    fi
    if [[ -f "${CSV_DIR}"/f21_cyclonedx_sbom.json ]]; then
      rm "${CSV_DIR}"/f21_cyclonedx_sbom.json
    fi

    write_csv_log "Type" "MimeType" "Supplier" "Author" "Publisher" "Group" "Name" "Version" "Scope" "LicenseExpressions" "LicenseNames" "Copyright" "Cpe" "Purl" "Modified" "SwidTagId" "SwidName" "SwidVersion" "SwidTagVersion" "SwidPatch" "SwidTextContentType" "SwidTextEncoding" "SwidTextContent" "SwidUrl" "MD5" "SHA-1" "SHA-256" "SHA-512" "BLAKE2b-256" "BLAKE2b-384" "BLAKE2b-512" "SHA-384" "SHA3-256" "SHA3-384" "SHA3-512" "BLAKE3" "Description"
    print_output "[*] Collect SBOM details of module $(basename "${F20_CSV_LOG}")."
    mapfile -t BIN_VER_SBOM_ARR < <(cut -d\; -f1,2 "${F20_CSV_LOG}" | tail -n +2 | sort -u)
    for BIN_VER_SBOM_ENTRY in "${BIN_VER_SBOM_ARR[@]}"; do
      BINARY=$(echo "${BIN_VER_SBOM_ENTRY}" | cut -d\; -f1)
      VERSION=$(echo "${BIN_VER_SBOM_ENTRY}" | cut -d\; -f2)
      write_csv_log "" "" "" "" "" "" "${BINARY}" "${VERSION}" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" "" ""
    done
    if [[ -f "${F21_CSV_LOG}" ]]; then
      # our csv is with ";" as deliminiter. cyclonedx needs "," -> lets do a quick tranlation
      sed -i 's/\;/,/g' "${F21_CSV_LOG}"
      cyclonedx convert --input-file "${F21_CSV_LOG}" --output-file "${LOG_DIR}"/f21_cyclonedx_sbom.json || true
    fi
    if [[ -f "${LOG_DIR}"/f21_cyclonedx_sbom.json ]]; then
      print_output "[+] SBOM in json format created:" "" "${LOG_DIR}/f21_cyclonedx_sbom.json"
      print_ln
      tee -a "${LOG_FILE}" < "${LOG_DIR}"/f21_cyclonedx_sbom.json
      print_ln
      local NEG_LOG=1
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}
