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

# Description:  This module generates a complete json SBOM from the identified software inventory

# shellcheck disable=SC2034

F14_cyclonedx_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "CycloneDX SBOM generator"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    if [[ -f "${CSV_DIR}"/f14_cyclonedx_sbom.json ]]; then
      rm "${CSV_DIR}"/f14_cyclonedx_sbom.json
    fi

    local lSBOM_LOG_FILE="${SBOM_LOG_PATH}/EMBA_cyclonedx_sbom"
    local lSBOM_JSON=""
    local lSBOM_SCHEMA="http://cyclonedx.org/schema/bom-1.5.schema.json"
    local lSBOM_FORMAT="CycloneDX"
    local lSBOM_SPEC_VERS="1.5"
    local lSBOM_VER=1
    local lSBOM_SERIAL_NR="urn:uuid:"
    lSBOM_SERIAL_NR+="$(uuidgen)"
    local lSBOM_TIMESTAMP=""
    lSBOM_TIMESTAMP=$(date -Iseconds)
    local lFW_TYPE=""
    local lFW_PATH=""

    if [[ -f "${FIRMWARE_PATH_BAK}" ]]; then
      export HASHES_ARR=()
      build_sbom_json_hashes_arr "${FIRMWARE_PATH_BAK}"
    fi
    if [[ -f "${TMP_DIR}"/fw_name.log ]] && [[ -f "${TMP_DIR}"/emba_command.log ]]; then
      lFW_PATH=$(sort -u "${TMP_DIR}"/fw_name.log)
    else
      lFW_PATH="${FIRMWARE_PATH_BAK}"
    fi

    if [[ -v CONTAINER_ID ]]; then
      lFW_TYPE="container"
    elif [[ "${lFW_PATH}" == *".exe" ]]; then
      lFW_TYPE="application"
    elif [[ -f "${lFW_PATH}" ]]; then
      lFW_TYPE="file"
    else
      lFW_TYPE="data"
    fi

    # EMBA details for the SBOM
    local lSBOM_TOOL="EMBA"
    local lSBOM_TOOL_VERS=""
    lSBOM_TOOL_VERS="$(cat "${CONFIG_DIR}"/VERSION.txt)"
    local lTOOL_COMP_ARR=()
    lTOOL_COMP_ARR+=( type="application" )
    lTOOL_COMP_ARR+=( author="EMBA community" )
    lTOOL_COMP_ARR+=( name="${lSBOM_TOOL}" )
    lTOOL_COMP_ARR+=( version="${lSBOM_TOOL_VERS}" )
    lTOOL_COMP_ARR+=( description="EMBA firmware analyzer - https://github.com/e-m-b-a/emba" )

    # Firmeware details for the SBOM
    local lFW_COMPONENT_DATA_ARR=()
    lFW_COMPONENT_DATA_ARR+=( type="${lFW_TYPE}" )
    lFW_COMPONENT_DATA_ARR+=( bom-ref="$(uuidgen)" )
    [[ -n "${FW_VENDOR}" ]] && lFW_COMPONENT_DATA_ARR+=( "supplier=$(jo -n name="${FW_VENDOR}")" )
    lFW_COMPONENT_DATA_ARR+=( path="${lFW_PATH}" )
    [[ -v HASHES_ARR ]] && lFW_COMPONENT_DATA_ARR+=( "hashes=$(jo -a "${HASHES_ARR[@]}")" )

    # build the component array for final sbom build:
    mapfile -t lCOMP_FILES_ARR < <(find "${SBOM_LOG_PATH}" -type f -name "*.json")
    local lCOMPONENTS_ARR=()
    for lCOMP_FILE in "${lCOMP_FILES_ARR[@]}"; do
      lCOMPONENTS_ARR+=( :"${lCOMP_FILE}" )
    done

    # final sbom build:
    lSBOM_JSON=$(jo -p -- \
      \$schema="${lSBOM_SCHEMA}" \
      bomFormat="${lSBOM_FORMAT}" \
      -s specVersion="${lSBOM_SPEC_VERS}" \
      serialNumber="${lSBOM_SERIAL_NR}" \
      version="${lSBOM_VER}" \
      metadata="$(jo \
        timestamp="${lSBOM_TIMESTAMP}" \
        tools="$(jo \
          components="$(jo -a "$(jo -n "${lTOOL_COMP_ARR[@]}")")")" \
        component="$(jo -n \
          "${lFW_COMPONENT_DATA_ARR[@]}")")" \
      components="$(jo -a \
        "${lCOMPONENTS_ARR[@]}" \
        )")

    unset HASHES_ARR

    # I am sure there is a much cleaner way but for now I am stuck and don't get it in a different way :(
    echo "${lSBOM_JSON//%SPACE%/\ }" > "${lSBOM_LOG_FILE}.json" 

    if [[ -f "${lSBOM_LOG_FILE}.json" ]]; then
      local lNEG_LOG=1
      print_output "[*] Converting CSV SBOM to Cyclonedx SBOM ..." "no_log"
      cyclonedx convert --output-format xml --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.xml.txt" || print_error "[-] Error while generating xml SBOM for SBOM"
      cyclonedx convert --output-format protobuf --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.proto.txt" || print_error "[-] Error while generating protobuf SBOM for SBOM"
      cyclonedx convert --output-format spdxjson --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.spdx.txt" || print_error "[-] Error while generating spdxjson SBOM for SBOM"

      print_output "[+] Cyclonedx SBOM in json and CSV format created:"
      print_output "$(indent "$(orange "-> Download SBOM as JSON${NC}")")" "" "${lSBOM_LOG_FILE}.json"
      if [[ -f "${lSBOM_LOG_FILE}.xml.txt" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as XML${NC}")")" "" "${lSBOM_LOG_FILE}.xml.txt"
      fi
      if [[ -f "${lSBOM_LOG_FILE}.spdx.txt" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as SPDX JSON${NC}")")" "" "${lSBOM_LOG_FILE}.spdx.txt"
      fi
      if [[ -f "${lSBOM_LOG_FILE}.proto.txt" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as PROTOBUF${NC}")")" "" "${lSBOM_LOG_FILE}.proto.txt"
      fi
      if [[ -f "${S08_CSV_LOG}" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as EMBA CSV${NC}")")" "" "${S08_CSV_LOG}"
      fi
      print_ln
      print_output "[+] Cyclonedx SBOM in json format:"
      print_ln
      tee -a "${LOG_FILE}" < "${lSBOM_LOG_FILE}.json"
      print_ln
    else
      print_output "[-] No SBOM created!"
      local lNEG_LOG=0
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}
