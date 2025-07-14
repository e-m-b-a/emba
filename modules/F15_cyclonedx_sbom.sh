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

# Description:  This module generates a complete json SBOM from the identified software inventory

# shellcheck disable=SC2034

F15_cyclonedx_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "CycloneDX SBOM generator"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    if [[ -f "${CSV_DIR}"/f15_cyclonedx_sbom.json ]]; then
      rm "${CSV_DIR}"/f15_cyclonedx_sbom.json
    fi

    local lSBOM_LOG_FILE="${SBOM_LOG_PATH%\/}/EMBA_cyclonedx_sbom"
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
    # local lEMBA_COMMAND=""
    local lCOMP_FILES_ARR=()
    local lCOMP_FILE_ID=""
    local lCOMP_FILE=""
    local lDEP_FILE=""
    local lDEP_FILE_ID=""
    local lDEP_FILES_ARR=()

    if [[ -f "${TMP_DIR}"/fw_name.log ]] && [[ -f "${TMP_DIR}"/emba_command.log ]]; then
      lFW_PATH=$(sort -u "${TMP_DIR}"/fw_name.log | head -n 1)
      if [[ $(sort -u "${TMP_DIR}"/fw_name.log | wc -l) -gt 1 ]]; then
        print_output "[*] Warning: Multiple firmware paths detected in fw_name.log. Using the first entry: ${lFW_PATH}"
      fi
      # lEMBA_COMMAND=$(sort -u "${TMP_DIR}"/emba_command.log)
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
    local lSBOM_TOOL="EMBA binary analysis environment"
    local lSBOM_TOOL_VERS=""
    lSBOM_TOOL_VERS="$(cat "${CONFIG_DIR}"/VERSION.txt)"
    local lEMBA_URLS_ARR=("https://github.com/e-m-b-a/emba")

    local lTOOL_COMP_ARR=()
    lTOOL_COMP_ARR+=( type="application" )
    lTOOL_COMP_ARR+=( author="EMBA community" )
    lTOOL_COMP_ARR+=( name="${lSBOM_TOOL}" )
    if [[ -f "${INVOCATION_PATH}"/.git/refs/heads/master ]]; then
      lSBOM_TOOL_VERS+="-$(cat "${INVOCATION_PATH}"/.git/refs/heads/master)"
    fi
    lTOOL_COMP_ARR+=( version="${lSBOM_TOOL_VERS}" )
    lTOOL_COMP_ARR+=( description="EMBA firmware analyzer - ${lEMBA_URLS_ARR[*]}" )

    # the following removes the duplicate untracked files that are handled from an other SBOM entry
    if [[ -s "${SBOM_LOG_PATH}"/duplicates_to_delete.txt ]]; then
      local lDUP_DEL=""
      print_output "[*] Deleting duplicates" "no_log"
      while read -r lDUP_DEL; do
        rm -f "${lDUP_DEL}" || true
      done < "${SBOM_LOG_PATH}"/duplicates_to_delete.txt
    fi

    # Firmeware details for the SBOM
    local lFW_COMPONENT_DATA_ARR=()
    lFW_COMPONENT_DATA_ARR+=( name="${lFW_PATH}" )
    lFW_COMPONENT_DATA_ARR+=( type="${lFW_TYPE}" )
    lFW_COMPONENT_DATA_ARR+=( bom-ref="$(uuidgen)" )

    # generate hashes for the firmware itself:
    if [[ -f "${FIRMWARE_PATH_BAK}" ]]; then
      build_sbom_json_hashes_arr "${FIRMWARE_PATH_BAK}" "NA" "NA"
    fi

    [[ -v HASHES_ARR ]] && lFW_COMPONENT_DATA_ARR+=( "hashes=$(jo -a "${HASHES_ARR[@]}")" )

    # build the component array for final sbom build:
    mapfile -t lCOMP_FILES_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "*.json" -not -name "unhandled_file_*" | sort -u)
    if [[ "${SBOM_UNTRACKED_FILES}" -gt 0 ]]; then
      mapfile -t lCOMP_FILES_ARR_UNHANDLED < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "unhandled_file_*.json" | sort -u)
      lCOMP_FILES_ARR+=("${lCOMP_FILES_ARR_UNHANDLED[@]}")
    fi

    # as we can have so many components that everything goes b00m we need to build the
    # components json manually:
    echo -n "[" > "${SBOM_LOG_PATH}/sbom_components_tmp.json"
    for lCOMP_FILE_ID in "${!lCOMP_FILES_ARR[@]}"; do
      lCOMP_FILE="${lCOMP_FILES_ARR["${lCOMP_FILE_ID}"]}"

      if [[ "${SBOM_UNTRACKED_FILES:-0}" -ne 1 ]] && [[ "${lCOMP_FILE}" == *"unhandled_file_"* ]]; then
        # if we do not include unhandled_file entries we can skipe them here
        continue
      fi

      if [[ -s "${lCOMP_FILE}" ]]; then
        if (json_pp < "${lCOMP_FILE}" &> /dev/null); then
          # before adding the new component we need to check that this is not our first entry (after the initial [) and for a ','
          # if it is not found we need to add it now
          if [[ "$(tail -c1 "${SBOM_LOG_PATH}/sbom_components_tmp.json")" != '[' ]] && [[ "$(tail -n1 "${SBOM_LOG_PATH}/sbom_components_tmp.json")" != ',' ]]; then
             echo -n "," >> "${SBOM_LOG_PATH}/sbom_components_tmp.json"
          fi
          cat "${lCOMP_FILE}" >> "${SBOM_LOG_PATH}/sbom_components_tmp.json"
        else
          print_error "[-] WARNING: SBOM component ${lCOMP_FILE} failed to validate with json_pp"
          continue
        fi
      else
        print_error "[-] WARNING: SBOM component ${lCOMP_FILE} failed to decode"
        continue
      fi
    done
    echo -n "]" >> "${SBOM_LOG_PATH}/sbom_components_tmp.json"
    tr -d '\n' < "${SBOM_LOG_PATH}/sbom_components_tmp.json" > "${lSBOM_LOG_FILE}_components.json"

    if [[ -d "${SBOM_LOG_PATH}/SBOM_deps/" ]]; then
      # build the dependency array for final sbom build:
      mapfile -t lDEP_FILES_ARR < <(find "${SBOM_LOG_PATH}/SBOM_deps/" -type f -name "SBOM_dependency_*.json" | sort -u)
    fi

    if [[ "${#lDEP_FILES_ARR[@]}" -gt 0 ]]; then
      # as we could have so many components that everything goes b00m we need to build the
      # components json now manually:
      echo -n "[" > "${SBOM_LOG_PATH}/sbom_dependencies_tmp.json"
      for lDEP_FILE_ID in "${!lDEP_FILES_ARR[@]}"; do
        lDEP_FILE="${lDEP_FILES_ARR["${lDEP_FILE_ID}"]}"
        cat "${lDEP_FILE}" >> "${SBOM_LOG_PATH}/sbom_dependencies_tmp.json"
        if [[ $((lDEP_FILE_ID+1)) -lt "${#lDEP_FILES_ARR[@]}" ]]; then
          echo -n "," >> "${SBOM_LOG_PATH}/sbom_dependencies_tmp.json"
        fi
      done
      echo -n "]" >> "${SBOM_LOG_PATH}/sbom_dependencies_tmp.json"
      tr -d '\n' < "${SBOM_LOG_PATH}/sbom_dependencies_tmp.json" > "${lSBOM_LOG_FILE}_dependencies.json"
    else
      echo -n "[" > "${lSBOM_LOG_FILE}_dependencies.json"
      echo -n "]" >> "${lSBOM_LOG_FILE}_dependencies.json"
    fi

    # final sbom build:
    jo -p -n -- \
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
          "${lFW_COMPONENT_DATA_ARR[@]}")" \
        supplier="$(jo -n \
          name="${FW_VENDOR:-EMBA binary analyzer}" url="$(jo -a "${lEMBA_URLS_ARR[@]}")")" \
        lifecycles="$(jo -a \
          "$(jo phase="${SBOM_LIFECYCLE_PHASE}")")")" \
      components=:"${lSBOM_LOG_FILE}_components.json" \
      dependencies=:"${lSBOM_LOG_FILE}_dependencies.json" \
      vulnerabilities="[]" \
      > "${lSBOM_LOG_FILE}.json" || print_error "[-] SBOM builder error!"

    # Replace placeholder '%SPACE%' with actual spaces in the generated JSON file to ensure proper formatting.
    sed -i 's/%SPACE%/\ /g' "${lSBOM_LOG_FILE}.json"

    if [[ -s "${lSBOM_LOG_FILE}.json" ]]; then
      local lNEG_LOG=1
      print_output "[*] Converting SBOM to further SBOM formats ..." "no_log"
      cyclonedx convert --output-format xml --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.xml" || print_error "[-] Error while generating xml SBOM for SBOM"
      cyclonedx convert --output-format protobuf --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.proto" || print_error "[-] Error while generating protobuf SBOM for SBOM"
      cyclonedx convert --output-format spdxjson --input-file "${lSBOM_LOG_FILE}.json" --output-file "${lSBOM_LOG_FILE}.spdx" || print_error "[-] Error while generating spdxjson SBOM for SBOM"

      print_output "[+] Cyclonedx SBOM in json and CSV format created:"
      print_output "$(indent "$(orange "-> Download SBOM as JSON${NC}")")" "" "${lSBOM_LOG_FILE}.json"
      if [[ -f "${lSBOM_LOG_FILE}.xml" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as XML${NC}")")" "" "${lSBOM_LOG_FILE}.xml"
      fi
      if [[ -f "${lSBOM_LOG_FILE}.spdx" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as SPDX JSON${NC}")")" "" "${lSBOM_LOG_FILE}.spdx"
      fi
      if [[ -f "${lSBOM_LOG_FILE}.proto" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as PROTOBUF${NC}")")" "" "${lSBOM_LOG_FILE}.proto"
      fi
      if [[ -f "${S08_CSV_LOG}" ]]; then
        print_output "$(indent "$(orange "-> Download SBOM as EMBA CSV${NC}")")" "" "${S08_CSV_LOG}"
      fi
      print_ln
      print_output "[+] Cyclonedx SBOM in json format:" "" "${lSBOM_LOG_FILE}.json"
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
