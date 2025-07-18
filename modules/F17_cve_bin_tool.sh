#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Based on the generated SBOM this module extracts known vulnerabilities
#               via cve-bin-tool
# shellcheck disable=SC2153

F17_cve_bin_tool() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  pre_module_reporter "${FUNCNAME[0]}"

  # our first approach is to use our beautiful SBOM and walk through it
  # if for any reasons (disabled F15 module) there is no SBOM we check for s08_package_mgmt_extractor.csv

  local lEMBA_SBOM_JSON="${EMBA_SBOM_JSON}"
  local lSBOM_ARR=()
  local lSBOM_ENTRY=""
  local lWAIT_PIDS_F17_ARR=()
  local lVEX_JSON_ENTRIES_ARR=()
  local lVEX_FILE_ID=0
  local lVEX_FILE=""
  local lNEG_LOG=0
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS*2))

  mkdir "${LOG_PATH_MODULE}/json/" || true
  mkdir "${LOG_PATH_MODULE}/cve_sum/" || true
  mkdir "${LOG_PATH_MODULE}/exploit/" || true

  print_output "[*] Loading SBOM ..." "no_log"

  if ! [[ -f "${lEMBA_SBOM_JSON}" ]]; then
    print_error "[-] No SBOM available!"
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  # read each item in the JSON array to an item in the Bash array
  readarray -t lSBOM_ARR < <(jq --compact-output '.components[]' "${lEMBA_SBOM_JSON}" || print_error "[-] SBOM loading error - Vulnerability analysis not available")

  sub_module_title "Software inventory overview"
  print_output "[*] Analyzing ${#lSBOM_ARR[@]} SBOM components ..." "no_log"

  # first round is primarly for removing duplicates, unhandled_file entries and printing a quick initial overview for the html report
  # 2nd round is for the real testing
  local lWAIT_PIDS_TEMP=()
  for lSBOM_ENTRY in "${lSBOM_ARR[@]}"; do
    sbom_preprocessing_threader "${lSBOM_ENTRY}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_TEMP+=( "${lTMP_PID}" )
    max_pids_protection $((2*"${MAX_MOD_THREADS}")) lWAIT_PIDS_TEMP
    local lNEG_LOG=1
  done
  wait_for_pid "${lWAIT_PIDS_TEMP[@]}"

  print_bar

  if ! [[ -f "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp" ]]; then
    print_output "[*] No SBOM components for further analysis detected"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  sub_module_title "Vulnerability overview"
  # we need to wait for the import of the CVE database
  # just to ensure everything is in place we wait a max of ~2 minutes
  # if we fail we try to proceed and hope ...
  local lCNT=0
  while ! [[ -f "${TMP_DIR}/tmp_state_data.log" ]]; do
    print_output "[*] Waiting for CVE database ..." "no_log"
    lCNT=$((lCNT+1))
    if [[ "${lCNT}" -gt 24 ]]; then
      print_output "[-] CVE database not prepared in time ... trying to proceed"
      break
    fi
    sleep 5
  done

  # 2nd round with pre-processed array -> we are going to check for CVEs now
  while read -r lSBOM_ENTRY; do
    local lBOM_REF=""
    local lORIG_SOURCE=""
    local lVENDOR_ARR=()
    local lPRODUCT_ARR=()
    local lPRODUCT_VERSION=""
    local lPRODUCT_NAME=""
    lPRODUCT_NAME=$(jq --raw-output '.name' <<< "${lSBOM_ENTRY}")

    # extract all our possible vendor names and product names:
    mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' <<< "${lSBOM_ENTRY}")
    if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
      lVENDOR_ARR+=("NOTDEFINED")
    fi
    mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' <<< "${lSBOM_ENTRY}")
    if [[ "${#lPRODUCT_ARR[@]}" -eq 0 ]]; then
      lPRODUCT_ARR+=("${lPRODUCT_NAME}")
    fi

    lPRODUCT_VERSION=$(jq --raw-output '.version' <<< "${lSBOM_ENTRY}")

    # avoid duplicates
    if (grep -q "${lVENDOR_ARR[*]//\\n};${lPRODUCT_ARR[*]//\\n};${lPRODUCT_VERSION}" "${LOG_PATH_MODULE}/sbom_entry_processed.tmp" 2>/dev/null); then
      continue
    fi
    echo "${lVENDOR_ARR[*]//\\n};${lPRODUCT_ARR[*]//\\n};${lPRODUCT_VERSION}" >> "${LOG_PATH_MODULE}/sbom_entry_processed.tmp"

    # BusyBox verification module handling - we already have all the data from s118. Now we just copy these details
    if [[ "${lPRODUCT_NAME}" == "busybox" ]] && [[ -s "${S118_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] BusyBox results from s118 detected ... no CVE detection needed" "no_log"
      cp "${S118_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" 2>/dev/null || true
      cp "${S118_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" 2>/dev/null || true
      cp "${S118_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" 2>/dev/null || true
      cp "${S118_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || true
      if [[ -f "${S118_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S118_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # now, lets write the main f20 log file with the results of the current binary:
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S118 Busybox details missing ... continue in default mode"
      fi
    elif [[ "${lPRODUCT_NAME}" == "lighttpd" ]] && [[ -s "${S36_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] lighttpd results from s36 detected ... no CVE detection needed" "no_log"
      cp "${S36_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || print_error "[-] lighttpd CVE log copy process failed"
      if [[ -f "${S36_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S36_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # now, lets write the main f20 log file with the results of the current binary:
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S36 lighttpd details missing ... continue in default mode"
      fi
    # Linux Kernel verification module handling - we already have all the data from s26. Now we just copy these details
    elif [[ "${lPRODUCT_NAME}" == "linux_kernel"* ]] && [[ -s "${S26_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] Possible Linux kernel results from s26 detected ... no CVE detection needed" "no_log"
      cp "${S26_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || print_error "[-] Linux Kernel CVE log copy process failed"
      if [[ -f "${S26_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S26_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # now, lets write the main f20 log file with the results of the current binary:
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S26 Linux Kernel details missing ... continue in default mode"
      fi
    fi

    lBOM_REF=$(jq --raw-output '."bom-ref"' <<< "${lSBOM_ENTRY}" || print_error "[-] BOM_REF failed to extract from ${lSBOM_ENTRY}")
    lORIG_SOURCE=$(jq --raw-output '.group' <<< "${lSBOM_ENTRY}" || print_error "[-] ORIG_SOURCE failed to extract from ${lSBOM_ENTRY}")

    cve_bin_tool_threader "${lBOM_REF}" "${lPRODUCT_VERSION}" "${lORIG_SOURCE}" lVENDOR_ARR lPRODUCT_ARR &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_F17_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_F17_ARR
  done < "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp"

  wait_for_pid "${lWAIT_PIDS_F17_ARR[@]}"

  print_output "[*] Generating final VEX vulnerability json ..." "no_log"

  # Handle rescan mode: preserve existing files as "previous" versions and use standard names for new files
  if [[ "${RESCAN_SBOM:-0}" -eq 1 ]]; then
    print_output "[*] Backing up existing VEX files as previous versions" "no_log"

    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" ]]; then
      backup_vex_file "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"
    else
      print_output "[-] No VEX only json file found"
    fi
    if [[ -f "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" ]]; then
      backup_vex_file "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json"
    else
      print_output "[-] No VEX SBOM json file found"
    fi

    # Handle EMBA_sbom_vex_tmp.json if it exists
    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json" ]]; then
      rm "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
    fi
  fi

  # now we need to build our full vex json
  mapfile -t lVEX_JSON_ENTRIES_ARR < <(find "${LOG_PATH_MODULE}/json/" -name "*.json")
  print_output "[*] Building final VEX - Vulnerability Exploitability eXchange" "no_log"
  if [[ "${#lVEX_JSON_ENTRIES_ARR[@]}" -gt 0 ]]; then
    local lNEG_LOG=1
    echo "\"vulnerabilities\": [" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"

    for lVEX_FILE_ID in "${!lVEX_JSON_ENTRIES_ARR[@]}"; do
      lVEX_FILE="${lVEX_JSON_ENTRIES_ARR["${lVEX_FILE_ID}"]}"
      if [[ -s "${lVEX_FILE}" ]]; then
        if (json_pp < "${lVEX_FILE}" &> /dev/null); then
          cat "${lVEX_FILE}" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
        else
          print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to validate with json_pp"
          continue
        fi
      else
        print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to decode"
        continue
      fi
      if [[ $((lVEX_FILE_ID+1)) -lt "${#lVEX_JSON_ENTRIES_ARR[@]}" ]]; then
        echo -n "," >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
      fi
    done

    echo -n "]" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
    tr -d '\n' < "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"

    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" ]]; then
      sub_module_title "VEX - Vulnerability Exploitability eXchange"
      print_output "[+] VEX data in json format is available" "" "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"

      # let's replace the vulnerability marker with our VEX:
      sed -e '/\"vulnerabilities\": \[\]/{r '"${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" -e 'd;}' "${SBOM_LOG_PATH}/EMBA_cyclonedx_sbom.json" > "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" || print_error "[-] SBOM - VEX merge failed"

      # now we ensure that we have a valid vex only json:
      # https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json
      sed -i '1i "version": 1,' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      sed -i '1i "specVersion": "1.5",' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      sed -i '1i "bomFormat": "CycloneDX",' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      sed -i '1i {' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"

      # adjust the end of our json:
      echo '}' >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
    fi
    if [[ -f "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" ]]; then
      print_output "[+] CycloneDX SBOM with VEX data in JSON format is ready" "" "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json"
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

sbom_preprocessing_threader() {
  local lSBOM_ENTRY="${1:-}"

  local lBOM_REF=""
  local lORIG_SOURCE=""
  local lVENDOR_ARR=()
  local lPRODUCT_ARR=()
  local lPRODUCT_VERSION=""
  local lPRODUCT_NAME=""

  lORIG_SOURCE=$(jq --raw-output '.group' <<< "${lSBOM_ENTRY}")

  # if source is unhandled_file we can skip this entry completely
  if [[ "${lORIG_SOURCE}" == "unhandled_file" ]]; then
    return
  fi

  lPRODUCT_VERSION=$(jq --raw-output '.version' <<< "${lSBOM_ENTRY}")

  # ensure we have some version to test
  if [[ -z "${lPRODUCT_VERSION}" ]]; then
    return
  fi

  # lPRODUCT_NAME is only used for duplicate checking:
  lPRODUCT_NAME=$(jq --raw-output '.name' <<< "${lSBOM_ENTRY}")

  # extract all our possible vendor names and product names:
  mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' <<< "${lSBOM_ENTRY}")
  if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
    lVENDOR_ARR+=("NOTDEFINED")
  fi
  mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' <<< "${lSBOM_ENTRY}")
  if [[ "${#lPRODUCT_ARR[@]}" -eq 0 ]]; then
    lPRODUCT_ARR+=("${lPRODUCT_NAME}")
  fi

  lBOM_REF=$(jq --raw-output '."bom-ref"' <<< "${lSBOM_ENTRY}")
  local lANCHOR=""
  lANCHOR="${lPRODUCT_ARR[0]//\'}_${lPRODUCT_VERSION}"
  lANCHOR="cve_${lANCHOR:0:20}"

  # ensure this product/version combination is not already in our testing array:
  if (grep -q "\"name\":\"${lPRODUCT_NAME}\",\"version\":\"${lPRODUCT_VERSION}\"" "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp" 2>/dev/null); then
    return
  fi
  echo "${lSBOM_ENTRY}" >> "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp"
  print_output "[*] Vulnerability details for ${ORANGE}${lPRODUCT_ARR[0]//\'/}${NC} - vendor ${ORANGE}${lVENDOR_ARR[0]//\'/}${NC} - version ${ORANGE}${lPRODUCT_VERSION}${NC} - BOM reference ${ORANGE}${lBOM_REF}${NC}" "" "f17#${lANCHOR}"
}

cve_bin_tool_threader() {
  local lBOM_REF="${1:-}"
  local lVERS="${2:-}"
  local lORIG_SOURCE="${3:-}"
  local -n lrVENDOR_ARR="${4:-}"
  local -n lrPRODUCT_ARR="${5:-}"
  local lWAIT_PIDS_F17_ARR_2=()

  if [[ "${#lrPRODUCT_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No product name available for ${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}" "no_log"
    return
  fi

  local lCVE_BIN_TOOL="/external/cve-bin-tool/cve_bin_tool/cli.py"
  write_log "product,vendor,version,bom-ref" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"
  for lVENDOR in "${lrVENDOR_ARR[@]}"; do
    lVENDOR="${lVENDOR#\'}"
    lVENDOR="${lVENDOR%\'}"
    for lPROD in "${lrPRODUCT_ARR[@]}"; do
      lPROD="${lPROD#\'}"
      lPROD="${lPROD%\'}"
      write_log "${lPROD},${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"
    done
  done
  if ! [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" ]]; then
    print_output "[-] No tmp vendor/product file for ${lrVENDOR_ARR[*]}/${lrPRODUCT_ARR[*]} for cve-bin-tool generated"
    return
  fi
  lPRODUCT_NAME="${lrPRODUCT_ARR[0]}"
  lPRODUCT_NAME="${lPRODUCT_NAME#\'}"
  lPRODUCT_NAME="${lPRODUCT_NAME%\'}"

  if ! [[ -d "${LOG_PATH_MODULE}/cve_sum/" ]]; then
    mkdir "${LOG_PATH_MODULE}/cve_sum/"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}/json/" ]]; then
    mkdir "${LOG_PATH_MODULE}/json/"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}/exploit/" ]]; then
    mkdir "${LOG_PATH_MODULE}/exploit/"
  fi

  python3 "${lCVE_BIN_TOOL}" -i "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" --disable-version-check --disable-validation-check --no-0-cve-report --offline -f csv -o "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}" || true

  if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" ]]; then
    rm "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" || true
  fi

  # walk through "${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}".csv and check for exploits, EPSS and print as in F20
  if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.csv" ]]; then
    print_output "[*] Identification of possible Exploits, EPSS and further details ..." "no_log"
    while read -r lCVE_LINE; do
      # print_output "${lBOM_REF},${lORIG_SOURCE},${lCVE_LINE}"
      tear_down_cve_threader "${lBOM_REF},${lORIG_SOURCE},${lCVE_LINE}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_F17_ARR_2+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_F17_ARR_2
    done < <(tail -n +2 "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.csv")
  fi
  wait_for_pid "${lWAIT_PIDS_F17_ARR_2[@]}"

  # lets start the final logging per component

  # now we have our nice formatted logs somewhere over here: "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
  # lets build the final log for every binary:
  local lBIN_LOG="${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}_finished.txt"
  write_log "" "${lBIN_LOG}"

  local lANCHOR=""
  lANCHOR="${lPRODUCT_NAME//\'}_${lVERS}"
  lANCHOR="cve_${lANCHOR:0:20}"
  write_log "[*] Vulnerability details for ${ORANGE}${lPRODUCT_NAME}${NC} / version ${ORANGE}${lVERS}${NC} / source ${ORANGE}${lORIG_SOURCE}${NC}:" "${lBIN_LOG}"
  write_anchor "${lANCHOR}" "${lBIN_LOG}"

  local lEXPLOIT_COUNTER_VERSION=0
  local lCVE_COUNTER_VERSION=0
  local lCVE_COUNTER_VERIFIED=0
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" ]]; then
    lEXPLOIT_COUNTER_VERSION=$(grep -c "Exploit (" "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" || true)
    lCVE_COUNTER_VERSION=$(grep -c -E "CVE-[0-9]+-[0-9]+" "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" || true)
    lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION}"
  fi

  # Todo: Include verified vulnerabilties
  # * s26
  # * s118
  if [[ "${lPRODUCT_NAME}" == "linux_kernel" ]]; then
    local lKVERIFIED=0
    if [[ -f "${S26_LOG_DIR}/kernel_verification_${lVERS}_detailed.log" ]]; then
      lKVERIFIED=$(grep -c " verified - " "${S26_LOG_DIR}/kernel_verification_${lVERS}_detailed.log" || true)
    fi
    if [[ "${lKVERIFIED}" -gt 0 ]]; then
      lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION} (${lKVERIFIED})"
    fi
  fi
  if [[ "${lPRODUCT_NAME}" == "busybox" ]]; then
    local lBB_VERIFIED=0
    if [[ -f "${S118_CSV_LOG}" ]]; then
      lBB_VERIFIED=$(grep -c ":busybox:.*;CVE-" "${S118_CSV_LOG}" || true)
      if [[ "${lBB_VERIFIED}" -gt 0 ]]; then
        lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION} (${lBB_VERIFIED})"
      fi
    fi
  fi

  if [[ "${lEXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    # write detailed log
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Identified ${RED}${BOLD}${lCVE_COUNTER_VERIFIED}${GREEN} CVEs and ${RED}${BOLD}${lEXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # write summary log:
    printf "[${MAGENTA}+${NC}]${MAGENTA} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  elif [[ "${lCVE_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Identified ${ORANGE}${BOLD}${lCVE_COUNTER_VERIFIED}${GREEN} CVEs in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # write summary log:
    printf "[${ORANGE}+${NC}]${ORANGE} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  else
    write_log "[+] Identified ${GREEN}${BOLD}${lCVE_COUNTER_VERIFIED:-0}${GREEN} CVEs in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    printf "[${GREEN}+${NC}]${GREEN} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED:-0}" "${lEXPLOIT_COUNTER_VERSION:-0}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  fi
  write_log "\\n-----------------------------------------------------------------\\n" "${lBIN_LOG}"

  # we can now delete the temp log file
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" ]]; then
    rm "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" || true
  fi

  # now, lets write the main f20 log file with the results of the current binary:
  if [[ -f "${lBIN_LOG}" ]]; then
    tee -a "${LOG_FILE}" < "${lBIN_LOG}"
  fi
}

tear_down_cve_threader() {
  local lCVE_LINE="${1:-}"
  local lCVE_DATA_ARR=()

  mapfile -t lCVE_DATA_ARR < <(echo "${lCVE_LINE}" | tr ',' '\n')
  # echo "lCVE_LINE: ${lCVE_LINE}"
  local lBOM_REF="${lCVE_DATA_ARR[*]:0:1}"
  local lORIG_SOURCE="${lCVE_DATA_ARR[*]:1:1}"

  # local lBIN_VENDOR="${lCVE_DATA_ARR[*]:2:1}"
  local lBIN_NAME="${lCVE_DATA_ARR[*]:3:1}"
  local lBIN_VERS="${lCVE_DATA_ARR[*]:4:1}"
  local lCVE_ID="${lCVE_DATA_ARR[*]:5:1}"
  local lCVSS_SEVERITY="${lCVE_DATA_ARR[*]:6:1}"
  local lCVSS_SCORE="${lCVE_DATA_ARR[*]:7:1}"
  local lVULN_SOURCE="${lCVE_DATA_ARR[*]:8:1}"
  local lCVSS_VERS="${lCVE_DATA_ARR[*]:9:1}"
  local lCVSS_VECTOR="${lCVE_DATA_ARR[*]:10:1}"

  # if we find a blacklist file we check if the current CVE value is in the blacklist
  # if we find it this CVE is not further processed
  if [[ -f "${CVE_BLACKLIST}" ]]; then
    if grep -q ^"${lCVE_ID}"$ "${CVE_BLACKLIST}"; then
      print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} blacklisted and ignored." "no_log"
      return
    fi
  fi
  # if we find a whitelist file we check if the current CVE value is in the whitelist
  # only if we find this CVE in the whitelist it is further processed
  if [[ -f "${CVE_WHITELIST}" ]]; then
    # do a quick check if there is some data in the whitelist config file
    if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
      if ! grep -q ^"${lCVE_ID}"$ "${CVE_WHITELIST}"; then
        print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} not in whitelist -> ignored." "no_log"
        return
      fi
    fi
  fi

  # default value
  local lEXPLOIT="No exploit available"
  local lKNOWN_EXPLOITED=0
  local lKERNEL_VERIFIED_VULN=0
  local lKERNEL_VERIFIED="no"
  local lBUSYBOX_VERIFIED="no"
  local lEDB=0
  local lKERNEL_CVE_EXPLOIT=""

  local lEXPLOIT_AVAIL_EDB_ARR=()
  local lEXPLOIT_AVAIL_MSF_ARR=()
  local lEXPLOIT_MSF=""
  local lEXPLOIT_PATH=""
  local lEXPLOIT_NAME=""
  local lEXPLOIT_AVAIL_PACKETSTORM_ARR=()
  local lEXPLOIT_AVAIL_SNYK_ARR=()
  local lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR=()
  local lVEX_EXPLOIT_PROP_ARRAY_ARR=()
  local lEID_VALUE=""
  local lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR=()
  local lEXPLOIT_IDS_ARR=()
  local lEXPLOIT_ID=""
  local lLOCAL=0
  local lREMOTE=0
  local lDOS=0
  local lEXPLOIT_ENTRY=""
  local lE_FILE=""
  local lEXPLOIT_SNYK=""
  local lEXPLOIT_PS=""
  local lEXPLOIT_RS=""
  local lPS_TYPE=""
  local lFIRST_EPSS=0

  # remote/local vulnerability
  local lTYPE="NA"
  if [[ "${lCVSS_VECTOR}" == *"AV:L"* ]]; then
    lTYPE="L"
  elif [[ "${lCVSS_VECTOR}" == *"AV:N"* ]]; then
    lTYPE="R"
  fi

  if [[ "${VEX_METRICS}" -eq 1 ]]; then
    # we get "EPSS;percentage" back
    lFIRST_EPSS=$(get_epss_data "${lCVE_ID}")
    # local lFIRST_PERC="${lFIRST_EPSS/*\;}"
    lFIRST_EPSS="${lFIRST_EPSS/\;*}"

    # check if the CVE is known as a knwon exploited vulnerability:
    if grep -q "^${lCVE_ID}," "${KNOWN_EXP_CSV}"; then
      write_log "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a known exploited vulnerability.${NC}" "${LOG_PATH_MODULE}/KEV.txt"

      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (KEV"
      else
        lEXPLOIT+=" / KEV"
      fi
      if [[ "${lTYPE}" != "NA" ]]; then
        lEXPLOIT+=" (${lTYPE})"
      fi
      lKNOWN_EXPLOITED=1
      lEDB=1
    fi

    if [[ "${lBIN_NAME}" == *kernel* ]]; then
      for lKERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
        lKERNEL_CVE_EXPLOIT=$(echo "${lKERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
        if [[ "${lKERNEL_CVE_EXPLOIT}" == "${lCVE_ID}" ]]; then
          lEXPLOIT="Exploit (linux-exploit-suggester"
          if [[ "${lTYPE}" != "NA" ]]; then
            lEXPLOIT+=" (${lTYPE})"
          fi
          write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};kernel exploit" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
          lEDB=1
        fi
      done

      if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv ]]; then
        # check if the current CVE is a verified kernel CVE from s26 module
        if grep -q ";${lCVE_ID};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
        if grep -q ";${lCVE_ID};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
        if grep -q ";${lCVE_ID};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
      fi
    fi

    if [[ -f "${CSV_DIR}"/s118_busybox_verifier.csv ]] && [[ "${lBIN_NAME}" == *"busybox"* ]]; then
      if grep -q ";${lCVE_ID};" "${CSV_DIR}"/s118_busybox_verifier.csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified BusyBox vulnerability (${ORANGE}BusyBox applet${GREEN})!" "no_log"
        lBUSYBOX_VERIFIED="yes"
      fi
    fi

    mapfile -t lEXPLOIT_AVAIL_EDB_ARR < <(cve_searchsploit "${lCVE_ID}" 2>/dev/null || true)
    mapfile -t lEXPLOIT_AVAIL_MSF_ARR < <(grep -E "${lCVE_ID}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
    mapfile -t lEXPLOIT_AVAIL_PACKETSTORM_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/PS_PoC_results.csv 2>/dev/null || true)
    mapfile -t lEXPLOIT_AVAIL_SNYK_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/Snyk_PoC_results.csv 2>/dev/null || true)
    mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR < <(grep -E "${lCVE_ID}"$ "${CONFIG_DIR}/routersploit_cve-db.txt" 2>/dev/null || true)

    # now, we check the exploit-db results if we have a routersploit module:
    if [[ " ${lEXPLOIT_AVAIL_EDB_ARR[*]} " =~ "Exploit DB Id:" ]]; then
      for lEID_VALUE in "${EXPLOIT_AVAIL_EDB_ARR[@]}"; do
        if ! echo "${lEID_VALUE}" | grep -q "Exploit DB Id:"; then
          continue
        fi
        lEID_VALUE=$(echo "${lEID_VALUE}" | grep "Exploit DB Id:" | cut -d: -f2)
        mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR < <(grep "${lEID_VALUE}" "${CONFIG_DIR}/routersploit_exploit-db.txt" 2>/dev/null || true)
      done

      readarray -t lEXPLOIT_IDS_ARR < <(echo "${lEXPLOIT_AVAIL_EDB_ARR[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (EDB ID:"
      else
        lEXPLOIT+=" / EDB ID:"
      fi

      for lEXPLOIT_ID in "${lEXPLOIT_IDS_ARR[@]}" ; do
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:EDB:${lEXPLOIT_ID}" )
        lEXPLOIT+=" ${lEXPLOIT_ID}"
        write_log "[+] Exploit for ${lCVE_ID}:\\n" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
        write_log "[+] EDB Exploit for ${lCVE_ID} identified"  "${LOG_PATH_MODULE}/exploit/EDB_${lEXPLOIT_ID}_notes.txt"
        write_log "${lEXPLOIT_AVAIL_EDB_ARR[*]/\ /\\n}" "${LOG_PATH_MODULE}/exploit/edb_${lEXPLOIT_ID}_notes.txt"
        # write_log "${lLINE}" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: local" && "${lLOCAL:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (L)"
          lLOCAL=1
        fi
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: remote" && "${lREMOTE:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (R)"
          lREMOTE=1
        fi
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: dos" && "${lDOS:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (D)"
          lDOS=1
        fi
        lEDB=1
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};exploit_db" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      done

      # copy the exploit-db exploits to the report
      for lEXPLOIT_ENTRY in "${lEXPLOIT_AVAIL_EDB_ARR[@]}"; do
        if [[ "${lEXPLOIT_ENTRY}" =~ "File:" ]]; then
          lE_FILE=$(echo "${lEXPLOIT_ENTRY}" | awk '{print $2}')
          if [[ -f "${lE_FILE}" ]] ; then
            cp "${lE_FILE}" "${LOG_PATH_MODULE}""/exploit/edb_""$(basename "${lE_FILE}")" || print_error "[-] Copy exploit error for ${lE_FILE}"
          fi
        fi
      done
    fi

    if [[ ${#lEXPLOIT_AVAIL_MSF_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (MSF:"
      else
        lEXPLOIT+=" / MSF:"
      fi

      for lEXPLOIT_MSF in "${lEXPLOIT_AVAIL_MSF_ARR[@]}" ; do
        if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
          lEXPLOIT_PATH=$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        else
          lEXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        fi
        lEXPLOIT_NAME=$(basename -s .rb "${lEXPLOIT_PATH}")
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:MSF:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ -f "${lEXPLOIT_PATH}" ]] ; then
          # for the web reporter we copy the original metasploit module into the EMBA log directory
          cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/msf_""${lEXPLOIT_NAME}".rb
          if grep -q "< Msf::Exploit::Remote" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (R)"
          fi
          if grep -q "< Msf::Exploit::Local" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (L)"
          fi
          if grep -q "include Msf::Auxiliary::Dos" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (D)"
          fi
        fi
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the msf exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};MSF" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ ${#lEXPLOIT_AVAIL_SNYK_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Snyk:"
      else
        lEXPLOIT+=" / Snyk:"
      fi

      for lEXPLOIT_SNYK in "${lEXPLOIT_AVAIL_SNYK_ARR[@]}" ; do
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_SNYK}" | cut -d\; -f2)
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:SNYK:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ "${lTYPE}" != "NA" ]]; then
          lEXPLOIT+=" (${lTYPE})"
        fi
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the snyk exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};SNYK" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ ${#lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (PSS:"
      else
        lEXPLOIT+=" / PSS:"
      fi

      for lEXPLOIT_PS in "${lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]}" ; do
        # we use the html file as lEXPLOIT_NAME.
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:PSS:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        lPS_TYPE=$(grep "^${lCVE_ID};" "${CONFIG_DIR}"/PS_PoC_results.csv | grep "${lEXPLOIT_NAME}" | cut -d\; -f4 || true)
        if [[ "${lPS_TYPE}" == "remote" ]]; then
          lPS_TYPE="R"
        elif [[ "${lPS_TYPE}" == "local" ]]; then
          lPS_TYPE="L"
        elif [[ "${lPS_TYPE}" == "DoS" ]]; then
          lPS_TYPE="D"
        else
          # fallback to CVSS type
          if [[ "${lTYPE}" != "NA" ]]; then
            lPS_TYPE="${lTYPE}"
          fi
        fi
        lEXPLOIT+=" (${lPS_TYPE})"
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the packetstorm exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};PSS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ "${#lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" -gt 0 || "${#lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}" -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Routersploit:"
      else
        lEXPLOIT+=" / Routersploit:"
      fi
      local lEXPLOIT_ROUTERSPLOIT_ARR=("${lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" "${lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}")

      for lEXPLOIT_RS in "${lEXPLOIT_ROUTERSPLOIT_ARR[@]}" ; do
        lEXPLOIT_PATH=$(echo "${lEXPLOIT_RS}" | cut -d: -f1)
        lEXPLOIT_NAME=$(basename -s .py "${lEXPLOIT_PATH}")
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:RS:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ -f "${lEXPLOIT_PATH}" ]] ; then
          # for the web reporter we copy the original metasploit module into the EMBA log directory
          cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${lEXPLOIT_NAME}".py
          if grep -q Port "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (R)"
          else
            # fallback to CVSS type
            if [[ "${lTYPE}" != "NA" ]]; then
              lEXPLOIT+=" (${lTYPE})"
            fi
          fi
        fi
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the routersploit exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};RS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ ${lEDB} -eq 1 ]]; then
      lEXPLOIT+=")"
    fi

    # if this CVE is a kernel verified CVE we add a V to the CVE
    if [[ "${lKERNEL_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi
    if [[ "${lBUSYBOX_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi
  fi

  lCVSS_SCORE_VERS="${lCVSS_SCORE} (v${lCVSS_VERS})"

  # we do not deal with output formatting the usual way -> we use printf
  if [[ ! -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt" ]]; then
    printf "${GREEN}\t%-20.20s:   %-12.12s:   %-20.20s:  %-10.10s : %-4.4s :   %-15.15s:   %s${NC}\n" "BIN NAME" "BIN VERS" "CVE ID" "CVSS VALUE" "EPSS" "SOURCE" "EXPLOIT" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
  fi
  if [[ "${lCVSS_SEVERITY}" == "CRITICAL" ]]; then
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  elif [[ "${lCVSS_SEVERITY}" == "HIGH" ]]; then
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  elif [[ "${lCVSS_SEVERITY}" == "MEDIUM" ]]; then
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  else
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      printf "${GREEN}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  fi

  # generate the vulnerability details for the SBOM (VEX)

  # external/nvd-json-data-feeds/CVE-2022/CVE-2022-25xx/CVE-2022-2586.json
  mapfile -t lCWE < <(grep -o -E "CWE-[0-9]+" "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null | sort -u | cut -d '-' -f2|| true)
  lCVE_DESC=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null || true)

  local lVULN_BOM_REF=""
  lVULN_BOM_REF=$(uuidgen)
  build_sbom_json_properties_arr "${lVEX_EXPLOIT_PROP_ARRAY_ARR[@]}"
  # => we get PROPERTIES_JSON_ARR as global

  # print_output "[*] Generating CVE entry as VEX json: ${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lEXPLOIT}" "no_log"

  # Todo: do this more dynamically
  if [[ "${lVULN_SOURCE}" == "NVD" ]]; then
    local lVULN_URL="https://nvd.nist.gov/vuln/detail/${lCVE_ID}"
  else
    local lVULN_URL="UNKNOWN"
  fi

  # trivially rounding the cvss score to ensure we have clean values:
  if [[ "${lCVSS_SCORE}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    lCVSS_SCORE=$(printf "%.${2:-1}f" "${lCVSS_SCORE}")
  else
    # just in case we have some bogus not number thing in the score field
    lCVSS_SCORE=0
  fi

  jo -p -n -- \
    bom-ref="${lVULN_BOM_REF}" \
    id="${lCVE_ID}" \
    source="$(jo -n name="${lVULN_SOURCE}" url="${lVULN_URL}")" \
    ratings="$(jo -a "$(jo -n score="${lCVSS_SCORE}" severity="${lCVSS_SEVERITY,,}" method="CVSSv${lCVSS_VERS}" vector="${lCVSS_VECTOR}")")" \
    cwes="$(jo -a "${lCWE[@]:-null}")" \
    analysis="$(jo -n state="in_triage")" \
    description="${lCVE_DESC}" \
    affects="$(jo -a "$(jo -n ref="${lBOM_REF}" versions="$(jo -a "$(jo -n -- -s component="${lPRODUCT_NAME}" -s version="${lVERS}")")")")" \
    properties="$(jo -a "${PROPERTIES_JSON_ARR[@]:-null}")" \
    > "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" || print_error "[*] VEX entry failed for ${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lEXPLOIT}"

  # make it nice:
  jq . "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" > "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.json"

  # cleanup
  rm "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" || true
}

get_kernel_s25_data() {
  export KERNEL_CVE_EXPLOITS_ARR=()

  if [[ -f "${S25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S25_LOG}")."
    readarray -t KERNEL_CVE_EXPLOITS_ARR < <(cut -d\; -f1-3 "${S25_LOG}" | tail -n +2 | sort -u || true)
    # we get something like this: ":linux:linux_kernel;5.10.59;CVE-2021-3490"
  fi
}

get_epss_data() {
  local lCVE_ID="${1:-}"
  local lCVE_EPSS_PATH=""
  local lEPSS_PERC=""
  local lEPSS_EPSS=""
  local lEPSS_DATA=""
  local lCVE_YEAR=""

  lCVE_YEAR="$(echo "${lCVE_ID}" | cut -d '-' -f2)"
  lCVE_EPSS_PATH="${EPSS_DATA_PATH}/CVE_${lCVE_YEAR}_EPSS.csv"
  if [[ -f "${lCVE_EPSS_PATH}" ]]; then
    lEPSS_DATA=$(grep "^${lCVE_ID};" "${lCVE_EPSS_PATH}" || true)
    lEPSS_PERC=$(echo "${lEPSS_DATA}" | cut -d ';' -f3)
    lEPSS_PERC=$(echo "${lEPSS_PERC} 100" | awk '{printf "%d", $1 * $2}')
    # just cut it for now ...
    lEPSS_EPSS=$(echo "${lEPSS_DATA}" | cut -d ';' -f2)
    lEPSS_EPSS=$(echo "${lEPSS_EPSS} 100" | awk '{printf "%d", $1 * $2}')
  fi
  [[ ! "${lEPSS_EPSS}" =~ ^[0-9]+$ ]] && lEPSS_EPSS="NA"
  [[ ! "${lEPSS_PERC}" =~ ^[0-9]+$ ]] && lEPSS_PERC="NA"
  echo "${lEPSS_EPSS};${lEPSS_PERC}"
}

backup_vex_file() {
  local lFILE_PATH="${1:-}"

  if [[ -f "${lFILE_PATH}" ]]; then
    local lCOUNTER=1
    local lBASE_NAME="${lFILE_PATH%%.json}"
    while [[ -f "${lBASE_NAME}.previous_${lCOUNTER}.json" ]]; do
      ((lCOUNTER++))
    done

    if [[ -f "${lBASE_NAME}.previous.json" ]]; then
      mv "${lBASE_NAME}.previous.json" "${lBASE_NAME}.previous_${lCOUNTER}.json"
    fi

    mv "${lFILE_PATH}" "${lBASE_NAME}.previous.json"
    print_output "[*] Backed up ${lFILE_PATH} as $(basename "${lBASE_NAME}.previous.json")" "no_log"
  fi
}

