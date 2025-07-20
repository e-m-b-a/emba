#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  After modules s115/s116 was able to identify BusyBox with the version identifier
#               and the included applets this module checks the possible vulnerabilities
#               with the BusyBox against the CVE database

S118_busybox_verifier()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Busybox vulnerability identification and verification"
  pre_module_reporter "${FUNCNAME[0]}"
  local lNEG_LOG=0

  local lBB_BINS_ARR=()
  local lBB_VERSION=""
  local lBB_BIN=""
  export PACKAGING_SYSTEM="bb_verified"
  local lBB_RESULT_FILE=""
  local lBB_SBOMs_ARR=()

  module_wait "S116_qemu_version_detection"
  module_wait "S09_firmware_base_version_check"

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    mapfile -t lBB_SBOMs_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -name "*busybox_*.json")
  fi

  # if we have no results already we can try to search manually now
  # this usually happens if s09 and s115/116 is disabled
  # This mode is a backup mode
  if [[ "${#lBB_SBOMs_ARR[@]}" -eq 0 ]]; then
    # first grep is for identification of possible binary files:
    mapfile -t lBB_BINS_ARR < <(grep -l -a -E "BusyBox" "${LOG_DIR}"/firmware -r 2>/dev/null || true)

    for lBB_BIN in "${lBB_BINS_ARR[@]}"; do
      if [[ "${lBB_BIN}" == *".raw" ]]; then
        # skip binwalk raw files
        continue
      fi
      # get the binary data from P99 log for further processing
      local lBINARY_DATA=""
      local lVERSION_JSON_CFG="${CONFIG_DIR}"/bin_version_identifiers/busybox.json
      local lVERSION_IDENTIFIER_ARR=()
      local lVERSION_IDENTIFIER=""
      lBINARY_DATA=$(grep ";${lBB_BIN};.*ELF" "${P99_CSV_LOG}" | head -1 || true)
      if [[ -z ${lBINARY_DATA} ]]; then
        # we have not found our binary as ELF
        continue
      fi

      # extract the grep commands for our version identification
      mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
      for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
        lVERSION_IDENTIFIED=$(strings "${lBB_BIN}" | grep -a -E "${lVERSION_IDENTIFIER}" | sort -u | head -1 || true)
        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          local lRULE_IDENTIFIER=""
          local lLICENSES_ARR=()
          local lPRODUCT_NAME_ARR=()
          local lVENDOR_NAME_ARR=()
          local lCSV_REGEX_ARR=()

          # lets build the data we need for version_parsing_logging
          lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
          mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
          # shellcheck disable=SC2034
          mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
          # shellcheck disable=SC2034
          mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
          # shellcheck disable=SC2034
          mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

          export TYPE="static"
          export CONFIDENCE_LEVEL=3

          if version_parsing_logging "${S09_CSV_LOG}" "S118_busybox_verifier" "${lVERSION_IDENTIFIED}" "${lBINARY_DATA}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
            # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
            continue 2
          fi
        fi
        print_output "[*] Found busybox binary - ${lBB_BIN} - ${lVERSION_IDENTIFIED:-NA} - ${lLICENSES_ARR[*]}" "no_log"
      done
    done
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  local lBB_VERSION_DONE_ARR=()
  mapfile -t lBB_SBOMs_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 ! -name "*unhandled_file*" -name "*busybox_*.json")
  for lBB_SBOM_JSON in "${lBB_SBOMs_ARR[@]}"; do
    export BB_VERIFIED_APPLETS=()
    local lBB_VERSION=""
    lBB_VERSION=$(jq -r .version "${lBB_SBOM_JSON}" || print_error "[-] S118 - BB version extraction failed for ${lBB_SBOM_JSON}")
    local lBB_PRODUCT=""
    lBB_PRODUCT=$(jq -r .name "${lBB_SBOM_JSON}" || print_error "[-] S118 - BB name extraction failed for ${lBB_SBOM_JSON}")
    lBB_PRODUCT=${lBB_PRODUCT,,}
    local lBB_VENDOR=""
    lBB_VENDOR=$(jq -r .supplier.name "${lBB_SBOM_JSON}" || print_error "[-] S118 - BB supplier.name extraction failed for ${lBB_SBOM_JSON}")
    lBB_VENDOR=${lBB_VENDOR,,}

    local lBB_BIN=""
    lBB_BIN="$(jq -r '.properties[]? | select(.name | test("source_path")) | .value' "${lBB_SBOM_JSON}" || print_error "[-] S118 - BB source_path extraction failed for ${lBB_SBOM_JSON}")"
    lBB_BIN="${lBB_BIN#\'}"
    lBB_BIN="${lBB_BIN%\'}"
    if ! [[ -f "${lBB_BIN}" ]]; then
      print_output "[-] No file detected for ${lBB_BIN} ... testing for further SBOM entries"
      continue
    fi
    if ! [[ "$(grep "${lBB_BIN}" "${P99_CSV_LOG}" | cut -d ';' -f8 || true)" == *"ELF"* ]]; then
      print_output "[-] No ELF file detected for ${lBB_BIN} ... testing for further SBOM entries"
      continue
    fi
    local lALL_BB_VULNS_ARR=()
    local lBB_APPLET=""
    local lSUMMARY=""
    local lWAIT_PIDS_S118_ARR=()

    if [[ "${lBB_VERSION_DONE_ARR[*]}" == *"${lBB_VERSION}"* ]]; then
      # we already tested this version and ensure we do not duplicate this check
      continue
    fi

    # rewrite our minimal version to an array ":vendor:product:version"
    print_output "[*] Testing busybox version :${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION} - ${lBB_SBOM_JSON}" "no_log"
    lBB_VERSION_DONE_ARR+=( "${lBB_VERSION}" )

    local lBOM_REF=""
    lBOM_REF=$(jq -r '."bom-ref"' "${lBB_SBOM_JSON}" || true)
    local lORIG_SOURCE="bb_verified"
    export CVE_DETAILS_PATH="${LOG_PATH_MODULE}/${lBOM_REF}_${lBB_PRODUCT}_${lBB_VERSION}.csv"

    get_cve_busybox_data "${lBB_SBOM_JSON}"

    if ! [[ -f "${CVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated (${lBOM_REF}_${lBB_PRODUCT}_${lBB_VERSION}.csv) ... check for further BusyBox version"
      continue
    fi

    get_busybox_applets_emu ":${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}"
    get_busybox_applets_stat ":${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}" "${lBB_BIN}"

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}_stat.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}_stat.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}.tmp"
    fi
    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}_emu.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}_emu.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}.tmp"
    fi

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}.tmp" ]]; then
      mapfile -t BB_VERIFIED_APPLETS < <(sort -u "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}.tmp")
      rm "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION}.tmp" || true
    fi

    print_output "[*] Create CVE vulnerabilities array for BusyBox version ${ORANGE}:${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}${NC} ..." "no_log"
    mapfile -t lALL_BB_VULNS_ARR < <(tail -n+2 "${CVE_DETAILS_PATH}")

    if [[ "${#lALL_BB_VULNS_ARR[@]}" -eq 0 ]] || [[ "${#BB_VERIFIED_APPLETS[@]}" -eq 0 ]]; then
      print_output "[-] No BusyBox vulnerability or applets found for ${ORANGE}:${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}${NC}"
      continue
    fi

    print_ln
    sub_module_title "BusyBox - Vulnerability verification - :${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}"
    print_output "[+] Extracted ${ORANGE}${#lALL_BB_VULNS_ARR[@]}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
    print_ln

    local lVULN_CNT=0
    local lVULN=""
    write_csv_log "BusyBox VERSION" "BusyBox APPLET" "Verified CVE" "CNT all CVEs" "CVE Summary"
    for lVULN in "${lALL_BB_VULNS_ARR[@]}"; do
      lVULN_CNT=$((lVULN_CNT+1))
      busybox_vuln_testing_threader "${lVULN}" "${lVULN_CNT}" "${#lALL_BB_VULNS_ARR[@]}" ":${lBB_VENDOR}:${lBB_PRODUCT}:${lBB_VERSION}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S118_ARR+=( "${lTMP_PID}" )
      lNEG_LOG=1
    done
    wait_for_pid "${lWAIT_PIDS_S118_ARR[@]}"
  done

  for lBB_RESULT_FILE in "${LOG_PATH_MODULE}"/tmp/*; do
    if [[ -f "${lBB_RESULT_FILE}" ]]; then
      tee -a "${LOG_FILE}" < "${lBB_RESULT_FILE}"
    fi
  done

  # fix the CVE log file and add the verified vulnerabilities:
  if [[ -f "${S118_LOG_DIR}/vuln_summary.txt" ]]; then
    # extract the verified CVEs:
    mapfile -t lVERIFIED_BB_VULNS_ARR < <(grep -E -o ";CVE-[0-9]+-[0-9]+;" "${S118_CSV_LOG}" 2>/dev/null || true)
    if [[ "${#lVERIFIED_BB_VULNS_ARR[@]}" -gt 0 ]]; then
      local lTMP_CVE_ENTRY=""
      # get the CVEs part of vuln_summary.txt
      lTMP_CVE_ENTRY=$(grep -o -E ":\s+CVEs:\ [0-9]+\s+:" "${LOG_PATH_MODULE}/vuln_summary.txt" | sort -u || true)
      # replace the spaces with the verified entry -> :  CVEs: 1234 (123):
      lTMP_CVE_ENTRY=$(echo "${lTMP_CVE_ENTRY}" | sed -r 's/(CVEs:\ [0-9]+)\s+/\1 ('"${#lVERIFIED_BB_VULNS_ARR[@]}"')/')
      # ensure we have the right length -> :  CVEs: 1234 (123)  :
      lTMP_CVE_ENTRY=$(printf '%s%*s' "${lTMP_CVE_ENTRY%:}" "$((22-"${#lTMP_CVE_ENTRY}"))" ":")

      # final replacement in file:
      sed -i -r 's/:\s+CVEs:\ [0-9]+\s+:/'"${lTMP_CVE_ENTRY}"'/' "${LOG_PATH_MODULE}/vuln_summary.txt" || print_error "[-] BusyBox verification module - final replacement failed for ${lTMP_CVE_ENTRY}"

      # now add the (V) entry to every verified vulnerability
      for lVERIFIED_BB_CVE in "${lVERIFIED_BB_VULNS_ARR[@]}"; do
        lVERIFIED_BB_CVE="${lVERIFIED_BB_CVE//;}"
        local lV_ENTRY="(V)"
        # ensure we have the correct length
        # shellcheck disable=SC2183
        lV_ENTRY=$(printf '%s%*s' "${lV_ENTRY}" "$((19-"${#lVERIFIED_BB_CVE}"-"${#lV_ENTRY}"))")
        sed -i -r 's/('"${lVERIFIED_BB_CVE}"')\s+/\1 '"${lV_ENTRY}"'/' "${S118_LOG_DIR}/cve_sum/"*_finished.txt || true
      done
    fi
    lNEG_LOG=1
  fi

  if [[ -d "${LOG_PATH_MODULE}/tmp" ]]; then
    rm -r "${LOG_PATH_MODULE}/tmp" || true
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

busybox_vuln_testing_threader() {
  local lVULN="${1:-}"
  local lVULN_CNT="${2:-}"
  local lALL_BB_VULNS_ARR_SIZE="${3:-}"
  local lBB_VERSION="${4:-}"


  # print_output "[*] VULN: ${lVULN}"
  local lCVE=""
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  local lLOG_FILE_BB_MODULE="${LOG_PATH_MODULE}/tmp/${lCVE}"

  if ! [[ -d "${LOG_PATH_MODULE}/tmp" ]]; then
    mkdir "${LOG_PATH_MODULE}/tmp" 2>/dev/null || true
  fi

  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)
  # print_output "[*] ${lCVE} - ${lSUMMARY}"
  print_output "[*] Testing vulnerability ${ORANGE}${lVULN_CNT}${NC} / ${ORANGE}${lALL_BB_VULNS_ARR_SIZE}${NC} / ${ORANGE}${lCVE}${NC}" "no_log"

  for lBB_APPLET in "${BB_VERIFIED_APPLETS[@]}"; do
    # remove false positives for applet "which"
    if [[ "${lBB_APPLET}" == "which" ]] && [[ "${lSUMMARY}" == *"\,\ ${lBB_APPLET}\ "* ]]; then
      continue
    fi
    # print_output "[*] Testing applet ${lBB_APPLET} against Summary: ${lSUMMARY}"
    if [[ "${lSUMMARY}" == *" ${lBB_APPLET} "* ]]; then
      write_log "[+] Verified BusyBox vulnerability ${ORANGE}${lCVE}${GREEN} - applet ${ORANGE}${lBB_APPLET}${GREEN}" "${lLOG_FILE_BB_MODULE}"
      echo -e "\t${lSUMMARY//\\/}" | sed -e "s/\ ${lBB_APPLET}\ /\ ${ORANGE_}${lBB_APPLET}${NC_}\ /g" | tee -a "${lLOG_FILE_BB_MODULE}"
      write_csv_log "${lBB_VERSION}" "${lBB_APPLET}" "${lCVE}" "${lALL_BB_VULNS_ARR_SIZE}" "${lSUMMARY}"
      write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_BB_MODULE}"
    fi
  done
}

get_busybox_applets_stat() {
  local lBB_VERSION_="${1:-}"
  local lBB_BIN_="${2:-}"

  local lBB_BINS_ARR=()
  local lAPP_CNT=0
  local lBB_DETECTED_APPLETS_ARR=()
  local lBB_DETECTED_APPLET=""

  print_ln
  sub_module_title "BusyBox - Static applet identification from binary"

  # quite often we only have the firmware path without the filesytem area: /bin/busybox
  # This results in another search for our binary
  mapfile -t lBB_BINS_ARR < <(find "${LOG_DIR}"/firmware -wholename "*${lBB_BIN_}*" -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "ELF" | cut -d: -f1' | sort -u || true)
  for lBB_BIN_ in "${lBB_BINS_ARR[@]}"; do
    print_output "[*] Extract applet data for BusyBox version ${ORANGE}${lBB_VERSION_}${NC} from binary ${ORANGE}${lBB_BIN_}${NC}"
    mapfile -t lBB_DETECTED_APPLETS_ARR < <(grep -oUaP "\x00\x5b(\x5b)?\x00.*\x00\x00" "${lBB_BIN_}" | strings | sort -u || true)
    for lBB_DETECTED_APPLET in "${lBB_DETECTED_APPLETS_ARR[@]}"; do
      if grep -E -q "^${lBB_DETECTED_APPLET}$" "${CONFIG_DIR}/busybox_commands.cfg"; then
        print_output "[*] BusyBox Applet found and identified as real BusyBox applet ... ${ORANGE}${lBB_DETECTED_APPLET}${NC}" "no_log"
        echo "${lBB_DETECTED_APPLET}" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION_/*:/}_stat.txt"
        lAPP_CNT=$((lAPP_CNT+1))
      fi
    done
  done
  print_output "[+] Extracted ${ORANGE}${lAPP_CNT}${GREEN} valid BusyBox applets via static analysis" "" "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION_/*:/}_stat.txt"
}

get_busybox_applets_emu() {
  local lBB_VERSION_="${1:-}"

  local lBB_QEMU_FILES_ARR=()
  local lBB_FILE=""
  local lAPP_CNT=0
  local lBB_DETECTED_APPLETS_ARR=()
  local lBB_DETECTED_APPLET=""

  print_ln
  sub_module_title "BusyBox - Applet identification via emulation results"

  mapfile -t lBB_QEMU_FILES_ARR < <(find "${LOG_DIR}"/s115_usermode_emulator/ -name "qemu_tmp*busybox*txt" 2>/dev/null || true)
  for lBB_FILE in "${lBB_QEMU_FILES_ARR[@]}"; do
    print_output "[*] Extract applet data for BusyBox version ${ORANGE}${lBB_VERSION_}${NC} from emulation logs" "" "${lBB_FILE}"
    mapfile -t lBB_DETECTED_APPLETS_ARR < <(sed -e '1,/Currently defined functions:/d' "${lBB_FILE}" | grep ", " | tr ',' '\n' | tr -d '[' | tr -d ']' | tr -d "[:blank:]" | tr -s '\n' '\n' | sort -u || true)
    for lBB_DETECTED_APPLET in "${lBB_DETECTED_APPLETS_ARR[@]}"; do
      if grep -E -q "^${lBB_DETECTED_APPLET}$" "${CONFIG_DIR}/busybox_commands.cfg"; then
        print_output "[*] BusyBox Applet found and identified as real BusyBox applet ... ${ORANGE}${lBB_DETECTED_APPLET}${NC}" "no_log"
        echo "${lBB_DETECTED_APPLET}" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION_/*:/}_emu.txt"
        lAPP_CNT=$((lAPP_CNT+1))
      fi
    done
  done
  print_output "[+] Extracted ${ORANGE}${lAPP_CNT}${GREEN} valid BusyBox applets from usermode log files" "" "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION_/*:/}_emu.txt"
}

get_cve_busybox_data() {
  local lBB_SBOM_JSON="${1:-}"
  local lVENDOR_ARR=()
  local lPRODUCT_ARR=()
  local lPRODUCT_VERSION=""

  mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' "${lBB_SBOM_JSON}" || print_error "[-] S118 - No SBOM vendor data extracted for ${lBB_SBOM_JSON}")
  if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
    lVENDOR_ARR+=("NOTDEFINED")
  fi
  # shellcheck disable=SC2034
  mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' "${lBB_SBOM_JSON}" || print_error "[-] S118 - No SBOM product data extracted for ${lBB_SBOM_JSON}")

  lPRODUCT_VERSION=$(jq --raw-output '.version' "${lBB_SBOM_JSON}" || print_error "[-] S118 - No SBOM version data extracted for ${lBB_SBOM_JSON}")
  if [[ -z "${lPRODUCT_VERSION}" ]]; then
    return
  fi

  local lVULN_CNT=""
  local lWAIT_PIDS_S118_ARR=()

  local lBOM_REF=""
  lBOM_REF=$(jq -r '."bom-ref"' "${lBB_SBOM_JSON}" || true)
  local lORIG_SOURCE="bb_verified"

  sub_module_title "BusyBox - Version based vulnerability detection"

  cve_bin_tool_threader "${lBOM_REF}" "${lPRODUCT_VERSION}" "${lORIG_SOURCE}" lVENDOR_ARR lPRODUCT_ARR

  if [[ -f "${CVE_DETAILS_PATH}" ]]; then
    lVULN_CNT="$(wc -l < "${CVE_DETAILS_PATH}")"
    if [[ "${lVULN_CNT}" -gt 0 ]]; then
      # remove the first csv line
      lVULN_CNT=$((lVULN_CNT-1))
    fi

    # lets create a more beautifull log for the report:
    local lCVE_LINE_ENTRY=""
    while read -r lCVE_LINE_ENTRY; do
      get_cve_busybox_data_threader "${lCVE_LINE_ENTRY}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S118_ARR+=( "${lTMP_PID}" )
    done < "${CVE_DETAILS_PATH}"

    wait_for_pid "${lWAIT_PIDS_S118_ARR[@]}"

    for lCVE_NICE_REPORT in "${CVE_DETAILS_PATH/.csv/_CVE-}"*; do
      cat "${lCVE_NICE_REPORT}" >> "${CVE_DETAILS_PATH/.csv/_nice.txt}"
      rm "${lCVE_NICE_REPORT}" >/dev/null || true
    done

    print_output "[+] Extracted ${ORANGE}${lVULN_CNT}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.csv/_nice.txt}"
  fi
}

get_cve_busybox_data_threader() {
  local lCVE_LINE_ENTRY="${1:-}"
  # print_output "[*] lCVE_LINE_ENTRY: ${lCVE_LINE_ENTRY}"

  local lCVE_ID=""
  local lCVSS_V3=""
  local lFIRST_EPSS=""
  local lCVE_SUMMARY=""

  lCVE_ID=$(echo "${lCVE_LINE_ENTRY}" | cut -d, -f4)
  lCVSS_V3=$(echo "${lCVE_LINE_ENTRY}" | cut -d, -f6)
  lFIRST_EPSS="$(get_epss_data "${lCVE_ID}")"
  lFIRST_EPSS="${lFIRST_EPSS/\;*}"
  lCVE_SUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null || true)
  # print_output "[*] ${lCVE_ID} - ${lCVSS_V3} - ${lFIRST_EPSS} - ${lCVE_SUMMARY}"

  write_log "${ORANGE}${lCVE_ID}:${NC}" "${CVE_DETAILS_PATH/.csv/_${lCVE_ID}_nice.txt}"
  write_log "$(indent "CVSS: ${ORANGE}${lCVSS_V3}${NC}")" "${CVE_DETAILS_PATH/.csv/_${lCVE_ID}_nice.txt}"
  write_log "$(indent "FIRST EPSS: ${ORANGE}${lFIRST_EPSS}${NC}")" "${CVE_DETAILS_PATH/.csv/_${lCVE_ID}_nice.txt}"
  write_log "$(indent "Summary: ${ORANGE}${lCVE_SUMMARY}${NC}")" "${CVE_DETAILS_PATH/.csv/_${lCVE_ID}_nice.txt}"
  write_log "" "${CVE_DETAILS_PATH/.csv/_${lCVE_ID}_nice.txt}"
}
