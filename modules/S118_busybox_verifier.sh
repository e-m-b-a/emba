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

  local lBB_VERSIONS_ARR=()
  local lBB_BINS_ARR=()
  local lBB_VERSION=""
  local lBB_BIN=""
  local lBB_ENTRY=""
  local lVERSION_IDENTIFIER=""
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lAPP_LIC="GPL-2.0-only"
  local lAPP_MAINT=""
  local lAPP_VERS=""
  local lBIN_FILE=""
  local lBIN_ARCH=""
  local lPACKAGING_SYSTEM="static_busybox_analysis"
  local lCPE_IDENTIFIER=""
  local lPURL_IDENTIFIER=""
  local lBB_RESULT_FILE=""

  module_wait "S116_qemu_version_detection"
  module_wait "S09_firmware_base_version_check"

  if [[ -f "${S116_CSV_LOG}" ]]; then
    mapfile -t lBB_VERSIONS_ARR < <(grep ";busybox;" "${S116_CSV_LOG}" | cut -d\; -f1,4 | sort -u || true)
  fi

  # if don't get our version details from S116/S115 we need to fallback to s09
  if [[ "${#lBB_VERSIONS_ARR[@]}" -eq 0 ]]; then
    if [[ -f "${S09_CSV_LOG}" ]]; then
      mapfile -t lBB_VERSIONS_ARR < <(grep ";busybox;" "${S09_CSV_LOG}" | cut -d\; -f1,4 | sort -u || true)
    fi
  fi

  # finally we search manually for the version
  if [[ "${#lBB_VERSIONS_ARR[@]}" -eq 0 ]]; then
    # first grep is for identification of possible binary files:
    mapfile -t lBB_BINS_ARR < <(grep -l -a -E "BusyBox\ v[0-9](\.[0-9]+)+?.*" "${LOG_DIR}"/firmware -r 2>/dev/null || true)
    for lBB_BIN in "${lBB_BINS_ARR[@]}"; do
      lBIN_FILE=$(file -b "${lBB_BIN}")
      if ! [[ "${lBIN_FILE}" == *"ELF"* ]]; then
        continue
      fi
      # now modify the version identifier to use it also for our CVE identification
      lVERSION_IDENTIFIER=$(strings "${lBB_BIN}" | grep -E "BusyBox\ v[0-9](\.[0-9]+)+?.*" | sort -u | sed -r 's/BusyBox\ v([0-9](\.[0-9]+)+?)\ .*/:busybox:busybox:\1/' | sort -u | head -1 || true)
      # build the needed array
      lBB_VERSIONS_ARR+=( "${lBB_BIN};${lVERSION_IDENTIFIER}" )

      check_for_s08_csv_log "${S08_CSV_LOG}"

      lMD5_CHECKSUM="$(md5sum "${lBB_BIN}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lBB_BIN}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lBB_BIN}" | awk '{print $1}')"
      lCPE_IDENTIFIER=$(build_cpe_identifier "${lVERSION_IDENTIFIER}")
      lOS_IDENTIFIED=$(distri_check)

      lBIN_ARCH=$(echo "${lBIN_FILE}" | cut -d ',' -f2)
      lBIN_ARCH=${lBIN_ARCH#\ }
      lPURL_IDENTIFIER=$(build_generic_purl "${lVERSION_IDENTIFIER}" "${lOS_IDENTIFIED}" "${lBIN_ARCH:-NA}")

      lAPP_MAINT=$(echo "${lVERSION_IDENTIFIER}" | cut -d ':' -f2)
      lAPP_NAME=$(echo "${lVERSION_IDENTIFIER}" | cut -d ':' -f3)
      lAPP_VERS=$(echo "${lVERSION_IDENTIFIER}" | cut -d ':' -f4-5)

      # add source file path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lBB_BIN}" )
      lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_details:${lBIN_FILE}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lVERSION_IDENTIFIER}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:medium" )

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lBB_BIN}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "static_busybox_analysis;${lBB_BIN:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};$(basename "${lBB_BIN}");NA;${lVERSION_IDENTIFIER:-NA};GPL-2.0-only;maintainer unknown;unknown;${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
      print_output "[*] Found busybox binary - ${lBB_BIN} - ${lVERSION_IDENTIFIER:-NA} - GPL-2.0-only" "no_log"
    done
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  local lBB_VERSION_DONE_ARR=()
  for lBB_ENTRY in "${lBB_VERSIONS_ARR[@]}"; do
    export BB_VERIFIED_APPLETS=()
    local lBB_VERSION="${lBB_ENTRY/*;}"
    local lBB_BIN="${lBB_ENTRY/;*}"
    local lBB_VERSION_tmp="${lBB_VERSION#:}"
    local lBB_VERSION_tmp="${lBB_VERSION_tmp//:/_}"
    local lALL_BB_VULNS_ARR=()
    local lBB_APPLET=""
    local lSUMMARY=""
    local lWAIT_PIDS_S118_ARR=()

    if [[ "${lBB_VERSION_DONE_ARR[*]}" == *"${lBB_VERSION}"* ]]; then
      # we already tested this version and ensure we do not duplicate this check
      continue
    fi

    mapfile -t lBB_VERSION_ARR < <(echo "${lBB_VERSION}" | tr ':' '\n')
    lBB_VERSION_DONE_ARR+=( "${lBB_VERSION}" )

    local lBOM_REF=""
    lBOM_REF=$(jq -r '."bom-ref"' "${SBOM_LOG_PATH}"/*busybox_*.json | sort -u | head -1 || true)
    local lORIG_SOURCE="static_busybox_analysis"
    local lVENDOR="${lBB_VERSION_ARR[*]:1:1}"
    local lPROD="${lBB_VERSION_ARR[*]:2:1}"
    local lVERS="${lBB_VERSION_ARR[*]:3:1}"
    export CVE_DETAILS_PATH="${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}.csv"
    # print_output "[*] ${lBOM_REF}_${lPROD}_${lVERS}.csv"

    get_cve_busybox_data "${lBB_VERSION_ARR[@]}"

    if ! [[ -f "${CVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated (${lBOM_REF}_${lPROD}_${lVERS}.csv) ... check for further BusyBox version"
      continue
    fi

    get_busybox_applets_emu "${lBB_VERSION}"
    get_busybox_applets_stat "${lBB_VERSION}" "${lBB_BIN}"

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}_stat.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}_stat.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}.tmp"
    fi
    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}_emu.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}_emu.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}.tmp"
    fi

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}.tmp" ]]; then
      mapfile -t BB_VERIFIED_APPLETS < <(sort -u "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}.tmp")
      rm "${LOG_PATH_MODULE}/busybox_applets_${lBB_VERSION/*:/}.tmp" || true
    fi

    print_output "[*] Create CVE vulnerabilities array for BusyBox version ${ORANGE}${lBB_VERSION}${NC} ..." "no_log"
    mapfile -t lALL_BB_VULNS_ARR < <(tail -n+2 "${CVE_DETAILS_PATH}")

    if [[ "${#lALL_BB_VULNS_ARR[@]}" -eq 0 ]] || [[ "${#BB_VERIFIED_APPLETS[@]}" -eq 0 ]]; then
      print_output "[-] No BusyBox vulnerability or applets found for ${ORANGE}${lBB_VERSION}${NC}"
      continue
    fi

    print_ln
    sub_module_title "BusyBox - Vulnerability verification - ${lBB_VERSION}"
    print_output "[+] Extracted ${ORANGE}${#lALL_BB_VULNS_ARR[@]}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
    print_ln

    local lVULN_CNT=0
    write_csv_log "BusyBox VERSION" "BusyBox APPLET" "Verified CVE" "CNT all CVEs" "CVE Summary"
    for VULN in "${lALL_BB_VULNS_ARR[@]}"; do
      lVULN_CNT=$((lVULN_CNT+1))
      busybox_vuln_testing_threader "${VULN}" "${lVULN_CNT}" "${#lALL_BB_VULNS_ARR[@]}" "${lBB_VERSION}" &
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
      lTMP_CVE_ENTRY=$(printf '%s%*s' "${lTMP_CVE_ENTRY%:}" $((22-${#lTMP_CVE_ENTRY})) ":")

      # final replacement in file:
      sed -i -r 's/:\s+CVEs:\ [0-9]+\s+:/'"${lTMP_CVE_ENTRY}"'/' "${LOG_PATH_MODULE}/vuln_summary.txt" || print_error "[-] BusyBox verification module - final replacement failed for ${lTMP_CVE_ENTRY}"

      # now add the (V) entry to every verified vulnerability
      for lVERIFIED_BB_CVE in "${lVERIFIED_BB_VULNS_ARR[@]}"; do
        lVERIFIED_BB_CVE="${lVERIFIED_BB_CVE//;}"
        local lV_ENTRY="(V)"
        # ensure we have the correct length
        lV_ENTRY=$(printf '%s%*s' ${lV_ENTRY} $((19-${#lVERIFIED_BB_CVE}-${#lV_ENTRY})))
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
  local VULN="${1:-}"
  local lVULN_CNT="${2:-}"
  local lALL_BB_VULNS_ARR_SIZE="${3:-}"
  local lBB_VERSION="${4:-}"

  # print_output "[*] VULN: ${VULN}"
  CVE=$(echo "${VULN}" | cut -d, -f5)
  local LOG_FILE_BB_MODULE="${LOG_PATH_MODULE}/tmp/${CVE}"

  if ! [[ -d "${LOG_PATH_MODULE}/tmp" ]]; then
    mkdir "${LOG_PATH_MODULE}/tmp" 2>/dev/null || true
  fi

  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${CVE%-*}/${CVE:0:11}"*"xx/${CVE}.json" 2>/dev/null || true)
  # print_output "[*] ${CVE} - ${lSUMMARY}"
  print_output "[*] Testing vulnerability ${ORANGE}${lVULN_CNT}${NC} / ${ORANGE}${lALL_BB_VULNS_ARR_SIZE}${NC} / ${ORANGE}${CVE}${NC}" "no_log"

  for lBB_APPLET in "${BB_VERIFIED_APPLETS[@]}"; do
    # remove false positives for applet "which"
    if [[ "${lBB_APPLET}" == "which" ]] && [[ "${lSUMMARY}" == *"\,\ ${lBB_APPLET}\ "* ]]; then
      continue
    fi
    # print_output "[*] Testing applet ${lBB_APPLET} against Summary: ${lSUMMARY}"
    if [[ "${lSUMMARY}" == *" ${lBB_APPLET} "* ]]; then
      write_log "[+] Verified BusyBox vulnerability ${ORANGE}${CVE}${GREEN} - applet ${ORANGE}${lBB_APPLET}${GREEN}" "${LOG_FILE_BB_MODULE}"
      echo -e "\t${lSUMMARY//\\/}" | sed -e "s/\ ${lBB_APPLET}\ /\ ${ORANGE_}${lBB_APPLET}${NC_}\ /g" | tee -a "${LOG_FILE_BB_MODULE}"
      write_csv_log "${lBB_VERSION}" "${lBB_APPLET}" "${CVE}" "${lALL_BB_VULNS_ARR_SIZE}" "${lSUMMARY}"
      write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_BB_MODULE}"
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
  local lBB_VERSION_ARR=("${@}")
  shift

  local lVULN_CNT=""
  local lWAIT_PIDS_S118_ARR=()

  local lBOM_REF=""
  lBOM_REF=$(jq -r '."bom-ref"' "${SBOM_LOG_PATH}"/*busybox_*.json | sort -u | head -1 || true)
  local lORIG_SOURCE="bb_verified"
  local lVENDOR="${lBB_VERSION_ARR[*]:1:1}"
  local lPROD="${lBB_VERSION_ARR[*]:2:1}"
  local lVERS="${lBB_VERSION_ARR[*]:3:1}"

  sub_module_title "BusyBox - Version based vulnerability detection"
  # print_output "${lBOM_REF} - ${lVENDOR} - ${lPROD} - ${lVERS} - ${lORIG_SOURCE}"

  cve_bin_tool_threader "${lBOM_REF}" "${lVENDOR}" "${lPROD}" "${lVERS}" "${lORIG_SOURCE}"

  if [[ -f "${CVE_DETAILS_PATH}" ]]; then
    lVULN_CNT="$(wc -l "${CVE_DETAILS_PATH}" | awk '{print $1}')"

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

  lCVE_ID=$(echo "${lCVE_LINE_ENTRY}" | cut -d, -f5)
  lCVSS_V3=$(echo "${lCVE_LINE_ENTRY}" | cut -d, -f7)
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
