#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
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
  local NEG_LOG=0

  local BB_VERSIONS_ARR=()
  local BB_VERSION=""
  local BB_BIN=""
  local BB_ENTRY=""
  local VERSION_IDENTIFIER=""

  module_wait "S116_qemu_version_detection"
  module_wait "S09_firmware_base_version_check"

  if [[ -f "${CSV_DIR}"/s116_qemu_version_detection.csv ]]; then
    mapfile -t BB_VERSIONS_ARR < <(grep ";busybox;" "${CSV_DIR}"/s116_qemu_version_detection.csv | cut -d\; -f1,4 | sort -u || true)
  fi

  # if don't get our version details from S116/S115 we need to fallback to s09
  if [[ "${#BB_VERSIONS_ARR[@]}" -eq 0 ]]; then
    if [[ -f "${CSV_DIR}"/s09_firmware_base_version_check.csv ]]; then
      mapfile -t BB_VERSIONS_ARR < <(grep ";busybox;" "${CSV_DIR}"/s09_firmware_base_version_check.csv | cut -d\; -f1,4 | sort -u || true)
    fi
  fi

  # finally we search manually for the version
  if [[ "${#BB_VERSIONS_ARR[@]}" -eq 0 ]]; then
    # first grep is for identification of possible binary files:
    mapfile -t BB_BINS_ARR < <(grep -l -a -E "BusyBox\ v[0-9](\.[0-9]+)+?.*" "${LOG_DIR}"/firmware -r 2>/dev/null || true)
    for BB_BIN in "${BB_BINS_ARR[@]}"; do
      if ! file "${BB_BIN}" | grep -q "ELF"; then
        continue
      fi
      # now modify the version identifier to use it also for our CVE identification
      VERSION_IDENTIFIER=$(strings "${BB_BIN}" | grep -E "BusyBox\ v[0-9](\.[0-9]+)+?.*" | sort -u | sed -r 's/BusyBox\ v([0-9](\.[0-9]+)+?)\ .*/busybox:\1/' | sort -u | head -1 || true)
      # build the needed array
      BB_VERSIONS_ARR+=( "${BB_BIN};${VERSION_IDENTIFIER}" )
    done
  fi

  for BB_ENTRY in "${BB_VERSIONS_ARR[@]}"; do
    export BB_VERIFIED_APPLETS=()
    local BB_VERSION="${BB_ENTRY/*;}"
    local BB_BIN="${BB_ENTRY/;*}"
    export CVE_DETAILS_PATH="${LOG_PATH_MODULE}""/${BB_VERSION/:/_}.txt"
    local ALL_BB_VULNS=()
    local BB_APPLET=""
    local SUMMARY=""

    if tail -n +2 "${CSV_DIR}"/s118_busybox_verifier.csv | cut -d\; -f1 | grep -v "BusyBox VERSION" | grep -q "${BB_VERSION}"; then
      # we already tested this version and ensure we do not duplicate this check
      continue
    fi

    get_cve_busybox_data "${BB_VERSION}"

    if ! [[ -f "${CVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated ... check for further BusyBox version"
      continue
    fi

    get_busybox_applets_emu "${BB_VERSION}"
    get_busybox_applets_stat "${BB_VERSION}" "${BB_BIN}"

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}_stat.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}_stat.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}.tmp"
    fi
    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}_emu.txt" ]]; then
      cat "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}_emu.txt" >> "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}.tmp"
    fi

    if [[ -f "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}.tmp" ]]; then
      mapfile -t BB_VERIFIED_APPLETS < <(sort -u "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}.tmp")
      rm "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION/*:/}.tmp" || true
    fi

    print_output "[*] Create CVE vulnerabilities array for BusyBox version ${ORANGE}${BB_VERSION}${NC} ..." "no_log"
    mapfile -t ALL_BB_VULNS < "${CVE_DETAILS_PATH}"

    if [[ "${#ALL_BB_VULNS[@]}" -eq 0 ]] || [[ "${#BB_VERIFIED_APPLETS[@]}" -eq 0 ]]; then
      print_output "[-] No BusyBox vulnerability or applets found for ${ORANGE}${BB_VERSION}${NC}"
      continue
    fi

    print_ln
    sub_module_title "BusyBox - Vulnerability verification"
    print_output "[+] Extracted ${ORANGE}${#ALL_BB_VULNS[@]}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
    print_ln

    local VULN_CNT=0
    write_csv_log "BusyBox VERSION" "BusyBox APPLET" "Verified CVE" "CNT all CVEs" "CVE Summary"
    for VULN in "${ALL_BB_VULNS[@]}"; do
      VULN_CNT=$((VULN_CNT+1))

      CVE=$(echo "${VULN}" | cut -d: -f1)
      SUMMARY="$(echo "${VULN}" | cut -d: -f6-)"
      print_output "[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#ALL_BB_VULNS[@]}${NC} / ${ORANGE}${CVE}${NC}" "no_log"

      for BB_APPLET in "${BB_VERIFIED_APPLETS[@]}"; do
        # remove false positives for applet "which"
        if [[ "${BB_APPLET}" == "which" ]] && [[ "${SUMMARY}" == *"\,\ ${BB_APPLET}\ "* ]]; then
          continue
        fi
        if [[ "${SUMMARY}" == *" ${BB_APPLET}\ "* ]]; then
          print_output "[+] Verified BusyBox vulnerability ${ORANGE}${CVE}${GREEN} - applet ${ORANGE}${BB_APPLET}${GREEN}"
          echo -e "\t${SUMMARY//\\/}" | sed -e "s/\ ${BB_APPLET}\ /\ ${ORANGE_}${BB_APPLET}${NC_}\ /g" | tee -a "${LOG_FILE}"
          NEG_LOG=1
          write_csv_log "${BB_VERSION}" "${BB_APPLET}" "${CVE}" "${#ALL_BB_VULNS[@]}" "${SUMMARY}"
          print_bar
        fi
      done
    done
  done

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

get_busybox_applets_stat() {
  local BB_VERSION_="${1:-}"
  local BB_BIN_="${2:-}"

  local BB_BINS_ARR=()
  local APP_CNT=0
  local BB_DETECTED_APPLETS_ARR=()
  local BB_DETECTED_APPLET=""

  print_ln
  sub_module_title "BusyBox - Static applet identification from binary"

  # quite often we only have the firmware path without the filesytem area: /bin/busybox
  # This results in another search for our binary
  mapfile -t BB_BINS_ARR < <(find "${LOG_DIR}"/firmware -wholename "*${BB_BIN_}*" -exec file {} \; | grep "ELF" | cut -d: -f1 | sort -u || true)
  for BB_BIN_ in "${BB_BINS_ARR[@]}"; do
    print_output "[*] Extract applet data for BusyBox version ${ORANGE}${BB_VERSION_}${NC} from binary ${ORANGE}${BB_BIN_}${NC}"
    mapfile -t BB_DETECTED_APPLETS_ARR < <(grep -oUaP "\x00\x5b(\x5b)?\x00.*\x00\x00" "${BB_BIN_}" | strings | sort -u || true)
    for BB_DETECTED_APPLET in "${BB_DETECTED_APPLETS_ARR[@]}"; do
      if grep -E -q "^${BB_DETECTED_APPLET}$" "${CONFIG_DIR}/busybox_commands.cfg"; then
        print_output "[*] BusyBox Applet found and identified as real BusyBox applet ... ${ORANGE}${BB_DETECTED_APPLET}${NC}" "no_log"
        echo "${BB_DETECTED_APPLET}" >> "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION_/*:/}_stat.txt"
        APP_CNT=$((APP_CNT+1))
      fi
    done
  done
  print_output "[+] Extracted ${ORANGE}${APP_CNT}${GREEN} valid BusyBox applets via static analysis" "" "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION_/*:/}_stat.txt"
}

get_busybox_applets_emu() {
  local BB_VERSION_="${1:-}"

  local BB_QEMU_FILES_ARR=()
  local BB_FILE=""
  local APP_CNT=0
  local BB_DETECTED_APPLETS_ARR=()
  local BB_DETECTED_APPLET=""

  print_ln
  sub_module_title "BusyBox - Applet identification via emulation results"

  mapfile -t BB_QEMU_FILES_ARR < <(find "${LOG_DIR}"/s115_usermode_emulator/ -name "qemu_tmp*busybox*txt" 2>/dev/null || true)
  for BB_FILE in "${BB_QEMU_FILES_ARR[@]}"; do
    print_output "[*] Extract applet data for BusyBox version ${ORANGE}${BB_VERSION_}${NC} from emulation logs" "" "${BB_FILE}"
    mapfile -t BB_DETECTED_APPLETS_ARR < <(sed -e '1,/Currently defined functions:/d' "${BB_FILE}" | grep ", " | tr ',' '\n' | tr -d '[' | tr -d ']' | tr -d "[:blank:]" | tr -s '\n' '\n' | sort -u || true)
    for BB_DETECTED_APPLET in "${BB_DETECTED_APPLETS_ARR[@]}"; do
      if grep -E -q "^${BB_DETECTED_APPLET}$" "${CONFIG_DIR}/busybox_commands.cfg"; then
        print_output "[*] BusyBox Applet found and identified as real BusyBox applet ... ${ORANGE}${BB_DETECTED_APPLET}${NC}" "no_log"
        echo "${BB_DETECTED_APPLET}" >> "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION_/*:/}_emu.txt"
        APP_CNT=$((APP_CNT+1))
      fi
    done
  done
  print_output "[+] Extracted ${ORANGE}${APP_CNT}${GREEN} valid BusyBox applets from usermode log files" "" "${LOG_PATH_MODULE}/busybox_applets_${BB_VERSION_/*:/}_emu.txt"
}

get_cve_busybox_data() {
  local lBB_VERSION="${1:-}"
  local lVULN_CNT=""
  export F20_DEEP=0

  sub_module_title "BusyBox - Version based vulnerability detection"

  prepare_cve_search_module

  cve_db_lookup_version "${lBB_VERSION}"

  if [[ -f "${CVE_DETAILS_PATH}" ]]; then
    lVULN_CNT="$(wc -l "${CVE_DETAILS_PATH}" | awk '{print $1}')"

    # lets create a more beautifull log for the report:
    local lCVE_LINE_ENTRY=""
    local lCVE_ID=""
    local lCVSS_V2=""
    local lCVSS_V3=""
    local lFIRST_EPSS=""
    local lCVE_SUMMARY=""

    while read -r lCVE_LINE_ENTRY; do
      lCVE_ID="${lCVE_LINE_ENTRY/:*}"
      lCVSS_V2=$(echo "${lCVE_LINE_ENTRY}" | cut -d: -f2)
      lCVSS_V3=$(echo "${lCVE_LINE_ENTRY}" | cut -d: -f3)
      lFIRST_EPSS=$(echo "${lCVE_LINE_ENTRY}" | cut -d: -f5)
      lCVE_SUMMARY=$(echo "${lCVE_LINE_ENTRY}" | cut -d: -f6-)

      write_log "${ORANGE}${lCVE_ID}:${NC}" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
      write_log "$(indent "CVSSv2: ${ORANGE}${lCVSS_V2}${NC}")" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
      write_log "$(indent "CVSSv3: ${ORANGE}${lCVSS_V3}${NC}")" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
      write_log "$(indent "FIRST EPSS: ${ORANGE}${lFIRST_EPSS}${NC}")" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
      write_log "$(indent "Summary: ${ORANGE}${lCVE_SUMMARY}${NC}")" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
      write_log "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
    done < "${CVE_DETAILS_PATH}"

    print_output "[+] Extracted ${ORANGE}${lVULN_CNT}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
  fi
}
