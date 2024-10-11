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
      if ! file "${lBB_BIN}" | grep -q "ELF"; then
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
      lPURL_IDENTIFIER=$(build_generic_purl "${lVERSION_IDENTIFIER}")

      write_log "static_busybox_analysis;${lBB_BIN:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};$(basename "${lBB_BIN}");NA;${lVERSION_IDENTIFIER:-NA};GPL-2.0-only;maintainer unknown;unknown;${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};DESC" "${S08_CSV_LOG}"
      print_output "[*] Found busybox binary - ${lBB_BIN} - ${lVERSION_IDENTIFIER:-NA} - GPL-2.0-only" "no_log"
    done
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  for lBB_ENTRY in "${lBB_VERSIONS_ARR[@]}"; do
    export BB_VERIFIED_APPLETS=()
    local lBB_VERSION="${lBB_ENTRY/*;}"
    local lBB_BIN="${lBB_ENTRY/;*}"
    export CVE_DETAILS_PATH="${LOG_PATH_MODULE}""/${lBB_VERSION/:/_}.txt"
    local lALL_BB_VULNS_ARR=()
    local lBB_APPLET=""
    local lSUMMARY=""

    if tail -n +2 "${S118_CSV_LOG}" | cut -d\; -f1 | grep -v "BusyBox VERSION" | grep -q "${lBB_VERSION}"; then
      # we already tested this version and ensure we do not duplicate this check
      continue
    fi

    get_cve_busybox_data "${lBB_VERSION}"

    if ! [[ -f "${CVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated ... check for further BusyBox version"
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
    mapfile -t lALL_BB_VULNS_ARR < "${CVE_DETAILS_PATH}"

    if [[ "${#lALL_BB_VULNS_ARR[@]}" -eq 0 ]] || [[ "${#BB_VERIFIED_APPLETS[@]}" -eq 0 ]]; then
      print_output "[-] No BusyBox vulnerability or applets found for ${ORANGE}${lBB_VERSION}${NC}"
      continue
    fi

    print_ln
    sub_module_title "BusyBox - Vulnerability verification"
    print_output "[+] Extracted ${ORANGE}${#lALL_BB_VULNS_ARR[@]}${GREEN} vulnerabilities based on BusyBox version only" "" "${CVE_DETAILS_PATH/.txt/_nice.txt}"
    print_ln

    local lVULN_CNT=0
    write_csv_log "BusyBox VERSION" "BusyBox APPLET" "Verified CVE" "CNT all CVEs" "CVE Summary"
    for VULN in "${lALL_BB_VULNS_ARR[@]}"; do
      lVULN_CNT=$((lVULN_CNT+1))

      CVE=$(echo "${VULN}" | cut -d: -f1)
      lSUMMARY="$(echo "${VULN}" | cut -d: -f6-)"
      print_output "[*] Testing vulnerability ${ORANGE}${lVULN_CNT}${NC} / ${ORANGE}${#lALL_BB_VULNS_ARR[@]}${NC} / ${ORANGE}${CVE}${NC}" "no_log"

      for lBB_APPLET in "${BB_VERIFIED_APPLETS[@]}"; do
        # remove false positives for applet "which"
        if [[ "${lBB_APPLET}" == "which" ]] && [[ "${lSUMMARY}" == *"\,\ ${lBB_APPLET}\ "* ]]; then
          continue
        fi
        if [[ "${lSUMMARY}" == *" ${lBB_APPLET}\ "* ]]; then
          print_output "[+] Verified BusyBox vulnerability ${ORANGE}${CVE}${GREEN} - applet ${ORANGE}${lBB_APPLET}${GREEN}"
          echo -e "\t${lSUMMARY//\\/}" | sed -e "s/\ ${lBB_APPLET}\ /\ ${ORANGE_}${lBB_APPLET}${NC_}\ /g" | tee -a "${LOG_FILE}"
          lNEG_LOG=1
          write_csv_log "${lBB_VERSION}" "${lBB_APPLET}" "${CVE}" "${#lALL_BB_VULNS_ARR[@]}" "${lSUMMARY}"
          print_bar
        fi
      done
    done
  done

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
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
  mapfile -t lBB_BINS_ARR < <(find "${LOG_DIR}"/firmware -wholename "*${lBB_BIN_}*" -exec file {} \; | grep "ELF" | cut -d: -f1 | sort -u || true)
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
