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

# Description:  This module extracts version information from the results of S115

S116_qemu_version_detection() {
  module_log_init "${FUNCNAME[0]}"
  local lNEG_LOG=0
  local lVERSION_LINE=""
  local lWAIT_PIDS_S116_ARR=()

  if [[ "${RTOS}" -eq 0 ]]; then
    module_title "Identified software components - via usermode emulation."
    pre_module_reporter "${FUNCNAME[0]}"

    # This module waits for S115_usermode_emulator
    # check emba.log for S115_usermode_emulator
    module_wait "S115_usermode_emulator"

    # if module s09 is in our running modules array we wait until this module created the unhandled_files entries
    # otherwise we can't delete the irrelevant entries
    while ! [[ -f "${TMP_DIR}/S09_strings_generated.tmp" ]]; do
      if ! [[ " ${MODULES_EXPORTED[*]} " == *S09* ]]; then
        break
      fi
      print_output "[*] Waiting for S09 module - strings and unhandled file generaation ..." "no_log"
      sleep 1
    done

    local lLOG_PATH_S115="${LOG_DIR}"/s115_usermode_emulator.txt
    if [[ -f "${lLOG_PATH_S115}" && -d "${LOG_DIR}/s115_usermode_emulator" ]]; then
      local lVERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings.cfg

      write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

      while read -r lVERSION_LINE; do
        if [[ -f "${CSV_DIR}"/s116_qemu_version_detection.csv ]]; then
          # this should prevent double checking - if a version identifier was already successful we do not need to
          # test the other identifiers. In threaded mode this usually does not decrease testing speed
          local lBINARY=""
          lBINARY="$(echo "${lVERSION_LINE}" | cut -d\; -f1)"
          if [[ "$(tail -n +2 "${CSV_DIR}"/s116_qemu_version_detection.csv | cut -d\; -f2 | grep -c "^${lBINARY}$")" -gt 0 ]]; then
            print_output "[*] Already identified component for identifier ${ORANGE}${lBINARY}${NC} ... skipping further tests" "no_log"
            continue
          fi
        fi

        if [[ ${THREADED} -eq 1 ]]; then
          version_detection_thread "${lVERSION_LINE}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_S116_ARR+=( "${lTMP_PID}" )
        else
          version_detection_thread "${lVERSION_LINE}"
        fi
      done < <(grep -v "multi_grep" "${lVERSION_IDENTIFIER_CFG}" | grep "^[^#*/;]")
      print_ln "no_log"

      [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S116_ARR[@]}"
      if [[ $(wc -l "${CSV_DIR}"/s116_qemu_version_detection.csv | awk '{print $1}' ) -gt 1 ]]; then
        lNEG_LOG=1
      fi
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

version_detection_thread() {
  local lVERSION_LINE="${1:-}"

  local lBINARY=""
  lBINARY="$(echo "${lVERSION_LINE}" | cut -d\; -f1)"
  local lSTRICT=""
  lSTRICT="$(echo "${lVERSION_LINE}" | cut -d\; -f2)"
  local lAPP_LIC=""
  lAPP_LIC="$(echo "${lVERSION_LINE}" | cut -d\; -f3)"
  local lCSV_REGEX=""
  lCSV_REGEX="$(echo "${lVERSION_LINE}" | cut -d\; -f5)"

  local lBINARY_PATH_=""
  local lBINARY_PATHS_ARR=()
  local lLOG_PATH_MODULE_S115="${LOG_DIR}"/s115_usermode_emulator/
  local lLOG_PATHS_ARR=()
  local lTYPE="emulation"
  local lVERSIONS_DETECTED_ARR=()
  local lVERSION_DETECTED=""

  if [[ ${lSTRICT} == "multi_grep" ]]; then
    print_output "[-] Multi grep version identifier for ${ORANGE}${lCSV_REGEX}${NC} currently not supported in emulation module" "no_log"
    return
  fi

  local lVERSION_IDENTIFIER=""
  # lVERSION_IDENTIFIER="$(echo "${lVERSION_LINE}" | cut -d\; -f4 | sed s/^\"// | sed s/\"$//)"
  lVERSION_IDENTIFIER="$(echo "${lVERSION_LINE}" | cut -d\; -f4)"
  lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER/\"}"
  lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER%\"}"

  local lBINARY_PATH=""
  local lBIN_NAME=""
  local lBIN_ARCH="NA"
  local lBIN_FILE="NA"
  local lBINARY_PATHS_ARR=()
  local lBINARY_PATHS_FINAL_ARR=()
  local lLOG_PATH_=""
  local lCSV_RULE=""
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lAPP_MAINT=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lPACKAGING_SYSTEM="user_mode_bin_analysis"

  # if we have the key strict this version identifier only works for the defined binary and is not generic!
  if [[ ${lSTRICT} == "strict" ]]; then
    if [[ -f "${lLOG_PATH_MODULE_S115}"/qemu_tmp_"${lBINARY}".txt ]]; then
      mapfile -t lVERSIONS_DETECTED_ARR < <(grep -a -o -E "${lVERSION_IDENTIFIER}" "${lLOG_PATH_MODULE_S115}"/qemu_tmp_"${lBINARY}".txt | sort -u 2>/dev/null || true)
      mapfile -t lBINARY_PATHS_ARR < <(strip_color_codes "$(grep -a -h "Emulating binary:" "${lLOG_PATH_MODULE_S115}"/qemu_tmp_"${lBINARY}".txt | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
      for lBINARY_PATH_ in "${lBINARY_PATHS_ARR[@]}"; do
        # lBINARY_PATH is the final array which we are using further
        # lBINARY_PATH_=$(find "${FIRMWARE_PATH}" -xdev -wholename "*${lBINARY_PATH_}" | sort -u | head -1)
        lBINARY_PATH_=$(grep "${lBINARY_PATH_}.*ELF" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1 || true)
        if [[ -z "${lBINARY_PATH_}" ]]; then
          lBINARY_PATH_=$(grep "${lBINARY_PATH_}" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1 || true)
        fi
        if [[ -z "${lBINARY_PATH_}" ]]; then
          lBINARY_PATH_=$(find "${FIRMWARE_PATH}" -xdev -wholename "*${lBINARY_PATH_}" | sort -u | head -1)
        fi
        # print_output "[*] Storing strict ${lBINARY_PATH_} in array" "no_log"
        if [[ -n "${lBINARY_PATH_}" ]]; then
          lBINARY_PATHS_FINAL_ARR+=( "${lBINARY_PATH_}" )
        fi
      done
      lTYPE="emulation/strict"
    fi
  else
    if [[ $(find "${lLOG_PATH_MODULE_S115}" -name "qemu_tmp*" | wc -l) -gt 0 ]]; then
      readarray -t lVERSIONS_DETECTED_ARR < <(grep -a -o -H -E "${lVERSION_IDENTIFIER}" "${lLOG_PATH_MODULE_S115}"/qemu_tmp*.txt | sort -u 2>/dev/null || true)
      # VERSIONS_DETECTED:
      # path_to_logfile:Version Identifier
      # └─$ grep -a -o -H -E "Version: 1.8" /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt                                                    130 ⨯
      # /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt:Version: 1.8
      # /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt:Version: 1.8
      for lVERSION_DETECTED in "${lVERSIONS_DETECTED_ARR[@]}"; do
        mapfile -t lLOG_PATHS_ARR < <(strip_color_codes "$(echo "${lVERSION_DETECTED}" | cut -d: -f1 | sort -u || true)")
        for lLOG_PATH_ in "${lLOG_PATHS_ARR[@]}"; do
          mapfile -t lBINARY_PATHS_ARR < <(strip_color_codes "$(grep -h -a "Emulating binary:" "${lLOG_PATH_}" 2>/dev/null | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
          for lBINARY_PATH_ in "${lBINARY_PATHS_ARR[@]}"; do
            # BINARY_PATH is the final array which we are using further
            lBINARY_PATH_=$(grep "${lBINARY_PATH_}.*ELF" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1 || true)
            if [[ -z "${lBINARY_PATH_}" ]]; then
              lBINARY_PATH_=$(grep "${lBINARY_PATH_}" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1 || true)
            fi
            if [[ -z "${lBINARY_PATH_}" ]]; then
              lBINARY_PATH_=$(find "${FIRMWARE_PATH}" -xdev -wholename "*${lBINARY_PATH_}" | sort -u | head -1)
            fi
            # print_output "[*] Storing ${lBINARY_PATH_} in array" "no_log"
            if [[ -n "${lBINARY_PATH_}" ]]; then
              lBINARY_PATHS_FINAL_ARR+=( "${lBINARY_PATH_}" )
            fi
          done
        done
      done
      lTYPE="emulation"
    fi
  fi

  for lVERSION_DETECTED in "${lVERSIONS_DETECTED_ARR[@]}"; do
    check_for_s08_csv_log "${S08_CSV_LOG}"
    lLOG_PATH_="$(strip_color_codes "$(echo "${lVERSION_DETECTED}" | cut -d: -f1 | sort -u || true)")"
    if [[ ${lSTRICT} != "strict" ]]; then
      lVERSION_DETECTED="$(echo "${lVERSION_DETECTED}" | cut -d: -f2- | sort -u)"
    fi

    lCSV_RULE=$(get_csv_rule "${lVERSION_DETECTED}" "${lCSV_REGEX}")
    lCPE_IDENTIFIER=$(build_cpe_identifier "${lCSV_RULE}")
    lOS_IDENTIFIED=$(distri_check)

    # ensure we have a unique array
    eval "lBINARY_PATHS_FINAL_ARR=($(for i in "${lBINARY_PATHS_FINAL_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

    local lCNT=0
    for lBINARY_PATH in "${lBINARY_PATHS_FINAL_ARR[@]}"; do
      lCNT=$((lCNT+1))
      # I think it is enough to log the same version identifier for 10 times
      [[ "${lCNT}" -gt 10 ]] && break

      print_output "[+] Version information found ${RED}""${lVERSION_DETECTED}""${NC}${GREEN} in binary ${ORANGE}${lBINARY_PATH}${GREEN} (license: ${ORANGE}${lAPP_LIC}${GREEN}) (${ORANGE}${lTYPE}${GREEN})." "" "${lLOG_PATH_}"
      write_csv_log "${lBINARY_PATH}" "${lBINARY}" "${lVERSION_DETECTED}" "${lCSV_RULE}" "${lAPP_LIC}" "${lTYPE}"
      lBIN_NAME=$(basename "${lBINARY_PATH}")
      lBIN_FILE=$(file -b "${lBINARY_PATH}")
      lBIN_ARCH=$(echo "${lBIN_FILE}" | cut -d ',' -f2)
      lBIN_ARCH=${lBIN_ARCH#\ }
      lBIN_ARCH=$(clean_package_details "${lBIN_ARCH}")
      lPURL_IDENTIFIER=$(build_generic_purl "${lCSV_RULE}" "${lOS_IDENTIFIED}" "${lBIN_ARCH:-NA}")

      lMD5_CHECKSUM="$(md5sum "${lBINARY_PATH}" | awk '{print $1}' || true)"
      lSHA256_CHECKSUM="$(sha256sum "${lBINARY_PATH}" | awk '{print $1}' || true)"
      lSHA512_CHECKSUM="$(sha512sum "${lBINARY_PATH}" | awk '{print $1}' || true)"

      lAPP_MAINT=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
      lAPP_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
      lAPP_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-5)
      # it could be that we have a version like 2.14b:* -> we remove the last field
      lAPP_VERS="${lAPP_VERS/:\*}"

      # add EXE path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lBINARY_PATH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_details:${lBIN_FILE}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:medium" )

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lBINARY_PATH}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "${lPACKAGING_SYSTEM};${lBINARY_PATH:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lBIN_NAME,,};${lVERSION_DETECTED:-NA};${lCSV_RULE:-NA};${lAPP_LIC:-NA};maintainer unknown;${lBIN_ARCH:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
    done
  done
}

