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
  local NEG_LOG=0
  local VERSION_LINE=""
  local WAIT_PIDS_S116=()

  if [[ "${RTOS}" -eq 0 ]]; then
    module_title "Identified software components - via usermode emulation."
    pre_module_reporter "${FUNCNAME[0]}"

    # This module waits for S115_usermode_emulator
    # check emba.log for S115_usermode_emulator
    module_wait "S115_usermode_emulator"

    local LOG_PATH_S115="${LOG_DIR}"/s115_usermode_emulator.txt
    if [[ -f "${LOG_PATH_S115}" && -d "${LOG_DIR}/s115_usermode_emulator" ]]; then
      local VERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings.cfg

      if [[ "${QUICK_SCAN:-0}" -eq 1 ]] && [[ -f "${CONFIG_DIR}"/bin_version_strings_quick.cfg ]]; then
        # the quick scan configuration has only entries that have known vulnerabilities in the CVE database
        local VERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings_quick.cfg
        local V_CNT=0
        V_CNT=$(wc -l "${CONFIG_DIR}"/bin_version_strings_quick.cfg)
        print_output "[*] Quick scan enabled - ${V_CNT/\ *} version identifiers loaded"
      fi

      write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

      while read -r VERSION_LINE; do
        if echo "${VERSION_LINE}" | grep -v -q "^[^#*/;]"; then
          continue
        fi
        if [[ -f "${CSV_DIR}"/s116_qemu_version_detection.csv ]]; then
          # this should prevent double checking - if a version identifier was already successful we do not need to
          # test the other identifiers. In threaded mode this usually does not decrease testing speed
          local BINARY=""
          BINARY="$(echo "${VERSION_LINE}" | cut -d\; -f1)"
          if [[ "$(tail -n +2 "${CSV_DIR}"/s116_qemu_version_detection.csv | cut -d\; -f2 | grep -c "^${BINARY}$")" -gt 0 ]]; then
            print_output "[*] Already identified component for identifier ${ORANGE}${BINARY}${NC} ... skipping further tests" "no_log"
            continue
          fi
        fi

        if [[ ${THREADED} -eq 1 ]]; then
          version_detection_thread "${VERSION_LINE}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_S116+=( "${TMP_PID}" )
        else
          version_detection_thread "${VERSION_LINE}"
        fi
      done < "${VERSION_IDENTIFIER_CFG}"
      print_ln "no_log"

      [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S116[@]}"
      if [[ $(wc -l "${CSV_DIR}"/s116_qemu_version_detection.csv | awk '{print $1}' ) -gt 1 ]]; then
        NEG_LOG=1
      fi
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

version_detection_thread() {
  local VERSION_LINE="${1:-}"

  local BINARY=""
  BINARY="$(echo "${VERSION_LINE}" | cut -d\; -f1)"
  local STRICT=""
  STRICT="$(echo "${VERSION_LINE}" | cut -d\; -f2)"
  local lAPP_LIC=""
  lAPP_LIC="$(echo "${VERSION_LINE}" | cut -d\; -f3)"
  local CSV_REGEX=""
  CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"

  local BINARY_PATH_=""
  local BINARY_PATHS_=()
  local LOG_PATH_MODULE_S115="${LOG_DIR}"/s115_usermode_emulator/
  local LOG_PATHS=()
  local TYPE="emulation"
  local VERSIONS_DETECTED=()
  local VERSION_DETECTED=""

  if [[ ${STRICT} == "multi_grep" ]]; then
    print_output "[-] Multi grep version identifier for ${ORANGE}${CSV_REGEX}${NC} currently not supported in emulation module" "no_log"
    return
  fi

  local VERSION_IDENTIFIER=""
  # VERSION_IDENTIFIER="$(echo "${VERSION_LINE}" | cut -d\; -f4 | sed s/^\"// | sed s/\"$//)"
  VERSION_IDENTIFIER="$(echo "${VERSION_LINE}" | cut -d\; -f4)"
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"

  local BINARY_PATH=""
  local BIN_NAME=""
  local lBIN_ARCH="NA"
  local BINARY_PATHS=()
  local LOG_PATH_=""
  local lCSV_RULE=""
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lAPP_MAINT=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lPACKAGING_SYSTEM="user_mode_bin_analysis"

  # if we have the key strict this version identifier only works for the defined binary and is not generic!
  if [[ ${STRICT} == "strict" ]]; then
    if [[ -f "${LOG_PATH_MODULE_S115}"/qemu_tmp_"${BINARY}".txt ]]; then
      mapfile -t VERSIONS_DETECTED < <(grep -a -o -E "${VERSION_IDENTIFIER}" "${LOG_PATH_MODULE_S115}"/qemu_tmp_"${BINARY}".txt | sort -u 2>/dev/null || true)
      mapfile -t BINARY_PATHS_ < <(strip_color_codes "$(grep -a -h "Emulating binary:" "${LOG_PATH_MODULE_S115}"/qemu_tmp_"${BINARY}".txt | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
      for BINARY_PATH_ in "${BINARY_PATHS_[@]}"; do
        # BINARY_PATH is the final array which we are using further
        BINARY_PATH_=$(find "${FIRMWARE_PATH}" -xdev -wholename "*${BINARY_PATH_}" | sort -u | head)
        BINARY_PATHS+=( "${BINARY_PATH_}" )
      done
      TYPE="emulation/strict"
    fi
  else
    if [[ $(find "${LOG_PATH_MODULE_S115}" -name "qemu_tmp*" | wc -l) -gt 0 ]]; then
      readarray -t VERSIONS_DETECTED < <(grep -a -o -H -E "${VERSION_IDENTIFIER}" "${LOG_PATH_MODULE_S115}"/qemu_tmp*.txt | sort -u 2>/dev/null || true)
      # VERSIONS_DETECTED:
      # path_to_logfile:Version Identifier
      # └─$ grep -a -o -H -E "Version: 1.8" /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt                                                    130 ⨯
      # /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt:Version: 1.8
      # /home/m1k3/firmware/emba_logs_manual/test_dir300/s115_usermode_emulator/qemu_tmp_radvd.txt:Version: 1.8
      for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
        mapfile -t LOG_PATHS < <(strip_color_codes "$(echo "${VERSION_DETECTED}" | cut -d: -f1 | sort -u || true)")
        for LOG_PATH_ in "${LOG_PATHS[@]}"; do
          mapfile -t BINARY_PATHS_ < <(strip_color_codes "$(grep -h -a "Emulating binary:" "${LOG_PATH_}" 2>/dev/null | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
          for BINARY_PATH_ in "${BINARY_PATHS_[@]}"; do
            # BINARY_PATH is the final array which we are using further
            BINARY_PATH_=$(find "${FIRMWARE_PATH}" -xdev -wholename "*${BINARY_PATH_}" | sort -u | head -1)
            BINARY_PATHS+=( "${BINARY_PATH_}" )
          done
        done
      done
      TYPE="emulation"
    fi
  fi

  for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
    check_for_s08_csv_log "${S08_CSV_LOG}"
    LOG_PATH_="$(strip_color_codes "$(echo "${VERSION_DETECTED}" | cut -d: -f1 | sort -u || true)")"
    if [[ ${STRICT} != "strict" ]]; then
      VERSION_DETECTED="$(echo "${VERSION_DETECTED}" | cut -d: -f2- | sort -u)"
    fi

    lCSV_RULE=$(get_csv_rule "${VERSION_DETECTED}" "${CSV_REGEX}")
    lCPE_IDENTIFIER=$(build_cpe_identifier "${lCSV_RULE}")
    lOS_IDENTIFIED=$(distri_check)

    # ensure we have a unique array
    eval "BINARY_PATHS=($(for i in "${BINARY_PATHS[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

    for BINARY_PATH in "${BINARY_PATHS[@]}"; do
      print_output "[+] Version information found ${RED}""${VERSION_DETECTED}""${NC}${GREEN} in binary ${ORANGE}${BINARY_PATH}${GREEN} (license: ${ORANGE}${lAPP_LIC}${GREEN}) (${ORANGE}${TYPE}${GREEN})." "" "${LOG_PATH_}"
      write_csv_log "${BINARY_PATH}" "${BINARY}" "${VERSION_DETECTED}" "${lCSV_RULE}" "${lAPP_LIC}" "${TYPE}"
      BIN_NAME=$(basename "${BINARY_PATH}")
      lBIN_ARCH=$(file -b "${BINARY_PATH}")
      lBIN_ARCH=$(echo "${lBIN_ARCH}" | cut -d ',' -f2)
      lBIN_ARCH=${lBIN_ARCH#\ }
      lBIN_ARCH=$(clean_package_details "${lBIN_ARCH}")
      lPURL_IDENTIFIER=$(build_generic_purl "${lCSV_RULE}" "${lOS_IDENTIFIED}" "${lBIN_ARCH:-NA}")

      lMD5_CHECKSUM="$(md5sum "${BINARY_PATH}" | awk '{print $1}' || true)"
      lSHA256_CHECKSUM="$(sha256sum "${BINARY_PATH}" | awk '{print $1}' || true)"
      lSHA512_CHECKSUM="$(sha512sum "${BINARY_PATH}" | awk '{print $1}' || true)"

      lAPP_MAINT=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
      lAPP_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
      lAPP_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-5)
      # it could be that we have a version like 2.14b:* -> we remove the last field
      lAPP_VERS="${lAPP_VERS/:\*}"

      ### new SBOM json testgenerator
      if command -v jo >/dev/null; then
        # add EXE path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${BINARY_PATH}" )
        lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${BINARY_PATH}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "${lPACKAGING_SYSTEM};${BINARY_PATH:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${BIN_NAME,,};${VERSION_DETECTED:-NA};${lCSV_RULE:-NA};${lAPP_LIC:-NA};maintainer unknown;${lBIN_ARCH:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
    done
  done
}

