#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Iterates through a list with regex identifiers of version details
#               (e.g. busybox:binary:"BusyBox\ v[0-9]\.[0-9][0-9]\.[0-9]\ .*\ multi-call\ binary" ) of all executables and
#               checks if these fit on a binary in the firmware.
#               The version configuration files are stored in config/bin_version_identifiers

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S09_firmware_base_version_check() {

  # this module check for version details statically.
  # this module is designed for *x based systems

  module_log_init "${FUNCNAME[0]}"
  module_title "Static binary firmware versions detection"
  pre_module_reporter "${FUNCNAME[0]}"

  if ! [[ -f "${P99_CSV_LOG}" ]]; then
    print_error "[-] Missing P99 CSV log file"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  print_output "[*] Static version detection running ..." "no_log" | tr -d "\n"
  write_csv_log "binary/file" "rule identifier" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

  export TYPE="static"
  local lVERSION_IDENTIFIER=""
  export WAIT_PIDS_S09=()
  export WAIT_PIDS_S09_1=()
  local lVERSIONS_DETECTED=""
  local lVERSION_IDENTIFIER_CFG_PATH="${CONFIG_DIR}"/bin_version_identifiers
  local lVERSION_IDENTIFIER_CFG_ARR=()
  local lVERSION_JSON_CFG=""
  mapfile -t lVERSION_IDENTIFIER_CFG_ARR < <(find "${lVERSION_IDENTIFIER_CFG_PATH}" -name "*.json" | sort)

  local lFILE_ARR_TMP=()
  # P99 csv log is already unique but it has a lot of non binary files in it -> we pre-filter it now
  export FILE_ARR=()
  mapfile -t FILE_ARR < <(grep -v "\/\.git\|Git\ pack\|image\ data\|ASCII\ text\|Unicode\ text\|\ compressed\ data\|\ archive" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  local lFILE=""
  local lBIN=""
  local lBIN_FILE=""

  # set default confidence level
  # 1 -> very-low
  # 2 -> low
  # 3 -> medium
  # 4 -> high
  export CONFIDENCE_LEVEL=3

  if [[ " ${MODULES_EXPORTED[*]} " == *S08* ]]; then
    print_output "[*] Checking for common package manager environments to optimize static version detection"
    # Debian:
    find "${LOG_DIR}"/firmware -path "*dpkg/info/*.list" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'cat "%"' | sort -u > "${LOG_PATH_MODULE}"/debian_known_files.txt || true
    # the extracted packages are used to further limit the static tests
    find "${LOG_DIR}"/firmware -path "*dpkg/status" -type f -exec grep "^Package: " {} \; | awk '{print $2}' | sort -u > "${LOG_PATH_MODULE}"/debian_known_packages.txt || true
    # OpenWRT
    find "${LOG_DIR}"/firmware -path "*opkg/info/*.list" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'cat "%"' | sort -u > "${LOG_PATH_MODULE}"/openwrt_known_files.txt || true
    find "${LOG_DIR}"/firmware -path "*opkg/status" -type f -exec grep "^Package: " {} \; | awk '{print $2}' | sort -u > "${LOG_PATH_MODULE}"/openwrt_known_packages.txt || true
    # Todo: rpm
    # lRPM_DIR=$(find "${LOG_DIR}"/firmware -xdev -path "*rpm/Package" -type f -exec dirname {} \; | sort -u || true)
    # lRPM_DIR=$(find "${LOG_DIR}"/firmware -xdev -path "*rpm/rpmdb.sqlite" -type f -exec dirname {} \; | sort -u || true)
    # get all packages in array and run through them to extract all paths
    # rpm -ql --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}"

    if [[ -f "${LOG_PATH_MODULE}"/debian_known_files.txt ]]; then
      cat "${LOG_PATH_MODULE}"/debian_known_files.txt >> "${LOG_PATH_MODULE}"/pkg_known_files.txt
    fi
    if [[ -f "${LOG_PATH_MODULE}"/openwrt_known_files.txt ]]; then
      cat "${LOG_PATH_MODULE}"/openwrt_known_files.txt >> "${LOG_PATH_MODULE}"/pkg_known_files.txt
    fi
    if [[ -f "${LOG_PATH_MODULE}"/rpm_known_files.txt ]]; then
      cat "${LOG_PATH_MODULE}"/rpm_known_files.txt >> "${LOG_PATH_MODULE}"/pkg_known_files.txt
    fi

    if [[ -f "${LOG_PATH_MODULE}"/pkg_known_files.txt ]]; then
      # sed -i '/\[/d' "${LOG_PATH_MODULE}"/pkg_known_files.txt || true
      sed -i '/\/\.$/d' "${LOG_PATH_MODULE}"/pkg_known_files.txt || true
      mapfile -t lFILE_ARR_PKG < "${LOG_PATH_MODULE}"/pkg_known_files.txt
    fi

    if [[ "${#lFILE_ARR_PKG[@]}" -gt 10 ]]; then
      print_output "[*] Found package manager with ${ORANGE}${#lFILE_ARR_PKG[@]}${NC} package files - testing against a limited file array with ${ORANGE}${#FILE_ARR[@]}${NC} entries." "${LOG_PATH_MODULE}/pkg_known_files.txt"
      local lPKG_FILE=""
      for lPKG_FILE in "${lFILE_ARR_PKG[@]}"; do
        lPKG_FILE=$(printf "%q\n" "${lPKG_FILE}")
        (grep -F "${lPKG_FILE};" "${P99_CSV_LOG}" | cut -d ';' -f2 >> "${LOG_PATH_MODULE}"/known_system_pkg_files.txt || true)&
      done

      print_output "[*] Waiting for finishing the build process of known_system_pkg_files" "no_log"
      # shellcheck disable=SC2046
      wait $(jobs -p) # nosemgrep

      sort -u "${LOG_PATH_MODULE}"/known_system_pkg_files.txt > "${LOG_PATH_MODULE}"/known_system_pkg_files_sorted.txt || true
      cut -d ';' -f2 "${P99_CSV_LOG}" | sort -u > "${LOG_PATH_MODULE}"/firmware_binaries_sorted.txt || true

      # we have now all our filesystem bins in "${P99_CSV_LOG}"
      # we have the matching filesystem bin in "${LOG_PATH_MODULE}"/known_system_files.txt
      # now we just need to do a diff on them and we should have only the non matching files
      comm -23 "${LOG_PATH_MODULE}/firmware_binaries_sorted.txt" "${LOG_PATH_MODULE}"/known_system_pkg_files_sorted.txt > "${LOG_PATH_MODULE}"/known_system_files_diffed.txt || true
      mapfile -t lFILE_ARR_TMP < "${LOG_PATH_MODULE}"/known_system_files_diffed.txt

      local lINIT_FILES_CNT=0
      lINIT_FILES_CNT="$(wc -l < "${P99_CSV_LOG}")"
      if [[ "${#lFILE_ARR_TMP[@]}" -lt "${lINIT_FILES_CNT}" ]]; then
        print_output "[*] Identified ${ORANGE}${lINIT_FILES_CNT}${NC} files before package manager matching" "${LOG_PATH_MODULE}/firmware_binaries_sorted.txt"
        print_output "[*] EMBA is further analyzing ${ORANGE}${#lFILE_ARR_TMP[@]}${NC} files which are not handled by the package manager" "${LOG_PATH_MODULE}/known_system_files_diffed.txt"
        print_output "[*] Generating analysis file array ..." "no_log"
        export FILE_ARR=()
        for lFILE in "${lFILE_ARR_TMP[@]}"; do
          if [[ "${lFILE}" =~ .*\.padding$ || "${lFILE}" =~ .*\.unknown$ || "${lFILE}" =~ .*\.uncompressed$ || "${lFILE}" =~ .*\.raw$ || "${lFILE}" =~ .*\.elf$ || "${lFILE}" =~ .*\.decompressed\.bin$ || "${lFILE}" =~ .*__symbols__.* ]]; then
            # binwalk and unblob are producing multiple files that are not relevant for the SBOM and can skip them here
            continue
          elif grep -F "${lFILE}" "${P99_CSV_LOG}" | cut -d ';' -f8 | grep -q "text\|compressed\|archive\|empty\|Git\ pack"; then
            # extract the stored file details and match it against some patterns we do not further process:
            continue
          fi
          # print_output "$(indent "$(orange "${lFILE}")")"
          FILE_ARR+=( "${lFILE}" )
        done
        print_output "[*] EMBA is testing ${ORANGE}${#FILE_ARR[@]}${NC} files which are not handled by the package manager" "${LOG_PATH_MODULE}/final_bins.txt"
      else
        print_output "[*] No package manager updates for static analysis"
      fi
    else
      print_output "[*] No package manager updates for static analysis"
    fi
  else
    print_output "[*] Info: No SBOM package manager analysis modules enabled"
  fi

  # lets start generating the strings from all our relevant binaries
  print_output "[*] Generate strings overview for static version analysis of ${ORANGE}${#FILE_ARR[@]}${NC} files ..."
  if ! [[ -d "${LOG_PATH_MODULE}"/strings_bins ]]; then
    mkdir "${LOG_PATH_MODULE}"/strings_bins || true 2>/dev/null
  fi
  export WAIT_PIDS_S09_ARR_tmp=()
  for lBIN in "${FILE_ARR[@]}"; do
    if [[ "${lBIN}" =~ .*\.padding$ || "${lBIN}" =~ .*\.unknown$ || "${lBIN}" =~ .*\.uncompressed$ || "${lBIN}" =~ .*\.raw$ || "${lBIN}" =~ .*\.elf$ || "${lBIN}" =~ .*\.decompressed\.bin$ || "${lBIN}" =~ .*__symbols__.* ]]; then
      continue
    fi
    generate_strings "${lBIN}" &
    local lTMP_PID="$!"
    WAIT_PIDS_S09_1+=( "${lTMP_PID}" )
    max_pids_protection $(( MAX_MOD_THREADS*2 )) WAIT_PIDS_S09_1
  done

  print_output "[*] Waiting for strings generator" "no_log"
  wait_for_pid "${WAIT_PIDS_S09_1[@]}"
  print_output "[*] Proceeding with version detection for ${ORANGE}${#FILE_ARR[@]}${NC} binary files"
  echo "S09_strings_generated" > "${TMP_DIR}/S09_strings_generated.tmp"
  print_ln

  lOS_IDENTIFIED=$(distri_check)
  local WAIT_PIDS_S09_main=()
  for lVERSION_JSON_CFG in "${lVERSION_IDENTIFIER_CFG_ARR[@]}"; do
    S09_identifier_threadings "${lVERSION_JSON_CFG}" "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    WAIT_PIDS_S09_main+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" WAIT_PIDS_S09_main
    print_dot
  done

  print_dot

  if [[ "${THREADED}" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S09_main[@]}"
    wait_for_pid "${WAIT_PIDS_S09_ARR_tmp[@]}"
  fi

  lVERSIONS_DETECTED=$(grep -c "Version information found" "${LOG_FILE}" || true)

  module_end_log "${FUNCNAME[0]}" "${lVERSIONS_DETECTED}"
}

S09_identifier_threadings() {
  local lVERSION_JSON_CFG="${1:-}"

  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_MAINT=""
  export CSV_REGEX=""

  local lSHA512_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lPURL_IDENTIFIER="NA"
  export PACKAGING_SYSTEM="static_bin_analysis"
  local lVERSION_IDENTIFIED=""
  local lBIN_DEPS_ARR=()
  local lBIN_DEPENDENCY=""
  local lPARSING_MODE_ARR=()
  local lLICENSES_ARR=()
  local lPRODUCT_NAME_ARR=()
  local lVENDOR_NAME_ARR=()
  local lCSV_REGEX_ARR=()
  local lVERSION_IDENTIFIER_ARR=()
  local lSTRICT_VERSION_IDENTIFIER_ARR=()
  local lZGREP_VERSION_IDENTIFIER_ARR=()

  mapfile -t lPARSING_MODE_ARR < <(jq -r .parsing_mode[] "${lVERSION_JSON_CFG}")
  # print_output "[*] Testing json config ${ORANGE}${lVERSION_JSON_CFG}${NC}" "no_log"
  local lRULE_IDENTIFIER=""
  lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
  mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  if [[ "${lPARSING_MODE_ARR[*]}" == *"strict"* ]]; then
    mapfile -t lSTRICT_VERSION_IDENTIFIER_ARR < <(jq -r .strict_grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  fi
  if [[ "${lPARSING_MODE_ARR[*]}" == *"zgrep"* ]]; then
    mapfile -t lZGREP_VERSION_IDENTIFIER_ARR < <(jq -r .zgrep_grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  fi
  mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  mapfile -t lAFFECTED_PATHS_ARR < <(jq -r .affected_paths[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # echo "Testing ${lRULE_IDENTIFIER} ..."
  # echo "lPARSING_MODE_ARR: ${lPARSING_MODE_ARR[*]}"
  # echo "lLICENSES_ARR: ${lLICENSES_ARR[*]}"
  # echo "lPRODUCT_NAME_ARR: ${lPRODUCT_NAME_ARR[*]}"
  # echo "lCSV_REGEX_ARR: ${lCSV_REGEX_ARR[*]}"
  # echo "lVERSION_IDENTIFIER_ARR: ${lVERSION_IDENTIFIER_ARR[*]}"
  # echo "lAFFECTED_PATHS_ARR: ${lAFFECTED_PATHS_ARR[*]}"

  # Todo: handle rpm based systems
  if [[ -f "${LOG_PATH_MODULE}"/debian_known_packages.txt || -f "${LOG_PATH_MODULE}"/openwrt_known_packages.txt ]]; then
    # Check all the product names that are configured in our json against the known files
    # if we have a match we can skip this detection and move on with the next json rule file
    for lPRODUCT_NAME in "${lPRODUCT_NAME_ARR[@]}"; do
      if [[ -s "${LOG_PATH_MODULE}"/debian_known_packages.txt ]]; then
        if grep -q "^${lPRODUCT_NAME}" "${LOG_PATH_MODULE}"/debian_known_packages.txt; then
          print_output "[*] Static rule for identifier ${lRULE_IDENTIFIER} - product name ${lPRODUCT_NAME} already covered by debian package manager" "no_log"
          # continue 2
          return
        fi
      elif [[ -s "${LOG_PATH_MODULE}"/openwrt_known_packages.txt ]]; then
        if grep -q "^${lPRODUCT_NAME}" "${LOG_PATH_MODULE}"/openwrt_known_packages.txt; then
          print_output "[*] Static rule for identifier ${lRULE_IDENTIFIER} - product name ${lPRODUCT_NAME}  already covered by OpenWRT package manager" "no_log"
          # continue 2
          return
        fi
      fi
    done
  fi
  # print_output "[*] Testing static rule for identifier ${lRULE_IDENTIFIER} - product name ${lPRODUCT_NAME}" "no_log"

  if [[ -f "${S09_CSV_LOG}" ]]; then
    # this should prevent double checking - if a version identifier was already successful we do not need to
    # test the other identifiers. In threaded mode this usually does not decrease testing speed.
    if [[ "$(tail -n +2 "${S09_CSV_LOG}" | cut -d\; -f4 | grep -c "^${lRULE_IDENTIFIER}$")" -gt 0 ]]; then
      print_output "[*] Already identified component for identifier ${lRULE_IDENTIFIER} ... skipping further tests" "no_log"
      # continue
      return
    fi
  fi

  if [[ "${lPARSING_MODE_ARR[*]}" == *"strict"* ]]; then
    # strict mode
    #   use the defined regex only on a binary with path/name from lAFFECTED_PATHS_ARR
    local lSTRICT_BINS_ARR=()
    local lBIN_ARCH=""
    local lBINARY_ENTRY=""
    local lBINARY_PATH=""
    local lBIN_FILE_DETAILS=""

    [[ "${RTOS}" -eq 1 ]] && return

    # we create an array with testing candidates based on the paths from the json configuration
    for lAPP_NAME in "${lAFFECTED_PATHS_ARR[@]}"; do
      local lSTRICT_BINS_ARR_TMP=()
      mapfile -t lSTRICT_BINS_ARR_TMP < <(grep "/${lAPP_NAME#/}" "${P99_CSV_LOG}" | sort -u || true)
      lSTRICT_BINS_ARR+=("${lSTRICT_BINS_ARR_TMP[@]}")
    done

    # before moving on we need to ensure our strings files are generated:
    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09_1[@]}"

    for lBINARY_ENTRY in "${lSTRICT_BINS_ARR[@]}"; do
      # as the STRICT_BINS array could also include other files we have to check for ELF files now
      # This information is already stored in P99_CSV_LOG and in our lBINARY_ENTRY details
      lBIN_FILE_DETAILS=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f8)
      if [[ "${lBIN_FILE_DETAILS}" == *"ELF"* ]] ; then
        # print_output "[*] Checking for strict bin ${lBINARY_ENTRY} - rule: ${lRULE_IDENTIFIER}" "no_log"
        MD5_SUM=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f9)
        lBINARY_PATH=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f2)
        lAPP_NAME="$(basename "${lBINARY_PATH}")"
        local lSTRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${MD5_SUM}"_"${lAPP_NAME}".txt
        if ! [[ -f "${lSTRINGS_OUTPUT}" ]]; then
          continue
        fi
        for lVERSION_IDENTIFIER in "${lSTRICT_VERSION_IDENTIFIER_ARR[@]}"; do
          # print_output "[*] Testing identifier ${lVERSION_IDENTIFIER}"
          lVERSION_IDENTIFIED=$(grep -a -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}" | sort -u || true)
          if [[ -n ${lVERSION_IDENTIFIED} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${lAPP_NAME} ${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}$(print_path "${lBINARY_PATH}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static - strict${GREEN})."
            if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
              # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
              continue 2
            fi
          fi
        done
      fi
    done
    print_dot
  fi

  if [[ "${lPARSING_MODE_ARR[*]}" == *"zgrep"* ]]; then
    # zgrep mode:
    #   search for files configured in json config
    #   use zgrep regex via zgrep on these files

    # we create an array with testing candidates based on the paths from the json configuration
    for lAPP_NAME in "${lAFFECTED_PATHS_ARR[@]}"; do
      local lZGREP_BINS_ARR_TMP=()
      mapfile -t lZGREP_BINS_ARR_TMP < <(grep "/${lAPP_NAME#/}" "${P99_CSV_LOG}" | sort -u || true)
      lZGREP_BINS_ARR+=("${lZGREP_BINS_ARR_TMP[@]}")
    done

    for lBINARY_ENTRY in "${lZGREP_BINS_ARR[@]}"; do
      lBINARY_PATH=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f2)
      if ! [[ -f "${lBINARY_PATH}" ]]; then
        continue
      fi
      for lVERSION_IDENTIFIER in "${lZGREP_VERSION_IDENTIFIER_ARR[@]}"; do
        # print_output "[*] Testing zgrep identifier ${ORANGE}${lVERSION_IDENTIFIER}${NC} on binary ${ORANGE}${lBINARY_PATH}${NC}"
        lVERSION_IDENTIFIED=$(zgrep -h "${lVERSION_IDENTIFIER}" "${lBINARY_PATH}" | sort -u || true)
        lVERSION_IDENTIFIED="${lVERSION_IDENTIFIED//[![:print:]]/}"
        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}$(print_path "${lBINARY_PATH}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static - zgrep${GREEN})."
          if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
            continue 2
          fi
        fi
      done
    done
    print_dot
  fi

  # This is the default mode!
  if [[ "${lPARSING_MODE_ARR[*]}" == *"normal"* ]]; then
    print_dot
    # print_output "[*] FIRMWARE: ${FIRMWARE} / RTOS: ${RTOS} / FIRMWARE_PATH: ${FIRMWARE_PATH} / FIRMWARE_PATH_BAK: ${FIRMWARE_PATH_BAK}" "no_log"

    # original firmware file:
    if [[ ${RTOS} -eq 1 ]]; then
      # in RTOS mode we also test the original firmware file

      lMD5_SUM=$(md5sum "${FIRMWARE_PATH_BAK}")
      lMD5_SUM="${lMD5_SUM/\ *}"
      lAPP_NAME="$(basename "${FIRMWARE_PATH_BAK}")"
      local lSTRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${lMD5_SUM}"_"${lAPP_NAME}".txt
      # generate strings output if not already available:
      if ! [[ -f "${lSTRINGS_OUTPUT}" ]]; then
        generate_strings "${FIRMWARE_PATH_BAK}"
      fi
      # if we were able to generate the strings we can now analyse these strings
      # if no strings available ... go ahead and test all the bins against our identifiers
      if [[ -f "${lSTRINGS_OUTPUT}" ]]; then
        for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
          # print_output "[*] Testing identifier ${lVERSION_IDENTIFIER} for RTOS firmware" "no_log"
          lVERSION_IDENTIFIED=$(grep -a -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}" | sort -u || true)
          if [[ -n ${lVERSION_IDENTIFIED} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in original firmware file (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static - firmware${GREEN})."
            # this is a little hack to get the original firmware look like a typical EMBA P99 entry
            lBIN_FILE_DETAILS=$(file -b "${FIRMWARE_PATH_BAK}")
            lBINARY_ENTRY="S09_tmp_entry_for_RTOS_detection;${FIRMWARE_PATH_BAK};3;4;5;6;7;${lBIN_FILE_DETAILS};${lMD5_SUM}"
            if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
              # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
              break
            fi
          fi
        done
      fi
    fi

    # The following area is responsible to check all binaries against our version database:

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09_1[@]}"
    # this will burn the CPU but in most cases the time of testing is cut into half
    # TODO: change to local vars via parameters - this is ugly as hell!
    local lVERSION_IDENTIFIER=""
    for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
      # print_output "[*] Calling with ${lVERSION_IDENTIFIER}" "no_log"
      bin_string_checker "${lVERSION_IDENTIFIER}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR" "lPARSING_MODE_ARR" &
      local lTMP_PID="$!"
      WAIT_PIDS_S09+=( "${lTMP_PID}" )
      # echo "WAIT_PIDS_S09: ${#WAIT_PIDS_S09[@]} / max: ${MAX_MOD_THREADS})"
      max_pids_protection "${MAX_MOD_THREADS}" WAIT_PIDS_S09
    done
    print_dot
  fi

  wait_for_pid "${WAIT_PIDS_S09[@]}"
}

version_parsing_logging() {
  local lCSV_TO_LOG="${1:-}"
  local lSRC_MODULE="${2:-}"
  local lVERSION_IDENTIFIED="${3:-}"
  local lBINARY_ENTRY="${4:-}"
  local lRULE_IDENTIFIER="${5:-}"
  local -n lrVENDOR_NAME_ARR_ref="${6:-}"
  local -n lrPRODUCT_NAME_ARR_ref="${7:-}"
  local -n lrLICENSES_ARR_ref="${8:-}"
  # shellcheck disable=SC2034
  local -n lrCSV_REGEX_ARR_ref="${9:-}"

  local lMD5_SUM=""
  local lBINARY_PATH="NA"
  local lCSV_REGEX=""
  local lCSV_RULE=""
  local lAPP_MAINT=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  local lCPE_IDENTIFIER=""
  local lBIN_ARCH=""
  local lPURL_IDENTIFIER=""

  if [[ "${lBINARY_ENTRY}" != "NA" ]]; then
    lBINARY_PATH=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f2)
    lBIN_FILE_DETAILS=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f8)
    lMD5_SUM=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f9)
  fi

  for lCSV_REGEX in "${lrCSV_REGEX_ARR_ref[@]}"; do
    lCSV_RULE=$(get_csv_rule "${lVERSION_IDENTIFIED}" "${lCSV_REGEX}")
    lCSV_RULE="${lCSV_RULE//\ }"

    lAPP_MAINT=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
    # lAPP_NAME is the name from the json configuration
    lAPP_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
    lAPP_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-5)

    if [[ "${lCSV_RULE}" != *":"*":"*":"* ]]; then
      # our csv rule not working ... continue with the next rule
      print_output "[*] CSV_REGEX (${lCSV_REGEX}) was not working for this version ... testing next regex" "no_log"
      continue
    fi
    print_output "[*] Parsing CSV_RULE: ${lCSV_RULE} - lAPP_MAINT: ${lAPP_MAINT} - lAPP_NAME: ${lAPP_NAME} - lAPP_VERS: ${lAPP_VERS}" "no_log"

    write_csv_log_to_path "${lCSV_TO_LOG}" "${lSRC_MODULE}" "${lBINARY_PATH}" "${lRULE_IDENTIFIER}" "${lAPP_NAME}" "${lVERSION_IDENTIFIED}" "${lCSV_RULE}" "${lrLICENSES_ARR_ref[*]}" "${TYPE}"
    check_for_s08_csv_log "${S08_CSV_LOG}"

    if [[ "${lBINARY_ENTRY}" != "NA" ]]; then
      lSHA256_CHECKSUM="$(sha256sum "${lBINARY_PATH}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lBINARY_PATH}" | awk '{print $1}')"
      lBIN_ARCH=$(echo "${lBIN_FILE_DETAILS}" | cut -d ',' -f2)
      lBIN_ARCH=${lBIN_ARCH#\ }
    fi
    lCPE_IDENTIFIER=$(build_cpe_identifier "${lCSV_RULE}")
    lPURL_IDENTIFIER=$(build_generic_purl "${lCSV_RULE}" "${lOS_IDENTIFIED:-NA}" "${lBIN_ARCH}")

    if [[ -z "${lAPP_MAINT}" ]]; then
      # if we have no vendor/maintainer we are going to set it to the first entry of our config
      lAPP_MAINT="${lrVENDOR_NAME_ARR_ref[0]}"
    fi
    if [[ -z "${lAPP_NAME}" ]]; then
      # if we have no product_name we are going to set it to the first entry of our config
      # This should not happen but we will need some functionality like this in the future
      lAPP_NAME="${lrPRODUCT_NAME_ARR_ref[0]}"
      lCSV_RULE="::${lAPP_NAME}:${lAPP_VERS}"
    fi

    # add source file path information to our properties array:
    local lPROP_ARRAY_INIT_ARR=()
    if [[ "${lBINARY_ENTRY}" != "NA" ]]; then
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lBINARY_PATH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_details:${lBIN_FILE_DETAILS}" )
    fi
    lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${lVERSION_IDENTIFIED}" )

    # minimal identifier is deprecated and will be replaced in the future
    lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lCSV_RULE}" )

    # lets store the vendor names and product names for later vulnerability identification
    for lPNAME in "${lrPRODUCT_NAME_ARR_ref[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "product_name:${lPNAME}" )
    done
    for lVENDOR in "${lrVENDOR_NAME_ARR_ref[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lVENDOR}" )
    done
    lPROP_ARRAY_INIT_ARR+=( "confidence:$(get_confidence_string "${CONFIDENCE_LEVEL:-0}")" )

    # build the dependencies based on linker details
    if [[ "${lBIN_FILE_DETAILS:-NA}" == *"dynamically linked"* ]]; then
      local lBIN_DEPS_ARR=()
      local lBIN_DEPENDENCY=""
      # now we can create the dependencies based on ldd
      mapfile -t lBIN_DEPS_ARR < <(ldd "${lBINARY_PATH}" 2>&1 | grep -v "not a dynamic executable" | awk '{print $1}' || true)
      for lBIN_DEPENDENCY in "${lBIN_DEPS_ARR[@]}"; do
        lPROP_ARRAY_INIT_ARR+=( "dependency:${lBIN_DEPENDENCY}" )
      done
    fi

    build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

    if [[ "${lBINARY_ENTRY}" != "NA" ]]; then
      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lBINARY_PATH:-NA}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${PACKAGING_SYSTEM:-NA}" "${CONFIDENCE_LEVEL:-0}"; then
        print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
        # we continue with the next binary -> set return value as marker to get the knowledge in the caller
        return 0
      fi
    fi

    # create component entry - this allows adding entries very flexible:
    build_sbom_json_component_arr "${PACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lrLICENSES_ARR_ref[*]}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

    write_log "${PACKAGING_SYSTEM};${lBINARY_PATH:-NA};${MD5_SUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME,,};${lVERSION_IDENTIFIED:-NA};${lCSV_RULE:-NA};${lrLICENSES_ARR_ref[*]};maintainer unknown;${lBIN_ARCH:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
    # we continue with the next binary -> set return as marker to get the knowledge in the caller
    return 0
  done
  return 1
}

# we create the final_bins.txt file which includes the binaries for further analysis
# Addtionally, it creates the unhandled files SBOM json entries
build_final_bins_threader() {
  local lFILE="${1:-}"
  local lBIN_FILE="${2:-}"

  if [[ "${lFILE}" =~ .*\.padding$ || "${lFILE}" =~ .*\.unknown$ || "${lFILE}" =~ .*\.uncompressed$ || "${lFILE}" =~ .*\.raw$ || "${lFILE}" =~ .*\.elf$ || "${lFILE}" =~ .*\.decompressed\.bin$ ]]; then
    # binwalk and unblob are producing multiple files that are not relevant for the SBOM and can skip them here
    return
  fi

  if [[ "${lBIN_FILE}" != *"text"* && "${lBIN_FILE}" != *"compressed"* && "${lBIN_FILE}" != *"archive"* && "${lBIN_FILE}" != *"empty"* && "${lBIN_FILE}" != *"Git pack"* ]]; then
    echo "${lFILE}" >> "${LOG_PATH_MODULE}"/final_bins.txt
  fi

  if [[ "${SBOM_UNTRACKED_FILES}" -lt 1 ]]; then
    return
  fi
  if [[ "${lBIN_FILE}" != *"ELF"* && "${SBOM_UNTRACKED_FILES}" -lt 2 ]]; then
    return
  fi

  # lets generate sbom entries for all files that are not handled by package manager
  # with this in place we can add this information later on to the SBOM (if this is really needed)

  lAPP_NAME=$(basename "${lFILE}")
  local lAPP_VERS="Unknown Version"
  if [[ "${lBIN_FILE}" == *"ELF"* ]]; then
    local lAPP_TYPE="library"
  elif [[ "${lBIN_FILE}" == *"data"* ]]; then
    # is this correct?
    local lAPP_TYPE="data"
  elif [[ "${lBIN_FILE}" == *"block special"* || "${lBIN_FILE}" == *"character special"* ]]; then
    # is this correct?
    local lAPP_TYPE="device-driver"
  else
    local lAPP_TYPE="file"
  fi
  local lPACKAGING_SYSTEM="unhandled_file"
  local lPROP_ARRAY_INIT_ARR=()
  lBIN_ARCH=$(echo "${lBIN_FILE}" | cut -d ',' -f2)
  lBIN_ARCH=${lBIN_ARCH#\ }
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lFILE}" )
  if [[ -n "${lBIN_ARCH}" ]]; then
    lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
  fi
  lPROP_ARRAY_INIT_ARR+=( "source_details:${lBIN_FILE}" )

  # build the dependencies based on linker details
  if [[ "${lBIN_FILE}" == "dynamically linked" ]]; then
    # now we can create the dependencies based on ldd
    mapfile -t lBIN_DEPS_ARR < <(ldd "${lFILE}" 2>&1 | grep -v "not a dynamic executable" | awk '{print $1}' || true)
    for lBIN_DEPENDENCY in "${lBIN_DEPS_ARR[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "dependency:${lBIN_DEPENDENCY}" )
    done
  fi

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lFILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}" "${CONFIDENCE_LEVEL:-0}"; then
    # print_output "[*] Already found results for ${lAPP_NAME:-NA} / ${lAPP_VERS:-NA}" "no_log"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lLICENSES_ARR[*]}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
}

check_pkg_files_filesystem() {
  local lPKG_FILE="${1:-}"
  local lFS_FILES="${2:-}"

  # if our file from the filesystem is in the package managers array we do not need to test it here
  if grep -E -q "${lPKG_FILE}$" "${lFS_FILES}"; then
    # print_output "[+] Adding ${ORANGE}${lFILE}${GREEN} to testing array ..." "no_log"
    grep -E "${lPKG_FILE}$" "${lFS_FILES}" >> "${LOG_PATH_MODULE}"/known_system_files.txt
  fi
}

build_generic_purl() {
  local lCSV_RULE="${1:-}"
  local lOS_IDENTIFIED="${2:-NA}"
  local lAPP_ARCH="${3:-}"

  if [[ "${lOS_IDENTIFIED}" == "NA" ]]; then
    lOS_IDENTIFIED="generic"
  fi

  local lBIN_VENDOR=""
  local lBIN_NAME=""
  local lBIN_VERS=""
  local lPURL_IDENTIFIER=""

  lBIN_VENDOR=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
  lBIN_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
  if [[ -z "${lBIN_VENDOR}" ]]; then
    # backup mode for setting the vendor in the CPE to the software component
    lBIN_VENDOR="${lBIN_NAME}"
  fi
  lPURL_IDENTIFIER="pkg:binary/${lOS_IDENTIFIED/-*}/${lBIN_NAME}"
  lBIN_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-)

  if [[ -n "${lBIN_VERS}" ]]; then
    lPURL_IDENTIFIER+="@${lBIN_VERS}"
  fi
  if [[ -n "${lAPP_ARCH}" ]]; then
    lPURL_IDENTIFIER+="?arch=${lAPP_ARCH//\ /-}"
  fi
  if [[ "${lOS_IDENTIFIED}" != "generic" ]]; then
    if [[ -n "${lAPP_ARCH}" ]]; then
      lPURL_IDENTIFIER+="&"
    else
      lPURL_IDENTIFIER+="?"
    fi
    lPURL_IDENTIFIER+="distro=${lOS_IDENTIFIED}"
  fi

  echo "${lPURL_IDENTIFIER}"
}

build_cpe_identifier() {
  local lCSV_RULE="${1:-}"
  local lBIN_VENDOR=""
  local lBIN_NAME=""
  local lBIN_VERS=""
  local lCPE_LENGTH=""
  local lCPE_IDENTIFIER=""

  lBIN_VENDOR=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
  lBIN_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
  if [[ -z "${lBIN_VENDOR}" ]]; then
    # backup mode for setting the vendor in the CPE to the software component
    lBIN_VENDOR="${lBIN_NAME}"
  fi
  lBIN_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-)
  # our CPE identifier should have 13 fields - sometimes our lBIN_VERS has multiple fields -> we need to count our fields and fill the rest
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lBIN_VENDOR:-*}:${lBIN_NAME:-*}:${lBIN_VERS:-*}:"
  lCPE_LENGTH=$(echo "${lCPE_IDENTIFIER}" | tr ':' '\n' | wc -l)

  while [[ "${lCPE_LENGTH}" -lt 13 ]]; do
    lCPE_IDENTIFIER+='*:'
    lCPE_LENGTH=$(echo "${lCPE_IDENTIFIER}" | tr ':' '\n' | wc -l)
  done
  lCPE_IDENTIFIER+='*'

  echo "${lCPE_IDENTIFIER}"
}

generate_strings() {
  local lBINARY_PATH="${1:-}"

  local lBIN_DATA_ARR=()
  local lBIN_FILE=""
  local lMD5_SUM=""
  local lBIN_NAME_REAL=""
  local lSTRINGS_OUTPUT=""

  if ! [[ -f "${lBINARY_PATH}" ]]; then
    # print_output "[*] No ${lBINARY_PATH} found ... return"
    return
  fi

  mapfile -t lBIN_DATA_ARR < <(grep -F ";${lBINARY_PATH};" "${P99_CSV_LOG}" | tr ';' '\n' || true)

  if [[ "${#lBIN_DATA_ARR[@]}" -lt 7 ]]; then
    # print_output "[*] No ${lBINARY_PATH} in P99 csv found ... return"
    # we have no entry in our P99 csv file! Should we create one now?
    return
  fi
  lBIN_FILE="${lBIN_DATA_ARR[7]}"
  # print_output "[*] ${lBIN_FILE} for ${lBINARY_PATH} found .."

  # Just in case we need to create SBOM entries for every file
  # This is configured via the scanning profiles
  if [[ "${SBOM_UNTRACKED_FILES:-0}" -gt 0 ]]; then
    build_final_bins_threader "${lBINARY_PATH}" "${lBIN_FILE}" &
    local lTMP_PID="$!"
    WAIT_PIDS_S09_ARR_tmp+=( "${lTMP_PID}" )
  fi

  if [[ "${lBIN_FILE}" == "empty" || "${lBIN_FILE}" == *"text"* || "${lBIN_FILE}" == *" archive "* || "${lBIN_FILE}" == *" compressed "* || "${lBIN_FILE}" == *" image data"* || "${lBIN_FILE}" == *"Git pack"* ]]; then
    return
  fi

  lMD5_SUM="${lBIN_DATA_ARR[8]}"
  lBIN_NAME_REAL="$(basename "${lBINARY_PATH}")"
  lSTRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${lMD5_SUM}"_"${lBIN_NAME_REAL}".txt
  if ! [[ -f "${lSTRINGS_OUTPUT}" ]]; then
    # print_output "[*] Generating strings for ${lBINARY_PATH} ..."
    strings "${lBINARY_PATH}" | uniq > "${lSTRINGS_OUTPUT}" || true
  fi
}

# bin_string_checker "${lVERSION_IDENTIFIER}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR" "lPARSING_MODE_ARR" &
bin_string_checker() {
  local lVERSION_IDENTIFIER="${1:-}"
  local lRULE_IDENTIFIER="${2:-}"
  # shellcheck disable=SC2034
  local -n lrVENDOR_NAME_ARR="${3:-}"
  # shellcheck disable=SC2034
  local -n lrPRODUCT_NAME_ARR="${4:-}"
  # shellcheck disable=SC2034
  local -n lrLICENSES_ARR="${5:-}"
  # shellcheck disable=SC2034
  local -n lrCSV_REGEX_ARR="${6:-}"
  local -n lrPARSING_MODE_ARR="${7:-}"

  # load lVERSION_IDENTIFIER string into array for multi_grep handling
  local lVERSION_IDENTIFIERS_ARR=()
  # remove the ' from the multi_grep identifiers:
  lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER%\'}"
  lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER#\'}"
  # nosemgrep
  local IFS='&&'
  IFS='&&' read -r -a lVERSION_IDENTIFIERS_ARR <<< "${lVERSION_IDENTIFIER}"

  local lPURL_IDENTIFIER="NA"
  local lOS_IDENTIFIED=""
  local lMD5_SUM=""
  local lMD5_SUM_MATCHES_ARR=()
  local lMD5_SUM_MATCHED=""
  local lMATCHED_FILE_DATA=""
  local lBIN_DEPS_ARR=()
  local lBIN_DEPENDENCY=""

  lOS_IDENTIFIED=$(distri_check)
  if [[ -d "${LOG_PATH_MODULE}"/strings_bins ]] && [[ -v lVERSION_IDENTIFIERS_ARR[0] ]]; then
    local lFILE_DATA_ARR=()
    # we always check for the first entry (also on multi greps) against all our generated strings.
    # if we have a match we can extract the md5sum from our path and use this to get the complete pathname from p99-csv log
    # this pathname ist finally used for the FILE_ARR which is then used for further analysis
    local lVERSION_IDENTIFIER_first_elem="${lVERSION_IDENTIFIERS_ARR[0]}"
    if [[ "${lVERSION_IDENTIFIER_first_elem: -1}" == '"' ]]; then
      lVERSION_IDENTIFIER_first_elem="${lVERSION_IDENTIFIER_first_elem#\"}"
      lVERSION_IDENTIFIER_first_elem="${lVERSION_IDENTIFIER_first_elem%\"}"
    fi
    # print_output "[*] Testing ${ORANGE}${lVERSION_IDENTIFIER_first_elem}${NC} from ${ORANGE}${lVERSION_IDENTIFIERS_ARR[*]}${NC}" "no_log"
    mapfile -t lMD5_SUM_MATCHES_ARR < <(grep -a -o -E -l -r "${lVERSION_IDENTIFIER_first_elem}" "${LOG_PATH_MODULE}"/strings_bins | rev | cut -d '/' -f 1 | rev | cut -d '_' -f2 | sort -u || true)
    for lMD5_SUM_MATCHED in "${lMD5_SUM_MATCHES_ARR[@]}"; do
      lMATCHED_FILE_DATA=$(grep ";${lMD5_SUM_MATCHED};" "${P99_CSV_LOG}" | head -1 || true)
      lFILE_DATA_ARR+=("${lMATCHED_FILE_DATA}")
      # print_output "[*] Matched ${lMATCHED_FILE_DATA}" "no_log"
    done
  fi
  if [[ "${#lFILE_DATA_ARR[@]}" -eq 0 ]]; then
    # print_output "[-] No file array created for ${lVERSION_IDENTIFIER}" "no_log"
    return
  fi

  # print_output "[*] Testing version identifier ${ORANGE}${lVERSION_IDENTIFIERS_ARR[*]}${NC} against ${ORANGE}${#lFILE_DATA_ARR[@]} files${NC}" "no_log"

  for lBINARY_DATA in "${lFILE_DATA_ARR[@]}"; do
    local lBIN_DATA_ARR=()
    local lBINARY_PATH=""
    local lBIN_NAME_REAL=""
    local lBIN_FILE=""

    mapfile -t lBIN_DATA_ARR < <(echo "${lBINARY_DATA}" | tr ';' '\n')
    lBINARY_PATH="${lBIN_DATA_ARR[1]}"
    if [[ ! -f "${lBINARY_PATH}" ]]; then
      print_output "[-] Binary ${lBINARY_PATH} not found - Not testing for versions"
      continue
    fi

    lBIN_NAME_REAL="$(basename "${lBINARY_PATH}")"
    lBIN_FILE="${lBIN_DATA_ARR[7]}"
    if [[ "${lBIN_FILE}" == *"text"* || "${lBIN_FILE}" == *" archive "* || "${lBIN_FILE}" == *" compressed "* ]]; then
      continue
    fi
    lMD5_SUM="${lBIN_DATA_ARR[8]}"
    local lSTRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${lMD5_SUM}"_"${lBIN_NAME_REAL}".txt
    if ! [[ -f "${lSTRINGS_OUTPUT}" ]]; then
      # print_output "[-] Warning: Strings for bin ${lBINARY_PATH} not found"
      continue
    fi
    local CONFIDENCE_LEVEL=3

    # print_output "[*] Testing ${lBINARY_PATH}" "no_log"
    for (( j=0; j<${#lVERSION_IDENTIFIERS_ARR[@]}; j++ )); do
      local lVERSION_IDENTIFIER="${lVERSION_IDENTIFIERS_ARR["${j}"]}"
      local lVERSION_IDENTIFIED=""
      [[ -z "${lVERSION_IDENTIFIER}" ]] && continue
      # this is a workaround to handle the new multi_grep
      if [[ "${lVERSION_IDENTIFIER: -1}" == '"' ]]; then
        lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER/\"}"
        lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER%\"}"
      fi
      if [[ ${RTOS} -eq 0 ]]; then
        if [[ "${lBIN_FILE}" == *ELF* || "${lBIN_FILE}" == *uImage* || "${lBIN_FILE}" == *Kernel\ Image* || "${lBIN_FILE}" == *"Linux\ kernel"* ]] ; then
          # print_output "[*] Testing ${lBINARY_PATH} with version identifier ${lVERSION_IDENTIFIER}" "no_log"
          lVERSION_IDENTIFIED=$(grep -o -a -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}" | sort -u | head -1 || true)

          if [[ -n ${lVERSION_IDENTIFIED} ]]; then
            if [[ "${#lVERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#lVERSION_IDENTIFIERS_ARR[@]}" ]]; then
              # we found the first identifier and now we need to check the other identifiers also
              print_output "[+] Found sub identifier ${ORANGE}${lVERSION_IDENTIFIER}${GREEN} in binary ${ORANGE}${lBINARY_PATH}${GREEN}" "no_log"
              continue
            fi
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}$(print_path "${lBINARY_PATH}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static${GREEN})."

            if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_DATA}" "${lRULE_IDENTIFIER}" "lrVENDOR_NAME_ARR" "lrPRODUCT_NAME_ARR" "lrLICENSES_ARR" "lrCSV_REGEX_ARR"; then
              # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
              continue 2
            fi
          fi
        else
          if [[ "${lrPARSING_MODE_ARR[*]}" == *"multi_grep"* ]]; then
            # we do not test multi_grep on other things then ELF files!
            continue
          fi
          # this is for all other "non-text" stuff -> this gets a very low confidence rating
          # the false positive rate is higher
          lVERSION_IDENTIFIED=$(grep -o -a -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}" | sort -u | head -1 || true)

          if [[ -n ${lVERSION_IDENTIFIED} ]]; then
            if [[ "${#lVERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#lVERSION_IDENTIFIERS_ARR[@]}" ]]; then
              # we found the first identifier and now we need to check the other identifiers also
              print_output "[+] Found sub identifier ${ORANGE}${lVERSION_IDENTIFIER}${GREEN} in file ${ORANGE}${lBINARY_PATH}${GREEN}" "no_log"
              continue
            fi
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in file ${ORANGE}$(print_path "${lBINARY_PATH}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static${GREEN})."

            if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_DATA}" "${lRULE_IDENTIFIER}" "lrVENDOR_NAME_ARR" "lrPRODUCT_NAME_ARR" "lrLICENSES_ARR" "lrCSV_REGEX_ARR"; then
              # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
              continue 2
            fi
          fi
        fi
      else
        # this is RTOS mode
        # echo "Testing $lBINARY_PATH - $lVERSION_IDENTIFIER"
        lVERSION_IDENTIFIED=$(grep -o -a -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}" | sort -u | head -1 || true)

        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          if [[ "${#lVERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#lVERSION_IDENTIFIERS_ARR[@]}" ]]; then
            # we found the first identifier and now we need to check the other identifiers also
            print_output "[+] Found sub identifier ${ORANGE}${lVERSION_IDENTIFIER}${GREEN} in binary ${ORANGE}${lBINARY_PATH}${GREEN}" "no_log"
            continue
          fi
          print_ln "no_log"
          print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}$(print_path "${lBINARY_PATH}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}static${GREEN})."

          if version_parsing_logging "${S09_CSV_LOG}" "S09_firmware_base_version_check" "${lVERSION_IDENTIFIED}" "${lBINARY_DATA}" "${lRULE_IDENTIFIER}" "lrVENDOR_NAME_ARR" "lrPRODUCT_NAME_ARR" "lrLICENSES_ARR" "lrCSV_REGEX_ARR"; then
            # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
            continue 2
          fi
        fi
      fi
      continue 2
    done
  done
}

