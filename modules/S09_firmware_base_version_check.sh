#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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
#               The version configuration file is stored in config/bin_version_strings.cfg

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S09_firmware_base_version_check() {

  # this module check for version details statically.
  # this module is designed for *x based systems

  module_log_init "${FUNCNAME[0]}"
  module_title "Static binary firmware versions detection"
  pre_module_reporter "${FUNCNAME[0]}"

  local EXTRACTOR_LOG="${LOG_DIR}"/p55_unblob_extractor/unblob_firmware.log

  print_output "[*] Static version detection running ..." "no_log" | tr -d "\n"
  write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

  export TYPE="static"
  export VERSION_IDENTIFIER=""
  export WAIT_PIDS_S09=()
  export WAIT_PIDS_S09_1=()
  local VERSIONS_DETECTED=""
  local VERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings.cfg

  if [[ "${QUICK_SCAN:-0}" -eq 1 ]] && [[ -f "${CONFIG_DIR}"/bin_version_strings_quick.cfg ]]; then
    # the quick scan configuration has only entries that have known vulnerabilities in the CVE database
    local VERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings_quick.cfg
    local V_CNT=0
    V_CNT=$(wc -l "${CONFIG_DIR}"/bin_version_strings_quick.cfg)
    print_output "[*] Quick scan enabled - ${V_CNT/\ *} version identifiers loaded"
  fi

  print_output "[*] Generate strings overview for further analysis ..." "no_log"
  local BIN=""
  # if we have a linux we only need to check our BINARIES array
  if [[ ${RTOS} -eq 0 ]]; then
    local FILE_ARR=( "${BINARIES[@]}" )
  fi
  mkdir "${LOG_PATH_MODULE}"/strings_bins/
  if ! [[ -d "${LOG_PATH_MODULE}"/strings_bins ]]; then
    mkdir "${LOG_PATH_MODULE}"/strings_bins || true
  fi
  for BIN in "${FILE_ARR[@]}"; do
    generate_strings "${BIN}" &
    local TMP_PID="$!"
    store_kill_pids "${TMP_PID}"
    WAIT_PIDS_S09_1+=( "${TMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S09_1[@]}"
  done

  while read -r VERSION_LINE; do
    if safe_echo "${VERSION_LINE}" | grep -v -q "^[^#*/;]"; then
      continue
    fi
    if safe_echo "${VERSION_LINE}" | grep -q ";no_static;"; then
      continue
    fi
    if safe_echo "${VERSION_LINE}" | grep -q ";live;"; then
      continue
    fi

    print_dot

    local STRICT=""
    export LIC=""
    local lAPP_NAME=""
    local lAPP_VERS=""
    local lAPP_MAINT=""
    local BIN_PATH=""
    export CSV_REGEX=""

    local lSHA512_CHECKSUM=""
    local lSHA256_CHECKSUM=""
    local lPURL_IDENTIFIER="NA"
    local lPACKAGING_SYSTEM="static_bin_analysis"

    STRICT="$(safe_echo "${VERSION_LINE}" | cut -d\; -f2)"
    LIC="$(safe_echo "${VERSION_LINE}" | cut -d\; -f3)"
    lAPP_NAME="$(safe_echo "${VERSION_LINE}" | cut -d\; -f1)"
    CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"

    if [[ -f "${S09_CSV_LOG}" ]]; then
      # this should prevent double checking - if a version identifier was already successful we do not need to
      # test the other identifiers. In threaded mode this usually does not decrease testing speed.
      if [[ "$(tail -n +2 "${S09_CSV_LOG}" | cut -d\; -f2 | grep -c "^${lAPP_NAME}$")" -gt 0 ]]; then
        print_output "[*] Already identified component for identifier ${lAPP_NAME} - ${CSV_REGEX} ... skipping further tests" "no_log"
        continue
      fi
    fi

    VERSION_IDENTIFIER="$(safe_echo "${VERSION_LINE}" | cut -d\; -f4)"
    if [[ "${VERSION_IDENTIFIER: 0:1}" == '"' ]]; then
      VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
      VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"
    fi

    if [[ "${STRICT}" == *"strict"* ]]; then
      local STRICT_BINS=()
      local BIN=""
      local lBIN_ARCH=""

      # strict mode
      #   use the defined regex only on a binary called lAPP_NAME (field 1)
      #   Warning: strict mode is deprecated and will be removed in the future.

      [[ "${RTOS}" -eq 1 ]] && continue

      mapfile -t STRICT_BINS < <(find "${OUTPUT_DIR}" -xdev -executable -type f -name "${lAPP_NAME}" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
      # before moving on we need to ensure our strings files are generated:
      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09_1[@]}"
      for BIN in "${STRICT_BINS[@]}"; do
        # as the STRICT_BINS array could also include executable scripts we have to check for ELF files now:
        lBIN_ARCH=$(file -b "${BIN}")
        if [[ "${lBIN_ARCH}" == *"ELF"* ]] ; then
          MD5_SUM="$(md5sum "${BIN}" | awk '{print $1}')"
          lAPP_NAME="$(basename "${BIN}")"
          STRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${MD5_SUM}"_"${lAPP_NAME}".txt
          if ! [[ -f "${STRINGS_OUTPUT}" ]]; then
            continue
          fi
          VERSION_FINDER=$(grep -a -E "${VERSION_IDENTIFIER}" "${STRINGS_OUTPUT}" | sort -u || true)
          if [[ -n ${VERSION_FINDER} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${lAPP_NAME} ${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static - strict - deprecated${GREEN})."
            CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
            write_csv_log "${BIN}" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            check_for_s08_csv_log "${S08_CSV_LOG}"

            lSHA256_CHECKSUM="$(sha256sum "${BIN}" | awk '{print $1}')"
            lSHA512_CHECKSUM="$(sha512sum "${BIN}" | awk '{print $1}')"
            lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
            lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")
            lBIN_ARCH=$(echo "${lBIN_ARCH}" | cut -d ',' -f2-3)
            lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
            lBIN_ARCH=${lBIN_ARCH#\ }

            lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
            lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
            lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

            ### new SBOM json testgenerator
            if command -v jo >/dev/null; then
              # add source file path information to our properties array:
              local lPROP_ARRAY_INIT_ARR=()
              lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
              lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
              lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
              lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

              build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

              # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
              # final array with all hash values
              build_sbom_json_hashes_arr "${BIN}"

              # create component entry - this allows adding entries very flexible:
              build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
            fi

            write_log "${lPACKAGING_SYSTEM};${BIN:-NA};${MD5_SUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME,,};${VERSION_FINDER:-NA};${CSV_RULE:-NA};${LIC:-NA};maintainer unknown;${lBIN_ARCH:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
            continue
          fi
        fi
      done
      print_dot

    elif [[ "${STRICT}" == "zgrep" ]]; then
      local SPECIAL_FINDS=()
      local SFILE=""

      # zgrep mode:
      #   search for files with identifier in field 1
      #   use regex (VERSION_IDENTIFIER) via zgrep on these files
      #   use csv-regex to get the csv-search string for csv lookup

      mapfile -t SPECIAL_FINDS < <(find "${FIRMWARE_PATH}" -xdev -type f -name "${lAPP_NAME}" -exec zgrep -H "${VERSION_IDENTIFIER}" {} \; || true)
      for SFILE in "${SPECIAL_FINDS[@]}"; do
        BIN_PATH=$(safe_echo "${SFILE}" | cut -d ":" -f1)
        lAPP_NAME="$(basename "$(safe_echo "${SFILE}" | cut -d ":" -f1)")"
        # CSV_REGEX=$(echo "${VERSION_LINE}" | cut -d\; -f5 | sed s/^\"// | sed s/\"$//)
        CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"
        CSV_REGEX="${CSV_REGEX/\"}"
        CSV_REGEX="${CSV_REGEX%\"}"
        VERSION_FINDER=$(safe_echo "${SFILE}" | cut -d ":" -f2-3 | tr -dc '[:print:]')
        CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")

        print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN_PATH}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static - zgrep${GREEN})."
        write_csv_log "${BIN_PATH}" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
        check_for_s08_csv_log "${S08_CSV_LOG}"

        lMD5_CHECKSUM="$(md5sum "${BIN_PATH}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${BIN_PATH}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${BIN_PATH}" | awk '{print $1}')"
        lBIN_ARCH=$(file -b "${BIN}")
        lBIN_ARCH=$(echo "${lBIN_ARCH}" | cut -d ',' -f2-3)
        lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
        lBIN_ARCH=${lBIN_ARCH#\ }
        lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
        lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")

        lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
        lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
        lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

        ### new SBOM json testgenerator
        if command -v jo >/dev/null; then
          # add source file path information to our properties array:
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
          lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
          lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          build_sbom_json_hashes_arr "${BIN}"

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "static_bin_analysis;${BIN_PATH:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;${lBIN_ARCH};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
      done
      print_dot

    else

      # This is default mode!

      if [[ -f "${EXTRACTOR_LOG}" ]]; then
        # check unblob files sometimes we can find kernel version information or something else in it
        VERSION_FINDER=$(grep -o -a -E "${VERSION_IDENTIFIER}" "${EXTRACTOR_LOG}" 2>/dev/null | head -1 2>/dev/null || true)
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in unblob logs (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
          write_csv_log "unblob logs" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
          check_for_s08_csv_log "${S08_CSV_LOG}"

          lMD5_CHECKSUM="$(md5sum "${EXTRACTOR_LOG}" | awk '{print $1}')"
          lSHA256_CHECKSUM="$(sha256sum "${EXTRACTOR_LOG}" | awk '{print $1}')"
          lSHA512_CHECKSUM="$(sha512sum "${EXTRACTOR_LOG}" | awk '{print $1}')"
          lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
          lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")

          lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
          lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
          lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

          ### new SBOM json testgenerator
          if command -v jo >/dev/null; then
            # add source file path information to our properties array:
            local lPROP_ARRAY_INIT_ARR=()
            lPROP_ARRAY_INIT_ARR+=( "source_path:${EXTRACTOR_LOG}" )
            lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
            lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

            build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

            # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
            # final array with all hash values
            build_sbom_json_hashes_arr "${EXTRACTOR_LOG}"

            # create component entry - this allows adding entries very flexible:
            build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
          fi

          write_log "static_bin_analysis;${EXTRACTOR_LOG:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;unknown;${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
          print_dot
        fi
      fi

      print_dot

      if [[ ${FIRMWARE} -eq 0 || -f ${FIRMWARE_PATH} ]]; then
        VERSION_FINDER=$(find "${FIRMWARE_PATH}" -xdev -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2>/dev/null || true)

        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in original firmware file (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
          write_csv_log "firmware" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
          check_for_s08_csv_log "${S08_CSV_LOG}"

          lMD5_CHECKSUM="$(md5sum "${FIRMWARE_PATH}" | awk '{print $1}')"
          lSHA256_CHECKSUM="$(sha256sum "${FIRMWARE_PATH}" | awk '{print $1}')"
          lSHA512_CHECKSUM="$(sha512sum "${FIRMWARE_PATH}" | awk '{print $1}')"
          lBIN_ARCH=$(file -b "${FIRMWARE_PATH}")
          lBIN_ARCH=$(echo "${lBIN_ARCH}" | cut -d ',' -f2-3)
          lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
          lBIN_ARCH=${lBIN_ARCH#\ }
          lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
          lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")

          lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
          lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
          lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

          ### new SBOM json testgenerator
          if command -v jo >/dev/null; then
            # add source file path information to our properties array:
            local lPROP_ARRAY_INIT_ARR=()
            lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
            lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
            lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
            lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

            build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

            # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
            # final array with all hash values
            build_sbom_json_hashes_arr "${BIN}"

            # create component entry - this allows adding entries very flexible:
            build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
          fi

          write_log "static_bin_analysis;${FIRMWARE_PATH:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};$(basename "${FIRMWARE_PATH}");${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;${lBIN_ARCH:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
        fi
        print_dot
      fi

      if [[ ${RTOS} -eq 1 ]]; then
        # in RTOS mode we also test the original firmware file
        VERSION_FINDER=$(find "${FIRMWARE_PATH_BAK}" -xdev -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2>/dev/null || true)
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in original firmware file (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
          write_csv_log "firmware" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
        fi
      fi

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09_1[@]}"
      if [[ "${THREADED}" -eq 1 ]]; then
        # this will burn the CPU but in most cases the time of testing is cut into half
        # TODO: change to local vars via parameters - this is ugly as hell!
        bin_string_checker &
        local TMP_PID="$!"
        store_kill_pids "${TMP_PID}"
        WAIT_PIDS_S09+=( "${TMP_PID}" )
      else
        bin_string_checker
      fi

      print_dot

    fi

    if [[ "${THREADED}" -eq 1 ]]; then
      if [[ "${#WAIT_PIDS_S09[@]}" -gt "${MAX_MOD_THREADS}" ]]; then
        recover_wait_pids "${WAIT_PIDS_S09[@]}"
        if [[ "${#WAIT_PIDS_S09[@]}" -gt "${MAX_MOD_THREADS}" ]]; then
          max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S09[@]}"
        fi
      fi
    fi

  done  < "${VERSION_IDENTIFIER_CFG}"

  print_dot

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09[@]}"

  VERSIONS_DETECTED=$(grep -c "Version information found" "${LOG_FILE}" || true)

  module_end_log "${FUNCNAME[0]}" "${VERSIONS_DETECTED}"
}

build_generic_purl() {
  local lCSV_RULE="${1:-}"
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
  lBIN_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-)
  lPURL_IDENTIFIER="pkg:generic/${lBIN_VENDOR}/${lBIN_NAME}@${lBIN_VERS}"

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

  echo "${lCPE_IDENTIFIER}"
}

generate_strings() {
  local BIN="${1:-}"
  local BIN_FILE=""
  local MD5_SUM=""
  local BIN_NAME_REAL=""
  local STRINGS_OUTPUT=""

  # if we do not talk about a RTOS it is a Linux and we test ELF files
  if [[ ${RTOS} -eq 0 ]]; then
    BIN_FILE=$(file -b "${BIN}" || true)
    if ! [[ "${BIN_FILE}" == *uImage* || "${BIN_FILE}" == *Kernel\ Image* || "${BIN_FILE}" == *ELF* ]] ; then
      return
    fi
  fi

  MD5_SUM="$(md5sum "${BIN}" | awk '{print $1}')"
  BIN_NAME_REAL="$(basename "${BIN}")"
  STRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${MD5_SUM}"_"${BIN_NAME_REAL}".txt
  if ! [[ -f "${STRINGS_OUTPUT}" ]]; then
    strings "${BIN}" > "${STRINGS_OUTPUT}" || true
  fi
}

bin_string_checker() {
  local VERSION_IDENTIFIERS_ARR=()
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\'}"
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\'}"
  local lPACKAGING_SYSTEM="static_bin_analysis"

  # load VERSION_IDENTIFIER string into array for multi_grep handling
  # nosemgrep
  local IFS='&&'
  IFS='&&' read -r -a VERSION_IDENTIFIERS_ARR <<< "${VERSION_IDENTIFIER}"

  local BIN_FILE=""
  local BIN=""
  local lPURL_IDENTIFIER="NA"

  if [[ ${RTOS} -eq 0 ]]; then
    local FILE_ARR=( "${BINARIES[@]}" )
  fi

  for BIN in "${FILE_ARR[@]}"; do
    MD5_SUM="$(md5sum "${BIN}" | awk '{print $1}')"
    BIN_NAME_REAL="$(basename "${BIN}")"
    STRINGS_OUTPUT="${LOG_PATH_MODULE}"/strings_bins/strings_"${MD5_SUM}"_"${BIN_NAME_REAL}".txt
    if ! [[ -f "${STRINGS_OUTPUT}" ]]; then
      continue
    fi

    # print_output "[*] Testing $BIN" "no_log"
    for (( j=0; j<${#VERSION_IDENTIFIERS_ARR[@]}; j++ )); do
      local VERSION_IDENTIFIER="${VERSION_IDENTIFIERS_ARR["${j}"]}"
      local VERSION_FINDER=""
      local BIN_FILE=""
      [[ -z "${VERSION_IDENTIFIER}" ]] && continue
      # this is a workaround to handle the new multi_grep
      if [[ "${VERSION_IDENTIFIER: 0:1}" == '"' ]]; then
        VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
        VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"
      fi
      if [[ ${RTOS} -eq 0 ]]; then
        BIN_FILE=$(file -b "${BIN}" || true)
        # as the FILE_ARR array also includes non binary stuff we have to check for relevant files now:
        if ! [[ "${BIN_FILE}" == *uImage* || "${BIN_FILE}" == *Kernel\ Image* || "${BIN_FILE}" == *ELF* ]] ; then
          continue 2
        fi

        if [[ "${BIN_FILE}" == *ELF* ]] ; then
          # print_output "[*] Testing $BIN with version identifier ${VERSION_IDENTIFIER}" "no_log"
          VERSION_FINDER=$(grep -o -a -E "${VERSION_IDENTIFIER}" "${STRINGS_OUTPUT}" | sort -u | head -1 || true)

          if [[ -n ${VERSION_FINDER} ]]; then
            if [[ "${#VERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#VERSION_IDENTIFIERS_ARR[@]}" ]]; then
              # we found the first identifier and now we need to check the other identifiers also
              print_output "[+] Found sub identifier ${ORANGE}${VERSION_IDENTIFIER}${GREEN} in binary ${ORANGE}${BIN}${GREEN}" "no_log"
              continue
            fi
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
            CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
            write_csv_log "${BIN}" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            check_for_s08_csv_log "${S08_CSV_LOG}"

            lMD5_CHECKSUM="$(md5sum "${BIN}" | awk '{print $1}')"
            lSHA256_CHECKSUM="$(sha256sum "${BIN}" | awk '{print $1}')"
            lSHA512_CHECKSUM="$(sha512sum "${BIN}" | awk '{print $1}')"
            lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
            lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")
            lBIN_ARCH=$(echo "${BIN_FILE}" | cut -d ',' -f2-3)
            lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
            lBIN_ARCH=${lBIN_ARCH#\ }

            lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
            lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
            lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

            ### new SBOM json testgenerator
            if command -v jo >/dev/null; then
              # add source file path information to our properties array:
              local lPROP_ARRAY_INIT_ARR=()
              lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
              lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
              lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
              lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

              build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

              # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
              # final array with all hash values
              build_sbom_json_hashes_arr "${BIN}"

              # create component entry - this allows adding entries very flexible:
              build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
            fi

            write_log "${lPACKAGING_SYSTEM};${BIN:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;${BIN_FILE};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
            # we test the next binary
            continue 2
          fi
        elif [[ "${BIN_FILE}" == *uImage* || "${BIN_FILE}" == *Kernel\ Image* ]] ; then
          VERSION_FINDER=$(grep -o -a -E "${VERSION_IDENTIFIER}" "${STRINGS_OUTPUT}" | sort -u | head -1 || true)

          if [[ -n ${VERSION_FINDER} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in kernel image ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
            CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
            write_csv_log "${BIN}" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            check_for_s08_csv_log "${S08_CSV_LOG}"

            lMD5_CHECKSUM="$(md5sum "${BIN}" | awk '{print $1}')"
            lSHA256_CHECKSUM="$(sha256sum "${BIN}" | awk '{print $1}')"
            lSHA512_CHECKSUM="$(sha512sum "${BIN}" | awk '{print $1}')"
            lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
            lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")
            lBIN_ARCH=$(echo "${BIN_FILE}" | cut -d ',' -f2-3)
            lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
            lBIN_ARCH=${lBIN_ARCH#\ }

            lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
            lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
            lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

            ### new SBOM json testgenerator
            if command -v jo >/dev/null; then
              # add source file path information to our properties array:
              local lPROP_ARRAY_INIT_ARR=()
              lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
              lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
              lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
              lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

              build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

              # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
              # final array with all hash values
              build_sbom_json_hashes_arr "${BIN}"

              # create component entry - this allows adding entries very flexible:
              build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
            fi

            write_log "${lPACKAGING_SYSTEM};${BIN:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;${BIN_FILE};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
            continue 2
          fi
        fi
      else
        # this is RTOS mode
        # echo "Testing $BIN - $VERSION_IDENTIFIER"
        VERSION_FINDER=$(grep -o -a -E "${VERSION_IDENTIFIER}" "${STRINGS_OUTPUT}" | sort -u | head -1 || true)

        if [[ -n ${VERSION_FINDER} ]]; then
          if [[ "${#VERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#VERSION_IDENTIFIERS_ARR[@]}" ]]; then
            # we found the first identifier and now we need to check the other identifiers also
            print_output "[+] Found sub identifier ${ORANGE}${VERSION_IDENTIFIER}${GREEN} in binary ${ORANGE}${BIN}${GREEN}" "no_log"
            continue
          fi
          print_ln "no_log"
          print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          CSV_RULE=$(get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}")
          write_csv_log "${BIN}" "${lAPP_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
          check_for_s08_csv_log "${S08_CSV_LOG}"

          lMD5_CHECKSUM="$(md5sum "${BIN}" | awk '{print $1}')"
          lSHA256_CHECKSUM="$(sha256sum "${BIN}" | awk '{print $1}')"
          lSHA512_CHECKSUM="$(sha512sum "${BIN}" | awk '{print $1}')"
          lCPE_IDENTIFIER=$(build_cpe_identifier "${CSV_RULE}")
          lPURL_IDENTIFIER=$(build_generic_purl "${CSV_RULE}")
          lBIN_ARCH=$(echo "${BIN_FILE}" | cut -d ',' -f2-3)
          lBIN_ARCH=${lBIN_ARCH//,\ /\ -\ }
          lBIN_ARCH=${lBIN_ARCH#\ }

          lAPP_MAINT=$(echo "${CSV_RULE}" | cut -d ':' -f2)
          lAPP_NAME=$(echo "${CSV_RULE}" | cut -d ':' -f3)
          lAPP_VERS=$(echo "${CSV_RULE}" | cut -d ':' -f4-5)

          ### new SBOM json testgenerator
          if command -v jo >/dev/null; then
            # add source file path information to our properties array:
            local lPROP_ARRAY_INIT_ARR=()
            lPROP_ARRAY_INIT_ARR+=( "source_path:${BIN}" )
            lPROP_ARRAY_INIT_ARR+=( "source_arch:${lBIN_ARCH}" )
            lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${VERSION_FINDER}" )
            lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${CSV_RULE}" )

            build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

            # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
            # final array with all hash values
            build_sbom_json_hashes_arr "${BIN}"

            # create component entry - this allows adding entries very flexible:
            build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
          fi

          write_log "${lPACKAGING_SYSTEM};${BIN:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${VERSION_FINDER:-NA};${CSV_RULE};${LIC};maintainer unknown;${BIN_FILE};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};DESC" "${S08_CSV_LOG}"
          # we test the next binary
          continue 2
        fi
      fi
      continue 2
    done
  done
}

recover_wait_pids() {
  local TEMP_PIDS=()
  local PID=""
  # check for really running PIDs and re-create the array
  for PID in "${WAIT_PIDS_S09[@]}"; do
    # print_output "[*] max pid protection: ${#WAIT_PIDS[@]}"
    if [[ -e /proc/"${PID}" ]]; then
      TEMP_PIDS+=( "${PID}" )
    fi
  done
  # print_output "[!] S09 - really running pids: ${#TEMP_PIDS[@]}"

  # recreate the array with the current running PIDS
  WAIT_PIDS_S09=()
  WAIT_PIDS_S09=("${TEMP_PIDS[@]}")
}

