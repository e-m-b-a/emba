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
#
# Description:  This module tests identified lighttpd configuration files for interesting areas.
#               It is based on details from the following sources:
#               https://wiki.alpinelinux.org/wiki/Lighttpd_Advanced_security
#               https://security-24-7.com/hardening-guide-for-lighttpd-1-4-26-on-redhat-5-5-64bit-edition/
#               https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL
#               https://redmine.lighttpd.net/projects/lighttpd/repository/14/revisions/master/entry/doc/config/lighttpd.conf
#               The module results should be reviewed in details. There are probably a lot of cases
#               which we are currently not handling correct. Please report such issues!


S36_lighttpd() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Lighttpd web server analysis"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lLIGHTTP_CFG_ARR=()
  local lLIGHTTP_BIN_ARR=()
  local lCFG_DATA=""
  local lCFG_FILE=""
  export LIGHT_VERSIONS_ARR=()

  readarray -t lLIGHTTP_CFG_ARR < <( grep ".*lighttp.*conf.*" "${P99_CSV_LOG}" | sort -u || true)
  readarray -t lLIGHTTP_BIN_ARR < <( grep "lighttpd.*ELF" "${P99_CSV_LOG}"| sort -u || true)

  if [[ ${#lLIGHTTP_BIN_ARR[@]} -gt 0 ]] ; then
    lighttpd_binary_analysis "${lLIGHTTP_BIN_ARR[@]}"
    # -> populates LIGHT_VERSIONS_ARR array which is used for some config analysis
    local lNEG_LOG=1
  else
    print_output "[-] No Lighttpd binary files found"
  fi

  if [[ ${#lLIGHTTP_CFG_ARR[@]} -gt 0 ]] ; then
    for lCFG_DATA in "${lLIGHTTP_CFG_ARR[@]}" ; do
      lCFG_FILE=$(echo "${lCFG_DATA}" | cut -d ';' -f2 || true)
      lighttpd_config_analysis "${lCFG_FILE}" "${LIGHT_VERSIONS_ARR[@]}"
      write_csv_log "Lighttpd web server configuration file" "$(basename "${lCFG_FILE}")" "${lCFG_FILE}"
      local lNEG_LOG=1
    done
  else
    print_output "[-] No Lighttpd related configuration files found"
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

lighttpd_binary_analysis() {
  sub_module_title "Lighttpd binary analysis"
  local lLIGHTTP_BIN_ARR=("${@}")
  local lLIGHT_VER=""
  local lVERSION_IDENTIFIER=""
  local lVULNERABLE_FUNCTIONS_VAR=""
  local lVULNERABLE_FUNCTIONS_ARR=()
  local lLIGHT_BIN=""
  local lLIGHT_SBOMs_ARR=()

  export PACKAGING_SYSTEM="static_lighttpd_analysis"

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    mapfile -t lLIGHT_SBOMs_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 ! -name "*unhandled_file*" -name "*lighttpd*.json")
  fi

  # Todo: backup mode - lets remove this in the future and replace it with
  # a module_wait for S09
  if [[ "${#lLIGHT_SBOMs_ARR[@]}" -eq 0 ]]; then
    local lBINARY_DATA=""
    for lBINARY_DATA in "${lLIGHTTP_BIN_ARR[@]}"; do
      lLIGHT_BIN="$(echo "${lBINARY_DATA}" | cut -d ';' -f2)"
      if [[ "${lLIGHT_BIN}" == *".raw" ]]; then
        # skip binwalk raw files
        continue
      fi

      local lVERSION_JSON_CFG="${CONFIG_DIR}"/bin_version_identifiers/lighttpd.json
      local lVERSION_IDENTIFIER_ARR=()
      local lVERSION_IDENTIFIER=""
      if [[ -z "${lBINARY_DATA}" ]]; then
        # we have not found our binary as ELF
        continue
      fi

      # extract the grep commands for our version identification
      mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
      for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
        lVERSION_IDENTIFIED=$(strings "${lLIGHT_BIN}" | grep -a -E "${lVERSION_IDENTIFIER}" | sort -u | head -1 || true)
        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          export TYPE="static"
          mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

          print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}$(print_path "${lLIGHT_BIN}")${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${TYPE}${GREEN})."

          local lRULE_IDENTIFIER=""
          local lLICENSES_ARR=()
          local lPRODUCT_NAME_ARR=()
          local lVENDOR_NAME_ARR=()
          local lCSV_REGEX_ARR=()

          # lets build the data we need for version_parsing_logging
          lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
          # shellcheck disable=SC2034
          mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
          # shellcheck disable=SC2034
          mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
          # shellcheck disable=SC2034
          mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

          export CONFIDENCE_LEVEL=3

          if version_parsing_logging "${S09_CSV_LOG}" "S36_lighttpd" "${lVERSION_IDENTIFIED}" "${lBINARY_DATA}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
            # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
            continue 2
          fi
        fi
      done
    done
  fi

  if [[ -d "${SBOM_LOG_PATH}" ]]; then
    mapfile -t lLIGHT_SBOMs_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 ! -name "*unhandled_file*" -name "*lighttpd*.json")
  fi
  if [[ "${#lLIGHT_SBOMs_ARR[@]}" -gt 0 ]]; then
    # lets do a quick vulnerability check on our lighttpd version
    lLIGHT_VERSIONS_DONE_ARR=()
    for lLIGHT_SBOM_JSON in "${lLIGHT_SBOMs_ARR[@]}"; do
      print_output "[*] Testing lighttpd json: ${lLIGHT_SBOM_JSON}" "no_log"
      local lPRODUCT_VERSION=""
      local lPRODUCT_NAME=""
      local lVENDOR_ARR=()
      local lPRODUCT_ARR=()
      lPRODUCT_VERSION=$(jq --raw-output '.version' "${lLIGHT_SBOM_JSON}" || print_error "[-] S36 - lighttpd version extraction failed for ${lLIGHT_SBOM_JSON}")
      print_output "[*] Identified version for ${lLIGHT_SBOM_JSON} - ${lPRODUCT_VERSION}" "no_log"
      if [[ "${lLIGHT_VERSIONS_DONE_ARR[*]}" == *"${lPRODUCT_VERSION}"* ]]; then
        print_output "[*] Found duplicate for ${lLIGHT_SBOM_JSON} - ${lPRODUCT_VERSION}" "no_log"
        continue
      fi
      lLIGHT_VERSIONS_DONE_ARR+=("${lPRODUCT_VERSION}")
      print_output "[*] Adjusted done array for ${lLIGHT_SBOM_JSON} - ${lPRODUCT_VERSION} - ${lLIGHT_VERSIONS_DONE_ARR[*]}" "no_log"
      local lORIG_SOURCE="${PACKAGING_SYSTEM}"
      local lBOM_REF=""
      lBOM_REF=$(jq -r '."bom-ref"' "${lLIGHT_SBOM_JSON}" || true)
      # print_output "[*] CVE analysis for ${lBOM_REF} - ${lLIGHT_VENDOR} - ${lLIGHT_PRODUCT} - ${lPRODUCT_VERSION} - ${lORIG_SOURCE}" "no_log"

      mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' "${lLIGHT_SBOM_JSON}")
      if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
        lVENDOR_ARR+=("NOTDEFINED")
      fi
      # shellcheck disable=SC2034
      mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' "${lLIGHT_SBOM_JSON}")

      # shellcheck disable=SC2034
      lPRODUCT_NAME=$(jq --raw-output '.name' "${lLIGHT_SBOM_JSON}")

      cve_bin_tool_threader "${lBOM_REF}" "${lPRODUCT_VERSION}" "${lORIG_SOURCE}" lVENDOR_ARR lPRODUCT_ARR
      LIGHT_VERSIONS_ARR+=("${lPRODUCT_VERSION}")
    done
  fi

  # check for binary protections on lighttpd binaries
  print_ln
  print_output "[*] Testing lighttpd binaries for binary protection mechanisms:\\n"
  for lLIGHT_BIN in "${lLIGHTTP_BIN_ARR[@]}" ; do
    lLIGHT_BIN="$(echo "${lLIGHT_BIN}" | cut -d ';' -f2)"
    print_output "$("${EXT_DIR}"/checksec --file="${lLIGHT_BIN}" || true)"
  done

  print_ln
  print_output "[*] Testing lighttpd binaries for deprecated function calls:\\n"
  lVULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
  # nosemgrep
  local IFS=" "
  IFS=" " read -r -a lVULNERABLE_FUNCTIONS_ARR <<<"$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"
  for lBINARY_DATA in "${lLIGHTTP_BIN_ARR[@]}"; do
    lLIGHT_BIN="$(echo "${lBINARY_DATA}" | cut -d ';' -f2)"
    if [[ "${lLIGHT_BIN}" == *".raw" ]]; then
      # skip binwalk raw files
      continue
    fi
    if ( file "${lLIGHT_BIN}" | grep -q "x86-64" ) ; then
      function_check_x86_64 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "Intel 80386" ) ; then
      function_check_x86 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "32-bit.*ARM" ) ; then
      function_check_ARM32 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "64-bit.*ARM" ) ; then
      function_check_ARM64 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "MIPS" ) ; then
      function_check_MIPS "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "PowerPC" ) ; then
      function_check_PPC32 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "Altera Nios II" ) ; then
      function_check_NIOS2 "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    elif ( file "${lLIGHT_BIN}" | grep -q "QUALCOMM DSP6" ) ; then
      radare_function_check_hexagon "${lLIGHT_BIN}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
    fi
  done
}

lighttpd_config_analysis() {
  local lLIGHTTPD_CONFIG="${1:-}"
  shift
  local lLIGHT_VERSIONS_ARR=("${@}")
  local lLIGHT_VER=""
  local lSSL_ENABLED=0
  local lPEM_FILES_ARR=()
  local lPEM_FILE=""
  local lREAL_PEMS_ARR=()
  local lREAL_PEM=""

  if ! [[ -f "${lLIGHTTPD_CONFIG}" ]]; then
    print_output "[-] No configuration file available"
    return
  fi
  sub_module_title "Lighttpd configuration analysis for $(basename "${lLIGHTTPD_CONFIG}")"

  print_output "[*] Testing web server configuration file ${ORANGE}${lLIGHTTPD_CONFIG}${NC}\\n"
  print_output "[*] Testing web server user"
  if grep "user=root" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server running as root user:${NC}"
    print_output "$(indent "$(orange "$(grep "user=root" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server.username.*root" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server running as root user:${NC}"
    print_output "$(indent "$(orange "$(grep -E "server.username.*root" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server.groupname.*root" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server running as root group:${NC}"
    print_output "$(indent "$(orange "$(grep -E "server.groupname.*root" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing web server root directory location"
  if grep -E "server_root\|server\.document-root" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
    print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following root directory"
    print_output "$(indent "$(orange "$(grep -E "server_root\|server\.document-root" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server_root\|server\.document-root.*\"\/\"" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
    print_output "[*] ${ORANGE}Possible configuration issue detected:${NC} Web server exposes filesystem"
    print_output "$(indent "$(orange "$(grep -E "server_root\|server\.document-root" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing for additional web server binaries"
  if grep -E "bin-path" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following additional binaries"
    print_output "$(indent "$(orange "$(grep -E "bin-path" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing for directory listing configuration"
  if grep -E "dir-listing.activate.*enable" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Configuration issue detected: ${ORANGE}Web server allows directory listings${NC}"
    print_output "$(indent "$(orange "$(grep -E "dir-listing.activate.*enable" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server.dir-listing.*enable" "${lLIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Configuration issue detected: ${ORANGE}Web server allows directory listings${NC}"
    print_output "$(indent "$(orange "$(grep -E "server.dir-listing.*enable" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing web server ssl.engine usage"
  if (! grep -E "ssl.engine.*enable" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#") && (! grep -E "server.modules.*mod_openssl" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"); then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not using ssl engine${NC}"
  else
    lSSL_ENABLED=1
  fi

  if [[ "${lSSL_ENABLED}" -eq 1 ]]; then
    print_output "[*] Testing web server pemfile location"
    if grep -E "ssl.pemfile" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following pem file"
      print_output "$(indent "$(orange "$(grep -E "ssl.pemfile" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      mapfile -t lPEM_FILES_ARR < <(grep -E "ssl.pemfile" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" | cut -d= -f2 | tr -d '"' || true)
      for lPEM_FILE in "${lPEM_FILES_ARR[@]}"; do
        lPEM_FILE=$(echo "${lPEM_FILE}" | tr -d "[:space:]")
        mapfile -t lREAL_PEMS_ARR < <(find "${FIRMWARE_PATH}" -wholename "*${lPEM_FILE}" || true)
        for lREAL_PEM in "${lREAL_PEMS_ARR[@]}"; do
          print_output "[*] ${ORANGE}Configuration note:${NC} Web server pem file found: ${ORANGE}${lREAL_PEM}${NC}"
          print_output "[*] $(find "${lREAL_PEM}" -ls)"
          # Todo: check for permissions 400 on pem file
          if [[ "$(stat -c "%a" "${lREAL_PEM}")" -ne 400 ]]; then
            print_output "[+] Possible configuration issue detected: ${ORANGE}Privileges of web server pem file not correct${NC}"
          fi
        done
      done
    fi
    print_output "[*] Testing web server private key file"
    if grep -E "ssl.privkey" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following private key file"
      print_output "$(indent "$(orange "$(grep -E "ssl.privkey" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
    fi

    print_output "[*] Testing web server BEAST mitigation"
    if grep -E "ssl.disable-client-renegotiation.*disable" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      if [[ ${#lLIGHT_VERSIONS_ARR[@]} -gt 0 ]] ; then
        for lLIGHT_VER in "${lLIGHT_VERSIONS_ARR[@]}"; do
          if [[ "$(version "${lLIGHT_VER}")" -lt "$(version "1.4.68")" ]]; then
            print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the BEAST attack (CVE-2009-3555) via ssl.disable-client-renegotiation.${NC}"
            print_output "$(indent "$(orange "$(grep -E "ssl.disable-client-renegotiation.*disable" "${lLIGHTTPD_CONFIG}" | grep -E -v "^([[:space:]])?#" || true)")")"
          fi
        done
      else
        # just in case we have not found a version number we show the warning.
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the BEAST attack (CVE-2009-3555) via ssl.disable-client-renegotiation.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.disable-client-renegotiation.*disable" "${lLIGHTTPD_CONFIG}" | grep -E -v "^([[:space:]])?#" || true)")")"
      fi
    fi

    print_output "[*] Testing web server for SSL ciphers supported"
    print_output "$(indent "$(orange "$(grep "ssl.cipher-list\|ssl.openssl.ssl-conf-cmd" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"

    if grep "ssl.cipher-list\|ssl.openssl.ssl-conf-cmd" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then

      print_output "[*] Testing web server POODLE attack mitigation"
      if grep -E "ssl.cipher-list.*:SSLv3" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        if [[ ${#lLIGHT_VERSIONS_ARR[@]} -eq 0 ]] ; then
          # if we have no version detected we show this issue:
          print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the POODLE attack (CVE-2014-3566) via disabled SSLv3 ciphers.${NC}"
          print_output "[*] Note that SSLv3 is automatically disabled on lighttpd since version ${ORANGE}1.4.36${NC}"
          print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
        fi

        for lLIGHT_VER in "${lLIGHT_VERSIONS_ARR[@]}"; do
          if [[ "$(version "${lLIGHT_VER}")" -le "$(version "1.4.35")" ]]; then
            print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the POODLE attack (CVE-2014-3566) via disabled SSLv3 ciphers.${NC}"
            print_output "[*] Note that SSLv3 is automatically disabled on lighttpd since version ${ORANGE}1.4.36${NC}"
            print_output "[*] EMBA detected lighttpd version ${ORANGE}${lLIGHT_VER}${NC}"
            print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
          fi
        done
      fi

      print_output "[*] Testing web server enabled minimal TLS version"
      if (! grep -E "ssl.openssl.*MinProtocol.*TLSv1.[23]" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"); then
        print_output "[+] Possible configuration issue detected: ${ORANGE}No web server minimal TLS version enforced.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.use-sslv2" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server enabled SSLv2"
      if grep -E "ssl.use-sslv2.*enable" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enables SSLv2 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.use-sslv2" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server enabled SSLv3"
      if grep -E "ssl.use-sslv3.*enable" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enables SSLv3 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.use-sslv3" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server FREAK attack mitigation"
      if grep -E "ssl.cipher-list.*:EXPORT" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling EXPORT ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server NULL ciphers"
      if grep -E "ssl.cipher-list.*:[ae]NULL" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling NULL ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server RC4 ciphers"
      if grep -E  "ssl.cipher-list.*:RC4" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling RC4 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server DES ciphers"
      if grep -E "ssl.cipher-list.*:DES" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling DES ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server 3DES ciphers"
      if grep -E "ssl.cipher-list.*:3DES" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling 3DES ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server MD5 ciphers"
      if grep -E "ssl.cipher-list.*:MD5" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling MD5 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u  | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      # lighttpd implicitly applies ssl.cipher-list = "HIGH" (since lighttpd 1.4.54) if ssl.cipher-list is not explicitly set in lighttpd.conf.
      print_output "[*] Testing web server LOW ciphers"
      if grep -E "ssl.cipher-list.*:LOW" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enabling LOW ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u  | grep -E -v "^([[:space:]])?#" || true)")")"
      fi
      print_output "[*] Testing web server MEDIUM ciphers"
      if grep -E "ssl.cipher-list.*:MEDIUM" "${lLIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enabling MEDIUM ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${lLIGHTTPD_CONFIG}" | sort -u  | grep -E -v "^([[:space:]])?#" || true)")")"
      fi
    fi
  fi
}
