#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner
#
# Description:  This module tests identified lighttpd configuration files for interesting areas.
#               It is based on details from the following sources:
#               https://wiki.alpinelinux.org/wiki/Lighttpd_Advanced_security
#               https://security-24-7.com/hardening-guide-for-lighttpd-1-4-26-on-redhat-5-5-64bit-edition/
#               https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL
#               The module results should be reviewed in details. There are probably a lot of cases
#               which we are currently not handling correct.


S36_lighttpd() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Lighttpd analysis"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local LIGHTTP_CFG_ARR=()
  local LIGHTTP_BIN_ARR=()
  local FILE=""

  readarray -t LIGHTTP_CFG_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*lighttp*conf*' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 || true)
  readarray -t LIGHTTP_BIN_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -iname 'lighttpd' -exec file {} \; 2>/dev/null | grep "ELF" | cut -d ':' -f1 | sort -u || true)

  if [[ ${#LIGHTTP_BIN_ARR[@]} -gt 0 ]] ; then
    lighttpd_binary_analysis "${LIGHTTP_BIN_ARR[@]}"
  fi

  if [[ ${#LIGHTTP_CFG_ARR[@]} -gt 0 ]] ; then
    for FILE in "${LIGHTTP_CFG_ARR[@]}" ; do
      lighttpd_config_analysis "${FILE}" "${LIGHT_VERSIONS[@]}"
      write_csv_log "Lighttpd web server configuration file" "$(basename "${FILE}")" "${FILE}"
      local NEG_LOG=1
    done
  else
    print_output "[-] No Lighttpd related configuration files found"
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

lighttpd_binary_analysis() {
  sub_module_title "Lighttpd binary analysis"
  local LIGHTTP_BIN_ARR=("${@}")
  export LIGHT_VERSIONS=()

  if [[ -f "${CSV_DIR}/s09_firmware_base_version_check.csv" ]] && grep -q "lighttpd" "${CSV_DIR}"/s09_firmware_base_version_check.csv; then
    # if we already have results from s09 we just use them
    mapfile -t LIGHT_VERSIONS < <(grep "lighttpd" "${CSV_DIR}"/s09_firmware_base_version_check.csv | cut -d\; -f4 | sort -u || true)
  else
    # most of the time we run through the lighttpd version identifiers and check them against the lighttpd binaries
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

      CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"
      LIC="$(safe_echo "${VERSION_LINE}" | cut -d\; -f3)"
      VERSION_IDENTIFIER="$(safe_echo "${VERSION_LINE}" | cut -d\; -f4)"
      VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
      VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"

      for BIN in "${LIGHTTP_BIN_ARR[@]}" ; do
        VERSION_FINDER=$(strings "${BIN}" | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2> /dev/null || true)
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
          LIGHT_VERSIONS+=( "${CSV_RULE}" )
          continue
        fi
      done
    done < <(grep "^lighttpd" "${CONFIG_DIR}"/bin_version_strings.cfg)
  fi
  eval "LIGHT_VERSIONS=($(for i in "${LIGHT_VERSIONS[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

  if [[ ${#LIGHT_VERSIONS[@]} -gt 0 ]] ; then
    prepare_cve_search_module
    print_ln
    # lets do a quick vulnerability check on our lighttpd version
    if ! [[ -d "${LOG_PATH_MODULE}"/cve_sum ]]; then
      mkdir "${LOG_PATH_MODULE}"/cve_sum
    fi
    for LIGHT_VER in "${LIGHT_VERSIONS[@]}"; do
      # cve_db_lookup_version writes the logs to "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt
      export F20_DEEP=1
      export S36_LOG="${CSV_DIR}"/s36_lighttpd.csv
      cve_db_lookup_version "${LIGHT_VER}"
    done
  fi

  # check for binary protections on lighttpd binaries
  print_ln
  print_output "[*] Testing lighttpd binaries for binary protection mechanisms:\\n"
  for BIN in "${LIGHTTP_BIN_ARR[@]}" ; do
    print_output "$("${EXT_DIR}"/checksec --file="${BIN}")"
  done

  print_ln
  print_output "[*] Testing lighttpd binaries for deprecated function calls:\\n"
  VULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
  IFS=" " read -r -a VULNERABLE_FUNCTIONS <<<"$( echo -e "${VULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"
  for BIN in "${LIGHTTP_BIN_ARR[@]}" ; do
    if ( file "${BIN}" | grep -q "x86-64" ) ; then
      function_check_x86_64 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "Intel 80386" ) ; then
      function_check_x86 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "32-bit.*ARM" ) ; then
      function_check_ARM32 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "64-bit.*ARM" ) ; then
      function_check_ARM64 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "MIPS" ) ; then
      function_check_MIPS "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "PowerPC" ) ; then
      function_check_PPC32 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "Altera Nios II" ) ; then
      function_check_NIOS2 "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    elif ( file "${BIN}" | grep -q "QUALCOMM DSP6" ) ; then
      radare_function_check_hexagon "${BIN}" "${VULNERABLE_FUNCTIONS[@]}"
    fi
  done
}

lighttpd_config_analysis() {
  local LIGHTTPD_CONFIG="${1:-}"
  shift
  local LIGHT_VERSIONS=("${@}")
  local SSL_ENABLED=0

  if ! [[ -f "${LIGHTTPD_CONFIG}" ]]; then
    print_output "[-] No configuration file available"
    return
  fi
  sub_module_title "Lighttpd configuration analysis for $(basename "${LIGHTTPD_CONFIG}")"

  print_output "[*] Testing web server configuration file ${ORANGE}${LIGHTTPD_CONFIG}${NC}\\n"
  print_output "[*] Testing web server user"
  if grep "user=root" "${LIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server running as root user:${NC}"
    print_output "$(indent "$(orange "$(grep "user=root" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server.username.*root" "${LIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server running as root user:${NC}"
    print_output "$(indent "$(orange "$(grep -E "server.username.*root" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing web server root directory location"
  if grep -E "server_root\|server\.document-root" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
    print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following root directory"
    print_output "$(indent "$(orange "$(grep -E "server_root\|server\.document-root" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing for additional web server binaries"
  if grep -E "bin-path" "${LIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following additional binaries"
    print_output "$(indent "$(orange "$(grep -E "bin-path" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing for directory listing configuration"
  if grep -E "dir-listing.activate.*enable" "${LIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Configuration issue detected: ${ORANGE}Web server allows directory listings${NC}"
    print_output "$(indent "$(orange "$(grep -E "dir-listing.activate.*enable" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi
  if grep -E "server.dir-listing.*enable" "${LIGHTTPD_CONFIG}" | grep -E -v -q "^([[:space:]])?#"; then
    print_output "[+] Configuration issue detected: ${ORANGE}Web server allows directory listings${NC}"
    print_output "$(indent "$(orange "$(grep -E "server.dir-listing.*enable" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#")")")"
  fi

  print_output "[*] Testing web server ssl.engine usage"
  if ! grep -E "ssl.engine.*enable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
    print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not using ssl engine${NC}"
  else
    SSL_ENABLED=1
  fi

  if [[ "${SSL_ENABLED}" -eq 1 ]]; then
    print_output "[*] Testing web server pemfile location"
    if grep -E "ssl.pemfile" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following pem file"
      print_output "$(indent "$(orange "$(grep -E "ssl.pemfile" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      mapfile -t PEM_FILES < <(grep -E "ssl.pemfile" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" | cut -d= -f2 | tr -d '"' || true)
      for PEM_FILE in "${PEM_FILES[@]}"; do
        PEM_FILE=$(echo "${PEM_FILE}" | tr -d "[:space:]")
        mapfile -t REAL_PEMS < <(find "${FIRMWARE_PATH}" -wholename "*${PEM_FILE}" || true)
        for REAL_PEM in "${REAL_PEMS[@]}"; do
          print_output "[*] ${ORANGE}Configuration note:${NC} Web server pem file found: ${ORANGE}${REAL_PEM}${NC}"
          print_output "[*] $(find "${REAL_PEM}" -ls)"
          # Todo: check for permissions 400 on pem file
          if [[ "$(stat -c "%a" "${REAL_PEM}")" -ne 400 ]]; then
            print_output "[+] Possible configuration issue detected: ${ORANGE}Privileges of web server pem file not correct${NC}"
          fi
        done
      done
    fi
    print_output "[*] Testing web server private key file"
    if grep -E "ssl.privkey" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      print_output "[*] ${ORANGE}Configuration note:${NC} Web server using the following private key file"
      print_output "$(indent "$(orange "$(grep -E "ssl.privkey" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
    fi

    print_output "[*] Testing web server BEAST mitigation"
    if grep -E "ssl.disable-client-renegotiation.*disable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the BEAST attack (CVE-2009-3555) via ssl.disable-client-renegotiation.${NC}"
      print_output "$(indent "$(orange "$(grep -E "ssl.disable-client-renegotiation.*disable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#" || true)")")"
    fi
    if grep -E "ssl.honor-cipher-order.*disable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
      # defaults to enable -> we only need to check if it is disabled
      print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the BEAST attack (CVE-2009-3555) via ssl.honor-cipher-order.${NC}"
      print_output "$(indent "$(orange "$(grep -E "ssl.honor-cipher-order.*disable" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
    fi

    print_output "[*] Testing web server for SSL ciphers supported"
    print_output "$(indent "$(orange "$(grep "ssl.cipher-list\|ssl.openssl.ssl-conf-cmd" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"

    if grep "ssl.cipher-list\|ssl.openssl.ssl-conf-cmd" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then

      print_output "[*] Testing web server POODLE attack mitigation"
      if grep -E "ssl.cipher-list.*:SSLv3" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        if [[ ${#LIGHT_VERSIONS[@]} -eq 0 ]] ; then
          # if we have no version detected we show this issue:
          print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the POODLE attack (CVE-2014-3566) via disabled SSLv3 ciphers.${NC}"
          print_output "[*] Note that SSLv3 is automatically disabled on lighttpd since version ${ORANGE}1.4.36${NC}"
          print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
        fi

        for LIGHT_VER in "${LIGHT_VERSIONS[@]}"; do
          LIGHT_VER="${LIGHT_VER/*:/}"
          if [[ "$(version "${LIGHT_VER}")" -le "$(version "1.4.35")" ]]; then
            print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not mitigating the POODLE attack (CVE-2014-3566) via disabled SSLv3 ciphers.${NC}"
            print_output "[*] Note that SSLv3 is automatically disabled on lighttpd since version ${ORANGE}1.4.36${NC}"
            print_output "[*] EMBA detected lighttpd version ${ORANGE}${LIGHT_VER}${NC}"
            print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
          fi
        done
      fi

      print_output "[*] Testing web server enabled SSLv2"
      if grep -E "ssl.use-sslv2.*enable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enables SSLv2 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.use-sslv2" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server enabled SSLv3"
      if grep -E "ssl.use-sslv3.*enable" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enables SSLv3 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep -E "ssl.use-sslv3" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server FREAK attack mitigation"
      if grep -E "ssl.cipher-list.*:EXPORT" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling EXPORT ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server NULL ciphers"
      if grep -E "ssl.cipher-list.*:[ae]NULL" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling NULL ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server RC4 ciphers"
      if grep -E  "ssl.cipher-list.*:RC4" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling RC4 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server DES ciphers"
      if grep -E "ssl.cipher-list.*:DES" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling DES ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -q -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server 3DES ciphers"
      if grep -E "ssl.cipher-list.*:3DES" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling 3DES ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u | grep -q -E -v "^([[:space:]])?#" || true)")")"
      fi

      print_output "[*] Testing web server MD5 ciphers"
      if grep -E "ssl.cipher-list.*:MD5" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server not disabling MD5 ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u  | grep -q -E -v "^([[:space:]])?#" || true)")")"
      fi

      # lighttpd implicitly applies ssl.cipher-list = "HIGH" (since lighttpd 1.4.54) if ssl.cipher-list is not explicitly set in lighttpd.conf.
      print_output "[*] Testing web server LOW ciphers"
      if grep -E "ssl.cipher-list.*:LOW" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enabling LOW ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u  | grep -q -E -v "^([[:space:]])?#" || true)")")"
      fi
      print_output "[*] Testing web server MEDIUM ciphers"
      if grep -E "ssl.cipher-list.*:MEDIUM" "${LIGHTTPD_CONFIG}" | grep -q -E -v "^([[:space:]])?#"; then
        print_output "[+] Possible configuration issue detected: ${ORANGE}Web server enabling MEDIUM ciphers.${NC}"
        print_output "$(indent "$(orange "$(grep "ssl.cipher-list" "${LIGHTTPD_CONFIG}" | sort -u  | grep -q -E -v "^([[:space:]])?#" || true)")")"
      fi
    fi
  fi
}
