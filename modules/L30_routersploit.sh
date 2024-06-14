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

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L30_routersploit() {

  export MODULE_END=0

  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Routersploit tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ ${IN_DOCKER} -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi
    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}"; then
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing routersploit checks"
          module_end_log "${FUNCNAME[0]}" "${MODULE_END}"
          return
        fi
      fi
      check_live_routersploit
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    module_end_log "${FUNCNAME[0]}" "${MODULE_END}"
  fi
}

check_live_routersploit() {
  sub_module_title "Routersploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"

  if [[ -f /tmp/routersploit.log ]]; then
    rm /tmp/routersploit.log
  fi

  timeout --preserve-status --signal SIGINT 300 "${EXT_DIR}"/routersploit/rsf.py "${IP_ADDRESS_}" 2>&1 | tee -a "${LOG_PATH_MODULE}"/routersploit-"${IP_ADDRESS_}".txt || true

  if [[ -f /tmp/routersploit.log ]]; then
    mv /tmp/routersploit.log "${LOG_PATH_MODULE}"/routersploit-detail-"${IP_ADDRESS_}".txt
  fi

  if grep -q "Target is vulnerable" "${LOG_PATH_MODULE}"/routersploit-"${IP_ADDRESS_}".txt; then
    print_output "[+] Found the following vulnerabilities:" "" "${LOG_PATH_MODULE}/routersploit-${IP_ADDRESS_}.txt"
    grep -B 1 "Target is vulnerable" "${LOG_PATH_MODULE}"/routersploit-"${IP_ADDRESS_}".txt | tee -a "${LOG_FILE}"
    print_ln
    MODULE_END=1
  fi
  if grep -q "Target seems to be vulnerable" "${LOG_PATH_MODULE}"/routersploit-"${IP_ADDRESS_}".txt; then
    print_ln
    print_output "[+] Found the following possible vulnerabilities:" "" "${LOG_PATH_MODULE}/routersploit-${IP_ADDRESS_}.txt"
    grep -B 1 "Target seems to be vulnerable" "${LOG_PATH_MODULE}"/routersploit-"${IP_ADDRESS_}".txt | tee -a "${LOG_FILE}"
    print_ln
    MODULE_END=1
  fi

  color_routersploit_log "${LOG_PATH_MODULE}/routersploit-${IP_ADDRESS_}.txt"

  print_output "[*] Routersploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC} finished"
}

color_routersploit_log() {
  local RSPLOIT_LOG_FILE_="${1:-}"
  if ! [[ -f "${RSPLOIT_LOG_FILE_:-}" ]]; then
    return
  fi

  sed -i -r "s/Target is vulnerable/\x1b[32m&\x1b[0m/" "${RSPLOIT_LOG_FILE_}"
  sed -i -r "s/Target seems to be vulnerable/\x1b[32m&\x1b[0m/" "${RSPLOIT_LOG_FILE_}"
}
