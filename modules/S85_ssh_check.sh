#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Looks for ssh-related files and checks squid configuration.
#               Checks for the XZ backdoor documented as CVE-2024-3094

S85_ssh_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check SSH"
  pre_module_reporter "${FUNCNAME[0]}"

  export SSH_VUL_CNT=0
  export SQUID_VUL_CNT=0
  local lNEG_LOG=0

  search_ssh_files
  check_lzma_backdoor
  check_squid

  write_log ""
  write_log "[*] Statistics:${SSH_VUL_CNT}:${SQUID_VUL_CNT}"

  if [[ "${SQUID_VUL_CNT}" -gt 0 || "${SSH_VUL_CNT}" -gt 0 ]]; then
    lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

check_lzma_backdoor() {
  sub_module_title "Check for possible lzma backdoor - CVE-2024-3094"

  local lSSH_FILES_ARR=()
  local lSSH_FILE=""
  local lLZMA_SSHD_ARR=()
  local lLZMA_SSHD_ENTRY=""
  local lLZMA_FILES_ARR=()
  local lLZMA_FILE=""
  local lXZ_FILES_ARR=()
  local lXZ_FILE=""
  local lXZ_V_OUT=""
  local lOUTPUT="The xz release tarballs from version 5.6.0 in late February and version 5.6.1 on Mach the 9th contain malicious code."
  local lCHECK=0

  mapfile -t lSSH_FILES_ARR < <(find "${LOG_DIR}"/firmware -name "*ssh*" -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "ELF"' || true)
  for lSSH_FILE in "${lSSH_FILES_ARR[@]}"; do
    print_output "[*] Testing ${ORANGE}${lSSH_FILE/:*}${NC}:" "no_log"

    # usually we have something like liblzma.so.5, but sometimes we have also seen the exact version information in the output
    mapfile -t lLZMA_SSHD_ARR < <(ldd "${lSSH_FILE/:*}" | grep "liblzma" || true)

    for lLZMA_SSHD_ENTRY in "${lLZMA_SSHD_ARR[@]}"; do
      print_output "The xz release tarballs from version 5.6.0 in late February and version 5.6.1 on Mach the 9th contain malicious code."
      if [[ "${lLZMA_SSHD_ENTRY}" == *"5.6.0"* ]] || [[ "${lLZMA_SSHD_ENTRY}" == *"5.6.1"* ]]; then
        print_output "${lOUTPUT}"
        print_output "[+] Found ${ORANGE}${lLZMA_SSHD_ENTRY}${GREEN} with affected version in ${ORANGE}${lSSH_FILE/:*}${GREEN}."
        write_link "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094"
        ((SSH_VUL_CNT+=1))
        lCHECK=1
      else
        print_output "[*] Found ${ORANGE}${lLZMA_SSHD_ENTRY}${NC} in ${ORANGE}${lSSH_FILE/:*}${NC}. Further manual checks are required."
      fi
    done
  done

  # letz find the library directly in the system:
  mapfile -t lLZMA_FILES_ARR < <(find "${LOG_DIR}"/firmware -name "*liblzma.so.5*" -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "ELF"' || true)
  for lLZMA_FILE in "${lLZMA_FILES_ARR[@]}"; do
    print_output "[*] Testing ${ORANGE}${lLZMA_FILE/:*}${NC}:" "no_log"
    if [[ "${lLZMA_FILE/:*}" == *"5.6.0"* ]] || [[ "${lLZMA_FILE/:*}" == *"5.6.1"* ]]; then
      print_output "${lOUTPUT}"
      print_output "[+] Found ${ORANGE}${lLZMA_FILE/:*}${GREEN} with affected version."
      write_link "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094"
      ((SSH_VUL_CNT+=1))
      lCHECK=1
    fi
  done

  # check for the xz binary in the vulnerable version
  mapfile -t lXZ_FILES_ARR < <(find "${LOG_DIR}"/firmware -name "xz" -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "ELF"' || true)
  for lXZ_FILE in "${lXZ_FILES_ARR[@]}"; do
    print_output "[*] Testing ${ORANGE}${lXZ_FILE/:*}${NC}:" "no_log"
    lXZ_V_OUT=$(strings "${lXZ_FILE/:*}" | grep "5\.6\.[01]" || true)
    if [[ "${lXZ_V_OUT}" == *"5.6."* ]]; then
      print_output "${lOUTPUT}"
      print_output "[+] Found ${ORANGE}${lXZ_FILE/:*}${GREEN} with affected version."
      write_link "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094"
      strings "${lXZ_FILE}" | grep -q "5\.6\.[01]" | tee -a "${LOG_FILE}" || true
      ((SSH_VUL_CNT+=1))
      lCHECK=1
    fi
  done

  if [[ ${lCHECK} -eq 0 ]]; then print_output "[-] No lzma implant identified."; fi
}

search_ssh_files()
{
  sub_module_title "Search ssh files"

  local lSSH_FILES_ARR=()
  local lSSH_FILE=""
  local lSSHD_ISSUES_ARR=()
  local lS_ISSUE=""

  mapfile -t lSSH_FILES_ARR < <(config_find "${CONFIG_DIR}""/ssh_files.cfg")

  if [[ "${lSSH_FILES_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lSSH_FILES_ARR[@]}" -ne 0 ]] ; then
    print_output "[+] Found ""${#lSSH_FILES_ARR[@]}"" ssh configuration files:"
    for lSSH_FILE in "${lSSH_FILES_ARR[@]}" ; do
      if [[ -f "${lSSH_FILE}" ]] ; then
        print_output "$(indent "$(orange "$(print_path "${lSSH_FILE}")")")" "" "${lSSH_FILE}"
        if [[ -f "${EXT_DIR}"/sshdcc ]]; then
          local lPRINTER=0
          if [[ "$(basename "${lSSH_FILE}")" == "sshd_config"  ]]; then
            print_output "[*] Testing sshd configuration file with sshdcc"
            readarray lSSHD_ISSUES_ARR < <("${EXT_DIR}"/sshdcc -ns -nc -f "${lSSH_FILE}" || true)
            for lS_ISSUE in "${lSSHD_ISSUES_ARR[@]}"; do
              if [[ "${lS_ISSUE}" == *RESULTS* || "${lPRINTER}" -eq 1 ]]; then
                # print finding title as EMBA finding:
                if [[ "${lS_ISSUE}" =~ ^\([0-9+]\)\ \[[A-Z]+\]\  ]]; then
                  print_output "[+] ${lS_ISSUE}"
                  ((SSH_VUL_CNT+=1))
                # print everything else (except RESULTS and done) as usual output
                elif ! [[ "${lS_ISSUE}" == *RESULTS* || "${lS_ISSUE}" == *done* ]]; then
                  print_output "[*] ${lS_ISSUE}"
                  # with indent the output looks weird:
                  # print_output "$(indent "$(orange "${lS_ISSUE}")")"
                fi
                lPRINTER=1
              fi
            done
          elif [[ "$(basename "${lSSH_FILE}")" == *"authorized_key"*  ]]; then
            print_output "[+] Warning: Possible ${ORANGE}authorized_key${GREEN} backdoor detected: ${ORANGE}${lSSH_FILE}${NC}"
            ((SSH_VUL_CNT+=1))
          fi
        fi
      fi
    done
  else
    print_output "[-] No ssh configuration files found"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_squid
# Detailed tests possible, check if necessary
check_squid() {
  sub_module_title "Check squid"
  local lSQUID_FILE=""
  local lCHECK=0
  local lSQUID_E=""
  local lSQUID_PATHS_ARR=()

  while read -r lSQUID_FILE; do
    lSQUID_FILE="$(echo "${lSQUID_FILE}" | cut -d ';' -f2)"
    print_output "[+] Found possible squid executable: ""${ORANGE}$(print_path "${lSQUID_FILE/;*}")${NC}"
    ((SQUID_VUL_CNT+=1))
  done < <(grep "squid" "${P99_CSV_LOG}" | grep ";ELF" || true)
  [[ ${SQUID_VUL_CNT} -eq 0 ]] && print_output "[-] No possible squid executable found"

  local lSQUID_DAEMON_CONFIG_LOCS_ARR=("/ETC_PATHS" "/ETC_PATHS/squid" "/ETC_PATHS/squid3" "/usr/local/etc/squid" "/usr/local/squid/etc")
  mapfile -t lSQUID_PATHS_ARR < <(mod_path_array "${lSQUID_DAEMON_CONFIG_LOCS_ARR[@]}")
  if [[ "${lSQUID_PATHS_ARR[0]-}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#lSQUID_PATHS_ARR[@]}" -ne 0 ]] ; then
    for lSQUID_E in "${lSQUID_PATHS_ARR[@]}"; do
      if [[ -f "${lSQUID_E}""/squid.conf" ]] ; then
        lCHECK=1
        print_output "[+] Found squid config: ""${ORANGE}$(print_path "${lSQUID_E}")${NC}"
        ((SQUID_VUL_CNT+=1))
      elif [[ -f "${lSQUID_E}""/squid3.conf" ]] ; then
        lCHECK=1
        print_output "[+] Found squid config: ""${ORANGE}$(print_path "${lSQUID_E}")${NC}"
        ((SQUID_VUL_CNT+=1))
      fi
      if [[ ${lCHECK} -eq 1 ]] ; then
        print_output "[*] Check external access control list type:"
        print_output "$(indent "$(grep "^external_acl_type" "${lSQUID_E}")")"
        print_output "[*] Check access control list:"
        print_output "$(indent "$(grep "^acl" "${lSQUID_E}" | sed 's/ /!space!/g')")"
      fi
    done
  fi
  if [[ ${lCHECK} -eq 0 ]]; then print_output "[-] No squid configuration found."; fi
}
