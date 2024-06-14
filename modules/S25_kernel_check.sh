#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Determines kernel version and description and checks for kernel configuration.
#               It uses linux-exploit-suggester to check for possible kernel exploits and analyzes kernel modules to find which
#               license they have and if they are stripped.
#               It also looks for the modprobe.d directory and lists its content.

S25_kernel_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Identify and analyze kernel version"
  pre_module_reporter "${FUNCNAME[0]}"

  export KERNEL_VERSION=()
  export KERNEL_DESC=()
  export KERNEL_MODULES=()
  local FOUND=0
  export KMOD_BAD=0

  # This module waits for S24_kernel_bin_identifier
  # check emba.log for S24_kernel_bin_identifier starting
  module_wait "S24_kernel_bin_identifier"

  # This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_kernel

  populate_karrays

  if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
    write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln"
    print_output "Kernel version:"
    for LINE in "${KERNEL_VERSION[@]}" ; do
      print_output "$(indent "${ORANGE}${LINE}${NC}")"
      FOUND=1
    done
    if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
      print_ln
      print_output "Kernel details:"
      for LINE in "${KERNEL_DESC[@]}" ; do
        print_output "$(indent "${LINE}")"
        FOUND=1
      done
    fi
    get_kernel_vulns
    check_modprobe
  else
    print_output "[-] No kernel version identified"
  fi

  if [[ "${KERNEL}" -eq 1 ]] && [[ -f "${KERNEL_CONFIG}" ]]; then
    # we use check_kconfig from s24 module
    check_kconfig "${KERNEL_CONFIG}"
    FOUND=1
  else
    print_output "[-] No check for kernel configuration"
  fi

  if [[ ${#KERNEL_MODULES[@]} -ne 0 ]] ; then
    analyze_kernel_module
    FOUND=1
  fi

  if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
    for K_VERS in "${KERNEL_VERSION[@]}" ; do
      write_log "[*] Statistics:${K_VERS}"
    done
  fi
  write_log "[*] Statistics1:${#KERNEL_MODULES[@]}:${KMOD_BAD}"

  module_end_log "${FUNCNAME[0]}" "${FOUND}"
}

populate_karrays() {
  local KERNEL_VERSION_=()
  local K_MODULE=""
  local VER=""
  local K_VER=""
  local V=""

  mapfile -t KERNEL_MODULES < <( find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev \( -iname "*.ko" -o -iname "*.o" \) -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  for K_MODULE in "${KERNEL_MODULES[@]}"; do
    if [[ "${K_MODULE}" =~ .*\.o ]]; then
      KERNEL_VERSION+=( "$(strings "${K_MODULE}" 2>/dev/null | grep "kernel_version=" | cut -d= -f2 || true)" )
      continue
    fi
    KERNEL_VERSION+=( "$(modinfo "${K_MODULE}" 2>/dev/null | grep -E "vermagic" | cut -d: -f2 | sed 's/^ *//g' || true)" )
    KERNEL_DESC+=( "$(modinfo "${K_MODULE}" 2>/dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g' | tr -c '[:alnum:]\n\r' '_' | sort -u || true)" )
  done

  for VER in "${KERNEL_VERSION[@]}" ; do
    demess_kv_version "${VER}"

    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    for V in "${KV_C_ARR[@]}" ; do
      if [[ -z "${V:-}" ]]; then
        # remove empty entries:
        continue
      fi
      if ! [[ "${V}" =~ .*[0-9]\.[0-9].* ]]; then
        continue
      fi
      KERNEL_VERSION_+=( "${V}" )
    done
  done

  # if we have found a kernel version in binary kernel:
  if [[ -f "${CSV_DIR}"/s24_kernel_bin_identifier.csv ]]; then
    while IFS=";" read -r K_VER; do
      K_VER="$(echo "${K_VER}" | sed 's/Linux\ version\ //g' | tr -d "(" | tr -d ")" | tr -d "#")"

      demess_kv_version "${K_VER}"

      IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

      for V in "${KV_C_ARR[@]}" ; do
        KERNEL_VERSION_+=( "${V}" )
      done
    done < <(cut -d ";" -f1 "${CSV_DIR}"/s24_kernel_bin_identifier.csv | tail -n +2)
  fi

  # unique our results
  eval "KERNEL_VERSION_=($(for i in "${KERNEL_VERSION_[@]}" ; do
    if [[ -z "${i}" ]]; then
      # remove empty entries:
      continue;
    fi
    if ! [[ "${i}" =~ .*[0-9]\.[0-9].* ]]; then
      # remove lines without a possible version identifier like *1.2*
      continue;
    fi
    echo "\"${i}\"" ;
  done | sort -u))"

  eval "KERNEL_DESC=($(for i in "${KERNEL_DESC[@]}" ; do echo "\"${i}}\"" ; done | sort -u))"

  # if we have no kernel version identified -> we try to identify a possible identifier in the path:
  if [[ "${#KERNEL_VERSION_[@]}" -eq 0 && "${#KERNEL_MODULES[@]}" -ne 0 ]];then
    # remove the first part of the path:
    local KERNEL_VERSION1=""
    KERNEL_VERSION1=$(echo "${KERNEL_MODULES[0]}" | sed 's/.*\/lib\/modules\///')
    KERNEL_VERSION_+=("${KERNEL_VERSION1}")
    # demess_kv_version removes the unneeded stuff after the version:
    demess_kv_version "${KERNEL_VERSION_[@]}"
    # now rewrite the temp KERNEL_VERSION_ array
    IFS=" " read -r -a KERNEL_VERSION_ <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
  fi

  KERNEL_VERSION=("${KERNEL_VERSION_[@]}")
}

demess_kv_version() {
  local K_VERSION=("$@")
  local KV=""
  local VER=""
  export KV_ARR=()

  # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
  for VER in "${K_VERSION[@]}" ; do
    if ! [[ "${VER}" == *[0-9]* ]]; then
      continue
    fi

    KV=$(echo "${VER}" | tr "-" " ")
    KV=$(echo "${KV}" | tr "+" " ")
    KV=$(echo "${KV}" | tr "_" " ")
    KV=$(echo "${KV}" | tr "/" " ")
    # the first field is the real kernel version:
    KV=$(echo "${KV}" | cut -d\  -f1)

    while echo "${KV}" | grep -q '[a-zA-Z]'; do
      KV="${KV::-1}"
    done
    KV_ARR=("${KV_ARR[@]}" "${KV}")
  done
}

get_kernel_vulns() {
  sub_module_title "Kernel vulnerabilities"

  local VER=""
  local LES_ENTRY=""
  local LES_CVE=""
  local LES_CVE_ENTRIES=()

  if [[ "${#KERNEL_VERSION[@]}" -gt 0 ]]; then
    print_output "[+] Found linux kernel version/s:"
    for VER in "${KERNEL_VERSION[@]}" ; do
      print_output "$(indent "${ORANGE}${VER}${NC}")"
    done
    print_ln

    if [[ -f "${EXT_DIR}""/linux-exploit-suggester.sh" ]] ; then
      # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
      demess_kv_version "${KERNEL_VERSION[@]}"
      IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
      for VER in "${KV_C_ARR[@]}" ; do
        sub_module_title "Possible exploits via linux-exploit-suggester.sh for kernel version ${ORANGE}${VER}${NC}"
        print_output "[*] Search possible exploits via linux-exploit-suggester.sh for kernel version ${ORANGE}${VER}${NC}"
        print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
        "${EXT_DIR}""/linux-exploit-suggester.sh" --skip-more-checks -f -d -k "${VER}" >> "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${VER}.txt"
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${VER}.txt"
        if [[ -f "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${VER}.txt" ]]; then
          mapfile -t LES_CVE_ENTRIES < <(grep "[+]" "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${VER}.txt" | grep -E "CVE-[0-9]+")
          for LES_ENTRY in "${LES_CVE_ENTRIES[@]}"; do
            LES_ENTRY=$(strip_color_codes "${LES_ENTRY}")
            LES_CVE=$(echo "${LES_ENTRY}" | awk '{print $2}' | tr -d '[' | tr -d ']')
            local KNOWN_EXPLOITED=0
            if [[ -f "${KNOWN_EXP_CSV}" ]]; then
              if grep -q \""${LES_CVE}"\", "${KNOWN_EXP_CSV}"; then
                print_output "[+] ${ORANGE}WARNING: ${GREEN}Vulnerability ${ORANGE}${LES_CVE}${GREEN} is a known exploited vulnerability.${NC}"
                KNOWN_EXPLOITED=1
              fi
            fi
            write_csv_log "linux_kernel" "${VER}" "${LES_CVE}" "NA" "NA" "NA" "NA" "NA" "NA" "NA" "NA" "${KNOWN_EXPLOITED}"
          done
        fi
      done
    else
      print_output "[-] linux-exploit-suggester.sh is not installed"
      print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
    fi
  else
    print_output "[-] No linux kernel version information found."
  fi
}

analyze_kernel_module() {
  sub_module_title "Analyze kernel modules"
  write_anchor "kernel_modules"

  KMOD_BAD=0
  local KMODULE=""
  local WAIT_PIDS_S25=()

  print_output "[*] Found ${ORANGE}${#KERNEL_MODULES[@]}${NC} kernel modules."

  for KMODULE in "${KERNEL_MODULES[@]}" ; do
    # modinfos can run in parallel:
    if [[ "${THREADED}" -eq 1 ]]; then
      module_analyzer "${KMODULE}" &
      local TMP_PID="$!"
      store_kill_pids "${TMP_PID}"
      WAIT_PIDS_S25+=( "${TMP_PID}" )
    else
      module_analyzer "${KMODULE}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S25[@]}"

  # in threading we need to go via a temp file with the need to count it now:
  if [[ -f "${TMP_DIR}"/KMOD_BAD.tmp ]]; then
    KMOD_BAD=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/KMOD_BAD.tmp)
  fi
}

module_analyzer() {
  local KMODULE="${1:-}"
  local LINE=""

  if [[ "${KMODULE}" == *".ko" ]]; then
    LINE=$(modinfo "${KMODULE}" | grep -E "filename|license" | cut -d: -f1,2 | sed ':a;N;$!ba;s/\nlicense//g' | sed 's/filename: //' | sed 's/ //g' | sed 's/:/||license:/' || true)
    local M_PATH=""
    M_PATH="$( echo "${LINE}" | cut -d '|' -f 1 )"
    local LICENSE=""
    LICENSE="$( echo "${LINE}" | cut -d '|' -f 3 | sed 's/license:/License: /' )"

    if file "${M_PATH}" 2>/dev/null | grep -q 'not stripped'; then
      if echo "${LINE}" | grep -q -e 'license:*GPL' -e 'license:.*BSD' ; then
        # kernel module is GPL/BSD license then not stripped is fine
        print_output "[-] Found kernel module ""${NC}""$(print_path "${M_PATH}")""  ${ORANGE}""${LICENSE}""${NC}"" - ""${GREEN}""NOT STRIPPED""${NC}"
      elif ! [[ ${LICENSE} =~ "License:" ]] ; then
        print_output "[+] Found kernel module ""${NC}""$(print_path "${M_PATH}")""  ${ORANGE}""License not found""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
      else
        # kernel module is NOT GPL license then not stripped is bad!
        print_output "[+] Found kernel module ""${NC}""$(print_path "${M_PATH}")""  ${ORANGE}""${LICENSE}""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
        echo "1" >> "${TMP_DIR}"/KMOD_BAD.tmp
      fi
    else
      print_output "[-] Found kernel module ""${NC}""$(print_path "${M_PATH}")""  ${ORANGE}""${LICENSE}""${NC}"" - ""${GREEN}""STRIPPED""${NC}"
    fi

  elif [[ "${KMODULE}" == *".o" ]]; then
    print_output "[-] No support for .o kernel modules - ${ORANGE}${KMODULE}${NC}"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_usb

check_modprobe() {
  sub_module_title "Check modprobe.d directory and content"

  local MODPROBE_D_DIRS=""
  local MP_CHECK=0
  local MP_F_CHECK=0
  local MODPROBE_D_DIRS=()
  local MPROBE_DIR=""
  local MP_CONF=""

  readarray -t MODPROBE_D_DIRS < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*modprobe.d*' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for MPROBE_DIR in "${MODPROBE_D_DIRS[@]}"; do
    if [[ -d "${MPROBE_DIR}" ]] ; then
      MP_CHECK=1
      print_output "[+] Found ""$(print_path "${MPROBE_DIR}")"
      readarray -t MODPROBE_D_DIR_CONTENT <<< "$( find "${MPROBE_DIR}" -xdev -iname '*.conf' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )"
      for MP_CONF in "${MODPROBE_D_DIR_CONTENT[@]}"; do
        if [[ -e "${MP_CONF}" ]] ; then
          MP_F_CHECK=1
          print_output "$(indent "$(orange "$(print_path "${MP_CONF}")")")"
        fi
      done
      if [[ ${MP_F_CHECK} -eq 0 ]] ; then
        print_output "[-] No config files in modprobe.d directory found"
      fi
    fi
  done
  if [[ ${MP_CHECK} -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  fi
}

