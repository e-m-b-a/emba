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
  export VERIFIED_KERNEL_MODULES=0
  local lFOUND=0
  export KMOD_BAD=0

  # This module waits for S24_kernel_bin_identifier
  # check emba.log for S24_kernel_bin_identifier starting
  module_wait "S24_kernel_bin_identifier"

  # This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_kernel

  populate_karrays

  if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
    write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln"
    print_output "Kernel version:"
    local lENTRY=""
    for lENTRY in "${KERNEL_VERSION[@]}" ; do
      print_output "$(indent "${ORANGE}${lENTRY}${NC}")"
      lFOUND=1
    done
    if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
      print_ln
      print_output "Kernel details:"
      for lENTRY in "${KERNEL_DESC[@]}" ; do
        print_output "$(indent "${lENTRY}")"
        lFOUND=1
      done
    fi
    if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
      get_kernel_vulns
      check_modprobe
    fi
  else
    print_output "[-] No kernel version identified"
  fi

  if [[ "${KERNEL}" -eq 1 ]] && [[ -f "${KERNEL_CONFIG}" ]] && [[ "${SBOM_MINIMAL:-0}" -eq 0 ]]; then
    # we use check_kconfig from s24 module
    check_kconfig "${KERNEL_CONFIG}"
    lFOUND=1
  else
    print_output "[-] No check for kernel configuration"
  fi

  if [[ ${#KERNEL_MODULES[@]} -ne 0 ]] ; then
    analyze_kernel_module
    lFOUND=1
  fi

  if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
    local lK_VERS=""
    for lK_VERS in "${KERNEL_VERSION[@]}" ; do
      write_log "[*] Statistics:${lK_VERS}"
    done
  fi
  write_log "[*] Statistics1:${VERIFIED_KERNEL_MODULES}:${KMOD_BAD}"

  module_end_log "${FUNCNAME[0]}" "${lFOUND}"
}

populate_karrays() {
  local lKERNEL_VERSION_ARR=()
  local lK_MODULE=""
  local lVER=""
  local lK_VER=""
  local lV=""
  local lK_MOD_FILE=""

  mapfile -t KERNEL_MODULES < <( find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev \( -iname "*.ko" -o -iname "*.o" \) -type f  -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  for lK_MODULE in "${KERNEL_MODULES[@]}"; do
    lK_MOD_FILE=$(file -b "${lK_MODULE}")

    # What is the old .o kernel modules showing in the file output?
    # Linux v2.4.x and before is using .o kernel modules
    if [[ "${lK_MODULE}" =~ .*\.o ]]; then
      KERNEL_VERSION+=( "$(strings "${lK_MODULE}" 2>/dev/null | grep "kernel_version=" | cut -d= -f2 || true)" )
      continue
    fi

    if [[ ! "${lK_MOD_FILE}" == *"ELF"* ]]; then
      continue
    fi
    KERNEL_VERSION+=( "$(modinfo "${lK_MODULE}" 2>/dev/null | grep -E "vermagic" | cut -d: -f2 | sed 's/^ *//g' || true)" )
    KERNEL_DESC+=( "$(modinfo "${lK_MODULE}" 2>/dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g' | tr -c '[:alnum:]\n\r' '_' | sort -u || true)" )
  done

  # we also extract the kernel version from the /lib/modules/<Kernel version>/ path
  local lKERNEL_MODULES_PATHS_ARR=()
  local lPATH_TO_CHECK=""

  mapfile -t lKERNEL_MODULES_PATHS_ARR < <(grep -E "/lib/modules/*[0-9]+\.[0-9]+" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)
  for lPATH_TO_CHECK in "${lKERNEL_MODULES_PATHS_ARR[@]}" ; do
    # we remove the complete path in front of the possible kernel version:
    # asdf/bla/root-dir/lib/modules/ -> gets removed
    lPATH_TO_CHECK="${lPATH_TO_CHECK/*\/lib\/modules\//}"
    if [[ "${lK_VERSION_ARR[*]}" != *"${lPATH_TO_CHECK}"* ]]; then
      # we currently do not care about additional parts of a path
      # This is later handled during cleanup
      KERNEL_VERSION+=("${lPATH_TO_CHECK}")
    fi
  done

  for lVER in "${KERNEL_VERSION[@]}" ; do
    demess_kv_version "${lVER}"

    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    for lV in "${KV_C_ARR[@]}" ; do
      if [[ -z "${lV:-}" ]]; then
        # remove empty entries:
        continue
      fi
      if ! [[ "${lV}" =~ .*[0-9]\.[0-9].* ]]; then
        continue
      fi
      lKERNEL_VERSION_ARR+=( "${lV}" )
    done
  done

  # if we have found a kernel version in binary kernel:
  if [[ -f "${S24_CSV_LOG}" ]]; then
    while IFS=";" read -r lK_VER; do
      shopt -s extglob
      lK_VER="${lK_VER//Linux\ version\ /}"
      lK_VER="${lK_VER//+([\(\)\#])/}"
      shopt -u extglob

      demess_kv_version "${lK_VER}"

      IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

      for lV in "${KV_C_ARR[@]}" ; do
        lKERNEL_VERSION_ARR+=( "${lV}" )
      done
    done < <(cut -d ";" -f2 "${S24_CSV_LOG}")
  fi

  # unique our results
  eval "lKERNEL_VERSION_ARR=($(for i in "${lKERNEL_VERSION_ARR[@]}" ; do
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

  # eval "KERNEL_DESC=($(for i in "${KERNEL_DESC[@]}" ; do echo "\"${i}}\"" ; done | sort -u))"
  mapfile -t KERNEL_DESC < <(printf "%s\n" "${KERNEL_DESC[@]}" | sort -u)

  # if we have no kernel version identified -> we try to identify a possible identifier in the path:
  if [[ "${#lKERNEL_VERSION_ARR[@]}" -eq 0 && "${#KERNEL_MODULES[@]}" -ne 0 ]];then
    # remove the first part of the path:
    local lKERNEL_VERSION1=""
    lKERNEL_VERSION1=$(echo "${KERNEL_MODULES[0]}" | sed 's/.*\/lib\/modules\///')
    lKERNEL_VERSION_ARR+=("${lKERNEL_VERSION1}")
    # demess_kv_version removes the unneeded stuff after the version:
    demess_kv_version "${lKERNEL_VERSION_ARR[@]}"
    # now rewrite the temp lKERNEL_VERSION_ARR array
    IFS=" " read -r -a lKERNEL_VERSION_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
  fi

  KERNEL_VERSION=("${lKERNEL_VERSION_ARR[@]}")
}

demess_kv_version() {
  local lK_VERSION_ARR=("$@")
  local lKV=""
  local lVER=""
  export KV_ARR=()

  # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
  for lVER in "${lK_VERSION_ARR[@]}" ; do
    if ! [[ "${lVER}" == *[0-9]* ]]; then
      continue
    fi

    # split dirty things on space
    shopt -s extglob
    lKV="${lVER//+([-+_\/\ ])/\ }"
    shopt -u extglob

    # the first field is usually the real kernel version:
    lKV="${lKV/\ *}"

    while [[ "${lKV}" =~ [a-zA-Z] ]]; do
      lKV="${lKV::-1}"
    done

    KV_ARR+=("${lKV}")
  done
}

get_kernel_vulns() {
  sub_module_title "Kernel vulnerabilities"

  local lVER=""
  local lLES_ENTRY=""
  local lLES_CVE=""
  local lLES_CVE_ENTRIES_ARR=()

  if [[ "${#KERNEL_VERSION[@]}" -gt 0 ]]; then
    print_output "[+] Found linux kernel version/s:"
    for lVER in "${KERNEL_VERSION[@]}" ; do
      print_output "$(indent "${ORANGE}${lVER}${NC}")"
    done
    print_ln

    if [[ -f "${EXT_DIR}""/linux-exploit-suggester.sh" ]] ; then
      # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
      demess_kv_version "${KERNEL_VERSION[@]}"
      IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
      for lVER in "${KV_C_ARR[@]}" ; do
        sub_module_title "Possible exploits via linux-exploit-suggester.sh for kernel version ${ORANGE}${lVER}${NC}"
        print_output "[*] Search possible exploits via linux-exploit-suggester.sh for kernel version ${ORANGE}${lVER}${NC}"
        print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
        "${EXT_DIR}""/linux-exploit-suggester.sh" --skip-more-checks -f -d -k "${lVER}" >> "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${lVER}.txt"
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${lVER}.txt"
        if [[ -f "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${lVER}.txt" ]]; then
          mapfile -t lLES_CVE_ENTRIES_ARR < <(grep "[+]" "${LOG_PATH_MODULE}""/linux_exploit_suggester_kernel_${lVER}.txt" | grep -E "CVE-[0-9]+")
          for lLES_ENTRY in "${lLES_CVE_ENTRIES_ARR[@]}"; do
            lLES_ENTRY=$(strip_color_codes "${lLES_ENTRY}")
            lLES_CVE=$(echo "${lLES_ENTRY}" | awk '{print $2}' | tr -d '[' | tr -d ']')
            local lKNOWN_EXPLOITED=0
            if [[ -f "${KNOWN_EXP_CSV}" ]]; then
              if grep -q \""${lLES_CVE}"\", "${KNOWN_EXP_CSV}"; then
                print_output "[+] ${ORANGE}WARNING: ${GREEN}Vulnerability ${ORANGE}${lLES_CVE}${GREEN} is a known exploited vulnerability.${NC}"
                lKNOWN_EXPLOITED=1
              fi
            fi

            if ! grep -q ":linux:linux_kernel;${lVER};${lLES_CVE}" "${S25_CSV_LOG}"; then
              write_csv_log ":linux:linux_kernel" "${lVER}" "${lLES_CVE}" "NA" "NA" "NA" "NA" "NA" "NA" "NA" "NA" "${lKNOWN_EXPLOITED}"
            fi
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

  local lKMODULE=""
  local lWAIT_PIDS_S25_ARR=()
  local lFILE_KMOD=""

  KMOD_BAD=0

  print_output "[*] Found ${ORANGE}${#KERNEL_MODULES[@]}${NC} potential kernel modules."

  local lOS_IDENTIFIED=""
  lOS_IDENTIFIED=$(distri_check)

  for lKMODULE in "${KERNEL_MODULES[@]}" ; do
    lFILE_KMOD=$(file "${lKMODULE}")
    if [[ "${lFILE_KMOD}" != *"ELF"* ]]; then
      continue
    fi
    VERIFIED_KERNEL_MODULES=$((VERIFIED_KERNEL_MODULES+1))
    module_analyzer "${lKMODULE}" "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S25_ARR+=( "${lTMP_PID}" )
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S25_ARR[@]}"

  if [[ "${VERIFIED_KERNEL_MODULES}" -eq 0 ]]; then
    print_output "[-] No verified kernel module identified."
  fi
  # in threading we need to go via a temp file with the need to count it now:
  if [[ -f "${TMP_DIR}"/KMOD_BAD.tmp ]]; then
    KMOD_BAD=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/KMOD_BAD.tmp)
  fi
}

module_analyzer() {
  local lKMODULE="${1:-}"
  local lOS_IDENTIFIED="${2:-}"

  if [[ "${lKMODULE}" == *".ko" ]]; then
    local lLICENSE=""
    local lK_VERSION=""
    local lMD5_CHECKSUM="NA"
    local lSHA256_CHECKSUM="NA"
    local lSHA512_CHECKSUM="NA"
    local lK_ARCH="NA"
    local lK_AUTHOR="NA"
    local lK_INTREE="NA"
    local lK_DESC="NA"
    local lCPE_IDENTIFIER=""
    local lPURL_IDENTIFIER=""
    local lMOD_VERSION=""
    local lAPP_NAME=""
    local lK_FILE_OUT=""
    local lAPP_TYPE="operating-system"

    lLICENSE=$(modinfo "${lKMODULE}" | grep "^license:" || true)
    lLICENSE=${lLICENSE/license:\ }
    lLICENSE=${lLICENSE//[[:space:]]}
    [[ "${lLICENSE}" == "GPL" ]] && lLICENSE="GPL-2.0-only"
    # intree - if the module is maintained in the kernel Git repository
    lK_INTREE=$(modinfo "${lKMODULE}" | grep "^intree:" || true)
    lK_INTREE=${lK_INTREE/vermagic:\ }
    lK_INTREE=$(clean_package_details "${lK_INTREE}")
    [[ "${lK_INTREE}" == "Y" ]] && lLICENSE="GPL-2.0-only"

    lK_VERSION=$(modinfo "${lKMODULE}" | grep "^vermagic:" || true)
    lK_VERSION=${lK_VERSION/vermagic:\ }
    lK_VERSION=$(clean_package_details "${lK_VERSION}")
    demess_kv_version "${lK_VERSION}"
    # => we make a nice KV_ARR with the one version only
    # this means we can further proceed with ${KV_ARR[*]} to access
    # the complete version

    # Just in case we have no kernel version extracted from the module
    # we can use the original array of kernel versions:
    if [[ "${#KV_ARR[@]}" -eq 0 && "${#KERNEL_VERSION[@]}" -gt 0 ]]; then
      KV_ARR+=("${KERNEL_VERSION[0]}")
    fi

    lMOD_VERSION=$(modinfo "${lKMODULE}" | grep "^version:" || true)
    lMOD_VERSION=${lMOD_VERSION/version:\ }
    lMOD_VERSION=${lMOD_VERSION//[[:space:]]}

    lAPP_NAME="$(basename "${lKMODULE}")"
    lAPP_NAME=${lAPP_NAME,,}

    lK_AUTHOR=$(modinfo "${lKMODULE}" | grep "^author:" || true)
    lK_AUTHOR="${lK_AUTHOR//author:\ }"
    lK_AUTHOR="${lK_AUTHOR//Maintainer:\ }"
    lK_AUTHOR="$(echo "${lK_AUTHOR}" | tr '\n' '-')"
    lK_AUTHOR=$(clean_package_details "${lK_AUTHOR}")

    lK_DESC=$(modinfo "${lKMODULE}" | grep "^description:" || true)
    lK_DESC=${lK_DESC/description:\ }
    lK_DESC=$(clean_package_details "${lK_DESC}")

    lMD5_CHECKSUM="$(md5sum "${lKMODULE}" | awk '{print $1}')"
    lSHA256_CHECKSUM="$(sha256sum "${lKMODULE}" | awk '{print $1}')"
    lSHA512_CHECKSUM="$(sha512sum "${lKMODULE}" | awk '{print $1}')"

    lK_FILE_OUT=$(file -b "${lKMODULE}" 2>/dev/null)
    lK_ARCH=$(echo "${lK_FILE_OUT}" | cut -d ',' -f2)
    lK_ARCH=${lK_ARCH#\ }

    if [[ "${lK_FILE_OUT}" == *"not stripped"* ]]; then
      if [[ "${lLICENSE}" == *"GPL"* || "${lLICENSE}" == *"BSD"* ]] ; then
        # kernel module is GPL/BSD license then not stripped is fine
        print_output "[*] Found kernel module ""${NC}""$(orange "$(print_path "${lKMODULE}")")"" - ${ORANGE}""License ${lLICENSE}""${NC}"" - ""${GREEN}""NOT STRIPPED""${NC}"
      elif ! [[ ${lLICENSE} =~ "License:" ]] ; then
        print_output "[-] Found kernel module ""${NC}""$(orange "$(print_path "${lKMODULE}")")"" - ${ORANGE}""License not found""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
      else
        # kernel module is NOT GPL license then not stripped is bad!
        print_output "[-] Found kernel module ""${NC}""$(orange "$(print_path "${lKMODULE}")")"" - ${ORANGE}""License ${lLICENSE}""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
        echo "1" >> "${TMP_DIR}"/KMOD_BAD.tmp
      fi
    else
      print_output "[*] Found kernel module ""${NC}""$(orange "$(print_path "${lKMODULE}")")"" - ${ORANGE}""License ${lLICENSE}""${NC}"" - ""${GREEN}""STRIPPED""${NC}"
    fi

    # we log to our sbom log with the kernel module details only if we have some module version detected
    if [[ -n "${lMOD_VERSION}" ]]; then
      # we store the kernel version (lVERSION:-NA) and the kernel module version (lMOD_VERSION:-NA)
      check_for_s08_csv_log "${S08_CSV_LOG}"

      local lPACKAGING_SYSTEM="kernel_module"
      # add source file path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lKMODULE}" )
      lPROP_ARRAY_INIT_ARR+=( "source_arch:${lK_ARCH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_details:${lK_FILE_OUT}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier::${lK_AUTHOR}:${lAPP_NAME}:${lMOD_VERSION}:" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )
      lPROP_ARRAY_INIT_ARR+=( "dependency:linux_kernel" )

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lKMODULE}" "${lAPP_NAME:-NA}" "${lMOD_VERSION:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        print_output "[*] Already found results for ${lAPP_NAME} / ${lMOD_VERSION}" "no_log"
      else
        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lMOD_VERSION:-NA}" "${lK_AUTHOR:-NA}" "${lLICENSE:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lK_DESC:-NA}"
      fi

      write_log "${lPACKAGING_SYSTEM};${lKMODULE:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lAPP_NAME};${lMOD_VERSION:-NA};NA;${lLICENSE};${lK_AUTHOR};${lK_ARCH};CPE not available;PURL not available;${SBOM_COMP_BOM_REF:-NA};Linux kernel module - ${lAPP_NAME} - description: ${lK_DESC:-NA}" "${S08_CSV_LOG}"
    fi

    if [[ "${#KV_ARR[@]}" -gt 0 ]]; then
      # ensure we do not log the kernel multiple times
      local lK_AUTHOR="linux"
      local lLICENSE="GPL-2.0-only"
      # we can rewrite the APP_NAME as we also log the source_path from where we know the exact source of this kernel entry
      local lAPP_NAME="linux_kernel"
      local lPACKAGING_SYSTEM="${lAPP_NAME}+module"

      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lK_AUTHOR}:${lAPP_NAME}:${KV_ARR[*]}:*:*:*:*:*:*"
      lPURL_IDENTIFIER=$(build_generic_purl ":${lK_AUTHOR}:${lAPP_NAME}:${KV_ARR[*]}" "${lOS_IDENTIFIED}" "${lK_ARCH:-NA}")

      # add source file path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lKMODULE}" )
      lPROP_ARRAY_INIT_ARR+=( "source_arch:${lK_ARCH}" )
      lPROP_ARRAY_INIT_ARR+=( "source_details:${lK_FILE_OUT}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier::${lK_AUTHOR}:${lAPP_NAME}:${KV_ARR[*]}:" )
      lPROP_ARRAY_INIT_ARR+=( "module_version_details:${lK_VERSION,,}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lKMODULE}" "${lAPP_NAME:-NA}" "${KV_ARR[*]}" "${lPACKAGING_SYSTEM:-NA}"; then
        print_output "[*] Already found results for ${lAPP_NAME} / ${KV_ARR[*]}" "no_log"
      else
        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${KV_ARR[*]}" "${lK_AUTHOR:-NA}" "${lLICENSE:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lK_DESC:-NA}"
        write_log "${lPACKAGING_SYSTEM};${lKMODULE:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};linux_kernel:${lAPP_NAME};${lK_VERSION,,};:linux:linux_kernel:${KV_ARR[*]};${lLICENSE};kernel.org;${lK_ARCH};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};Detected via Linux kernel module - ${lAPP_NAME}" "${S08_CSV_LOG}"
      fi
    fi
  elif [[ "${lKMODULE}" == *".o" ]] && [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    print_output "[-] No support for .o kernel modules - ${ORANGE}${lKMODULE}${NC}" "no_log"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_usb

check_modprobe() {
  sub_module_title "Check modprobe.d directory and content"

  local lMODPROBE_D_DIRS_ARR=()
  local lMPROBE_DIR=""
  local lMP_CHECK=0
  local lMP_F_CHECK=0
  local lMP_CONF=""

  readarray -t lMODPROBE_D_DIRS_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*modprobe.d*'  -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  for lMPROBE_DIR in "${lMODPROBE_D_DIRS_ARR[@]}"; do
    if [[ -d "${lMPROBE_DIR}" ]] ; then
      lMP_CHECK=1
      print_output "[+] Found ""$(print_path "${lMPROBE_DIR}")"
      readarray -t MODPROBE_D_DIR_CONTENT <<< "$( find "${lMPROBE_DIR}" -xdev -iname '*.conf'  -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )"
      for lMP_CONF in "${MODPROBE_D_DIR_CONTENT[@]}"; do
        if [[ -e "${lMP_CONF}" ]] ; then
          lMP_F_CHECK=1
          print_output "$(indent "$(orange "$(print_path "${lMP_CONF}")")")"
        fi
      done
      if [[ ${lMP_F_CHECK} -eq 0 ]] ; then
        print_output "[-] No config files in modprobe.d directory found"
      fi
    fi
  done
  if [[ ${lMP_CHECK} -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  fi
}

