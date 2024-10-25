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

# Description:  This module tries to identify the kernel file and the init command line
#               The identified kernel binary file is extracted with vmlinux-to-elf

export THREAD_PRIO=1

S24_kernel_bin_identifier()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Kernel Binary and Configuration Identifier"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lFILE=""
  local lK_VER=""
  local lK_INITS_ARR=()
  local lK_INIT=""
  local lCFG_MD5=""
  export KCFG_MD5_ARR=()

  prepare_file_arr_limited "${FIRMWARE_PATH_CP}"

  write_csv_log "Kernel version orig" "Kernel version stripped" "file" "generated elf" "identified init" "config extracted" "kernel symbols" "architecture" "endianness"

  for lFILE in "${FILE_ARR_LIMITED[@]}" ; do
    local lK_ELF="NA"
    local lKCONFIG_EXTRACTED="NA"
    local lK_VER_CLEAN="NA"
    local lK_INIT="NA"
    local CFG_CNT=0
    local K_SYMBOLS=0
    local K_ARCH="NA"
    local K_ARCH_END="NA"
    local K_CON_DET=""
    local K_FILE=""
    local K_VER_TMP=""
    local lSTRIPPED_VERS=""
    local lPACKAGING_SYSTEM="linux_kernel"
    local lAPP_LIC="GPL-2.0-only"
    local lAPP_MAINT="kernel.org"
    local lAPP_NAME=""
    local lAPP_VERS=""
    local lAPP_TYPE="operating-system"

    if file -b "${lFILE}" | grep -q "ASCII text"; then
      # reduce false positive rate
      continue
    fi
    lK_VER=$(strings "${lFILE}" 2>/dev/null | grep -E "^Linux version [0-9]+\.[0-9]+" | sort -u | tr -dc '[:print:]' || true)

    if [[ "${lK_VER}" =~ Linux\ version\ .* ]]; then
      print_ln
      print_output "[+] Possible Linux Kernel found: ${ORANGE}${lFILE}${NC}"
      print_ln
      print_output "$(indent "$(orange "${lK_VER}")")"
      print_ln

      # not perfect, but not too bad for now:
      mapfile -t lK_INITS_ARR < <(strings "${lFILE}" 2>/dev/null | grep -E "init=\/" | sed 's/.*rdinit/rdinit/' | sed 's/.*\ init/init/' | awk '{print $1}' | tr -d '"' | sort -u || true)
      for lK_INIT in "${lK_INITS_ARR[@]}"; do
        if [[ "${lK_INIT}" =~ init=\/.* ]]; then
          print_output "[+] Init found in Linux kernel file ${ORANGE}${lFILE}${NC}"
          print_ln
          print_output "$(indent "$(orange "${lK_INIT}")")"
          print_ln
        else
          lK_INIT="NA"
        fi
      done

      check_for_s08_csv_log "${S08_CSV_LOG}"
      lSTRIPPED_VERS=$(echo "${lK_VER}" | sed -r 's/Linux\ version\ ([1-6](\.[0-9]+)+?).*/:linux:linux_kernel:\1/' || true)
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a${lSTRIPPED_VERS}:*:*:*:*:*:*"
      lPURL_IDENTIFIER=$(build_generic_purl ":${lSTRIPPED_VERS}")
      lK_VER="${lK_VER//[,;\/()\[\]\\#]}"
      lAPP_MAINT=$(echo "${lSTRIPPED_VERS}" | cut -d ':' -f2)
      lAPP_NAME=$(echo "${lSTRIPPED_VERS}" | cut -d ':' -f3)
      lAPP_VERS=$(echo "${lSTRIPPED_VERS}" | cut -d ':' -f4-5)
      # it could be that we have a version like 2.14b:* -> we remove the last field
      lAPP_VERS="${lAPP_VERS/:\*}"

      if [[ -e "${EXT_DIR}"/vmlinux-to-elf/vmlinux-to-elf ]]; then
        print_output "[*] Testing possible Linux kernel file ${ORANGE}${lFILE}${NC} with ${ORANGE}vmlinux-to-elf:${NC}"
        print_ln
        "${EXT_DIR}"/vmlinux-to-elf/vmlinux-to-elf "${lFILE}" "${lFILE}".elf 2>/dev/null | tee -a "${LOG_FILE}" || true
        if [[ -f "${lFILE}".elf ]]; then
          lK_ELF=$(file -b "${lFILE}".elf)

          if [[ "${lK_ELF}" == *"ELF "* ]]; then
            print_ln
            print_output "[+] Successfully generated Linux kernel elf file: ${ORANGE}${lFILE}.elf${NC}"
            lMD5_CHECKSUM="$(md5sum "${lFILE}.elf" | awk '{print $1}')"
            lSHA256_CHECKSUM="$(sha256sum "${lFILE}.elf" | awk '{print $1}')"
            lSHA512_CHECKSUM="$(sha512sum "${lFILE}.elf" | awk '{print $1}')"
            lK_ELF=$(echo "${lK_ELF}" | cut -d ',' -f2-3)
            lK_ELF=${lK_ELF//,\ /\ -\ }

            if command -v jo >/dev/null; then
              # add source file path information to our properties array:
              local lPROP_ARRAY_INIT_ARR=()
              lPROP_ARRAY_INIT_ARR+=( "path:${lFILE}" )
              lPROP_ARRAY_INIT_ARR+=( "path:${lFILE}.elf" )

              build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

              # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
              # final array with all hash values
              build_sbom_json_hashes_arr "${lFILE}.elf"

              # create component entry - this allows adding entries very flexible:
              build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-unknown}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lK_ELF:-NA}" "${lAPP_DESC:-NA}"
            fi

            write_log "${lPACKAGING_SYSTEM};${lFILE:-NA}.elf;${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};linux_kernel:$(basename "${lFILE}").elf;${lK_VER:-NA};${lSTRIPPED_VERS:-NA};${lAPP_LIC:-unknown};${lAPP_MAINT:-NA};${lK_ELF:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};Linux Kernel" "${S08_CSV_LOG}"
          else
            print_ln
            print_output "[-] No Linux kernel elf file was created."
          fi
        fi
        print_ln
      fi

      # if we have not elf file created and logged we now log the original kernel
      # in case we have an elf file lFILE was already included in the SBOM
      if [[ ! -f "${lFILE}".elf ]]; then
        lMD5_CHECKSUM="$(md5sum "${lFILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lFILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lFILE}" | awk '{print $1}')"
        lK_ELF=$(file -b "${lFILE}")
        lK_ELF=$(echo "${lK_ELF}" | cut -d ',' -f2-3)
        lK_ELF=${lK_ELF//,\ /\ -\ }

        write_log "${lPACKAGING_SYSTEM};${lFILE:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};linux_kernel:$(basename "${lFILE}");${lK_VER:-NA};${lSTRIPPED_VERS:-NA};${lAPP_LIC:-unknown};${lAPP_MAINT:-NA};${lK_ELF:-NA};${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF:-NA};Linux Kernel" "${S08_CSV_LOG}"
      fi

      # ensure this is only done in non SBOM_MINIMAL mode
      if [[ "${SBOM_MINIMAL:-0}" -eq 0 ]] ; then
        disable_strict_mode "${STRICT_MODE}" 0
        extract_kconfig "${lFILE}"
        enable_strict_mode "${STRICT_MODE}" 0

        K_VER_TMP="${lK_VER/Linux version /}"
        demess_kv_version "${K_VER_TMP}"
        # -> KV_ARR

        if [[ "${lK_ELF}" == *"ELF "* ]]; then
          lK_ELF="$(echo "${lK_ELF}" | cut -d: -f1)"
          K_SYMBOLS="$(readelf -s "${lK_ELF}" | grep -c "FUNC\|OBJECT" || true)"
          K_FILE="$(file -b "${lK_ELF}")"

          [[ "${K_FILE}" == *"LSB"* ]] && K_ARCH_END="EL"
          [[ "${K_FILE}" == *"MSB"* ]] && K_ARCH_END="EB"

          [[ "${K_FILE}" == *"MIPS"* ]] && K_ARCH="MIPS"
          [[ "${K_FILE}" == *"ARM"* ]] && K_ARCH="ARM"
          [[ "${K_FILE}" == *"80386"* ]] && K_ARCH="x86"
          [[ "${K_FILE}" == *"x86-64"* ]] && K_ARCH="x64"
          [[ "${K_FILE}" == *"PowerPC"* ]] && K_ARCH="PPC"
          [[ "${K_FILE}" == *"UCB RISC-V"* ]] && K_ARCH="RISCV"
          [[ "${K_FILE}" == *"QUALCOMM DSP6"* ]] && K_ARCH="QCOM_DSP6"
        else
          # fallback
          K_ARCH=$(grep "Guessed architecture" "${LOG_FILE}" | cut -d: -f2 | awk '{print $1}' | sort -u || true)
          [[ "${K_ARCH: -2}" == "le" ]] && K_ARCH_END="EL"
          [[ "${K_ARCH: -2}" == "be" ]] && K_ARCH_END="EB"
        fi

        # double check we really have a Kernel config extracted
        if [[ -f "${lKCONFIG_EXTRACTED}" ]] && [[ $(grep -c CONFIG_ "${lKCONFIG_EXTRACTED}") -gt 50 ]]; then
          CFG_CNT=$(grep -c CONFIG_ "${lKCONFIG_EXTRACTED}")
          print_output "[+] Extracted kernel configuration (${ORANGE}${CFG_CNT} configuration entries${GREEN}) from ${ORANGE}$(basename "${lFILE}")${NC}" "" "${lKCONFIG_EXTRACTED}"
          check_kconfig "${lKCONFIG_EXTRACTED}" "${K_ARCH}"
        fi

        # we should only get one element back, but as array
        for lK_VER_CLEAN in "${KV_ARR[@]}"; do
          if [[ "${#lK_INITS_ARR[@]}" -gt 0 ]]; then
            for lK_INIT in "${lK_INITS_ARR[@]}"; do
              if [[ "${CFG_CNT}" -lt 50 ]]; then
                lKCONFIG_EXTRACTED="NA"
              fi
              write_csv_log "${lK_VER}" "${lK_VER_CLEAN}" "${lFILE}" "${lK_ELF}" "${lK_INIT}" "${lKCONFIG_EXTRACTED}" "${K_SYMBOLS}" "${K_ARCH}" "${K_ARCH_END}"
            done
          else
            write_csv_log "${lK_VER}" "${lK_VER_CLEAN}" "${lFILE}" "${lK_ELF}" "NA" "${lKCONFIG_EXTRACTED}" "${K_SYMBOLS}" "${K_ARCH}" "${K_ARCH_END}"
          fi
        done
        lNEG_LOG=1
      fi
    # ASCII kernel config files:
    elif file -b "${lFILE}" | grep -q "ASCII"; then
      lCFG_MD5=$(md5sum "${lFILE}" | awk '{print $1}')
      if [[ ! " ${KCFG_MD5_ARR[*]} " =~ ${lCFG_MD5} ]]; then
        K_CON_DET=$(strings "${lFILE}" 2>/dev/null | grep -E "^# Linux.*[0-9]{1}\.[0-9]{1,2}\.[0-9]{1,2}.* Kernel Configuration" || true)
        if [[ "${K_CON_DET}" =~ \ Kernel\ Configuration ]]; then
          print_ln
          print_output "[+] Found kernel configuration file: ${ORANGE}${lFILE}${NC}"
          check_kconfig "${lFILE}"
          lNEG_LOG=1
          KCFG_MD5_ARR+=("${lCFG_MD5}")
        fi
      fi
    fi
  done

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

extract_kconfig() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  # # extract-ikconfig - Extract the .config file from a kernel image
  #
  # This will only work when the kernel was compiled with CONFIG_IKCONFIG.
  #
  # The obscure use of the "tr" filter is to work around older versions of
  # "grep" that report the byte offset of the line instead of the pattern.
  #
  # (c) 2009,2010 Dick Streefland <dick@streefland.net>
  # Licensed under the terms of the GNU General Public License.

  # Check invocation:
  export IMG="${1:-}"
  export KCONFIG_EXTRACTED=""

  if ! [[ -f "${IMG}" ]]; then
    print_output "[-] No kernel file to analyze here - ${ORANGE}${IMG}${NC}"
    return
  fi

  print_output "[*] Trying to extract kernel configuration from ${ORANGE}${IMG}${NC}"

  export CF1='IKCFG_ST\037\213\010'
  export CF2='0123456789'

  # Prepare temp files:
  export TMP1="${TMP_DIR}"/ikconfig$$.1
  export TMP2="${TMP_DIR}"/ikconfig$$.2
  # shellcheck disable=SC2064
  trap "rm -f ${TMP1} ${TMP2}" 0

  # Initial attempt for uncompressed images or objects:
  dump_config "${IMG}"
  [[ $? -eq 4 ]] && return

  # That didn't work, so retry after decompression.
  try_decompress '\037\213\010' xy    gunzip
  [[ $? -eq 4 ]] && return

  try_decompress '\3757zXZ\000' abcde unxz
  [[ $? -eq 4 ]] && return

  try_decompress 'BZh'          xy    bunzip2
  [[ $? -eq 4 ]] && return

  try_decompress '\135\0\0\0'   xxx   unlzma
  [[ $? -eq 4 ]] && return

  try_decompress '\211\114\132' xy    'lzop -d'
  [[ $? -eq 4 ]] && return

  try_decompress '\002\041\114\030' xyy 'lz4 -d -l'
  [[ $? -eq 4 ]] && return

  try_decompress '\050\265\057\375' xxx unzstd
  [[ $? -eq 4 ]] && return
}

dump_config() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  local IMG_="${1:-}"
  local lCFG_MD5=""

  if ! [[ -f "${IMG_}" ]]; then
    print_output "[-] No kernel file to analyze here - ${ORANGE}${IMG_}${NC}"
    return
  fi

  if POS=$(tr "${CF1}\n${CF2}" "\n${CF2}=" < "${IMG_}" | grep -abo "^${CF2}"); then
    POS=${POS%%:*}

    tail -c+"$((POS + 8))" "${IMG_}" | zcat > "${TMP1}" 2> /dev/null

    if [[ $? != 1 ]]; then  # exit status must be 0 or 2 (trailing garbage warning)
      [[ "${STRICT_MODE}" -eq 1 ]] && set +e

      if ! [[ -f "${TMP1}" ]]; then
        return
      fi

      lCFG_MD5=$(md5sum "${TMP1}" | awk '{print $1}')
      if [[ ! " ${KCFG_MD5_ARR[*]} " =~ ${lCFG_MD5} ]]; then
        KCONFIG_EXTRACTED="${LOG_PATH_MODULE}/kernel_config_extracted_$(basename "${IMG_}").log"
        cp "${TMP1}" "${KCONFIG_EXTRACTED}"
        KCFG_MD5_ARR+=("${lCFG_MD5}")
        # return value of 4 means we are done and we are going back to the main function of this module for the next file
        return 4
      else
        print_output "[*] Firmware binary ${ORANGE}${IMG}${NC} already analyzed .. skipping"
        return 4
      fi
    fi
  fi
}

try_decompress() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  export POS=""
  for POS in $(tr "$1\n$2" "\n$2=" < "${IMG}" | grep -abo "^$2"); do
    POS=${POS%%:*}
    tail -c+"${POS}" "${IMG}" | "${3}" > "${TMP2}" 2> /dev/null
    dump_config "${TMP2}"
    [[ $? -eq 4 ]] && return 4
  done
}

check_kconfig() {
  local lKCONFIG_FILE="${1:-}"
  local lKCONFIG_ARCH="${2:-NA}"
  local lKCONF_HARD_CHECKER="${EXT_DIR}"/kconfig-hardened-check/bin/kernel-hardening-checker
  local lFAILED_KSETTINGS=""
  local lKCONF_LOG=""

  if ! [[ -e "${lKCONF_HARD_CHECKER}" ]]; then
    print_output "[-] Kernel config hardening checker not found"
    return
  fi

  if ! [[ -f "${lKCONFIG_FILE}" ]]; then
    return
  fi

  if [[ "${lKCONFIG_ARCH,,}" == *"mips"* ]]; then
    print_output "[-] Architecture ${ORANGE}${lKCONFIG_ARCH}${NC} not supported by ${ORANGE}kernel-hardening-checker${NC}."
    return
  fi

  print_output "[*] Testing kernel configuration file ${ORANGE}${lKCONFIG_FILE}${NC} with kconfig-hardened-check (architecture ${lKCONFIG_ARCH})."
  lKCONF_LOG="${LOG_PATH_MODULE}/kconfig_hardening_check_$(basename "${lKCONFIG_FILE}").log"
  "${lKCONF_HARD_CHECKER}" -c "${lKCONFIG_FILE}" | tee -a "${lKCONF_LOG}" || true
  if [[ -f "${lKCONF_LOG}" ]]; then
    lFAILED_KSETTINGS=$(grep -c "FAIL: " "${lKCONF_LOG}" || true)
    if [[ "${lFAILED_KSETTINGS}" -gt 0 ]]; then
      print_output "[+] Found ${ORANGE}${lFAILED_KSETTINGS}${GREEN} security related kernel settings which should be reviewed - ${ORANGE}$(print_path "${lKCONFIG_FILE}")${NC}" "" "${lKCONF_LOG}"
      print_ln
      write_log "[*] Statistics:${lFAILED_KSETTINGS}"
    fi
  fi
}
