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

# Description:  Preparation for testing firmware:
#                 Check log directory
#                 Excluding paths
#                 Check architecture
#                 Binary array
#                 etc path handling
#                 Check firmware
#               Access:
#                 firmware root path via $FIRMWARE_PATH

log_folder() {
  if [[ ${ONLY_DEP} -eq 0 ]] && [[ -d "${LOG_DIR}" ]] ; then
    # If RESCAN_SBOM is enabled, skip log directory deletion prompt and reuse existing directory
    if [[ "${RESCAN_SBOM}" -eq 1 ]]; then
      print_output "[*] Rescanning SBOM using existing log directory ${ORANGE}${LOG_DIR}${NC}" "no_log"
      return
    fi
    export RESTART=0          # indicator for testing unfinished tests again
    local lNOT_FINISHED=0      # identify unfinished firmware tests
    local lPOSSIBLE_RESTART=0  # used for testing the checksums of the firmware with stored checksum
    local lUSER_ANSWER="n"
    local lD_LOG_FILES_ARR=()
    local lD_LOG_FILE=""
    local lSTORED_SHA512=""
    local lFW_SHA512=""

    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    There are files in the specified directory: ""${LOG_DIR}"
    echo -e "    You can now delete the content here or start the tool again and specify a different directory."

    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
      if check_emba_ended; then
        print_output "[*] A finished EMBA firmware test was found in the log directory" "no_log"
      elif grep -q "System emulation phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}system emulation phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      elif grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}testing phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      elif grep -q "Pre-checking phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}pre-checking phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      else
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory" "no_log"
        lNOT_FINISHED=1
      fi
    fi

    # we check the found sha512 hash with the firmware to test:
    # shellcheck disable=SC2153
    if [[ -f "${CSV_DIR}"/p02_firmware_bin_file_check.csv ]] && [[ -f "${FIRMWARE_PATH}" ]] && grep -q "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv; then
      lSTORED_SHA512=$(grep "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv | cut -d\; -f2 | sort -u)
      lFW_SHA512=$(sha512sum "${FIRMWARE_PATH}" | awk '{print $1}')
      if [[ "${lSTORED_SHA512}" == "${lFW_SHA512}" ]]; then
        # the found analysis is for the same firmware
        lPOSSIBLE_RESTART=1
      fi
    fi
    echo -e "\\n${ORANGE}Delete content of log directory: ${LOG_DIR} ?${NC}\\n"
    if [[ "${lNOT_FINISHED}" -eq 1 ]] && [[ "${lPOSSIBLE_RESTART}" -eq 1 ]]; then
      print_output "[*] If you answer with ${ORANGE}n${NC}o, EMBA tries to process the unfinished test${NC}" "no_log"
    fi

    if [[ ${OVERWRITE_LOG} -eq 1 ]] ; then
      lUSER_ANSWER="y"
    else
      read -p "(Y/n)  " -r lUSER_ANSWER
    fi
    case ${lUSER_ANSWER:0:1} in
        y|Y|"" )
          if mount | grep "${LOG_DIR}" | grep -e "proc\|sys\|run" > /dev/null; then
            print_ln "no_log"
            print_output "[!] We found unmounted areas from a former emulation process in your log directory ${LOG_DIR}." "no_log"
            print_output "[!] You should unmount this stuff manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "${LOG_DIR}")")" "no_log"
            echo -e "\\n${RED}Terminate EMBA${NC}\\n"
            exit 1
          elif mount | grep "${LOG_DIR}" > /dev/null; then
            print_ln "no_log"
            print_output "[!] We found unmounted areas in your log directory ${LOG_DIR}." "no_log"
            print_output "[!] If EMBA is failing check this manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "${LOG_DIR}")")" "no_log"
          else
            rm -R "${LOG_DIR:?}/"* 2>/dev/null || true
            echo -e "\\n${GREEN}Successfully deleted: ${ORANGE}${LOG_DIR}${NC}\\n"
          fi
        ;;
        n|N )
          if [[ "${lNOT_FINISHED}" -eq 1 ]] && [[ -f "${LOG_DIR}"/backup_vars.log ]] && [[ "${lPOSSIBLE_RESTART}" -eq 1 ]]; then
            print_output "[*] EMBA tries to process the unfinished test" "no_log"
            if ! [[ -d "${TMP_DIR}" ]]; then
              mkdir "${TMP_DIR}"
            fi
            touch "${TMP_DIR}"/restart_emba
          else
            echo -e "\\n${RED}Terminate EMBA${NC}\\n"
            exit 1
          fi
        ;;
        * )
          echo -e "\\n${RED}Terminate EMBA${NC}\\n"
          exit 1
        ;;
    esac
  fi

  readarray -t lD_LOG_FILES_ARR < <( find . \( -path ./external -o -path ./config -o -path ./licenses -o -path ./tools \) -prune -false -o \( -name "*.txt" -o -name "*.log" \) | head -100 )
  if [[ ${USE_DOCKER} -eq 1 && ${#lD_LOG_FILES_ARR[@]} -gt 0 ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    It appears that there are log files in the EMBA directory.\\n    You should move these files to another location where they won't be exposed to the Docker container."
    for lD_LOG_FILE in "${lD_LOG_FILES_ARR[@]}" ; do
      echo -e "        ""$(orange "${lD_LOG_FILE}")"
    done
    echo -e "\\n${ORANGE}Continue to run EMBA and ignore this warning?${NC}\\n"
    read -p "(Y/n)  " -r lUSER_ANSWER
    case ${lUSER_ANSWER:0:1} in
        y|Y|"" )
          print_ln "no_log"
        ;;
        * )
          echo -e "\\n${RED}Terminate EMBA${NC}\\n"
          exit 1
        ;;
    esac
  fi
}

set_exclude()
{
  export EXCLUDE_PATHS=""
  export EXCLUDE=()

  if [[ "${FIRMWARE_PATH}" == "/" ]]; then
    EXCLUDE=("${EXCLUDE[@]}" "/proc" "/sys" "$(pwd)")
    print_output "[!] Apparently you want to test your live system. This can lead to errors. Please report the bugs so the software can be fixed." "no_log"
  fi

  print_ln "no_log"

  # exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
  EXCLUDE_PATHS="$(set_excluded_path)"
  export EXCL_FIND=()
  IFS=" " read -r -a EXCL_FIND <<< "$( echo -e "$(get_excluded_find "${EXCLUDE_PATHS}")" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
  print_excluded
}

binary_architecture_threader() {
  local lBINARY="${1:-}"
  local lSOURCE_MODULE="${2:-}"

  local lD_FLAGS_CNT=""
  local lD_MACHINE="NA"
  local lD_CLASS="NA"
  local lD_DATA="NA"
  local lD_ARCH_GUESSED="NA"
  local lMD5SUM=""
  lMD5SUM="$(md5sum "${lBINARY}" || print_output "[-] Checksum error for binary ${lBINARY}" "no_log")"
  lMD5SUM="${lMD5SUM/\ *}"
  if [[ "${lBINARY}" == *".raw" ]]; then
    return
  fi

  if grep -q "${lMD5SUM}" "${TMP_DIR}/p99_md5sum_done.tmp" 2>/dev/null; then
    return
  fi
  if [[ -f "${P99_CSV_LOG}" ]] && grep -q "${lMD5SUM}" "${P99_CSV_LOG}" 2>/dev/null; then
    return
  fi
  echo "${lMD5SUM}" >> "${TMP_DIR}/p99_md5sum_done.tmp"

  print_dot

  D_FILE_OUTPUT=$(file -b "${lBINARY}")
  if [[ "${D_FILE_OUTPUT}" == *"ELF"* ]]; then
    # noreorder, pic, cpic, o32, mips32
    local lREADELF_H_ARR=()

    mapfile -t lREADELF_H_ARR < <(readelf -W -h "${lBINARY}" 2>/dev/null || true)

    lD_FLAGS_CNT=$(printf -- '%s\n' "${lREADELF_H_ARR[@]}" | grep "Flags:" || true)
    lD_FLAGS_CNT="${lD_FLAGS_CNT// /}"
    lD_FLAGS_CNT="${lD_FLAGS_CNT/*Flags:/}"
    lD_FLAGS_CNT="${lD_FLAGS_CNT/0x0/}"

    lD_MACHINE=$(printf -- '%s\n' "${lREADELF_H_ARR[@]}" | grep "Machine:" || true)
    lD_MACHINE="${lD_MACHINE// /}"
    lD_MACHINE="${lD_MACHINE/*Machine:/}"
    lD_MACHINE=$(echo "${lD_MACHINE}" | sed -E 's/^[[:space:]]+//')

    # ELF32/64
    lD_CLASS=$(printf -- '%s\n' "${lREADELF_H_ARR[@]}" | grep "Class:" || true)
    lD_CLASS="${lD_CLASS/*Class:/}"
    lD_CLASS=$(echo "${lD_CLASS}" | sed -E 's/^[[:space:]]+//')

    # endianes
    lD_DATA=$(printf -- '%s\n' "${lREADELF_H_ARR[@]}" | grep "Data:" || true)
    lD_DATA="${lD_DATA/*Data:/}"
    lD_DATA=$(echo "${lD_DATA}" | sed -E 's/^[[:space:]]+//')

    lD_ARCH_GUESSED=$(readelf -W -p .comment "${lBINARY}" 2>/dev/null| grep -v "String dump" | awk '{print $3,$4,$5}' | sort -u | tr '\n' ',' || true)
    lD_ARCH_GUESSED="${lD_ARCH_GUESSED%%,/}"
    lD_ARCH_GUESSED="${lD_ARCH_GUESSED##,/}"
  fi

  write_csv_log_to_path "${P99_CSV_LOG}" "${lSOURCE_MODULE}" "${lBINARY}" "${lD_CLASS}" "${lD_DATA}" "${lD_MACHINE}" "${lD_FLAGS_CNT}" "${lD_ARCH_GUESSED}" "${D_FILE_OUTPUT//\;/,}" "${lMD5SUM}" &
}

architecture_check() {
  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] WARNING: Architecture auto detection and backend data population not possible\\n"
    return
  fi

  if [[ ${ARCH_CHECK} -eq 1 ]] ; then
    print_output "[*] Architecture auto detection and backend data population for ${ORANGE}${#ALL_FILES_ARR[@]}${NC} files (could take some time)\\n"
    # lARCH_MIPS_CNT -> 32 bit MIPS
    local lARCH_MIPS_CNT=0
    local lARCH_ARM_CNT=0
    local lARCH_ARM64_CNT=0
    local lARCH_X64_CNT=0
    local lARCH_X86_CNT=0
    local lARCH_PPC_CNT=0
    local lARCH_NIOS2_CNT=0
    local lARCH_MIPS64R2_CNT=0
    local lARCH_MIPS64_III_CNT=0
    local lARCH_MIPS64v1_CNT=0
    local lARCH_MIPS64_N32_CNT=0
    local lARCH_RISCV_CNT=0
    local lARCH_PPC64_CNT=0
    local lARCH_QCOM_DSP6_CNT=0
    local lARCH_TRICORE_CNT=0
    local lD_END_LE_CNT=0
    local lD_END_BE_CNT=0
    export ARM_HF=0
    export ARM_SF=0
    export D_END="NA"
    local lBINARY=""
    local D_FILE_OUTPUT=""

    # sort and make P99_CSV_LOG unique
    sort -u -t';' -k9,9 -o "${P99_CSV_LOG}" "${P99_CSV_LOG}"
    # this needs to be added to the first line
    # write_csv_log_to_path "CSV log file" "SOURCE MODULE" "FILE" "BINARY_CLASS" "END_DATA" "MACHINE-TYPE" "BINARY_FLAGS" "ARCH_GUESSED" "ELF-DATA" "MD5SUM"

    lARCH_MIPS64_N32_CNT=$(grep -c "N32 MIPS64 rel2" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64R2_CNT=$(grep -c "MIPS64 rel2" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64_III_CNT=$(grep -c "64-bit.*MIPS-III" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64v1_CNT=$(grep -c "64-bit.*MIPS64 version 1" "${P99_CSV_LOG}" || true)
    lARCH_MIPS_CNT=$(grep -c "32-bit.*MIPS" "${P99_CSV_LOG}" || true)
    lARCH_ARM64_CNT=$(grep -c "ARM aarch64" "${P99_CSV_LOG}" || true)
    lARCH_ARM_CNT=$(grep -c "32-bit.*ARM" "${P99_CSV_LOG}" || true)
    if [[ "${lARCH_ARM64_CNT}" -gt 0 || "${lARCH_ARM_CNT}" -gt 0 ]]; then
      ARM_HF=$(cut -d ';' -f5 "${P99_CSV_LOG}" | grep -c "hard-float" || true)
      ARM_SF=$(cut -d ';' -f5 "${P99_CSV_LOG}" | grep -c "soft-float" || true)
    fi
    lARCH_X64_CNT=$(grep -c "x86-64" "${P99_CSV_LOG}" || true)
    lARCH_X86_CNT=$(grep -c "80386" "${P99_CSV_LOG}" || true)
    lARCH_PPC64_CNT=$(grep -c "64-bit PowerPC" "${P99_CSV_LOG}" || true)
    if [[ "${lARCH_PPC64_CNT}" -eq 0 ]]; then
      lARCH_PPC_CNT=$(grep -c "PowerPC" "${P99_CSV_LOG}" || true)
    fi
    lARCH_NIOS2_CNT=$(grep -c "Altera Nios II" "${P99_CSV_LOG}" || true)
    lARCH_RISCV_CNT=$(grep -c "UCB RISC-V" "${P99_CSV_LOG}" || true)
    lARCH_QCOM_DSP6_CNT=$(grep -c "QUALCOMM DSP6" "${P99_CSV_LOG}" || true)
    lARCH_TRICORE_CNT=$(grep -c "Tricore" "${P99_CSV_LOG}" || true)

    lD_END_BE_CNT=$(cut -d ';' -f8 "${P99_CSV_LOG}" | grep -c "MSB" || true)
    lD_END_LE_CNT=$(cut -d ';' -f8 "${P99_CSV_LOG}" | grep -c "LSB" || true)

    if [[ $((lARCH_MIPS_CNT+lARCH_ARM_CNT+lARCH_X64_CNT+lARCH_X86_CNT+lARCH_PPC_CNT+lARCH_NIOS2_CNT+lARCH_MIPS64R2_CNT+lARCH_MIPS64_III_CNT+lARCH_MIPS64_N32_CNT+lARCH_ARM64_CNT+lARCH_MIPS64v1_CNT+lARCH_RISCV_CNT+lARCH_PPC64_CNT+lARCH_QCOM_DSP6_CNT+lARCH_TRICORE_CNT)) -gt 0 ]] ; then
      print_output "$(indent "$(orange "Architecture Count")")"
      if [[ ${lARCH_MIPS_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS          ""${lARCH_MIPS_CNT}")")" ; fi
      if [[ ${lARCH_MIPS64R2_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64r2     ""${lARCH_MIPS64R2_CNT}")")" ; fi
      if [[ ${lARCH_MIPS64_III_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 III     ""${lARCH_MIPS64_III_CNT}")")" ; fi
      if [[ ${lARCH_MIPS64_N32_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 N32     ""${lARCH_MIPS64_N32_CNT}")")" ; fi
      if [[ ${lARCH_MIPS64v1_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64v1      ""${lARCH_MIPS64v1_CNT}")")" ; fi
      if [[ ${lARCH_ARM_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "ARM           ""${lARCH_ARM_CNT}")")" ; fi
      if [[ ${lARCH_ARM64_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "ARM64         ""${lARCH_ARM64_CNT}")")" ; fi
      if [[ ${lARCH_X64_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "x64           ""${lARCH_X64_CNT}")")" ; fi
      if [[ ${lARCH_X86_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "x86           ""${lARCH_X86_CNT}")")" ; fi
      if [[ ${lARCH_PPC_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "PPC           ""${lARCH_PPC_CNT}")")" ; fi
      if [[ ${lARCH_PPC64_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "PPC64         ""${lARCH_PPC64_CNT}")")" ; fi
      if [[ ${lARCH_NIOS2_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "NIOS II       ""${lARCH_NIOS2_CNT}")")" ; fi
      if [[ ${lARCH_RISCV_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "RISC-V        ""${lARCH_RISCV_CNT}")")" ; fi
      if [[ ${lARCH_QCOM_DSP6_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "Qualcom DSP6  ""${lARCH_QCOM_DSP6_CNT}")")" ; fi
      if [[ ${lARCH_TRICORE_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "Tricore       ""${lARCH_TRICORE_CNT}")")" ; fi

      if [[ ${lARCH_MIPS_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_PPC_CNT} ]] && \
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && \
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_ARM64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_RISCV_CNT} ]] && \
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && \
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS"
      elif [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_X86_CNT} ]] && \
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="ARM"
      elif [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_X86_CNT} ]] && \
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_ARM_CNT} ]] && \
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="ARM64"
      elif [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_X86_CNT} ]] && \
        [[ ${lARCH_X64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_X64_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_X64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="x64"
      elif [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_ARM_CNT} ]] && \
        [[ ${lARCH_X86_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_X86_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_X86_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="x86"
      elif [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="PPC"
      elif [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && \
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="NIOS2"
      elif [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64R2"
      elif [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64_3"
      elif [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64N32"
      elif [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64v1"
      elif [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_PPC64_CNT} ]] && \
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="RISCV"
      elif [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_RISCV_CNT} ]] && \
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="PPC64"
      elif [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_RISCV_CNT} ]] && \
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="QCOM_DSP6"
      elif [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_X64_CNT} ]] && \
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_NIOS2_CNT} ]] && \
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM64_CNT} ]] && \
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_RISCV_CNT} ]] && \
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]]; then
        D_ARCH="TRICORE"
      else
        D_ARCH="unknown"
      fi

      if [[ $((lD_END_BE_CNT+lD_END_LE_CNT)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "Endianness  Count")")"
        if [[ ${lD_END_BE_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "Big endian          ""${lD_END_BE_CNT}")")" ; fi
        if [[ ${lD_END_LE_CNT} -gt 0 ]] ; then print_output "$(indent "$(orange "Little endian          ""${lD_END_LE_CNT}")")" ; fi
      fi
      if [[ $((ARM_SF+ARM_HF)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "ARM Hardware/Software floating Count")")"
        if [[ ${ARM_SF} -gt 0 ]] ; then print_output "$(indent "$(orange "Software floating          ""${ARM_SF}")")" ; fi
        if [[ ${ARM_HF} -gt 0 ]] ; then print_output "$(indent "$(orange "Hardware floating          ""${ARM_HF}")")" ; fi
      fi

      if [[ ${lD_END_LE_CNT} -gt ${lD_END_BE_CNT} ]] ; then
        D_END="EL"
      elif [[ ${lD_END_BE_CNT} -gt ${lD_END_LE_CNT} ]] ; then
        D_END="EB"
      else
        D_END="NA"
      fi

      print_ln

      if [[ $((lD_END_BE_CNT+lD_END_LE_CNT)) -gt 0 ]] ; then
        print_output "$(indent "Detected architecture and endianness of the firmware: ""${ORANGE}""${D_ARCH}"" / ""${D_END}""${NC}")""\\n"
        export D_END
      else
        print_output "$(indent "Detected architecture of the firmware: ""${ORANGE}""${D_ARCH}""${NC}")""\\n"
      fi

      if [[ -n "${ARCH:-}" ]] ; then
        if [[ "${ARCH}" != "${D_ARCH}" ]] ; then
          print_output "[!] Your set architecture (""${ARCH}"") is different from the automatically detected one. The set architecture will be used."
        fi
      else
        print_output "[*] No architecture was enforced, so the automatically detected one is used." "no_log"
        export ARCH=""
        ARCH="${D_ARCH}"
      fi
    elif [[ -n "${EFI_ARCH}" ]]; then
      print_output "$(indent "Detected architecture of the UEFI firmware: ""${ORANGE}""${EFI_ARCH}""${NC}")""\\n"
      export ARCH=""
      ARCH="${EFI_ARCH}"
    else
      print_output "$(indent "$(red "Based on binary identification no architecture was detected.")")"
      if [[ -n "${ARCH}" ]] ; then
        print_output "[*] Manually enforced architecture (""${ARCH}"") will be used."
      fi
    fi
    backup_var "ARCH" "${ARCH}"
    backup_var "D_END" "${D_END}"

  else
    print_output "[*] Architecture auto detection disabled\\n"
    if [[ -n "${ARCH}" ]] ; then
      print_output "[*] Manually enforced architecture (""${ARCH}"") will be used."
    else
      print_output "[!] Since no architecture could be detected, you should set one."
    fi
  fi
}

prepare_all_file_arrays() {
  local lFIRMWARE_PATH="${1:-}"
  echo ""
  print_output "[*] Auto detection of all files with further details for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"
  export ALL_FILES_ARR=()

  # we exclude all the raw files from binwalk
  # readarray -t ALL_FILES_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f ! -name "*.raw")
  readarray -t ALL_FILES_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}" | grep -v "\.raw$")

  # RTOS handling:
  if [[ -f ${lFIRMWARE_PATH} && ${RTOS} -eq 1 ]]; then
    # local lFILE_ARR_RTOS=()
    # readarray -t lFILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f)
    # ALL_FILES_ARR+=( "${lFILE_ARR_RTOS[@]}" )
    ALL_FILES_ARR+=( "${lFIRMWARE_PATH}" )
  fi
}

prepare_file_arr() {
  local lFIRMWARE_PATH="${1:-}"
  echo ""
  print_output "[*] Unique files auto detection for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"

  export FILE_ARR=()
  # readarray -t FILE_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" || true' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- || true)
  # readarray -t FILE_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3- )
  readarray -t FILE_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}"| grep -v "\.raw$" || true)
  # RTOS handling:
  if [[ -f ${lFIRMWARE_PATH} && ${RTOS} -eq 1 ]]; then
    # readarray -t FILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3- )
    # readarray -t FILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" || true' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
    # FILE_ARR+=( "${FILE_ARR_RTOS[@]}" )
    FILE_ARR+=( "${lFIRMWARE_PATH}" )
  fi
  print_output "[*] Found ${ORANGE}${#FILE_ARR[@]}${NC} unique files."

  # xdev will do the trick for us:
  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${FILE_ARR[@]}"
}

prepare_binary_arr() {
  local lFIRMWARE_PATH="${1:-}"
  if ! [[ -d "${lFIRMWARE_PATH}" ]]; then
    return
  fi
  echo ""
  print_output "[*] Unique binary auto detection for ${ORANGE}${lFIRMWARE_PATH}${NC} (could take some time)\\n"

  # lets try to get an unique binary array
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES=()
  local lBINARIES_TMP_ARR=()
  local lBINARY=""
  local lBIN_MD5=""
  local lMD5_DONE_INT_ARR=()
  # readarray -t BINARIES < <( find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # In some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  # readarray -t lBINARIES_TMP_ARR < <(find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -exec file {} \; grep "ELF\|PE32" | cut -d: -f1 || true)
  # readarray -t lBINARIES_TMP_ARR < <(find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file %' | grep "ELF\|PE32" | cut -d: -f1 2>/dev/null || true)
  readarray -t lBINARIES_TMP_ARR < <(grep ";ELF\|;PE32" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)
  if [[ "${#lBINARIES_TMP_ARR[@]}" -gt 0 ]]; then
    for lBINARY in "${lBINARIES_TMP_ARR[@]}"; do
      if [[ -f "${lBINARY}" ]]; then
        lBIN_MD5=$(md5sum "${lBINARY}" | cut -d\  -f1)
        if [[ ! " ${lMD5_DONE_INT_ARR[*]} " =~ ${lBIN_MD5} ]]; then
          BINARIES+=( "${lBINARY}" )
          lMD5_DONE_INT_ARR+=( "${lBIN_MD5}" )
        fi
      fi
    done
    print_output "[*] Found ${ORANGE}${#BINARIES[@]}${NC} unique executables."
  fi

  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${BINARIES[@]}"
}

prepare_file_arr_limited() {
  local lFIRMWARE_PATH="${1:-}"
  export FILE_ARR_LIMITED=()

  if ! [[ -d "${lFIRMWARE_PATH}" ]]; then
    return
  fi

  echo ""
  print_output "[*] Unique and limited file array generation for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"

  # readarray -t FILE_ARR_LIMITED < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
  #  -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
  #  -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" -o -iname "*.png" -o -iname "*.svg" \
  #  -o -iname "*.js" -o -iname "*.info" -o -iname "*.md" -o -iname "*.log" -o -iname "*.yml" -o -iname "*.bmp" -o -path "*/\.git/*" \) \
  #  -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3-)

  readarray -t FILE_ARR_LIMITED < <(cut -d ';' -f2 "${P99_CSV_LOG}" | grep -v "\.udeb$\|\.deb$\|\.ipk$\|\.pdf$\\|\.php$\|\.txt$\|\.doc$\|\.rtf$\|\.docx\|\.htm$\|\.md5$\|\..sha1$\|\.torrent$\|\.png$\|\.svg$\|\.js$\|\.info$\|\.md$\|\.log$\|\.yml$\|\.bmp$\|\.git\/" | sort -u || true)

}

set_etc_paths()
{
  # For the case if ./etc isn't in root of provided firmware or is renamed like e.g. ./etc-ro:
  # search etc paths
  # set them in ETC_PATHS variable
  # If another variable needs a "Extrawurst", you only need to copy 'set_etc_path' function, modify it and change
  # 'mod_path' for project wide path modification
  export ETC_PATHS
  set_etc_path
  print_etc
}

check_firmware() {
  # this detection is only running if we have not found a Linux system:
  local lDIR_COUNT=0
  local lR_PATH=""
  local lL_PATH=""

  if [[ "${RTOS}" -eq 1 ]]; then
    # Check if firmware got normal linux directory structure and warn if not
    # as we already have done some root directory detection we are going to use it now
    local lLINUX_PATHS_ARR=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
    if [[ ${#ROOT_PATH[@]} -gt 0 ]]; then
      for lR_PATH in "${ROOT_PATH[@]}"; do
        for lL_PATH in "${lLINUX_PATHS_ARR[@]}"; do
          if [[ -d "${lR_PATH}"/"${lL_PATH}" ]] ; then
            ((lDIR_COUNT+=1))
          fi
        done
      done
    else
      # this is needed for directories we are testing
      # in such a case the pre-checking modules are not executed and no RPATH is available
      for lL_PATH in "${lLINUX_PATHS_ARR[@]}"; do
        if [[ -d "${FIRMWARE_PATH}"/"${lL_PATH}" ]] ; then
          ((lDIR_COUNT+=1))
        fi
      done
    fi
  fi

  if [[ ${lDIR_COUNT} -lt 5 ]] && [[ "${RTOS}" -eq 1 ]]; then
    print_output "[-] Your firmware does not look like a regular Linux system."
  fi
  if [[ "${RTOS}" -eq 0 ]] || [[ ${lDIR_COUNT} -gt 4 ]]; then
    print_output "[+] Your firmware looks like a regular Linux system."
  fi
}

detect_root_dir_helper() {
  local lSEARCH_PATH="${1:-}"

  print_output "[*] Root directory auto detection for ${ORANGE}${lSEARCH_PATH}${NC} (could take some time)\\n"
  export ROOT_PATH=()
  local lMECHANISM=""
  local lROOTx_PATH_ARR=()
  local lINTERPRETER_FULL_PATH_ARR=()
  local lINTERPRETER_PATH=""
  local lINTERPRETER_FULL_RPATH_ARR=()
  local lR_PATH=""
  local lINTERPRETER_ESCAPED=""
  local lCNT=0

  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] No ${P99_CSV_LOG} log file created ... no root directory detection possible"
    return
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 0 ]]; then
    # xargs threading is much faster. Big testcase firmware 9mins vs. 3mins
    # mapfile -t lINTERPRETER_FULL_PATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file -b % 2>/dev/null' | grep "ELF.*interpreter /" | sed "s/.*interpreter\ //" | sed "s/,\ .*$//" | sort -u || true)
    mapfile -t lINTERPRETER_FULL_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | cut -d ';' -f8 | grep "ELF.*interpreter /" | sed "s/.*interpreter\ //" | sed "s/,\ .*$//" | sort -u || true)

    if [[ "${#lINTERPRETER_FULL_PATH_ARR[@]}" -gt 0 ]]; then
      for lINTERPRETER_PATH in "${lINTERPRETER_FULL_PATH_ARR[@]}"; do
        # now we have a result like this "/lib/ld-uClibc.so.0"
        # lets escape it
        lINTERPRETER_ESCAPED=$(echo "${lINTERPRETER_PATH}" | sed -e 's/\//\\\//g')
        # mapfile -t lINTERPRETER_FULL_RPATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -wholename "*${lINTERPRETER_PATH}" 2>/dev/null | sort -u)
        mapfile -t lINTERPRETER_FULL_RPATH_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}" 2>/dev/null | grep "${lINTERPRETER_PATH}" | sort -u || true)
        for lR_PATH in "${lINTERPRETER_FULL_RPATH_ARR[@]}"; do
          # remove the interpreter path from the full path:
          lR_PATH="${lR_PATH//${lINTERPRETER_ESCAPED}/}"
          # common false positive:
          if [[ -v lR_PATH ]] && [[ -d "${lR_PATH}" ]]; then
            [[ "${lR_PATH}" =~ \/lib\/$ ]] && continue
            ROOT_PATH+=( "${lR_PATH}" )
            lMECHANISM="binary interpreter"
          fi
        done
      done
    fi

    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/busybox" | sed -E 's/\/.?bin\/busybox//')
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/busybox" | cut -d ';' -f2 | sed -E 's/\/.?bin\/busybox.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=( "${lR_PATH}" )
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="busybox"
        elif [[ -n "${lMECHANISM}" ]] && ! echo "${lMECHANISM}" | grep -q "busybox"; then
          lMECHANISM="${lMECHANISM} / busybox"
        fi
      fi
    done
    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/bash" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/bash//' || true)
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/bash" | cut -d ';' -f2 | sed -E 's/\/.?bin\/bash.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=( "${lR_PATH}" )
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="shell"
        elif [[ -n "${lMECHANISM}" ]] && ! echo "${lMECHANISM}" | grep -q "shell"; then
          lMECHANISM="${lMECHANISM} / shell"
        fi
      fi
    done
    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/sh" -print0|xargs -r -0 -P 16 -I % sh -c 'file % | grep "ELF" | cut -d: -f1 | sed -E "s/\/.?bin\/sh//"' || true)
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/sh" | cut -d ';' -f2 | sed -E 's/\/.?bin\/sh.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=( "${lR_PATH}" )
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="shell"
        elif [[ -n "${lMECHANISM}" ]] && ! echo "${lMECHANISM}" | grep -q "shell"; then
          lMECHANISM="${lMECHANISM} / shell"
        fi
      fi
    done
  fi

  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev \( -path "*/sbin" -o -path "*/bin" -o -path "*/lib" -o -path "*/etc" -o -path "*/root" -o -path "*/dev" -o -path "*/opt" -o -path "*/proc" -o -path "*/lib64" -o -path "*/boot" -o -path "*/home" \) -exec dirname {} \; | sort | uniq -c | sort -r)
  # currently not working: mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "/bin/\|/lib/\|/etc/\|/root/\|/dev/\|/opt/\|/proc/\|/lib64\|/boot/\|/home/" | cut -d ';' -f2 | grep "${lSEARCH_PATH}" | sort -u || true)
  for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
    lCNT=$(echo "${lR_PATH}" | awk '{print $1}')
    if [[ "${lCNT}" -lt 5 ]]; then
      # we only use paths with more then 4 matches as possible root path
      continue
    fi
    lR_PATH=$(echo "${lR_PATH}" | awk '{print $2}')
    if [[ -d "${lR_PATH}" ]]; then
      ROOT_PATH+=( "${lR_PATH}" )
      if [[ -z "${lMECHANISM}" ]]; then
        lMECHANISM="dir names"
      elif [[ -n "${lMECHANISM}" ]] && ! echo "${lMECHANISM}" | grep -q "dir names"; then
        lMECHANISM="${lMECHANISM} / dir names"
      fi
    fi
  done

  if [[ ${#ROOT_PATH[@]} -eq 0 ]]; then
    export RTOS=1
    ROOT_PATH+=( "${lSEARCH_PATH}" )
    lMECHANISM="last resort"
  else
    export RTOS=0
  fi

  eval "ROOT_PATH=($(for i in "${ROOT_PATH[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
  if [[ -v ROOT_PATH[@] && "${RTOS}" -eq 0 ]]; then
    print_output "[*] Found ${ORANGE}${#ROOT_PATH[@]}${NC} different root directories:"
    write_link "s05#file_dirs"
  fi

  for lR_PATH in "${ROOT_PATH[@]}"; do
    if [[ "${lMECHANISM}" == "last resort" ]]; then
      print_output "[*] Found no real root directory - setting it to: ${ORANGE}${lR_PATH}${NC} via ${ORANGE}${lMECHANISM}${NC}."
    else
      print_output "[+] Found the following root directory: ${ORANGE}${lR_PATH}${GREEN} via ${ORANGE}${lMECHANISM}${GREEN}."
    fi
    write_link "s05#file_dirs"
  done
}

check_init_size() {
  local lSIZE=""

  lSIZE=$(du -b --max-depth=0 "${FIRMWARE_PATH}"| awk '{print $1}' || true)
  if [[ ${lSIZE} -gt 400000000 ]]; then
    print_ln "no_log"
    print_output "[!] WARNING: Your firmware is very big!" "no_log"
    print_output "[!] WARNING: Analysing huge firmwares will take a lot of disk space, RAM and time!" "no_log"
    print_ln "no_log"
  fi
}

