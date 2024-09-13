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
    export RESTART=0          # indicator for testing unfinished tests again
    local NOT_FINISHED=0      # identify unfinished firmware tests
    local POSSIBLE_RESTART=0  # used for testing the checksums of the firmware with stored checksum
    local ANSWER="n"
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
        NOT_FINISHED=1
      elif grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}testing phase${NC} already finished" "no_log"
        NOT_FINISHED=1
      elif grep -q "Pre-checking phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}pre-checking phase${NC} already finished" "no_log"
        NOT_FINISHED=1
      else
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory" "no_log"
        NOT_FINISHED=1
      fi
    fi

    # we check the found sha512 hash with the firmware to test:
    if [[ -f "${CSV_DIR}"/p02_firmware_bin_file_check.csv ]] && [[ -f "${FIRMWARE_PATH}" ]] && grep -q "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv; then
      lSTORED_SHA512=$(grep "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv | cut -d\; -f2 | sort -u)
      lFW_SHA512=$(sha512sum "${FIRMWARE_PATH}" | awk '{print $1}')
      if [[ "${lSTORED_SHA512}" == "${lFW_SHA512}" ]]; then
        # the found analysis is for the same firmware
        POSSIBLE_RESTART=1
      fi
    fi
    echo -e "\\n${ORANGE}Delete content of log directory: ${LOG_DIR} ?${NC}\\n"
    if [[ "${NOT_FINISHED}" -eq 1 ]] && [[ "${POSSIBLE_RESTART}" -eq 1 ]]; then
      print_output "[*] If you answer with ${ORANGE}n${NC}o, EMBA tries to process the unfinished test${NC}" "no_log"
    fi

    if [[ ${OVERWRITE_LOG} -eq 1 ]] ; then
      ANSWER="y"
    else
      read -p "(Y/n)  " -r ANSWER
    fi
    case ${ANSWER:0:1} in
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
            echo -e "\\n${GREEN}Sucessfully deleted: ${ORANGE}${LOG_DIR}${NC}\\n"
          fi
        ;;
        n|N )
          if [[ "${NOT_FINISHED}" -eq 1 ]] && [[ -f "${LOG_DIR}"/backup_vars.log ]] && [[ "${POSSIBLE_RESTART}" -eq 1 ]]; then
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
    read -p "(Y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
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

architecture_check() {
  if [[ ${ARCH_CHECK} -eq 1 ]] ; then
    print_output "[*] Architecture auto detection (could take some time)\\n"
    local ARCH_MIPS=0
    local ARCH_ARM=0
    local ARCH_ARM64=0
    local ARCH_X64=0
    local ARCH_X86=0
    local ARCH_PPC=0
    local ARCH_NIOS2=0
    local ARCH_MIPS64R2=0
    local ARCH_MIPS64_III=0
    local ARCH_MIPS64v1=0
    local ARCH_MIPS64_N32=0
    local ARCH_RISCV=0
    local ARCH_PPC64=0
    local ARCH_QCOM_DSP6=0
    local D_END_LE=0
    local D_END_BE=0
    local D_FLAGS=""
    local D_MACHINE=""
    local D_CLASS=""
    local D_DATA=""
    local D_ARCH_GUESSED=""
    local MD5SUM=""
    export ARM_HF=0
    export ARM_SF=0
    export D_END="NA"
    local BINARY=""

    write_csv_log "BINARY" "BINARY_CLASS" "END_DATA" "MACHINE-TYPE" "BINARY_FLAGS" "ARCH_GUESSED" "ELF-DATA" "MD5SUM"
    # we use the binaries array which is already unique
    for BINARY in "${BINARIES[@]}" ; do
      # noreorder, pic, cpic, o32, mips32
      D_FLAGS=$(readelf -h "${BINARY}" 2>/dev/null | grep "Flags:" || true)
      D_FLAGS="${D_FLAGS// /}"
      D_FLAGS="${D_FLAGS/*Flags:/}"
      D_FLAGS="${D_FLAGS/0x0/}"
      D_MACHINE=$(readelf -h "${BINARY}" 2>/dev/null | grep "Machine:" 2>/dev/null || true)
      D_MACHINE="${D_MACHINE/*Machine:/}"
      D_MACHINE=$(echo "${D_MACHINE}" | sed -E 's/^[[:space:]]+//')
      # ELF32/64
      D_CLASS=$(readelf -h "${BINARY}" 2>/dev/null | grep "Class" || true)
      D_CLASS="${D_CLASS/*Class:/}"
      D_CLASS=$(echo "${D_CLASS}" | sed -E 's/^[[:space:]]+//')
      # endianes
      D_DATA=$(readelf -h "${BINARY}" 2>/dev/null | grep "Data" || true)
      D_DATA="${D_DATA/*Data:/}"
      D_DATA=$(echo "${D_DATA}" | sed -E 's/^[[:space:]]+//')

      D_ARCH_GUESSED=$(readelf -p .comment "${BINARY}" 2>/dev/null| grep -v "String dump" | awk '{print $3,$4,$5}' | sort -u | tr '\n' ',' || true)
      D_ARCH_GUESSED="${D_ARCH_GUESSED%%,/}"
      D_ARCH_GUESSED="${D_ARCH_GUESSED##,/}"

      D_ARCH=$(file -b "${BINARY}")

      MD5SUM="$(md5sum "${BINARY}" || print_output "[-] Checksum error for binary ${BINARY}" "no_log")"
      MD5SUM="${MD5SUM/\ *}"

      if [[ "${D_ARCH}" == *"MSB"* ]] ; then
        D_END_BE=$((D_END_BE+1))
      elif [[ "${D_ARCH}" == *"LSB"* ]] ; then
        D_END_LE=$((D_END_LE+1))
      fi
      write_csv_log "${BINARY}" "${D_CLASS}" "${D_DATA}" "${D_MACHINE}" "${D_FLAGS}" "${D_ARCH_GUESSED}" "${D_ARCH}" "${MD5SUM}"

      if [[ "${D_ARCH}" == *"N32 MIPS64 rel2"* ]] ; then
        # ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2 version 1
        ARCH_MIPS64_N32=$((ARCH_MIPS64_N32+1))
        continue
      elif [[ "${D_ARCH}" == *"MIPS64 rel2"* ]] ; then
        ARCH_MIPS64R2=$((ARCH_MIPS64R2+1))
        continue
      elif [[ "${D_ARCH}" == *"64-bit"*"MIPS-III"* ]] ; then
        ARCH_MIPS64_III=$((ARCH_MIPS64_III+1))
        continue
      elif [[ "${D_ARCH}" == *"64-bit"*"MIPS64 version 1"* ]] ; then
        ARCH_MIPS64v1=$((ARCH_MIPS64v1+1))
        continue
      elif [[ "${D_ARCH}" == *"MIPS"* ]] ; then
        ARCH_MIPS=$((ARCH_MIPS+1))
        continue
      elif [[ "${D_ARCH}" == *"ARM"* ]] ; then
        if [[ "${D_ARCH}" == *"ARM aarch64"* ]] ; then
          ARCH_ARM64=$((ARCH_ARM64+1))
        else
          ARCH_ARM=$((ARCH_ARM+1))
        fi
        if [[ "${D_FLAGS}" == *"hard-float"* ]]; then
          ARM_HF=$((ARM_HF+1))
        fi
        if [[ "${D_FLAGS}" == *"soft-float"* ]]; then
          ARM_SF=$((ARM_SF+1))
        fi
        continue
      elif [[ "${D_ARCH}" == *"x86-64"* ]] ; then
        ARCH_X64=$((ARCH_X64+1))
        continue
      elif [[ "${D_ARCH}" == *"80386"* ]] ; then
        ARCH_X86=$((ARCH_X86+1))
        continue
      elif [[ "${D_ARCH}" == *"64-bit PowerPC"* ]] ; then
        ARCH_PPC64=$((ARCH_PPC64+1))
        continue
      elif [[ "${D_ARCH}" == *"PowerPC"* ]] ; then
        ARCH_PPC=$((ARCH_PPC+1))
        continue
      elif [[ "${D_ARCH}" == *"Altera Nios II"* ]] ; then
        ARCH_NIOS2=$((ARCH_NIOS2+1))
        continue
      elif [[ "${D_ARCH}" == *"UCB RISC-V"* ]] ; then
        ARCH_RISCV=$((ARCH_RISCV+1))
        continue
      elif [[ "${D_ARCH}" == *"QUALCOMM DSP6"* ]] ; then
        ARCH_QCOM_DSP6=$((ARCH_QCOM_DSP6+1))
        continue
      fi
    done

    if [[ $((ARCH_MIPS+ARCH_ARM+ARCH_X64+ARCH_X86+ARCH_PPC+ARCH_NIOS2+ARCH_MIPS64R2+ARCH_MIPS64_III+ARCH_MIPS64_N32+ARCH_ARM64+ARCH_MIPS64v1+ARCH_RISCV+ARCH_PPC64+ARCH_QCOM_DSP6)) -gt 0 ]] ; then
      print_output "$(indent "$(orange "Architecture  Count")")"
      if [[ ${ARCH_MIPS} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS          ""${ARCH_MIPS}")")" ; fi
      if [[ ${ARCH_MIPS64R2} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64r2     ""${ARCH_MIPS64R2}")")" ; fi
      if [[ ${ARCH_MIPS64_III} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 III     ""${ARCH_MIPS64_III}")")" ; fi
      if [[ ${ARCH_MIPS64_N32} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 N32     ""${ARCH_MIPS64_N32}")")" ; fi
      if [[ ${ARCH_MIPS64v1} -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64v1      ""${ARCH_MIPS64v1}}")")" ; fi
      if [[ ${ARCH_ARM} -gt 0 ]] ; then print_output "$(indent "$(orange "ARM           ""${ARCH_ARM}")")" ; fi
      if [[ ${ARCH_ARM64} -gt 0 ]] ; then print_output "$(indent "$(orange "ARM64         ""${ARCH_ARM64}")")" ; fi
      if [[ ${ARCH_X64} -gt 0 ]] ; then print_output "$(indent "$(orange "x64           ""${ARCH_X64}")")" ; fi
      if [[ ${ARCH_X86} -gt 0 ]] ; then print_output "$(indent "$(orange "x86           ""${ARCH_X86}")")" ; fi
      if [[ ${ARCH_PPC} -gt 0 ]] ; then print_output "$(indent "$(orange "PPC           ""${ARCH_PPC}")")" ; fi
      if [[ ${ARCH_PPC} -gt 0 ]] ; then print_output "$(indent "$(orange "PPC64         ""${ARCH_PPC64}")")" ; fi
      if [[ ${ARCH_NIOS2} -gt 0 ]] ; then print_output "$(indent "$(orange "NIOS II       ""${ARCH_NIOS2}")")" ; fi
      if [[ ${ARCH_RISCV} -gt 0 ]] ; then print_output "$(indent "$(orange "RISC-V        ""${ARCH_RISCV}")")" ; fi
      if [[ ${ARCH_QCOM_DSP6} -gt 0 ]] ; then print_output "$(indent "$(orange "Qualcom DSP6  ""${ARCH_QCOM_DSP6}")")" ; fi

      if [[ ${ARCH_MIPS} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_X64} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_X86} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_PPC} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_MIPS} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_MIPS} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_MIPS} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="MIPS"
      elif [[ ${ARCH_ARM} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_ARM} -gt ${ARCH_X64} ]] && [[ ${ARCH_ARM} -gt ${ARCH_X86} ]] && [[ ${ARCH_ARM} -gt ${ARCH_PPC} ]] && [[ ${ARCH_ARM} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_ARM} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_ARM} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_ARM} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_ARM} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_ARM} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_ARM} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_ARM} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_ARM} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="ARM"
      elif [[ ${ARCH_ARM64} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_X64} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_X86} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_PPC} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_ARM64} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_ARM} ]] && \
        [[ ${ARCH_ARM64} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_ARM64} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="ARM64"
      elif [[ ${ARCH_X64} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_X64} -gt ${ARCH_ARM} ]] && [[ ${ARCH_X64} -gt ${ARCH_X86} ]] && [[ ${ARCH_X64} -gt ${ARCH_PPC} ]] && [[ ${ARCH_X64} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_X64} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_X64} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_X64} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_X64} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_X64} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_X64} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_X64} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_X64} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="x64"
      elif [[ ${ARCH_X86} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_X86} -gt ${ARCH_X64} ]] && [[ ${ARCH_X86} -gt ${ARCH_ARM} ]] && [[ ${ARCH_X86} -gt ${ARCH_PPC} ]] && [[ ${ARCH_X86} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_X86} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_X86} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_X86} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_X86} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_X86} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_X86} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_X86} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_X86} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="x86"
      elif [[ ${ARCH_PPC} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_PPC} -gt ${ARCH_ARM} ]] && [[ ${ARCH_PPC} -gt ${ARCH_X64} ]] && [[ ${ARCH_PPC} -gt ${ARCH_X86} ]] && [[ ${ARCH_PPC} -gt ${ARCH_NIOS2} ]] && \
        [[ ${ARCH_PPC} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_PPC} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_PPC} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_PPC} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_PPC} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_PPC} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_PPC} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_PPC} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="PPC"
      elif [[ ${ARCH_NIOS2} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_ARM} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_X64} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_X86} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_NIOS2} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_NIOS2} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_NIOS2} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="NIOS2"
      elif [[ ${ARCH_MIPS64R2} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_X64} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_X86} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_MIPS64R2} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_MIPS64_III} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_MIPS64R2} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_MIPS64R2} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="MIPS64R2"
      elif [[ ${ARCH_MIPS64_III} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_X64} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_X86} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_MIPS64_III} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_MIPS64_III} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_MIPS64_III} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="MIPS64_3"
      elif [[ ${ARCH_MIPS64_N32} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_X64} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_X86} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_MIPS64_N32} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_MIPS64_N32} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_MIPS64_N32} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="MIPS64N32"
      elif [[ ${ARCH_MIPS64v1} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_X64} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_X86} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_MIPS64v1} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_ARM} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_MIPS64v1} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_MIPS64v1} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="MIPS64v1"
      elif [[ ${ARCH_RISCV} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_ARM} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_X64} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_X86} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_RISCV} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_ARM} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_RISCV} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_PPC64} ]] && [[ ${ARCH_RISCV} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="RISCV"
      elif [[ ${ARCH_PPC64} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_ARM} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_X64} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_X86} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_PPC64} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_ARM} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_PPC64} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_PPC64} -gt ${ARCH_QCOM_DSP6} ]]; then
        D_ARCH="PPC64"
      elif [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_MIPS} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_ARM} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_X64} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_X86} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_PPC} ]] && \
        [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_NIOS2} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_MIPS64R2} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_ARM} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_ARM64} ]] && \
        [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_MIPS64_N32} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_MIPS64v1} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_RISCV} ]] && [[ ${ARCH_QCOM_DSP6} -gt ${ARCH_PPC64} ]]; then
        D_ARCH="QCOM_DSP6"
      else
        D_ARCH="unknown"
      fi

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "Endianness  Count")")"
        if [[ ${D_END_BE} -gt 0 ]] ; then print_output "$(indent "$(orange "Big endian          ""${D_END_BE}")")" ; fi
        if [[ ${D_END_LE} -gt 0 ]] ; then print_output "$(indent "$(orange "Little endian          ""${D_END_LE}")")" ; fi
      fi
      if [[ $((ARM_SF+ARM_HF)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "ARM Hardware/Software floating Count")")"
        if [[ ${ARM_SF} -gt 0 ]] ; then print_output "$(indent "$(orange "Software floating          ""${ARM_SF}")")" ; fi
        if [[ ${ARM_HF} -gt 0 ]] ; then print_output "$(indent "$(orange "Hardware floating          ""${ARM_HF}")")" ; fi
      fi

      if [[ ${D_END_LE} -gt ${D_END_BE} ]] ; then
        D_END="EL"
      elif [[ ${D_END_BE} -gt ${D_END_LE} ]] ; then
        D_END="EB"
      else
        D_END="NA"
      fi

      print_ln

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
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
        print_output "[*] Your set architecture (""${ARCH}"") will be used."
      fi
    fi
    backup_var "ARCH" "${ARCH}"
    backup_var "D_END" "${D_END}"

  else
    print_output "[*] Architecture auto detection disabled\\n"
    if [[ -n "${ARCH}" ]] ; then
      print_output "[*] Your set architecture (""${ARCH}"") will be used."
    else
      print_output "[!] Since no architecture could be detected, you should set one."
    fi
  fi
}

prepare_file_arr()
{
  echo ""
  print_output "[*] Unique files auto detection for ${ORANGE}${FIRMWARE_PATH}${NC} (could take some time)\\n"

  export FILE_ARR=()
  readarray -t FILE_ARR < <(find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
  # RTOS handling:
  if [[ -f ${FIRMWARE_PATH} && ${RTOS} -eq 1 ]]; then
    readarray -t FILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
    FILE_ARR+=( "${FILE_ARR_RTOS[@]}" )
    FILE_ARR+=( "${FIRMWARE_PATH}" )
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
  local MD5_DONE_INT=()
  # readarray -t BINARIES < <( find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # In some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  readarray -t lBINARIES_TMP_ARR < <(find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -exec file {} \; 2>/dev/null | grep ELF | cut -d: -f1 || true)
  if [[ -v lBINARIES_TMP_ARR[@] ]]; then
    for lBINARY in "${lBINARIES_TMP_ARR[@]}"; do
      if [[ -f "${lBINARY}" ]]; then
        lBIN_MD5=$(md5sum "${lBINARY}" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${lBIN_MD5} ]]; then
          BINARIES+=( "${lBINARY}" )
          MD5_DONE_INT+=( "${lBIN_MD5}" )
        fi
      fi
    done
    print_output "[*] Found ${ORANGE}${#BINARIES[@]}${NC} unique executables."
  fi

  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${BINARIES[@]}"
}

prepare_file_arr_limited() {
  local FIRMWARE_PATH="${1:-}"
  export FILE_ARR_LIMITED=()

  if ! [[ -d "${FIRMWARE_PATH}" ]]; then
    return
  fi

  echo ""
  print_output "[*] Unique and limited file array generation for ${ORANGE}${FIRMWARE_PATH}${NC} (could take some time)\\n"

  readarray -t FILE_ARR_LIMITED < <(find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
    -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
    -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" -o -iname "*.png" -o -iname "*.svg" \
    -o -iname "*.js" -o -iname "*.info" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3-)
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
    local LINUX_PATHS=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
    if [[ ${#ROOT_PATH[@]} -gt 0 ]]; then
      for lR_PATH in "${ROOT_PATH[@]}"; do
        for lL_PATH in "${LINUX_PATHS[@]}"; do
          if [[ -d "${lR_PATH}"/"${lL_PATH}" ]] ; then
            ((lDIR_COUNT+=1))
          fi
        done
      done
    else
      # this is needed for directories we are testing
      # in such a case the pre-checking modules are not executed and no RPATH is available
      for lL_PATH in "${LINUX_PATHS[@]}"; do
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

  mapfile -t lINTERPRETER_FULL_PATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -type f -exec file {} \; 2>/dev/null | grep "ELF" | grep "interpreter" | sed s/.*interpreter\ // | sed 's/,\ .*$//' | sort -u 2>/dev/null || true)

  if [[ "${#lINTERPRETER_FULL_PATH_ARR[@]}" -gt 0 ]]; then
    for lINTERPRETER_PATH in "${lINTERPRETER_FULL_PATH_ARR[@]}"; do
      # now we have a result like this "/lib/ld-uClibc.so.0"
      # lets escape it
      lINTERPRETER_ESCAPED=$(echo "${lINTERPRETER_PATH}" | sed -e 's/\//\\\//g')
      mapfile -t lINTERPRETER_FULL_RPATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -wholename "*${lINTERPRETER_PATH}" 2>/dev/null | sort -u)
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

  # if we can't find the interpreter we fall back to a search for something like "*root/bin/* and take this:
  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev \( -path "*extracted/bin" -o -path "*root/bin" \) -exec dirname {} \; 2>/dev/null)
  for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
    if [[ -d "${lR_PATH}" ]]; then
      ROOT_PATH+=( "${lR_PATH}" )
      if [[ -z "${lMECHANISM}" ]]; then
        lMECHANISM="dir names"
      elif [[ -n "${lMECHANISM}" ]] && ! echo "${lMECHANISM}" | grep -q "dir names"; then
        lMECHANISM="${lMECHANISM} / dir names"
      fi
    fi
  done

  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev \( -path "*/sbin" -o -path "*/bin" -o -path "*/lib" -o -path "*/etc" -o -path "*/root" -o -path "*/dev" -o -path "*/opt" -o -path "*/proc" -o -path "*/lib64" -o -path "*/boot" -o -path "*/home" \) -exec dirname {} \; | sort | uniq -c | sort -r)
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

  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/busybox" | sed -E 's/\/.?bin\/busybox//')
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

  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/bash" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/bash//' || true)
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

  mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/sh" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/sh//' || true)
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

