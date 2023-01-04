#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
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

log_folder()
{
  if [[ $ONLY_DEP -eq 0 ]] && [[ -d "$LOG_DIR" ]] ; then
    export RESTART=0          # indicator for testing unfinished tests again
    local NOT_FINISHED=0      # identify unfinished firmware tests
    local POSSIBLE_RESTART=0  # used for testing the checksums of the firmware with stored checksum

    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    There are files in the specified directory: ""$LOG_DIR""\\n    You can now delete the content here or start the tool again and specify a different directory."

    if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
      if grep -q "Test ended" "$LOG_DIR"/"$MAIN_LOG_FILE"; then
        print_output "[*] A finished EMBA firmware test was found in the log directory" "no_log"
      elif grep -q "System emulation phase ended" "$LOG_DIR"/"$MAIN_LOG_FILE"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}system emulation phase${NC} already finished" "no_log"
        NOT_FINISHED=1
      elif grep -q "Testing phase ended" "$LOG_DIR"/"$MAIN_LOG_FILE"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}testing phase${NC} already finished" "no_log"
        NOT_FINISHED=1
      elif grep -q "Pre-checking phase ended" "$LOG_DIR"/"$MAIN_LOG_FILE"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}pre-checking phase${NC} already finished" "no_log"
        NOT_FINISHED=1
      else
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory" "no_log"
        NOT_FINISHED=1
      fi
    fi

    # we check the found sha512 hash with the firmware to test:
    if [[ -f "$CSV_DIR"/p02_firmware_bin_file_check.csv ]] && [[ -f "$FIRMWARE_PATH" ]] && grep -q "SHA512" "$CSV_DIR"/p02_firmware_bin_file_check.csv; then
      STORED_SHA512=$(grep "SHA512" "$CSV_DIR"/p02_firmware_bin_file_check.csv | cut -d\; -f2)
      FW_SHA512=$(sha512sum "$FIRMWARE_PATH" | awk '{print $1}')
      if [[ "$STORED_SHA512" == "$FW_SHA512" ]]; then
        # the found analysis is for the same firmware
        POSSIBLE_RESTART=1
      fi
    fi
    echo -e "\\n${ORANGE}Delete content of log directory: $LOG_DIR ?${NC}\\n"
    if [[ "$NOT_FINISHED" -eq 1 ]] && [[ "$POSSIBLE_RESTART" -eq 1 ]]; then
      print_output "[*] If you answer with ${ORANGE}n${NC}o, EMBA tries to process the unfinished test${NC}" "no_log"
    fi

    if [[ $OVERWRITE_LOG -eq 1 ]] ; then
      ANSWER="y"
    else
      read -p "(Y/n)  " -r ANSWER
    fi
    case ${ANSWER:0:1} in
        y|Y|"" )
          if mount | grep "$LOG_DIR" | grep -e "proc\|sys\|run" > /dev/null; then
            print_ln "no_log"
            print_output "[!] We found unmounted areas from a former emulation process in your log directory $LOG_DIR." "no_log"
            print_output "[!] You should unmount this stuff manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
            echo -e "\\n${RED}Terminate EMBA${NC}\\n"
            exit 1
          elif mount | grep "$LOG_DIR" > /dev/null; then
            print_ln "no_log"
            print_output "[!] We found unmounted areas in your log directory $LOG_DIR." "no_log"
            print_output "[!] If EMBA is failing check this manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
          else
            rm -R "${LOG_DIR:?}/"* 2>/dev/null || true
            echo -e "\\n${GREEN}Sucessfully deleted: $ORANGE$LOG_DIR${NC}\\n"
          fi
        ;;
        n|N )
          if [[ "$NOT_FINISHED" -eq 1 ]] && [[ -f "$LOG_DIR"/backup_vars.log ]] && [[ "$POSSIBLE_RESTART" -eq 1 ]]; then
            print_output "[*] EMBA tries to process the unfinished test" "no_log"
            if ! [[ -d "$TMP_DIR" ]]; then
              mkdir "$TMP_DIR"
            fi
            if [[ -d "$LOG_DIR"/html-report ]]; then
              print_output "[*] EMBA needs to remove and re-create the current HTML report" "no_log"
              rm -r "$LOG_DIR""/html-report" && mkdir "$LOG_DIR""/html-report"
            fi
            touch "$TMP_DIR"/restart
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

  readarray -t D_LOG_FILES < <( find . \( -path ./external -o -path ./config -o -path ./licenses -o -path ./tools \) -prune -false -o \( -name "*.txt" -o -name "*.log" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  if [[ $USE_DOCKER -eq 1 && ${#D_LOG_FILES[@]} -gt 0 ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    It appears that there are log files in the EMBA directory.\\n    You should move these files to another location where they won't be exposed to the Docker container."
    for D_LOG_FILE in "${D_LOG_FILES[@]}" ; do
      echo -e "        ""$(print_path "$D_LOG_FILE")"
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
  export EXCLUDE_PATHS

  if [[ "$FIRMWARE_PATH" == "/" ]]; then
    EXCLUDE=("${EXCLUDE[@]}" "/proc" "/sys" "$(pwd)")
    print_output "[!] Apparently you want to test your live system. This can lead to errors. Please report the bugs so the software can be fixed." "no_log"
  fi

  print_ln "no_log"

  # exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
  EXCLUDE_PATHS="$(set_excluded_path)"
  export EXCL_FIND
  IFS=" " read -r -a EXCL_FIND <<< "$( echo -e "$(get_excluded_find "$EXCLUDE_PATHS")" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
  print_excluded
}

architecture_check()
{
  if [[ $ARCH_CHECK -eq 1 ]] ; then
    print_output "[*] Architecture auto detection (could take some time)\\n"
    local ARCH_MIPS=0 ARCH_ARM=0 ARCH_ARM64=0 ARCH_X64=0 ARCH_X86=0 ARCH_PPC=0 ARCH_NIOS2=0 ARCH_MIPS64R2=0 ARCH_MIPS64_III=0
    local ARCH_MIPS64v1=0 ARCH_MIPS64_N32=0 ARCH_RISCV=0 ARCH_PPC64=0 ARCH_QCOM_DSP6=0
    local D_END_LE=0 D_END_BE=0
    local D_FLAGS=""
    export ARM_HF=0
    export ARM_SF=0
    D_END="NA"

    # we use the binaries array which is already unique
    for D_ARCH in "${BINARIES[@]}" ; do
      D_FLAGS=$(readelf -h "$D_ARCH" | grep "Flags:" 2>/dev/null || true)
      D_ARCH=$(file "$D_ARCH")

      if [[ "$D_ARCH" == *"MSB"* ]] ; then
        D_END_BE=$((D_END_BE+1))
      elif [[ "$D_ARCH" == *"LSB"* ]] ; then
        D_END_LE=$((D_END_LE+1))
      fi

      if [[ "$D_ARCH" == *"N32 MIPS64 rel2"* ]] ; then
        # ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2 version 1
        ARCH_MIPS64_N32=$((ARCH_MIPS64_N32+1))
        continue
      elif [[ "$D_ARCH" == *"MIPS64 rel2"* ]] ; then
        ARCH_MIPS64R2=$((ARCH_MIPS64R2+1))
        continue
      elif [[ "$D_ARCH" == *"64-bit"*"MIPS-III"* ]] ; then
        ARCH_MIPS64_III=$((ARCH_MIPS64_III+1))
        continue
      elif [[ "$D_ARCH" == *"64-bit"*"MIPS64 version 1"* ]] ; then
        ARCH_MIPS64v1=$((ARCH_MIPS64v1+1))
        continue
      elif [[ "$D_ARCH" == *"MIPS"* ]] ; then
        ARCH_MIPS=$((ARCH_MIPS+1))
        continue
      elif [[ "$D_ARCH" == *"ARM"* ]] ; then
        if [[ "$D_ARCH" == *"ARM aarch64"* ]] ; then
          ARCH_ARM64=$((ARCH_ARM64+1))
        else
          ARCH_ARM=$((ARCH_ARM+1))
        fi
        if [[ "$D_FLAGS" == *"hard-float"* ]]; then
          ARM_HF=$((ARM_HF+1))
        fi
        if [[ "$D_FLAGS" == *"soft-float"* ]]; then
          ARM_SF=$((ARM_SF+1))
        fi
        continue
      elif [[ "$D_ARCH" == *"x86-64"* ]] ; then
        ARCH_X64=$((ARCH_X64+1))
        continue
      elif [[ "$D_ARCH" == *"80386"* ]] ; then
        ARCH_X86=$((ARCH_X86+1))
        continue
      elif [[ "$D_ARCH" == *"64-bit PowerPC"* ]] ; then
        ARCH_PPC64=$((ARCH_PPC64+1))
        continue
      elif [[ "$D_ARCH" == *"PowerPC"* ]] ; then
        ARCH_PPC=$((ARCH_PPC+1))
        continue
      elif [[ "$D_ARCH" == *"Altera Nios II"* ]] ; then
        ARCH_NIOS2=$((ARCH_NIOS2+1))
        continue
      elif [[ "$D_ARCH" == *"UCB RISC-V"* ]] ; then
        ARCH_RISCV=$((ARCH_RISCV+1))
        continue
      elif [[ "$D_ARCH" == *"QUALCOMM DSP6"* ]] ; then
        ARCH_QCOM_DSP6=$((ARCH_QCOM_DSP6+1))
        continue
      fi
    done

    if [[ $((ARCH_MIPS+ARCH_ARM+ARCH_X64+ARCH_X86+ARCH_PPC+ARCH_NIOS2+ARCH_MIPS64R2+ARCH_MIPS64_III+ARCH_MIPS64_N32+ARCH_ARM64+ARCH_MIPS64v1+ARCH_RISCV+ARCH_PPC64+ARCH_QCOM_DSP6)) -gt 0 ]] ; then
      print_output "$(indent "$(orange "Architecture  Count")")"
      if [[ $ARCH_MIPS -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS          ""$ARCH_MIPS")")" ; fi
      if [[ $ARCH_MIPS64R2 -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64r2     ""$ARCH_MIPS64R2")")" ; fi
      if [[ $ARCH_MIPS64_III -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 III     ""$ARCH_MIPS64_III")")" ; fi
      if [[ $ARCH_MIPS64_N32 -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64 N32     ""$ARCH_MIPS64_N32")")" ; fi
      if [[ $ARCH_MIPS64v1 -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS64v1      ""$ARCH_MIPS64v1")")" ; fi
      if [[ $ARCH_ARM -gt 0 ]] ; then print_output "$(indent "$(orange "ARM           ""$ARCH_ARM")")" ; fi
      if [[ $ARCH_ARM64 -gt 0 ]] ; then print_output "$(indent "$(orange "ARM64         ""$ARCH_ARM64")")" ; fi
      if [[ $ARCH_X64 -gt 0 ]] ; then print_output "$(indent "$(orange "x64           ""$ARCH_X64")")" ; fi
      if [[ $ARCH_X86 -gt 0 ]] ; then print_output "$(indent "$(orange "x86           ""$ARCH_X86")")" ; fi
      if [[ $ARCH_PPC -gt 0 ]] ; then print_output "$(indent "$(orange "PPC           ""$ARCH_PPC")")" ; fi
      if [[ $ARCH_PPC -gt 0 ]] ; then print_output "$(indent "$(orange "PPC64         ""$ARCH_PPC64")")" ; fi
      if [[ $ARCH_NIOS2 -gt 0 ]] ; then print_output "$(indent "$(orange "NIOS II       ""$ARCH_NIOS2")")" ; fi
      if [[ $ARCH_RISCV -gt 0 ]] ; then print_output "$(indent "$(orange "RISC-V        ""$ARCH_RISCV")")" ; fi
      if [[ $ARCH_QCOM_DSP6 -gt 0 ]] ; then print_output "$(indent "$(orange "Qualcom DSP6  ""$ARCH_QCOM_DSP6")")" ; fi

      if [[ $ARCH_MIPS -gt $ARCH_ARM ]] && [[ $ARCH_MIPS -gt $ARCH_X64 ]] && [[ $ARCH_MIPS -gt $ARCH_X86 ]] && [[ $ARCH_MIPS -gt $ARCH_PPC ]] && [[ $ARCH_MIPS -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_MIPS -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_MIPS -gt $ARCH_MIPS64_III ]] && [[ $ARCH_MIPS -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_MIPS -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_MIPS -gt $ARCH_RISCV ]] && [[ $ARCH_MIPS -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_MIPS -gt $ARCH_PPC64 ]] && [[ $ARCH_MIPS -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="MIPS"
      elif [[ $ARCH_ARM -gt $ARCH_MIPS ]] && [[ $ARCH_ARM -gt $ARCH_X64 ]] && [[ $ARCH_ARM -gt $ARCH_X86 ]] && [[ $ARCH_ARM -gt $ARCH_PPC ]] && [[ $ARCH_ARM -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_ARM -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_ARM -gt $ARCH_MIPS64_III ]] && [[ $ARCH_ARM -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_ARM -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_ARM -gt $ARCH_RISCV ]] && [[ $ARCH_ARM -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_ARM -gt $ARCH_PPC64 ]] && [[ $ARCH_ARM -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="ARM"
      elif [[ $ARCH_ARM64 -gt $ARCH_MIPS ]] && [[ $ARCH_ARM64 -gt $ARCH_X64 ]] && [[ $ARCH_ARM64 -gt $ARCH_X86 ]] && [[ $ARCH_ARM64 -gt $ARCH_PPC ]] && [[ $ARCH_ARM64 -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_ARM64 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_ARM64 -gt $ARCH_MIPS64_III ]] && [[ $ARCH_ARM64 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_ARM64 -gt $ARCH_ARM ]] && \
        [[ $ARCH_ARM64 -gt $ARCH_RISCV ]] && [[ $ARCH_ARM64 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_ARM64 -gt $ARCH_PPC64 ]] && [[ $ARCH_ARM64 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="ARM64"
      elif [[ $ARCH_X64 -gt $ARCH_MIPS ]] && [[ $ARCH_X64 -gt $ARCH_ARM ]] && [[ $ARCH_X64 -gt $ARCH_X86 ]] && [[ $ARCH_X64 -gt $ARCH_PPC ]] && [[ $ARCH_X64 -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_X64 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_X64 -gt $ARCH_MIPS64_III ]] && [[ $ARCH_X64 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_X64 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_X64 -gt $ARCH_RISCV ]] && [[ $ARCH_X64 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_X64 -gt $ARCH_PPC64 ]] && [[ $ARCH_X64 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="x64"
      elif [[ $ARCH_X86 -gt $ARCH_MIPS ]] && [[ $ARCH_X86 -gt $ARCH_X64 ]] && [[ $ARCH_X86 -gt $ARCH_ARM ]] && [[ $ARCH_X86 -gt $ARCH_PPC ]] && [[ $ARCH_X86 -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_X86 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_X86 -gt $ARCH_MIPS64_III ]] && [[ $ARCH_X86 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_X86 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_X86 -gt $ARCH_RISCV ]] && [[ $ARCH_X86 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_X86 -gt $ARCH_PPC64 ]] && [[ $ARCH_X86 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="x86"
      elif [[ $ARCH_PPC -gt $ARCH_MIPS ]] && [[ $ARCH_PPC -gt $ARCH_ARM ]] && [[ $ARCH_PPC -gt $ARCH_X64 ]] && [[ $ARCH_PPC -gt $ARCH_X86 ]] && [[ $ARCH_PPC -gt $ARCH_NIOS2 ]] && \
        [[ $ARCH_PPC -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_PPC -gt $ARCH_MIPS64_III ]] && [[ $ARCH_PPC -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_PPC -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_PPC -gt $ARCH_RISCV ]] && [[ $ARCH_PPC -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_PPC -gt $ARCH_PPC64 ]] && [[ $ARCH_PPC -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="PPC"
      elif [[ $ARCH_NIOS2 -gt $ARCH_MIPS ]] && [[ $ARCH_NIOS2 -gt $ARCH_ARM ]] && [[ $ARCH_NIOS2 -gt $ARCH_X64 ]] && [[ $ARCH_NIOS2 -gt $ARCH_X86 ]] && [[ $ARCH_NIOS2 -gt $ARCH_PPC ]] && \
        [[ $ARCH_NIOS2 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_NIOS2 -gt $ARCH_MIPS64_III ]] && [[ $ARCH_NIOS2 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_NIOS2 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_NIOS2 -gt $ARCH_RISCV ]] && [[ $ARCH_NIOS2 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_NIOS2 -gt $ARCH_PPC64 ]] && [[ $ARCH_NIOS2 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="NIOS2"
      elif [[ $ARCH_MIPS64R2 -gt $ARCH_MIPS ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_X64 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_X86 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_PPC ]] && \
        [[ $ARCH_MIPS64R2 -gt $ARCH_NIOS2 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_MIPS64_III ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_MIPS64R2 -gt $ARCH_RISCV ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_PPC64 ]] && [[ $ARCH_MIPS64R2 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="MIPS64R2"
      elif [[ $ARCH_MIPS64_III -gt $ARCH_MIPS ]] && [[ $ARCH_MIPS64_III -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64_III -gt $ARCH_X64 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_X86 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_PPC ]] && \
        [[ $ARCH_MIPS64_III -gt $ARCH_NIOS2 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_MIPS64_III -gt $ARCH_RISCV ]] && [[ $ARCH_MIPS64_III -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_PPC64 ]] && [[ $ARCH_MIPS64_III -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="MIPS64_3"
      elif [[ $ARCH_MIPS64_N32 -gt $ARCH_MIPS ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_X64 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_X86 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_PPC ]] && \
        [[ $ARCH_MIPS64_N32 -gt $ARCH_NIOS2 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_MIPS64_N32 -gt $ARCH_RISCV ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_PPC64 ]] && [[ $ARCH_MIPS64_N32 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="MIPS64N32"
      elif [[ $ARCH_MIPS64v1 -gt $ARCH_MIPS ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_X64 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_X86 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_PPC ]] && \
        [[ $ARCH_MIPS64v1 -gt $ARCH_NIOS2 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_ARM ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_MIPS64v1 -gt $ARCH_RISCV ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_PPC64 ]] && [[ $ARCH_MIPS64v1 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="MIPS64v1"
      elif [[ $ARCH_RISCV -gt $ARCH_MIPS ]] && [[ $ARCH_RISCV -gt $ARCH_ARM ]] && [[ $ARCH_RISCV -gt $ARCH_X64 ]] && [[ $ARCH_RISCV -gt $ARCH_X86 ]] && [[ $ARCH_RISCV -gt $ARCH_PPC ]] && \
        [[ $ARCH_RISCV -gt $ARCH_NIOS2 ]] && [[ $ARCH_RISCV -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_RISCV -gt $ARCH_ARM ]] && [[ $ARCH_RISCV -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_RISCV -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_RISCV -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_RISCV -gt $ARCH_PPC64 ]] && [[ $ARCH_RISCV -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="RISCV"
      elif [[ $ARCH_PPC64 -gt $ARCH_MIPS ]] && [[ $ARCH_PPC64 -gt $ARCH_ARM ]] && [[ $ARCH_PPC64 -gt $ARCH_X64 ]] && [[ $ARCH_PPC64 -gt $ARCH_X86 ]] && [[ $ARCH_PPC64 -gt $ARCH_PPC ]] && \
        [[ $ARCH_PPC64 -gt $ARCH_NIOS2 ]] && [[ $ARCH_PPC64 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_PPC64 -gt $ARCH_ARM ]] && [[ $ARCH_PPC64 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_PPC64 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_PPC64 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_PPC64 -gt $ARCH_RISCV ]] && [[ $ARCH_PPC64 -gt $ARCH_QCOM_DSP6 ]]; then
        D_ARCH="PPC64"
      elif [[ $ARCH_QCOM_DSP6 -gt $ARCH_MIPS ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_ARM ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_X64 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_X86 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_PPC ]] && \
        [[ $ARCH_QCOM_DSP6 -gt $ARCH_NIOS2 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_MIPS64R2 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_ARM ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_ARM64 ]] && \
        [[ $ARCH_QCOM_DSP6 -gt $ARCH_MIPS64_N32 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_MIPS64v1 ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_RISCV ]] && [[ $ARCH_QCOM_DSP6 -gt $ARCH_PPC64 ]]; then
        D_ARCH="QCOM_DSP6"
      else
        D_ARCH="unknown"
      fi

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "Endianness  Count")")"
        if [[ $D_END_BE -gt 0 ]] ; then print_output "$(indent "$(orange "Big endian          ""$D_END_BE")")" ; fi
        if [[ $D_END_LE -gt 0 ]] ; then print_output "$(indent "$(orange "Little endian          ""$D_END_LE")")" ; fi
      fi
      if [[ $((ARM_SF+ARM_HF)) -gt 0 ]] ; then
        print_ln
        print_output "$(indent "$(orange "ARM Hardware/Software floating Count")")"
        if [[ $ARM_SF -gt 0 ]] ; then print_output "$(indent "$(orange "Software floating          ""$ARM_SF")")" ; fi
        if [[ $ARM_HF -gt 0 ]] ; then print_output "$(indent "$(orange "Hardware floating          ""$ARM_HF")")" ; fi
      fi

      if [[ $D_END_LE -gt $D_END_BE ]] ; then
        D_END="EL"
      elif [[ $D_END_BE -gt $D_END_LE ]] ; then
        D_END="EB"
      else
        D_END="NA"
      fi

      print_ln

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
        print_output "$(indent "Detected architecture and endianness of the firmware: ""$ORANGE""$D_ARCH"" / ""$D_END""$NC")""\\n"
        export D_END
      else
        print_output "$(indent "Detected architecture of the firmware: ""$ORANGE""$D_ARCH""$NC")""\\n"
      fi

      if [[ -n "${ARCH:-}" ]] ; then
        if [[ "$ARCH" != "$D_ARCH" ]] ; then
          print_output "[!] Your set architecture (""$ARCH"") is different from the automatically detected one. The set architecture will be used."
        fi
      else
        print_output "[*] No architecture was enforced, so the automatically detected one is used."
        ARCH="$D_ARCH"
        export ARCH
      fi
    else
      print_output "$(indent "$(red "No architecture in firmware found")")"
      if [[ -n "$ARCH" ]] ; then
        print_output "[*] Your set architecture (""$ARCH"") will be used."
      else
        print_output "[!] Since no architecture could be detected, you should set one."
      fi
    fi
    backup_var "ARCH" "$ARCH"
    backup_var "D_END" "$D_END"

  else
    print_output "[*] Architecture auto detection disabled\\n"
    if [[ -n "$ARCH" ]] ; then
      print_output "[*] Your set architecture (""$ARCH"") will be used."
    else
      print_output "[!] Since no architecture could be detected, you should set one."
    fi
  fi
}

prepare_file_arr()
{
  echo ""
  print_output "[*] Unique files auto detection for $ORANGE$FIRMWARE_PATH$NC (could take some time)\\n"

  export FILE_ARR
  readarray -t FILE_ARR < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
  # RTOS handling:
  if [[ -f $FIRMWARE_PATH && $RTOS -eq 1 ]]; then
    readarray -t FILE_ARR_RTOS < <(find "$OUTPUT_DIR" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
    FILE_ARR+=( "${FILE_ARR_RTOS[@]}" )
    FILE_ARR+=( "$FIRMWARE_PATH" )
  fi
  print_output "[*] Found $ORANGE${#FILE_ARR[@]}$NC unique files."

  # xdev will do the trick for us:
  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${FILE_ARR[@]}"
}

prepare_binary_arr()
{
  echo ""
  print_output "[*] Unique binary auto detection for $ORANGE$FIRMWARE_PATH$NC (could take some time)\\n"

  # lets try to get an unique binary array
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES=()
  # readarray -t BINARIES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # In some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  readarray -t BINARIES_TMP < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -exec file {} \; 2>/dev/null | grep ELF | cut -d: -f1 || true)
  if [[ -v BINARIES_TMP[@] ]]; then
    for BINARY in "${BINARIES_TMP[@]}"; do
      if [[ -f "$BINARY" ]]; then
        BIN_MD5=$(md5sum "$BINARY" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5} ]]; then
          BINARIES+=( "$BINARY" )
          MD5_DONE_INT+=( "$BIN_MD5" )
        fi
      fi
    done
    print_output "[*] Found $ORANGE${#BINARIES[@]}$NC unique executables."
  fi

  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${BINARIES[@]}"
}

prepare_file_arr_limited() {
  local FIRMWARE_PATH="${1:-}"
  export FILE_ARR_LIMITED=()

  if ! [[ -d "$FIRMWARE_PATH" ]]; then
    return
  fi

  echo ""
  print_output "[*] Unique and limited file array generation for $ORANGE$FIRMWARE_PATH$NC (could take some time)\\n"

  readarray -t FILE_ARR_LIMITED < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
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

check_firmware()
{
  # this detection is only running if we have not found a Linux system:
  local DIR_COUNT=0
  if [[ "$RTOS" -eq 1 ]]; then
    # Check if firmware got normal linux directory structure and warn if not
    # as we already have done some root directory detection we are going to use it now
    local LINUX_PATHS=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
    if [[ ${#ROOT_PATH[@]} -gt 0 ]]; then
      for R_PATH in "${ROOT_PATH[@]}"; do
        for L_PATH in "${LINUX_PATHS[@]}"; do
          if [[ -d "$R_PATH"/"$L_PATH" ]] ; then
            ((DIR_COUNT+=1))
          fi
        done
      done
    else
      # this is needed for directories we are testing
      # in such a case the pre-checking modules are not executed and no RPATH is available
      for L_PATH in "${LINUX_PATHS[@]}"; do
        if [[ -d "$FIRMWARE_PATH"/"$L_PATH" ]] ; then
          ((DIR_COUNT+=1))
        fi
      done
    fi
  fi

  if [[ $DIR_COUNT -lt 5 ]] && [[ "$RTOS" -eq 1 ]]; then
    print_ln "no_log"
    print_output "[!] Your firmware looks not like a regular Linux system, sure that you have entered the correct path?"
  fi
  if [[ "$RTOS" -eq 0 ]] || [[ $DIR_COUNT -gt 4 ]]; then
    print_output "[+] Your firmware looks like a regular Linux system."
  fi
}

detect_root_dir_helper() {
  SEARCH_PATH="${1:-}"

  print_output "[*] Root directory auto detection for $ORANGE$SEARCH_PATH$NC (could take some time)\\n"
  ROOT_PATH=()
  export ROOT_PATH
  local R_PATH
  local MECHANISM=""

  mapfile -t INTERPRETER_FULL_PATH < <(find "$SEARCH_PATH" -ignore_readdir_race -type f -exec file {} \; 2>/dev/null | grep "ELF" | grep "interpreter" | sed s/.*interpreter\ // | sed s/,\ .*$// | sort -u 2>/dev/null || true)

  if [[ "${#INTERPRETER_FULL_PATH[@]}" -gt 0 ]]; then
    for INTERPRETER_PATH in "${INTERPRETER_FULL_PATH[@]}"; do
      # now we have a result like this "/lib/ld-uClibc.so.0"
      # lets escape it
      INTERPRETER_ESCAPED=$(echo "$INTERPRETER_PATH" | sed -e 's/\//\\\//g')
      mapfile -t INTERPRETER_FULL_RPATH < <(find "$SEARCH_PATH" -ignore_readdir_race -wholename "*$INTERPRETER_PATH" 2>/dev/null | sort -u)
      for R_PATH in "${INTERPRETER_FULL_RPATH[@]}"; do
        # remove the interpreter path from the full path:
        R_PATH="${R_PATH//$INTERPRETER_ESCAPED/}"
        if [[ -v R_PATH ]] && [[ -d "$R_PATH" ]]; then
          ROOT_PATH+=( "$R_PATH" )
          MECHANISM="binary interpreter"
        fi
      done
    done
  fi

  # if we can't find the interpreter we fall back to a search for something like "*root/bin/* and take this:
  mapfile -t ROOTx_PATH < <(find "$SEARCH_PATH" -xdev \( -path "*extracted/bin" -o -path "*root/bin" \) -exec dirname {} \; 2>/dev/null)
  for R_PATH in "${ROOTx_PATH[@]}"; do
    if [[ -d "$R_PATH" ]]; then
      ROOT_PATH+=( "$R_PATH" )
      if [[ -z "$MECHANISM" ]]; then
        MECHANISM="dir names"
      elif [[ -n "$MECHANISM" ]] && ! echo "$MECHANISM" | grep -q "dir names"; then
        MECHANISM="$MECHANISM / dir names"
      fi
    fi
  done

  mapfile -t ROOTx_PATH < <(find "$SEARCH_PATH" -xdev \( -path "*/sbin" -o -path "*/bin" -o -path "*/lib" -o -path "*/etc" -o -path "*/root" -o -path "*/dev" -o -path "*/opt" -o -path "*/proc" -o -path "*/lib64" -o -path "*/boot" -o -path "*/home" \) -exec dirname {} \; | sort | uniq -c | sort -r)
  for R_PATH in "${ROOTx_PATH[@]}"; do
    CNT=$(echo "$R_PATH" | awk '{print $1}')
    if [[ "$CNT" -lt 5 ]]; then
      # we only use paths with more then 4 matches as possible root path
      continue
    fi
    R_PATH=$(echo "$R_PATH" | awk '{print $2}')
    if [[ -d "$R_PATH" ]]; then
      ROOT_PATH+=( "$R_PATH" )
      if [[ -z "$MECHANISM" ]]; then
        MECHANISM="dir names"
      elif [[ -n "$MECHANISM" ]] && ! echo "$MECHANISM" | grep -q "dir names"; then
        MECHANISM="$MECHANISM / dir names"
      fi
    fi
  done

  mapfile -t ROOTx_PATH < <(find "$SEARCH_PATH" -xdev -path "*bin/busybox" | sed -E 's/\/.?bin\/busybox//')
  for R_PATH in "${ROOTx_PATH[@]}"; do
    if [[ -d "$R_PATH" ]]; then
      ROOT_PATH+=( "$R_PATH" )
      if [[ -z "$MECHANISM" ]]; then
        MECHANISM="busybox"
      elif [[ -n "$MECHANISM" ]] && ! echo "$MECHANISM" | grep -q "busybox"; then
        MECHANISM="$MECHANISM / busybox"
      fi
    fi
  done

  mapfile -t ROOTx_PATH < <(find "$SEARCH_PATH" -xdev -path "*bin/bash" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/bash//' || true)
  for R_PATH in "${ROOTx_PATH[@]}"; do
    if [[ -d "$R_PATH" ]]; then
      ROOT_PATH+=( "$R_PATH" )
      if [[ -z "$MECHANISM" ]]; then
        MECHANISM="shell"
      elif [[ -n "$MECHANISM" ]] && ! echo "$MECHANISM" | grep -q "shell"; then
        MECHANISM="$MECHANISM / shell"
      fi
    fi
  done

  mapfile -t ROOTx_PATH < <(find "$SEARCH_PATH" -xdev -path "*bin/sh" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/sh//' || true)
  for R_PATH in "${ROOTx_PATH[@]}"; do
    if [[ -d "$R_PATH" ]]; then
      ROOT_PATH+=( "$R_PATH" )
      if [[ -z "$MECHANISM" ]]; then
        MECHANISM="shell"
      elif [[ -n "$MECHANISM" ]] && ! echo "$MECHANISM" | grep -q "shell"; then
        MECHANISM="$MECHANISM / shell"
      fi
    fi
  done

  if [[ ${#ROOT_PATH[@]} -eq 0 ]]; then
    export RTOS=1
    ROOT_PATH+=( "$SEARCH_PATH" )
    MECHANISM="last resort"
  else
    export RTOS=0
  fi

  eval "ROOT_PATH=($(for i in "${ROOT_PATH[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ -v ROOT_PATH[@] && "$RTOS" -eq 0 ]]; then
    print_output "[*] Found $ORANGE${#ROOT_PATH[@]}$NC different root directories:"
    write_link "s05#file_dirs"
  fi

  for R_PATH in "${ROOT_PATH[@]}"; do
    if [[ "$MECHANISM" == "last resort" ]]; then
      print_output "[*] Found no real root directory - setting it to: $ORANGE$R_PATH$NC via $ORANGE$MECHANISM$NC."
    else
      print_output "[+] Found the following root directory: $ORANGE$R_PATH$GREEN via $ORANGE$MECHANISM$GREEN."
    fi
    write_link "s05#file_dirs"
  done
}

check_init_size() {
  SIZE=$(du -b --max-depth=0 "$FIRMWARE_PATH"| awk '{print $1}' || true)
  if [[ $SIZE -gt 400000000 ]]; then
    print_ln "no_log"
    print_output "[!] WARNING: Your firmware is very big!" "no_log"
    print_output "[!] WARNING: Analysing huge firmwares will take a lot of disk space, RAM and time!" "no_log"
    print_ln "no_log"
  fi
}

generate_msf_db() {
  # only running on host in full installation (with metapsloit installed)
  print_output "[*] Building the Metasploit exploit database" "no_log"
  # search all ruby files in the metasploit directory and create a temporary file with the module path and CVE:
  find "$MSF_PATH" -type f -iname "*.rb" -exec grep -H -E -o "CVE', '[0-9]{4}-[0-9]+" {} \; | sed "s/', '/-/g" | sort > "$MSF_DB_PATH"
  if [[ -f "$MSF_DB_PATH" ]]; then
    print_output "[*] Metasploit exploit database now has $ORANGE$(wc -l "$MSF_DB_PATH" | awk '{print $1}')$NC exploit entries." "no_log"
  fi
}

generate_trickest_db() {
  # only running on host with trickest database installed
  # search all markdown files in the trickest directory and create a temporary file with the module path (including CVE) and github URL to exploit:

  if [[ -d "$EXT_DIR"/trickest-cve ]]; then
    print_output "[*] Update and build the Trickest CVE/exploit database" "no_log"
    cd "$EXT_DIR"/trickest-cve || true
    git pull || true
    cd ../.. || true

    find "$EXT_DIR"/trickest-cve -type f -iname "*.md" -exec grep -o -H "^\-\ https://github.com.*" {} \; | sed 's/:-\ /:/g' | sort > "$TRICKEST_DB_PATH" || true

    # if we have a blacklist file we are going to apply it to the generated trickest database
    if [[ -f "$CONFIG_DIR"/trickest_blacklist.txt ]] && [[ -f "$TRICKEST_DB_PATH" ]]; then
      grep -Fvf "$CONFIG_DIR"/trickest_blacklist.txt "$TRICKEST_DB_PATH" > "$EXT_DIR"/trickest_db-cleaned.txt || true
      mv "$EXT_DIR"/trickest_db-cleaned.txt "$TRICKEST_DB_PATH" || true
    fi

    if [[ -f "$TRICKEST_DB_PATH" ]]; then
      print_output "[*] Trickest CVE database now has $ORANGE$(wc -l "$TRICKEST_DB_PATH" | awk '{print $1}')$NC exploit entries." "no_log"
    fi
  else
    print_output "[*] No update of the Trickest exploit database performed." "no_log"
  fi
}

update_known_exploitable() {
  # only running on host with known_exploited_vulnerabilities.csv installed

  if [[ -f "$EXT_DIR"/known_exploited_vulnerabilities.csv ]]; then
    print_output "[*] Update the known_exploited_vulnerabilities file" "no_log"
    wget https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv -O "$EXT_DIR"/known_exploited_vulnerabilities_new.csv || true
    if [[ $(wc -l "$EXT_DIR"/known_exploited_vulnerabilities_new.csv | awk '{print $1}') -ge $(wc -l "$EXT_DIR"/known_exploited_vulnerabilities.csv | awk '{print $1}') ]]; then
      # copy it only if the updated file is bigger then the installed one
      cp "$EXT_DIR"/known_exploited_vulnerabilities_new.csv "$KNOWN_EXP_CSV"
      mv "$EXT_DIR"/known_exploited_vulnerabilities_new.csv "$EXT_DIR"/known_exploited_vulnerabilities.csv
    fi
    if [[ -f "$KNOWN_EXP_CSV" ]]; then
      print_output "[*] Known exploit database now has $ORANGE$(wc -l "$KNOWN_EXP_CSV" | awk '{print $1}')$NC exploit entries." "no_log"
    fi
  else
    print_output "[*] No update of the known_exploited_vulnerabilities.csv file performed." "no_log"
  fi
}
