#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Google Gemini AI

S130_binary_map_builder() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary dependency map builder"

  if [[ "${EMBA_MAP_GENERATOR:-0}" -eq 0 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_wait "S115_usermode_emulator"

  # needed if we start the module standalone via the helper script
  [[ ! -d "${LOG_PATH_MODULE}" ]] && mkdir -p "${LOG_PATH_MODULE}"

  load_default_environment
  setup_environment
  build_dot
  build_svg
  build_html

  module_end_log "${FUNCNAME[0]}" 1

  # we need to adjust the html linking after the html report was created:
  if [[ "${HTML}" -eq 1 ]]; then
    if [[ -f "${HTML_PATH}/s130_binary_map_builder.html" && -f "${HTML_PATH}/s130_binary_map_builder/res/EMBA-dependency-map.html" ]]; then
      # now we can add the link around our svg image
      sed -i '/img class.*EMBA-dependency-map.svg.*/i <a href=./s130_binary_map_builder/res/EMBA-dependency-map.html>' "${HTML_PATH}/s130_binary_map_builder.html"
      sed -i '/img class.*EMBA-dependency-map.svg.*/a <\/a>' "${HTML_PATH}/s130_binary_map_builder.html"
    fi

    if [[ -f "${HTML_PATH}/s130_binary_map_builder.html" && -f "${HTML_PATH}/s130_binary_map_builder/res/EMBA-dependency-dot_map.html" ]]; then
      # replace <img class="image" src="./style/EMBA-dependency-map_dot.svg">
      sed -i '/img class.*EMBA-dependency-map_dot.svg.*/i <a href=./s130_binary_map_builder/res/EMBA-dependency-dot_map.html>' "${HTML_PATH}/s130_binary_map_builder.html"
      sed -i '/img class.*EMBA-dependency-map_dot.svg.*/a <\/a>' "${HTML_PATH}/s130_binary_map_builder.html"
    fi
  fi
}

load_default_environment() {
  # Limit the number of processed files to 2000 for handling firmware images
  # For testing this should be limited to something lower
  [[ -z "${MAX_MAP_FILES}" ]] && export MAX_MAP_FILES=2000

  # hard-coded dependency blacklist - is fp prone and overwhelming output
  # add entries if you do not want to see them
  export DEP_BLACKLIST_ARR=("echo" "test" "free" "event" "full" "port")
  local lBL_COMMAND=""
  print_output "[*] Blacklisted the following commands:"
  for lBL_COMMAND in "${DEP_BLACKLIST_ARR[@]}"; do
    print_output "$(indent "- ${lBL_COMMAND}")"
  done

  # Remove detection mechanism you do not want to check for
  # FUZZY-STR is very powerful but also fp prone
  # DETECTION_MECHANISMS_ARR=("FUZZY-STR" "STRICT-STR" "LDD-LIB" "QEMU-USER" "QEMU-SYS" "OBJDUMP-LIB")
  export DETECTION_MECHANISMS_ARR=("FUZZY-STR" "STRICT-STR" "QEMU-USER" "QEMU-SYS" "OBJDUMP-LIB")

  # in case we have not EMBA s115 module results we can remove these checks
  if ! [[ -d "${S115_LOG_DIR}" ]]; then
    print_ln ""
    print_output "[-] No s115 qemu check possible - missing s115 EMBA log directory"
    DETECTION_MECHANISMS_ARR=("${DETECTION_MECHANISMS_ARR[@]/QEMU-USER/}")
  fi

  # system emulation checks are only possible in standalone run via the helper script
  # During EMBA run the system emulation results are not available
  if ! [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    print_output "[-] No system emualtion checks possible - missing L10 EMBA log directory (future extension)"
    DETECTION_MECHANISMS_ARR=("${DETECTION_MECHANISMS_ARR[@]/QEMU-SYS/}")
  fi

  local lDET_MECHANISM=""
  print_ln ""
  print_output "[*] Using the following detection mechanisms:"
  for lDET_MECHANISM in "${DETECTION_MECHANISMS_ARR[@]}"; do
    [[ -z "${lDET_MECHANISM}" ]] && continue
    print_output "$(indent "- ${lDET_MECHANISM}")"
  done

  print_ln ""
  # for threading
  if [[ -z "${MAX_MAP_JOBS}" ]]; then
    export MAX_MAP_JOBS=""
    MAX_MAP_JOBS="$(nproc)"
  fi

  # Define temporary and output filenames.
  export HTML_FILE="${LOG_PATH_MODULE}/EMBA-dependency-map.html"
  export BASE_HTML_TEMPLATE="${HELP_DIR}/firmware_map_base.html"

  export DOT_FILE="${LOG_PATH_MODULE}/EMBA-dependency-map.dot"
  export DOT_FILE_tmp_dir="${LOG_PATH_MODULE}/tmp_dot"
  rm -rf "${DOT_FILE_tmp_dir}"
  mkdir "${DOT_FILE_tmp_dir}"

  export SVG_FILE="${LOG_PATH_MODULE}/EMBA-dependency-map.svg"

  # External assets - downloaded once for offline capability.
  export JS_LIB="${EXT_DIR}/svg-pan-zoom.min.js"
  export LOGO_FILE="${HELP_DIR}/emba.svg"

  export COLOR_BIN="#1a3a5f" # Deep Blue for Executables
  export COLOR_LNK="#D5AAAA"

  export DEPENDENCY_MAP_LOG="${LOG_PATH_MODULE}/dependency_map_details.log"
}

setup_environment() {
  if [[ -f "${LOGO_FILE}" ]]; then
    cp "${LOGO_FILE}" "${LOG_PATH_MODULE}" || print_error "[-] No EMBA logo found"
  elif [[ -f "/tmp/${LOGO_FILE}" ]]; then
    # if we start it from external script without an EMBA directory we have the logo
    # already loaded to /tmp
    cp "/tmp/${LOGO_FILE}" "${LOG_PATH_MODULE}" || print_error "[-] No EMBA logo found"
  fi
  if [[ -f "${JS_LIB}" ]]; then
    cp "${JS_LIB}" "${LOG_PATH_MODULE}" || print_error "[-] No JS lib ${JS_LIB} found"
  elif [[ -f "/tmp/${JS_LIB}" ]]; then
    cp "/tmp/${JS_LIB}" "${LOG_PATH_MODULE}" || print_error "[-] No JS lib ${JS_LIB} found"
  fi

  # Count total files in search directory for the dashboard display.
  export ALL_EXEC_FILES_ARR=()
  mapfile -t ALL_EXEC_FILES_ARR < <(find "${FIRMWARE_PATH}" -type f 2>/dev/null | sort -u)
  if [[ "${#ALL_EXEC_FILES_ARR[@]}" -gt "${MAX_MAP_FILES}" ]]; then
    print_output "[*] INFO: Too many files (${#ALL_EXEC_FILES_ARR[@]} -gt ${MAX_MAP_FILES}) detected ... limit it to executables only"
    mapfile -t ALL_EXEC_FILES_ARR < <(find "${FIRMWARE_PATH}" -type f -executable ! -name "*.raw" 2>/dev/null | sort -u)
  fi
  print_ln ""
  print_output "[+] Testing ${ORANGE}${#ALL_EXEC_FILES_ARR[@]}${GREEN} files/executables in ${ORANGE}${FIRMWARE_PATH}${NC}"
  print_ln ""
}

# system emulation checks are only possible in standalone run via the helper script
# During EMBA run the system emulation results are not available
system_emulator_init_runner() {
  local lSYS_EMU_ENTRY=""
  if [[ -f "${LOG_DIR}"/emulator_online_results.log ]]; then
    lSYS_EMU_ENTRY=$(grep "ICMP ok\|TCP ok" "${LOG_DIR}"/emulator_online_results.log | sort -k 7 -t ';' | tail -1 || true)
  else
    print_output "[-] Identified NO system emulation details"
    return
  fi
  print_output "[*] Identified the following system emulation details"
  print_output "  ->  ${lSYS_EMU_ENTRY}"

  lEMU_PATH=$(echo "${lSYS_EMU_ENTRY}" | cut -d ';' -f11)
  lEMU_PATH=${LOG_DIR}"/l10_system_emulation/${lEMU_PATH}"
  if [[ ! -d "${lEMU_PATH}" ]]; then
    print_output "[-] No system emulation results available ... no checks performed"
    return
  fi

  print_output "[*] Adjusting emulation runner script ..."
  cp -r "${lEMU_PATH}" "${LOG_PATH_MODULE}/emulation_engine" || {
    print_error "[-] S130 - Adjusting emulation runner script failed"
    return
  }
  sed -i 's/firmadyne.syscall=[0-9]*/firmadyne.syscall=32/' "${LOG_PATH_MODULE}"/emulation_engine/run.sh || {
    print_error "[-] S130 - Adjusting emulation runner script failed"
    return
  }
  sed -i 's#file:./qemu.serial.log#file:./qemu.map.log#' "${LOG_PATH_MODULE}"/emulation_engine/run.sh || {
    print_error "[-] S130 - Adjusting emulation runner script failed"
    return
  }

  print_output "[*] Starting emulation engine ... running for 360 seconds"
  local lHOME_DIR=""
  lHOME_DIR=$(pwd)
  cd "${LOG_PATH_MODULE}"/emulation_engine || {
    print_error "[-] S130 - Emulation run failed"
    return
  }

  if  [[ ${EUID} -eq 0 ]] ; then
    timeout 360 ./run.sh
  else
    timeout 360 sudo ./run.sh
  fi

  cd "${lHOME_DIR}" || {
    print_error "[-] S130 - Emulation run failed"
    return
  }

  grep -a ANALYZE "${LOG_PATH_MODULE}"/emulation_engine/qemu.map.log | sed -e 's/.*PID: //' | awk '{print $2,$3}' | sort -u | sed 's/^(//' | sed 's/)]: / -> /' >>"${LOG_PATH_MODULE}"/system_emulation_results.log
  # we should have something like "UPDATELEASES.sh -> /usr/sbin/phpsh"
  print_ln ""
  print_output "[+] Identified $(wc -l 2>/dev/null <"${LOG_PATH_MODULE}"/system_emulation_results.log) calls via system emulation"
  print_ln ""
}

# Function to identify binary capabilities via syscall analysis (x86, ARM, MIPS)
get_capabilities() {
  local lELF_FILE="${1}"
  local lARCH_INFO="${2}"
  local lCAPABILITIES=""
  local lRAW_DISASM=""

  # x86-64
  if [[ "${lARCH_INFO}" =~ "x86-64" ]]; then
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "syscall" | grep -oE "mov\s+\\\$0x[0-9a-f]+,%eax" | cut -d"$" -f2 | cut -d"," -f1 || true)
    [[ "${lRAW_DISASM}" =~ (0x3b|0x39) ]] && lCAPABILITIES+="EXEC "
    [[ "${lRAW_DISASM}" =~ (0x29|0x2a|0x2b) ]] && lCAPABILITIES+="NET "
    [[ "${lRAW_DISASM}" =~ (0x2|0x0|0x1) ]] && lCAPABILITIES+="FILE "

  # x86 (32-bit)
  elif [[ "${lARCH_INFO}" =~ "Intel 80386" || "${lARCH_INFO}" =~ "x86" ]]; then
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "int\s+\$0x80" | grep -oE "mov\s+\\\$0x[0-9a-f]+,%eax" | cut -d"$" -f2 | cut -d"," -f1 || true)
    [[ "${lRAW_DISASM}" =~ (0xb|0x2) ]] && lCAPABILITIES+="EXEC "
    [[ "${lRAW_DISASM}" =~ (0x66|0x167) ]] && lCAPABILITIES+="NET "
    [[ "${lRAW_DISASM}" =~ (0x5|0x3|0x4) ]] && lCAPABILITIES+="FILE "

  # ARM / AArch64
  elif [[ "${lARCH_INFO}" =~ "ARM" ]]; then
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "svc\s+#0" || true)
    [[ "${lRAW_DISASM}" =~ (r7|x8) ]] && {
      [[ "${lRAW_DISASM}" =~ (0xb|0xdd|0x1) ]] && lCAPABILITIES+="EXEC "
      [[ "${lRAW_DISASM}" =~ (0x119|0xc6|0xc7) ]] && lCAPABILITIES+="NET "
      [[ "${lRAW_DISASM}" =~ (0x5|0x3|0x4) ]] && lCAPABILITIES+="FILE "
    }

  # MIPS / MIPS64
  elif [[ "${lARCH_INFO}" =~ "MIPS" ]]; then
    if [[ "${lARCH_INFO}" =~ "64" ]]; then
      lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "syscall" | grep -oE "li\s+v0,[0-9]+" || true)
      [[ "${lRAW_DISASM}" =~ (5057|5056) ]] && lCAPABILITIES+="EXEC "
      [[ "${lRAW_DISASM}" =~ (5040|5041) ]] && lCAPABILITIES+="NET "
      [[ "${lRAW_DISASM}" =~ (5002|5000|5001) ]] && lCAPABILITIES+="FILE "
    else
      lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "syscall" | grep -oE "li\s+v0,[0-9]+" || true)
      [[ "${lRAW_DISASM}" =~ (4011|4002) ]] && lCAPABILITIES+="EXEC "
      [[ "${lRAW_DISASM}" =~ (4183|4170) ]] && lCAPABILITIES+="NET "
      [[ "${lRAW_DISASM}" =~ (4005|4003|4004) ]] && lCAPABILITIES+="FILE "
    fi

  # RISC-V (rv32/rv64)
  elif [[ "${lARCH_INFO}" =~ "RISC-V" ]]; then
    # RISC-V: ecall, Register a7 (x17)
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "ecall" | grep -oE "li\s+a7,[0-9]+" || true)
    [[ "${lRAW_DISASM}" =~ (221|220) ]] && lCAPABILITIES+="EXEC "  # execve=221, clone=220
    [[ "${lRAW_DISASM}" =~ (198|203) ]] && lCAPABILITIES+="NET "   # socket=198, connect=203
    [[ "${lRAW_DISASM}" =~ (56|63|64) ]] && lCAPABILITIES+="FILE " # openat=56, read=63, write=64

  # PowerPC
  elif [[ "${lARCH_INFO}" =~ "PowerPC" ]]; then
    # PPC: sc, Register r0
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "sc" | grep -oE "li\s+r0,[0-9]+" || true)
    [[ "${lRAW_DISASM}" =~ (11|2) ]] && lCAPABILITIES+="EXEC "   # execve=11, fork=2
    [[ "${lRAW_DISASM}" =~ (102|359) ]] && lCAPABILITIES+="NET " # socketcall=102, socket=359
    [[ "${lRAW_DISASM}" =~ (5|3|4) ]] && lCAPABILITIES+="FILE "  # open=5, read=3, write=4

  # Nios II
  elif [[ "${lARCH_INFO}" =~ "Altera Nios II" || "${lARCH_INFO}" =~ "Nios II" ]]; then
    lRAW_DISASM=$("${OBJDUMP}" -d "${lELF_FILE}" 2>/dev/null | grep -B 3 "trap" | grep -oE "movi\s+r2,[0-9]+" || true)
    [[ "${lRAW_DISASM}" =~ (11|2) ]] && lCAPABILITIES+="EXEC "
    [[ "${lRAW_DISASM}" =~ (97|98|99) ]] && lCAPABILITIES+="NET "
    [[ "${lRAW_DISASM}" =~ (5|3|4) ]] && lCAPABILITIES+="FILE "
  fi

  echo "${lCAPABILITIES:-NONE}"
}

binary_sec_scan() {
  local lELF_FILE="${1:-}"
  local lBIN_SEC_FLAGS=""
  local lFILE_INFO=""
  local lREADELF_l=""
  local lREADELF_h=""
  local lSYMBOLS=""

  # Check for Static Linking (Security Indicator)
  lFILE_INFO=$(file -b "${lELF_FILE}" 2>/dev/null)
  if [[ "${lFILE_INFO}" =~ "statically linked" ]]; then
    lBIN_SEC_FLAGS+="STATIC "
  fi

  lREADELF_l=$(readelf -lW "${lELF_FILE}" 2>/dev/null)
  lREADELF_h=$(readelf -h "${lELF_FILE}" 2>/dev/null)
  lSYMBOLS=$(readelf -s "${lELF_FILE}" 2>/dev/null)

  # NX (No-Execute) check
  [[ "${lREADELF_l}" =~ "GNU_STACK" ]] && lBIN_SEC_FLAGS+="NX " || lBIN_SEC_FLAGS+="!NX "
  # PIE (Position Independent Executable) check
  [[ "${lREADELF_h}" =~ "DYN" ]] && lBIN_SEC_FLAGS+="PIE " || lBIN_SEC_FLAGS+="!PIE "
  # Stack Canary check
  [[ "${lSYMBOLS}" =~ "__stack_chk_fail" ]] && lBIN_SEC_FLAGS+="CANARY " || lBIN_SEC_FLAGS+="!CANARY "
  echo "${lBIN_SEC_FLAGS}"
}

fuzzy_string_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local STRING_DEPS_SRC_ARR=()
  local lSTR_DEP=""

  # lets check for fuzzy string dependencies - we check for a minimum of 4 character strings, remove commends and entries with slashes
  # as they are already handled from the strict_string_dependency_checker
  mapfile -t STRING_DEPS_SRC_ARR < <(strings -n 4 "${lFILE_TO_CHECK}" | sed -r 's/^[[:space:]]*#.*$//' | tr " " "\n" | grep -v '/' | tr -d '[:blank:]' | grep -E '.{4,}' | sort -u || true)
  # print_output "[*] Testing ${#STRING_DEPS_SRC_ARR[@]} strings from source ${lFILE_TO_CHECK}"
  # check for all identified strings - if they match a file in the filesystem
  for lSTR_DEP in "${STRING_DEPS_SRC_ARR[@]}"; do
    search_parse_log_helper "${lSTR_DEP}" "FUZZY-STR" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
  done
}

strict_string_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local STRING_DEPS_SRC_ARR=()
  local lSTR_DEP=""

  # lets check for fuzzy string dependencies - we check for a minimum of 4 character strings, remove commends and /dev/ entries
  # additionally we check for a slash / as path indicator
  mapfile -t STRING_DEPS_SRC_ARR < <(strings -n 4 "${lFILE_TO_CHECK}" | sed -r 's/^[[:space:]]*#.*$//' | tr " " "\n" | grep -v '/dev/' | grep '/' | tr -d '[:blank:]' | grep -E '.{4,}' | sort -u || true)
  # print_output "[*] Testing ${#STRING_DEPS_SRC_ARR[@]} strings from source ${lFILE_TO_CHECK}"
  # check for all identified strings - if they match a file in the filesystem
  for lSTR_DEP in "${STRING_DEPS_SRC_ARR[@]}"; do
    search_parse_log_helper "${lSTR_DEP}" "STRICT-STR" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
  done
}

get_arch() {
  local lFILE_OUTPUT="${1:-}"

  local lARCH=""

  if [[ "${lFILE_OUTPUT}" == *"ELF"* ]]; then
    # e.g. ELF 32-bit LSB shared object, MIPS, MIPS32 version 1 (SYSV)
    # -> we need the part after the ','
    lARCH=$(echo "${lFILE_OUTPUT}" | cut -d ',' -f2-3)
  else
    # e.g. HTML document, ASCII text, with CRLF line terminators
    # -> we need the part in front of the ','
    lARCH=${lFILE_OUTPUT/,*/}
  fi
  echo "${lARCH//\"/\\\"}"
}

search_parse_log_helper() {
  local lDEPENDENCY="${1:-}"
  local lMARKER="${2:-}"
  local lFILE_TO_CHECK="${3:-}"
  local lDOT_FILE_tmp_FILE="${4:-}"
  local lSAFE_NAME="${5:-}"

  local lDEPENDENCY_TARGET_ARR=()
  local lDEPENDENCY_TARGET=""
  local lDEPNAME=""
  local lFILE_PATH=""
  local lSAFE_DEP_NAME=""
  local lFILE_SIZE=""
  local lBIN_SEC_FLAGS=""
  local lFILE_ARCH=""
  local lFILE_BIN_DATA=""
  local lCAPABILITIES=""
  local lFILENAME=""
  lFILENAME=$(basename "${lFILE_TO_CHECK}")

  [[ -z "${lDEPENDENCY}" ]] && return
  if ! [[ "${lDEPENDENCY}" =~ ^[a-zA-Z0-9./_~'-']+$ ]]; then
    return
  fi
  # remove paths like "/////////" or "asdf////bla"
  if [[ "${lDEPENDENCY}" == *"//"* ]]; then
    return
  fi
  # as we always search for paths we add a / to the search term
  if [[ "${lDEPENDENCY:0:1}" != "/" ]]; then
    lDEPENDENCY="/${lDEPENDENCY}"
  fi
  # print_output "[*] Testing ${lDEPENDENCY} from ${lFILE_TO_CHECK} against ${FIRMWARE_PATH} - marker ${lMARKER}"
  mapfile -t lDEPENDENCY_TARGET_ARR < <(find "${FIRMWARE_PATH}" -wholename "*${lDEPENDENCY%\/}" || true)
  if [[ "${#lDEPENDENCY_TARGET_ARR[@]}" -gt 0 ]]; then
    print_output "[*] ${lMARKER}: Testing ${#lDEPENDENCY_TARGET_ARR[@]} possible targets from source ${lFILE_TO_CHECK}" "${DEPENDENCY_MAP_LOG}" "" 0
    for lDEPENDENCY_TARGET in "${lDEPENDENCY_TARGET_ARR[@]}"; do
      # print_output "[*] Testing dependency ${lDEPENDENCY_TARGET} from source ${lFILE_TO_CHECK}"
      [[ -d "${lDEPENDENCY_TARGET}" ]] && continue
      lBIN_SEC_FLAGS="NONE"
      lFILE_ARCH="NA"
      lCAPABILITIES="NA"

      # echo "lDEPENDENCY_TARGET: ${lDEPENDENCY_TARGET}"
      lDEPNAME=$(basename "${lDEPENDENCY_TARGET}")
      if printf '%s\0' "${DEP_BLACKLIST_ARR[@]}" | grep -Fxqz -- "${lDEPNAME}"; then
        continue
      fi
      [[ "${lDEPNAME}" == "${lFILENAME}" ]] && continue
      lFILE_PATH=$(realpath "${lDEPENDENCY_TARGET}" 2>/dev/null || echo "${lDEPENDENCY_TARGET}")
      lSAFE_DEP_NAME="${lDEPNAME//\"/\\\"}"
      lFILE_SIZE=$(stat -c%s "${lDEPENDENCY_TARGET}" 2>/dev/null | numfmt --to=iec || echo "0")
      lFILE_BIN_DATA=$(file -b "${lDEPENDENCY_TARGET}" 2>/dev/null)
      lFILE_ARCH=$(get_arch "${lFILE_BIN_DATA}")
      lCOLOR=$(get_file_color "${lFILE_BIN_DATA}")

      if [[ "${lFILE_BIN_DATA}" == *"ELF"* ]]; then
        lBIN_SEC_FLAGS="$(binary_sec_scan "${lDEPENDENCY_TARGET}")"
        lCAPABILITIES=$(get_capabilities "${lFILE_TO_CHECK}" "${lFILE_ARCH}")
      fi
      # print_output "[!] Found ${lFILE_ARCH} - ${lDEPENDENCY_TARGET}"
      print_output "[*] ${lMARKER}: Found possible dependency ${ORANGE}${lDEPNAME}${NC} in ${ORANGE}${lSAFE_NAME}${NC}" "${DEPENDENCY_MAP_LOG}" "" 0
      if grep -q "  \"${lSAFE_NAME}\" -> \"${lSAFE_DEP_NAME}\";" "${lDOT_FILE_tmp_FILE}" 2>/dev/null; then
        print_output "[*] ${lMARKER}: The dependency is already available ... lets check ..." "${DEPENDENCY_MAP_LOG}" "" 0
        lURL="${lFILE_SIZE}|${lFILE_ARCH}|${lBIN_SEC_FLAGS}|${lFILE_PATH}|${lCAPABILITIES}"
        write_entry_with_marker_check "${lURL}" "${lSAFE_DEP_NAME}" "${lMARKER}" "${lCOLOR}" "${lDOT_FILE_tmp_FILE}"
      else
        print_output "[*] ${lMARKER}: Creating new dependency ${ORANGE}${lSAFE_DEP_NAME}${NC} for ${ORANGE}${lSAFE_NAME}${NC}" "${DEPENDENCY_MAP_LOG}" "" 0
        echo "  \"${lSAFE_NAME}\" -> \"${lSAFE_DEP_NAME}\";" >>"${lDOT_FILE_tmp_FILE}"
      fi
    done
  fi
}

write_entry_with_marker_check() {
  local lURL="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lMARKER="${3:-}"
  local lCOLOR="${4:-}"
  local lDOT_FILE_tmp_FILE="${5:-}"

  # if we find an entry we need to update our source markers
  local lCURRENT_ENTRY_ARR=()
  local lCURRENT_ENTRY=""
  local lCURRENT_SOURCES=""
  if ! [[ -f "${lDOT_FILE_tmp_FILE}" ]]; then
    touch "${lDOT_FILE_tmp_FILE}"
    echo "  \"${lSAFE_NAME}\" [shape=box, fillcolor=\"${lCOLOR}\", fontcolor=\"white\", URL=\"${lURL}|${lMARKER}\"];" >>"${lDOT_FILE_tmp_FILE}"
    return
  fi
  mapfile -t lCURRENT_ENTRY_ARR < <(grep "  \"${lSAFE_NAME}\" \[shape=.*, fillcolor=\".*\", URL=\".*" "${lDOT_FILE_tmp_FILE}" || true)
  if [[ "${#lCURRENT_ENTRY_ARR[@]}" -gt 0 ]]; then
    for lCURRENT_ENTRY in "${lCURRENT_ENTRY_ARR[@]}"; do
      lCURRENT_SOURCES=$(echo "${lCURRENT_ENTRY}" | grep -o "URL=.*" | cut -d '|' -f6 | cut -d '"' -f1 || true)
      # print_output "[*] lCURRENT_ENTRY: ${lCURRENT_ENTRY}" "no_log"
      # print_output "[*] lCURRENT_SOURCES: ${lCURRENT_SOURCES}" "no_log"
      local lUPDATED_SOURCES="${lCURRENT_SOURCES//NA/}"
      if [[ "${lCURRENT_SOURCES}" != *"${lMARKER}"* ]]; then
        local lUPDATED_SOURCES+=" ${lMARKER}"
        # print_output "[*] lUPDATED_SOURCES: ${lUPDATED_SOURCES}" "no_log"
        # missing sed command to replace the current marker field with the updated sources
        local lNEW_ENTRY=""
        # lNEW_ENTRY=$(echo "${lCURRENT_ENTRY}" | sed "s#|${lCURRENT_SOURCES}\"#|${lUPDATED_SOURCES}\"#")
        lNEW_ENTRY="${lCURRENT_ENTRY//\|${lCURRENT_SOURCES}\"/\|${lUPDATED_SOURCES}\"}"
        # print_output "[*] lNEW_ENTRY: ${lNEW_ENTRY}" "no_log"
        # awk -v s="$lCURRENT_ENTRY" -v r="$lNEW_ENTRY" 's != "" { while ( (i = index($0, s)) > 0 ) { $0 = substr($0, 1, i-1) r substr($0, i + length(s)) } } 1' "${lDOT_FILE_tmp_FILE}"
        awk -v s="${lCURRENT_ENTRY}" -v r="${lNEW_ENTRY}" '
          BEGIN {
              l = length(s)
          }
          {
              out = ""
              while (i = index($0, s)) {
                  out = out substr($0, 1, i-1) r
                  $0 = substr($0, i + l)
              }
              print out $0
          }' "${lDOT_FILE_tmp_FILE}" >"${lDOT_FILE_tmp_FILE}.tmp" && mv "${lDOT_FILE_tmp_FILE}.tmp" "${lDOT_FILE_tmp_FILE}"
      fi
    done
  fi
}

objdump_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local lOBJDUMP_DEPENDENCY_ARR=""
  local lOBJDUMP_DEP=""

  # Extract dynamic dependencies via objdump.
  mapfile -t lOBJDUMP_DEPENDENCY_ARR < <(objdump -p "${lFILE_TO_CHECK}" 2>/dev/null | grep "NEEDED" | awk '{print $2}' | sort -u || true)
  for lOBJDUMP_DEP in "${lOBJDUMP_DEPENDENCY_ARR[@]}"; do
    # print_output "[*] Testing OBJDUMP-LIB for $lFILE_TO_CHECK - dependency $lOBJDUMP_DEP"
    search_parse_log_helper "${lOBJDUMP_DEP}" "OBJDUMP-LIB" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
  done
}

ldd_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local lLDD_DEPENDENCY_ARR=""
  local lLDD_DEP=""

  # Extract dynamic dependencies via ldd.
  mapfile -t lLDD_DEPENDENCY_ARR < <(ldd "${lFILE_TO_CHECK}" 2>/dev/null | grep -o '/lib[^ ]*' | sort -u || true)
  for lLDD_DEP in "${lLDD_DEPENDENCY_ARR[@]}"; do
    # print_output "[*] Testing LDD-LIB for $lFILE_TO_CHECK - dependency $lLDD_DEP"
    search_parse_log_helper "${lLDD_DEP}" "LDD-LIB" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
  done
}

s115_emulation_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local lQEMU_STRACER_FILES_ARR=()
  local lQEMU_STRACER_FILE=""

  mapfile -t lQEMU_STRACER_FILES_ARR < <(find "${S115_LOG_DIR}" -name "stracer_*${lSAFE_NAME}*")

  for lQEMU_STRACER_FILE in "${lQEMU_STRACER_FILES_ARR[@]}"; do
    local lSTRACER_DEP_ARR=()
    local lSTRACER_DEP=""
    # extract all the open calls from the qemu logs:
    # grep -a "open\|stat\|bind\|chmod\|link\|write" | grep "/" | tr '"' '\n' | grep "^/" | sort -u
    mapfile -t lSTRACER_DEP_ARR < <(grep -a 'open\|stat\|bind\|chmod\|link\|write' "${lQEMU_STRACER_FILE}" | grep -v "proc" | tr '"' '\n' | grep "^/" | sort -u || true)
    for lSTRACER_DEP in "${lSTRACER_DEP_ARR[@]}"; do
      search_parse_log_helper "${lSTRACER_DEP}" "QEMU-USER" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
    done
  done
}

qemu_system_emulation_dependency_checker() {
  local lFILE_TO_CHECK="${1:-}"
  local lSAFE_NAME="${2:-}"
  local lDOT_FILE_tmp_FILE="${3:-}"

  local lQEMU_DEPENDENCY_ARR=""
  local lQEMU_DEP=""

  mapfile -t lQEMU_DEPENDENCY_ARR < <(grep "${lSAFE_NAME}" "${LOG_PATH_MODULE}"/system_emulation_results.log | awk '{print $3}' | sort -u || true)
  for lQEMU_DEP in "${lQEMU_DEPENDENCY_ARR[@]}"; do
    # print_output "[*] Testing system emulation dependency for $lFILE_TO_CHECK - dependency $lQEMU_DEP"
    search_parse_log_helper "${lQEMU_DEP}" "QEMU-SYS" "${lFILE_TO_CHECK}" "${lDOT_FILE_tmp_FILE}" "${lSAFE_NAME}"
  done
}

get_file_color() {
  local lFILE_BIN_DATA="${1:-}"

  if [[ "${lFILE_BIN_DATA}" == *"perl"* ]]; then
    lCOLOR="#b4a7d6" # some purple style
  elif [[ "${lFILE_BIN_DATA}" == *"lua"* ]]; then
    lCOLOR="#d5a6bd" # some light pink style
  elif [[ "${lFILE_BIN_DATA}" == *"PHP"* ]]; then
    lCOLOR="#f6b26b" # some light orange style
  elif [[ "${lFILE_BIN_DATA}" == *"Python"* ]]; then
    lCOLOR="#e69138" # some orange style
  elif [[ "${lFILE_BIN_DATA}" == *"shell script"* ]]; then
    lCOLOR="#93c47d" # light green
  elif [[ "${lFILE_BIN_DATA}" == *"shared object"* ]]; then
    lCOLOR="#3d85c6" # light dark blue
  elif [[ "${lFILE_BIN_DATA}" == *"ELF"* ]]; then
    lCOLOR="#1a3a5f" # dark blue
  elif [[ "${lFILE_BIN_DATA}" == *"Squashfs filesystem"* ]]; then
    lCOLOR="#b45f06" # dark orange
  elif [[ "${lFILE_BIN_DATA}" == *"HTML document"* ]]; then
    lCOLOR="#c27ba0" # light pink
  elif [[ "${lFILE_BIN_DATA}" == *"JavaScript"* ]]; then
    lCOLOR="#d5a6bd" # light pink
  elif [[ "${lFILE_BIN_DATA}" == *"ASCII text"* ]]; then
    lCOLOR="#ffd966" # orange
  elif [[ "${lFILE_BIN_DATA}" == *"data"* ]]; then
    lCOLOR="#8fce00" # green
  else
    lCOLOR="#f9cb9c" # very light orange
  fi
  echo "${lCOLOR}"
}

main_processing_thread_helper() {
  local lFILE_TO_CHECK="${1:-}"

  # Extract metadata and sanitize names to prevent DOT injection.
  local lFILENAME=""
  lFILENAME=$(basename "${lFILE_TO_CHECK}")
  local lSAFE_NAME=""
  lSAFE_NAME="${lFILENAME//\"/\\\"}"
  # ensure we escape stuff like [
  lSAFE_NAME=$(printf "%q\n" "${lSAFE_NAME}")
  local lFILE_PATH=""
  lFILE_PATH=$(realpath "${lFILE_TO_CHECK}" 2>/dev/null)

  local lMD5_SUM_FILE=""
  lMD5_SUM_FILE=$(md5sum "${lFILE_TO_CHECK}" | awk '{print $1}')
  local lDOT_FILE_tmp_FILE="${DOT_FILE_tmp_dir}/tmp_dot_${lMD5_SUM_FILE}.dot"
  # print_output "[*] Using tmp log file ${lDOT_FILE_tmp_FILE} for ${lFILE_TO_CHECK}" "no_log"

  local lBIN_SEC_FLAGS="NA"
  local lFILE_ARCH="NA"
  local lCAPABILITIES="NA"

  # Get file size and architecture.
  local lFILE_SIZE=""
  lFILE_SIZE=$(stat -c%s "${lFILE_TO_CHECK}" 2>/dev/null | numfmt --to=iec || echo 0)
  local lFILE_BIN_DATA=""
  lFILE_BIN_DATA=$(file -b "${lFILE_TO_CHECK}" 2>/dev/null)
  local lFILE_ARCH=""
  lFILE_ARCH=$(get_arch "${lFILE_BIN_DATA}")
  local lCOLOR=""
  lCOLOR=$(get_file_color "${lFILE_BIN_DATA}")

  if [[ "${lFILE_BIN_DATA}" == *"ELF"* ]]; then
    # BINARY SECURITY SCAN
    lBIN_SEC_FLAGS="$(binary_sec_scan "${lFILE_TO_CHECK}")"

    # CAPABILITY DISCOVERY
    lCAPABILITIES=$(get_capabilities "${lFILE_TO_CHECK}" "${lFILE_ARCH}")
  fi
  # print_output "[*] Testing details $lSAFE_NAME - arch: $lFILE_ARCH - $lBIN_SEC_FLAGS - $lCAPABILITIES"

  # Store data in the URL attribute for JavaScript retrieval.
  # Format: Size | Arch | SecFlags | FullPath | Capabilities | Source
  # echo "  \"${lSAFE_NAME}\" [shape=box, fillcolor=\"${COLOR_BIN}\", fontcolor=\"white\", URL=\"${lFILE_SIZE}|${lFILE_ARCH}|${lBIN_SEC_FLAGS}|${lFILE_PATH}|${lCAPABILITIES}|main-binary\"];" > "${lDOT_FILE_tmp_FILE}"
  local lMARKER="main-binary"
  local lURL="${lFILE_SIZE}|${lFILE_ARCH}|${lBIN_SEC_FLAGS}|${lFILE_PATH}|${lCAPABILITIES}"
  write_entry_with_marker_check "${lURL}" "${lSAFE_NAME}" "${lMARKER}" "${lCOLOR}" "${lDOT_FILE_tmp_FILE}"

  # following we can find calls to all our dependency checking modules
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "LDD-LIB"; then
    ldd_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
  fi
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "OBJDUMP-LIB"; then
    objdump_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
  fi
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "QEMU-USER"; then
    s115_emulation_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
  fi
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "QEMU-SYS"; then
    qemu_system_emulation_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
  fi
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "STRICT-STR"; then
    if [[ "${lFILE_BIN_DATA}" != *"Zip archive data"* ]]; then
      strict_string_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
    fi
  fi
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "FUZZY-STR"; then
    if [[ "${lFILE_BIN_DATA}" != *"Zip archive data"* ]]; then
      fuzzy_string_dependency_checker "${lFILE_TO_CHECK}" "${lSAFE_NAME}" "${lDOT_FILE_tmp_FILE}"
    fi
  fi
}

build_dot() {
  # GENERATE GRAPHVIZ DOT DATA
  # We use orthogonal splines and specific node separation for a clean dashboard look.
  print_output "[*] Dependency map analysis for ${FIRMWARE_PATH}" "" "${DEPENDENCY_MAP_LOG}"

  # preparation step - prepare and run the system emulation
  if printf '%s\0' "${DETECTION_MECHANISMS_ARR[@]}" | grep -Fxqz -- "QEMU-SYS"; then
    if [[ $(wc -l 2>/dev/null <"${LOG_PATH_MODULE}"/system_emulation_results.log) -lt 100 ]]; then
      system_emulator_init_runner
    fi
  fi

  # generate the header in our final dot file:
  # { cmd1; cmd2; } >> file
  {
    echo "digraph EMBA_Map {"
    echo "  rankdir=LR;"
    echo "  concentrate=true;"
    echo "  splines=ortho;"
    echo "  nodesep=0.2;"
    echo "  ranksep=2.0;"
    echo "  node [fontsize=10, fontname=\"Arial\", style=filled];"
  } >>"${DOT_FILE}"

  local lFILE_CNT=0
  local lFILE_TO_CHECK=""
  for lFILE_TO_CHECK in "${ALL_EXEC_FILES_ARR[@]}"; do
    lFILE_CNT=$((lFILE_CNT + 1))
    print_output "[*] Testing file ${ORANGE}${lFILE_CNT} / ${#ALL_EXEC_FILES_ARR[@]}${NC} - ${lFILE_TO_CHECK}" "${DEPENDENCY_MAP_LOG}" "" 0

    if [[ "${lFILE_CNT}" -gt "${MAX_MAP_FILES}" ]]; then
      break
    fi

    # which files should not be handled
    [[ "${lFILE_TO_CHECK}" == *"/decompressed.bin" ]] && continue
    [[ "${lFILE_TO_CHECK}" == *".raw" ]] && continue


    main_processing_thread_helper "${lFILE_TO_CHECK}" &
    while (($(jobs -r | wc -l) >= MAX_MAP_JOBS)); do
      wait -n
    done
  done

  # handle links
  local lFS_LINKS_ARR=()
  local lLINK_TO_CHECK=""
  mapfile -t lFS_LINKS_ARR < <(find "${FIRMWARE_PATH}" -type l)

  for lLINK_TO_CHECK in "${lFS_LINKS_ARR[@]}"; do
    print_output "[*] Testing link ${ORANGE}${lFILE_CNT} / $((${#ALL_EXEC_FILES_ARR[@]} + ${#lFS_LINKS_ARR[@]}))${NC} - ${lLINK_TO_CHECK}" "${DEPENDENCY_MAP_LOG}" "" 0
    lLNK_TARGET=$(readlink "${lLINK_TO_CHECK}" 2>/dev/null || echo "${lLINK_TO_CHECK}")
    # if the link targets something like ../../asdf -> we check for asdf
    while [[ "${lLNK_TARGET}" == "../"* ]]; do
      lLNK_TARGET="${lLNK_TARGET#..\/}"
    done
    local lLNK_TARGET_FILES_ARR=()
    mapfile -t lLNK_TARGET_FILES_ARR < <(find "${FIRMWARE_PATH}" -type f -wholename "*${lLNK_TARGET%\/}")
    local LNK_TARGET_FILE=""
    for LNK_TARGET_FILE in "${lLNK_TARGET_FILES_ARR[@]}"; do
      lMD5_SUM_FILE=""
      lMD5_SUM_FILE=$(md5sum "${LNK_TARGET_FILE}" | awk '{print $1}')
      lDOT_FILE_tmp_FILE="${DOT_FILE_tmp_dir}/tmp_dot_${lMD5_SUM_FILE}.dot"
      print_output "[*] Using tmp log file ${lDOT_FILE_tmp_FILE} for link ${lLINK_TO_CHECK}" "${DEPENDENCY_MAP_LOG}" "" 0
      if [[ -f ${lDOT_FILE_tmp_FILE} ]]; then
        print_output "[*] dot file for ${lMD5_SUM_FILE} - link: ${lLINK_TO_CHECK} - target file: ${LNK_TARGET_FILE} already available" "${DEPENDENCY_MAP_LOG}" "" 0
      else
        touch "${lDOT_FILE_tmp_FILE}"
      fi
      lDEPNAME=$(basename "${lLINK_TO_CHECK}")
      local lLNK_TARGET_NAME=""
      lLNK_TARGET_NAME=$(basename "${LNK_TARGET_FILE}")
      lURL="NA|LNK to ${lLNK_TARGET_NAME}|NA|${lLINK_TO_CHECK}|NA"
      lMARKER="lnk_detection"
      echo "  \"${lDEPNAME}\" [shape=ellipse, fillcolor=\"${COLOR_LNK}\", fontcolor=\"white\", URL=\"${lURL}|${lMARKER}\"];" >>"${lDOT_FILE_tmp_FILE}"
      echo "  \"${lDEPNAME}\" -> \"${lLNK_TARGET_NAME}\";" >>"${lDOT_FILE_tmp_FILE}"
    done
    if [[ "${lFILE_CNT}" -gt "${MAX_MAP_FILES}" ]]; then
      break
    fi
    lFILE_CNT=$((lFILE_CNT + 1))
  done

  # wait for all jobs finished
  print_output "[*] Waiting for all map building jobs ..." "no_log"
  wait

  # lets put all dot files together to the final dot
  print_output "[*] Processing tmp dot files - building the final map ..." "${DEPENDENCY_MAP_LOG}" "" 0
  mapfile -t lDOT_FILE_tmp_ALL_FILES < <(find "${DOT_FILE_tmp_dir}" -type f)
  for lDOT_FILE_tmp in "${lDOT_FILE_tmp_ALL_FILES[@]}"; do
    print_output "[*] Processing dot file ${lDOT_FILE_tmp}" "${DEPENDENCY_MAP_LOG}" "" 0
    cat "${lDOT_FILE_tmp}" >>"${DOT_FILE}"
  done

  echo "}" >>"${DOT_FILE}"
}

build_svg() {
  sub_module_title "SVG dependency map"

  print_output "[*] Neato map with overlap prevention" "" "${SVG_FILE}"
  neato -Goverlap=false -Gsep=+20 -Tsvg "${DOT_FILE}" -o "${SVG_FILE}" || print_output "[-] WARNING: Neato SVG generation failed"

  # in case the neato generator failed
  if [[ ! -f "${SVG_FILE}" ]]; then
    print_output "[*] Dot map with overlap prevention" "" "${SVG_FILE//\.svg/_dot.svg}"
    dot -Goverlap=false -Gsep=+20 -Tsvg "${DOT_FILE}" -o "${SVG_FILE//\.svg/_dot.svg}" || print_output "[-] WARNING: Dot SVG generation failed"
  fi

  if [[ -f "${SVG_FILE}" ]]; then
    # Modify SVG header to include an ID for the pan-zoom library.
    sed -i 's|<svg [^>]*>|<svg id="map-svg" style="width:100%;height:100%;">|' "${SVG_FILE}"
    # Optional: Falls Graphviz hartgecodete width/height reinschreibt, diese löschen
    sed -i 's/width="[^"]*" height="[^"]*"//i' "${SVG_FILE}"
  fi
  if [[ -f "${SVG_FILE//\.svg/_dot.svg}" ]]; then
    # Modify SVG header to include an ID for the pan-zoom library.
    sed -i 's|<svg [^>]*>|<svg id="map-svg" style="width:100%;height:100%;">|' "${SVG_FILE//\.svg/_dot.svg}"
    # Optional: Falls Graphviz hartgecodete width/height reinschreibt, diese löschen
    sed -i 's/width="[^"]*" height="[^"]*"//i' "${SVG_FILE//\.svg/_dot.svg}"
  fi
}

build_html() {
  sub_module_title "Interactive HTML dependency map"

  if [[ -f "${SVG_FILE}" ]]; then
    sed -e "/%%SVG_FILE_CONTENT%%/{r ${SVG_FILE}" -e "d}" "${BASE_HTML_TEMPLATE}" >"${HTML_FILE}"
    sed -i "s/%%COLOR_BIN%%/${COLOR_BIN}/" "${HTML_FILE}"
    sed -i "s#%%EMBA_LOGO%%#$(basename "${LOGO_FILE}")#" "${HTML_FILE}"
    sed -i "s#%%JS_LIB%%#$(basename "${JS_LIB}")#" "${HTML_FILE}"
  fi
  if [[ -f "${SVG_FILE//\.svg/_dot.svg}" ]]; then
    sed -e "/%%SVG_FILE_CONTENT%%/{r ${SVG_FILE//\.svg/_dot.svg}" -e "d}" "${BASE_HTML_TEMPLATE}" >"${HTML_FILE//-map.html/-dot_map.html}"
    sed -i "s/%%COLOR_BIN%%/${COLOR_BIN}/" "${HTML_FILE//-map.html/-dot_map.html}"
    sed -i "s#%%EMBA_LOGO%%#$(basename "${LOGO_FILE}")#" "${HTML_FILE//-map.html/-dot_map.html}"
    sed -i "s#%%JS_LIB%%#$(basename "${JS_LIB}")#" "${HTML_FILE//-map.html/-dot_map.html}"
  fi

  if [[ -f "${HTML_FILE}" && -f "${SVG_FILE}" ]]; then
    print_output "[+] EMBA dependency neato map generated: ${ORANGE}${HTML_FILE}${NC}"
    write_link "${HTML_FILE}"
  fi
  if [[ -f "${HTML_FILE//-map.html/-dot_map.html}" && -f "${SVG_FILE//\.svg/_dot.svg}" ]]; then
    print_output "[+] EMBA dependency dot map generated: ${ORANGE}${HTML_FILE//-map.html/-dot_map.html}${NC}"
    write_link "${HTML_FILE//-map.html/-dot_map.html}"
  fi
}
