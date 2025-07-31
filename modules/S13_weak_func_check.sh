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

# Description:  This module was the first module that existed in emba. The main idea was to identify the binaries that were using weak
#               functions and to establish a ranking of areas to look at first.
#               It iterates through all executables and searches with objdump for interesting functions like strcpy (defined in helpers.cfg).

# Threading priority - if set to 1, these modules will be executed first
# do not prio s13 and s14 as the dependency check during runtime will fail!
export THREAD_PRIO=0

S13_weak_func_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for weak functions (intense)"
  pre_module_reporter "${FUNCNAME[0]}"

  local lSTRCPY_CNT=0
  local lBINARY=""
  local lVULNERABLE_FUNCTIONS_ARR=()
  local lVULNERABLE_FUNCTIONS_VAR=""
  local lERR_PRINTED=0
  local lWAIT_PIDS_S13_ARR=()
  local lBIN_FILE=""

  if [[ -n "${ARCH}" ]] ; then
    # This module waits for S12 - binary protections
    # check emba.log for S12_binary_protection starting
    module_wait "S12_binary_protection"

    if ! [[ -d "${TMP_DIR}" ]]; then
      mkdir "${TMP_DIR}"
    fi

    # OBJDMP_ARCH, READELF are set in dependency check
    # Test source: https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml

    lVULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a lVULNERABLE_FUNCTIONS_ARR <<<"$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"

    write_csv_log "binary" "function" "function count" "common linux file" "networking"

    while read -r lBINARY; do
      lBIN_FILE="$(echo "${lBINARY}" | cut -d ';' -f8)"
      lBINARY="$(echo "${lBINARY}" | cut -d ';' -f2)"
      if [[ "${lBIN_FILE}" == *"ELF"* ]]; then
        if [[ "${lBIN_FILE}" == *"x86-64"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_x86_64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_x86_64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" =~ Intel.80386 ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" =~ Intel\ i386 ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi

        elif [[ "${lBIN_FILE}" =~ 32-bit.*ARM ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_ARM32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_ARM32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" =~ 64-bit.*ARM ]]; then
          # ARM 64 code is in alpha state and nearly not tested!
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_ARM64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_ARM64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"MIPS"* ]]; then
          # MIPS32 and MIPS64
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_MIPS "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_MIPS "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"PowerPC"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_PPC32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_PPC32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"Altera Nios II"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            function_check_NIOS2 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S13_ARR+=( "${lTMP_PID}" )
          else
            function_check_NIOS2 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"QUALCOMM DSP6"* ]]; then
          if [[ "${lERR_PRINTED}" -eq 0 ]]; then
            print_output "[-] Qualcom DSP6 is currently not supported from objdump"
            print_output "[-] The binaries will be analysed from radare2 module s14"
            lERR_PRINTED=1
          fi
        elif [[ "${lBIN_FILE}" == *"Tricore"* ]]; then
          if [[ "${lERR_PRINTED}" -eq 0 ]]; then
            print_output "[-] Tricore architecture is currently not supported from objdump"
            print_output "[-] The binaries will be analysed from radare2 module s14"
            lERR_PRINTED=1
          fi
        else
          print_output "[-] Something went wrong ... no supported architecture available"
          print_output "[-] Tested binary: ${ORANGE}${lBINARY}${NC}"
          print_output "[-] Please open an issue at https://github.com/e-m-b-a/emba/issues"
        fi
      fi
      if [[ "${THREADED}" -eq 1 ]]; then
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S13_ARR
      fi
    done < <(grep -v "ASCII text\|Unicode text\|.raw;" "${P99_CSV_LOG}" | grep "ELF" || true)

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S13_ARR[@]}"

    # ensure that we do not have result files without real results:
    find "${LOG_DIR}"/s13_weak_func_check/vul_func_0*.txt -exec rm {} \; 2>/dev/null || true

    print_top10_statistics "${lVULNERABLE_FUNCTIONS_ARR[@]}"

    if [[ -f "${TMP_DIR}"/S13_STRCPY_CNT.tmp ]]; then
      lSTRCPY_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S13_STRCPY_CNT.tmp)
    fi

    local lBINS_CNT=0
    lBINS_CNT=$(grep -v "ASCII text\|Unicode text\|.raw;" "${P99_CSV_LOG}" | grep -c ";ELF")
    write_log ""
    write_log "[*] Statistics:${lSTRCPY_CNT}:${lBINS_CNT}"
    write_log ""
    write_log "[*] Statistics1:${ARCH}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lSTRCPY_CNT}"
}

function_check_NIOS2() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  local lSTRCPY_CNT=0
  local lSTRLEN_ADDR=""
  local lFUNC_ADDR=""
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lOBJDUMP_PARAM_ARR=("-d")
  # if we have less than 3 lines of output we do not have disassembled code and we try
  # again with another set of options
  if [[ "$("${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | wc -l)" -lt 4 ]]; then
    if [[ "$("${OBJDUMP}" -D -b binary -m nios2 "${lBINARY_}" | wc -l)" -ge 4 ]]; then
      lOBJDUMP_PARAM_ARR=("-D" "-b" "binary" "-m" "nios2")
    fi
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    # identify working readelf params:
    local lREADELF_PARAM_ARR=("-W" "-a")
    local lFUNC_TEST=""
    lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
    if [[ -z "${lFUNC_TEST}" ]] || [[ "${lFUNC_TEST}" == "00000000" ]]; then
      lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
      if [[ -n "${lFUNC_TEST}" ]] && [[ "${lFUNC_TEST}" != "00000000" ]]; then
        lREADELF_PARAM_ARR+=("--use-dynamic")
      fi
    fi

    if ( readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2> /dev/null ) ; then
      NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      lFUNC_ADDR=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E \ "${lFUNCTION}" | grep -m1 UND | cut -d: -f2 | awk '{print $1}' | sed -e 's/^[0]*//' 2> /dev/null || true)
      if [[ -z "${lFUNC_ADDR}" ]] || [[ "${lFUNC_ADDR}" == "00000000" ]]; then
        continue
      fi
      lSTRLEN_ADDR=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E \ "strlen" | grep -m1 UND | cut -d: -f2 | awk '{print $1}' | sed -e 's/^[0]*//' 2> /dev/null || true)

      log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
      log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -E -A 20 "call.*${lFUNC_ADDR}" | sed s/-"${lFUNC_ADDR}"\(gp\)/"${lFUNCTION}"/ 2> /dev/null >> "${FUNC_LOG}" || true
      else
        "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -E -A 2 -B 20 "call.*${lFUNC_ADDR}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        sed -i -r "s/^.*:.*(${lFUNC_ADDR}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
        COUNT_FUNC="$(grep -c "call.*""${lFUNC_ADDR}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*${lSTRLEN_ADDR}" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "${FUNC_LOG}"  2> /dev/null || true)
          COUNT_MMAP_OK="NA"
        fi
        log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_PPC32() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    # identify working readelf params:
    local lREADELF_PARAM_ARR=("-W" "-a")
    local lFUNC_TEST=""
    lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
    if [[ -z "${lFUNC_TEST}" ]] || [[ "${lFUNC_TEST}" == "00000000" ]]; then
      lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
      if [[ -n "${lFUNC_TEST}" ]] && [[ "${lFUNC_TEST}" != "00000000" ]]; then
        lREADELF_PARAM_ARR+=("--use-dynamic")
      fi
    fi

    if ( readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2> /dev/null ) ; then
      NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
      log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 20 "bl.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 2 -B 20 "bl.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
        COUNT_FUNC="$(grep -c "bl.*""${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_MIPS() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lSTRLEN_ADDR=""
  local lFUNC_ADDR=""
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lOBJDUMP_PARAM_ARR=("-d")
  # if we have less than 3 lines of output we do not have disassembled code and we try
  # again with another set of options
  if [[ "$("${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | wc -l)" -lt 4 ]]; then
    if [[ "$("${OBJDUMP}" -D -b binary -m mips "${lBINARY_}" | wc -l)" -ge 4 ]]; then
      lOBJDUMP_PARAM_ARR=("-D" "-b" "binary" "-m" "mips")
    fi
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    local lREADELF_PARAM_ARR=("-W" "-a")
    lFUNC_ADDR=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E \ "${lFUNCTION}" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null || true)
    if [[ -z "${lFUNC_ADDR}" ]] || [[ "${lFUNC_ADDR}" == "00000000" ]]; then
      lFUNC_ADDR=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E \ "${lFUNCTION}" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null || true)
      if [[ -n "${lFUNC_ADDR}" ]] && [[ "${lFUNC_ADDR}" != "00000000" ]]; then
        lREADELF_PARAM_ARR+=("--use-dynamic")
      fi
    fi
    if [[ -z "${lFUNC_ADDR}" ]] || [[ "${lFUNC_ADDR}" == "00000000" ]]; then
      continue
    fi
    lSTRLEN_ADDR=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E \ "strlen" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null || true)
    NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    if [[ -n "${lFUNC_ADDR}" ]] ; then
      export FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
      log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 20 "${lFUNC_ADDR}""(gp)" | sed s/-"${lFUNC_ADDR}"\(gp\)/"${lFUNCTION}"/ >> "${FUNC_LOG}" || true
      else
        "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 2 -B 25 "${lFUNC_ADDR}""(gp)" | sed s/-"${lFUNC_ADDR}"\(gp\)/"${lFUNCTION}"/ | sed s/-"${lSTRLEN_ADDR}"\(gp\)/strlen/ >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
        COUNT_FUNC="$(grep -c "l[wd].*""${lFUNCTION}" "${FUNC_LOG}" 2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "l[wd].*strlen" "${FUNC_LOG}" 2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # Check this. This test is very rough:
          COUNT_MMAP_OK=$(grep -c ",-1$" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_ARM64() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi
  # if we have less than 3 lines of output we do not have disassembled code and we try
  # again with another set of options
  local lOBJDUMP_PARAM_ARR=("-d")
  if [[ "$("${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | wc -l)" -lt 4 ]]; then
    if [[ "$("${OBJDUMP}" -D -b binary -m aarch64 "${lBINARY_}" | wc -l)" -ge 4 ]]; then
      lOBJDUMP_PARAM_ARR=("-D" "-b" "binary" "-m" "aarch64")
    fi
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    local lREADELF_PARAM_ARR=("-W" "-a")
    NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    if [[ -z "${NETWORKING}" ]] || [[ "${NETWORKING}" == "00000000" ]]; then
      NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    fi
    export FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
    log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 20 "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 2 -B 20 "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l 2>/dev/null < "${FUNC_LOG}") -gt 0 ]] ; then
      sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
      COUNT_FUNC="$(grep -c "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "[[:blank:]]bl[[:blank:]].*<strlen" "${FUNC_LOG}"  2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Test not implemented on ARM64
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_ARM32() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi
  # if we have less than 3 lines of output we do not have disassembled code and we try
  # again with another set of options
  local lOBJDUMP_PARAM_ARR=("-d")
  if [[ "$("${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | wc -l)" -lt 4 ]]; then
    if [[ "$("${OBJDUMP}" -D -b binary -m arm "${lBINARY_}" | wc -l)" -ge 4 ]]; then
      lOBJDUMP_PARAM_ARR=("-D" "-b" "binary" "-m" "arm")
    fi
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    local lREADELF_PARAM_ARR=("-W" "-a")
    NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    if [[ -z "${NETWORKING}" ]] || [[ "${NETWORKING}" == "00000000" ]]; then
      NETWORKING=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    fi

    export FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
    log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 20 "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      "${OBJDUMP}" "${lOBJDUMP_PARAM_ARR[@]}" "${lBINARY_}" | grep -A 2 -B 20 "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
      sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
      COUNT_FUNC="$(grep -c "[[:blank:]]bl[[:blank:]].*<${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "[[:blank:]]bl[[:blank:]].*<strlen" "${FUNC_LOG}"  2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this testcase. Not sure if it works in all cases!
        COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null || true)
      fi
      log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_x86() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    # identify working readelf params:
    local lREADELF_PARAM_ARR=("-W" "-a")
    local lFUNC_TEST=""
    lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
    if [[ -z "${lFUNC_TEST}" ]] || [[ "${lFUNC_TEST}" == "00000000" ]]; then
      lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
      if [[ -n "${lFUNC_TEST}" ]] && [[ "${lFUNC_TEST}" != "00000000" ]]; then
        lREADELF_PARAM_ARR+=("--use-dynamic")
      fi
    fi

    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2>/dev/null ) ; then
      NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
      export FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
      log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 20 "call.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 2 -B 20 "call.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
        COUNT_FUNC="$(grep -c -e "call.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

function_check_x86_64() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_FUNC=0
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    # identify working readelf params:
    local lREADELF_PARAM_ARR=("-W" "-a")
    local lFUNC_TEST=""
    lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
    if [[ -z "${lFUNC_TEST}" ]] || [[ "${lFUNC_TEST}" == "00000000" ]]; then
      lFUNC_TEST=$(readelf "${lBINARY_}" "${lREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
      if [[ -n "${lFUNC_TEST}" ]] && [[ "${lFUNC_TEST}" != "00000000" ]]; then
        lREADELF_PARAM_ARR+=("--use-dynamic")
      fi
    fi

    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2>/dev/null ) ; then
      NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2>/dev/null || true)
      export FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      log_bin_hardening "${lBINARY_}" "${FUNC_LOG}"
      log_func_header "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 20 "call.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        "${OBJDUMP}" -D "${lBINARY_}" | grep -E -A 2 -B 20 "call.*<${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        sed -i -r "s/^.*:.*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${FUNC_LOG}" || true
        COUNT_FUNC="$(grep -c -e "call.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy"  ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap"  ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S13_STRCPY_CNT.tmp
}

print_top10_statistics() {
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lFUNCTION=""
  local lRESULTS_ARR=()
  local lBINARY=""

  sub_module_title "Top 10 legacy C functions - Objdump disasm mode"

  if [[ "$(find "${LOG_PATH_MODULE}" -xdev -iname "vul_func_*_*-*.txt" | wc -l)" -gt 0 ]]; then
    for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
      local lSEARCH_TERM=""
      local lF_COUNTER=0
      readarray -t lRESULTS_ARR < <( find "${LOG_PATH_MODULE}" -xdev -iname "vul_func_*_""${lFUNCTION}""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""${lFUNCTION}""-/  /" | sed "s/\.txt//" | grep -v "^0\ " 2> /dev/null || true)

      if [[ "${#lRESULTS_ARR[@]}" -gt 0 ]]; then
        print_ln
        print_output "[+] ""${lFUNCTION}"" - top 10 results:"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          write_anchor "strcpysummary"
        elif [[ "${lFUNCTION}" == "system" ]] ; then
          write_anchor "systemsummary"
        fi
        for lBINARY in "${lRESULTS_ARR[@]}" ; do
          lSEARCH_TERM="$(echo "${lBINARY}" | awk '{print $2}')"
          lF_COUNTER="$(echo "${lBINARY}" | awk '{print $1}')"
          [[ "${lF_COUNTER}" -eq 0 ]] && continue
          if [[ -f "${BASE_LINUX_FILES}" ]]; then
            # if we have the base linux config file we are checking it:
            if grep -E -q "^${lSEARCH_TERM}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
              # shellcheck disable=SC2153
              printf "${GREEN}\t%-5.5s : %-15.15s : common linux file: yes${NC}\n" "${lF_COUNTER}" "${lSEARCH_TERM}" | tee -a "${LOG_FILE}" || true
            else
              printf "${ORANGE}\t%-5.5s : %-15.15s : common linux file: no${NC}\n" "${lF_COUNTER}" "${lSEARCH_TERM}" | tee -a "${LOG_FILE}" || true
            fi
          else
            print_output "$(indent "$(orange "${lF_COUNTER}""\t:\t""${lSEARCH_TERM}")")"
          fi
          if [[ -f "${LOG_PATH_MODULE}""/vul_func_""${lF_COUNTER}""_""${lFUNCTION}"-"${lSEARCH_TERM}"".txt" ]]; then
            write_link "${LOG_PATH_MODULE}""/vul_func_""${lF_COUNTER}""_""${lFUNCTION}"-"${lSEARCH_TERM}"".txt"
          fi
        done
        print_ln
      fi
    done
  else
    print_output "$(indent "$(orange "No weak binary functions found - check it manually with readelf and objdump -D")")"
  fi
}

log_bin_hardening() {
  local lBIN="${1:-}"
  local lFUNC_LOG="${2:-}"

  local lNAME=""
  lNAME="$(basename "${lBIN}")"

  local lHEAD_BIN_PROT=""
  local lBIN_PROT=""

  if [[ -f "${S12_LOG}" ]]; then
    write_log "[*] Binary protection state of ${ORANGE}${lNAME}${NC}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
    # get headline:
    lHEAD_BIN_PROT=$(grep "FORTI.*FILE" "${S12_LOG}" | sed 's/FORTI.*//'| sort -u || true)
    write_log "  ${lHEAD_BIN_PROT}" "${lFUNC_LOG}"
    # get binary entry - we have three possibilities
    # #1 - the full binary path
    # #2 - stripped binary path from cut_path()
    # #3 - only binary name - weakest mechanism
    if [[ "$(grep "${lBIN} " "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u | wc -l)" -gt 0 ]]; then
      # print_output "[*] Binary protection state of ${lNAME} / ${GREEN}${lBIN}${NC}"
      lBIN_PROT=$(grep "${lBIN} " "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    elif [[ "$(grep "$(cut_path "${lBIN}") " "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u | wc -l)" -gt 0 ]]; then
      # print_output "[*] Binary protection state of ${lNAME} / ${GREEN}$(cut_path ${lBIN})${NC}"
      lBIN_PROT=$(grep "$(cut_path "${lBIN}") " "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    else
      # print_output "[*] Binary protection state of ${GREEN}${lNAME}${NC} / ${lBIN}"
      lBIN_PROT=$(grep '/'"${lNAME}"' ' "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    fi
    write_log "  ${lBIN_PROT}${NC}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
  fi
}

log_func_header() {
  local lNAME="${1:-}"
  local lFUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  write_log "${NC}" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${lFUNCTION}${NC} tear down of ${ORANGE}${lNAME}${NC}" "${lFUNC_LOG}"
  write_log "" "${lFUNC_LOG}"
}

log_func_footer() {
  local lNAME="${1:-}"
  local lFUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  write_log "\n${NC}" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${lFUNCTION}${NC} used ${ORANGE}${COUNT_FUNC}${NC} times ${ORANGE}${lNAME}${NC}" "${lFUNC_LOG}"
  write_log "" "${lFUNC_LOG}"
}

output_function_details()
{
  write_s13_log()
  {
    local lOUTPUT="${1:-}"
    local lLINK="${2:-}"
    local lLOG_FILE="${3:-}"

    local lOLD_LOG_FILE="${lLOG_FILE}"
    print_output "${lOUTPUT}" "" "${lLINK}"

    if [[ -f "${lLOG_FILE}" ]]; then
      cat "${lLOG_FILE}" >> "${lOLD_LOG_FILE}"
      rm "${lLOG_FILE}" 2> /dev/null || true
    fi
    lLOG_FILE="${lOLD_LOG_FILE}"
  }

  local lBINARY_="${1:-}"
  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi
  local lFUNCTION="${2:-}"
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}")

  local lLOG_FILE_LOC=""
  lLOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${lFUNCTION}"-"${lBIN_NAME}".txt

  # check if this is common linux file:
  local lCOMMON_FILES_FOUND=""
  local lSEARCH_TERM=""
  local lNETWORKING_=""
  local lNW_CSV=""
  local lCFF_CSV=""

  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    lSEARCH_TERM=$(basename "${lBINARY_}")
    if grep -q "^${lSEARCH_TERM}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      lCOMMON_FILES_FOUND="${CYAN}"" - common linux file: yes - "
      write_log "[+] File $(print_path "${lBINARY_}") found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
      lCFF_CSV="true"
    else
      write_log "[+] File $(print_path "${lBINARY_}") not found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
      lCOMMON_FILES_FOUND="${RED}"" - common linux file: no -"
      lCFF_CSV="false"
    fi
  else
    lCOMMON_FILES_FOUND=" -"
  fi

  local lLOG_FILE_LOC_OLD="${lLOG_FILE_LOC}"
  lLOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${COUNT_FUNC}"_"${lFUNCTION}"-"${lBIN_NAME}".txt

  if [[ -f "${lLOG_FILE_LOC_OLD}" ]]; then
    mv "${lLOG_FILE_LOC_OLD}" "${lLOG_FILE_LOC}" 2> /dev/null || true
  fi

  if [[ "${NETWORKING}" -gt 1 ]]; then
    lNETWORKING_="${ORANGE}networking: yes${NC}"
    lNW_CSV="yes"
  else
    lNETWORKING_="${GREEN}networking: no${NC}"
    lNW_CSV="no"
  fi

  if [[ ${COUNT_FUNC} -ne 0 ]] ; then
    local lOUTPUT=""
    if [[ "${lFUNCTION}" == "strcpy" ]] ; then
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""strlen: ""${COUNT_STRLEN}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    elif [[ "${lFUNCTION}" == "mmap" ]] ; then
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""${COUNT_MMAP_OK}"" ""${NC}"
    else
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    fi
    write_s13_log "${lOUTPUT}" "${lLOG_FILE_LOC}" "${LOG_PATH_MODULE}""/vul_func_tmp_""${lFUNCTION}"-"${lBIN_NAME}"".txt"
    write_csv_log "$(print_path "${lBINARY_}")" "${lFUNCTION}" "${COUNT_FUNC}" "${lCFF_CSV}" "${lNW_CSV}"
  fi
}

