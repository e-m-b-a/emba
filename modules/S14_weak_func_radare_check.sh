#!/bin/bash -p
# shellcheck disable=SC2016

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  This module identifies binaries that are using weak functions and creates a ranking of areas to look first.
#               It iterates through all executables and searches with radare for interesting functions like strcpy (defined in helpers.cfg).
#               As the module runs quite long with high CPU load it only gets executed when the objdump module fails.

# Threading priority - if set to 1, these modules will be executed first
# do not prio s13 and s14 as the dependency check during runtime will fail!
export THREAD_PRIO=0

S14_weak_func_radare_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for weak functions (radare mode)"
  pre_module_reporter "${FUNCNAME[0]}"

  local lSTRCPY_CNT=0
  local lFCT_CNT=0
  export FUNC_LOG=""
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0
  export COUNT_FUNC=0
  local lWAIT_PIDS_S14_ARR=()

  if [[ -n "${ARCH}" ]] ; then
    # as this module is slow we only run it in case the objdump method from s13 was not working as expected
    # This module waits for S12 - binary protections and s13
    # check emba.log for S12_binary_protection starting
    module_wait "S12_binary_protection"
    module_wait "S13_weak_func_check"

    local lBINARY=""
    local lBIN_NAME=""
    local lBIN_FILE=""
    local lVULNERABLE_FUNCTIONS_ARR=()
    local lVULNERABLE_FUNCTIONS_VAR=""

    lVULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a lVULNERABLE_FUNCTIONS_ARR <<<"$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"

    write_csv_log "binary" "function" "function count" "common linux file" "networking"

    while read -r lBINARY; do
      lBIN_FILE="$(echo "${lBINARY}" | cut -d ';' -f8)"
      lBINARY="$(echo "${lBINARY}" | cut -d ';' -f2)"
      # we run throught the bins and check if the bin was already analysed via objdump:
      lBIN_NAME=$(basename "${lBINARY}" 2> /dev/null)
      if [[ "$(find "${LOG_DIR}"/s13_weak_func_check/vul_func_*"${lBIN_NAME}".txt 2>/dev/null | wc -l)" -gt 0 ]]; then
        continue
      fi
      if [[ "${lBIN_FILE}" == *"ELF"* ]]; then
        if [[ "${lBIN_FILE}" == *"x86-64"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_x86_64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_x86_64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" =~ Intel.80386 ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_x86
          fi
        elif [[ "${lBIN_FILE}" =~ Intel\ i386 ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_x86 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_x86
          fi

        elif [[ "${lBIN_FILE}" =~ 32-bit.*ARM ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_ARM32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_ARM32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" =~ 64-bit.*ARM ]]; then
          # ARM 64 code is in alpha state and nearly not tested!
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_ARM64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_ARM64 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"MIPS"* ]]; then
          # MIPS32 and MIPS64
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_MIPS "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_MIPS "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"PowerPC"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_PPC32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_PPC32 "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"QUALCOMM DSP6"* ]]; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_hexagon "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
            local lTMP_PID="$!"
            store_kill_pids "${lTMP_PID}"
            lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          else
            radare_function_check_hexagon "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          fi
        elif [[ "${lBIN_FILE}" == *"Tricore"* ]]; then
          print_output "[-] Tricore architecture currently not fully supported."
          print_output "[-] Tested binary: ${ORANGE}${lBINARY}${NC}"
          print_output "[-] Please open an issue at https://github.com/e-m-b-a/emba/issues"
          # if [[ "${THREADED}" -eq 1 ]]; then
          #   radare_function_check_tricore "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
          #   local lTMP_PID="$!"
          #   store_kill_pids "${lTMP_PID}"
          #   lWAIT_PIDS_S14_ARR+=( "${lTMP_PID}" )
          # else
          #   radare_function_check_tricore "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
          # fi
        else
          print_output "[-] Something went wrong ... no supported architecture available"
          print_output "[-] Tested binary: ${ORANGE}${lBINARY}${NC}"
          print_output "[-] Please open an issue at https://github.com/e-m-b-a/emba/issues"
        fi
      fi

      if [[ "${THREADED}" -eq 1 ]]; then
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S14_ARR
      fi
    done < <(grep -v "ASCII text\|Unicode text\|.raw;" "${P99_CSV_LOG}" | grep "ELF" || true)

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S14_ARR[@]}"

    radare_print_top10_statistics "${lVULNERABLE_FUNCTIONS_ARR[@]}"

    if [[ -f "${TMP_DIR}"/S14_STRCPY_CNT.tmp ]]; then
      lSTRCPY_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S14_STRCPY_CNT.tmp)
      lFCT_CNT="${lSTRCPY_CNT}"
    fi
    if [[ "${lFCT_CNT}" -eq 0 ]] && [[ -f "${TMP_DIR}"/S14_FCT_CNT.tmp ]]; then
      # lFCT_CNT respects also other functions
      lFCT_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S14_FCT_CNT.tmp)
    fi

    write_log ""
    write_log "[*] Statistics:${lSTRCPY_CNT}"
    write_log ""
    write_log "[*] Statistics1:${ARCH}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lFCT_CNT}"
}

identify_readelf_params() {
  local -n lnREADELF_PARAM_ARR="${1:-}"

  local lFUNC_TEST=""
  lFUNC_TEST=$(readelf "${lBINARY_}" "${lnREADELF_PARAM_ARR[@]}" 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
  if [[ -z "${lFUNC_TEST}" ]] || [[ "${lFUNC_TEST}" == "00000000" ]]; then
    lFUNC_TEST=$(readelf "${lBINARY_}" "${lnREADELF_PARAM_ARR[@]}" --use-dynamic 2>/dev/null | grep -E "${lFUNCTION}" 2>/dev/null || true)
    if [[ -n "${lFUNC_TEST}" ]] && [[ "${lFUNC_TEST}" != "00000000" ]]; then
      lnREADELF_PARAM_ARR+=("--use-dynamic")
    fi
  fi
}

radare_function_check_PPC32() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0
  export COUNT_STRLEN=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 2 -B 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c "bl.*""${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_MIPS() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      # For the mmap check we need the disasm after the call
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${lBINARY_}" 2>/dev/null | grep -A 20 "^l[wd] .*${lFUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${lBINARY_}" 2>/dev/null | grep -A 20 -B 25 "^l[wd] .*${lFUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
      radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "l[wd].*""${lFUNCTION}" "${FUNC_LOG}" 2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "l[wd].*strlen" "${FUNC_LOG}" 2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this. This test is very rough:
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c ",-1$" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_tricore() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      # For the mmap check we need the disasm after the call
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${lBINARY_}" 2>/dev/null | grep -A 20 "^l[wd] .*${lFUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${lBINARY_}" 2>/dev/null | grep -A 20 -B 25 "^l[wd] .*${lFUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
      radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "l[wd].*""${lFUNCTION}" "${FUNC_LOG}" 2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "l[wd].*strlen" "${FUNC_LOG}" 2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this. This test is very rough:
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c ",-1$" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}


radare_function_check_ARM64() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -A 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -A 2 -B 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
      radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "bl.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Test not implemented on ARM64
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_ARM32() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    if [[ "${lFUNCTION}" == "mmap" ]] ; then
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -A 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -A 2 -B 20 "bl.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
      radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "bl.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      elif [[ "${lFUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this testcase. Not sure if it works in all cases!
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_hexagon() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | grep -q "${lFUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 2 -B 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # TODO: check this in radare2
          COUNT_MMAP_OK="NA"
        fi
        radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 2 -B 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # TODO: check this in radare2
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86_64() {
  local lBINARY_="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY_}" 2> /dev/null)
  local lSTRCPY_CNT=0
  local lFUNCTION=""
  export NETWORKING=0

  if ! [[ -f "${lBINARY_}" ]]; then
    return
  fi

  local lREADELF_PARAM_ARR=("-W" "-a")
  identify_readelf_params "lREADELF_PARAM_ARR"

  NETWORKING=$(readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" 2>/dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    if ( readelf "${lREADELF_PARAM_ARR[@]}" "${lBINARY_}" | awk '{print $5}' | grep -E -q "^${lFUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
      radare_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      if [[ "${lFUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${lBINARY_}" | grep -E -A 2 -B 20 "call.*${lFUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 0 ]] ; then
        radare_color_output "${lFUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${lFUNCTION}" == "strcpy"  ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
        elif [[ "${lFUNCTION}" == "mmap"  ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${lBINARY_}" "${lFUNCTION}"
      fi
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_print_top10_statistics() {
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lFUNCTION=""
  local lRESULTS_ARR=()
  local lBINARY=""

  sub_module_title "Top 10 legacy C functions - Radare2 disasm mode"

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
        echo "${#lRESULTS_ARR[@]}" >> "${TMP_DIR}"/S14_FCT_CNT.tmp
      fi
    done
  else
    print_output "$(indent "$(orange "No weak binary functions found - check it manually with readelf and objdump -D")")"
  fi
}

radare_color_output() {
  local lFUNCTION="${1:-}"
  local lFUNC_LOG="${2:-}"

  sed -i -r "s/^[[:alnum:]].*(${lFUNCTION}).*/\x1b[31m&\x1b[0m/" "${lFUNC_LOG}" 2>/dev/null || true
}

radare_log_bin_hardening() {
  local lBIN_NAME="${1:-}"
  local lFUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  local lBIN_PROT=""
  local lHEAD_BIN_PROT=""

  if [[ -f "${S12_LOG}" ]]; then
    write_log "[*] Binary protection state of ${ORANGE}${lBIN_NAME}${NC}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
    # get headline:
    lHEAD_BIN_PROT=$(grep "FORTI.*FILE" "${S12_LOG}" | sed 's/FORTI.*//'| sort -u || true)
    write_log "  ${lHEAD_BIN_PROT}" "${lFUNC_LOG}"
    # get binary entry
    lBIN_PROT=$(grep '/'"${lBIN_NAME}"' ' "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    write_log "  ${lBIN_PROT}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
  fi

  write_log "${NC}" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${lFUNCTION}${NC} tear down of ${ORANGE}${lBIN_NAME}${NC}" "${lFUNC_LOG}"
  write_log "" "${lFUNC_LOG}"
}

radare_log_func_footer() {
  local lBIN_NAME="${1:-}"
  local lFUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  write_log "" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${lFUNCTION}${NC} used ${ORANGE}${COUNT_FUNC}${NC} times ${ORANGE}${lBIN_NAME}${NC}" "${lFUNC_LOG}"
  write_log "" "${lFUNC_LOG}"
}

radare_output_function_details()
{
  write_s14_log()
  {
    local lOUTPUT="${1:-}"
    local lLINK="${2:-}"
    local lLOG_FILE="${3:-}"

    local lOLD_LOG_FILE="${lLOG_FILE}"
    print_output "${lOUTPUT}" "" "${lLINK}"

    if [[ -f "${lLOG_FILE}" ]]; then
      cat "${lLOG_FILE}" >> "${lOLD_LOG_FILE}" || true
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

  local lLOG_FILE_LOC
  lLOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${lFUNCTION}"-"${lBIN_NAME}".txt
  local lOUTPUT=""

  # check if this is common linux file:
  local lCOMMON_FILES_FOUND=""
  local lSEARCH_TERM=""
  local lCFF_CSV=""
  local lNETWORKING_=""
  local lNW_CSV=""

  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    lSEARCH_TERM="${lBIN_NAME}"
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
  local lLOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${COUNT_FUNC}"_"${lFUNCTION}"-"${lBIN_NAME}".txt

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
    if [[ "${lFUNCTION}" == "strcpy" ]] ; then
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""strlen: ""${COUNT_STRLEN}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    elif [[ "${lFUNCTION}" == "mmap" ]] ; then
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""${COUNT_MMAP_OK}"" ""${NC}"
    else
      lOUTPUT="[+] ""$(print_path "${lBINARY_}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    fi
    write_s14_log "${lOUTPUT}" "${lLOG_FILE_LOC}" "${LOG_PATH_MODULE}""/vul_func_tmp_""${lFUNCTION}"-"${lBIN_NAME}"".txt"
    write_csv_log "$(print_path "${lBINARY_}")" "${lFUNCTION}" "${COUNT_FUNC}" "${lCFF_CSV}" "${lNW_CSV}"
  fi
}
