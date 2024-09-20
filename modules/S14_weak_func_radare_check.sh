#!/bin/bash -p
# shellcheck disable=SC2016

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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

  local STRCPY_CNT=0
  local FCT_CNT=0
  export FUNC_LOG=""
  export COUNT_STRLEN=0
  export COUNT_MMAP_OK=0
  export COUNT_FUNC=0
  local WAIT_PIDS_S14=()

  if [[ -n "${ARCH}" ]] ; then
    # as this module is slow we only run it in case the objdump method from s13 was not working as expected
    # This module waits for S12 - binary protections and s13
    # check emba.log for S12_binary_protection starting
    module_wait "S12_binary_protection"
    module_wait "S13_weak_func_check"

    local BINARY=""
    local VULNERABLE_FUNCTIONS=()
    local VULNERABLE_FUNCTIONS_VAR=""

    VULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "${VULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a VULNERABLE_FUNCTIONS <<<"$( echo -e "${VULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"

    write_csv_log "binary" "function" "function count" "common linux file" "networking"

    for BINARY in "${BINARIES[@]}" ; do
      # we run throught the bins and check if the bin was already analysed via objdump:
      if [[ "$(find "${LOG_DIR}"/s13_weak_func_check/vul_func_*"$(basename "${BINARY}")".txt 2>/dev/null | wc -l)" -gt 0 ]]; then
        continue
      fi
      if ( file "${BINARY}" | grep -q ELF ) ; then
        NAME=$(basename "${BINARY}" 2> /dev/null)

        if ( file "${BINARY}" | grep -q "x86-64" ) ; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_x86_64 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_x86_64 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi
        elif ( file "${BINARY}" | grep -q "Intel 80386" ) ; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_x86 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_x86
          fi
        elif ( file "${BINARY}" | grep -q "32-bit.*ARM" ) ; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_ARM32 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_ARM32 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi
        elif ( file "${BINARY}" | grep -q "64-bit.*ARM" ) ; then
          # ARM 64 code is in alpha state and nearly not tested!
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_ARM64 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_ARM64 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi
        elif ( file "${BINARY}" | grep -q "MIPS" ) ; then
          # MIPS32 and MIPS64
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_MIPS "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_MIPS "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi
        elif ( file "${BINARY}" | grep -q "PowerPC" ) ; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_PPC32 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_PPC32 "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi
        elif ( file "${BINARY}" | grep -q "QUALCOMM DSP6" ) ; then
          if [[ "${THREADED}" -eq 1 ]]; then
            radare_function_check_hexagon "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
            local TMP_PID="$!"
            store_kill_pids "${TMP_PID}"
            WAIT_PIDS_S14+=( "${TMP_PID}" )
          else
            radare_function_check_hexagon "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
          fi

        else
          print_output "[-] Something went wrong ... no supported architecture available"
          print_output "[-] Tested binary: ${ORANGE}${BINARY}${NC}"
          print_output "[-] Please open an issue at https://github.com/e-m-b-a/emba/issues"
        fi
      fi

      if [[ "${THREADED}" -eq 1 ]]; then
        max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S14[@]}"
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S14[@]}"

    radare_print_top10_statistics "${VULNERABLE_FUNCTIONS[@]}"

    if [[ -f "${TMP_DIR}"/S14_STRCPY_CNT.tmp ]]; then
      STRCPY_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S14_STRCPY_CNT.tmp)
      FCT_CNT="${STRCPY_CNT}"
    fi
    if [[ "${FCT_CNT}" -eq 0 ]] && [[ -f "${TMP_DIR}"/S14_FCT_CNT.tmp ]]; then
      # FCT_CNT respects also other functions
      FCT_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S14_FCT_CNT.tmp)
    fi

    write_log ""
    write_log "[*] Statistics:${STRCPY_CNT}"
    write_log ""
    write_log "[*] Statistics1:${ARCH}"
  fi

  module_end_log "${FUNCNAME[0]}" "${FCT_CNT}"
}

radare_function_check_PPC32() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0
  export COUNT_STRLEN=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r "${BINARY_}" | awk '{print $5}' | grep -E -q "^${FUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
      radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      if [[ "${FUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 2 -B 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
        radare_color_output "${FUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c "bl.*""${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${FUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "${FUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${BINARY_}" "${FUNCTION}"
      fi
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_MIPS() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
    radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
    if [[ "${FUNCTION}" == "mmap" ]] ; then
      # For the mmap check we need the disasm after the call
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${BINARY_}" 2>/dev/null | grep -A 20 "^l[wd] .*${FUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $ss' "${BINARY_}" 2>/dev/null | grep -A 20 -B 25 "^l[wd] .*${FUNCTION}""(gp)" >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
      radare_color_output "${FUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "l[wd].*""${FUNCTION}" "${FUNC_LOG}" 2> /dev/null || true)"
      if [[ "${FUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "l[wd].*strlen" "${FUNC_LOG}" 2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "${FUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this. This test is very rough:
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c ",-1$" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${BINARY_}" "${FUNCTION}"
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_ARM64() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
    radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
    if [[ "${FUNCTION}" == "mmap" ]] ; then
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -A 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -A 2 -B 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
      radare_color_output "${FUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "bl.*${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${FUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "${FUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Test not implemented on ARM64
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${BINARY_}" "${FUNCTION}"
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_ARM32() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
    radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
    if [[ "${FUNCTION}" == "mmap" ]] ; then
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -A 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    else
      r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -A 2 -B 20 "bl.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
    fi
    ! [[ -f "${FUNC_LOG}" ]] && continue
    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
      radare_color_output "${FUNCTION}" "${FUNC_LOG}"

      COUNT_FUNC="$(grep -c "bl.*${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      if [[ "${FUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "${FUNCTION}" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this testcase. Not sure if it works in all cases!
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "${FUNC_LOG}"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      radare_output_function_details "${BINARY_}" "${FUNCTION}"
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_hexagon() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -s --use-dynamic "${BINARY_}" | grep -q "${FUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
      radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      if [[ "${FUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 2 -B 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
        radare_color_output "${FUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${FUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "${FUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # TODO: check this in radare2
          COUNT_MMAP_OK="NA"
        fi
        radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${BINARY_}" "${FUNCTION}"
      fi
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r --use-dynamic "${BINARY_}" | awk '{print $5}' | grep -E -q "^${FUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
      radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      if [[ "${FUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 2 -B 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
        radare_color_output "${FUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${FUNCTION}" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "${FUNCTION}" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # TODO: check this in radare2
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${BINARY_}" "${FUNCTION}"
      fi
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86_64() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  export NETWORKING=0

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r --use-dynamic "${BINARY_}" | awk '{print $5}' | grep -E -q "^${FUNCTION}" 2> /dev/null ) ; then
      FUNC_LOG="${LOG_PATH_MODULE}""/vul_func_""${FUNCTION}""-""${NAME}"".txt"
      radare_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      if [[ "${FUNCTION}" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      else
        r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -c 'pI $s' "${BINARY_}" | grep -E -A 2 -B 20 "call.*${FUNCTION}" 2> /dev/null >> "${FUNC_LOG}" || true
      fi
      ! [[ -f "${FUNC_LOG}" ]] && continue
      if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 0 ]] ; then
        radare_color_output "${FUNCTION}" "${FUNC_LOG}"

        COUNT_FUNC="$(grep -c -e "call.*${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
        if [[ "${FUNCTION}" == "strcpy"  ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "${FUNC_LOG}"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "${FUNCTION}" == "mmap"  ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "${FUNC_LOG}"  2> /dev/null || true)
        fi
        radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
        radare_output_function_details "${BINARY_}" "${FUNCTION}"
      fi
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S14_STRCPY_CNT.tmp
}

radare_print_top10_statistics() {
  local VULNERABLE_FUNCTIONS=("$@")
  local FUNCTION=""
  local RESULTS=()
  local BINARY=""

  sub_module_title "Top 10 legacy C functions - Radare2 disasm mode"

  if [[ "$(find "${LOG_PATH_MODULE}" -xdev -iname "vul_func_*_*-*.txt" | wc -l)" -gt 0 ]]; then
    for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
      local SEARCH_TERM=""
      local F_COUNTER=0
      readarray -t RESULTS < <( find "${LOG_PATH_MODULE}" -xdev -iname "vul_func_*_""${FUNCTION}""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""${FUNCTION}""-/  /" | sed "s/\.txt//" | grep -v "^0\ " 2> /dev/null || true)

      if [[ "${#RESULTS[@]}" -gt 0 ]]; then
        print_ln
        print_output "[+] ""${FUNCTION}"" - top 10 results:"
        if [[ "${FUNCTION}" == "strcpy" ]] ; then
          write_anchor "strcpysummary"
        fi
        for BINARY in "${RESULTS[@]}" ; do
          SEARCH_TERM="$(echo "${BINARY}" | awk '{print $2}')"
          F_COUNTER="$(echo "${BINARY}" | awk '{print $1}')"
          [[ "${F_COUNTER}" -eq 0 ]] && continue

          if [[ -f "${BASE_LINUX_FILES}" ]]; then
            # if we have the base linux config file we are checking it:
            if grep -E -q "^${SEARCH_TERM}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
              # shellcheck disable=SC2153
              printf "${GREEN}\t%-5.5s : %-15.15s : common linux file: yes${NC}\n" "${F_COUNTER}" "${SEARCH_TERM}" | tee -a "${LOG_FILE}" || true
            else
              printf "${ORANGE}\t%-5.5s : %-15.15s : common linux file: no${NC}\n" "${F_COUNTER}" "${SEARCH_TERM}" | tee -a "${LOG_FILE}" || true
            fi
          else
            print_output "$(indent "$(orange "${F_COUNTER}""\t:\t""${SEARCH_TERM}")")"
          fi
          if [[ -f "${LOG_PATH_MODULE}""/vul_func_""${F_COUNTER}""_""${FUNCTION}"-"${SEARCH_TERM}"".txt" ]]; then
            write_link "${LOG_PATH_MODULE}""/vul_func_""${F_COUNTER}""_""${FUNCTION}"-"${SEARCH_TERM}"".txt"
          fi
        done
        print_ln
        echo "${#RESULTS[@]}" >> "${TMP_DIR}"/S14_FCT_CNT.tmp
      fi
    done
  else
    print_output "$(indent "$(orange "No weak binary functions found - check it manually with readelf and objdump -D")")"
  fi
}

radare_color_output() {
  local FUNCTION="${1:-}"
  local lFUNC_LOG="${2:-}"

  sed -i -r "s/^[[:alnum:]].*(${FUNCTION}).*/\x1b[31m&\x1b[0m/" "${lFUNC_LOG}" 2>/dev/null || true
}

radare_log_bin_hardening() {
  local NAME="${1:-}"
  local FUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  local BIN_PROT=""
  local HEAD_BIN_PROT=""

  if [[ -f "${S12_LOG}" ]]; then
    write_log "[*] Binary protection state of ${ORANGE}${NAME}${NC}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
    # get headline:
    HEAD_BIN_PROT=$(grep "FORTI.*FILE" "${S12_LOG}" | sed 's/FORTI.*//'| sort -u || true)
    write_log "  ${HEAD_BIN_PROT}" "${lFUNC_LOG}"
    # get binary entry
    BIN_PROT=$(grep '/'"${NAME}"' ' "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    write_log "  ${BIN_PROT}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
  fi

  write_log "${NC}" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${FUNCTION}${NC} tear down of ${ORANGE}${NAME}${NC}" "${lFUNC_LOG}"
  write_log "" "${lFUNC_LOG}"
}

radare_log_func_footer() {
  local NAME="${1:-}"
  local FUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  write_log "" "${lFUNC_LOG}"
  write_log "[*] Function ${ORANGE}${FUNCTION}${NC} used ${ORANGE}${COUNT_FUNC}${NC} times ${ORANGE}${NAME}${NC}" "${lFUNC_LOG}"
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

  local BINARY_="${1:-}"
  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  local FUNCTION="${2:-}"
  local NAME=""
  NAME=$(basename "${BINARY_}")

  local LOG_FILE_LOC
  LOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${FUNCTION}"-"${NAME}".txt
  local OUTPUT=""

  # check if this is common linux file:
  local COMMON_FILES_FOUND=""
  local SEARCH_TERM=""
  local CFF_CSV=""
  local NETWORKING_=""
  local NW_CSV=""

  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    SEARCH_TERM=$(basename "${BINARY_}")
    if grep -q "^${SEARCH_TERM}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      COMMON_FILES_FOUND="${CYAN}"" - common linux file: yes - "
      write_log "[+] File $(print_path "${BINARY_}") found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
      CFF_CSV="true"
    else
      write_log "[+] File $(print_path "${BINARY_}") not found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
      COMMON_FILES_FOUND="${RED}"" - common linux file: no -"
      CFF_CSV="false"
    fi
  else
    COMMON_FILES_FOUND=" -"
  fi

  local LOG_FILE_LOC_OLD="${LOG_FILE_LOC}"
  local LOG_FILE_LOC="${LOG_PATH_MODULE}"/vul_func_"${COUNT_FUNC}"_"${FUNCTION}"-"${NAME}".txt

  if [[ -f "${LOG_FILE_LOC_OLD}" ]]; then
    mv "${LOG_FILE_LOC_OLD}" "${LOG_FILE_LOC}" 2> /dev/null || true
  fi

  if [[ "${NETWORKING}" -gt 1 ]]; then
    NETWORKING_="${ORANGE}networking: yes${NC}"
    NW_CSV="yes"
  else
    NETWORKING_="${GREEN}networking: no${NC}"
    NW_CSV="no"
  fi

  if [[ ${COUNT_FUNC} -ne 0 ]] ; then
    if [[ "${FUNCTION}" == "strcpy" ]] ; then
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""strlen: ""${COUNT_STRLEN}"" ""${NC}""/ ""${NETWORKING_}""${NC}"
    elif [[ "${FUNCTION}" == "mmap" ]] ; then
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""${COUNT_MMAP_OK}"" ""${NC}"
    else
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${NETWORKING_}""${NC}"
    fi
    write_s14_log "${OUTPUT}" "${LOG_FILE_LOC}" "${LOG_PATH_MODULE}""/vul_func_tmp_""${FUNCTION}"-"${NAME}"".txt"
    write_csv_log "$(print_path "${BINARY_}")" "${FUNCTION}" "${COUNT_FUNC}" "${CFF_CSV}" "${NW_CSV}"
  fi
}
