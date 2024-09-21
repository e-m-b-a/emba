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

# Description:  This module identifies binaries that are using weak functions and creates a ranking of areas to look first.
#               It iterates through all executables and searches with radare for interesting functions like strcpy (defined in helpers.cfg).
#               The analysis is done via the r2dec plugin from radara2 (see https://github.com/wargio/r2dec-js)

# Threading priority - if set to 1, these modules will be executed first
# do not prio s13 and s14 as the dependency check during runtime will fail!
export THREAD_PRIO=0

S15_radare_decompile_checks()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Create and analyze decompilation of binaries"
  pre_module_reporter "${FUNCNAME[0]}"

  local STRCPY_CNT=0
  export COUNT_STRLEN=0
  local WAIT_PIDS_S15=()

  if [[ -n "${ARCH}" ]] ; then
    # as this module is slow we only run it in case the objdump method from s13 was not working as expected
    # This module waits for S12 - binary protections and s13
    # check emba.log for S12_binary_protection starting
    module_wait "S12_binary_protection"
    module_wait "S13_weak_func_check"
    module_wait "S14_weak_func_radare_check"

    local BINARY=""
    local VULNERABLE_FUNCTIONS=()
    local VULNERABLE_FUNCTIONS_VAR=""
    export FUNC_LOG=""

    VULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "${VULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a VULNERABLE_FUNCTIONS <<<"$( echo -e "${VULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"

    write_csv_log "binary" "function" "function count" "common linux file" "networking"

    for BINARY in "${BINARIES[@]}" ; do
      if ( file "${BINARY}" | grep -q ELF ) ; then
        NAME=$(basename "${BINARY}" 2> /dev/null)

        if [[ "${THREADED}" -eq 1 ]]; then
          radare_decompilation "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_S15+=( "${TMP_PID}" )
        else
          radare_decompilation "${BINARY}" "${VULNERABLE_FUNCTIONS[@]}"
        fi
      fi

      if [[ "${THREADED}" -eq 1 ]]; then
        max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S15[@]}"
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S15[@]}"

    radare_decomp_print_top10_statistics "${VULNERABLE_FUNCTIONS[@]}"

    if [[ -f "${TMP_DIR}"/S15_STRCPY_CNT.tmp ]]; then
      STRCPY_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S15_STRCPY_CNT.tmp)
    fi

    write_log ""
    write_log "[*] Statistics:${STRCPY_CNT}"
    write_log ""
    write_log "[*] Statistics1:${ARCH}"
  fi

  module_end_log "${FUNCNAME[0]}" "${STRCPY_CNT}"
}

radare_decompilation() {
  local BINARY_="${1:-}"
  shift 1
  local VULNERABLE_FUNCTIONS=("$@")
  local NAME=""
  NAME=$(basename "${BINARY_}" 2> /dev/null)
  local STRCPY_CNT=0
  local COUNT_FUNC=0
  export NETWORKING=""

  if ! [[ -f "${BINARY_}" ]]; then
    return
  fi

  NETWORKING=$(readelf -a "${BINARY_}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/decompilation_vul_func_""${FUNCTION}""-""${NAME}"".txt"
    radare_decomp_log_bin_hardening "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
    # with axt we are looking for function usages and store this in $FUNCTION_usage
    # pdd is for decompilation - with @@ we are working through all the identified functions
    # We analyse only 150 functions per binary
    timeout --preserve-status --signal SIGINT 3600 r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -A -c \
      'axt `is~'"${FUNCTION}"'[2]`~[0] | tail -n +2 | grep -v "nofunc" | sort -u | tail -n 150 > '"${LOG_PATH_MODULE}""/""${FUNCTION}""_""${NAME}""_usage"'; pdda @@ `cat '"${LOG_PATH_MODULE}""/""${FUNCTION}""_""${NAME}"'_usage`' "${BINARY}" >> "${FUNC_LOG}" || true
#      'axt `is~'"${FUNCTION}"'[2]`~[0] | tail -n +2 | grep -v "nofunc" | sort -u | tail -n 200 > '"${LOG_PATH_MODULE}""/""${FUNCTION}""_""${NAME}""_usage"'; pdd --assembly @@ `cat '"${LOG_PATH_MODULE}""/""${FUNCTION}""_""${NAME}"'_usage`' "${BINARY}" 2> /dev/null >> "${FUNC_LOG}" || true

    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l "${FUNC_LOG}" | awk '{print $1}') -gt 3 ]] ; then
      radare_decomp_color_output "${FUNCTION}" "${FUNC_LOG}"

      # Todo: check this with other architectures
      COUNT_FUNC="$(grep -c "${FUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      # we have already the header with the function name - remove it
      COUNT_FUNC=$((COUNT_FUNC-1))
      if [[ "${FUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "strlen" "${FUNC_LOG}"  2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      fi

      # from S14_weak_func_radare_check
      radare_log_func_footer "${NAME}" "${FUNCTION}" "${FUNC_LOG}"
      radare_decomp_output_function_details "${BINARY_}" "${FUNCTION}"
    else
      rm "${FUNC_LOG}" || true
    fi
  done
  echo "${STRCPY_CNT}" >> "${TMP_DIR}"/S15_STRCPY_CNT.tmp
}

radare_decomp_log_bin_hardening() {
  local NAME="${1:-}"
  local FUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  local HEAD_BIN_PROT=""
  local BIN_PROT=""

  if [[ -f "${S12_LOG}" ]]; then
    write_log "[*] Binary protection state of ${ORANGE}${NAME}${NC}" "${lFUNC_LOG}"
    # write_link "$LOG_DIR/s12_binary_protection.txt" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
    # get headline:
    HEAD_BIN_PROT=$(grep "FORTIFY Fortified" "${S12_LOG}" | sed 's/FORTIFY.*//'| sort -u || true)
    write_log "  ${HEAD_BIN_PROT}" "${lFUNC_LOG}"
    # get binary entry
    BIN_PROT=$(grep '/'"${NAME}"' ' "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    write_log "  ${BIN_PROT}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
  fi

  write_log "${NC}" "${lFUNC_LOG}"
# not working - check this:
#  if [[ -d "${LOG_DIR}"/s14_weak_func_radare_check/ ]] && [[ "$(find "${LOG_DIR}"/s14_weak_func_radare_check/ -name "vul_func_*""${FUNCTION}""-""${NAME}"".txt" | wc -l | awk '{print $1}')" -gt 0 ]]; then
#    write_log "[*] Function $ORANGE$FUNCTION$NC tear down of $ORANGE$NAME$NC / Switch to Radare2 disasm$NC" "${lFUNC_LOG}"
#    write_link "$(find "${LOG_DIR}"/s14_weak_func_radare_check/ -name "vul_func_*""${FUNCTION}""-""${NAME}"".txt")" "${lFUNC_LOG}"
#  elif [[ -d "${LOG_DIR}"/s13_weak_func_check/ ]] && [[ "$(find "${LOG_DIR}"/s13_weak_func_check/ -name "vul_func_*""${FUNCTION}""-""${NAME}"".txt" | wc -l | awk '{print $1}')" -gt 0 ]]; then
#    write_log "[*] Function $ORANGE$FUNCTION$NC tear down of $ORANGE$NAME$NC / Switch to Objdump disasm$NC" "${lFUNC_LOG}"
#    write_link "$(find "${LOG_DIR}"/s13_weak_func_check/ -name "vul_func_*""${FUNCTION}""-""${NAME}"".txt")" "${lFUNC_LOG}"
#  else
  write_log "[*] Function ${ORANGE}${FUNCTION}${NC} tear down of ${ORANGE}${NAME}${NC}" "${lFUNC_LOG}"
#  fi
  write_log "" "${lFUNC_LOG}"
}

radare_decomp_print_top10_statistics() {
  local VULNERABLE_FUNCTIONS=("$@")
  local FUNCTION=""
  local RESULTS=()
  local BINARY=""
  local GPT_ANCHOR_=""
  local GPT_PRIO=2

  sub_module_title "Top 10 legacy C functions - Radare2 decompilation mode"

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
            # FIXME
            if [[ "${GPT_OPTION}" -gt 0 ]]; then
              print_output "[*] Asking OpenAI chatbot about ${LOG_PATH_MODULE}/vul_func_${F_COUNTER}_${FUNCTION}-${SEARCH_TERM}.txt"
              GPT_ANCHOR_="$(openssl rand -hex 8)"
              # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
              write_csv_gpt_tmp "${LOG_PATH_MODULE}/vul_func_${F_COUNTER}_${FUNCTION}-${SEARCH_TERM}.txt" "${GPT_ANCHOR_}" "${GPT_PRIO}" "Can you give me a side by side desciption of the following code in a table, where on the left is the code and on the right the desciption. And please use proper spacing and | to make it terminal friendly:" "${LOG_PATH_MODULE}/vul_func_${F_COUNTER}_${FUNCTION}-${SEARCH_TERM}.txt" "" ""
              # add ChatGPT link
              printf '%s\n\n' "" >> "${LOG_PATH_MODULE}/vul_func_${F_COUNTER}_${FUNCTION}-${SEARCH_TERM}.txt"
              write_anchor_gpt "${GPT_ANCHOR_}" "${LOG_PATH_MODULE}/vul_func_${F_COUNTER}_${FUNCTION}-${SEARCH_TERM}.txt"
            fi
          fi
        done
        print_ln
      fi
    done
  else
    print_output "$(indent "$(orange "No weak binary functions found - check it manually")")"
  fi
}

radare_decomp_color_output() {
  local FUNCTION="${1:-}"
  local lFUNC_LOG="${2:-}"
  sed -i -r "s/.* \| .*(${FUNCTION}).*$/\x1b[31m&\x1b[0m/" "${lFUNC_LOG}" 2>/dev/null || true
}

radare_decomp_output_function_details() {
  write_s15_log()
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
  LOG_FILE_LOC="${LOG_PATH_MODULE}"/decompilation_vul_func_"${FUNCTION}"-"${NAME}".txt

  # check if this is common linux file:
  local COMMON_FILES_FOUND=""
  local SEARCH_TERM=""
  local CFF_CSV=""

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
    local NW_CSV="yes"
    local NETWORKING_="${ORANGE}networking: ${NW_CSV}${NC}"
  else
    local NW_CSV="no"
    local NETWORKING_="${GREEN}networking: ${NW_CSV}${NC}"
  fi

  if [[ ${COUNT_FUNC} -gt 0 ]] ; then
    local OUTPUT=""
    if [[ "${FUNCTION}" == "strcpy" ]] ; then
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""strlen: ""${COUNT_STRLEN}"" ""${NC}""/ ""${NETWORKING_}""${NC}"
    elif [[ "${FUNCTION}" == "mmap" ]] ; then
      local COUNT_MMAP_OK="NA"
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""${COUNT_MMAP_OK}"" ""${NC}"
    else
      OUTPUT="[+] ""$(print_path "${BINARY_}")""${COMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${FUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${NETWORKING_}""${NC}"
    fi
    write_s15_log "${OUTPUT}" "${LOG_FILE_LOC}" "${LOG_PATH_MODULE}""/decompilation_vul_func_""${FUNCTION}"-"${NAME}"".txt"
    write_csv_log "$(print_path "${BINARY_}")" "${FUNCTION}" "${COUNT_FUNC}" "${CFF_CSV}" "${NW_CSV}"
  fi
}
