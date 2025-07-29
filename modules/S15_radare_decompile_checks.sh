#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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

  local lSTRCPY_CNT=0
  export COUNT_STRLEN=0
  local lWAIT_PIDS_S15_ARR=()

  if [[ -n "${ARCH}" ]] ; then
    # as this module is slow we only run it in case the objdump method from s13 was not working as expected
    # This module waits for S12 - binary protections and s13
    # check emba.log for S12_binary_protection starting
    module_wait "S12_binary_protection"
    module_wait "S13_weak_func_check"
    module_wait "S14_weak_func_radare_check"

    local lBINARY=""
    local lBIN_NAME=""
    local lBIN_FILE=""
    local lVULNERABLE_FUNCTIONS_ARR=()
    local lVULNERABLE_FUNCTIONS_VAR=""
    export FUNC_LOG=""

    lVULNERABLE_FUNCTIONS_VAR="$(config_list "${CONFIG_DIR}""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    # nosemgrep
    local IFS=" "
    IFS=" " read -r -a lVULNERABLE_FUNCTIONS_ARR <<<"$( echo -e "${lVULNERABLE_FUNCTIONS_VAR}" | sed ':a;N;$!ba;s/\n/ /g' )"

    write_csv_log "binary" "function" "function count" "common linux file" "networking"

    while read -r lBINARY; do
      lBIN_FILE="$(echo "${lBINARY}" | cut -d ';' -f8)"
      lBINARY="$(echo "${lBINARY}" | cut -d ';' -f2)"
      lBINARY="${lBINARY/;*}"
      if [[ "${lBIN_FILE}" == *"ELF"* ]]; then
        lBIN_NAME=$(basename "${lBINARY}" 2> /dev/null)

        if [[ "${THREADED}" -eq 1 ]]; then
          radare_decompilation "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_S15_ARR+=( "${lTMP_PID}" )
        else
          radare_decompilation "${lBINARY}" "${lVULNERABLE_FUNCTIONS_ARR[@]}"
        fi
      fi

      if [[ "${THREADED}" -eq 1 ]]; then
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S15_ARR
      fi
    done < <(grep -v "ASCII text\|Unicode text\|.raw;" "${P99_CSV_LOG}" | grep "ELF" || true)

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S15_ARR[@]}"

    radare_decomp_print_top10_statistics "${lVULNERABLE_FUNCTIONS_ARR[@]}"

    if [[ -f "${TMP_DIR}"/S15_STRCPY_CNT.tmp ]]; then
      lSTRCPY_CNT=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S15_STRCPY_CNT.tmp)
    fi

    write_log ""
    write_log "[*] Statistics:${lSTRCPY_CNT}"
    write_log ""
    write_log "[*] Statistics1:${ARCH}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lSTRCPY_CNT}"
}

radare_decompilation() {
  local lBINARY="${1:-}"
  shift 1
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY}" 2> /dev/null)
  local lSTRCPY_CNT=0
  export COUNT_FUNC=0
  export NETWORKING=""

  if ! [[ -f "${lBINARY}" ]]; then
    return
  fi

  NETWORKING=$(readelf -W -a "${lBINARY}" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for lFUNCTION in "${lVULNERABLE_FUNCTIONS_ARR[@]}" ; do
    FUNC_LOG="${LOG_PATH_MODULE}""/decompilation_vul_func_""${lFUNCTION}""-""${lBIN_NAME}"".txt"
    radare_decomp_log_bin_hardening "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
    # with axt we are looking for function usages and store this in $FUNCTION_usage
    # pdd is for decompilation - with @@ we are working through all the identified functions
    # We analyse only 150 functions per binary
    timeout --preserve-status --signal SIGINT 3600 r2 -e bin.cache=true -e io.cache=true -e scr.color=false -q -A -c \
      'axt `is~'"${lFUNCTION}"'[2]`~[0] | tail -n +2 | grep -v "nofunc" | sort -u | tail -n 150 > '"${LOG_PATH_MODULE}""/""${lFUNCTION}""_""${lBIN_NAME}""_usage"'; pdda @@ `cat '"${LOG_PATH_MODULE}""/""${lFUNCTION}""_""${lBIN_NAME}"'_usage`' "${lBINARY}" >> "${FUNC_LOG}" || true
#      'axt `is~'"${lFUNCTION}"'[2]`~[0] | tail -n +2 | grep -v "nofunc" | sort -u | tail -n 200 > '"${LOG_PATH_MODULE}""/""${lFUNCTION}""_""${lBIN_NAME}""_usage"'; pdd --assembly @@ `cat '"${LOG_PATH_MODULE}""/""${lFUNCTION}""_""${lBIN_NAME}"'_usage`' "${lBINARY}" 2> /dev/null >> "${FUNC_LOG}" || true

    if [[ -f "${FUNC_LOG}" ]] && [[ $(wc -l < "${FUNC_LOG}") -gt 3 ]] ; then
      radare_decomp_color_output "${lFUNCTION}" "${FUNC_LOG}"

      # Todo: check this with other architectures
      COUNT_FUNC="$(grep -c "${lFUNCTION}" "${FUNC_LOG}"  2> /dev/null || true)"
      # we have already the header with the function name - remove it
      COUNT_FUNC=$((COUNT_FUNC-1))
      if [[ "${lFUNCTION}" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "strlen" "${FUNC_LOG}"  2> /dev/null || true)
        lSTRCPY_CNT=$((lSTRCPY_CNT+COUNT_FUNC))
      fi

      # from S14_weak_func_radare_check
      radare_log_func_footer "${lBIN_NAME}" "${lFUNCTION}" "${FUNC_LOG}"
      radare_decomp_output_function_details "${lBINARY}" "${lFUNCTION}"
    else
      rm "${FUNC_LOG}" || true
    fi
  done
  echo "${lSTRCPY_CNT}" >> "${TMP_DIR}"/S15_STRCPY_CNT.tmp
}

radare_decomp_log_bin_hardening() {
  local lBIN_NAME="${1:-}"
  local lFUNCTION="${2:-}"
  local lFUNC_LOG="${3:-}"

  local lHEAD_BIN_PROT=""
  local lBIN_PROT=""

  if [[ -f "${S12_LOG}" ]]; then
    write_log "[*] Binary protection state of ${ORANGE}${lBIN_NAME}${NC}" "${lFUNC_LOG}"
    # write_link "$LOG_DIR/s12_binary_protection.txt" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
    # get headline:
    lHEAD_BIN_PROT=$(grep "FORTIFY Fortified" "${S12_LOG}" | sed 's/FORTIFY.*//'| sort -u || true)
    write_log "  ${lHEAD_BIN_PROT}" "${lFUNC_LOG}"
    # get binary entry
    lBIN_PROT=$(grep '/'"${lBIN_NAME}"' ' "${S12_LOG}" | sed 's/Symbols.*/Symbols/' | sort -u || true)
    write_log "  ${lBIN_PROT}" "${lFUNC_LOG}"
    write_log "" "${lFUNC_LOG}"
  fi

  write_log "${NC}" "${lFUNC_LOG}"
# not working - check this:
#  if [[ -d "${LOG_DIR}"/s14_weak_func_radare_check/ ]] && [[ "$(find "${LOG_DIR}"/s14_weak_func_radare_check/ -name "vul_func_*""${lFUNCTION}""-""${lBIN_NAME}"".txt" | wc -l | awk '{print $1}')" -gt 0 ]]; then
#    write_log "[*] Function $ORANGE$lFUNCTION$NC tear down of $ORANGE$lBIN_NAME$NC / Switch to Radare2 disasm$NC" "${lFUNC_LOG}"
#    write_link "$(find "${LOG_DIR}"/s14_weak_func_radare_check/ -name "vul_func_*""${lFUNCTION}""-""${lBIN_NAME}"".txt")" "${lFUNC_LOG}"
#  elif [[ -d "${LOG_DIR}"/s13_weak_func_check/ ]] && [[ "$(find "${LOG_DIR}"/s13_weak_func_check/ -name "vul_func_*""${lFUNCTION}""-""${lBIN_NAME}"".txt" | wc -l | awk '{print $1}')" -gt 0 ]]; then
#    write_log "[*] Function $ORANGE$lFUNCTION$NC tear down of $ORANGE$lBIN_NAME$NC / Switch to Objdump disasm$NC" "${lFUNC_LOG}"
#    write_link "$(find "${LOG_DIR}"/s13_weak_func_check/ -name "vul_func_*""${lFUNCTION}""-""${lBIN_NAME}"".txt")" "${lFUNC_LOG}"
#  else
  write_log "[*] Function ${ORANGE}${lFUNCTION}${NC} tear down of ${ORANGE}${lBIN_NAME}${NC}" "${lFUNC_LOG}"
#  fi
  write_log "" "${lFUNC_LOG}"
}

radare_decomp_print_top10_statistics() {
  local lVULNERABLE_FUNCTIONS_ARR=("$@")
  local lFUNCTION=""
  local lRESULTS_ARR=()
  local lBINARY=""
  local lGPT_ANCHOR_=""
  local lGPT_PRIO=2

  sub_module_title "Top 10 legacy C functions - Radare2 decompilation mode"

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
            # FIXME
            if [[ "${GPT_OPTION}" -gt 0 ]]; then
              print_output "[*] Asking OpenAI chatbot about ${LOG_PATH_MODULE}/vul_func_${lF_COUNTER}_${lFUNCTION}-${lSEARCH_TERM}.txt"
              lGPT_ANCHOR_="$(openssl rand -hex 8)"
              # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
              write_csv_gpt_tmp "${LOG_PATH_MODULE}/vul_func_${lF_COUNTER}_${lFUNCTION}-${lSEARCH_TERM}.txt" "${lGPT_ANCHOR_}" "${lGPT_PRIO}" "Can you give me a side by side desciption of the following code in a table, where on the left is the code and on the right the desciption. And please use proper spacing and | to make it terminal friendly:" "${LOG_PATH_MODULE}/vul_func_${lF_COUNTER}_${lFUNCTION}-${lSEARCH_TERM}.txt" "" ""
              # add ChatGPT link
              printf '%s\n\n' "" >> "${LOG_PATH_MODULE}/vul_func_${lF_COUNTER}_${lFUNCTION}-${lSEARCH_TERM}.txt"
              write_anchor_gpt "${lGPT_ANCHOR_}" "${LOG_PATH_MODULE}/vul_func_${lF_COUNTER}_${lFUNCTION}-${lSEARCH_TERM}.txt"
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
  local lFUNCTION="${1:-}"
  local lFUNC_LOG="${2:-}"
  sed -i -r "s/.* \| .*(${lFUNCTION}).*$/\x1b[31m&\x1b[0m/" "${lFUNC_LOG}" 2>/dev/null || true
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

  local lBINARY="${1:-}"
  if ! [[ -f "${lBINARY}" ]]; then
    return
  fi
  local lFUNCTION="${2:-}"
  local lBIN_NAME=""
  lBIN_NAME=$(basename "${lBINARY}")

  local lLOG_FILE_LOC=""
  lLOG_FILE_LOC="${LOG_PATH_MODULE}"/decompilation_vul_func_"${lFUNCTION}"-"${lBIN_NAME}".txt

  # check if this is common linux file:
  local lCOMMON_FILES_FOUND=""
  local lSEARCH_TERM=""
  local lCFF_CSV=""

  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    lSEARCH_TERM=$(basename "${lBINARY}")
    if grep -q "^${lSEARCH_TERM}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      lCOMMON_FILES_FOUND="${CYAN}"" - common linux file: yes - "
      write_log "[+] File $(print_path "${lBINARY}") found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
      lCFF_CSV="true"
    else
      write_log "[+] File $(print_path "${lBINARY}") not found in default Linux file dictionary" "${LOG_PATH_MODULE}/common_linux_files.txt"
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
    local lNW_CSV="yes"
    local lNETWORKING_="${ORANGE}networking: ${lNW_CSV}${NC}"
  else
    local lNW_CSV="no"
    local lNETWORKING_="${GREEN}networking: ${lNW_CSV}${NC}"
  fi

  if [[ ${COUNT_FUNC} -gt 0 ]] ; then
    local lOUTPUT=""
    if [[ "${lFUNCTION}" == "strcpy" ]] ; then
      lOUTPUT="[+] ""$(print_path "${lBINARY}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""strlen: ""${COUNT_STRLEN}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    elif [[ "${lFUNCTION}" == "mmap" ]] ; then
      local lCOUNT_MMAP_OK="NA"
      lOUTPUT="[+] ""$(print_path "${lBINARY}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""${lCOUNT_MMAP_OK}"" ""${NC}"
    else
      lOUTPUT="[+] ""$(print_path "${lBINARY}")""${lCOMMON_FILES_FOUND}""${NC}"" Vulnerable function: ""${CYAN}""${lFUNCTION}"" ""${NC}""/ ""${RED}""Function count: ""${COUNT_FUNC}"" ""${NC}""/ ""${lNETWORKING_}""${NC}"
    fi
    write_s15_log "${lOUTPUT}" "${lLOG_FILE_LOC}" "${LOG_PATH_MODULE}""/decompilation_vul_func_""${lFUNCTION}"-"${lBIN_NAME}"".txt"
    write_csv_log "$(print_path "${lBINARY}")" "${lFUNCTION}" "${COUNT_FUNC}" "${lCFF_CSV}" "${lNW_CSV}"
  fi
}
