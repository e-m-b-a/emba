#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2022 Siemens AG
# Copyright 2022-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Pascal Eckmann
# Contributor(s): Michael Messner

# Description: Show stats about EMBA run on the bottom of the terminal window

# helper for box drawing
repeat_char() {
  local lREP_CHAR="${1:-}"
  local lREP_COUNT="${2:-0}"
  local lRET=""
  local lA=0
  for ((lA=1; lA<=lREP_COUNT; lA++)) ; do lRET+="${lREP_CHAR}"; done
  echo -e "${lRET}"
}

draw_box() {
  shopt -s checkwinsize

  local lLINES=""
  [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log")

  local lBOX_W="${1:-0}"
  local lBOX_TITLE="${2:-}"
  lBOX_TITLE=" ${lBOX_TITLE} "
  local lBOX_L="${3:-0}"
  local lBOX=""
  lBOX+="\e[$((lLINES - 4));${lBOX_L}f┌\033[1m${lBOX_TITLE}\033[0m$(repeat_char "─" "$((lBOX_W - "${#lBOX_TITLE}" - 2))")┐"
  lBOX+="\e[$((lLINES - 3));${lBOX_L}f│""$(repeat_char " " "$((lBOX_W - 2))")""│"
  lBOX+="\e[$((lLINES - 2));${lBOX_L}f│$(repeat_char " " "$((lBOX_W - 2))")│"
  lBOX+="\e[$((lLINES - 1));${lBOX_L}f│$(repeat_char " " "$((lBOX_W - 2))")│"
  lBOX+="\e[${lLINES};${lBOX_L}f└$(repeat_char "─" "$((lBOX_W - 2))")┘"
  echo -e "${lBOX}"
}

draw_arrows() {
  local lARROW_L="${1:-0}"
  local lARROWS=""
  local lLINES=""
  [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log")

  lARROWS+="\e[$((lLINES - 3));${lARROW_L}f \033[1m>\033[0m"
  lARROWS+="\e[$((lLINES - 2));${lARROW_L}f \033[1m>\033[0m"
  lARROWS+="\e[$((lLINES - 1));${lARROW_L}f \033[1m>\033[0m"
  echo -e "${lARROWS}"
}

# Helper first box "SYSTEM LOAD"
# we have three lines per box and here we build the string for each line ($2=line)
# Because we have to draw a colored bar, we need the percentage of the cpu load ($1)
system_load_util_str() {
  local lPERCENTAGE="${1:-0}"
  local lUTIL_TYPE_NO="${2:-0}"
  local lUTIL_TYPES=('CPU  ' 'MEM  ' 'DISK ')
  local lUTIL_STR="${lUTIL_TYPES[${lUTIL_TYPE_NO}]}"
  local lUTIL_BAR_COLOR=""
  local lUTIL_BAR_BLANK=""
  local lUTIL_PERCENTAGE=$(("${lPERCENTAGE}"/(100/12)))

  local lA=0
  local lBAR_COUNT=0
  for ((lA=1; lA<=lUTIL_PERCENTAGE; lA++)) ; do
    lUTIL_BAR_COLOR+="■"
    lBAR_COUNT=$((lBAR_COUNT + 1))
  done

  local lB=0
  local lB_LEN=$((12-lBAR_COUNT))
  for ((lB=1; lB<=lB_LEN; lB++)) ; do
    lUTIL_BAR_BLANK+="■"
  done

  if [[ ${lBAR_COUNT} -gt 8 ]] ; then
    lUTIL_BAR_COLOR="\033[31m${lUTIL_BAR_COLOR}\033[0m"
  elif [[ ${lBAR_COUNT} -gt 4 ]] ; then
    lUTIL_BAR_COLOR="\033[33m${lUTIL_BAR_COLOR}\033[0m"
  else
    lUTIL_BAR_COLOR="\033[32m${lUTIL_BAR_COLOR}\033[0m"
  fi

  lPERCENTAGE+=""
  if [[ ${#lPERCENTAGE} -gt 2 ]] ; then
    lPERCENTAGE="${lPERCENTAGE}%"
  elif [[ ${#lPERCENTAGE} -gt 1 ]] ; then
    lPERCENTAGE=" ${lPERCENTAGE}%"
  else
    lPERCENTAGE="  ${lPERCENTAGE}%"
  fi

  echo -e "${lUTIL_STR}${lUTIL_BAR_COLOR}${lUTIL_BAR_BLANK} ${lPERCENTAGE}"
}

# Update first box "SYSTEM LOAD"
# we need to use the tmp file for the cpu load, because it takes about a second to get the information and therefore we
# load this information in the background, write it to the file in a rythm of .2s and when needed, it will be readed from it
update_box_system_load() {
  shopt -s checkwinsize

  local lLINES=""

  update_cpu() {
    local lCPU_LOG_STR=""
    local lCPU_LOG_IDLE=""
    lCPU_LOG_IDLE="$(vmstat 1 2 | tail -1 | awk '{print $15}')"
    lCPU_LOG_STR="$(system_load_util_str "$((100-"${lCPU_LOG_IDLE}"))" 0 2> /dev/null || true)"
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      sed -i "2s/.*/${lCPU_LOG_STR}/" "${STATUS_TMP_PATH}" 2> /dev/null || true
    fi
  }

  update_cpu

  local lBOX_SIZE=0
  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi
  while [[ "${lBOX_SIZE}" -gt 0 ]]; do
    [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log" || true)
    local lMEM_PERCENTAGE_STR=""
    lMEM_PERCENTAGE_STR="$(system_load_util_str "$(LANG=en free | grep Mem | awk '{print int($3/$2 * 100)}')" 1)"
    local lDISK_PERCENTAGE_STR=""
    lDISK_PERCENTAGE_STR="$(system_load_util_str "$(df "${LOG_DIR}" | tail -1 | awk '{print substr($5, 1, length($5)-1)}')" 2)"
    local lACTUAL_CPU=0
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      lACTUAL_CPU="$(sed '2q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
    else
      lACTUAL_CPU=0
    fi
    printf '\e[s\e[%s;3f%s\e[%s;3f%s\e[%s;3f%s\e[u' "$(( lLINES - 3 ))" "${lACTUAL_CPU}" "$(( lLINES - 2 ))" "${lMEM_PERCENTAGE_STR}" "$(( lLINES - 1 ))" "${lDISK_PERCENTAGE_STR}" || true
    update_cpu &
    sleep .2
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
    fi
    if check_emba_ended; then
      exit
    fi
  done
}

# Helper second box "STATUS"
# we have three lines per box and here we build the string for each line ($1=line)
status_util_str() {
  local lUTIL_TYPE_NO="${1:-0}"
  local lUTIL_TYPES=('RUN' 'LOG_DIR' 'PROCESSES')
  local lUTIL_STR="${lUTIL_TYPES[${lUTIL_TYPE_NO}]}"
  local lUTIL_VALUE="${2:-}"
  local lUTIL_BAR_BLANK=""

  local lUTIL_LEN=$((22-"${#lUTIL_STR}"-"${#lUTIL_VALUE}"))
  local lU=0
  for ((lU=1; lU<=lUTIL_LEN; lU++)) ; do
    lUTIL_BAR_BLANK+=" "
  done

  echo -e "${lUTIL_STR}${lUTIL_BAR_BLANK}${lUTIL_VALUE}"
}

# Update second box "STATUS"
# we need to use the tmp file for the start time point, because the content of the boxes will be refreshed in the background
update_box_status() {
  shopt -s checkwinsize

  local lDATE_STR=""
  local lLINES=""

  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lDATE_STR="$(sed '3q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi
  if [[ "${lDATE_STR}" == "" ]] ; then
    lDATE_STR="$(date +%s)"
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      sed -i "3s/^$/${lDATE_STR}/" "${STATUS_TMP_PATH}" 2> /dev/null || true
    fi
  fi

  local lLOG_DIR_SIZE=""
  local lRUN_EMBA_PROCESSES=0
  local lRUN_EMBA_PROCESSES_QUEST=0

  local lBOX_SIZE=0
  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi
  while [[ "${lBOX_SIZE}" -gt 0 ]]; do
    [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log" || true)
    local lRUNTIME=0
    # lRUNTIME="$(date -d@"$(( "$(date +%s)" - "${lDATE_STR}" ))" -u +%H:%M:%S)"
    lRUNTIME=$(show_runtime 1)
    lLOG_DIR_SIZE="$(du -sh "${LOG_DIR}" 2> /dev/null | cut -d$'\t' -f1 2> /dev/null || true)"
    # if we are running in a docker environment, we can count the processes withing our containers:
    if [[ -n "${MAIN_CONTAINER}" ]]; then
      lRUN_EMBA_PROCESSES="$(docker exec "${MAIN_CONTAINER}" ps 2>/dev/null | wc -l || true)"
      lRUN_EMBA_PROCESSES_QUEST="$(docker exec "${QUEST_CONTAINER}" ps 2>/dev/null | wc -l || true)"
      lRUN_EMBA_PROCESSES=$((lRUN_EMBA_PROCESSES + lRUN_EMBA_PROCESSES_QUEST))
    else
      # this is a dirty solution if we have not MAIN_CONTAINER set
      # this happens in dev mode or in non silent mode -> but in both modes
      # the status bar is not supported
      lRUN_EMBA_PROCESSES="$(ps -C emba | wc -l || true)"
    fi
    printf '\e[s\e[%s;29f%s\e[%s;29f%s\e[%s;29f%s\e[u' "$(( lLINES - 3 ))" "$(status_util_str 0 "${lRUNTIME}")" "$(( lLINES - 2 ))" "$(status_util_str 1 "${lLOG_DIR_SIZE}")" "$(( lLINES - 1 ))" "$(status_util_str 2 "${lRUN_EMBA_PROCESSES}")" || true
    sleep .5
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
    fi
    if check_emba_ended; then
      exit
    fi
  done
}

# Helper third box "MODULES"
# we have three lines per box and here we build the string for each line ($1=line)
# we also need to show a value: $2
module_util_str() {
  local lUTIL_TYPE_NO="${1:-0}"
  local lUTIL_TYPES=('RUNNING' 'LAST FINISHED' 'PROGRESS')
  local lUTIL_STR="${lUTIL_TYPES[${lUTIL_TYPE_NO}]}"
  local lUTIL_VALUE="${2:-}"
  local lUTIL_BAR_BLANK=""

  local lUTIL_LEN=$((22-"${#lUTIL_STR}"-"${#lUTIL_VALUE}"))
  local lU=0
  for ((lU=1; lU<=lUTIL_LEN; lU++)) ; do
    lUTIL_BAR_BLANK+=" "
  done

  echo -e "${lUTIL_STR}${lUTIL_BAR_BLANK}${lUTIL_VALUE}"
}

# Update third box "MODULES"
update_box_modules() {
  shopt -s checkwinsize

  local lSTARTED_MODULE_STR=""
  local lFINISHED_MODULE_STR=""
  local lLAST_FINISHED_MODULE_STR=""
  local lCOUNT_MODULES=0
  local lMODULES_ARR=()
  local lMODULES_LOCAL_ARR=()
  local lMODULES_EMBA_ARR=()
  local lMODULE_FILE=""
  local lMODULE_NAME=""
  local lLINES=""

  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lCOUNT_MODULES="$(sed '4q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi
  if [[ ${lCOUNT_MODULES} -eq 0 || "${lCOUNT_MODULES}" == "" ]] ; then
    mapfile -t lMODULES_EMBA_ARR < <(find "${MOD_DIR}" -maxdepth 1 -name "*.sh" 2> /dev/null)
    if [[ -d "${MOD_DIR_LOCAL}" ]]; then
      mapfile -t lMODULES_LOCAL_ARR < <(find "${MOD_DIR_LOCAL}" -maxdepth 1 -name "*.sh" 2> /dev/null)
    fi
    lMODULES_ARR=( "${lMODULES_EMBA_ARR[@]}" "${lMODULES_LOCAL_ARR[@]}" )
    for lMODULE_FILE in "${lMODULES_ARR[@]}" ; do
      if ( file "${lMODULE_FILE}" | grep -q "shell script" ) && ! [[ "${lMODULE_FILE}" =~ \ |\' ]]; then
        # if system emulation is not enabled, we do not count the L modules
        lMODULE_NAME="$(basename "${lMODULE_FILE}")"
        if [[ "${lMODULE_NAME}" =~ ^L[0-9]* ]] && [[ "${FULL_EMULATION}" -ne 1 ]]; then
          continue
        fi
        # if diffing is not enabled, we do not count the diffing modules
        if [[ "${lMODULE_NAME}" =~ ^D[0-9]* ]] && [[ -z "${FIRMWARE_PATH1}" ]]; then
          continue
        fi
        # we do not count the quest modules
        if [[ "${lMODULE_NAME}" =~ ^Q[0-9]* ]]; then
          continue
        fi
        if [[ "${MODULE_BLACKLIST[*]}" == *"${lMODULE_NAME%\.sh}"* ]]; then
          continue
        fi
        (( lCOUNT_MODULES+=1 ))
      fi
    done
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      sed -i "4s/^$/${lCOUNT_MODULES}/" "${STATUS_TMP_PATH}" 2> /dev/null || true
    fi
  fi

  local lBOX_SIZE=0
  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi
  while [[ "${lBOX_SIZE}" -gt 0 ]]; do
    [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log" || true)
    lSTARTED_MODULE_STR="$(grep -c "starting\|blacklist triggered" "${LOG_DIR}/emba.log" 2> /dev/null || true )"
    lFINISHED_MODULE_STR="$(grep "finished\|blacklist triggered" "${LOG_DIR}/emba.log" 2> /dev/null | grep -vc "Quest container finished" || true )"
    lLAST_FINISHED_MODULE_STR="$(grep "finished" "${LOG_DIR}/emba.log" 2> /dev/null | grep -v "Quest container finished"| tail -1 | awk '{print $9}' | cut -d"_" -f1 || true )"
    printf '\e[s\e[%s;55f%s\e[%s;55f%s\e[%s;55f%s\e[u' "$(( lLINES - 3 ))" "$(module_util_str 0 "$((lSTARTED_MODULE_STR - lFINISHED_MODULE_STR))")" "$(( lLINES - 2 ))" "$(module_util_str 1 "${lLAST_FINISHED_MODULE_STR}")" "$(( lLINES - 1 ))" "$(module_util_str 2 "${lFINISHED_MODULE_STR}/${lCOUNT_MODULES}")" || true
    sleep 1
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
    fi
    if check_emba_ended; then
      exit
    fi
  done
}

# Helper fourth box "STATUS 2"
# we have three lines per box and here we build the string for each line ($1=line)
# we also need to show a value: $2
status_2_util_str() {
  local lUTIL_TYPE_NO="${1:-0}"
  local lUTIL_TYPES=('PHASE' 'MODE' '')
  local lUTIL_STR="${lUTIL_TYPES[${lUTIL_TYPE_NO}]}"
  local lUTIL_VALUE="${2:-}"
  local lUTIL_BAR_BLANK=""

  local lUTIL_LEN=$((22-"${#lUTIL_STR}"-"${#lUTIL_VALUE}"))
  local lU=0
  for ((lU=1; lU<=lUTIL_LEN; lU++)) ; do
    lUTIL_BAR_BLANK+=" "
  done

  echo -e "${lUTIL_STR}${lUTIL_BAR_BLANK}${lUTIL_VALUE}"
}

# Update fourth box "STATUS 2"
update_box_status_2() {
  shopt -s checkwinsize

  local lPHASE_STR=""
  local lMODE_STR=""
  local lLINES=""

  if [[ ${USE_DOCKER} -eq 0 && ${IN_DOCKER} -eq 0 ]] ; then
    lMODE_STR+="DEV/"
  elif [[ ${STRICT_MODE} -eq 1 ]] ; then
    lMODE_STR+="STRICT"
  else
    lMODE_STR+="DEFAULT"
  fi

  local lERROR_STR=0
  local lBOX_SIZE=0

  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
  fi

  while [[ "${lBOX_SIZE}" -gt 0 ]]; do
    [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log" || true)

    lPHASE_STR=$(grep 'phase started' "${LOG_DIR}/emba.log" 2> /dev/null | tail -1 | cut -d"-" -f2 | awk '{print $1}' || true)
    [[ "${lPHASE_STR}" == "Pre" ]] && lPHASE_STR="Extraction"
    [[ "${lPHASE_STR}" == "Testing" ]] && lPHASE_STR="Analysis"
    [[ "${lPHASE_STR}" == "System" ]] && lPHASE_STR="Emulation"

    lERROR_STR="/$(grep -c 'Error detected' "${LOG_DIR}/emba_error.log" 2> /dev/null || true )"
    if [[ "${lERROR_STR}" == "/0" || "${lERROR_STR}" == "/" ]] ; then
      lERROR_STR=""
    fi
    printf '\e[s\e[%s;81f%s\e[%s;81f%s\e[%s;81f%s\e[u' "$(( lLINES - 3 ))" "$(status_2_util_str 0 "${lPHASE_STR}")" "$(( lLINES - 2 ))" "$(status_2_util_str 1 "${lMODE_STR}${lERROR_STR}")" "$(( lLINES - 1 ))" "$(status_2_util_str 2 "")" || true
    sleep .5
    if [[ -f "${STATUS_TMP_PATH}" ]] ; then
      lBOX_SIZE="$(sed '1q;d' "${STATUS_TMP_PATH}" 2> /dev/null || true)"
    fi
    if check_emba_ended; then
      exit
    fi
  done
}

remove_status_bar() {
  if [[ "${DISABLE_STATUS_BAR}" -eq 1 ]]; then
    return
  fi

  shopt -s checkwinsize
  local lLINE_POS=""
  local lLINES=""
  [[ -f "${TMP_DIR}""/LINES.log" ]] && lLINES=$(cat "${TMP_DIR}""/LINES.log" 2>/dev/null || true)

  if [[ -f "${STATUS_TMP_PATH:-}" ]] ; then
    sed -i "1s/.*/0/" "${STATUS_TMP_PATH}" 2> /dev/null || true
  fi

  if [[ "${PID_SYSTEM_LOAD:-}" =~ ^[0-9]+$ ]]; then
    kill_box_pid "${PID_SYSTEM_LOAD}" &
  elif [[ -f "${TMP_DIR}"/PID_SYSTEM_LOAD.log ]]; then
    local PID_SYSTEM_LOAD=""
    PID_SYSTEM_LOAD="$(cat "${TMP_DIR}"/PID_SYSTEM_LOAD.log)"
    kill_box_pid "${PID_SYSTEM_LOAD}" &
  fi

  if [[ "${PID_STATUS:-}" =~ ^[0-9]+$ ]]; then
    kill_box_pid "${PID_STATUS}" &
  elif [[ -f "${TMP_DIR}"/PID_STATUS.log ]]; then
    local PID_STATUS=""
    PID_STATUS="$(cat "${TMP_DIR}"/PID_STATUS.log)"
    kill_box_pid "${PID_STATUS}" &
  fi

  if [[ "${PID_MODULES:-}" =~ ^[0-9]+$ ]]; then
    kill_box_pid "${PID_MODULES}" &
  elif [[ -f "${TMP_DIR}"/PID_MODULES.log ]]; then
    local PID_MODULES=""
    PID_MODULES="$(cat "${TMP_DIR}"/PID_MODULES.log)"
    kill_box_pid "${PID_MODULES}" &
  fi

  if [[ "${PID_STATUS_2:-}" =~ ^[0-9]+$ ]]; then
    kill_box_pid "${PID_STATUS_2}" &
  elif [[ -f "${TMP_DIR}"/PID_STATUS_2.log ]]; then
    local PID_STATUS_2=""
    PID_STATUS_2="$(cat "${TMP_DIR}"/PID_STATUS_2.log)"
    kill_box_pid "${PID_STATUS_2}" &
  fi

  if [[ ! -v lLINES ]] || [[ "${lLINES}" -lt 6 ]]; then
    return
  fi

  sleep 1
  if check_emba_ended; then
    exit
  fi
  local lRM_STR=""
  lLINE_POS="$(( lLINES - 6 ))"
  # lRM_STR="\e[""${lLINE_POS}"";1f\e[0J\e[;r\e[""${lLINE_POS}"";1f"
  # clear from cursor to the end of the screen -> removes status bar
  lRM_STR="\e[""${lLINE_POS}"";1f\e[0J\e[;r"
  printf "%b" "${lRM_STR}"
}

box_updaters() {
  # start threaded updater
  # echo "PID_SYSTEM_LOAD: ${PID_SYSTEM_LOAD}" >> "${TMP_DIR}"/pids_to_kill.log
  # echo "PID_STATUS: ${PID_STATUS}" >> "${TMP_DIR}"/pids_to_kill.log
  # echo "PID_MDOULES: ${PID_MODULES}" >> "${TMP_DIR}"/pids_to_kill.log
  # echo "PID_STATUS_2: ${PID_STATUS_2}" >> "${TMP_DIR}"/pids_to_kill.log
  if [[ -z "${PID_SYSTEM_LOAD}" && ${STATUS_BAR_BOX_COUNT} -gt 0 ]] ; then
    update_box_system_load &
    export PID_SYSTEM_LOAD="$!"
    echo "${PID_SYSTEM_LOAD}" > "${TMP_DIR}"/PID_SYSTEM_LOAD.log 2>/dev/null
  elif [[ -n "${PID_SYSTEM_LOAD}" && ${STATUS_BAR_BOX_COUNT} -le 0 ]] ; then
    kill_box_pid "${PID_SYSTEM_LOAD}" &
    export PID_SYSTEM_LOAD=""
    rm "${TMP_DIR}"/PID_SYSTEM_LOAD.log || true
  fi
  if [[ -z "${PID_STATUS}" && ${STATUS_BAR_BOX_COUNT} -gt 1 ]] ; then
    update_box_status &
    export PID_STATUS="$!"
    echo "${PID_STATUS}" > "${TMP_DIR}"/PID_STATUS.log 2>/dev/null
  elif [[ -n "${PID_STATUS}" && ${STATUS_BAR_BOX_COUNT} -le 1 ]] ; then
    kill_box_pid "${PID_STATUS}" &
    export PID_STATUS=""
    rm "${TMP_DIR}"/PID_STATUS.log || true
  fi
  if [[ -z "${PID_MODULES}" && ${STATUS_BAR_BOX_COUNT} -gt 2 ]] ; then
    update_box_modules &
    export PID_MODULES="$!"
    echo "${PID_MODULES}" > "${TMP_DIR}"/PID_MODULES.log 2>/dev/null
  elif [[ -n "${PID_MODULES}" && ${STATUS_BAR_BOX_COUNT} -le 2 ]] ; then
    kill_box_pid "${PID_MODULES}" &
    export PID_MODULES=""
    rm "${TMP_DIR}"/PID_MODULES.log || true
  fi
  if [[ -z "${PID_STATUS_2}" && ${STATUS_BAR_BOX_COUNT} -gt 3 ]] ; then
    update_box_status_2 &
    export PID_STATUS_2="$!"
    echo "${PID_STATUS_2}" > "${TMP_DIR}"/PID_STATUS_2.log 2>/dev/null
  elif [[ -n "${PID_STATUS_2}" && ${STATUS_BAR_BOX_COUNT} -le 3 ]] ; then
    kill_box_pid "${PID_STATUS_2}" &
    export PID_STATUS_2=""
    rm "${TMP_DIR}"/PID_STATUS_2.log || true
  fi
}

kill_box_pid() {
  local lPID="${1:-}"
  # echo "$lPID" >> "${TMP_DIR}"/pids_to_kill.txt
  if ! [[ -e /proc/"${lPID}" ]]; then
    return
  fi
  while [[ -e /proc/"${lPID}" ]]; do
    # print_output "[*] Status bar - kill pid: $lPID" "no_log"
    kill -9 "${lPID}" 2>/dev/null || true
    sleep 0.1
  done
}

initial_status_bar() {
  # PID for box updater threads
  export PID_SYSTEM_LOAD=""
  [[ -f "${TMP_DIR}"/PID_SYSTEM_LOAD.log ]] && PID_SYSTEM_LOAD="$(cat "${TMP_DIR}"/PID_SYSTEM_LOAD.log)"
  export PID_STATUS=""
  [[ -f "${TMP_DIR}"/PID_STATUS.log ]] && PID_STATUS="$(cat "${TMP_DIR}"/PID_STATUS.log)"
  export PID_MODULES=""
  [[ -f "${TMP_DIR}"/PID_MODULES.log ]] && PID_MODULES="$(cat "${TMP_DIR}"/PID_MODULES.log)"
  export PID_STATUS_2=""
  [[ -f "${TMP_DIR}"/PID_STATUS_2.log ]] && PID_STATUS_2="$(cat "${TMP_DIR}"/PID_STATUS_2.log)"

  # Path to status tmp file
  # each line is dedicated to a specific function
  # 1: Count of boxes visible
  # 2: CPU load string (needs to be cached, because it takes about a second to get the information)
  # 3: Start time of status bar - not exactly the same as the EMBA timer, but near enough to get an idea
  # 4: Count modules
  export STATUS_TMP_PATH=""

  # overwrites $LINES and "${COLUMNS}" with the actual values of the window
  # shopt -s checkwinsize; (:;:)
  shopt -s checkwinsize
  # echo "LINES: $LINES" >> "${TMP_DIR}"/shopts.log
  # echo "COLUMNS: $COLUMNS" >> "${TMP_DIR}"/shopts.log
  if ! [[ -v LINES ]] ; then
    return
  fi
  local lLINE_POS="$(( LINES - 6 ))"
  printf "\e[%s;1f\e[0J\e[%s;1f" "${lLINE_POS}" "${lLINE_POS}"
  echo "${LINES}" > "${TMP_DIR}""/LINES.log"

  # we need to restart our foreground logging:
  pkill -f "tail.*-f ${LOG_DIR}/emba.log" 2>/dev/null || true
  if ! [[ -f "${LOG_DIR}"/emba.log ]]; then
    touch "${LOG_DIR}"/emba.log
  fi
  # resets adn clears the screen for the status bar
  printf "\x1Bc"

  tail -f "${LOG_DIR}"/emba.log &
  local lTAIL_PID="$!"
  disown "${lTAIL_PID}" 2> /dev/null || true

  # create new tmp file with empty lines
  STATUS_TMP_PATH="${TMP_DIR}/status"
  if [[ ! -f "${STATUS_TMP_PATH}" && -d "${TMP_DIR}" ]] ; then
    echo -e "\\n\\n\\n\\n" > "${STATUS_TMP_PATH}"
  fi
  # calculate boxes fitting and draw them
  local lINITIAL_STR=""
  lINITIAL_STR="\e[${lLINE_POS};1f\e[0J\e[0;${lLINE_POS}r\e[${lLINE_POS};1f"
  if [[ ${LINES} -gt 10 ]] ; then
    # column has to be increased with 2 characters because of possible arrow column
    local lARROW_POS=0
    export STATUS_BAR_BOX_COUNT=0
    if [[ ${COLUMNS} -ge 27 ]] ; then
      lINITIAL_STR+="$(draw_box 26 "SYSTEM LOAD" 0)"
      STATUS_BAR_BOX_COUNT=1
      lARROW_POS=27
    fi
    if [[ ${COLUMNS} -ge 54 ]] ; then
      lINITIAL_STR+="$(draw_box 26 "STATUS" 27)"
      STATUS_BAR_BOX_COUNT=2
      lARROW_POS=53
    fi
    if [[ ${COLUMNS} -ge 80 ]] ; then
      lINITIAL_STR+="$(draw_box 26 "MODULES" 53)"
      STATUS_BAR_BOX_COUNT=3
      lARROW_POS=79
    fi
    if [[ ${COLUMNS} -ge 104 ]] ; then
      lINITIAL_STR+="$(draw_box 26 "STATUS 2" 79)"
      STATUS_BAR_BOX_COUNT=4
    fi

    if [[ ${STATUS_BAR_BOX_COUNT} -lt 4 ]] ; then
      lINITIAL_STR+="$(draw_arrows "${lARROW_POS}")"
    fi
  fi
  if [[ -f "${STATUS_TMP_PATH}" ]] ; then
    sed -i "1s/.*/${STATUS_BAR_BOX_COUNT}/" "${STATUS_TMP_PATH}" 2> /dev/null || true
  fi
  lINITIAL_STR+="\e[H"
  # set cursor and boxes
  printf "%b" "${lINITIAL_STR}"
  box_updaters
}
