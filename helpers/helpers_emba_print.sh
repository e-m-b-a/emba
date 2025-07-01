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

# Description:  All functions for colorizing terminal output and handling logging

## Color definition
export RED="\033[0;31m"
export GREEN="\033[0;32m"
export ORANGE="\033[0;33m"
export BLUE="\033[0;34m"
export MAGENTA="\033[0;35m"
export CYAN="\033[0;36m"
export NC="\033[0m"  # no color

export RED_="\x1b[31m"
export GREEN_="\x1b[32m"
export ORANGE_="\x1b[33m"
export BLUE_="\x1b[34m"
export MAGENTA_="\x1b[35m"
export CYAN_="\x1b[36m"
export NC_="\x1b[0m"

## Attribute definition
export BOLD="\033[1m"
export ITALIC="\033[3m"

export MODULE_NUMBER="--"
export SUB_MODULE_COUNT=0
export GREP_LOG_DELIMITER=";"
export GREP_LOG_LINEBREAK=" || "
export MESSAGE_TYPE=""
export OLD_MESSAGE_TYPE=""

welcome()
{
  echo -e "\\n""${BOLD}""╔═══════════════════════════════════════════════════════════════╗""${NC}"
  echo -e "${BOLD}""║""${BLUE}""${BOLD}""${ITALIC}""                            E M B A                            ""${NC}""${BOLD}""║""${NC}"
  echo -e "${BOLD}""║                   EMBEDDED FIRMWARE ANALYZER                  ""${NC}""${BOLD}""║""${NC}"
  echo -e "${BOLD}""╚═══════════════════════════════════════════════════════════════╝""${NC}"
}

module_log_init()
{
  export LOG_FILE_NAME="${1:-}"
  local lFILE_NAME=""
  # local lMODULE_NUMBER=""
  # lMODULE_NUMBER="$(echo "${LOG_FILE_NAME}" | cut -d "_" -f1 | cut -c2- )"
  lFILE_NAME=$(echo "${LOG_FILE_NAME}" | sed -e 's/\(.*\)/\L\1/' | tr " " _ )
  LOG_FILE="${LOG_DIR}""/""${lFILE_NAME}"".txt"
  LOG_FILE_NAME="${lFILE_NAME}"".txt"

  if [[ -f "${LOG_FILE}" ]]; then
    print_output "[*] Found old module log file ${ORANGE}${LOG_FILE}${NC}... creating a backup" "no_log"
    export OLD_LOG_FILE=""
    OLD_LOG_FILE="${LOG_FILE}".bak."${RANDOM}"
    mv "${LOG_FILE}" "${OLD_LOG_FILE}" || true
  fi

  module_start_log "${lFILE_NAME^}"

  if [[ "${DISABLE_NOTIFICATIONS}" -eq 0 ]]; then
    write_notification "Module ${lFILE_NAME} started"
  fi
}

# $1: module title
# $2: (optional) log file to log -> this is typically used in combination with write_log to write
#                logs to another log file
#                no_log is also valid to just print to cli
module_title()
{
  local lMODULE_TITLE="${1:-}"
  local lLOG_FILE_TO_LOG="${2:-}"

  if [[ "${lLOG_FILE_TO_LOG:-}" != "no_log" ]] && ! [[ -f "${lLOG_FILE_TO_LOG}" ]]; then
    lLOG_FILE_TO_LOG="${LOG_FILE}"
  fi

  local lMODULE_TITLE_FORMAT="[""${BLUE}""+""${NC}""] ""${CYAN}""${BOLD}""${lMODULE_TITLE}""${NC}""\\n""${BOLD}""=================================================================""${NC}"
  echo -e "\\n\\n""${lMODULE_TITLE_FORMAT}" || true

  if [[ "${lLOG_FILE_TO_LOG:-}" != "no_log" ]] ; then
    echo -e "$(format_log "${lMODULE_TITLE_FORMAT}")" | tee -a "${lLOG_FILE_TO_LOG}" >/dev/null || true
  fi

  SUB_MODULE_COUNT=0
}

# $1: sub module title
# $2: (optional) log file to log -> this is typically used in combination with write_log to write another log file
sub_module_title()
{
  local lSUB_MODULE_TITLE="${1:-}"
  local lLOG_FILE_TO_LOG="${2:-}"
  # if $2 is not set, we are going to log to the original LOG_FILE
  if [[ -z "${lLOG_FILE_TO_LOG:-}" ]]; then
    lLOG_FILE_TO_LOG="${LOG_FILE}"
  fi

  local lSUB_MODULE_TITLE_FORMAT=""

  lSUB_MODULE_TITLE_FORMAT="\\n\\n""${BLUE}""==>""${NC}"" ""${CYAN}""${lSUB_MODULE_TITLE}""${NC}""\\n-----------------------------------------------------------------"
  echo -e "${lSUB_MODULE_TITLE_FORMAT}" || true
  if [[ "${lLOG_FILE_TO_LOG:-}" != "no_log" ]] ; then
    echo -e "$(format_log "${lSUB_MODULE_TITLE_FORMAT}")" | tee -a "${lLOG_FILE_TO_LOG}" >/dev/null || true
  fi
}

print_error() {
  local lOUTPUT="${1:-\n}"
  # local lLOG_SETTING="${2:-}"

  local lTYPE_CHECK=""
  lTYPE_CHECK="$( echo "${lOUTPUT}" | cut -c1-3 )"

  if [[ ! -f "${ERROR_LOG}" ]]; then
    touch "${ERROR_LOG}"
  fi

  if ! [[ "${lTYPE_CHECK}" == "[E]" || "${lTYPE_CHECK}" == "[-]" ]] ; then
    print_output "[*] Warning: Wrong error output declaration: ${lOUTPUT}" "${ERROR_LOG}"
  fi
  local lCOLOR_OUTPUT_STRING=""
  lCOLOR_OUTPUT_STRING="$(color_output "${lOUTPUT}")"
  safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")" "${ERROR_LOG}"
}

print_output() {
  local lOUTPUT="${1:-\n}"
  local lLOG_SETTING="${2:-}"
  if [[ -n "${lLOG_SETTING}" && -d "$(dirname "${lLOG_SETTING}")" && "${LOG_FILE:-}" != "${lLOG_FILE_MOD:-}" ]]; then
    local lLOG_FILE_MOD="${2:-}"
  fi
  # add a link as third argument to add a link marker for web report
  local lREF_LINK="${3:-}"
  local lTYPE_CHECK=""
  lTYPE_CHECK="$( echo "${lOUTPUT}" | cut -c1-3 )"

  if [[ "${lTYPE_CHECK}" == "[-]" || "${lTYPE_CHECK}" == "[*]" || "${lTYPE_CHECK}" == "[!]" || "${lTYPE_CHECK}" == "[+]" ]] ; then
    local lCOLOR_OUTPUT_STRING=""
    lCOLOR_OUTPUT_STRING="$(color_output "${lOUTPUT}")"
    safe_echo "${lCOLOR_OUTPUT_STRING}"
    if [[ "${lLOG_SETTING}" == "main" ]] ; then
      safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")" "${MAIN_LOG}"
    elif [[ "${lLOG_SETTING}" != "no_log" ]] ; then
      if [[ -z "${lREF_LINK:-}" ]] ; then
        safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")" "${LOG_FILE}"
        if [[ -n "${lLOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")" "${lLOG_FILE_MOD}"
        fi
      else
        safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")""\\r\\n""$(format_log "[REF] ""${lREF_LINK}" 1)" "${LOG_FILE}"
        if [[ -n "${lLOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${lCOLOR_OUTPUT_STRING}")""\\r\\n""$(format_log "[REF] ""${lREF_LINK}" 1)" "${lLOG_FILE_MOD}"
        fi
      fi
    fi
  else
    safe_echo "${lOUTPUT}"
    if [[ "${lLOG_SETTING}" == "main" ]] ; then
      safe_echo "$(format_log "${lOUTPUT}")" "${MAIN_LOG}"
    elif [[ "${lLOG_SETTING}" != "no_log" ]] ; then
      if [[ -z "${lREF_LINK}" ]] ; then
        safe_echo "$(format_log "${lOUTPUT}")" "${LOG_FILE:-}"
        if [[ -n "${lLOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${lOUTPUT}")" "${lLOG_FILE_MOD}"
        fi
      else
        safe_echo "$(format_log "${lOUTPUT}")""\\r\\n""$(format_log "[REF] ""${lREF_LINK}" 1)" "${LOG_FILE}"
        if [[ -n "${lLOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${lOUTPUT}")""\\r\\n""$(format_log "[REF] ""${lREF_LINK}" 1)" "${lLOG_FILE_MOD}"
        fi
      fi
    fi
  fi
}

# echo unknown data in a consistent way:
safe_echo() {
  local lSTRING_TO_ECHO="${1:-}"

  # %b  ARGUMENT  as a string with '\' escapes interpreted, except that octal escapes are of the form \0 or
  if [[ -v 2 ]]; then
    local lLOG_TO_FILE="${2:-}"
    printf -- "%b" "${lSTRING_TO_ECHO}\r\n" | tee -a "${lLOG_TO_FILE}" >/dev/null || true
  else
    printf -- "%b" "${lSTRING_TO_ECHO}\r\n" || true
  fi
}

# This should be used for using untrusted data as input for other commands:
escape_echo() {
  local lSTRING_TO_ECHO="${1:-}"

  # %q  ARGUMENT is printed in a format that can be reused as shell input, escaping non-printable characters with the proposed POSIX $'' syntax.
  if [[ -v 2 ]]; then
    local lLOG_TO_FILE="${2:-}"
    printf "%q\n" "${lSTRING_TO_ECHO}" | tee -a "${lLOG_TO_FILE}" >/dev/null || true
  else
    printf "%q\n" "${lSTRING_TO_ECHO}" || true
  fi
}

check_int() {
  local lINT_TO_CHECK="${1:-}"
  [[ -z "${lINT_TO_CHECK}" ]] && return
  if [[ -n "${lINT_TO_CHECK//[0-9]/}" ]]; then
    print_output "[-] Invalid input detected - integers only" "no_log"
    exit 1
  fi
}

check_alnum() {
  local lINPUT_TO_CHECK="${1:-}"
  [[ -z "${lINPUT_TO_CHECK}" ]] && return
  if ! [[ "${lINPUT_TO_CHECK}" =~ ^[[:alnum:]]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only" "no_log"
    exit 1
  fi
}

check_vendor() {
  local lINPUT_TO_CHECK="${1:-}"
  [[ -z "${lINPUT_TO_CHECK}" ]] && return
  if ! [[ "${lINPUT_TO_CHECK}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only" "no_log"
    exit 1
  fi
}

check_notes() {
  local lINPUT_TO_CHECK="${1:-}"
  [[ -z "${lINPUT_TO_CHECK}" ]] && return
  if ! [[ "${lINPUT_TO_CHECK}" =~ ^[[:alnum:][:blank:][:punct:]]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only allowed in notes" "no_log"
    exit 1
  fi
}

check_path_input() {
  local lINPUT_TO_CHECK="${1:-}"
  [[ -z "${lINPUT_TO_CHECK}" ]] && return
  if ! [[ "${lINPUT_TO_CHECK}" =~ ^[a-zA-Z0-9./_~'-']+$ ]]; then
    print_output "[-] Invalid input detected - paths aka ~/abc/def123/ASDF only" "no_log"
    exit 1
  fi
}

check_version() {
  local lINPUT_TO_CHECK="${1:-}"
  [[ -z "${lINPUT_TO_CHECK}" ]] && return
  if ! [[ "${lINPUT_TO_CHECK}" =~ ^[a-zA-Z0-9./_:\+'-']+$ ]]; then
    print_output "[-] Invalid input detected - versions aka 1.2.3-a:b only" "no_log"
    exit 1
  fi
}

print_ln() {
  local lLOG_SETTING="${1:-}"
  print_output "" "${lLOG_SETTING}"
}

print_dot() {
  [[ "${DISABLE_DOTS:-0}" -eq 1 ]] && return
  echo -n "." 2>/dev/null ||true
}

write_log() {
  local lTEXT_ARR=()
  readarray lTEXT_ARR <<< "${1}"
  local lLOG_FILE_ALT="${2:-}"
  if [[ "${lLOG_FILE_ALT}" == "" ]] ; then
    local lW_LOG_FILE="${LOG_FILE}"
  else
    local lW_LOG_FILE="${lLOG_FILE_ALT}"
  fi
  local lENTRY=""

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    local lTYPE_CHECK=""
    lTYPE_CHECK="$( echo "${lENTRY}" | cut -c1-3 )"
    if [[ ( "${lTYPE_CHECK}" == "[-]" || "${lTYPE_CHECK}" == "[*]" || "${lTYPE_CHECK}" == "[!]" || "${lTYPE_CHECK}" == "[+]") && ("${lENTRY}" != "[*] Statistic"* ) ]] ; then
      local lCOLOR_OUTPUT_STRING=""
      lCOLOR_OUTPUT_STRING="$(color_output "${lENTRY}")"
      echo -e "$(format_log "${lCOLOR_OUTPUT_STRING}")" | tee -a "${lW_LOG_FILE}" >/dev/null || true
    else
      echo -e "$(format_log "${lENTRY}")" | tee -a "${lW_LOG_FILE}" >/dev/null || true
    fi
  done
}

# for generating csv log file in LOG_DIR/csv_logs/<module_name>.csv
write_csv_log() {
  local lCSV_ITEMS=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  local lCSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  lCSV_LOG="${CSV_DIR}""/""${lCSV_LOG}"

  # shellcheck disable=SC2005
  echo "$(printf '%s;' "${lCSV_ITEMS[@]}" && printf '\n')"  >> "${lCSV_LOG}" || true
}

# for generating csv log file in somewhere else
# $1: path with filename for csv log file
# $2: source module
# $@: array with csv items
write_csv_log_to_path() {
  local lCSV_LOG="${1:-}"
  local lSOURCE_MODULE="${2:-}"
  shift 2
  local lCSV_ITEMS=("$@")

  # shellcheck disable=SC2005
  echo "$(printf '%s;%s;' "${lSOURCE_MODULE}" "${lCSV_ITEMS[@]}" && printf '\n')"  >> "${lCSV_LOG}" || true
}


# For generating json log file in LOG_DIR/json_logs/<module_name>.json
# Usually this is the json equivalent to the write_csv_log
# We write to tmp files which we put together via write_json_module_log(), which is automatically called in module_end_log()
write_json_module_log_entry() {
  local lJSON_ITEMS_ARR=("$@")

  if ! [[ -d "${JSON_DIR}" ]]; then
    print_output "[-] WARNING: JSON directory ${ORANGE}${JSON_DIR}${NC} not found"
    return
  fi
  local lJSON_LOG="${LOG_PATH_MODULE}""/""JSON_tmp_${RANDOM}_${LOG_FILE_NAME/\.txt/\.json}"

  jo -p "${lJSON_ITEMS_ARR[@]}" >> "${lJSON_LOG}" || true
}

# This function collects all temp json files from LOG_PATH_MODULE and puts all temp json files together to a complete json log file
write_json_module_log() {
  local lJSON_TMP_FILES_ARR=()
  mapfile -t lJSON_TMP_FILES_ARR < <(find "${LOG_PATH_MODULE}" -maxdepth 1 -type f -name "JSON_tmp_*.json" | sort -u || true)
  if [[ "${#lJSON_TMP_FILES_ARR[@]}" -eq 0 ]]; then
    return
  fi

  local lJSON_LOG="${JSON_DIR}""/""${LOG_FILE_NAME/\.txt/\.tmp}"
  local lCOMP_FILE_ID=0

  echo -n "[" > "${lJSON_LOG}"
  for lCOMP_FILE_ID in "${!lJSON_TMP_FILES_ARR[@]}"; do
    local lCOMP_FILE="${lJSON_TMP_FILES_ARR["${lCOMP_FILE_ID}"]}"
    if [[ -s "${lCOMP_FILE}" ]]; then
      if (json_pp < "${lCOMP_FILE}" &> /dev/null); then
        cat "${lCOMP_FILE}" >> "${lJSON_LOG}"
      else
        print_error "[-] WARNING: JSON entry ${lCOMP_FILE} failed to validate with json_pp"
        continue
      fi
    else
      print_error "[-] WARNING: JSON entry ${lCOMP_FILE} failed to decode"
      continue
    fi
    if [[ $((lCOMP_FILE_ID+1)) -lt "${#lJSON_TMP_FILES_ARR[@]}" ]]; then
      echo -n "," >> "${lJSON_LOG}"
    fi
  done
  echo -n "]" >> "${lJSON_LOG}"

  # as our json is not beautifull we remove all \n and further formatting should be done via jq
  tr -d '\n' < "${lJSON_LOG}" > "${lJSON_LOG/\.tmp/\.json}"
  find "${LOG_PATH_MODULE}" -maxdepth 1 -type f -name "JSON_tmp_*.json" -delete || true
  rm "${lJSON_LOG}" || true
}

# write_pid_log is a functions used for debugging
# enable it with setting PID_LOGGING to 1 in the main emba script
# additionally you need to add a function call like the following to
# every threaded call you need the PID
# write_pid_log "${FUNCNAME[0]} - emulate_binary - $BIN_ - $TMP_PID"
# with this you can trace the PIDs. Additionally it is sometimes
# useful to enable PID output in wait_for_pid from helpers_emba_helpers.sh
write_pid_log() {
  local lLOG_MESSAGE="${1:-}"
  if [[ "${PID_LOGGING}" -eq 0 ]]; then
    return
  fi
  if ! [[ -d "${TMP_DIR}" ]]; then
    print_output "[-] WARNING: TMP directory ${ORANGE}${TMP_DIR}${NC} not found"
    return
  fi

  # shellcheck disable=SC2153
  echo "${lLOG_MESSAGE}" >> "${TMP_DIR}"/"${PID_LOG_FILE}" || true
}

write_link() {
  if [[ ${HTML} -eq 1 ]] ; then
    local lLINK="${1:-}"
    lLINK="$(format_log "[REF] ""${lLINK}" 1)"
    local lLOG_FILE_ALT="${2:-}"
    if [[ "${lLOG_FILE_ALT}" != "no_log" ]] && [[ "${lLOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${lLOG_FILE_ALT}" ]] ; then
        echo -e "${lLINK}" | tee -a "${lLOG_FILE_ALT}" >/dev/null
      else
        echo -e "${lLINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}

# The copy_and_link_file is used to copy files from the filesystem to the web-report and
# automatically link it
# This is usually used after a print_output "[*] asdf"
copy_and_link_file() {
  local lSRC_FILE="${1:-}"
  local lDST_FILE="${2:-}"

  if [[ ${HTML} -eq 1 ]] ; then
    if ! [[ -d "$(dirname "${lDST_FILE}")" ]]; then
      mkdir -p "$(dirname "${lDST_FILE}")" || true
    fi
    if [[ -f "${lSRC_FILE}" ]]; then
      cp "${lSRC_FILE}" "${lDST_FILE}" 2>/dev/null || true
    fi
    if [[ -f "${lDST_FILE}" ]]; then
      write_link "${lDST_FILE}"
    fi
  fi
}

# we add an entry like
# [LOV] local_link
# this entry is later replaced from web reporter with the
# correct call to JS function
write_local_overlay_link()
{
  if [[ ${HTML} -eq 1 ]] ; then
    local lLINK="${1:-}"
    lLINK="$(format_log "[LOV] ""${lLINK}" 1)"
    local lLOG_FILE_ALT="${2:-}"
    if [[ "${lLOG_FILE_ALT}" != "no_log" ]] && [[ "${lLOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${lLOG_FILE_ALT}" ]] ; then
        echo -e "${lLINK}" | tee -a "${lLOG_FILE_ALT}" >/dev/null
      else
        echo -e "${lLINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}


write_anchor()
{
  if [[ ${HTML} -eq 1 ]] ; then
    local lANCHOR="${1:-}"
    lANCHOR="$(format_log "[ANC] ""${lANCHOR}" 1)"
    local lLOG_FILE_ALT="${2:-}"
    if [[ "${lLOG_FILE_ALT}" != "no_log" ]] && [[ "${lLOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${lLOG_FILE_ALT}" ]] ; then
        echo -e "${lANCHOR}" | tee -a "${lLOG_FILE_ALT}" >/dev/null
      else
        echo -e "${lANCHOR}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}

reset_module_count()
{
  export MODULE_NUMBER="--"
  export SUB_MODULE_COUNT=0
}

color_output()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray lTEXT_ARR <<< "${1:-}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    local lTYPE_CHECK=""
    lTYPE_CHECK="$( echo "${lENTRY}" | cut -c1-3 )"
    if [[ "${lTYPE_CHECK}" == "[-]" || "${lTYPE_CHECK}" == "[*]" || "${lTYPE_CHECK}" == "[!]" || "${lTYPE_CHECK}" == "[+]" ]] ; then
      local lSTR=""
      lSTR="$( echo "${lENTRY}" | cut -c 4- || true)"
      if [[ "${lTYPE_CHECK}" == "[-]" ]] ; then
        lTEXT="${lTEXT}""[""${RED}""-""${NC}""]""${lSTR}"
      elif [[ "${lTYPE_CHECK}" == "[*]" ]] ; then
        lTEXT="${lTEXT}""[""${ORANGE}""*""${NC}""]""${lSTR}"
      elif [[ "${lTYPE_CHECK}" == "[!]" ]] ; then
        lTEXT="${lTEXT}""[""${MAGENTA}""!""${NC}""]""${MAGENTA}""${lSTR}""${NC}"
      elif [[ "${lTYPE_CHECK}" == "[+]" ]] ; then
        lTEXT="${lTEXT}""[""${GREEN}""+""${NC}""]""${GREEN}""${lSTR}""${NC}"
      else
        lTEXT="${lTEXT}""${lENTRY}"
      fi
    else
      lTEXT="${lTEXT}""${lENTRY}"
    fi
  done
  echo "${lTEXT}"
}

white()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${NC}""${lENTRY}""\\n"
  done
  echo -e "${lTEXT}"
}

red()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${RED}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

green()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${GREEN}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

blue()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${BLUE}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

cyan()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${CYAN}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

magenta()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${MAGENTA}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

orange()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${ORANGE}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

bold()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${BOLD}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

italic()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""${ITALIC}""${lENTRY}""${NC}""\\n"
  done
  echo -e "${lTEXT}"
}

indent()
{
  local lTEXT_ARR=()
  local lTEXT=""
  local lENTRY=""
  readarray -t lTEXT_ARR <<< "${1}"

  for lENTRY in "${lTEXT_ARR[@]}" ; do
    lTEXT="${lTEXT}""    ""${lENTRY}""\\n"
  done
  echo -e "${lTEXT}"
}

format_log()
{
  local lLOG_STRING="${1:-}"
  # remove log formatting, even if EMBA is set to format it (for [REF] markers used)
  local lOVERWRITE_SETTING="${2:-}"
  if [[ ${FORMAT_LOG} -eq 0 ]] || [[ ${lOVERWRITE_SETTING} -eq 1 ]] ; then
    echo "${lLOG_STRING}" | sed -r "s/\\\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\[([0-9]{1,2}(;[0-9]{1,2}(;[0-9]{1,2})?)?)?[m|K]//g" \
      | sed -e "s/\\\\n/\\n/g"
  else
    echo "${lLOG_STRING}"
  fi
}

format_grep_log()
{
  local lLOG_STRING="${1:-}"
  echo "${lLOG_STRING}" | sed -r "s/\\\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\[([0-9]{1,2}(;[0-9]{1,2}(;[0-9]{1,2})?)?)?[m|K]//g" \
      | sed -e "s/^ *//" \
      | sed -e "s/\\\\n/\n/g" \
      | sed -e "s/${GREP_LOG_DELIMITER}/,/g"
}

add_info_grep_log()
{
  echo "${MODULE_NUMBER}""${GREP_LOG_DELIMITER}""${SUB_MODULE_COUNT}""${GREP_LOG_DELIMITER}"
}

print_help()
{
  ## help and command line parsing

  echo -e "\\n""${CYAN}""USAGE""${NC}"
  echo -e "\\nTest firmware"
  echo -e "${CYAN}""-l [~/path]""${NC}""       Log path"
  echo -e "${CYAN}""-f [~/path]""${NC}""       Firmware path"
  echo -e "${CYAN}""-m [MODULE_NO.]""${NC}""   Test only with set modules [e.g. -m p05 -m s10 ... or -m p to run all p modules]"
  echo -e "                                    (multiple usage possible, case insensitive)"
  echo -e "${CYAN}""-p [PROFILE]""${NC}""      EMBA starts with a pre-defined profile (stored in ./scan-profiles)"
  # Threading is now only available via profile parameter. In default mode EMBA is running in threading mode
#  echo -e "${CYAN}""-t""${NC}""                Activate multi threading (destroys regular console output)"
  echo -e "${CYAN}""-P""${NC}""                Overwrite auto MAX_MODS (maximum modules in parallel) configuration"
  echo -e "${CYAN}""-T""${NC}""                Overwrite auto MAX_MOD_THREADS (maximum threads per module) configuration"
  echo -e "\\nDeveloper options"
  echo -e "${CYAN}""-D""${NC}""                Developer mode - EMBA runs on the host without container protection (deprecated)"
  echo -e "${CYAN}""-S""${NC}""                STRICT mode - developer option to improve code quality (not enabled by default)"
#  echo -e "${CYAN}""-i""${NC}""                EMBA internally used for container identification (do not use it as cli parameter)"
  echo -e "${CYAN}""-y""${NC}""                Overwrite log directory automaticially, even if it is not empty"
  echo -e "\\nSystem check"
  echo -e "${CYAN}""-d [1/2]""${NC}""          Only checks dependencies (1 - on host and in container, 2 - only container)"
  echo -e "${CYAN}""-F""${NC}""                Checks dependencies but ignore errors"
  echo -e "${CYAN}""-U""${NC}""                Check and apply available updates and exit"
  echo -e "${CYAN}""-V""${NC}""                Show EMBA version"
  echo -e "\\nSpecial tests"
  echo -e "${CYAN}""-k [~/config]""${NC}""     Kernel config path"
  echo -e "${CYAN}""-C [container id]""${NC}"" Extract and analyze a local docker container via container id"
  echo -e "${CYAN}""-r""${NC}""                Remove temporary firmware directory after testing"
  echo -e "${CYAN}""-b""${NC}""                Just print a random banner and exit"
  echo -e "${CYAN}""-o [~/path]""${NC}""       2nd Firmware path to diff against the main firmware file - diff mode only (no other firmware analysis)"
  echo -e "${CYAN}""-c""${NC}""                Enable extended binary analysis"
  echo -e "${CYAN}""-E""${NC}""                Enables automated qemu user emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-Q""${NC}""                Enables automated qemu system emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-q""${NC}""                Disables the deep-extractor module"
  echo -e "${CYAN}""-R""${NC}""                Rescans existing SBOM (-l required) and generates a new VEX JSON"
  echo -e "${CYAN}""-a [MIPS]""${NC}""         Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (usually not needed)"
  echo -e "${CYAN}""-A [MIPS]""${NC}""         Force Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (disable architecture check - usually not needed)"
  echo -e "${CYAN}""-e [./path]""${NC}""       Exclude paths from testing (multiple usage possible - usually not needed)"
  echo -e "\\nReporter options"
  echo -e "${CYAN}""-W""${NC}""                Activates web report creation in log path (overwrites -z)"
  echo -e "${CYAN}""-g""${NC}""                Create grep-able log file in [log_path]/fw_grep.log"
#  echo -e "                  Schematic: MESSAGE_TYPE;MODULE_NUMBER;SUB_MODULE_NUMBER;MESSAGE"
  echo -e "${CYAN}""-s""${NC}""                Prints only relative paths"
  echo -e "${CYAN}""-z""${NC}""                Adds ANSI color codes to log"
  echo -e "\\nFirmware details"
  echo -e "${CYAN}""-X [version]""${NC}""      Firmware version (versions aka 1.2.3-a:b only)"
  echo -e "${CYAN}""-Y [vendor]""${NC}""       Firmware vendor (alphanummerical values only)"
  echo -e "${CYAN}""-Z [device]""${NC}""       Device (alphanummerical values only)"
  echo -e "${CYAN}""-N [notes]""${NC}""        Testing notes (alphanummerical values only)"
  echo -e "\\nHelp"
  echo -e "${CYAN}""-h""${NC}""                Prints this help message"

}

print_firmware_info()
{
  local lVENDOR="${1:-}"
  local lVERSION="${2:-}"
  local lDEVICE="${3:-}"
  local lNOTES="${4:-}"

  if [[ -n "${lVENDOR}" || -n "${lVERSION}" || -n "${lDEVICE}" || -n "${lNOTES}" ]]; then
    print_bar "no_log"
    print_output "[*] Firmware information:" "no_log"
    if [[ -n "${lVENDOR}" ]]; then
      print_output "$(indent "${BOLD}""Vendor:\t""${NC}""${ORANGE}""${lVENDOR}""${NC}")" "no_log"
    fi
    if [[ -n "${lVERSION}" ]]; then
      print_output "$(indent "${BOLD}""Version:\t""${NC}""${ORANGE}""${lVERSION}""${NC}")" "no_log"
    fi
    if [[ -n "${lDEVICE}" ]]; then
      print_output "$(indent "${BOLD}""Device:\t""${NC}""${ORANGE}""${lDEVICE}""${NC}")" "no_log"
    fi
    if [[ -n "${lNOTES}" ]]; then
      print_output "$(indent "${BOLD}""Additional notes:\t""${NC}""${ORANGE}""${lNOTES}""${NC}")" "no_log"
    fi
    print_bar "no_log"
  fi
}

print_etc()
{
  local lETC=""

  if [[ ${#ETC_PATHS[@]} -gt 1 ]] ; then
    print_ln "no_log"
    print_output "[*] Found more paths for etc (these are automatically taken into account):" "no_log"
    for lETC in "${ETC_PATHS[@]}" ; do
      if [[ "${lETC}" != "${FIRMWARE_PATH}""/etc" ]] ; then
        print_output "$(indent "$(orange "$(print_path "${lETC}")")")" "no_log"
      fi
    done
  fi
}

print_excluded() {
  local lEXCL=""
  local lEXCLUDE_PATHS_ARR=()

  readarray -t lEXCLUDE_PATHS_ARR < <(printf '%s' "${EXCLUDE_PATHS}")
  if [[ ${#lEXCLUDE_PATHS_ARR[@]} -gt 0 ]] ; then
    print_ln "no_log"
    print_output "[*] Excluded: " "no_log"
    for lEXCL in "${lEXCLUDE_PATHS_ARR[@]}" ; do
      print_output ".""$(indent "$(orange "$(print_path "${lEXCL}")")")" "no_log"
    done
    print_ln "no_log"
  fi
}

print_bar() {
  local lLOG_SETTINGS="${1:-}"

  if [[ -n "${lLOG_SETTINGS}" ]]; then
    print_output "\\n-----------------------------------------------------------------\\n" "${lLOG_SETTINGS}"
  else
    print_output "\\n-----------------------------------------------------------------\\n"
  fi
}

module_start_log() {
  local lMODULE_MAIN_NAME="${1:-}"
  print_output "[*] $(print_date) - ${lMODULE_MAIN_NAME} starting" "main"
  export LOG_PATH_MODULE=""
  if [[ "${LOG_DIR: -1}" == "/" ]]; then
    # strip final slash from log dir
    LOG_DIR="${LOG_DIR:: -1}"
  fi
  # LOG_PATH_MODULE=$(abs_path "${LOG_DIR}""/""$(echo "${lMODULE_MAIN_NAME}" | tr '[:upper:]' '[:lower:]')")
  LOG_PATH_MODULE=$(abs_path "${LOG_DIR}""/""${lMODULE_MAIN_NAME,,}")
  if [[ -d "${LOG_PATH_MODULE}" ]] ; then
    print_output "[*] Found old module log path for ${ORANGE}${lMODULE_MAIN_NAME}${NC} ... creating a backup" "no_log"
    export OLD_LOG_DIR=""
    OLD_LOG_DIR="${LOG_PATH_MODULE}".bak."${RANDOM}" || true
    mv "${LOG_PATH_MODULE}" "${OLD_LOG_DIR}" || true
  fi
  if ! [[ -d "${LOG_PATH_MODULE}" ]]; then
    mkdir "${LOG_PATH_MODULE}" || true
  fi
}

pre_module_reporter() {
  local lMODULE_MAIN_NAME="${1:-}"
  local lREPORT_TEMPLATE=""
  lREPORT_TEMPLATE="$(basename -s ".sh" "${lMODULE_MAIN_NAME}")-pre"

  # We handle .txt and .sh files in report_template folder.
  # .txt are just echoed on cli and report
  # .sh are executed via source -> you can use variables, color codes, execute further commands
  if [[ -f "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.txt" ]]; then
    tee -a "${LOG_FILE}" < "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.txt"
  elif [[ -f "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.sh" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.sh"
  fi
  print_ln
}

# on module end we log that the module is finished in emba.log
# additionally we log that EMBA has nothing found -> this is used for index generation of the web reporter
# additionally we generate the HTML file of the web reporter if web reporting is enabled
module_end_log() {
  local lMODULE_MAIN_NAME="${1:-}"
  local lMODULE_REPORT_STATE="${2:-}"

  if [[ "${lMODULE_REPORT_STATE}" -eq 0 ]]; then
    print_output "[-] $(print_date) - ${lMODULE_MAIN_NAME} nothing reported"
  fi

  # we do not report the templates on restarted tests
  if [[ "${lMODULE_REPORT_STATE}" -ne 0 ]]; then
    lREPORT_TEMPLATE="$(basename -s ".sh" "${lMODULE_MAIN_NAME}")-post"
    # We handle .txt and .sh files in report_template folder.
    # .txt are just echoed on cli and report
    # .sh are executed via source -> you can use variables, color codes, execute further commands
    if [[ -f "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.txt" ]]; then
      print_bar ""
      tee -a "${LOG_FILE}" < "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.txt"
      print_bar ""
    elif [[ -f "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.sh" ]]; then
      print_bar ""
      # shellcheck source=/dev/null
      source "${CONFIG_DIR}/report_templates/${lREPORT_TEMPLATE}.sh"
      print_bar ""
    fi
  fi

  # if we have json logs we need to put them together now
  write_json_module_log

  [[ "${HTML}" -eq 1 ]] && run_web_reporter_mod_name "${lMODULE_MAIN_NAME}"
  if [[ -v LOG_PATH_MODULE ]]; then
    if [[ -d "${LOG_PATH_MODULE}" ]]; then
      if [[ "$(find "${LOG_PATH_MODULE}" -type f | wc -l)" -eq 0 ]]; then
        rm -r "${LOG_PATH_MODULE}"
      fi
    fi
  fi

  # check if there is some content in the csv log file. If there is only
  # one entry line we remove the file at all
  lCSV_LOG="${LOG_FILE/\.txt/\.csv}"
  if [[ -f "${lCSV_LOG}" ]]; then
    if [[ $(wc -l "${lCSV_LOG}" | awk '{print $1}') -lt 2 ]]; then
      rm "${lCSV_LOG}"
    fi
  fi

  if [[ "${DISABLE_NOTIFICATIONS}" -eq 0 ]]; then
    write_notification "Module ${lMODULE_MAIN_NAME} finished"
  fi
  print_output "[*] $(print_date) - ${lMODULE_MAIN_NAME} finished" "main"
}

strip_color_codes() {
  echo "${1:-}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"
}

banner_printer() {
  local lBANNER_TO_PRINT=""

  echo ""
  lBANNER_TO_PRINT=$(find "${CONFIG_DIR}"/banner/ -type f -name "*${EMBA_VERSION}*"| shuf -n 1)
  if [[ "${RELEASE}" -ne 1 ]]; then
    lBANNER_TO_PRINT=$(find "${CONFIG_DIR}"/banner/ -type f | shuf -n 1)
  fi

  if [[ -f "${lBANNER_TO_PRINT}" ]]; then
    cat "${lBANNER_TO_PRINT}"
    echo ""
  fi
}

# write notfication is the central notification area
# if you want to print a notification via the notification system
# call this function with the message as parameter
write_notification() {
  [[ "${DISABLE_NOTIFICATIONS}" -eq 1 ]] && return
  # in case DISPLAY is not set we are not able to show notifications
  if ! [[ -v DISPLAY ]]; then
    return
  fi

  local lMESSAGE="${1:-}"

  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -d "${TMP_DIR}" ]]; then
    # we are in the docker container and so we need to write the
    # notification to a temp file which is checked via print_notification
    local lNOTIFICATION_LOCATION="${TMP_DIR}"/notifications.log
    echo "${lMESSAGE}" > "${lNOTIFICATION_LOCATION}" || true
  else
    # if we are on the host (e.g., in developer mode) we can directly handle
    # the notification
    NOTIFICATION_ID=$(notify-send -p -r "${NOTIFICATION_ID}" --icon="${EMBA_ICON}" "EMBA" "${lMESSAGE}" -t 2 || true)
  fi
}

# print_notification handles the monitoring of the notification tmp file
# from the docker container. If someone prints something into this file
# this function will handle it and generate a desktop notification
print_notification() {
  [[ "${DISABLE_NOTIFICATIONS}" -eq 1 ]] && return
  if ! [[ -v DISPLAY ]]; then
    # in case DISPLAY is not set we are not able to show notifications
    return
  fi
  local lNOTIFICATION_LOCATION="${TMP_DIR}"/notifications.log

  until [[ -f "${lNOTIFICATION_LOCATION}" ]]; do
    sleep 1
    if check_emba_ended; then
      exit
    fi
  done

  local lCURRENT=""
  lCURRENT=$(<"${lNOTIFICATION_LOCATION}")

  disable_strict_mode "${STRICT_MODE}" 0
  inotifywait -q -m -e modify "${lNOTIFICATION_LOCATION}" --format "%e" | while read -r EVENT; do
    if [[ "${EVENT}" == "MODIFY" ]]; then
      if ! [[ -f "${lNOTIFICATION_LOCATION}" ]]; then
        return
      fi
      local lPREV="${lCURRENT}"
      lCURRENT=$(<"${lNOTIFICATION_LOCATION}")
      if ! [[ "${lCURRENT}" == "${lPREV}" ]]; then
        # notification replacement see https://super-unix.com/ubuntu/ubuntu-how-to-use-notify-send-to-immediately-replace-an-existing-notification/
        export NOTIFICATION_ID=""
        NOTIFICATION_ID=$(notify-send -p -r "${NOTIFICATION_ID}" --icon="${EMBA_ICON}" "EMBA" "${lCURRENT}" -t 2)
      fi
    fi
  done
}

# writes inputs into csv for chatgpt
# Args: "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "${GPT_RESPONSE_}"
write_csv_gpt() {
  local lCSV_ITEMS_ARR=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  printf '%s;' "${lCSV_ITEMS_ARR[@]}" >> "${CSV_DIR}/q02_openai_question.csv" || true
  printf '\n' >> "${CSV_DIR}/q02_openai_question.csv" || true
}

# writes inputs into tmp csv for chatgpt
# Args: "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "${GPT_RESPONSE_}"
write_csv_gpt_tmp() {
  local lCSV_ITEMS_ARR=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  printf '%s;' "${lCSV_ITEMS_ARR[@]}" >> "${CSV_DIR}/q02_openai_question.csv.tmp" || true
  printf '\n' >> "${CSV_DIR}/q02_openai_question.csv.tmp" || true
}

write_anchor_gpt() {
  if [[ ${HTML} -eq 1 ]] ; then
    local lLINK="${1:-}"
    lLINK="$(format_log "[ASK_GPT] ""${lLINK}" 1)"
    local lLOG_FILE_ALT="${2:-}"
    if [[ "${lLOG_FILE_ALT}" != "no_log" ]] && [[ "${lLOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${lLOG_FILE_ALT}" ]] ; then
        echo -e "${lLINK}" | tee -a "${lLOG_FILE_ALT}" >/dev/null
      else
        echo -e "${lLINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}

# secure sleep is for longer sleeps
# it checks every 10 secs if EMBA is running
# if EMBA is finished it returns and the caller can exit also
# paramter: $1 is sleep time in seconds
secure_sleep() {
  local lSLEEP_TIME="${1:-}"
  local lCUR_SLEEP_TIME=0

  while [[ "${lCUR_SLEEP_TIME}" -lt "${lSLEEP_TIME}" ]]; do
    sleep 10
    lCUR_SLEEP_TIME=$((lCUR_SLEEP_TIME + 10))
    if check_emba_ended; then
      exit
    fi
  done
}

print_running_modules() {
  while true; do
    if [[ -f "${LOG_DIR}""/""${MAIN_LOG_FILE}" ]]; then
      if check_emba_ended; then
        exit
      fi
    fi

    # we print status about running modules every hour
    secure_sleep 3600

    local lSTARTED_EMBA_PROCESSES_ARR=()
    local lEMBA_STARTED_PROC=""
    mapfile -t lSTARTED_EMBA_PROCESSES_ARR < <(grep starting "${LOG_DIR}""/""${MAIN_LOG_FILE}" | cut -d '-' -f2 | awk '{print $1}' || true)

    for lEMBA_STARTED_PROC in "${lSTARTED_EMBA_PROCESSES_ARR[@]}"; do
      if ! grep -i -q "${lEMBA_STARTED_PROC}"" finished" "${LOG_DIR}""/""${MAIN_LOG_FILE}"; then
        print_output "[*] $(print_date) - ${ORANGE}${lEMBA_STARTED_PROC}${NC} currently running" "no_log"
      fi
    done
  done
}

show_runtime() {
  local lSHORT="${1:-0}"
  if [[ "${lSHORT}" -eq 1 ]]; then
    date -ud "@${SECONDS}" +"$(( SECONDS/3600/24 )):%H:%M:%S"
  else
    date -ud "@${SECONDS}" +"$(( SECONDS/3600/24 )) days and %H:%M:%S"
  fi
}

print_date() {
  local LANG=""
  LANG=en date
}
