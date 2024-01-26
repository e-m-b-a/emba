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

MODULE_NUMBER="--"
SUB_MODULE_COUNT=0
GREP_LOG_DELIMITER=";"
GREP_LOG_LINEBREAK=" || "
MESSAGE_TYPE=""
OLD_MESSAGE_TYPE=""

welcome()
{
  echo -e "\\n""${BOLD}""╔═══════════════════════════════════════════════════════════════╗""${NC}"
  echo -e "${BOLD}""║""${BLUE}""${BOLD}""${ITALIC}""                            E M B A                            ""${NC}""${BOLD}""║""${NC}"
  echo -e "${BOLD}""║                   EMBEDDED FIRMWARE ANALYZER                  ""${NC}""${BOLD}""║""${NC}"
  echo -e "${BOLD}""╚═══════════════════════════════════════════════════════════════╝""${NC}"
}

module_log_init()
{
  # local LOG_FILE_NAME
  LOG_FILE_NAME="${1:-}"
  local FILE_NAME
  MODULE_NUMBER="$(echo "${LOG_FILE_NAME}" | cut -d "_" -f1 | cut -c2- )"
  FILE_NAME=$(echo "${LOG_FILE_NAME}" | sed -e 's/\(.*\)/\L\1/' | tr " " _ )
  LOG_FILE="${LOG_DIR}""/""${FILE_NAME}"".txt"
  LOG_FILE_NAME="${FILE_NAME}"".txt"

  if [[ -f "${LOG_FILE}" ]]; then
    print_output "[*] Found old module log file ${ORANGE}${LOG_FILE}${NC}... creating a backup" "no_log"
    export OLD_LOG_FILE=""
    OLD_LOG_FILE="${LOG_FILE}".bak."${RANDOM}"
    mv "${LOG_FILE}" "${OLD_LOG_FILE}" || true
  fi

  module_start_log "${FILE_NAME^}"

  if [[ "${DISABLE_NOTIFICATIONS}" -eq 0 ]]; then
    write_notification "Module ${FILE_NAME} started"
  fi
}

module_title()
{
  local MODULE_TITLE
  MODULE_TITLE="${1:-}"
  local MODULE_TITLE_FORMAT
  MODULE_TITLE_FORMAT="[""${BLUE}""+""${NC}""] ""${CYAN}""${BOLD}""${MODULE_TITLE}""${NC}""\\n""${BOLD}""=================================================================""${NC}"
  echo -e "\\n\\n""${MODULE_TITLE_FORMAT}" || true
  if [[ "${2:-}" != "no_log" ]] ; then
    echo -e "$(format_log "${MODULE_TITLE_FORMAT}")" | tee -a "${LOG_FILE}" >/dev/null || true
    if [[ ${LOG_GREP} -eq 1 ]] ; then
      write_grep_log "${MODULE_TITLE}" "MODULE_TITLE"
    fi
  fi
  SUB_MODULE_COUNT=0
}

# $1: sub module title
# $2: (optional) log file to log -> this is typically used in combination with write_log to write another log file
sub_module_title()
{
  local SUB_MODULE_TITLE="${1:-}"
  local LOG_FILE_TO_LOG="${2:-}"
  # if $2 is not set, we are going to log to the original LOG_FILE
  if ! [[ -f "${LOG_FILE_TO_LOG}" ]]; then
    LOG_FILE_TO_LOG="${LOG_FILE}"
  fi

  local SUB_MODULE_TITLE_FORMAT=""

  SUB_MODULE_TITLE_FORMAT="\\n""${BLUE}""==>""${NC}"" ""${CYAN}""${SUB_MODULE_TITLE}""${NC}""\\n-----------------------------------------------------------------"
  echo -e "${SUB_MODULE_TITLE_FORMAT}" || true
  echo -e "$(format_log "${SUB_MODULE_TITLE_FORMAT}")" | tee -a "${LOG_FILE_TO_LOG}" >/dev/null || true

  if [[ ${LOG_GREP} -eq 1 ]] ; then
    SUB_MODULE_COUNT=$((SUB_MODULE_COUNT + 1))
    write_grep_log "${SUB_MODULE_TITLE}" "SUB_MODULE_TITLE"
  fi
}

print_output()
{
  local OUTPUT="${1:-\n}"
  local LOG_SETTING="${2:-}"
  if [[ -n "${LOG_SETTING}" && -d "$(dirname "${LOG_SETTING}")" && "${LOG_FILE:-}" != "${LOG_FILE_MOD:-}" ]]; then
    local LOG_FILE_MOD="${2:-}"
  fi
  # add a link as third argument to add a link marker for web report
  local REF_LINK="${3:-}"
  local TYPE_CHECK
  TYPE_CHECK="$( echo "${OUTPUT}" | cut -c1-3 )"
  if [[ "${TYPE_CHECK}" == "[-]" || "${TYPE_CHECK}" == "[*]" || "${TYPE_CHECK}" == "[!]" || "${TYPE_CHECK}" == "[+]" ]] ; then
    local COLOR_OUTPUT_STRING=""
    COLOR_OUTPUT_STRING="$(color_output "${OUTPUT}")"
    safe_echo "${COLOR_OUTPUT_STRING}"
    if [[ "${LOG_SETTING}" == "main" ]] ; then
      safe_echo "$(format_log "${COLOR_OUTPUT_STRING}")" "${MAIN_LOG}"
    elif [[ "${LOG_SETTING}" != "no_log" ]] ; then
      if [[ -z "${REF_LINK:-}" ]] ; then
        safe_echo "$(format_log "${COLOR_OUTPUT_STRING}")" "${LOG_FILE}"
        if [[ -n "${LOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${COLOR_OUTPUT_STRING}")" "${LOG_FILE_MOD}"
        fi
      else
        safe_echo "$(format_log "${COLOR_OUTPUT_STRING}")""\\r\\n""$(format_log "[REF] ""${REF_LINK}" 1)" "${LOG_FILE}"
        if [[ -n "${LOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${COLOR_OUTPUT_STRING}")""\\r\\n""$(format_log "[REF] ""${REF_LINK}" 1)" "${LOG_FILE_MOD}"
        fi
      fi
    fi
  else
    safe_echo "${OUTPUT}"
    if [[ "${LOG_SETTING}" == "main" ]] ; then
      safe_echo "$(format_log "${OUTPUT}")" "${MAIN_LOG}"
    elif [[ "${LOG_SETTING}" != "no_log" ]] ; then
      if [[ -z "${REF_LINK}" ]] ; then
        safe_echo "$(format_log "${OUTPUT}")" "${LOG_FILE:-}"
        if [[ -n "${LOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${OUTPUT}")" "${LOG_FILE_MOD}"
        fi
      else
        safe_echo "$(format_log "${OUTPUT}")""\\r\\n""$(format_log "[REF] ""${REF_LINK}" 1)" "${LOG_FILE}"
        if [[ -n "${LOG_FILE_MOD:-}" ]]; then
          safe_echo "$(format_log "${OUTPUT}")""\\r\\n""$(format_log "[REF] ""${REF_LINK}" 1)" "${LOG_FILE_MOD}"
        fi
      fi
    fi
  fi
  if [[ "${LOG_SETTING}" != "no_log" ]]; then
    write_grep_log "${OUTPUT}"
  fi
}

# echo unknown data in a consistent way:
safe_echo() {
  STRING_TO_ECHO="${1:-}"

  # %b  ARGUMENT  as a string with '\' escapes interpreted, except that octal escapes are of the form \0 or
  if [[ -v 2 ]]; then
    local LOG_TO_FILE="${2:-}"
    printf -- "%b" "${STRING_TO_ECHO}\r\n" | tee -a "${LOG_TO_FILE}" >/dev/null || true
  else
    printf -- "%b" "${STRING_TO_ECHO}\r\n" || true
  fi
}

# This should be used for using untrusted data as input for other commands:
escape_echo() {
  STRING_TO_ECHO="${1:-}"

  # %q  ARGUMENT is printed in a format that can be reused as shell input, escaping non-printable characters with the proposed POSIX $'' syntax.
  if [[ -v 2 ]]; then
    local LOG_TO_FILE="${2:-}"
    printf -- "%q" "${STRING_TO_ECHO}" | tee -a "${LOG_TO_FILE}" >/dev/null || true
  else
    printf -- "%q" "${STRING_TO_ECHO}" || true
  fi
}

check_int() {
  local INT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if [[ -n "${INT_TO_CHECK//[0-9]/}" ]]; then
    print_output "[-] Invalid input detected - integers only" "no_log"
    exit 1
  fi
}

check_alnum() {
  local INPUT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if ! [[ "${INPUT_TO_CHECK}" =~ ^[[:alnum:]]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only" "no_log"
    exit 1
  fi
}

check_vendor() {
  local INPUT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if ! [[ "${INPUT_TO_CHECK}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only" "no_log"
    exit 1
  fi
}

check_notes() {
  local INPUT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if ! [[ "${INPUT_TO_CHECK}" =~ ^[[:alnum:][:blank:][:punct:]]+$ ]]; then
    print_output "[-] Invalid input detected - alphanumerical only allowed in notes" "no_log"
    exit 1
  fi
}

check_path_input() {
  local INPUT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if ! [[ "${INPUT_TO_CHECK}" =~ ^[a-zA-Z0-9./_~'-']+$ ]]; then
    print_output "[-] Invalid input detected - paths aka ~/abc/def123/ASDF only" "no_log"
    exit 1
  fi
}

check_version() {
  local INPUT_TO_CHECK="${1:-}"
  [[ -z "${INPUT_TO_CHECK}" ]] && return
  if ! [[ "${INPUT_TO_CHECK}" =~ ^[a-zA-Z0-9./_:\+'-']+$ ]]; then
    print_output "[-] Invalid input detected - versions aka 1.2.3-a:b only" "no_log"
    exit 1
  fi
}

print_ln() {
  local LOG_SETTING="${1:-}"
  print_output "" "${LOG_SETTING}"
}

print_dot() {
  [[ "${DISABLE_DOTS}" -eq 1 ]] && return
  echo -n "." 2>/dev/null ||true
}

write_log() {
  readarray TEXT_ARR <<< "${1}"
  local LOG_FILE_ALT="${2:-}"
  local GREP_LOG_WRITE="${3:-}"
  if [[ "${LOG_FILE_ALT}" == "" ]] ; then
    W_LOG_FILE="${LOG_FILE}"
  else
    W_LOG_FILE="${LOG_FILE_ALT}"
  fi

  for E in "${TEXT_ARR[@]}" ; do
    local TYPE_CHECK
    TYPE_CHECK="$( echo "${E}" | cut -c1-3 )"
    if [[ ( "${TYPE_CHECK}" == "[-]" || "${TYPE_CHECK}" == "[*]" || "${TYPE_CHECK}" == "[!]" || "${TYPE_CHECK}" == "[+]") && ("${E}" != "[*] Statistic"* ) ]] ; then
      local COLOR_OUTPUT_STRING
      COLOR_OUTPUT_STRING="$(color_output "${E}")"
      echo -e "$(format_log "${COLOR_OUTPUT_STRING}")" | tee -a "${W_LOG_FILE}" >/dev/null
    else
      echo -e "$(format_log "${E}")" | tee -a "${W_LOG_FILE}" >/dev/null || true
    fi
  done
  if [[ "${GREP_LOG_WRITE}" == "g" ]] ; then
    write_grep_log "${1:-}"
  fi
}

write_csv_log() {
  local CSV_ITEMS=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  CSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  CSV_LOG="${CSV_DIR}""/""${CSV_LOG}"

  printf '%s;' "${CSV_ITEMS[@]}" >> "${CSV_LOG}" || true
  printf '\n' >> "${CSV_LOG}" || true
}

# write_pid_log is a functions used for debugging
# enable it with setting PID_LOGGING to 1 in the main emba script
# additionally you need to add a function call like the following to
# every threaded call you need the PID
# write_pid_log "${FUNCNAME[0]} - emulate_binary - $BIN_ - $TMP_PID"
# with this you can trace the PIDs. Additionally it is sometimes
# useful to enable PID output in wait_for_pid from helpers_emba_helpers.sh
write_pid_log() {
  local LOG_MESSAGE="${1:-}"
  if [[ "${PID_LOGGING}" -eq 0 ]]; then
    return
  fi
  if ! [[ -d "${TMP_DIR}" ]]; then
    print_output "[-] WARNING: TMP directory ${ORANGE}${TMP_DIR}${NC} not found"
    return
  fi

  # shellcheck disable=SC2153
  echo "${LOG_MESSAGE}" >> "${TMP_DIR}"/"${PID_LOG_FILE}" || true
}

write_grep_log()
{
  OLD_MESSAGE_TYPE=""
  if [[ ${LOG_GREP} -eq 1 ]] ; then
    readarray -t OUTPUT_ARR <<< "${1}"
    local MESSAGE_TYPE_PAR="${2:-}"
    for E in "${OUTPUT_ARR[@]}" ; do
      if [[ -n "${E//[[:blank:]]/}" ]] && [[ "${E}" != "\\n" ]] && [[ -n "${E}" ]] ; then
        if [[ -n "${MESSAGE_TYPE_PAR}" ]] ; then
          MESSAGE_TYPE="${MESSAGE_TYPE_PAR}"
          OLD_MESSAGE_TYPE="${MESSAGE_TYPE}"
          TYPE=2
        else
          TYPE_CHECK="$( echo "${E}" | cut -c1-3 )"
          if [[ "${TYPE_CHECK}" == "[-]" ]] ; then
            MESSAGE_TYPE="FALSE"
            OLD_MESSAGE_TYPE="${MESSAGE_TYPE}"
            TYPE=1
          elif [[ "${TYPE_CHECK}" == "[*]" ]] ; then
            MESSAGE_TYPE="MESSAGE"
            OLD_MESSAGE_TYPE="${MESSAGE_TYPE}"
            TYPE=1
          elif [[ "${TYPE_CHECK}" == "[!]" ]] ; then
            MESSAGE_TYPE="WARNING"
            OLD_MESSAGE_TYPE="${MESSAGE_TYPE}"
            TYPE=1
          elif [[ "${TYPE_CHECK}" == "[+]" ]] ; then
            MESSAGE_TYPE="POSITIVE"
            OLD_MESSAGE_TYPE="${MESSAGE_TYPE}"
            TYPE=1
          else
            MESSAGE_TYPE="${OLD_MESSAGE_TYPE}"
            TYPE=3
          fi
        fi
        if [[ ${TYPE} -eq 1 ]] ; then
          echo -e "${MESSAGE_TYPE}""${GREP_LOG_DELIMITER}""$(echo -e "$(add_info_grep_log)")""$(echo -e "$(format_grep_log "$(echo "${E}" | cut -c4- )")")" | tee -a "${GREP_LOG_FILE}" >/dev/null
        elif [[ ${TYPE} -eq 2 ]] ; then
          echo -e "${MESSAGE_TYPE}""${GREP_LOG_DELIMITER}""$(echo -e "$(add_info_grep_log)")""$(echo -e "$(format_grep_log "${E}")")" | tee -a "${GREP_LOG_FILE}" >/dev/null
        elif [[ ${TYPE} -eq 3 ]] ; then
          truncate -s -1 "${GREP_LOG_FILE}"
          echo -e "${GREP_LOG_LINEBREAK}""$(echo -e "$(format_grep_log "${E}")")" | tee -a "${GREP_LOG_FILE}" >/dev/null
        fi
      fi
    done
  fi
}

write_link()
{
  if [[ ${HTML} -eq 1 ]] ; then
    local LINK
    LINK="${1:-}"
    LINK="$(format_log "[REF] ""${LINK}" 1)"
    local LOG_FILE_ALT="${2:-}"
    if [[ "${LOG_FILE_ALT}" != "no_log" ]] && [[ "${LOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${LOG_FILE_ALT}" ]] ; then
        echo -e "${LINK}" | tee -a "${LOG_FILE_ALT}" >/dev/null
      else
        echo -e "${LINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
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
    local LINK
    LINK="${1:-}"
    LINK="$(format_log "[LOV] ""${LINK}" 1)"
    local LOG_FILE_ALT="${2:-}"
    if [[ "${LOG_FILE_ALT}" != "no_log" ]] && [[ "${LOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${LOG_FILE_ALT}" ]] ; then
        echo -e "${LINK}" | tee -a "${LOG_FILE_ALT}" >/dev/null
      else
        echo -e "${LINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}


write_anchor()
{
  if [[ ${HTML} -eq 1 ]] ; then
    local ANCHOR
    ANCHOR="${1:-}"
    ANCHOR="$(format_log "[ANC] ""${ANCHOR}" 1)"
    local LOG_FILE_ALT="${2:-}"
    if [[ "${LOG_FILE_ALT}" != "no_log" ]] && [[ "${LOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${LOG_FILE_ALT}" ]] ; then
        echo -e "${ANCHOR}" | tee -a "${LOG_FILE_ALT}" >/dev/null
      else
        echo -e "${ANCHOR}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}

reset_module_count()
{
  MODULE_NUMBER="--"
  SUB_MODULE_COUNT=0
}

color_output()
{
  local TEXT=""
  readarray TEXT_ARR <<< "${1:-}"
  for E in "${TEXT_ARR[@]}" ; do
    local TYPE_CHECK
    TYPE_CHECK="$( echo "${E}" | cut -c1-3 )"
    if [[ "${TYPE_CHECK}" == "[-]" || "${TYPE_CHECK}" == "[*]" || "${TYPE_CHECK}" == "[!]" || "${TYPE_CHECK}" == "[+]" ]] ; then
      local STR=""
      STR="$( echo "${E}" | cut -c 4- || true)"
      if [[ "${TYPE_CHECK}" == "[-]" ]] ; then
        TEXT="${TEXT}""[""${RED}""-""${NC}""]""${STR}"
      elif [[ "${TYPE_CHECK}" == "[*]" ]] ; then
        TEXT="${TEXT}""[""${ORANGE}""*""${NC}""]""${STR}"
      elif [[ "${TYPE_CHECK}" == "[!]" ]] ; then
        TEXT="${TEXT}""[""${MAGENTA}""!""${NC}""]""${MAGENTA}""${STR}""${NC}"
      elif [[ "${TYPE_CHECK}" == "[+]" ]] ; then
        TEXT="${TEXT}""[""${GREEN}""+""${NC}""]""${GREEN}""${STR}""${NC}"
      else
        TEXT="${TEXT}""${E}"
      fi
    else
      TEXT="${TEXT}""${E}"
    fi
  done
  echo "${TEXT}"
}

white()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${NC}""${E}""\\n"
  done
  echo -e "${TEXT}"
}

red()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${RED}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

green()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${GREEN}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

blue()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${BLUE}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

cyan()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${CYAN}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

magenta()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${MAGENTA}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

orange()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${ORANGE}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

bold()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${BOLD}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

italic()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""${ITALIC}""${E}""${NC}""\\n"
  done
  echo -e "${TEXT}"
}

indent()
{
  local TEXT=""
  readarray -t TEXT_ARR <<< "${1}"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="${TEXT}""    ""${E}""\\n"
  done
  echo -e "${TEXT}"
}

format_log()
{
  local LOG_STRING="${1:-}"
  # remove log formatting, even if EMBA is set to format it (for [REF] markers used)
  local OVERWRITE_SETTING="${2:-}"
  if [[ ${FORMAT_LOG} -eq 0 ]] || [[ ${OVERWRITE_SETTING} -eq 1 ]] ; then
    echo "${LOG_STRING}" | sed -r "s/\\\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\[([0-9]{1,2}(;[0-9]{1,2}(;[0-9]{1,2})?)?)?[m|K]//g" \
      | sed -e "s/\\\\n/\\n/g"
  else
    echo "${LOG_STRING}"
  fi
}

format_grep_log()
{
  local LOG_STRING="${1:-}"
  echo "${LOG_STRING}" | sed -r "s/\\\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
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
  echo -e "${CYAN}""-a [MIPS]""${NC}""         Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC]"
  echo -e "${CYAN}""-A [MIPS]""${NC}""         Force Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (disable architecture check)"
  echo -e "${CYAN}""-l [./path]""${NC}""       Log path"
  echo -e "${CYAN}""-f [./path]""${NC}""       Firmware path"
  echo -e "${CYAN}""-e [./path]""${NC}""       Exclude paths from testing (multiple usage possible)"
  echo -e "${CYAN}""-m [MODULE_NO.]""${NC}""   Test only with set modules [e.g. -m p05 -m s10 ... or -m p to run all p modules]"
  echo -e "                  (multiple usage possible, case insensitive, final modules aren't selectable, if firmware isn't a binary, the p modules won't run)"
  echo -e "${CYAN}""-c""${NC}""                Enable cwe-checker"
  echo -e "${CYAN}""-g""${NC}""                Create grep-able log file in [log_path]/fw_grep.log"
  echo -e "                  Schematic: MESSAGE_TYPE;MODULE_NUMBER;SUB_MODULE_NUMBER;MESSAGE"
  echo -e "${CYAN}""-E""${NC}""                Enables automated qemu emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-p [PROFILE]""${NC}""      EMBA starts with a pre-defined profile (stored in ./scan-profiles)"
  echo -e "${CYAN}""-Q""${NC}""                Enables automated qemu system emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-P""${NC}""                Overwrite auto MAX_MODS (maximum modules in parallel) configuration"
  echo -e "${CYAN}""-T""${NC}""                Overwrite auto MAX_MOD_THREADS (maximum threads per module) configuration"
  echo -e "\\nDeveloper options"
  echo -e "${CYAN}""-D""${NC}""                Developer mode - EMBA runs on the host without container protection"
  echo -e "${CYAN}""-S""${NC}""                STRICT mode - developer option to improve code quality (not enabled by default)"
  echo -e "${CYAN}""-i""${NC}""                Ignores log path check"
  echo -e "${CYAN}""-y""${NC}""                Overwrite log directory automaticially, even if it is not empty"
  echo -e "\\nWeb reporter"
  echo -e "${CYAN}""-W""${NC}""                Activates web report creation in log path (overwrites -z)"
  echo -e "\\nSystem check"
  echo -e "${CYAN}""-d [1/2]""${NC}""          Only checks dependencies (1 - on host and in container, 2 - only container)"
  echo -e "${CYAN}""-F""${NC}""                Checks dependencies but ignore errors"
  echo -e "${CYAN}""-U""${NC}""                Check and apply available updates and exit"
  echo -e "${CYAN}""-V""${NC}""                Show EMBA version"
  echo -e "\\nSpecial tests"
  echo -e "${CYAN}""-k [./config]""${NC}""     Kernel config path"
  echo -e "${CYAN}""-C [container id]""${NC}"" Extract and analyze a local docker container via container id"
  echo -e "${CYAN}""-x""${NC}""                Enable deep extraction - try to extract every file two times with binwalk (WARNING: Uses a lot of disk space)"
  echo -e "${CYAN}""-t""${NC}""                Activate multi threading (destroys regular console output)"
  echo -e "${CYAN}""-r""${NC}""                Remove temporary firmware directory after testing"
  echo -e "${CYAN}""-b""${NC}""                Just print a random banner and exit"
  echo -e "${CYAN}""-o [./path]""${NC}""       2nd Firmware path to diff against the main firmware file - diff mode only (no other firmware analysis)"
  echo -e "\\nModify output"
  echo -e "${CYAN}""-s""${NC}""                Prints only relative paths"
  echo -e "${CYAN}""-z""${NC}""                Adds ANSI color codes to log"
  echo -e "${CYAN}""-B""${NC}""                Enables status bar in silent mode (Warning: unstable on window size change)"
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
  local _VENDOR="${1:-}"
  local _VERSION="${2:-}"
  local _DEVICE="${3:-}"
  local _NOTES="${4:-}"
  if [[ -n "${_VENDOR}" || -n "${_VERSION}" || -n "${_DEVICE}" || -n "${_NOTES}" ]]; then
    print_bar "no_log"
    print_output "[*] Firmware information:" "no_log"
    if [[ -n "${_VENDOR}" ]]; then
      print_output "$(indent "${BOLD}""Vendor:\t""${NC}""${ORANGE}""${_VENDOR}""${NC}")" "no_log"
    fi
    if [[ -n "${_VERSION}" ]]; then
      print_output "$(indent "${BOLD}""Version:\t""${NC}""${ORANGE}""${_VERSION}""${NC}")" "no_log"
    fi
    if [[ -n "${_DEVICE}" ]]; then
      print_output "$(indent "${BOLD}""Device:\t""${NC}""${ORANGE}""${_DEVICE}""${NC}")" "no_log"
    fi
    if [[ -n "${_NOTES}" ]]; then
      print_output "$(indent "${BOLD}""Additional notes:\t""${NC}""${ORANGE}""${_NOTES}""${NC}")" "no_log"
    fi
    print_bar "no_log"
  fi
}

print_etc()
{
  if [[ ${#ETC_PATHS[@]} -gt 1 ]] ; then
    print_ln "no_log"
    print_output "[*] Found more paths for etc (these are automatically taken into account):" "no_log"
    for ETC in "${ETC_PATHS[@]}" ; do
      if [[ "${ETC}" != "${FIRMWARE_PATH}""/etc" ]] ; then
        print_output "$(indent "$(orange "$(print_path "${ETC}")")")" "no_log"
      fi
    done
  fi
}

print_excluded() {
  readarray -t EXCLUDE_PATHS_ARR < <(printf '%s' "${EXCLUDE_PATHS}")
  if [[ ${#EXCLUDE_PATHS_ARR[@]} -gt 0 ]] ; then
    print_ln "no_log"
    print_output "[*] Excluded: " "no_log"
    for EXCL in "${EXCLUDE_PATHS_ARR[@]}" ; do
      print_output ".""$(indent "$(orange "$(print_path "${EXCL}")")")" "no_log"
    done
    print_ln "no_log"
  fi
}

print_bar() {
  local LOG_SETTINGS="${1:-}"
  if [[ -n "${LOG_SETTINGS}" ]]; then
    print_output "\\n-----------------------------------------------------------------\\n" "${LOG_SETTINGS}"
  else
    print_output "\\n-----------------------------------------------------------------\\n"
  fi
}

module_start_log() {
  MODULE_MAIN_NAME="${1:-}"
  print_output "[*] $(print_date) - ${MODULE_MAIN_NAME} starting" "main"
  export LOG_PATH_MODULE
  if [[ "${LOG_DIR: -1}" == "/" ]]; then
    # strip final slash from log dir
    LOG_DIR="${LOG_DIR:: -1}"
  fi
  LOG_PATH_MODULE=$(abs_path "${LOG_DIR}""/""$(echo "${MODULE_MAIN_NAME}" | tr '[:upper:]' '[:lower:]')")
  if [[ -d "${LOG_PATH_MODULE}" ]] ; then
    print_output "[*] Found old module log path for ${ORANGE}${MODULE_MAIN_NAME}${NC} ... creating a backup" "no_log"
    export OLD_LOG_DIR=""
    OLD_LOG_DIR="${LOG_PATH_MODULE}".bak."${RANDOM}" || true
    mv "${LOG_PATH_MODULE}" "${OLD_LOG_DIR}" || true
  fi
  if ! [[ -d "${LOG_PATH_MODULE}" ]]; then
    mkdir "${LOG_PATH_MODULE}" || true
  fi
}

pre_module_reporter() {
  MODULE_MAIN_NAME="${1:-}"
  REPORT_TEMPLATE="$(basename -s ".sh" "${MODULE_MAIN_NAME}")-pre"
  # We handle .txt and .sh files in report_template folder.
  # .txt are just echoed on cli and report
  # .sh are executed via source -> you can use variables, color codes, execute further commands
  if [[ -f "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.txt" ]]; then
    tee -a "${LOG_FILE}" < "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.txt"
  elif [[ -f "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.sh" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.sh"
  fi
  print_ln
}

# on module end we log that the module is finished in emba.log
# additionally we log that EMBA has nothing found -> this is used for index generation of the web reporter
# additionally we generate the HTML file of the web reporter if web reporting is enabled
module_end_log() {
  MODULE_MAIN_NAME="${1:-}"
  MODULE_REPORT_STATE="${2:-}"

  if [[ "${MODULE_REPORT_STATE}" -eq 0 ]]; then
    print_output "[-] $(print_date) - ${MODULE_MAIN_NAME} nothing reported"
  fi

  # we do not report the templates on restarted tests
  if [[ "${MODULE_REPORT_STATE}" -ne 0 ]]; then
    REPORT_TEMPLATE="$(basename -s ".sh" "${MODULE_MAIN_NAME}")-post"
    # We handle .txt and .sh files in report_template folder.
    # .txt are just echoed on cli and report
    # .sh are executed via source -> you can use variables, color codes, execute further commands
    if [[ -f "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.txt" ]]; then
      print_bar ""
      tee -a "${LOG_FILE}" < "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.txt"
      print_bar ""
    elif [[ -f "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.sh" ]]; then
      print_bar ""
      # shellcheck source=/dev/null
      source "${CONFIG_DIR}/report_templates/${REPORT_TEMPLATE}.sh"
      print_bar ""
    fi
  fi
  [[ "${HTML}" -eq 1 ]] && run_web_reporter_mod_name "${MODULE_MAIN_NAME}"
  if [[ -v LOG_PATH_MODULE ]]; then
    if [[ -d "${LOG_PATH_MODULE}" ]]; then
      if [[ "$(find "${LOG_PATH_MODULE}" -type f | wc -l)" -eq 0 ]]; then
        rm -r "${LOG_PATH_MODULE}"
      fi
    fi
  fi

  # check if there is some content in the csv log file. If there is only
  # one entry line we remove the file at all
  CSV_LOG="${LOG_FILE/\.txt/\.csv}"
  if [[ -f "${CSV_LOG}" ]]; then
    if [[ $(wc -l "${CSV_LOG}" | awk '{print $1}') -lt 2 ]]; then
      rm "${CSV_LOG}"
    fi
  fi

  if [[ "${DISABLE_NOTIFICATIONS}" -eq 0 ]]; then
    write_notification "Module ${MODULE_MAIN_NAME} finished"
  fi
  print_output "[*] $(print_date) - ${MODULE_MAIN_NAME} finished" "main"
}

strip_color_codes() {
  echo "${1:-}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"
}

banner_printer() {
  echo ""
  BANNER_TO_PRINT=$(find "${CONFIG_DIR}"/banner/ -type f -name "*${EMBA_VERSION}*"| shuf -n 1)
  if [[ "${RELEASE}" -ne 1 ]]; then
    BANNER_TO_PRINT=$(find "${CONFIG_DIR}"/banner/ -type f | shuf -n 1)
  fi

  if [[ -f "${BANNER_TO_PRINT}" ]]; then
    cat "${BANNER_TO_PRINT}"
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

  local MESSAGE="${1:-}"

  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -d "${TMP_DIR}" ]]; then
    # we are in the docker container and so we need to write the
    # notification to a temp file which is checked via print_notification
    local NOTIFICATION_LOCATION="${TMP_DIR}"/notifications.log
    echo "${MESSAGE}" > "${NOTIFICATION_LOCATION}" || true
  else
    # if we are on the host (e.g., in developer mode) we can directly handle
    # the notification
    NOTIFICATION_ID=$(notify-send -p -r "${NOTIFICATION_ID}" --icon="${EMBA_ICON}" "EMBA" "${MESSAGE}" -t 2)
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
  local NOTIFICATION_LOCATION="${TMP_DIR}"/notifications.log

  until [[ -f "${NOTIFICATION_LOCATION}" ]]; do
    sleep 1
  done

  local CURRENT=""
  CURRENT=$(<"${NOTIFICATION_LOCATION}")

  disable_strict_mode "${STRICT_MODE}" 0
  inotifywait -q -m -e modify "${NOTIFICATION_LOCATION}" --format "%e" | while read -r EVENT; do
    if [[ "${EVENT}" == "MODIFY" ]]; then
      if ! [[ -f "${NOTIFICATION_LOCATION}" ]]; then
        return
      fi
      local PREV="${CURRENT}"
      CURRENT=$(<"${NOTIFICATION_LOCATION}")
      if ! [[ "${CURRENT}" == "${PREV}" ]]; then
        # notification replacement see https://super-unix.com/ubuntu/ubuntu-how-to-use-notify-send-to-immediately-replace-an-existing-notification/
        NOTIFICATION_ID=$(notify-send -p -r "${NOTIFICATION_ID}" --icon="${EMBA_ICON}" "EMBA" "${CURRENT}" -t 2)
      fi
    fi
  done
}

# writes inputs into csv for chatgpt
# Args: "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "${GPT_RESPONSE_}"
write_csv_gpt() {
  local CSV_ITEMS=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  printf '%s;' "${CSV_ITEMS[@]}" >> "${CSV_DIR}/q02_openai_question.csv" || true
  printf '\n' >> "${CSV_DIR}/q02_openai_question.csv" || true
}

# writes inputs into tmp csv for chatgpt
# Args: "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "${GPT_RESPONSE_}"
write_csv_gpt_tmp() {
  local CSV_ITEMS=("$@")
  if ! [[ -d "${CSV_DIR}" ]]; then
    print_output "[-] WARNING: CSV directory ${ORANGE}${CSV_DIR}${NC} not found"
    return
  fi
  printf '%s;' "${CSV_ITEMS[@]}" >> "${CSV_DIR}/q02_openai_question.csv.tmp" || true
  printf '\n' >> "${CSV_DIR}/q02_openai_question.csv.tmp" || true
}

write_anchor_gpt() {
  if [[ ${HTML} -eq 1 ]] ; then
    local LINK
    LINK="${1:-}"
    LINK="$(format_log "[ASK_GPT] ""${LINK}" 1)"
    local LOG_FILE_ALT="${2:-}"
    if [[ "${LOG_FILE_ALT}" != "no_log" ]] && [[ "${LOG_FILE_ALT}" != "main" ]] ; then
      if [[ -f "${LOG_FILE_ALT}" ]] ; then
        echo -e "${LINK}" | tee -a "${LOG_FILE_ALT}" >/dev/null
      else
        echo -e "${LINK}" | tee -a "${LOG_FILE}" >/dev/null
      fi
    fi
  fi
}

print_running_modules() {
  sleep 1h
  while true; do
    local STARTED_EMBA_PROCESSES=()
    local EMBA_STARTED_PROC=""
    mapfile -t STARTED_EMBA_PROCESSES < <(grep starting "${LOG_DIR}""/""${MAIN_LOG_FILE}" | cut -d '-' -f2 | awk '{print $1}' || true)

    for EMBA_STARTED_PROC in "${STARTED_EMBA_PROCESSES[@]}"; do
      if ! grep -i -q "${EMBA_STARTED_PROC}"" finished" "${LOG_DIR}""/""${MAIN_LOG_FILE}"; then
        print_output "[*] $(print_date) - ${ORANGE}${EMBA_STARTED_PROC}${NC} currently running" "no_log"
      fi
    done
    sleep 1h
  done
}

show_runtime() {
  date -ud "@${SECONDS}" +"$(( SECONDS/3600/24 )) days and %H:%M:%S"
}

print_date() {
  LANG=en date
}
