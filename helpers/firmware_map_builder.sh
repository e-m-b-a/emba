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

# Description:  Linux system map dependency generator includes deep binary analysis
#               and hardening & multi-arch syscalls
#               This script can be run standalone from CLI. It prepares the EMBA S130
#               module and uses this module.

trap cleanup SIGINT SIGTERM EXIT

# setup some paths for EMBA
export HELP_DIR="./helpers"
export EXT_DIR="/tmp"
export MOD_DIR="./modules"

# setup some paths for the module
export EMBA_MAP_GENERATOR=1
export MAX_MAP_FILES=2000

# import EMBA helpers
# shellcheck source=/dev/null
source "${HELP_DIR}/helpers_emba_print.sh"
# shellcheck source=/dev/null
source "${HELP_DIR}/helpers_emba_helpers.sh"
# shellcheck source=/dev/null
source "${HELP_DIR}/helpers_emba_path.sh"
# shellcheck source=/dev/null
source "${MOD_DIR}/S130_binary_map_builder.sh"

# we need -e or "-l and -f"
parameter_parsing() {
  while getopts l:e:f:hm:j: OPT; do
    case "${OPT}" in
    l)
      export LOG_PATH_MODULE="${OPTARG%\/}"
      ;;
    e)
      export LOG_DIR="${OPTARG%\/}"
      export FIRMWARE_PATH="${LOG_DIR}/firmware"
      export LOG_PATH_MODULE="${LOG_DIR}/s130_binary_map_builder"
      ;;
    f)
      export FIRMWARE_PATH="${OPTARG%\/}"
      ;;
    m)
      export MAX_FILES="${OPTARG}"
      ;;
    j)
      export MAX_JOBS="${OPTARG}"
      ;;
    h)
      print_help
      exit 1
      ;;
    *)
      print_help
      exit 1
      ;;
    esac
  done

  # setup some paths for the EMBA module
  [[ -z "${LOG_DIR}" ]] && LOG_DIR="${LOG_PATH_MODULE}"
  export HTML_PATH="${LOG_DIR}/html-report"
  export S115_LOG="${LOG_DIR}/s115_usermode_emulator.txt"
  export S115_LOG_DIR="${S115_LOG/\.txt/\/}"
  export L10_SYS_EMU_RESULTS="${LOG_DIR}/emulator_online_results.log"
}

print_help() {
  echo -e "\\n${CYAN}USAGE${NC}"
  echo -e "${CYAN}-e [~/path]${NC}       EMBA log path of already analyzed firmware (if -f is set, this parameter can't be used)"
  echo -e "${CYAN}-f [~/path]${NC}       Firmware path (firmware needs to be extracted - only needed if -e is not used)"
  echo -e "${CYAN}-l [~/path]${NC}       Log path (only needed if -e is not used)"
  echo -e "${CYAN}-m [cnt]${NC}          Number of files that should be processed (optional)"
  echo -e "${CYAN}-j [cnt]${NC}          Number of jobs that are used (optional)"

  echo -e "\\nHelp"
  echo -e "${CYAN}-h${NC}                Prints this help message"
}

setup_special_environment() {
  echo "[*] External assets - download for offline capability."

  export JS_LIB="svg-pan-zoom.min.js"
  local JS_EMBA_LIB="${EXT_DIR}/svg-pan-zoom.min.js"
  local JS_URL="https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.5.0/dist/${JS_LIB}"

  export LOGO_FILE="emba.svg"
  local LOGO_FILE_EMBA="${HELP_DIR}/${LOGO_FILE}"
  local LOGO_URL="https://raw.githubusercontent.com/e-m-b-a/emba/refs/heads/master/helpers/${LOGO_FILE}"

  # EXT_DIR -> /tmp
  [[ ! -f "${JS_EMBA_LIB}" ]] && wget -q --timeout=15 "${JS_URL}" -O "${EXT_DIR}/${JS_LIB}"
  [[ ! -f "${LOGO_FILE_EMBA}" ]] && wget -q --timeout=15 "${LOGO_URL}" -O "${EXT_DIR}/${LOGO_FILE}"
  [[ ! -f "${EXT_DIR}/${LOGO_FILE}" || ! -f "${LOGO_FILE_EMBA}" ]] && exit 1
  [[ ! -f "${EXT_DIR}/${JS_LIB}" ]] && exit 1
}

# job cleanup for multi processing
cleanup() {
  if [[ $(jobs -r | wc -l) -gt 0 ]]; then
    echo "[*] Cleaning up all jobs ..."
    jobs -p | xargs -r kill
  fi
  exit 1
}

main() {
  if [[ $# -eq 0 ]]; then
    echo -e "${ORANGE}In order to be able to use EMBA, you have to specify at least a firmware (-f) and a log directory (-l).${NC}"
    echo -e "${ORANGE}If you have an already finished EMBA scan you can also set the -e parameter to the EMBA directory instead of -f.${NC}"
    print_help
    exit 1
  fi

  parameter_parsing "$@"

  if [[ -z "${LOG_PATH_MODULE}" ]]; then
    print_help
    exit 1
  fi
  if ! command -v neato >/dev/null; then
    echo -e "[-] ERROR: Install graphviz neato - graphviz, python3-pygraphviz"
    exit 1
  fi

  if [[ -d "${LOG_PATH_MODULE}" ]]; then
    echo "[-] WARNING: Log directory ${LOG_PATH_MODULE} available - remove before proceeding"
    exit 1
  fi

  export MAIN_LOG="${LOG_PATH_MODULE}.txt"
  setup_special_environment

  S130_binary_map_builder
}

main "$@"

if [[ -f "${HTML_FILE}" ]]; then
  echo -e "[+] Process complete. EMBA dependency map generated at: ${ORANGE}${HTML_FILE}${NC}"
else
  echo "[-] Process complete. EMBA dependency map not generated at."
  exit 1
fi
