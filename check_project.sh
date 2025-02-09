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
# Contributor(s): Benedikt Kuehne, Thomas Gingele

# Description:  Check all shell scripts inside ./helpers, ./modules, emba and itself with shellchecker

STRICT_MODE=1

INSTALLER_DIR="./installer"
HELP_DIR="./helpers"
MOD_DIR="./modules"
PYTHON_MOD_DIR="${MOD_DIR}/S28_python_run"
MOD_DIR_LOCAL="./modules_local"
CONF_DIR="./config"
EXT_DIR="./external"
REP_DIR="${CONF_DIR}/report_templates"

if [[ "${STRICT_MODE}" -eq 1 ]]; then
  # shellcheck source=./installer/wickStrictModeFail.sh
  source "${INSTALLER_DIR}"/wickStrictModeFail.sh
  export DEBUG_SCRIPT=0
  # shellcheck source=./helpers/helpers_emba_load_strict_settings.sh
  source "${HELP_DIR}"/helpers_emba_load_strict_settings.sh
  load_strict_mode_settings
  trap 'wickStrictModeFail $?' ERR  # The ERR trap is triggered when a script catches an error
fi

export GREEN='\033[0;32m'
export ORANGE='\033[0;33m'
export RED='\033[0;31m'
export BLUE='\033[0;34m'
export BOLD='\033[1m'
export NC='\033[0m' # no color

SOURCES=()
MODULES_TO_CHECK_ARR=()
MODULES_TO_CHECK_ARR_TAB=()
MODULES_TO_CHECK_ARR_SEMGREP=()
MODULES_TO_CHECK_ARR_DOCKER=()
MODULES_TO_CHECK_ARR_PYTHON=()
MODULES_TO_CHECK_ARR_PERM=()
MODULES_TO_CHECK_ARR_COMMENT=()
MODULES_TO_CHECK_ARR_GREP=()
MODULES_TO_CHECK_ARR_COPYRIGHT=()
MODULES_TO_CHECK_ARR_FCT_SPACE=()
CNT_VAR_CHECKER_ISSUES=0

import_config_scripts() {
  mapfile -t HELPERS < <(find "${CONF_DIR}" -iname "*.sh" 2>/dev/null)
  for LINE in "${HELPERS[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

import_helper() {
  mapfile -t HELPERS < <(find "${HELP_DIR}" -iname "*.sh" 2>/dev/null)
  for LINE in "${HELPERS[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

import_reporting_templates() {
  mapfile -t REP_TEMP < <(find "${REP_DIR}" -iname "*.sh" 2>/dev/null)
  for LINE in "${REP_TEMP[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

import_module() {
  MODULES=()
  mapfile -t MODULES < <(find "${MOD_DIR}" -iname "*.sh" 2>/dev/null)
  if [[ -d "${MOD_DIR_LOCAL}" ]]; then
    mapfile -t MODULES_LOCAL < <(find "${MOD_DIR_LOCAL}" -iname "*.sh" 2>/dev/null)
    MODULES=( "${MODULES_[@]}" "${MODULES_LOCAL[@]}")
  fi
  for LINE in "${MODULES[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

import_installer() {
  MODULES=()
  mapfile -t MODULES < <(find "${INSTALLER_DIR}" -iname "*.sh" 2>/dev/null)
  for LINE in "${MODULES[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

import_emba_main() {
  MODULES=()
  mapfile -t MODULES < <(find ./ -iname "emba" -o -iname "installer.sh" -o -iname "check_project.sh" 2>/dev/null)
  for LINE in "${MODULES[@]}"; do
    if (file "${LINE}" | grep -q "shell script"); then
      echo "${LINE}"
      SOURCES+=("${LINE}")
    fi
  done
}

dockerchecker() {
  echo -e "\\n""${ORANGE}""${BOLD}""EMBA docker-files check""${NC}"
  echo -e "${BOLD}""=================================================================""${NC}"
  mapfile -t DOCKER_COMPS < <(find . -maxdepth 1 -iname "docker-compose*.yml")
  for DOCKER_COMP in "${DOCKER_COMPS[@]}"; do
    echo -e "\\n""${GREEN}""Run docker check on ${DOCKER_COMP}:""${NC}""\\n"
    if docker compose -f "${DOCKER_COMP}" config 1>/dev/null || [[ $? -ne 1 ]]; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
      ((MODULES_TO_CHECK=MODULES_TO_CHECK+1))
      MODULES_TO_CHECK_ARR_DOCKER+=( "${DOCKER_COMP}" )
    fi
  done
}

pythoncheck() {
  echo -e "\\n""${ORANGE}""${BOLD}""EMBA Python modules check""${NC}"
  echo -e "${BOLD}""=================================================================""${NC}"
  PYTHON_MODULES=()
  mapfile -t PYTHON_MODULES < <(find "${PYTHON_MOD_DIR}" -iname "*.py" 2>/dev/null)
  for PYTHON_MODULE in "${PYTHON_MODULES[@]}"; do
    if (file "${PYTHON_MODULE}" | grep -q "Python script"); then
      echo -e "\\n""${GREEN}""Run Python check on ${PYTHON_MODULE}:""${NC}""\\n"
      PYTHON_ISSUE_FOUND=0
      flake8 "${PYTHON_MODULE}" || ((PYTHON_ISSUE_FOUND=PYTHON_ISSUE_FOUND+$?))
      pylint "${PYTHON_MODULE}" || ((PYTHON_ISSUE_FOUND=PYTHON_ISSUE_FOUND+$?))
      if [[ "${PYTHON_ISSUE_FOUND}" -eq 0 ]]; then
        echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
      else
        echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
        MODULES_TO_CHECK_ARR_PYTHON+=( "${PYTHON_MODULE}" )
      fi
    fi
  done
}

check() {
  echo -e "\\n""${ORANGE}""${BOLD}""Embedded Linux Analyzer Shellcheck""${NC}"
  echo -e "${BOLD}""=================================================================""${NC}"

  echo -e "\\n""${GREEN}""Load all files for check:""${NC}""\\n"

  import_emba_main
  import_installer
  import_helper
  import_config_scripts
  import_reporting_templates
  import_module

  echo -e "\\n""${GREEN}""Check all source for correct tab usage:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""${GREEN}""Run ${ORANGE}tab check${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    if [[ $(grep -cP '\t' "${SOURCE}") -eq 0 ]]; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_TAB+=("${SOURCE}")
    fi
  done

  echo -e "\\n""${GREEN}""Check all source for correct comment usage:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""${GREEN}""Run ${ORANGE}comment check${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    if [[ $(grep -E -r "^( )+?#" "${SOURCE}" | grep -v "#\ \|bash\|/bin/sh\|shellcheck" | grep -v -E -c "#$") -eq 0 ]]; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      grep -E -r -n "^( )+?#" "${SOURCE}" | grep -v "#\ \|bash\|shellcheck" | grep -v -E "#$"
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_COMMENT+=("${SOURCE}")
    fi
  done

  echo -e "\\n""${GREEN}""Check all source for correct space usage:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""${GREEN}""Run ${ORANGE}space check${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    if ! grep -q -E ' +$' "${SOURCE}"; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      grep -E -H -n ' +$' "${SOURCE}"
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_COMMENT+=("${SOURCE}")
    fi
  done

  echo -e "\\n""${GREEN}""Check all scripts for not using grep -R:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    [[ "${SOURCE}" == *"check_project.sh" ]] && continue
    echo -e "\\n""${GREEN}""Run ${ORANGE}recursive grep check${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"

    if [[ $(grep -cP "grep.* -R " "${SOURCE}") -eq 0 ]]; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_GREP+=("${SOURCE}")
    fi
  done

  echo -e "\\n""${GREEN}""Run shellcheck and semgrep:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""${GREEN}""Run ${ORANGE}shellcheck${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    if shellcheck -x -o require-variable-braces -P "${INSTALLER_DIR}":"${HELP_DIR}":"${MOD_DIR}":"${MOD_DIR_LOCAL}" "${SOURCE}" || [[ $? -ne 1 && $? -ne 2 ]]; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR+=("${SOURCE}")
    fi

    echo -e "\\n""${GREEN}""Run ${ORANGE}semgrep${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    semgrep --disable-version-check --metrics=off --config "${EXT_DIR}"/semgrep-rules/bash "${SOURCE}" | tee /tmp/emba_semgrep.log
    if grep -q "Findings:" /tmp/emba_semgrep.log; then
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_SEMGREP+=("${SOURCE}")
    else
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    fi
  done

  echo -e "\\n""${GREEN}""Check all scripts for correct permissions:""${NC}""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""${GREEN}""Check ${ORANGE}permission${GREEN} on ${ORANGE}${SOURCE}""${NC}""\\n"
    if stat -L -c "%a" "${SOURCE}" | grep -q "755"; then
      echo -e "${GREEN}""${BOLD}""==> SUCCESS""${NC}""\\n"
    else
      echo -e "\\n""${ORANGE}""${BOLD}""==> FIX ERRORS""${NC}""\\n"
      MODULES_TO_CHECK_ARR_PERM+=("${SOURCE}")
    fi
  done
}

summary() {
  if [[ -f /tmp/emba_semgrep.log ]]; then
    rm /tmp/emba_semgrep.log
  fi

  if [[ "${#MODULES_TO_CHECK_ARR_TAB[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (tab vs spaces): ${#MODULES_TO_CHECK_ARR_TAB[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_TAB[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi

  if [[ "${#MODULES_TO_CHECK_ARR_COMMENT[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (space after # sign): ${#MODULES_TO_CHECK_ARR_COMMENT[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_COMMENT[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi

  if [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (shellcheck): ${#MODULES_TO_CHECK_ARR[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi

  if [[ "${#MODULES_TO_CHECK_ARR_SEMGREP[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (semgrep): ${#MODULES_TO_CHECK_ARR_SEMGREP[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_SEMGREP[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi
  if [[ "${#MODULES_TO_CHECK_ARR_DOCKER[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (docker compose): ${#MODULES_TO_CHECK_ARR_DOCKER[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_DOCKER[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi
  if [[ "${#MODULES_TO_CHECK_ARR_PERM[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (permissions): ${#MODULES_TO_CHECK_ARR_PERM[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_PERM[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi
  if [[ "${#MODULES_TO_CHECK_ARR_GREP[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (recursive grep usage -R): ${#MODULES_TO_CHECK_ARR_GREP[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_GREP[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi
  if [[ "${#MODULES_TO_CHECK_ARR_FCT_SPACE[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Modules to check (space usage in function definition): ${#MODULES_TO_CHECK_ARR_FCT_SPACE[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR_FCT_SPACE[@]}"; do
      echo -e "${ORANGE}${BOLD}==> FIX MODULE: ""${MODULE}""${NC}"
    done
    echo -e "${ORANGE}""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi
  if [[ "${CNT_VAR_CHECKER_ISSUES}" -gt 0 ]]; then
    echo -e "\\n\\n""${GREEN}${BOLD}""SUMMARY:${NC}\\n"
    echo -e "Found ${ORANGE}${CNT_VAR_CHECKER_ISSUES}${NC} variable scope issues in EMBA scripts${NC}\\n"
    echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
  else
    echo -e "\\n""${GREEN}""==> Found no problems with variable scope definition""${NC}""\\n"
  fi
}

# check that all tools are installed
check_tools() {
  TOOLS=("semgrep" "shellcheck")
  for TOOL in "${TOOLS[@]}";do
    if ! command -v "${TOOL}" > /dev/null ; then
      echo -e "\\n""${RED}""${TOOL} is not installed correctly""${NC}""\\n"
      exit 1
    fi
  done
  if ! [[ -d ./external/semgrep-rules/bash ]]; then
    echo -e "\\n""${RED}""${BOLD}""Please install semgrep-rules to directory ./external to perform all checks""${NC}""\\n"
    echo -e "${ORANGE}git clone https://github.com/returntocorp/semgrep-rules.git external/semgrep-rules${NC}"
    exit 1
  fi

  if [[ ! -f "${HELP_DIR}"/var_check.sh ]]; then
    echo -e "\\n""${RED}""${BOLD}""EMBA var_checker helper script missing""${NC}""\\n"
    echo -e "\\n""${RED}""${BOLD}""Please fix the EMBA installation to perform all checks""${NC}""\\n"
    exit 1
  fi
}

list_linter_exceptions(){
  # lists all linter exceptions for a given toolname inside a directory
  # $1 tool name
  # $2 directory
  # $3 excluded dir for find
  local TOOL_NAME_="${1:-}"
  local DIR_="${2:-}"
  local EXCLUDE_="${3:-}"
  local SEARCH_PAR_=""
  local SEARCH_TYPE_=""
  echo -e "\\n""${GREEN}""Checking for ${TOOL_NAME_} exceptions inside ${DIR_}:""${NC}""\\n"
  case "${TOOL_NAME_}" in
    shellcheck)
      SEARCH_PAR_="shellcheck disable"
      SEARCH_TYPE_="sh"
      ;;
    semgrep)
      SEARCH_PAR_="nosemgrep"
      SEARCH_TYPE_="sh"
      ;;
  esac
  mapfile -t EXCEPTION_SCRIPTS < <(find "${DIR_}" -type d -path "${EXCLUDE_}" -prune -false -o -iname "*.${SEARCH_TYPE_}" -exec grep -H "${SEARCH_PAR_}" {} \;)
  if [[ "${#EXCEPTION_SCRIPTS[@]}" -gt 0 ]]; then
    for EXCEPTION_ in "${EXCEPTION_SCRIPTS[@]}"; do
      echo -e "${GREEN}Found exception in ${ORANGE}${EXCEPTION_%%:*}:${EXCEPTION_##*:}${NC}"
      EXCEPTIONS_TO_CHECK_ARR+=( "${EXCEPTION_%%:*}" )
    done
  else
    echo -e "\\n""${GREEN}""=> Found no exceptions for ${TOOL_NAME_}""${NC}""\\n"
  fi
}

copy_right_check(){
  # checks all Copyright occurences for supplied end-year
  # $1 copyright holder
  # $2 end-year
  # $3 dir to look in
  # $4 excluded dir for find
  local OWNER_="${1:-}"
  local YEAR_="${2:-}"
  local DIR_="${3:-}"
  local EXCLUDE_="${4:-}"
  echo -e "\\n""${ORANGE}""${BOLD}""EMBA Copyright check""${NC}""\\n""${BOLD}""=================================================================""${NC}"
  mapfile -t COPYRIGHT_LINE_ < <(find "${DIR_}" -type d -path "${EXCLUDE_}" -prune -false -o -type f -not -wholename "${0}" -iname "*.sh" -exec grep -H "Copyright" {} \;)
  if [[ "${#COPYRIGHT_LINE_[@]}" -gt 0 ]]; then
    for LINE_ in "${COPYRIGHT_LINE_[@]}"; do
      if [[ "${LINE_##*:}" == *"${OWNER_}" && "${LINE_##*:}" != *"${YEAR_}"* ]]; then
        MODULES_TO_CHECK_ARR_COPYRIGHT+=( "${LINE_%%:*}" )
        echo -e "Found problem with Copyright for ${GREEN}${OWNER_}${NC} in ${LINE_%%:*}: ${ORANGE}${LINE_##*:}""${NC}""\\n"
        echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
      fi
    done
  fi
  if [[ "${#MODULES_TO_CHECK_ARR_COPYRIGHT[@]}" -eq 0 ]]; then
    echo -e "\\n""${GREEN}""==> Found no problems with copyrights""${NC}""\\n"
  fi
}

function_entry_space_check() {
  # ensure we have the space in the function definition:
  # function_name() {
  # invalid:
  # function_name(){
  echo -e "\\n""${ORANGE}""${BOLD}""EMBA function space definition check""${NC}""\\n""${BOLD}""=================================================================""${NC}"

  mapfile -t FCT_SPACE_MODULES_ARR < <(grep -r '(){' modules/* || true)
  mapfile -t FCT_SPACE_HLP_ARR < <(grep -r '(){' helpers/* || true)

  if [[ "${#FCT_SPACE_MODULES_ARR[@]}" -gt 0 ]] || [[ "${#FCT_SPACE_HLP_ARR[@]}" -gt 0 ]]; then
    echo -e "Found problem with spaces in function definition${NC}\\n"
    echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
    MODULES_TO_CHECK_ARR_FCT_SPACE=("${FCT_SPACE_MODULES_ARR[@]}" "${FCT_SPACE_HLP_ARR[@]}")
  else
    echo -e "\\n""${GREEN}""==> Found no problems with spaces in function definition. Helpers are currently ignored.""${NC}""\\n"
  fi
}

var_checker() {
  local MODE="${1:-}"
  local RET_ISSUES=0

  echo -e "\\n""${ORANGE}""${BOLD}""EMBA variable declation scope check for ${MODE}""${NC}""\\n""${BOLD}""=================================================================""${NC}"

  disable_strict_mode 1
  "${HELP_DIR}"/var_check.sh "${MODE}"
  RET_ISSUES="$?"

  CNT_VAR_CHECKER_ISSUES=$((CNT_VAR_CHECKER_ISSUES+RET_ISSUES))

  if [[ "${CNT_VAR_CHECKER_ISSUES}" -gt 0 ]]; then
    echo -e "Found ${ORANGE}${CNT_VAR_CHECKER_ISSUES}${NC} variable scope issues in EMBA ${MODE} scripts${NC}\\n"
    echo -e "\\n""${ORANGE}${BOLD}==> FIX ERRORS""${NC}""\\n"
  else
    echo -e "\\n""${GREEN}""==> Found no problems with variable scope definition""${NC}""\\n"
  fi
  enable_strict_mode 1
}

# main:
check_tools
check
var_checker modules
var_checker helpers
function_entry_space_check
dockerchecker
pythoncheck
copy_right_check "Siemens Energy AG" 2025 ./ ./external
list_linter_exceptions shellcheck ./ ./external
list_linter_exceptions semgrep ./ ./external
summary

if [[ "${#MODULES_TO_CHECK_ARR_TAB[@]}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]] || \
  [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR_SEMGREP[@]}" -gt 0 ]] || \
  [[ "${#MODULES_TO_CHECK_ARR_DOCKER[@]}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR_PERM[@]}" -gt 0 ]] || \
  [[ "${#MODULES_TO_CHECK_ARR_COMMENT[@]}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR_GREP[@]}" -gt 0 ]] || \
  [[ "${#MODULES_TO_CHECK_ARR_COPYRIGHT[@]}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR_FCT_SPACE[@]}" -gt 0 ]] || \
  [[ "${CNT_VAR_CHECKER_ISSUES}" -gt 0 ]] || [[ "${#MODULES_TO_CHECK_ARR_PYTHON[@]}" -gt 0 ]]; then
  exit 1
fi
