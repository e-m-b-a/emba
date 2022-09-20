#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check all shell scripts inside ./helpers, ./modules, emba.sh and itself with shellchecker

STRICT_MODE=1

if [[ "$STRICT_MODE" -eq 1 ]]; then
  # shellcheck disable=SC1091
  source ./installer/wickStrictModeFail.sh
  # http://redsymbol.net/articles/unofficial-bash-strict-mode/
  # https://github.com/tests-always-included/wick/blob/master/doc/bash-strict-mode.md
  set -e          # Exit immediately if a command exits with a non-zero status
  set -u          # Exit and trigger the ERR trap when accessing an unset variable
  set -o pipefail # The return value of a pipeline is the value of the last (rightmost) command to exit with a non-zero status
  set -E          # The ERR trap is inherited by shell functions, command substitutions and commands in subshells
  shopt -s extdebug # Enable extended debugging
  IFS=$'\n\t'     # Set the "internal field separator"
  trap 'wickStrictModeFail $?' ERR  # The ERR trap is triggered when a script catches an error
fi

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # no color

INSTALLER_DIR="./installer"
HELP_DIR="./helpers"
MOD_DIR="./modules"
MOD_DIR_LOCAL="./modules_local"
CONF_DIR="./config"
EXT_DIR="./external"
REP_DIR="$CONF_DIR/report_templates"

SOURCES=()
MODULES_TO_CHECK_ARR=()
MODULES_TO_CHECK_ARR_SEMGREP=()

import_config_scripts() {
  mapfile -t HELPERS < <(find "$CONF_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in "${HELPERS[@]}"; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

import_helper() {
  mapfile -t HELPERS < <(find "$HELP_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in "${HELPERS[@]}"; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

import_reporting_templates() {
  mapfile -t REP_TEMP < <(find "$REP_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in "${REP_TEMP[@]}"; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

import_module() {
  MODULES=()
  mapfile -t MODULES < <(find "$MOD_DIR" -iname "*.sh" 2>/dev/null)
  if [[ -d "$MOD_DIR_LOCAL" ]]; then
    mapfile -t MODULES_LOCAL < <(find "$MOD_DIR_LOCAL" -iname "*.sh" 2>/dev/null)
    MODULES=( "${MODULES_[@]}" "${MODULES_LOCAL[@]}")
  fi
  for LINE in "${MODULES[@]}"; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

import_installer() {
  MODULES=()
  mapfile -t MODULES < <(find "$INSTALLER_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in "${MODULES[@]}"; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}


check()
{
  echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Shellcheck""$NC""\\n""$BOLD""=================================================================""$NC"

  echo -e "\\n""$GREEN""Run shellcheck on this script:""$NC""\\n"
  if shellcheck ./check_project.sh || [[ $? -ne 1 && $? -ne 2 ]]; then
    echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
  else
    echo -e "\\n""$ORANGE$BOLD==> FIX ERRORS""$NC""\\n"
    MODULES_TO_CHECK_ARR+=("check_project.sh")
  fi

  echo -e "\\n""$GREEN""Run shellcheck on installer:""$NC""\\n"
  if shellcheck ./installer.sh || [[ $? -ne 1 && $? -ne 2 ]]; then
    echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
  else
    echo -e "\\n""$ORANGE$BOLD==> FIX ERRORS""$NC""\\n"
    MODULES_TO_CHECK_ARR+=("installer.sh")
  fi

  echo -e "\\n""$GREEN""Load all files for check:""$NC""\\n"
  echo "./emba.sh"
  import_installer
  import_helper
  import_config_scripts
  import_reporting_templates
  import_module

  echo -e "\\n""$GREEN""Run shellcheck and semgrep:""$NC""\\n"
  for SOURCE in "${SOURCES[@]}"; do
    echo -e "\\n""$GREEN""Run ${ORANGE}shellcheck$GREEN on $ORANGE$SOURCE""$NC""\\n"
    if shellcheck -P "$HELP_DIR":"$MOD_DIR":"$MOD_DIR_LOCAL" -a ./emba.sh "$SOURCE" || [[ $? -ne 1 && $? -ne 2 ]]; then
      echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
    else
      echo -e "\\n""$ORANGE""$BOLD""==> FIX ERRORS""$NC""\\n"
      MODULES_TO_CHECK_ARR+=("$SOURCE")
    fi

    echo -e "\\n""$GREEN""Run ${ORANGE}semgrep$GREEN on $ORANGE$SOURCE""$NC""\\n"
    semgrep --disable-version-check --config "$EXT_DIR"/semgrep-rules/bash "$SOURCE" | tee /tmp/emba_semgrep.log
    if grep -q "Findings:" /tmp/emba_semgrep.log; then
      echo -e "\\n""$ORANGE""$BOLD""==> FIX ERRORS""$NC""\\n"
      MODULES_TO_CHECK_ARR_SEMGREP+=("$SOURCE")
    else
      echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
    fi
  done
}

summary() {
  if [[ -f /tmp/emba_semgrep.log ]]; then
    rm /tmp/emba_semgrep.log
  fi

  if [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""$GREEN$BOLD""SUMMARY:$NC\\n"
    echo -e "Modules to check (shellcheck): ${#MODULES_TO_CHECK_ARR[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR[@]}"; do
      echo -e "$ORANGE$BOLD==> FIX MODULE: ""$MODULE""$NC"
    done
    echo -e "$ORANGE""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi

  if [[ "${#MODULES_TO_CHECK_ARR_SEMGREP[@]}" -gt 0 ]]; then
    echo -e "\\n\\n""$GREEN$BOLD""SUMMARY:$NC\\n"
    echo -e "Modules to check (semgrep): ${#MODULES_TO_CHECK_ARR_SEMGREP[@]}\\n"
    for MODULE in "${MODULES_TO_CHECK_ARR[@]}"; do
      echo -e "$ORANGE$BOLD==> FIX MODULE: ""$MODULE""$NC"
    done
    echo -e "$ORANGE""WARNING: Fix the errors before pushing to the EMBA repository!"
  fi

}

# check that all tools are installed
check_tools(){
  TOOLS=("semgrep" "shellcheck")
  for TOOL in "${TOOLS[@]}";do
    if ! command -v "$TOOL" > /dev/null ; then
      echo -e "\\n""$RED""$TOOL is not installed correctly""$NC""\\n"
      exit 1
    fi
  done
  if ! [[ -d ./external/semgrep-rules/bash ]]; then
    echo -e "\\n""$RED""$BOLD""Please install semgrep-rules to directory ./external to perform all checks""$NC""\\n"
    exit 1
  fi
}

# main:
check_tools
check
summary

