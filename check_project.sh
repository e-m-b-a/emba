#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check all shell scripts inside ./helpers, ./modules, emba.sh and itself with shellchecker

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m' # no color

HELP_DIR="./helpers"
MOD_DIR="./modules"

SOURCES=()

import_helper() {
  HELPERS=$(find "$HELP_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in $HELPERS; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

import_module() {
  MODULES=$(find "$MOD_DIR" -iname "*.sh" 2>/dev/null)
  for LINE in $MODULES; do
    if (file "$LINE" | grep -q "shell script"); then
      echo "$LINE"
      SOURCES+=("$LINE")
    fi
  done
}

check()
{
  echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Shellcheck""$NC""\\n""$BOLD""=================================================================""$NC"
  if ! command -v shellcheck >/dev/null 2>&1; then
    echo -e "\\n""$ORANGE""Shellcheck not found!""$NC""\\n""$ORANGE""Install shellcheck via 'apt-get install shellcheck'!""$NC\\n"
    exit 1
  fi

  echo -e "\\n""$GREEN""Run shellcheck on this script:""$NC""\\n"
  if shellcheck ./check_project.sh || [[ $? -ne 1 && $? -ne 2 ]]; then
    echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
  else
    echo -e "\\n""$ORANGE$BOLD==> FIX ERRORS""$NC""\\n"
  fi

  echo -e "\\n""$GREEN""Run shellcheck on installer:""$NC""\\n"
  if shellcheck ./installer.sh || [[ $? -ne 1 && $? -ne 2 ]]; then
    echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
  else
    echo -e "\\n""$ORANGE$BOLD==> FIX ERRORS""$NC""\\n"
  fi

  echo -e "\\n""$GREEN""Load all files for check:""$NC""\\n"
  echo "./emba.sh"
  import_helper
  import_module

  echo -e "\\n""$GREEN""Run shellcheck:""$NC""\\n"
  if shellcheck -P "$HELP_DIR":"$MOD_DIR" -a ./emba.sh "${SOURCES[@]}" || [[ $? -ne 1 && $? -ne 2 ]]; then
    echo -e "$GREEN""$BOLD""==> SUCCESS""$NC""\\n"
  else
    echo -e "\\n""$ORANGE""$BOLD""==> FIX ERRORS""$NC""\\n"
  fi
}

check
