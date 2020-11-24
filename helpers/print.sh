#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  All functions for colorizing terminal output and handling logging


## Color definition
RED="\033[0;31m"
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m"  # no color

## Attribute definition
BOLD="\033[1m"
ITALIC="\033[3m"

welcome()
{
  echo -e "\\n""$BOLD""╔═══════════════════════════════════════════════════════════════╗""$NC"
  echo -e "$BOLD""║""$BLUE""$BOLD""$ITALIC""                            e m b a                            ""$NC""$BOLD""║""$NC"
  echo -e "$BOLD""║                    EMBEDDED LINUX ANALYZER                    ""$NC""$BOLD""║""$NC"
  echo -e "$BOLD""╚═══════════════════════════════════════════════════════════════╝""$NC"
  echo -e "\\n""$RED""Warning: This script is in an early alpha state - use it on your own risk.""$NC"
}

module_log_init()
{
  local LOG_FILE_NAME
  LOG_FILE_NAME="$1"
  local FILE_NAME
  FILE_NAME=$(echo "$LOG_FILE_NAME" | sed -e 's/\(.*\)/\L\1/' | tr " " _ )
  LOG_FILE="$LOG_DIR""/""$FILE_NAME"".txt"
}

module_title()
{
  local MODULE_TITLE
  MODULE_TITLE="$1"
  local MODULE_TITLE_FORMAT
  MODULE_TITLE_FORMAT="[""${BLUE}""+""${NC}""] ""${CYAN}""${BOLD}""$MODULE_TITLE""${NC}""\\n""${BOLD}""=================================================================""${NC}"
  echo -e "\\n\\n""$MODULE_TITLE_FORMAT"
  if [[ "$2" != "no_log" ]] ; then
    echo -e "$(format_log "$MODULE_TITLE_FORMAT")" | tee -a "$LOG_FILE" >/dev/null
  fi
}

get_log_file()
{
  echo "$LOG_FILE"
}

sub_module_title()
{
  local SUB_MODULE_TITLE
  SUB_MODULE_TITLE="$1"
  local SUB_MODULE_TITLE_FORMAT
  SUB_MODULE_TITLE_FORMAT="\\n""${BLUE}""==>""${NC}"" ""${CYAN}""$SUB_MODULE_TITLE""${NC}""\\n-----------------------------------------------------------------"
  echo -e "$SUB_MODULE_TITLE_FORMAT"
  echo -e "$(format_log "$SUB_MODULE_TITLE_FORMAT")" | tee -a "$LOG_FILE" >/dev/null
}

print_output()
{
  local OUTPUT
  OUTPUT="$1"
  local TYPE_CHECK
  TYPE_CHECK="$( echo "$OUTPUT" | cut -c1-3 )"
  if [[ "$TYPE_CHECK" == "[-]" || "$TYPE_CHECK" == "[*]" || "$TYPE_CHECK" == "[!]" || "$TYPE_CHECK" == "[+]" ]] ; then
    local COLOR_OUTPUT_STRING
    COLOR_OUTPUT_STRING="$(color_output "$OUTPUT")"
    echo -e "$COLOR_OUTPUT_STRING"
    if [[ "$2" != "no_log" ]] ; then
      echo -e "$(format_log "$COLOR_OUTPUT_STRING")" | tee -a "$LOG_FILE" >/dev/null
    fi
  else
    echo -e "$OUTPUT"
    if [[ "$2" != "no_log" ]] ; then
      echo -e "$(format_log "$OUTPUT")" | tee -a "$LOG_FILE" >/dev/null
    fi
  fi
}

write_log()
{
  readarray TEXT_ARR <<< "$1"

  for E in "${TEXT_ARR[@]}" ; do
    local TYPE_CHECK
    TYPE_CHECK="$( echo "$E" | cut -c1-3 )"
    if [[ "$TYPE_CHECK" == "[-]" || "$TYPE_CHECK" == "[*]" || "$TYPE_CHECK" == "[!]" || "$TYPE_CHECK" == "[+]" ]] ; then
      local COLOR_OUTPUT_STRING
      COLOR_OUTPUT_STRING="$(color_output "$E")"
      echo -e "$(format_log "$COLOR_OUTPUT_STRING")" | tee -a "$LOG_FILE" >/dev/null
    else
      echo -e "$(format_log "$E")" | tee -a "$LOG_FILE" >/dev/null
    fi
  done
}

warning()
{
  echo -e "\\n[""$RED""-""$NC""] ""$ORANGE""$1""$NC"
}

color_output()
{
  local TEXT
  readarray TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    local TYPE_CHECK
    TYPE_CHECK="$( echo "$E" | cut -c1-3 )"
    if [[ "$TYPE_CHECK" == "[-]" || "$TYPE_CHECK" == "[*]" || "$TYPE_CHECK" == "[!]" || "$TYPE_CHECK" == "[+]" ]] ; then
      local STR
      STR="$( echo "$E" | cut -c 4- )"
      if [[ "$TYPE_CHECK" == "[-]" ]] ; then
        TEXT="$TEXT""[""$RED""-""$NC""]""$STR"
      elif [[ "$TYPE_CHECK" == "[*]" ]] ; then
        TEXT="$TEXT""[""$ORANGE""*""$NC""]""$STR"
      elif [[ "$TYPE_CHECK" == "[!]" ]] ; then
        TEXT="$TEXT""[""$MAGENTA""!""$NC""]""$MAGENTA""$STR""$NC"
      elif [[ "$TYPE_CHECK" == "[+]" ]] ; then
        TEXT="$TEXT""[""$GREEN""+""$NC""]""$GREEN""$STR""$NC"
      else
        TEXT="$TEXT""$E"
      fi
    else
      TEXT="$TEXT""$E"
    fi
  done
  echo "$TEXT"
}

white()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$NC""$E""\\n"
  done
  echo -e "$TEXT"
}

red()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$RED""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

green()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$GREEN""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

blue()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$BLUE""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

cyan()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$CYAN""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

magenta()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$MAGENTA""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

orange()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$ORANGE""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

bold()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$BOLD""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

italic()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""$ITALIC""$E""$NC""\\n"
  done
  echo -e "$TEXT"
}

indent()
{
  local TEXT
  readarray -t TEXT_ARR <<< "$1"
  for E in "${TEXT_ARR[@]}" ; do
    TEXT="$TEXT""    ""$E""\\n"
  done
  echo -e "$TEXT"
}

format_log()
{
  if [[ $FORMAT_LOG -eq 1 ]] ; then
    echo "$1"
  else
    echo "$1" | sed -r "s/\\\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" \
      | sed -r "s/\[([0-9]{1,2}(;[0-9]{1,2}(;[0-9]{1,2})?)?)?[m|K]//g" \
      | sed -e "s/\\\\n/\\n/g"
  fi
}


print_help()
{
  ## help and command line parsing

  echo -e "\\n""$CYAN""USAGE""$NC"
  echo -e "\\nTest firmware / live system"
  echo -e "$CYAN""-a [MIPS]""$NC""         Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC]"
  echo -e "$CYAN""-A [MIPS]""$NC""         Force Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (disable architecture check)"
  echo -e "$CYAN""-l [./path]""$NC""       Log path"
  echo -e "$CYAN""-f [./path]""$NC""       Firmware path"
  echo -e "$CYAN""-e [./path]""$NC""       Exclude paths from testing (multiple usage possible)"
  echo -e "$CYAN""-m [MODULE_NO.]""$NC""   Test only with set modules [e.g. -m 05 -m 10 ... ]] (multiple usage possible)"
  echo -e "$CYAN""-c""$NC""                Enable cwe-checker"
  echo -e "\\nDependency check"
  echo -e "$CYAN""-d""$NC""                Only check dependencies"
  echo -e "$CYAN""-F""$NC""                Check dependencies but ignore errors"
  echo -e "\\nTest kernel config"
  echo -e "$CYAN""-k [./config]""$NC""     Kernel config path"
  echo -e "\\nModify output"
  echo -e "$CYAN""-s""$NC""                Print only relative paths"
  echo -e "$CYAN""-z""$NC""                Add ANSI color codes to log"
  echo -e "\\nHelp"
  echo -e "$CYAN""-h""$NC""                Print this help message"


  echo -e "\\n""$RED""Warning: This script is in an early alpha state - use it on your own risk ...""$NC"
  echo -e "$RED""Hint: Look into the readme to get some examples for using emba""$NC\\n"
}

print_etc()
{
  if [[ ${#ETC_PATHS[@]} -gt 1 ]] ; then
    echo
    print_output "[*] Found more paths for etc (these are automatically taken into account):" "no_log"
    for ETC in "${ETC_PATHS[@]}" ; do
      if [[ "$ETC" != "$FIRMWARE_PATH""/etc" ]] ; then
        print_output "$(indent "$(orange "$(print_path "$ETC")")")" "no_log"
      fi
    done
  fi
}

print_excluded()
{
  readarray -t EXCLUDE_PATHS_ARR < <(printf '%s' "$EXCLUDE_PATHS")
  if [[ ${#EXCLUDE_PATHS_ARR[@]} -gt 0 ]] ; then
    echo
    print_output "[*] Excluded: " "no_log"
    for EXCL in "${EXCLUDE_PATHS_ARR[@]}" ; do
      print_output ".""$(indent "$(orange "$(print_path "$EXCL")")")" "no_log"
    done
    echo
  fi
}
