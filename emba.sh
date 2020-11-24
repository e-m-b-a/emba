#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# Emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Main script for load all necessary files and call main function of modules


import_helper()
{
  local HELPERS
  HELPERS=$(find "$HELP_DIR" -iname "*.sh" 2> /dev/null)
  local HELPERS_COUNT
  HELPERS_COUNT=$(echo "$HELPERS" | wc -l)
  for HELPER_FILE in $HELPERS ; do
    if ( file "$HELPER_FILE" | grep -q "shell script" ) ; then
      # https://github.com/koalaman/shellcheck/wiki/SC1090
      # shellcheck source=/dev/null
      source "$HELPER_FILE"
    fi
  done
  print_output "==> ""$GREEN""Imported ""$HELPERS_COUNT"" necessary files""$NC" "no_log"
}

import_module()
{
  local MODULES
  MODULES=$(find "$MOD_DIR" -iname "*.sh" 2> /dev/null)
  local MODULES_COUNT
  MODULES_COUNT=$(echo "$MODULES" | wc -l)
  for MODULE_FILE in $MODULES ; do
    if ( file "$MODULE_FILE" | grep -q "shell script" ) ; then
      # https://github.com/koalaman/shellcheck/wiki/SC1090
      # shellcheck source=/dev/null
      source "$MODULE_FILE"
    fi
  done
  print_output "==> ""$GREEN""Imported ""$MODULES_COUNT"" module/s""$NC" "no_log"
}

main()
{

  set -a 

  export ARCH_CHECK=1
  export FORMAT_LOG=0
  export FIRMWARE=0
  export KERNEL=0
  export SHELLCHECK=1
  export V_FEED=1
  export BAP=0
  export YARA=1
  export SHORT_PATH=0           # short paths in cli output
  export ONLY_DEP=0             # test only dependency
  export FORCE=0
  export HTML=0
  export GHIDRA=1

  export LOG_DIR="./logs"
  export CONFIG_DIR="./config"
  export EXT_DIR="./external"
  export HELP_DIR="./helpers"
  export MOD_DIR="./modules"
  export VUL_FEED_DB="$EXT_DIR""/allitems.csv"
  export BASE_LINUX_FILES="$CONFIG_DIR""/linux_common_files.txt"
  export HTML_PATH="./html/html-files"         # directory for html path
  export HTML_DIR="./html"                     # directory for css and pictures
  export AHA_PATH="$EXT_DIR""/aha-master/aha"

  echo

  import_helper
  import_module

  welcome

  if [[ $# -eq 0 ]]; then
    print_help
    exit 1
  fi
  
  export EMBACOMMAND="sudo ""$(dirname "$0")""/emba.sh ""$*"

  while getopts a:A:cde:f:Fhk:l:mW:n:gpsvz OPT ; do
    case $OPT in
      a)
        export ARCH="$OPTARG"
        ;;
      A)
        export ARCH="$OPTARG"
        export ARCH_CHECK=0
        ;;
      c)
        export BAP=1
        ;;
      d)
        export ONLY_DEP=1
        export BAP=1
        ;;
      e)
        export EXCLUDE=("${EXCLUDE[@]}" "$OPTARG")
        ;;
      f)
        export FIRMWARE=1
        export FIRMWARE_PATH="$OPTARG"
        ;;
      F)
        export FORCE=1
        ;;
      g)
        export GHIDRA=1
        ;;
      h)
        print_help
        exit 0
        ;;
      k)
        export KERNEL=1
        export KERNEL_CONFIG="$OPTARG"
        ;;
      l)
        export LOG_DIR="$OPTARG"
        ;;
      m)
        SELECT_MODULES=("${SELECT_MODULES[@]}" "$OPTARG")
        ;;
      n)
        export HTML_HEADLINE="$OPTARG"
        ;;
      s)
        export SHORT_PATH=1
        ;;
      W)
        export HTML=1
        ARG_ARRAY=($OPTARG)
        export HTML_PATH="${ARG_ARRAY[0]}"
        export HTML_HEADLINE="${ARG_ARRAY[1]}"
        ;;
      z)
        export FORMAT_LOG=1
        ;;
      *)
        print_output "[-] Invalid option" "no_log"
        print_help
        exit 1
        ;;
    esac
  done
  LOG_DIR="$(abs_path "$LOG_DIR")"
  HTML_PATH="$(abs_path "$HTML_PATH")"
  HTML_STYLE_PATH="$(abs_path "./html")"

  if [[ $KERNEL -eq 1 ]] ; then
    LOG_DIR="$LOG_DIR""/""$(basename "$KERNEL_CONFIG")"
  fi

  FIRMWARE_PATH="$(abs_path "$FIRMWARE_PATH")"

  if [[ $ONLY_DEP -eq 0 ]] ; then
    # check if LOG_DIR and HTML_PATH exists and prompt to terminal to delete its content (y/n)
    log_folder
    html_folder

    set_exclude

    if [[ $KERNEL -eq 0 ]] ; then
      architecture_check
    fi
  fi

  dependency_check

  if [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]] ; then
    if ! [[ -f "$KERNEL_CONFIG" ]] ; then
      print_output "[-] Invalid kernel configuration file: $KERNEL_CONFIG" "no_log"
      exit 1
    else
      if ! [[ -d "$LOG_DIR" ]] ; then
        mkdir -p "$LOG_DIR" 2> /dev/null
      fi
      S25_kernel_check
    fi
  fi
 
  if [[ $FIRMWARE -eq 1 ]] ; then
    if [[ -d "$FIRMWARE_PATH" ]]; then

      check_firmware

      prepare_binary_arr
      set_etc_paths
      echo

      print_output "[!] Test started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "no_log"

      # 'main' functions of imported modules

      if [[ ${#SELECT_MODULES[@]} -eq 0 ]] ; then
        local MODULES
        MODULES=$(find "$MOD_DIR" -name "S*_*.sh" | sort -V 2> /dev/null)
        for MODULE_FILE in $MODULES ; do
          if ( file "$MODULE_FILE" | grep -q "shell script" ) ; then
            MODULE_BN=$(basename "$MODULE_FILE")
            MODULE_MAIN=${MODULE_BN%.*}
            $MODULE_MAIN
          fi
        done
      else
        for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
          local MODULE
          MODULE=$(find "$MOD_DIR" -name "S""$SELECT_NUM""_*.sh" | sort -V 2> /dev/null)
          if ( file "$MODULE" | grep -q "shell script" ) ; then
            MODULE_BN=$(basename "$MODULE")
            MODULE_MAIN=${MODULE_BN%.*}
            $MODULE_MAIN
          fi
        done
      fi
      # Add your personal checks to X150_user_checks.sh (change starting 'X' in filename to 'S') or write a new module, add it to ./modules

      echo
      DURATIONTIME="$(date -d@$SECONDS -u +%H:%M:%S)"
      print_output "[!] Test ended on ""$(date)"" and took about ""$DURATIONTIME"" \\n" "no_log"

    else
      print_output "\\n" "no_log"
      print_output "[!] No extracted firmware found" "no_log"
      print_output "$(indent "Try using binwalk or something else to extract the Linux operating system")" "no_log"

      exit 1
    fi
  fi

  exit 1

}

main "$@"
