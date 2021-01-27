#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Main script for load all necessary files and call main function of modules

INVOCATION_PATH="."

import_helper()
{
  local HELPERS
  local HELPER_COUNT
  mapfile -d '' HELPERS < <(find "$HELP_DIR" -iname "*.sh" -print0 2> /dev/null)
  for HELPER_FILE in "${HELPERS[@]}" ; do
    if ( file "$HELPER_FILE" | grep -q "shell script" ) && ! [[ "$HELPER_FILE" =~ \ |\' ]] ; then
      # https://github.com/koalaman/shellcheck/wiki/SC1090
      # shellcheck source=/dev/null
      source "$HELPER_FILE"
      (( HELPER_COUNT+=1 ))
    fi
  done
  print_output "==> ""$GREEN""Imported ""$HELPER_COUNT"" necessary files""$NC" "no_log"
}

import_module()
{
  local MODULES
  local MODULE_COUNT
  mapfile -t MODULES < <(find "$MOD_DIR" -name "*.sh" | sort -V 2> /dev/null)
  for MODULE_FILE in "${MODULES[@]}" ; do
    if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
      # https://github.com/koalaman/shellcheck/wiki/SC1090
      # shellcheck source=/dev/null
      source "$MODULE_FILE"
      (( MODULE_COUNT+=1 ))
    fi
  done
  print_output "==> ""$GREEN""Imported ""$MODULE_COUNT"" module/s""$NC" "no_log"
}

main()
{
  INVOCATION_PATH="$(dirname "$0")"

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
  export DOCKER=0
  export IGNORE_LOG_DEL=0
  export FORCE=0
  export LOG_GREP=0
  export QEMULATION=0
  export PRE_CHECK=0            # test and extract binary files with binwalk
                                # afterwards do a default emba scan

  export LOG_DIR="$INVOCATION_PATH""/logs"
  export CONFIG_DIR="$INVOCATION_PATH""/config"
  export EXT_DIR="$INVOCATION_PATH""/external"
  export HELP_DIR="$INVOCATION_PATH""/helpers"
  export MOD_DIR="$INVOCATION_PATH""/modules"
  export VUL_FEED_DB="$EXT_DIR""/allitems.csv"
  export VUL_FEED_CVSS_DB="$EXT_DIR""/allitemscvss.csv"
  export BASE_LINUX_FILES="$CONFIG_DIR""/linux_common_files.txt"

  echo

  import_helper
  import_module

  welcome

  if [[ $# -eq 0 ]]; then
    print_help
    exit 1
  fi

  EMBACOMMAND="$(dirname "$0")""/emba.sh ""$*"
  export EMBACOMMAND

  while getopts a:A:cdDe:Ef:Fghik:l:m:N:sX:Y:zZ: OPT ; do
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
      D)
        export DOCKER=1
        ;;
      e)
        export EXCLUDE=("${EXCLUDE[@]}" "$OPTARG")
        ;;
      E)
        export QEMULATION=1
        ;;
      f)
        export FIRMWARE=1
        export FIRMWARE_PATH="$OPTARG"
        ;;
      F)
        export FORCE=1
        ;;
      g)
        export LOG_GREP=1
        ;;
      h)
        print_help
        exit 0
        ;;
      i)
        export IGNORE_LOG_DEL=1
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
      N)
        export FW_NOTES="$OPTARG"
        ;;
      s)
        export SHORT_PATH=1
        ;;
      X)
        export FW_VERSION="$OPTARG"
        ;;
      Y)
        export FW_VENDOR="$OPTARG"
        ;;
      z)
        export FORMAT_LOG=1
        ;;
      Z)
        export FW_DEVICE="$OPTARG"
        ;;
      *)
        print_output "[-] Invalid option" "no_log"
        print_help
        exit 1
        ;;
    esac
  done

  LOG_DIR="$(abs_path "$LOG_DIR")"
  print_output "" "no_log"

  if [[ -n "$FW_VENDOR" || -n "$FW_VERSION" || -n "$FW_DEVICE" || -n "$FW_NOTES" ]]; then
    print_output "\\n-----------------------------------------------------------------\\n" "no_log"

    if [[ -n "$FW_VENDOR" ]]; then
      print_output "[*] Testing Firmware from vendor: ""$ORANGE""""$FW_VENDOR""""$NC""" "no_log"
    fi
    if [[ -n "$FW_VERSION" ]]; then
      print_output "[*] Testing Firmware version: ""$ORANGE""""$FW_VERSION""""$NC""" "no_log"
    fi
    if [[ -n "$FW_DEVICE" ]]; then
      print_output "[*] Testing Firmware from device: ""$ORANGE""""$FW_DEVICE""""$NC""" "no_log"
    fi
    if [[ -n "$FW_NOTES" ]]; then
      print_output "[*] Additional notes: ""$ORANGE""""$FW_NOTES""""$NC""" "no_log"
    fi

    print_output "\\n-----------------------------------------------------------------\\n" "no_log"
  fi

  if [[ $KERNEL -eq 1 ]] ; then
    LOG_DIR="$LOG_DIR""/""$(basename "$KERNEL_CONFIG")"
  fi

  FIRMWARE_PATH="$(abs_path "$FIRMWARE_PATH")"

  echo
  if [[ -d "$FIRMWARE_PATH" ]]; then
    PRE_CHECK=0
    print_output "[*] Firmware directory detected." "no_log"
    print_output "[*] Emba starts with testing the environment." "no_log"
  elif [[ -f "$FIRMWARE_PATH" ]]; then
    PRE_CHECK=1
    print_output "[*] Firmware binary detected." "no_log"
    print_output "[*] Emba starts with the pre-testing phase." "no_log"
  else
    print_output "[-] Invalid firmware file" "no_log"
    print_help
    exit 1
  fi

  if [[ $ONLY_DEP -eq 0 ]] ; then
    if [[ $IGNORE_LOG_DEL -eq 0 ]] ; then
      # check if LOG_DIR exists and prompt to terminal to delete its content (y/n)
      log_folder
    fi

    if [[ $LOG_GREP -eq 1 ]] ; then
      create_grep_log
      write_grep_log "sudo ""$INVOCATION_PATH""/emba.sh ""$*" "COMMAND"
    fi

    set_exclude
  fi


  dependency_check

  if [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]] ; then
    if ! [[ -f "$KERNEL_CONFIG" ]] ; then
      print_output "[-] Invalid kernel configuration file: $KERNEL_CONFIG" "no_log"
      exit 1
    else
      if ! [[ -d "$LOG_DIR" ]] ; then
        mkdir -p "$LOG_DIR" 2> /dev/null
        chmod 777 "$LOG_DIR" 2> /dev/null
      fi
      S25_kernel_check
    fi
  fi

  if [[ $PRE_CHECK -eq 1 ]] ; then
    if [[ -f "$FIRMWARE_PATH" ]]; then
    
      # we have to fix this, so that also the pre-checker modules are running inside the docker
      if [[ $DOCKER -eq 1 ]] ; then
        print_output "" "no_log"
        print_output "[!] Running pre checker modules outside of the docker environment for preparation" "no_log"
      fi
      
      echo
      print_output "[!] Extraction started on ""$(date)""\\n""$(indent "$NC""Firmware binary path: ""$FIRMWARE_PATH")" "no_log"

      # 'main' functions of imported modules
      # in the pre-check phase we execute all modules with P[Number]_Name.sh

      if [[ ${#SELECT_MODULES[@]} -eq 0 ]] ; then
        local MODULES
        mapfile -t MODULES < <(find "$MOD_DIR" -name "P*_*.sh" | sort -V 2> /dev/null)
        for MODULE_FILE in "${MODULES[@]}" ; do
          if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
            MODULE_BN=$(basename "$MODULE_FILE")
            MODULE_MAIN=${MODULE_BN%.*}
            $MODULE_MAIN
          fi
        done
      else
        for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
          if [[ "$SELECT_NUM" =~ ^[p,P]{1}[0-9]+ ]]; then
            local MODULE
            MODULE=$(find "$MOD_DIR" -name "P""${SELECT_NUM:1}""_*.sh" | sort -V 2> /dev/null)
            if ( file "$MODULE" | grep -q "shell script" ) && ! [[ "$MODULE" =~ \ |\' ]] ; then
              MODULE_BN=$(basename "$MODULE")
              MODULE_MAIN=${MODULE_BN%.*}
              $MODULE_MAIN
            fi
          fi
        done

        echo
        print_output "[!] Extraction ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
      fi
    fi
  fi
  
  if [[ $DOCKER -eq 1 ]] ; then
    if ! command -v docker-compose > /dev/null ; then
      print_output "[!] No docker-compose found" "no_log"
      print_output "$(indent "Install docker-compose via apt-get install docker-compose to use emba with docker")" "no_log"
      exit 1
    fi

    OPTIND=1
    ARGS=""
    while getopts a:A:cdDe:Ef:Fghik:l:m:sz OPT ; do
      case $OPT in
        D|f|i|l)
          ;;
        *)
          export ARGS="$ARGS -$OPT"
          ;;
      esac
    done

    print_output "" "no_log"
    print_output "[!] Emba initializes kali docker container.\\n" "no_log"

    FIRMWARE="$FIRMWARE_PATH" LOG="$LOG_DIR" docker-compose run emba -c "./emba.sh -l /log/ -f /firmware/ -i $ARGS"

    print_output "[*] Emba finished analysis in docker container.\\n" "no_log"
    print_output "[*] Firmware tested: $FIRMWARE_PATH" "no_log"
    print_output "[*] Log directory: $LOG_DIR" "no_log"
    exit
  fi

  if [[ $FIRMWARE -eq 1 ]] ; then
    if [[ -d "$FIRMWARE_PATH" ]]; then

      echo
      print_output "=================================================================\n" "no_log"

      if [[ $KERNEL -eq 0 ]] ; then
        architecture_check
        architecture_dep_check
      fi

      check_firmware

      prepare_binary_arr
      set_etc_paths
      echo

      print_output "[!] Test started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "no_log"
      write_grep_log "$(date)" "TIMESTAMP"

      # 'main' functions of imported modules

      if [[ ${#SELECT_MODULES[@]} -eq 0 ]] ; then
        local MODULES
        mapfile -t MODULES < <(find "$MOD_DIR" -name "S*_*.sh" | sort -V 2> /dev/null)
        for MODULE_FILE in "${MODULES[@]}" ; do
          if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
            MODULE_BN=$(basename "$MODULE_FILE")
            MODULE_MAIN=${MODULE_BN%.*}
            $MODULE_MAIN
            reset_module_count
          fi
        done
      else
        for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
          if [[ "$SELECT_NUM" =~ ^[s,S]{1}[0-9]+ ]]; then
            local MODULE
            MODULE=$(find "$MOD_DIR" -name "S""${SELECT_NUM:1}""_*.sh" | sort -V 2> /dev/null)
            if ( file "$MODULE" | grep -q "shell script" ) && ! [[ "$MODULE" =~ \ |\' ]] ; then
              MODULE_BN=$(basename "$MODULE")
              MODULE_MAIN=${MODULE_BN%.*}
              $MODULE_MAIN
            fi
          fi
        done
      fi

      # Add your personal checks to X150_user_checks.sh (change starting 'X' in filename to 'S') or write a new module, add it to ./modules
      TESTING_DONE=1
    fi
  fi

  # 'main' functions of imported finishing modules
  local MODULES
  mapfile -t MODULES < <(find "$MOD_DIR" -name "F*_*.sh" | sort -V 2> /dev/null)
  for MODULE_FILE in "${MODULES[@]}" ; do
    if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
      MODULE_BN=$(basename "$MODULE_FILE")
      MODULE_MAIN=${MODULE_BN%.*}
      $MODULE_MAIN
      reset_module_count
    fi
  done

  if [[ "$TESTING_DONE" -eq 1 ]]; then
      echo
      print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n"
      write_grep_log "$(date)" "TIMESTAMP"
      write_grep_log "$(date -d@$SECONDS -u +%H:%M:%S)" "DURATION"
  else
      print_output "[!] No extracted firmware found" "no_log"
      print_output "$(indent "Try using binwalk or something else to extract the Linux operating system")"
      exit 1
  fi
}

main "$@"
