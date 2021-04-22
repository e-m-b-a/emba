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
# Contributor(s): Stefan Haboeck

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

sort_modules()
{
  local SORTED_MODULES
  for MODULE_FILE in "${MODULES[@]}" ; do
    if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
      THREAD_PRIO=0
      # https://github.com/koalaman/shellcheck/wiki/SC1090
      # shellcheck source=/dev/null
      source "$MODULE_FILE"
      if [[ $THREAD_PRIO -eq 1 ]] ; then
        SORTED_MODULES=( "$MODULE_FILE" "${SORTED_MODULES[@]}" )
      else
        SORTED_MODULES=( "${SORTED_MODULES[@]}" "$MODULE_FILE" )
      fi
    fi
  done
  MODULES=( "${SORTED_MODULES[@]}" )
}

# $1: module group letter [P, S, R, F]
# $2: 0=single thread 1=multithread
# $3: HTML=1 - generate html file
run_modules()
{
  MODULE_GROUP="$1"
  printf -v THREADING_SET '%d\n' "$2" 2>/dev/null

  local SELECT_PRE_MODULES_COUNT=0

  for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
    if [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1} ]]; then
      (( SELECT_PRE_MODULES_COUNT+=1 ))
    fi
  done

  if [[ ${#SELECT_MODULES[@]} -eq 0 ]] || [[ $SELECT_PRE_MODULES_COUNT -eq 0 ]]; then
    local MODULES
    mapfile -t MODULES < <(find "$MOD_DIR" -name "${MODULE_GROUP^^}""*_*.sh" | sort -V 2> /dev/null)
    if [[ $THREADING_SET -eq 1 ]] ; then
      sort_modules
    fi
    for MODULE_FILE in "${MODULES[@]}" ; do
      if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
        MODULE_BN=$(basename "$MODULE_FILE")
        MODULE_MAIN=${MODULE_BN%.*}
        module_start_log "$MODULE_MAIN"
        if [[ $THREADING_SET -eq 1 ]]; then
          $MODULE_MAIN &
          WAIT_PIDS+=( "$!" )
          max_pids_protection "${WAIT_PIDS[@]}"
        else
          $MODULE_MAIN
        fi
        reset_module_count
      fi
    done
  else
    for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
      if [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1}[0-9]+ ]]; then
        local MODULE
        MODULE=$(find "$MOD_DIR" -name "${MODULE_GROUP^^}""${SELECT_NUM:1}""_*.sh" | sort -V 2> /dev/null)
        if ( file "$MODULE" | grep -q "shell script" ) && ! [[ "$MODULE" =~ \ |\' ]] ; then
          MODULE_BN=$(basename "$MODULE")
          MODULE_MAIN=${MODULE_BN%.*}
          module_start_log "$MODULE_MAIN"
          if [[ $THREADING_SET -eq 1 ]]; then
            $MODULE_MAIN &
            WAIT_PIDS+=( "$!" )
            max_pids_protection "${WAIT_PIDS[@]}"
          else
            $MODULE_MAIN
          fi
          reset_module_count
        fi
      elif [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1} ]]; then
        local MODULES
        mapfile -t MODULES < <(find "$MOD_DIR" -name "${MODULE_GROUP^^}""*_*.sh" | sort -V 2> /dev/null)
        if [[ $THREADING_SET -eq 1 ]] ; then
          sort_modules
        fi
        for MODULE_FILE in "${MODULES[@]}" ; do
          if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
            MODULE_BN=$(basename "$MODULE_FILE")
            MODULE_MAIN=${MODULE_BN%.*}
            module_start_log "$MODULE_MAIN"
            if [[ $THREADING_SET -eq 1 ]]; then
              $MODULE_MAIN &
              WAIT_PIDS+=( "$!" )
              max_pids_protection "${WAIT_PIDS[@]}"
            else
              $MODULE_MAIN
            fi
            reset_module_count
          fi
        done
      fi
    done
  fi
}

ctrl_c() {
  print_output "[*] Ctrl+C detected" "no_log"
  print_output "[*] Cleanup started" "no_log"
  # now we can unmount the stuff from emulator and delete temporary stuff
  exit 1
}

main()
{
  set -a 
  trap ctrl_c INT

  INVOCATION_PATH="$(dirname "$0")"

  export ARCH_CHECK=1
  export CWE_CHECKER=0
  export DEEP_EXTRACTOR=0
  export FACT_EXTRACTOR=0
  export FIRMWARE=0
  export FORCE=0
  export FORMAT_LOG=0
  export HTML=0
  export IN_DOCKER=0
  export KERNEL=0
  export LOG_GREP=0
  export MOD_RUNNING=0          # for tracking how many modules currently running
  export ONLY_DEP=0             # test only dependency
  export PHP_CHECK=1
  export PRE_CHECK=0            # test and extract binary files with binwalk
                                # afterwards do a default emba scan
  export PYTHON_CHECK=1
  export QEMULATION=0
  export SHELLCHECK=1
  export SHORT_PATH=0           # short paths in cli output
  export THREADED=0             # 0 -> single thread
                                # 1 -> multi threaded
  export USE_DOCKER=0
  export V_FEED=1
  export YARA=1
  export MAX_PIDS=5             # the maximum modules in parallel -> after S09 is finished this value gets adjusted

  export MAX_EXT_SPACE=11000     # a useful value, could be adjusted if you deal with very big firmware images
  export LOG_DIR="$INVOCATION_PATH""/logs"
  export TMP_DIR="$LOG_DIR""/tmp"
  export MAIN_LOG_FILE="emba.log"
  export CONFIG_DIR="$INVOCATION_PATH""/config"
  export EXT_DIR="$INVOCATION_PATH""/external"
  export HELP_DIR="$INVOCATION_PATH""/helpers"
  export MOD_DIR="$INVOCATION_PATH""/modules"
  export VUL_FEED_DB="$EXT_DIR""/allitems.csv"
  export VUL_FEED_CVSS_DB="$EXT_DIR""/allitemscvss.csv"
  export BASE_LINUX_FILES="$CONFIG_DIR""/linux_common_files.txt"
  export AHA_PATH="$EXT_DIR""/aha"

  echo

  import_helper
  import_module

  welcome  # Print emba welcome message

  if [[ $# -eq 0 ]]; then
    print_output "\\n""$ORANGE""In order to be able to use emba, you have to specify at least a firmware (-f).\\nIf you don't set a log directory (-l), then ./logs will be used.""$NC" "no_log"
    print_help
    exit 1
  fi

  export EMBA_COMMAND
  EMBA_COMMAND="$(dirname "$0")""/emba.sh ""$*"

  while getopts a:A:cdDe:Ef:Fghik:l:m:N:stxX:Y:WzZ: OPT ; do
    case $OPT in
      a)
        export ARCH="$OPTARG"
        ;;
      A)
        export ARCH="$OPTARG"
        export ARCH_CHECK=0
        ;;
      c)
        export CWE_CHECKER=1
        ;;
      d)
        export ONLY_DEP=1
        ;;
      D)
        export USE_DOCKER=1
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
        export FIRMWARE_PATH_BAK="$FIRMWARE_PATH"   # as we rewrite the firmware path variable in the pre-checker phase
                                                    # we store the original firmware path variable
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
        export IN_DOCKER=1
        ;;
      k)
        export KERNEL=1
        export KERNEL_CONFIG="$OPTARG"
        ;;
      l)
        export LOG_DIR="$OPTARG"
        export TMP_DIR="$LOG_DIR""/tmp"
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
      t)
        export THREADED=1
        ;;
      x)
        export DEEP_EXTRACTOR=1
        ;;
      W)
        export HTML=1
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

  echo

  # Check all dependencies of emba
  dependency_check

  if [[ $IN_DOCKER -eq 0 ]] ; then
    # check if LOG_DIR exists and prompt to terminal to delete its content (Y/n)
    log_folder
  fi

  # create log directory, if not exists and needed subdirectories
  create_log_dir

  # Print additional information about the firmware (-Y, -X, -Z, -N)
  print_firmware_info "$FW_VENDOR" "$FW_VERSION" "$FW_DEVICE" "$FW_NOTES"

  # Now we have the firmware and log path, lets set some additional paths
  FIRMWARE_PATH="$(abs_path "$FIRMWARE_PATH")"
  export MAIN_LOG="$LOG_DIR""/""$MAIN_LOG_FILE"

  if [[ $KERNEL -eq 1 ]] ; then
    LOG_DIR="$LOG_DIR""/""$(basename "$KERNEL_CONFIG")"
  fi

  # Check firmware type (file/directory)
  if [[ -d "$FIRMWARE_PATH" ]]; then
    PRE_CHECK=0
    print_output "[*] Firmware directory detected." "no_log"
    print_output "    Emba starts with testing the environment." "no_log"
    print_output "    The provided firmware will be copied to ""$FIRMWARE_PATH_CP" "no_log"
    cp -R "$FIRMWARE_PATH" "$FIRMWARE_PATH_CP""/""$(basename "$FIRMWARE_PATH")"
    FIRMWARE_PATH="$FIRMWARE_PATH_CP""/""$(basename "$FIRMWARE_PATH")"
    OUTPUT_DIR="$FIRMWARE_PATH_CP"
  elif [[ -f "$FIRMWARE_PATH" ]]; then
    PRE_CHECK=1
    print_output "[*] Firmware binary detected." "no_log"
    print_output "    Emba starts with the pre-testing phase." "no_log"
  else
    print_output "[!] Invalid firmware file" "no_log"
    print_help
    exit 1
  fi

  # Change log output to color for web report
  if [[ $HTML -eq 1 ]] && [[ $FORMAT_LOG -eq 0 ]]; then
    FORMAT_LOG=1
    print_output "[*] Activate colored log for webreporter" "no_log"
  fi

  if [[ $LOG_GREP -eq 1 ]] ; then
    # Create grep-able log file
    create_grep_log
    write_grep_log "sudo ""$EMBA_COMMAND" "COMMAND"
  fi

  # Exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
  set_exclude

  #######################################################################################
  # Kernel configuration check
  #######################################################################################
  if [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]] ; then
    if ! [[ -f "$KERNEL_CONFIG" ]] ; then
      print_output "[-] Invalid kernel configuration file: $KERNEL_CONFIG" "no_log"
      exit 1
    else
      if ! [[ -d "$LOG_DIR" ]] ; then
        chmod 777 "$LOG_DIR" 2> /dev/null
      fi
      S25_kernel_check
    fi
  fi

  #######################################################################################
  # Docker
  #######################################################################################
  if [[ $USE_DOCKER -eq 1 ]] ; then
    if ! [[ $EUID -eq 0 ]] ; then
      print_output "[!] Using emba with docker-compose requires root permissions" "no_log"
      print_output "$(indent "Run emba with root permissions to use docker")" "no_log"
      exit 1
    fi
    if ! command -v docker-compose > /dev/null ; then
      print_output "[!] No docker-compose found" "no_log"
      print_output "$(indent "Install docker-compose via apt-get install docker-compose to use emba with docker")" "no_log"
      exit 1
    fi

    OPTIND=1
    ARGS=""
    while getopts a:A:cdDe:Ef:Fghik:l:m:N:stX:Y:WxzZ: OPT ; do
      case $OPT in
        D|f|i|l)
          ;;
        *)
          export ARGS="$ARGS -$OPT"
          ;;
      esac
    done

    echo
    print_output "[!] Emba initializes kali docker container.\\n" "no_log"

    FIRMWARE="$FIRMWARE_PATH" LOG="$LOG_DIR" docker-compose run --rm emba -c "./emba.sh -l /log/ -f /firmware -i $ARGS"
    D_RETURN=$?

    if [[ $D_RETURN -eq 0 ]] ; then
      if [[ $ONLY_DEP -eq 0 ]] ; then
        print_output "[*] Emba finished analysis in docker container.\\n" "no_log"
        print_output "[*] Firmware tested: $FIRMWARE_PATH" "no_log"
        print_output "[*] Log directory: $LOG_DIR" "no_log"
        exit
      fi
    else
      print_output "[-] Emba docker failed!" "no_log"
      exit 1
    fi
  fi


  #######################################################################################
  # Pre-Check (P-modules)
  #######################################################################################
  if [[ $PRE_CHECK -eq 1 ]] ; then
    if [[ -f "$FIRMWARE_PATH" ]]; then

      echo
      if [[ -d "$LOG_DIR" ]]; then
        print_output "[!] Pre-checking phase started on ""$(date)""\\n""$(indent "$NC""Firmware binary path: ""$FIRMWARE_PATH")" "main"
      else
        print_output "[!] Pre-checking phase started on ""$(date)""\\n""$(indent "$NC""Firmware binary path: ""$FIRMWARE_PATH")" "no_log"
      fi

      # 'main' functions of imported modules
      # in the pre-check phase we execute all modules with P[Number]_Name.sh

      ## IMPORTANT NOTE: Threading is handled withing the pre-checking modules, therefore overwriting $THREADED as 0
      ## as there are internal dependencies it is easier to handle it in the modules
      run_modules "P" "0" "0"

      # if we running threaded we ware going to wait for the slow guys here
      if [[ $THREADED -eq 1 ]]; then
        wait_for_pid "${WAIT_PIDS[@]}"
      fi

      if [[ $LINUX_PATH_COUNTER -gt 0 || ${#ROOT_PATH[@]} -gt 1 ]] ; then
        FIRMWARE=1
        FIRMWARE_PATH="$(abs_path "$OUTPUT_DIR")"
      fi

      echo
      if [[ -d "$LOG_DIR" ]]; then
        print_output "[!] Pre-checking phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main" 
      else
        print_output "[!] Pre-checking phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
      fi

      # useful prints for debugging:
      # print_output "[!] Firmware value: $FIRMWARE"
      # print_output "[!] Firmware path: $FIRMWARE_PATH"
      # print_output "[!] Output dir: $OUTPUT_DIR"
      # print_output "[!] LINUX_PATH_COUNTER: $LINUX_PATH_COUNTER"
      # print_output "[!] LINUX_PATH_ARRAY: ${#ROOT_PATH[@]}"
    fi
  fi

  #######################################################################################
  # Firmware-Check (S- and R-modules)
  #######################################################################################
  if [[ $FIRMWARE -eq 1 ]] ; then
    if [[ -d "$FIRMWARE_PATH" ]]; then

      print_output "\n=================================================================\n" "no_log"

      if [[ $KERNEL -eq 0 ]] ; then
        architecture_check
        architecture_dep_check
      fi

      if [[ -d "$LOG_DIR" ]]; then
        print_output "[!] Testing phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "main" 
      else
        print_output "[!] Testing phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "no_log"
      fi
      write_grep_log "$(date)" "TIMESTAMP"

      if [[ "${#ROOT_PATH[@]}" -eq 0 ]]; then
        detect_root_dir_helper "$FIRMWARE_PATH"
      fi

      check_firmware
      prepare_binary_arr
      prepare_file_arr
      set_etc_paths
      echo

      run_modules "S" "$THREADED" "$HTML"

      if [[ $THREADED -eq 1 ]]; then
        wait_for_pid "${WAIT_PIDS[@]}"
      fi
    else
      # here we can deal with other non linux things like RTOS specific checks
      # lets call it R* modules
      # 'main' functions of imported finishing modules
      run_modules "R" "$THREADED" "$HTML"

      if [[ $THREADED -eq 1 ]]; then
        wait_for_pid "${WAIT_PIDS[@]}"
      fi
    fi

    echo
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Testing phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main"
    else
      print_output "[!] Testing phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi

    TESTING_DONE=1
  fi

  #######################################################################################
  # Reporting (F-modules)
  #######################################################################################
  if [[ -d "$LOG_DIR" ]]; then
    print_output "[!] Reporting phase started on ""$(date)""\\n" "main" 
  else
    print_output "[!] Reporting phase started on ""$(date)""\\n" "no_log" 
  fi
 
  run_modules "F" "0" "$HTML"

  run_web_reporter_build_index

  if [[ "$TESTING_DONE" -eq 1 ]]; then
    if [[ -f "$HTML_PATH"/index.html ]]; then
      print_output "[*] Web report created HTML report in $LOG_DIR/html-report\\n" "main" 
    fi
    echo
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main" 
      rm -r "$TMP_DIR" 2>/dev/null
    else
      print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi
    write_grep_log "$(date)" "TIMESTAMP"
    write_grep_log "$(date -d@$SECONDS -u +%H:%M:%S)" "DURATION"
  else
    print_output "[!] No extracted firmware found" "no_log"
    print_output "$(indent "Try using binwalk or something else to extract the Linux operating system")"
    exit 1
  fi
}

main "$@"
