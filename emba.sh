#!/bin/bash

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
# Contributor(s): Stefan Haboeck

# Description:  Main script for load all necessary files and call main function of modules

INVOCATION_PATH="."

import_helper()
{
  local HELPERS=()
  local HELPER_COUNT=0
  local HELPER_FILE=""
  mapfile -d '' HELPERS < <(find "$HELP_DIR" -iname "helpers_emba_*.sh" -print0 2> /dev/null)
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
  local MODULES=()
  local MODULES_LOCAL=()
  local MODULES_EMBA=()
  local MODULE_COUNT=0
  local MODULE_FILE=""
  # to ensure we are only auto load modules from the modules main directory we set maxdepth
  # with this in place we can create sub directories per module. For using/loading stuff from
  # these sub directories the modules are responsible!
  mapfile -t MODULES_EMBA < <(find "$MOD_DIR" -maxdepth 1 -name "*.sh" | sort -V 2> /dev/null)
  if [[ -d "${MOD_DIR_LOCAL}" ]]; then
    mapfile -t MODULES_LOCAL < <(find "${MOD_DIR_LOCAL}" -maxdepth 1 -name "*.sh" 2>/dev/null | sort -V 2> /dev/null)
  fi
  MODULES=( "${MODULES_EMBA[@]}" "${MODULES_LOCAL[@]}" )
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
  local SORTED_MODULES=()
  local MODULE_FILE=""
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

# lets check cve-search in a background job
check_cve_search_job() {
  local EMBA_PID="${1:-}"

  if ! [[ "$EMBA_PID" =~ [0-9]+ ]]; then
    print_output "[-] WARNING: No EMBA PID detected ... are we really running?!?"
    return
  fi

  while true; do
    if [[ -f "$LOG_DIR"/emba.log ]]; then
      if grep -q "Test ended\|EMBA failed" "$LOG_DIR"/emba.log 2>/dev/null; then
        break
      fi
    fi
    # shellcheck disable=SC2009
    if ! ps aux | grep -v grep | grep -q "$EMBA_PID"; then
      break
    fi
    check_nw_interface
    check_cve_search
    sleep 90
  done
}

# $1: module group letter [P, S, L, F]
# $2: 0=single thread 1=multithread
# $3: HTML=1 - generate html file
run_modules()
{
  MODULE_GROUP="${1:-}"
  printf -v THREADING_SET '%d\n' "$2" 2>/dev/null
  THREADING_MOD_GROUP="$THREADING_SET"

  local SELECT_PRE_MODULES_COUNT=0

  for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
    if [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1} ]]; then
      (( SELECT_PRE_MODULES_COUNT+=1 ))
    fi
  done

  if [[ ${#SELECT_MODULES[@]} -eq 0 ]] || [[ $SELECT_PRE_MODULES_COUNT -eq 0 ]]; then
    local MODULES=()
    local MODULES_LOCAL=()
    local MODULES_EMBA=()
    mapfile -t MODULES_EMBA < <(find "$MOD_DIR" -name "${MODULE_GROUP^^}""*_*.sh" | sort -V 2> /dev/null)
    if [[ -d "${MOD_DIR_LOCAL}" ]]; then
      mapfile -t MODULES_LOCAL < <(find "${MOD_DIR_LOCAL}" -name "${MODULE_GROUP^^}""*.sh" 2>/dev/null | sort -V 2> /dev/null)
    fi
    MODULES=( "${MODULES_EMBA[@]}" "${MODULES_LOCAL[@]}" )
    if [[ $THREADING_SET -eq 1 && "${MODULE_GROUP^^}" != "P" ]] ; then
      sort_modules
    fi
    for MODULE_FILE in "${MODULES[@]}" ; do
      if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
        if [[ "${MODULE_GROUP^^}" == "P" ]]; then
          # we are able to enable/disable threading on module basis in the the pre-checker modules with the header:
          # export PRE_THREAD_ENA=1/0
          # shellcheck source=/dev/null
          source "$MODULE_FILE"
          if [[ $PRE_THREAD_ENA -eq 0 ]] ; then
            THREADING_SET=0
          fi
        fi
        MODULE_BN=$(basename "$MODULE_FILE")
        MODULE_MAIN=${MODULE_BN%.*}
        module_start_log "$MODULE_MAIN"
        if [[ $THREADING_SET -eq 1 ]]; then
          $MODULE_MAIN &
          WAIT_PIDS+=( "$!" )
          max_pids_protection "$MAX_MODS" "${WAIT_PIDS[@]}"
        else
          $MODULE_MAIN
        fi
        reset_module_count
      fi
      if [[ "${MODULE_GROUP^^}" == "P" ]]; then
        THREADING_SET="$THREADING_MOD_GROUP"
      fi
    done
  else
    for SELECT_NUM in "${SELECT_MODULES[@]}" ; do
      if [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1}[0-9]+ ]]; then
        local MODULE=""
        MODULE=$(find "$MOD_DIR" -name "${MODULE_GROUP^^}""${SELECT_NUM:1}""_*.sh" | sort -V 2> /dev/null)
        if ( file "$MODULE" | grep -q "shell script" ) && ! [[ "$MODULE" =~ \ |\' ]] ; then
          MODULE_BN=$(basename "$MODULE")
          MODULE_MAIN=${MODULE_BN%.*}
          module_start_log "$MODULE_MAIN"
          if [[ $THREADING_SET -eq 1 ]]; then
            $MODULE_MAIN &
            WAIT_PIDS+=( "$!" )
            max_pids_protection "$MAX_MODS" "${WAIT_PIDS[@]}"
          else
            $MODULE_MAIN
          fi
          reset_module_count
        fi
      elif [[ "$SELECT_NUM" =~ ^["${MODULE_GROUP,,}","${MODULE_GROUP^^}"]{1} ]]; then
        local MODULES=()
        local MODULES_LOCAL=()
        local MODULES_EMBA=()
        mapfile -t MODULES_EMBA < <(find "$MOD_DIR" -name "${MODULE_GROUP^^}""*_*.sh" | sort -V 2> /dev/null)
        if [[ -d "${MOD_DIR_LOCAL}" ]]; then
          mapfile -t MODULES_LOCAL < <(find "${MOD_DIR_LOCAL}" -name "${MODULE_GROUP^^}""*.sh" 2>/dev/null | sort -V 2> /dev/null)
        fi
        MODULES=( "${MODULES_EMBA[@]}" "${MODULES_LOCAL[@]}" )
        if [[ $THREADING_SET -eq 1 ]] ; then
          sort_modules
        fi
        for MODULE_FILE in "${MODULES[@]}" ; do
          if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
            if [[ "${MODULE_GROUP^^}" == "P" ]]; then
              # we are able to enable/disable threading on module basis in the the pre-checker modules with the header:
              # export PRE_THREAD_ENA=1/0
              # shellcheck source=/dev/null
              source "$MODULE_FILE"
              if [[ $PRE_THREAD_ENA -eq 0 ]] ; then
                THREADING_SET=0
              fi
            fi

            MODULE_BN=$(basename "$MODULE_FILE")
            MODULE_MAIN=${MODULE_BN%.*}
            module_start_log "$MODULE_MAIN"
            if [[ $THREADING_SET -eq 1 ]]; then
              $MODULE_MAIN &
              WAIT_PIDS+=( "$!" )
              max_pids_protection "$MAX_MODS" "${WAIT_PIDS[@]}"
            else
              $MODULE_MAIN
            fi
            reset_module_count
          fi
          if [[ "${MODULE_GROUP^^}" == "P" ]]; then
            THREADING_SET="$THREADING_MOD_GROUP"
          fi
        done
      fi
    done
  fi
}

main()
{

  set -a 
  trap cleaner INT

  INVOCATION_PATH="$(dirname "$0")"

  export EMBA_PID="$$"
  # if this is a release version set RELEASE to 1, add a banner to config/banner and name the banner with the version details
  export RELEASE=0
  export EMBA_VERSION="1.1.x"
  export STRICT_MODE=0
  export MATRIX_MODE=0
  export UPDATE=0
  export ARCH_CHECK=1
  export RTOS=0                 # Testing RTOS based OS
  export CWE_CHECKER=0
  export CONTAINER_EXTRACT=0
  export DEEP_EXTRACTOR=0
  export FACT_EXTRACTOR=0
  export FIRMWARE=0
  export FORCE=0
  export FORMAT_LOG=0
  export HTML=0
  export IN_DOCKER=0
  export USE_DOCKER=1
  export KERNEL=0
  export KERNEL_CONFIG=""
  export FIRMWARE_PATH=""
  export FW_VENDOR=""
  export FW_VERSION=""
  export FW_DEVICE=""
  export FW_NOTES=""
  export ARCH=""
  export EXLUDE=()
  export SELECT_MODULES=()
  export ROOT_PATH=()
  export FILE_ARR=()
  export LOG_GREP=0
  export FINAL_FW_RM=0          # remove the firmware working copy after testing (do not waste too much disk space)
  export ONLY_DEP=0             # test only dependency
  export ONLINE_CHECKS=0        # checks with internet connection needed (e.g. upload of firmware to virustotal)
  export PHP_CHECK=1
  export PRE_CHECK=0            # test and extract binary files with binwalk
                                # afterwards do a default EMBA scan
  export PYTHON_CHECK=1
  export QEMULATION=0
  export FULL_EMULATION=0
  # to get rid of all the running stuff we are going to kill it after RUNTIME
  export QRUNTIME="20s"

  export SHELLCHECK=1
  export SHORT_PATH=0           # short paths in cli output
  export THREADED=0             # 0 -> single thread
                                # 1 -> multi threaded
  export YARA=1
  export OVERWRITE_LOG=0        # automaticially overwrite log directory, if necessary
  export JUMP_OVER_CVESEARCH_CHECK=0 # ignore long CVEsearch check in dep check

  export MAX_EXT_SPACE=11000     # a useful value, could be adjusted if you deal with very big firmware images
  export LOG_DIR="$INVOCATION_PATH""/logs"
  export TMP_DIR="$LOG_DIR""/tmp"
  export MAIN_LOG_FILE="emba.log"
  export CONFIG_DIR="$INVOCATION_PATH""/config"
  export EXT_DIR="$INVOCATION_PATH""/external"
  export HELP_DIR="$INVOCATION_PATH""/helpers"
  export MOD_DIR="$INVOCATION_PATH""/modules"
  export MOD_DIR_LOCAL="$INVOCATION_PATH""/modules_local"
  export BASE_LINUX_FILES="$CONFIG_DIR""/linux_common_files.txt"
  export PATH_CVE_SEARCH="$EXT_DIR""/cve-search/bin/search.py"
  export MSF_PATH="/usr/share/metasploit-framework/modules/"
  export PHP_INISCAN_PATH="$EXT_DIR""/iniscan/bin/iniscan"
  if [[ -f "$CONFIG_DIR"/msf_cve-db.txt ]]; then
    export MSF_DB_PATH="$CONFIG_DIR"/msf_cve-db.txt
  fi
  export VT_API_KEY_FILE="$CONFIG_DIR"/vt_api_key.txt     # virustotal API key for P03 module
  export GTFO_CFG="$CONFIG_DIR"/gtfobins_urls.cfg         # gtfo urls
  export DISABLE_NOTIFICATIONS=0    # disable notifications and further desktop experience
  export EMBA_ICON=""
  EMBA_ICON=$(realpath "$HELP_DIR"/emba.svg)

  import_helper
  print_ln "no_log"
  import_module

  welcome  # Print EMBA welcome message

  if [[ $# -eq 0 ]]; then
    print_output "\\n""$ORANGE""In order to be able to use EMBA, you have to specify at least a firmware (-f).\\nIf you don't set a log directory (-l), then ./logs will be used.""$NC" "no_log"
    print_help
    exit 1
  fi

  export EMBA_COMMAND
  EMBA_COMMAND="$(dirname "$0")""/emba.sh ""$*"

  while getopts a:bA:cC:dDe:Ef:Fghijk:l:m:MN:op:QrsStUxX:yY:WzZ: OPT ; do
    case $OPT in
      a)
        export ARCH="$OPTARG"
        ;;
      A)
        export ARCH="$OPTARG"
        export ARCH_CHECK=0
        ;;
      b)
        banner_printer
        exit 0
        ;;
      C)
        # container extract only works outside the docker container
        # lets extract it outside and afterwards start the EMBA docker
        export CONTAINER_ID="$OPTARG"
        export CONTAINER_EXTRACT=1
        ;;
      c)
        export CWE_CHECKER=1
        ;;
      d)
        export ONLY_DEP=1
        ;;
      D)
        # new debugging mode
        export USE_DOCKER=0
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
        # for detecting the execution in docker container:
        export IN_DOCKER=1
        export USE_DOCKER=0
        ;;
      j)
        export JUMP_OVER_CVESEARCH_CHECK=1
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
      M)
        export MATRIX_MODE=1
        ;;
      N)
        export FW_NOTES="$OPTARG"
        ;;
      o)
        export ONLINE_CHECKS=1
        ;;
      p)
        export PROFILE="$OPTARG"
       ;;
      Q)
        # this is for experimental system emulation module
        export FULL_EMULATION=1
        ;;
      r)
        export FINAL_FW_RM=1
       ;;
      s)
        export SHORT_PATH=1
        ;;
      S)
        export STRICT_MODE=1
        ;;
      t)
        export THREADED=1
        ;;
      U)
        export UPDATE=1
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
      y)
        export OVERWRITE_LOG=1
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

  print_ln "no_log"

  write_notification "EMBA starting"

  # WSL support - currently experimental!
  if [[ $IN_DOCKER -eq 0 ]]; then
    if grep -q -i wsl /proc/version; then
      print_ln
      print_output "[*] INFO: System running in WSL environment!"
      print_output "[*] INFO: WSL is currently experimental."
      print_output "[*] INFO: Please report issues to https://github.com/e-m-b-a/emba/issues."
      print_ln
    fi
  fi

  # print it only once per EMBA run - not again from started container
  if [[ $IN_DOCKER -eq 0 ]]; then
    banner_printer
  fi

  if [[ "$UPDATE" -eq 1 ]]; then
    write_notification "EMBA starts with update"
    emba_updater
    exit 0
  fi

  if [[ $USE_DOCKER -eq 0 && $IN_DOCKER -eq 0 ]]; then
    print_bar "no_log"
    print_output "[!] WARNING: EMBA running in developer mode!" "no_log"
    write_notification "WARNING: EMBA running in developer mode"
    print_bar "no_log"
  fi

  enable_strict_mode "$STRICT_MODE"

  # profile handling
  if [[ -n "${PROFILE:-}" ]]; then
    if [[ -f "$PROFILE" ]]; then
      print_bar "no_log"
      if [[ $IN_DOCKER -ne 1 ]] ; then
        print_output "[*] Loading EMBA scan profile with the following settings:" "no_log"
      else
        print_output "[*] Loading EMBA scan profile." "no_log"
      fi
      # all profile output and settings are done by the profile file located in ./scan-profiles/
      # shellcheck disable=SC1090
      source "$PROFILE"
      print_output "[*] Profile $PROFILE loaded." "no_log"
      print_bar "no_log"
    else
      print_output "[!] Profile $PROFILE not found." "no_log"
      exit 1
    fi
  fi
 
  # check provided paths for validity 
  check_path_valid "$FIRMWARE_PATH"
  check_path_valid "$KERNEL_CONFIG"
  check_path_valid "$LOG_DIR"

  if [[ $IN_DOCKER -eq 1 ]] ; then
    # set external path new for docker
    export EXT_DIR="/external"
    export PATH_CVE_SEARCH="$EXT_DIR""/cve-search/bin/search.py"
  fi

  # Check all dependencies of EMBA
  dependency_check

  if [[ $IN_DOCKER -eq 0 ]] ; then
    # check if LOG_DIR exists and prompt to terminal to delete its content (Y/n)
    log_folder
  fi

  # create log directory, if not exists and needed subdirectories
  create_log_dir

  if [[ "$IN_DOCKER" -eq 0 ]]; then
    print_notification &
  fi

  # Print additional information about the firmware (-Y, -X, -Z, -N)
  print_firmware_info "$FW_VENDOR" "$FW_VERSION" "$FW_DEVICE" "$FW_NOTES"
  if [[ "$KERNEL" -ne 1 && "$CONTAINER_EXTRACT" -ne 1 ]]; then
    check_init_size
  fi

  # Now we have the firmware and log path, lets set some additional paths
  FIRMWARE_PATH="$(abs_path "$FIRMWARE_PATH")"
  export MAIN_LOG="$LOG_DIR""/""$MAIN_LOG_FILE"

  if [[ $KERNEL -eq 1 ]] ; then
    LOG_DIR="$LOG_DIR""/""$(basename "$KERNEL_CONFIG")"
  fi

  # Check firmware type (file/directory)
  # copy the firmware outside of the docker and not a second time within the docker
  if [[ -d "$FIRMWARE_PATH" ]] ; then
    PRE_CHECK=1
    print_output "[*] Firmware directory detected." "no_log"
    print_output "[*] EMBA starts with testing the environment." "no_log"
    if [[ $IN_DOCKER -eq 0 ]] ; then
      # in docker environment the firmware is already available
      print_output "    The provided firmware will be copied to $ORANGE""$FIRMWARE_PATH_CP""/""$(basename "$FIRMWARE_PATH")""$NC" "no_log"
      cp -R "$FIRMWARE_PATH" "$FIRMWARE_PATH_CP""/""$(basename "$FIRMWARE_PATH")"
      FIRMWARE_PATH="$FIRMWARE_PATH_CP""/""$(basename "$FIRMWARE_PATH")"
      export OUTPUT_DIR="$FIRMWARE_PATH_CP"
    else
      # need to set it as fallback:
      export OUTPUT_DIR="$FIRMWARE_PATH"
    fi
  elif [[ "$CONTAINER_EXTRACT" -eq 1 ]]; then
    PRE_CHECK=1
    print_output "[*] Firmware analysis of docker image starting." "no_log"
    print_output "    EMBA starts with extracting the docker image $ORANGE$CONTAINER_ID$NC." "no_log"
    export FIRMWARE_PATH="$LOG_DIR"/firmware/firmware_docker_extracted.tar
    export OUTPUT_DIR="$FIRMWARE_PATH"
    export FIRMWARE=1
  elif [[ -f "$FIRMWARE_PATH" ]]; then
    PRE_CHECK=1
    print_output "[*] Firmware binary detected." "no_log"
    print_output "    EMBA starts with the pre-testing phase." "no_log"
    export OUTPUT_DIR="$FIRMWARE_PATH"
  elif [[ -f "$KERNEL_CONFIG" && "$KERNEL" -eq 1 ]]; then
    print_output "[*] Kernel configuration file detected." "no_log"
  else
    print_output "[!] Invalid firmware file" "no_log"
    print_help
    exit 1
  fi

  # calculate the maximum modules are running in parallel
  if [[ $THREADED -eq 1 ]]; then
    # the maximum modules in parallel
    # rule of thumb - per core half a module, minimum 2 modules
    MAX_MODS="$(( $(grep -c ^processor /proc/cpuinfo) /2 +1))"
    # the maximum threads per modules - if this value does not match adjust it via
    # local MAX_MOD_THREADS=123 in module area
    export MAX_MOD_THREADS="$(( 3* $(grep -c ^processor /proc/cpuinfo) ))"

    # if we have only one core we run two modules in parallel
    if [[ "$MAX_MODS" -lt 2 ]]; then
      MAX_MODS=2
    fi
    export MAX_MODS
    print_output "    EMBA is running with $ORANGE$MAX_MODS$NC modules in parallel." "no_log"
  fi

  # Change log output to color for web report and prepare report
  if [[ $HTML -eq 1 ]] ; then
    if [[ $FORMAT_LOG -eq 0 ]] ; then
      FORMAT_LOG=1
      print_output "[*] Activate colored log for webreport" "no_log"
    fi
    print_output "[*] Prepare webreport" "no_log"
    prepare_report
  fi

  if [[ $LOG_GREP -eq 1 ]] ; then
    # Create grep-able log file
    create_grep_log
    write_grep_log "sudo ""$EMBA_COMMAND" "COMMAND"
  fi

  if [[ "$KERNEL" -ne 1 ]]; then
    # Exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
    set_exclude
  fi

  #######################################################################################
  # Kernel configuration check
  #######################################################################################
  if [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]] ; then
    if ! [[ -f "$KERNEL_CONFIG" ]] ; then
      print_output "[-] Invalid kernel configuration file: $ORANGE$KERNEL_CONFIG" "no_log"
      exit 1
    else
      if ! [[ -d "$LOG_DIR" ]] ; then
        mkdir "$LOG_DIR" || true
      fi
      S25_kernel_check
      exit 0
    fi
  fi

  # we use the metasploit path for exploit information from the metasploit framework
  if [[ -d "$MSF_PATH" && "$IN_DOCKER" -eq 0 ]]; then
    generate_msf_db &
  fi

  # we create the trickest cve database on the host - if the trickest-cve repo is here
  # typically this is on installations in full mode
  export TRICKEST_DB_PATH="$TMP_DIR"/trickest_cve-db.txt
  if [[ -d "$EXT_DIR/trickest-cve" && "$IN_DOCKER" -eq 0 ]]; then
    # we update the trickest database on every scan and store the database in the tmp directory
    generate_trickest_db &
  fi

  # we update the known_exploited_vulnerabilities.csv file on the host - if the file is here
  export KNOWN_EXP_CSV="$TMP_DIR"/known_exploited_vulnerabilities.csv
  if [[ -f "$EXT_DIR/known_exploited_vulnerabilities.csv" && "$IN_DOCKER" -eq 0 ]]; then
    # we update the known_exploited_vulnerabilities.csv file on every scan and store the database in the tmp directory
    update_known_exploitable &
  fi

  if [[ $IN_DOCKER -eq 0 ]] ; then
    check_cve_search_job "$EMBA_PID" &
  fi

  if [[ "$MATRIX_MODE" -eq 1 && $IN_DOCKER -eq 0 ]]; then
    matrix_mode &
  fi

  # if $CONTAINER_EXTRACT is set we extract the docker container with id $CONTAINER_ID outside of the
  # EMBA container into log directory
  # we do this only outside of the EMBA container - otherwise we will not reach the docker environment
  if [[ "$CONTAINER_EXTRACT" -eq 1 && "$IN_DOCKER" -eq 0 ]] ; then
    docker_container_extractor "$CONTAINER_ID"
  fi

  #######################################################################################
  # Docker
  #######################################################################################
  if [[ $USE_DOCKER -eq 1 ]] ; then
    if ! [[ $EUID -eq 0 ]] ; then
      print_output "[!] Using EMBA with docker-compose requires root permissions" "no_log"
      print_output "$(indent "Run EMBA with root permissions to use docker")" "no_log"
      exit 1
    fi
    if ! command -v docker-compose > /dev/null ; then
      print_output "[!] No docker-compose found" "no_log"
      print_output "$(indent "Install docker-compose via apt-get install docker-compose to use EMBA with docker")" "no_log"
      exit 1
    fi

    OPTIND=1
    ARGUMENTS=()
    while getopts a:A:cC:dDe:Ef:Fghijk:l:m:MN:op:QrsStUX:yY:WxzZ: OPT ; do
      case $OPT in
        D|f|i|l)
          ;;
        *)
          if [[ -v OPTARG[@] ]] ; then
            ARGUMENTS=( "${ARGUMENTS[@]}" "-$OPT" "${OPTARG[@]}" )
          else
            ARGUMENTS=( "${ARGUMENTS[@]}" "-$OPT" )
          fi
          ;;
      esac
    done

    print_ln "no_log"

    print_output "[*] EMBA sets up the docker environment.\\n" "no_log"

    if [[ "$UPDATE" -eq 1 ]]; then
      EMBA="$INVOCATION_PATH" FIRMWARE="$FIRMWARE_PATH" LOG="$LOG_DIR" docker pull embeddedanalyzer/emba
    fi

    if ! docker images | grep -qE "emba[[:space:]]*latest"; then
      print_output "[*] Available docker images:" "no_log"
      docker images | grep -E "emba[[:space:]]*latest"
      print_output "[-] EMBA docker not ready!" "no_log"
      exit 1
    else
      print_output "[*] EMBA initializes docker container.\\n" "no_log"

      # store some details that we do not have in the docker container:
      echo "$FIRMWARE_PATH" >> "$TMP_DIR"/fw_name.log
      echo "$LOG_DIR" >> "$TMP_DIR"/emba_log_dir.log
      echo "$EMBA_COMMAND" >> "$TMP_DIR"/emba_command.log
      write_notification "EMBA starting docker container"

      if [[ "$STRICT_MODE" -eq 1 ]]; then
        set +e
      fi
      disable_strict_mode "$STRICT_MODE" 0
      EMBA="$INVOCATION_PATH" FIRMWARE="$FIRMWARE_PATH" LOG="$LOG_DIR" docker-compose run --rm emba -c './emba.sh -l /log -f /firmware -i "$@"' _ "${ARGUMENTS[@]}"
      D_RETURN=$?
      enable_strict_mode "$STRICT_MODE" 0

      if [[ $D_RETURN -eq 0 ]] ; then
        if [[ $ONLY_DEP -eq 0 ]] ; then
          print_output "[*] EMBA finished analysis in docker container.\\n" "no_log"
          write_notification "EMBA finished analysis in default mode"
          print_output "[*] Firmware tested: $ORANGE$FIRMWARE_PATH$NC" "no_log"
          print_output "[*] Log directory: $ORANGE$LOG_DIR$NC" "no_log"
          if [[ -f "$HTML_PATH"/index.html ]]; then
            print_output "[*] Open the web-report with$ORANGE firefox $(abs_path "$HTML_PATH/index.html")$NC\\n" "main"
          fi
          exit
        fi
      else
        print_output "[-] EMBA failed in docker mode!" "main"
        write_notification "EMBA failed analysis in default mode"
        exit 1
      fi
    fi
  fi


  #######################################################################################
  # Pre-Check (P-modules)
  #######################################################################################
  if [[ $PRE_CHECK -eq 1 ]] ; then

    print_ln "no_log"
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Pre-checking phase started on ""$(date)""\\n""$(indent "$NC""Firmware binary path: ""$FIRMWARE_PATH")" "main"
    else
      print_output "[!] Pre-checking phase started on ""$(date)""\\n""$(indent "$NC""Firmware binary path: ""$FIRMWARE_PATH")" "no_log"
    fi
    write_notification "Pre-checking phase started"

    # 'main' functions of imported modules
    # in the pre-check phase we execute all modules with P[Number]_Name.sh

    run_modules "P" "$THREADED" "0"

    # if we running threaded we ware going to wait for the slow guys here
    if [[ $THREADED -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS[@]}"
    fi

    print_ln "no_log"

    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Pre-checking phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main" 
    else
      print_output "[!] Pre-checking phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi
    write_notification "Pre-checking phase finished"

    # useful prints for debugging:
    # print_output "[!] Firmware value: $FIRMWARE"
    # print_output "[!] Firmware path: $FIRMWARE_PATH"
    # print_output "[!] Output dir: $OUTPUT_DIR"
    # print_output "[!] LINUX_PATH_COUNTER: $LINUX_PATH_COUNTER"
    # print_output "[!] LINUX_PATH_ARRAY: ${#ROOT_PATH[@]}"
  fi

  #######################################################################################
  # Firmware-Check (S modules)
  #######################################################################################
  WAIT_PIDS=()
  if [[ $FIRMWARE -eq 1 ]] ; then
    print_output "\n=================================================================\n" "no_log"

    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Testing phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "main" 
    else
      print_output "[!] Testing phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "no_log"
    fi
    write_notification "Testing phase finished"
    write_grep_log "$(date)" "TIMESTAMP"

    run_modules "S" "$THREADED" "$HTML"

    if [[ $THREADED -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS[@]}"
    fi

    print_ln "no_log"

    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Testing phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main"
    else
      print_output "[!] Testing phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi
    write_notification "Testing phase ended"

    TESTING_DONE=1
  fi

  #######################################################################################
  # Live Emulation - Check (L-modules)
  #######################################################################################
  if [[ $FULL_EMULATION -eq 1 ]] ; then
    print_output "\n=================================================================\n" "no_log"
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] System emulation phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "main" 
    else
      print_output "[!] System emulation phase started on ""$(date)""\\n""$(indent "$NC""Firmware path: ""$FIRMWARE_PATH")" "no_log"
    fi
    write_notification "System emulation phase started"

    write_grep_log "$(date)" "TIMESTAMP"
    # these modules are not threaded!
    run_modules "L" "0" "$HTML"

    print_ln "no_log"
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] System emulation phase ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main"
    else
      print_output "[!] System emulation ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi
    write_notification "System emulation phase ended"
  fi

  #######################################################################################
  # Reporting (F-modules)
  #######################################################################################
  if [[ -d "$LOG_DIR" ]]; then
    print_output "[!] Reporting phase started on ""$(date)""\\n" "main" 
  else
    print_output "[!] Reporting phase started on ""$(date)""\\n" "no_log" 
  fi
  write_notification "Reporting phase started"
 
  run_modules "F" "0" "$HTML"

  write_notification "Reporting phase ended"

  if [[ "$TESTING_DONE" -eq 1 ]]; then
    if [[ "$FINAL_FW_RM" -eq 1 && -d "$LOG_DIR"/firmware ]]; then
      print_output "[*] Removing temp firmware directory\\n" "no_log" 
      rm -r "$LOG_DIR"/firmware 2>/dev/null
    fi
    print_ln "no_log"
    if [[ -d "$LOG_DIR" ]]; then
      print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "main" 
      write_notification "EMBA finished analysis"
      rm -r "$TMP_DIR" 2>/dev/null || true
    else
      print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
    fi
    write_grep_log "$(date)" "TIMESTAMP"
    write_grep_log "$(date -d@$SECONDS -u +%H:%M:%S)" "DURATION"
  else
    print_output "[!] No extracted firmware found" "no_log"
    print_output "$(indent "Try using binwalk or something else to extract the firmware")"
    exit 1
  fi
  if [[ "$HTML" -eq 1 ]]; then
    update_index
  fi
  if [[ "$IN_DOCKER" -eq 0 ]]; then
    # stop inotifywait on host
    pkill -f "inotifywait.*$LOG_DIR.*"
  fi
  if [[ -f "$HTML_PATH"/index.html ]] && [[ "$IN_DOCKER" -eq 0 ]]; then
    print_output "[*] Web report created HTML report in $ORANGE$LOG_DIR/html-report$NC\\n" "main" 
    print_output "[*] Open the web-report with$ORANGE firefox $(abs_path "$HTML_PATH/index.html")$NC\\n" "main"
  fi
}

main "$@"
