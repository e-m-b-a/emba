#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2026 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: print_help and parameter parsing

print_help() {
  ## help and command line parsing

  echo -e "\\n""${CYAN}""USAGE""${NC}"
  echo -e "\\nTest firmware"
  echo -e "${CYAN}""-l [~/path]""${NC}""       Log path"
  echo -e "${CYAN}""-f [~/path]""${NC}""       Firmware path"
  echo -e "${CYAN}""-m [MODULE_NO.]""${NC}""   Test only with set modules [e.g. -m p05 -m s10 ... or -m p to run all p modules]"
  echo -e "                                    (multiple usage possible, case insensitive)"
  echo -e "${CYAN}""-p [PROFILE]""${NC}""      EMBA starts with a pre-defined profile (stored in ./scan-profiles)"
  # Threading is now only available via profile parameter. In default mode EMBA is running in threading mode
  #  echo -e "${CYAN}""-t""${NC}""                Activate multi threading (destroys regular console output)"
  echo -e "${CYAN}""-P""${NC}""                Overwrite auto MAX_MODS (maximum modules in parallel) configuration"
  echo -e "${CYAN}""-T""${NC}""                Overwrite auto MAX_MOD_THREADS (maximum threads per module) configuration"
  echo -e "\\nDeveloper options"
  echo -e "${CYAN}""-D""${NC}""                Developer mode - EMBA runs on the host without container protection (deprecated)"
  echo -e "${CYAN}""-S""${NC}""                STRICT mode - developer option for error tracing / not deleting docker container logs"
  #  echo -e "${CYAN}""-i""${NC}""                EMBA internally used for container identification (do not use it as cli parameter)"
  echo -e "${CYAN}""-y""${NC}""                Overwrite log directory automaticially, even if it is not empty"
  echo -e "\\nSystem check"
  echo -e "${CYAN}""-d [1/2]""${NC}""          Only checks dependencies (1 - on host and in container, 2 - only container)"
  echo -e "${CYAN}""-F""${NC}""                Checks dependencies but ignore errors"
  echo -e "${CYAN}""-U""${NC}""                Check and apply available updates and exit"
  echo -e "${CYAN}""-V""${NC}""                Show EMBA version"
  echo -e "\\nSpecial tests"
  echo -e "${CYAN}""-k [~/config]""${NC}""     Kernel config path"
  echo -e "${CYAN}""-C [container id]""${NC}"" Extract and analyze a local docker container via container id"
  echo -e "${CYAN}""-r""${NC}""                Remove temporary firmware directory after testing"
  echo -e "${CYAN}""-b""${NC}""                Just print a random banner and exit"
  echo -e "${CYAN}""-o [~/path]""${NC}""       2nd Firmware path to diff against the main firmware file - diff mode only (no other firmware analysis)"
  echo -e "${CYAN}""-c""${NC}""                Enable extended binary analysis"
  echo -e "${CYAN}""-E""${NC}""                Enables automated qemu user emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-Q""${NC}""                Enables automated qemu system emulation tests (WARNING this module could harm your host!)"
  echo -e "${CYAN}""-q""${NC}""                Disables the deep-extractor module"
  echo -e "${CYAN}""-R""${NC}""                Rescans existing SBOM (-l required) and generates a new VEX JSON"
  echo -e "${CYAN}""-a [MIPS]""${NC}""         Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (usually not needed)"
  echo -e "${CYAN}""-A [MIPS]""${NC}""         Force Architecture of the linux firmware [MIPS, ARM, x86, x64, PPC] (disable architecture check - usually not needed)"
  echo -e "${CYAN}""-e [./path]""${NC}""       Exclude paths from testing (multiple usage possible - usually not needed)"
  echo -e "\\nReporter options"
  echo -e "${CYAN}""-W""${NC}""                Activates web report creation in log path (overwrites -z)"
  echo -e "${CYAN}""-g""${NC}""                Create grep-able log file in [log_path]/fw_grep.log"
  #  echo -e "                  Schematic: MESSAGE_TYPE;MODULE_NUMBER;SUB_MODULE_NUMBER;MESSAGE"
  echo -e "${CYAN}""-s""${NC}""                Prints only relative paths"
  echo -e "${CYAN}""-z""${NC}""                Adds ANSI color codes to log"
  echo -e "\\nFirmware details"
  echo -e "${CYAN}""-X [version]""${NC}""      Firmware version (versions aka 1.2.3-a:b only)"
  echo -e "${CYAN}""-Y [vendor]""${NC}""       Firmware vendor (alphanumerical values only)"
  echo -e "${CYAN}""-Z [device]""${NC}""       Device (alphanumerical values only)"
  echo -e "${CYAN}""-N [notes]""${NC}""        Testing notes (alphanumerical values only)"
  echo -e "\\nHelp"
  echo -e "${CYAN}""-h""${NC}""                Prints this help message"
}

emba_parameter_parsing() {
  while getopts a:bBA:cC:d:De:Ef:Fhik:l:m:N:o:p:P:qQRrsStT:UVX:yY:WzZ: OPT; do
    case "${OPT}" in
    a)
      check_alnum "${OPTARG}"
      export ARCH=""
      ARCH="$(escape_echo "${OPTARG}")"
      ;;
    A)
      check_alnum "${OPTARG}"
      export ARCH=""
      ARCH="$(escape_echo "${OPTARG}")"
      export ARCH_CHECK=0
      ;;
    b)
      banner_printer
      exit 0
      ;;
    B)
      export DISABLE_STATUS_BAR=0
      export SILENT=1
      ;;
    C)
      # container extract only works outside the docker container
      # lets extract it outside and afterwards start the EMBA docker
      check_alnum "${OPTARG}"
      export CONTAINER_ID=""
      CONTAINER_ID="$(escape_echo "${OPTARG}")"
      export CONTAINER_EXTRACT=1
      ;;
    c)
      export BINARY_EXTENDED=1
      ;;
    d)
      check_int "${OPTARG}"
      export ONLY_DEP="${OPTARG}"
      # a value of 1 means dep check on host and in container
      # a value of 2 means dep check only in container
      ! [[ "${ONLY_DEP}" =~ [12] ]] && {
        echo "Error: Invalid value for ONLY_DEP. Valid values are 1 (host and container) or 2 (container only)."
        exit 1
      }
      # on dependency check we need to check all deps -> activate all modules:
      export BINARY_EXTENDED=1
      export FULL_EMULATION=1
      ;;
    D)
      # debugging mode
      # EMBA runs without docker in full install mode
      # WARNING: this should only be used for dev tasks and not for real fw analysis
      export USE_DOCKER=0
      ;;
    e)
      check_path_input "${OPTARG}"
      export EXCLUDE=("${EXCLUDE[@]}" "$(escape_echo "${OPTARG}")")
      ;;
    E)
      export QEMULATION=1
      ;;
    f)
      check_path_input "${OPTARG}"
      export FIRMWARE=1
      export FIRMWARE_PATH=""
      FIRMWARE_PATH="$(escape_echo "${OPTARG}")"
      readonly FIRMWARE_PATH_BAK="${FIRMWARE_PATH}" # as we rewrite the firmware path variable in the pre-checker phase
      export FIRMWARE_PATH_BAK                      # we store the original firmware path variable and make it readonly
      # for firmware diff option, see option o
      ;;
    F)
      export FORCE=1
      ;;
    h)
      print_help
      exit 0
      ;;
    i)
      # for detecting the execution in docker container:
      # this parameter is only EMBA internally used
      export IN_DOCKER=1
      export USE_DOCKER=0
      ;;
    k)
      check_path_input "${OPTARG}"
      export KERNEL=1
      export KERNEL_CONFIG=""
      KERNEL_CONFIG="$(escape_echo "${OPTARG}")"
      if [[ "${FIRMWARE}" -ne 1 ]]; then
        # this is a little hack to enable kernel config only checks
        export FIRMWARE_PATH="${KERNEL_CONFIG}"
      fi
      ;;
    l)
      check_path_input "${OPTARG}"
      export LOG_DIR=""
      LOG_DIR="$(escape_echo "${OPTARG}")"
      export TMP_DIR="${LOG_DIR}/tmp"
      export CSV_DIR="${LOG_DIR}/csv_logs"
      export JSON_DIR="${LOG_DIR}/json_logs"
      export BASIC_DATA_LOG_DIR="${LOG_DIR}/basic_data"
      ;;
    m)
      check_alnum "${OPTARG}"
      export SELECT_MODULES=("${SELECT_MODULES[@]}" "$(escape_echo "${OPTARG}")")
      ;;
    N)
      check_notes "${OPTARG}"
      export FW_NOTES=""
      FW_NOTES="$(escape_echo "${OPTARG}")"
      ;;
    o)
      # other firmware file -> we do a diff check
      check_path_input "${OPTARG}"
      export FIRMWARE=1
      export FIRMWARE_PATH1=""
      FIRMWARE_PATH1="$(escape_echo "${OPTARG}")"
      export HTML=1
      ;;
    p)
      check_path_input "${OPTARG}"
      export PROFILE=""
      PROFILE="$(escape_echo "${OPTARG}")"
      PROFILE="${INVOCATION_PATH}/scan-profiles/$(basename "${PROFILE}")"
      if ! [[ -f "${PROFILE}" ]]; then
        print_output "[-] No profile found!" "no_log"
        print_output "[*] Note: A profile needs to be stored in the EMBA scan-profile directory!" "no_log"
        exit 1
      fi
      ;;
    P)
      check_int "${OPTARG}"
      export MAX_MODS=""
      MAX_MODS="$(escape_echo "${OPTARG}")"
      ;;
    q)
      export DISABLE_DEEP=1
      ;;
    Q)
      export FULL_EMULATION=1
      ;;
    R)
      export RESCAN_SBOM=1
      # in VEX rescanning mode we only run F17
      export SELECT_MODULES=("f17")
      ;;
    r)
      # removes the extracted firmware as well as the emulation archives from l10
      export FINAL_FW_RM=1
      ;;
    s)
      export SHORT_PATH=1
      ;;
    S)
      export STRICT_MODE=1
      ;;
      #      t)
      #        export THREADED=1
      #        ;;
    T)
      check_int "${OPTARG}"
      export MAX_MOD_THREADS=""
      MAX_MOD_THREADS="$(escape_echo "${OPTARG}")"
      ;;
    U)
      export UPDATE=1
      ;;
    V)
      print_output "[+] EMBA version: ${ORANGE}${EMBA_VERSION}${NC}" "no_log"
      local lLOCAL_HASH=""
      if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if [[ -f .git/refs/heads/master ]]; then
          lLOCAL_HASH="$(head .git/refs/heads/master)"
          print_output "[+] EMBA git hash: ${ORANGE}${lLOCAL_HASH}${NC}" "no_log"
        fi
      fi
      exit 0
      ;;
    W)
      export HTML=1
      ;;
    X)
      check_version "${OPTARG}"
      export FW_VERSION=""
      FW_VERSION="$(escape_echo "${OPTARG}")"
      ;;
    y)
      export OVERWRITE_LOG=1
      ;;
    Y)
      check_vendor "${OPTARG}"
      export FW_VENDOR=""
      FW_VENDOR="$(escape_echo "${OPTARG}")"
      ;;
    z)
      export FORMAT_LOG=1
      ;;
    Z)
      check_vendor "${OPTARG}"
      export FW_DEVICE=""
      FW_DEVICE="$(escape_echo "${OPTARG}")"
      ;;
    *)
      print_output "[-] Invalid option" "no_log"
      print_help
      exit 1
      ;;
    esac
  done
}
