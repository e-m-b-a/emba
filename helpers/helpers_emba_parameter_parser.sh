#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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

# Description: Parameter parsing


emba_parameter_parsing() {
  while getopts a:bBA:cC:d:De:Ef:Fhik:l:m:N:o:p:P:qQRrsStT:UVX:yY:WzZ: OPT ; do
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
        ! [[ "${ONLY_DEP}" =~ [12] ]] && { echo "Error: Invalid value for ONLY_DEP. Valid values are 1 (host and container) or 2 (container only)."; exit 1; }
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
        readonly FIRMWARE_PATH_BAK="${FIRMWARE_PATH}"   # as we rewrite the firmware path variable in the pre-checker phase
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
          # this is little hack to enable kernel config only checks
          export FIRMWARE_PATH="${KERNEL_CONFIG}"
        fi
        ;;
      l)
        check_path_input "${OPTARG}"
        export LOG_DIR=""
        LOG_DIR="$(escape_echo "${OPTARG}")"
        export TMP_DIR="${LOG_DIR}""/tmp"
        export CSV_DIR="${LOG_DIR}""/csv_logs"
        export JSON_DIR="${LOG_DIR}""/json_logs"
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
