#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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

# Description:  This module looks for protection mechanisms in the binaries via checksec.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S12_binary_protection()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binary protection mechanisms"
  pre_module_reporter "${FUNCNAME[0]}"
  local lBIN_PROT_COUNTER=0
  local lCSV_LOG=""
  lCSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  lCSV_LOG="${CSV_DIR}""/""${lCSV_LOG}"
  local lBINARY=""
  local lCANARY=""
  local lFORTIFY=""
  local lNX=""
  local lPIE=""
  local lRELRO=""
  local lRPATH=""
  local lRUNPATH=""
  local lSYMBOLS=""
  local lFILE=""
  local lCSV_BIN_OUT=""


  if [[ -f "${EXT_DIR}"/checksec ]] ; then
    echo "RELRO;STACK CANARY;NX;PIE;RPATH;RUNPATH;Symbols;FORTIFY;Fortified;Fortifiable;FILE" >> "${lCSV_LOG}"
    printf "\t%-13.13s  %-16.16s  %-11.11s  %-11.11s  %-11.11s  %-11.11s  %-11.11s  %-5.5s  %s\n" \
      "RELRO" "CANARY" "NX" "PIE" "RPATH" "RUNPATH" "SYMBOLS" "FORTIFY" "FILE" | tee -a "${TMP_DIR}"/s12.tmp

    for lBINARY in "${BINARIES[@]}" ; do
      if ( file "${lBINARY}" | grep -q ELF ) ; then
        lCSV_BIN_OUT=$("${EXT_DIR}"/checksec --format=csv --file="${lBINARY}")

        # we usually use ; instead of , for csv ...
        lCSV_BIN_OUT=${lCSV_BIN_OUT//,/\;}
        echo "${lCSV_BIN_OUT}" >> "${lCSV_LOG}"

        # coloring the output from csv
        lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ RELRO)/${RED_}&${NC_}/g")
        lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(Partial\ RELRO)/${ORANGE_}&${NC_}/g")
        lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(Full\ RELRO)/${GREEN_}&${NC_}/g")

        lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(NX\ enabled)/${GREEN_}&${NC_}/g")
        lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(NX\ disabled)/${RED_}&${NC_}/g")

        if [[ "${lCSV_BIN_OUT}" == *"No PIE"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ PIE)/${RED_}&${NC_}/g")
        elif [[ "${lCSV_BIN_OUT}" == *"PIE enabled"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(PIE\ enabled)/${GREEN_}&${NC_}/g")
        elif [[ "${lCSV_BIN_OUT}" == *"DSO"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(DSO)/${ORANGE_}&${NC_}/g")
        elif [[ "$(echo "${lCSV_BIN_OUT}" | cut -d\; -f4)" == "REL" ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | awk -F ';' -v repl="${ORANGE_}REL${NC_}" '$4 == "REL"{OFS = ";"; $4=repl}1')
        fi

        if [[ "${lCSV_BIN_OUT}" == *"No Canary found"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ Canary\ found)/${RED_}&${NC_}/g")
        else
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(Canary\ found)/${GREEN_}&${NC_}/g")
        fi

        if [[ "${lCSV_BIN_OUT}" == *"No RPATH"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ RPATH)/${GREEN_}&${NC_}/g")
        else
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(RPATH)/${RED_}&${NC_}/g")
        fi

        if [[ "${lCSV_BIN_OUT}" == *"No RUNPATH"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ RUNPATH)/${GREEN_}&${NC_}/g")
        else
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(RUNPATH)/${RED_}&${NC_}/g")
        fi

        if [[ "${lCSV_BIN_OUT}" == *"No Symbols"* ]]; then
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(No\ Symbols)/${GREEN_}&${NC_}/g")
        else
          lCSV_BIN_OUT=$(echo "${lCSV_BIN_OUT}" | sed -r "s/(Symbols)/${RED_}&${NC_}/g")
        fi

        lRELRO=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f1)
        lCANARY=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f2)
        lNX=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f3)
        lPIE=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f4)
        lRPATH=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f5)
        lRUNPATH=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f6)
        lSYMBOLS=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f7)
        lFORTIFY=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f8)
        lFILE=$(echo "${lCSV_BIN_OUT}" | cut -d\; -f11)
        lFILE=$(print_path "${lFILE}")

        printf "\t%-22.22s  %-25.25s  %-20.20s  %-20.20s  %-20.20s  %-20.20s  %-20.20s  %-5.5s  %s\n" \
          "${lRELRO}" "${lCANARY}" "${lNX}" "${lPIE}" "${lRPATH}" "${lRUNPATH}" "${lSYMBOLS}" "${lFORTIFY}" "${lFILE}" | tee -a "${TMP_DIR}"/s12.tmp || true
        lBIN_PROT_COUNTER=$((lBIN_PROT_COUNTER+1))
      fi
    done

    [[ -f "${TMP_DIR}"/s12.tmp ]] && cat "${TMP_DIR}"/s12.tmp >> "${LOG_FILE}"
  else
    print_output "[-] Binary protection analyzer ${ORANGE}${EXT_DIR}/checksec${NC} not found - check your installation."
  fi

  module_end_log "${FUNCNAME[0]}" "${lBIN_PROT_COUNTER}"
}

