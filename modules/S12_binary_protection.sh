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
  local BIN_PROT_COUNTER=0
  local CSV_LOG=""
  CSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  CSV_LOG="${CSV_DIR}""/""${CSV_LOG}"
  local BINARY=""
  local CANARY=""
  local FORTIFY=""
  local NX=""
  local PIE=""
  local RELRO=""
  local RPATH=""
  local RUNPATH=""
  local SYMBOLS=""
  local FILE=""
  local CSV_BIN_OUT=""


  if [[ -f "${EXT_DIR}"/checksec ]] ; then
    echo "RELRO;STACK CANARY;NX;PIE;RPATH;RUNPATH;Symbols;FORTIFY;Fortified;Fortifiable;FILE" >> "${CSV_LOG}"
    printf "\t%-13.13s  %-16.16s  %-11.11s  %-11.11s  %-11.11s  %-11.11s  %-11.11s  %-5.5s  %s\n" \
      "RELRO" "CANARY" "NX" "PIE" "RPATH" "RUNPATH" "SYMBOLS" "FORTIFY" "FILE" | tee -a "${TMP_DIR}"/s12.tmp

    for BINARY in "${BINARIES[@]}" ; do
      if ( file "${BINARY}" | grep -q ELF ) ; then
        CSV_BIN_OUT=$("${EXT_DIR}"/checksec --format=csv --file="${BINARY}")

        # we usually use ; instead of , for csv ...
        CSV_BIN_OUT=${CSV_BIN_OUT//,/\;}
        echo "${CSV_BIN_OUT}" >> "${CSV_LOG}"

        # coloring the output from csv
        CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ RELRO)/${RED_}&${NC_}/g")
        CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(Partial\ RELRO)/${ORANGE_}&${NC_}/g")
        CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(Full\ RELRO)/${GREEN_}&${NC_}/g")

        CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(NX\ enabled)/${GREEN_}&${NC_}/g")
        CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(NX\ disabled)/${RED_}&${NC_}/g")

        if [[ "${CSV_BIN_OUT}" == *"No PIE"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ PIE)/${RED_}&${NC_}/g")
        elif [[ "${CSV_BIN_OUT}" == *"PIE enabled"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(PIE\ enabled)/${GREEN_}&${NC_}/g")
        elif [[ "${CSV_BIN_OUT}" == *"DSO"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(DSO)/${ORANGE_}&${NC_}/g")
        elif [[ "$(echo "${CSV_BIN_OUT}" | cut -d\; -f4)" == "REL" ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | awk -F ';' -v repl="${ORANGE_}REL${NC_}" '$4 == "REL"{OFS = ";"; $4=repl}1')
        fi

        if [[ "${CSV_BIN_OUT}" == *"No Canary found"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ Canary\ found)/${RED_}&${NC_}/g")
        else
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(Canary\ found)/${GREEN_}&${NC_}/g")
        fi

        if [[ "${CSV_BIN_OUT}" == *"No RPATH"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ RPATH)/${GREEN_}&${NC_}/g")
        else
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(RPATH)/${RED_}&${NC_}/g")
        fi

        if [[ "${CSV_BIN_OUT}" == *"No RUNPATH"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ RUNPATH)/${GREEN_}&${NC_}/g")
        else
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(RUNPATH)/${RED_}&${NC_}/g")
        fi

        if [[ "${CSV_BIN_OUT}" == *"No Symbols"* ]]; then
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(No\ Symbols)/${GREEN_}&${NC_}/g")
        else
          CSV_BIN_OUT=$(echo "${CSV_BIN_OUT}" | sed -r "s/(Symbols)/${RED_}&${NC_}/g")
        fi

        RELRO=$(echo "${CSV_BIN_OUT}" | cut -d\; -f1)
        CANARY=$(echo "${CSV_BIN_OUT}" | cut -d\; -f2)
        NX=$(echo "${CSV_BIN_OUT}" | cut -d\; -f3)
        PIE=$(echo "${CSV_BIN_OUT}" | cut -d\; -f4)
        RPATH=$(echo "${CSV_BIN_OUT}" | cut -d\; -f5)
        RUNPATH=$(echo "${CSV_BIN_OUT}" | cut -d\; -f6)
        SYMBOLS=$(echo "${CSV_BIN_OUT}" | cut -d\; -f7)
        FORTIFY=$(echo "${CSV_BIN_OUT}" | cut -d\; -f8)
        FILE=$(echo "${CSV_BIN_OUT}" | cut -d\; -f11)
        FILE=$(print_path "${FILE}")

        printf "\t%-22.22s  %-25.25s  %-20.20s  %-20.20s  %-20.20s  %-20.20s  %-20.20s  %-5.5s  %s\n" \
          "${RELRO}" "${CANARY}" "${NX}" "${PIE}" "${RPATH}" "${RUNPATH}" "${SYMBOLS}" "${FORTIFY}" "${FILE}" | tee -a "${TMP_DIR}"/s12.tmp || true
        BIN_PROT_COUNTER=$((BIN_PROT_COUNTER+1))
      fi
    done

    [[ -f "${TMP_DIR}"/s12.tmp ]] && cat "${TMP_DIR}"/s12.tmp >> "${LOG_FILE}"
  else
    print_output "[-] Binary protection analyzer ${ORANGE}${EXT_DIR}/checksec${NC} not found - check your installation."
  fi

  module_end_log "${FUNCNAME[0]}" "${BIN_PROT_COUNTER}"
}

