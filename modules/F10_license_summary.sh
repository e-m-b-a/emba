#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Collects license details and gives a list with binaries, identified version and
#               the corresponding license (if available). The license details are maintained in the
#               configuration file config/bin_version_strings.cfg


F10_license_summary() {
  module_log_init "${FUNCNAME[0]}"
  module_title "License inventory"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCOUNT_LIC=0
  local lLICENSE_DETECTION_STATIC_ARR=()
  local lLICENSE_DETECTION_DYN_ARR=()
  local lENTRY=""
  local lVERSION_RULE="NA"
  local lCSV_RULE="NA"
  local lBINARY=""
  local lVERSION=""
  local lLICENSE=""
  local lTYPE=""

  mapfile -t lLICENSE_DETECTION_STATIC_ARR < <(grep -v "version_rule" "${CSV_DIR}"/s09_*.csv 2>/dev/null | cut -d\; -f1,4,5 | sort -u || true)
  mapfile -t lLICENSE_DETECTION_DYN_ARR < <(grep -v "version_rule" "${CSV_DIR}"/s116_*.csv 2>/dev/null | cut -d\; -f1,4,5 |sort -u || true)
  # TODO: Currently the final kernel details from s25 are missing

  write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

  # static version detection
  if [[ "${#lLICENSE_DETECTION_STATIC_ARR[@]}" -gt 0 ]]; then
    lTYPE="static"
    for lENTRY in "${lLICENSE_DETECTION_STATIC_ARR[@]}"; do
      if [[ -z "${lENTRY}" ]]; then
        continue
      fi

      # first field
      lBINARY="${lENTRY/;*}"
      # middle field
      lVERSION="${lENTRY#*;}"
      lVERSION="${lVERSION/;*}"
      # last field
      lLICENSE="${lENTRY##*;}"

      print_output "[+] Binary: ${ORANGE}$(basename "${lBINARY}" | cut -d\  -f1)${GREEN} / Version: ${ORANGE}${lVERSION}${GREEN} / License: ${ORANGE}${lLICENSE}${NC}"
      write_csv_log "${lBINARY}" "${lVERSION_RULE}" "${lVERSION}" "${lCSV_RULE}" "${lLICENSE}" "${lTYPE}"
      ((lCOUNT_LIC+=1))
    done
  fi

  # Qemu version detection
  if [[ "${#lLICENSE_DETECTION_DYN_ARR[@]}" -gt 0 ]]; then
    lTYPE="emulation"
    for lENTRY in "${lLICENSE_DETECTION_DYN_ARR[@]}"; do
      if [[ -z "${lENTRY}" ]]; then
        continue
      fi

      # first field
      lBINARY="${lENTRY/;*}"
      # middle field
      lVERSION="${lENTRY#*;}"
      lVERSION="${lVERSION/;*}"
      # last field
      lLICENSE="${lENTRY##*;}"

      print_output "[+] Binary: ${ORANGE}$(basename "${lBINARY}")${GREEN} / Version: ${ORANGE}${lVERSION}${GREEN} / License: ${ORANGE}${lLICENSE}${NC}"
      write_csv_log "${lBINARY}" "${lVERSION_RULE}" "${lVERSION}" "${lCSV_RULE}" "${lLICENSE}" "${lTYPE}"
      ((lCOUNT_LIC+=1))
    done
  fi

  module_end_log "${FUNCNAME[0]}" "${lCOUNT_LIC}"
}
