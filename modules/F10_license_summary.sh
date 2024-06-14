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

  local COUNT_LIC=0
  local LICENSE_DETECTION_STATIC=()
  local LICENSE_DETECTION_DYN=()
  local ENTRY=""
  local VERSION_RULE="NA"
  local CSV_RULE="NA"
  local BINARY=""
  local VERSION=""
  local LICENSE=""
  local TYPE=""

  mapfile -t LICENSE_DETECTION_STATIC < <(grep -v "version_rule" "${CSV_DIR}"/s09_*.csv 2>/dev/null | cut -d\; -f1,4,5 | sort -u || true)
  mapfile -t LICENSE_DETECTION_DYN < <(grep -v "version_rule" "${CSV_DIR}"/s116_*.csv 2>/dev/null | cut -d\; -f1,4,5 |sort -u || true)
  # TODO: Currently the final kernel details from s25 are missing

  write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"

  # static version detection
  if [[ "${#LICENSE_DETECTION_STATIC[@]}" -gt 0 ]]; then
    TYPE="static"
    for ENTRY in "${LICENSE_DETECTION_STATIC[@]}"; do
      if [[ -z "${ENTRY}" ]]; then
        continue
      fi

      # first field
      BINARY="${ENTRY/;*}"
      # middle field
      VERSION="${ENTRY#*;}"
      VERSION="${VERSION/;*}"
      # last field
      LICENSE="${ENTRY##*;}"

      print_output "[+] Binary: ${ORANGE}$(basename "${BINARY}" | cut -d\  -f1)${GREEN} / Version: ${ORANGE}${VERSION}${GREEN} / License: ${ORANGE}${LICENSE}${NC}"
      write_csv_log "${BINARY}" "${VERSION_RULE}" "${VERSION}" "${CSV_RULE}" "${LICENSE}" "${TYPE}"
      ((COUNT_LIC+=1))
    done
  fi

  # Qemu version detection
  if [[ "${#LICENSE_DETECTION_DYN[@]}" -gt 0 ]]; then
    TYPE="emulation"
    for ENTRY in "${LICENSE_DETECTION_DYN[@]}"; do
      if [[ -z "${ENTRY}" ]]; then
        continue
      fi

      # first field
      BINARY="${ENTRY/;*}"
      # middle field
      VERSION="${ENTRY#*;}"
      VERSION="${VERSION/;*}"
      # last field
      LICENSE="${ENTRY##*;}"

      print_output "[+] Binary: ${ORANGE}$(basename "${BINARY}")${GREEN} / Version: ${ORANGE}${VERSION}${GREEN} / License: ${ORANGE}${LICENSE}${NC}"
      write_csv_log "${BINARY}" "${VERSION_RULE}" "${VERSION}" "${CSV_RULE}" "${LICENSE}" "${TYPE}"
      ((COUNT_LIC+=1))
    done
  fi

  module_end_log "${FUNCNAME[0]}" "${COUNT_LIC}"
}
