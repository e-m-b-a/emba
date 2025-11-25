#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Collects information from s-phase and builds tags that can be used for further tools
#               like dependency track or EMBArk


F14_tag_builder() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final Tag builder"
  pre_module_reporter "${FUNCNAME[0]}"

  local lTAGs_ARR=("EMBA")
  local lTAG=""
  local lARCH=""

  if [[ -n "${FW_VENDOR}" ]]; then
    lTAGs_ARR+=("${FW_VENDOR}")
  fi

  # architecture
  if [[ -f "${P99_LOG}" ]]; then
    lARCH="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f2 | grep -v "NA" || true)"
    lTAGs_ARR+=("${lARCH}")
  fi

  # scripting languages
  if [[ -f "${S22_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f2 || true) -gt 0 ]] || \
       [[ $(grep -a "\[\*\]\ Statistics1:" "${S22_LOG}" | cut -d: -f2 || true) -gt 0 ]]; then
      lTAGs_ARR+=("PHP")
    fi
  fi
  if [[ -f "${S21_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S21_LOG}" | cut -d: -f2 || true) ]]; then
      lTAGs_ARR+=("Python")
    fi
  fi
  if [[ -f "${S23_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S23_LOG}" | cut -d: -f3 || true) -gt 0 ]]; then
      lTAGs_ARR+=("LUA")
    fi
  fi

  # OS detection
  if [[ -f "${S03_LOG}" ]]; then
    if [[ $(grep -a -c "verified Linux" "${S03_LOG}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("Linux")
    fi
  fi
  if [[ -f "${S25_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S25_LOG}" | cut -d: -f2 || true) =~ [0-9]+\.[0-9]+(\.[0-9]+)+? ]]; then
      lTAGs_ARR+=("Linux")
    fi
  fi
  if os_detector | grep -q "verified.*Linux"; then
    lTAGs_ARR+=("Linux")
  fi

  # other module tags like passwords cracked
  if [[ -f "${S109_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S109_LOG}" | cut -d: -f2 || true) -gt 0 ]]; then
      lTAGs_ARR+=("cracked")
    fi
  fi

  # emulation
  if [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    if [[ $(grep -c "TCP ok;" "${L10_SYS_EMU_RESULTS}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("emulated")
    fi
  fi
  if [[ -f "${L35_CSV_LOG}" ]]; then
    if [[ $(grep -v -c "Source" "${L35_CSV_LOG}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("exploited")
    fi
  fi

  mapfile -t lTAGs_ARR < <(printf "%s\n" "${lTAGs_ARR[@]}" | sort -u)

  jo -p tags=$(jo -a "${lTAGs_ARR[@]}") > "${LOG_PATH_MODULE}"/tags.json
  if [[ -f "${LOG_PATH_MODULE}"/tags.json ]]; then
    print_output "[*] Generated tags:" "" "${LOG_PATH_MODULE}"/tags.json
    for lTAG in "${lTAGs_ARR[@]}"; do
      print_output "$(indent "$(orange "${lTAG}")")"
    done
    print_ln
  fi

  module_end_log "${FUNCNAME[0]}" "${#lTAGs_ARR[@]}"
}
