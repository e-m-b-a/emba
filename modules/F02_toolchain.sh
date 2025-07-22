#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner
# Based on the original idea from Thomas Riedmaier

# Description:  Collects further details that are useful for building/identifying a working toolchain


F02_toolchain() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Toolchain overview"
  pre_module_reporter "${FUNCNAME[0]}"

  local lKERNEL_V_ARR=()
  local lKERNEL_V_ARR_S25=()
  local lKERNEL_STRING_ARR=()
  local lCOMPILE_FILES_ARR=()
  local lBINARY_DETAILS_ARR=()
  local lBINARY_FLAGS_ARR=()
  local lBINARY_COMPILER_GUESSED_ARR=()

  local lGCC_VERSION_ARR=()
  local lGCC_VERSION_1_ARR=()
  local lCOMPILE_FILE_NAME_GCC_DATE_ARR=()

  local lKERNEL_V=""
  local lKERNEL_VERSION=""
  local lKERNEL_CONFIG=""
  local lK_RELEASE_DATE=""

  local lKERNEL_STR=""
  local lGCC_VERSION=""
  local lGCC_VERSION_STRIPPED=""
  local lGCC_RELEASE_DATE=""

  local lCOMPILE_FILE=""
  local lCOMPILE_FILE_NAME=""
  local lCOMPILE_FILE_NAME_GCC_DATE=""
  local lBINARY_DETAILS=""
  local lBINARY_END=""
  local lBINARY_ARCH=""
  local lBINARY_MACHINE=""
  local lBINARY_COMPILER_GUESSED=""
  local lBINARY_FLAG=""

  local lNEG_LOG=0

  mapfile -t lKERNEL_V_ARR < <(tail -n +2 "${CSV_DIR}"/s24_*.csv 2>/dev/null | cut -d\; -f2,6 | grep -v -e '^$' | grep -v "^;" | sort -u || true)
  mapfile -t lKERNEL_V_ARR_S25 < <(tail -n +2 "${CSV_DIR}"/s25_*.csv 2>/dev/null | cut -d\; -f2 | grep -v -e '^$' | sort -u || true)
  mapfile -t lKERNEL_STRING_ARR < <(tail -n +2 "${CSV_DIR}"/s24_*.csv 2>/dev/null | cut -d\; -f1 | grep -v -e '^$' | sort -u || true)

  mapfile -t lCOMPILE_FILES_ARR < <(tail -n +2 "${CSV_DIR}"/s95_*.csv 2>/dev/null | cut -d\; -f2 | grep "libstdc++.so.6." | sort -u || true)

  mapfile -t lBINARY_DETAILS_ARR < <(tail -n +2 "${CSV_DIR}"/p99_*.csv 2>/dev/null | cut -d\; -f4,7 | cut -d\, -f1-3 | grep "ELF" | grep -v -e '^$' | sort -u || true)
  mapfile -t lBINARY_FLAGS_ARR < <(tail -n +2 "${CSV_DIR}"/p99_*.csv 2>/dev/null | cut -d\; -f5 | grep -v -e '^$' | tr ',' '\n' | grep -v "unknown\|NA" | sort -u || true)
  mapfile -t lBINARY_COMPILER_GUESSED_ARR < <(cut -d\; -f6 "${CSV_DIR}"/p99_*.csv 2>/dev/null | grep -v -e '^$' | tr ',' '\n' | grep "GCC\|Buildroot\|GNU" | awk '{print $1,$2,$3}' | tr -d ':' | sort -u || true)
  # results in some entries like the following
  # GCC (Buildroot 2012.11.1)
  # GCC (GNU) 3.3.2

  # kernel with release date from s24 (s25 only holds the kernel version and is used as fallback)
  if [[ "${#lKERNEL_V_ARR[@]}" -gt 0 ]]; then
    for lKERNEL_V in "${lKERNEL_V_ARR[@]}"; do
      if [[ -z "${lKERNEL_V}" ]]; then
        continue
      fi
      lKERNEL_VERSION="${lKERNEL_V/;*}"
      lKERNEL_CONFIG="${lKERNEL_V/*;}"

      lK_RELEASE_DATE=""
      if [[ -f "${CONFIG_DIR}"/kernel_details.csv ]]; then
        lK_RELEASE_DATE=$(grep "^linux-${lKERNEL_VERSION};" "${CONFIG_DIR}"/kernel_details.csv | cut -d\; -f2 | sort -u || true)
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${lK_RELEASE_DATE}" ]] && [[ "${lKERNEL_VERSION}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          lK_RELEASE_DATE=$(grep "^linux-${lKERNEL_VERSION%%\.0};" "${CONFIG_DIR}"/kernel_details.csv || true)
          lK_RELEASE_DATE="${lK_RELEASE_DATE/*;}"
        fi
      fi

      if [[ -n "${lK_RELEASE_DATE}" ]]; then
        if [[ -n "${lKERNEL_CONFIG}" ]]; then
          print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_VERSION}${GREEN} which was released on ${ORANGE}${lK_RELEASE_DATE}${GREEN} - kernel configuration available."
        else
          print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_VERSION}${GREEN} which was released on ${ORANGE}${lK_RELEASE_DATE}${GREEN} - no kernel configuration available."
        fi
      else
        if [[ -n "${lKERNEL_CONFIG}" ]]; then
          print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_VERSION}${GREEN} without a known release date - kernel configuration available."
        else
          print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_VERSION}${GREEN} without a known release date - no kernel configuration available."
        fi
      fi
      write_link "s24"
      lNEG_LOG=1
    done
    if [[ -n "${lK_RELEASE_DATE}" ]]; then
      print_ln
    fi
  elif [[ "${#lKERNEL_V_ARR_S25[@]}" -gt 0 ]]; then
    for lKERNEL_V in "${lKERNEL_V_ARR_S25[@]}"; do
      if [[ -z "${lKERNEL_V}" ]]; then
        continue
      fi
      lK_RELEASE_DATE=""
      if [[ -f "${CONFIG_DIR}"/kernel_details.csv ]]; then
        lK_RELEASE_DATE=$(grep "^linux-${lKERNEL_V};" "${CONFIG_DIR}"/kernel_details.csv | cut -d\; -f2 | sort -u || true)
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${lK_RELEASE_DATE}" ]] && [[ "${lKERNEL_V}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          lK_RELEASE_DATE=$(grep "^linux-${lKERNEL_V%%\.0};" "${CONFIG_DIR}"/kernel_details.csv || true)
          lK_RELEASE_DATE="${lK_RELEASE_DATE/*;}"
        fi
      fi
      if [[ -n "${lK_RELEASE_DATE}" ]]; then
        print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_V}${GREEN} which was released on ${ORANGE}${lK_RELEASE_DATE}${GREEN} - no kernel configuration available."
      else
        print_output "[+] Identified kernel version ${ORANGE}${lKERNEL_V}${GREEN} without a known release date - no kernel configuration available."
      fi
    done
    print_ln
  fi

  # kernel version string with GCC notes
  if [[ "${#lKERNEL_STRING_ARR[@]}" -gt 0 ]]; then
    for lKERNEL_STR in "${lKERNEL_STRING_ARR[@]}"; do
      if [[ -z "${lKERNEL_STR}" ]]; then
        continue
      fi

      mapfile -t lGCC_VERSION_ARR < <(echo "${lKERNEL_STR}" | grep -o -i -E "gcc version [0-9](\.[0-9]+)+?" | sort -u || true)
      mapfile -t lGCC_VERSION_1_ARR < <(echo "${lKERNEL_STR}" | grep -o -E "GCC [0-9](\.[0-9]+)+?" | sort -u || true)
      lGCC_VERSION_ARR=( "${lGCC_VERSION_ARR[@]}" "${lGCC_VERSION_1_ARR[@]}")
      mapfile -t lGCC_VERSION_ARR < <(printf "%s\n" "${lGCC_VERSION_ARR[@]}" | sort -u)

      if [[ "${#lGCC_VERSION_ARR[@]}" -gt 0 ]]; then
        for lGCC_VERSION in "${lGCC_VERSION_ARR[@]}"; do
          # print_output "[*] Testing GCC version ${lGCC_VERSION}" "no_log"
          lGCC_VERSION_STRIPPED=$(echo "${lGCC_VERSION}" | grep -o -E "[0-9](\.[0-9]+)+?" || true)
          if [[ -n "${lGCC_VERSION_STRIPPED}" ]]; then
            lGCC_RELEASE_DATE=$(grep "\ ${lGCC_VERSION_STRIPPED};" "${CONFIG_DIR}"/gcc_details.csv || true)
            lGCC_RELEASE_DATE="${lGCC_RELEASE_DATE/*;}"
            # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
            if [[ -z "${lGCC_RELEASE_DATE}" ]] && [[ "${lGCC_VERSION_STRIPPED}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
              lGCC_RELEASE_DATE=$(grep "\ ${lGCC_VERSION_STRIPPED%%\.0};" "${CONFIG_DIR}"/gcc_details.csv || true)
              lGCC_RELEASE_DATE="${lGCC_RELEASE_DATE/*;}"
            fi
            if [[ -n "${lGCC_RELEASE_DATE}" ]]; then
              print_output "[+] Identified GCC version ${ORANGE}${lGCC_VERSION}${GREEN} released on ${ORANGE}${lGCC_RELEASE_DATE:-"NA"}${GREEN} in the Linux kernel identifier string."
            else
              print_output "[+] Identified GCC version ${ORANGE}${lGCC_VERSION}${GREEN} without a known release date in the Linux kernel identifier string."
            fi
            write_link "s24"
            print_output "$(indent "$(orange "${lKERNEL_STR}")")"
            lNEG_LOG=1
          fi
        done
      fi
    done
    print_ln
  fi

  # libstdc++.so -> GCC version
  # https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html
  if [[ "${#lCOMPILE_FILES_ARR[@]}" -gt 0 ]]; then
    for lCOMPILE_FILE in "${lCOMPILE_FILES_ARR[@]}"; do
      if [[ -z "${lCOMPILE_FILE}" ]]; then
        continue
      fi
      if ! [[ "${lCOMPILE_FILE}" == *"libstdc"* ]]; then
        # currently we only handle libstdc++
        continue
      fi

      lCOMPILE_FILE_NAME=$(basename "${lCOMPILE_FILE}")
      mapfile -t lCOMPILE_FILE_NAME_GCC_DATE_ARR < <(grep ";${lCOMPILE_FILE_NAME};" "${CONFIG_DIR}"/gcc_libstdc_details.csv | sort -u || true)
      for lCOMPILE_FILE_NAME_GCC_DATE in "${lCOMPILE_FILE_NAME_GCC_DATE_ARR[@]}"; do
        lGCC_VERSION=$(echo "${lCOMPILE_FILE_NAME_GCC_DATE}" | cut -d\; -f1 || true)
        lGCC_RELEASE_DATE=$(echo "${lCOMPILE_FILE_NAME_GCC_DATE}" | cut -d\; -f3 || true)
        if [[ -n "${lGCC_VERSION}" ]] || [[ -n "${lGCC_RELEASE_DATE}" ]]; then
          print_output "[+] Identified GCC version ${ORANGE}${lGCC_VERSION:-"NA"}${GREEN} released on ${ORANGE}${lGCC_RELEASE_DATE:-"NA"}${GREEN} via libstdc++ ${ORANGE}${lCOMPILE_FILE_NAME}${GREEN}."
          write_link "s95"
          lNEG_LOG=1
        fi
      done
    done
    print_ln
  fi

  if [[ "${#lBINARY_DETAILS_ARR[@]}" -gt 0 ]]; then
    local lTEMP_ARR=()
    for lBINARY_DETAILS in "${lBINARY_DETAILS_ARR[@]}"; do
      lBINARY_END="NA"
      lBINARY_ARCH="NA"
      lBINARY_MACHINE="${lBINARY_DETAILS/;*}"
      lBINARY_DETAILS="${lBINARY_DETAILS/*;}"
      if [[ "${lBINARY_DETAILS}" == *"LSB"* ]]; then
        lBINARY_END="little"
      elif [[ "${lBINARY_DETAILS}" == *"MSB"* ]]; then
        lBINARY_END="big"
      fi
      lBINARY_ARCH="${lBINARY_DETAILS#*, }"
      if [[ "${lTEMP_ARR[*]}" == *"${lBINARY_ARCH};${lBINARY_END};${lBINARY_MACHINE}"* ]]; then
        continue
      fi

      print_output "[+] Identified firmware architecture ${ORANGE}${lBINARY_ARCH}${GREEN} / endianes ${ORANGE}${lBINARY_END}${GREEN} / machine configuration ${ORANGE}${lBINARY_MACHINE}${GREEN} on binary level."
      write_link "p99"
      lTEMP_ARR+=( "${lBINARY_ARCH};${lBINARY_END};${lBINARY_MACHINE}" )
      lNEG_LOG=1
    done
    print_ln
  fi

  if [[ "${#lBINARY_COMPILER_GUESSED_ARR[@]}" -gt 0 ]]; then
    for lBINARY_COMPILER_GUESSED in "${lBINARY_COMPILER_GUESSED_ARR[@]}"; do
      if [[ -z "${lBINARY_COMPILER_GUESSED}" ]]; then
        continue
      fi

      # print_output "[*] Testing GCC version ${lBINARY_COMPILER_GUESSED}" "no_log"
      if [[ "${lBINARY_COMPILER_GUESSED}" == "*Buildroot" ]]; then
        # e.g. GCC (Buildroot 2012.11.1)
        lGCC_VERSION_STRIPPED=$(echo "${lBINARY_COMPILER_GUESSED}" | grep -o -E " [0-9]{4}\.[0-9]+(\.[0-9]+)+?" | head -1 || true)
      else
        lGCC_VERSION_STRIPPED=$(echo "${lBINARY_COMPILER_GUESSED}" | grep -o -E " [0-9]\.[0-9](\.[0-9]+)+?" | head -1 || true)
      fi
      lGCC_VERSION_STRIPPED="${lGCC_VERSION_STRIPPED/ }"
      if [[ -n "${lGCC_VERSION_STRIPPED}" ]]; then
        lGCC_RELEASE_DATE=$(grep "\ ${lGCC_VERSION_STRIPPED};" "${CONFIG_DIR}"/gcc_details.csv || true)
        lGCC_RELEASE_DATE="${lGCC_RELEASE_DATE/*;}"
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${lGCC_RELEASE_DATE}" ]] && [[ "${lGCC_VERSION_STRIPPED}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          lGCC_RELEASE_DATE=$(grep "\ ${lGCC_VERSION_STRIPPED%%\.0};" "${CONFIG_DIR}"/gcc_details.csv || true)
          lGCC_RELEASE_DATE="${lGCC_RELEASE_DATE/*;}"
        fi
        if [[ -n "${lGCC_RELEASE_DATE}" ]]; then
          print_output "[+] Identified possible GCC version on binary level ${ORANGE}${lBINARY_COMPILER_GUESSED} / ${lGCC_VERSION_STRIPPED}${GREEN} released on ${ORANGE}${lGCC_RELEASE_DATE}${GREEN}."
        else
          print_output "[+] Identified possible GCC version on binary level ${ORANGE}${lBINARY_COMPILER_GUESSED} / ${lGCC_VERSION_STRIPPED}${GREEN} without a known release date."
        fi
        lNEG_LOG=1
      fi
    done
  fi

  if [[ "${#lBINARY_FLAGS_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Identified the following used binary flags:"
    for lBINARY_FLAG in "${lBINARY_FLAGS_ARR[@]}"; do
      print_output "$(indent "$(orange "${lBINARY_FLAG}")")"
    done
    print_ln
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}
