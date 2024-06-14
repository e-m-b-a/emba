#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
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

  local KERNEL_V_ARR=()
  local KERNEL_V_ARR_S25=()
  local KERNEL_STRING_ARR=()
  local COMPILE_FILES_ARR=()
  local BINARY_DETAILS_ARR=()
  local BINARY_FLAGS_ARR=()
  local BINARY_COMPILER_GUESSED_ARR=()

  local GCC_VERSION_ARR=()
  local GCC_VERSION_1_ARR=()
  local COMPILE_FILE_NAME_GCC_DATE_ARR=()

  local KERNEL_V=""
  local KERNEL_VERSION=""
  local KERNEL_CONFIG=""
  local K_RELEASE_DATE=""

  local KERNEL_STR=""
  local GCC_VERSION=""
  local GCC_VERSION_STRIPPED=""
  local GCC_RELEASE_DATE=""

  local COMPILE_FILE=""
  local COMPILE_FILE_NAME=""
  local COMPILE_FILE_NAME_GCC_DATE=""
  local BINARY_DETAILS=""
  local BINARY_END=""
  local BINARY_ARCH=""
  local BINARY_MACHINE=""
  local BINARY_COMPILER_GUESSED=""
  local BINARY_FLAG=""

  local NEG_LOG=0

  mapfile -t KERNEL_V_ARR < <(tail -n +2 "${CSV_DIR}"/s24_*.csv 2>/dev/null | cut -d\; -f2,6 | grep -v -e '^$' | sort -u || true)
  mapfile -t KERNEL_V_ARR_S25 < <(tail -n +2 "${CSV_DIR}"/s25_*.csv 2>/dev/null | cut -d\; -f2 | grep -v -e '^$' | sort -u || true)
  mapfile -t KERNEL_STRING_ARR < <(tail -n +2 "${CSV_DIR}"/s24_*.csv 2>/dev/null | cut -d\; -f1 | grep -v -e '^$' | sort -u || true)

  mapfile -t COMPILE_FILES_ARR < <(tail -n +2 "${CSV_DIR}"/s95_*.csv 2>/dev/null | cut -d\; -f2 | grep "libstdc++.so.6." | sort -u || true)

  mapfile -t BINARY_DETAILS_ARR < <(tail -n +2 "${CSV_DIR}"/p99_*.csv 2>/dev/null | cut -d\; -f4,7 | cut -d\, -f1-3 | grep "ELF" | grep -v -e '^$' | sort -u || true)
  mapfile -t BINARY_FLAGS_ARR < <(tail -n +2 "${CSV_DIR}"/p99_*.csv 2>/dev/null | cut -d\; -f5 | grep -v -e '^$' | tr ',' '\n' | grep -v "unknown" | sort -u || true)
  mapfile -t BINARY_COMPILER_GUESSED_ARR < <(cut -d\; -f6 "${CSV_DIR}"/p99_*.csv 2>/dev/null | grep -v -e '^$' | tr ',' '\n' | grep "GCC\|Buildroot\|GNU" | awk '{print $1,$2,$3}' | tr -d ':' | sort -u || true)
  # results in some entries like the following
  # GCC (Buildroot 2012.11.1)
  # GCC (GNU) 3.3.2

  # kernel with release date from s24 (s25 only holds the kernel version and is used as fallback)
  if [[ "${#KERNEL_V_ARR[@]}" -gt 0 ]]; then
    for KERNEL_V in "${KERNEL_V_ARR[@]}"; do
      if [[ -z "${KERNEL_V}" ]]; then
        continue
      fi
      KERNEL_VERSION="${KERNEL_V/;*}"
      KERNEL_CONFIG="${KERNEL_V/*;}"

      K_RELEASE_DATE=""
      if [[ -f "${CONFIG_DIR}"/kernel_details.csv ]]; then
        K_RELEASE_DATE=$(grep "^linux-${KERNEL_VERSION};" "${CONFIG_DIR}"/kernel_details.csv | cut -d\; -f2 | sort -u || true)
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${K_RELEASE_DATE}" ]] && [[ "${KERNEL_VERSION}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          K_RELEASE_DATE=$(grep "^linux-${KERNEL_VERSION%%\.0};" "${CONFIG_DIR}"/kernel_details.csv || true)
          K_RELEASE_DATE="${K_RELEASE_DATE/*;}"
        fi
      fi

      if [[ -n "${K_RELEASE_DATE}" ]]; then
        if [[ -n "${KERNEL_CONFIG}" ]]; then
          print_output "[+] Identified kernel version ${ORANGE}${KERNEL_VERSION}${GREEN} which was released on ${ORANGE}${K_RELEASE_DATE}${GREEN} - kernel configuration available."
        else
          print_output "[+] Identified kernel version ${ORANGE}${KERNEL_VERSION}${GREEN} which was released on ${ORANGE}${K_RELEASE_DATE}${GREEN} - no kernel configuration available."
        fi
      else
        if [[ -n "${KERNEL_CONFIG}" ]]; then
          print_output "[+] Identified kernel version ${ORANGE}${KERNEL_VERSION}${GREEN} without a known release date - kernel configuration available."
        else
          print_output "[+] Identified kernel version ${ORANGE}${KERNEL_VERSION}${GREEN} without a known release date - no kernel configuration available."
        fi
      fi
      write_link "s24"
      NEG_LOG=1
    done
    print_ln
  elif [[ "${#KERNEL_V_ARR_S25[@]}" -gt 0 ]]; then
    for KERNEL_V in "${KERNEL_V_ARR_S25[@]}"; do
      if [[ -z "${KERNEL_V}" ]]; then
        continue
      fi
      K_RELEASE_DATE=""
      if [[ -f "${CONFIG_DIR}"/kernel_details.csv ]]; then
        K_RELEASE_DATE=$(grep "^linux-${KERNEL_V};" "${CONFIG_DIR}"/kernel_details.csv | cut -d\; -f2 | sort -u || true)
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${K_RELEASE_DATE}" ]] && [[ "${KERNEL_V}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          K_RELEASE_DATE=$(grep "^linux-${KERNEL_V%%\.0};" "${CONFIG_DIR}"/kernel_details.csv || true)
          K_RELEASE_DATE="${K_RELEASE_DATE/*;}"
        fi
      fi
      if [[ -n "${K_RELEASE_DATE}" ]]; then
        print_output "[+] Identified kernel version ${ORANGE}${KERNEL_V}${GREEN} which was released on ${ORANGE}${K_RELEASE_DATE}${GREEN} - no kernel configuration available."
      else
        print_output "[+] Identified kernel version ${ORANGE}${KERNEL_V}${GREEN} without a known release date - no kernel configuration available."
      fi
    done
    print_ln
  fi

  # kernel version string with GCC notes
  if [[ "${#KERNEL_STRING_ARR[@]}" -gt 0 ]]; then
    for KERNEL_STR in "${KERNEL_STRING_ARR[@]}"; do
      if [[ -z "${KERNEL_STR}" ]]; then
        continue
      fi

      mapfile -t GCC_VERSION_ARR < <(echo "${KERNEL_STR}" | grep -o -i -E "gcc version [0-9](\.[0-9]+)+?" | sort -u || true)
      mapfile -t GCC_VERSION_1_ARR < <(echo "${KERNEL_STR}" | grep -o -E "GCC [0-9](\.[0-9]+)+?" | sort -u || true)
      GCC_VERSION_ARR=( "${GCC_VERSION_ARR[@]}" "${GCC_VERSION_1_ARR[@]}")

      if [[ "${#GCC_VERSION_ARR[@]}" -gt 0 ]]; then
        for GCC_VERSION in "${GCC_VERSION_ARR[@]}"; do
          # print_output "[*] Testing GCC version ${GCC_VERSION}" "no_log"
          GCC_VERSION_STRIPPED=$(echo "${GCC_VERSION}" | grep -o -E "[0-9](\.[0-9]+)+?" || true)
          if [[ -n "${GCC_VERSION_STRIPPED}" ]]; then
            GCC_RELEASE_DATE=$(grep "\ ${GCC_VERSION_STRIPPED};" "${CONFIG_DIR}"/gcc_details.csv || true)
            GCC_RELEASE_DATE="${GCC_RELEASE_DATE/*;}"
            # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
            if [[ -z "${GCC_RELEASE_DATE}" ]] && [[ "${GCC_VERSION_STRIPPED}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
              GCC_RELEASE_DATE=$(grep "\ ${GCC_VERSION_STRIPPED%%\.0};" "${CONFIG_DIR}"/gcc_details.csv || true)
              GCC_RELEASE_DATE="${GCC_RELEASE_DATE/*;}"
            fi
            if [[ -n "${GCC_RELEASE_DATE}" ]]; then
              print_output "[+] Identified GCC version ${ORANGE}${GCC_VERSION}${GREEN} released on ${ORANGE}${GCC_RELEASE_DATE:-"NA"}${GREEN} in the Linux kernel identifier string."
            else
              print_output "[+] Identified GCC version ${ORANGE}${GCC_VERSION}${GREEN} without a known release date in the Linux kernel identifier string."
            fi
            write_link "s24"
            print_output "$(indent "$(orange "${KERNEL_STR}")")"
            NEG_LOG=1
          fi
        done
      fi
    done
    print_ln
  fi

  # libstdc++.so -> GCC version
  # https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html
  if [[ "${#COMPILE_FILES_ARR[@]}" -gt 0 ]]; then
    for COMPILE_FILE in "${COMPILE_FILES_ARR[@]}"; do
      if [[ -z "${COMPILE_FILE}" ]]; then
        continue
      fi
      if ! [[ "${COMPILE_FILE}" == *"libstdc"* ]]; then
        # currently we only handle libstdc++
        continue
      fi

      COMPILE_FILE_NAME=$(basename "${COMPILE_FILE}")
      mapfile -t COMPILE_FILE_NAME_GCC_DATE_ARR < <(grep ";${COMPILE_FILE_NAME};" "${CONFIG_DIR}"/gcc_libstdc_details.csv | sort -u || true)
      for COMPILE_FILE_NAME_GCC_DATE in "${COMPILE_FILE_NAME_GCC_DATE_ARR[@]}"; do
        GCC_VERSION=$(echo "${COMPILE_FILE_NAME_GCC_DATE}" | cut -d\; -f1 || true)
        GCC_RELEASE_DATE=$(echo "${COMPILE_FILE_NAME_GCC_DATE}" | cut -d\; -f3 || true)
        if [[ -n "${GCC_VERSION}" ]] || [[ -n "${GCC_RELEASE_DATE}" ]]; then
          print_output "[+] Identified GCC version ${ORANGE}${GCC_VERSION:-"NA"}${GREEN} released on ${ORANGE}${GCC_RELEASE_DATE:-"NA"}${GREEN} via libstdc++ ${ORANGE}${COMPILE_FILE_NAME}${GREEN}."
          write_link "s95"
          NEG_LOG=1
        fi
      done
    done
    print_ln
  fi

  if [[ "${#BINARY_DETAILS_ARR[@]}" -gt 0 ]]; then
    local TEMP_ARR=()
    for BINARY_DETAILS in "${BINARY_DETAILS_ARR[@]}"; do
      BINARY_END="NA"
      BINARY_ARCH="NA"
      BINARY_MACHINE="${BINARY_DETAILS/;*}"
      BINARY_DETAILS="${BINARY_DETAILS/*;}"
      if [[ "${BINARY_DETAILS}" == *"LSB"* ]]; then
        BINARY_END="little"
      elif [[ "${BINARY_DETAILS}" == *"MSB"* ]]; then
        BINARY_END="big"
      fi
      BINARY_ARCH="${BINARY_DETAILS#*, }"
      if [[ "${TEMP_ARR[*]}" == *"${BINARY_ARCH};${BINARY_END};${BINARY_MACHINE}"* ]]; then
        continue
      fi

      print_output "[+] Identified firmware architecture ${ORANGE}${BINARY_ARCH}${GREEN} / endianes ${ORANGE}${BINARY_END}${GREEN} / machine configuration ${ORANGE}${BINARY_MACHINE}${GREEN} on binary level."
      write_link "p99"
      TEMP_ARR+=( "${BINARY_ARCH};${BINARY_END};${BINARY_MACHINE}" )
      NEG_LOG=1
    done
    print_ln
  fi

  if [[ "${#BINARY_COMPILER_GUESSED_ARR[@]}" -gt 0 ]]; then
    for BINARY_COMPILER_GUESSED in "${BINARY_COMPILER_GUESSED_ARR[@]}"; do
      if [[ -z "${BINARY_COMPILER_GUESSED}" ]]; then
        continue
      fi

      # print_output "[*] Testing GCC version ${BINARY_COMPILER_GUESSED}" "no_log"
      if [[ "${BINARY_COMPILER_GUESSED}" == "*Buildroot" ]]; then
        # e.g. GCC (Buildroot 2012.11.1)
        GCC_VERSION_STRIPPED=$(echo "${BINARY_COMPILER_GUESSED}" | grep -o -E " [0-9]{4}\.[0-9]+(\.[0-9]+)+?" | head -1 || true)
      else
        GCC_VERSION_STRIPPED=$(echo "${BINARY_COMPILER_GUESSED}" | grep -o -E " [0-9]\.[0-9](\.[0-9]+)+?" | head -1 || true)
      fi
      GCC_VERSION_STRIPPED="${GCC_VERSION_STRIPPED/ }"
      if [[ -n "${GCC_VERSION_STRIPPED}" ]]; then
        GCC_RELEASE_DATE=$(grep "\ ${GCC_VERSION_STRIPPED};" "${CONFIG_DIR}"/gcc_details.csv || true)
        GCC_RELEASE_DATE="${GCC_RELEASE_DATE/*;}"
        # if we have not identified a release date and the version is something linke 1.2.0 we are testing also 1.2
        if [[ -z "${GCC_RELEASE_DATE}" ]] && [[ "${GCC_VERSION_STRIPPED}" =~ [0-9]+\.[0-9]+\.0$ ]]; then
          GCC_RELEASE_DATE=$(grep "\ ${GCC_VERSION_STRIPPED%%\.0};" "${CONFIG_DIR}"/gcc_details.csv || true)
          GCC_RELEASE_DATE="${GCC_RELEASE_DATE/*;}"
        fi
        if [[ -n "${GCC_RELEASE_DATE}" ]]; then
          print_output "[+] Identified possible GCC version on binary level ${ORANGE}${BINARY_COMPILER_GUESSED} / ${GCC_VERSION_STRIPPED}${GREEN} released on ${ORANGE}${GCC_RELEASE_DATE}${GREEN}."
        else
          print_output "[+] Identified possible GCC version on binary level ${ORANGE}${BINARY_COMPILER_GUESSED} / ${GCC_VERSION_STRIPPED}${GREEN} without a known release date."
        fi
        NEG_LOG=1
      fi
    done
  fi

  if [[ "${#BINARY_FLAGS_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Identified the following used binary flags:"
    for BINARY_FLAG in "${BINARY_FLAGS_ARR[@]}"; do
      print_output "$(indent "$(orange "${BINARY_FLAG}")")"
    done
    print_ln
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}
