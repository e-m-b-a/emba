#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Functions for handling paths and other file/directories based operations
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}

check_path_valid() {
  local lC_PATH="${1:-}"

  if [[ -n "${lC_PATH}" ]] && { [[ "${lC_PATH:0:1}" != "/" ]] && [[ "${lC_PATH:0:2}" != "./" ]] && [[ "${lC_PATH:0:3}" != "../" ]] ; } ; then
    print_output "[!] ""${lC_PATH}"" is not a valid path in the context of emba" "no_log"
    print_output "    Try it again with \"/\", \"./\" or \"../\" at the beginning of the path.\\n" "no_log"
    print_output "${RED}""Terminate emba""${NC}\\n" "no_log"
    exit 1
  fi
}

abs_path() {
  if [[ -e "${1:-}" ]] ; then
    realpath -s "${1:-}"
  else
    echo "${1:-}"
  fi
}

print_path() {
  echo -e "$(cut_path "${1:-}")""$(path_attr "${1:-}")"
}

cut_path() {
  local lC_PATH=""
  lC_PATH="$(abs_path "${1:-}")"

  if [[ ${SHORT_PATH} -eq 1 ]] ;  then
    local lSHORT=""
    local lFIRST=""
    local lPREFIX_PRE_CHECK=""
    local lR_PATH=""
    lSHORT="${lC_PATH#"$(dirname "$(abs_path "${LOG_DIR}")")"}"
    lPREFIX_PRE_CHECK="."
    lFIRST="${lSHORT:0:1}"
    if [[ "${lFIRST}" == "/" ]] ;  then
      local lPATH="${lPREFIX_PRE_CHECK}""${lSHORT}"
    else
      local lPATH="${lPREFIX_PRE_CHECK}""/""${lSHORT}"
    fi
    if [[ "${#ROOT_PATH[@]}" -eq 1 && "${HTML}" -eq 1 ]]; then
      # strip detected root directory from complete path
      # currently only one detected root directory supported
      # ./log/firmware/firmware_binwalk_emba/_firmware.extracted/_rootfs.squashfs.extracted/squashfs-root/usr/bin/curl
      # -> /usr/bin/curl
      lR_PATH="$(realpath "${ROOT_PATH[0]}")"
      echo -e "${lC_PATH}" | sed "s|${lR_PATH}|\/|" | sed 's/^.//'
    else
      echo -e "${lPATH}"
    fi
  else
    local lFIRST="${lC_PATH:0:2}"
    if [[ "${lFIRST}" == "//" ]] ;  then
      echo -e "${lC_PATH:1}"
    else
      echo -e "${lC_PATH}"
    fi
  fi
}

path_attr() {
  if [[ -L "${1:-}" ]] ;  then
    echo -e " $(find "${1:-}" -xdev -maxdepth 0 -printf "(%M %u %g) -> %l")"
  elif [[ -f "${1:-}" ]] || [[ -d "${1:-}" ]] ;  then
    echo -e " $(find "${1:-}" -xdev -maxdepth 0 -printf "(%M %u %g)")"
  fi
}

permission_clean() {
  if [[ -f "${1:-}" ]] || [[ -d "${1:-}" ]] ;  then
    echo -e "$(find "${1}" -xdev -maxdepth 0 -printf "%M")"
  fi
}

owner_clean() {
  if [[ -f "${1:-}" ]] || [[ -d "${1:-}" ]] ;  then
    echo -e "$(find "${1}" -xdev -maxdepth 0 -printf "%U")"
  fi
}

group_clean() {
  if [[ -f "${1:-}" ]] || [[ -d "${1:-}" ]] ;  then
    echo -e "$(find "${1}" -xdev -maxdepth 0 -printf "%G")"
  fi
}

set_etc_path() {
  export ETC_PATHS=()
  IFS=" " read -r -a ETC_COMMAND <<<"( -type d  ( -iwholename */etc -o ( -iwholename */etc* -a ! -iwholename */etc*/* ) -o -iwholename */*etc ) )"

  readarray -t ETC_PATHS < <(find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" "${ETC_COMMAND[@]}")
}

set_excluded_path() {
  local lRET_PATHS=""
  local lEXCLUDE_ENTRY=""

  if [[ -v EXCLUDE[@] ]] ;  then
    for lEXCLUDE_ENTRY in "${EXCLUDE[@]}"; do
      if [[ -n ${lEXCLUDE_ENTRY} ]] ; then
        lRET_PATHS="${lRET_PATHS}""$(abs_path "${lEXCLUDE_ENTRY}")""\n"
      fi
    done
  fi
  echo -e "${lRET_PATHS:-}"
}

get_excluded_find() {
  local lRETURN_ENTRY=""
  local lRETURN_LENGTH=""
  local lENTRY=""

  if [[ ${#1} -gt 0 ]] ;  then
    lRETURN_ENTRY=' -not ( '
    for lENTRY in $1; do
      lRETURN_ENTRY="${lRETURN_ENTRY}"'-path '"${lENTRY}"' -prune -o '
    done
    lRETURN_LENGTH=${#lRETURN_ENTRY}
    lRETURN_ENTRY="${lRETURN_ENTRY::lRETURN_LENGTH-3}"') '
  fi
  echo "${lRETURN_ENTRY:-}"
}

rm_proc_binary() {
  local lBIN_ARR=()
  local lBIN_REMOVE_COUNT=0
  lBIN_ARR=("$@")

  for I in "${!lBIN_ARR[@]}"; do
    if [[ "${lBIN_ARR[I]}" == "${FIRMWARE_PATH}""/proc/"* ]]; then
      unset 'lBIN_ARR[I]'
      ((lBIN_REMOVE_COUNT += 1))
    fi
  done
  local lTMP_ARRAY=()
  local lBIN_INDEX=0
  for lBIN_INDEX in "${!lBIN_ARR[@]}"; do
    lTMP_ARRAY+=("${lBIN_ARR[lBIN_INDEX]}")
  done
  if [[ ${lBIN_REMOVE_COUNT} -gt 0 ]] ;  then
    print_ln "no_log"
    print_output "[!] ""${lBIN_REMOVE_COUNT}"" executable/s removed (./proc/*)" "no_log"
  fi
  export BINARIES=()
  BINARIES=("${lTMP_ARRAY[@]}")
  unset lTMP_ARRAY
}

mod_path() {
  local lRET_PATHS_ARR=()
  local lETC_PATH_I=""
  local lNEW_ETC_PATH=""
  local lEXCL_P=""

  if [[ "${1}" == "/ETC_PATHS"* ]] ; then
    for lETC_PATH_I in "${ETC_PATHS[@]}"; do
      lNEW_ETC_PATH="$(echo -e "${1}" | sed -e 's!/ETC_PATHS!'"${lETC_PATH_I}"'!g')"
      lRET_PATHS_ARR=("${lRET_PATHS_ARR[@]}" "${lNEW_ETC_PATH}")
    done
  else
    readarray -t lRET_PATHS_ARR <<< "${1}"
  fi

  for lEXCL_P in "${EXCLUDE_PATHS[@]}"; do
    for I in "${!lRET_PATHS_ARR[@]}"; do
      if [[ "${lRET_PATHS_ARR[I]}" == "${lEXCL_P}"* ]] && [[ -n "${lEXCL_P}" ]] ; then
        unset 'lRET_PATHS_ARR[I]'
      fi
    done
  done

  echo "${lRET_PATHS_ARR[@]}"
}

mod_path_array() {
  local lRET_PATHS_ARR=()
  local lM_PATH=""

  for lM_PATH in ${1}; do
    lRET_PATHS_ARR=("${lRET_PATHS_ARR[@]}" "$(mod_path "${lM_PATH}")")
  done
  echo "${lRET_PATHS_ARR[@]}"
}

create_log_dir() {
  if ! [[ -d "${LOG_DIR}" ]] ; then
    mkdir "${LOG_DIR}" 2>/dev/null || (print_output "[!] WARNING: Cannot create log directory" "no_log" && exit 1)
  fi
  if ! [[ -d "${TMP_DIR}" ]] ; then
    mkdir "${TMP_DIR}" 2>/dev/null || (print_output "[!] WARNING: Cannot create TMP log directory" "no_log" && exit 1)
  fi
  if ! [[ -d "${CSV_DIR}" ]]; then
    mkdir "${CSV_DIR}" 2>/dev/null || (print_output "[!] WARNING: Cannot create CSV log directory" "no_log" && exit 1)
  fi
  if ! [[ -d "${JSON_DIR}" ]]; then
    mkdir "${JSON_DIR}" 2>/dev/null || (print_output "[!] WARNING: Cannot create JSON log directory" "no_log" && exit 1)
  fi

  if ! [[ -f "${MAIN_LOG}" ]]; then
    touch "${MAIN_LOG}" || true
  fi

  export HTML_PATH="${LOG_DIR}""/html-report"
  if ! [[ -d "${HTML_PATH}" ]] && [[ "${HTML}" -eq 1 ]]; then
    mkdir "${HTML_PATH}" 2> /dev/null || true
  fi

  export FIRMWARE_PATH_CP="${LOG_DIR}""/firmware"
  mkdir -p "${FIRMWARE_PATH_CP}" 2> /dev/null || true
  export SUPPL_PATH="${LOG_DIR}""/etc"
  mkdir -p "${SUPPL_PATH}" 2> /dev/null || true
}

config_list() {
  if [[ -f "${1:-}" ]] ;  then
    if [[ "$(wc -l "${1:-}" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local lSTRING_ARR=()
      readarray -t lSTRING_ARR <"${1:-}"
      local lLIST=""
      local lSTRING_ENTRY=""
      for lSTRING_ENTRY in "${lSTRING_ARR[@]}"; do
        lLIST="${lLIST}""${lSTRING_ENTRY}""\n"
      done
      echo -e "${lLIST}" | sed -z '$ s/\n$//' | sort -u
    fi
  else
    echo "C_N_F"
  fi
}

config_find() {
  # $1 -> config file

  local lFIND_RESULTS_ARR=()
  local lFOUND_ENTRY=""

  if [[ -f "${1:-}" ]] ; then
    if [[ "$( wc -l "${1:-}" | cut -d \  -f1 2>/dev/null )" -gt 0 ]] ;  then
      local lFIND_COMMAND_ARR=()
      local lFIND_O_ARR=()
      IFS=" " read -r -a lFIND_COMMAND_ARR <<<"$(sed 's/^/-o -iwholename /g' "${1:-}" | tr '\r\n' ' ' | sed 's/^-o//' 2>/dev/null)"
      mapfile -t lFIND_O_ARR < <(find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" "${lFIND_COMMAND_ARR[@]}")
      for lFOUND_ENTRY in "${lFIND_O_ARR[@]}"; do
        if [[ -L "${lFOUND_ENTRY}" ]] ; then
          local lREAL_PATH=""
          lREAL_PATH="$(realpath "${lFOUND_ENTRY}" 2>/dev/null || true)"
          if [[ -f  "${lREAL_PATH}" ]] ; then
            lFIND_RESULTS_ARR+=( "${lREAL_PATH}" )
          fi
        else
          lFIND_RESULTS_ARR+=( "${lFOUND_ENTRY}" )
        fi
      done

      eval "lFIND_RESULTS_ARR=($(for i in "${lFIND_RESULTS_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
      # Todo: we should remove this and use the lFIND_RESULTS_ARR array in the modules
      for lFOUND_ENTRY in "${lFIND_RESULTS_ARR[@]}"; do
        echo -e "${lFOUND_ENTRY}"
      done
    fi
  else
    echo "C_N_F"
  fi
}

config_grep() {
  local lGREP_FILE_ARR=()
  mapfile -t lGREP_FILE_ARR < <(mod_path "${2}")

  if [[ -f "${1:-}" ]] ;  then
    if [[ "$(wc -l "${1:-}" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local lGREP_COMMAND_ARR=()
      local lGREP_O_ARR=()
      local lG_LOC=""
      IFS=" " read -r -a lGREP_COMMAND_ARR <<<"$(sed 's/^/-Eo /g' "${1}" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
      for lG_LOC in "${lGREP_FILE_ARR[@]}"; do
        lGREP_O_ARR=("${lGREP_O_ARR[@]}" "$(strings "${lG_LOC}" | grep -a -D skip "${lGREP_COMMAND_ARR[@]}" 2>/dev/null)")
      done
      echo "${lGREP_O_ARR[@]}"
    fi
  else
    echo "C_N_F"
  fi
}

config_grep_string() {
  if [[ -f "${1:-}" ]] ;  then
    if [[ "$(wc -l "${1:-}" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local lGREP_COMMAND_ARR=()
      local lGREP_O_ARR=()
      IFS=" " read -r -a lGREP_COMMAND_ARR <<<"$(sed 's/^/-e /g' "${1:-}" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
      lGREP_O_ARR=("${lGREP_O_ARR[@]}" "$(echo "${2}"| grep -a -D skip "${lGREP_COMMAND_ARR[@]}" 2>/dev/null)")
      echo "${lGREP_O_ARR[@]}"
    fi
  else
    echo "C_N_F"
  fi
}
