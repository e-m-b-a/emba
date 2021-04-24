#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Functions for handling paths and other file/directories based operations
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}

abs_path() {
  if [[ -e "$1" ]] ; then
    echo -e "$(realpath -s "$1")"
  else
    echo "$1"
  fi
}

print_path() {
  echo -e "$(cut_path "$1")""$(path_attr "$1")"
}

cut_path() {
  C_PATH="$(abs_path "$1")"
  if [[ $SHORT_PATH -eq 1 ]] ;  then
    local SHORT
    local FIRST
    local PREFIX_PRE_CHECK
    SHORT="${C_PATH#"$(dirname "$(abs_path "$LOG_DIR")")"}"
    PREFIX_PRE_CHECK="."
    FIRST="${SHORT:0:1}"
    if [[ "$FIRST" == "/" ]] ;  then
      echo -e "$PREFIX_PRE_CHECK""$SHORT"
    else
      echo -e "$PREFIX_PRE_CHECK""/""$SHORT"
    fi
  else
    local FIRST
    FIRST="${C_PATH:0:2}"
    if [[ "$FIRST" == "//" ]] ;  then
      echo -e "${C_PATH:1}"
    else
      echo -e "$C_PATH"
    fi
  fi
}

path_attr() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e " ""$(find "$1" -xdev -maxdepth 0 -printf "(%M %u %g)")"
  elif [[ -L "$1" ]] ;  then
    echo -e " ""$(find "$1" -xdev -maxdepth 0 -printf "(%M %u %g) -> %l")"
  fi
}

permission_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -xdev -maxdepth 0 -printf "%M")"
  fi
}

owner_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -xdev -maxdepth 0 -printf "%U")"
  fi
}

group_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -xdev -maxdepth 0 -printf "%G")"
  fi
}

set_etc_path() {
  export ETC_PATHS
  IFS=" " read -r -a ETC_COMMAND <<<"( -type d  ( -iwholename */etc -o ( -iwholename */etc* -a ! -iwholename */etc*/* ) -o -iwholename */*etc ) )"

  readarray -t ETC_PATHS < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" "${ETC_COMMAND[@]}")
}

set_excluded_path() {
  local RET_PATHS
  if [[ ${#EXCLUDE[@]} -gt 0 ]] ;  then
    for LINE in "${EXCLUDE[@]}"; do
      if [[ -n $LINE ]] ; then
        RET_PATHS="$RET_PATHS""$(abs_path "$LINE")""\n"
      fi
    done
  fi
  echo -e "$RET_PATHS"
}

get_excluded_find() {
  local RET
  if [[ ${#1} -gt 0 ]] ;  then
    RET=' -not ( '
    for LINE in $1; do
      RET="$RET"'-path '"$LINE"' -prune -o '
    done
    RET_LEN=${#RET}
    RET="${RET::RET_LEN-3}"') '
  fi
  echo "$RET"
}

rm_proc_binary() {
  local BIN_ARR
  local COUNT=0
  BIN_ARR=("$@")
  for I in "${!BIN_ARR[@]}"; do
    if [[ "${BIN_ARR[I]}" == "$FIRMWARE_PATH""/proc/"* ]]; then
      unset 'BIN_ARR[I]'
      ((COUNT += 1))
    fi
  done
  local NEW_ARRAY
  for I in "${!BIN_ARR[@]}"; do
    NEW_ARRAY+=("${BIN_ARR[I]}")
  done
  if [[ $COUNT -gt 0 ]] ;  then
    echo
    print_output "[!] ""$COUNT"" executable/s removed (./proc/*)" "no_log"
  fi
  export BINARIES
  BINARIES=("${NEW_ARRAY[@]}")
  unset NEW_ARRAY
}

mod_path() {
  local RET_PATHS
  RET_PATHS=()


  if [[ "$1" == "/ETC_PATHS"* ]] ; then
    for ETC_PATH_I in "${ETC_PATHS[@]}"; do
      NEW_ETC_PATH="$(echo -e "$1" | sed -e 's!/ETC_PATHS!'"$ETC_PATH_I"'!g')"
      RET_PATHS=("${RET_PATHS[@]}" "$NEW_ETC_PATH")
    done
  else
    readarray -t RET_PATHS <<< "$1"
  fi

  for EXCL_P in "${EXCLUDE_PATHS[@]}"; do
    for I in "${!RET_PATHS[@]}"; do
      if [[ "${RET_PATHS[I]}" == "$EXCL_P"* ]] && [[ -n "$EXCL_P" ]] ; then
        unset 'RET_PATHS[I]'
      fi
    done
  done

  local NEW_RET_PATHS

  for RET_PATHS_I in "${RET_PATHS[@]}"; do
    mapfile -t NEW_RET_PATHS < <(find "$FIRMWARE_PATH" -xdev -path "$RET_PATHS_I")
    for I in "${!NEW_RET_PATHS[@]}"; do
      if ! [[ -e "${NEW_RET_PATHS[I]}" ]] || ! [[ -d "${NEW_RET_PATHS[I]}" ]] ;  then
        unset 'NEW_RET_PATHS[I]'
      fi
    done
  done

  echo "${NEW_RET_PATHS[@]}"
}

mod_path_array() {
  for M_PATH in $1; do
    RET_PATHS=("${RET_PATHS[@]}" "$(mod_path "$M_PATH")")
  done
  echo "${RET_PATHS[@]}"
}

create_log_dir() {
  if ! [[ -d "$LOG_DIR" ]] ; then
      mkdir "$LOG_DIR" 2> /dev/null
  fi
  if [[ $FIRMWARE -eq 1 ]] ; then
    if ! [[ -d "$LOG_DIR""/vul_func_checker" ]] ; then
      mkdir -p "$LOG_DIR""/vul_func_checker" 2> /dev/null
    fi
    if ! [[ -d "$LOG_DIR""/objdumps" ]] ; then
      mkdir -p "$LOG_DIR""/objdumps" 2> /dev/null
    fi
    if ! [[ -d "$LOG_DIR""/dtb_dump" ]] && [[ $DTBDUMP -eq 1 ]] ; then
      mkdir -p "$LOG_DIR""/dtb_dump" 2> /dev/null
    fi
    if ! [[ -d "$LOG_DIR""/cwe_checker" ]] && [[ $CWE_CHECKER -eq 1 ]] ; then
      mkdir "$LOG_DIR""/cwe_checker" 2> /dev/null
    fi
    export HTML_PATH="$LOG_DIR""/html-report"
    if ! [[ -d "$HTML_PATH" ]] && [[ "$HTML" -eq 1 ]]; then
      mkdir "$HTML_PATH" 2> /dev/null
    fi
    export FIRMWARE_PATH_CP="$LOG_DIR""/firmware"
    mkdir "$FIRMWARE_PATH_CP" 2> /dev/null
    mkdir "$TMP_DIR" 2> /dev/null
  fi
}

create_grep_log() {
  export GREP_LOG_FILE
  GREP_LOG_FILE="$LOG_DIR""/fw_grep_log.log"
  print_output "[*] grep-able log file will be generated:""$NC""\\n    ""$ORANGE""$GREP_LOG_FILE""$NC" "no_log"
}

config_list() {
  if [[ -f "$1" ]] ;  then
    if [[ "$(wc -l "$1" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local STRING_LIST
      readarray -t STRING_LIST <"$1"
      local LIST
      for STRING in "${STRING_LIST[@]}"; do
        LIST="$LIST""$STRING""\n"
      done
      echo -e "$LIST" | sed -z '$ s/\n$//' | sort -u
    fi
  else
    echo "C_N_F"
  fi
}

config_find() {
  # $1 -> config file

  local FIND_RESULTS
  FIND_RESULTS=()

  if [[ -f "$1" ]] ; then
    if [[ "$( wc -l "$1" | cut -d \  -f1 2>/dev/null )" -gt 0 ]] ;  then
      local FIND_COMMAND
      IFS=" " read -r -a FIND_COMMAND <<<"$(sed 's/^/-o -iwholename /g' "$1" | tr '\r\n' ' ' | sed 's/^-o//' 2>/dev/null)"
      mapfile -t FIND_O < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" "${FIND_COMMAND[@]}")
      for LINE in "${FIND_O[@]}"; do
        if [[ -L "$LINE" ]] ; then
          local REAL_PATH
          REAL_PATH="$(realpath "$LINE" 2>/dev/null)"
          if [[ -f  "$REAL_PATH" ]] ; then
            FIND_RESULTS+=( "$REAL_PATH" )
          fi
        else
          FIND_RESULTS+=( "$LINE" )
        fi
      done

      eval "FIND_RESULTS=($(for i in "${FIND_RESULTS[@]}" ; do echo "\"$i\"" ; done | sort -u))"
      # Todo: we should remove this and use the FIND_RESULTS array in the modules
      for LINE in "${FIND_RESULTS[@]}"; do
        echo -e "$LINE"
      done
    fi
  else
    echo "C_N_F"
  fi
}

config_grep() {
  local GREP_FILE
  mapfile -t GREP_FILE < <(mod_path "$2")

  if [[ -f "$1" ]] ;  then
    if [[ "$(wc -l "$1" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local GREP_COMMAND
      IFS=" " read -r -a GREP_COMMAND <<<"$(sed 's/^/-Eo /g' "$1" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
      for G_LOC in "${GREP_FILE[@]}"; do
        GREP_O=("${GREP_O[@]}" "$(strings "$G_LOC" | grep -a -D skip "${GREP_COMMAND[@]}" 2>/dev/null)")
      done
      echo "${GREP_O[@]}"
    fi
  else
    echo "C_N_F"
  fi
}

config_grep_string() {
  if [[ -f "$1" ]] ;  then
    if [[ "$(wc -l "$1" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local GREP_COMMAND
      IFS=" " read -r -a GREP_COMMAND <<<"$(sed 's/^/-e /g' "$1" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
      GREP_O=("${GREP_O[@]}" "$(echo "$2"| grep -a -D skip "${GREP_COMMAND[@]}" 2>/dev/null)")
      echo "${GREP_O[@]}"
    fi
  else
    echo "C_N_F"
  fi
}
