#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
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
    echo "$(realpath -s "$1")"""
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
    SHORT="${C_PATH#"$FIRMWARE_PATH"}"
    FIRST="${SHORT:0:1}"
    if [[ "$FIRST" == "/" ]] ;  then
      echo -e "$SHORT"
    else
      echo -e "/""$SHORT"
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
    echo -e " ""$(find "$1" -maxdepth 0 -printf "(%M %u %g)")"
  elif [[ -L "$1" ]] ;  then
    echo -e " ""$(find "$1" -maxdepth 0 -printf "(%M %u %g) -> %l")"
  fi
}

permission_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -maxdepth 0 -printf "%M")"
  fi
}

owner_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -maxdepth 0 -printf "%U")"
  fi
}

group_clean() {
  if [[ -f "$1" ]] || [[ -d "$1" ]] ;  then
    echo -e "$(find "$1" -maxdepth 0 -printf "%G")"
  fi
}

set_etc_path() {
  export ETC_PATHS
  IFS=" " read -r -a ETC_COMMAND <<<"( -type d  ( -iwholename */etc -o ( -iwholename */etc* -a ! -iwholename */etc*/* ) -o -iwholename */*etc ) )"

  readarray -t ETC_PATHS < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" "${ETC_COMMAND[@]}")
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

  if [[ "$1" == "$FIRMWARE_PATH""/ETC_PATHS"* ]] ; then
    for ETC_PATH_I in "${ETC_PATHS[@]}"; do
      ORIG_ETC_PATH="$FIRMWARE_PATH""/ETC_PATHS"
      NEW_ETC_PATH="$(echo -e "$1" | sed -e 's!'"$ORIG_ETC_PATH"'!'"$ETC_PATH_I"'!g')"
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
    if [[ -e "$RET_PATHS_I" ]] || [[ -d "$RET_PATHS_I" ]] ;  then
      NEW_RET_PATHS=("${NEW_RET_PATHS[@]}" "$RET_PATHS_I")
    fi
  done

  echo "${NEW_RET_PATHS[@]}"
}

mod_path_array() {
  for M_PATH in $1; do
    RET_PATHS=("${RET_PATHS[@]}" "$(mod_path "$M_PATH")")
  done
  echo "${RET_PATHS[@]}"
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
        LIST="$LIST""$STRING""\\n"
      done
      echo -e "$LIST"
    fi
  else
    echo "C_N_F"
  fi
}

config_find() {
  local SEARCH_LOC
  SEARCH_LOC="$(mod_path "$FIRMWARE_PATH""$2")"
  if [[ -f "$1" ]] ;  then
    if [[ "$(wc -l "$1" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local FIND_COMMAND
      IFS=" " read -r -a FIND_COMMAND <<<"$(sed 's/^/-o -iwholename /g' "$1" | tr '\r\n' ' ' | sed 's/^-o//' 2>/dev/null)"
      local FILES
      for S_LOC in $SEARCH_LOC ; do
        FIND_O="$(find "$S_LOC" "${EXCL_FIND[@]}" "${FIND_COMMAND[@]}")"
        for LINE in $FIND_O; do
          if [[ -L "$LINE" ]] ; then
            FILES="$FILES""$FIRMWARE_PATH""$(realpath "$LINE" 2>/dev/null )""\n"
          else
            FILES="$FILES""$LINE""\n"
          fi
        done
      done
      if [[ -n "$FILES" ]]; then
        echo -e "$FILES"
      fi
    fi
  else
    echo "C_N_F"
  fi
}

config_grep() {
  local GREP_FILE
  GREP_FILE="$(mod_path "$2")"
  if [[ -f "$1" ]] ;  then
    if [[ "$(wc -l "$1" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
      local GREP_COMMAND
      IFS=" " read -r -a GREP_COMMAND <<<"$(sed 's/^/-Eo /g' "$1" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
      for G_LOC in $GREP_FILE; do
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
