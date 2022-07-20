#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Pascal Eckmann

# Description: Show stats about EMBA run on the bottom of the terminal window

repeat_char(){
  local REP_CHAR="$1"
  local REP_COUNT="$2"
  local RET=""
  local A=0
	for ((A=1; A<=$REP_COUNT; A++)) ; do RET+="$REP_CHAR"; done
  echo -e "$RET"
}

draw_box() {
  local BOX_W="$1"
  local BOX_TITLE=" $2 "
  local BOX_L="$3"

  local BOX=""
  BOX+="\e[$(($LINES - 4));${BOX_L}f┌${BOX_TITLE}$(repeat_char "─" $(($BOX_W - ${#BOX_TITLE} - 2)))┐"
  BOX+="\e[$(($LINES - 3));${BOX_L}f│""$(repeat_char " " $(($BOX_W - 2)))""│"
  BOX+="\e[$(($LINES - 2));${BOX_L}f│$(repeat_char " " $(($BOX_W - 2)))│"
  BOX+="\e[$(($LINES - 1));${BOX_L}f│$(repeat_char " " $(($BOX_W - 2)))│"
  BOX+="\e[${LINES};${BOX_L}f└$(repeat_char "─" $(($BOX_W - 2)))┘"
  echo -e "$BOX"
}

update_system_load() {
  system_load_util_str $((100-$(vmstat 1 2 | tail -1 | awk '{print $15}'))) 0 > "$TMP_DIR""/cpu"
  while true; do
    local MEM_PERCENTAGE_STR="$(system_load_util_str $(free | grep Mem | awk '{print int($3/$2 * 100)}') 1)"
    local DISK_PERCENTAGE_STR="$(system_load_util_str $(df "$LOG_DIR" | tail -1 | awk '{print substr($5, 1, length($5)-1)}') 2)"
    printf '\e[s\e[%s;2f%s\e[%s;2f%s\e[%s;2f%s\e[u' "$(( $LINES - 4 ))" "$(head -n 1 "$TMP_DIR""/cpu")" "$(( $LINES - 3 ))" "$MEM_PERCENTAGE_STR" "$(( $LINES - 2 ))" "$DISK_PERCENTAGE_STR" "$LINES"
    system_load_util_str $((100-$(vmstat 1 2 | tail -1 | awk '{print $15}'))) 0 > "$TMP_DIR""/cpu" &
    sleep .2
  done
}

system_load_util_str() {
  local PERCENTAGE="${1:0}"
  local UTIL_TYPE_NO="${2:0}"
  local UTIL_TYPES=('CPU  ' 'MEM  ' 'DISK ')
  local UTIL_STR="${UTIL_TYPES[$UTIL_TYPE_NO]}"
  local UTIL_BAR_COLOR=""
  local UTIL_BAR_BLANK=""
  local UTIL_PERCENTAGE=$(($PERCENTAGE/10))

  local A=0
  local BAR_COUNT=0
  for ((A=1; A<=$UTIL_PERCENTAGE; A++)) ; do
    UTIL_BAR_COLOR+="■"
    (( BAR_COUNT++ ))
  done

  local B=0
  local B_LEN=$((10-$BAR_COUNT))
  for ((B=1; B<=$B_LEN; B++)) ; do
    UTIL_BAR_BLANK+="■"
  done

  if [[ $BAR_COUNT -gt 7 ]] ; then
    UTIL_BAR_COLOR="\033[31m$UTIL_BAR_COLOR\033[0m"
  elif [[ $BAR_COUNT -gt 4 ]] ; then
    UTIL_BAR_COLOR="\033[33m$UTIL_BAR_COLOR\033[0m"
  else 
    UTIL_BAR_COLOR="\033[32m$UTIL_BAR_COLOR\033[0m"
  fi

  PERCENTAGE+=""
  if [[ ${#PERCENTAGE} -gt 2 ]] ; then
    PERCENTAGE="$PERCENTAGE%"
  elif [[ ${#PERCENTAGE} -gt 1 ]] ; then
    PERCENTAGE=" $PERCENTAGE%"
  else
    PERCENTAGE="  $PERCENTAGE%"
  fi

  echo -e "$UTIL_STR$UTIL_BAR_COLOR$UTIL_BAR_BLANK $PERCENTAGE"
}

emba_status_bar() {
  shopt -s checkwinsize; (:;:)
  if [[ $LINES -gt 20 && $COLUMNS -gt 80 ]] ; then
    #printf "\e[%s;1f\e[0J" \e[5;%sr\e[5;0H\e[2J
    local LINE_POS="$(( $LINES - 6 ))"
    # set cursor and boxes
    local INITIAL_STR="\e[%s;1f\e[0J\e[0;%sr\e[%s;1f"
    printf "\e[${LINE_POS};1f\e[0J\e[0;${LINE_POS}r\e[${LINE_POS};1f$(draw_box 26 "SYSTEM LOAD" 0)$(draw_box 26 "STATUS" 27)$(draw_box 26 "MODULES" 54)\e[H" 
    printf "%s" "$INITIAL_STR"
    # start threaded updater
    update_bar &
  fi
}
