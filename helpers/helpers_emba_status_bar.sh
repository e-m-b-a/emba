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
  BOX+="\e[$(($LINES - 4));${BOX_L}f┌\033[1m${BOX_TITLE}\033[1m$(repeat_char "─" $(($BOX_W - ${#BOX_TITLE} - 2)))┐"
  BOX+="\e[$(($LINES - 3));${BOX_L}f│""$(repeat_char " " $(($BOX_W - 2)))""│"
  BOX+="\e[$(($LINES - 2));${BOX_L}f│$(repeat_char " " $(($BOX_W - 2)))│"
  BOX+="\e[$(($LINES - 1));${BOX_L}f│$(repeat_char " " $(($BOX_W - 2)))│"
  BOX+="\e[${LINES};${BOX_L}f└$(repeat_char "─" $(($BOX_W - 2)))┘"
  echo -e "$BOX"
}

system_load_util_str() {
  local PERCENTAGE="${1:0}"
  local UTIL_TYPE_NO="${2:0}"
  local UTIL_TYPES=('CPU  ' 'MEM  ' 'DISK ')
  local UTIL_STR="${UTIL_TYPES[$UTIL_TYPE_NO]}"
  local UTIL_BAR_COLOR=""
  local UTIL_BAR_BLANK=""
  local UTIL_PERCENTAGE=$(($PERCENTAGE/(100/12)))

  local A=0
  local BAR_COUNT=0
  for ((A=1; A<=$UTIL_PERCENTAGE; A++)) ; do
    UTIL_BAR_COLOR+="■"
    BAR_COUNT=$(($BAR_COUNT + 1))
  done

  local B=0
  local B_LEN=$((12-$BAR_COUNT))
  for ((B=1; B<=$B_LEN; B++)) ; do
    UTIL_BAR_BLANK+="■"
  done

  if [[ $BAR_COUNT -gt 8 ]] ; then
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

update_box_system_load() {
  shopt -s checkwinsize; (:;:)
  system_load_util_str $((100-$(vmstat 1 2 | tail -1 | awk '{print $15}'))) 0 > "$TMP_DIR""/cpu"
  while true; do
    local MEM_PERCENTAGE_STR="$(system_load_util_str $(free | grep Mem | awk '{print int($3/$2 * 100)}') 1)"
    local DISK_PERCENTAGE_STR="$(system_load_util_str $(df "$LOG_DIR" | tail -1 | awk '{print substr($5, 1, length($5)-1)}') 2)"
    printf '\e[s\e[%s;3f%s\e[%s;3f%s\e[%s;3f%s\e[u' "$(( $LINES - 3 ))" "$(head -n 1 "$TMP_DIR""/cpu")" "$(( $LINES - 2 ))" "$MEM_PERCENTAGE_STR" "$(( $LINES - 1 ))" "$DISK_PERCENTAGE_STR" "$LINES"
    system_load_util_str $((100-$(vmstat 1 2 | tail -1 | awk '{print $15}'))) 0 > "$TMP_DIR""/cpu" &
    WAIT_PIDS+=( "$!" )
    sleep .2
  done
}

status_util_str() {
  local UTIL_TYPE_NO="${1:0}"
  local UTIL_TYPES=('RUN' 'LOG_DIR' 'PROCESSES')
  local UTIL_STR="${UTIL_TYPES[$UTIL_TYPE_NO]}"
  local UTIL_VALUE="${2:-}"
  local UTIL_BAR_BLANK=""

  local UTIL_LEN=$((22-${#UTIL_STR}-${#UTIL_VALUE}))
  local U=0
  for ((U=1; U<=$UTIL_LEN; U++)) ; do
    UTIL_BAR_BLANK+=" "
  done

  echo -e "$UTIL_STR$UTIL_BAR_BLANK$UTIL_VALUE"
}

update_box_status() {
  shopt -s checkwinsize; (:;:)
  local START_TIME=0
  START_TIME=$(date +%s)
  local LOG_DIR_SIZE=""
  local RUN_EMBA_PROCESSES=0
  while true; do
    local RUNTIME=0
    RUNTIME=$(date -d@$(( $(date +%s) - $START_TIME )) -u +%H:%M:%S)
    LOG_DIR_SIZE="$(du -sh "$LOG_DIR" | cut -d$'\t' -f1)"
    RUN_EMBA_PROCESSES="$(ps -C emba.sh | wc -l)"
    printf '\e[s\e[%s;29f%s\e[%s;29f%s\e[%s;29f%s\e[u' "$(( $LINES - 3 ))" "$(status_util_str 0 "$RUNTIME")" "$(( $LINES - 2 ))" "$(status_util_str 1 "$LOG_DIR_SIZE")" "$(( $LINES - 1 ))" "$(status_util_str 2 "$RUN_EMBA_PROCESSES")" "$LINES"
    sleep .5
  done
}

module_util_str() {
  local UTIL_TYPE_NO="${1:0}"
  local UTIL_TYPES=('RUNNING' 'LAST FINISHED' 'PROGRESS')
  local UTIL_STR="${UTIL_TYPES[$UTIL_TYPE_NO]}"
  local UTIL_VALUE="${2:-}"
  local UTIL_BAR_BLANK=""

  local UTIL_LEN=$((22-${#UTIL_STR}-${#UTIL_VALUE}))
  local U=0
  for ((U=1; U<=$UTIL_LEN; U++)) ; do
    UTIL_BAR_BLANK+=" "
  done

  echo -e "$UTIL_STR$UTIL_BAR_BLANK$UTIL_VALUE"
}

update_box_modules() {
  shopt -s checkwinsize; (:;:)
  local STARTED_MODULE_STR=""
  local FINISHED_MODULE_STR=""
  local LAST_FINISHED_MODULE_STR=""
  local COUNT_MODULES=0
  local MODULES=()
  local MODULES_LOCAL=()
  local MODULES_EMBA=()
  local MODULE_FILE=""

  mapfile -t MODULES_EMBA < <(find "$MOD_DIR" -maxdepth 1 -name "*.sh" 2> /dev/null)
  if [[ -d "${MOD_DIR_LOCAL}" ]]; then
    mapfile -t MODULES_LOCAL < <(find "${MOD_DIR_LOCAL}" -maxdepth 1 -name "*.sh" 2> /dev/null)
  fi
  MODULES=( "${MODULES_EMBA[@]}" "${MODULES_LOCAL[@]}" )
  for MODULE_FILE in "${MODULES[@]}" ; do
    if ( file "$MODULE_FILE" | grep -q "shell script" ) && ! [[ "$MODULE_FILE" =~ \ |\' ]] ; then
      (( COUNT_MODULES+=1 ))
    fi
  done

  while true; do
    STARTED_MODULE_STR="$(grep "starting" "$LOG_DIR/emba.log" 2> /dev/null | wc -l || true )"
    FINISHED_MODULE_STR="$(grep "finished" "$LOG_DIR/emba.log" 2> /dev/null | wc -l || true )"
    LAST_FINISHED_MODULE_STR="$(grep "finished" "$LOG_DIR/emba.log" 2> /dev/null | tail -1 | awk '{print $9}' | cut -d"_" -f1 || true )"
    printf '\e[s\e[%s;55f%s\e[%s;55f%s\e[%s;55f%s\e[u' "$(( $LINES - 3 ))" "$(module_util_str 0 $(($STARTED_MODULE_STR - $FINISHED_MODULE_STR)))" "$(( $LINES - 2 ))" "$(module_util_str 1 "$LAST_FINISHED_MODULE_STR")" "$(( $LINES - 1 ))" "$(module_util_str 2 "$FINISHED_MODULE_STR/$COUNT_MODULES")" "$LINES"
    sleep 1
  done
}

status_2_util_str() {
  local UTIL_TYPE_NO="${1:0}"
  local UTIL_TYPES=('PHASE' 'MODE' '')
  local UTIL_STR="${UTIL_TYPES[$UTIL_TYPE_NO]}"
  local UTIL_VALUE="${2:-}"
  local UTIL_BAR_BLANK=""

  local UTIL_LEN=$((22-${#UTIL_STR}-${#UTIL_VALUE}))
  local U=0
  for ((U=1; U<=$UTIL_LEN; U++)) ; do
    UTIL_BAR_BLANK+=" "
  done

  echo -e "$UTIL_STR$UTIL_BAR_BLANK$UTIL_VALUE"
}

update_box_status_2() {
  shopt -s checkwinsize; (:;:)
  local PHASE_STR=""
  local MODE_STR=""
  if [[ $USE_DOCKER -eq 0 && $IN_DOCKER -eq 0 ]] ; then
    MODE_STR+="DEV/"
  elif [[ $STRICT_MODE -eq 1 ]] ; then
    MODE_STR+="STRICT"
  else
    MODE_STR+="DEFAULT"
  fi
  local ERROR_STR=0
  while true; do
    PHASE_STR=$(grep 'phase started' "$LOG_DIR/emba.log" 2> /dev/null | tail -1 | cut -d" " -f2- | grep -Eo '^.*phase' | cut -d" " -f-1 || true  )
    ERROR_STR="/$(grep 'Error detected' "$LOG_DIR/emba_error.log" 2> /dev/null | wc -l || true )"
    if [[ "$ERROR_STR" == "/0" ]] ; then
      ERROR_STR=""
    fi
    printf '\e[s\e[%s;81f%s\e[%s;81f%s\e[%s;81f%s\e[u' "$(( $LINES - 3 ))" "$(status_2_util_str 0 "$PHASE_STR")" "$(( $LINES - 2 ))" "$(status_2_util_str 1 "$MODE_STR$ERROR_STR")" "$(( $LINES - 1 ))" "$(status_2_util_str 2 "")" "$LINES"
    sleep .5
  done
}

remove_status_bar() {
  local LINE_POS="$(( $LINES - 6 ))"
  local RM_STR="\e[;r\e[""$LINE_POS"";1f\e[0J\e[""$LINE_POS"";1f"
  printf "%b" "$RM_STR"
}

box_updaters() {
  # start threaded updater
  update_box_system_load &
  WAIT_PIDS+=( "$!" )
  update_box_modules &
  WAIT_PIDS+=( "$!" )
  update_box_status &
  WAIT_PIDS+=( "$!" )
  update_box_status_2 &
  WAIT_PIDS+=( "$!" )
}

initial_status_bar() {
  shopt -s checkwinsize; (:;:)
  if [[ $LINES -gt 20 && $COLUMNS -gt 105 ]] ; then
    local LINE_POS="$(( $LINES - 6 ))"
    # set cursor and boxes
    local INITIAL_STR="\e[""$LINE_POS"";1f\e[0J\e[0;""$LINE_POS""r\e[""$LINE_POS"";1f$(draw_box 26 "SYSTEM LOAD" 0)$(draw_box 26 "STATUS" 27)$(draw_box 26 "MODULES" 53)$(draw_box 26 "STATUS 2" 79)\e[H" 
    printf "%b" "$INITIAL_STR"

  fi
}
