#!/bin/bash
# shellcheck disable=SC2001

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Pascal Eckmann, Stefan Haboeck

INDEX_FILE="index.html"
STYLE_PATH="/style"

# variables for html style
P_START="<pre>"
P_END="</pre>"
SPAN_RED="<span class=\"red\">"
SPAN_GREEN="<span class=\"green\">"
SPAN_ORANGE="<span class=\"orange\">"
SPAN_BLUE="<span class=\"blue\">"
SPAN_MAGENTA="<span class=\"magenta\">"
SPAN_CYAN="<span class=\"cyan\">"
SPAN_BOLD="<span class=\"bold\">"
SPAN_ITALIC="<span class=\"italic\">"
SPAN_END="</span>"
HR_MONO="<hr class=\"mono\" />"
HR_DOUBLE="<hr class=\"double\" />"
BR="<br />"
LINK="<a href=\"LINK\" target=\"\_blank\" >"
EXPLOIT_LINK="<a href=\"https://www.exploit-db.com/exploits/LINK\" target=\"\_blank\" >"
MODUL_LINK="<a class=\"modul\" href=\"LINK\">"
MODUL_INDEX_LINK="<a class=\"modul CLASS\" data=\"DATA\" href=\"LINK\">"
SUBMODUL_LINK="<a class=\"submodul\" href=\"LINK\">"
ANCHOR="<a id=\"ANCHOR\">"
LINK_END="</a>"
ENTROPY_IMAGE="<img id=\"entropy\" src=\".$STYLE_PATH/entropy.png\">"

add_color_tags()
{
  LINE="$1"
  if [[ -z "$LINE" ]] ; then
    echo "$BR"
  else
    for (( COUNT=0; COUNT<${#LINE}; COUNT++ )) ; do
      if [[ "${LINE:$COUNT:1}" == "" ]] ; then
        COLOR_ELEM="$( echo "${LINE:$COUNT}" | cut -d 'm' -f 1)""m"
        readarray -t COLOR_ELEM_ARR < <(echo -e "$COLOR_ELEM" | sed -e 's/\x1b\[//' | sed -e 's/m//' | sed -e 's/;/\n/g' | sed '1!G;h;$!d')
        for ELEM in "${COLOR_ELEM_ARR[@]}" ; do
          case "$ELEM" in
            0) LINE="${LINE:0:$COUNT}""$SPAN_END""${LINE:$COUNT}";;
            1) LINE="${LINE:0:$COUNT}""$SPAN_BOLD""${LINE:$COUNT}";;
            3) LINE="${LINE:0:$COUNT}""$SPAN_ITALIC""${LINE:$COUNT}";;
            31) LINE="${LINE:0:$COUNT}""$SPAN_RED""${LINE:$COUNT}";;
            32) LINE="${LINE:0:$COUNT}""$SPAN_GREEN""${LINE:$COUNT}";;
            33) LINE="${LINE:0:$COUNT}""$SPAN_ORANGE""${LINE:$COUNT}";;
            34) LINE="${LINE:0:$COUNT}""$SPAN_BLUE""${LINE:$COUNT}";;
            35) LINE="${LINE:0:$COUNT}""$SPAN_MAGENTA""${LINE:$COUNT}";;
            36) LINE="${LINE:0:$COUNT}""$SPAN_CYAN""${LINE:$COUNT}";;
          esac
        done
        LINE="${LINE//$COLOR_ELEM/}"
      fi
    done
    LINE="$(strip_color_tags "$LINE")"
    echo "$LINE"
  fi  
}

add_link_tags() {
  LINE="$1"
  F_LINK="$(echo "$LINE" | grep -o -E '(\b(https?|ftp|file):\/\/) ?[-A-Za-z0-9+&@#\/%?=~_|!:,.;]+[-A-Za-z0-9+&@#\/%=~a_|]' )"
  if [[ -n "$F_LINK" ]] ; then
    HTML_LINK="$(echo "$LINK" | sed -e "s@LINK@$F_LINK@g")""$F_LINK""$LINK_END"
    LINE="$(echo "$LINE" | sed -e "s@$F_LINK@$HTML_LINK@g")"
  fi
  EXPLOIT_ID="$(echo "$LINE" | sed -n -e 's/^.*Exploit database ID //p' | sed 's/[^0-9]//g' )"
  if [[ -n "$EXPLOIT_ID" ]] ; then
    HTML_LINK="$(echo "$EXPLOIT_LINK" | sed -e "s@LINK@$EXPLOIT_ID@g")""$EXPLOIT_ID""$LINK_END"
    LINE="$(echo "$LINE" | sed -e "s@$EXPLOIT_ID@$HTML_LINK@g")"
  fi
  echo "$LINE"
}

strip_color_tags()
{
  LINE="$(echo "$1" | sed 's/\x1b\[[0-9;]*m//g' )"
  LINE="$(echo "$LINE" | tr -d '\000-\010\013\014\016-\037' )"
  echo "$LINE"
}

generate_report_file()
{
  FILE=$1
  HTML_FILE="$(basename "${FILE%.txt}"".html")"
  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$HTML_FILE"
  MODUL_NAME=""

  # parse log content and add to html file
  readarray -t FILE_LINES < "$FILE"
  LINE_NUMBER=$(grep -n "content start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  LINE_NUMBER_REP_NAV=$(grep -n "navigation start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  if [[ "$HTML_FILE" == "f50"* ]] ; then
    LINE_NUMBER_INDEX=$(grep -n "content start" "$ABS_HTML_PATH""/""$INDEX_FILE" | cut -d ":" -f 1)
  fi
  PREV_LINE=""
  for LINE in "${FILE_LINES[@]}" ; do
    if [[ "$(strip_color_tags "$LINE" )" != "[*] Statistics"* ]] ; then
      LINE="${LINE//&/&amp;}"
      LINE="${LINE//</&lt;}"
      LINE="${LINE//>/&gt;}"
      # get (sub)modul names and add anchor
      if [[ "$(strip_color_tags "$LINE" )" == "=================================================================" ]] && [[ "$(strip_color_tags "$PREV_LINE" )" == "[+] "* ]]; then
        MODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/\[+\]\ //g")"
        if [[ -n "$MODUL_NAME" ]] ; then
          LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo "$MODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$HR_DOUBLE""$LINK_END"
          # add link to index navigation
          add_link_to_index "$HTML_FILE" "$MODUL_NAME"
          ((LINE_NUMBER_INDEX++))
          # add module anchor to navigation
          NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@#$(echo "$MODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
          sed -i "$LINE_NUMBER_REP_NAV""i""$NAV_LINK""$MODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
          ((LINE_NUMBER++))
          ((LINE_NUMBER_REP_NAV++))
        fi
      elif [[ "$(strip_color_tags "$LINE" )" == "-----------------------------------------------------------------" ]] && [[ "$(strip_color_tags "$PREV_LINE" )" == *"==&gt; "* ]]; then
        SUBMODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/==&gt; //g")"
        if [[ -n "$SUBMODUL_NAME" ]] ; then
          LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo "$SUBMODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$HR_MONO""$LINK_END"
          SUB_NAV_LINK="$(echo "$SUBMODUL_LINK" | sed -e "s@LINK@#$(echo "$SUBMODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
          sed -i "$LINE_NUMBER_REP_NAV""i""$SUB_NAV_LINK""$SUBMODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
          ((LINE_NUMBER++))
          ((LINE_NUMBER_REP_NAV++))
        fi
      fi
      # add html tags for style and replace lt character
      HTML_LINE="$(add_color_tags "$LINE" )"
      # add link tags to links
      HTML_LINE="$(add_link_tags "$HTML_LINE")"
      ((LINE_NUMBER++))
      sed -i "$LINE_NUMBER""i""$P_START""$HTML_LINE""$P_END" "$ABS_HTML_PATH""/""$HTML_FILE"
      # add aggregator lines to index page
      if [[ "$HTML_FILE" == "f50"* ]] ; then
        ((LINE_NUMBER_INDEX++))
        sed -i "$LINE_NUMBER_INDEX""i""$P_START""$HTML_LINE""$P_END" "$ABS_HTML_PATH""/""$INDEX_FILE"
      fi
      PREV_LINE="$LINE"
    fi
  done
}

add_link_to_index() {

  insert_line() {
    SEARCH_VAL="$1"
    MODUL_NAME="$2"
    LINE_NUMBER_NAV=$(grep -n "$SEARCH_VAL" "$ABS_HTML_PATH""/""$INDEX_FILE" | cut -d ":" -f 1)
    REP_NAV_LINK="$(echo "$MODUL_INDEX_LINK" | sed -e "s@LINK@./$HTML_FILE@g" | sed -e "s@CLASS@$CLASS@g" | sed -e "s@DATA@$DATA@g")"
    sed -i "$LINE_NUMBER_NAV""i""$REP_NAV_LINK""$MODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$INDEX_FILE"
  }

  HTML_FILE="$1"
  MODUL_NAME="$2"
  DATA="$( echo "$HTML_FILE" | cut -d "_" -f 1)"
  CLASS="${DATA:0:1}"

  readarray -t INDEX_NAV_ARR < <(sed -n -e '/navigation start/,/navigation end/p' "$ABS_HTML_PATH""/""$INDEX_FILE" | sed -e '1d;$d' | grep -P -o '(?<=data=\").*?(?=\")')
  readarray -t INDEX_NAV_GROUP_ARR < <(printf -- '%s\n' "${INDEX_NAV_ARR[@]}" | grep "$CLASS")

  if [[ ${#INDEX_NAV_GROUP_ARR[@]} -eq 0 ]] ; then
    # due the design of emba, which are already groups the modules (even threaded), it isn't necessary to check - 
    # insert new entry at bottom of the navigation
    insert_line "navigation end" "$MODUL_NAME"
  else
    for (( COUNT=0; COUNT<=${#INDEX_NAV_GROUP_ARR[@]}; COUNT++ )) ; do
      if [[ $COUNT -eq 0 ]] && [[ ${DATA:1} -lt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] ; then
        insert_line "${INDEX_NAV_GROUP_ARR[$COUNT]}" "$MODUL_NAME"
      elif [[ ${DATA:1} -gt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] && [[ ${DATA:1} -lt ${INDEX_NAV_GROUP_ARR[$((COUNT+1))]:1} ]] ; then
        insert_line "${INDEX_NAV_GROUP_ARR[$((COUNT+1))]}" "$MODUL_NAME"
      elif [[ $COUNT -eq $((${#INDEX_NAV_GROUP_ARR[@]}-1)) ]] && [[ ${DATA:1} -gt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] ; then
        insert_line "navigation end" "$MODUL_NAME"
      fi
    done
  fi
}

update_index()
{
  LINE_NUMBER_ENTROPY=$(grep -n "entropy.png" "$ABS_HTML_PATH""/""$INDEX_FILE" | cut -d ":" -f 1)
  if [[ "$LINE_NUMBER" -ne 0 ]] ; then 
    readarray -t ENTROPY_IMAGES_ARR < <( find "$LOG_DIR" -xdev -iname "*_entropy.png" 2> /dev/null )
    if [[ -f "${ENTROPY_IMAGES_ARR[0]}" ]] ; then
      cp "${ENTROPY_IMAGES_ARR[0]}" "$ABS_HTML_PATH$STYLE_PATH/entropy.png"
      sed -i "$((LINE_NUMBER_ENTROPY+1))""i""$ENTROPY_IMAGE" "$ABS_HTML_PATH""/""$INDEX_FILE"
    fi
  fi
}

prepare_report()
{
  ABS_HTML_PATH="$(abs_path "$HTML_PATH")"
  
  if [ ! -d "$ABS_HTML_PATH$STYLE_PATH" ] ; then
    mkdir "$ABS_HTML_PATH$STYLE_PATH"
    cp "$HELP_DIR/style.css" "$ABS_HTML_PATH$STYLE_PATH/style.css"
    cp "$HELP_DIR/emba.svg" "$ABS_HTML_PATH$STYLE_PATH/emba.svg"
  fi

  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$INDEX_FILE"
  sed -i 's/back/back hidden/g' "$ABS_HTML_PATH""/""$INDEX_FILE"
}