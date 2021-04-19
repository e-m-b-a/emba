#!/bin/bash

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

# variables for html style
P_START="<p>"
P_END="</p>"
SPAN="<span>"
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

update_navigation()
{
  echo
}

add_color_tags()
{
  if [[ -z "$LINE" ]] ; then
    echo "$BR"
  else
    LINE="$1"
    LINE="${LINE//-----------------------------------------------------------------/$HR_MONO}"
    LINE="${LINE//[1m=================================================================[0m/$HR_DOUBLE}"
    LINE="$SPAN""$LINE"
    LINE="${LINE//[0;31m/$SPAN_END$SPAN_RED}"
    LINE="${LINE//[0;32m/$SPAN_END$SPAN_GREEN}"
    LINE="${LINE//[0;33m/$SPAN_END$SPAN_ORANGE}"
    LINE="${LINE//[0;34m/$SPAN_END$SPAN_BLUE}"
    LINE="${LINE//[0;35m/$SPAN_END$SPAN_MAGENTA}"
    LINE="${LINE//[0;36m/$SPAN_END$SPAN_CYAN}"
    LINE="${LINE//[1m/$SPAN_BOLD}"
    LINE="${LINE//[3m/$SPAN_ITALIC}"
    LINE="${LINE//[0m/$SPAN_END}"
    echo "$LINE"
  fi
}

generate_aggregator()
{
  echo
}

generate_report_file()
{
  FILE=$1
  FILENAME=$(basename "$FILE")
  HTML_FILE="$(basename "${FILE%.txt}"".html")"
  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$HTML_FILE"

  readarray -t FILE_LINES < "$FILE"
  LINE_NUMBER=$(grep -n "content start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  for LINE in "${FILE_LINES[@]}" ; do
    LINE="$(add_color_tags "$LINE")"
    ((LINE_NUMBER++))
    sed -i "$LINE_NUMBER""i""$P_START""$LINE""$P_END" "$ABS_HTML_PATH""/""$HTML_FILE"
  done
}

update_index()
{
  echo
}

generate_index()
{
  echo
}

prepare_report()
{
  ABS_HTML_PATH="$(abs_path "$HTML_PATH")"
  
  if [ ! -d "$ABS_HTML_PATH/style" ] ; then
    mkdir "$ABS_HTML_PATH/style"
    cp "$HELP_DIR/style_new.css" "$ABS_HTML_PATH/style/style_new.css"
    cp "$HELP_DIR/emba.svg" "$ABS_HTML_PATH/style/emba.svg"
  fi


}