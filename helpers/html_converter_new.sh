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
LINK="<a href=\"LINK\" target=\"\_blank\" >"
MODUL_LINK="<a class=\"modul\" href=\"LINK\">"
SUBMODUL_LINK="<a class=\"submodul\" href=\"LINK\">"
ANCHOR="<a id=\"ANCHOR\">"
LINK_END="</a>"

update_navigation()
{
  echo

}

add_color_tags()
{
  LINE="$1"
  if [[ -z "$LINE" ]] ; then
    echo "$BR"
  else
    LINE="${LINE//-----------------------------------------------------------------/$HR_MONO}"
    LINE="${LINE//=================================================================/$HR_DOUBLE}"
    LINE="$SPAN""$LINE"
    LINE="${LINE//[0;31m/$SPAN_END$SPAN_RED}"
    LINE="${LINE//[0;32m/$SPAN_END$SPAN_GREEN}"
    LINE="${LINE//[0;33m/$SPAN_END$SPAN_ORANGE}"
    LINE="${LINE//[0;34m/$SPAN_END$SPAN_BLUE}"
    LINE="${LINE//[0;35m/$SPAN_END$SPAN_MAGENTA}"
    LINE="${LINE//[0;36m/$SPAN_END$SPAN_CYAN}"
    LINE="${LINE//[1;31m/$SPAN_END$SPAN_BOLD$SPAN_RED}"
    LINE="${LINE//[1;32m/$SPAN_END$SPAN_BOLD$SPAN_GREEN}"
    LINE="${LINE//[1;33m/$SPAN_END$SPAN_BOLD$SPAN_ORANGE}"
    LINE="${LINE//[1;34m/$SPAN_END$SPAN_BOLD$SPAN_BLUE}"
    LINE="${LINE//[1;35m/$SPAN_END$SPAN_BOLD$SPAN_MAGENTA}"
    LINE="${LINE//[1;36m/$SPAN_END$SPAN_BOLD$SPAN_CYAN}"
    LINE="${LINE//[3;31m/$SPAN_END$SPAN_ITALIC$SPAN_RED}"
    LINE="${LINE//[3;32m/$SPAN_END$SPAN_ITALIC$SPAN_GREEN}"
    LINE="${LINE//[3;33m/$SPAN_END$SPAN_ITALIC$SPAN_ORANGE}"
    LINE="${LINE//[3;34m/$SPAN_END$SPAN_ITALIC$SPAN_BLUE}"
    LINE="${LINE//[3;35m/$SPAN_END$SPAN_ITALIC$SPAN_MAGENTA}"
    LINE="${LINE//[3;36m/$SPAN_END$SPAN_ITALIC$SPAN_CYAN}"
    LINE="${LINE//[1m/$SPAN_BOLD}"
    LINE="${LINE//[3m/$SPAN_ITALIC}"
    LINE="${LINE//[0m/$SPAN_END}"
    LINE="$(echo "$LINE" | sed 's/\x1b\[[0-9;]*m//g' )"
    LINE="$(echo "$LINE" | tr -d '\000-\010\013\014\016-\037' )"
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
  echo "$LINE"
}

strip_color_tags()
{
  LINE="$(echo "$1" | sed 's/\x1b\[[0-9;]*m//g' )"
  LINE="$(echo "$LINE" | tr -d '\000-\010\013\014\016-\037' )"
  echo "$LINE"
}

generate_aggregator()
{
  echo
}

get_modul_name()
{
  FILE=$1
}

generate_report_file()
{
  FILE=$1
  HTML_FILE="$(basename "${FILE%.txt}"".html")"
  cp "./helpers/base.html" "$A_HTML_PATH""/""$HTML_FILE"

  MODUL_NAME=""
  SUBMODUL_NAMES=()

  # parse log content and add to html file
  readarray -t FILE_LINES < "$FILE"
  LINE_NUMBER=$(grep -n "content start" "$A_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  PREV_LINE=""
  for LINE in "${FILE_LINES[@]}" ; do
    LINE="${LINE//&/&amp;}"
    LINE="${LINE//</&lt;}"
    LINE="${LINE//>/&gt;}"
    # get (sub)modul names and add anchor
    if [[ "$(strip_color_tags "$LINE" )" == *"================================================================="* ]] ; then
      MODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/\[+\]\ //g")"
      if [[ -n "$MODUL_NAME" ]] ; then
        LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo $MODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$LINE""$LINK_END"
      fi
    elif [[ "$(strip_color_tags "$LINE" )" == *"-----------------------------------------------------------------"* ]] ; then
      SUBMODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/==> //g" | sed -e "s/\[+\]\ //g")"
      if [[ -n "$SUBMODUL_NAME" ]] ; then
        SUBMODUL_NAMES=( "${SUBMODUL_NAMES[@]}" "$SUBMODUL_NAME" )
        LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo $SUBMODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$LINE""$LINK_END"
      fi
    fi
    # add html tags for style and replace lt character
    HTML_LINE="$(add_color_tags "$LINE" )"
    # add link tags to links
    HTML_LINE="$(add_link_tags "$HTML_LINE")"
    ((LINE_NUMBER++))
    sed -i "$LINE_NUMBER""i""$P_START""$HTML_LINE""$P_END" "$A_HTML_PATH""/""$HTML_FILE"
    PREV_LINE="$LINE"
  done

  # add link to index navigation
  LINE_NUMBER=$(grep -n "navigation start" "$A_HTML_PATH""/index2.html" | cut -d ":" -f 1)
  REP_NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@./$HTML_FILE@g")"
  sed -i "$LINE_NUMBER""i""$REP_NAV_LINK""$MODUL_NAME""$LINK_END" "$A_HTML_PATH""/index2.html"

  # add module anchor to navigation
  LINE_NUMBER=$(grep -n "navigation start" "$A_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@#$(echo $MODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
  sed -i "$LINE_NUMBER""i""$NAV_LINK""$MODUL_NAME""$LINK_END" "$A_HTML_PATH""/""$HTML_FILE"
  ((LINE_NUMBER++))

  for NAME in "${SUBMODUL_NAMES[@]}" ; do
    # add submodule anchors to navigation
    LINE_NUMBER=$(grep -n "navigation start" "$A_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
    SUB_NAV_LINK="$(echo "$SUBMODUL_LINK" | sed -e "s@LINK@#$(echo $NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
    sed -i "$LINE_NUMBER""i""$SUB_NAV_LINK""$NAME""$LINK_END" "$A_HTML_PATH""/""$HTML_FILE"
    ((LINE_NUMBER++))
  done
}

update_index()
{
  echo
}

generate_index()
{
  FILE=$1
  HTML_FILE="index2.html"
  cp "./helpers/base.html" "$A_HTML_PATH""/""$HTML_FILE"
}

prepare_report()
{
  A_HTML_PATH="$(abs_path "$HTML_PATH2")"
  
  if [ ! -d "$A_HTML_PATH/style2" ] ; then
    mkdir "$A_HTML_PATH/style2"
    cp "$HELP_DIR/style_new.css" "$A_HTML_PATH/style2/style_new.css"
    cp "$HELP_DIR/emba.svg" "$A_HTML_PATH/style2/emba.svg"
  fi

  generate_index
}