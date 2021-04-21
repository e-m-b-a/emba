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
  if [[ -z "$LINE" ]] ; then
    echo "$BR"
  else
    LINE="$(echo "$1" | tr -d '\000-\010\013\014\016-\037' )"
    LINE="${LINE//-----------------------------------------------------------------/$HR_MONO}"
    LINE="${LINE//=================================================================/$HR_DOUBLE}"
    LINE="$SPAN""$LINE"
    LINE="${LINE//[0;31m/$SPAN_END$SPAN_RED}"
    LINE="${LINE//[0;32m/$SPAN_END$SPAN_GREEN}"
    LINE="${LINE//[0;33m/$SPAN_END$SPAN_ORANGE}"
    LINE="${LINE//[0;34m/$SPAN_END$SPAN_BLUE}"
    LINE="${LINE//[0;35m/$SPAN_END$SPAN_MAGENTA}"
    LINE="${LINE//[0;36m/$SPAN_END$SPAN_CYAN}"
    LINE="${LINE//[1m/$SPAN_BOLD}"
    LINE="${LINE//[3m/$SPAN_ITALIC}"
    LINE="${LINE//[0m/$SPAN_END}"
    echo "$LINE"
  fi
}

strip_color_tags()
{
  LINE="$(echo "$1" | tr -d '\000-\010\013\014\016-\037' )"
  LINE="${LINE//[0;31m/}"
  LINE="${LINE//[0;32m/}"
  LINE="${LINE//[0;33m/}"
  LINE="${LINE//[0;34m/}"
  LINE="${LINE//[0;35m/}"
  LINE="${LINE//[0;36m/}"
  LINE="${LINE//[1m/}"
  LINE="${LINE//[3m/}"
  LINE="${LINE//[0m/}"
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
  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$HTML_FILE"

  MODUL_NAME=""
  SUBMODUL_NAMES=()

  # parse log content and add to html file
  readarray -t FILE_LINES < "$FILE"
  LINE_NUMBER=$(grep -n "content start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  PREV_LINE=""
  for LINE in "${FILE_LINES[@]}" ; do
    # get (sub)modul names and add anchor
    if [[ $LINE == *"================================================================="* ]] ; then
      MODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/\[+\]\ //g")"
      LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo $MODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$LINE""$LINK_END"
    elif [[ $LINE == *"-----------------------------------------------------------------"* ]] ; then
      SUBMODUL_NAME="$(strip_color_tags "$PREV_LINE" | sed -e "s/==> //g" | sed -e "s/\[+\]\ //g")"
      SUBMODUL_NAMES=( "${SUBMODUL_NAMES[@]}" "$SUBMODUL_NAME" )
      LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo $SUBMODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$LINE""$LINK_END"
    fi
    # add html tags for style and add to document
    HTML_LINE="$(add_color_tags "$LINE")"
    ((LINE_NUMBER++))
    sed -i "$LINE_NUMBER""i""$P_START""$HTML_LINE""$P_END" "$ABS_HTML_PATH""/""$HTML_FILE"
    PREV_LINE="$LINE"
  done

  # add link to index navigation
  LINE_NUMBER=$(grep -n "navigation start" "$ABS_HTML_PATH""/index2.html" | cut -d ":" -f 1)
  REP_NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@./$HTML_FILE@g")"
  sed -i "$LINE_NUMBER""i""$REP_NAV_LINK""$MODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/index2.html"

  # add module anchor to navigation
  LINE_NUMBER=$(grep -n "navigation start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@#$(echo $MODUL_NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
  sed -i "$LINE_NUMBER""i""$NAV_LINK""$MODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
  ((LINE_NUMBER++))

  for NAME in "${SUBMODUL_NAMES[@]}" ; do
    # add submodule anchors to navigation
    LINE_NUMBER=$(grep -n "navigation start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
    SUB_NAV_LINK="$(echo "$SUBMODUL_LINK" | sed -e "s@LINK@#$(echo $NAME | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
    sed -i "$LINE_NUMBER""i""$SUB_NAV_LINK""$NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
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
  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$HTML_FILE"
}

prepare_report()
{
  ABS_HTML_PATH="$(abs_path "$HTML_PATH2")"
  
  if [ ! -d "$ABS_HTML_PATH/style2" ] ; then
    mkdir "$ABS_HTML_PATH/style2"
    cp "$HELP_DIR/style_new.css" "$ABS_HTML_PATH/style2/style_new.css"
    cp "$HELP_DIR/emba.svg" "$ABS_HTML_PATH/style2/emba.svg"
  fi

  generate_index
}