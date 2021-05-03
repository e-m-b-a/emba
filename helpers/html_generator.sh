#!/bin/bash
# shellcheck disable=SC2001

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
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haboeck

INDEX_FILE="index.html"
STYLE_PATH="/style"
TEMP_PATH="/tmp"

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
LOCAL_LINK="<a class=\"local\" href=\"LINK\">"
EXPLOIT_LINK="<a href=\"https://www.exploit-db.com/exploits/LINK\" target=\"\_blank\" >"
CVE_LINK="<a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=LINK\" target=\"\_blank\" >"
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
    LINE="$(echo "$LINE" | sed 's/\x1b\[/##/g' | sed -E 's/(##[0-9]);/\1##/g' | sed -E 's/(##[0-9]{1,2})m/\1/g' )"
    LINE="${LINE//"##31"/"$SPAN_RED"}"
    LINE="${LINE//"##32"/"$SPAN_GREEN"}"
    LINE="${LINE//"##33"/"$SPAN_ORANGE"}"
    LINE="${LINE//"##34"/"$SPAN_BLUE"}"
    LINE="${LINE//"##35"/"$SPAN_MAGENTA"}"
    LINE="${LINE//"##36"/"$SPAN_CYAN"}"
    LINE="${LINE//"##0"/"$SPAN_END"}"
    LINE="${LINE//"##1"/"$SPAN_BOLD"}"
    LINE="${LINE//"##3"/"$SPAN_ITALIC"}"
    LINE="$(strip_color_tags "$LINE")"
    echo "$LINE"
  fi  
}

add_link_tags() {
  LINE="$1"
  EXPLOITS_IDS=()
  F_LINK="$(echo "$LINE" | grep -o -E '(\b(https?|ftp|file):\/\/) ?[-A-Za-z0-9+&@#\/%?=~_|!:,.;]+[-A-Za-z0-9+&@#\/%=~a_|]' )"
  if [[ -n "$F_LINK" ]] ; then
    HTML_LINK="$(echo "$LINK" | sed -e "s@LINK@$F_LINK@g")""$F_LINK""$LINK_END"
    LINE="$(echo "$LINE" | sed -e "s@$F_LINK@$HTML_LINK@g")"
  fi

  # Exploit links and additional files
  readarray -t EXPLOITS_IDS_F < <(echo "$LINE" | sed -n -e 's/^.*Exploit database ID //p' | sed 's/[^0-9\ ]//g' )
  readarray -t EXPLOITS_IDS_S < <(echo "$LINE" | sed -n -e 's/^.*exploit-db: //p' | sed 's/[^0-9\ ]//g' )
  EXPLOITS_IDS=( "${EXPLOITS_IDS_F[@]}" "${EXPLOITS_IDS_S[@]}" )
  for EXPLOIT_ID in "${EXPLOITS_IDS[@]}" ; do
    if [[ -n "$EXPLOIT_ID" ]] ; then
      EXPLOIT_FILE="$LOG_DIR""/aggregator/exploit/""$EXPLOIT_ID"".txt"
      if [[ -f "$EXPLOIT_FILE" ]] ; then
        HTML_LINK="$(echo "$LOCAL_LINK" | sed -e "s@LINK@$EXPLOIT_ID.html@g")""$EXPLOIT_ID""$LINK_END"
        LINE="$(echo "$LINE" | sed -e "s@$EXPLOIT_ID@$HTML_LINK@g")"
        EXPLOIT_FILE_ARR=( "${EXPLOIT_FILE_ARR[@]}" "$EXPLOIT_FILE" )
      else
        HTML_LINK="$(echo "$EXPLOIT_LINK" | sed -e "s@LINK@$EXPLOIT_ID@g")""$EXPLOIT_ID""$LINK_END"
        LINE="$(echo "$LINE" | sed -e "s@$EXPLOIT_ID@$HTML_LINK@g")"
      fi
    fi
  done

  readarray -t CVE_IDS < <(echo "$LINE" | grep -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' )
  for CVE_ID in "${CVE_IDS[@]}" ; do
    if [[ -n "$CVE_ID" ]] ; then
      HTML_LINK="$(echo "$CVE_LINK" | sed -e "s@LINK@$CVE_ID@g")""$CVE_ID""$LINK_END"
      LINE="$(echo "$LINE" | sed -e "s@$CVE_ID@$HTML_LINK@g")"
    fi
  done

  echo "$LINE"

  for EXPLOIT_FILE in "${EXPLOIT_FILE_ARR[@]}" ; do
    HTML_LINK="$(echo "$EXPLOIT_LINK" | sed -e "s@LINK@$EXPLOIT_ID@g")""$EXPLOIT_ID""$LINK_END"
    readarray -t EXPLOIT_FILES < <(grep "File: " "$EXPLOIT_FILE" | cut -d ":" -f 2 | sed 's/^\ //')
    generate_info_file "$EXPLOIT_FILE" "./f19_cve_aggregator.html" "$HTML_LINK" "${EXPLOIT_FILES[@]}"
  done
}

strip_color_tags()
{
  LINE="$(echo "$1" | sed 's/\x1b\[[0-9;]*m//g' )"
  LINE="$(echo "$LINE" | tr -d '\000-\010\013\014\016-\037' )"
  echo "$LINE"
}

# often we have additional information, like exploits or cve's
generate_info_file()
{
  FILE=$1
  SRC_FILE=$2
  ONLINE=$3
  shift            
  ADD_PATH=("$@")
  INFO_HTML_FILE="$(basename "${FILE%.txt}"".html")"

  if ! [[ -f "$ABS_HTML_PATH""/""$INFO_HTML_FILE" ]] ; then
    cp "./helpers/base.html" "$ABS_HTML_PATH""/""$INFO_HTML_FILE"
    TMP_INFO_FILE="$ABS_HTML_PATH""$TEMP_PATH""/""$INFO_HTML_FILE"

    # parse log content and add to html file
    LINE_NUMBER_INFO_NAV=$(grep -n "navigation start" "$ABS_HTML_PATH""/""$INFO_HTML_FILE" | cut -d ":" -f 1)
    ((LINE_NUMBER_INFO_NAV++))
    NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@$SRC_FILE@g")"
    sed -i "$LINE_NUMBER_INFO_NAV""i""$NAV_LINK""&laquo; Back to ""$(basename "${SRC_FILE%.html}")""$LINK_END" "$ABS_HTML_PATH""/""$INFO_HTML_FILE"

    while IFS= read -r LINE; do 
      LINE_NO_C="$(strip_color_tags "$LINE")"
      if [[ "$LINE_NO_C" != "[*] Statistics"* ]] ; then
        LINE="${LINE//&/&amp;}"
        LINE="${LINE//</&lt;}"
        LINE="${LINE//>/&gt;}"
        # add html tags for style
        HTML_INFO_LINE="$(add_color_tags "$LINE" )"
        # add link tags to links/generate info files and link to them and write line to tmp file
        HTML_INFO_LINE="$(add_link_tags "$HTML_INFO_LINE")"
        echo -e "$P_START""$HTML_INFO_LINE""$P_END" | tee -a "$TMP_INFO_FILE" >/dev/null
      fi
    done < "$FILE"

    if [[ -f "$E_PATH" ]] ; then
      cp "$E_PATH" "$ABS_HTML_PATH""/""$(basename "$E_PATH")"
      HTML_LINK="$(echo "$LOCAL_LINK" | sed -e "s@LINK@./$(basename "$E_PATH")@g")""$(basename "$E_PATH")""$LINK_END"
      LINE="$(echo "$LINE" | sed -e "s@$EXPLOIT_ID@$HTML_LINK@g")"
      echo -e "$HR_MONO""$P_START""$HTML_LINK""$P_END" | tee -a "$TMP_INFO_FILE" >/dev/null
    fi

    for E_PATH in "${ADD_PATH[@]}" ; do
      if [[ -f "$E_PATH" ]] ; then
        cp "$E_PATH" "$ABS_HTML_PATH""/""$(basename "$E_PATH")"
        HTML_LINK="$(echo "$LOCAL_LINK" | sed -e "s@LINK@./$(basename "$E_PATH")@g")""$(basename "$E_PATH")""$LINK_END"
        LINE="$(echo "$LINE" | sed -e "s@$EXPLOIT_ID@$HTML_LINK@g")"
        echo -e "$HR_MONO""$P_START""$HTML_LINK""$P_END" | tee -a "$TMP_INFO_FILE" >/dev/null
      fi
    done

    # add content of temporary html into template
    sed -i "/content start/ r $TMP_INFO_FILE" "$ABS_HTML_PATH""/""$INFO_HTML_FILE"
    rm "$TMP_INFO_FILE"
  fi
}

generate_report_file()
{
  SECONDS=0

  FILE=$1
  HTML_FILE="$(basename "${FILE%.txt}"".html")"
  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$HTML_FILE"
  TMP_FILE="$ABS_HTML_PATH""$TEMP_PATH""/""$HTML_FILE"
  MODUL_NAME=""

  # parse log content and add to html file
  LINE_NUMBER_REP_NAV=$(grep -n "navigation start" "$ABS_HTML_PATH""/""$HTML_FILE" | cut -d ":" -f 1)
  PREV_LINE=""
  while IFS= read -r LINE; do 
    if [[ "$LINE_NO_C" != "[*] Statistics"* ]] ; then
      LINE="${LINE//&/&amp;}"
      LINE="${LINE//</&lt;}"
      LINE="${LINE//>/&gt;}"
      LINE_NO_C="$(strip_color_tags "$LINE")"
      # get (sub)modul names and add anchor
      if [[ "$LINE_NO_C" == "=================================================================" ]] && [[ "$PREV_LINE" == "[+] "* ]]; then
        MODUL_NAME="$(echo -e "$PREV_LINE" | sed -e "s/\[+\]\ //g")"
        if [[ -n "$MODUL_NAME" ]] ; then
          LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo "$MODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$HR_DOUBLE""$LINK_END"
          # add link to index navigation
          add_link_to_index "$HTML_FILE" "$MODUL_NAME"
          # add module anchor to navigation
          NAV_LINK="$(echo "$MODUL_LINK" | sed -e "s@LINK@#$(echo "$MODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
          sed -i "$LINE_NUMBER_REP_NAV""i""$NAV_LINK""$MODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
          ((LINE_NUMBER_REP_NAV++))
        fi
      elif [[ "$LINE_NO_C" == "-----------------------------------------------------------------" ]] && [[ "$PREV_LINE" == "==&gt; "* ]]; then
        SUBMODUL_NAME="$(echo -e "$PREV_LINE" | sed -e "s/==&gt; //g")"
        if [[ -n "$SUBMODUL_NAME" ]] ; then
          LINE="$(echo "$ANCHOR" | sed -e "s@ANCHOR@$(echo "$SUBMODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")""$HR_MONO""$LINK_END"
          SUB_NAV_LINK="$(echo "$SUBMODUL_LINK" | sed -e "s@LINK@#$(echo "$SUBMODUL_NAME" | sed -e "s/\ /_/g" | tr "[:upper:]" "[:lower:]")@g")"
          sed -i "$LINE_NUMBER_REP_NAV""i""$SUB_NAV_LINK""$SUBMODUL_NAME""$LINK_END" "$ABS_HTML_PATH""/""$HTML_FILE"
          ((LINE_NUMBER_REP_NAV++))
        fi
      fi
      # add html tags for style
      HTML_LINE="$(add_color_tags "$LINE" )"
      # add link tags to links/generate info files and link to them and write line to tmp file
      echo "$P_START""$(add_link_tags "$HTML_LINE")""$P_END" >> "$TMP_FILE"
      PREV_LINE="$LINE_NO_C"
    fi
  done < "$FILE"

  # add content of temporary html into template
  sed -i "/content start/ r $TMP_FILE" "$ABS_HTML_PATH""/""$HTML_FILE"
  # add aggregator lines to index page
  if [[ "$HTML_FILE" == "f50"* ]] ; then
    sed -i "/content start/ r $TMP_FILE" "$ABS_HTML_PATH""/""$INDEX_FILE"
  fi
  rm "$TMP_FILE"
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
  C_NUMBER="$(echo "${DATA:1}" | sed -E 's/^0*//g')"

  readarray -t INDEX_NAV_ARR < <(sed -n -e '/navigation start/,/navigation end/p' "$ABS_HTML_PATH""/""$INDEX_FILE" | sed -e '1d;$d' | grep -P -o '(?<=data=\").*?(?=\")')
  readarray -t INDEX_NAV_GROUP_ARR < <(printf -- '%s\n' "${INDEX_NAV_ARR[@]}" | grep "$CLASS" )

  if [[ ${#INDEX_NAV_GROUP_ARR[@]} -eq 0 ]] ; then
    # due the design of emba, which are already groups the modules (even threaded), it isn't necessary to check - 
    # insert new entry at bottom of the navigation
    insert_line "navigation end" "$MODUL_NAME"
  else
    for (( COUNT=0; COUNT<=${#INDEX_NAV_GROUP_ARR[@]}; COUNT++ )) ; do
      if [[ $COUNT -eq 0 ]] && [[ $C_NUMBER -lt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] ; then
        insert_line "${INDEX_NAV_GROUP_ARR[$COUNT]}" "$MODUL_NAME"
      elif [[ $C_NUMBER -gt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] && [[ $C_NUMBER -lt ${INDEX_NAV_GROUP_ARR[$((COUNT+1))]:1} ]] ; then
        insert_line "${INDEX_NAV_GROUP_ARR[$((COUNT+1))]}" "$MODUL_NAME"
      elif [[ $COUNT -eq $((${#INDEX_NAV_GROUP_ARR[@]}-1)) ]] && [[ $C_NUMBER -gt ${INDEX_NAV_GROUP_ARR[$COUNT]:1} ]] ; then
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
  if [ ! -d "$ABS_HTML_PATH$TEMP_PATH" ] ; then
    mkdir "$ABS_HTML_PATH$TEMP_PATH"
  fi

  cp "./helpers/base.html" "$ABS_HTML_PATH""/""$INDEX_FILE"
  sed -i 's/back/back hidden/g' "$ABS_HTML_PATH""/""$INDEX_FILE"
}