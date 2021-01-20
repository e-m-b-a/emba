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
# Author(s): Stefan Haböck

declare -a MENU_LIST

build_index_file(){
 FILE=$1
 FILENAME=$(basename "$FILE")
 local HTML_FILE
 HTML_FILE="$(basename "${FILE%.txt}"".html")"
 COULORLESS_FILE_LINE=$(head -1 "$FILE" | tail -n 1 | cut -c27-)
 if [[ -z "$HTML_HEADLINE" ]]; then
    HTML_HEADLINE="EMBA Report Manager"
 fi
 if [[ ${FILENAME%.txt} == "s05"* ]] || [[ ${FILENAME%.txt} == "s25"* ]]; then
    if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
       readarray -t STRING_LIST <"$FILE"
       INDEX_CONTENT_ARR+=("${STRING_LIST[@]}")
    fi
 elif [[ ${FILENAME%.txt} == "f50"* ]]; then
    echo "Execute f50"
    if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
       readarray -t STRING_LIST <"$FILE"
       INDEX_CONTENT_ARR+=("${STRING_LIST[@]}")
    fi
 elif [[ ${FILENAME%.txt} == "f19"* ]]; then
    echo "Execute f19"
    if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
       readarray -t STRING_LIST <"$FILE"
       INDEX_CONTENT_ARR=("${STRING_LIST[@]}")
    fi
 fi
 
 MENU_LIST+=("<li><a href=\"$HTML_FILE\">$COULORLESS_FILE_LINE</a></li>")

 if [ ${#FILENAMES[@]} -ne 0 ]; then
   FILENAMES[${#FILENAMES[@]}]="${FILENAME%.txt}"
 else
   FILENAMES[0]="${FILENAME%.txt}"
 fi

 echo "<header>
      <div class=\"pictureleft\">
        <img src=\"$CONFIG_DIR/emba.png\">
      </div>
      
      <div class=\"headline\">
        <h1>$HTML_HEADLINE</h1>
      </div>

      <div class=\"pictureright\">
         <img src=\"$CONFIG_DIR/emba.png\">
      </div>
    </header>
    <div>
      <ul>" | tee -a "$HTML_PATH""/index.txt" >/dev/null

      	
 if [[ -n ${MENU_LIST[*]} ]]; then
   for OUTPUT in "${MENU_LIST[@]}"; do
	  echo -e "$OUTPUT" | tee -a "$HTML_PATH""/index.txt" >/dev/null	
   done
 fi
      	 
      	 if test -f "$HTML_PATH""/collection.html"; then
      	   echo "<li><a href=""$HTML_PATH""/collection.html"">""Nothing found""</a></li>" | tee -a "$HTML_PATH""/index.txt" >/dev/null
        fi
      echo "</ul>
      	 </div>
      	  <div class=\"main\">"| tee -a "$HTML_PATH""/index.txt" >/dev/null
      if [[ ${FILENAME%.txt} != "f"* ]]; then
     	  echo "<h2>[[0;34m+[0m] [0;36m[1mGerneral Information[0m[1m[0m</h2>
     	  File: $(basename "$FIRMWARE_PATH")<br>
     	  Architecture: $ARCH<br>
     	  Date: $(date) <br>
     	  Duration time: $(date -d@$SECONDS -u +%H:%M:%S) <br>
     	  EMBA Command: $EMBACOMMAND <br>
     " | tee -a "$HTML_PATH""/index.txt" >/dev/null
     fi
     	
 i=0
 if [[ -n ${INDEX_CONTENT_ARR[*]} ]]; then
   for OUTPUT in "${INDEX_CONTENT_ARR[@]}"; do
	if [[ "$OUTPUT" == *"Kernel vulnerabilities"* ]]; then
	   break
	fi
	if [[ "$OUTPUT" == *"0;34m+"*"0;36m"* ]] && [[ "$OUTPUT" != *"h2 id"* ]]; then
 	   echo -e "<h2 id=""${FILENAMES[$i]}"">""$OUTPUT""</h2><br>" | tee -a "$HTML_PATH""/index.txt" >/dev/null
           i=$(( i+1 ))
	else
	   echo -e "$OUTPUT""<br>" | tee -a "$HTML_PATH""/index.txt" >/dev/null
	fi
   done
 fi

 cat "$HTML_PATH""/index.txt" | $AHA_PATH > "$HTML_PATH""/index.html"
 rm "$HTML_PATH""/index.txt"

 sed -i 's/&lt;/</g' "$HTML_PATH""/index.html"
 sed -i 's/&quot;/"/g' "$HTML_PATH""/index.html"
 sed -i 's/&gt;/>/g' "$HTML_PATH""/index.html"
 sed -i 's/<pre>//g' "$HTML_PATH""/index.html"
 sed -i 's/<\/pre>//g' "$HTML_PATH""/index.html"
 ESCAPED_CONFIG_DIR=$(sed 's|/|\\/|g' <<< "$CONFIG_DIR")
 sed -i "s/<head>/<head><br><link rel=\"stylesheet\" href=\"$ESCAPED_CONFIG_DIR\/style.css\" type=\"text\/css\"\/>/g" "$HTML_PATH""/index.html"
}


build_collection_file(){
 FILE=$1
 local FILENAME
 FILENAME=$(basename "$FILE")
 if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
    readarray -t STRING_LIST <"$FILE"
    NOT_FINDINGS_CONTENT_ARR+=("${STRING_LIST[@]}")
 fi

  
 HTML_FILE="${FILE%.txt}.html"
 COULORLESS_FILE_LINE=$(head -1 "$FILE" | tail -n 1 | cut -c27-)
 LINKNAME="${COULORLESS_FILE_LINE// /_}"
 NOT_FINDINGS_MENU_LIST+="<li><a href=\"collection.html#$LINKNAME\">$COULORLESS_FILE_LINE</a></li>"
 if [ ${#NOT_FINDINGS_FILENAMES[@]} -ne 0 ]; then
   NOT_FINDINGS_FILENAMES[${#NOT_FINDINGS_FILENAMES[@]}]="$LINKNAME"
 else
   NOT_FINDINGS_FILENAMES[0]="$LINKNAME"
 fi

 echo "<header>
      <div class=\"pictureleft\">
        <img src=\"$CONFIG_DIR/emba.png\">
      </div>
      
      <div class=\"headline\">
        <h1>$HTML_HEADLINE</h1>
      </div>

      <div class=\"pictureright\">
         <img src=\"$CONFIG_DIR/emba.png\">
      </div>
    </header>
    <div>
      <ul>
      	 $NOT_FINDINGS_MENU_LIST
      </ul>
     </div>
     <div class=\"main\">" | tee -a "$HTML_PATH""/collection.txt" >/dev/null
     	
 i=0
 if [[ -n ${NOT_FINDINGS_CONTENT_ARR[*]} ]]; then
 for OUTPUT in "${NOT_FINDINGS_CONTENT_ARR[@]}"; do
 	   if [[ "$OUTPUT" == *"0;34m+"*"0;36m"* ]] && [[ "$OUTPUT" != *"h2 id"* ]]; then
	      	echo -e "<h2 id=""${NOT_FINDINGS_FILENAMES[$i]}"">""$OUTPUT""</h2><br>" | tee -a "$HTML_PATH""/collection.txt" >/dev/null
	      	i=$(( i+1 ))
  	   else
	        echo -e "$OUTPUT""<br>" | tee -a "$HTML_PATH""/collection.txt" >/dev/null
           fi
 done
 fi
 cat "$HTML_PATH""/collection.txt" | $AHA_PATH > "$HTML_PATH""/collection.html"
 rm "$HTML_PATH""/collection.txt"

 sed -i 's/&lt;/</g' "$HTML_PATH""/collection.html"
 sed -i 's/&quot;/"/g' "$HTML_PATH""/collection.html"
 sed -i 's/&gt;/>/g' "$HTML_PATH""/collection.html"
 sed -i 's/<pre>//g' "$HTML_PATH""/collection.html"
 sed -i 's/<\/pre>//g' "$HTML_PATH""/collection.html"
 ESCAPED_CONFIG_DIR=$(sed 's|/|\\/|g' <<< "$CONFIG_DIR")
 sed -i "s/<head>/<head><br><link rel=\"stylesheet\" href=\"$ESCAPED_CONFIG_DIR\/style.css\" type=\"text\/css\"\/>/g" "$HTML_PATH""/collection.html"
}

build_report_files(){
 
 local SUB_MENU_LIST
 local FILE=$1
 local FILENAME
 local HTML_FILE
 local LINES
 local REPORT_ARRAY
 FILENAME=$(basename "$FILE")
 HTML_FILE="$(basename "${FILE%.txt}".html)"
 LINES="$(cat "$FILE" | wc -l)"
 HEADLINE=$(head -n 1 "$FILE" | tail -n 1 | cut -c27-)
 
 if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
       readarray -t STRING_LIST <"$FILE"
       REPORT_ARRAY+=("${STRING_LIST[@]}")
 fi
 
 echo "<h1>$HEADLINE</h1><div><ul>$SUB_MENU_LIST</ul></div><div class=\"main\">" | tee -a "$HTML_PATH""/$FILENAME" >/dev/null
 
  if [[ -n ${REPORT_ARRAY[*]} ]]; then
   for FILE_LINE in "${REPORT_ARRAY[@]}"; do
        if [[ $FILE_LINE == *"[[0;34m+[0m] [0;36m[1m"* ]]; then
 	   COULORLESS_FILE_LINE=$(echo "$FILE_LINE" | tail -n 1 | cut -c27-)
 	   COULORLESS_FILE_LINE=${COULORLESS_FILE_LINE%[0m}		
 	   echo "<h2 id=""${COULORLESS_FILE_LINE// /_}"">$FILE_LINE</h2>" | tee -a "$HTML_PATH""/$FILENAME" >/dev/null
 	   SUB_MENU_LIST="$SUB_MENU_LIST<li><a href=\"$HTML_FILE#${COULORLESS_FILE_LINE// /_}\">$COULORLESS_FILE_LINE</a></li>"
 	elif [[ $FILE_LINE == *"0;34m==>[0m [0;36m"* ]]; then
 	   COULORLESS_FILE_LINE=$(echo "$FILE_LINE" | tail -n 1 | cut -c23-)
 	   COULORLESS_FILE_LINE=${COULORLESS_FILE_LINE%[0m}	
	   echo "<h4 id=""${COULORLESS_FILE_LINE// /_}"">$FILE_LINE</h4>" | tee -a "$HTML_PATH""/$FILENAME" >/dev/null
	   SUB_MENU_LIST="$SUB_MENU_LIST<li><a href=\"$HTML_FILE#${COULORLESS_FILE_LINE// /_}\">$COULORLESS_FILE_LINE</a></li>"
	else
	   echo "<br> $FILE_LINE" | tee -a "$HTML_PATH""/$FILENAME" >/dev/null
 	fi
   done
 fi
  echo "</div>" | tee -a "$HTML_PATH""/$FILENAME" >/dev/null
  cat "$HTML_PATH""/$FILENAME" | $AHA_PATH > "$HTML_PATH""/$HTML_FILE"
  rm "$HTML_PATH""/$FILENAME"
  sed -i 's/&lt;/</g' "$HTML_PATH""/$HTML_FILE"
  sed -i 's/&gt;/>/g' "$HTML_PATH""/$HTML_FILE"
  sed -i 's/&quot;/"/g' "$HTML_PATH""/$HTML_FILE"
  ESCAPED_CONFIG_DIR=$(sed 's|/|\\/|g' <<< "$CONFIG_DIR")
  ESCAPED_SUB_MENU_LIST=$(sed 's|/|\\/|g' <<< "$SUB_MENU_LIST")
  sed -i "s/<ul><\/ul>/<ul>$ESCAPED_SUB_MENU_LIST<\/ul>/g" "$HTML_PATH""/$HTML_FILE"
  sed -i "s/<head>/<head><br><link rel=\"stylesheet\" href=\"$ESCAPED_CONFIG_DIR\/style.css\" type=\"text\/css\"\/>/g" "$HTML_PATH""/$HTML_FILE"
}

generate_html_file(){

  if [[ $2 == 1 ]]; then
     build_report_files "$1"
     build_index_file "$1"
  else
     build_collection_file "$1"
  fi
}
