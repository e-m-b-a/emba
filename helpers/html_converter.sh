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

AHA_PATH=/home/test/Documents/aha-master/aha
declare -a REPORT_LINKS
declare -a MENU_LIST

build_index_file(){
 FILE=$1
 FILENAME=$(basename $FILE)
 
 if [[ "$(wc -l "$FILE" | cut -d\  -f1 2>/dev/null)" -gt 0 ]] ;  then
    readarray -t STRING_LIST <"$FILE"
    CONTENT_ARR+=("${STRING_LIST[@]}")
 fi

  
 FIRSTLINE=$(head -1 $FILE)
 HTML_FILE="${FILE%.txt}.html"
 REPORT_LINKS+="<br><a href="$HTML_FILE">"$FIRSTLINE"</a>"
 MENU_LIST+="<li><a href="#"${FILENAME%.txt}"">"${FILENAME%.txt}"</a></li>"
 if [ ${#FILENAMES[@]} -ne 0 ]; then
   FILENAMES[${#FILENAMES[@]}]="${FILENAME%.txt}"
 else
   FILENAMES[0]="${FILENAME%.txt}"
 fi
 rm './index.txt'
 echo "<header>
      <div class=\"pictureleft\">
        <img src=\"./html-files/emba.png\">
      </div>
      
      <div class=\"headline\">
        <h1>EMBA Report Manager</h1>
      </div>

      <div class=\"pictureright\">
         <img src=\"./html-files/emba.png\">
      </div>
    </header>
    <div>
      <ul>
      	 $MENU_LIST
      	<li><a href=\"#reports\">Reports</a></li>
      </ul>
     </div>
     <div class=\"main\">" | tee -a './index.txt' >/dev/null
     	
 i=0
 for OUTPUT in "${CONTENT_ARR[@]}"; do
 	echo "OUTPUT: $OUTPUT" >> debug.txt
 	   if [[ "$OUTPUT" == *"0;34m+"*"0;36m"* ]] && [[ "$OUTPUT" != *"h2 id"* ]]; then
	      	echo -e "<h2 id=""${FILENAMES[$i]}"">""$OUTPUT""</h2><br>" | tee -a './index.txt' >/dev/null
	      	i=$(( $i+1 ))
  	   else
	        echo -e "$OUTPUT""<br>" | tee -a './index.txt' >/dev/null
           fi
 done
 
 echo "<br>
     	<h2 id=\"reports\">[[0;34m+[0m] [0;36m[1mReports[0m[1m[0m</h2>
     	$REPORT_LINKS
     </div>" | tee -a './index.txt' >/dev/null
 cat "./index.txt" | $AHA_PATH > "./index.html"

 sed -i 's/&lt;/</g' "./index.html"
 sed -i 's/&quot;/"/g' "./index.html"
 sed -i 's/&gt;/>/g' "./index.html"
 sed -i 's/<pre>//g' "./index.html"
 sed -i 's/<\/pre>//g' "./index.html"
#  sed -i 's/<head>/<head><br><meta http-equiv="Refresh" content="5"><br><link rel="stylesheet" href="..\/..\/html-files\/style.css" type="text\/css"\/>/g' $(dirname "$html_file")/index.html
 sed -i 's/<head>/<head><br><link rel="stylesheet" href=".\/html-files\/style.css" type="text\/css"\/>/g' "./index.html"
}

build_report_files(){
 
 local FILE_CONTENT
 local SUB_MENU_LIST
 local FILE=$1
 local HTML_FILE="${FILE%.txt}.html"
 local LINES="$(cat $FILE | wc -l)"
 LINE_COUNTER=1
 HEADLINE=$(head -n 1 "$FILE" | tail -n 1 | cut -c27-)

 while [ $LINE_COUNTER -le "$LINES" ]
 do
   local FILE_LINE
   FILE_LINE=$(head -n $LINE_COUNTER "$FILE" | tail -n 1)
   if [[ $FILE_LINE == *"0;34m"* ]]; then
 		if [[ $FILE_LINE == *"[[0;34m+[0m] [0;36m[1m"* ]]; then
 			COULORLESS_FILE_LINE=$(head -n $LINE_COUNTER "$FILE" | tail -n 1 | cut -c27-)		
 			FILE_LINE="<h2 id="$COULORLESS_FILE_LINE">$FILE_LINE</h2>"
 		elif [[ $FILE_LINE == *"0;34m==>[0m [0;36m"* ]]; then
 			COULORLESS_FILE_LINE=$(head -n $LINE_COUNTER "$FILE" | tail -n 1 | cut -c23-)
			FILE_LINE="<h4 id="$COULORLESS_FILE_LINE">$FILE_LINE</h4>"
 		fi
  		SUB_MENU_LIST="$SUB_MENU_LIST<li><a href="#"$COULORLESS_FILE_LINE"">"$COULORLESS_FILE_LINE"</a></li>"
   fi
   FILE_CONTENT+="<br> $FILE_LINE"
   LINE_COUNTER=$(( $LINE_COUNTER + 1 ))
 done
 
  echo "<h1>"$HEADLINE"</h1><div><ul>$SUB_MENU_LIST</ul></div> <div class="main">$FILE_CONTENT</div>" | $AHA_PATH > "$HTML_FILE"
  sed -i 's/&lt;/</g' "$HTML_FILE"
  sed -i 's/&gt;/>/g' "$HTML_FILE"
  sed -i 's/<head>/<head><br><link rel="stylesheet" href="..\/..\/html-files\/style.css" type="text\/css"\/>/g' "$HTML_FILE"
}

generate_html_file(){
  build_index_file "$1"
  build_report_files "$1"
}
