#!/bin/bash

URL="https://packetstormsecurity.com/files/tags/exploit/page"
LINKS="packet_storm_links.txt"
SAVE_PATH="/tmp/packet_storm"
EMBA_CONFIG_PATH="./config/"

if ! [[ -d "$EMBA_CONFIG_PATH" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if [[ -d "$SAVE_PATH" ]]; then
  rm -r "$SAVE_PATH"
fi
if ! [[ -d "$SAVE_PATH/advisory" ]]; then
  mkdir -p "$SAVE_PATH/advisory"
fi

echo "[*] Generating URL list for packetstorm advisories"
ID=1
CUR_SLEEP_TIME=1
echo "CVE;advisory name;advisory URL;exploit type (local/remote)" > "$SAVE_PATH"/PS_PoC_results.csv

while ( true ); do
  FAIL_CNT=0
  while ! lynx -dump -hiddenlinks=listonly "$URL""$ID" > "$SAVE_PATH"/"$LINKS"; do 
    ((CUR_SLEEP_TIME+=$(shuf -i 1-5 -n 1)))
    ((FAIL_CNT+=1))
    if [[ "$FAIL_CNT" -gt 20 ]]; then
      echo "[-] No further download possible ... exit now"
      exit 1
    fi
    echo "[-] Error downloading $URL$ID ... waiting for $CUR_SLEEP_TIME seconds"
    sleep "$CUR_SLEEP_TIME"
  done
  CUR_SLEEP_TIME=1

  if grep -q "No Results Found" "$SAVE_PATH"/"$LINKS"; then
    echo "[-] Finished downloading exploits from packetstormsecurity.com with page$ID ... exit now"
    break
  fi

  echo ""
  echo "[*] Generating list of URLs of packetstorm advisory page $ID"

  mapfile -t MARKERS < <(grep -zoP "\n   \[[0-9]+\].*" "$SAVE_PATH"/"$LINKS" | grep -a -v '\]packet storm\|Register\|Login\|SERVICES_TAB')

  for ((index=0; index < ${#MARKERS[@]}; index++)); do
    CVEs=()
    REMOTE=0
    LOCAL=0
    DoS=0
    MSF=0
    TYPE="unknown"

    # init marker with name:
    # e.g.: [22]Spitfire CMS 1.0.475 PHP Object Injection
    CURRENT_MARKER=$(echo "${MARKERS[index]}" | cut -d '[' -f2 | cut -d ']' -f1)
    # the name is after the first marker
    ADV_NAME=$(echo "${MARKERS[index]}" | cut -d '[' -f2 | cut -d ']' -f2)

    # with the following search we are going to find the URL of the marker
    ADV_URL=$(grep " $CURRENT_MARKER\.\ " "$SAVE_PATH"/"$LINKS" | awk '{print $2}' | sort -u)
    NEXT_MARKER=$(echo "${MARKERS[index+1]}" | cut -d '[' -f2 | cut -d ']' -f1)
    if [[ -z "$NEXT_MARKER" ]]; then
      NEXT_MARKER=$(grep -E "Back\[[0-9]+\]" "$SAVE_PATH"/"$LINKS" | cut -d '[' -f2 | cut -d ']' -f1)
    fi

    # we do not store metasploit exploits as we already have the MSF database in EMBA
    MSF=$(sed '/\['"$CURRENT_MARKER"'\]/,/\['"$NEXT_MARKER"'\]/!d' "$SAVE_PATH"/"$LINKS" | grep -c "metasploit.com\|This Metasploit module")
    REMOTE=$(sed '/\['"$CURRENT_MARKER"'\]/,/\['"$NEXT_MARKER"'\]/!d' "$SAVE_PATH"/"$LINKS" | grep -c "tags .*remote")
    LOCAL=$(sed '/\['"$CURRENT_MARKER"'\]/,/\['"$NEXT_MARKER"'\]/!d' "$SAVE_PATH"/"$LINKS" | grep -c "tags .*local")
    DoS=$(sed '/\['"$CURRENT_MARKER"'\]/,/\['"$NEXT_MARKER"'\]/!d' "$SAVE_PATH"/"$LINKS" | grep -c "tags .*denial of service")

    if [[ "$REMOTE" -gt 0 ]]; then
      TYPE="remote"
    fi
    if [[ "$LOCAL" -gt 0 ]]; then
      # if it is not unknown it is remote and we have now remote/local
      if ! [[ "$TYPE" == "unknown" ]]; then
        TYPE="$TYPE""/local"
      else
        TYPE="local"
      fi
    fi
    if [[ "$DoS" -gt 0 ]]; then
      if ! [[ "$TYPE" == "unknown" ]]; then
        TYPE="$TYPE""/DoS"
      else
        TYPE="DoS"
      fi
    fi
    
    mapfile -t CVEs < <(sed '/\['"$CURRENT_MARKER"'\]/,/\['"$NEXT_MARKER"'\]/!d' "$SAVE_PATH"/"$LINKS" | grep -o -E "\[[0-9]+\]CVE-[0-9]+-[0-9]+" \
      | sed 's/\[[0-9]*\]//' | sort -u)
    if [[ -v CVEs ]]; then
      for CVE in "${CVEs[@]}";do
        echo -e "[+] Found PoC for $ORANGE$CVE$NC in advisory $ORANGE$ADV_NAME$NC / $ORANGE$ADV_URL$NC"
        if [[ "$MSF" -eq 0 ]]; then
          echo "$CVE;$ADV_NAME;$ADV_URL;$TYPE" >> "$SAVE_PATH"/PS_PoC_results.csv
        fi
      done
    fi
  done
  ((ID+=1))

  sleep "$CUR_SLEEP_TIME"
done

sed -i '/\;\;\;/d' "$SAVE_PATH"/PS_PoC_results.csv

## apply blacklist
if [[ -f "$EMBA_CONFIG_PATH"/pss_blacklist.txt ]]; then
  grep -Fvf "$EMBA_CONFIG_PATH"/pss_blacklist.txt "$SAVE_PATH"/PS_PoC_results.csv >  "$SAVE_PATH"/PS_PoC_results1.csv
  mv "$SAVE_PATH"/PS_PoC_results1.csv "$SAVE_PATH"/PS_PoC_results.csv
fi

if [[ -f "$SAVE_PATH"/PS_PoC_results.csv ]] && [[ -d "$EMBA_CONFIG_PATH" ]]; then
  mv "$SAVE_PATH"/PS_PoC_results.csv "$EMBA_CONFIG_PATH"
  rm -r "$SAVE_PATH"
  echo -e "${GREEN}[+] Successfully stored generated PoC file in EMBA configuration directory."
else
  echo "[-] Not able to copy generated PoC file to configuration directory $EMBA_CONFIG_PATH"
fi
