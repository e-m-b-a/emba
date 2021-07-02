#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Uploads the firmware to virustotal
# Important:   This module needs a VT API key in the config file ./config/vt_api_key.txt
#              This key is avilable via your VT profile
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=1

P03_firmware_virustotal_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware VirusTotal analyzer"

  if [[ -f "$VT_API_KEY_FILE" && "$ONLINE_CHECKS" -eq 1 ]]; then
    VT_API_KEY=$(cat "$VT_API_KEY_FILE")
    # upload our firmware file to VT:
    print_output "[*] Upload to VirusTotal in progress ..."
    VT_UPLOAD_ID=$(curl -s --request POST --url "https://www.virustotal.com/api/v3/files" --header "x-apikey: $VT_API_KEY" --form "file=@$FIRMWARE_PATH" | jq -r '.data.id')

    if [[ "$VT_UPLOAD_ID" == "null" ]]; then
      print_output "[-] Upload to VirusTotal failed ..."
    else
      print_output "[*] Upload to VirusTotal finished ..."
      print_output "[*] Uploaded firmware to VirusTotal with ID: $ORANGE$VT_UPLOAD_ID$NC"
      VT_ANALYSIS_RESP="init"
      while [[ "$VT_ANALYSIS_RESP" != "completed" ]]; do
        VT_ANALYSIS_RESP=$(curl -m 10 -s --request GET --url "https://www.virustotal.com/api/v3/analyses/$VT_UPLOAD_ID" --header "x-apikey: $VT_API_KEY"  | jq -r '.data.attributes.status')
        if [[ "$VT_ANALYSIS_RESP" != "completed" && "$VT_ANALYSIS_RESP" == "queued" ]]; then
          echo "." | tr -d "\n" 2>/dev/null
        else
          print_output "[*] Analysis of file $ORANGE$FIRMWARE_PATH$NC is $VT_ANALYSIS_RESP."
        fi
        sleep 2
      done

      VT_ANALYSIS_RESP=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/analyses/$VT_UPLOAD_ID" --header "x-apikey: $VT_API_KEY" >> "$TMP_DIR"/vt_response.json)

      if [[ $(wc -l "$TMP_DIR"/vt_response.json | awk '{print $1}') -gt 1 ]]; then
        print_output ""
        print_output "[*] Firmware metadata reported by VirusTotal:"
        jq -r '.meta' "$TMP_DIR"/vt_response.json | tee -a "$LOG_FILE"
        VT_SUSP=$(jq -r '.data.attributes.stats.suspicious' "$TMP_DIR"/vt_response.json)
        VT_MAL=$(jq -r '.data.attributes.stats.malicious' "$TMP_DIR"/vt_response.json)

        print_output ""
        if [[ "$VT_SUSP" -gt 0 || "$VT_MAL" -gt 0 ]]; then
          print_output "[+] Infection via malicious code detected!"
        else
          print_output "[-] No infection via malicious code detected."
        fi

        print_output ""
        print_output "[*] VirusTotal test overview:"
        jq -r '.data.attributes' "$TMP_DIR"/vt_response.json | tee -a "$LOG_FILE"
        print_output ""
        NEG_LOG=1
      fi
    fi

  else
    print_output "[-] No Virustotal API key file found in $ORANGE$VT_API_KEY$NC or online checks disabled."
    NEG_LOG=0
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
