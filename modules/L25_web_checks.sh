#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Performs web server tests of the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L25_web_checks() {

  export ARACHNI_BIN_PATH="$EXT_DIR/arachni/arachni-1.6.1.3-0.6.1.1/bin"
  export WEB_RESULTS=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Web tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}" ; then
        if ! restart_emulation "$IP_ADDRESS_" "$IMAGE_NAME" 0 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing web checks"
          module_end_log "${FUNCNAME[0]}" "$WEB_RESULTS"
          return
        fi
      fi
      main_web_check "$IP_ADDRESS_"
    else
      print_output "[-] No IP address found ... skipping live system tests"
    fi

    write_log ""
    write_log "[*] Statistics:$WEB_RESULTS"
    module_end_log "${FUNCNAME[0]}" "$WEB_RESULTS"
  fi
}

main_web_check() {
  local IP_ADDRESS_="${1:-}"
  local PORT=""
  local SERVICE=""
  local SSL=0
  WEB_RESULTS=0
  WEB_DONE=0

  # NMAP_PORTS_SERVICES from L15
  if [[ "${#NMAP_PORTS_SERVICES[@]}" -gt 0 ]]; then
    for PORT_SERVICE in "${NMAP_PORTS_SERVICES[@]}"; do
      PORT=$(echo "$PORT_SERVICE" | cut -d/ -f1 | tr -d "[:blank:]")
      SERVICE=$(echo "$PORT_SERVICE" | awk '{print $2}' | tr -d "[:blank:]")
      print_output "[*] Analyzing service $ORANGE$SERVICE - $PORT - $IP_ADDRESS_$NC" "no_log"
      if [[ "$SERVICE" == "unknown" ]] || [[ "$SERVICE" == "tcpwrapped" ]]; then
        continue
      fi

      # handle first https and afterwards http
      if [[ "$SERVICE" == *"ssl|http"* ]] || [[ "$SERVICE" == *"ssl/http"* ]];then
        SSL=1
        if system_online_check "${IP_ADDRESS_}"; then
          # we make a screenshot for every web server
          make_web_screenshot "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No screenshot possible"
        fi

        if system_online_check "${IP_ADDRESS_}" ; then
          testssl_check "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No SSL test possible"
        fi

        if system_online_check "${IP_ADDRESS_}" ; then
          web_access_crawler "$IP_ADDRESS_" "$PORT" "$SSL"
        else
          print_output "[-] System not responding - Not performing crawler checks"
        fi

        # but we only test the server with Nikto and other long running tools once
        # Note: this is not a full vulnerability scan. The checks are running only for
        # a limited time! At the end the tester needs to perform further investigation!
        if [[ "$WEB_DONE" -eq 0 ]]; then
          if system_online_check "${IP_ADDRESS_}" ; then
            sub_module_title "Nikto web server analysis for $ORANGE$IP_ADDRESS_:$PORT$NC"
            timeout --preserve-status --signal SIGINT 600 nikto -timeout 3 -nointeractive -maxtime 8m -ssl -port "$PORT" -host "$IP_ADDRESS_" | tee -a "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt || true
            cat "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt >> "$LOG_FILE"
            WEB_DONE=1
            print_output "[*] Finished Nikto web server analysis for $ORANGE$IP_ADDRESS_:$PORT$NC"
            write_link "$LOG_PATH_MODULE/nikto-scan-$IP_ADDRESS_.txt"
            print_bar ""
          else
            print_output "[-] System not responding - Not performing Nikto checks"
          fi

          if system_online_check "${IP_ADDRESS_}" ; then
            arachni_scan "$IP_ADDRESS_" "$PORT" "$SSL"
            WEB_DONE=1
          else
            print_output "[-] System not responding - Not performing Arachni checks"
          fi
        fi
      elif [[ "$SERVICE" == *"http"* ]];then
        SSL=0
        if system_online_check "${IP_ADDRESS_}" ; then
          check_for_basic_auth_init "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No basic auth check possible"
        fi


        if system_online_check "${IP_ADDRESS_}" ; then
          # we make a screenshot for every web server
          make_web_screenshot "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No screenshot possible"
        fi

        if system_online_check "${IP_ADDRESS_}" ; then
          web_access_crawler "$IP_ADDRESS_" "$PORT" "$SSL"
        else
          print_output "[-] System not responding - Not performing crawler checks"
        fi

        if [[ "$WEB_DONE" -eq 0 ]]; then

          if system_online_check "${IP_ADDRESS_}" ; then
            sub_module_title "Nikto web server analysis for $ORANGE$IP_ADDRESS_:$PORT$NC"
            timeout --preserve-status --signal SIGINT 600 nikto -timeout 3 -nointeractive -maxtime 8m -port "$PORT" -host "$IP_ADDRESS_" | tee -a "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt || true
            cat "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt >> "$LOG_FILE"
            WEB_DONE=1
            print_output "[*] Finished Nikto web server analysis for $ORANGE$IP_ADDRESS_:$PORT$NC"
            write_link "$LOG_PATH_MODULE/nikto-scan-$IP_ADDRESS_.txt"
            print_bar ""
          else
            print_output "[-] System not responding - Not performing Nikto checks"
          fi

          if system_online_check "${IP_ADDRESS_}" ; then
            arachni_scan "$IP_ADDRESS_" "$PORT" "$SSL"
            WEB_DONE=1
          else
            print_output "[-] System not responding - Not performing Arachni checks"
          fi
        fi
      fi
    done

    if [[ -f "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt ]]; then
      print_ln
      mapfile -t VERSIONS < <(grep "+ Server: " "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt | cut -d: -f2 | sort -u | grep -v "null" | grep -e "[0-9]" | sed 's/^\ //' || true)
      for VERSION in "${VERSIONS[@]}"; do
        if [[ "$VERSION" != *"Server banner has changed from"* ]]; then
          l15_version_detector "$VERSION" "Nikto web server scanning"
        fi
      done

      mapfile -t VERSIONS < <(grep "Retrieved x-powered-by header" "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt | cut -d: -f2 | sort -u | sed 's/^\ //' | grep -e "[0-9]" || true)
      for VERSION in "${VERSIONS[@]}"; do
        l15_version_detector "$VERSION" "Nikto web server scanning"
      done

      print_ln
      if [[ $(grep -c "+ [1-9] host(s) tested" "$LOG_PATH_MODULE"/nikto-scan-"$IP_ADDRESS_".txt || true) -gt 0 ]]; then
        WEB_RESULTS=1
      fi
    fi
  fi

  print_output "[*] Web server checks for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}

check_for_basic_auth_init() {
  local IP_="${1:-}"
  local PORT_="${2:-}"
  local CREDS="NA"

  BASIC_AUTH=$(find "$LOG_DIR"/l15_emulated_checks_nmap/ -name "nmap*" -exec grep -i "401 Unauthorized" {} \; | wc -l)

  if [[ "$BASIC_AUTH" -gt 0 ]]; then
    disable_strict_mode 1
    print_output "[*] Web server with basic auth protected ... performing login attempt"
    # basic auth from nmap found
    curl -v -L --max-redir 0 -f -m 5 -s -X GET http://"${IP_}"/ 2> >(tee -a "$LOG_FILE")
    CURL_RET="$?"

    # if authentication required, we try user "admin" without password and "admin":"password"
    if [[ "$CURL_RET" == 22 ]]; then
      local CREDS="admin:"
      curl -v -L --max-redir 0 -f -m 5 -s -X GET -u "${CREDS}" http://"${IP_}"/ 2> >(tee -a "$LOG_FILE")
      local CURL_RET="$?"
    fi
    if [[ "$CURL_RET" == 22 ]]; then
      local CREDS="user:"
      curl -v -L --max-redir 0 -f -m 5 -s -X GET -u "${CREDS}" http://"${IP_}"/ 2> >(tee -a "$LOG_FILE")
      local CURL_RET="$?"
    fi
    if [[ "$CURL_RET" == 22 ]]; then
      local CREDS="admin:password"
      curl -v -L --max-redir 0 -f -m 5 -s -X GET -u "${CREDS}" http://"${IP_}"/ 2> >(tee -a "$LOG_FILE")
      local CURL_RET="$?"
    fi
    enable_strict_mode 1
    if [[ "$CURL_RET" != 22 ]] && [[ "$CREDS" != "NA" ]]; then
      print_output "[+] Basic auth credentials for web server found: $ORANGE$CREDS$NC"
      export CURL_CREDS=(-u "${CREDS}")
    fi
  else
      print_output "[*] No basic auth found in Nmap logs"
  fi
}

testssl_check() {
  local IP_="${1:-}"
  local PORT_="${2:-}"
  local TESTSSL_VULNERABLE=0

  if ! [[ -d "$EXT_DIR"/testssl.sh ]]; then
    print_output "[-] testssl.sh not found!"
    return
  fi

  sub_module_title "Starting testssl.sh analysis for $ORANGE$IP_:$PORT$NC"

  timeout --preserve-status --signal SIGINT 600 "$EXT_DIR"/testssl.sh/testssl.sh "$IP_":"$PORT_" | tee -a "$LOG_PATH_MODULE"/testssl-"$IP_"-"$PORT".txt || true

  if [[ -f "$LOG_PATH_MODULE"/testssl-"$IP_"-"$PORT".txt ]]; then
    if grep -q "Service detected" "$LOG_PATH_MODULE"/testssl-"$IP_"-"$PORT".txt; then
      WEB_RESULTS=1
    fi

    TESTSSL_VULNERABLE=$(grep -c "VULNERABLE\|NOT\ ok" "$LOG_PATH_MODULE"/testssl-"$IP_"-"$PORT".txt || true)
    if [[ "$TESTSSL_VULNERABLE" -gt 0 ]]; then
      print_ln
      print_output "[+] Weaknesses in the SSL service of system $ORANGE$IP_:$PORT$GREEN found."
      write_link "$LOG_PATH_MODULE/testssl-$IP_-$PORT.txt"
      print_ln
    fi
  fi

  print_output "[*] Finished testssl.sh web server analysis for $ORANGE$IP_:$PORT$NC"
  write_link "$LOG_PATH_MODULE/testssl-$IP_-$PORT.txt"
  print_bar ""
}

web_access_crawler() {
  local IP_="$1"
  local PORT_="$2"
  local SSL_="$3"
  local PROTO=""
  local WEB_FILE=""
  local WEB_DIR_L1=""
  local WEB_DIR_L2=""
  local WEB_DIR_L3=""
  local CURL_OPTS=( -sS -D )
  [[ -v CURL_CREDS ]] && local CURL_OPTS+=( "${CURL_CREDS}" )
  local CRAWLED_ARR=()

  if [[ "$SSL_" -eq 1 ]]; then
    PROTO="https"
    CURL_OPTS+=( -k )
  else
    PROTO="http"
  fi

  sub_module_title "Starting web server crawling for $ORANGE$IP_:$PORT$NC"
  print_ln

  local HOME_=""
  HOME_=$(pwd)
  for R_PATH in "${ROOT_PATH[@]}" ; do
    # we need files and links (for cgi files)
    cd "${R_PATH}" || exit 1
    mapfile -t FILE_ARR_EXT < <(find "." -type f -o -type l || true)

    for WEB_PATH in "${FILE_ARR_EXT[@]}"; do
      if ! system_online_check "${IP_}" ; then
        print_output "[-] System not responding - Stopping crawling"
        break
      fi
      print_dot
      WEB_FILE="$(basename "$WEB_PATH")"
      if [[ -n "${WEB_FILE}" ]] && ! [[ "${CRAWLED_ARR[*]}" == *" ${WEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing $ORANGE$PROTO://$IP_:$PORT_/$WEB_FILE$NC" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
        timeout --preserve-status --signal SIGINT 2 curl "${CURL_OPTS[@]}" - "$PROTO""://""$IP_":"$PORT_""/""$WEB_FILE" -o /dev/null >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" 2>/dev/null || true
        CRAWLED_ARR+=( "${WEB_FILE}" )
      fi
      WEB_DIR_L1="$(dirname "$WEB_PATH" | rev | cut -d'/' -f1 | rev)"
      WEB_DIR_L1="${WEB_DIR_L1#\.}"
      WEB_DIR_L1="${WEB_DIR_L1#\/}"
      if [[ -n "${WEB_DIR_L1}" ]] && ! [[ "${CRAWLED_ARR[*]}" == *" ${WEB_DIR_L1}/${WEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing $ORANGE$PROTO://$IP_:$PORT_/${WEB_DIR_L1}/${WEB_FILE}$NC" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
        timeout --preserve-status --signal SIGINT 2 curl "${CURL_OPTS[@]}" - "$PROTO""://""$IP_":"$PORT_""/""${WEB_DIR_L1}""/""$WEB_FILE" -o /dev/null >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" 2>/dev/null || true
        CRAWLED_ARR+=( "${WEB_DIR_L1}/${WEB_FILE}" )
      fi
      WEB_DIR_L2="$(dirname "$WEB_PATH" | rev | cut -d'/' -f1-2 | rev)"
      WEB_DIR_L2="${WEB_DIR_L2#\.}"
      WEB_DIR_L2="${WEB_DIR_L2#\/}"
      if [[ -n "${WEB_DIR_L2}" ]] && [[ "${WEB_DIR_L2}" != "${WEB_DIR_L1}" ]] && ! [[ "${CRAWLED_ARR[*]}" == *" ${WEB_DIR_L2}/${WEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing $ORANGE$PROTO://$IP_:$PORT_/${WEB_DIR_L2}/${WEB_FILE}$NC" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
        timeout --preserve-status --signal SIGINT 2 curl "${CURL_OPTS[@]}" - "$PROTO""://""$IP_":"$PORT_""/""${WEB_DIR_L2}""/""$WEB_FILE" -o /dev/null >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" 2>/dev/null || true
        CRAWLED_ARR+=( "${WEB_DIR_L2}/${WEB_FILE}" )
      fi
      WEB_DIR_L3="$(dirname "$WEB_PATH" | rev | cut -d'/' -f1-3 | rev)"
      WEB_DIR_L3="${WEB_DIR_L3#\.}"
      WEB_DIR_L3="${WEB_DIR_L3#\/}"
      if [[ -n "${WEB_DIR_L3}" ]] && [[ "${WEB_DIR_L3}" != "${WEB_DIR_L2}" ]] && [[ "${WEB_DIR_L3}" != "${WEB_DIR_L1}" ]] && ! [[ "${CRAWLED_ARR[*]}" == *" ${WEB_DIR_L3}/${WEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing $ORANGE$PROTO://$IP_:$PORT_/${WEB_DIR_L3}/${WEB_FILE}$NC" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
        timeout --preserve-status --signal SIGINT 2 curl "${CURL_OPTS[@]}" - "$PROTO""://""$IP_":"$PORT_""/""${WEB_DIR_L3}""/""$WEB_FILE" -o /dev/null >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" 2>/dev/null || true
        CRAWLED_ARR+=( "${WEB_DIR_L3}/${WEB_FILE}" )
      fi
    done
    cd "${HOME_}" || exit 1
  done

  if [[ -f "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" ]]; then
    grep -A1 Testing "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" | grep -i -B1 "200 OK" | grep Testing | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/.*$IP_:$PORT//" | sort -u >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" || true
    grep -A1 Testing "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" | grep -i -B1 "401 Unauth" | grep Testing | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/.*$IP_:$PORT//" | sort -u >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-401Unauth.log" || true
    CRAWL_RESP_200=$(wc -l "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" | awk '{print $1}')
    CRAWL_RESP_401=$(wc -l "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-401Unauth.log" | awk '{print $1}')

    # Colorizing the log file:
    sed -i -r "s/.*HTTP\/.*\ 200\ .*/\x1b[32m&\x1b[0m/" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    sed -i -r "s/.*HTTP\/.*\ [3-9][0-9][0-9]\ .*/\x1b[31m&\x1b[0m/" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"

    if [[ "$CRAWL_RESP_200" -gt 0 ]]; then
      print_output "[+] Found $ORANGE$CRAWL_RESP_200$GREEN valid responses - please check the log for further details" "" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    fi
    if [[ "$CRAWL_RESP_401" -gt 0 ]]; then
      print_output "[+] Found $ORANGE$CRAWL_RESP_401$GREEN unauthorized responses - please check the log for further details" "" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    fi

    if [[ -f "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" ]] && [[ -f "$LOG_DIR"/s22_php_check/semgrep_php_results_xml.log ]]; then
      while read -r WEB_PATH; do
        WEB_NAME="$(basename "${WEB_PATH}")"
        mapfile -t CRAWLED_VULNS < <(grep "semgrep-rules.php.lang.security.*${WEB_NAME}" "$LOG_DIR"/s22_php_check/semgrep_php_results_xml.log || true)
        for C_VULN in "${CRAWLED_VULNS[@]}"; do
          VULN_NAME=$(echo "$C_VULN" | tr ' ' '\n' | grep "^name=" | cut -d '=' -f2 || true)
          VULN_FILE=$(echo "$C_VULN" | tr ' ' '\n' | grep "^file=" | cut -d '=' -f2 || true)

          if ! [[ -f "$CSV_DIR"/l25_web_checks.csv ]]; then
            write_csv_log "vuln file crawled" "source of vuln" "language" "vuln name" "filesystem path with vuln"
          fi
          print_output "[+] Found possible vulnerability ${ORANGE}${VULN_NAME}${GREEN} in semgrep analysis for ${ORANGE}${WEB_NAME}${NC}." "" "$LOG_DIR"/s22_php_check/semgrep_php_results_xml.log
          write_csv_log "$WEB_NAME" "semgrep" "php" "$VULN_NAME" "$VULN_FILE"
        done
      done  < "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log"
    fi

    if [[ -f "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" ]] && [[ -f "$LOG_DIR"/23_lua_check.txt ]]; then
      while read -r WEB_PATH; do
        WEB_NAME="$(basename "${WEB_PATH}")"
        mapfile -t CRAWLED_VULNS < <(grep "Found lua.*${WEB_NAME}.*capabilities" "$LOG_DIR"/23_lua_check.txt || true)
        for C_VULN in "${CRAWLED_VULNS[@]}"; do
          [[ "$C_VULN" == *"command execution"* ]] && VULN_NAME="os exec"
          [[ "$C_VULN" == *"file access"* ]] && VULN_NAME="file read/write"

          if ! [[ -f "$CSV_DIR"/l25_web_checks.csv ]]; then
            write_csv_log "vuln file crawled" "source of vuln" "language" "vuln name" "filesystem path with vuln"
          fi
          print_output "[+] Found possible vulnerability in lua analysis for ${ORANGE}${WEB_NAME}${NC}." "$LOG_DIR"/s23_lua_check.txt
          write_csv_log "$WEB_NAME" "lua check" "lua" "$VULN_NAME" "$WEB_PATH"
        done
      done  < "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log"
    fi


    # todo: Python, further PHP analysis

    print_output "[*] Finished web server crawling." "" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
  else
    print_output "[*] Finished web server crawling."
  fi
  print_bar ""
}

arachni_scan() {
  local IP_="${1:-}"
  local PORT_="${2:-}"
  local SSL_="${3:-}"
  local PROTO="http"
  if [[ "$SSL_" -eq 1 ]]; then
    PROTO="https"
  fi
  # prepare arachni checks:
  local ARACHNI_CHECKS="*,-cvs_svn_users,-private_ip,-html_objects,-credit_card,-captcha,-emails,-ssn,-interesting_responses,-xss_dom*,-csrf,-session_fixation"

  if ! [[ -d "$ARACHNI_BIN_PATH" ]]; then
    print_output "[-] Arachni installation not found!"
    return
  fi
  if ! grep -q arachni /etc/passwd; then
    print_output "[-] Arachni user not found!"
    return
  fi
 
  sub_module_title "Starting Arachni web server testing for $ORANGE$IP_:$PORT_$NC"

  if [[ "$IN_DOCKER" -eq 1 ]]; then
    # we need to prepare the directories mounted as tempfs for arachni user:
    chown arachni:arachni "$EXT_DIR"/arachni/arachni-1.6.1.3-0.6.1.1/bin/../.system/arachni-ui-web/config/component_cache -R
    chown arachni:arachni "$EXT_DIR"/arachni/arachni-1.6.1.3-0.6.1.1/bin/../.system/arachni-ui-web/db -R
    chown arachni:arachni "$EXT_DIR"/arachni/arachni-1.6.1.3-0.6.1.1/bin/../.system/arachni-ui-web/tmp -R
    chown arachni:arachni "$EXT_DIR"/arachni/arachni-1.6.1.3-0.6.1.1/bin/../.system/../logs -R
    chown arachni:arachni "$EXT_DIR"/arachni/arachni-1.6.1.3-0.6.1.1/bin/../.system/home -R
  fi

  # as we are running with a low priv arachni user we report to /tmp and proceed afterwards
  if [[ -f "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" ]]; then
    sudo -H -u arachni "$ARACHNI_BIN_PATH"/arachni --output-only-positives --report-save-path /tmp/arachni_report_"$IP_"-"$PORT_".afr --http-request-concurrency=5 --timeout 00:30:00 --scope-extend-paths "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" --checks="$ARACHNI_CHECKS" "$PROTO"://"$IP_":"$PORT_"/ || true
  else
    sudo -H -u arachni "$ARACHNI_BIN_PATH"/arachni --output-only-positives --report-save-path /tmp/arachni_report_"$IP_"-"$PORT_".afr --http-request-concurrency=5 --timeout 00:30:00 --checks="$ARACHNI_CHECKS" "$PROTO"://"$IP_":"$PORT_"/ || true
  fi

  if [[ -f /tmp/arachni_report_"$IP_"-"$PORT_".afr ]]; then
    mv /tmp/arachni_report_"$IP_"-"$PORT_".afr "$LOG_PATH_MODULE"
  fi

  if [[ -f "$LOG_PATH_MODULE"/arachni_report_"$IP_"-"$PORT_".afr ]]; then
    # as we are running with a low priv arachni user we report to /tmp and proceed afterwards
    sudo -H -u arachni "$ARACHNI_BIN_PATH"/arachni_reporter "$LOG_PATH_MODULE"/arachni_report_"$IP_"-"$PORT_".afr | sudo -u arachni tee /tmp/arachni_report.tmp
    mv /tmp/arachni_report.tmp "$LOG_PATH_MODULE"
    sudo -H -u arachni "$ARACHNI_BIN_PATH"/arachni_reporter "$LOG_PATH_MODULE"/arachni_report_"$IP_"-"$PORT_".afr --reporter=html:outfile=/tmp/arachni_report_"$IP_"_"$PORT_".html.zip
    if [[ -f /tmp/arachni_report_"$IP_"_"$PORT_".html.zip ]]; then
      mv /tmp/arachni_report_"$IP_"_"$PORT_".html.zip "$LOG_PATH_MODULE"
    fi
    if [[ -f "$LOG_PATH_MODULE"/arachni_report_"$IP_"_"$PORT_".html.zip ]]; then
      mkdir "$LOG_PATH_MODULE"/arachni_report/
      unzip "$LOG_PATH_MODULE"/arachni_report_"$IP_"_"$PORT_".html.zip -d "$LOG_PATH_MODULE"/arachni_report/
    fi
    ARACHNI_ISSUES=$(grep "With issues" "$LOG_PATH_MODULE"/arachni_report.tmp | awk '{print $4}' || true)
    if [[ "$ARACHNI_ISSUES" -gt 0 ]]; then
      print_ln
      print_output "[+] Web application weaknesses in system $ORANGE$IP_:$PORT_$GREEN found."
      print_ln
    fi
    if [[ -f "$LOG_PATH_MODULE"/arachni_report/index.html ]]; then
      print_ln
      print_output "[*] Arachni report created" "" "$LOG_PATH_MODULE/arachni_report/index.html"
      print_ln
      WEB_RESULTS=1
    fi
  fi
  print_output "[*] Finished Arachni web server analysis for $ORANGE$IP_:$PORT$NC"
  print_bar ""
}

make_web_screenshot() {
  local IP_="${1:-}"
  local PORT_="${2:-}"

  sub_module_title "Starting screenshot for $ORANGE$IP_:$PORT_$NC"

  timeout --preserve-status --signal SIGINT 20 xvfb-run --server-args="-screen 0, 1024x768x24" cutycapt --url="$IP_":"$PORT_" --out="$LOG_PATH_MODULE"/screenshot_"$IP_"_"$PORT_".png || true

  if [[ -f "$LOG_PATH_MODULE"/screenshot_"$IP_"_"$PORT_".png ]]; then
    print_output "[*] Screenshot of web server on IP $ORANGE$IP_:$PORT_$NC created"
    write_link "$LOG_PATH_MODULE/screenshot_${IP_}_$PORT_.png"
    WEB_RESULTS=1
  else
    print_output "[-] Screenshot of web server on IP $ORANGE$IP_:$PORT_$NC failed"
  fi
  print_bar ""
}

