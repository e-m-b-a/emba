#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
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

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L25_web_checks() {

  export ARACHNI_BIN_PATH="$EXT_DIR/arachni/arachni-1.6.1.3-0.6.1.1/bin"
  export WEB_RESULTS=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Web tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ -n "$IP_ADDRESS_" ]]; then
      if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
        main_web_check "$IP_ADDRESS_"
      else
        print_output "[-] System not responding - Not performing web checks"
      fi
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
        if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
          # we make a screenshot for every web server
          make_web_screenshot "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No screenshot possible"
        fi

        if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
          testssl_check "$IP_ADDRESS_" "$PORT"
        else
          print_output "[-] System not responding - No SSL test possible"
        fi

        # but we only test the server with Nikto and other long running tools once
        # Note: this is not a full vulnerability scan. The checks are running only for
        # a limited time! At the end the tester needs to perform further investigation!
        if [[ "$WEB_DONE" -eq 0 ]]; then
          SSL=1

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
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

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
            web_access_crawler "$IP_ADDRESS_" "$PORT" "$SSL"
          else
            print_output "[-] System not responding - Not performing crawler checks"
          fi

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
            arachni_scan "$IP_ADDRESS_" "$PORT" "$SSL"
            WEB_DONE=1
          else
            print_output "[-] System not responding - Not performing Arachni checks"
          fi
        fi
      elif [[ "$SERVICE" == *"http"* ]];then
        make_web_screenshot "$IP_ADDRESS_" "$PORT"

        if [[ "$WEB_DONE" -eq 0 ]]; then
          SSL=0

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
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

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
            web_access_crawler "$IP_ADDRESS_" "$PORT" "$SSL"
          else
            print_output "[-] System not responding - Not performing Nikto checks"
          fi

          if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
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
          l15_version_detector "$VERSION" "Nikto web server scanning log"
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

  if [[ "$SSL_" -eq 1 ]]; then
    PROTO="https"
  else
    PROTO="http"
  fi

  sub_module_title "Starting web server crawling for $ORANGE$IP_:$PORT$NC"
  print_ln

  for WEB_PATH in "${FILE_ARR[@]}"; do
    if ! ping -c 1 "$IP_" &> /dev/null; then
      print_output "[-] System not responding - Stopping crawling"
      break
    fi
    print_dot
    WEB_FILE="$(basename "$WEB_PATH")"
    echo -e "\\n[*] Testing $ORANGE$PROTO://$IP_:$PORT_/$WEB_FILE$NC" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    timeout --preserve-status --signal SIGINT 2 curl -I "$PROTO""://""$IP_":"$PORT_""/""$WEB_FILE" >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" 2>/dev/null || true
  done

  if [[ -f "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" ]]; then
    grep -A1 Testing "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log" | grep -B1 "200 OK" | grep Testing | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/.*$IP_:$PORT//" | sort -u >> "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" || true
    CRAWL_RESP_200=$(wc -l "$LOG_PATH_MODULE/crawling_$IP_-$PORT_-200ok.log" | awk '{print $1}')

    # Colorizing the log file:
    sed -i -r "s/.*HTTP\/.*\ 200\ .*/\x1b[32m&\x1b[0m/" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    sed -i -r "s/.*HTTP\/.*\ [3-9][0-9][0-9]\ .*/\x1b[31m&\x1b[0m/" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"

    if [[ "$CRAWL_RESP_200" -gt 0 ]]; then
      print_output "[+] Found $ORANGE$CRAWL_RESP_200$GREEN valid responses - please check the log for further details" "" "$LOG_PATH_MODULE/crawling_$IP_-$PORT_.log"
    fi

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

