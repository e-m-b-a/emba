#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Performs web server tests of the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L25_web_checks() {
  export WEB_RESULTS=0
  export CHROME_HEADLESS_BIN=""

  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Web server analysis of emulated device"
    pre_module_reporter "${FUNCNAME[0]}"
    export CURL_CREDS_ARR=()

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}" ; then
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing web checks"
          module_end_log "${FUNCNAME[0]}" "${WEB_RESULTS}"
          return
        fi
      fi
      CHROME_HEADLESS_BIN=$(find "${EXT_DIR}/chrome-headless-shell/" -type f -executable -name chrome-headless-shell 2>/dev/null | head -1)
      main_web_check "${IP_ADDRESS_}"
    else
      print_output "[-] No IP address found ... skipping live system tests"
    fi

    write_log ""
    write_log "[*] Statistics:${WEB_RESULTS}"
    module_end_log "${FUNCNAME[0]}" "${WEB_RESULTS}"
  fi
}

main_web_check() {
  local lIP_ADDRESS_="${1:-}"
  local lPORT=""
  local lSERVICE=""
  local lSSL=0
  local lPORT_SERVICE=""
  local lVERSIONS_ARR=()
  local lVERSION=""
  local lWEB_DONE=0
  WEB_RESULTS=0

  # NMAP_PORTS_SERVICES from L15
  if [[ "${#NMAP_PORTS_SERVICES_ARR[@]}" -gt 0 ]]; then
    for lPORT_SERVICE in "${NMAP_PORTS_SERVICES_ARR[@]}"; do
      lPORT=$(echo "${lPORT_SERVICE}" | cut -d/ -f1 | tr -d "[:blank:]")
      lSERVICE=$(echo "${lPORT_SERVICE}" | awk '{print $2}' | tr -d "[:blank:]")
      print_output "[*] Analyzing service ${ORANGE}${lSERVICE} - ${lPORT} - ${lIP_ADDRESS_}${NC}" "no_log"
      if [[ "${lSERVICE}" == "unknown" ]] || [[ "${lSERVICE}" == "tcpwrapped" ]]; then
        continue
      fi

      # handle first https and afterwards http
      if [[ "${lSERVICE}" == *"ssl|http"* ]] || [[ "${lSERVICE}" == *"ssl/http"* ]];then
        lSSL=1
        if system_online_check "${lIP_ADDRESS_}"; then
          # we make a screenshot for every web server
          make_web_screenshot "${lIP_ADDRESS_}" "${lPORT}" "https"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            make_web_screenshot "${lIP_ADDRESS_}" "${lPORT}" "https"
          else
            print_output "[-] System not responding - No screenshot possible"
          fi
        fi

        if system_online_check "${lIP_ADDRESS_}" ; then
          testssl_check "${lIP_ADDRESS_}" "${lPORT}"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            testssl_check "${lIP_ADDRESS_}" "${lPORT}"
          else
            print_output "[-] System not responding - No SSL test possible"
          fi
        fi

        if system_online_check "${lIP_ADDRESS_}" ; then
          web_access_crawler "${lIP_ADDRESS_}" "${lPORT}" "${lSSL}"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            web_access_crawler "${lIP_ADDRESS_}" "${lPORT}" "${lSSL}"
          else
            print_output "[-] System not responding - Not performing crawler checks"
          fi
        fi

        # but we only test the server with Nikto and other long running tools once
        # Note: this is not a full vulnerability scan. The checks are running only for
        # a limited time! At the end the tester needs to perform further investigation!
        if [[ "${lWEB_DONE}" -eq 0 ]]; then
          if system_online_check "${lIP_ADDRESS_}" ; then
            sub_module_title "Nikto web server analysis for ${ORANGE}${lIP_ADDRESS_}:${lPORT}${NC}"
            timeout --preserve-status --signal SIGINT 600 "${EXT_DIR}"/nikto/program/nikto.pl -timeout 3 -nointeractive -maxtime 8m -ssl -port "${lPORT}" -host "${lIP_ADDRESS_}" | tee -a "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt || true
            cat "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt >> "${LOG_FILE}"
            lWEB_DONE=1
            print_output "[*] Finished Nikto web server analysis for ${ORANGE}${lIP_ADDRESS_}:${lPORT}${NC}"
            write_link "${LOG_PATH_MODULE}/nikto-scan-${lIP_ADDRESS_}.txt"
            print_bar ""
          else
            print_output "[-] System not responding - Not performing Nikto checks"
          fi
        fi
      elif [[ "${lSERVICE}" == *"http"* ]];then
        lSSL=0
        if system_online_check "${lIP_ADDRESS_}" ; then
          check_for_basic_auth_init "${lIP_ADDRESS_}" "${lPORT}"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            check_for_basic_auth_init "${lIP_ADDRESS_}" "${lPORT}"
          else
            print_output "[-] System not responding - No basic auth check possible"
          fi
        fi

        if system_online_check "${lIP_ADDRESS_}" ; then
          # we make a screenshot for every web server
          make_web_screenshot "${lIP_ADDRESS_}" "${lPORT}" "http"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            make_web_screenshot "${lIP_ADDRESS_}" "${lPORT}" "http"
          else
            print_output "[-] System not responding - No screenshot possible"
          fi
        fi

        if system_online_check "${lIP_ADDRESS_}" ; then
          web_access_crawler "${lIP_ADDRESS_}" "${lPORT}" "${lSSL}"
        else
          if restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
            web_access_crawler "${lIP_ADDRESS_}" "${lPORT}" "${lSSL}"
          else
            print_output "[-] System not responding - Not performing crawler checks"
          fi
        fi

        if [[ "${lWEB_DONE}" -eq 0 ]]; then

          if system_online_check "${lIP_ADDRESS_}" ; then
            sub_module_title "Nikto web server analysis for ${ORANGE}${lIP_ADDRESS_}:${lPORT}${NC}"
            timeout --preserve-status --signal SIGINT 600 "${EXT_DIR}"/nikto/program/nikto.pl -timeout 3 -nointeractive -maxtime 8m -port "${lPORT}" -host "${lIP_ADDRESS_}" | tee -a "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt || true
            cat "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt >> "${LOG_FILE}"
            lWEB_DONE=1
            print_output "[*] Finished Nikto web server analysis for ${ORANGE}${lIP_ADDRESS_}:${lPORT}${NC}"
            write_link "${LOG_PATH_MODULE}/nikto-scan-${lIP_ADDRESS_}.txt"
            print_bar ""
          else
            print_output "[-] System not responding - Not performing Nikto checks"
          fi
        fi
      fi
    done

    if [[ -f "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt ]]; then
      print_ln
      mapfile -t lVERSIONS_ARR < <(grep "+ Server: " "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt | cut -d: -f2 | sort -u | grep -v "null" | grep -e "[0-9]" | sed 's/^\ //' || true)
      for lVERSION in "${lVERSIONS_ARR[@]}"; do
        if [[ "${lVERSION}" != *"Server banner has changed from"* ]]; then
          l15_version_detector "${lVERSION}" "Nikto web server scanning"
        fi
      done

      mapfile -t lVERSIONS_ARR < <(grep "Retrieved x-powered-by header" "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt | cut -d: -f2 | sort -u | sed 's/^\ //' | grep -e "[0-9]" || true)
      for lVERSION in "${lVERSIONS_ARR[@]}"; do
        l15_version_detector "${lVERSION}" "Nikto web server scanning"
      done

      print_ln
      if [[ $(grep -c "+ [1-9] host(s) tested" "${LOG_PATH_MODULE}"/nikto-scan-"${lIP_ADDRESS_}".txt || true) -gt 0 ]]; then
        WEB_RESULTS=1
      fi
    fi
  fi

  print_output "[*] Web server checks for emulated system with IP ${ORANGE}${lIP_ADDRESS_}${NC} finished"
}

check_for_basic_auth_init() {
  local lIP_="${1:-}"
  local lPORT_="${2:-}"
  local lCREDS="NA"
  local lBASIC_AUTH=0

  lBASIC_AUTH=$(find "${LOG_DIR}"/l15_emulated_checks_nmap/ -type f -name "*_nmap_*" -exec grep -i "401 Unauthorized" {} \; | wc -l)

  if [[ "${lBASIC_AUTH}" -gt 0 ]]; then
    disable_strict_mode "${STRICT_MODE}" 1
    print_output "[*] Web server with basic auth protected ... performing login attempt"
    # basic auth from nmap found
    curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET http://"${lIP_}"/ 2> >(tee -a "${LOG_FILE}")
    local lCURL_RET="$?"

    # if authentication required, we try user "admin" without password and "admin":"password"
    if [[ "${lCURL_RET}" == 22 ]]; then
      local lCREDS="admin:"
      curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET -u "${lCREDS}" http://"${lIP_}"/ 2> >(tee -a "${LOG_FILE}")
      local lCURL_RET="$?"
    fi
    if [[ "${lCURL_RET}" == 22 ]]; then
      local lCREDS="user:"
      curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET -u "${lCREDS}" http://"${lIP_}"/ 2> >(tee -a "${LOG_FILE}")
      local lCURL_RET="$?"
    fi
    if [[ "${lCURL_RET}" == 22 ]]; then
      local lCREDS="admin:password"
      curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET -u "${lCREDS}" http://"${lIP_}"/ 2> >(tee -a "${LOG_FILE}")
      local lCURL_RET="$?"
    fi
    enable_strict_mode "${STRICT_MODE}" 1
    if [[ "${lCURL_RET}" != 22 ]] && [[ "${lCREDS}" != "NA" ]]; then
      print_output "[+] Basic auth credentials for web server found: ${ORANGE}${lCREDS}${NC}"
      CURL_CREDS_ARR=("--user" "${lCREDS}")
    fi
  else
    print_output "[*] No basic auth found in Nmap logs"
  fi
}

testssl_check() {
  local lIP_="${1:-}"
  local lPORT="${2:-}"
  local lTESTSSL_VULNERABLE=0

  if ! [[ -d "${EXT_DIR}"/testssl.sh ]]; then
    print_output "[-] testssl.sh not found!"
    return
  fi

  sub_module_title "Starting testssl.sh analysis for ${ORANGE}${lIP_}:${lPORT}${NC}"

  timeout --preserve-status --signal SIGINT 600 "${EXT_DIR}"/testssl.sh/testssl.sh "${lIP_}":"${lPORT}" | tee -a "${LOG_PATH_MODULE}"/testssl-"${lIP_}"-"${lPORT}".txt || true

  if [[ -f "${LOG_PATH_MODULE}"/testssl-"${lIP_}"-"${lPORT}".txt ]]; then
    if grep -q "Service detected" "${LOG_PATH_MODULE}"/testssl-"${lIP_}"-"${lPORT}".txt; then
      WEB_RESULTS=1
    fi

    lTESTSSL_VULNERABLE=$(grep -c "VULNERABLE\|NOT\ ok" "${LOG_PATH_MODULE}"/testssl-"${lIP_}"-"${lPORT}".txt || true)
    if [[ "${lTESTSSL_VULNERABLE}" -gt 0 ]]; then
      print_ln
      print_output "[+] Weaknesses in the SSL service of system ${ORANGE}${lIP_}:${lPORT}${GREEN} found."
      write_link "${LOG_PATH_MODULE}/testssl-${lIP_}-${lPORT}.txt"
      print_ln
    fi
  fi

  print_output "[*] Finished testssl.sh web server analysis for ${ORANGE}${lIP_}:${lPORT}${NC}"
  write_link "${LOG_PATH_MODULE}/testssl-${lIP_}-${lPORT}.txt"
  print_bar ""
}

check_curl_ret() {
  local lIP_="${1:-}"
  local lPORT_="${2:-}"
  local lCURL_RET="${3:-}"

  local lCURL_RET_CODE=""
  local lCURL_RET_SIZE=""

  lCURL_RET_CODE="$(echo "${lCURL_RET}" | cut -d: -f1 || true)"
  lCURL_RET_SIZE="$(echo "${lCURL_RET}" | cut -d: -f2 || true)"
  # print_output "[*] lCURL_RET: $lCURL_RET / ${HTTP_RAND_REF_SIZE} / Port: ${lPORT_}" "no_log"

  if [[ "${lCURL_RET_CODE}" -eq 200 ]]; then
    if [[ "${HTTP_RAND_REF_SIZE}" == "NA" ]] || [[ "${lCURL_RET_SIZE}" != "${HTTP_RAND_REF_SIZE}" ]]; then
      echo "${lCURL_RET_CODE} OK:${lCURL_RET_SIZE}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" 2>/dev/null || true
    fi
  elif [[ "${lCURL_RET_CODE}" == "401" ]] && [[ "${lCURL_RET_SIZE}" != "${HTTP_RAND_REF_SIZE}" ]]; then
    echo "${lCURL_RET_CODE} Unauth:${lCURL_RET_SIZE}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" 2>/dev/null || true
  else
    echo "${lCURL_RET_CODE}:${lCURL_RET_SIZE}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" 2>/dev/null || true
  fi
}

web_access_crawler() {
  local lIP_="${1:-}"
  local lPORT_="${2:-}"
  local lSSL_="${3:-}"

  local lPROTO=""
  local lWEB_FILE=""
  local lWEB_DIR_L1=""
  local lWEB_DIR_L2=""
  local lWEB_DIR_L3=""
  local lCURL_OPTS_ARR=( "-sS" "--noproxy" '*' )
  [[ "${#CURL_CREDS_ARR[@]}" -gt 0 ]] && local lCURL_OPTS_ARR+=( "${CURL_CREDS_ARR[@]}" )
  local lCRAWLED_ARR=()
  local lCRAWLED_VULNS_ARR=()
  local lCURL_RET="000:0"
  local lCRAWL_RESP_200=0
  local lCRAWL_RESP_401=0
  local lC_VULN=""
  local lFILE_ARR_EXT=()
  local lFILENAME_STARTED_PROCESSES_ARR=()
  local lFILEPATH_QEMU_START_ARR=()
  local lFILENAME_ARR_QEMU_START=()
  local lFILENAME_QEMU_START=""
  local lFILENAME_QEMU_STARTED=""
  local lFILE_QEMU_START=""
  local lFILE_QEMU_TEST=""
  export HTTP_RAND_REF_SIZE=""
  local lPOSSIBLE_FILES_ARR=()
  local lR_PATH=""
  local lVULN_FILE=""
  local lVULN_NAME=""
  local lWEB_NAME=""
  local lWEB_PATH=""

  if [[ "${lSSL_}" -eq 1 ]]; then
    lPROTO="https"
    lCURL_OPTS_ARR+=( "-k" )
  else
    lPROTO="http"
  fi

  sub_module_title "Starting web server crawling for ${ORANGE}${lIP_}:${lPORT}${NC}"
  print_ln

  disable_strict_mode "${STRICT_MODE}" 0

  # just in case our web server is not available we try it multiple times
  # if we fail in reaching it, we return later on checking "${CURL_RET_CODE}" == "000:0"
  local lCNT=0
  local lRETRY_MAX=20
  # if we fail the return code is usually 000 and the size is 0
  while [[ "${lCURL_RET}" == "000:0" ]]; do
    if [[ "${lCNT}" -ge "${lRETRY_MAX}" ]]; then
      # we break here and we return later on with a print_output
      break
    fi
    print_output "[*] Checking for return values on web server access #${lCNT}/${lRETRY_MAX}" "no_log"

    lCURL_RET=$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}://${lIP_}:${lPORT_}/EMBA/${RANDOM}/${RANDOM}.${RANDOM}" -o /dev/null -w '%{http_code}:%{size_download}')
    if [[ "${lCNT}" -ne 0 ]]; then
      # don't wait on first round
      sleep 10
    fi
    lCNT=$((lCNT+1))
  done

  # the refernce size is used for identifying incorrect 200 ok results
  local lCURL_RET=""
  lCURL_RET=$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}://${lIP_}:${lPORT_}/EMBA/${RANDOM}/${RANDOM}.${RANDOM}" -o /dev/null -w '%{http_code}:%{size_download}')
  CURL_RET_CODE="${lCURL_RET//:*}"
  if [[ "${CURL_RET_CODE}" -eq 200 ]]; then
    # we only use the reponse size if we get a 200 ok on a non existing site
    # otherwise we set it to "NA" which means that we do need to check the response size on further requests
    HTTP_RAND_REF_SIZE="${lCURL_RET//*:}"
    print_output "[*] HTTP status detection - 200 ok on random site with reference size: ${HTTP_RAND_REF_SIZE}"
  else
    HTTP_RAND_REF_SIZE="NA"
    print_output "[*] HTTP status detection failed with non 200ok return code: ${CURL_RET_CODE}/${HTTP_RAND_REF_SIZE}"
  fi

  print_output "[*] Init CURL_RET: ${lCURL_RET} / ${HTTP_RAND_REF_SIZE}" "no_log"

  if [[ "${CURL_RET_CODE}" == "000:0" ]]; then
    # this is usually hit if everything was going wrong
    print_output "[*] Invalid hit ${lCURL_RET} / ${HTTP_RAND_REF_SIZE} - stopping now"
    return
  fi

  local lHOME_=""
  lHOME_=$(pwd)
  for lR_PATH in "${ROOT_PATH[@]}" ; do
    # we need files and links (for cgi files)
    cd "${lR_PATH}" || exit 1
    mapfile -t lFILE_ARR_EXT < <(find "." -type f -o -type l || true)

    for lWEB_PATH in "${lFILE_ARR_EXT[@]}"; do
      print_dot

      lWEB_FILE="$(basename "${lWEB_PATH}")"

      # some basic filtering to not handle defect file names
      ! [[ "${lWEB_FILE}" =~ ^[a-zA-Z0-9./_~'-']+$ ]] && continue

      if [[ -n "${lWEB_FILE}" ]] && ! [[ "${lCRAWLED_ARR[*]}" == *" ${lWEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lWEB_FILE}${NC}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
        lCURL_RET="$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}""://""${lIP_}":"${lPORT_}""/""${lWEB_FILE}" -o /dev/null -w '%{http_code}:%{size_download}')"
        check_curl_ret "${lIP_}" "${lPORT_}" "${lCURL_RET}"
        lCRAWLED_ARR+=( "${lWEB_FILE}" )
      fi

      lWEB_DIR_L1="$(dirname "${lWEB_PATH}" | rev | cut -d'/' -f1 | rev)"
      lWEB_DIR_L1="${lWEB_DIR_L1#\.}"
      lWEB_DIR_L1="${lWEB_DIR_L1#\/}"
      if [[ -n "${lWEB_DIR_L1}" ]] && ! [[ "${lCRAWLED_ARR[*]}" == *" ${lWEB_DIR_L1}/${lWEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lWEB_DIR_L1}/${lWEB_FILE}${NC}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
        lCURL_RET="$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}""://""${lIP_}":"${lPORT_}""/""${lWEB_DIR_L1}""/""${lWEB_FILE}" -o /dev/null -w '%{http_code}:%{size_download}')"
        check_curl_ret "${lIP_}" "${lPORT_}" "${lCURL_RET}"
        lCRAWLED_ARR+=( "${lWEB_DIR_L1}/${lWEB_FILE}" )
      fi

      lWEB_DIR_L2="$(dirname "${lWEB_PATH}" | rev | cut -d'/' -f1-2 | rev)"
      lWEB_DIR_L2="${lWEB_DIR_L2#\.}"
      lWEB_DIR_L2="${lWEB_DIR_L2#\/}"
      if [[ -n "${lWEB_DIR_L2}" ]] && [[ "${lWEB_DIR_L2}" != "${lWEB_DIR_L1}" ]] && ! [[ "${lCRAWLED_ARR[*]}" == *" ${lWEB_DIR_L2}/${lWEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lWEB_DIR_L2}/${lWEB_FILE}${NC}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
        lCURL_RET="$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}""://""${lIP_}":"${lPORT_}""/""${lWEB_DIR_L2}""/""${lWEB_FILE}" -o /dev/null -w '%{http_code}:%{size_download}')"
        check_curl_ret "${lIP_}" "${lPORT_}" "${lCURL_RET}"
        lCRAWLED_ARR+=( "${lWEB_DIR_L2}/${lWEB_FILE}" )
      fi

      lWEB_DIR_L3="$(dirname "${lWEB_PATH}" | rev | cut -d'/' -f1-3 | rev)"
      lWEB_DIR_L3="${lWEB_DIR_L3#\.}"
      lWEB_DIR_L3="${lWEB_DIR_L3#\/}"
      if [[ -n "${lWEB_DIR_L3}" ]] && [[ "${lWEB_DIR_L3}" != "${lWEB_DIR_L2}" ]] && [[ "${lWEB_DIR_L3}" != "${lWEB_DIR_L1}" ]] && ! [[ "${lCRAWLED_ARR[*]}" == *" ${lWEB_DIR_L3}/${lWEB_FILE} "* ]]; then
        echo -e "\\n[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lWEB_DIR_L3}/${lWEB_FILE}${NC}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
        lCURL_RET="$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}""://""${lIP_}":"${lPORT_}""/""${lWEB_DIR_L3}""/""${lWEB_FILE}" -o /dev/null -w '%{http_code}:%{size_download}')"
        check_curl_ret "${lIP_}" "${lPORT_}" "${lCURL_RET}"

        lCRAWLED_ARR+=( "${lWEB_DIR_L3}/${lWEB_FILE}" )
      fi

      if ! system_online_check "${lIP_ADDRESS_}" ; then
        if ! restart_emulation "${lIP_ADDRESS_}" "${IMAGE_NAME}" 0 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing web crawling"
          enable_strict_mode "${STRICT_MODE}" 0
          return
        fi
      fi
    done
    cd "${lHOME_}" || exit 1
  done
  enable_strict_mode "${STRICT_MODE}" 0

  # extract started processes from all our qemu logs:
  #
  # find all qemu logs:
  mapfile -t lFILENAME_ARR_QEMU_START < <(find "${LOG_DIR}/l10_system_emulation" -type f -name "qemu.serial.log" | sort -u || true)
  for lFILENAME_QEMU_START in "${lFILENAME_ARR_QEMU_START[@]}"; do
    # find open service names from qemu logs:
    print_output "[*] Testing Qemu log file: ${lFILENAME_QEMU_START}" "no_log"
    mapfile -t lFILENAME_STARTED_PROCESSES_ARR < <(grep -a "inet_bind" "${lFILENAME_QEMU_START}" | cut -d: -f3 | awk -F[\(\)] '{print $2}' | sort -u || true)
    for lFILENAME_QEMU_STARTED in "${lFILENAME_STARTED_PROCESSES_ARR[@]}"; do
      print_output "[*] Searching for filename: ${lFILENAME_QEMU_STARTED}" "no_log"
      # find the names in the filesystem:
      mapfile -t lFILEPATH_QEMU_START_ARR < <(find "${LOG_DIR}"/firmware -name "${lFILENAME_QEMU_STARTED}" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
      # check every file for further possible files to crawl:
      for lFILE_QEMU_START in "${lFILEPATH_QEMU_START_ARR[@]}"; do
        if ! file "${lFILE_QEMU_START}" | grep -q "ELF"; then
          continue
        fi
        print_output "[*] Identification of possible web files in: ${lFILE_QEMU_START}" "no_log"
        mapfile -t lPOSSIBLE_FILES_ARR < <(strings "${lFILE_QEMU_START}" | grep -o -E '[-_a-zA-Z0-9]+\.[a-zA-Z0-9]{3}$' | sort -u || true)
        # crawl all the files:
        for lFILE_QEMU_TEST in "${lPOSSIBLE_FILES_ARR[@]}"; do
          print_output "[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lFILE_QEMU_TEST}${NC}" "no_log"
          echo -e "\\n[*] Testing ${ORANGE}${lPROTO}://${lIP_}:${lPORT_}/${lFILE_QEMU_TEST}${NC}" >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
          lCURL_RET="$(timeout --preserve-status --signal SIGINT 2 curl "${lCURL_OPTS_ARR[@]}" "${lPROTO}""://""${lIP_}":"${lPORT_}""/""${lFILE_QEMU_TEST}" -o /dev/null -w '%{http_code}:%{size_download}' || true)"
          check_curl_ret "${lIP_}" "${lPORT_}" "${lCURL_RET}"
        done
      done
    done
  done

  if [[ -f "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" ]]; then
    grep -A1 Testing "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" | grep -i -B1 "200 OK:" | grep Testing | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/.*${lIP_}:${lPORT}//" | sort -u >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log" || true
    grep -A1 Testing "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log" | grep -i -B1 "401 Unauth:" | grep Testing | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/.*${lIP_}:${lPORT}//" | sort -u >> "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-401Unauth.log" || true
    lCRAWL_RESP_200=$(wc -l < "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log")
    lCRAWL_RESP_401=$(wc -l < "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-401Unauth.log")

    # Colorizing the log file:
    sed -i -r "s/.*HTTP\/.*\ 200\ .*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
    sed -i -r "s/.*HTTP\/.*\ [3-9][0-9][0-9]\ .*/\x1b[31m&\x1b[0m/" "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"

    if [[ "${lCRAWL_RESP_200}" -gt 0 ]]; then
      print_output "[+] Found ${ORANGE}${lCRAWL_RESP_200}${GREEN} unique valid responses - please check the log for further details" "" "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
    fi
    if [[ "${lCRAWL_RESP_401}" -gt 0 ]]; then
      print_output "[+] Found ${ORANGE}${lCRAWL_RESP_401}${GREEN} unique unauthorized responses - please check the log for further details" "" "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
    fi

    if [[ -f "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log" ]] && [[ -f "${LOG_DIR}"/s22_php_check/semgrep_php_results_xml.log ]]; then
      while read -r lWEB_PATH; do
        lWEB_NAME="$(basename "${lWEB_PATH}")"
        mapfile -t lCRAWLED_VULNS_ARR < <(grep "${lWEB_NAME}.*semgrep-rules.php.lang.security" "${S22_CSV_LOG}" || true)
        for lC_VULN in "${lCRAWLED_VULNS_ARR[@]}"; do
          lVULN_NAME=$(echo "${lC_VULN}" | cut -d ';' -f2)
          lVULN_FILE="${lC_VULN/;*}"
          lVULN_FILE=$(basename "${lVULN_FILE}")

          if ! [[ -f "${L25_CSV_LOG}" ]]; then
            write_csv_log "vuln file crawled" "source of vuln" "language" "vuln name" "filesystem path with vuln"
          fi
          print_output "[+] Found possible vulnerability ${ORANGE}${lVULN_NAME}${GREEN} in semgrep analysis for ${ORANGE}${lWEB_NAME}${NC}."
          write_link "s22"
          write_csv_log "${lWEB_NAME}" "semgrep" "php" "${lVULN_NAME}" "${lVULN_FILE}"
        done
      done < "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log"
    fi

    if [[ -f "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log" ]] && [[ -f "${S23_LOG}" ]]; then
      while read -r lWEB_PATH; do
        lWEB_NAME="$(basename "${lWEB_PATH}")"
        mapfile -t lCRAWLED_VULNS_ARR < <(grep "Found lua.*${lWEB_NAME}.*capabilities" "${S23_LOG}" || true)
        for lC_VULN in "${lCRAWLED_VULNS_ARR[@]}"; do
          [[ "${lC_VULN}" == *"command execution"* ]] && lVULN_NAME="os exec"
          [[ "${lC_VULN}" == *"file access"* ]] && lVULN_NAME="file read/write"

          if ! [[ -f "${L25_CSV_LOG}" ]]; then
            write_csv_log "vuln file crawled" "source of vuln" "language" "vuln name" "filesystem path with vuln"
          fi
          print_output "[+] Found possible vulnerability in lua analysis for ${ORANGE}${lWEB_NAME}${NC}." "${S23_LOG}"
          write_csv_log "${lWEB_NAME}" "lua check" "lua" "${lVULN_NAME}" "${lWEB_PATH}"
        done
      done < "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}-200ok.log"
    fi

    # todo: Python, further PHP analysis

    print_output "[*] Finished web server crawling for ${ORANGE}${lIP_}:${lPORT}${NC}." "" "${LOG_PATH_MODULE}/crawling_${lIP_}-${lPORT_}.log"
  else
    print_output "[*] Finished web server crawling for ${ORANGE}${lIP_}:${lPORT}${NC}."
  fi
  print_bar ""
}

make_web_screenshot() {
  local lIP_="${1:-}"
  local lPORT_="${2:-}"
  # http or https for our url:
  local lSSL="${3:-}"

  sub_module_title "Starting screenshot for ${ORANGE}${lIP_}:${lPORT_}${NC}"

  timeout --preserve-status --signal SIGINT 20 "${CHROME_HEADLESS_BIN}" --no-sandbox --hide-scrollbars --window-size=1024,768 --disable-gpu --screenshot="${LOG_PATH_MODULE}"/screenshot_"${lIP_}"_"${lPORT_}".png "${lSSL}://${lIP_}:${lPORT_}" 2>/dev/null || true

  if [[ -f "${LOG_PATH_MODULE}"/screenshot_"${lIP_}"_"${lPORT_}".png ]]; then
    print_output "[+] Screenshot of web server on IP ${ORANGE}${lIP_}:${lPORT_}${NC} created"
    write_link "${LOG_PATH_MODULE}/screenshot_${lIP_}_${lPORT_}.png"
    WEB_RESULTS=1
  else
    print_output "[-] Screenshot of web server on IP ${ORANGE}${lIP_}:${lPORT_}${NC} failed"
  fi
  print_bar ""
}

