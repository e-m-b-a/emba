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

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L22_upnp_hnap_checks() {

  export UPNP_UP=0
  export HNAP_UP=0
  export JNAP_UP=0

  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Live UPnP/HNAP tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ ${IN_DOCKER} -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}"; then
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing UPnP/HNAP checks"
          module_end_log "${FUNCNAME[0]}" "${UPNP_UP}"
          return
        fi
      fi
      if [[ -v HOSTNETDEV_ARR ]]; then
        check_basic_upnp "${HOSTNETDEV_ARR[@]}"
        check_basic_hnap_jnap
        [[ "${JNAP_UP}" -gt 0 ]] && check_jnap_access
      else
        print_output "[!] No network interface found"
      fi
    else
      print_output "[!] No IP address found"
    fi

    write_log ""
    write_log "[*] Statistics:${UPNP_UP}:${HNAP_UP}:${JNAP_UP}"
    module_end_log "${FUNCNAME[0]}" "${UPNP_UP}"
  fi
}

check_basic_upnp() {
  local lINTERFACE_ARR=("$@")
  local lINTERFACE=""

  sub_module_title "UPnP enumeration for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"

  if command -v upnpc > /dev/null; then
    for lINTERFACE in "${lINTERFACE_ARR[@]}"; do
      print_output "[*] UPnP scan with upnpc on local network interface ${ORANGE}${lINTERFACE}${NC}"
      upnpc -m "${lINTERFACE}" -P >> "${LOG_PATH_MODULE}"/upnp-discovery-check.txt || true
      if [[ -f "${LOG_PATH_MODULE}"/upnp-discovery-check.txt ]]; then
        print_ln
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/upnp-discovery-check.txt
        print_ln
      fi
    done
    UPNP_UP=$(grep -c "desc\|IGD" "${LOG_PATH_MODULE}"/upnp-discovery-check.txt || true)
  fi

  if [[ "${UPNP_UP}" -gt 0 ]]; then
    UPNP_UP=1
    print_output "[+] UPnP service successfully identified"
  fi

  print_ln
  print_output "[*] UPnP basic enumeration finished"
}

check_basic_hnap_jnap() {
  local lPORT=""
  local lSERVICE=""
  local lSSL=0
  local lPORT_SERVICE=""

  sub_module_title "HNAP/JNAP enumeration for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"

  if [[ "${#NMAP_PORTS_SERVICES_ARR[@]}" -gt 0 ]]; then
    for lPORT_SERVICE in "${NMAP_PORTS_SERVICES_ARR[@]}"; do
      [[ "${HNAP_UP}" -eq 1 && "${JNAP_UP}" -eq 1 ]] && break

      lPORT=$(echo "${lPORT_SERVICE}" | cut -d/ -f1 | tr -d "[:blank:]")
      lSERVICE=$(echo "${lPORT_SERVICE}" | awk '{print $2}' | tr -d "[:blank:]")
      if [[ "${lSERVICE}" == "unknown" ]] || [[ "${lSERVICE}" == "tcpwrapped" ]]; then
        continue
      fi

      if [[ "${lSERVICE}" == *"ssl|http"* ]] || [[ "${lSERVICE}" == *"ssl/http"* ]];then
        lSSL=1
      elif [[ "${lSERVICE}" == *"http"* ]];then
        lSSL=0
      else
        # no http service - check the next one
        continue
      fi

      print_output "[*] Analyzing service ${ORANGE}${lSERVICE} - ${lPORT} - ${IP_ADDRESS_}${NC}" "no_log"

      if ! command -v curl > /dev/null; then
        print_output "[-] WARNING: No curl command available - your installation seems to be weird"
        return
      fi

      # we use the following JNAP-Action for identifying JNAP services on Linksys routers:
      local lJNAP_ACTION="X-JNAP-Action: http://cisco.com/jnap/core/GetDeviceInfo"
      if [[ "${lSSL}" -eq 0 ]]; then
        # HNAP
        curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET http://"${IP_ADDRESS_}":"${lPORT}"/HNAP/ >> "${LOG_PATH_MODULE}"/hnap-discovery-check.txt || true
        curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET http://"${IP_ADDRESS_}":"${lPORT}"/HNAP1/ >> "${LOG_PATH_MODULE}"/hnap-discovery-check.txt || true
        # JNAP
        curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X POST -H "${lJNAP_ACTION}" -d "{}" http://"${IP_ADDRESS_}":"${lPORT}"/JNAP/ >> "${LOG_PATH_MODULE}"/jnap-discovery-check.txt || true
      else
        # HNAP - SSL
        curl -v -L -k --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET https://"${IP_ADDRESS_}":"${lPORT}"/HNAP/ >> "${LOG_PATH_MODULE}"/hnap-discovery-check.txt || true
        curl -v -L -k --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET https://"${IP_ADDRESS_}":"${lPORT}"/HNAP1/ >> "${LOG_PATH_MODULE}"/hnap-discovery-check.txt || true
        # JNAP - SSL
        curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X POST -H "${lJNAP_ACTION}" -d "{}" https://"${IP_ADDRESS_}":"${lPORT}"/JNAP/ >> "${LOG_PATH_MODULE}"/jnap-discovery-check.txt || true
      fi

      if [[ -s "${LOG_PATH_MODULE}"/hnap-discovery-check.txt ]]; then
        print_ln
        # tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/hnap-discovery-check.txt
        sed 's/></>\n</g' "${LOG_PATH_MODULE}"/hnap-discovery-check.txt | tee -a "${LOG_FILE}"
        print_ln

        HNAP_UP=$(grep -c "HNAP1" "${LOG_PATH_MODULE}"/hnap-discovery-check.txt || true)
      fi

      if [[ -s "${LOG_PATH_MODULE}"/jnap-discovery-check.txt ]]; then
        print_ln
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/jnap-discovery-check.txt
        print_ln

        JNAP_UP=$(grep -c "/jnap/" "${LOG_PATH_MODULE}"/jnap-discovery-check.txt || true)
      fi


      if [[ "${HNAP_UP}" -gt 0 ]]; then
        HNAP_UP=1
        print_output "[+] HNAP service successfully identified"
      fi
      if [[ "${JNAP_UP}" -gt 0 ]]; then
        JNAP_UP=1
        print_output "[+] JNAP service successfully identified"
      fi

    done
  fi

  print_ln
  print_output "[*] HNAP/JNAP basic enumeration finished"
}

check_jnap_access() {
  sub_module_title "JNAP enumeration for unauthenticated JNAP endpoints"

  local lJNAP_ENDPOINTS_ARR=()
  local lSYSINFO_CGI_ARR=()
  local lSYSINFO_CGI=""
  local lJNAP_EPT=""
  local lJNAP_EPT_NAME=""

  mapfile -t lJNAP_ENDPOINTS_ARR < <(find "${LOG_DIR}"/firmware -type f -exec grep -a "\[.*/jnap/.*\]\ =" {} \; | cut -d\' -f2 | sort -u 2>/dev/null || true)

  # Todo: PORT!!!
  local lPORT=80

  # https://korelogic.com/Resources/Advisories/KL-001-2015-006.txt
  mapfile -t lSYSINFO_CGI_ARR < <(find "${LOG_DIR}"/firmware -type f -name "sysinfo.cgi" -o -name "getstinfo.cgi"| sort -u 2>/dev/null || true)

  for lSYSINFO_CGI in "${lSYSINFO_CGI_ARR[@]}"; do
    print_output "[*] Testing for sysinfo.cgi" "no_log"
    curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X GET http://"${IP_ADDRESS_}":"${lPORT}"/"${lSYSINFO_CGI}" > "${LOG_PATH_MODULE}"/JNAP_"${lSYSINFO_CGI}".log || true

    if [[ -f "${LOG_PATH_MODULE}"/JNAP_"${lSYSINFO_CGI}".log ]]; then
      if grep -q "wl0_ssid=\|wl1_ssid=\|wl0_passphrase=\|wl1_passphrase=\|wps_pin=\|default_passphrase=" "${LOG_PATH_MODULE}"/JNAP_"${lSYSINFO_CGI}".log; then
        print_output "[+] Found sensitive information in sysinfo.cgi - see https://korelogic.com/Resources/Advisories/KL-001-2015-006.txt:"
        grep "wl0_ssid=\|wl1_ssid=\|wl0_passphrase=\|wl1_passphrase=\|wps_pin=\|default_passphrase=" "${LOG_PATH_MODULE}"/JNAP_"${lSYSINFO_CGI}".log | tee -a "${LOG_FILE}"
      fi
    fi
  done

  for lJNAP_EPT in "${lJNAP_ENDPOINTS_ARR[@]}"; do
    print_output "[*] Testing JNAP action: ${ORANGE}${lJNAP_EPT}${NC}" "no_log"
    lJNAP_EPT_NAME="$(echo "${lJNAP_EPT}" | rev | cut -d '/' -f1 | rev)"
    local lJNAP_ACTION="X-JNAP-Action: ${lJNAP_EPT}"
    local lDATA="{}"
    curl -v -L --noproxy '*' --max-redirs 0 -f -m 5 -s -X POST -H "${lJNAP_ACTION}" -d "${lDATA}" http://"${IP_ADDRESS_}":"${lPORT}"/JNAP/ > "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log || true

    if [[ -s "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log ]]; then
      if grep -q "_ErrorUnauthorized" "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log; then
        print_output "[-] Authentication needed for ${ORANGE}${lJNAP_EPT}${NC}" "no_log"
        [[ -f "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log ]] && rm "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log
      fi
      if [[ -f "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log ]] && grep -q "_ErrorInvalidInput" "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log; then
        print_output "[-] Invalid request detected for ${ORANGE}${lJNAP_EPT}${NC}" "no_log"
        [[ -f "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log ]] && rm "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log
      fi
    else
      rm "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log
    fi

    if [[ -f "${LOG_PATH_MODULE}"/JNAP_"${lJNAP_EPT_NAME}".log ]]; then
      print_output "[+] Unauthenticated JNAP endpoint detected - ${ORANGE}${lJNAP_EPT_NAME}${NC}" "" "${LOG_PATH_MODULE}/JNAP_${lJNAP_EPT_NAME}.log"
    fi
  done
}
