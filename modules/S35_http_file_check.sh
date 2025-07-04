#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches for http and webserver (Apache, nginx, Lighttpd, etc.) related files and checks for php.ini.

S35_http_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check HTTP files"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S35_ARR=()

  write_csv_log "type" "filename" "file"

  web_file_search &
  local lTMP_PID="$!"
  store_kill_pids "${lTMP_PID}"
  lWAIT_PIDS_S35_ARR+=( "${lTMP_PID}" )

  http_file_search &
  local lTMP_PID="$!"
  store_kill_pids "${lTMP_PID}"
  lWAIT_PIDS_S35_ARR+=( "${lTMP_PID}" )

  webserver_check &
  local lTMP_PID="$!"
  store_kill_pids "${lTMP_PID}"
  lWAIT_PIDS_S35_ARR+=( "${lTMP_PID}" )

  php_check &
  local lTMP_PID="$!"
  store_kill_pids "${lTMP_PID}"
  lWAIT_PIDS_S35_ARR+=( "${lTMP_PID}" )

  wait_for_pid "${lWAIT_PIDS_S35_ARR[@]}"

  # Reporting - we report now to ensure our output is not destroyed from threading
  if [[ -s "${LOG_PATH_MODULE}"/php_check.txt ]]; then
    sub_module_title "Check for php.ini"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/php_check.txt
    if grep -v -q "No.*found" "${LOG_PATH_MODULE}"/php_check.txt; then
      lNEG_LOG=1
    fi
  fi

  if [[ -s "${LOG_PATH_MODULE}"/web_file_search.txt ]]; then
    sub_module_title "Search web served files"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/web_file_search.txt
    if grep -v -q "No.*found" "${LOG_PATH_MODULE}"/web_file_search.txt; then
      lNEG_LOG=1
    fi
  fi

  if [[ -s "${LOG_PATH_MODULE}"/http_file_search.txt ]]; then
    sub_module_title "Search http files"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/http_file_search.txt
    if grep -v -q "No.*found" "${LOG_PATH_MODULE}"/http_file_search.txt; then
      lNEG_LOG=1
    fi
  fi

  if [[ -s "${LOG_PATH_MODULE}"/webserver_search.txt ]]; then
    sub_module_title "Check for apache or nginx related files"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/webserver_search.txt
    if grep -v -q "No.*found" "${LOG_PATH_MODULE}"/webserver_search.txt; then
      lNEG_LOG=1
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

web_file_search()
{
  local lWEB_STUFF_ARR=()
  local lWEB_FILE=""

  # mapfile -t lWEB_STUFF_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f \( -iname "*.htm" -o -iname "*.html" -o -iname "*.cgi" \
  #  -o -iname "*.asp" -o -iname "*.php" -o -iname "*.xml" -o -iname "*.rg" \) -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' \
  #  | sort -u -k1,1 | cut -d\  -f3)
  mapfile -t lWEB_STUFF_ARR < <(grep ".htm;\|.html\|.cgi\|.asp\|.php\|.xml\|.rg" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ "${#lWEB_STUFF_ARR[@]}" -gt 0 ]] ; then
    write_log "[+] Found web related files:" "${LOG_PATH_MODULE}"/web_file_search.txt
    for lWEB_FILE in "${lWEB_STUFF_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lWEB_FILE/;*}")")" "${LOG_PATH_MODULE}"/web_file_search.txt &
      write_csv_log "Web served files" "$(basename "${lWEB_FILE/;*}")" "${lWEB_FILE/;*}" &
    done
  else
    write_log "[-] No web related files found" "${LOG_PATH_MODULE}"/web_file_search.txt
  fi
}

http_file_search()
{
  local lHTTP_STUFF_ARR=()
  local lHTTP_FILE=""
  mapfile -t lHTTP_STUFF_ARR < <(config_find "${CONFIG_DIR}""/http_files.cfg")

  if [[ "${lHTTP_STUFF_ARR[0]-}" == "C_N_F" ]] ; then print_error "[!] Config not found"
  elif [[ "${#lHTTP_STUFF_ARR[@]}" -ne 0 ]] ; then
    write_log "[+] Found http related files:" "${LOG_PATH_MODULE}"/http_file_search.txt
    for lHTTP_FILE in "${lHTTP_STUFF_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lHTTP_FILE}")")" "${LOG_PATH_MODULE}"/http_file_search.txt
      write_csv_log "HTTP server files" "$(basename "${lHTTP_FILE}")" "${lHTTP_FILE}"
    done
  else
    write_log "[-] No http related files found" "${LOG_PATH_MODULE}"/http_file_search.txt
  fi
}

webserver_check()
{
  local lAPACHE_FILE_ARR=()
  local lNGINX_FILE_ARR=()
  local lLIGHTTP_FILE_ARR=()
  local lCHEROKEE_FILE_ARR=()
  local lHTTPD_FILE_ARR=()
  local lLINE=""

  readarray -t lAPACHE_FILE_ARR < <(grep -a -i "apache" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  readarray -t lNGINX_FILE_ARR < <(grep -a -i "nginx" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  readarray -t lLIGHTTP_FILE_ARR < <(grep -a -i "lighttp" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  readarray -t lCHEROKEE_FILE_ARR < <(grep -a -i "cheroke" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  readarray -t lHTTPD_FILE_ARR < <(grep -a -i "httpd" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ ${#lAPACHE_FILE_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found Apache related files:" "${LOG_PATH_MODULE}"/webserver_search.txt
    for lLINE in "${lAPACHE_FILE_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lLINE}")")" "${LOG_PATH_MODULE}"/webserver_search.txt
      write_csv_log "Apache web server file" "$(basename "${lLINE}")" "${lLINE}"
    done
  else
    write_log "[-] No Apache related files found" "${LOG_PATH_MODULE}"/webserver_search.txt
  fi

  if [[ ${#lNGINX_FILE_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found nginx related files:" "${LOG_PATH_MODULE}"/webserver_search.txt
    for lLINE in "${lNGINX_FILE_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lLINE}")")" "${LOG_PATH_MODULE}"/webserver_search.txt
      write_csv_log "Nginx web server file" "$(basename "${lLINE}")" "${lLINE}"
    done
  else
    write_log "[-] No nginx related files found" "${LOG_PATH_MODULE}"/webserver_search.txt
  fi

  if [[ ${#lLIGHTTP_FILE_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found Lighttpd related files:" "${LOG_PATH_MODULE}"/webserver_search.txt
    for lLINE in "${lLIGHTTP_FILE_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lLINE}")")" "${LOG_PATH_MODULE}"/webserver_search.txt
      write_csv_log "Lighttpd web server file" "$(basename "${lLINE}")" "${lLINE}"
    done
  else
    write_log "[-] No Lighttpd related files found" "${LOG_PATH_MODULE}"/webserver_search.txt
  fi

  if [[ ${#lCHEROKEE_FILE_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found Cherokee related files:" "${LOG_PATH_MODULE}"/webserver_search.txt
    for lLINE in "${lCHEROKEE_FILE_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lLINE}")")" "${LOG_PATH_MODULE}"/webserver_search.txt
      write_csv_log "Cherokee web server file" "$(basename "${lLINE}")" "${lLINE}"
    done
  else
    write_log "[-] No Cherokee related files found" "${LOG_PATH_MODULE}"/webserver_search.txt
  fi

  if [[ ${#lHTTPD_FILE_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found HTTPd related files:" "${LOG_PATH_MODULE}"/webserver_search.txt
    for lLINE in "${lHTTPD_FILE_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lLINE}")")" "${LOG_PATH_MODULE}"/webserver_search.txt
      write_csv_log "HTTPd web server file" "$(basename "${lLINE}")" "${lLINE}"
    done
  else
    write_log "[-] No HTTPd related files found" "${LOG_PATH_MODULE}"/webserver_search.txt
  fi
}

php_check()
{
  local lPHP_INI_ARR=()
  local lPHP_INI_ENTRY=""

  readarray -t lPHP_INI_ARR < <(grep "php.ini" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ ${#lPHP_INI_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found php.ini:" "${LOG_PATH_MODULE}"/php_check.txt
    for lPHP_INI_ENTRY in "${lPHP_INI_ARR[@]}" ; do
      write_log "$(indent "$(print_path "${lPHP_INI_ENTRY}")")" "${LOG_PATH_MODULE}"/php_check.txt
      write_csv_log "php.ini file" "$(basename "${lPHP_INI_ENTRY}")" "${lPHP_INI_ENTRY}"
    done
  else
    write_log "[-] No php.ini found" "${LOG_PATH_MODULE}"/php_check.txt
  fi
}
