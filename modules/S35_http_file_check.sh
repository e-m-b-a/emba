#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
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

  export HTTP_COUNTER=0

  write_csv_log "type" "filename" "file"
  web_file_search
  http_file_search
  webserver_check
  php_check

  module_end_log "${FUNCNAME[0]}" "${HTTP_COUNTER}"
}

web_file_search()
{
  sub_module_title "Search web served files"

  local lWEB_STUFF_ARR=()
  local lWEB_FILE=""

  # mapfile -t lWEB_STUFF_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f \( -iname "*.htm" -o -iname "*.html" -o -iname "*.cgi" \
  #  -o -iname "*.asp" -o -iname "*.php" -o -iname "*.xml" -o -iname "*.rg" \) -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' \
  #  | sort -u -k1,1 | cut -d\  -f3)
  mapfile -t lWEB_STUFF_ARR < <(grep ".htm;\|.html\|.cgi\|.asp\|.php\|.xml\|.rg" "${P99_CSV_LOG}" | sort -u || true)

  if [[ -v lWEB_STUFF_ARR[@] ]] ; then
    print_output "[+] Found web related files:"
    for lWEB_FILE in "${lWEB_STUFF_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lWEB_FILE/;*}")")"
      write_csv_log "Web served files" "$(basename "${lWEB_FILE/;*}")" "${lWEB_FILE/;*}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No web related files found"
  fi
}

http_file_search()
{
  sub_module_title "Search http files"

  local lHTTP_STUFF_ARR=()
  local lHTTP_FILE=""
  mapfile -t lHTTP_STUFF_ARR < <(config_find "${CONFIG_DIR}""/http_files.cfg")

  if [[ "${lHTTP_STUFF_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lHTTP_STUFF_ARR[@]}" -ne 0 ]] ; then
    print_output "[+] Found http related files:"
    for lHTTP_FILE in "${lHTTP_STUFF_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lHTTP_FILE}")")"
      write_csv_log "HTTP server files" "$(basename "${lHTTP_FILE}")" "${lHTTP_FILE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No http related files found"
  fi
}

webserver_check()
{
  sub_module_title "Check for apache or nginx related files"

  local lAPACHE_FILE_ARR=()
  local lNGINX_FILE_ARR=()
  local lLIGHTTP_FILE_ARR=()
  local lCHEROKEE_FILE_ARR=()
  local lHTTPD_FILE_ARR=()
  local lLINE=""

  # readarray -t lAPACHE_FILE_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*apache*' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lAPACHE_FILE_ARR < <(grep "apache" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)
  # readarray -t lNGINX_FILE_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*nginx*' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lAPACHE_FILE_ARR < <(grep "nginx" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)
  # readarray -t lLIGHTTP_FILE_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*lighttp*' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lAPACHE_FILE_ARR < <(grep "lighttp" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)
  # readarray -t lCHEROKEE_FILE_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*cheroke*' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lAPACHE_FILE_ARR < <(grep "cheroke" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)
  # readarray -t lHTTPD_FILE_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*httpd*' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lAPACHE_FILE_ARR < <(grep "httpd" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)

  if [[ ${#lAPACHE_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Apache related files:"
    for lLINE in "${lAPACHE_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      write_csv_log "Apache web server file" "$(basename "${lLINE}")" "${lLINE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No Apache related files found"
  fi

  if [[ ${#lNGINX_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found nginx related files:"
    for lLINE in "${lNGINX_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      write_csv_log "Nginx web server file" "$(basename "${lLINE}")" "${lLINE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No nginx related files found"
  fi

  if [[ ${#lLIGHTTP_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Lighttpd related files:"
    for lLINE in "${lLIGHTTP_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      write_csv_log "Lighttpd web server file" "$(basename "${lLINE}")" "${lLINE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No Lighttpd related files found"
  fi

  if [[ ${#lCHEROKEE_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Cherokee related files:"
    for lLINE in "${lCHEROKEE_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      write_csv_log "Cherokee web server file" "$(basename "${lLINE}")" "${lLINE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No Cherokee related files found"
  fi

  if [[ ${#lHTTPD_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found HTTPd related files:"
    for lLINE in "${lHTTPD_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      write_csv_log "HTTPd web server file" "$(basename "${lLINE}")" "${lLINE}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No HTTPd related files found"
  fi
}

php_check()
{
  sub_module_title "Check for php.ini"
  local lPHP_INI_ARR=()
  local lPHP_INI_ENTRY=""

  # readarray -t lPHP_INI_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*php.ini' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 )
  readarray -t lPHP_INI_ARR < <(grep "php.ini" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)

  if [[ ${#lPHP_INI_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found php.ini:"
    for lPHP_INI_ENTRY in "${lPHP_INI_ARR[@]}" ; do
      print_output "$(indent "$(print_path "${lPHP_INI_ENTRY}")")"
      write_csv_log "php.ini file" "$(basename "${lPHP_INI_ENTRY}")" "${lPHP_INI_ENTRY}"
      ((HTTP_COUNTER+=1))
    done
  else
    print_output "[-] No php.ini found"
  fi
}
