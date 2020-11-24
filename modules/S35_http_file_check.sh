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
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check for web server related files, web server and php.ini
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S35_http_file_check()
{
  module_log_init "s35_check_http_file"
  module_title "Check HTTP files"
  CONTENT_AVAILABLE=0
  
  http_file_search
  webserver_check
  php_check
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

http_file_search()
{
  sub_module_title "Search http files"

  local HTTP_STUFF
  HTTP_STUFF="$(config_find "$CONFIG_DIR""/http_files.cfg" "")"

  if [[ "$HTTP_STUFF" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -z "$HTTP_STUFF" ]] ; then
    print_output "[+] Found http related files:"
    for LINE in $HTTP_STUFF ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No http related files found"
  fi
}

webserver_check()
{
  sub_module_title "Check for apache or nginx related files"

  readarray -t APACHE_FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*apache*' )
  readarray -t NGINX_FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*nginx*' )
  readarray -t LIGHTTP_FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*lighttp*' )
  readarray -t CHEROKEE_FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*cheroke*' )
  readarray -t HTTPD_FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*httpd*' )

  if [[ ${#APACHE_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Apache related files:"
    for LINE in "${APACHE_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No Apache related files found"
  fi

  if [[ ${#NGINX_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found nginx related files:"
    for LINE in "${NGINX_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No nginx related files found"
  fi

  if [[ ${#LIGHTTP_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Lighttpd related files:"
    for LINE in "${LIGHTTP_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No Lighttpd related files found"
  fi

  if [[ ${#CHEROKEE_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found Cherokee related files:"
    for LINE in "${CHEROKEE_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No Cherokee related files found"
  fi

  if [[ ${#HTTPD_FILE_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found HTTPd related files:"
    for LINE in "${HTTPD_FILE_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No HTTPd related files found"
  fi

}

php_check()
{
  sub_module_title "Check for php.ini"

  readarray -t PHP_INI_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*php.ini' )

  if [[ ${#PHP_INI_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found php.ini:"
    for LINE in "${PHP_INI_ARR[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[!] No php.ini found"
  fi
}
