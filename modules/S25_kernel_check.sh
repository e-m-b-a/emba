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

# Description:  Check kernel configuration file, look for vulnerabilities with linux-exploit-suggester, analyze kernel
#               modules and check modprobe directory for loadable kernel modules
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S25_kernel_check()
{
  module_log_init "s25_check_kernel"
  module_title "Check kernel"
  CONTENT_AVAILABLE=0

  # This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_kernel

  if [[ "$KERNEL" -eq 0 ]] && [[ "$FIRMWARE" -eq 1 ]] ; then
    mapfile -t KERNEL_VERSION < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -iname "*.ko" -execdir modinfo {} \; 2> /dev/null | grep -E "vermagic" | cut -d: -f2 | sort -u | sed 's/^ *//g' 2> /dev/null)
    mapfile -t KERNEL_DESC < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -iname "*.ko" -execdir modinfo {} \; 2> /dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g')
    if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
      print_output "Kernel version:"
      for LINE in "${KERNEL_VERSION[@]}" ; do
        print_output "$(indent "$LINE")"
      done
      if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
        print_output "Kernel description:"
        for LINE in "${KERNEL_DESC[@]}" ; do
          print_output "$(indent "$LINE")"
        done
        CONTENT_AVAILABLE=1
      fi
      print_output "[-] No check for kernel configuration"

      get_kernel_vulns
      analyze_kernel_module
      check_modprobe
    else
      print_output "[-] No kernel found"
    fi

  elif [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]]  ; then
    print_output "[*] Check kernel configuration ""$(print_path "$KERNEL_CONFIG" )"" via checksec.sh"
    print_output "$("$EXT_DIR""/checksec" --kernel="$KERNEL_CONFIG")"
    CONTENT_AVAILABLE=1

  elif [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 1 ]] ; then
    mapfile -t KERNEL_VERSION < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -iname "*.ko" -execdir modinfo {} \; 2> /dev/null | grep -E "vermagic" | cut -d: -f2 | sort -u | sed 's/^ *//g' 2> /dev/null)
    mapfile -t KERNEL_DESC < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -iname "*.ko" -execdir modinfo {} \; 2> /dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g')
    if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
      print_output "Kernel version:"
      for LINE in "${KERNEL_VERSION[@]}" ; do
        print_output "$(indent "$LINE")"
      done
      if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
        print_output "Kernel description:"
        for LINE in "${KERNEL_DESC[@]}" ; do
          print_output "$(indent "$LINE")"
        done
        CONTENT_AVAILABLE=1
      fi
      print_output "[*] Check kernel configuration ""$(print_path "$KERNEL_CONFIG" )"" via checksec.sh"
      print_output "$("$EXT_DIR""/checksec" --kernel="$KERNEL_CONFIG")"

      get_kernel_vulns
      #analyze_kernel_module
      check_modprobe
    else
      print_output "[-] No kernel found"
    fi
  fi
  
    
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

get_kernel_vulns()
{
  sub_module_title "Kernel vulnerabilities"

  print_output "[+] Found linux kernel version/s:"
  for VER in "${KERNEL_VERSION[@]}" ; do
    print_output "$(indent "$VER")"
  done

  if [[ -f "$EXT_DIR""/linux-exploit-suggester.sh" ]] ; then
    print_output "[*] Searching for possible exploits via linux-exploit-suggester.sh"
    print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
    # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
    local KV_ARR
    for VER in "${KERNEL_VERSION[@]}" ; do
      local KV
      KV=$(echo "$VER" | tr "-" " ")
      KV=$(echo "$KV" | tr "+" " ")
      KV=$(echo "$KV" | cut -d\  -f1)

      while echo "$KV" | grep -q '[a-zA-Z]'; do
        KV="${KV::-1}"
      done
      KV_ARR=("${KV_ARR[@]}" "$KV")
    done
    IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    for V in "${KV_C_ARR[@]}" ; do
      print_output "$( "$EXT_DIR""/linux-exploit-suggester.sh" -f -d -k "$V")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] linux-exploit-suggester.sh is not installed"
    print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
  fi
}

analyze_kernel_module()
{
  sub_module_title "Analyze kernel modules"

  local MOD_DATA
  MOD_DATA="$(find "$FIRMWARE_PATH" -iname "*.ko" -execdir modinfo {} \; 2> /dev/null | grep -E "filename|license" | cut -d: -f1,2 | \
  sed ':a;N;$!ba;s/\nlicense//g' | sed 's/filename: //' | sed 's/ //g' | sed 's/:/||license:/' 2> /dev/null)"
  local MOD_COUNT
  MOD_COUNT=$(echo "$MOD_DATA" | wc -l)
  print_output "[*] Found ""$MOD_COUNT"" kernel modules"

  for LINE in $MOD_DATA ; do
    local M_PATH
    M_PATH="$( echo "$LINE" | cut -d '|' -f 1 )"
    local LICENSE
    LICENSE="$( echo "$LINE" | cut -d '|' -f 3 | sed 's/license:/License: /' )"
    if file "$M_PATH" 2>/dev/null | grep -q 'not stripped'; then
      if echo "$LINE" | grep -q -e 'license:GPL' -e 'license:.*BSD' ; then
        # kernel module is GPL/BSD license then not stripped is fine
        print_output "[-] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""$LICENSE""${NC}"" - ""${GREEN}""NOT STRIPPED""${NC}"
      elif ! [[ $LICENSE =~ "License:" ]] ; then
        print_output "[+] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""License not found""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
        CONTENT_AVAILABLE=1
      else
        # kernel module is NOT GPL license then not stripped is bad!
        print_output "[+] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""$LICENSE""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
        CONTENT_AVAILABLE=1
      fi
    else
      print_output "[-] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""$LICENSE""${NC}"" - ""${GREEN}""STRIPPED""${NC}"
    fi
  done
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_usb

check_modprobe()
{
  sub_module_title "Check modprobe.d directory and content (loadable kernel module config)"

  local MODPROBE_D_DIRS MP_CHECK=0 MP_F_CHECK=0
  readarray -t MODPROBE_D_DIRS < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*modprobe.d*' )
  for MP_DIR in "${MODPROBE_D_DIRS[@]}"; do
    if [[ -d "$MP_DIR" ]] ; then
      MP_CHECK=1
      print_output "[+] Found ""$(print_path "$MP_DIR")"
      readarray -t MODPROBE_D_DIR_CONTENT <<< "$( find "$MP_DIR" -xdev -iname '*.conf' )"
      for MP_CONF in "${MODPROBE_D_DIR_CONTENT[@]}"; do
        if [[ -e "$MP_CONF" ]] ; then
          MP_F_CHECK=1
          print_output "$(indent "$(orange "$(print_path "$MP_CONF")")")"
        fi
      done
      if [[ $MP_F_CHECK -eq 0 ]] ; then
        print_output "[-] No config files in modprobe.d directory found"
      else
        CONTENT_AVAILABLE=1
      fi
    fi
  done
  if [[ $MP_CHECK -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  else
    CONTENT_AVAILABLE=1
  fi
}

