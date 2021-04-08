#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Determines kernel version and description and checks for kernel configuration. 
#               It uses linux-exploit-suggester to check for possible kernel exploits and analyzes kernel modules to find which 
#               license they have and if they are stripped. 
#               It also looks for the modprobe.d directory and lists its content.

S25_kernel_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check kernel"

  # This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_kernel

  KERNEL_VERSION=()
  KERNEL_DESC=()
  LOG_FILE="$( get_log_file )"

  if [[ "$KERNEL" -eq 0 ]] && [[ "$FIRMWARE" -eq 1 ]] ; then

    populate_karrays

    if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
      print_output "Kernel version:"
      for LINE in "${KERNEL_VERSION[@]}" ; do
        print_output "$(indent "$LINE")"
      done
      if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
        print_output "Kernel details:"
        for LINE in "${KERNEL_DESC[@]}" ; do
          print_output "$(indent "$LINE")"
        done
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

  elif [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 1 ]] ; then

    populate_karrays

    if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
      print_output "Kernel version:"
      for LINE in "${KERNEL_VERSION[@]}" ; do
        print_output "$(indent "$LINE")"
      done
      if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
        print_output "Kernel details:"
        for LINE in "${KERNEL_DESC[@]}" ; do
          print_output "$(indent "$LINE")"
        done
      fi
      print_output "[*] Check kernel configuration ""$(print_path "$KERNEL_CONFIG" )"" via checksec.sh"
      print_output "$("$EXT_DIR""/checksec" --kernel="$KERNEL_CONFIG")"

      get_kernel_vulns
      check_modprobe

    else
      print_output "[-] No kernel found"
    fi
  fi

  if [[ ${#KV_C_ARR[@]} -ne 0 ]] ; then
    for LINE in "${KV_C_ARR[@]}" ; do
      echo "[*] Statistics:$LINE" >> "$LOG_FILE"
    done
  fi
  echo "[*] Statistics1:${#KERNEL_MODULES[@]}:$KMOD_BAD" >> "$LOG_FILE"

  module_end_log "${FUNCNAME[0]}" "${#KERNEL_VERSION[@]}"
}

populate_karrays() {
  mapfile -t KERNEL_MODULES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -iname "*.ko" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  for K_MODULE in "${KERNEL_MODULES[@]}"; do
    KERNEL_VERSION+=( "$(modinfo "$K_MODULE" 2>/dev/null | grep -E "vermagic" | cut -d: -f2 | sed 's/^ *//g')" )
    KERNEL_DESC+=( "$(modinfo "$K_MODULE" 2>/dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g' | tr -c '[:alnum:]\n\r' '_')" )
  done

  # unique our results
  eval "KERNEL_VERSION=($(for i in "${KERNEL_VERSION[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  eval "KERNEL_DESC=($(for i in "${KERNEL_DESC[@]}" ; do echo "\"$i\"" ; done | sort -u))"
}

get_kernel_vulns()
{
  sub_module_title "Kernel vulnerabilities"

  if [[ "${#KERNEL_VERSION[@]}" -gt 0 ]]; then
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
        KV=$(echo "$KV" | tr "_" " ")
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
    else
      print_output "[-] linux-exploit-suggester.sh is not installed"
      print_output "$(indent "https://github.com/mzet-/linux-exploit-suggester")"
    fi
  else
      print_output "[-] No linux kernel version information found."
  fi
}

analyze_kernel_module()
{
  sub_module_title "Analyze kernel modules"

  KMOD_BAD=0

  print_output "[*] Found ${#KERNEL_MODULES[@]} kernel modules."

  for LINE in "${KERNEL_MODULES[@]}" ; do
    LINE=$(modinfo "$LINE" | grep -E "filename|license" | cut -d: -f1,2 | sed ':a;N;$!ba;s/\nlicense//g' | sed 's/filename: //' | sed 's/ //g' | sed 's/:/||license:/')
    local M_PATH
    M_PATH="$( echo "$LINE" | cut -d '|' -f 1 )"
    local LICENSE
    LICENSE="$( echo "$LINE" | cut -d '|' -f 3 | sed 's/license:/License: /' )"
    if file "$M_PATH" 2>/dev/null | grep -q 'not stripped'; then
      if echo "$LINE" | grep -q -e 'license:*GPL' -e 'license:.*BSD' ; then
        # kernel module is GPL/BSD license then not stripped is fine
        print_output "[-] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""$LICENSE""${NC}"" - ""${GREEN}""NOT STRIPPED""${NC}"
      elif ! [[ $LICENSE =~ "License:" ]] ; then
        print_output "[+] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""License not found""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
      else
        # kernel module is NOT GPL license then not stripped is bad!
        print_output "[+] Found kernel module ""${NC}""$(print_path "$M_PATH")""  ${ORANGE}""$LICENSE""${NC}"" - ""${RED}""NOT STRIPPED""${NC}"
        KMOD_BAD=$((KMOD_BAD+1))
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
  readarray -t MODPROBE_D_DIRS < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*modprobe.d*' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for MP_DIR in "${MODPROBE_D_DIRS[@]}"; do
    if [[ -d "$MP_DIR" ]] ; then
      MP_CHECK=1
      print_output "[+] Found ""$(print_path "$MP_DIR")"
      readarray -t MODPROBE_D_DIR_CONTENT <<< "$( find "$MP_DIR" -xdev -iname '*.conf' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )"
      for MP_CONF in "${MODPROBE_D_DIR_CONTENT[@]}"; do
        if [[ -e "$MP_CONF" ]] ; then
          MP_F_CHECK=1
          print_output "$(indent "$(orange "$(print_path "$MP_CONF")")")"
        fi
      done
      if [[ $MP_F_CHECK -eq 0 ]] ; then
        print_output "[-] No config files in modprobe.d directory found"
      fi
    fi
  done
  if [[ $MP_CHECK -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  fi
}

