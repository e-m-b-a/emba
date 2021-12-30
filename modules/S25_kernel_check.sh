#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Determines kernel version and description and checks for kernel configuration. 
#               It uses linux-exploit-suggester to check for possible kernel exploits and analyzes kernel modules to find which 
#               license they have and if they are stripped. 
#               It also looks for the modprobe.d directory and lists its content.

S25_kernel_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Identify and check kernel version"

  KERNEL_VERSION=()
  KERNEL_DESC=()
  FOUND=0

  # This module waits for S24_kernel_bin_identifier
  # check emba.log for S24_kernel_bin_identifier starting
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 ]]; do
      sleep 1
    done
  fi

  # This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_kernel

  if [[ "$KERNEL" -eq 0 ]] && [[ "$FIRMWARE" -eq 1 ]] ; then

    populate_karrays

    if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
      print_output "Kernel version:"
      for LINE in "${KERNEL_VERSION[@]}" ; do
        print_output "$(indent "$LINE")"
        FOUND=1
      done
      if [[ ${#KERNEL_DESC[@]} -ne 0 ]] ; then
        print_output ""
        print_output "Kernel details:"
        for LINE in "${KERNEL_DESC[@]}" ; do
          print_output "$(indent "$LINE")"
          FOUND=1
        done
      fi
      print_output "[-] No check for kernel configuration"

      get_kernel_vulns
      check_modprobe
    else
      print_output "[-] No kernel version identified"
    fi
    if [[ ${#KERNEL_MODULES[@]} -ne 0 ]] ; then
      analyze_kernel_module
      FOUND=1
    fi

  elif [[ $KERNEL -eq 1 ]] && [[ $FIRMWARE -eq 0 ]]  ; then
    print_output "[*] Check kernel configuration ""$(print_path "$KERNEL_CONFIG" )"" via checksec.sh"
    print_output "$("$EXT_DIR""/checksec" --kernel="$KERNEL_CONFIG")"
    FOUND=1

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
      FOUND=1

      get_kernel_vulns
      check_modprobe

    else
      print_output "[-] No kernel found"
    fi
  fi

  if [[ ${#KERNEL_VERSION[@]} -ne 0 ]] ; then
    for K_VERS in "${KERNEL_VERSION[@]}" ; do
      write_log "[*] Statistics:$K_VERS"
    done
  fi
  write_log "[*] Statistics1:${#KERNEL_MODULES[@]}:$KMOD_BAD"

  module_end_log "${FUNCNAME[0]}" "$FOUND"
}

populate_karrays() {
  mapfile -t KERNEL_MODULES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev \( -iname "*.ko" -o -iname "*.o" \) -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  local KERNEL_VERSION_

  for K_MODULE in "${KERNEL_MODULES[@]}"; do
    KERNEL_VERSION+=( "$(modinfo "$K_MODULE" 2>/dev/null | grep -E "vermagic" | cut -d: -f2 | sed 's/^ *//g')" )
    if [[ "$K_MODULE" =~ .*\.o ]]; then
      KERNEL_VERSION+=( "$(strings "$K_MODULE" 2>/dev/null | grep "kernel_version=" | cut -d= -f2)" )
    fi
    KERNEL_DESC+=( "$(modinfo "$K_MODULE" 2>/dev/null | grep -E "description" | cut -d: -f2 | sed 's/^ *//g' | tr -c '[:alnum:]\n\r' '_')" )
  done

  for VER in "${KERNEL_VERSION[@]}" ; do
    demess_kv_version "$VER"

    IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    for V in "${KV_C_ARR[@]}" ; do
      if [[ -z "$i" ]]; then
        # remove empty entries:
        continue
      fi
      if ! [[ "$i" =~ .*[0-9]\.[0-9].* ]]; then
        continue
      fi
      KERNEL_VERSION_+=( "$V" )
    done
  done

  # if we have found a kernel version in binary kernel:
  if [[ -f "$LOG_DIR"/s24_kernel_bin_identifier.csv ]]; then
    while IFS=";" read -r K_VER; do
      K_VER="$(echo "$K_VER" | sed 's/Linux\ version\ //g' | tr -d "(" | tr -d ")" | tr -d "#")"

      demess_kv_version "$K_VER"

      IFS=" " read -r -a KV_C_ARR <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

      for V in "${KV_C_ARR[@]}" ; do
        KERNEL_VERSION_+=( "$V" )
      done
    done < <(cut -d ";" -f1 "$LOG_DIR"/s24_kernel_bin_identifier.csv | tail -n +2)
  fi

  # unique our results
  eval "KERNEL_VERSION_=($(for i in "${KERNEL_VERSION_[@]}" ; do
    if [[ -z "$i" ]]; then
      # remove empty entries:
      continue;
    fi
    if ! [[ "$i" =~ .*[0-9]\.[0-9].* ]]; then
      # remove lines without someting like *1.2*
      continue;
    fi
    echo "\"$i\"" ;
  done | sort -u))"

  eval "KERNEL_DESC=($(for i in "${KERNEL_DESC[@]}" ; do echo "\"$i\"" ; done | sort -u))"

  # if we have no kernel version identified -> we try to identify something via the path:
  if [[ "${#KERNEL_VERSION_[@]}" -eq 0 && "${#KERNEL_MODULES[@]}" -ne 0 ]];then
    # remove the first part of the path:
    KERNEL_VERSION1=$(echo "${KERNEL_MODULES[1]}" | sed 's/.*\/lib\/modules\///')
    KERNEL_VERSION_+=("$KERNEL_VERSION1")
    # demess_kv_version removes the unneeded stuff after the version:
    demess_kv_version "${KERNEL_VERSION_[@]}"
    # now rewrite the temp KERNEL_VERSION_ array
    IFS=" " read -r -a KERNEL_VERSION_ <<< "$(echo "${KV_ARR[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
  fi

  KERNEL_VERSION=("${KERNEL_VERSION_[@]}")

}

demess_kv_version() {
  K_VERSION=("$@")
  # sometimes our kernel version is wasted with some "-" -> so we exchange them with spaces for the exploit suggester
  for VER in "${K_VERSION[@]}" ; do
    if ! [[ "$VER" == *[0-9]* ]]; then
      continue;
    fi

    local KV
    KV=$(echo "$VER" | tr "-" " ")
    KV=$(echo "$KV" | tr "+" " ")
    KV=$(echo "$KV" | tr "_" " ")
    KV=$(echo "$KV" | tr "/" " ")
    # the first field is the real kernel version:
    KV=$(echo "$KV" | cut -d\  -f1)

    while echo "$KV" | grep -q '[a-zA-Z]'; do
      KV="${KV::-1}"
    done
    KV_ARR=("${KV_ARR[@]}" "$KV")
  done
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
      demess_kv_version "${KERNEL_VERSION[@]}"
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
  write_anchor "kernel_modules"

  KMOD_BAD=0

  print_output "[*] Found ${#KERNEL_MODULES[@]} kernel modules."

  for LINE in "${KERNEL_MODULES[@]}" ; do
    # modinfos can run in parallel:
    if [[ "$THREADED" -eq 1 ]]; then
      module_analyzer &
      WAIT_PIDS_S25+=( "$!" )
    else
      module_analyzer
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S25[@]}"
  fi

  # in threading we need to go via a temp file with the need to count it now:
  # shellcheck disable=SC2153
  if [[ -f "$TMP_DIR"/KMOD_BAD.tmp ]]; then
    while read -r COUNTING; do
      (( KMOD_BAD="$KMOD_BAD"+"$COUNTING" ))
    done < "$TMP_DIR"/KMOD_BAD.tmp
  fi
}

module_analyzer() {
  if [[ "$LINE" == *".ko" ]]; then
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

    echo "$KMOD_BAD" >> "$TMP_DIR"/KMOD_BAD.tmp
  elif [[ "$LINE" == *".o" ]]; then
    print_output "[-] No support for .o kernel modules - $ORANGE$LINE$NC"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_usb

check_modprobe()
{
  sub_module_title "Check modprobe.d directory and content"

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

