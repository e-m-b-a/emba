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

# Description:  Scans for device tree blobs, bootloader and startup files and checks for the default runlevel.

# This module is based on source code from lynis: https://raw.githubusercontent.com/CISOfy/lynis/master/include/tests_boot_services
S15_bootloader_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check bootloader and system startup"

  STARTUP_FINDS=0

  check_dtb
  check_bootloader
  find_boot_files
  find_runlevel

  module_end_log "${FUNCNAME[0]}" "$STARTUP_FINDS"
}

check_dtb()
{
  sub_module_title "Scan for device tree blobs"

  readarray -t DTB_ARR < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -iname "*.dtb" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  if [[ ${#DTB_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Device tree blobs found - output of fdtdump into log, could take a moment"
    for DTB_FILE in "${DTB_ARR[@]}" ; do
      print_output "$(indent "$DTB_FILE")"
      if [[ $DTBDUMP -eq 1 ]] ; then
        write_log "$(fdtdump "$DTB_FILE" 2> /dev/null)" "$LOG_DIR""/dtb_dump/""$(basename "$DTB_FILE" .dtb)""-DUMP.txt" "g"
        ((STARTUP_FINDS++))
      fi
    done
  else
    print_output "[-] No device tree blobs found"
  fi
}

check_bootloader()
{
  sub_module_title "Scan for bootloader"

  local BOOTLOADER
  local CHECK

  # Syslinux
  CHECK=0
  mapfile -t SYSLINUX_PATHS < <(mod_path "/boot/syslinux/syslinux.cfg")
  for SYSLINUX_FILE in "${SYSLINUX_PATHS[@]}" ; do
    if [[ -f "$SYSLINUX_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Syslinux config: ""$(print_path "$SYSLINUX_FILE")"
      BOOTLOADER="Syslinux"
      ((STARTUP_FINDS++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No Syslinux configuration file found"
  fi

  # Grub
  CHECK=0
  mapfile -t GRUB_PATHS < <(mod_path "/boot/grub/grub.conf")
  for GRUB_FILE in "${GRUB_PATHS[@]}" ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Grub config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub"
      ((STARTUP_FINDS++))
    fi
  done
  mapfile -t GRUB_PATHS < <(mod_path "/boot/grub/menu.lst")
  for GRUB_FILE in "${GRUB_PATHS[@]}" ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Grub config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub"
      ((STARTUP_FINDS++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No Grub configuration file found"
  fi

  # Grub2
  CHECK=0
  mapfile -t GRUB_PATHS < <(mod_path "/boot/grub/grub.cfg")
  for GRUB_FILE in "${GRUB_PATHS[@]}" ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Grub2 config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub2"
      ((STARTUP_FINDS++))
    fi
  done
  mapfile -t GRUB_PATHS < <(mod_path "/boot/grub2/grub.conf")
  for GRUB_FILE in "${GRUB_PATHS[@]}" ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Grub2 config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub2"
      ((STARTUP_FINDS++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No Grub configuration file found"
  fi
  
  # Grub configuration
  if [[ -n "$GRUB" ]] ; then
    print_output "[*] Check Grub config: ""$(print_path "$GRUB")"
    FIND=$(grep 'password --md5' "$GRUB"| grep -v '^#')
    FIND2=$(grep 'password --encrypted' "$GRUB"| grep -v '^#')
    FIND3=$(grep 'set superusers' "$GRUB"| grep -v '^#')
    FIND4=$(grep 'password_pbkdf2' "$GRUB"| grep -v '^#')
    FIND5=$(grep 'grub.pbkdf2' "$GRUB"| grep -v '^#')
    FOUND=0
    # GRUB1: Password should be set (MD5 or SHA1)
    if [[ -n "${FIND}" ]] || [[ -n "${FIND2}" ]] ; then
      FOUND=1
    # GRUB2: Superusers AND password should be defined
    elif [[ -n "${FIND3}" ]] ; then
      if [[ -n "${FIND4}" ]] || [[ -n "${FIND5}" ]] ; then 
        FOUND=1;
        ((STARTUP_FINDS++))
      fi
    fi
    if [[ $FOUND -eq 1 ]] ; then
      print_output "[+] GRUB has password protection"
    else
      print_output "[-] No hashed password line in GRUB boot file"
    fi
  else
    print_output "[-] No Grub configuration check"
  fi

  # FreeBSD or DragonFly
  CHECK=0
  local BOOT1 BOOT2 BOOTL
  mapfile -t BOOT1 < <(mod_path "/boot/boot1")
  mapfile -t BOOT2 < <(mod_path "/boot/boot2")
  mapfile -t BOOTL < <(mod_path "/boot/loader")

  for B1 in "${BOOT1[@]}" ; do
    for B2 in "${BOOT2[@]}" ; do
      for BL in "${BOOTL[@]}" ; do
        if [[ -f "$B1" ]] && [[ -f "$B2" ]] && [[ -f "$BL" ]] ; then
          CHECK=1
          print_output "[+] Found ""$(print_path "$B1")"", ""$(print_path "$B2")"" and ""$(print_path "$BL")"" (FreeBSD or DragonFly)"
          BOOTLOADER="FreeBSD / DragonFly"
          ((STARTUP_FINDS++))
        fi
      done
    done
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No FreeBSD or DragonFly bootloader files found"
  fi

  # LILO
  CHECK=0
  mapfile -t LILO_PATH < <(mod_path "/ETC_PATHS/lilo.conf")
  for LILO_FILE in "${LILO_PATH[@]}" ; do
    if [[ -f "$LILO_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found lilo.conf: ""$(print_path "$LILO_FILE")"" (LILO)"
      FIND=$(grep 'password[[:space:]]?=' "$LILO_FILE" | grep -v "^#")
        if [[ -z "${FIND}" ]] ; then
          print_output "[+] LILO has password protection"
          ((STARTUP_FINDS++))
        fi
      BOOTLOADER="LILO"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No LILO configuration file found"
  fi

  # SILO
  CHECK=0
  mapfile -t SILO_PATH < <(mod_path "/ETC_PATHS/silo.conf")
  for SILO_FILE in "${SILO_PATH[@]}" ; do
    if [[ -f "$SILO_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found silo.conf: ""$(print_path "$SILO_FILE")"" (SILO)"
      BOOTLOADER="SILO"
      ((STARTUP_FINDS++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No SILO configuration file found"
  fi

  # YABOOT
  CHECK=0
  mapfile -t YABOOT_PATH < <(mod_path "/ETC_PATHS/yaboot.conf")
  for YABOOT_FILE in "${YABOOT_PATH[@]}" ; do
    if [[ -f "$YABOOT_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found yaboot.conf: ""$(print_path "$YABOOT_FILE")"" (YABOOT)"
      BOOTLOADER="Yaboot"
      ((STARTUP_FINDS++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No YABOOT configuration file found"
  fi

  # OpenBSD
  CHECK=0
  local OBSD_PATH1 OBSD_PATH2
  mapfile -t OBSD_PATH1 < <(mod_path "/usr/mdec/biosboot")
  mapfile -t OBSD_PATH2 < <(mod_path "/boot")
  for OBSD_FILE1 in "${OBSD_PATH1[@]}" ; do
    for OBSD_FILE2 in "${OBSD_PATH2[@]}" ; do
      if [[ -f "$OBSD_FILE2" ]] && [[ -f "OBSD_FILE2" ]] ; then
        CHECK=1
        print_output "[+] Found first and second stage bootstrap in ""$(print_path "$OBSD_FILE1")"" and ""$(print_path "$OBSD_FILE2")"" (OpenBSD)"
        BOOTLOADER="OpenBSD"
        ((STARTUP_FINDS++))
      fi
    done
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No OpenBSD/bootstrap files found"
  fi

  # OpenBSD boot configuration
  CHECK=0
  mapfile -t OPENBSD_PATH < <(mod_path "/ETC_PATHS/boot.conf")
  for OPENBSD in "${OPENBSD_PATH[@]}" ; do
    if [[ -f "$OPENBSD" ]] ; then
      CHECK=1
      print_output "[+] Found ""$(print_path "$OPENBSD")"" (OpenBSD)"
      FIND=$(grep '^boot' "$OPENBSD")
      if [[ -z "${FIND}" ]] ; then
        print_output "[+] System can be booted into single user mode without password"
        ((STARTUP_FINDS++))
      fi
      mapfile -t OPENBSD_PATH2 < <(mod_path "/ETC_PATHS/rc.conf")
      for OPENBSD2 in "${OPENBSD_PATH2[@]}" ; do
        if [[ -e "$OPENBSD2" ]] ; then
          FIND=$(grep -v -i '^#|none' "$OPENBSD2" | grep-i '_enable.*(yes|on|1)' | sort | awk -F= '{ print $1 }' | sed 's/_enable//')
          print_output "[+] Found OpenBSD boot services ""$(print_path "$OPENBSD2")"
          if [[ -z "$FIND" ]] ; then
            print_output "$(indent "$(orange "$FIND")")"
            ((STARTUP_FINDS++))
          fi
        fi
      done
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No OpenBSD configuration file found"
  fi

  if [[ -z "$BOOTLOADER" ]] ; then
    print_output "[-] No bootloader found"
  fi
}

find_boot_files()
{
  sub_module_title "Scan for startup files"

  local BOOT_FILES
  mapfile -t BOOT_FILES < <(config_find "$CONFIG_DIR""/boot_files.cfg")

  if [[ "${BOOT_FILES[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#BOOT_FILES[@]}" -ne 0 ]] ; then
    print_output "[+] Found ""${#BOOT_FILES[@]}"" startup files:"
    for LINE in "${BOOT_FILES[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      if [[ "$(basename "$LINE")" == "inittab" ]]  ; then
        INITTAB_V=("${INITTAB_V[@]}" "$LINE")
      fi
      ((STARTUP_FINDS++))
    done
  else
    print_output "[-] No startup files found"
  fi
}

find_runlevel()
{
  sub_module_title "Check default run level"

  local SYSTEMD_PATH
  mapfile -t SYSTEMD_PATH < <(mod_path "/ETC_PATHS/systemd")
  for SYSTEMD_P in "${SYSTEMD_PATH[@]}" ; do
    if [[ -d "$SYSTEMD_P" ]] ; then
      print_output "[*] Check runlevel in systemd directory: ""$(print_path "$SYSTEMD_P")"
      DEFAULT_TARGET_PATH="$SYSTEMD_P""/system/default.target"
      if [[ -L "$DEFAULT_TARGET_PATH" ]] ; then
        FIND="$( read -r "$DEFAULT_TARGET_PATH"'' | grep "runlevel")"
        if [[ -z "$FIND" ]] ; then
          print_output "[+] systemd run level information:"
          print_output "$(indent "$FIND")"
          ((STARTUP_FINDS++))
        else
          print_output "[-] No run level in ""$(print_path "$DEFAULT_TARGET_PATH")"" found"
        fi
      else
        print_output "[-] ""$(print_path "$DEFAULT_TARGET_PATH")"" not found"
      fi
    fi
  done

  if [[ ${#INITTAB_V[@]} -gt 0 ]] ; then
    for INIT_TAB_F in "${INITTAB_V[@]}" ; do
      print_output "[*] Check runlevel in ""$(print_path "$INIT_TAB_F")"
      FIND=$(awk -F: '/^id/ { print $2; }' "$INIT_TAB_F" | head -n 1)
      if [[ -z "$FIND" ]] ; then
        print_output "[-] No default run level ""$(print_path "$INIT_TAB_F")"" found"
      else
        print_output "[+] Found default run level: ""$(orange "$FIND")"
        ((STARTUP_FINDS++))
      fi
    done
  else
    print_output "[-] No default run level found"
  fi
}
