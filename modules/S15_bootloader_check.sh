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

# Description:  Dump device tree blob into log, check for various bootloaders, boot files and valid runlevel
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


# This module is based on source code from lynis: https://raw.githubusercontent.com/CISOfy/lynis/master/include/tests_boot_services

S15_bootloader_check()
{
  module_log_init "s15_check_bootloader_and_system_startup"
  module_title "Check bootloader and system startup"
  CONTENT_AVAILABLE=0

  check_dtb
  check_bootloader
  find_boot_files
  find_runlevel
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

check_dtb()
{
  sub_module_title "Scan for device tree blobs"
  readarray -t DTB_ARR < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -iname "*.dtb" )

  if [[ ${#DTB_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Device tree blobs found - output of fdtdump into log, could take a moment"
    for DTB_FILE in "${DTB_ARR[@]}" ; do
      print_output "$(indent "$DTB_FILE")"
      if [[ $DTBDUMP -eq 1 ]] ; then
        local LOG_FILE_LOC
        LOG_FILE_LOC="$LOG_DIR""/dtb_dump/""$(basename "$DTB_FILE" .dtb)""-DUMP.txt"
        LOG_FILE_O="$LOG_FILE"
        LOG_FILE="$LOG_FILE_LOC"
        write_log "$(fdtdump "$DTB_FILE" 2> /dev/null)"
        LOG_FILE="$LOG_FILE_O"
      fi
    done
    CONTENT_AVAILABLE=1
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
  SYSLINUX_PATHS="$(mod_path "$FIRMWARE_PATH""/boot/syslinux/syslinux.cfg")"
  for SYSLINUX_FILE in $SYSLINUX_PATHS ; do
    if [[ -f "$SYSLINUX_FILE" ]] ; then
      CHECK=1
      CONTENT_AVAILABLE
      =1
      print_output "[+] Found Syslinux config: ""$(print_path "$SYSLINUX_FILE")"
      BOOTLOADER="Syslinux"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No Syslinux configuration file found"
  fi

  # Grub
  CHECK=0
  GRUB_PATHS="$(mod_path "$FIRMWARE_PATH""/boot/grub/grub.conf")"
  for GRUB_FILE in $GRUB_PATHS ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found Grub config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub"
    fi
  done
  GRUB_PATHS="$(mod_path "$FIRMWARE_PATH""/boot/grub/menu.lst")"
  for GRUB_FILE in $GRUB_PATHS ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      CONTENT_AVAILABLE=1
      print_output "[+] Found Grub config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No Grub configuration file found"
  fi

  # Grub2
  CHECK=0
  GRUB_PATHS="$(mod_path "$FIRMWARE_PATH""/boot/grub/grub.cfg")"
  for GRUB_FILE in $GRUB_PATHS ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      CONTENT_AVAILABLE=1
      print_output "[+] Found Grub2 config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub2"
    fi
  done
  GRUB_PATHS="$(mod_path "$FIRMWARE_PATH""/boot/grub2/grub.cfg")"
  for GRUB_FILE in $GRUB_PATHS ; do
    if [[ -f "$GRUB_FILE" ]] ; then
      CHECK=1
      CONTENT_AVAILABLE=1
      print_output "[+] Found Grub2 config: ""$(print_path "$GRUB_FILE")"
      GRUB="$GRUB_FILE"
      BOOTLOADER="Grub2"
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
      fi
    fi
    if [[ $FOUND -eq 1 ]] ; then
      CONTENT_AVAILABLE=1
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
  BOOT1="$(mod_path "$FIRMWARE_PATH""/boot/boot1")"
  BOOT2="$(mod_path "$FIRMWARE_PATH""/boot/boot2")"
  BOOTL="$(mod_path "$FIRMWARE_PATH""/boot/loader")"
  for B1 in $BOOT1 ; do
    for B2 in $BOOT2 ; do
      for BL in $BOOTL ; do
        if [[ -f "$B1" ]] && [[ -f "$B2" ]] && [[ -f "$BL" ]] ; then
          CHECK=1
          print_output "[+] Found ""$(print_path "$B1")"", ""$(print_path "$B2")"" and ""$(print_path "$BL")"" (FreeBSD or DragonFly)"
          BOOTLOADER="FreeBSD / DragonFly"
        fi
      done
    done
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No FreeBSD or DragonFly bootloader files found"
  else
    CONTENT_AVAILABLE=1
  fi

  # LILO
  CHECK=0
  LILO_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/lilo.conf")"
  for LILO_FILE in $LILO_PATH ; do
  if [[ -f "$LILO_FILE" ]] ; then
    CHECK=1
    print_output "[+] Found lilo.conf: ""$(print_path "$LILO_FILE")"" (LILO)"
    FIND=$(grep 'password[[:space:]]?=' "$LILO_FILE" | grep -v "^#")
      if [[ -z "${FIND}" ]] ; then
        print_output "[+] LILO has password protection"
      fi
    BOOTLOADER="LILO"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No LILO configuration file found"
  else
    CONTENT_AVAILABLE=1
  fi

  # SILO
  CHECK=0
  SILO_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/silo.conf")"
  for SILO_FILE in $SILO_PATH ; do
  if [[ -f "$SILO_FILE" ]] ; then
    CHECK=1
    print_output "[+] Found silo.conf: ""$(print_path "$SILO_FILE")"" (SILO)"
    BOOTLOADER="SILO"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No SILO configuration file found"
  else
    CONTENT_AVAILABLE=1
  fi

  # YABOOT
  CHECK=0
  YABOOT_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/yaboot.conf")"
  for YABOOT_FILE in $YABOOT_PATH ; do
    if [[ -f "$YABOOT_FILE" ]] ; then
      CHECK=1
      print_output "[+] Found yaboot.conf: ""$(print_path "$YABOOT_FILE")"" (YABOOT)"
      BOOTLOADER="Yaboot"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No YABOOT configuration file found"
  else
    CONTENT_AVAILABLE=1
  fi

  # OpenBSD
  CHECK=0
  local OBSD_PATH1 OBSD_PATH2
  OBSD_PATH1="$(mod_path "$FIRMWARE_PATH""/usr/mdec/biosboot")"
  OBSD_PATH2="$(mod_path "$FIRMWARE_PATH""/boot")"
  for OBSD_FILE1 in $OBSD_PATH1 ; do
    for OBSD_FILE2 in $OBSD_PATH2 ; do
      if [[ -f "$OBSD_FILE2" ]] && [[ -f "OBSD_FILE2" ]] ; then
        CHECK=1
        print_output "[+] Found first and second stage bootstrap in ""$(print_path "$OBSD_FILE1")"" and ""$(print_path "$OBSD_FILE2")"" (OpenBSD)"
        BOOTLOADER="OpenBSD"
      fi
    done
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No OpenBSD/bootstrap files found"
  else
    CONTENT_AVAILABLE=1
  fi

  # OpenBSD boot configuration
  CHECK=0
  OPENBSD_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/boot.conf")"
  for OPENBSD in $OPENBSD_PATH ; do
    if [[ -f "$OPENBSD" ]] ; then
      CHECK=1
      print_output "[+] Found ""$(print_path "$OPENBSD")"" (OpenBSD)"
      FIND=$(grep '^boot' "$OPENBSD")
      if [[ -z "${FIND}" ]] ; then
        print_output "[+] System can be booted into single user mode without password"
      fi
      OPENBSD_PATH2="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/rc.conf")"
      for OPENBSD2 in $OPENBSD_PATH2 ; do
        if [[ -e "$OPENBSD2" ]] ; then
          FIND=$(grep -v -i '^#|none' "$OPENBSD2" | grep-i '_enable.*(yes|on|1)' | sort | awk -F= '{ print $1 }' | sed 's/_enable//')
          print_output "[+] Found OpenBSD boot services ""$(print_path "$OPENBSD2")"
          if [[ -z "$FIND" ]] ; then
            print_output "$(indent "$(orange "$FIND")")"
          fi
        fi
      done
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No OpenBSD configuration file found"
  else
    CONTENT_AVAILABLE=1
  fi

  if [[ -z "$BOOTLOADER" ]] ; then
    print_output "[-] No bootloader found"
  else
    CONTENT_AVAILABLE=1
  fi
}

find_boot_files()
{
  sub_module_title "Scan for startup files"

  local BOOT_FILES
  BOOT_FILES="$(config_find "$CONFIG_DIR""/boot_files.cfg" "")"

  if [[ "$BOOT_FILES" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$BOOT_FILES" ]] ; then
    local KEY_COUNT
    KEY_COUNT="$(echo "$BOOT_FILES" | wc -w)"
    print_output "[+] Found ""$KEY_COUNT"" startup files:"
    for LINE in $BOOT_FILES ; do
      print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      if [[ "$(basename "$LINE")" == "inittab" ]]  ; then
        INITTAB_V=("${INITTAB_V[@]}" "$LINE")
      fi
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No startup files found"
  fi
}

find_runlevel()
{
  sub_module_title "Check default run level"
  local SYSTEMD_PATH
  SYSTEMD_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/systemd")"
  for SYSTEMD_P in $SYSTEMD_PATH ; do
    if [[ -d "$SYSTEMD_P" ]] ; then
      print_output "[*] Check runlevel in systemd directory: ""$(print_path "$SYSTEMD_P")"
      DEFAULT_TARGET_PATH="$SYSTEMD_P""/system/default.target"
      if [[ -L "$DEFAULT_TARGET_PATH" ]] ; then
        FIND="$( read -r "$DEFAULT_TARGET_PATH"'' | grep "runlevel")"
        if [[ -z "$FIND" ]] ; then
          print_output "[+] systemd run level information:"
          print_output "$(indent "$FIND")"
          CONTENT_AVAILABLE=1
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
      fi
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No default run level found"
  fi
}
