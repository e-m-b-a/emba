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

# Description:  Scans for device tree blobs, bootloader and startup files and checks for the default runlevel.

# This module is based on source code from lynis: https://raw.githubusercontent.com/CISOfy/lynis/master/include/tests_boot_services
S07_bootloader_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check bootloader and system startup"
  pre_module_reporter "${FUNCNAME[0]}"

  export STARTUP_FINDS=0
  export INITTAB_V=()

  check_dtb
  check_bootloader
  find_boot_files
  find_runlevel

  module_end_log "${FUNCNAME[0]}" "${STARTUP_FINDS}"
}

check_dtb()
{
  sub_module_title "Scan for device tree blobs"

  local lDTB_ARR=()
  local lDTB_FILE=""

  # readarray -t lDTB_ARR < <( find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -iname "*.dtb" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 || true)
  mapfile -t lDTB_ARR < <(grep "\\.dtb;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ ${#lDTB_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Device tree blobs found:"
    for lDTB_FILE in "${lDTB_ARR[@]}" ; do
      print_output "$(indent "$(orange "${lDTB_FILE}")")"
      write_link "${LOG_PATH_MODULE}""/""$(basename "${lDTB_FILE}" .dtb)""-DUMP.txt"
      write_log "$(fdtdump "${lDTB_FILE}" 2>/dev/null || true)" "${LOG_PATH_MODULE}""/""$(basename "${lDTB_FILE}" .dtb)""-DUMP.txt" "g"
      ((STARTUP_FINDS+=1))
    done
    print_ln
  else
    print_output "[-] No device tree blobs found"
  fi
}

check_bootloader()
{
  sub_module_title "Scan for bootloader"

  local lBOOTLOADER=0
  local lCHECK=0

  # Syslinux
  local lSYSLINUX_PATHS_ARR=()
  local lSYSLINUX_FILE=""
  # mapfile -t lSYSLINUX_PATHS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/syslinux/syslinux.cfg" || true)
  mapfile -t lSYSLINUX_PATHS_ARR < <(grep "/boot/syslinux/syslinux.cfg;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lSYSLINUX_FILE in "${lSYSLINUX_PATHS_ARR[@]}" ; do
    if [[ -f "${lSYSLINUX_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found Syslinux config: ""$(print_path "${lSYSLINUX_FILE}")"
      lBOOTLOADER="Syslinux"
      ((STARTUP_FINDS+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No Syslinux configuration file found"
  fi

  # Grub
  lCHECK=0
  local lGRUB_PATHS_ARR=()
  local lGRUB_FILE=""
  local lGRUB=""
  # mapfile -t lGRUB_PATHS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/grub/grub.conf" || true)
  mapfile -t lGRUB_PATHS_ARR < <(grep "/boot/grub/grub.conf;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lGRUB_FILE in "${lGRUB_PATHS_ARR[@]}" ; do
    if [[ -f "${lGRUB_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found Grub config: ""$(print_path "${lGRUB_FILE}")"
      lGRUB="${lGRUB_FILE}"
      lBOOTLOADER="Grub"
      ((STARTUP_FINDS+=1))
    fi
  done
  # mapfile -t lGRUB_PATHS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/grub/menu.lst" || true)
  mapfile -t lGRUB_PATHS_ARR < <(grep "/boot/grub/menu.lst;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lGRUB_FILE in "${lGRUB_PATHS_ARR[@]}" ; do
    if [[ -f "${lGRUB_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found Grub config: ""$(print_path "${lGRUB_FILE}")"
      lGRUB="${lGRUB_FILE}"
      lBOOTLOADER="Grub"
      ((STARTUP_FINDS+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No Grub configuration file found"
  fi

  # Grub2
  lCHECK=0
  # mapfile -t lGRUB_PATHS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/grub/grub.cfg" || true)
  mapfile -t lGRUB_PATHS_ARR < <(grep "/boot/grub/grub.cfg;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lGRUB_FILE in "${lGRUB_PATHS_ARR[@]}" ; do
    if [[ -f "${lGRUB_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found Grub2 config: ""$(print_path "${lGRUB_FILE}")"
      lGRUB="${lGRUB_FILE}"
      lBOOTLOADER="Grub2"
      ((STARTUP_FINDS+=1))
    fi
  done
  # mapfile -t lGRUB_PATHS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/grub/grub.conf" || true)
  mapfile -t lGRUB_PATHS_ARR < <(grep "/boot/grub/grub.conf;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lGRUB_FILE in "${lGRUB_PATHS_ARR[@]}" ; do
    if [[ -f "${lGRUB_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found Grub2 config: ""$(print_path "${lGRUB_FILE}")"
      lGRUB="${lGRUB_FILE}"
      lBOOTLOADER="Grub2"
      ((STARTUP_FINDS+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No Grub configuration file found"
  fi

  # Grub configuration
  local lFIND=""
  local lFIND2=""
  local lFIND3=""
  local lFIND4=""
  local lFIND5=""
  local lFOUND=0
  if [[ -n "${lGRUB:-}" ]] ; then
    print_output "[*] Check Grub config: ""$(print_path "${lGRUB}")"
    lFIND=$(grep 'password --md5' "${lGRUB}"| grep -v '^#' || true)
    lFIND2=$(grep 'password --encrypted' "${lGRUB}"| grep -v '^#' || true)
    lFIND3=$(grep 'set superusers' "${lGRUB}"| grep -v '^#' || true)
    lFIND4=$(grep 'password_pbkdf2' "${lGRUB}"| grep -v '^#' || true)
    lFIND5=$(grep 'grub.pbkdf2' "${lGRUB}"| grep -v '^#' || true)
    # GRUB1: Password should be set (MD5 or SHA1)
    if [[ -n "${lFIND}" ]] || [[ -n "${lFIND2}" ]] ; then
      lFOUND=1
    # GRUB2: Superusers AND password should be defined
    elif [[ -n "${lFIND3}" ]] ; then
      if [[ -n "${lFIND4}" ]] || [[ -n "${lFIND5}" ]] ; then
        lFOUND=1
        ((STARTUP_FINDS+=1))
      fi
    fi
    if [[ ${lFOUND} -eq 1 ]] ; then
      print_output "[+] GRUB has password protection"
    else
      print_output "[-] No hashed password line in GRUB boot file"
    fi
  else
    print_output "[-] No Grub configuration check"
  fi

  # FreeBSD or DragonFly
  lCHECK=0
  local lBOOT1_ARR=()
  local lBOOT2_ARR=()
  local lBOOTL_ARR=()
  # mapfile -t lBOOT1_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/boot1" || true)
  mapfile -t lBOOT1_ARR < <(grep "/boot/boot1;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  mapfile -t lBOOT2_ARR < <(grep "/boot/boot2;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  mapfile -t lBOOTL_ARR < <(grep "/boot/loader;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  # mapfile -t lBOOT2_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/boot2" || true)
  # mapfile -t lBOOTL_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot/loader" || true)

  local lB1=""
  local lB2=""
  local lBL=""
  for lB1 in "${lBOOT1_ARR[@]}" ; do
    for lB2 in "${lBOOT2_ARR[@]}" ; do
      for lBL in "${lBOOTL_ARR[@]}" ; do
        if [[ -f "${lB1}" ]] && [[ -f "${lB2}" ]] && [[ -f "${lBL}" ]] ; then
          lCHECK=1
          print_output "[+] Found ""$(print_path "${lB1}")"", ""$(print_path "${lB2}")"" and ""$(print_path "${lBL}")"" (FreeBSD or DragonFly)"
          lBOOTLOADER="FreeBSD / DragonFly"
          ((STARTUP_FINDS+=1))
        fi
      done
    done
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No FreeBSD or DragonFly bootloader files found"
  fi

  # LILO=""
  lCHECK=0
  local lLILO_PATH_ARR=()
  local lLILO_FILE=""
  mapfile -t lLILO_PATH_ARR < <(mod_path "/ETC_PATHS/lilo.conf")
  for lLILO_FILE in "${lLILO_PATH_ARR[@]}" ; do
    if [[ -f "${lLILO_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found lilo.conf: ""$(print_path "${lLILO_FILE}")"" (LILO)"
      lFIND=$(grep 'password[[:space:]]?=' "${lLILO_FILE}" | grep -v "^#" || true)
        if [[ -z "${lFIND}" ]] ; then
          print_output "[+] LILO has password protection"
          ((STARTUP_FINDS+=1))
        fi
      lBOOTLOADER="LILO"
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No LILO configuration file found"
  fi

  # SILO
  lCHECK=0
  local lSILO_PATH_ARR=()
  local lSILO_FILE=""
  mapfile -t lSILO_PATH_ARR < <(mod_path "/ETC_PATHS/silo.conf")
  for lSILO_FILE in "${lSILO_PATH_ARR[@]}" ; do
    if [[ -f "${lSILO_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found silo.conf: ""$(print_path "${lSILO_FILE}")"" (SILO)"
      lBOOTLOADER="SILO"
      ((STARTUP_FINDS+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No SILO configuration file found"
  fi

  # YABOOT
  lCHECK=0
  local lYABOOT_PATH_ARR=()
  local lYABOOT_FILE=""
  mapfile -t lYABOOT_PATH_ARR < <(mod_path "/ETC_PATHS/yaboot.conf")
  for lYABOOT_FILE in "${lYABOOT_PATH_ARR[@]}" ; do
    if [[ -f "${lYABOOT_FILE}" ]] ; then
      lCHECK=1
      print_output "[+] Found yaboot.conf: ""$(print_path "${lYABOOT_FILE}")"" (YABOOT)"
      lBOOTLOADER="Yaboot"
      ((STARTUP_FINDS+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No YABOOT configuration file found"
  fi

  # OpenBSD
  lCHECK=0
  local lOBSD_PATH1_ARR=()
  local lOBSD_PATH2_ARR=()
  local lOBSD_FILE1=""
  local lOBSD_FILE2=""
  # mapfile -t lOBSD_PATH1_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/usr/mdec/biosboot" || true)
  mapfile -t lOBSD_PATH1_ARR < <(grep "/usr/mdec/biosboot;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  # mapfile -t lOBSD_PATH2_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iwholename "/boot" || true)
  mapfile -t lOBSD_PATH2_ARR < <(grep "/boot;" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  for lOBSD_FILE1 in "${lOBSD_PATH1_ARR[@]}" ; do
    for lOBSD_FILE2 in "${lOBSD_PATH2_ARR[@]}" ; do
      if [[ -f "${lOBSD_FILE2}" ]] && [[ -f "${lOBSD_FILE2}" ]] ; then
        lCHECK=1
        print_output "[+] Found first and second stage bootstrap in ""$(print_path "${lOBSD_FILE1}")"" and ""$(print_path "${lOBSD_FILE2}")"" (OpenBSD)"
        lBOOTLOADER="OpenBSD"
        ((STARTUP_FINDS+=1))
      fi
    done
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No OpenBSD/bootstrap files found"
  fi

  # OpenBSD boot configuration
  lCHECK=0
  local lOPENBSD_PATH_ARR=()
  local lOPENBSD_PATH2_ARR=()
  local lOPENBSD=""
  local lOPENBSD2=""
  mapfile -t lOPENBSD_PATH_ARR < <(mod_path "/ETC_PATHS/boot.conf")
  for lOPENBSD in "${lOPENBSD_PATH_ARR[@]}" ; do
    if [[ -f "${lOPENBSD}" ]] ; then
      lCHECK=1
      print_output "[+] Found ""$(print_path "${lOPENBSD}")"" (OpenBSD)"
      lFIND=$(grep '^boot' "${lOPENBSD}" || true)
      if [[ -z "${lFIND}" ]] ; then
        print_output "[+] System can be booted into single user mode without password"
        ((STARTUP_FINDS+=1))
      fi
      mapfile -t lOPENBSD_PATH2_ARR < <(mod_path "/ETC_PATHS/rc.conf")
      for lOPENBSD2 in "${lOPENBSD_PATH2_ARR[@]}" ; do
        if [[ -e "${lOPENBSD2}" ]] ; then
          lFIND=$(grep -v -i '^#|none' "${lOPENBSD2}" | grep-i '_enable.*(yes|on|1)' || true| sort | awk -F= '{ print $1 }' | sed 's/_enable//')
          print_output "[+] Found OpenBSD boot services ""$(print_path "${lOPENBSD2}")"
          if [[ -z "${lFIND}" ]] ; then
            print_output "$(indent "$(orange "${lFIND}")")"
            ((STARTUP_FINDS+=1))
          fi
        fi
      done
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No OpenBSD configuration file found"
  fi

  # U-Boot quick check on firmware file
  lCHECK=0
  if [[ "${UBOOT_IMAGE}" -eq 1 ]]; then
    lCHECK=1
    print_output "[+] Found uboot image: ""$(print_path "${FIRMWARE_PATH}")"" (U-BOOT)"
    lBOOTLOADER="U-Boot"
    ((STARTUP_FINDS+=1))
  fi
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No U-Boot image found"
  fi

  if [[ -z "${lBOOTLOADER:-}" ]] ; then
    print_output "[-] No bootloader found"
  fi
}

find_boot_files()
{
  sub_module_title "Scan for startup files"

  local lBOOT_FILES_ARR=()
  local lLINE=""
  mapfile -t lBOOT_FILES_ARR < <(config_find "${CONFIG_DIR}""/boot_files.cfg")

  if [[ "${lBOOT_FILES_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lBOOT_FILES_ARR[@]}" -ne 0 ]] ; then
    print_output "[+] Found ""${#lBOOT_FILES_ARR[@]}"" startup files:"
    for lLINE in "${lBOOT_FILES_ARR[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "${lLINE}")")")"
      if [[ "$(basename "${lLINE}")" == "inittab" ]]  ; then
        INITTAB_V=("${INITTAB_V[@]}" "${lLINE}")
      fi
      ((STARTUP_FINDS+=1))
    done
  else
    print_output "[-] No startup files found"
  fi
}

find_runlevel()
{
  sub_module_title "Check default run level"

  local lSYSTEMD_PATH_ARR=()
  local lSYSTEMD_P=""
  local lDEFAULT_TARGET_PATH=""
  local lFIND=""
  local lINIT_TAB_F=""

  mapfile -t lSYSTEMD_PATH_ARR < <(mod_path "/ETC_PATHS/systemd")
  for lSYSTEMD_P in "${lSYSTEMD_PATH_ARR[@]}" ; do
    if [[ -d "${lSYSTEMD_P}" ]] ; then
      print_output "[*] Check runlevel in systemd directory: ""$(print_path "${lSYSTEMD_P}")"
      lDEFAULT_TARGET_PATH="${lSYSTEMD_P}""/system/default.target"
      if [[ -L "${lDEFAULT_TARGET_PATH}" ]] ; then
        lFIND="$( read -r "${lDEFAULT_TARGET_PATH}"'' | grep "runlevel" || true)"
        if [[ -z "${lFIND}" ]] ; then
          print_output "[+] systemd run level information:"
          print_output "$(indent "${lFIND}")"
          ((STARTUP_FINDS+=1))
        else
          print_output "[-] No run level in ""$(print_path "${lDEFAULT_TARGET_PATH}")"" found"
        fi
      else
        print_output "[-] ""$(print_path "${lDEFAULT_TARGET_PATH}")"" not found"
      fi
    fi
  done

  if [[ -v INITTAB_V[@] ]] ; then
    if [[ ${#INITTAB_V[@]} -gt 0 ]] ; then
      for lINIT_TAB_F in "${INITTAB_V[@]}" ; do
        print_output "[*] Check runlevel in ""$(print_path "${lINIT_TAB_F}")"
        lFIND=$(awk -F: '/^id/ { print $2; }' "${lINIT_TAB_F}" | head -n 1)
        if [[ -z "${lFIND}" ]] ; then
          print_output "[-] No default run level ""$(print_path "${lINIT_TAB_F}")"" found"
        else
          print_output "[+] Found default run level: ""$(orange "${lFIND}")"
          ((STARTUP_FINDS+=1))
        fi
      done
    else
      print_output "[-] No default run level found"
    fi
  else
    print_output "[-] No default run level found"
  fi
}
