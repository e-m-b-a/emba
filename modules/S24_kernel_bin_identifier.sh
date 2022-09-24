#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  This module tries to identify the kernel file and the init command line
#               The identified kernel binary file is extracted with vmlinux-to-elf

S24_kernel_bin_identifier()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Kernel Binary Identifier"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local FILE_ARR_TMP=()
  local FILE=""
  local K_VER=""
  local K_INIT=""

  readarray -t FILE_ARR_TMP < <(find "$FIRMWARE_PATH_CP" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
    -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
    -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" \) \
    -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  write_csv_log "Kernel version" "file" "identified init"

  for FILE in "${FILE_ARR_TMP[@]}" ; do
    K_VER=$(strings "$FILE" 2>/dev/null | grep -E "^Linux version [0-9]+\.[0-9]+" || true)
    if [[ "$K_VER" =~ Linux\ version\ .* ]]; then
	    print_output "[+] Possible Linux Kernel found: $ORANGE$FILE$NC"
      print_ln
      print_output "$(indent "$(orange "$K_VER")")"
      print_ln

      K_INIT=$(strings "$FILE" 2>/dev/null | grep -E "init=\/" || true)
      if [[ "$K_INIT" =~ init=\/.* ]]; then
        print_output "[+] Init found in Linux kernel file $ORANGE$FILE$NC"
        print_ln
        print_output "$(indent "$(orange "$K_INIT")")"
        print_ln
      fi

      if [[ -e "$EXT_DIR"/vmlinux-to-elf/vmlinux-to-elf ]]; then
        print_output "[*] Testing possible Linux kernel file $ORANGE$FILE$NC with ${ORANGE}vmlinux-to-elf:$NC"
        print_ln
        "$EXT_DIR"/vmlinux-to-elf/vmlinux-to-elf "$FILE" "$FILE".elf | tee -a "$LOG_FILE" || true
        if [[ -f "$FILE".elf ]]; then
          K_ELF=$(file "$FILE".elf)
          if [[ "$K_ELF" == *"ELF "* ]]; then
            print_ln
            print_output "[+] Successfully generated Linux kernel elf file: $ORANGE$FILE.elf$NC"
          else
            print_ln
            print_output "[-] No Linux kernel elf file was created."
          fi
        fi
        print_ln
      fi

      write_csv_log "$K_VER" "$FILE" "$K_INIT"

      NEG_LOG=1
    fi
  done

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
