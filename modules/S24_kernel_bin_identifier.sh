#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
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
  module_title "Kernel Binary and Configuration Identifier"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local FILE=""
  local K_VER=""
  local K_INITS=()
  local K_INIT=""
  local CFG_MD5=""
  export KCFG_MD5=()

  prepare_file_arr_limited "$FIRMWARE_PATH_CP"

  write_csv_log "Kernel version orig" "Kernel version stripped" "file" "generated elf" "identified init" "config extracted" "kernel symbols"

  for FILE in "${FILE_ARR_LIMITED[@]}" ; do
    local K_ELF="NA"
    local KCONFIG_EXTRACTED="NA"
    local K_VER_CLEAN="NA"
    local K_INIT="NA"
    local CFG_CNT=0
    local K_SYMBOLS=0

    if file "$FILE" | grep -q "ASCII text"; then
      # reduce false positive rate
      continue
    fi
    K_VER=$(strings "$FILE" 2>/dev/null | grep -E "^Linux version [0-9]+\.[0-9]+" | sort -u || true)

    if [[ "$K_VER" =~ Linux\ version\ .* ]]; then
      print_ln
      print_output "[+] Possible Linux Kernel found: $ORANGE$FILE$NC"
      print_ln
      print_output "$(indent "$(orange "$K_VER")")"
      print_ln

      # not perfect, but not too bad for now:
      mapfile -t K_INITS < <(strings "$FILE" 2>/dev/null | grep -E "init=\/" | sed 's/.*rdinit/rdinit/' | sed 's/.*\ init/init/' | awk '{print $1}' | sort -u || true)
      for K_INIT in "${K_INITS[@]}"; do
        if [[ "$K_INIT" =~ init=\/.* ]]; then
          print_output "[+] Init found in Linux kernel file $ORANGE$FILE$NC"
          print_ln
          print_output "$(indent "$(orange "$K_INIT")")"
          print_ln
        else
          K_INIT="NA"
        fi
      done

      if [[ -e "$EXT_DIR"/vmlinux-to-elf/vmlinux-to-elf ]]; then
        print_output "[*] Testing possible Linux kernel file $ORANGE$FILE$NC with ${ORANGE}vmlinux-to-elf:$NC"
        print_ln
        "$EXT_DIR"/vmlinux-to-elf/vmlinux-to-elf "$FILE" "$FILE".elf 2>/dev/null | tee -a "$LOG_FILE" || true
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

      disable_strict_mode "$STRICT_MODE" 0
      extract_kconfig "$FILE"
      enable_strict_mode "$STRICT_MODE" 0

      # double check we really have a Kernel config extracted
      if [[ -f "$KCONFIG_EXTRACTED" ]] && [[ $(grep -c CONFIG_ "$KCONFIG_EXTRACTED") -gt 50 ]]; then
        CFG_CNT=$(grep -c CONFIG_ "$KCONFIG_EXTRACTED")
        print_output "[+] Extracted kernel configuration ($ORANGE$CFG_CNT configuration entries$GREEN) from $ORANGE$(basename "$FILE")$NC" "" "$KCONFIG_EXTRACTED"
        check_kconfig "$KCONFIG_EXTRACTED"
      fi

      K_VER_TMP="${K_VER/Linux version /}"
      demess_kv_version "$K_VER_TMP"
      # -> KV_ARR

      if [[ "$K_ELF" == *"ELF "* ]]; then
        K_ELF="$(echo "$K_ELF" | cut -d: -f1)"
        K_SYMBOLS="$(readelf -s "$K_ELF" | grep -c "FUNC\|OBJECT" || true)"
      fi

      # we should only get one element back, but as array
      for K_VER_CLEAN in "${KV_ARR[@]}"; do
        if [[ "${#K_INITS[@]}" -gt 0 ]]; then
          for K_INIT in "${K_INITS[@]}"; do
            if [[ "$CFG_CNT" -lt 50 ]]; then
              KCONFIG_EXTRACTED="NA"
            fi
            write_csv_log "$K_VER" "$K_VER_CLEAN" "$FILE" "$K_ELF" "$K_INIT" "$KCONFIG_EXTRACTED" "$K_SYMBOLS"
          done
        else
          write_csv_log "$K_VER" "$K_VER_CLEAN" "$FILE" "$K_ELF" "NA" "$KCONFIG_EXTRACTED" "$K_SYMBOLS"
        fi
      done
      NEG_LOG=1

    # ASCII kernel config files:
    elif file "$FILE" | grep -q "ASCII"; then
      CFG_MD5=$(md5sum "$FILE" | awk '{print $1}')
      if [[ ! " ${KCFG_MD5[*]} " =~ ${CFG_MD5} ]]; then
        K_CON_DET=$(strings "$FILE" 2>/dev/null | grep -E "^# Linux.*[0-9]{1}\.[0-9]{1,2}\.[0-9]{1,2}.* Kernel Configuration" || true)
        if [[ "$K_CON_DET" =~ \ Kernel\ Configuration ]]; then
          print_ln
          print_output "[+] Found kernel configuration file: $ORANGE$FILE$NC"
          check_kconfig "$FILE"
          NEG_LOG=1
          KCFG_MD5+=("$CFG_MD5")
        fi
      fi
    fi
  done

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

extract_kconfig() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  # # extract-ikconfig - Extract the .config file from a kernel image
  #
  # This will only work when the kernel was compiled with CONFIG_IKCONFIG.
  #
  # The obscure use of the "tr" filter is to work around older versions of
  # "grep" that report the byte offset of the line instead of the pattern.
  #
  # (c) 2009,2010 Dick Streefland <dick@streefland.net>
  # Licensed under the terms of the GNU General Public License.

  # Check invocation:
  export IMG="${1:-}"
  export KCONFIG_EXTRACTED=""

  if ! [[ -f "$IMG" ]]; then
    print_output "[-] No kernel file to analyze here - $ORANGE$IMG$NC"
    return
  fi

  print_output "[*] Trying to extract kernel configuration from $ORANGE$IMG$NC"

  export CF1='IKCFG_ST\037\213\010'
  export CF2='0123456789'

  # Prepare temp files:
  export TMP1="$TMP_DIR"/ikconfig$$.1
  export TMP2="$TMP_DIR"/ikconfig$$.2
  # shellcheck disable=SC2064
  trap "rm -f $TMP1 $TMP2" 0

  # Initial attempt for uncompressed images or objects:
  dump_config "$IMG"
  if [[ $? -eq 4 ]]; then
    return
  fi

  # That didn't work, so retry after decompression.
  try_decompress '\037\213\010' xy    gunzip
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress '\3757zXZ\000' abcde unxz
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress 'BZh'          xy    bunzip2
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress '\135\0\0\0'   xxx   unlzma
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress '\211\114\132' xy    'lzop -d'
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress '\002\041\114\030' xyy 'lz4 -d -l'
  if [[ $? -eq 4 ]]; then
    return
  fi

  try_decompress '\050\265\057\375' xxx unzstd
  if [[ $? -eq 4 ]]; then
    return
  fi
}

dump_config() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  local IMG_="${1:-}"
  local CFG_MD5=""

  if ! [[ -f "$IMG_" ]]; then
    print_output "[-] No kernel file to analyze here - $ORANGE$IMG_$NC"
    return
  fi

  if POS=$(tr "$CF1\n$CF2" "\n$CF2=" < "$IMG_" | grep -abo "^$CF2"); then
    POS=${POS%%:*}

    tail -c+"$((POS + 8))" "$IMG_" | zcat > "$TMP1" 2> /dev/null

    if [[ $? != 1 ]]; then  # exit status must be 0 or 2 (trailing garbage warning)
      if [[ "$STRICT_MODE" -eq 1 ]]; then
        set +e
      fi

      if ! [[ -f "$TMP1" ]]; then
        return
      fi

      CFG_MD5=$(md5sum "$TMP1" | awk '{print $1}')
      if [[ ! " ${KCFG_MD5[*]} " =~ ${CFG_MD5} ]]; then
        KCONFIG_EXTRACTED="$LOG_PATH_MODULE/kernel_config_extracted_$(basename "$IMG_").log"
        cp "$TMP1" "$KCONFIG_EXTRACTED"
        KCFG_MD5+=("$CFG_MD5")
        # return value of 4 means we are done and we are going back to the main function of this module for the next file
        return 4
      else
        print_output "[*] Firmware binary $ORANGE$IMG$NC already analyzed .. skipping"
        return 4
      fi
    fi
  fi
}

try_decompress() {
  # Source: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  for POS in $(tr "$1\n$2" "\n$2=" < "$IMG" | grep -abo "^$2"); do
    POS=${POS%%:*}
    tail -c+"$POS" "$IMG" | "$3" > "$TMP2" 2> /dev/null
    dump_config "$TMP2"
    if [[ $? -eq 4 ]]; then
      return 4
    fi
  done
}

check_kconfig() {
  local KCONFIG_FILE="${1:-}"

  if [[ -e "$EXT_DIR"/kconfig-hardened-check/bin/kconfig-hardened-check ]]; then
    KCONF_HARD_CHECKER="$EXT_DIR/kconfig-hardened-check/bin/kconfig-hardened-check"
  else
    print_output "[-] Kernel config hardening checker not found"
    return
  fi

  if ! [[ -f "$KCONFIG_FILE" ]]; then
    return
  fi

  print_output "[*] Testing kernel configuration file $ORANGE$KCONFIG_FILE$NC with kconfig-hardened-check"
  local KCONF_LOG=""
  KCONF_LOG="$LOG_PATH_MODULE/kconfig_hardening_check_$(basename "$KCONFIG_FILE").log"
  "$KCONF_HARD_CHECKER" -c "$KCONFIG_FILE" | tee -a "$KCONF_LOG" || true
  if [[ -f "$KCONF_LOG" ]]; then
    FAILED_KSETTINGS=$(grep -c "FAIL: " "$KCONF_LOG" || true)
    if [[ "$FAILED_KSETTINGS" -gt 0 ]]; then
      print_output "[+] Found $ORANGE$FAILED_KSETTINGS$GREEN security related kernel settings which should be reviewed - $ORANGE$(print_path "$KCONFIG_FILE")$NC" "" "$KCONF_LOG"
      print_ln
      write_log "[*] Statistics:$FAILED_KSETTINGS"
    fi
  fi
}
