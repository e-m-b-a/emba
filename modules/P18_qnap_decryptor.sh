#!/bin/bash

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

# Description: Extracts encrypted firmware images from QNAP as shown here:
#              https://github.com/max-boehm/qnap-utils
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P18_qnap_decryptor() {
  local NEG_LOG=0

  if [[ "$QNAP_ENC_DETECTED" -ne 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "QNAP encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_qnap_dec.tgz

    qnap_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    if [[ "$QNAP" -eq 1 ]]; then
      qnap_extractor "$FIRMWARE_PATH"
    fi

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
  fi
}

qnap_enc_extractor() {
  local QNAP_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"
  export QNAP=0

  if ! [[ -f "$QNAP_ENC_PATH_" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "QNAP encrypted firmware extractor"

  hexdump -C "$QNAP_ENC_PATH_" | head | tee -a "$LOG_FILE" || true

  if [[ -f "$EXT_DIR"/PC1 ]]; then
    print_ln
    print_output "[*] Decrypting QNAP firmware with leaked key material ..."
    print_ln
    "$EXT_DIR"/PC1 d QNAPNASVERSION4 "$QNAP_ENC_PATH_" "$EXTRACTION_FILE_" | tee -a "$LOG_FILE"
  else
    print_output "[-] QNAP decryptor not found - check your installation"
  fi

  print_ln
  if [[ -f "$EXTRACTION_FILE_" && "$(file "$EXTRACTION_FILE_")" == *"gzip compressed data"* ]]; then
    print_output "[+] Decrypted QNAP firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    MD5_DONE_DEEP+=( "$(md5sum "$QNAP_ENC_PATH_" | awk '{print $1}')" )
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    backup_var "FIRMWARE_PATH" "$FIRMWARE_PATH"
    export QNAP=1
    print_ln
    print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
    print_ln
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "QNAP decryptor" "$QNAP_ENC_PATH_" "$EXTRACTION_FILE_" "1" "NA" "gzip compressed data"
    if [[ -z "${FW_VENDOR:-}" ]]; then
      FW_VENDOR="QNAP"
      backup_var "FW_VENDOR" "$FW_VENDOR"
    fi

  else
    print_output "[-] Decryption of QNAP firmware file failed"
  fi
}

qnap_extractor() {
  local DECRYPTED_FW_="${1:-}"
  if ! [[ -f "$DECRYPTED_FW_" ]]; then
    return
  fi

  sub_module_title "QNAP firmware extraction"
  print_output "[!] WARNING: This module is in an very early alpha state."
  print_output "[!] WARNING: Some areas of this module are not tested."

  # This module is a full copy of https://github.com/max-boehm/qnap-utils/blob/master/extract_qnap_fw.sh
  # some areas of this code are completely untested. Please report bugs via https://github.com/e-m-b-a/emba/issues

  QNAP_EXTRACTION_ROOT="$LOG_DIR"/firmware/qnap_extraction
  QNAP_EXTRACTION_ROOT_DST="$QNAP_EXTRACTION_ROOT"/root_filesystem
  mkdir -p "$QNAP_EXTRACTION_ROOT_DST" || true

  if file "$DECRYPTED_FW_" | grep -q ": gzip" ; then
    print_output "[*] Extracting $ORANGE$DECRYPTED_FW_$NC into $ORANGE$QNAP_EXTRACTION_ROOT$NC."
    mkdir -p "$QNAP_EXTRACTION_ROOT" || true
    tar xvf "$DECRYPTED_FW_" -C "$QNAP_EXTRACTION_ROOT" 2>/dev/null || true | tee -a "$LOG_FILE"
    print_ln
    print_output "[*] Extracted firmware structure ($ORANGE$QNAP_EXTRACTION_ROOT$NC):"
    #shellcheck disable=SC2012
    ls -lh "$QNAP_EXTRACTION_ROOT" | tee -a "$LOG_FILE"
    print_files_dirs
    print_bar ""
  else
    print_output "[-] No QNAP firmware file found"
    return 1
  fi

  UIMAGE="$QNAP_EXTRACTION_ROOT/uImage"               # x31,x31+
  UBI="$QNAP_EXTRACTION_ROOT/rootfs2.ubi"             # x31,x31+
  IMAGE="$QNAP_EXTRACTION_ROOT_DST/image"

  # initial ramdisk root filesystem
  INITRAMFS="$QNAP_EXTRACTION_ROOT_DST/initramfs"        # x31,x31+
  INITRD="$QNAP_EXTRACTION_ROOT/initrd.boot"          # x10,x12,x19,x20,x21
  if [ ! -e "$INITRD" ]; then
    INITRD="$QNAP_EXTRACTION_ROOT/initrd"             # x51,x53
  fi

  ROOTFS2="$QNAP_EXTRACTION_ROOT/rootfs2.tgz"
  ROOTFS2_BZ="$QNAP_EXTRACTION_ROOT/rootfs2.bz"
  ROOTFS2_IMG="$QNAP_EXTRACTION_ROOT/rootfs2.img"
  ROOTFS_EXT="$QNAP_EXTRACTION_ROOT/rootfs_ext.tgz"
  QPKG="$QNAP_EXTRACTION_ROOT/qpkg.tar"

  if [ -e "$UBI" ]; then
    ROOTFS2="$QNAP_EXTRACTION_ROOT_DST/rootfs2.tgz"
    ROOTFS_EXT="$QNAP_EXTRACTION_ROOT_DST/rootfs_ext.tgz"
    QPKG="$QNAP_EXTRACTION_ROOT_DST/qpkg.tar"
  fi

  SYSROOT="$QNAP_EXTRACTION_ROOT_DST/sysroot"
  mkdir "$SYSROOT"

  if [ -e "$UIMAGE" ]; then
    print_ln
    print_output "[*] Scanning $ORANGE$UIMAGE$NC for (gzipped) parts..."

    a=$(od -t x1 -w4 -Ad -v "$UIMAGE" | grep '1f 8b 08 00' | awk '{print $1}')
    if [ -n "$a" ]; then
      dd if="$UIMAGE" bs="$a" skip=1 of="$IMAGE.gz" status=none
      gunzip --quiet "$IMAGE.gz" || [ $? -eq 2 ]
      print_output "[+] Extracted and uncompressed $ORANGE$IMAGE$NC at offset $ORANGE$a$NC"

      i=0
      for a in $(od -t x1 -w4 -Ad -v "$IMAGE" | grep '1f 8b 08 00' | awk '{print $1}'); do
        i=$((i+1))
        dd if="$IMAGE" bs="$a" skip=1 of="$IMAGE.part$i.gz" status=none
        gunzip --quiet "$IMAGE.part$i.gz" || [ $? -eq 2 ]
        print_output "[+] Extracted and uncompressed '$IMAGE.part$i' at offset $a"
      done

      if [ $i -gt 0 ]; then
        mv "$IMAGE.part$i" "$INITRAMFS" || true
        print_output "[*] Renamed $ORANGE$IMAGE.part$i$NC to $ORANGE$INITRAMFS$NC"
        rm "$IMAGE" || true
      fi
    fi
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$UBI" ]; then
    print_ln
    print_output "[*] Unpacking $ORANGE$UBI$NC."
    # TODO: we should evaluate moving to the EMBA UBI extractor in the future

    # see http://trac.gateworks.com/wiki/linux/ubi
    #
    # apt-get install mtd-utils

    # 256MB flash
    modprobe -r nandsim || true
    if [ -e /dev/mtdblock0 ]; then
      print_output "[-] /dev/mtdblock0 does already exist! Exiting to not overwrite it."; exit
    fi
    modprobe nandsim first_id_byte=0x2c second_id_byte=0xda third_id_byte=0x90 fourth_id_byte=0x95

    print_output "[*] Copy UBI image into simulated flash device"
    # populate NAND with an existing ubi:
    modprobe mtdblock
    dd if="$UBI" of=/dev/mtdblock0 bs=2048 status=none

    print_output "[*] Attach simulated flash device"
    # attach ubi
    modprobe ubi
    ubiattach /dev/ubi_ctrl -m0 -O2048
    #ubinfo -a

    print_output "[*] Mounting ubifs file system"
    # mount the ubifs to host
    modprobe ubifs
    local TMP_EXT_MOUNT="$TMP_DIR""/ext_mount_$RANDOM"
    mkdir -p "$TMP_EXT_MOUNT" || true
    mount -t ubifs ubi0 "$TMP_EXT_MOUNT"
    if mount | grep -q ext_mount; then
      print_output "[*] Copying contents from UBI mount"
      cp -a "$TMP_EXT_MOUNT"/boot/* "$QNAP_EXTRACTION_ROOT_DST" || true
      print_ln
      print_output "[*] Extracted firmware structure ($ORANGE$QNAP_EXTRACTION_ROOT_DST$NC):"
      #shellcheck disable=SC2012
      ls -lh "$QNAP_EXTRACTION_ROOT_DST" | tee -a "$LOG_FILE"

      print_output "[*] UBI cleanup"
      umount "$TMP_EXT_MOUNT"
    else
      print_output "[-] Something went wrong!"
    fi
    rm -r "$TMP_EXT_MOUNT" || true
    ubidetach /dev/ubi_ctrl -m0
    modprobe -r nandsim
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$INITRAMFS" ]; then
    print_ln
    print_output "[*] Extracting $ORANGE$INITRAMFS$NC."
    # shellcheck disable=SC2002
    cat "$INITRAMFS" | (cd "$SYSROOT" && (cpio -i --make-directories||true) )
    print_ln
    print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
    #shellcheck disable=SC2012
    ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$INITRD" ]; then
    print_ln
    if file "$INITRD" | grep -q LZMA ; then
      print_output "[*] Extracting $ORANGE$INITRD$NC (LZMA)."
      lzma -d <"$INITRD" | (cd "$SYSROOT" && (cpio -i --make-directories||true) )
      print_ln
      print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
      #shellcheck disable=SC2012
      ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
      print_files_dirs
      print_bar ""
    fi

    if file "$INITRD" | grep -q gzip ; then
      print_ln
      print_output "[*] Extracting $ORANGE$INITRD$NC (gzip)."
      gzip -d <"$INITRD" >"$QNAP_EXTRACTION_ROOT_DST/initrd.$$"
      print_output "[*] Mounting $ORANGE$INITRD$NC."
      local TMP_EXT_MOUNT="$TMP_DIR""/ext_mount_$RANDOM"
      mkdir -p "$TMP_EXT_MOUNT" || true
      mount -t ext2 "$QNAP_EXTRACTION_ROOT_DST/initrd.$$" "$TMP_EXT_MOUNT" -oro,loop
      if mount | grep -q ext_mount; then
        cp -a "$TMP_EXT_MOUNT"/* "$SYSROOT" || true
        umount "$TMP_EXT_MOUNT"
        print_ln
        print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
        #shellcheck disable=SC2012
        ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
        rm "$QNAP_EXTRACTION_ROOT_DST/initrd.$$" || true
      else
        print_output "[-] Something went wrong!"
      fi
      rm -r "$TMP_EXT_MOUNT" || true
      print_files_dirs
      print_bar ""
    fi
  fi

  if [ -e "$ROOTFS2" ]; then
    print_ln
    print_output "[*] Extracting $ORANGE$ROOTFS2$NC (gzip, tar)."
    tar -xvzf "$ROOTFS2" -C "$SYSROOT"
    print_ln
    print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
    #shellcheck disable=SC2012
    ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$ROOTFS2_BZ" ]; then
    print_ln
    if file "$ROOTFS2_BZ" | grep -q "LZMA"; then
      print_output "[*] Extracting $ORANGE$ROOTFS2_BZ$NC (LZMA)."
      lzma -d <"$ROOTFS2_BZ" | (cd "$SYSROOT" && (cpio -i --make-directories||true) )
    else
      print_output "[*] Extracting $ORANGE$ROOTFS2_BZ$NC (bzip2, tar)."
      tar -xvjf "$ROOTFS2_BZ" -C "$SYSROOT"
    fi
    print_ln
    print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
    #shellcheck disable=SC2012
    ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
    print_files_dirs
    print_bar ""
  fi

  if [ -f "$ROOTFS2_IMG" ]; then
    print_ln
    print_output "[*] Extracting $ORANGE$ROOTFS2_IMG$NC (ext2)..."
    local TMP_EXT_MOUNT="$TMP_DIR""/ext_mount_$RANDOM"
    mkdir -p "$TMP_EXT_MOUNT" || true
    mount -t ext2 "$ROOTFS2_IMG" "$TMP_EXT_MOUNT" -oro,loop
    if mount | grep -q ext_mount; then
      tar -xvjf "$TMP_EXT_MOUNT"/rootfs2.bz -C "$SYSROOT"
      print_ln
      print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
      #shellcheck disable=SC2012
      ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
      umount "$TMP_EXT_MOUNT"
    else
      print_output "[-] Something went wrong!"
    fi
    rm -r "$TMP_EXT_MOUNT" || true
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$ROOTFS_EXT" ]; then
    print_ln
    print_output "[*] Extracting EXT filesystem $ORANGE$ROOTFS_EXT$NC."
    tar xzvf "$ROOTFS_EXT" -C "$QNAP_EXTRACTION_ROOT_DST"
    print_output "[*] Mounting EXT filesystem $ORANGE$ROOTFS_EXT$NC."
    local TMP_EXT_MOUNT="$TMP_DIR""/ext_mount_$RANDOM"
    mkdir -p "$TMP_EXT_MOUNT" || true
    mount "$QNAP_EXTRACTION_ROOT_DST"/rootfs_ext.img "$TMP_EXT_MOUNT" -oro,loop
    if mount | grep -q ext_mount; then
      cp -a "$TMP_EXT_MOUNT"/* "$SYSROOT" || true
      umount "$TMP_EXT_MOUNT" 
    fi
    print_output "[*] Removing EXT filesystem ${ORANGE}rootfs_ext.img$NC."
    rm "$QNAP_EXTRACTION_ROOT_DST"/rootfs_ext.img || true
    rm -r "$TMP_EXT_MOUNT" || true
    print_ln
    print_output "[*] Extracted firmware structure ($ORANGE$SYSROOT$NC):"
    #shellcheck disable=SC2012
    ls -lh "$SYSROOT" | tee -a "$LOG_FILE"
    print_files_dirs
    print_bar ""
  fi

  USR_LOCAL=$(find "$SYSROOT/opt/source" -name "*.tgz" 2>/dev/null)
  #if [[ "${#USR_LOCAL[@]}" -gt 0 ]]; then
  if [[ -v USR_LOCAL[@] ]]; then
    print_ln
    for f in "${USR_LOCAL[@]}"; do
      print_output "[*] Extracting $ORANGE$f$NC -> ${ORANGE}sysroot/usr/local$NC ..."
      mkdir -p "$SYSROOT/usr/local" || true
      tar xvzf "$f" -C "$SYSROOT/usr/local"
    done
    print_files_dirs
    print_bar ""
  fi

  if [ -e "$QPKG" ]; then
    print_ln
    print_output "[*] Extracting $ORANGE$QPKG$NC."
    mkdir -p "$QNAP_EXTRACTION_ROOT_DST/qpkg" || true
    tar xvf "$QPKG" -C "$QNAP_EXTRACTION_ROOT_DST/qpkg"
    for f in "$QNAP_EXTRACTION_ROOT_DST"/qpkg/*.tgz; do
      if file "$f" | grep -q gzip; then
        print_output "[*] Extracting QPKG $ORANGE$f$NC."
        tar tvzf "$f" > "$f".txt
      fi
    done
    print_files_dirs
    print_bar ""
  fi

  for name in apache_php5 mysql5 mariadb5; do
    if [ -e "$QNAP_EXTRACTION_ROOT_DST/qpkg/$name.tgz" ]; then
      print_output "[*] Extracting ${ORANGE}qpkg/$name.tgz$NC -> ${ORANGE}sysroot/usr/local$NC ..."
      tar xvzf "$QNAP_EXTRACTION_ROOT_DST/qpkg/$name.tgz" -C "$SYSROOT/usr/local"
    fi
  done

  if [ -e "$QNAP_EXTRACTION_ROOT_DST"/qpkg/libboost.tgz ]; then
    print_ln
    print_output "[*] Extracting ${ORANGE}qpkg/libboost.tgz$NC -> ${ORANGE}sysroot/usr/lib$NC."
    mkdir -p "$SYSROOT/usr/lib" || true
    tar xvzf "$QNAP_EXTRACTION_ROOT_DST"/qpkg/libboost.tgz -C "$SYSROOT/usr/lib"
  elif [ -e "$QNAP_EXTRACTION_ROOT_DST"/qpkg/DSv3.tgz ]; then
    print_output "[*] Extracting ${ORANGE}libboost$NC from ${ORANGE}qpkg/DSv3.tgz$NC -> ${ORANGE}sysroot/usr/lib$NC."
    tar tzf "$QNAP_EXTRACTION_ROOT_DST"/qpkg/DSv3.tgz |grep libboost | tar xzf "$QNAP_EXTRACTION_ROOT_DST"/qpkg/DSv3.tgz -C "$SYSROOT" -T -
  fi

  if [[ -d "$SYSROOT"/usr/lib ]]; then
    HOME_DIR="$(pwd)"
    (cd "$SYSROOT/usr/lib" || exit; for f in libboost*.so.1.42.0; do ln -s "$f" "${f%.1.42.0}"; done)
    cd "$HOME_DIR" || exit
  fi
  print_files_dirs
  print_bar ""
}

print_files_dirs() {
  FILES_QNAP=$(find "$QNAP_EXTRACTION_ROOT" -type f | wc -l)
  DIRS_QNAP=$(find "$QNAP_EXTRACTION_ROOT" -type d | wc -l)
  print_ln
  print_output "[*] Extracted $ORANGE$FILES_QNAP$NC files and $ORANGE$DIRS_QNAP$NC directories from the QNAP firmware image.\n"
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
  write_csv_log "QNAP extractor" "$DECRYPTED_FW_" "$QNAP_EXTRACTION_ROOT" "$FILES_QNAP" "$DIRS_QNAP" "NA"
}
