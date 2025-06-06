#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Gives some very basic information about the provided firmware binary.
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P02_firmware_bin_file_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware file analyzer"
  pre_module_reporter "${FUNCNAME[0]}"
  set_p02_default_exports

  # we set this var global to 1 if we find something UEFI related
  export UEFI_DETECTED=0

  write_csv_log "Entity" "data" "Notes"
  write_csv_log "Firmware path" "${FIRMWARE_PATH}" "NA"

  if [[ -d "${FIRMWARE_PATH}" ]]; then
    export FIRMWARE_PATH="${LOG_DIR}"/firmware/
  fi

  if [[ -f "${FIRMWARE_PATH}" ]] && [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    get_fw_file_details "${FIRMWARE_PATH}"
    generate_entropy_graph "${FIRMWARE_PATH}"
  fi

  local lFILE_LS_OUT=""
  lFILE_LS_OUT=$(ls -lh "${FIRMWARE_PATH}")

  print_ln
  print_output "[*] Details of the firmware file:"
  print_output "$(indent "${lFILE_LS_OUT}")"
  if [[ -f "${FIRMWARE_PATH}" ]]; then
    if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
      print_fw_file_details "${FIRMWARE_PATH}"
      generate_pixde "${FIRMWARE_PATH}"
    fi
    fw_bin_detector "${FIRMWARE_PATH}"
    backup_p02_vars
  fi

  module_end_log "${FUNCNAME[0]}" 1
}

get_fw_file_details() {
  local lFIRMWARE_PATH_BIN="${1:-}"

  SHA512_CHECKSUM="$(sha512sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "SHA512" "${SHA512_CHECKSUM:-}" "NA"
  SHA1_CHECKSUM="$(sha1sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "SHA1" "${SHA1_CHECKSUM:-}" "NA"
  MD5_CHECKSUM="$(md5sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "MD5" "${MD5_CHECKSUM:-}" "NA"

  # entropy checking on binary file
  ENTROPY="$(ent "${lFIRMWARE_PATH_BIN}" | grep Entropy | sed -e 's/^Entropy\ \=\ //')"
  write_csv_log "Entropy" "${ENTROPY:-}" "NA"
}

print_fw_file_details() {
  local lFIRMWARE_PATH_BIN="${1:-}"

  print_output "$(indent "$(file "${lFIRMWARE_PATH_BIN}")")"
  print_ln
  hexdump -C "${lFIRMWARE_PATH_BIN}"| head | tee -a "${LOG_FILE}" || true
  print_ln
  print_output "[*] SHA512 checksum: ${ORANGE}${SHA512_CHECKSUM}${NC}"
  print_ln
  print_output "[*] Entropy of firmware file:"
  print_output "$(indent "${ENTROPY}")"
  print_ln
}

generate_pixde() {
  local lFIRMWARE_PATH_BIN="${1:-}"
  local lPIXD_PNG_PATH="${LOG_DIR}"/pixd.png

  if [[ -x "${EXT_DIR}"/pixde ]]; then
    print_output "[*] Visualized firmware file (first 2000 bytes):"
    print_ln "no_log"
    "${EXT_DIR}"/pixde -r-0x2000 "${lFIRMWARE_PATH_BIN}" | tee -a "${LOG_DIR}"/p02_pixd.txt
    python3 "${EXT_DIR}"/pixd_png.py -i "${LOG_DIR}"/p02_pixd.txt -o "${lPIXD_PNG_PATH}" -p 10 > /dev/null
    write_link "${lPIXD_PNG_PATH}"
    print_ln "no_log"
  fi
}

set_p02_default_exports() {
  export SHA512_CHECKSUM="NA"
  export SHA1_CHECKSUM="NA"
  export MD5_CHECKSUM="NA"
  export ENTROPY="NA"
  export DLINK_ENC_DETECTED=0
  export VMDK_DETECTED=0
  export UBOOT_IMAGE=0
  export EXT_IMAGE=0
  export AVM_DETECTED=0
  export BMC_ENC_DETECTED=0
  export UBI_IMAGE=0
  export OPENSSL_ENC_DETECTED=0
  export ENGENIUS_ENC_DETECTED=0
  export BUFFALO_ENC_DETECTED=0
  export QNAP_ENC_DETECTED=0
  export GPG_COMPRESS=0
  export BSD_UFS=0
  export ANDROID_OTA=0
  # Note: we do not set UEFI_DETECTED in this function. If so, we are going to reset it and we only need
  #       an indicator if this could be some UEFI firmware for further processing
  export UEFI_AMI_CAPSULE=0
  export ZYXEL_ZIP=0
  export QCOW_DETECTED=0
  export UEFI_VERIFIED=0
  export DJI_PRAK_DETECTED=0
  export DJI_XV4_DETECTED=0
  export WINDOWS_EXE=0
}

generate_entropy_graph() {
  local lFIRMWARE_PATH_BIN="${1:-}"
  local lENTROPY_PIC_PATH="${LOG_DIR}/firmware_entropy.png"

  # we use the original FIRMWARE_PATH for entropy testing, just if it is a file
  if [[ -f "${lFIRMWARE_PATH_BIN}" ]] && ! [[ -f "${lENTROPY_PIC_PATH}" ]]; then
    print_output "[*] Entropy testing with binwalk ... "
    print_output "$("${BINWALK_BIN[@]}" -E -p "${lENTROPY_PIC_PATH}" "${lFIRMWARE_PATH_BIN}")"
    if [[ -s "${lENTROPY_PIC_PATH}" ]]; then
      write_link "${lENTROPY_PIC_PATH}"
    fi
  fi
}

fw_bin_detector() {
  local lCHECK_FILE="${1:-}"
  local lCHECK_FILE_NAME=""
  lCHECK_FILE_NAME="$(basename "${lCHECK_FILE}")"
  local lFILE_BIN_OUT=""
  local lHEX_FIRST_LINE=""
  local lQNAP_ENC_CHECK=""
  local lAVM_CHECK=0
  local lUEFI_CHECK=0
  local lDJI_PRAK_ENC_CHECK=0
  local lDJI_XV4_ENC_CHECK=0
  local lBMC_CHECK=0
  local lGPG_CHECK=0

  set_p02_default_exports

  strings "${lCHECK_FILE}" > "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" &
  local lTMP_PID="$!"
  lFILE_BIN_OUT=$(file "${lCHECK_FILE}")
  lHEX_FIRST_LINE=$(hexdump -C "${lCHECK_FILE}" | head -1 || true)
  wait_for_pid "${lTMP_PID}"
  lAVM_CHECK=$(grep -c "AVM GmbH .*. All rights reserved.\|(C) Copyright .* AVM" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)
  lBMC_CHECK=$(grep -c "libipmi.so" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)
  if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    lDJI_PRAK_ENC_CHECK=$(grep -c "PRAK\|RREK\|IAEK\|PUEK" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)
    lDJI_XV4_ENC_CHECK=$(grep -boUaP "\x78\x56\x34" "${lCHECK_FILE}" | grep -c "^0:"|| true)
    # we are running binwalk on the file to analyze the output afterwards:
    "${BINWALK_BIN[@]}" "${lCHECK_FILE}" > "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true
    if [[ -f "${LOG_PATH_MODULE}"/p02_binwalk_output.txt ]]; then
      lQNAP_ENC_CHECK=$(grep -a -i "qnap encrypted" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    else
      lQNAP_ENC_CHECK=$("${BINWALK_BIN[@]}" -y "qnap encrypted" "${lCHECK_FILE}")
    fi

    # the following check is very weak. It should be only an indicator if the firmware could be a UEFI/BIOS firmware
    # further checks will follow in P35
    lUEFI_CHECK=$(grep -c "UEFI\|BIOS" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    lUEFI_CHECK=$(( "${lUEFI_CHECK}" + "$(grep -c "UEFI\|BIOS" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)" ))
  fi

  if [[ -f "${KERNEL_CONFIG}" ]] && [[ "${KERNEL}" -eq 1 ]]; then
    # we set the FIRMWARE_PATH to the kernel config path if we have only -k parameter
    if [[ "$(md5sum "${KERNEL_CONFIG}" | awk '{print $1}')" == "$(md5sum "${FIRMWARE_PATH}" | awk '{print $1}')" ]]; then
      print_output "[+] Identified Linux kernel configuration file"
      write_csv_log "kernel config" "yes" "NA"
      export SKIP_PRE_CHECKERS=1
      # for the kernel configuration only test we only need module s25
      export SELECT_MODULES=( "S25" )
      return
    fi
  fi

  if [[ "${lBMC_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible Supermicro BMC encrpyted firmware - using BMC extraction module"
    export BMC_ENC_DETECTED=1
    write_csv_log "BMC encrypted" "yes" "NA"
  fi
  if [[ "${lDJI_PRAK_ENC_CHECK}" -gt 0 ]]; then
    if file "${FIRMWARE_PATH}" | grep -q "POSIX tar archive"; then
      print_output "[+] Identified possible DJI PRAK drone firmware - using DJI extraction module"
      DJI_PRAK_DETECTED=1
      # UEFI is FP and we reset it now
      lUEFI_CHECK=0
      write_csv_log "DJI-PRAK" "yes" "tar compressed"
    fi
  fi
  if [[ "${lDJI_XV4_ENC_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible DJI xV4 drone firmware - using DJI extraction module"
    DJI_XV4_DETECTED=1
    # UEFI is FP and we reset it now
    lUEFI_CHECK=0
    write_csv_log "DJI-xV4" "yes" "NA"
  fi
  if [[ "${lAVM_CHECK}" -gt 0 ]] || [[ "${FW_VENDOR}" == *"AVM"* ]]; then
    print_output "[+] Identified AVM firmware."
    export AVM_DETECTED=1
    write_csv_log "AVM firmware detected" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"gzip compressed data"* || "${lFILE_BIN_OUT}" == *"Zip archive data"* || \
    "${lFILE_BIN_OUT}" == *"POSIX tar archive"* || "${lFILE_BIN_OUT}" == *"ISO 9660 CD-ROM filesystem data"* || \
    "${lFILE_BIN_OUT}" == *"7-zip archive data"* || "${lFILE_BIN_OUT}" == *"XZ compressed data"* || \
    "${lFILE_BIN_OUT}" == *"bzip2 compressed data"* ]]; then
    # as the AVM images are also zip files we need to bypass it here:
    if [[ "${AVM_DETECTED}" -ne 1 ]]; then
      print_output "[+] Identified gzip/zip/tar/iso/xz/bzip2 archive file"
      write_csv_log "basic compressed" "yes" "NA"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"QEMU QCOW2 Image"* ]] || [[ "${lFILE_BIN_OUT}" == *"QEMU QCOW Image"* ]]; then
    print_output "[+] Identified Qemu QCOW image - using QCOW extraction module"
    export QCOW_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "Qemu QCOW firmware detected" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"VMware4 disk image"* ]]; then
    print_output "[+] Identified VMWware VMDK archive file - using VMDK extraction module"
    export VMDK_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "VMDK" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"UBI image"* ]]; then
    print_output "[+] Identified UBI filesystem image - using UBI extraction module"
    export UBI_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "UBI filesystem" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"SHRS"* ]]; then
    print_output "[+] Identified D-Link SHRS encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "D-Link SHRS" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 0.\ ..\ \ 00\ 00\ 0.\ ..\ 31\ 32\ 33\ 00 ]]; then
    print_output "[+] Identified EnGenius encrpyted firmware - using EnGenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 01\ 01\ \ 00\ 00\ 0.\ ..\ 33\ 2e\ 3[89]\ 2e ]]; then
    print_output "[+] Identified EnGenius encrpyted firmware - using EnGenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"encrpted_img"* ]]; then
    print_output "[+] Identified D-Link encrpted_img encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=2
    lUEFI_CHECK=0
    write_csv_log "D-Link encrpted_img encrypted" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"u-boot legacy uImage"* ]]; then
    print_output "[+] Identified u-boot firmware image"
    export UBOOT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "Uboot image" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Unix Fast File system [v2]"* ]]; then
    print_output "[+] Identified UFS filesytem - using UFS filesytem extraction module"
    export BSD_UFS=1
    lUEFI_CHECK=0
    write_csv_log "BSD UFS filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext2 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext2 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT2 filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext3 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext3 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT3 filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext4 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext4 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT4 filesystem" "yes" "NA"
  fi
  if [[ "${lQNAP_ENC_CHECK}" == *"QNAP encrypted firmware footer , model"* ]]; then
    print_output "[+] Identified QNAP encrpyted firmware - using QNAP extraction module"
    export QNAP_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "QNAP encrypted filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"ELF"* ]]; then
    # looks like we have only and ELF file to test
    print_output "[+] Identified ELF file - performing binary tests on this ELF file"
    if ! [[ -f "${LOG_DIR}"/firmware/firmware ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}"/firmware/ || print_error "[-] Binary file copy process failed"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Perl script text executable"* ]]; then
    print_output "[+] Identified Perl script - performing perl checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.pl" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.pl" || print_error "[-] Perl script file copy process failed"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"PHP script,"* ]]; then
    print_output "[+] Identified PHP script - performing PHP checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.php" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.php" || print_error "[-] PHP script file copy process failed"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Python script,"* ]]; then
    print_output "[+] Identified Python script - performing Python checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.py" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.py" || print_error "[-] Python script file copy process failed"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"shell script,"* ]]; then
    print_output "[+] Identified shell script - performing shell checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.sh" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.sh" || print_error "[-] Shell script file copy process failed"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Android package (APK),"* ]]; then
    print_output "[+] Identified Android APK package - performing APK checks"
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.apk" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.apk" || print_error "[-] APK file copy process failed"
      export DISABLE_DEEP=1
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"PE32 executable"* ]] || [[ "${lFILE_BIN_OUT}" == *"PE32+ executable"* ]] || [[ "${lFILE_BIN_OUT}" == *"MSI Installer"* ]]; then
    print_output "[+] Identified Windows executable"
    export DISABLE_DEEP=1
    export WINDOWS_EXE=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.exe" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.exe" || print_error "[-] Windows executable copy process failed"
    fi
  fi
  # probably we need to take a deeper look to identify the gpg compressed firmware files better.
  # Currently this detection mechanism works quite good on the known firmware images
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ a3\ 01\  ]]; then
    lGPG_CHECK="$(gpg --list-packets "${FIRMWARE_PATH}" | grep "compressed packet:" || true)"
    if [[ "${lGPG_CHECK}" == *"compressed packet: algo="* ]]; then
      print_output "[+] Identified GPG compressed firmware - using GPG extraction module"
      export GPG_COMPRESS=1
      lUEFI_CHECK=0
      write_csv_log "GPG compressed firmware" "yes" "NA"
    fi
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"CrAU"* ]]; then
    print_output "[+] Identified Android OTA payload.bin update file - using Android extraction module"
    export ANDROID_OTA=1
    lUEFI_CHECK=0
    write_csv_log "Android OTA update" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"openssl enc'd data with salted password"* ]]; then
    print_output "[+] Identified OpenSSL encrypted file - trying OpenSSL module for Foscam firmware"
    export OPENSSL_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "OpenSSL encrypted" "yes" "NA"
  fi
  # This check is currently only tested on one firmware - further tests needed:
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 62\ 67\ 6e\ 00\ 00\ 00\ 00\ 00\ \ 00\ 00\ 00\  ]]; then
    print_output "[+] Identified Buffalo encrpyted firmware - using Buffalo extraction module"
    export BUFFALO_ENC_DETECTED=1
    write_csv_log "Buffalo encrypted" "yes" "NA"
  fi
  if [[ "${lCHECK_FILE_NAME}" =~ .*\.ri ]] && [[ "${lFILE_BIN_OUT}" == *"data"* ]]; then
    # ri files are usually used by zyxel
    if [[ $(find "${LOG_DIR}"/firmware -name "$(basename -s .ri "${lCHECK_FILE}")".bin | wc -l) -gt 0 ]]; then
      # if we find a bin file with the same name then it is a Zyxel firmware image
      print_output "[+] Identified ZyXel encrpyted ZIP firmware - using ZyXel extraction module"
      export ZYXEL_ZIP=1
      lUEFI_CHECK=0
      write_csv_log "ZyXel encrypted ZIP" "yes" ""
    fi
  fi
  if [[ "${lUEFI_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible UEFI/BIOS firmware - using UEFI extraction module"
    UEFI_DETECTED=1
    UEFI_AMI_CAPSULE=$(grep -c "AMI.*EFI.*capsule" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      print_output "[+] Identified possible UEFI-AMI capsule firmware - using capsule extractors"
    fi
    write_csv_log "UEFI firmware detected" "yes" "NA"
  fi

  print_ln
}

backup_p02_vars() {
  backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
  backup_var "UEFI_DETECTED" "${UEFI_DETECTED}"
  backup_var "AVM_DETECTED" "${AVM_DETECTED}"
  backup_var "VMDK_DETECTED" "${VMDK_DETECTED}"
  backup_var "UBI_IMAGE" "${UBI_IMAGE}"
  backup_var "DLINK_ENC_DETECTED" "${DLINK_ENC_DETECTED}"
  backup_var "ENGENIUS_ENC_DETECTED" "${ENGENIUS_ENC_DETECTED}"
  backup_var "UBOOT_IMAGE" "${UBOOT_IMAGE}"
  backup_var "BSD_UFS" "${BSD_UFS}"
  backup_var "EXT_IMAGE" "${EXT_IMAGE}"
  backup_var "QNAP_ENC_DETECTED" "${QNAP_ENC_DETECTED}"
  backup_var "GPG_COMPRESS" "${GPG_COMPRESS}"
  backup_var "ANDROID_OTA" "${ANDROID_OTA}"
  backup_var "OPENSSL_ENC_DETECTED" "${OPENSSL_ENC_DETECTED}"
  backup_var "BUFFALO_ENC_DETECTED" "${BUFFALO_ENC_DETECTED}"
  backup_var "ZYXEL_ZIP" "${ZYXEL_ZIP}"
  backup_var "QCOW_DETECTED" "${QCOW_DETECTED}"
}
