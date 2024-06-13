#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Extracts Zyxel firmware images that are protected with a password
#               Further information can be found in this paper:
#               https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Jay%20Lagorio%20-%20Tear%20Down%20this%20Zywall%20Breaking%20Open%20Zyxel%20Encrypted%20Firmware.pdf
#               Thanks to https://twitter.com/jaylagorio

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P22_Zyxel_zip_decrypt() {
  local NEG_LOG=0

  if [[ "${ZYXEL_ZIP}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Zyxel protected ZIP firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="${LOG_DIR}"/firmware/firmware_zyxel_zip

    zyxel_zip_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

zyxel_zip_extractor() {
  local RI_FILE_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"

  local RI_FILE_BIN=""
  local ZLD_DIR=""
  local RI_FILE_BIN_PATH=""
  local ZLD_BINS=()
  local ZLD_BIN=""
  local COMPRESS_IMG=""

  sub_module_title "Zyxel protected ZIP firmware extractor"

  if ! [[ -f "${RI_FILE_}" ]]; then
    print_output "[-] Zyxel - No file for extraction provided"
    return
  fi
  if ! [[ "${RI_FILE_}" =~ .*\.ri ]]; then
    print_output "[-] Zyxel - No valid ri file for extraction provided"
    return
  fi

  unblobber "${RI_FILE_}" "${EXTRACTION_DIR_}"
  print_ln

  if command -v jchroot > /dev/null; then
    local CHROOT="jchroot"
    # OPTS see https://github.com/vincentbernat/jchroot#security-note
    local OPTS=(-n emba -U -u 0 -g 0 -M "0 $(id -u) 1" -G "0 $(id -g) 1")
    print_output "[*] Using ${ORANGE}jchroot${NC} for building more secure chroot environments"
  else
    print_output "[-] No jchroot binary found ..."
    return
  fi

  mapfile -t ZLD_BINS < <(find "${EXTRACTION_DIR_}" -name "zld_fsextract")
  RI_FILE_BIN="$(basename -s .ri "${RI_FILE_}")".bin

  for ZLD_BIN in "${ZLD_BINS[@]}"; do
    local FILES_ZYXEL=0
    local DIRS_ZYXEL=0
    local ZIP_KEY=""
    print_output "[*] Checking ${ORANGE}${ZLD_BIN}${NC}"

    ZLD_DIR=$(dirname "${ZLD_BIN}")
    RI_FILE_BIN_PATH=$(find "${LOG_DIR}"/firmware -name "${RI_FILE_BIN}" | head -1)
    # => this should be the protected Zip file

    if [[ $(file "${ZLD_BIN}") == *"ELF"* ]] && [[ $(file "${RI_FILE_BIN_PATH}") == *"Zip archive data"* ]]; then
      print_output "[*] Found Zyxel environment in ${ORANGE}${ZLD_DIR}${NC}"
      # now we know that we have an elf for extraction and and unzip binary in the extraction dir
      # this is everything we need for the key
      if ( file "${ZLD_BIN}" | grep -q "ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2 version 1" ) ; then
        # todo: check if Zyxel also uses other architectures
        local EMULATOR="qemu-mipsn32-static"
        print_output "[*] Found valid emulator ${ORANGE}${EMULATOR}${NC}"
      else
        print_output "[-] WARNING: Unsupported architecture for key identification:"
        print_output "$(indent "$(file "${ZLD_BIN}")")"
        print_output "[-] Please open an issue at https://github.com/e-m-b-a/emba/issues"
        continue
      fi

      print_output "[*] Running Zyxel emulation for key extraction ..."

      if ! [[ -e "$(command -v "${EMULATOR}")" ]]; then
        print_output "[-] No valid emulator (${ORANGE}${EMULATOR}${NC}) found in your environment"
        return
      fi

      cp "$(command -v "${EMULATOR}")" "${ZLD_DIR}" || ( print_output "[-] Something went wrong" && return)
      cp "${RI_FILE_BIN_PATH}" "${ZLD_DIR}" || ( print_output "[-] Something went wrong" && return)
      ZLD_BIN=$(basename "${ZLD_BIN}")

      chmod +x "${ZLD_DIR}"/"${ZLD_BIN}"
      timeout --preserve-status --signal SIGINT 2s "${CHROOT}" "${OPTS[@]}" "${ZLD_DIR}" -- ./"${EMULATOR}" -strace ./"${ZLD_BIN}" "${RI_FILE_BIN}" AABBCCDD >> "${LOG_PATH_MODULE}"/zld_strace.log 2>&1 || true
      rm "${ZLD_DIR}"/"${EMULATOR}" || true

      if [[ -f "${LOG_PATH_MODULE}"/zld_strace.log ]] && [[ -s "${LOG_PATH_MODULE}"/zld_strace.log ]]; then
        ZIP_KEY=$(grep -a -E "^[0-9]+\ execve.*AABBCCDD\",\"-o" "${LOG_PATH_MODULE}"/zld_strace.log| cut -d, -f6 | sort -u | sed 's/^\"//' | sed 's/\"$//')
      else
        print_output "[-] No qemu strace log generated -> no further processing possible"
      fi

      # if we have found a ZIP_KEY:
      if [[ -v ZIP_KEY ]]; then
        print_ln
        print_output "[+] Possible ZIP key detected: ${ORANGE}${ZIP_KEY}${NC}" "" "${LOG_PATH_MODULE}/zld_strace.log"

        7z x -p"${ZIP_KEY}" -o"${EXTRACTION_DIR_}"/firmware_zyxel_extracted "${RI_FILE_BIN_PATH}" || true

        FILES_ZYXEL=$(find "${EXTRACTION_DIR_}"/firmware_zyxel_extracted -type f | wc -l)
        DIRS_ZYXEL=$(find "${EXTRACTION_DIR_}"/firmware_zyxel_extracted -type d | wc -l)

        print_ln
        print_output "[*] Zyxel 1st stage - Extracted ${ORANGE}${FILES_ZYXEL}${NC} files and ${ORANGE}${DIRS_ZYXEL}${NC} directories from the firmware image."
        write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
        write_csv_log "Zyxel extractor" "${RI_FILE_BIN_PATH}" "${EXTRACTION_DIR_}/firmware_zyxel_extracted" "${FILES_ZYXEL}" "${DIRS_ZYXEL}" "NA"
      else
        print_output "[-] No ZIP key detected -> no further processing possible"
      fi

      # if it was possible to extract something with the key:
      if [[ "${FILES_ZYXEL}" -gt 0 ]]; then
        # compress.img ist the firmware -> letz search for it
        COMPRESS_IMG=$(find "${EXTRACTION_DIR_}"/firmware_zyxel_extracted -type f -name compress.img | sort -u)
        if [[ $(file "${COMPRESS_IMG}") == *"Squashfs"* ]]; then
          print_output "[+] Found valid ${ORANGE}compress.img${GREEN} and extract it now"
          unblobber "${COMPRESS_IMG}" "${EXTRACTION_DIR_}/firmware_zyxel_extracted/compress_img_extracted"
          FILES_ZYXEL=$(find "${EXTRACTION_DIR_}"/firmware_zyxel_extracted/compress_img_extracted -type f | wc -l)
          DIRS_ZYXEL=$(find "${EXTRACTION_DIR_}"/firmware_zyxel_extracted/compress_img_extracted -type d | wc -l)
          print_output "[*] Zyxel 2nd stage - Extracted ${ORANGE}${FILES_ZYXEL}${NC} files and ${ORANGE}${DIRS_ZYXEL}${NC} directories from the firmware image."
          write_csv_log "Zyxel extractor" "${RI_FILE_BIN_PATH}" "${EXTRACTION_DIR_}/firmware_zyxel_extracted/compress_img_extracted" "${FILES_ZYXEL}" "${DIRS_ZYXEL}" "NA"
          export FIRMWARE_PATH="${LOG_DIR}"/firmware/
          backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
          print_ln
          break
        else
          print_output "[-] No valid ${ORANGE}compress.img${NC} file found"
        fi
      else
        print_output "[-] 1st stage Zip extraction failed"
      fi
      print_ln
    else
      print_output "[-] No environment for Zyxel decryption found"
    fi
  done
}
