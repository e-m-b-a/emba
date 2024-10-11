#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# The documentation can be generated with the following command:
# perl -ne "s/^\t+//; print if m/END_OF_DOCS'?\$/ .. m/^\s*'?END_OF_DOCS'?\$/ and not m/END_OF_DOCS'?$/;" modules/template_module.sh
# or with pod2text modules/template_module.sh
: <<'END_OF_DOCS'
=pod

=head1 P07_windows_exe_extract

==head2 P07_windows_exe_extract Short description

Please write a short description of your module. Usually ~2-3 sentences are fine to get an idea.

==head2 P07_windows_exe_extract Detailed description

Please write a longer description of your module. This should also include further references and links
that were used.

==head2 P07_windows_exe_extract 3rd party tools

Any 3rd party tool that is needed from your module. Also include the tested and known working version and
download link.

==head2 P07_windows_exe_extract Testfirmware

For verification of the module we need some testfirmware.

Testfirmware details:
- Name:
- Vendor:
- Checksum (MD5/SHA1/SHA256):
- Download Link:

==head2 P07_windows_exe_extract Output

Example output of module

==head2 P07_windows_exe_extract License

EMBA module P07_windows_exe_extract is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only
Link to license document: https://github.com/e-m-b-a/emba/blob/master/LICENSE

==head2 P07_windows_exe_extract Todo

This module is in very early state and is only able to extract exe files that are provided via the -f switch
to an EMBA analysis process.
In the future we need better detection if it will be possible to extract the exe via 7z or if we need a different
approach.

==head2 P07_windows_exe_extract Known issues

See Todo section.

==head2 P07_windows_exe_extract Author(s)

Michael Messner

=cut

END_OF_DOCS


P07_windows_exe_extract() {
  local lNEG_LOG=0

  if [[ "${WINDOWS_EXE}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Windows executable extraction module"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/exe_extraction/

    exe_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ "${FILES_EXE}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

exe_extractor() {
  sub_module_title "Windows exe extractor"

  local lFIRMWARE_PATH="${1:-}"
  local lEXTRACTION_DIR="${2:-}"
  export FILES_EXE=0
  local lDIRS_EXE=0
  local lFIRMWARE_NAME=""

  if ! [[ -f "${lFIRMWARE_PATH}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME="$(basename "${lFIRMWARE_PATH}")"

  if ! [[ -d "${lEXTRACTION_DIR}" ]]; then
    mkdir "${lEXTRACTION_DIR}"
  fi

  7z x -o"${lEXTRACTION_DIR}" "${lFIRMWARE_PATH}" 2>&1 | tee -a "${LOG_PATH_MODULE}"/exe_extraction_"${lFIRMWARE_NAME}".log || print_error "[-] Windows exe extraction failed"

  if [[ -s "${LOG_PATH_MODULE}"/exe_extraction_"${lFIRMWARE_NAME}".log ]]; then
    cat "${LOG_PATH_MODULE}"/exe_extraction_"${lFIRMWARE_NAME}".log >> "${LOG_FILE}"
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR}${NC}) as base directory:"
  find "${lEXTRACTION_DIR}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  FILES_EXE=$(find "${lEXTRACTION_DIR}" -type f | wc -l)
  lDIRS_EXE=$(find "${lEXTRACTION_DIR}" -type d | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_EXE}${NC} files and ${ORANGE}${lDIRS_EXE}${NC} directories from the Windows executable."
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
  write_csv_log "EXE extractor" "${lFIRMWARE_PATH}" "${lEXTRACTION_DIR}" "${FILES_EXE}" "${lDIRS_EXE}" "NA"
  print_ln
}
