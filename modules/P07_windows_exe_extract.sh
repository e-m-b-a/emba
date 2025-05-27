#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
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

This module extracts Windows executables with 7z.

==head2 P07_windows_exe_extract Detailed description

Please write a longer description of your module. This should also include further references and links
that were used.

==head2 P07_windows_exe_extract 3rd party tools

Any 3rd party tool that is needed from your module. Also include the tested and known working
version and download link:

* 7zip installation on current Kali Linux:

└─$ dpkg -l | grep 7z
ii  7zip                      23.01+dfsg-8                    amd64        7-Zip file archiver with a high compression ratio
ii  p7zip-full                16.02+transitional.1            all          transitional package

==head2 P07_windows_exe_extract Testfirmware

Most Windows exe files should work fine.

==head2 P07_windows_exe_extract Output

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=C.UTF-8 Threads:128 OPEN_MAX:1048576

Scanning the drive for archives:
1 file, 1974272 bytes (1928 KiB)

Extracting archive: /firmware
--
Path = /firmware
Type = Compound
Physical Size = 1974272
Extension = msi
Cluster Size = 4096
Sector Size = 64
----
Path = media1.cab
Size = 1184244
Packed Size = 1187840
--
Path = media1.cab
Type = Cab
Physical Size = 1184244
Method = MSZip
Blocks = 1
Volumes = 1
Volume Index = 0
ID = 0

Everything is Ok

Files: 32
Size:       6280647
Compressed: 1974272

[*] Using the following firmware directory (/logs/firmware/exe_extraction/) as base directory:
  3407924      4 drwxr-xr-x   2 root     root         4096 Oct 11 15:30 /logs/firmware/exe_extraction/
  3407955    116 -rw-r--r--   1 root     root       114896 Jul 22  2014 /logs/firmware/exe_extraction/file_F25F71FF5ED347D6AF737982BCA5AF43
  <snip>

[*] Extracted 32 files and 1 directories from the Windows executable.

==head2 P07_windows_exe_extract License

EMBA module P07_windows_exe_extract is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only
Link to license document: https://github.com/e-m-b-a/emba/blob/master/LICENSE

==head2 P07_windows_exe_extract Todo

This module is in very early state and is currently only able to extract exe files that are provided via the -f switch
to an EMBA analysis process.
In the future we need better detection if it will be possible to extract the exe via 7z or if we need a different
approach.
Additionally, we need to walk through the extracted content if we can extract further exe files. This could be also done
via the deep extractor.

==head2 P07_windows_exe_extract Known issues

See Todo section.

==head2 P07_windows_exe_extract Author(s)

Michael Messner

=cut

END_OF_DOCS


P07_windows_exe_extract() {
  local lNEG_LOG=0

  if [[ "${WINDOWS_EXE:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Windows executable extraction module"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/exe_extraction/

    exe_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
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

    # Error handling. If we have errors on exe extraction we try binwalk
    if [[ "$(grep -c "ERROR: " "${LOG_PATH_MODULE}"/exe_extraction_"${lFIRMWARE_NAME}".log)" -gt 0 ]]; then
      print_ln
      print_output "[*] Windows exe extraction error detected -> using binwalk as fallback extraction mechanism"
      binwalker_matryoshka "${lFIRMWARE_PATH}" "${lEXTRACTION_DIR%\/}_binwalk"

      print_ln
      print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR%\/}_binwalk${NC}) as base directory:"
      find "${lEXTRACTION_DIR%\/}_binwalk" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    else
      print_ln
      print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR}${NC}) as base directory:"
      find "${lEXTRACTION_DIR}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    fi
  fi

  print_ln

  local lFILES_EXE_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  mapfile -t lFILES_EXE_ARR < <(find "${lEXTRACTION_DIR}" -type f)
  if [[ -d "${lEXTRACTION_DIR%\/}_binwalk" ]]; then
    local lFILES_EXE_ARR_2=()
    mapfile -t lFILES_EXE_ARR_2 < <(find "${lEXTRACTION_DIR%\/}_binwalk" -type f ! -name "*.raw")
    lFILES_EXE_ARR=( "${lFILES_EXE_ARR[@]}" "${lFILES_EXE_ARR_2[@]}" )
  fi

  print_output "[*] Extracted ${ORANGE}${#lFILES_EXE_ARR[@]}${NC} files from the Windows executable."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_EXE_ARR[@]}${NC} files ... could take some time" "no_log"
  for lBINARY in "${lFILES_EXE_ARR[@]}"; do
    binary_architecture_threader "${lBINARY}" "P07_windows_exe_extract" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
  write_csv_log "EXE extractor" "${lFIRMWARE_PATH}" "${lEXTRACTION_DIR}" "${#lFILES_EXE_ARR[@]}" "NA"
  print_ln
}
