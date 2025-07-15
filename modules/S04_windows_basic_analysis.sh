#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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

=head1 S04_windows_basic_analysis

==head2 S04_windows_basic_analysis Short description

This module uses exiftool and readpe to access pe details details of Windows binaries.

==head2 S04_windows_basic_analysis Detailed description

Module starts exiftool without further parameters and writes output to LOG_PATH_MODULE/$(basename $BIN).txt

└─$ exiftool ./vncviewer.exe
ExifTool Version Number         : 12.76
File Name                       : vncviewer.exe
Directory                       : /home/m1k3/
File Size                       : 365 kB
File Modification Date/Time     : 2024:09:26 16:21:46+02:00
File Access Date/Time           : 2024:09:26 16:26:30+02:00
File Inode Change Date/Time     : 2024:09:26 16:21:46+02:00
File Permissions                : -rwxr-xr-x
File Type                       : Win32 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Machine Type                    : Intel 386 or later, and compatibles
Time Stamp                      : 2004:11:25 14:45:33+01:00
Image File Characteristics      : No relocs, Executable, No line numbers, No symbols, 32-bit
PE Type                         : PE32
Linker Version                  : 6.0
Code Size                       : 241664
Initialized Data Size           : 122880
Uninitialized Data Size         : 0
Entry Point                     : 0x316f9
OS Version                      : 4.0
Image Version                   : 0.0
Subsystem Version               : 4.0
Subsystem                       : Windows GUI
File Version Number             : 1.3.6.0
Product Version Number          : 1.3.6.0
File Flags Mask                 : 0x003f
File Flags                      : (none)
File OS                         : Windows NT 32-bit
Object File Type                : Executable application
File Subtype                    : 0
Language Code                   : English (U.S.)
Character Set                   : Unicode
Comments                        : Based on TridiaVNC by Tridia Corporation
Company Name                    : Constantin Kaplinsky
File Description                : vncviewer
File Version                    : 1, 3, 6, 0
Internal Name                   : vncviewer
Legal Copyright                 : Copyright   1999-2004 [many holders]
Legal Trademarks                :
Original File Name              : vncviewer.exe
Private Build                   :
Product Name                    : TightVNC Win32 Viewer
Product Version                 : 1, 3, 6, 0
Special Build                   :
Tag 080904b 0                   :

==head2 S04_windows_basic_analysis 3rd party tools

Any 3rd party tool that is needed from your module. Also include the tested and known working
version and download link:
* exiftool installation on current Kali Linux:

ii  libimage-exiftool-perl     12.76+dfsg-1        all       library and program to read and write meta information in multimedia files

* readpe installation on current Kali Linux:

ii  readpe                     0.84-1              amd64     command-line tools to manipulate Windows PE files

==head2 S04_windows_basic_analysis Testfirmware

Any Windows binary (exe) file should be fine.

==head2 S04_windows_basic_analysis Output

Example output of module see "Detailed description"

==head2 S04_windows_basic_analysis License

EMBA module S04_windows_basic_analysis is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only
Link to license document: https://github.com/e-m-b-a/emba/blob/master/LICENSE

==head2 S04_windows_basic_analysis Todo

None

==head2 S04_windows_basic_analysis Known issues

None

==head2 S04_windows_basic_analysis Author(s)

Michael Messner

=cut

END_OF_DOCS


S04_windows_basic_analysis() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Discover basic information of Windows executables"

  local lNEG_LOG=0
  local lEXE_ARCHIVES_ARR=()
  local lEXE_ARCHIVE=""
  local lEXE_NAME=""

  mapfile -t lEXE_ARCHIVES_ARR < <(grep "PE32\|MSI" "${P99_CSV_LOG}" | sort -u || true)

  if [[ "${#lEXE_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    for lEXE_ARCHIVE in "${lEXE_ARCHIVES_ARR[@]}" ; do
      lEXE_ARCHIVE=$(echo "${lEXE_ARCHIVE}" | cut -d ';' -f2)
      lEXE_NAME=$(basename "${lEXE_ARCHIVE}")

      sub_module_title "exifdata for ${lEXE_NAME}" "${LOG_PATH_MODULE}/exifdata_${lEXE_NAME}.log"
      print_output "[*] Extract exifdata from ${ORANGE}${lEXE_NAME}${NC}" "no_log"
      exiftool "${lEXE_ARCHIVE}" 2>/dev/null >> "${LOG_PATH_MODULE}/exifdata_${lEXE_NAME}.log" || print_error "[-] Something happened on exiftool analysis for ${lEXE_ARCHIVE}"

      sub_module_title "PEdata for ${lEXE_NAME}" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      print_output "[*] Extract pedata from ${ORANGE}${lEXE_NAME}${NC}" "no_log"
      write_log "" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      write_log "[*] pescan for ${ORANGE}${lEXE_NAME}${NC}" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      pescan -v "${lEXE_ARCHIVE}" 2>/dev/null >> "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log" || print_error "[-] Something happened on pescan analysis for ${lEXE_ARCHIVE}"

      write_log "" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      write_log "[*] readpe for ${ORANGE}${lEXE_NAME}${NC}" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      readpe "${lEXE_ARCHIVE}" 2>/dev/null >> "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log" || print_error "[-] Something happened on pedata analysis for ${lEXE_ARCHIVE}"

      if [[ -s "${LOG_PATH_MODULE}/exifdata_${lEXE_NAME}.log" ]]; then
        print_output "[*] Windows binary exifdata - $(orange "$(print_path "${lEXE_ARCHIVE}")")" "" "${LOG_PATH_MODULE}/exifdata_${lEXE_NAME}.log"
      else
        print_output "[-] No exif data for binary $(orange "$(print_path "${lEXE_ARCHIVE}")") available"
      fi
      if [[ -s "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log" ]]; then
        print_output "[*] Windows binary pedata - $(orange "$(print_path "${lEXE_ARCHIVE}")")" "" "${LOG_PATH_MODULE}/readpe_${lEXE_NAME}.log"
      else
        print_output "[-] No pedata for binary $(orange "$(print_path "${lEXE_ARCHIVE}")") available"
      fi

      lNEG_LOG=1
    done
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

