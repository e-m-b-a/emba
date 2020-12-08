#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

P02_firmware_bin_file_check() {
  module_log_init "firmware_bin_file_log"
  module_title "Binary firmware file analyser"

  local FILE_BIN_OUT
  FILE_BIN_OUT=$(file "$FIRMWARE_PATH")
  local FILE_LS_OUT
  FILE_LS_OUT=$(ls -lh "$FIRMWARE_PATH")
  
  print_output "[*] Details of the binary file:"
  print_output "[*] $FILE_LS_OUT"
  print_output "[*] $FILE_BIN_OUT"
}
