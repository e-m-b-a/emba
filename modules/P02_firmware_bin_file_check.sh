#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Gives some very basic information about the provided firmware binary.

P02_firmware_bin_file_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware file analyzer"

  local FILE_BIN_OUT
  FILE_BIN_OUT=$(file "$FIRMWARE_PATH")
  local FILE_LS_OUT
  FILE_LS_OUT=$(ls -lh "$FIRMWARE_PATH")

  # entropy checking on binary file
  ENTROPY=$(ent "$FIRMWARE_PATH" | grep Entropy)
  
  print_output "[*] Details of the binary file:"
  print_output "$(indent "$FILE_LS_OUT")"
  echo
  print_output "$(indent "$FILE_BIN_OUT")"
  echo
  print_output "$(indent "$ENTROPY")"

  module_end_log "${FUNCNAME[0]}" 1
}
