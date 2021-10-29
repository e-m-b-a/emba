#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Extracts AVM firmware images with Freetz-NG (see https://github.com/Freetz-NG/freetz-ng.git)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P12_avm_freetz_ng_extract() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$AVM_DETECTED" -eq 1 ]]; then
    module_title "AVM freetz-ng firmware extractor"
    "$EXT_DIR"/freetz-ng/fwmod -u -d "$LOG_DIR"/firmware/freetz_ng_extractor "$FIRMWARE_PATH"
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
