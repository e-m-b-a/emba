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

# Description:  Stop and cleanup emulation environment

L99_cleanup() {

  local MODULE_END=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Cleanup of emulated environment."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ -n "$IP_ADDRESS_" ]]; then
      if [[ -n "$IMAGE_NAME" ]]; then
        # stop function from L10
        stopping_emulation_process "$IMAGE_NAME"
      fi

      # now we only execute the network reset
      reset_network_emulation 2
    fi
    module_end_log "${FUNCNAME[0]}" "$MODULE_END"
  fi
}

