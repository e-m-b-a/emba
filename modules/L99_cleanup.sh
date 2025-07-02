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

# Description:  Stop and cleanup emulation environment

L99_cleanup() {
  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Cleanup of emulated environment."
    pre_module_reporter "${FUNCNAME[0]}"

    # as we are running from the run.sh startup script the network is also reconfigured
    stopping_emulation_process "${IMAGE_NAME}"

    module_end_log "${FUNCNAME[0]}" 0
  fi
}

