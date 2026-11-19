#!/usr/bin/env bats

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#

load ../setup.bash

# Static regression for #2201: firmware basenames used to be interpolated into
# the radare2 -c script (which can reach system()), so a name containing
# $(...) executed as the EMBA user. The usage-file path must be built from the
# already-computed MD5, not lBIN_NAME. This does not re-run the reporter's PoC.

@test "S15 r2 -c script does not interpolate the firmware basename" {
  local lMOD="${MOD_DIR}/S15_radare_decompile_checks.sh"

  [ -f "${lMOD}" ]

  # The r2 invocation's -c argument must not mention lBIN_NAME.
  ! grep -n "r2 " -A2 "${lMOD}" | grep -q 'lBIN_NAME'

  grep -q 'lUSAGE_FILE="${LOG_PATH_MODULE}/${lFUNCTION}_${lBIN_MD5_SUM}_usage"' "${lMOD}"
  grep -q 'pdda @@ `cat '"'"'"${lUSAGE_FILE}"'"' "${lMOD}" || grep -q '"\${lUSAGE_FILE}"' "${lMOD}"
}
