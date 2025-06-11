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

# Description:  load strict mode settings helper function

load_strict_mode_settings() {
  # http://redsymbol.net/articles/unofficial-bash-strict-mode/
  # https://github.com/tests-always-included/wick/blob/master/doc/bash-strict-mode.md
  set -e          # Exit immediately if a command exits with a non-zero status
  set -u          # Exit and trigger the ERR trap when accessing an unset variable
  set -o pipefail # The return value of a pipeline is the value of the last (rightmost) command to exit with a non-zero status
  set -E          # The ERR trap is inherited by shell functions, command substitutions and commands in subshells
  if [[ "${DEBUG_SCRIPT}" -eq 1 ]]; then
    # set DEBUG to 1 in the main emba script - be warned this produces a lot of output!
    # https://wiki.bash-hackers.org/scripting/debuggingtips#making_xtrace_more_useful
    export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
    set -x
  fi
  shopt -s extdebug # Enable extended debugging
  # nosemgrep
  IFS=$'\n\t'     # Set the "internal field separator"
  trap 'wickStrictModeFail $?' ERR  # The ERR trap is triggered when a script catches an error
}

