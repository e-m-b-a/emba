#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2023-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Endri Hoxha

# Description: creates a VERSION.txt file containing the version number of emba and the local hash commit

create_version() {
  local VERSION=""
  # VERSION="$(echo "$(grep "export EMBA_VERSION=" helpers/helpers_emba_defaults.sh | cut -d\" -f2)"-"$(git describe --always)")"
  VERSION="$(grep "export EMBA_VERSION=" helpers/helpers_emba_defaults.sh | cut -d\" -f2)"
  echo "${VERSION}" > config/VERSION.txt
}

create_version "$@"
