#!/bin/bash -p

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

# Prints the static rule coverage statistics of tests/bin_version_testdata.
#
# The statistics are computed by the bats test
# modules/s09_bin_version_identifiers.bats - bats swallows the output of
# passing tests, so this wrapper enables the output of passing tests to get
# the numbers printed always and not just in case of a failure.

set -e

INVOCATION_PATH="$(cd "$(dirname "${0}")" && pwd)"
BATS_BIN="${INVOCATION_PATH}/../../bats-core/bin/bats"
BATS_FILE="${INVOCATION_PATH}/../../modules/s09_bin_version_identifiers.bats"

if ! [[ -x "${BATS_BIN}" ]]; then
  echo "[-] bats not found at ${BATS_BIN}"
  echo "[*] Install it via: cd tests && curl -sL https://github.com/bats-core/bats-core/archive/refs/tags/v1.11.0.tar.gz | tar xz && mv bats-core-1.11.0 bats-core"
  echo "[*]   or: sudo apt-get install bats"
  exit 1
fi

if ! [[ -f "${BATS_FILE}" ]]; then
  echo "[-] bats test not found at ${BATS_FILE}"
  exit 1
fi

exec "${BATS_BIN}" --show-output-of-passing-tests --filter "coverage report" "${BATS_FILE}"
