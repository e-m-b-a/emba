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

create_mock_firmware() {
  local lFW_DIR="${1:-/tmp/test_fw}"
  if [[ -z "${lFW_DIR}" || "${lFW_DIR}" == "/" || "${lFW_DIR}" == "/tmp" || "${lFW_DIR}" != /tmp/* ]]; then
    echo "Refusing to create mock firmware in unsafe directory: ${lFW_DIR}" >&2
    return 1
  fi
  rm -rf "${lFW_DIR}"
  mkdir -p "${lFW_DIR}/bin" "${lFW_DIR}/etc" "${lFW_DIR}/lib" "${lFW_DIR}/usr/bin"
  echo "#!/bin/sh" >"${lFW_DIR}/bin/busybox"
  echo "root:x:0:0:root:/root:/bin/sh" >"${lFW_DIR}/etc/passwd"
  echo "#!/bin/sh" >"${lFW_DIR}/usr/bin/test_script.sh"
  chmod +x "${lFW_DIR}/bin/busybox" "${lFW_DIR}/usr/bin/test_script.sh"
  echo "mock libc" >"${lFW_DIR}/lib/libc.so.6"
  echo "${lFW_DIR}"
}
