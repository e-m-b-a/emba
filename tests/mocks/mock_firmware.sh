create_mock_firmware() {
  local lFW_DIR="${1:-/tmp/test_fw}"
  rm -rf "${lFW_DIR}"
  mkdir -p "${lFW_DIR}/bin" "${lFW_DIR}/etc" "${lFW_DIR}/lib" "${lFW_DIR}/usr/bin"
  echo "#!/bin/sh" > "${lFW_DIR}/bin/busybox"
  echo "root:x:0:0:root:/root:/bin/sh" > "${lFW_DIR}/etc/passwd"
  echo "#!/bin/sh" > "${lFW_DIR}/usr/bin/test_script.sh"
  chmod +x "${lFW_DIR}/bin/busybox" "${lFW_DIR}/usr/bin/test_script.sh"
  echo "mock libc" > "${lFW_DIR}/lib/libc.so.6"
  echo "${lFW_DIR}"
}
