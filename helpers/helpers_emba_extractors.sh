#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Multiple useful helpers used in the extraction process

docker_container_extractor() {
  local CONT_ID="${1:-}"
  export LOG_FILE="${LOG_DIR}"/p00_docker_extractor.txt
  if ! [[ -d "${LOG_DIR}"/firmware/ ]]; then
    mkdir "${LOG_DIR}"/firmware/
  fi
  if docker container ls -a | grep -q "${CONT_ID}"; then
    print_output "[*] Found docker container for extraction:"
    docker container ls -a | grep "${CONT_ID}" | tee -a "${LOG_FILE}"
    print_ln
  else
    print_output "[-] Warning: Docker container with ID ${ORANGE}${CONT_ID}${NC} not found"
    exit 1
  fi

  docker export -o "${LOG_DIR}"/firmware/firmware_docker_extracted.tar "${CONT_ID}"

  if [[ -f "${LOG_DIR}"/firmware/firmware_docker_extracted.tar ]]; then
    print_output "[+] Exported docker container to ${ORANGE}${LOG_DIR}/firmware/firmware_docker_extracted.tar${NC}"
  else
    print_output "[-] Warning: Docker export for container ID ${ORANGE}${CONT_ID}${NC} failed"
    exit 1
  fi
}

binwalker_matryoshka() {
  local FIRMWARE_PATH_="${1:-}"
  local OUTPUT_DIR_BINWALK="${2:-}"
  local BINWALK_BIN="binwalk"

  sub_module_title "Analyze binary firmware blob with binwalk"

  print_output "[*] Extracting firmware to directory ${ORANGE}${OUTPUT_DIR_BINWALK}${NC}"

  if ! [[ -d "${OUTPUT_DIR_BINWALK}" ]]; then
    mkdir -p "${OUTPUT_DIR_BINWALK}"
  fi

  timeout --preserve-status --signal SIGINT 300 "${BINWALK_BIN}" --run-as=root --preserve-symlinks -e -M --dd='.*' -C "${OUTPUT_DIR_BINWALK}" "${FIRMWARE_PATH_}" | tee -a "${LOG_FILE}" || true
  print_ln
}
