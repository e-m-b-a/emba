#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Dependency Track SBOM uploader module for container #2
# Note:        Important requirement for Q-modules is the self termination when a certain phase ends

Q20_dependency_track_connector() {
  if [[ "${DEPENDENCY_TRACK_ENABLED}" -gt 0 ]] && [[ -n "${DEPENDENCY_TRACK_HOST_IP}" ]] && \
    [[ -n "${DEPENDENCY_TRACK_API_KEY}" ]]; then

    module_log_init "${FUNCNAME[0]}"
    module_title "Dependency Track SBOM uploader module"
    pre_module_reporter "${FUNCNAME[0]}"

    local lNEG_LOG=0

    while ! [[ -f "${LOG_DIR}/${MAIN_LOG_FILE}" ]]; do
      if ! [[ -d "${LOG_DIR}" ]]; then
        # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
        return
      fi
      sleep 5
    done

    print_output "[*] Waiting for SBOM to upload ..." "no_log"

    # we need to wait until the SBOM module is finished:
    while ! grep -q "F15_cyclonedx_sbom finished" "${LOG_DIR}/${MAIN_LOG_FILE}"; do
      if grep -q "Test ended on " "${LOG_DIR}/${MAIN_LOG_FILE}"; then
        exit
      fi
      sleep 1
    done

    if [[ -f "${EMBA_SBOM_JSON}" ]]; then
      lNEG_LOG=1
      dep_track_upload_sbom
    fi

    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

dep_track_upload_sbom() {
  local lHTTP_CODE=""
  local lFW_TESTED="${FW_DEVICE}"

  if [[ -z "${lFW_TESTED}" ]] && [[ -f "${TMP_DIR}"/fw_name.log ]]; then
    lFW_TESTED=$(sort -u "${TMP_DIR}/fw_name.log" | head -1)
    lFW_TESTED=$(basename "${lFW_TESTED}")
  fi

  print_output "[*] Dependency Track upload to ${ORANGE}http://${DEPENDENCY_TRACK_HOST_IP}/${DEPENDENCY_TRACK_API}${NC}"
  print_output "$(indent "Dependency Track upload ${ORANGE}projectName=${lFW_TESTED}${NC}")"
  print_output "$(indent "Dependency Track upload ${ORANGE}projectVersion=${FW_VERSION:-unknown}${NC}")"
  print_output "$(indent "Dependency Track upload ${ORANGE}bom=@${EMBA_SBOM_JSON}${NC}")"

  lHTTP_CODE=$(curl -X "POST" "http://${DEPENDENCY_TRACK_HOST_IP}/${DEPENDENCY_TRACK_API}" \
    -H 'Content-Type: multipart/form-data' \
    -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
    -F "autoCreate=true" \
    -F "projectName=${lFW_TESTED}" \
    -F "projectVersion=${FW_VERSION:-unknown}" \
    -F "projectTags=${DEPENDENCY_TRACK_TAGS}" \
    -F "bom=@${EMBA_SBOM_JSON}" \
    -o "${TMP_DIR}/${DEPENDENCY_TRACK_HOST_IP}_sbom_upload_response.txt" --write-out "%{http_code}" || true)

  if [[ "${lHTTP_CODE}" -eq 200 ]] ; then
    print_output "[+] SBOM upload to Dependency Track environment was successful"
  else
    print_output "[-] ${MAGENTA}WARNING: Dependency Track SBOM upload failed!${NC}"
  fi
  tee -a "${LOG_FILE}" < "${TMP_DIR}/${DEPENDENCY_TRACK_HOST_IP}_sbom_upload_response.txt"
}

