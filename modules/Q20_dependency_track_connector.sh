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
  local lDEPENDENCY_TRACK_TAGS=""

  if [[ -z "${lFW_TESTED}" ]] && [[ -f "${BASIC_DATA_LOG_DIR}"/fw_name.log ]]; then
    lFW_TESTED=$(sort -u "${BASIC_DATA_LOG_DIR}/fw_name.log" | head -1)
    lFW_TESTED=$(basename "${lFW_TESTED}")
  fi

  print_output "[*] Dependency Track upload to ${ORANGE}http://${DEPENDENCY_TRACK_HOST_IP}/${DEPENDENCY_TRACK_API}${NC}"
  print_output "$(indent "Dependency Track upload ${ORANGE}projectName=${lFW_TESTED}${NC}")"
  print_output "$(indent "Dependency Track upload ${ORANGE}projectVersion=${FW_VERSION:-unknown}${NC}")"
  print_output "$(indent "Dependency Track upload ${ORANGE}bom=@${EMBA_SBOM_JSON}${NC}")"
  if [[ -f "${F14_JSON_LOG}" ]]; then
    lDEPENDENCY_TRACK_TAGS=$(jq -r .tags[] "${F14_JSON_LOG}" | tr '\n' ',')
    lDEPENDENCY_TRACK_TAGS="${lDEPENDENCY_TRACK_TAGS%,}"
    print_output "$(indent "Dependency Track tags to use: ${ORANGE}${lDEPENDENCY_TRACK_TAGS}${NC}")"
  fi

  # upload SBOM
  lHTTP_CODE=$(curl -X "POST" "http://${DEPENDENCY_TRACK_HOST_IP}/${DEPENDENCY_TRACK_API}" \
    -H 'Content-Type: multipart/form-data' \
    -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
    -F "autoCreate=true" \
    -F "projectName=${lFW_TESTED}" \
    -F "projectVersion=${FW_VERSION:-unknown}" \
    -F "projectTags=${lDEPENDENCY_TRACK_TAGS:-EMBA,firmware}" \
    -F "bom=@${EMBA_SBOM_JSON}" \
    -o "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_upload_response.txt" --write-out "%{http_code}" || true)

  if [[ "${lHTTP_CODE}" -eq 200 ]] && grep -q token "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_upload_response.txt" 2>/dev/null; then
    # with the following request we check for our UUID and build a link
    lHTTP_CODE=$(curl "http://${DEPENDENCY_TRACK_HOST_IP}/api/v1/project?name=${lFW_TESTED}&sortName=lastBomImport&sortOrder=desc&offset=0&limit=1" \
      -H 'Content-Type: multipart/form-data' \
      -H "X-Api-Key: ${DEPENDENCY_TRACK_API_KEY}" \
      -o "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_details_response.txt" --write-out "%{http_code}" || true)

    print_output "[+] SBOM upload to Dependency Track environment was successful"
    if [[ "${lHTTP_CODE}" -eq 200 ]] ; then
      lPROJ_UUID=$(jq -r .[].uuid "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_details_response.txt" || true)
      # should be something like 830e6820-751a-4656-8274-08227c17cf62
      if [[ "${lPROJ_UUID}" =~ [0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+ ]]; then
        # Usually dependency track API is listening on port 8081 and the web server is listening on port 8080:
        write_link "http://${DEPENDENCY_TRACK_HOST_IP/:*}:8080/projects/${lPROJ_UUID}"
        print_output "[*] Found dependency track project UUID ${lPROJ_UUID}:"
        jq -r . "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_details_response.txt" | tee -a "${LOG_FILE}"
      fi
    fi
  else
    print_output "[-] ${MAGENTA}WARNING: Dependency Track SBOM upload failed!${NC}"
  fi
  # tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}/${DEPENDENCY_TRACK_HOST_IP/:*}_sbom_upload_response.txt"
}

