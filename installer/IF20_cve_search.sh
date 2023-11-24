#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou, Benedikt Kuehne

# Description: Installs cve-search for CVE search module in EMBA (F20)

IF20_cve_search() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] || [[ "${CVE_SEARCH}" -eq 1 ]] || [[ "${FULL}" -eq 1 ]]; then

    print_git_info "cve-search" "EMBA-support-repos/cve-search" "CVE-Search is a tool to import CVE and CPE into a database to facilitate search and processing of CVEs."
    echo -e "${ORANGE}""cve-search will be downloaded.""${NC}"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""cve-search and mongodb will be downloaded, installed and populated!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )

        echo -e "\\n""${MAGENTA}""Check if the cve-search database is already installed and populated.""${NC}"
        git clone https://github.com/fkie-cad/nvd-json-data-feeds.git external/nvd-json-data-feeds
        if [[ $(grep -l -E "cpe.*busybox:" external/nvd-json-data-feeds/* -r 2>/dev/null | wc -l) -gt 18 ]]; then
          echo -e "\\n""${GREEN}""cve-search database already installed - no further action performed.""${NC}"
        else
          echo -e "\\n""${MAGENTA}""cve-search database not ready.""${NC}"
        fi

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )
      ;;
    esac
  fi
}
