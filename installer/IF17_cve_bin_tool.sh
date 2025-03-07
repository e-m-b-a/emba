#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Installs cve-bin-tool including database for offline work

IF17_cve_bin_tool() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    INSTALL_APP_LIST=()

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] ; then
      print_tool_info "gsutil"
      print_pip_info "protobuf"
      # print_pip_info "cve_bin_tool"
      print_git_info "cve-bin-tool" "https://github.com/EMBA-support-repos/cve-bin-tool.git" "cve-bin-tool"
    fi

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}"" cve-bin-tool will be downloaded (if not already on the system)!""${NC}"
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        # cve-bin-tool installation
        echo -e "${ORANGE}""${BOLD}""Install cve-bin-tool""${NC}"
        git clone https://github.com/EMBA-support-repos/cve-bin-tool.git external/cve-bin-tool
        cd external/cve-bin-tool || ( echo "Could not install EMBA component cve-bin-tool" && exit 1 )
        pip install -U -r requirements.txt
        python3 -m pip install -e .

        # we need a more up to date protobuf for the android extractor -> lets update it now
        pip_install "protobuf==5.*"
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-bin-tool" && exit 1 )
        python3 external/cve-bin-tool/cve_bin_tool/cli.py --update now || true
        python3 external/cve-bin-tool/cve_bin_tool/cli.py --export external/cve-bin-tool/cve-database.db || true
        rm -r "${HOME}"/.cache/cve-bin-tool
        # cp -pr "${HOME}"/.cache/cve-bin-tool ./external/cve-bin-tool/cache_cve-bin-tool
      ;;
    esac
  fi
}
